//! PostgreSQL-authoritative capacity leases for one-shot model evaluation.
//!
//! The adapter serializes every tenant/site capacity decision with a
//! transaction-scoped advisory lock and database time. It only controls model
//! provider concurrency; it never grants a business operation, evidence read,
//! approval, or policy publication.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, TimeDelta, Timelike, Utc};
use openssl::{rand::rand_bytes, sha::sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
use xshield_core::{
    domain::ModelEvaluationLeaseId,
    model_evaluation_admission::{
        ModelEvaluationAdmissionAttempt, ModelEvaluationAdmissionDenied,
        ModelEvaluationAdmissionReleaseState, ModelEvaluationAdmissionState,
    },
    ports::ModelEvaluationAdmissionPort,
};
use zeroize::Zeroizing;

const PROVIDER_SEND_SECONDS: i64 = 10;

/// Private `PostgreSQL` lease for one provider-call capacity reservation.
///
/// The lease token is generated with OS-backed entropy, stored only as a
/// SHA-256 digest, and deliberately has no formatter, clone, debug, or
/// serialization implementation. A later worker cannot close a replacement
/// lease by knowing a call ID alone.
pub struct ModelEvaluationAdmissionLease {
    attempt: ModelEvaluationAdmissionAttempt,
    lease_id: ModelEvaluationLeaseId,
    policy_revision: String,
    token: Zeroizing<[u8; 32]>,
}

impl ModelEvaluationAdmissionLease {
    /// Returns the non-secret durable lease identity for diagnostics.
    #[must_use]
    pub const fn lease_id(&self) -> &ModelEvaluationLeaseId {
        &self.lease_id
    }
}

struct AdmissionScope {
    policy_revision: String,
    max_active_calls: i64,
    lease_seconds: i64,
}

struct StoredLease {
    status: String,
    lease_until: DateTime<Utc>,
}

impl PostgresIdentityStore {
    /// Acquires one private, tenant/site-scoped provider capacity lease.
    ///
    /// The deployment must have provisioned the scope in
    /// `model_evaluation_admission_scopes`; this worker never turns local
    /// environment values into a distributed capacity policy. Expired active
    /// leases are terminally recovered before the capacity count. A denial
    /// occurs before model evidence or HTTP, and this method creates no outbox
    /// event because the lease is scheduling state rather than an audit truth.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the database cannot atomically make the
    /// capacity decision or OS entropy is unavailable. It never calls a model,
    /// opens evidence, grants business authorization, or creates an approval.
    pub async fn acquire_model_evaluation_admission(
        &self,
        attempt: &ModelEvaluationAdmissionAttempt,
    ) -> Result<ModelEvaluationAdmissionState<ModelEvaluationAdmissionLease>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_admission_timeouts(&mut transaction).await?;
        lock_scope(&mut transaction, attempt).await?;
        let now = database_now(&mut transaction).await?;
        expire_active_leases(&mut transaction, attempt, now).await?;
        let Some(scope) = locked_scope(&mut transaction, attempt).await? else {
            transaction.rollback().await?;
            return Ok(ModelEvaluationAdmissionState::Denied(
                ModelEvaluationAdmissionDenied::ScopeNotConfigured,
            ));
        };
        if scope.policy_revision != attempt.policy_revision().as_str() {
            transaction.rollback().await?;
            return Ok(ModelEvaluationAdmissionState::Denied(
                ModelEvaluationAdmissionDenied::PolicyRevisionMismatch,
            ));
        }
        if let Some(existing) = existing_call(&mut transaction, attempt).await? {
            let outcome = if existing.0 == attempt.request_id().as_str()
                && existing.1 == attempt.runner_id()
            {
                ModelEvaluationAdmissionDenied::RecoveryRequired
            } else {
                ModelEvaluationAdmissionDenied::Conflict
            };
            transaction.rollback().await?;
            return Ok(ModelEvaluationAdmissionState::Denied(outcome));
        }
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM xshield.model_evaluation_admission_leases
             WHERE tenant_id=$1 AND site_id=$2 AND status='active'",
        )
        .bind(attempt.tenant_id().as_str())
        .bind(attempt.site_id().as_str())
        .fetch_one(&mut *transaction)
        .await?;
        if active >= scope.max_active_calls {
            transaction.rollback().await?;
            return Ok(ModelEvaluationAdmissionState::Denied(
                ModelEvaluationAdmissionDenied::CapacityExhausted,
            ));
        }
        let lease_id = ModelEvaluationLeaseId::parse(format!("mle_{}", Uuid::now_v7()))
            .map_err(|_| StoreError::Entropy)?;
        let mut token = [0_u8; 32];
        rand_bytes(&mut token).map_err(|_| StoreError::Entropy)?;
        let token_digest = sha256(&token);
        let lease_until = date_millis(
            now.checked_add_signed(TimeDelta::seconds(scope.lease_seconds))
                .ok_or(StoreError::NumericRange("model_evaluation_lease_until"))?,
        );
        sqlx::query(
            "INSERT INTO xshield.model_evaluation_admission_leases
                 (tenant_id, site_id, lease_id, request_id, model_call_id,
                  runner_id, policy_revision, lease_token_digest, status,
                  acquired_at, lease_until)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10)",
        )
        .bind(attempt.tenant_id().as_str())
        .bind(attempt.site_id().as_str())
        .bind(lease_id.as_str())
        .bind(attempt.request_id().as_str())
        .bind(attempt.model_call_id().as_str())
        .bind(attempt.runner_id())
        .bind(&scope.policy_revision)
        .bind(token_digest.as_slice())
        .bind(now)
        .bind(lease_until)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ModelEvaluationAdmissionState::Admitted(
            ModelEvaluationAdmissionLease {
                attempt: attempt.clone(),
                lease_id,
                policy_revision: scope.policy_revision,
                token: Zeroizing::new(token),
            },
        ))
    }

    /// Confirms one active lease immediately before provider network I/O.
    ///
    /// The check uses database time and requires enough remaining lifetime for
    /// the fixed ten-second HTTP exchange. It therefore prevents an instance
    /// that stalled while preparing evidence from sending after another worker
    /// is allowed to recover its expired capacity.
    ///
    /// # Errors
    /// Returns [`StoreError`] for authoritative-store failures. A normal
    /// capacity-state refusal is returned as a closed denial and must prevent
    /// HTTP send.
    pub async fn confirm_model_evaluation_admission(
        &self,
        lease: &ModelEvaluationAdmissionLease,
    ) -> Result<ModelEvaluationAdmissionState<()>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_admission_timeouts(&mut transaction).await?;
        lock_scope(&mut transaction, &lease.attempt).await?;
        let now = database_now(&mut transaction).await?;
        expire_active_leases(&mut transaction, &lease.attempt, now).await?;
        let Some(scope) = locked_scope(&mut transaction, &lease.attempt).await? else {
            transaction.rollback().await?;
            return Ok(ModelEvaluationAdmissionState::Denied(
                ModelEvaluationAdmissionDenied::ScopeNotConfigured,
            ));
        };
        let Some(stored) = locked_private_lease(&mut transaction, lease).await? else {
            transaction.rollback().await?;
            return Ok(ModelEvaluationAdmissionState::Denied(
                ModelEvaluationAdmissionDenied::Conflict,
            ));
        };
        let required_until = now
            .checked_add_signed(TimeDelta::seconds(PROVIDER_SEND_SECONDS))
            .ok_or(StoreError::NumericRange("model_evaluation_send_deadline"))?;
        let outcome = if scope.policy_revision != lease.policy_revision
            || scope.policy_revision != lease.attempt.policy_revision().as_str()
        {
            ModelEvaluationAdmissionState::Denied(
                ModelEvaluationAdmissionDenied::PolicyRevisionMismatch,
            )
        } else if stored.status == "active" && stored.lease_until > required_until {
            ModelEvaluationAdmissionState::Admitted(())
        } else {
            ModelEvaluationAdmissionState::Denied(ModelEvaluationAdmissionDenied::LeaseExpired)
        };
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Closes one private capacity lease after the worker's terminal audit.
    ///
    /// A release is idempotent only for the same private token. An expired or
    /// unavailable lease is never turned back into active capacity and cannot
    /// release a successor held by another worker.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the authoritative release transaction cannot
    /// be confirmed. Callers must leave the lease for TTL recovery in that case.
    pub async fn release_model_evaluation_admission(
        &self,
        lease: &ModelEvaluationAdmissionLease,
    ) -> Result<ModelEvaluationAdmissionReleaseState, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_admission_timeouts(&mut transaction).await?;
        lock_scope(&mut transaction, &lease.attempt).await?;
        let now = database_now(&mut transaction).await?;
        expire_active_leases(&mut transaction, &lease.attempt, now).await?;
        let Some(stored) = locked_private_lease(&mut transaction, lease).await? else {
            transaction.rollback().await?;
            return Ok(ModelEvaluationAdmissionReleaseState::Unavailable);
        };
        let outcome = match stored.status.as_str() {
            "active" => {
                sqlx::query(
                    "UPDATE xshield.model_evaluation_admission_leases
                     SET status='released', released_at=$4
                     WHERE tenant_id=$1 AND site_id=$2 AND lease_id=$3 AND status='active'",
                )
                .bind(lease.attempt.tenant_id().as_str())
                .bind(lease.attempt.site_id().as_str())
                .bind(lease.lease_id.as_str())
                .bind(now)
                .execute(&mut *transaction)
                .await?;
                ModelEvaluationAdmissionReleaseState::Released
            }
            "released" => ModelEvaluationAdmissionReleaseState::AlreadyReleased,
            "expired" => ModelEvaluationAdmissionReleaseState::Expired,
            _ => return Err(StoreError::CorruptData("model_evaluation_lease_status")),
        };
        transaction.commit().await?;
        Ok(outcome)
    }
}

impl ModelEvaluationAdmissionPort for PostgresIdentityStore {
    type Lease = ModelEvaluationAdmissionLease;
    type Error = StoreError;

    async fn acquire_model_evaluation_admission(
        &self,
        attempt: &ModelEvaluationAdmissionAttempt,
    ) -> Result<ModelEvaluationAdmissionState<Self::Lease>, Self::Error> {
        self.acquire_model_evaluation_admission(attempt).await
    }

    async fn confirm_model_evaluation_admission(
        &self,
        lease: &Self::Lease,
    ) -> Result<ModelEvaluationAdmissionState<()>, Self::Error> {
        self.confirm_model_evaluation_admission(lease).await
    }

    async fn release_model_evaluation_admission(
        &self,
        lease: &Self::Lease,
    ) -> Result<ModelEvaluationAdmissionReleaseState, Self::Error> {
        self.release_model_evaluation_admission(lease).await
    }
}

async fn set_admission_timeouts(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), StoreError> {
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn lock_scope(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: &ModelEvaluationAdmissionAttempt,
) -> Result<(), StoreError> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended(
             'xshield-model-evaluation-admission-v1:' || $1 || ':' || $2, 0
         ))",
    )
    .bind(attempt.tenant_id().as_str())
    .bind(attempt.site_id().as_str())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn database_now(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<DateTime<Utc>, StoreError> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(date_millis(now))
}

async fn locked_scope(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: &ModelEvaluationAdmissionAttempt,
) -> Result<Option<AdmissionScope>, StoreError> {
    let Some(row) = sqlx::query(
        "SELECT policy_revision, max_active_calls, lease_seconds
         FROM xshield.model_evaluation_admission_scopes
         WHERE tenant_id=$1 AND site_id=$2
         FOR UPDATE",
    )
    .bind(attempt.tenant_id().as_str())
    .bind(attempt.site_id().as_str())
    .fetch_optional(&mut **transaction)
    .await?
    else {
        return Ok(None);
    };
    let policy_revision = row.try_get::<String, _>("policy_revision")?;
    let max_active_calls = i64::from(row.try_get::<i32, _>("max_active_calls")?);
    let lease_seconds = i64::from(row.try_get::<i32, _>("lease_seconds")?);
    if !valid_policy_revision(&policy_revision)
        || !(1..=32).contains(&max_active_calls)
        || !(30..=60).contains(&lease_seconds)
    {
        return Err(StoreError::CorruptData("model_evaluation_admission_scope"));
    }
    Ok(Some(AdmissionScope {
        policy_revision,
        max_active_calls,
        lease_seconds,
    }))
}

async fn expire_active_leases(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: &ModelEvaluationAdmissionAttempt,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE xshield.model_evaluation_admission_leases
         SET status='expired', expired_at=$3
         WHERE tenant_id=$1 AND site_id=$2
           AND status='active' AND lease_until <= $3",
    )
    .bind(attempt.tenant_id().as_str())
    .bind(attempt.site_id().as_str())
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn existing_call(
    transaction: &mut Transaction<'_, Postgres>,
    attempt: &ModelEvaluationAdmissionAttempt,
) -> Result<Option<(String, String)>, StoreError> {
    let row = sqlx::query(
        "SELECT request_id, runner_id
         FROM xshield.model_evaluation_admission_leases
         WHERE tenant_id=$1 AND site_id=$2 AND model_call_id=$3
         FOR KEY SHARE",
    )
    .bind(attempt.tenant_id().as_str())
    .bind(attempt.site_id().as_str())
    .bind(attempt.model_call_id().as_str())
    .fetch_optional(&mut **transaction)
    .await?;
    row.map(|row| Ok((row.try_get("request_id")?, row.try_get("runner_id")?)))
        .transpose()
}

async fn locked_private_lease(
    transaction: &mut Transaction<'_, Postgres>,
    lease: &ModelEvaluationAdmissionLease,
) -> Result<Option<StoredLease>, StoreError> {
    let token_digest = sha256(&lease.token[..]);
    let row = sqlx::query(
        "SELECT status, lease_until
         FROM xshield.model_evaluation_admission_leases
         WHERE tenant_id=$1 AND site_id=$2 AND lease_id=$3 AND lease_token_digest=$4
         FOR UPDATE",
    )
    .bind(lease.attempt.tenant_id().as_str())
    .bind(lease.attempt.site_id().as_str())
    .bind(lease.lease_id.as_str())
    .bind(token_digest.as_slice())
    .fetch_optional(&mut **transaction)
    .await?;
    row.map(|row| {
        let status: String = row.try_get("status")?;
        let lease_until: DateTime<Utc> = row.try_get("lease_until")?;
        if !matches!(status.as_str(), "active" | "released" | "expired") {
            return Err(StoreError::CorruptData("model_evaluation_lease_status"));
        }
        Ok(StoredLease {
            status,
            lease_until: date_millis(lease_until),
        })
    })
    .transpose()
}

fn valid_policy_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn date_millis(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_nanosecond(value.timestamp_subsec_millis() * 1_000_000)
        .unwrap_or(value)
}
