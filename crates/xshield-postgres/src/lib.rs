//! `PostgreSQL` adapters for identity and grant transactions.
//!
//! SQL statements always include tenant and site scope. Security state changes
//! and their outbox event commit in one database transaction.

#![warn(missing_docs)]

mod action_read;
mod binding_inspection;
mod calibration_read_capability;
mod case_close;
mod case_evidence;
mod case_evidence_holds;
mod case_evidence_read;
mod case_list;
mod evidence_access_decision;
mod evidence_access_inspection;
mod evidence_access_list;
mod evidence_access_request;
mod evidence_catalog;
mod evidence_orphan;
mod evidence_retention;
mod grant;
mod grant_inspection;
mod grant_read;
mod identity_read;
mod investigation_case;
mod outbox;
mod provenance;
mod request_replay;
mod response_grant;
mod service_identity_read;
mod share_grant_issue;
mod share_grant_read;

pub use action_read::ResponseActionDescriptorQuery;
pub use binding_inspection::BindingInspection;
pub use calibration_read_capability::{
    CalibrationEvidenceBatchBegin, CalibrationEvidenceBatchBeginOutcome,
    CalibrationReadCapabilityIssue, CalibrationReadCapabilityIssueOutcome,
    CalibrationReadCapabilityRecord,
};
pub use case_close::{
    InvestigationCaseClose, InvestigationCaseCloseRecord, InvestigationCaseCloseWriteOutcome,
};
pub use case_evidence::{
    CASE_EVIDENCE_ITEMS_MAX, CaseEvidenceAdd, CaseEvidenceRecord, CaseEvidenceWriteOutcome,
};
pub use case_evidence_holds::{
    CASE_EVIDENCE_HOLD_ACTIVE_MAX, CASE_EVIDENCE_HOLD_HISTORY_MAX, CASE_EVIDENCE_HOLD_MAX_DAYS,
    CaseEvidenceHoldCreate, CaseEvidenceHoldCreateOutcome, CaseEvidenceHoldPage,
    CaseEvidenceHoldQuery, CaseEvidenceHoldRecord, CaseEvidenceHoldRelease,
    CaseEvidenceHoldReleaseOutcome,
};
pub use case_evidence_read::{
    CaseEvidenceAvailability, CaseEvidenceItem, CaseEvidencePage, CaseEvidenceQuery,
};
pub use case_list::{InvestigationCasePage, InvestigationCaseQuery};
pub use evidence_access_decision::{
    EvidenceAccessCapability, EvidenceAccessDecisionCreate, EvidenceAccessDecisionRecord,
    EvidenceAccessDecisionWriteOutcome,
};
pub use evidence_access_inspection::EvidenceAccessInspection;
pub use evidence_access_list::{
    EvidenceAccessListQuery, EvidenceAccessListView, EvidenceAccessPage,
};
pub use evidence_access_request::{
    EvidenceAccessRequestCreate, EvidenceAccessRequestRecord, EvidenceAccessRequestWriteOutcome,
};
pub use evidence_catalog::{
    CatalogArtifact, EvidenceCatalogArtifactQuery, EvidenceCatalogPage, EvidenceCatalogPublish,
    EvidenceCatalogQuery, EvidenceCatalogWriteOutcome,
};
pub use evidence_orphan::{EvidenceOrphanPurgeJob, EvidenceOrphanPurgeResult};
pub use evidence_retention::{EvidencePurgeJob, EvidencePurgeResult};
pub use grant::{GrantPersistence, GrantWriteOutcome};
pub use grant_inspection::{BindingRecordStatus, GrantInspection, GrantRecordStatus};
pub use identity_read::{SensorSession, SensorSessionQuery, SensorSessionState};
pub use investigation_case::{
    InvestigationCaseCreate, InvestigationCaseRecord, InvestigationCaseWriteOutcome,
};
pub use outbox::{
    OutboxAckOutcome, OutboxEvent, OutboxFailureOutcome, OutboxLease, OutboxLeaseConfig,
    OutboxScope, ack_outbox_event, claim_outbox_batch, claim_outbox_batch_for_types,
    fail_outbox_event,
};
pub use provenance::{ProvenancePersistence, ProvenanceWriteOutcome};
pub use request_replay::{RequestCryptoMessage, RequestCryptoMessageOutcome};
pub use response_grant::{
    CommittedResponseGrant, ResponseGrantItem, ResponseGrantPersistence, ResponseGrantWriteOutcome,
};
pub use share_grant_issue::{ShareGrantPersistence, ShareGrantWriteOutcome};

use serde_json::Value;
use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction, postgres::PgPoolOptions};
use std::{collections::BTreeMap, error::Error, fmt, time::Duration};
use xshield_core::{
    domain::{AuthBindingId, EventId, SiteId, TenantId},
    identity::{
        AnonymousSession, AuthBinding, AuthEpoch, AuthSnapshot, AuthorizationContextRef,
        BindingStatus, CredentialFingerprint, CredentialGeneration, CredentialSlot, UnixSeconds,
    },
};

/// One empty anonymous WAF session ready for bounded persistence.
pub struct AnonymousSessionEstablishment<'a> {
    tenant_id: &'a TenantId,
    binding_id: &'a AuthBindingId,
    session: &'a AnonymousSession,
    session_fingerprint: &'a [u8; 32],
    source_fingerprint: &'a [u8; 32],
    max_active_sessions: u32,
    rate_window_seconds: u64,
    max_creations_per_source: u32,
    max_creations_per_site: u32,
    now: UnixSeconds,
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> AnonymousSessionEstablishment<'a> {
    /// Validates an anonymous-session persistence command.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an expired session, a zero
    /// capacity, or a non-object audit envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: &'a TenantId,
        binding_id: &'a AuthBindingId,
        session: &'a AnonymousSession,
        session_fingerprint: &'a [u8; 32],
        source_fingerprint: &'a [u8; 32],
        max_active_sessions: u32,
        rate_window_seconds: u64,
        max_creations_per_source: u32,
        max_creations_per_site: u32,
        now: UnixSeconds,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        session
            .verify(session.site_id(), now)
            .map_err(|_| StoreError::InvalidCommand)?;
        if max_active_sessions == 0
            || rate_window_seconds == 0
            || max_creations_per_source == 0
            || max_creations_per_source > max_creations_per_site
            || !event_envelope.is_object()
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant_id,
            binding_id,
            session,
            session_fingerprint,
            source_fingerprint,
            max_active_sessions,
            rate_window_seconds,
            max_creations_per_source,
            max_creations_per_site,
            now,
            event_id,
            event_envelope,
        })
    }
}

/// One verified authentication result ready for atomic binding establishment.
pub struct BindingEstablishment<'a> {
    binding: &'a AuthBinding,
    session_fingerprint: &'a [u8; 32],
    credentials_expire_at: UnixSeconds,
    now: UnixSeconds,
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> BindingEstablishment<'a> {
    /// Validates an initial binding persistence command.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when the binding is not a fresh
    /// active generation, expiry bounds are incoherent, or the event is invalid.
    pub fn new(
        binding: &'a AuthBinding,
        session_fingerprint: &'a [u8; 32],
        credentials_expire_at: UnixSeconds,
        now: UnixSeconds,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        if binding.status() != BindingStatus::Active
            || binding.epoch() != AuthEpoch::new(1)
            || binding.generation() != CredentialGeneration::new(1)
            || binding.absolute_expires_at() <= now
            || credentials_expire_at <= now
            || credentials_expire_at > binding.absolute_expires_at()
            || !event_envelope.is_object()
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            binding,
            session_fingerprint,
            credentials_expire_at,
            now,
            event_id,
            event_envelope,
        })
    }
}

/// Complete replacement credential set for a verified identity transition.
pub struct CredentialTransition<'a> {
    snapshot: &'a AuthSnapshot,
    previous_credentials: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
    credentials: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
    credentials_expire_at: UnixSeconds,
    now: UnixSeconds,
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

/// Verified replacement identity and credentials for one existing WAF binding.
pub struct IdentityContextSwitch<'a> {
    transition: CredentialTransition<'a>,
    principal_ref: &'a str,
    authorization_context_ref: &'a AuthorizationContextRef,
}

/// One verified identity snapshot ready for atomic binding revocation.
pub struct BindingRevocation<'a> {
    snapshot: &'a AuthSnapshot,
    now: UnixSeconds,
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> CredentialTransition<'a> {
    /// Validates a credential transition persistence command.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when the credential set is empty,
    /// already expired, or the event envelope is not a JSON object.
    pub fn new(
        snapshot: &'a AuthSnapshot,
        previous_credentials: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
        credentials: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
        credentials_expire_at: UnixSeconds,
        now: UnixSeconds,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        if previous_credentials.is_empty()
            || credentials.is_empty()
            || previous_credentials == credentials
            || credentials_expire_at <= now
            || !event_envelope.is_object()
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            snapshot,
            previous_credentials,
            credentials,
            credentials_expire_at,
            now,
            event_id,
            event_envelope,
        })
    }
}

impl<'a> IdentityContextSwitch<'a> {
    /// Validates an identity-context switch persistence command.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when neither principal nor
    /// authorization context changes, the principal is invalid, or the
    /// credential transition is invalid.
    pub fn new(
        transition: CredentialTransition<'a>,
        principal_ref: &'a str,
        authorization_context_ref: &'a AuthorizationContextRef,
    ) -> Result<Self, StoreError> {
        if (principal_ref == transition.snapshot.principal_ref()
            && authorization_context_ref == transition.snapshot.authorization_context_ref())
            || principal_ref.is_empty()
            || principal_ref.len() > 256
            || principal_ref.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            transition,
            principal_ref,
            authorization_context_ref,
        })
    }
}

impl<'a> BindingRevocation<'a> {
    /// Validates a binding-revocation persistence command.
    ///
    /// The complete v3 envelope is supplied by the trusted transaction
    /// producer and is persisted byte-for-byte as JSONB. Binding liveness and
    /// expiry are checked again while holding the database row lock.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for a zero/uncopiable epoch or a
    /// non-object event envelope.
    pub fn new(
        snapshot: &'a AuthSnapshot,
        now: UnixSeconds,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        if snapshot.epoch().value() == 0
            || snapshot.generation().value() == 0
            || i64::try_from(snapshot.epoch().value()).is_err()
            || i64::try_from(now.value()).is_err()
            || !event_envelope.is_object()
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            snapshot,
            now,
            event_id,
            event_envelope,
        })
    }
}

/// Result of an optimistic identity refresh transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshOutcome {
    /// Binding, credentials, and outbox event committed atomically.
    Updated {
        /// Generation required by the command.
        previous_generation: CredentialGeneration,
        /// Newly committed generation.
        current_generation: CredentialGeneration,
    },
    /// Binding state no longer matches the request snapshot.
    Conflict,
}

/// Result of an optimistic identity-context switch transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextSwitchOutcome {
    /// Principal, epoch, credentials, and outbox event committed atomically.
    Updated {
        /// Epoch required by the command.
        previous_epoch: AuthEpoch,
        /// Newly committed epoch.
        current_epoch: AuthEpoch,
        /// Generation required by the command.
        previous_generation: CredentialGeneration,
        /// Newly committed generation.
        current_generation: CredentialGeneration,
    },
    /// Binding state no longer matches the request snapshot.
    Conflict,
}

/// Result of an optimistic binding-revocation transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingRevocationOutcome {
    /// Binding, credentials, and outbox event committed atomically.
    Revoked,
    /// Binding state no longer matches the request snapshot.
    Conflict,
}

/// Result of creating a bounded anonymous WAF session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnonymousSessionWriteOutcome {
    /// The empty session and its outbox event committed atomically.
    Created,
    /// The configured active anonymous-session bound is already reached.
    CapacityExceeded,
    /// The source or site creation-rate bound is already reached.
    RateExceeded,
}

/// PostgreSQL-backed identity state writer.
#[derive(Clone, Debug)]
pub struct PostgresIdentityStore {
    pool: PgPool,
}

impl PostgresIdentityStore {
    /// Connects a bounded `PostgreSQL` pool.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid pool bounds or connection failure.
    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self, StoreError> {
        if max_connections == 0 || acquire_timeout.is_zero() {
            return Err(StoreError::InvalidPoolConfig);
        }
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(acquire_timeout)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    /// Uses an existing pool configured by the executable composition root.
    #[must_use]
    pub const fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Atomically creates one empty anonymous session and its outbox event.
    ///
    /// A transaction-scoped advisory lock serializes capacity checks per
    /// tenant/site. Expired anonymous rows are removed before counting; they
    /// cannot own credentials or grants through this API.
    ///
    /// # Errors
    /// Returns [`StoreError`] when numeric conversion, persistence, or audit
    /// durability prevents a complete transaction.
    pub async fn establish_anonymous_session(
        &self,
        command: AnonymousSessionEstablishment<'_>,
    ) -> Result<AnonymousSessionWriteOutcome, StoreError> {
        let now = to_i64(command.now.value(), "now")?;
        let absolute_expires_at = to_i64(
            command.session.absolute_expires_at().value(),
            "absolute_expires_at",
        )?;
        let rate_cutoff = to_i64(
            command
                .now
                .value()
                .saturating_sub(command.rate_window_seconds),
            "rate_cutoff",
        )?;
        let rate_cleanup_cutoff = to_i64(
            command
                .now
                .value()
                .saturating_sub(command.rate_window_seconds.saturating_mul(2)),
            "rate_cleanup_cutoff",
        )?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-anonymous-v1:' || $1 || ':' || $2, 0
             ))",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.session.site_id().as_str())
        .execute(&mut *transaction)
        .await?;
        if !consume_anonymous_rates(
            &mut transaction,
            &command,
            rate_cutoff,
            rate_cleanup_cutoff,
            now,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(AnonymousSessionWriteOutcome::RateExceeded);
        }
        sqlx::query(
            "DELETE FROM xshield.auth_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND status = 'anonymous'
               AND absolute_expires_at <= to_timestamp($3)",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.session.site_id().as_str())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM xshield.auth_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND status = 'anonymous'
               AND absolute_expires_at > to_timestamp($3)",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.session.site_id().as_str())
        .bind(now)
        .fetch_one(&mut *transaction)
        .await?;
        if active >= i64::from(command.max_active_sessions) {
            transaction.commit().await?;
            return Ok(AnonymousSessionWriteOutcome::CapacityExceeded);
        }
        sqlx::query(
            "INSERT INTO xshield.auth_bindings (
                tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
                authorization_context_ref, auth_epoch, credential_generation, status,
                absolute_expires_at, updated_at
             ) VALUES ($1, $2, $3, $4, NULL, NULL, 0, 0, 'anonymous',
                       to_timestamp($5), to_timestamp($6))",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.session.site_id().as_str())
        .bind(command.binding_id.as_str())
        .bind(command.session_fingerprint.as_slice())
        .bind(absolute_expires_at)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO xshield.audit_outbox (
                event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
             ) VALUES ($1, $2, $3, $4, 'session.created', $5)",
        )
        .bind(command.event_id.as_str())
        .bind(command.tenant_id.as_str())
        .bind(command.session.site_id().as_str())
        .bind(command.binding_id.as_str())
        .bind(command.event_envelope)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(AnonymousSessionWriteOutcome::Created)
    }

    /// Atomically creates one authenticated binding, its credential generation,
    /// and the corresponding outbox event.
    ///
    /// # Errors
    /// Returns [`StoreError`] when numeric bounds, uniqueness, or database
    /// durability prevents the complete transaction from committing.
    pub async fn establish_binding(
        &self,
        command: BindingEstablishment<'_>,
    ) -> Result<(), StoreError> {
        let epoch = to_i64(command.binding.epoch().value(), "auth_epoch")?;
        let generation = to_i64(
            command.binding.generation().value(),
            "credential_generation",
        )?;
        let now = to_i64(command.now.value(), "now")?;
        let absolute_expires_at = to_i64(
            command.binding.absolute_expires_at().value(),
            "absolute_expires_at",
        )?;
        let credentials_expire_at = to_i64(
            command.credentials_expire_at.value(),
            "credentials_expire_at",
        )?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO xshield.auth_bindings (
                tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
                authorization_context_ref, auth_epoch, credential_generation, status,
                absolute_expires_at, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', to_timestamp($9), to_timestamp($10))",
        )
        .bind(command.binding.tenant_id().as_str())
        .bind(command.binding.site_id().as_str())
        .bind(command.binding.binding_id().as_str())
        .bind(command.session_fingerprint.as_slice())
        .bind(command.binding.principal_ref())
        .bind(command.binding.authorization_context_ref().as_str())
        .bind(epoch)
        .bind(generation)
        .bind(absolute_expires_at)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        for (slot, fingerprint) in command.binding.credentials() {
            sqlx::query(
                "INSERT INTO xshield.credential_bindings (
                    tenant_id, site_id, binding_id, generation, credential_kind,
                    fingerprint, expires_at, status
                 ) VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), 'active')",
            )
            .bind(command.binding.tenant_id().as_str())
            .bind(command.binding.site_id().as_str())
            .bind(command.binding.binding_id().as_str())
            .bind(generation)
            .bind(slot.as_str())
            .bind(fingerprint.as_bytes().as_slice())
            .bind(credentials_expire_at)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO xshield.audit_outbox (
                event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
             ) VALUES ($1, $2, $3, $4, 'binding.created', $5)",
        )
        .bind(command.event_id.as_str())
        .bind(command.binding.tenant_id().as_str())
        .bind(command.binding.site_id().as_str())
        .bind(command.binding.binding_id().as_str())
        .bind(command.event_envelope)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Atomically advances a same-context credential generation and writes its outbox event.
    ///
    /// The SQL predicate compares tenant, site, binding, principal, epoch,
    /// generation, active status, and both server-side expiry bounds. A zero-row
    /// update is a deterministic conflict rather than an automatic retry.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid numeric bounds or a database failure.
    pub async fn refresh_same_context(
        &self,
        command: CredentialTransition<'_>,
    ) -> Result<RefreshOutcome, StoreError> {
        let expected_generation = to_i64(
            command.snapshot.generation().value(),
            "credential_generation",
        )?;
        let current_generation = expected_generation
            .checked_add(1)
            .ok_or(StoreError::NumericRange("credential_generation"))?;
        let epoch = to_i64(command.snapshot.epoch().value(), "auth_epoch")?;
        let now = to_i64(command.now.value(), "now")?;
        let credentials_expire_at = to_i64(
            command.credentials_expire_at.value(),
            "credentials_expire_at",
        )?;
        let mut transaction = self.pool.begin().await?;

        let updated = sqlx::query(
            "UPDATE xshield.auth_bindings
             SET credential_generation = $1, updated_at = to_timestamp($2)
             WHERE tenant_id = $3 AND site_id = $4 AND binding_id = $5
               AND principal_ref = $6 AND auth_epoch = $7
               AND authorization_context_ref = $8
               AND credential_generation = $9 AND status = 'active'
               AND absolute_expires_at > GREATEST(to_timestamp($2), clock_timestamp())
               AND absolute_expires_at >= to_timestamp($10)
               AND to_timestamp($10) > clock_timestamp()",
        )
        .bind(current_generation)
        .bind(now)
        .bind(command.snapshot.tenant_id().as_str())
        .bind(command.snapshot.site_id().as_str())
        .bind(command.snapshot.binding_id().as_str())
        .bind(command.snapshot.principal_ref())
        .bind(epoch)
        .bind(command.snapshot.authorization_context_ref().as_str())
        .bind(expected_generation)
        .bind(credentials_expire_at)
        .execute(&mut *transaction)
        .await?;

        if updated.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(RefreshOutcome::Conflict);
        }

        if !replace_credentials(
            &mut transaction,
            CredentialReplacement {
                snapshot: command.snapshot,
                previous_credentials: command.previous_credentials,
                credentials: command.credentials,
                expected_generation,
                current_generation,
                credentials_expire_at,
                now,
                event_id: command.event_id,
                event_type: "identity.refreshed",
                event_envelope: command.event_envelope,
            },
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(RefreshOutcome::Conflict);
        }

        transaction.commit().await?;
        Ok(RefreshOutcome::Updated {
            previous_generation: CredentialGeneration::new(
                u64::try_from(expected_generation)
                    .map_err(|_| StoreError::NumericRange("credential_generation"))?,
            ),
            current_generation: CredentialGeneration::new(
                u64::try_from(current_generation)
                    .map_err(|_| StoreError::NumericRange("credential_generation"))?,
            ),
        })
    }

    /// Atomically changes the principal, epoch, and credential generation.
    ///
    /// The old request snapshot and complete active credential set are checked
    /// under row locks. Advancing the epoch makes prior grants immediately
    /// ineligible; physical grant cleanup may happen independently.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid numeric bounds or a database failure.
    pub async fn switch_identity_context(
        &self,
        command: IdentityContextSwitch<'_>,
    ) -> Result<ContextSwitchOutcome, StoreError> {
        let transition = command.transition;
        let previous_epoch = to_i64(transition.snapshot.epoch().value(), "auth_epoch")?;
        let current_epoch = previous_epoch
            .checked_add(1)
            .ok_or(StoreError::NumericRange("auth_epoch"))?;
        let previous_generation = to_i64(
            transition.snapshot.generation().value(),
            "credential_generation",
        )?;
        let current_generation = previous_generation
            .checked_add(1)
            .ok_or(StoreError::NumericRange("credential_generation"))?;
        let now = to_i64(transition.now.value(), "now")?;
        let credentials_expire_at = to_i64(
            transition.credentials_expire_at.value(),
            "credentials_expire_at",
        )?;
        let mut transaction = self.pool.begin().await?;
        let updated = sqlx::query(
            "UPDATE xshield.auth_bindings
             SET principal_ref = $1, authorization_context_ref = $2,
                 auth_epoch = $3, credential_generation = $4,
                 updated_at = to_timestamp($5)
             WHERE tenant_id = $6 AND site_id = $7 AND binding_id = $8
               AND principal_ref = $9 AND authorization_context_ref = $10
               AND auth_epoch = $11 AND credential_generation = $12
               AND status = 'active'
               AND absolute_expires_at > GREATEST(to_timestamp($5), clock_timestamp())
               AND absolute_expires_at >= to_timestamp($13)
               AND to_timestamp($13) > clock_timestamp()",
        )
        .bind(command.principal_ref)
        .bind(command.authorization_context_ref.as_str())
        .bind(current_epoch)
        .bind(current_generation)
        .bind(now)
        .bind(transition.snapshot.tenant_id().as_str())
        .bind(transition.snapshot.site_id().as_str())
        .bind(transition.snapshot.binding_id().as_str())
        .bind(transition.snapshot.principal_ref())
        .bind(transition.snapshot.authorization_context_ref().as_str())
        .bind(previous_epoch)
        .bind(previous_generation)
        .bind(credentials_expire_at)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(ContextSwitchOutcome::Conflict);
        }
        if !replace_credentials(
            &mut transaction,
            CredentialReplacement {
                snapshot: transition.snapshot,
                previous_credentials: transition.previous_credentials,
                credentials: transition.credentials,
                expected_generation: previous_generation,
                current_generation,
                credentials_expire_at,
                now,
                event_id: transition.event_id,
                event_type: "epoch.changed",
                event_envelope: transition.event_envelope,
            },
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(ContextSwitchOutcome::Conflict);
        }
        transaction.commit().await?;
        Ok(ContextSwitchOutcome::Updated {
            previous_epoch: AuthEpoch::new(
                u64::try_from(previous_epoch)
                    .map_err(|_| StoreError::NumericRange("auth_epoch"))?,
            ),
            current_epoch: AuthEpoch::new(
                u64::try_from(current_epoch).map_err(|_| StoreError::NumericRange("auth_epoch"))?,
            ),
            previous_generation: CredentialGeneration::new(
                u64::try_from(previous_generation)
                    .map_err(|_| StoreError::NumericRange("credential_generation"))?,
            ),
            current_generation: CredentialGeneration::new(
                u64::try_from(current_generation)
                    .map_err(|_| StoreError::NumericRange("credential_generation"))?,
            ),
        })
    }

    /// Atomically revokes one active binding and all of its live credentials.
    ///
    /// The binding row is locked using the complete tenant/site, binding,
    /// principal, authorization-context, and epoch snapshot. Current
    /// active/transition credentials are then locked before both their status
    /// and the binding status are changed. The supplied complete v3
    /// `binding.revoked` envelope is inserted in the same transaction.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid numeric bounds, corrupt stored
    /// values, or a database/transaction failure. A failed insert or commit
    /// leaves the binding and credentials unchanged.
    pub async fn revoke_binding(
        &self,
        command: BindingRevocation<'_>,
    ) -> Result<BindingRevocationOutcome, StoreError> {
        let epoch = to_i64(command.snapshot.epoch().value(), "auth_epoch")?;
        let now = to_i64(command.now.value(), "now")?;
        let mut transaction = self.pool.begin().await?;

        let binding = sqlx::query(
            "SELECT binding_id
             FROM xshield.auth_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
               AND principal_ref = $4 AND authorization_context_ref = $5
               AND auth_epoch = $6 AND status = 'active'
               AND absolute_expires_at > GREATEST(to_timestamp($7), clock_timestamp())
               FOR UPDATE",
        )
        .bind(command.snapshot.tenant_id().as_str())
        .bind(command.snapshot.site_id().as_str())
        .bind(command.snapshot.binding_id().as_str())
        .bind(command.snapshot.principal_ref())
        .bind(command.snapshot.authorization_context_ref().as_str())
        .bind(epoch)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(_) = binding else {
            transaction.rollback().await?;
            return Ok(BindingRevocationOutcome::Conflict);
        };
        // Lock every still-usable credential before revoking it. This includes
        // transition rows from a previous rotation so no credential can remain
        // usable after the binding reaches its terminal state.
        sqlx::query(
            "SELECT credential_kind
             FROM xshield.credential_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
               AND status IN ('active', 'transition')
             FOR UPDATE",
        )
        .bind(command.snapshot.tenant_id().as_str())
        .bind(command.snapshot.site_id().as_str())
        .bind(command.snapshot.binding_id().as_str())
        .fetch_all(&mut *transaction)
        .await?;

        sqlx::query(
            "UPDATE xshield.credential_bindings
             SET status = 'revoked'
             WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
               AND status IN ('active', 'transition')",
        )
        .bind(command.snapshot.tenant_id().as_str())
        .bind(command.snapshot.site_id().as_str())
        .bind(command.snapshot.binding_id().as_str())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE xshield.auth_bindings
             SET status = 'revoked', updated_at = to_timestamp($1)
             WHERE tenant_id = $2 AND site_id = $3 AND binding_id = $4",
        )
        .bind(now)
        .bind(command.snapshot.tenant_id().as_str())
        .bind(command.snapshot.site_id().as_str())
        .bind(command.snapshot.binding_id().as_str())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO xshield.audit_outbox (
                event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
             ) VALUES ($1, $2, $3, $4, 'binding.revoked', $5)",
        )
        .bind(command.event_id.as_str())
        .bind(command.snapshot.tenant_id().as_str())
        .bind(command.snapshot.site_id().as_str())
        .bind(command.snapshot.binding_id().as_str())
        .bind(command.event_envelope)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(BindingRevocationOutcome::Revoked)
    }
}

#[allow(clippy::too_many_arguments)]
async fn consume_anonymous_rate(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &TenantId,
    site_id: &SiteId,
    scope_kind: &str,
    scope_fingerprint: &[u8; 32],
    cutoff: i64,
    now: i64,
    limit: u32,
) -> Result<bool, StoreError> {
    let used: i64 = sqlx::query_scalar(
        "INSERT INTO xshield.anonymous_session_rate_limits (
            tenant_id, site_id, scope_kind, scope_fingerprint,
            window_started_at, used, updated_at
         ) VALUES ($1, $2, $3, $4, to_timestamp($5), 1, to_timestamp($5))
         ON CONFLICT (tenant_id, site_id, scope_kind, scope_fingerprint)
         DO UPDATE SET
            window_started_at = CASE
                WHEN xshield.anonymous_session_rate_limits.window_started_at
                     <= to_timestamp($6)
                THEN excluded.window_started_at
                ELSE xshield.anonymous_session_rate_limits.window_started_at
            END,
            used = CASE
                WHEN xshield.anonymous_session_rate_limits.window_started_at
                     <= to_timestamp($6)
                THEN 1
                ELSE xshield.anonymous_session_rate_limits.used + 1
            END,
            updated_at = excluded.updated_at
         RETURNING used",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(scope_kind)
    .bind(scope_fingerprint.as_slice())
    .bind(now)
    .bind(cutoff)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(used <= i64::from(limit))
}

async fn consume_anonymous_rates(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AnonymousSessionEstablishment<'_>,
    cutoff: i64,
    cleanup_cutoff: i64,
    now: i64,
) -> Result<bool, StoreError> {
    sqlx::query(
        "DELETE FROM xshield.anonymous_session_rate_limits
         WHERE tenant_id = $1 AND site_id = $2
           AND window_started_at <= to_timestamp($3)",
    )
    .bind(command.tenant_id.as_str())
    .bind(command.session.site_id().as_str())
    .bind(cleanup_cutoff)
    .execute(&mut **transaction)
    .await?;
    if !consume_anonymous_rate(
        transaction,
        command.tenant_id,
        command.session.site_id(),
        "source",
        command.source_fingerprint,
        cutoff,
        now,
        command.max_creations_per_source,
    )
    .await?
    {
        return Ok(false);
    }
    consume_anonymous_rate(
        transaction,
        command.tenant_id,
        command.session.site_id(),
        "site",
        &[0; 32],
        cutoff,
        now,
        command.max_creations_per_site,
    )
    .await
}

struct CredentialReplacement<'a> {
    snapshot: &'a AuthSnapshot,
    previous_credentials: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
    credentials: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
    expected_generation: i64,
    current_generation: i64,
    credentials_expire_at: i64,
    now: i64,
    event_id: &'a EventId,
    event_type: &'static str,
    event_envelope: &'a Value,
}

async fn replace_credentials(
    transaction: &mut Transaction<'_, Postgres>,
    replacement: CredentialReplacement<'_>,
) -> Result<bool, StoreError> {
    let stored_credentials = lock_active_credentials(
        transaction,
        replacement.snapshot,
        replacement.expected_generation,
        replacement.now,
    )
    .await?;
    if &stored_credentials != replacement.previous_credentials {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE xshield.credential_bindings
         SET status = 'revoked'
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
           AND generation = $4 AND status IN ('active', 'transition')",
    )
    .bind(replacement.snapshot.tenant_id().as_str())
    .bind(replacement.snapshot.site_id().as_str())
    .bind(replacement.snapshot.binding_id().as_str())
    .bind(replacement.expected_generation)
    .execute(&mut **transaction)
    .await?;
    for (slot, fingerprint) in replacement.credentials {
        sqlx::query(
            "INSERT INTO xshield.credential_bindings (
                tenant_id, site_id, binding_id, generation, credential_kind,
                fingerprint, predecessor_generation, expires_at, status
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8), 'active')",
        )
        .bind(replacement.snapshot.tenant_id().as_str())
        .bind(replacement.snapshot.site_id().as_str())
        .bind(replacement.snapshot.binding_id().as_str())
        .bind(replacement.current_generation)
        .bind(slot.as_str())
        .bind(fingerprint.as_bytes().as_slice())
        .bind(replacement.expected_generation)
        .bind(replacement.credentials_expire_at)
        .execute(&mut **transaction)
        .await?;
    }
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(replacement.event_id.as_str())
    .bind(replacement.snapshot.tenant_id().as_str())
    .bind(replacement.snapshot.site_id().as_str())
    .bind(replacement.snapshot.binding_id().as_str())
    .bind(replacement.event_type)
    .bind(replacement.event_envelope)
    .execute(&mut **transaction)
    .await?;
    Ok(true)
}

// Recheck frozen leases after lock/constraint waits. Callers roll back their
// transaction when this gate fails so expiry cannot commit new authority.
async fn lease_is_live(connection: &mut PgConnection, expires_at: i64) -> Result<bool, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT to_timestamp($1) > clock_timestamp()")
            .bind(expires_at)
            .fetch_one(connection)
            .await?,
    )
}

async fn lock_active_credentials(
    transaction: &mut Transaction<'_, Postgres>,
    snapshot: &AuthSnapshot,
    generation: i64,
    now: i64,
) -> Result<BTreeMap<CredentialSlot, CredentialFingerprint>, StoreError> {
    let rows = sqlx::query(
        "SELECT credential_kind, fingerprint
         FROM xshield.credential_bindings
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
           AND generation = $4 AND status = 'active'
           AND expires_at > GREATEST(to_timestamp($5), clock_timestamp())
         FOR UPDATE",
    )
    .bind(snapshot.tenant_id().as_str())
    .bind(snapshot.site_id().as_str())
    .bind(snapshot.binding_id().as_str())
    .bind(generation)
    .bind(now)
    .fetch_all(&mut **transaction)
    .await?;
    let mut credentials = BTreeMap::new();
    for row in rows {
        let slot = match row.try_get::<&str, _>("credential_kind")? {
            "cookie" => CredentialSlot::Cookie,
            "bearer" => CredentialSlot::Bearer,
            "body_token" => CredentialSlot::BodyToken,
            _ => return Err(StoreError::CorruptData("credential_kind")),
        };
        let fingerprint = CredentialFingerprint::from_bytes(
            row.try_get::<Vec<u8>, _>("fingerprint")?
                .try_into()
                .map_err(|_| StoreError::CorruptData("credential_fingerprint"))?,
        );
        if credentials.insert(slot, fingerprint).is_some() {
            return Err(StoreError::CorruptData("duplicate_credential_kind"));
        }
    }
    Ok(credentials)
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::NumericRange(field))
}

/// `PostgreSQL` adapter failure with safe, non-secret context.
#[derive(Debug)]
pub enum StoreError {
    /// Pool configuration cannot serve requests.
    InvalidPoolConfig,
    /// Persistence command violates a local trust-boundary invariant.
    InvalidCommand,
    /// Unsigned domain value cannot fit the `PostgreSQL` signed integer column.
    NumericRange(&'static str),
    /// A stored value violates the adapter's domain contract.
    CorruptData(&'static str),
    /// The operating system could not obtain required cryptographic entropy.
    Entropy,
    /// `SQLx` connection, statement, or transaction failure.
    Database(sqlx::Error),
}

impl From<sqlx::Error> for StoreError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPoolConfig => formatter.write_str("invalid PostgreSQL pool configuration"),
            Self::InvalidCommand => formatter.write_str("invalid persistence command"),
            Self::NumericRange(field) => write!(formatter, "{field} exceeds PostgreSQL range"),
            Self::CorruptData(field) => write!(formatter, "invalid stored {field}"),
            Self::Entropy => formatter.write_str("cryptographic entropy unavailable"),
            Self::Database(_) => formatter.write_str("PostgreSQL operation failed"),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::InvalidPoolConfig
            | Self::InvalidCommand
            | Self::NumericRange(_)
            | Self::CorruptData(_)
            | Self::Entropy => None,
        }
    }
}
