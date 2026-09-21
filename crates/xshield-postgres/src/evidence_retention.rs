use crate::{
    CatalogArtifact, PostgresIdentityStore, StoreError, evidence_catalog::catalog_artifact,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
use xshield_core::domain::{EventId, SiteId, TenantId};
use xshield_evidence::EvidencePurgeOutcome;

/// Exact catalog snapshot backed by a committed deletion-intent event.
pub struct EvidencePurgeJob {
    artifact: CatalogArtifact,
    intent_event_id: EventId,
}

impl EvidencePurgeJob {
    /// Returns the expected manifest; the vault must authenticate and match it.
    #[must_use]
    pub const fn artifact(&self) -> &CatalogArtifact {
        &self.artifact
    }
}

/// Terminal result of one deletion attempt; failures retain the retryable intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidencePurgeResult {
    /// Directory-synced ciphertext removal (including recovery of a prior removal).
    Deleted(EvidencePurgeOutcome),
    /// Manifest, scope, permissions, expiry or digest validation failed.
    Rejected,
    /// Storage or cryptographic operations could not complete.
    Unavailable,
}

impl EvidencePurgeResult {
    /// Stable reason for the terminal audit event; carries no evidence content.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Deleted(EvidencePurgeOutcome::Removed) => "EVIDENCE_DELETED",
            Self::Deleted(EvidencePurgeOutcome::AlreadyAbsent) => "EVIDENCE_DELETE_ALREADY_ABSENT",
            Self::Rejected => "EVIDENCE_PURGE_REJECTED",
            Self::Unavailable => "EVIDENCE_PURGE_UNAVAILABLE",
        }
    }
}

impl PostgresIdentityStore {
    /// Commits deletion intent for up to 32 expired artifacts in one exact scope/key.
    ///
    /// Uses the database clock, row locks and atomic outbox publication. Retries
    /// reuse the original intent. Callers hold the exclusive local vault lock
    /// through preparation, physical removal and completion. Pending/approved
    /// content-access requests do not extend the immutable evidence deadline.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid bounds, corrupt state or database
    /// failures. Statements/lock waits are capped at five seconds. No job is
    /// returned before commit; an uncertain commit is safe to retry.
    #[allow(clippy::too_many_lines)]
    pub async fn prepare_evidence_purge(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        key_id: &str,
        limit: u16,
    ) -> Result<Vec<EvidencePurgeJob>, StoreError> {
        if !(1..=32).contains(&limit)
            || key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(StoreError::InvalidCommand);
        }
        let mut tx = self.retention_transaction().await?;
        let rows = sqlx::query(
            "SELECT * FROM xshield.artifact_catalog
             WHERE tenant_id = $1 AND site_id = $2 AND key_ref = $3
               AND status = 'active' AND expires_at <= clock_timestamp()
               AND NOT EXISTS (
                   SELECT 1
                   FROM xshield.calibration_evidence_release_reservations reservation
                   WHERE reservation.tenant_id = artifact_catalog.tenant_id
                     AND reservation.site_id = artifact_catalog.site_id
                     AND reservation.artifact_id = artifact_catalog.artifact_id
                     AND reservation.reserved_until > clock_timestamp()
               )
               AND (purge_requested_event_id IS NOT NULL OR NOT EXISTS (
                   SELECT 1 FROM xshield.case_evidence_holds hold
                   WHERE hold.tenant_id = artifact_catalog.tenant_id
                     AND hold.site_id = artifact_catalog.site_id
                     AND hold.artifact_id = artifact_catalog.artifact_id
                     AND hold.released_at IS NULL
                     AND hold.hold_until > clock_timestamp()
               ))
             ORDER BY expires_at, artifact_id LIMIT $4 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(key_id)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await?;
        let mut jobs = Vec::with_capacity(rows.len());
        for row in rows {
            let artifact = catalog_artifact(&row)?;
            // The catalog row is already locked. Recheck the hold in this
            // statement snapshot after that lock to avoid a stale pre-lock
            // NOT EXISTS decision under READ COMMITTED.
            let held: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                     SELECT 1 FROM xshield.case_evidence_holds
                     WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3
                       AND released_at IS NULL AND hold_until > clock_timestamp()
                 )",
            )
            .bind(tenant.as_str())
            .bind(site.as_str())
            .bind(artifact.artifact_id().as_str())
            .fetch_one(&mut *tx)
            .await?;
            // A durable intent already excludes future holds. After a crash,
            // retry it even if clock rollback makes an old expired hold active.
            if held
                && row
                    .try_get::<Option<&str>, _>("purge_requested_event_id")?
                    .is_none()
            {
                continue;
            }
            let intent_event_id =
                if let Some(id) = row.try_get::<Option<String>, _>("purge_requested_event_id")? {
                    let id = EventId::parse(id)
                        .map_err(|_| StoreError::CorruptData("purge_intent_id"))?;
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM xshield.audit_outbox
                     WHERE event_id = $1 AND tenant_id = $2 AND site_id = $3
                       AND aggregate_ref = $4 AND event_type = 'evidence.purge_requested'
                       AND envelope->'payload'->>'reason_code' = 'EVIDENCE_PURGE_REQUESTED')",
                    )
                    .bind(id.as_str())
                    .bind(tenant.as_str())
                    .bind(site.as_str())
                    .bind(artifact.artifact_id().as_str())
                    .fetch_one(&mut *tx)
                    .await?;
                    if !exists {
                        return Err(StoreError::CorruptData("purge_intent_audit"));
                    }
                    id
                } else {
                    let id = retention_event(
                        &mut tx,
                        &artifact,
                        "evidence.purge_requested",
                        "EVIDENCE_PURGE_REQUESTED",
                        "PASS",
                        None,
                    )
                    .await?;
                    sqlx::query(
                        "UPDATE xshield.artifact_catalog SET purge_requested_event_id = $4
                    WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3",
                    )
                    .bind(tenant.as_str())
                    .bind(site.as_str())
                    .bind(artifact.artifact_id().as_str())
                    .bind(id.as_str())
                    .execute(&mut *tx)
                    .await?;
                    id
                };
            jobs.push(EvidencePurgeJob {
                artifact,
                intent_event_id,
            });
        }
        tx.commit().await?;
        Ok(jobs)
    }

    /// Atomically records an attempt result and, on success, a catalog tombstone.
    ///
    /// The exact prepared manifest/intent is rechecked under a row lock. Successful
    /// retries are idempotent; failed attempts emit a terminal event and remain
    /// eligible for a later maintenance pass. Physical removal must already be
    /// directory-synced before a successful result is supplied.
    ///
    /// # Errors
    /// Returns [`StoreError`] for changed state, expired-clock mismatch or database
    /// failures. A completion failure leaves a recoverable committed intent.
    pub async fn finish_evidence_purge(
        &self,
        job: &EvidencePurgeJob,
        result: EvidencePurgeResult,
    ) -> Result<(), StoreError> {
        let manifest = job.artifact.manifest();
        let mut tx = self.retention_transaction().await?;
        let row = sqlx::query(
            "SELECT *, expires_at <= clock_timestamp() AS expired
            FROM xshield.artifact_catalog
            WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3 FOR UPDATE",
        )
        .bind(&manifest.tenant_id)
        .bind(&manifest.site_id)
        .bind(&manifest.artifact_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::InvalidCommand)?;
        if catalog_artifact(&row)? != job.artifact
            || row.try_get::<Option<&str>, _>("purge_requested_event_id")?
                != Some(job.intent_event_id.as_str())
        {
            return Err(StoreError::CorruptData("purge_snapshot"));
        }
        if row.try_get::<&str, _>("status")? == "deleted"
            && row
                .try_get::<Option<&str>, _>("purge_completed_event_id")?
                .is_some()
        {
            tx.commit().await?;
            return Ok(());
        }
        if row.try_get::<&str, _>("status")? != "active" || !row.try_get::<bool, _>("expired")? {
            return Err(StoreError::InvalidCommand);
        }
        let success = matches!(result, EvidencePurgeResult::Deleted(_));
        let event = retention_event(
            &mut tx,
            &job.artifact,
            if success {
                "evidence.deleted"
            } else {
                "evidence.purge_failed"
            },
            result.reason_code(),
            if success { "PASS" } else { "ERROR" },
            Some(&job.intent_event_id),
        )
        .await?;
        if success {
            sqlx::query(
                "UPDATE xshield.artifact_catalog SET status = 'deleted',
                deleted_at = clock_timestamp(), purge_completed_event_id = $4
                WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3",
            )
            .bind(&manifest.tenant_id)
            .bind(&manifest.site_id)
            .bind(&manifest.artifact_id)
            .bind(event.as_str())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn retention_transaction(
        &self,
    ) -> Result<Transaction<'_, Postgres>, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
}

async fn retention_event(
    tx: &mut Transaction<'_, Postgres>,
    artifact: &CatalogArtifact,
    event_type: &str,
    reason: &str,
    outcome: &str,
    cause: Option<&EventId>,
) -> Result<EventId, StoreError> {
    let manifest = artifact.manifest();
    let event_id =
        EventId::parse(format!("ev_{}", Uuid::now_v7())).map_err(|_| StoreError::InvalidCommand)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let now = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace = Uuid::now_v7().simple().to_string();
    let envelope = json!({
        "schema_version":3, "event_id":event_id.as_str(), "event_type":event_type,
        "tenant_id":manifest.tenant_id, "site_id":manifest.site_id,
        "request_id":null, "trace_id":trace, "span_id":&trace[..16],
        "producer_id":"evidence-retention", "producer_boot_id":Uuid::now_v7().to_string(),
        "producer_seq":1, "request_seq":1, "occurred_at":now, "observed_at":now,
        "policy_revision":"evidence-retention-v1", "example_only":false,
        "evidence_refs":[manifest.artifact_id], "cause_event_ids":cause.map(EventId::as_str).into_iter().collect::<Vec<_>>(),
        "payload":{"stage":"evidence_retention", "outcome":outcome, "reason_code":reason,
            "proof_kind":"deterministic", "confidence":null, "confidence_status":"not_applicable",
            "artifact_id":manifest.artifact_id, "source_request_id":manifest.request_id,
            "expires_at":manifest.expires_at, "retained_metadata":true},
        "sensitivity":"RESTRICTED", "integrity":{"state":"pending", "previous_hash":null, "event_hash":null}
    });
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
        VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(event_id.as_str()).bind(&manifest.tenant_id).bind(&manifest.site_id)
        .bind(&manifest.artifact_id).bind(event_type).bind(envelope).execute(&mut **tx).await?;
    Ok(event_id)
}
