use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
use xshield_core::domain::{ArtifactId, EventId, SiteId, TenantId};
use xshield_evidence::{EvidenceOrphanCandidate, EvidencePurgeOutcome};

const ORPHAN_EVENT_TYPE: &str = "evidence.orphan.purge_requested";

/// Durable local orphan deletion intent and its exact filesystem observation.
pub struct EvidenceOrphanPurgeJob {
    tenant_id: TenantId,
    site_id: SiteId,
    artifact_id: ArtifactId,
    intent_event_id: EventId,
    candidate: EvidenceOrphanCandidate,
}

impl EvidenceOrphanPurgeJob {
    /// Returns the exact tenant scope of this maintenance observation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the exact site scope of this maintenance observation.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the opaque artifact identity.
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Returns the candidate required for filesystem revalidation.
    #[must_use]
    pub const fn candidate(&self) -> &EvidenceOrphanCandidate {
        &self.candidate
    }

    /// Returns the durable intent event identity.
    #[must_use]
    pub const fn intent_event_id(&self) -> &EventId {
        &self.intent_event_id
    }
}

/// Result recorded for one orphan deletion attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceOrphanPurgeResult {
    /// Ciphertext was removed or already absent after authenticated observation.
    Deleted(EvidencePurgeOutcome),
    /// The object changed or had unsafe/incomplete sidecars and remains retained.
    Rejected,
    /// Storage or cryptographic infrastructure failed; the intent remains pending.
    Unavailable,
}

impl EvidenceOrphanPurgeResult {
    /// Stable audit reason for this terminal attempt.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Deleted(EvidencePurgeOutcome::Removed) => "EVIDENCE_ORPHAN_DELETED",
            Self::Deleted(EvidencePurgeOutcome::AlreadyAbsent) => {
                "EVIDENCE_ORPHAN_DELETE_ALREADY_ABSENT"
            }
            Self::Rejected => "EVIDENCE_ORPHAN_PURGE_REJECTED",
            Self::Unavailable => "EVIDENCE_ORPHAN_PURGE_UNAVAILABLE",
        }
    }
}

impl PostgresIdentityStore {
    /// Creates or reuses deletion intents for bounded local orphan observations.
    ///
    /// Catalog rows always win: a candidate whose artifact identity is already
    /// cataloged in any scope is omitted. A pending intent reuses its event and
    /// observation; a completed intent is never reused for a reappeared path.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid scope, changed durable observations,
    /// corrupt intent events, or database failure.
    #[allow(clippy::too_many_lines)]
    pub async fn prepare_evidence_orphan_purge(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        candidates: &[EvidenceOrphanCandidate],
    ) -> Result<Vec<EvidenceOrphanPurgeJob>, StoreError> {
        if candidates.is_empty() || candidates.len() > 32 {
            return Err(StoreError::InvalidCommand);
        }
        let mut tx = self.retention_transaction().await?;
        let mut jobs = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let artifact_id = ArtifactId::parse(candidate.artifact_id())
                .map_err(|_| StoreError::InvalidCommand)?;
            let cataloged: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM xshield.artifact_catalog
                 WHERE artifact_id = $1)",
            )
            .bind(artifact_id.as_str())
            .fetch_one(&mut *tx)
            .await?;
            if cataloged {
                continue;
            }
            let existing = sqlx::query(
                "SELECT requested_event_id, observed_bytes, observed_modified_seconds,
                        observed_modified_nanos, authenticated_manifest, status
                 FROM xshield.evidence_orphan_purges
                 WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3
                 FOR UPDATE",
            )
            .bind(tenant.as_str())
            .bind(site.as_str())
            .bind(artifact_id.as_str())
            .fetch_optional(&mut *tx)
            .await?;
            let intent_event_id = if let Some(row) = existing {
                if row.try_get::<&str, _>("status")? == "deleted"
                    || row.try_get::<i64, _>("observed_bytes")?
                        != i64::try_from(candidate.observed_bytes())
                            .map_err(|_| StoreError::NumericRange("orphan_observed_bytes"))?
                    || row.try_get::<bool, _>("authenticated_manifest")?
                        != candidate.authenticated_manifest()
                    || row.try_get::<i64, _>("observed_modified_seconds")?
                        != i64::try_from(candidate.observed_modified().0)
                            .map_err(|_| StoreError::NumericRange("orphan_modified_seconds"))?
                    || row.try_get::<i32, _>("observed_modified_nanos")?
                        != i32::try_from(candidate.observed_modified().1)
                            .map_err(|_| StoreError::NumericRange("orphan_modified_nanos"))?
                {
                    continue;
                }
                let intent =
                    EventId::parse(row.try_get::<&str, _>("requested_event_id")?.to_owned())
                        .map_err(|_| StoreError::CorruptData("orphan_intent_id"))?;
                let audited: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM xshield.audit_outbox
                     WHERE event_id = $1 AND tenant_id = $2 AND site_id = $3
                       AND aggregate_ref = $4
                       AND event_type = 'evidence.orphan.purge_requested'
                       AND envelope->'payload'->>'reason_code' =
                           'EVIDENCE_ORPHAN_PURGE_REQUESTED')",
                )
                .bind(intent.as_str())
                .bind(tenant.as_str())
                .bind(site.as_str())
                .bind(artifact_id.as_str())
                .fetch_one(&mut *tx)
                .await?;
                if !audited {
                    return Err(StoreError::CorruptData("orphan_intent_audit"));
                }
                intent
            } else {
                let intent = orphan_event(
                    &mut tx,
                    tenant,
                    site,
                    &artifact_id,
                    ORPHAN_EVENT_TYPE,
                    "EVIDENCE_ORPHAN_PURGE_REQUESTED",
                    "PASS",
                    None,
                    candidate.authenticated_manifest(),
                )
                .await?;
                let observed_bytes = i64::try_from(candidate.observed_bytes())
                    .map_err(|_| StoreError::NumericRange("orphan_observed_bytes"))?;
                sqlx::query(
                    "INSERT INTO xshield.evidence_orphan_purges (
                        tenant_id, site_id, artifact_id, storage_locator,
                        observed_bytes, observed_modified_seconds, observed_modified_nanos,
                        authenticated_manifest, requested_event_id,
                        status, requested_at
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', clock_timestamp())",
                )
                .bind(tenant.as_str())
                .bind(site.as_str())
                .bind(artifact_id.as_str())
                .bind(format!("{}.xev", artifact_id.as_str()))
                .bind(observed_bytes)
                .bind(
                    i64::try_from(candidate.observed_modified().0)
                        .map_err(|_| StoreError::NumericRange("orphan_modified_seconds"))?,
                )
                .bind(
                    i32::try_from(candidate.observed_modified().1)
                        .map_err(|_| StoreError::NumericRange("orphan_modified_nanos"))?,
                )
                .bind(candidate.authenticated_manifest())
                .bind(intent.as_str())
                .execute(&mut *tx)
                .await?;
                intent
            };
            jobs.push(EvidenceOrphanPurgeJob {
                tenant_id: tenant.clone(),
                site_id: site.clone(),
                artifact_id,
                intent_event_id,
                candidate: candidate.clone(),
            });
        }
        tx.commit().await?;
        Ok(jobs)
    }

    /// Returns pending intents so a crash after physical removal can converge.
    ///
    /// # Errors
    /// Returns [`StoreError`] for corrupt observations or database failure.
    pub async fn pending_evidence_orphan_purges(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        limit: u16,
    ) -> Result<Vec<EvidenceOrphanPurgeJob>, StoreError> {
        if !(1..=32).contains(&limit) {
            return Err(StoreError::InvalidCommand);
        }
        let mut tx = self.retention_transaction().await?;
        let rows = sqlx::query(
            "SELECT orphan.* FROM xshield.evidence_orphan_purges orphan
             WHERE orphan.tenant_id = $1 AND orphan.site_id = $2
               AND orphan.status = 'pending'
               AND NOT EXISTS (
                   SELECT 1 FROM xshield.artifact_catalog catalog
                   WHERE catalog.artifact_id = orphan.artifact_id
               )
             ORDER BY requested_at, artifact_id LIMIT $3",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await?;
        let mut jobs = Vec::with_capacity(rows.len());
        for row in rows {
            let requested_event_id = row.try_get::<&str, _>("requested_event_id")?;
            let audited: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM xshield.audit_outbox
                 WHERE event_id = $1 AND tenant_id = $2 AND site_id = $3
                   AND aggregate_ref = $4
                   AND event_type = 'evidence.orphan.purge_requested'
                   AND envelope->'payload'->>'reason_code' =
                       'EVIDENCE_ORPHAN_PURGE_REQUESTED')",
            )
            .bind(requested_event_id)
            .bind(tenant.as_str())
            .bind(site.as_str())
            .bind(row.try_get::<&str, _>("artifact_id")?)
            .fetch_one(&mut *tx)
            .await?;
            if !audited {
                return Err(StoreError::CorruptData("orphan_intent_audit"));
            }
            jobs.push(orphan_job_from_row(&row)?);
        }
        tx.commit().await?;
        Ok(jobs)
    }

    /// Records an orphan deletion attempt and terminal audit event.
    ///
    /// Physical deletion must be directory-synced before a successful result is
    /// passed. A failed completion leaves the durable intent pending and can be
    /// retried with the same candidate.
    ///
    /// # Errors
    /// Returns [`StoreError`] for changed observations, corrupt intent state or
    /// database failure.
    pub async fn finish_evidence_orphan_purge(
        &self,
        job: &EvidenceOrphanPurgeJob,
        result: EvidenceOrphanPurgeResult,
    ) -> Result<(), StoreError> {
        let mut tx = self.retention_transaction().await?;
        let row = sqlx::query(
            "SELECT * FROM xshield.evidence_orphan_purges
             WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3 FOR UPDATE",
        )
        .bind(job.tenant_id.as_str())
        .bind(job.site_id.as_str())
        .bind(job.artifact_id.as_str())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::InvalidCommand)?;
        if row.try_get::<&str, _>("requested_event_id")? != job.intent_event_id.as_str()
            || row.try_get::<i64, _>("observed_bytes")?
                != i64::try_from(job.candidate.observed_bytes())
                    .map_err(|_| StoreError::NumericRange("orphan_observed_bytes"))?
            || row.try_get::<bool, _>("authenticated_manifest")?
                != job.candidate.authenticated_manifest()
            || row.try_get::<i64, _>("observed_modified_seconds")?
                != i64::try_from(job.candidate.observed_modified().0)
                    .map_err(|_| StoreError::NumericRange("orphan_modified_seconds"))?
            || row.try_get::<i32, _>("observed_modified_nanos")?
                != i32::try_from(job.candidate.observed_modified().1)
                    .map_err(|_| StoreError::NumericRange("orphan_modified_nanos"))?
        {
            return Err(StoreError::CorruptData("orphan_purge_snapshot"));
        }
        if row.try_get::<&str, _>("status")? == "deleted" {
            tx.commit().await?;
            return Ok(());
        }
        let cataloged: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM xshield.artifact_catalog
             WHERE artifact_id = $1)",
        )
        .bind(job.artifact_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if cataloged {
            return Err(StoreError::InvalidCommand);
        }
        let success = matches!(result, EvidenceOrphanPurgeResult::Deleted(_));
        let event = orphan_event(
            &mut tx,
            &job.tenant_id,
            &job.site_id,
            &job.artifact_id,
            if success {
                "evidence.orphan.deleted"
            } else {
                "evidence.orphan.purge_failed"
            },
            result.reason_code(),
            if success { "PASS" } else { "ERROR" },
            Some(&job.intent_event_id),
            job.candidate.authenticated_manifest(),
        )
        .await?;
        if success {
            sqlx::query(
                "UPDATE xshield.evidence_orphan_purges
                 SET status = 'deleted', completed_event_id = $4, completed_at = clock_timestamp()
                 WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3",
            )
            .bind(job.tenant_id.as_str())
            .bind(job.site_id.as_str())
            .bind(job.artifact_id.as_str())
            .bind(event.as_str())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

fn orphan_job_from_row(row: &sqlx::postgres::PgRow) -> Result<EvidenceOrphanPurgeJob, StoreError> {
    let tenant_id = TenantId::parse(row.try_get::<&str, _>("tenant_id")?.to_owned())
        .map_err(|_| StoreError::CorruptData("orphan_tenant_id"))?;
    let site_id = SiteId::parse(row.try_get::<&str, _>("site_id")?.to_owned())
        .map_err(|_| StoreError::CorruptData("orphan_site_id"))?;
    let artifact_id = ArtifactId::parse(row.try_get::<&str, _>("artifact_id")?.to_owned())
        .map_err(|_| StoreError::CorruptData("orphan_artifact_id"))?;
    let candidate = EvidenceOrphanCandidate::from_observation(
        artifact_id.as_str(),
        row.try_get("authenticated_manifest")?,
        u64::try_from(row.try_get::<i64, _>("observed_bytes")?)
            .map_err(|_| StoreError::CorruptData("orphan_observed_bytes"))?,
        u64::try_from(row.try_get::<i64, _>("observed_modified_seconds")?)
            .map_err(|_| StoreError::CorruptData("orphan_modified_seconds"))?,
        u32::try_from(row.try_get::<i32, _>("observed_modified_nanos")?)
            .map_err(|_| StoreError::CorruptData("orphan_modified_nanos"))?,
    )
    .map_err(|_| StoreError::CorruptData("orphan_observation"))?;
    let intent_event_id = EventId::parse(row.try_get::<&str, _>("requested_event_id")?.to_owned())
        .map_err(|_| StoreError::CorruptData("orphan_intent_id"))?;
    Ok(EvidenceOrphanPurgeJob {
        tenant_id,
        site_id,
        artifact_id,
        intent_event_id,
        candidate,
    })
}

#[allow(clippy::too_many_arguments)]
async fn orphan_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    site: &SiteId,
    artifact: &ArtifactId,
    event_type: &str,
    reason: &str,
    outcome: &str,
    cause: Option<&EventId>,
    authenticated_manifest: bool,
) -> Result<EventId, StoreError> {
    let event_id =
        EventId::parse(format!("ev_{}", Uuid::now_v7())).map_err(|_| StoreError::InvalidCommand)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let now = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace = Uuid::now_v7().simple().to_string();
    let envelope = json!({
        "schema_version": 3, "event_id": event_id.as_str(), "event_type": event_type,
        "tenant_id": tenant.as_str(), "site_id": site.as_str(), "request_id": null,
        "trace_id": trace, "span_id": &trace[..16], "producer_id": "evidence-retention",
        "producer_boot_id": Uuid::now_v7().to_string(), "producer_seq": 1, "request_seq": 1,
        "occurred_at": now, "observed_at": now, "policy_revision": "evidence-retention-v1",
        "example_only": false, "evidence_refs": [artifact.as_str()],
        "cause_event_ids": cause.map(EventId::as_str).into_iter().collect::<Vec<_>>(),
        "payload": {"stage": "evidence_orphan_retention", "outcome": outcome,
            "reason_code": reason, "proof_kind": "deterministic", "confidence": null,
            "confidence_status": "not_applicable", "artifact_id": artifact.as_str(),
            "authenticated_manifest": authenticated_manifest},
        "sensitivity": "RESTRICTED",
        "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
    });
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(event_id.as_str())
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(artifact.as_str())
    .bind(event_type)
    .bind(envelope)
    .execute(&mut **tx)
    .await?;
    Ok(event_id)
}
