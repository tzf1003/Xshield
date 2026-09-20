//! Atomic evidence-access decisions and short-lived capability metadata.

use crate::evidence_catalog::{CatalogArtifact, catalog_artifact};
use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::Value;
use sqlx::{PgConnection, Postgres, Row, Transaction};
use xshield_core::{
    domain::{ArtifactId, CaseId, EventId, EvidenceAccessRequestId, RequestId},
    investigation::{EvidenceAccessDecisionDraft, EvidenceAccessDecisionKind},
};

/// A validated approval or denial ready for an atomic transaction.
pub struct EvidenceAccessDecisionCreate<'a> {
    draft: &'a EvidenceAccessDecisionDraft,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> EvidenceAccessDecisionCreate<'a> {
    /// Binds one terminal decision and outbox event to the same scope and actor.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for a mismatched event identity,
    /// scope, target, actor, digest, decision, or terminal reason.
    pub fn new(
        draft: &'a EvidenceAccessDecisionDraft,
        idempotency_digest: &'a [u8; 32],
        request_digest: &'a [u8; 32],
        request_id: &'a RequestId,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        if !decision_event_matches(draft, request_digest, request_id, event_id, event_envelope) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            draft,
            idempotency_digest,
            request_digest,
            event_id,
            event_envelope,
        })
    }
}

/// Durable decision metadata returned for first writes and exact retries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceAccessDecisionRecord {
    access_request_id: EvidenceAccessRequestId,
    case_id: CaseId,
    artifact_id: ArtifactId,
    requested_by: String,
    decided_by: String,
    status: &'static str,
    decided_at: DateTime<Utc>,
    access_expires_at: Option<DateTime<Utc>>,
}

/// An approved, still-valid capability bound to one reader subject and object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceAccessCapability {
    access_request_id: EvidenceAccessRequestId,
    case_id: CaseId,
    artifact: CatalogArtifact,
    requested_by: String,
    access_expires_at: DateTime<Utc>,
}

impl EvidenceAccessCapability {
    /// Returns the approved request identity.
    #[must_use]
    pub const fn access_request_id(&self) -> &EvidenceAccessRequestId {
        &self.access_request_id
    }

    /// Returns the open investigation case bound to the capability.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the authenticated catalog artifact metadata.
    #[must_use]
    pub const fn artifact(&self) -> &CatalogArtifact {
        &self.artifact
    }

    /// Returns the subject allowed to consume the capability.
    #[must_use]
    pub fn requested_by(&self) -> &str {
        &self.requested_by
    }

    /// Returns the exclusive capability expiry from the database clock.
    #[must_use]
    pub const fn access_expires_at(&self) -> DateTime<Utc> {
        self.access_expires_at
    }
}

impl EvidenceAccessDecisionRecord {
    /// Returns the decided request identity.
    #[must_use]
    pub const fn access_request_id(&self) -> &EvidenceAccessRequestId {
        &self.access_request_id
    }

    /// Returns the owning investigation case.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the scoped evidence object.
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Returns the subject receiving an approved capability.
    #[must_use]
    pub fn requested_by(&self) -> &str {
        &self.requested_by
    }

    /// Returns the independent decision subject.
    #[must_use]
    pub fn decided_by(&self) -> &str {
        &self.decided_by
    }

    /// Returns the current terminal status.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        self.status
    }

    /// Returns the database decision time.
    #[must_use]
    pub const fn decided_at(&self) -> DateTime<Utc> {
        self.decided_at
    }

    /// Returns the effective approved lease, clamped to artifact expiry.
    #[must_use]
    pub const fn access_expires_at(&self) -> Option<DateTime<Utc>> {
        self.access_expires_at
    }
}

/// Deterministic result of one idempotent access decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceAccessDecisionWriteOutcome {
    /// The decision and outbox event committed atomically.
    Created(EvidenceAccessDecisionRecord),
    /// The exact decision was already committed.
    Existing(EvidenceAccessDecisionRecord),
    /// The key or target is already bound to a different decision.
    Conflict,
    /// The request or an approval target is unavailable.
    TargetUnavailable,
    /// The requesting subject attempted to decide their own request.
    SelfApprovalDenied,
}

impl PostgresIdentityStore {
    /// Loads one approved capability while rechecking its complete live scope.
    ///
    /// The query binds the authenticated reader, access request, artifact,
    /// tenant, and site. `PostgreSQL`'s clock, open case, active catalog row,
    /// artifact expiry, and capability expiry are checked together before the
    /// vault is allowed to authenticate and decrypt the object. The read/write
    /// transaction holds shared locks through a fresh database clock check and
    /// changes no business data. Statements and lock waits are limited to 5
    /// seconds; callers must bound the overall operation.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt catalog state.
    pub async fn find_evidence_access_capability(
        &self,
        tenant_id: &xshield_core::domain::TenantId,
        site_id: &xshield_core::domain::SiteId,
        access_request_id: &EvidenceAccessRequestId,
        artifact_id: &ArtifactId,
        requested_by: &str,
    ) -> Result<Option<EvidenceAccessCapability>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        let row = sqlx::query(
            "SELECT access_request.access_request_id AS capability_access_request_id,
                    access_request.case_id AS capability_case_id,
                    access_request.requested_by AS capability_requested_by,
                    access_request.access_expires_at AS capability_expires_at,
                    artifact.*
             FROM xshield.evidence_access_requests access_request
             JOIN xshield.investigation_cases case_record
               ON case_record.tenant_id = access_request.tenant_id
              AND case_record.site_id = access_request.site_id
              AND case_record.case_id = access_request.case_id
              AND case_record.owner_ref = access_request.requested_by
              AND case_record.status = 'open'
             JOIN xshield.artifact_catalog artifact
               ON artifact.tenant_id = access_request.tenant_id
              AND artifact.site_id = access_request.site_id
              AND artifact.artifact_id = access_request.artifact_id
              AND artifact.status = 'active'
              AND artifact.deleted_at IS NULL
             WHERE access_request.tenant_id = $1
               AND access_request.site_id = $2
               AND access_request.access_request_id = $3
               AND access_request.artifact_id = $4
               AND access_request.requested_by = $5
               AND access_request.status = 'approved'
             FOR SHARE OF access_request, case_record, artifact",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(access_request_id.as_str())
        .bind(artifact_id.as_str())
        .bind(requested_by)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.rollback().await?;
            return Ok(None);
        };
        // Row locks can wait across either independent deadline without any
        // tuple update. Obtain the clock only after all locks are held.
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        let access_expires_at: DateTime<Utc> = row.try_get("capability_expires_at")?;
        if row.try_get::<DateTime<Utc>, _>("expires_at")? <= now || access_expires_at <= now {
            transaction.rollback().await?;
            return Ok(None);
        }
        let capability = EvidenceAccessCapability {
            access_request_id: EvidenceAccessRequestId::parse(
                row.try_get::<&str, _>("capability_access_request_id")?,
            )
            .map_err(|_| StoreError::CorruptData("evidence_access_request_id"))?,
            case_id: CaseId::parse(row.try_get::<&str, _>("capability_case_id")?)
                .map_err(|_| StoreError::CorruptData("evidence_access_case_id"))?,
            requested_by: row.try_get("capability_requested_by")?,
            access_expires_at,
            artifact: catalog_artifact(&row)?,
        };
        transaction.commit().await?;
        Ok(Some(capability))
    }

    /// Applies one independent terminal decision to a pending access request.
    ///
    /// Exact retries are resolved before current target checks. Approvals lock
    /// and revalidate the requester-owned open case and active evidence object,
    /// then clamp the capability lease to the object's database expiry. Denials
    /// close a pending request without producing a content capability. Decision
    /// time and lease start are sampled after all target locks. Statements and
    /// lock waits are limited to 5 seconds; callers bound the overall operation.
    /// Cancellation rolls back uncommitted state; exact retries preserve the
    /// original decision time and expiry after an uncertain commit.
    ///
    /// # Errors
    /// Returns [`StoreError`] for corrupt durable state or database failure.
    pub async fn decide_evidence_access(
        &self,
        command: EvidenceAccessDecisionCreate<'_>,
    ) -> Result<EvidenceAccessDecisionWriteOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-evidence-decision-v1:' || $1 || ':' || $2 || ':' || $3, 0
             ))",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.decided_by())
        .execute(&mut *transaction)
        .await?;

        if let Some(outcome) = existing_decision(&mut transaction, &command).await? {
            transaction.rollback().await?;
            return Ok(outcome);
        }
        let Some(target) = lock_request(&mut transaction, &command).await? else {
            transaction.rollback().await?;
            return Ok(EvidenceAccessDecisionWriteOutcome::TargetUnavailable);
        };
        if target.status != "pending" {
            transaction.rollback().await?;
            return Ok(EvidenceAccessDecisionWriteOutcome::Conflict);
        }
        if target.requested_by == command.draft.decided_by() {
            transaction.rollback().await?;
            return Ok(EvidenceAccessDecisionWriteOutcome::SelfApprovalDenied);
        }

        let (decided_at, access_expires_at) = match command.draft.kind() {
            EvidenceAccessDecisionKind::Approved => {
                let Some((now, artifact_expires_at)) =
                    lock_approval_targets(&mut transaction, &command, &target).await?
                else {
                    transaction.rollback().await?;
                    return Ok(EvidenceAccessDecisionWriteOutcome::TargetUnavailable);
                };
                let ttl = command
                    .draft
                    .requested_ttl_seconds()
                    .ok_or(StoreError::InvalidCommand)?;
                let requested_expiry = now
                    .checked_add_signed(TimeDelta::seconds(i64::from(ttl)))
                    .ok_or(StoreError::InvalidCommand)?;
                let expiry = requested_expiry.min(artifact_expires_at);
                if expiry <= now {
                    transaction.rollback().await?;
                    return Ok(EvidenceAccessDecisionWriteOutcome::TargetUnavailable);
                }
                (now, Some(expiry))
            }
            EvidenceAccessDecisionKind::Denied => {
                let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                    .fetch_one(&mut *transaction)
                    .await?;
                (now, None)
            }
        };
        update_decision(
            &mut transaction,
            &command,
            &target,
            decided_at,
            access_expires_at,
        )
        .await?;
        insert_event(&mut transaction, &command).await?;
        transaction.commit().await?;
        Ok(EvidenceAccessDecisionWriteOutcome::Created(
            EvidenceAccessDecisionRecord {
                access_request_id: command.draft.access_request_id().clone(),
                case_id: target.case_id,
                artifact_id: target.artifact_id,
                requested_by: target.requested_by,
                decided_by: command.draft.decided_by().to_owned(),
                status: command.draft.kind().as_str(),
                decided_at,
                access_expires_at,
            },
        ))
    }
}

struct LockedRequest {
    case_id: CaseId,
    artifact_id: ArtifactId,
    requested_by: String,
    status: String,
}

async fn lock_request(
    transaction: &mut Transaction<'_, Postgres>,
    command: &EvidenceAccessDecisionCreate<'_>,
) -> Result<Option<LockedRequest>, StoreError> {
    let row = sqlx::query(
        "SELECT case_id, artifact_id, requested_by, status
         FROM xshield.evidence_access_requests
         WHERE tenant_id = $1 AND site_id = $2 AND access_request_id = $3
         FOR UPDATE",
    )
    .bind(command.draft.tenant_id().as_str())
    .bind(command.draft.site_id().as_str())
    .bind(command.draft.access_request_id().as_str())
    .fetch_optional(&mut **transaction)
    .await?;
    row.map(|row| {
        Ok(LockedRequest {
            case_id: CaseId::parse(row.try_get::<&str, _>("case_id")?)
                .map_err(|_| StoreError::CorruptData("evidence_access_case_id"))?,
            artifact_id: ArtifactId::parse(row.try_get::<&str, _>("artifact_id")?)
                .map_err(|_| StoreError::CorruptData("evidence_access_artifact_id"))?,
            requested_by: row.try_get("requested_by")?,
            status: row.try_get("status")?,
        })
    })
    .transpose()
}

async fn lock_approval_targets(
    transaction: &mut Transaction<'_, Postgres>,
    command: &EvidenceAccessDecisionCreate<'_>,
    target: &LockedRequest,
) -> Result<Option<(DateTime<Utc>, DateTime<Utc>)>, StoreError> {
    let row = sqlx::query(
        "SELECT artifact.expires_at
         FROM xshield.investigation_cases case_record
         JOIN xshield.artifact_catalog artifact
           ON artifact.tenant_id = case_record.tenant_id
          AND artifact.site_id = case_record.site_id
          AND artifact.artifact_id = $5
          AND artifact.status = 'active'
          AND artifact.deleted_at IS NULL
         WHERE case_record.tenant_id = $1 AND case_record.site_id = $2
           AND case_record.case_id = $3 AND case_record.owner_ref = $4
           AND case_record.status = 'open'
         FOR SHARE OF case_record, artifact",
    )
    .bind(command.draft.tenant_id().as_str())
    .bind(command.draft.site_id().as_str())
    .bind(target.case_id.as_str())
    .bind(&target.requested_by)
    .bind(target.artifact_id.as_str())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    // A locking query may evaluate its projection before waiting. Sampling in
    // a new statement ensures both expiry validation and TTL use post-lock time.
    let now = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(Some((now, row.try_get("expires_at")?)))
}

async fn update_decision(
    transaction: &mut Transaction<'_, Postgres>,
    command: &EvidenceAccessDecisionCreate<'_>,
    target: &LockedRequest,
    decided_at: DateTime<Utc>,
    access_expires_at: Option<DateTime<Utc>>,
) -> Result<(), StoreError> {
    let result = sqlx::query(
        "UPDATE xshield.evidence_access_requests
         SET status = $4, decided_by = $5, decision_reason = $6,
             decision_ttl_seconds = $7, decision_idempotency_digest = $8,
             decision_request_digest = $9, decision_event_id = $10,
             decided_at = $11, access_expires_at = $12
         WHERE tenant_id = $1 AND site_id = $2 AND access_request_id = $3
           AND requested_by = $13 AND status = 'pending'",
    )
    .bind(command.draft.tenant_id().as_str())
    .bind(command.draft.site_id().as_str())
    .bind(command.draft.access_request_id().as_str())
    .bind(command.draft.kind().as_str())
    .bind(command.draft.decided_by())
    .bind(command.draft.reason())
    .bind(command.draft.requested_ttl_seconds().map(i64::from))
    .bind(command.idempotency_digest.as_slice())
    .bind(command.request_digest.as_slice())
    .bind(command.event_id.as_str())
    .bind(decided_at)
    .bind(access_expires_at)
    .bind(&target.requested_by)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(StoreError::CorruptData("evidence_access_decision_update"));
    }
    Ok(())
}

async fn insert_event(
    transaction: &mut Transaction<'_, Postgres>,
    command: &EvidenceAccessDecisionCreate<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(command.event_id.as_str())
    .bind(command.draft.tenant_id().as_str())
    .bind(command.draft.site_id().as_str())
    .bind(command.draft.access_request_id().as_str())
    .bind(command.draft.kind().event_type())
    .bind(command.event_envelope)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn existing_decision(
    connection: &mut PgConnection,
    command: &EvidenceAccessDecisionCreate<'_>,
) -> Result<Option<EvidenceAccessDecisionWriteOutcome>, StoreError> {
    let row = sqlx::query(
        "SELECT access.access_request_id, access.case_id, access.artifact_id,
                access.requested_by, access.decided_by, access.status,
                access.decision_reason, access.decision_ttl_seconds,
                access.decision_request_digest, access.decided_at,
                access.access_expires_at, outbox.event_id AS outbox_event_id
         FROM xshield.evidence_access_requests access
         LEFT JOIN xshield.audit_outbox outbox
           ON outbox.event_id = access.decision_event_id
          AND outbox.tenant_id = access.tenant_id
          AND outbox.site_id = access.site_id
          AND outbox.aggregate_ref = access.access_request_id
          AND outbox.event_type IN ('evidence.access.approved', 'evidence.access.denied')
         WHERE access.tenant_id = $1 AND access.site_id = $2
           AND access.decided_by = $3 AND access.decision_idempotency_digest = $4",
    )
    .bind(command.draft.tenant_id().as_str())
    .bind(command.draft.site_id().as_str())
    .bind(command.draft.decided_by())
    .bind(command.idempotency_digest.as_slice())
    .fetch_optional(connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.try_get::<Option<&str>, _>("outbox_event_id")?.is_none() {
        return Err(StoreError::CorruptData("evidence_access_decision_outbox"));
    }
    let stored_ttl = row
        .try_get::<Option<i32>, _>("decision_ttl_seconds")?
        .map(u32::try_from)
        .transpose()
        .map_err(|_| StoreError::CorruptData("evidence_access_decision_ttl"))?;
    let same_request = row.try_get::<&str, _>("access_request_id")?
        == command.draft.access_request_id().as_str()
        && row
            .try_get::<Vec<u8>, _>("decision_request_digest")?
            .as_slice()
            == command.request_digest.as_slice()
        && row.try_get::<&str, _>("decision_reason")? == command.draft.reason()
        && stored_ttl == command.draft.requested_ttl_seconds()
        && decision_kind_from_status(row.try_get("status")?) == Some(command.draft.kind());
    if !same_request {
        return Ok(Some(EvidenceAccessDecisionWriteOutcome::Conflict));
    }
    Ok(Some(EvidenceAccessDecisionWriteOutcome::Existing(
        decision_record(&row)?,
    )))
}

fn decision_record(
    row: &sqlx::postgres::PgRow,
) -> Result<EvidenceAccessDecisionRecord, StoreError> {
    let status = match row.try_get::<&str, _>("status")? {
        "approved" => "approved",
        "denied" => "denied",
        "expired" => "expired",
        "revoked" => "revoked",
        _ => return Err(StoreError::CorruptData("evidence_access_decision_status")),
    };
    Ok(EvidenceAccessDecisionRecord {
        access_request_id: EvidenceAccessRequestId::parse(
            row.try_get::<&str, _>("access_request_id")?,
        )
        .map_err(|_| StoreError::CorruptData("evidence_access_request_id"))?,
        case_id: CaseId::parse(row.try_get::<&str, _>("case_id")?)
            .map_err(|_| StoreError::CorruptData("evidence_access_case_id"))?,
        artifact_id: ArtifactId::parse(row.try_get::<&str, _>("artifact_id")?)
            .map_err(|_| StoreError::CorruptData("evidence_access_artifact_id"))?,
        requested_by: row.try_get("requested_by")?,
        decided_by: row.try_get("decided_by")?,
        status,
        decided_at: row.try_get("decided_at")?,
        access_expires_at: row.try_get("access_expires_at")?,
    })
}

fn decision_kind_from_status(status: &str) -> Option<EvidenceAccessDecisionKind> {
    match status {
        "approved" | "expired" | "revoked" => Some(EvidenceAccessDecisionKind::Approved),
        "denied" => Some(EvidenceAccessDecisionKind::Denied),
        _ => None,
    }
}

fn decision_event_matches(
    draft: &EvidenceAccessDecisionDraft,
    request_digest: &[u8; 32],
    request_id: &RequestId,
    event_id: &EventId,
    envelope: &Value,
) -> bool {
    let Some(payload) = envelope.get("payload").and_then(Value::as_object) else {
        return false;
    };
    envelope.get("schema_version").and_then(Value::as_u64) == Some(3)
        && envelope.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
        && envelope.get("event_type").and_then(Value::as_str) == Some(draft.kind().event_type())
        && envelope.get("tenant_id").and_then(Value::as_str) == Some(draft.tenant_id().as_str())
        && envelope.get("site_id").and_then(Value::as_str) == Some(draft.site_id().as_str())
        && envelope.get("request_id").and_then(Value::as_str) == Some(request_id.as_str())
        && payload.get("access_request_id").and_then(Value::as_str)
            == Some(draft.access_request_id().as_str())
        && payload.get("subject_ref").and_then(Value::as_str) == Some(draft.decided_by())
        && payload.get("decision").and_then(Value::as_str) == Some(draft.kind().as_str())
        && payload.get("ttl_seconds").and_then(Value::as_u64)
            == draft.requested_ttl_seconds().map(u64::from)
        && payload.get("stage").and_then(Value::as_str) == Some("evidence_access_decision")
        && payload.get("request_digest").and_then(Value::as_str)
            == Some(lower_hex(request_digest).as_str())
        && payload.get("outcome").and_then(Value::as_str) == Some("PASS")
        && payload.get("reason_code").and_then(Value::as_str) == Some(draft.kind().reason_code())
}

fn lower_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
