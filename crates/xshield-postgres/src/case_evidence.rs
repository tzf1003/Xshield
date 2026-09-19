//! Bounded case evidence membership and atomic outbox persistence.
//!
//! Associations carry references only; approval and retention remain separate.

use crate::{PostgresIdentityStore, StoreError, investigation_case::lower_hex};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use xshield_core::{
    domain::{ArtifactId, EventId, RequestId},
    investigation::CaseEvidenceDraft,
};

/// Maximum evidence references retained in one investigation case.
pub const CASE_EVIDENCE_ITEMS_MAX: u32 = 128;
const ADDED_EVENT: &str = "case.evidence.added";
const ADDED_REASON: &str = "CASE_EVIDENCE_ADDED";

/// A validated association and audit event ready for atomic persistence.
pub struct CaseEvidenceAdd<'a> {
    draft: &'a CaseEvidenceDraft,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> CaseEvidenceAdd<'a> {
    /// Binds the outbox event to the exact scope, actor, case, and artifact.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an event binding mismatch.
    /// Construction has no side effects and does not authorize content access.
    pub fn new(
        draft: &'a CaseEvidenceDraft,
        idempotency_digest: &'a [u8; 32],
        request_digest: &'a [u8; 32],
        request_id: &'a RequestId,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        if !event_matches(draft, request_digest, request_id, event_id, event_envelope) {
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

/// Durable membership metadata returned by addition and exact retries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseEvidenceRecord {
    artifact_id: ArtifactId,
    added_by: String,
    added_at: DateTime<Utc>,
}

impl CaseEvidenceRecord {
    /// Returns the associated evidence identity, not a content capability.
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Returns the authenticated actor who created the association.
    #[must_use]
    pub fn added_by(&self) -> &str {
        &self.added_by
    }

    /// Returns the database-assigned association time.
    #[must_use]
    pub const fn added_at(&self) -> DateTime<Utc> {
        self.added_at
    }
}

/// Deterministic outcome of one idempotent evidence association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseEvidenceWriteOutcome {
    /// Membership and its outbox event committed atomically.
    Added(CaseEvidenceRecord),
    /// The same actor, scope, key, case, artifact, and request already committed.
    Existing(CaseEvidenceRecord),
    /// The key or case/artifact pair is already bound to another request.
    Conflict,
    /// The owned open case or available scoped artifact is unavailable.
    TargetUnavailable,
    /// The case already contains the fixed maximum number of references.
    CapacityExceeded,
}

impl PostgresIdentityStore {
    /// Associates one available evidence reference with its owner's open case.
    ///
    /// Lock order is actor advisory lock, case row, then artifact row. The case
    /// lock serializes capacity and natural uniqueness; the actor lock binds
    /// keys across that actor's cases. Exact retries still require an owned open
    /// case, but return historical membership after an artifact expires.
    ///
    /// Statements and lock waits have 5-second deadlines. The caller must bound
    /// the overall operation; cancellation rolls back an uncommitted transaction
    /// and exact retries resolve an uncertain commit. A new association and its
    /// outbox commit together, without changing content approvals or expiry.
    ///
    /// # Errors
    /// Returns [`StoreError`] for corrupt durable state or database failure.
    pub async fn add_case_evidence(
        &self,
        command: CaseEvidenceAdd<'_>,
    ) -> Result<CaseEvidenceWriteOutcome, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-case-evidence-v1:' || $1 || ':' || $2 || ':' || $3, 0
             ))",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.added_by())
        .execute(&mut *tx)
        .await?;
        let available = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM xshield.investigation_cases
             WHERE tenant_id = $1 AND site_id = $2 AND case_id = $3
               AND owner_ref = $4 AND status = 'open' FOR UPDATE",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.case_id().as_str())
        .bind(command.draft.added_by())
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        let outcome = if !available {
            CaseEvidenceWriteOutcome::TargetUnavailable
        } else if let Some(outcome) = existing_membership(&mut tx, &command).await? {
            outcome
        } else {
            add_membership(&mut tx, &command).await?
        };
        tx.commit().await?;
        Ok(outcome)
    }
}

async fn existing_membership(
    connection: &mut PgConnection,
    command: &CaseEvidenceAdd<'_>,
) -> Result<Option<CaseEvidenceWriteOutcome>, StoreError> {
    let draft = command.draft;
    let row = sqlx::query(
        "SELECT item.case_id, item.artifact_id, item.request_digest, item.added_at,
                outbox.event_id AS outbox_event_id
         FROM xshield.case_items item
         LEFT JOIN xshield.audit_outbox outbox
           ON outbox.event_id = item.added_event_id
          AND outbox.tenant_id = item.tenant_id AND outbox.site_id = item.site_id
          AND outbox.aggregate_ref = item.case_id
          AND outbox.event_type = 'case.evidence.added'
         WHERE item.tenant_id = $1 AND item.site_id = $2 AND item.added_by = $3
           AND item.idempotency_digest = $4",
    )
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(draft.added_by())
    .bind(command.idempotency_digest.as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(row) = row {
        if row.try_get::<Option<&str>, _>("outbox_event_id")?.is_none() {
            return Err(StoreError::CorruptData("case_evidence_outbox"));
        }
        let same = row.try_get::<&str, _>("case_id")? == draft.case_id().as_str()
            && row.try_get::<&str, _>("artifact_id")? == draft.artifact_id().as_str()
            && row.try_get::<Vec<u8>, _>("request_digest")?.as_slice()
                == command.request_digest.as_slice();
        return Ok(Some(if same {
            CaseEvidenceWriteOutcome::Existing(CaseEvidenceRecord {
                artifact_id: draft.artifact_id().clone(),
                added_by: draft.added_by().to_owned(),
                added_at: row.try_get("added_at")?,
            })
        } else {
            CaseEvidenceWriteOutcome::Conflict
        }));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM xshield.case_items
         WHERE tenant_id = $1 AND site_id = $2 AND case_id = $3 AND artifact_id = $4)",
    )
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(draft.case_id().as_str())
    .bind(draft.artifact_id().as_str())
    .fetch_one(connection)
    .await?;
    Ok(exists.then_some(CaseEvidenceWriteOutcome::Conflict))
}

async fn add_membership(
    connection: &mut PgConnection,
    command: &CaseEvidenceAdd<'_>,
) -> Result<CaseEvidenceWriteOutcome, StoreError> {
    let draft = command.draft;
    // Materialization acquires the row lock before evaluating the current clock;
    // a wait on retention cannot revive a now-expired artifact.
    let available: bool = sqlx::query_scalar(
        "WITH locked AS MATERIALIZED (
             SELECT expires_at FROM xshield.artifact_catalog
             WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3
               AND status = 'active' AND deleted_at IS NULL FOR SHARE
         ) SELECT EXISTS(SELECT 1 FROM locked WHERE expires_at > clock_timestamp())",
    )
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(draft.artifact_id().as_str())
    .fetch_one(&mut *connection)
    .await?;
    if !available {
        return Ok(CaseEvidenceWriteOutcome::TargetUnavailable);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT 1 FROM xshield.case_items
         WHERE tenant_id = $1 AND site_id = $2 AND case_id = $3 LIMIT $4) items",
    )
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(draft.case_id().as_str())
    .bind(i64::from(CASE_EVIDENCE_ITEMS_MAX))
    .fetch_one(&mut *connection)
    .await?;
    if count >= i64::from(CASE_EVIDENCE_ITEMS_MAX) {
        return Ok(CaseEvidenceWriteOutcome::CapacityExceeded);
    }
    let added_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "INSERT INTO xshield.case_items (
             tenant_id, site_id, case_id, artifact_id, added_by,
             idempotency_digest, request_digest, added_event_id
         ) SELECT $1, $2, $3, $4, $5, $6, $7, $8
           FROM xshield.artifact_catalog
           WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $4
             AND status = 'active' AND deleted_at IS NULL
             AND expires_at > clock_timestamp()
         RETURNING added_at",
    )
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(draft.case_id().as_str())
    .bind(draft.artifact_id().as_str())
    .bind(draft.added_by())
    .bind(command.idempotency_digest.as_slice())
    .bind(command.request_digest.as_slice())
    .bind(command.event_id.as_str())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(added_at) = added_at else {
        return Ok(CaseEvidenceWriteOutcome::TargetUnavailable);
    };
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
             event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(command.event_id.as_str())
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(draft.case_id().as_str())
    .bind(ADDED_EVENT)
    .bind(command.event_envelope)
    .execute(connection)
    .await?;
    Ok(CaseEvidenceWriteOutcome::Added(CaseEvidenceRecord {
        artifact_id: draft.artifact_id().clone(),
        added_by: draft.added_by().to_owned(),
        added_at,
    }))
}

fn event_matches(
    draft: &CaseEvidenceDraft,
    request_digest: &[u8; 32],
    request_id: &RequestId,
    event_id: &EventId,
    envelope: &Value,
) -> bool {
    let Some(payload) = envelope.get("payload").and_then(Value::as_object) else {
        return false;
    };
    let digest = lower_hex(request_digest);
    envelope.get("schema_version").and_then(Value::as_u64) == Some(3)
        && envelope.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
        && envelope.get("event_type").and_then(Value::as_str) == Some(ADDED_EVENT)
        && envelope.get("tenant_id").and_then(Value::as_str) == Some(draft.tenant_id().as_str())
        && envelope.get("site_id").and_then(Value::as_str) == Some(draft.site_id().as_str())
        && envelope.get("request_id").and_then(Value::as_str) == Some(request_id.as_str())
        && envelope
            .get("evidence_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.len() == 1 && refs[0].as_str() == Some(draft.artifact_id().as_str())
            })
        && payload.get("case_id").and_then(Value::as_str) == Some(draft.case_id().as_str())
        && payload.get("artifact_id").and_then(Value::as_str) == Some(draft.artifact_id().as_str())
        && payload.get("subject_ref").and_then(Value::as_str) == Some(draft.added_by())
        && payload.get("stage").and_then(Value::as_str) == Some("case_management")
        && payload.get("request_digest").and_then(Value::as_str) == Some(digest.as_str())
        && payload.get("outcome").and_then(Value::as_str) == Some("PASS")
        && payload.get("reason_code").and_then(Value::as_str) == Some(ADDED_REASON)
}
