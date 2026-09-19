//! Atomic investigation-case closure and its durable outbox event.

use crate::{PostgresIdentityStore, StoreError, investigation_case::lower_hex};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use xshield_core::{
    domain::{CaseId, EventId, RequestId},
    investigation::InvestigationCaseCloseDraft,
};

const CLOSED_EVENT: &str = "case.closed";
const CLOSED_REASON: &str = "CASE_CLOSED";

/// A validated case closure and its exact outbox envelope.
pub struct InvestigationCaseClose<'a> {
    draft: &'a InvestigationCaseCloseDraft,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> InvestigationCaseClose<'a> {
    /// Binds the outbox event to the exact scoped owner and closure request.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when event identity, scope,
    /// request digest, or terminal reason does not match the draft.
    pub fn new(
        draft: &'a InvestigationCaseCloseDraft,
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

/// Durable terminal metadata returned after closing a case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationCaseCloseRecord {
    case_id: CaseId,
    closed_at: DateTime<Utc>,
}

impl InvestigationCaseCloseRecord {
    /// Returns the closed case identity.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the database-assigned closure time.
    #[must_use]
    pub const fn closed_at(&self) -> DateTime<Utc> {
        self.closed_at
    }
}

/// Deterministic result of one idempotent case closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvestigationCaseCloseWriteOutcome {
    /// The case transitioned from open to closed and its event committed.
    Closed(InvestigationCaseCloseRecord),
    /// The exact closure request was already committed.
    Existing(InvestigationCaseCloseRecord),
    /// The idempotency key is bound to different closure parameters.
    Conflict,
    /// The scoped owner/case is unavailable or already closed by another request.
    TargetUnavailable,
}

impl PostgresIdentityStore {
    /// Closes one owned open case and publishes `case.closed` atomically.
    ///
    /// The actor advisory lock matches case creation so closure frees capacity
    /// in the same serial order. The case row lock also serializes association
    /// and access approval. Exact retries recheck ownership and terminal state.
    /// No evidence, approval, or retention history is deleted. Statements and
    /// lock waits have 5-second limits; callers bound the whole operation.
    ///
    /// # Errors
    /// Returns [`StoreError`] for corrupt durable state or database failure.
    /// An uncertain commit is safe to retry using the original request.
    pub async fn close_investigation_case(
        &self,
        command: InvestigationCaseClose<'_>,
    ) -> Result<InvestigationCaseCloseWriteOutcome, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        let draft = command.draft;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-case-v1:' || $1 || ':' || $2 || ':' || $3, 0
             ))",
        )
        .bind(draft.tenant_id().as_str())
        .bind(draft.site_id().as_str())
        .bind(draft.owner_ref())
        .execute(&mut *tx)
        .await?;

        let status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM xshield.investigation_cases
             WHERE tenant_id = $1 AND site_id = $2 AND case_id = $3
               AND owner_ref = $4 FOR UPDATE",
        )
        .bind(draft.tenant_id().as_str())
        .bind(draft.site_id().as_str())
        .bind(draft.case_id().as_str())
        .bind(draft.owner_ref())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(status) = status else {
            tx.rollback().await?;
            return Ok(InvestigationCaseCloseWriteOutcome::TargetUnavailable);
        };
        if status != "open" && status != "closed" {
            return Err(StoreError::CorruptData("case_status"));
        }
        if let Some(outcome) = existing_closure(&mut tx, &command).await? {
            if matches!(outcome, InvestigationCaseCloseWriteOutcome::Existing(_))
                && status != "closed"
            {
                return Err(StoreError::CorruptData("case_closure_status"));
            }
            tx.rollback().await?;
            return Ok(outcome);
        }
        if status != "open" {
            tx.rollback().await?;
            return Ok(InvestigationCaseCloseWriteOutcome::TargetUnavailable);
        }

        let closed_at: DateTime<Utc> = sqlx::query_scalar(
            "INSERT INTO xshield.case_closures (
                tenant_id, site_id, case_id, closed_by, reason,
                idempotency_digest, request_digest, closed_event_id
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING closed_at",
        )
        .bind(draft.tenant_id().as_str())
        .bind(draft.site_id().as_str())
        .bind(draft.case_id().as_str())
        .bind(draft.owner_ref())
        .bind(draft.reason())
        .bind(command.idempotency_digest.as_slice())
        .bind(command.request_digest.as_slice())
        .bind(command.event_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE xshield.investigation_cases
             SET status = 'closed'
             WHERE tenant_id = $1 AND site_id = $2 AND case_id = $3",
        )
        .bind(draft.tenant_id().as_str())
        .bind(draft.site_id().as_str())
        .bind(draft.case_id().as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO xshield.audit_outbox (
                event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
             ) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(command.event_id.as_str())
        .bind(draft.tenant_id().as_str())
        .bind(draft.site_id().as_str())
        .bind(draft.case_id().as_str())
        .bind(CLOSED_EVENT)
        .bind(command.event_envelope)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(InvestigationCaseCloseWriteOutcome::Closed(
            InvestigationCaseCloseRecord {
                case_id: draft.case_id().clone(),
                closed_at,
            },
        ))
    }
}

async fn existing_closure(
    connection: &mut PgConnection,
    command: &InvestigationCaseClose<'_>,
) -> Result<Option<InvestigationCaseCloseWriteOutcome>, StoreError> {
    let draft = command.draft;
    let row = sqlx::query(
        "SELECT closure.case_id, closure.reason, closure.request_digest,
                closure.closed_at, outbox.event_id AS outbox_event_id,
                outbox.envelope AS outbox_envelope
         FROM xshield.case_closures closure
         LEFT JOIN xshield.audit_outbox outbox
           ON outbox.event_id = closure.closed_event_id
          AND outbox.tenant_id = closure.tenant_id
          AND outbox.site_id = closure.site_id
          AND outbox.aggregate_ref = closure.case_id
          AND outbox.event_type = 'case.closed'
         WHERE closure.tenant_id = $1 AND closure.site_id = $2
           AND closure.closed_by = $3 AND closure.idempotency_digest = $4",
    )
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(draft.owner_ref())
    .bind(command.idempotency_digest.as_slice())
    .fetch_optional(connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let event_id = row
        .try_get::<Option<&str>, _>("outbox_event_id")?
        .and_then(|id| EventId::parse(id).ok())
        .ok_or(StoreError::CorruptData("case_closure_outbox"))?;
    let same_request = row.try_get::<Vec<u8>, _>("request_digest")?.as_slice()
        == command.request_digest.as_slice()
        && row.try_get::<&str, _>("case_id")? == draft.case_id().as_str()
        && row.try_get::<&str, _>("reason")? == draft.reason();
    if !same_request {
        return Ok(Some(InvestigationCaseCloseWriteOutcome::Conflict));
    }
    let envelope: Value = row.try_get("outbox_envelope")?;
    let request_id = envelope
        .get("request_id")
        .and_then(Value::as_str)
        .and_then(|id| RequestId::parse(id).ok())
        .ok_or(StoreError::CorruptData("case_closure_outbox"))?;
    if !event_matches(
        draft,
        command.request_digest,
        &request_id,
        &event_id,
        &envelope,
    ) {
        return Err(StoreError::CorruptData("case_closure_outbox"));
    }
    let case_id = CaseId::parse(row.try_get::<&str, _>("case_id")?)
        .map_err(|_| StoreError::CorruptData("case_id"))?;
    Ok(Some(InvestigationCaseCloseWriteOutcome::Existing(
        InvestigationCaseCloseRecord {
            case_id,
            closed_at: row.try_get("closed_at")?,
        },
    )))
}

fn event_matches(
    draft: &InvestigationCaseCloseDraft,
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
        && envelope.get("event_type").and_then(Value::as_str) == Some(CLOSED_EVENT)
        && envelope.get("tenant_id").and_then(Value::as_str) == Some(draft.tenant_id().as_str())
        && envelope.get("site_id").and_then(Value::as_str) == Some(draft.site_id().as_str())
        && envelope.get("request_id").and_then(Value::as_str) == Some(request_id.as_str())
        && envelope
            .get("evidence_refs")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && payload.get("case_id").and_then(Value::as_str) == Some(draft.case_id().as_str())
        && payload.get("subject_ref").and_then(Value::as_str) == Some(draft.owner_ref())
        && payload.get("stage").and_then(Value::as_str) == Some("case_management")
        && payload.get("request_digest").and_then(Value::as_str)
            == Some(lower_hex(request_digest).as_str())
        && payload.get("outcome").and_then(Value::as_str) == Some("PASS")
        && payload.get("reason_code").and_then(Value::as_str) == Some(CLOSED_REASON)
        && payload.get("proof_kind").and_then(Value::as_str) == Some("deterministic")
        && payload.get("confidence").is_some_and(Value::is_null)
        && payload.get("confidence_status").and_then(Value::as_str) == Some("not_applicable")
}

#[cfg(test)]
mod tests {
    use super::InvestigationCaseClose;
    use serde_json::json;
    use xshield_core::{
        domain::{CaseId, EventId, RequestId, SiteId, TenantId},
        investigation::InvestigationCaseCloseDraft,
    };

    #[test]
    fn command_requires_matching_close_event() {
        let draft = InvestigationCaseCloseDraft::new(
            TenantId::parse("tenant_case").unwrap(),
            SiteId::parse("site_case").unwrap(),
            CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000903").unwrap(),
            "investigator-1",
            "review complete",
        )
        .unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000904").unwrap();
        let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000905").unwrap();
        let envelope = json!({
            "schema_version": 3,
            "event_id": event.as_str(),
            "event_type": "case.closed",
            "tenant_id": draft.tenant_id().as_str(),
            "site_id": draft.site_id().as_str(),
            "request_id": request.as_str(),
            "evidence_refs": [],
            "payload": {
                "case_id": draft.case_id().as_str(),
                "subject_ref": draft.owner_ref(),
                "stage": "case_management",
                "request_digest": super::lower_hex(&[2; 32]),
                "outcome": "PASS",
                "reason_code": "CASE_CLOSED",
                "proof_kind": "deterministic",
                "confidence": null,
                "confidence_status": "not_applicable"
            }
        });
        assert!(
            InvestigationCaseClose::new(&draft, &[1; 32], &[2; 32], &request, &event, &envelope)
                .is_ok()
        );
    }
}
