//! Atomic investigation-case creation and its outbox event.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use xshield_core::{
    domain::{CaseId, EventId, RequestId},
    investigation::InvestigationCaseDraft,
};

const CASE_CREATED_EVENT: &str = "case.created";
const CASE_CREATED_REASON: &str = "CASE_CREATED";

/// A validated case creation ready for an atomic `PostgreSQL` transaction.
pub struct InvestigationCaseCreate<'a> {
    draft: &'a InvestigationCaseDraft,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
    event_id: &'a EventId,
    event_envelope: &'a Value,
    max_open_cases: u32,
}

impl<'a> InvestigationCaseCreate<'a> {
    /// Validates the capacity and binds the outbox event to this exact case.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for zero capacity or mismatched
    /// event identity, scope, target, actor, or terminal reason.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        draft: &'a InvestigationCaseDraft,
        idempotency_digest: &'a [u8; 32],
        request_digest: &'a [u8; 32],
        request_id: &'a RequestId,
        event_id: &'a EventId,
        event_envelope: &'a Value,
        max_open_cases: u32,
    ) -> Result<Self, StoreError> {
        if max_open_cases == 0
            || !case_event_matches(draft, request_digest, request_id, event_id, event_envelope)
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            draft,
            idempotency_digest,
            request_digest,
            event_id,
            event_envelope,
            max_open_cases,
        })
    }
}

/// Durable investigation-case metadata returned by creation and retries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationCaseRecord {
    pub(super) case_id: CaseId,
    pub(super) status: &'static str,
    pub(super) purpose: String,
    pub(super) created_at: DateTime<Utc>,
}

impl InvestigationCaseRecord {
    /// Returns the stable case identity.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the current case state.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        self.status
    }

    /// Returns the original bounded purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Returns the database-assigned creation time.
    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

/// Deterministic result of one idempotent case creation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvestigationCaseWriteOutcome {
    /// The case and outbox event committed atomically.
    Created(InvestigationCaseRecord),
    /// The same actor, scope, idempotency key, and request were already committed.
    Existing(InvestigationCaseRecord),
    /// The idempotency key is already bound to different case parameters.
    Conflict,
    /// The configured per-owner open-case capacity is exhausted.
    CapacityExceeded,
}

impl PostgresIdentityStore {
    /// Creates one scoped case and its `case.created` outbox event atomically.
    ///
    /// A transaction advisory lock serializes idempotency and capacity checks
    /// for the same owner and scope. Exact retries return the original case.
    /// Statements and lock waits are limited to 5 seconds; callers bound the
    /// whole operation and retain original input to recover uncertain commits.
    ///
    /// # Errors
    /// Returns [`StoreError`] for corrupt durable state or database failure.
    pub async fn create_investigation_case(
        &self,
        command: InvestigationCaseCreate<'_>,
    ) -> Result<InvestigationCaseWriteOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-case-v1:' || $1 || ':' || $2 || ':' || $3, 0
             ))",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.owner_ref())
        .execute(&mut *transaction)
        .await?;

        if let Some(outcome) = existing_case(&mut transaction, &command).await? {
            transaction.rollback().await?;
            return Ok(outcome);
        }
        let open_cases: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM xshield.investigation_cases
             WHERE tenant_id = $1 AND site_id = $2 AND owner_ref = $3
               AND status = 'open'",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.owner_ref())
        .fetch_one(&mut *transaction)
        .await?;
        if open_cases >= i64::from(command.max_open_cases) {
            transaction.rollback().await?;
            return Ok(InvestigationCaseWriteOutcome::CapacityExceeded);
        }

        let created_at: DateTime<Utc> = sqlx::query_scalar(
            "INSERT INTO xshield.investigation_cases (
                tenant_id, site_id, case_id, owner_ref, purpose, status,
                idempotency_digest, request_digest, created_event_id
             ) VALUES ($1, $2, $3, $4, $5, 'open', $6, $7, $8)
             RETURNING created_at",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.case_id().as_str())
        .bind(command.draft.owner_ref())
        .bind(command.draft.purpose())
        .bind(command.idempotency_digest.as_slice())
        .bind(command.request_digest.as_slice())
        .bind(command.event_id.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO xshield.audit_outbox (
                event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
             ) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(command.event_id.as_str())
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.case_id().as_str())
        .bind(CASE_CREATED_EVENT)
        .bind(command.event_envelope)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(InvestigationCaseWriteOutcome::Created(case_record(
            command.draft.case_id().clone(),
            command.draft.purpose().to_owned(),
            created_at,
        )))
    }
}

async fn existing_case(
    connection: &mut PgConnection,
    command: &InvestigationCaseCreate<'_>,
) -> Result<Option<InvestigationCaseWriteOutcome>, StoreError> {
    let row = sqlx::query(
        "SELECT case_record.case_id, case_record.status, case_record.purpose,
                case_record.request_digest, case_record.created_at,
                outbox.event_id AS outbox_event_id
         FROM xshield.investigation_cases case_record
         LEFT JOIN xshield.audit_outbox outbox
           ON outbox.event_id = case_record.created_event_id
          AND outbox.tenant_id = case_record.tenant_id
          AND outbox.site_id = case_record.site_id
          AND outbox.aggregate_ref = case_record.case_id
          AND outbox.event_type = 'case.created'
         WHERE case_record.tenant_id = $1 AND case_record.site_id = $2
           AND case_record.owner_ref = $3
           AND case_record.idempotency_digest = $4",
    )
    .bind(command.draft.tenant_id().as_str())
    .bind(command.draft.site_id().as_str())
    .bind(command.draft.owner_ref())
    .bind(command.idempotency_digest.as_slice())
    .fetch_optional(connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.try_get::<Option<&str>, _>("outbox_event_id")?.is_none() {
        return Err(StoreError::CorruptData("investigation_case_outbox"));
    }
    let same_request = row.try_get::<Vec<u8>, _>("request_digest")?.as_slice()
        == command.request_digest.as_slice()
        && row.try_get::<&str, _>("purpose")? == command.draft.purpose();
    if !same_request {
        return Ok(Some(InvestigationCaseWriteOutcome::Conflict));
    }
    let case_id = CaseId::parse(row.try_get::<&str, _>("case_id")?)
        .map_err(|_| StoreError::CorruptData("case_id"))?;
    let status = match row.try_get::<&str, _>("status")? {
        "open" => "open",
        "closed" => "closed",
        _ => return Err(StoreError::CorruptData("case_status")),
    };
    Ok(Some(InvestigationCaseWriteOutcome::Existing(
        InvestigationCaseRecord {
            case_id,
            status,
            purpose: row.try_get("purpose")?,
            created_at: row.try_get("created_at")?,
        },
    )))
}

fn case_record(
    case_id: CaseId,
    purpose: String,
    created_at: DateTime<Utc>,
) -> InvestigationCaseRecord {
    InvestigationCaseRecord {
        case_id,
        status: "open",
        purpose,
        created_at,
    }
}

fn case_event_matches(
    draft: &InvestigationCaseDraft,
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
        && envelope.get("event_type").and_then(Value::as_str) == Some(CASE_CREATED_EVENT)
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
        && payload.get("reason_code").and_then(Value::as_str) == Some(CASE_CREATED_REASON)
}

pub(crate) fn lower_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::InvestigationCaseCreate;
    use serde_json::json;
    use xshield_core::{
        domain::{CaseId, EventId, RequestId, SiteId, TenantId},
        investigation::InvestigationCaseDraft,
    };

    #[test]
    fn command_requires_matching_event_and_capacity() {
        let tenant = TenantId::parse("tenant_case").unwrap();
        let site = SiteId::parse("site_case").unwrap();
        let case_id = CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000901").unwrap();
        let draft = InvestigationCaseDraft::new(
            case_id,
            tenant,
            site,
            "investigator-1",
            "Review evidence anomaly",
        )
        .unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000902").unwrap();
        let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000903").unwrap();
        let envelope = json!({
            "schema_version": 3,
            "event_id": event.as_str(),
            "event_type": "case.created",
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
                "reason_code": "CASE_CREATED"
            }
        });
        assert!(
            InvestigationCaseCreate::new(
                &draft, &[1; 32], &[2; 32], &request, &event, &envelope, 1,
            )
            .is_ok()
        );
        assert!(
            InvestigationCaseCreate::new(
                &draft, &[1; 32], &[2; 32], &request, &event, &envelope, 0,
            )
            .is_err()
        );
        let mut mismatched = envelope;
        mismatched["payload"]["request_digest"] = json!(super::lower_hex(&[3; 32]));
        assert!(
            InvestigationCaseCreate::new(
                &draft,
                &[1; 32],
                &[2; 32],
                &request,
                &event,
                &mismatched,
                1,
            )
            .is_err()
        );
    }
}
