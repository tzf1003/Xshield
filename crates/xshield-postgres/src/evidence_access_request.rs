//! Atomic evidence-access requests and their outbox events.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use xshield_core::{
    domain::{EventId, EvidenceAccessRequestId, RequestId},
    investigation::EvidenceAccessRequestDraft,
};

const ACCESS_REQUESTED_EVENT: &str = "evidence.access.requested";
const ACCESS_REQUESTED_REASON: &str = "EVIDENCE_ACCESS_REQUESTED";

/// A validated evidence-access request ready for an atomic transaction.
pub struct EvidenceAccessRequestCreate<'a> {
    draft: &'a EvidenceAccessRequestDraft,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
    event_id: &'a EventId,
    event_envelope: &'a Value,
    max_pending_requests: u32,
}

impl<'a> EvidenceAccessRequestCreate<'a> {
    /// Binds one pending request and outbox event to the same scope and actor.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for zero capacity or a mismatched
    /// event identity, scope, target, actor, digest, or terminal reason.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        draft: &'a EvidenceAccessRequestDraft,
        idempotency_digest: &'a [u8; 32],
        request_digest: &'a [u8; 32],
        request_id: &'a RequestId,
        event_id: &'a EventId,
        event_envelope: &'a Value,
        max_pending_requests: u32,
    ) -> Result<Self, StoreError> {
        if max_pending_requests == 0
            || !access_event_matches(draft, request_digest, request_id, event_id, event_envelope)
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            draft,
            idempotency_digest,
            request_digest,
            event_id,
            event_envelope,
            max_pending_requests,
        })
    }
}

/// Durable metadata returned by access-request creation and exact retries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceAccessRequestRecord {
    access_request_id: EvidenceAccessRequestId,
    status: &'static str,
    requested_at: DateTime<Utc>,
}

impl EvidenceAccessRequestRecord {
    /// Returns the stable access-request identity.
    #[must_use]
    pub const fn access_request_id(&self) -> &EvidenceAccessRequestId {
        &self.access_request_id
    }

    /// Returns the current approval state.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        self.status
    }

    /// Returns the database-assigned request time.
    #[must_use]
    pub const fn requested_at(&self) -> DateTime<Utc> {
        self.requested_at
    }
}

/// Deterministic result of one idempotent evidence-access request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceAccessRequestWriteOutcome {
    /// The pending request and outbox event committed atomically.
    Created(EvidenceAccessRequestRecord),
    /// The exact request was already committed.
    Existing(EvidenceAccessRequestRecord),
    /// The idempotency key is bound to different parameters.
    Conflict,
    /// The owned open case or active unexpired artifact is unavailable.
    TargetUnavailable,
    /// The configured pending-request capacity is exhausted.
    CapacityExceeded,
}

impl PostgresIdentityStore {
    /// Creates one pending evidence-access request and its outbox event.
    ///
    /// Exact retries are resolved before current target checks. New requests
    /// require an open case owned by the requester and an active, unexpired
    /// artifact in the same tenant/site scope. Expiry is checked after target
    /// locks and again at insertion. Statements and lock waits are limited to
    /// 5 seconds; callers must bound the overall operation. Cancellation rolls
    /// back uncommitted state, and exact retries resolve uncertain commits.
    ///
    /// # Errors
    /// Returns [`StoreError`] for corrupt durable state or database failure.
    pub async fn create_evidence_access_request(
        &self,
        command: EvidenceAccessRequestCreate<'_>,
    ) -> Result<EvidenceAccessRequestWriteOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-evidence-access-v1:' || $1 || ':' || $2 || ':' || $3, 0
             ))",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.requested_by())
        .execute(&mut *transaction)
        .await?;

        if let Some(outcome) = existing_request(&mut transaction, &command).await? {
            transaction.rollback().await?;
            return Ok(outcome);
        }
        if !lock_request_targets(&mut transaction, command.draft).await? {
            transaction.rollback().await?;
            return Ok(EvidenceAccessRequestWriteOutcome::TargetUnavailable);
        }
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM xshield.evidence_access_requests
             WHERE tenant_id = $1 AND site_id = $2 AND requested_by = $3
               AND status = 'pending'",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.requested_by())
        .fetch_one(&mut *transaction)
        .await?;
        if pending >= i64::from(command.max_pending_requests) {
            transaction.rollback().await?;
            return Ok(EvidenceAccessRequestWriteOutcome::CapacityExceeded);
        }

        let requested_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "INSERT INTO xshield.evidence_access_requests (
                tenant_id, site_id, access_request_id, case_id, artifact_id,
                requested_by, access_kind, justification, status,
                idempotency_digest, request_digest, requested_event_id
             ) SELECT $1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11
               FROM xshield.artifact_catalog
               WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $5
                 AND status = 'active' AND deleted_at IS NULL
                 AND expires_at > clock_timestamp()
             RETURNING requested_at",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.access_request_id().as_str())
        .bind(command.draft.case_id().as_str())
        .bind(command.draft.artifact_id().as_str())
        .bind(command.draft.requested_by())
        .bind(command.draft.kind().as_str())
        .bind(command.draft.justification())
        .bind(command.idempotency_digest.as_slice())
        .bind(command.request_digest.as_slice())
        .bind(command.event_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(requested_at) = requested_at else {
            transaction.rollback().await?;
            return Ok(EvidenceAccessRequestWriteOutcome::TargetUnavailable);
        };
        sqlx::query(
            "INSERT INTO xshield.audit_outbox (
                event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
             ) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(command.event_id.as_str())
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.access_request_id().as_str())
        .bind(ACCESS_REQUESTED_EVENT)
        .bind(command.event_envelope)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(EvidenceAccessRequestWriteOutcome::Created(
            EvidenceAccessRequestRecord {
                access_request_id: command.draft.access_request_id().clone(),
                status: "pending",
                requested_at,
            },
        ))
    }
}

async fn lock_request_targets(
    connection: &mut PgConnection,
    draft: &EvidenceAccessRequestDraft,
) -> Result<bool, StoreError> {
    // Materialization keeps the expiry check after both locks, even when
    // the blocking transaction releases its lock without updating a row.
    Ok(sqlx::query_scalar(
        "WITH locked AS MATERIALIZED (
             SELECT artifact.expires_at
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
             FOR SHARE OF case_record, artifact
         ) SELECT EXISTS(SELECT 1 FROM locked WHERE expires_at > clock_timestamp())",
    )
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(draft.case_id().as_str())
    .bind(draft.requested_by())
    .bind(draft.artifact_id().as_str())
    .fetch_one(connection)
    .await?)
}

async fn existing_request(
    connection: &mut PgConnection,
    command: &EvidenceAccessRequestCreate<'_>,
) -> Result<Option<EvidenceAccessRequestWriteOutcome>, StoreError> {
    let row = sqlx::query(
        "SELECT access.access_request_id, access.status, access.case_id,
                access.artifact_id, access.access_kind, access.justification,
                access.request_digest, access.requested_at,
                outbox.event_id AS outbox_event_id
         FROM xshield.evidence_access_requests access
         LEFT JOIN xshield.audit_outbox outbox
           ON outbox.event_id = access.requested_event_id
          AND outbox.tenant_id = access.tenant_id
          AND outbox.site_id = access.site_id
          AND outbox.aggregate_ref = access.access_request_id
          AND outbox.event_type = 'evidence.access.requested'
         WHERE access.tenant_id = $1 AND access.site_id = $2
           AND access.requested_by = $3 AND access.idempotency_digest = $4",
    )
    .bind(command.draft.tenant_id().as_str())
    .bind(command.draft.site_id().as_str())
    .bind(command.draft.requested_by())
    .bind(command.idempotency_digest.as_slice())
    .fetch_optional(connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.try_get::<Option<&str>, _>("outbox_event_id")?.is_none() {
        return Err(StoreError::CorruptData("evidence_access_request_outbox"));
    }
    let same_request = row.try_get::<Vec<u8>, _>("request_digest")?.as_slice()
        == command.request_digest.as_slice()
        && row.try_get::<&str, _>("case_id")? == command.draft.case_id().as_str()
        && row.try_get::<&str, _>("artifact_id")? == command.draft.artifact_id().as_str()
        && row.try_get::<&str, _>("access_kind")? == command.draft.kind().as_str()
        && row.try_get::<&str, _>("justification")? == command.draft.justification();
    if !same_request {
        return Ok(Some(EvidenceAccessRequestWriteOutcome::Conflict));
    }
    let access_request_id =
        EvidenceAccessRequestId::parse(row.try_get::<&str, _>("access_request_id")?)
            .map_err(|_| StoreError::CorruptData("evidence_access_request_id"))?;
    let status = match row.try_get::<&str, _>("status")? {
        "pending" => "pending",
        "approved" => "approved",
        "denied" => "denied",
        "expired" => "expired",
        "revoked" => "revoked",
        _ => return Err(StoreError::CorruptData("evidence_access_request_status")),
    };
    Ok(Some(EvidenceAccessRequestWriteOutcome::Existing(
        EvidenceAccessRequestRecord {
            access_request_id,
            status,
            requested_at: row.try_get("requested_at")?,
        },
    )))
}

fn access_event_matches(
    draft: &EvidenceAccessRequestDraft,
    request_digest: &[u8; 32],
    request_id: &RequestId,
    event_id: &EventId,
    envelope: &Value,
) -> bool {
    let Some(payload) = envelope.get("payload").and_then(Value::as_object) else {
        return false;
    };
    let evidence_matches = envelope
        .get("evidence_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.len() == 1 && refs[0].as_str() == Some(draft.artifact_id().as_str())
        });
    envelope.get("schema_version").and_then(Value::as_u64) == Some(3)
        && envelope.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
        && envelope.get("event_type").and_then(Value::as_str) == Some(ACCESS_REQUESTED_EVENT)
        && envelope.get("tenant_id").and_then(Value::as_str) == Some(draft.tenant_id().as_str())
        && envelope.get("site_id").and_then(Value::as_str) == Some(draft.site_id().as_str())
        && envelope.get("request_id").and_then(Value::as_str) == Some(request_id.as_str())
        && evidence_matches
        && payload.get("access_request_id").and_then(Value::as_str)
            == Some(draft.access_request_id().as_str())
        && payload.get("case_id").and_then(Value::as_str) == Some(draft.case_id().as_str())
        && payload.get("artifact_id").and_then(Value::as_str) == Some(draft.artifact_id().as_str())
        && payload.get("subject_ref").and_then(Value::as_str) == Some(draft.requested_by())
        && payload.get("access_kind").and_then(Value::as_str) == Some(draft.kind().as_str())
        && payload.get("stage").and_then(Value::as_str) == Some("evidence_access")
        && payload.get("request_digest").and_then(Value::as_str)
            == Some(lower_hex(request_digest).as_str())
        && payload.get("outcome").and_then(Value::as_str) == Some("PASS")
        && payload.get("reason_code").and_then(Value::as_str) == Some(ACCESS_REQUESTED_REASON)
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

#[cfg(test)]
mod tests {
    use super::EvidenceAccessRequestCreate;
    use serde_json::json;
    use xshield_core::{
        domain::{
            ArtifactId, CaseId, EventId, EvidenceAccessRequestId, RequestId, SiteId, TenantId,
        },
        investigation::{EvidenceAccessKind, EvidenceAccessRequestDraft},
    };

    #[test]
    fn command_requires_matching_event_and_capacity() {
        let draft = EvidenceAccessRequestDraft::new(
            EvidenceAccessRequestId::parse("access_018f2a3b-4c5d-7000-8000-000000000921").unwrap(),
            TenantId::parse("tenant_access").unwrap(),
            SiteId::parse("site_access").unwrap(),
            CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000922").unwrap(),
            ArtifactId::parse("artifact_018f2a3b-4c5d-7000-8000-000000000923").unwrap(),
            "investigator-1",
            EvidenceAccessKind::SensitiveRaw,
            "Verify source response",
        )
        .unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000924").unwrap();
        let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000925").unwrap();
        let envelope = json!({
            "schema_version": 3,
            "event_id": event.as_str(),
            "event_type": "evidence.access.requested",
            "tenant_id": draft.tenant_id().as_str(),
            "site_id": draft.site_id().as_str(),
            "request_id": request.as_str(),
            "evidence_refs": [draft.artifact_id().as_str()],
            "payload": {
                "access_request_id": draft.access_request_id().as_str(),
                "case_id": draft.case_id().as_str(),
                "artifact_id": draft.artifact_id().as_str(),
                "subject_ref": draft.requested_by(),
                "access_kind": draft.kind().as_str(),
                "stage": "evidence_access",
                "request_digest": super::lower_hex(&[2; 32]),
                "outcome": "PASS",
                "reason_code": "EVIDENCE_ACCESS_REQUESTED"
            }
        });
        assert!(
            EvidenceAccessRequestCreate::new(
                &draft, &[1; 32], &[2; 32], &request, &event, &envelope, 1,
            )
            .is_ok()
        );
        assert!(
            EvidenceAccessRequestCreate::new(
                &draft, &[1; 32], &[2; 32], &request, &event, &envelope, 0,
            )
            .is_err()
        );
    }
}
