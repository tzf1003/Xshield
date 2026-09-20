//! Scoped historical access-request metadata from one read-only SQL snapshot.
//!
//! Visibility belongs to the request row; corrupt visible associations fail
//! closed. This observation grants no content capability and emits no outbox.

use crate::{PostgresIdentityStore, StoreError, grant_inspection::time};
use chrono::{DateTime, TimeDelta, Utc};
use sqlx::{Row, postgres::PgRow};
use xshield_core::{
    domain::{ArtifactId, CaseId, EventId, EvidenceAccessRequestId, SiteId, TenantId},
    investigation::{EvidenceAccessDecisionDraft, EvidenceAccessKind, EvidenceAccessRequestDraft},
};

/// Historical approval metadata; current content eligibility is checked separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceAccessInspection {
    /// Database statement time for this observation.
    pub as_of: DateTime<Utc>,
    /// Exact access-request identity in the authenticated scope.
    pub access_request_id: EvidenceAccessRequestId,
    /// Investigation case bound to the request.
    pub case_id: CaseId,
    /// Evidence reference, without object storage or cryptographic metadata.
    pub artifact_id: ArtifactId,
    /// Original requesting subject, also the case owner.
    pub requested_by: String,
    /// Requested content scope.
    pub access_kind: EvidenceAccessKind,
    /// Bounded original investigation justification.
    pub justification: String,
    /// Persisted lifecycle state, independent of observed expiry.
    pub stored_status: &'static str,
    /// Database-assigned request time.
    pub requested_at: DateTime<Utc>,
    /// Associated immutable request event.
    pub requested_event_id: EventId,
    /// Independent deciding subject, if decided.
    pub decided_by: Option<String>,
    /// Original bounded decision reason, if decided.
    pub decision_reason: Option<String>,
    /// Requested approval lease before clamping to artifact expiry.
    pub decision_ttl_seconds: Option<u32>,
    /// Associated immutable approval or denial event.
    pub decision_event_id: Option<EventId>,
    /// Original database decision time, if decided.
    pub decided_at: Option<DateTime<Utc>>,
    /// Original absolute approval expiry, if approved.
    pub access_expires_at: Option<DateTime<Utc>>,
    /// Current stored open or closed case state.
    pub case_status: &'static str,
    /// Current stored active or deleted catalog state.
    pub artifact_status: &'static str,
    /// Original artifact expiry, independent of its stored state.
    pub artifact_expires_at: DateTime<Utc>,
}

// Both detail and discovery validate exactly these request associations.
pub(crate) const PROJECTION: &str = "access.access_request_id, access.case_id, access.artifact_id,
                    access.requested_by, access.access_kind, access.justification,
                    access.status, access.requested_at, access.requested_event_id,
                    access.decided_by, access.decision_reason, access.decision_ttl_seconds,
                    access.decision_event_id, access.decided_at, access.access_expires_at,
                    case_record.owner_ref, case_record.status AS case_status,
                    artifact.status AS artifact_status, artifact.expires_at AS artifact_expires_at,
                    artifact.deleted_at,
                    requested.event_id AS request_outbox_id, decided.event_id AS decision_outbox_id,
                    (isfinite(access.requested_at) AND isfinite(artifact.expires_at)
                     AND COALESCE(isfinite(access.decided_at), true)
                     AND COALESCE(isfinite(access.access_expires_at), true)
                     AND COALESCE(isfinite(artifact.deleted_at), true)) AS finite_timestamps,
                    CASE WHEN access.status = 'pending' THEN
                        access.decision_idempotency_digest IS NULL AND access.decision_request_digest IS NULL
                    ELSE octet_length(access.decision_idempotency_digest) = 32
                         AND octet_length(access.decision_request_digest) = 32 END AS decision_digests_valid";
pub(crate) const JOINS: &str = "             LEFT JOIN xshield.investigation_cases case_record
               ON case_record.tenant_id = access.tenant_id AND case_record.site_id = access.site_id
              AND case_record.case_id = access.case_id
             LEFT JOIN xshield.artifact_catalog artifact
               ON artifact.tenant_id = access.tenant_id AND artifact.site_id = access.site_id
              AND artifact.artifact_id = access.artifact_id
             LEFT JOIN xshield.audit_outbox requested
               ON requested.event_id = access.requested_event_id
              AND requested.tenant_id = access.tenant_id AND requested.site_id = access.site_id
              AND requested.aggregate_ref = access.access_request_id
              AND requested.event_type = 'evidence.access.requested'
             LEFT JOIN xshield.audit_outbox decided
               ON decided.event_id = access.decision_event_id
              AND decided.tenant_id = access.tenant_id AND decided.site_id = access.site_id
              AND decided.aggregate_ref = access.access_request_id
              AND decided.event_type = CASE WHEN access.status = 'denied' THEN 'evidence.access.denied'
                  WHEN access.status IN ('approved', 'expired', 'revoked') THEN 'evidence.access.approved' END";

impl PostgresIdentityStore {
    /// Reads one access request visible to its owner or an authorized reviewer.
    ///
    /// The caller authenticates subject and fixed tenant/site, and derives
    /// `can_review_all` only from the trusted server-side approver role. A false
    /// value restricts visibility to the requesting subject in the same SQL row.
    /// Missing, foreign-scope and non-owned requests return `None`; historical
    /// states, closed cases and deleted catalog records remain observable.
    ///
    /// No business row locks, mutations, content reads or outbox writes occur.
    /// SQL and lock waits have five-second limits. The caller bounds the entire
    /// operation, including pool acquisition, to 15 seconds and durably audits
    /// the result after this read transaction ends. Cancellation rolls back.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] before I/O for invalid subject text,
    /// or [`StoreError`] for database failures and corrupt visible metadata.
    pub async fn read_evidence_access_request(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        access: &EvidenceAccessRequestId,
        subject: &str,
        can_review_all: bool,
    ) -> Result<Option<EvidenceAccessInspection>, StoreError> {
        if !valid_subject(subject) {
            return Err(StoreError::InvalidCommand);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        let mut statement = sqlx::QueryBuilder::new("SELECT statement_timestamp() AS as_of, ");
        statement.push(PROJECTION).push(" FROM xshield.evidence_access_requests access ")
            .push(JOINS).push(" WHERE access.tenant_id = $1 AND access.site_id = $2 AND access.access_request_id = $3 AND ($5 OR access.requested_by = $4)");
        let row = statement
            .build()
            .bind(tenant.as_str())
            .bind(site.as_str())
            .bind(access.as_str())
            .bind(subject)
            .bind(can_review_all)
            .fetch_optional(&mut *tx)
            .await?;
        let inspection = row
            .as_ref()
            .map(|row| decode(row, tenant, site))
            .transpose()
            .map_err(|error| match error {
                StoreError::Database(_) => {
                    StoreError::CorruptData("evidence_access_inspection_row")
                }
                other => other,
            });
        tx.rollback().await?;
        inspection
    }
}

pub(crate) fn decode(
    row: &PgRow,
    tenant: &TenantId,
    site: &SiteId,
) -> Result<EvidenceAccessInspection, StoreError> {
    if !row.try_get::<bool, _>("finite_timestamps")?
        || !row.try_get::<bool, _>("decision_digests_valid")?
    {
        return Err(StoreError::CorruptData("evidence_access_inspection_record"));
    }
    let draft = EvidenceAccessRequestDraft::new(
        EvidenceAccessRequestId::parse(row.try_get::<&str, _>("access_request_id")?)
            .map_err(|_| StoreError::CorruptData("evidence_access_request_id"))?,
        tenant.clone(),
        site.clone(),
        CaseId::parse(row.try_get::<&str, _>("case_id")?)
            .map_err(|_| StoreError::CorruptData("evidence_access_case_id"))?,
        ArtifactId::parse(row.try_get::<&str, _>("artifact_id")?)
            .map_err(|_| StoreError::CorruptData("evidence_access_artifact_id"))?,
        row.try_get::<&str, _>("requested_by")?,
        match row.try_get::<&str, _>("access_kind")? {
            "sensitive_raw" => EvidenceAccessKind::SensitiveRaw,
            _ => return Err(StoreError::CorruptData("evidence_access_kind")),
        },
        row.try_get::<&str, _>("justification")?,
    )
    .map_err(|_| StoreError::CorruptData("evidence_access_request_record"))?;
    let record = EvidenceAccessInspection {
        as_of: supported_time(time(row, "as_of")?)?,
        access_request_id: draft.access_request_id().clone(),
        case_id: draft.case_id().clone(),
        artifact_id: draft.artifact_id().clone(),
        requested_by: draft.requested_by().to_owned(),
        access_kind: draft.kind(),
        justification: draft.justification().to_owned(),
        stored_status: match row.try_get::<&str, _>("status")? {
            "pending" => "pending",
            "approved" => "approved",
            "denied" => "denied",
            "expired" => "expired",
            "revoked" => "revoked",
            _ => return Err(StoreError::CorruptData("evidence_access_request_status")),
        },
        requested_at: supported_time(time(row, "requested_at")?)?,
        requested_event_id: EventId::parse(row.try_get::<&str, _>("requested_event_id")?)
            .map_err(|_| StoreError::CorruptData("evidence_access_requested_event"))?,
        decided_by: row.try_get("decided_by")?,
        decision_reason: row.try_get("decision_reason")?,
        decision_ttl_seconds: row
            .try_get::<Option<i32>, _>("decision_ttl_seconds")?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| StoreError::CorruptData("evidence_access_decision_ttl"))?,
        decision_event_id: row
            .try_get::<Option<&str>, _>("decision_event_id")?
            .map(EventId::parse)
            .transpose()
            .map_err(|_| StoreError::CorruptData("evidence_access_decision_event"))?,
        decided_at: optional_time(row, "decided_at")?,
        access_expires_at: optional_time(row, "access_expires_at")?,
        case_status: match row.try_get::<&str, _>("case_status")? {
            "open" => "open",
            "closed" => "closed",
            _ => return Err(StoreError::CorruptData("evidence_access_case_status")),
        },
        artifact_status: match row.try_get::<&str, _>("artifact_status")? {
            "active" => "active",
            "deleted" => "deleted",
            _ => return Err(StoreError::CorruptData("evidence_access_artifact_status")),
        },
        artifact_expires_at: supported_time(time(row, "artifact_expires_at")?)?,
    };
    if !valid_subject(&record.requested_by)
        || row.try_get::<&str, _>("owner_ref")? != record.requested_by
        || (record.artifact_status == "deleted") != optional_time(row, "deleted_at")?.is_some()
        || row.try_get::<Option<&str>, _>("request_outbox_id")?
            != Some(record.requested_event_id.as_str())
        || row.try_get::<Option<&str>, _>("decision_outbox_id")?
            != record.decision_event_id.as_ref().map(EventId::as_str)
    {
        return Err(StoreError::CorruptData(
            "evidence_access_inspection_linkage",
        ));
    }
    validate_decision(&record, tenant, site)?;
    Ok(record)
}

fn validate_decision(
    record: &EvidenceAccessInspection,
    tenant: &TenantId,
    site: &SiteId,
) -> Result<(), StoreError> {
    let corrupt = || StoreError::CorruptData("evidence_access_inspection_decision");
    if record.stored_status == "pending" {
        return if record.decided_by.is_none()
            && record.decision_reason.is_none()
            && record.decision_ttl_seconds.is_none()
            && record.decision_event_id.is_none()
            && record.decided_at.is_none()
            && record.access_expires_at.is_none()
        {
            Ok(())
        } else {
            Err(corrupt())
        };
    }
    let actor = record.decided_by.as_deref().ok_or_else(corrupt)?;
    let reason = record.decision_reason.as_deref().ok_or_else(corrupt)?;
    let event = record.decision_event_id.as_ref().ok_or_else(corrupt)?;
    let at = record.decided_at.ok_or_else(corrupt)?;
    if !valid_subject(actor) || actor == record.requested_by || event == &record.requested_event_id
    {
        return Err(corrupt());
    }
    if record.stored_status == "denied" {
        EvidenceAccessDecisionDraft::deny(
            tenant.clone(),
            site.clone(),
            record.access_request_id.clone(),
            actor,
            reason,
        )
        .map_err(|_| corrupt())?;
        if record.decision_ttl_seconds.is_some() || record.access_expires_at.is_some() {
            return Err(corrupt());
        }
    } else {
        let ttl = record.decision_ttl_seconds.ok_or_else(corrupt)?;
        EvidenceAccessDecisionDraft::approve(
            tenant.clone(),
            site.clone(),
            record.access_request_id.clone(),
            actor,
            reason,
            ttl,
            86_400,
        )
        .map_err(|_| corrupt())?;
        let expiry = record.access_expires_at.ok_or_else(corrupt)?;
        // The write path clamps a lease from one decision clock reading. It
        // does not guarantee wall-clock ordering between request and decision.
        if expiry <= at
            || expiry > record.artifact_expires_at
            || expiry - at > TimeDelta::seconds(i64::from(ttl))
        {
            return Err(corrupt());
        }
    }
    Ok(())
}

pub(crate) fn valid_subject(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn supported_time(value: DateTime<Utc>) -> Result<DateTime<Utc>, StoreError> {
    if value.timestamp() < 0
        || value.timestamp_nanos_opt().is_none()
        || value.timestamp_subsec_nanos() >= 1_000_000_000
    {
        return Err(StoreError::CorruptData("evidence_access_inspection_time"));
    }
    Ok(value)
}

fn optional_time(row: &PgRow, field: &'static str) -> Result<Option<DateTime<Utc>>, StoreError> {
    row.try_get::<Option<DateTime<Utc>>, _>(field)?
        .map(supported_time)
        .transpose()
}
