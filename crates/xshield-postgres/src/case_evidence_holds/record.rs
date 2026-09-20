use super::{CaseEvidenceHoldRecord, valid_text, valid_time};
use crate::{StoreError, investigation_case::lower_hex};
use chrono::{SecondsFormat, TimeDelta};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row, postgres::PgRow};
use xshield_core::domain::{ArtifactId, CaseId, EventId, SiteId, TenantId};

pub(super) fn decode_hold(row: &PgRow) -> Result<CaseEvidenceHoldRecord, StoreError> {
    let record = CaseEvidenceHoldRecord {
        created_event_id: EventId::parse(row.try_get::<&str, _>("created_event_id")?)
            .map_err(|_| StoreError::CorruptData("hold_event_id"))?,
        tenant_id: TenantId::parse(row.try_get::<&str, _>("tenant_id")?)
            .map_err(|_| StoreError::CorruptData("hold_tenant_id"))?,
        site_id: SiteId::parse(row.try_get::<&str, _>("site_id")?)
            .map_err(|_| StoreError::CorruptData("hold_site_id"))?,
        case_id: CaseId::parse(row.try_get::<&str, _>("case_id")?)
            .map_err(|_| StoreError::CorruptData("hold_case_id"))?,
        artifact_id: ArtifactId::parse(row.try_get::<&str, _>("artifact_id")?)
            .map_err(|_| StoreError::CorruptData("hold_artifact_id"))?,
        created_by: row.try_get("created_by")?,
        reason: row.try_get("reason")?,
        created_at: row.try_get("created_at")?,
        hold_until: row.try_get("hold_until")?,
        released_event_id: row
            .try_get::<Option<&str>, _>("released_event_id")?
            .map(|id| EventId::parse(id).map_err(|_| StoreError::CorruptData("hold_release_id")))
            .transpose()?,
        released_by: row.try_get("released_by")?,
        released_reason: row.try_get("released_reason")?,
        released_at: row.try_get("released_at")?,
    };
    let release_key: Option<Vec<u8>> = row.try_get("release_idempotency_digest")?;
    let release_digest: Option<Vec<u8>> = row.try_get("release_request_digest")?;
    let release_valid = match (
        &record.released_event_id,
        &record.released_by,
        &record.released_reason,
        record.released_at,
        release_key.as_deref(),
        release_digest.as_deref(),
    ) {
        (None, None, None, None, None, None) => true,
        (Some(id), Some(actor), Some(reason), Some(at), Some(key), Some(digest)) => {
            *id != record.created_event_id
                && valid_text(actor, 256)
                && valid_text(reason, 512)
                && valid_time(at)
                && key.len() == 32
                && digest.len() == 32
        }
        _ => false,
    };
    let lifetime = record.hold_until - record.created_at;
    if !valid_text(&record.created_by, 256)
        || !valid_text(&record.reason, 512)
        || !valid_time(record.created_at)
        || !valid_time(record.hold_until)
        || lifetime <= TimeDelta::zero()
        || lifetime > TimeDelta::days(super::CASE_EVIDENCE_HOLD_MAX_DAYS)
        || row.try_get::<Vec<u8>, _>("idempotency_digest")?.len() != 32
        || row.try_get::<Vec<u8>, _>("request_digest")?.len() != 32
        || !release_valid
    {
        return Err(StoreError::CorruptData("hold_record"));
    }
    Ok(record)
}

// Reconstruct the complete immutable fact on retries. Existence alone cannot
// prove that a successful transition was durably audited with these parameters.
pub(super) fn event(
    row: &PgRow,
    released: bool,
) -> Result<(EventId, &'static str, Value), StoreError> {
    let record = decode_hold(row)?;
    let (event_id, event_type, reason, actor, at, digest, causes) = if released {
        (
            record
                .released_event_id
                .as_ref()
                .ok_or(StoreError::CorruptData("hold_release_id"))?,
            "evidence.hold.released",
            "EVIDENCE_HOLD_RELEASED",
            record
                .released_by
                .as_deref()
                .ok_or(StoreError::CorruptData("hold_release_actor"))?,
            record
                .released_at
                .ok_or(StoreError::CorruptData("hold_release_at"))?,
            row.try_get::<Vec<u8>, _>("release_request_digest")?,
            vec![record.created_event_id.as_str()],
        )
    } else {
        (
            &record.created_event_id,
            "evidence.hold.created",
            "EVIDENCE_HOLD_CREATED",
            record.created_by.as_str(),
            record.created_at,
            row.try_get::<Vec<u8>, _>("request_digest")?,
            vec![],
        )
    };
    let digest: &[u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::CorruptData("hold_request_digest"))?;
    let trace = event_id.as_str().trim_start_matches("ev_").replace('-', "");
    let at = at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let envelope = json!({
        "schema_version":3, "event_id":event_id.as_str(), "event_type":event_type,
        "tenant_id":record.tenant_id.as_str(), "site_id":record.site_id.as_str(),
        "request_id":null, "trace_id":trace, "span_id":&trace[..16],
        "producer_id":"evidence-hold", "producer_boot_id":event_id.as_str(),
        "producer_seq":1, "request_seq":1, "occurred_at":at, "observed_at":at,
        "policy_revision":"evidence-hold-v1", "example_only":false,
        "evidence_refs":[record.artifact_id.as_str()], "cause_event_ids":causes,
        "payload":{"stage":"evidence_hold", "outcome":"PASS", "reason_code":reason,
            "proof_kind":"deterministic", "confidence":null, "confidence_status":"not_applicable",
            "hold_id":record.created_event_id.as_str(), "case_id":record.case_id.as_str(),
            "artifact_id":record.artifact_id.as_str(), "subject_ref":actor,
            "request_digest":lower_hex(digest),
            "hold_until":record.hold_until.to_rfc3339_opts(SecondsFormat::Millis, true)},
        "sensitivity":"RESTRICTED", "integrity":{"state":"pending", "previous_hash":null, "event_hash":null}
    });
    Ok((event_id.clone(), event_type, envelope))
}

pub(super) async fn insert_event(
    connection: &mut PgConnection,
    row: &PgRow,
    released: bool,
) -> Result<(), StoreError> {
    let (id, event_type, envelope) = event(row, released)?;
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
                 VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(id.as_str()).bind(row.try_get::<&str, _>("tenant_id")?)
        .bind(row.try_get::<&str, _>("site_id")?).bind(row.try_get::<&str, _>("artifact_id")?)
        .bind(event_type).bind(envelope).execute(connection).await?;
    Ok(())
}

pub(super) async fn verify_events(
    connection: &mut PgConnection,
    row: &PgRow,
) -> Result<(), StoreError> {
    for released in [false, true] {
        if released
            && row
                .try_get::<Option<&str>, _>("released_event_id")?
                .is_none()
        {
            continue;
        }
        let (id, event_type, envelope) = event(row, released)?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM xshield.audit_outbox WHERE event_id=$1 AND tenant_id=$2
             AND site_id=$3 AND aggregate_ref=$4 AND event_type=$5 AND envelope=$6)",
        )
        .bind(id.as_str())
        .bind(row.try_get::<&str, _>("tenant_id")?)
        .bind(row.try_get::<&str, _>("site_id")?)
        .bind(row.try_get::<&str, _>("artifact_id")?)
        .bind(event_type)
        .bind(envelope)
        .fetch_one(&mut *connection)
        .await?;
        if !exists {
            return Err(StoreError::CorruptData("hold_outbox"));
        }
    }
    Ok(())
}
