//! Bounded, authenticated request lookup before analytical publication.

use super::{
    AuditEventSummary, IndexRow, PublishError, PublisherConfig, RequestEventPosition,
    RequestEvents, RequestStageSummary, RequestSummary, RequestSummaryRow, hex,
    parse_authenticated_wire_event, validate_stage_summary,
};
use chrono::Utc;
use std::collections::BTreeMap;
use xshield_audit::{AuthenticatedJournalRecord, JournalError, JournalKey, LocalJournal};
use xshield_core::domain::{EventId, RequestId, SiteId, TenantId};

const MAX_SCAN_RECORDS: u64 = 1_000_000;
const MAX_SCAN_BYTES: u64 = 1_073_741_824;
const MAX_MATCHING_EVENTS: usize = 4_096;

/// Returns the redacted request aggregate from authenticated local records.
///
/// Scope comes from the authenticated control principal. A scan budget or
/// integrity failure returns an error instead of an ambiguous missing result.
///
/// # Errors
/// Returns [`PublishError`] for journal, schema, or budget failures.
pub fn query_local_request_summary(
    config: &PublisherConfig,
    key_id: &str,
    key: &JournalKey,
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
) -> Result<Option<RequestSummary>, PublishError> {
    let rows = local_rows(config, key_id, key, tenant_id, site_id, request_id)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let first = rows
        .iter()
        .map(|row| row.occurred_at)
        .min()
        .ok_or(PublishError::InvalidEvent)?;
    let last = rows
        .iter()
        .map(|row| row.occurred_at)
        .max()
        .ok_or(PublishError::InvalidEvent)?;
    let method = rows
        .iter()
        .filter(|row| {
            !row.method.is_empty()
                && (row.event_type == "request.accepted" || row.stage == "control_access")
        })
        .min_by_key(|row| (row.request_seq, &row.event_id))
        .map_or_else(String::new, |row| row.method.clone());
    let operation_id = rows
        .iter()
        .filter(|row| {
            !row.operation_id.is_empty()
                && matches!(
                    row.event_type.as_str(),
                    "request.accepted" | "stage.completed" | "stage.skipped"
                )
        })
        .min_by_key(|row| (row.request_seq, &row.event_id))
        .map_or_else(String::new, |row| row.operation_id.clone());
    let terminal = rows
        .iter()
        .filter(|row| row.is_terminal == 1)
        .max_by_key(|row| (row.request_seq, &row.event_id));
    let mut summary = RequestSummary::try_from(RequestSummaryRow {
        event_count: u64::try_from(rows.len()).map_err(|_| PublishError::InvalidEvent)?,
        first_occurred_at: first,
        last_occurred_at: last,
        method,
        operation_id,
        decision: terminal.map_or_else(String::new, |row| row.outcome.clone()),
        reason_code: terminal.map_or_else(String::new, |row| row.reason_code.clone()),
        status: terminal.and_then(|row| row.http_status),
        origin_state: terminal.map_or_else(String::new, |row| row.origin_state.clone()),
        duration_us: terminal.map_or(0, |row| row.duration_us),
        forwarded: u8::from(
            rows.iter()
                .any(|row| row.event_type == "origin.forward_intent"),
        ),
        terminal: u8::from(terminal.is_some()),
    })?;
    let mut stages: BTreeMap<String, RequestStageSummary> = BTreeMap::new();
    for row in rows.iter().filter(|row| !row.stage.is_empty()) {
        let stage = stages
            .entry(row.stage.clone())
            .or_insert_with(|| RequestStageSummary {
                stage: row.stage.clone(),
                outcome: row.outcome.clone(),
                reason_code: row.reason_code.clone(),
                proof_kind: row.proof_kind.clone(),
                confidence: row.confidence,
                confidence_status: row.confidence_status.clone(),
                first_request_seq: row.request_seq,
                last_request_seq: row.request_seq,
                duration_us: row.duration_us,
                event_count: 0,
            });
        stage.first_request_seq = stage.first_request_seq.min(row.request_seq);
        stage.event_count = stage
            .event_count
            .checked_add(1)
            .ok_or(PublishError::InvalidEvent)?;
        if row.request_seq >= stage.last_request_seq {
            stage.last_request_seq = row.request_seq;
            stage.outcome.clone_from(&row.outcome);
            stage.reason_code.clone_from(&row.reason_code);
            stage.proof_kind.clone_from(&row.proof_kind);
            stage.confidence = row.confidence;
            stage.confidence_status.clone_from(&row.confidence_status);
            stage.duration_us = row.duration_us;
        }
    }
    summary.stages = stages.into_values().collect();
    summary.stages.sort_by(|left, right| {
        (left.first_request_seq, &left.stage).cmp(&(right.first_request_seq, &right.stage))
    });
    for stage in &summary.stages {
        validate_stage_summary(stage)?;
    }
    Ok(Some(summary))
}

/// Returns a request timeline from authenticated local records, with the same
/// keyset position and redaction shape as the analytical query.
///
/// # Errors
/// Returns [`PublishError`] for journal, schema, or budget failures.
// The arguments mirror `query_request_events` plus the journal key material;
// bundling them would only move the same fields into a single-use struct.
#[allow(clippy::too_many_arguments)]
pub fn query_local_request_events(
    config: &PublisherConfig,
    key_id: &str,
    key: &JournalKey,
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
    after: Option<&RequestEventPosition>,
    limit: u16,
) -> Result<Option<RequestEvents>, PublishError> {
    if limit == 0 {
        return Err(PublishError::InvalidConfig);
    }
    let rows = local_rows(config, key_id, key, tenant_id, site_id, request_id)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut events = rows
        .into_iter()
        .filter(|row| {
            after.is_none_or(|position| {
                (row.request_seq, row.event_id.as_str())
                    > (position.request_seq(), position.event_id().as_str())
            })
        })
        .map(|row| AuditEventSummary {
            event_id: row.event_id,
            event_type: row.event_type,
            stage: row.stage,
            outcome: row.outcome,
            reason_code: row.reason_code,
            proof_kind: row.proof_kind,
            confidence: row.confidence,
            confidence_status: row.confidence_status,
            occurred_at: row.occurred_at,
            request_seq: row.request_seq,
            duration_us: row.duration_us,
            policy_revision: row.policy_revision,
            model_revision: row.model_revision,
            model_call_id: (!row.model_call_id.is_empty()).then_some(row.model_call_id),
            evidence_refs: row.evidence_refs,
            cause_event_ids: row.cause_event_ids,
            sensitivity: row.sensitivity,
        })
        .collect::<Vec<_>>();
    events.sort_by(|left, right| {
        (left.request_seq, &left.event_id).cmp(&(right.request_seq, &right.event_id))
    });
    let truncated = events.len() > usize::from(limit);
    events.truncate(usize::from(limit));
    let next_position = if truncated {
        let row = events.last().ok_or(PublishError::InvalidEvent)?;
        Some(RequestEventPosition::new(
            row.request_seq,
            EventId::parse(&row.event_id).map_err(|_| PublishError::InvalidEvent)?,
        )?)
    } else {
        None
    };
    Ok(Some(RequestEvents {
        events,
        truncated,
        next_position,
    }))
}

fn local_rows(
    config: &PublisherConfig,
    key_id: &str,
    key: &JournalKey,
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
) -> Result<Vec<IndexRow>, PublishError> {
    let mut rows = BTreeMap::<String, IndexRow>::new();
    let now = Utc::now();
    LocalJournal::visit_committed_records(
        &config.journal_directory,
        key_id,
        key,
        MAX_SCAN_RECORDS,
        MAX_SCAN_BYTES,
        |record| {
            if let Some(row) = matching_row(config, record, tenant_id, site_id, request_id)
                .map_err(|_| JournalError::InvalidEvent)?
                && row.retention_expires_at > now
            {
                if rows.len() >= MAX_MATCHING_EVENTS {
                    return Err(JournalError::RecordLimitExceeded);
                }
                match rows.entry(row.event_id.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(row);
                    }
                    std::collections::btree_map::Entry::Occupied(entry) => {
                        if entry.get().event_hash != row.event_hash {
                            return Err(JournalError::InvalidEvent);
                        }
                    }
                }
            }
            Ok(())
        },
    )?;
    Ok(rows.into_values().collect())
}

fn matching_row(
    config: &PublisherConfig,
    record: &AuthenticatedJournalRecord,
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
) -> Result<Option<IndexRow>, PublishError> {
    let event = parse_authenticated_wire_event(
        record.plaintext(),
        record.event_id(),
        record.producer_sequence(),
        record.producer_boot_id(),
    )?;
    if event.tenant_id != tenant_id.as_str()
        || event.site_id != site_id.as_str()
        || event.request_id.as_deref() != Some(request_id.as_str())
    {
        return Ok(None);
    }
    let digest = hex(record.plaintext_digest());
    let mut row = IndexRow::parse(
        record.plaintext(),
        record.event_id(),
        record.producer_sequence(),
        record.producer_boot_id(),
        digest,
        config.metadata_retention,
    )?;
    row.payload_json.clear();
    Ok(Some(row))
}
