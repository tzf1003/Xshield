//! Publishes authenticated audit journal segments to the analytical index.

#![warn(missing_docs)]

use chrono::{DateTime, TimeDelta, Utc};
use clickhouse::{Client, Row, sql::Identifier};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    fs::{File, OpenOptions, TryLockError},
    io::{self, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::{Uuid, Version};
use xshield_audit::{
    JournalError, JournalKey, SealVerifyingKey, SealedSegmentReader, verify_sealed_segment,
};
use xshield_core::domain::{EventId, ModelCallId, PolicyRevision, RequestId, SiteId, TenantId};

pub mod calibration_audit;
pub mod calibration_evaluator;
mod calibration_vault_reader;
mod control_audit;
pub mod model_eval;
mod outbox;
mod search;
pub use calibration_vault_reader::{
    CalibrationEvidenceContent, CalibrationEvidenceReadError, LocalCalibrationEvidenceReader,
};
pub use outbox::{
    OutboxPublishReport, OutboxPublisherConfig, publish_calibration_outbox_batch,
    publish_case_outbox_batch, publish_evidence_access_outbox_batch,
    publish_evidence_catalog_outbox_batch, publish_evidence_retention_outbox_batch,
    publish_grant_outbox_batch, publish_identity_outbox_batch, publish_response_grant_outbox_batch,
    publish_share_grant_outbox_batch,
};
pub use search::{
    AuditSearchResult, MODEL_CALL_LIST_LIMIT_MAX, ModelCallEventSummary, ModelCallListPlan,
    ModelCallListPlanError, ModelCallListPosition, ModelCallListResult, ModelCallListSummary,
    ModelCallSummary, SearchEventSummary, SearchPosition, query_audit_events, query_model_call,
    query_model_calls,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const MANIFEST_BYTES_MAX: u64 = 1024;
const LIST_ITEMS_MAX: usize = 256;
const NAME_BYTES_MAX: usize = 128;
const MAX_METADATA_RETENTION_DAYS: u16 = 3_650;
const MAX_REQUEST_STAGES: usize = 128;
// Historical rows predate the indexed column. Only model-derived events may
// recover their redacted link from the already-indexed payload; result rows
// still pass through `ModelCallId::parse` before reaching a caller.
const MODEL_CALL_ID_PROJECTION: &str = "nullIf(if(proof_kind = 'model',if(model_call_id = '',JSONExtractString(payload_json,'model_call_id'),model_call_id),''),'') AS model_call_id";

/// Immutable publication settings for one analytical destination.
#[derive(Clone, Debug)]
pub struct PublisherConfig {
    journal_directory: PathBuf,
    manifest_directory: PathBuf,
    checkpoint_directory: PathBuf,
    target_id: String,
    table: String,
    active_view: String,
    metadata_retention_days: u16,
    metadata_retention: TimeDelta,
    max_segment_bytes: u64,
}

impl PublisherConfig {
    /// Validates paths, target identity, table name, retention, and the segment memory ceiling.
    ///
    /// # Errors
    /// Returns [`PublishError::InvalidConfig`] for an unsafe scalar setting.
    pub fn new(
        journal_directory: impl Into<PathBuf>,
        manifest_directory: impl Into<PathBuf>,
        checkpoint_directory: impl Into<PathBuf>,
        target_id: impl Into<String>,
        table: impl Into<String>,
        metadata_retention_days: u16,
        max_segment_bytes: u64,
    ) -> Result<Self, PublishError> {
        let target_id = target_id.into();
        let table = table.into();
        let active_view = format!("{table}_active");
        let metadata_retention = TimeDelta::try_days(i64::from(metadata_retention_days))
            .filter(|_| (1..=MAX_METADATA_RETENTION_DAYS).contains(&metadata_retention_days))
            .ok_or(PublishError::InvalidConfig)?;
        if !valid_name(&target_id)
            || !valid_name(&table)
            || !valid_name(&active_view)
            || max_segment_bytes == 0
        {
            return Err(PublishError::InvalidConfig);
        }
        Ok(Self {
            journal_directory: journal_directory.into(),
            manifest_directory: manifest_directory.into(),
            checkpoint_directory: checkpoint_directory.into(),
            target_id,
            table,
            active_view,
            metadata_retention_days,
            metadata_retention,
            max_segment_bytes,
        })
    }
}

/// Result of one finite publisher pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReport {
    /// Segments newly acknowledged by `ClickHouse` and checkpointed locally.
    pub published_segments: usize,
    /// Events newly submitted during this pass.
    pub published_events: u64,
    /// Sealed segments already covered by an exact checkpoint.
    pub checkpointed_segments: usize,
    /// Producer boot ID of the latest contiguous checkpoint, if any.
    pub watermark_producer_boot_id: Option<String>,
    /// Final producer sequence within the watermark segment.
    pub watermark_producer_sequence: u64,
}

/// Latest contiguous segment represented by the analytical index.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IndexWatermark {
    /// Producer boot ID committed by the sealed segment.
    pub producer_boot_id: String,
    /// Final producer-local sequence in that segment.
    pub producer_sequence: u64,
}

/// Authenticated local view of journal-to-index publication state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicationHealth {
    /// Non-secret operator identity for the selected analytical destination.
    pub target_id: String,
    /// Escaped single-table destination bound into every checkpoint.
    pub table: String,
    /// UTC observation time for this snapshot.
    pub as_of: String,
    /// Configured query-visible metadata lifetime.
    pub metadata_retention_days: u16,
    /// Number of immutable closed journal segments.
    pub closed_segments: usize,
    /// Total bytes occupied by immutable closed journal segments.
    pub closed_segment_bytes: u64,
    /// Number of segments covered by exact destination checkpoints.
    pub published_segments: usize,
    /// Number of closed segments not yet covered by a checkpoint.
    pub pending_segments: usize,
    /// Pending segments for which no signed manifest exists yet.
    pub unsealed_segments: usize,
    /// True when a published segment appears after an unpublished segment.
    pub has_gaps: bool,
    /// Latest continuously published segment, excluding any later island.
    pub index_watermark: Option<IndexWatermark>,
}

/// Redacted analytical event returned by the request timeline query.
#[derive(Clone, Debug, Deserialize, Serialize, Row)]
pub struct AuditEventSummary {
    /// Stable immutable event identity.
    pub event_id: String,
    /// Versioned event kind.
    pub event_type: String,
    /// Pipeline stage extracted by the publisher adapter.
    pub stage: String,
    /// Stable stage outcome.
    pub outcome: String,
    /// Stable decision or failure reason.
    pub reason_code: String,
    /// Deterministic, model, agent, or client-claimed proof class.
    pub proof_kind: String,
    /// Provider confidence when the proof contract permits one.
    pub confidence: Option<f64>,
    /// Explicit confidence availability state.
    pub confidence_status: String,
    /// Authenticated producer occurrence time.
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    pub occurred_at: DateTime<Utc>,
    /// Request-local event order.
    pub request_seq: u32,
    /// Stage duration in microseconds when available.
    pub duration_us: u64,
    /// Policy revision used for the recorded decision.
    pub policy_revision: String,
    /// Model revision when the event was model-derived.
    pub model_revision: String,
    /// Exact model-call reference when the event was model-derived.
    ///
    /// This is an investigation link only. It neither grants evidence access
    /// nor substitutes for the independently authorized model-call lookup.
    pub model_call_id: Option<String>,
    /// Opaque evidence references; content requires separate authorization.
    pub evidence_refs: Vec<String>,
    /// Earlier event identities that directly caused this event.
    pub cause_event_ids: Vec<String>,
    /// Data classification for downstream redaction decisions.
    pub sensitivity: String,
}

/// One bounded request-timeline result from the active analytical view.
#[derive(Clone, Debug, Serialize)]
pub struct RequestEvents {
    /// Events ordered by request sequence and stable event identity.
    pub events: Vec<AuditEventSummary>,
    /// True when additional rows exist beyond this bounded result.
    pub truncated: bool,
    /// Validated last row used to continue a truncated page.
    #[serde(skip)]
    pub next_position: Option<RequestEventPosition>,
}

/// Redacted aggregate facts for one request in the active analytical view.
#[derive(Clone, Debug, Serialize)]
pub struct RequestSummary {
    /// Number of retained, deduplicated events represented by this summary.
    pub event_count: u64,
    /// First authenticated producer occurrence time.
    pub first_occurred_at: DateTime<Utc>,
    /// Latest authenticated producer occurrence time.
    pub last_occurred_at: DateTime<Utc>,
    /// Validated HTTP method when a retained event supplied it.
    pub method: Option<String>,
    /// Validated operation identifier when available.
    pub operation_id: Option<String>,
    /// Terminal request decision when a terminal event is retained.
    pub decision: Option<String>,
    /// Terminal stable reason code when a terminal event is retained.
    pub reason_code: Option<String>,
    /// Terminal HTTP status when available.
    pub status: Option<u16>,
    /// Terminal origin state when available.
    pub origin_state: Option<String>,
    /// Terminal duration in microseconds when available.
    pub duration_us: Option<u64>,
    /// Whether a validated origin-forward intent is retained.
    pub forwarded: bool,
    /// Whether a terminal request event is retained.
    pub terminal: bool,
    /// Whether the terminal event confirms an origin response.
    pub business_result_confirmed: bool,
    /// Observed stage aggregates ordered by their first request sequence.
    pub stages: Vec<RequestStageSummary>,
}

/// Latest redacted outcome and ordering facts for one observed request stage.
#[derive(Clone, Debug, Deserialize, Serialize, Row)]
pub struct RequestStageSummary {
    /// Validated stage identifier.
    pub stage: String,
    /// Latest stage outcome.
    pub outcome: String,
    /// Latest stable stage reason.
    pub reason_code: String,
    /// Latest stage proof class.
    pub proof_kind: String,
    /// Latest provider confidence when permitted by the proof contract.
    pub confidence: Option<f64>,
    /// Explicit confidence availability state.
    pub confidence_status: String,
    /// First request-local sequence observed for this stage.
    pub first_request_seq: u32,
    /// Latest request-local sequence observed for this stage.
    pub last_request_seq: u32,
    /// Latest stage duration in microseconds.
    pub duration_us: u64,
    /// Number of retained events associated with this stage.
    pub event_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Row)]
struct RequestSummaryRow {
    event_count: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    first_occurred_at: DateTime<Utc>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    last_occurred_at: DateTime<Utc>,
    method: String,
    operation_id: String,
    decision: String,
    reason_code: String,
    status: Option<u16>,
    origin_state: String,
    duration_us: u64,
    forwarded: u8,
    terminal: u8,
}

/// Reads one scoped request aggregate from the deduplicated retention-aware view.
///
/// The result contains only publisher-validated redacted columns. Tenant and site
/// are supplied from authenticated management scope, and an absent group returns
/// `None` without consulting payload JSON.
///
/// # Errors
/// Returns [`PublishError::ClickHouse`] when the index is unavailable and
/// [`PublishError::InvalidEvent`] when an analytical row violates its contract.
pub async fn query_request_summary(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
) -> Result<Option<RequestSummary>, PublishError> {
    // Independent outbox producers may describe a future target operation.
    // Only request-context events can establish the original method/operation.
    let row = client
        .query(
            "SELECT count() AS event_count,min(occurred_at) AS first_occurred_at,\
             max(occurred_at) AS last_occurred_at,\
             argMinIf(method,tuple(request_seq,event_id),method != '' AND \
               (event_type = 'request.accepted' OR stage = 'control_access')) AS method,\
             argMinIf(operation_id,tuple(request_seq,event_id),operation_id != '' AND \
               event_type IN ('request.accepted','stage.completed','stage.skipped')) AS operation_id,\
             argMaxIf(outcome,tuple(request_seq,event_id),is_terminal = 1) AS decision,\
             argMaxIf(reason_code,tuple(request_seq,event_id),is_terminal = 1) AS reason_code,\
             argMaxIf(http_status,tuple(request_seq,event_id),is_terminal = 1) AS status,\
             argMaxIf(origin_state,tuple(request_seq,event_id),is_terminal = 1) AS origin_state,\
             argMaxIf(duration_us,tuple(request_seq,event_id),is_terminal = 1) AS duration_us,\
             toUInt8(countIf(event_type = 'origin.forward_intent') > 0) AS forwarded,\
             max(is_terminal) AS terminal FROM ? WHERE tenant_id = ? AND site_id = ? \
             AND request_id = ? GROUP BY request_id LIMIT 1",
        )
        .bind(Identifier(&config.active_view))
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(request_id.as_str())
        .with_setting("max_execution_time", "2")
        .with_setting("max_rows_to_read", "1000000")
        .fetch_optional::<RequestSummaryRow>()
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut summary = RequestSummary::try_from(row)?;
    summary.stages = query_request_stages(config, client, tenant_id, site_id, request_id).await?;
    Ok(Some(summary))
}

async fn query_request_stages(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
) -> Result<Vec<RequestStageSummary>, PublishError> {
    // argMax skips bare NULLs; the tuple keeps confidence and its availability
    // status on the same latest event even when that confidence is NULL.
    let mut stages = client
        .query(
            "SELECT stage,argMax(outcome,tuple(request_seq,event_id)) AS outcome,\
             argMax(reason_code,tuple(request_seq,event_id)) AS reason_code,\
             argMax(proof_kind,tuple(request_seq,event_id)) AS proof_kind,\
             argMax(tuple(confidence),tuple(request_seq,event_id)).1 AS confidence,\
             argMax(confidence_status,tuple(request_seq,event_id)) AS confidence_status,\
             min(request_seq) AS first_request_seq,max(request_seq) AS last_request_seq,\
             argMax(duration_us,tuple(request_seq,event_id)) AS duration_us,\
             count() AS event_count FROM ? WHERE tenant_id = ? AND site_id = ? \
             AND request_id = ? AND stage != '' GROUP BY stage \
             ORDER BY first_request_seq,stage LIMIT ?",
        )
        .bind(Identifier(&config.active_view))
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(request_id.as_str())
        .bind(MAX_REQUEST_STAGES + 1)
        .with_setting("max_execution_time", "2")
        .with_setting("max_rows_to_read", "1000000")
        .fetch_all::<RequestStageSummary>()
        .await?;
    if stages.len() > MAX_REQUEST_STAGES {
        return Err(PublishError::InvalidEvent);
    }
    for stage in &stages {
        validate_stage_summary(stage)?;
    }
    stages.shrink_to_fit();
    Ok(stages)
}

fn validate_stage_summary(stage: &RequestStageSummary) -> Result<(), PublishError> {
    if !valid_name(&stage.stage)
        || !matches!(
            stage.outcome.as_str(),
            "PASS" | "DENY" | "UNKNOWN" | "ERROR" | "SKIPPED" | "CANCELLED"
        )
        || !valid_name(&stage.reason_code)
        || !matches!(
            stage.proof_kind.as_str(),
            "deterministic" | "model" | "observation" | "none"
        )
        || !valid_confidence(
            &stage.proof_kind,
            &stage.outcome,
            stage.confidence,
            &stage.confidence_status,
        )
        || stage.first_request_seq == 0
        || stage.last_request_seq < stage.first_request_seq
        || stage.event_count == 0
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(())
}

impl TryFrom<RequestSummaryRow> for RequestSummary {
    type Error = PublishError;

    fn try_from(row: RequestSummaryRow) -> Result<Self, Self::Error> {
        let method = optional_validated(row.method, valid_method)?;
        let operation_id = optional_validated(row.operation_id, valid_name)?;
        let decision = optional_validated(row.decision, |value| {
            matches!(value, "ALLOW" | "DENY" | "UNKNOWN")
        })?;
        let reason_code = optional_validated(row.reason_code, valid_name)?;
        let origin_state = optional_validated(row.origin_state, |value| {
            matches!(value, "not_sent" | "unknown" | "response_received")
        })?;
        if row.event_count == 0
            || row.forwarded > 1
            || row.terminal > 1
            || row
                .status
                .is_some_and(|status| !(100..=599).contains(&status))
            || (row.terminal == 0
                && (decision.is_some()
                    || reason_code.is_some()
                    || row.status.is_some()
                    || origin_state.is_some()
                    || row.duration_us != 0))
        {
            return Err(PublishError::InvalidEvent);
        }
        let terminal = row.terminal == 1;
        Ok(Self {
            event_count: row.event_count,
            first_occurred_at: row.first_occurred_at,
            last_occurred_at: row.last_occurred_at,
            method,
            operation_id,
            decision,
            reason_code,
            status: row.status,
            business_result_confirmed: terminal
                && origin_state.as_deref() == Some("response_received"),
            origin_state,
            duration_us: terminal.then_some(row.duration_us),
            forwarded: row.forwarded == 1,
            terminal,
            stages: Vec::new(),
        })
    }
}

fn optional_validated(
    value: String,
    predicate: impl FnOnce(&str) -> bool,
) -> Result<Option<String>, PublishError> {
    if value.is_empty() {
        Ok(None)
    } else if predicate(&value) {
        Ok(Some(value))
    } else {
        Err(PublishError::InvalidEvent)
    }
}

/// Stable keyset position for one request-event page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestEventPosition {
    request_seq: u32,
    event_id: EventId,
}

impl RequestEventPosition {
    /// Builds a position from already validated analytical row fields.
    ///
    /// # Errors
    /// Returns [`PublishError::InvalidEvent`] when the sequence is zero.
    pub fn new(request_seq: u32, event_id: EventId) -> Result<Self, PublishError> {
        if request_seq == 0 {
            return Err(PublishError::InvalidEvent);
        }
        Ok(Self {
            request_seq,
            event_id,
        })
    }

    /// Returns the request-local sequence component.
    #[must_use]
    pub const fn request_seq(&self) -> u32 {
        self.request_seq
    }

    /// Returns the stable event identity component.
    #[must_use]
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }
}

/// Reads a redacted request timeline from the deduplicated, retention-aware view.
///
/// Tenant and site come from the authenticated management scope. The query has
/// fixed execution and scan ceilings and returns at most `limit` rows.
///
/// # Errors
/// Returns [`PublishError::InvalidConfig`] for a zero limit and
/// [`PublishError::ClickHouse`] when the analytical index is unavailable.
pub async fn query_request_events(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
    after: Option<&RequestEventPosition>,
    limit: u16,
) -> Result<RequestEvents, PublishError> {
    if limit == 0 {
        return Err(PublishError::InvalidConfig);
    }
    let fetch_limit = u64::from(limit) + 1;
    let query_sql = match after {
        Some(_) => format!(
            "SELECT event_id,event_type,stage,outcome,reason_code,proof_kind,confidence,\
             confidence_status,occurred_at,request_seq,duration_us,policy_revision,\
             model_revision,{MODEL_CALL_ID_PROJECTION},\
             evidence_refs,cause_event_ids,sensitivity FROM ? \
             WHERE tenant_id = ? AND site_id = ? AND request_id = ? \
             AND (request_seq > ? OR (request_seq = ? AND event_id > ?)) \
             ORDER BY request_seq,event_id LIMIT ?"
        ),
        None => format!(
            "SELECT event_id,event_type,stage,outcome,reason_code,proof_kind,confidence,\
             confidence_status,occurred_at,request_seq,duration_us,policy_revision,\
             model_revision,{MODEL_CALL_ID_PROJECTION},\
             evidence_refs,cause_event_ids,sensitivity FROM ? \
             WHERE tenant_id = ? AND site_id = ? AND request_id = ? \
             ORDER BY request_seq,event_id LIMIT ?"
        ),
    };
    let query = match after {
        Some(position) => client
            .query(&query_sql)
            .bind(Identifier(&config.active_view))
            .bind(tenant_id.as_str())
            .bind(site_id.as_str())
            .bind(request_id.as_str())
            .bind(position.request_seq())
            .bind(position.request_seq())
            .bind(position.event_id().as_str())
            .bind(fetch_limit),
        None => client
            .query(&query_sql)
            .bind(Identifier(&config.active_view))
            .bind(tenant_id.as_str())
            .bind(site_id.as_str())
            .bind(request_id.as_str())
            .bind(fetch_limit),
    };
    let mut events = query
        .with_setting("max_execution_time", "2")
        .with_setting("max_rows_to_read", "1000000")
        .fetch_all::<AuditEventSummary>()
        .await?;
    for event in &events {
        if event
            .model_call_id
            .as_deref()
            .is_some_and(|value| ModelCallId::parse(value).is_err())
            || (event.proof_kind == "model") != event.model_call_id.is_some()
            || (matches!(
                event.event_type.as_str(),
                "stage.completed" | "stage.skipped"
            ) && (!valid_confidence(
                &event.proof_kind,
                &event.outcome,
                event.confidence,
                &event.confidence_status,
            ) || (!event.model_revision.is_empty()
                && (event.proof_kind != "model" || !valid_name(&event.model_revision)))))
        {
            return Err(PublishError::InvalidEvent);
        }
    }
    let truncated = events.len() > usize::from(limit);
    events.truncate(usize::from(limit));
    let next_position = if truncated {
        let last = events.last().ok_or(PublishError::InvalidEvent)?;
        Some(RequestEventPosition::new(
            last.request_seq,
            EventId::parse(&last.event_id).map_err(|_| PublishError::InvalidEvent)?,
        )?)
    } else {
        None
    };
    Ok(RequestEvents {
        events,
        truncated,
        next_position,
    })
}

/// Inspects sealed segments and exact checkpoints without querying `ClickHouse`.
///
/// Segment signatures, journal authentication, and checkpoint bindings are
/// verified before they affect the returned counters. A missing manifest is a
/// visible pending state; malformed or mismatched evidence is an error.
///
/// # Errors
/// Returns [`PublishError`] for unsafe paths, corrupt evidence, invalid
/// checkpoint bindings, or arithmetic overflow.
pub fn inspect_publication_health(
    config: &PublisherConfig,
    journal_key_id: &str,
    journal_key: &JournalKey,
    seal_key: &SealVerifyingKey,
) -> Result<PublicationHealth, PublishError> {
    prepare_private_directory(&config.journal_directory, false)?;
    prepare_private_directory(&config.manifest_directory, false)?;
    let checkpoint_directory_exists = match fs::symlink_metadata(&config.checkpoint_directory) {
        Ok(_) => {
            prepare_private_directory(&config.checkpoint_directory, false)?;
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let paths = closed_segment_paths(&config.journal_directory)?;
    let mut health = PublicationHealth {
        target_id: config.target_id.clone(),
        table: config.table.clone(),
        as_of: Utc::now().to_rfc3339(),
        metadata_retention_days: config.metadata_retention_days,
        closed_segments: paths.len(),
        closed_segment_bytes: 0,
        published_segments: 0,
        pending_segments: 0,
        unsealed_segments: 0,
        has_gaps: false,
        index_watermark: None,
    };
    let mut continuous = true;
    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.len() > config.max_segment_bytes {
            return Err(PublishError::SegmentLimitExceeded);
        }
        health.closed_segment_bytes = health
            .closed_segment_bytes
            .checked_add(metadata.len())
            .ok_or(PublishError::InvalidEvent)?;
        let boot_id = segment_boot_id(&path)?;
        let manifest_path = config
            .manifest_directory
            .join(format!("segment-{boot_id}.xjs"));
        let manifest = match fs::symlink_metadata(&manifest_path) {
            Ok(_) => read_private_bounded(&manifest_path, MANIFEST_BYTES_MAX)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                health.pending_segments += 1;
                health.unsealed_segments += 1;
                continuous = false;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let segment =
            verify_sealed_segment(&path, journal_key_id, journal_key, &manifest, seal_key)?;
        let checkpoint = Checkpoint::from_segment(&config.target_id, &config.table, &segment);
        let published = checkpoint_directory_exists
            && checkpoint_matches(&config.checkpoint_directory, &checkpoint)?;
        if published {
            health.published_segments += 1;
            if continuous {
                health.index_watermark = Some(IndexWatermark {
                    producer_boot_id: segment.producer_boot_id,
                    producer_sequence: segment.final_sequence,
                });
            } else {
                health.has_gaps = true;
            }
        } else {
            health.pending_segments += 1;
            continuous = false;
        }
    }
    Ok(health)
}

/// Publishes every closed segment in filename order using at-least-once delivery.
///
/// Every segment and manifest is authenticated before use. Existing event IDs are
/// compared by canonical plaintext digest; a mismatch terminates the pass. The
/// durable checkpoint is created only after `ClickHouse` acknowledges the insert.
///
/// # Errors
/// Returns [`PublishError`] for unsafe storage, invalid events, integrity
/// conflicts, `ClickHouse` failure, or checkpoint durability failure.
pub async fn publish_sealed_segments(
    config: &PublisherConfig,
    client: &Client,
    journal_key_id: &str,
    journal_key: &JournalKey,
    seal_key: &SealVerifyingKey,
) -> Result<PublishReport, PublishError> {
    prepare_private_directory(&config.journal_directory, false)?;
    prepare_private_directory(&config.manifest_directory, false)?;
    prepare_private_directory(&config.checkpoint_directory, true)?;
    let _lock = lock_publisher(&config.checkpoint_directory)?;
    let paths = closed_segment_paths(&config.journal_directory)?;
    let mut report = PublishReport {
        published_segments: 0,
        published_events: 0,
        checkpointed_segments: 0,
        watermark_producer_boot_id: None,
        watermark_producer_sequence: 0,
    };

    // ponytail: a linear pass makes the first missing/corrupt segment an explicit
    // gap; add a signed segment catalog only when retained-file scans are measured.
    for path in paths {
        let boot_id = segment_boot_id(&path)?;
        let manifest_path = config
            .manifest_directory
            .join(format!("segment-{boot_id}.xjs"));
        let manifest = read_private_bounded(&manifest_path, MANIFEST_BYTES_MAX)?;
        let mut reader = SealedSegmentReader::open(
            &path,
            config.max_segment_bytes,
            journal_key_id,
            journal_key,
            &manifest,
            seal_key,
        )?;
        let segment = reader.segment().clone();
        let checkpoint = Checkpoint::from_segment(&config.target_id, &config.table, &segment);
        if checkpoint_matches(&config.checkpoint_directory, &checkpoint)? {
            report.checkpointed_segments += 1;
            set_watermark(&mut report, &checkpoint);
            continue;
        }

        let mut rows = Vec::with_capacity(
            usize::try_from(segment.record_count).map_err(|_| PublishError::InvalidEvent)?,
        );
        let mut local_digests = BTreeMap::new();
        while let Some(record) = reader.next_record()? {
            let digest = hex(record.plaintext_digest());
            if let Some(existing) =
                local_digests.insert(record.event_id().as_str().to_owned(), digest.clone())
                && existing != digest
            {
                return Err(PublishError::IntegrityConflict);
            }
            rows.push(IndexRow::parse(
                record.plaintext(),
                record.event_id(),
                record.producer_sequence(),
                &segment.producer_boot_id,
                digest,
                config.metadata_retention,
            )?);
        }
        reject_remote_conflicts(client, &config.table, &local_digests).await?;
        insert_rows(client, &config.table, &checkpoint.segment_digest, &rows).await?;
        reject_remote_conflicts(client, &config.table, &local_digests).await?;
        write_checkpoint(&config.checkpoint_directory, &checkpoint)?;
        report.published_segments += 1;
        report.published_events = report
            .published_events
            .checked_add(segment.record_count)
            .ok_or(PublishError::InvalidEvent)?;
        set_watermark(&mut report, &checkpoint);
    }
    Ok(report)
}

fn set_watermark(report: &mut PublishReport, checkpoint: &Checkpoint) {
    report.watermark_producer_boot_id = Some(checkpoint.producer_boot_id.clone());
    report.watermark_producer_sequence = checkpoint.final_sequence;
}

#[derive(Clone, Debug, Deserialize, Serialize, Row)]
struct IndexRow {
    tenant_id: String,
    site_id: String,
    request_id: String,
    trace_id: [u8; 32],
    event_id: String,
    event_type: String,
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    confidence: Option<f64>,
    confidence_status: String,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    occurred_at: DateTime<Utc>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    observed_at: DateTime<Utc>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    retention_expires_at: DateTime<Utc>,
    producer_id: String,
    producer_boot_id: String,
    producer_seq: u64,
    request_seq: u32,
    method: String,
    operation_id: String,
    origin_state: String,
    http_status: Option<u16>,
    is_terminal: u8,
    duration_us: u64,
    policy_revision: String,
    model_revision: String,
    // `clickhouse::Row` encodes this struct in field order for `INSERT INTO`
    // without an explicit column list. Keep this next to `model_revision`,
    // matching both the CREATE schema and expand-contract ALTER placement.
    model_call_id: String,
    evidence_refs: Vec<String>,
    cause_event_ids: Vec<String>,
    sensitivity: String,
    payload_json: String,
    event_hash: String,
    #[serde(with = "fixed_bytes")]
    content_digest: [u8; 64],
    ingest_revision: u64,
}

#[derive(Clone, Copy)]
enum ParseSource {
    Journal,
    Outbox,
}

/// Parses common v3 envelope fields that the authenticated journal/outbox
/// metadata must bind before a source-specific payload parser is selected.
fn parse_authenticated_wire_event(
    bytes: &[u8],
    authenticated_event_id: &EventId,
    authenticated_sequence: u64,
    authenticated_boot_id: &str,
) -> Result<WireEvent, PublishError> {
    reject_duplicate_json(bytes)?;
    let event: WireEvent = serde_json::from_slice(bytes)?;
    let event_id =
        EventId::parse(event.event_id.clone()).map_err(|_| PublishError::InvalidEvent)?;
    if event.schema_version != 3
        || &event_id != authenticated_event_id
        || event.producer_seq != authenticated_sequence
        || event.producer_boot_id != authenticated_boot_id
        || event.request_seq == 0
        || event.example_only
        || !valid_event_type(&event.event_type)
        || !valid_name(&event.producer_id)
        || !valid_lower_hex(&event.trace_id, 32)
        || !valid_lower_hex(&event.span_id, 16)
        || !matches!(
            event.sensitivity.as_str(),
            "PUBLIC" | "INTERNAL" | "SENSITIVE" | "RESTRICTED"
        )
        || event.integrity.state != "pending"
        || event.integrity.previous_hash.is_some()
        || event.integrity.event_hash.is_some()
    {
        return Err(PublishError::InvalidEvent);
    }
    TenantId::parse(event.tenant_id.clone()).map_err(|_| PublishError::InvalidEvent)?;
    SiteId::parse(event.site_id.clone()).map_err(|_| PublishError::InvalidEvent)?;
    PolicyRevision::parse(event.policy_revision.clone()).map_err(|_| PublishError::InvalidEvent)?;
    if let Some(request_id) = &event.request_id {
        RequestId::parse(request_id.clone()).map_err(|_| PublishError::InvalidEvent)?;
    }
    validate_id_list(&event.evidence_refs, None)?;
    validate_id_list(&event.cause_event_ids, Some("ev_"))?;
    if event.event_type.starts_with("model.") {
        model_eval::ModelEvent::validate_envelope(&event)?;
    }
    Ok(event)
}

impl IndexRow {
    fn parse(
        bytes: &[u8],
        authenticated_event_id: &EventId,
        authenticated_sequence: u64,
        authenticated_boot_id: &str,
        digest: String,
        metadata_retention: TimeDelta,
    ) -> Result<Self, PublishError> {
        Self::parse_with(
            bytes,
            authenticated_event_id,
            authenticated_sequence,
            authenticated_boot_id,
            digest,
            metadata_retention,
            ParseSource::Journal,
        )
    }

    fn parse_outbox(
        bytes: &[u8],
        authenticated_event_id: &EventId,
        authenticated_sequence: u64,
        authenticated_boot_id: &str,
        digest: String,
        metadata_retention: TimeDelta,
    ) -> Result<Self, PublishError> {
        Self::parse_with(
            bytes,
            authenticated_event_id,
            authenticated_sequence,
            authenticated_boot_id,
            digest,
            metadata_retention,
            ParseSource::Outbox,
        )
    }

    fn parse_with(
        bytes: &[u8],
        authenticated_event_id: &EventId,
        authenticated_sequence: u64,
        authenticated_boot_id: &str,
        digest: String,
        metadata_retention: TimeDelta,
        source: ParseSource,
    ) -> Result<Self, PublishError> {
        let event = parse_authenticated_wire_event(
            bytes,
            authenticated_event_id,
            authenticated_sequence,
            authenticated_boot_id,
        )?;
        let occurred_at = DateTime::parse_from_rfc3339(&event.occurred_at)
            .map_err(|_| PublishError::InvalidEvent)?
            .with_timezone(&Utc);
        let observed_at = DateTime::parse_from_rfc3339(&event.observed_at)
            .map_err(|_| PublishError::InvalidEvent)?
            .with_timezone(&Utc);
        let retention_expires_at = occurred_at
            .checked_add_signed(metadata_retention)
            .ok_or(PublishError::InvalidEvent)?;
        let summary = match source {
            ParseSource::Journal if calibration_audit::supports(&event.event_type) => {
                calibration_audit::parse(&event)?
            }
            ParseSource::Journal if control_audit::supports(&event.event_type) => {
                control_audit::parse(&event)?
            }
            // Transactional outbox facts are never valid in a local journal.
            // Without this source gate, an attacker-controlled journal payload
            // could bypass a dedicated journal parser by naming an outbox type.
            ParseSource::Journal if outbox::supports(&event.event_type) => {
                return Err(PublishError::UnsupportedEventType);
            }
            ParseSource::Journal => PayloadSummary::parse(&event.event_type, event.payload.get())?,
            ParseSource::Outbox if outbox::supports(&event.event_type) => outbox::parse(&event)?,
            ParseSource::Outbox => return Err(PublishError::UnsupportedEventType),
        };
        let ingest_revision = digest_revision(&digest)?;
        Ok(Self {
            tenant_id: event.tenant_id,
            site_id: event.site_id,
            request_id: event.request_id.unwrap_or_default(),
            trace_id: event
                .trace_id
                .as_bytes()
                .try_into()
                .map_err(|_| PublishError::InvalidEvent)?,
            event_id: event.event_id,
            event_type: event.event_type,
            stage: summary.stage,
            outcome: summary.outcome,
            reason_code: summary.reason_code,
            proof_kind: summary.proof_kind,
            confidence: summary.confidence,
            confidence_status: summary.confidence_status,
            occurred_at,
            observed_at,
            retention_expires_at,
            producer_id: event.producer_id,
            producer_boot_id: event.producer_boot_id,
            producer_seq: event.producer_seq,
            request_seq: event.request_seq,
            method: summary.method,
            operation_id: summary.operation_id,
            origin_state: summary.origin_state,
            http_status: summary.http_status,
            is_terminal: u8::from(summary.is_terminal),
            duration_us: summary.duration_us,
            model_call_id: summary.model_call_id,
            policy_revision: event.policy_revision,
            model_revision: summary.model_revision,
            evidence_refs: event.evidence_refs,
            cause_event_ids: event.cause_event_ids,
            sensitivity: event.sensitivity,
            payload_json: event.payload.get().to_owned(),
            content_digest: digest
                .as_bytes()
                .try_into()
                .map_err(|_| PublishError::InvalidEvent)?,
            event_hash: digest,
            ingest_revision,
        })
    }
}

// FixedString uses exactly N bytes; RowBinary strings include a length prefix.
mod fixed_bytes {
    use serde::{
        Deserializer, Serializer,
        de::{Error, SeqAccess, Visitor},
        ser::SerializeTuple,
    };
    use std::fmt;

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(N)?;
        for byte in bytes {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        struct BytesVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
            type Value = [u8; N];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "exactly {N} bytes")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = [0; N];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(index, &self))?;
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_tuple(N, BytesVisitor::<N>)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    schema_version: u8,
    event_id: String,
    event_type: String,
    tenant_id: String,
    site_id: String,
    #[serde(deserialize_with = "Option::deserialize")]
    request_id: Option<String>,
    trace_id: String,
    span_id: String,
    producer_id: String,
    producer_boot_id: String,
    producer_seq: u64,
    request_seq: u32,
    occurred_at: String,
    observed_at: String,
    policy_revision: String,
    example_only: bool,
    evidence_refs: Vec<String>,
    cause_event_ids: Vec<String>,
    payload: Box<RawValue>,
    sensitivity: String,
    integrity: Integrity,
}

struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UniqueVisitor;

        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }

            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                while sequence.next_element::<UniqueJson>()?.is_some() {}
                Ok(UniqueJson)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    map.next_value::<UniqueJson>()?;
                }
                Ok(UniqueJson)
            }
        }

        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn reject_duplicate_json(bytes: &[u8]) -> Result<(), PublishError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    UniqueJson::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Integrity {
    state: String,
    previous_hash: Option<String>,
    event_hash: Option<String>,
}

#[derive(Default)]
struct PayloadSummary {
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    confidence: Option<f64>,
    confidence_status: String,
    model_revision: String,
    model_call_id: String,
    method: String,
    operation_id: String,
    origin_state: String,
    http_status: Option<u16>,
    is_terminal: bool,
    duration_us: u64,
}

impl PayloadSummary {
    fn parse(event_type: &str, json: &str) -> Result<Self, PublishError> {
        match event_type {
            "model.started" | "model.requested" | "model.responded" | "model.failed"
            | "model.timeout" | "model.cancelled" => {
                serde_json::from_str::<model_eval::ModelEvent>(json)?.validate(event_type)
            }
            "stage.completed" | "stage.skipped" => {
                let payload: StagePayload = serde_json::from_str(json)?;
                payload.validate()
            }
            "request.accepted" => serde_json::from_str::<RequestAcceptedPayload>(json)?.validate(),
            "decision.composed" => {
                let payload: DecisionPayload = serde_json::from_str(json)?;
                payload.validate()
            }
            "origin.forward_intent" | "origin.unknown" | "origin.response" => {
                let payload: OriginPayload = serde_json::from_str(json)?;
                payload.validate()
            }
            "request.completed" => serde_json::from_str::<CompletionPayload>(json)?.validate(true),
            "request.aborted" => serde_json::from_str::<CompletionPayload>(json)?.validate(false),
            "audit.recovered" => {
                let payload: RecoveryPayload = serde_json::from_str(json)?;
                payload.validate()
            }
            _ => Err(PublishError::UnsupportedEventType),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestAcceptedPayload {
    method: String,
    operation_id: Option<String>,
    origin_state: String,
}

impl RequestAcceptedPayload {
    fn validate(self) -> Result<PayloadSummary, PublishError> {
        if !valid_method(&self.method)
            || self
                .operation_id
                .as_deref()
                .is_some_and(|value| !valid_name(value))
            || self.origin_state != "not_sent"
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(PayloadSummary {
            method: self.method,
            operation_id: self.operation_id.unwrap_or_default(),
            origin_state: self.origin_state,
            ..PayloadSummary::default()
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagePayload {
    stage: String,
    stage_execution_id: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    #[serde(deserialize_with = "Option::deserialize")]
    confidence: Option<f64>,
    confidence_status: String,
    duration_us: u64,
    rule_revision: Option<String>,
    model_call_id: Option<String>,
    model_revision: Option<String>,
    facts: StageFacts,
    coverage: StageCoverage,
}

impl StagePayload {
    fn validate(self) -> Result<PayloadSummary, PublishError> {
        valid_prefixed_v7(&self.stage_execution_id, "stg_")?;
        if !valid_name(&self.stage)
            || !valid_name(&self.reason_code)
            || !matches!(
                self.outcome.as_str(),
                "PASS" | "DENY" | "UNKNOWN" | "ERROR" | "SKIPPED" | "CANCELLED"
            )
            || !matches!(
                self.proof_kind.as_str(),
                "deterministic" | "model" | "observation" | "none"
            )
            || !valid_confidence(
                &self.proof_kind,
                &self.outcome,
                self.confidence,
                &self.confidence_status,
            )
            || self
                .rule_revision
                .as_deref()
                .is_some_and(|value| PolicyRevision::parse(value).is_err())
            || self
                .model_call_id
                .as_deref()
                .is_some_and(|value| ModelCallId::parse(value).is_err())
            || (self.proof_kind == "model") != self.model_call_id.is_some()
            || self
                .model_revision
                .as_deref()
                .is_some_and(|value| self.proof_kind != "model" || !valid_name(value))
            || self
                .facts
                .operation_id
                .as_deref()
                .is_some_and(|value| !valid_name(value))
        {
            return Err(PublishError::InvalidEvent);
        }
        let _ = self.coverage.admission_checked;
        Ok(PayloadSummary {
            stage: self.stage,
            outcome: self.outcome,
            reason_code: self.reason_code,
            proof_kind: self.proof_kind,
            confidence: self.confidence,
            confidence_status: self.confidence_status,
            model_revision: self.model_revision.unwrap_or_default(),
            model_call_id: self.model_call_id.unwrap_or_default(),
            operation_id: self.facts.operation_id.unwrap_or_default(),
            duration_us: self.duration_us,
            ..PayloadSummary::default()
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageFacts {
    operation_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageCoverage {
    admission_checked: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionPayload {
    decision: String,
    reason_code: String,
    origin_state: String,
}

impl DecisionPayload {
    fn validate(self) -> Result<PayloadSummary, PublishError> {
        if !matches!(self.decision.as_str(), "ALLOW" | "DENY")
            || !valid_name(&self.reason_code)
            || self.origin_state != "not_sent"
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(PayloadSummary {
            outcome: self.decision,
            reason_code: self.reason_code,
            origin_state: self.origin_state,
            ..PayloadSummary::default()
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginPayload {
    method: String,
    operation_id: Option<String>,
    origin_state: String,
    reason_code: String,
    status: Option<u16>,
}

impl OriginPayload {
    fn validate(self) -> Result<PayloadSummary, PublishError> {
        if !valid_method(&self.method)
            || self
                .operation_id
                .as_deref()
                .is_some_and(|value| !valid_name(value))
            || !matches!(
                self.origin_state.as_str(),
                "not_sent" | "unknown" | "response_received"
            )
            || !valid_name(&self.reason_code)
            || self
                .status
                .is_some_and(|value| !(100..=599).contains(&value))
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(PayloadSummary {
            outcome: self.origin_state.clone(),
            reason_code: self.reason_code,
            method: self.method,
            operation_id: self.operation_id.unwrap_or_default(),
            origin_state: self.origin_state,
            http_status: self.status,
            ..PayloadSummary::default()
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionPayload {
    decision: String,
    reason_code: String,
    status: Option<u16>,
    origin_state: String,
    duration_us: u64,
}

impl CompletionPayload {
    fn validate(self, requires_status: bool) -> Result<PayloadSummary, PublishError> {
        if !matches!(self.decision.as_str(), "ALLOW" | "DENY" | "UNKNOWN")
            || (self.decision == "UNKNOWN" && requires_status)
            || !valid_name(&self.reason_code)
            || (requires_status && self.status.is_none())
            || self
                .status
                .is_some_and(|status| !(100..=599).contains(&status))
            || !matches!(
                self.origin_state.as_str(),
                "not_sent" | "unknown" | "response_received"
            )
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(PayloadSummary {
            outcome: self.decision,
            reason_code: self.reason_code,
            origin_state: self.origin_state,
            http_status: self.status,
            is_terminal: true,
            duration_us: self.duration_us,
            ..PayloadSummary::default()
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryPayload {
    recovered_records: u64,
    truncated_bytes: u64,
    reason_code: String,
}

impl RecoveryPayload {
    fn validate(self) -> Result<PayloadSummary, PublishError> {
        if !valid_name(&self.reason_code) || self.truncated_bytes == 0 {
            return Err(PublishError::InvalidEvent);
        }
        let _ = self.recovered_records;
        Ok(PayloadSummary {
            reason_code: self.reason_code,
            ..PayloadSummary::default()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Row)]
struct ExistingDigest {
    event_id: String,
    #[serde(with = "fixed_bytes")]
    content_digest: [u8; 64],
    digest_count: u64,
}

async fn reject_remote_conflicts(
    client: &Client,
    table: &str,
    expected: &BTreeMap<String, String>,
) -> Result<(), PublishError> {
    if expected.is_empty() {
        return Ok(());
    }
    let ids = expected.keys().cloned().collect::<Vec<_>>();
    let existing = client
        .query(
            "SELECT event_id, any(events.content_digest) AS content_digest, \
             uniqExact(events.content_digest) AS digest_count FROM ? AS events \
             WHERE event_id IN ? GROUP BY event_id",
        )
        .bind(Identifier(table))
        .bind(ids)
        .fetch_all::<ExistingDigest>()
        .await?;
    for row in existing {
        if row.digest_count != 1
            || expected.get(&row.event_id).map(String::as_bytes)
                != Some(row.content_digest.as_slice())
        {
            return Err(PublishError::IntegrityConflict);
        }
    }
    Ok(())
}

async fn insert_rows(
    client: &Client,
    table: &str,
    deduplication_token: &str,
    rows: &[IndexRow],
) -> Result<(), PublishError> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut insert = client
        .insert::<IndexRow>(table)
        .await?
        .with_setting("insert_deduplication_token", deduplication_token)
        .with_timeouts(Some(Duration::from_secs(15)), Some(Duration::from_secs(30)));
    for row in rows {
        insert.write(row).await?;
    }
    insert.end().await?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema_version: u8,
    target_id: String,
    table: String,
    producer_boot_id: String,
    segment_digest: String,
    record_count: u64,
    final_sequence: u64,
}

impl Checkpoint {
    fn from_segment(
        target_id: &str,
        table: &str,
        segment: &xshield_audit::VerifiedSegment,
    ) -> Self {
        Self {
            schema_version: 1,
            target_id: target_id.to_owned(),
            table: table.to_owned(),
            producer_boot_id: segment.producer_boot_id.clone(),
            segment_digest: hex(&segment.segment_digest),
            record_count: segment.record_count,
            final_sequence: segment.final_sequence,
        }
    }

    fn path(&self, directory: &Path) -> PathBuf {
        directory.join(format!("segment-{}.published.json", self.producer_boot_id))
    }
}

fn checkpoint_matches(directory: &Path, expected: &Checkpoint) -> Result<bool, PublishError> {
    let path = expected.path(directory);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let actual: Checkpoint = serde_json::from_slice(&read_private_bounded(&path, 1024)?)?;
            if actual.schema_version != expected.schema_version
                || actual.target_id != expected.target_id
                || actual.table != expected.table
                || actual.producer_boot_id != expected.producer_boot_id
                || actual.segment_digest != expected.segment_digest
                || actual.record_count != expected.record_count
                || actual.final_sequence != expected.final_sequence
            {
                return Err(PublishError::CheckpointConflict);
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn write_checkpoint(directory: &Path, checkpoint: &Checkpoint) -> Result<(), PublishError> {
    let path = checkpoint.path(directory);
    if checkpoint_matches(directory, checkpoint)? {
        return Ok(());
    }
    let bytes = serde_json::to_vec(checkpoint)?;
    let temporary = directory.join(format!(".checkpoint-{}.tmp", Uuid::now_v7()));
    let mut file = private_new_file(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    if let Err(error) = fs::hard_link(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return if error.kind() == io::ErrorKind::AlreadyExists {
            Err(PublishError::CheckpointConflict)
        } else {
            Err(error.into())
        };
    }
    fs::remove_file(&temporary)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn closed_segment_paths(directory: &Path) -> Result<Vec<PathBuf>, PublishError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("segment-") && name.ends_with(".closed.xja") {
            if !entry.file_type()?.is_file() {
                return Err(PublishError::UnsafePath);
            }
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn segment_boot_id(path: &Path) -> Result<String, PublishError> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PublishError::UnsafePath)?;
    let value = name
        .strip_prefix("segment-")
        .and_then(|value| value.strip_suffix(".closed.xja"))
        .ok_or(PublishError::UnsafePath)?;
    valid_uuid_v7(value)?;
    Ok(value.to_owned())
}

fn lock_publisher(directory: &Path) -> Result<File, PublishError> {
    let path = directory.join("publisher.lock");
    let file = private_open_file(&path)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(PublishError::AlreadyRunning),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

fn prepare_private_directory(path: &Path, create: bool) -> Result<(), PublishError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(PublishError::UnsafePath);
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(PublishError::UnsafePermissions);
            }
        }
        Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn read_private_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, PublishError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > max_bytes
    {
        return Err(PublishError::UnsafePath);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(PublishError::UnsafePermissions);
    }
    Ok(fs::read(path)?)
}

fn private_open_file(path: &Path) -> Result<File, PublishError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(PublishError::UnsafePath);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(PublishError::UnsafePermissions);
    }
    Ok(file)
}

fn private_new_file(path: &Path) -> Result<File, PublishError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    Ok(options.open(path)?)
}

fn validate_id_list(values: &[String], prefix: Option<&str>) -> Result<(), PublishError> {
    if values.len() > LIST_ITEMS_MAX {
        return Err(PublishError::InvalidEvent);
    }
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value) {
            return Err(PublishError::InvalidEvent);
        }
        match prefix {
            Some(prefix) => valid_prefixed_v7(value, prefix)?,
            None => valid_any_prefixed_v7(value)?,
        }
    }
    Ok(())
}

fn valid_any_prefixed_v7(value: &str) -> Result<(), PublishError> {
    let Some((prefix, uuid)) = value.split_once('_') else {
        return Err(PublishError::InvalidEvent);
    };
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return Err(PublishError::InvalidEvent);
    }
    valid_uuid_v7(uuid)
}

fn valid_prefixed_v7(value: &str, prefix: &str) -> Result<(), PublishError> {
    valid_uuid_v7(
        value
            .strip_prefix(prefix)
            .ok_or(PublishError::InvalidEvent)?,
    )
}

fn valid_uuid_v7(value: &str) -> Result<(), PublishError> {
    let uuid = Uuid::parse_str(value).map_err(|_| PublishError::InvalidEvent)?;
    if uuid.get_version() != Some(Version::SortRand) || value != uuid.hyphenated().to_string() {
        return Err(PublishError::InvalidEvent);
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= NAME_BYTES_MAX
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_confidence(
    proof_kind: &str,
    outcome: &str,
    confidence: Option<f64>,
    status: &str,
) -> bool {
    matches!(
        status,
        "provided" | "not_applicable" | "not_provided" | "unavailable"
    ) && confidence.is_none_or(|value| value.is_finite() && (0.0..=1.0).contains(&value))
        && (confidence.is_some() == (status == "provided"))
        && (proof_kind != "deterministic" || (confidence.is_none() && status == "not_applicable"))
        && (!matches!(outcome, "SKIPPED" | "CANCELLED") || confidence.is_none())
}

fn valid_event_type(value: &str) -> bool {
    (3..=NAME_BYTES_MAX).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        })
}

fn valid_method(value: &str) -> bool {
    !value.is_empty() && value.len() <= 16 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn digest_revision(digest: &str) -> Result<u64, PublishError> {
    if digest.len() != 64 {
        return Err(PublishError::InvalidEvent);
    }
    u64::from_str_radix(&digest[..16], 16).map_err(|_| PublishError::InvalidEvent)
}

/// Stable publisher failure classes suitable for retry and alert decisions.
#[derive(Debug)]
pub enum PublishError {
    /// Configuration scalar failed validation.
    InvalidConfig,
    /// A path was not a regular private file or directory.
    UnsafePath,
    /// A file or directory is accessible outside its owner.
    UnsafePermissions,
    /// Another publisher owns the destination checkpoint lock.
    AlreadyRunning,
    /// A checkpoint exists but does not match the authenticated segment/target.
    CheckpointConflict,
    /// The same event ID was observed with different canonical content.
    IntegrityConflict,
    /// Event schema, identity, ordering, or payload validation failed.
    InvalidEvent,
    /// A closed segment exceeds the configured health inspection ceiling.
    SegmentLimitExceeded,
    /// The adapter does not recognize the versioned event type.
    UnsupportedEventType,
    /// An analytical query exceeded a server or local response budget.
    QueryBudgetExceeded,
    /// An analytical query exceeded its client deadline.
    QueryTimeout,
    /// Local journal authentication or decryption failed.
    Journal(JournalError),
    /// Local durable storage failed.
    Io(io::Error),
    /// Typed JSON decoding or encoding failed.
    Json(serde_json::Error),
    /// `ClickHouse` query or insert failed.
    ClickHouse(clickhouse::error::Error),
    /// `PostgreSQL` outbox lease or acknowledgement failed.
    Postgres(xshield_postgres::StoreError),
    /// A claimed outbox row no longer belongs to this publisher lease.
    OutboxLeaseLost,
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("invalid publisher configuration"),
            Self::UnsafePath => formatter.write_str("unsafe publisher path"),
            Self::UnsafePermissions => formatter.write_str("unsafe publisher permissions"),
            Self::AlreadyRunning => formatter.write_str("publisher already running"),
            Self::CheckpointConflict => formatter.write_str("publisher checkpoint conflict"),
            Self::IntegrityConflict => formatter.write_str("audit integrity conflict"),
            Self::InvalidEvent => formatter.write_str("invalid authenticated audit event"),
            Self::SegmentLimitExceeded => formatter.write_str("audit segment read limit exceeded"),
            Self::UnsupportedEventType => formatter.write_str("unsupported audit event type"),
            Self::QueryBudgetExceeded => formatter.write_str("audit query budget exceeded"),
            Self::QueryTimeout => formatter.write_str("audit query timed out"),
            Self::Journal(error) => error.fmt(formatter),
            Self::Io(_) => formatter.write_str("publisher storage failed"),
            Self::Json(_) => formatter.write_str("publisher JSON processing failed"),
            Self::ClickHouse(_) => formatter.write_str("audit index unavailable"),
            Self::Postgres(_) => formatter.write_str("outbox store unavailable"),
            Self::OutboxLeaseLost => formatter.write_str("outbox delivery lease lost"),
        }
    }
}

impl std::error::Error for PublishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::ClickHouse(error) => Some(error),
            Self::Postgres(error) => Some(error),
            _ => None,
        }
    }
}

impl From<JournalError> for PublishError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<io::Error> for PublishError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for PublishError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<clickhouse::error::Error> for PublishError {
    fn from(value: clickhouse::error::Error) -> Self {
        Self::ClickHouse(value)
    }
}

impl From<xshield_postgres::StoreError> for PublishError {
    fn from(value: xshield_postgres::StoreError) -> Self {
        Self::Postgres(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuditEventSummary, Checkpoint, ExistingDigest, IndexRow, MODEL_CALL_ID_PROJECTION,
        PayloadSummary, PublishError, PublisherConfig, RequestStageSummary, RequestSummaryRow,
        SearchEventSummary, SearchPosition, TimeDelta, closed_segment_paths,
        inspect_publication_health, prepare_private_directory, publish_sealed_segments,
        query_audit_events, query_model_call, query_request_events, query_request_summary,
        read_private_bounded, write_checkpoint,
    };
    use chrono::{DateTime, Utc};
    use clickhouse::{Client, sql::Identifier, test};
    use std::{
        fs,
        path::{Path, PathBuf},
    };
    use uuid::Uuid;
    use xshield_audit::{
        JournalKey, JournalLimits, JournalRecord, LocalJournal, SealSigningKey,
        SealedSegmentReader, seal_closed_segments,
    };
    use xshield_core::{
        domain::{
            ArtifactId, AuthBindingId, CalibrationReportId, CaseId, EventId, GrantId, ModelCallId,
            RequestId, SiteId, TenantId,
        },
        identity::UnixSeconds,
        query::{
            ConfidenceThreshold, QueryFilter, QueryOutcome, QueryPlan, QuerySort, QueryTextField,
            QueryWindow,
        },
    };

    const JOURNAL_KEY_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const SEAL_KEY_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    struct Fixture {
        root: PathBuf,
        config: PublisherConfig,
        journal_key: JournalKey,
        seal_key: SealSigningKey,
        event_ids: Vec<String>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_events(1)
        }

        fn with_events(event_count: usize) -> Self {
            let (fixture, journal) = Self::with_open_journal(event_count);
            drop(journal);
            fixture
        }

        fn with_model_stage(revision: Option<&str>) -> Self {
            let (mut fixture, mut journal) = Self::with_open_journal(0);
            let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
            let mut event: serde_json::Value =
                serde_json::from_str(&event_json(event_id.as_str(), &journal.producer_boot_id()))
                    .unwrap();
            event["event_type"] = "stage.completed".into();
            let now = Utc::now().to_rfc3339();
            event["occurred_at"] = now.clone().into();
            event["observed_at"] = now.into();
            event["payload"] = model_stage_payload();
            if let Some(revision) = revision {
                event["payload"]["model_revision"] = revision.into();
            }
            let plaintext = serde_json::to_vec(&event).unwrap();
            journal
                .append_batch(&[JournalRecord {
                    event_id: &event_id,
                    plaintext: &plaintext,
                }])
                .unwrap();
            seal_closed_segments(
                &fixture.config.journal_directory,
                &fixture.config.manifest_directory,
                "journal-key-r1",
                &fixture.journal_key,
                &fixture.seal_key,
            )
            .unwrap();
            fixture.event_ids.push(event_id.as_str().to_owned());
            drop(journal);
            fixture
        }

        fn with_open_journal(event_count: usize) -> (Self, LocalJournal) {
            let root = std::env::temp_dir().join(format!("xshield-worker-test-{}", Uuid::now_v7()));
            let journal_directory = root.join("journal");
            let manifest_directory = root.join("manifests");
            let checkpoint_directory = root.join("checkpoints");
            private_directory(&root);
            private_directory(&journal_directory);
            private_directory(&manifest_directory);
            let journal_key = JournalKey::from_hex(JOURNAL_KEY_HEX).unwrap();
            let limits = JournalLimits::new(1024 * 1024, 512 * 1024, 1).unwrap();
            let (mut journal, _) = LocalJournal::open(
                &journal_directory,
                "journal-key-r1",
                JournalKey::from_hex(JOURNAL_KEY_HEX).unwrap(),
                limits,
            )
            .unwrap();
            let mut event_ids = Vec::with_capacity(event_count);
            for _ in 0..event_count {
                let boot_id = journal.producer_boot_id();
                let event_id = format!("ev_{}", Uuid::now_v7());
                let plaintext = event_json(&event_id, &boot_id);
                let typed_event_id = EventId::parse(event_id.clone()).unwrap();
                journal
                    .append_batch(&[JournalRecord {
                        event_id: &typed_event_id,
                        plaintext: plaintext.as_bytes(),
                    }])
                    .unwrap();
                event_ids.push(event_id);
            }
            let seal_key = SealSigningKey::from_hex("seal-key-r1", SEAL_KEY_HEX).unwrap();
            seal_closed_segments(
                &journal_directory,
                &manifest_directory,
                "journal-key-r1",
                &journal_key,
                &seal_key,
            )
            .unwrap();
            let config = PublisherConfig::new(
                journal_directory,
                manifest_directory,
                checkpoint_directory,
                "clickhouse-primary",
                "audit_events",
                30,
                1024 * 1024,
            )
            .unwrap();
            (
                Self {
                    root,
                    config,
                    journal_key,
                    seal_key,
                    event_ids,
                },
                journal,
            )
        }

        fn checkpoint_count(&self) -> usize {
            let path = self.root.join("checkpoints");
            fs::read_dir(path).map_or(0, |entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .ends_with(".published.json")
                    })
                    .count()
            })
        }

        fn first_content_digest(&self) -> String {
            let paths = closed_segment_paths(&self.config.journal_directory).unwrap();
            let boot_id = super::segment_boot_id(&paths[0]).unwrap();
            let manifest = read_private_bounded(
                &self
                    .config
                    .manifest_directory
                    .join(format!("segment-{boot_id}.xjs")),
                super::MANIFEST_BYTES_MAX,
            )
            .unwrap();
            let mut reader = SealedSegmentReader::open(
                &paths[0],
                self.config.max_segment_bytes,
                "journal-key-r1",
                &self.journal_key,
                &manifest,
                &self.seal_key.verifying_key().unwrap(),
            )
            .unwrap();
            super::hex(reader.next_record().unwrap().unwrap().plaintext_digest())
        }

        fn append_conflicting_event(&self, journal: &mut LocalJournal) {
            let event_id = EventId::parse(self.event_ids[0].clone()).unwrap();
            let plaintext = event_json(event_id.as_str(), &journal.producer_boot_id())
                .replace("\"method\":\"GET\"", "\"method\":\"POST\"");
            journal
                .append_batch(&[JournalRecord {
                    event_id: &event_id,
                    plaintext: plaintext.as_bytes(),
                }])
                .unwrap();
            seal_closed_segments(
                &self.config.journal_directory,
                &self.config.manifest_directory,
                "journal-key-r1",
                &self.journal_key,
                &self.seal_key,
            )
            .unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[tokio::test]
    #[ignore = "requires XSHIELD_TEST_CLICKHOUSE_URL"]
    async fn real_schema_publisher_preserves_digests_replay_and_conflicts() {
        let url = std::env::var("XSHIELD_TEST_CLICKHOUSE_URL")
            .expect("XSHIELD_TEST_CLICKHOUSE_URL must identify a test ClickHouse server");
        let mut admin = Client::default().with_url(url);
        if let Ok(user) = std::env::var("XSHIELD_TEST_CLICKHOUSE_USER") {
            admin = admin.with_user(user);
        }
        if let Ok(password) = std::env::var("XSHIELD_TEST_CLICKHOUSE_PASSWORD") {
            admin = admin.with_password(password);
        }
        let database = format!("xshield_publisher_test_{}", Uuid::now_v7().simple());
        // CREATE succeeds only for a database exclusively owned by this test.
        admin
            .query("CREATE DATABASE ?")
            .bind(Identifier(&database))
            .execute()
            .await
            .expect("create isolated publisher database");
        let client = admin.clone().with_database(database.clone());
        let schema_database = database.clone();
        // Capture assertions and setup panics so cleanup is awaited by the owner.
        let outcome = tokio::spawn(async move {
            let schema = include_str!("../../../sql/clickhouse.sql")
                .lines()
                .filter(|line| !line.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n")
                .replace("xshield.", &format!("{schema_database}."));
            for statement in schema.split(';').map(str::trim) {
                if statement.is_empty() || statement == "CREATE DATABASE IF NOT EXISTS xshield" {
                    continue;
                }
                client.query(statement).execute().await.unwrap();
            }
            // The fixture has a fixed timestamp; retain raw rows for digest checks.
            for table in ["audit_events", "events_by_time"] {
                client
                    .query("SYSTEM STOP TTL MERGES ?")
                    .bind(Identifier(table))
                    .execute()
                    .await
                    .unwrap();
            }
            assert_real_publisher(&client).await;
            assert_real_model_stage_publication(&client).await;
            assert_real_model_call_publication(&client).await;
        })
        .await;
        let cleanup = admin
            .query("DROP DATABASE ? SYNC")
            .bind(Identifier(&database))
            .execute()
            .await;
        assert!(
            cleanup.is_ok(),
            "cleanup failed for owned database {database}"
        );
        if let Err(error) = outcome {
            if error.is_panic() {
                std::panic::resume_unwind(error.into_panic());
            }
            panic!("ClickHouse publisher regression task was cancelled");
        }
    }

    async fn assert_real_publisher(client: &Client) {
        let (fixture, mut journal) = Fixture::with_open_journal(1);
        let verifier = fixture.seal_key.verifying_key().unwrap();
        let paths = closed_segment_paths(&fixture.config.journal_directory).unwrap();
        let boot_id = super::segment_boot_id(&paths[0]).unwrap();
        let expected_digest = fixture.first_content_digest();
        let published = publish_sealed_segments(
            &fixture.config,
            client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap();
        assert_eq!(published.published_segments, 1);
        assert_eq!(published.published_events, 1);
        assert_eq!(
            published.watermark_producer_boot_id.as_deref(),
            Some(boot_id.as_str())
        );
        assert_eq!(published.watermark_producer_sequence, 1);
        assert_eq!(fixture.checkpoint_count(), 1);
        for table in ["audit_events", "events_by_time"] {
            let rows = client
                .query("SELECT ?fields FROM ?")
                .bind(Identifier(table))
                .fetch_all::<IndexRow>()
                .await
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].event_id, fixture.event_ids[0]);
            assert_eq!(&rows[0].trace_id, b"01a0afa63320758a9554d0d3b561b8c6");
            assert_eq!(
                rows[0].content_digest.as_slice(),
                expected_digest.as_bytes()
            );
            assert_eq!(rows[0].event_hash, expected_digest);
            assert_eq!(rows[0].method, "GET");
            assert_eq!(rows[0].occurred_at.timestamp_subsec_micros(), 123_000);
            assert_eq!(
                rows[0].retention_expires_at,
                rows[0].occurred_at + fixture.config.metadata_retention
            );
        }
        let replayed = publish_sealed_segments(
            &fixture.config,
            client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap();
        assert_eq!(replayed.published_segments, 0);
        assert_eq!(replayed.published_events, 0);
        assert_eq!(replayed.checkpointed_segments, 1);
        assert_eq!(
            replayed.watermark_producer_boot_id,
            published.watermark_producer_boot_id
        );
        assert_eq!(
            replayed.watermark_producer_sequence,
            published.watermark_producer_sequence
        );
        fixture.append_conflicting_event(&mut journal);
        let error = publish_sealed_segments(
            &fixture.config,
            client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PublishError::IntegrityConflict));
        assert_eq!(fixture.checkpoint_count(), 1);
        let health = inspect_publication_health(
            &fixture.config,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .unwrap();
        assert_eq!(health.published_segments, 1);
        assert_eq!(health.pending_segments, 1);
        assert_eq!(health.index_watermark.unwrap().producer_boot_id, boot_id);
        let row_count = client
            .query("SELECT count() FROM audit_events")
            .fetch_one::<u64>()
            .await
            .unwrap();
        assert_eq!(row_count, 1);
    }

    async fn assert_real_model_stage_publication(client: &Client) {
        let revisions = [Some("jev-1.13.0"), None];
        let fixtures = revisions.map(Fixture::with_model_stage);
        for (fixture, revision) in fixtures.iter().zip(revisions) {
            let report = publish_sealed_segments(
                &fixture.config,
                client,
                "journal-key-r1",
                &fixture.journal_key,
                &fixture.seal_key.verifying_key().unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(report.published_events, 1);
            let rows = client
                .query("SELECT ?fields FROM audit_events WHERE event_id = ?")
                .bind(&fixture.event_ids[0])
                .fetch_all::<IndexRow>()
                .await
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].proof_kind, "model");
            assert_eq!(rows[0].model_revision, revision.unwrap_or_default());
            let payload: serde_json::Value = serde_json::from_str(&rows[0].payload_json).unwrap();
            assert_eq!(
                payload["model_call_id"],
                model_stage_payload()["model_call_id"]
            );
            assert_eq!(fixture.checkpoint_count(), 1);
        }
        let now = u64::try_from(Utc::now().timestamp()).unwrap();
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(now - 60), UnixSeconds::new(now + 60)).unwrap(),
            vec![QueryFilter::Text {
                field: QueryTextField::ModelRevision,
                value: "jev-1.13.0".to_owned(),
            }],
            QuerySort::OccurredAtAsc,
            10,
        )
        .unwrap();
        let found = query_audit_events(
            &fixtures[0].config,
            client,
            &TenantId::parse("tenant_demo").unwrap(),
            &SiteId::parse("site_demo").unwrap(),
            &plan,
            None,
        )
        .await
        .unwrap();
        assert_eq!(found.events.len(), 1);
        assert_eq!(found.events[0].event_id, fixtures[0].event_ids[0]);
        assert_eq!(
            found.events[0].model_revision.as_deref(),
            Some("jev-1.13.0")
        );
        assert!(!found.truncated);
    }

    #[allow(clippy::too_many_lines)]
    async fn assert_real_model_call_publication(client: &Client) {
        let (mut fixture, mut journal) = Fixture::with_open_journal(0);
        let call = ModelCallId::parse(format!("mdl_{}", Uuid::now_v7())).unwrap();
        let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
        let refs: [String; 4] = std::array::from_fn(|_| format!("artifact_{}", Uuid::now_v7()));
        for (event_type, status, reason, request_seq, ref_count, confidence) in [
            (
                "model.started",
                "started",
                "MODEL_EVALUATION_STARTED",
                1,
                0,
                None,
            ),
            (
                "model.requested",
                "requested",
                "MODEL_REQUESTED",
                4,
                2,
                None,
            ),
            (
                "model.responded",
                "success",
                "MODEL_EVALUATED",
                7,
                4,
                Some(0.8),
            ),
        ] {
            let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
            let mut event: serde_json::Value =
                serde_json::from_str(&event_json(event_id.as_str(), &journal.producer_boot_id()))
                    .unwrap();
            let now = Utc::now().to_rfc3339();
            event["event_type"] = event_type.into();
            event["producer_id"] = "model-eval".into();
            event["producer_seq"] = journal.next_sequence().unwrap().into();
            event["request_id"] = request.as_str().into();
            event["request_seq"] = request_seq.into();
            event["occurred_at"] = now.clone().into();
            event["observed_at"] = now.into();
            event["sensitivity"] = "RESTRICTED".into();
            event["evidence_refs"] = serde_json::json!(&refs[..ref_count]);
            event["cause_event_ids"] =
                serde_json::json!(fixture.event_ids.last().into_iter().collect::<Vec<_>>());
            event["payload"] = serde_json::json!({
                "model_call_id": call.as_str(),
                "model_revision": "jev-1.13.0",
                "prompt_revision": "evaluation-r1",
                "question_type": "choice",
                "status": status,
                "reason_code": reason,
                "confidence": confidence,
                "confidence_status": if confidence.is_some() { "provided" } else { "unavailable" },
                "duration_us": if confidence.is_some() { 1200 } else { 0 },
                "input_artifact_id": (ref_count >= 2).then_some(&refs[1]),
                "output_artifact_id": (ref_count == 4).then_some(&refs[2]),
                "call_artifact_id": (ref_count == 4).then_some(&refs[3]),
            });
            journal
                .append_batch(&[JournalRecord {
                    event_id: &event_id,
                    plaintext: &serde_json::to_vec(&event).unwrap(),
                }])
                .unwrap();
            fixture.event_ids.push(event_id.as_str().to_owned());
        }
        drop(journal);
        seal_closed_segments(
            &fixture.config.journal_directory,
            &fixture.config.manifest_directory,
            "journal-key-r1",
            &fixture.journal_key,
            &fixture.seal_key,
        )
        .unwrap();
        let verifier = fixture.seal_key.verifying_key().unwrap();
        let published = publish_sealed_segments(
            &fixture.config,
            client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap();
        assert_eq!(published.published_segments, 3);
        assert_eq!(published.published_events, 3);
        assert_eq!(fixture.checkpoint_count(), 3);
        let tenant = TenantId::parse("tenant_demo").unwrap();
        let site = SiteId::parse("site_demo").unwrap();
        let summary = query_model_call(&fixture.config, client, &tenant, &site, &call)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(summary.model_call_id, call.as_str());
        assert_eq!(summary.request_id, request.as_str());
        assert_eq!(summary.status, "success");
        assert_eq!(summary.model_revision, "jev-1.13.0");
        assert_eq!(summary.prompt_revision, "evaluation-r1");
        assert_eq!(summary.confidence, Some(0.8));
        assert!(summary.lifecycle_complete);
        assert_eq!(summary.input_artifact_id.as_deref(), Some(refs[1].as_str()));
        assert_eq!(
            summary.output_artifact_id.as_deref(),
            Some(refs[2].as_str())
        );
        assert_eq!(summary.call_artifact_id.as_deref(), Some(refs[3].as_str()));
        assert_eq!(summary.events.len(), 3);
        for (event, event_id) in summary.events.iter().zip(&fixture.event_ids) {
            assert_eq!(&event.event_id, event_id);
        }
        assert_eq!(summary.events[1].evidence_refs, refs[..2]);
        assert_eq!(summary.events[2].evidence_refs, refs);
        for (other_tenant, other_site) in
            [("tenant_other", "site_demo"), ("tenant_demo", "site_other")]
        {
            assert!(
                query_model_call(
                    &fixture.config,
                    client,
                    &TenantId::parse(other_tenant).unwrap(),
                    &SiteId::parse(other_site).unwrap(),
                    &call,
                )
                .await
                .unwrap()
                .is_none()
            );
        }
        let request_summary =
            query_request_summary(&fixture.config, client, &tenant, &site, &request)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(request_summary.event_count, 3);
        assert!(!request_summary.terminal);
        assert!(!request_summary.forwarded);
        assert!(!request_summary.business_result_confirmed);
        assert!(request_summary.decision.is_none());
        let replayed = publish_sealed_segments(
            &fixture.config,
            client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap();
        assert_eq!(replayed.published_events, 0);
        assert_eq!(replayed.published_segments, 0);
        assert_eq!(replayed.checkpointed_segments, 3);
        assert_eq!(
            replayed.watermark_producer_boot_id,
            published.watermark_producer_boot_id
        );
        assert_eq!(
            replayed.watermark_producer_sequence,
            published.watermark_producer_sequence
        );
        assert_eq!(fixture.checkpoint_count(), 3);
        let rows = client
            .query("SELECT ?fields FROM audit_events WHERE request_id = ? ORDER BY request_seq")
            .bind(request.as_str())
            .fetch_all::<IndexRow>()
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.is_terminal == 0));
        assert!(rows[0].cause_event_ids.is_empty());
        assert_eq!(rows[1].cause_event_ids, fixture.event_ids[..1]);
        assert_eq!(rows[2].cause_event_ids, fixture.event_ids[1..2]);
    }

    #[tokio::test]
    async fn acknowledges_then_reuses_exact_checkpoint() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
        let insertion = mock.add(test::handlers::record::<IndexRow>());
        mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
        let client = Client::default().with_mock(&mock);
        let verifier = fixture.seal_key.verifying_key().unwrap();
        let report = publish_sealed_segments(
            &fixture.config,
            &client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap();
        let rows: Vec<IndexRow> = insertion.collect().await;
        assert_eq!(report.published_segments, 1);
        assert_eq!(report.published_events, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_id, fixture.event_ids[0]);
        assert_eq!(rows[0].method, "GET");
        assert_eq!(rows[0].origin_state, "not_sent");
        assert_eq!(rows[0].is_terminal, 0);
        assert_eq!(
            rows[0].content_digest.as_slice(),
            fixture.first_content_digest().as_bytes()
        );
        assert_eq!(
            rows[0].retention_expires_at,
            rows[0].occurred_at + TimeDelta::try_days(30).unwrap()
        );
        assert_eq!(fixture.checkpoint_count(), 1);

        let second = publish_sealed_segments(
            &fixture.config,
            &client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap();
        assert_eq!(second.published_segments, 0);
        assert_eq!(second.checkpointed_segments, 1);
    }

    #[tokio::test]
    async fn publishes_model_stage_with_optional_revision() {
        for revision in [Some("jev-1.13.0"), None] {
            let fixture = Fixture::with_model_stage(revision);
            let mock = test::Mock::new();
            mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
            let insertion = mock.add(test::handlers::record::<IndexRow>());
            mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
            let report = publish_sealed_segments(
                &fixture.config,
                &Client::default().with_mock(&mock),
                "journal-key-r1",
                &fixture.journal_key,
                &fixture.seal_key.verifying_key().unwrap(),
            )
            .await
            .unwrap();
            let rows: Vec<IndexRow> = insertion.collect().await;
            assert_eq!(report.published_events, 1);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].event_id, fixture.event_ids[0]);
            assert_eq!(rows[0].proof_kind, "model");
            assert_eq!(rows[0].confidence, Some(0.75));
            assert_eq!(rows[0].confidence_status, "provided");
            assert_eq!(rows[0].model_revision, revision.unwrap_or_default());
            assert_eq!(
                rows[0].model_call_id,
                model_stage_payload()["model_call_id"].as_str().unwrap()
            );
            assert_eq!(fixture.checkpoint_count(), 1);
        }
    }

    #[test]
    fn model_stage_rejects_inconsistent_identity_revision_and_confidence() {
        for changes in [
            serde_json::json!({"model_call_id": null}),
            serde_json::json!({"model_call_id": "model_01a0afa6-3320-7791-8f45-b4d5a34ffb57"}),
            serde_json::json!({"model_call_id": "mdl_01a0afa6-3320-4791-8f45-b4d5a34ffb57"}),
            serde_json::json!({"model_call_id": "mdl_01A0afa6-3320-7791-8f45-b4d5a34ffb57"}),
            serde_json::json!({"model_revision": ""}),
            serde_json::json!({"model_revision": "x".repeat(129)}),
            serde_json::json!({"model_revision": "model/revision"}),
            serde_json::json!({"proof_kind": "none"}),
            serde_json::json!({"proof_kind": "observation"}),
            serde_json::json!({"proof_kind": "observation", "model_call_id": null, "model_revision": "r1"}),
            serde_json::json!({"proof_kind": "deterministic", "model_call_id": null}),
            serde_json::json!({"proof_kind": "deterministic", "model_call_id": null, "confidence": null, "confidence_status": "not_provided"}),
            serde_json::json!({"confidence": null}),
            serde_json::json!({"confidence": -0.01}),
            serde_json::json!({"confidence": 1.01}),
            serde_json::json!({"confidence_status": "not_applicable"}),
            serde_json::json!({"confidence_status": "not_provided"}),
            serde_json::json!({"confidence_status": "unavailable"}),
            serde_json::json!({"outcome": "SKIPPED"}),
            serde_json::json!({"outcome": "CANCELLED"}),
        ] {
            let mut payload = model_stage_payload();
            payload
                .as_object_mut()
                .unwrap()
                .extend(changes.as_object().unwrap().clone());
            assert!(
                matches!(
                    PayloadSummary::parse("stage.completed", &payload.to_string()),
                    Err(PublishError::InvalidEvent)
                ),
                "{changes}"
            );
        }
        let mut payload = model_stage_payload();
        payload.as_object_mut().unwrap().remove("model_call_id");
        assert!(PayloadSummary::parse("stage.completed", &payload.to_string()).is_err());
        let mut payload = model_stage_payload();
        payload.as_object_mut().unwrap().remove("confidence");
        payload["confidence_status"] = "not_provided".into();
        assert!(PayloadSummary::parse("stage.completed", &payload.to_string()).is_err());
    }

    #[test]
    fn model_stage_preserves_explicit_absent_confidence_and_legacy_deterministic_events() {
        for status in ["not_applicable", "not_provided", "unavailable"] {
            let mut payload = model_stage_payload();
            payload["confidence"] = serde_json::Value::Null;
            payload["confidence_status"] = status.into();
            let summary = PayloadSummary::parse("stage.completed", &payload.to_string()).unwrap();
            assert_eq!(summary.confidence, None);
            assert_eq!(summary.confidence_status, status);
            assert!(summary.model_revision.is_empty());
        }
        let mut payload = model_stage_payload();
        payload["proof_kind"] = "deterministic".into();
        payload["model_call_id"] = serde_json::Value::Null;
        payload["confidence"] = serde_json::Value::Null;
        payload["confidence_status"] = "not_applicable".into();
        let summary = PayloadSummary::parse("stage.completed", &payload.to_string()).unwrap();
        assert_eq!(summary.confidence, None);
        assert_eq!(summary.confidence_status, "not_applicable");
        assert!(summary.model_revision.is_empty());
    }

    fn model_stage_payload() -> serde_json::Value {
        serde_json::json!({
            "stage": "ui_semantic_match",
            "stage_execution_id": "stg_01a0afa6-3320-7637-b792-f997e8a40536",
            "outcome": "PASS",
            "reason_code": "CANDIDATE_CLASSIFICATION_COMPLETE",
            "proof_kind": "model",
            "confidence": 0.75,
            "confidence_status": "provided",
            "duration_us": 120,
            "rule_revision": null,
            "model_call_id": "mdl_01a0afa6-3320-7791-8f45-b4d5a34ffb57",
            "facts": {"operation_id": "orders.detail"},
            "coverage": {"admission_checked": true}
        })
    }

    #[tokio::test]
    async fn request_event_query_is_bounded() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        mock.add(test::handlers::provide([
            event_summary("ev_018f2a3b-4c5d-7000-8000-000000000001", 1),
            event_summary("ev_018f2a3b-4c5d-7000-8000-000000000002", 2),
        ]));
        mock.add(test::handlers::provide([event_summary(
            "ev_018f2a3b-4c5d-7000-8000-000000000002",
            2,
        )]));
        let client = Client::default().with_mock(&mock);
        let result = query_request_events(
            &fixture.config,
            &client,
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_a").unwrap(),
            &RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
            None,
            1,
        )
        .await
        .unwrap();
        assert!(result.truncated);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].request_seq, 1);
        assert_eq!(
            result
                .next_position
                .as_ref()
                .map(|position| (position.request_seq(), position.event_id().as_str())),
            Some((1, "ev_018f2a3b-4c5d-7000-8000-000000000001"))
        );
        let next = query_request_events(
            &fixture.config,
            &client,
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_a").unwrap(),
            &RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
            result.next_position.as_ref(),
            1,
        )
        .await
        .unwrap();
        assert!(!next.truncated);
        assert_eq!(next.events[0].request_seq, 2);
        assert!(matches!(
            query_request_events(
                &fixture.config,
                &client,
                &TenantId::parse("tenant_a").unwrap(),
                &SiteId::parse("site_a").unwrap(),
                &RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
                None,
                0,
            )
            .await,
            Err(PublishError::InvalidConfig)
        ));
    }

    #[tokio::test]
    async fn request_timeline_backfills_only_empty_model_call_indexes() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let recorded = mock.add(test::handlers::record_ddl());
        let result = query_request_events(
            &fixture.config,
            &Client::default().with_mock(&mock),
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_a").unwrap(),
            &RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
            None,
            1,
        )
        .await
        .unwrap();
        assert!(result.events.is_empty());
        let sql = recorded.query().await;
        assert!(sql.contains(MODEL_CALL_ID_PROJECTION), "{sql}");
        assert_eq!(
            sql.matches("JSONExtractString(payload_json,'model_call_id')")
                .count(),
            1,
            "{sql}"
        );
    }

    #[tokio::test]
    async fn request_event_query_validates_model_stage_metadata_before_pagination() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        let mut valid = event_summary("ev_018f2a3b-4c5d-7000-8000-000000000001", 1);
        valid.proof_kind = "model".to_owned();
        valid.confidence = Some(0.75);
        valid.confidence_status = "provided".to_owned();
        valid.model_revision = "jev-1.13.0".to_owned();
        valid.model_call_id = Some("mdl_018f2a3b-4c5d-7000-8000-000000000001".to_owned());
        mock.add(test::handlers::provide([valid.clone()]));
        let result =
            query_request_events(&fixture.config, &client, &tenant, &site, &request, None, 1)
                .await
                .unwrap();
        assert_eq!(result.events[0].model_revision, "jev-1.13.0");

        let mutations: [fn(&mut AuditEventSummary); 10] = [
            |row| row.confidence = None,
            |row| row.confidence = Some(f64::NAN),
            |row| row.confidence_status = "unavailable".to_owned(),
            |row| row.outcome = "CANCELLED".to_owned(),
            |row| {
                row.event_type = "stage.skipped".to_owned();
                row.outcome = "SKIPPED".to_owned();
            },
            |row| row.model_revision = "model/revision".to_owned(),
            |row| row.model_call_id = Some("model_018f2a3b-4c5d-7000-8000-000000000001".to_owned()),
            |row| row.model_call_id = None,
            |row| row.proof_kind = "observation".to_owned(),
            |row| {
                row.proof_kind = "deterministic".to_owned();
                row.confidence = None;
                row.confidence_status = "not_applicable".to_owned();
            },
        ];
        for mutate in mutations {
            let mut invalid = valid.clone();
            mutate(&mut invalid);
            mock.add(test::handlers::provide([valid.clone(), invalid]));
            assert!(matches!(
                query_request_events(&fixture.config, &client, &tenant, &site, &request, None, 1,)
                    .await,
                Err(PublishError::InvalidEvent)
            ));
        }
    }

    #[tokio::test]
    async fn cross_request_query_is_typed_and_keyset_bounded() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        mock.add(test::handlers::provide_with_summary(
            [
                search_event("req_018f2a3b-4c5d-7000-8000-000000000001", 1),
                search_event("req_018f2a3b-4c5d-7000-8000-000000000002", 2),
            ],
            r#"{"read_rows":"13","read_bytes":"2048"}"#,
        ));
        mock.add(test::handlers::provide([search_event(
            "req_018f2a3b-4c5d-7000-8000-000000000002",
            2,
        )]));
        let client = Client::default().with_mock(&mock);
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            vec![QueryFilter::Text {
                field: QueryTextField::ReasonCode,
                value: "POLICY_ALLOWED".to_owned(),
            }],
            QuerySort::OccurredAtAsc,
            1,
        )
        .unwrap();
        let result = query_audit_events(
            &fixture.config,
            &client,
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_a").unwrap(),
            &plan,
            None,
        )
        .await
        .unwrap();
        assert!(result.truncated);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.scanned_rows, Some(13));
        assert_eq!(result.scanned_bytes, Some(2048));
        let json = serde_json::to_value(&result.events[0]).unwrap();
        assert_eq!(json["occurred_at"], "1970-01-01T00:00:20.000123Z");
        let decoded: SearchEventSummary = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.occurred_at, result.events[0].occurred_at);
        let next = query_audit_events(
            &fixture.config,
            &client,
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_a").unwrap(),
            &plan,
            result.next_position.as_ref(),
        )
        .await
        .unwrap();
        assert!(!next.truncated);
        assert!(next.next_position.is_none());
        assert_eq!(next.scanned_rows, None);
        assert_eq!(next.scanned_bytes, None);
        assert_eq!(
            next.events[0].request_id.as_deref(),
            Some("req_018f2a3b-4c5d-7000-8000-000000000002")
        );
    }

    #[tokio::test]
    async fn cross_request_query_binds_scope_predicates_and_keyset() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_b").unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000002").unwrap();
        let position = SearchPosition::new(
            DateTime::from_timestamp_micros(20_000_123).unwrap(),
            event.clone(),
        )
        .unwrap();
        for (sort, operator, order) in [
            (QuerySort::OccurredAtAsc, ">", "ASC"),
            (QuerySort::OccurredAtDesc, "<", "DESC"),
        ] {
            let recorded = mock.add(test::handlers::record_ddl());
            let plan = QueryPlan::new(
                QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
                vec![
                    QueryFilter::RequestId(request.clone()),
                    QueryFilter::EventId(event.clone()),
                    QueryFilter::Text {
                        field: QueryTextField::EventType,
                        value: "stage.completed".to_owned(),
                    },
                    QueryFilter::Text {
                        field: QueryTextField::Stage,
                        value: "admission".to_owned(),
                    },
                    QueryFilter::Text {
                        field: QueryTextField::OperationId,
                        value: "orders.detail".to_owned(),
                    },
                    QueryFilter::Text {
                        field: QueryTextField::ModelRevision,
                        value: "model-r1".to_owned(),
                    },
                    QueryFilter::Outcome(QueryOutcome::Allow),
                    QueryFilter::ConfidenceAtMost(ConfidenceThreshold::new(8_250).unwrap()),
                ],
                sort,
                7,
            )
            .unwrap();
            let result = query_audit_events(
                &fixture.config,
                &client,
                &tenant,
                &site,
                &plan,
                Some(&position),
            )
            .await
            .unwrap();
            assert!(result.events.is_empty());
            let sql = recorded.query().await;
            for fragment in [
                "FROM `audit_events_active` WHERE tenant_id = 'tenant_a' AND site_id = 'site_b'",
                "occurred_at >= fromUnixTimestamp64Micro(1000000) AND occurred_at < fromUnixTimestamp64Micro(61000000)",
                "request_id = 'req_018f2a3b-4c5d-7000-8000-000000000001'",
                "event_id = 'ev_018f2a3b-4c5d-7000-8000-000000000002'",
                "event_type = 'stage.completed'",
                "stage = 'admission'",
                "operation_id = 'orders.detail'",
                "model_revision = 'model-r1'",
                "outcome = 'ALLOW'",
                "confidence <= 0.825",
            ] {
                assert!(sql.contains(fragment), "{fragment}: {sql}");
            }
            assert!(sql.contains(&format!("tuple(occurred_at,event_id) {operator} tuple(fromUnixTimestamp64Micro(20000123),'ev_018f2a3b-4c5d-7000-8000-000000000002')")));
            assert!(sql.contains(&format!(
                "ORDER BY occurred_at {order},event_id {order} LIMIT 8"
            )));
            assert!(sql.contains(MODEL_CALL_ID_PROJECTION), "{sql}");
            assert_eq!(
                sql.matches("JSONExtractString(payload_json,'model_call_id')")
                    .count(),
                1,
                "{sql}"
            );
        }
    }

    #[tokio::test]
    async fn cross_request_query_binds_historical_grant_and_identity_fields() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let captured = mock.add(test::handlers::record_ddl());
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            vec![
                QueryFilter::GrantId(
                    GrantId::parse("grant_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
                ),
                QueryFilter::AuthBindingId(
                    AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
                ),
            ],
            QuerySort::OccurredAtDesc,
            2,
        )
        .unwrap();
        query_audit_events(
            &fixture.config,
            &Client::default().with_mock(&mock),
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_b").unwrap(),
            &plan,
            None,
        )
        .await
        .unwrap();
        let sql = captured.query().await;
        for fragment in [
            "WHERE tenant_id = 'tenant_a' AND site_id = 'site_b'",
            "occurred_at >= fromUnixTimestamp64Micro(1000000) AND occurred_at < fromUnixTimestamp64Micro(61000000)",
            "AND ((event_type IN ('grant.issued','response_grant.issued') AND JSONExtractString(payload_json,'grant_id') = 'grant_018f2a3b-4c5d-7000-8000-000000000001') OR (event_type = 'share.issued' AND JSONExtractString(payload_json,'issuer_grant_id') = 'grant_018f2a3b-4c5d-7000-8000-000000000001'))",
            "AND ((event_type IN ('session.created','binding.created','identity.refreshed','epoch.changed','binding.revoked','grant.issued','response_grant.issued') AND JSONExtractString(payload_json,'binding_id') = 'auth_018f2a3b-4c5d-7000-8000-000000000002') OR (event_type = 'share.issued' AND JSONExtractString(payload_json,'issuer_binding_id') = 'auth_018f2a3b-4c5d-7000-8000-000000000002'))",
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 3",
        ] {
            assert!(sql.contains(fragment), "missing query fragment: {fragment}");
        }
        let projection = sql.split_once(" FROM ").unwrap().0;
        assert!(projection.contains(MODEL_CALL_ID_PROJECTION), "{sql}");
        assert_eq!(projection.matches("payload_json").count(), 1, "{sql}");
    }

    #[tokio::test]
    async fn cross_request_query_binds_direct_case_and_artifact_references() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let captured = mock.add(test::handlers::record_ddl());
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            vec![
                QueryFilter::CaseId(
                    CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
                ),
                QueryFilter::ArtifactId(
                    ArtifactId::parse("artifact_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
                ),
            ],
            QuerySort::OccurredAtDesc,
            2,
        )
        .unwrap();
        query_audit_events(
            &fixture.config,
            &Client::default().with_mock(&mock),
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_b").unwrap(),
            &plan,
            None,
        )
        .await
        .unwrap();
        let sql = captured.query().await;
        for fragment in [
            "WHERE tenant_id = 'tenant_a' AND site_id = 'site_b'",
            "occurred_at >= fromUnixTimestamp64Micro(1000000) AND occurred_at < fromUnixTimestamp64Micro(61000000)",
            "tuple(stage,event_type) IN (('case_management','case.created'),('case_management','case.closed'),('case_management','case.evidence.added'),('evidence_access','evidence.access.requested'),('evidence_hold','evidence.hold.created'),('evidence_hold','evidence.hold.released'))",
            "JSONExtractString(payload_json,'case_id') = 'case_018f2a3b-4c5d-7000-8000-000000000001'",
            "stage = 'control_access' AND event_type IN ('case.created','case.closed','case.evidence.added','console.case.read','evidence.access.requested','evidence.access.approved','evidence.access.denied','console.evidence.hold.created','console.evidence.hold.released','console.evidence.hold.read','console.evidence.access.read')",
            "JSONExtractString(payload_json,'target_case_id') = 'case_018f2a3b-4c5d-7000-8000-000000000001'",
            "AND (has(evidence_refs,'artifact_018f2a3b-4c5d-7000-8000-000000000002') OR (stage = 'control_access' AND event_type IN ('console.manifest.read','case.evidence.added','evidence.access.requested','evidence.access.approved','evidence.access.denied','evidence.read','console.evidence.hold.created','console.evidence.hold.released')",
            "JSONExtractString(payload_json,'target_artifact_id') = 'artifact_018f2a3b-4c5d-7000-8000-000000000002'",
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 3",
        ] {
            assert!(sql.contains(fragment), "missing query fragment: {fragment}");
        }
        let projection = sql.split_once(" FROM ").unwrap().0;
        assert!(projection.contains(MODEL_CALL_ID_PROJECTION), "{sql}");
        assert_eq!(projection.matches("payload_json").count(), 1, "{sql}");
    }

    #[tokio::test]
    async fn cross_request_query_binds_restricted_calibration_report_history() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let captured = mock.add(test::handlers::record_ddl());
        let report =
            CalibrationReportId::parse("calr_018f2a3b-4c5d-7000-8000-000000000003").unwrap();
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            vec![QueryFilter::CalibrationReportId(report)],
            QuerySort::OccurredAtDesc,
            2,
        )
        .unwrap();
        query_audit_events(
            &fixture.config,
            &Client::default().with_mock(&mock),
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_b").unwrap(),
            &plan,
            None,
        )
        .await
        .unwrap();
        let sql = captured.query().await;
        for fragment in [
            "event_type = 'calibration.reported'",
            "'calibration.report_retention.purge_requested'",
            "'calibration.report_retention.orphan_purge_failed'",
            "JSONExtractString(payload_json,'report_id') = 'calr_018f2a3b-4c5d-7000-8000-000000000003'",
            "stage = 'control_access' AND event_type = 'console.calibration.report.read'",
            "JSONExtractString(payload_json,'target_calibration_report_id') = 'calr_018f2a3b-4c5d-7000-8000-000000000003'",
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 3",
        ] {
            assert!(sql.contains(fragment), "missing query fragment: {fragment}");
        }
        assert_eq!(sql.matches("payload_json").count(), 3, "{sql}");
    }

    #[tokio::test]
    async fn cross_request_query_binds_restricted_model_call_history() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let captured = mock.add(test::handlers::record_ddl());
        let model_call = ModelCallId::parse("mdl_018f2a3b-4c5d-7000-8000-000000000004").unwrap();
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            vec![QueryFilter::ModelCallId(model_call)],
            QuerySort::OccurredAtDesc,
            2,
        )
        .unwrap();
        query_audit_events(
            &fixture.config,
            &Client::default().with_mock(&mock),
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_b").unwrap(),
            &plan,
            None,
        )
        .await
        .unwrap();
        let sql = captured.query().await;
        for fragment in [
            "event_type IN ('model.started','model.requested','model.responded','model.failed','model.timeout','model.cancelled')",
            "JSONExtractString(payload_json,'model_call_id') = 'mdl_018f2a3b-4c5d-7000-8000-000000000004'",
            "stage = 'control_access' AND event_type = 'console.model.read'",
            "JSONExtractString(payload_json,'target_model_call_id') = 'mdl_018f2a3b-4c5d-7000-8000-000000000004'",
            "ORDER BY occurred_at DESC,event_id DESC LIMIT 3",
        ] {
            assert!(sql.contains(fragment), "missing query fragment: {fragment}");
        }
        assert_eq!(sql.matches("payload_json").count(), 3, "{sql}");
    }

    #[tokio::test]
    async fn cross_request_query_descends_and_preserves_optional_fields() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let first = search_event("req_018f2a3b-4c5d-7000-8000-000000000001", 1);
        let mut second = search_event("req_018f2a3b-4c5d-7000-8000-000000000002", 2);
        second.event_type = "request.completed".to_owned();
        second.outcome = Some("ALLOW".to_owned());
        second.stage = None;
        second.proof_kind = None;
        second.confidence_status = None;
        let mut third = search_event("req_018f2a3b-4c5d-7000-8000-000000000003", 3);
        third.event_type = "audit.recovered".to_owned();
        third.request_id = None;
        third.stage = None;
        third.outcome = None;
        third.proof_kind = None;
        third.confidence_status = None;
        mock.add(test::handlers::provide([third, second.clone()]));
        mock.add(test::handlers::provide([second, first]));
        let client = Client::default().with_mock(&mock);
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            Vec::new(),
            QuerySort::OccurredAtDesc,
            1,
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let result = query_audit_events(&fixture.config, &client, &tenant, &site, &plan, None)
            .await
            .unwrap();
        assert_eq!(result.events[0].request_seq, 3);
        assert_eq!(result.events[0].request_id, None);
        assert_eq!(result.events[0].outcome, None);
        let next = query_audit_events(
            &fixture.config,
            &client,
            &tenant,
            &site,
            &plan,
            result.next_position.as_ref(),
        )
        .await
        .unwrap();
        assert_eq!(next.events[0].request_seq, 2);
        assert_eq!(next.events[0].outcome.as_deref(), Some("ALLOW"));
        assert_eq!(next.events[0].proof_kind, None);
        assert!(next.truncated);
    }

    #[tokio::test]
    async fn cross_request_query_rejects_invalid_rows() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            Vec::new(),
            QuerySort::OccurredAtAsc,
            1,
        )
        .unwrap();
        let mutations: [fn(&mut SearchEventSummary); 12] = [
            |row| row.confidence = Some(f64::NAN),
            |row| row.request_id = Some("invalid".to_owned()),
            |row| row.event_id = "invalid".to_owned(),
            |row| row.stage = Some("invalid stage".to_owned()),
            |row| row.outcome = Some("GRANTED".to_owned()),
            |row| row.proof_kind = Some("trusted".to_owned()),
            |row| row.confidence_status = Some("provided".to_owned()),
            |row| row.confidence = Some(0.5),
            |row| row.request_seq = 0,
            |row| row.model_revision = Some(String::new()),
            |row| row.sensitivity = "UNKNOWN".to_owned(),
            |row| row.evidence_refs = vec!["invalid".to_owned()],
        ];
        for mutate in mutations {
            let mut invalid = search_event("req_018f2a3b-4c5d-7000-8000-000000000001", 1);
            mutate(&mut invalid);
            mock.add(test::handlers::provide([invalid]));
            assert!(matches!(
                query_audit_events(
                    &fixture.config,
                    &client,
                    &TenantId::parse("tenant_a").unwrap(),
                    &SiteId::parse("site_a").unwrap(),
                    &plan,
                    None,
                )
                .await,
                Err(PublishError::InvalidEvent)
            ));
        }
    }

    #[tokio::test]
    async fn cross_request_query_rejects_invalid_order_and_window() {
        let fixture = Fixture::new();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let first = search_event("req_018f2a3b-4c5d-7000-8000-000000000001", 1);
        let second = search_event("req_018f2a3b-4c5d-7000-8000-000000000002", 2);
        let mut early = first.clone();
        early.occurred_at = DateTime::from_timestamp(0, 0).unwrap();
        let mut end = first.clone();
        end.occurred_at = DateTime::from_timestamp(61, 0).unwrap();
        let mut repeated_id = first.clone();
        repeated_id.occurred_at = DateTime::from_timestamp(21, 0).unwrap();
        let after =
            SearchPosition::new(first.occurred_at, EventId::parse(&first.event_id).unwrap())
                .unwrap();
        for (sort, rows, position) in [
            (
                QuerySort::OccurredAtAsc,
                vec![first.clone(), first.clone()],
                None,
            ),
            (
                QuerySort::OccurredAtAsc,
                vec![second.clone(), first.clone()],
                None,
            ),
            (
                QuerySort::OccurredAtDesc,
                vec![first.clone(), second.clone()],
                None,
            ),
            (QuerySort::OccurredAtAsc, vec![early], None),
            (QuerySort::OccurredAtAsc, vec![end], None),
            (
                QuerySort::OccurredAtAsc,
                vec![first.clone(), repeated_id.clone()],
                None,
            ),
            (
                QuerySort::OccurredAtAsc,
                vec![repeated_id],
                Some(after.clone()),
            ),
            (
                QuerySort::OccurredAtAsc,
                vec![first.clone()],
                Some(after.clone()),
            ),
            (QuerySort::OccurredAtDesc, vec![second.clone()], Some(after)),
            // A malformed lookahead must fail the whole page, including valid rows.
            (
                QuerySort::OccurredAtAsc,
                vec![first.clone(), second.clone(), second],
                None,
            ),
        ] {
            let mock = test::Mock::new();
            mock.add(test::handlers::provide(rows));
            let client = Client::default().with_mock(&mock);
            let plan = QueryPlan::new(
                QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
                Vec::new(),
                sort,
                1,
            )
            .unwrap();
            assert!(matches!(
                query_audit_events(
                    &fixture.config,
                    &client,
                    &tenant,
                    &site,
                    &plan,
                    position.as_ref()
                )
                .await,
                Err(PublishError::InvalidEvent)
            ));
        }
    }

    #[tokio::test]
    async fn cross_request_query_validates_cursor_before_index_access() {
        let fixture = Fixture::new();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let event_id = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            Vec::new(),
            QuerySort::OccurredAtAsc,
            1,
        )
        .unwrap();
        let outside =
            SearchPosition::new(DateTime::from_timestamp(61, 0).unwrap(), event_id.clone())
                .unwrap();
        assert!(matches!(
            query_audit_events(
                &fixture.config,
                &client,
                &tenant,
                &site,
                &plan,
                Some(&outside)
            )
            .await,
            Err(PublishError::InvalidConfig)
        ));
        for timestamp in [(20, 1), (59, 1_000_000_000)] {
            assert!(
                SearchPosition::new(
                    DateTime::from_timestamp(timestamp.0, timestamp.1).unwrap(),
                    event_id.clone()
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn cross_request_query_classifies_budget_and_dependency_failures() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let client = Client::default().with_mock(&mock);
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            Vec::new(),
            QuerySort::OccurredAtAsc,
            1,
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        for code in [158, 159, 241, 209] {
            mock.add(test::handlers::exception(code));
            let error = query_audit_events(&fixture.config, &client, &tenant, &site, &plan, None)
                .await
                .unwrap_err();
            if code == 209 {
                assert!(matches!(error, PublishError::ClickHouse(_)));
            } else {
                assert!(matches!(error, PublishError::QueryBudgetExceeded));
            }
        }
        let mut oversized = search_event("req_018f2a3b-4c5d-7000-8000-000000000001", 1);
        oversized.event_type = "x".repeat(16 * 1024 * 1024);
        mock.add(test::handlers::provide([oversized]));
        assert!(matches!(
            query_audit_events(&fixture.config, &client, &tenant, &site, &plan, None).await,
            Err(PublishError::QueryBudgetExceeded)
        ));
    }

    #[tokio::test]
    async fn analytical_query_deadlines_bound_stalled_connections() {
        let fixture = Fixture::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client =
            Client::default().with_url(format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
            drop(stream);
        });
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(1), UnixSeconds::new(61)).unwrap(),
            Vec::new(),
            QuerySort::OccurredAtAsc,
            1,
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let model_call = ModelCallId::parse("mdl_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        let (result, model_result) = tokio::join!(
            query_audit_events(&fixture.config, &client, &tenant, &site, &plan, None),
            query_model_call(&fixture.config, &client, &tenant, &site, &model_call),
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        assert!(matches!(result, Err(PublishError::QueryTimeout)));
        assert!(matches!(model_result, Err(PublishError::QueryTimeout)));
    }

    #[tokio::test]
    async fn request_summary_is_scoped_and_validated() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        mock.add(test::handlers::provide([RequestSummaryRow {
            event_count: 4,
            first_occurred_at: Utc::now(),
            last_occurred_at: Utc::now(),
            method: "POST".to_owned(),
            operation_id: "orders.create".to_owned(),
            decision: "ALLOW".to_owned(),
            reason_code: "POLICY_ALLOWED".to_owned(),
            status: Some(201),
            origin_state: "response_received".to_owned(),
            duration_us: 42,
            forwarded: 1,
            terminal: 1,
        }]));
        mock.add(test::handlers::provide([RequestStageSummary {
            stage: "admission".to_owned(),
            outcome: "PASS".to_owned(),
            reason_code: "POLICY_ALLOWED".to_owned(),
            proof_kind: "deterministic".to_owned(),
            confidence: None,
            confidence_status: "not_applicable".to_owned(),
            first_request_seq: 2,
            last_request_seq: 2,
            duration_us: 10,
            event_count: 1,
        }]));
        mock.add(test::handlers::provide(Vec::<RequestSummaryRow>::new()));
        let client = Client::default().with_mock(&mock);
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        let summary = query_request_summary(&fixture.config, &client, &tenant, &site, &request)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(summary.method.as_deref(), Some("POST"));
        assert_eq!(summary.status, Some(201));
        assert!(summary.forwarded);
        assert!(summary.terminal);
        assert!(summary.business_result_confirmed);
        assert_eq!(summary.stages[0].stage, "admission");
        let mut invalid_stage = summary.stages[0].clone();
        invalid_stage.first_request_seq = 0;
        assert!(super::validate_stage_summary(&invalid_stage).is_err());
        for (outcome, confidence, status) in [
            ("PASS", None, "provided"),
            ("PASS", Some(0.75), "not_provided"),
            ("SKIPPED", Some(0.75), "provided"),
            ("CANCELLED", Some(0.75), "provided"),
        ] {
            let mut invalid_stage = summary.stages[0].clone();
            invalid_stage.proof_kind = "model".to_owned();
            invalid_stage.outcome = outcome.to_owned();
            invalid_stage.confidence = confidence;
            invalid_stage.confidence_status = status.to_owned();
            assert!(super::validate_stage_summary(&invalid_stage).is_err());
        }
        assert!(
            query_request_summary(&fixture.config, &client, &tenant, &site, &request)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn request_stage_summary_keeps_latest_null_confidence() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        let recorded = mock.add(test::handlers::record_ddl());
        let stages = super::query_request_stages(
            &fixture.config,
            &Client::default().with_mock(&mock),
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_a").unwrap(),
            &RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
        )
        .await
        .unwrap();
        assert!(stages.is_empty());
        assert!(
            recorded
                .query()
                .await
                .contains("argMax(tuple(confidence),tuple(request_seq,event_id)).1 AS confidence")
        );
    }

    fn event_summary(event_id: &str, request_seq: u32) -> AuditEventSummary {
        AuditEventSummary {
            event_id: event_id.to_owned(),
            event_type: "stage.completed".to_owned(),
            stage: "admission".to_owned(),
            outcome: "PASS".to_owned(),
            reason_code: "POLICY_ALLOWED".to_owned(),
            proof_kind: "deterministic".to_owned(),
            confidence: None,
            confidence_status: "not_applicable".to_owned(),
            occurred_at: Utc::now(),
            request_seq,
            duration_us: 10,
            policy_revision: "policy-r1".to_owned(),
            model_revision: String::new(),
            model_call_id: None,
            evidence_refs: Vec::new(),
            cause_event_ids: Vec::new(),
            sensitivity: "INTERNAL".to_owned(),
        }
    }

    fn search_event(request_id: &str, request_seq: u32) -> SearchEventSummary {
        SearchEventSummary {
            request_id: Some(request_id.to_owned()),
            event_id: format!("ev_018f2a3b-4c5d-7000-8000-{request_seq:012x}"),
            event_type: "stage.completed".to_owned(),
            stage: Some("admission".to_owned()),
            outcome: Some("PASS".to_owned()),
            reason_code: Some("POLICY_ALLOWED".to_owned()),
            proof_kind: Some("deterministic".to_owned()),
            confidence: None,
            confidence_status: Some("not_applicable".to_owned()),
            occurred_at: DateTime::from_timestamp(20, 123_000).unwrap(),
            request_seq,
            duration_us: 10,
            policy_revision: "policy-r1".to_owned(),
            model_revision: None,
            model_call_id: None,
            evidence_refs: Vec::new(),
            cause_event_ids: Vec::new(),
            sensitivity: "INTERNAL".to_owned(),
        }
    }

    #[test]
    fn metadata_retention_is_bounded() {
        for days in [0, 3_651] {
            assert!(matches!(
                PublisherConfig::new(
                    "journal",
                    "manifests",
                    "checkpoints",
                    "clickhouse-primary",
                    "audit_events",
                    days,
                    1024,
                ),
                Err(PublishError::InvalidConfig)
            ));
        }
    }

    #[tokio::test]
    async fn failed_insert_never_advances_checkpoint() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
        mock.add(test::handlers::exception(209));
        let client = Client::default().with_mock(&mock);
        let verifier = fixture.seal_key.verifying_key().unwrap();
        let error = publish_sealed_segments(
            &fixture.config,
            &client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PublishError::ClickHouse(_)));
        assert_eq!(fixture.checkpoint_count(), 0);
    }

    #[tokio::test]
    async fn rejects_same_event_id_with_different_content() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        mock.add(test::handlers::provide([ExistingDigest {
            event_id: fixture.event_ids[0].clone(),
            content_digest: [b'0'; 64],
            digest_count: 1,
        }]));
        let client = Client::default().with_mock(&mock);
        let verifier = fixture.seal_key.verifying_key().unwrap();
        let error = publish_sealed_segments(
            &fixture.config,
            &client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PublishError::IntegrityConflict));
        assert_eq!(fixture.checkpoint_count(), 0);
    }

    #[tokio::test]
    async fn detects_conflict_created_during_insert() {
        let fixture = Fixture::new();
        let mock = test::Mock::new();
        mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
        let insertion = mock.add(test::handlers::record::<IndexRow>());
        mock.add(test::handlers::provide([ExistingDigest {
            event_id: fixture.event_ids[0].clone(),
            content_digest: [b'0'; 64],
            digest_count: 1,
        }]));
        let client = Client::default().with_mock(&mock);
        let verifier = fixture.seal_key.verifying_key().unwrap();
        let error = publish_sealed_segments(
            &fixture.config,
            &client,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .await
        .unwrap_err();
        let _: Vec<IndexRow> = insertion.collect().await;
        assert!(matches!(error, PublishError::IntegrityConflict));
        assert_eq!(fixture.checkpoint_count(), 0);
    }

    #[test]
    fn rejects_event_outside_authenticated_envelope() {
        let boot_id = Uuid::now_v7().to_string();
        let event_id = format!("ev_{}", Uuid::now_v7());
        let typed_event_id = EventId::parse(event_id.clone()).unwrap();
        let json = event_json(&event_id, &boot_id);
        let sequence_error = IndexRow::parse(
            json.as_bytes(),
            &typed_event_id,
            2,
            &boot_id,
            "1".repeat(64),
            TimeDelta::try_days(30).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(sequence_error, PublishError::InvalidEvent));

        let synthetic = json.replace("\"example_only\":false", "\"example_only\":true");
        let synthetic_error = IndexRow::parse(
            synthetic.as_bytes(),
            &typed_event_id,
            1,
            &boot_id,
            "1".repeat(64),
            TimeDelta::try_days(30).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(synthetic_error, PublishError::InvalidEvent));
    }

    #[test]
    fn reports_only_the_contiguous_publication_watermark() {
        let fixture = Fixture::with_events(2);
        let later_boot_id = checkpoint_segment(&fixture, 1);
        let verifier = fixture.seal_key.verifying_key().unwrap();
        let gapped = inspect_publication_health(
            &fixture.config,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .unwrap();
        assert_eq!(gapped.closed_segments, 2);
        assert_eq!(gapped.published_segments, 1);
        assert_eq!(gapped.pending_segments, 1);
        assert!(gapped.has_gaps);
        assert_eq!(gapped.index_watermark, None);

        checkpoint_segment(&fixture, 0);
        let continuous = inspect_publication_health(
            &fixture.config,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .unwrap();
        assert_eq!(continuous.published_segments, 2);
        assert_eq!(continuous.pending_segments, 0);
        assert!(!continuous.has_gaps);
        assert_eq!(
            continuous.index_watermark.unwrap().producer_boot_id,
            later_boot_id
        );
    }

    #[test]
    fn reports_unsealed_tail_as_pending() {
        let fixture = Fixture::new();
        let manifest = fs::read_dir(&fixture.config.manifest_directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::remove_file(manifest).unwrap();
        let verifier = fixture.seal_key.verifying_key().unwrap();
        let health = inspect_publication_health(
            &fixture.config,
            "journal-key-r1",
            &fixture.journal_key,
            &verifier,
        )
        .unwrap();
        assert_eq!(health.pending_segments, 1);
        assert_eq!(health.unsealed_segments, 1);
        assert!(!health.has_gaps);
        assert_eq!(health.index_watermark, None);
    }

    #[test]
    fn indexes_reconciled_abort_without_inventing_an_http_status() {
        let payload = r#"{"decision":"ALLOW","reason_code":"ORIGIN_OUTCOME_UNKNOWN","status":null,"origin_state":"unknown","duration_us":0}"#;
        let summary = PayloadSummary::parse("request.aborted", payload).unwrap();
        assert_eq!(summary.outcome, "ALLOW");
        assert_eq!(summary.reason_code, "ORIGIN_OUTCOME_UNKNOWN");
        assert!(PayloadSummary::parse("request.completed", payload).is_err());

        let prefix = r#"{"decision":"UNKNOWN","reason_code":"REQUEST_INCOMPLETE","status":null,"origin_state":"not_sent","duration_us":0}"#;
        let summary = PayloadSummary::parse("request.aborted", prefix).unwrap();
        assert_eq!(summary.outcome, "UNKNOWN");
        assert!(PayloadSummary::parse("request.completed", prefix).is_err());
    }

    fn checkpoint_segment(fixture: &Fixture, index: usize) -> String {
        prepare_private_directory(&fixture.config.checkpoint_directory, true).unwrap();
        let paths = closed_segment_paths(&fixture.config.journal_directory).unwrap();
        let path = &paths[index];
        let boot_id = super::segment_boot_id(path).unwrap();
        let manifest_path = fixture
            .config
            .manifest_directory
            .join(format!("segment-{boot_id}.xjs"));
        let manifest = read_private_bounded(&manifest_path, super::MANIFEST_BYTES_MAX).unwrap();
        let verifier = fixture.seal_key.verifying_key().unwrap();
        let segment = super::verify_sealed_segment(
            path,
            "journal-key-r1",
            &fixture.journal_key,
            &manifest,
            &verifier,
        )
        .unwrap();
        let checkpoint =
            Checkpoint::from_segment(&fixture.config.target_id, &fixture.config.table, &segment);
        write_checkpoint(&fixture.config.checkpoint_directory, &checkpoint).unwrap();
        segment.producer_boot_id
    }

    fn private_directory(path: &Path) {
        fs::create_dir(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn event_json(event_id: &str, boot_id: &str) -> String {
        format!(
            r#"{{"schema_version":3,"event_id":"{event_id}","event_type":"request.accepted","tenant_id":"tenant_demo","site_id":"site_demo","request_id":"req_01a0afa6-3320-758a-9554-d0d3b561b8c6","trace_id":"01a0afa63320758a9554d0d3b561b8c6","span_id":"01a0afa63320758a","producer_id":"gateway-1","producer_boot_id":"{boot_id}","producer_seq":1,"request_seq":1,"occurred_at":"2026-09-18T00:00:00.123Z","observed_at":"2026-09-18T00:00:00.123Z","policy_revision":"policy-r1","example_only":false,"evidence_refs":[],"cause_event_ids":[],"payload":{{"method":"GET","operation_id":null,"origin_state":"not_sent"}},"sensitivity":"INTERNAL","integrity":{{"state":"pending","previous_hash":null,"event_hash":null}}}}"#
        )
    }
}
