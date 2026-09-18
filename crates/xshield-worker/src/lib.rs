//! Publishes authenticated audit journal segments to the analytical index.

#![warn(missing_docs)]

use chrono::{DateTime, TimeDelta, Utc};
use clickhouse::{Client, Row, sql::Identifier};
use serde::{Deserialize, Serialize};
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
use xshield_core::domain::{EventId, PolicyRevision, RequestId, SiteId, TenantId};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const MANIFEST_BYTES_MAX: u64 = 1024;
const LIST_ITEMS_MAX: usize = 256;
const NAME_BYTES_MAX: usize = 128;
const MAX_METADATA_RETENTION_DAYS: u16 = 3_650;

/// Immutable publication settings for one analytical destination.
#[derive(Clone, Debug)]
pub struct PublisherConfig {
    journal_directory: PathBuf,
    manifest_directory: PathBuf,
    checkpoint_directory: PathBuf,
    target_id: String,
    table: String,
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
        let metadata_retention = TimeDelta::try_days(i64::from(metadata_retention_days))
            .filter(|_| (1..=MAX_METADATA_RETENTION_DAYS).contains(&metadata_retention_days))
            .ok_or(PublishError::InvalidConfig)?;
        if !valid_name(&target_id) || !valid_name(&table) || max_segment_bytes == 0 {
            return Err(PublishError::InvalidConfig);
        }
        Ok(Self {
            journal_directory: journal_directory.into(),
            manifest_directory: manifest_directory.into(),
            checkpoint_directory: checkpoint_directory.into(),
            target_id,
            table,
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
    trace_id: String,
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
    duration_us: u64,
    policy_revision: String,
    model_revision: String,
    evidence_refs: Vec<String>,
    cause_event_ids: Vec<String>,
    sensitivity: String,
    payload_json: String,
    event_hash: String,
    content_digest: String,
    ingest_revision: u64,
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
        PolicyRevision::parse(event.policy_revision.clone())
            .map_err(|_| PublishError::InvalidEvent)?;
        if let Some(request_id) = &event.request_id {
            RequestId::parse(request_id.clone()).map_err(|_| PublishError::InvalidEvent)?;
        }
        validate_id_list(&event.evidence_refs, None)?;
        validate_id_list(&event.cause_event_ids, Some("ev_"))?;
        let occurred_at = DateTime::parse_from_rfc3339(&event.occurred_at)
            .map_err(|_| PublishError::InvalidEvent)?
            .with_timezone(&Utc);
        let observed_at = DateTime::parse_from_rfc3339(&event.observed_at)
            .map_err(|_| PublishError::InvalidEvent)?
            .with_timezone(&Utc);
        let retention_expires_at = occurred_at
            .checked_add_signed(metadata_retention)
            .ok_or(PublishError::InvalidEvent)?;
        let summary = PayloadSummary::parse(&event.event_type, event.payload.get())?;
        let ingest_revision = digest_revision(&digest)?;
        Ok(Self {
            tenant_id: event.tenant_id,
            site_id: event.site_id,
            request_id: event.request_id.unwrap_or_default(),
            trace_id: event.trace_id,
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
            duration_us: summary.duration_us,
            policy_revision: event.policy_revision,
            model_revision: String::new(),
            evidence_refs: event.evidence_refs,
            cause_event_ids: event.cause_event_ids,
            sensitivity: event.sensitivity,
            payload_json: event.payload.get().to_owned(),
            event_hash: digest.clone(),
            content_digest: digest,
            ingest_revision,
        })
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
    duration_us: u64,
}

impl PayloadSummary {
    fn parse(event_type: &str, json: &str) -> Result<Self, PublishError> {
        match event_type {
            "stage.completed" | "stage.skipped" => {
                let payload: StagePayload = serde_json::from_str(json)?;
                payload.validate()
            }
            "request.accepted" => {
                serde_json::from_str::<RequestAcceptedPayload>(json)?.validate()?;
                Ok(Self::default())
            }
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
    fn validate(self) -> Result<(), PublishError> {
        if !valid_method(&self.method)
            || self
                .operation_id
                .as_deref()
                .is_some_and(|value| !valid_name(value))
            || self.origin_state != "not_sent"
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(())
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
    confidence: Option<f64>,
    confidence_status: String,
    duration_us: u64,
    rule_revision: Option<String>,
    model_call_id: Option<String>,
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
            || !matches!(
                self.confidence_status.as_str(),
                "provided" | "not_applicable" | "not_provided" | "unavailable"
            )
            || self
                .confidence
                .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
            || (self.proof_kind == "deterministic"
                && (self.confidence.is_some() || self.confidence_status != "not_applicable"))
            || (matches!(self.outcome.as_str(), "SKIPPED" | "CANCELLED")
                && self.confidence.is_some())
            || self
                .rule_revision
                .as_deref()
                .is_some_and(|value| PolicyRevision::parse(value).is_err())
            || self
                .model_call_id
                .as_deref()
                .is_some_and(|value| valid_prefixed_v7(value, "model_").is_err())
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
            duration_us: self.duration_us,
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
            outcome: self.origin_state,
            reason_code: self.reason_code,
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
    content_digest: String,
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
            "SELECT event_id, any(content_digest) AS content_digest, \
             uniqExact(content_digest) AS digest_count FROM ? \
             WHERE event_id IN ? GROUP BY event_id",
        )
        .bind(Identifier(table))
        .bind(ids)
        .fetch_all::<ExistingDigest>()
        .await?;
    for row in existing {
        if row.digest_count != 1 || expected.get(&row.event_id) != Some(&row.content_digest) {
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
    /// Local journal authentication or decryption failed.
    Journal(JournalError),
    /// Local durable storage failed.
    Io(io::Error),
    /// Typed JSON decoding or encoding failed.
    Json(serde_json::Error),
    /// `ClickHouse` query or insert failed.
    ClickHouse(clickhouse::error::Error),
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
            Self::Journal(error) => error.fmt(formatter),
            Self::Io(_) => formatter.write_str("publisher storage failed"),
            Self::Json(_) => formatter.write_str("publisher JSON processing failed"),
            Self::ClickHouse(_) => formatter.write_str("audit index unavailable"),
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

#[cfg(test)]
mod tests {
    use super::{
        Checkpoint, ExistingDigest, IndexRow, PayloadSummary, PublishError, PublisherConfig,
        TimeDelta, closed_segment_paths, inspect_publication_health, prepare_private_directory,
        publish_sealed_segments, read_private_bounded, write_checkpoint,
    };
    use clickhouse::{Client, test};
    use std::{
        fs,
        path::{Path, PathBuf},
    };
    use uuid::Uuid;
    use xshield_audit::{
        JournalKey, JournalLimits, JournalRecord, LocalJournal, SealSigningKey,
        seal_closed_segments,
    };
    use xshield_core::domain::EventId;

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
            drop(journal);
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
            Self {
                root,
                config,
                journal_key,
                seal_key,
                event_ids,
            }
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
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
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
        assert_eq!(rows[0].content_digest.len(), 64);
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
            content_digest: "0".repeat(64),
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
            content_digest: "0".repeat(64),
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
