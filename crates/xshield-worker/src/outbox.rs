//! Typed adapters for transactional `PostgreSQL` outbox facts.
//!
//! Outbox envelopes are a different producer contract from sealed journal
//! records. This module only accepts complete case, catalog, access, identity,
//! calibration-report, response-grant, share-grant, generic grant and retention envelopes from
//! their producers.
//! Other families remain unsupported until their producers expose validated fields.

use super::{
    IndexRow, PayloadSummary, PublishError, WireEvent, hex, insert_rows, reject_remote_conflicts,
    valid_lower_hex, valid_name, valid_prefixed_v7, valid_uuid_v7,
};
use chrono::TimeDelta;
use clickhouse::Client;
use serde::Deserialize;
use std::{collections::BTreeMap, time::Duration};
use xshield_audit::sha256_digest;
use xshield_postgres::{
    OutboxAckOutcome, OutboxEvent, OutboxFailureOutcome, OutboxLeaseConfig, OutboxScope,
    PostgresIdentityStore,
};

mod calibration;
#[cfg(test)]
mod calibration_delivery_tests;
#[cfg(test)]
mod calibration_maintenance_delivery_tests;
#[cfg(test)]
mod clickhouse_tests;
#[cfg(test)]
mod delivery_tests;
mod grant;
#[cfg(test)]
mod grant_producer_tests;
mod hold;
mod identity;
mod response_grant;
mod retention;
#[cfg(test)]
mod retention_delivery_tests;
mod share_grant;

const MAX_OUTBOX_EVENT_BYTES: usize = 64 * 1024;
const MAX_RETRY_SECONDS: u64 = 3_600;
const INVALID_EVENT_CODE: &str = "OUTBOX_INVALID_EVENT";
const INDEX_UNAVAILABLE_CODE: &str = "OUTBOX_INDEX_UNAVAILABLE";
const INTEGRITY_CONFLICT_CODE: &str = "OUTBOX_INTEGRITY_CONFLICT";
const CASE_EVENT_TYPES: &[&str] = &["case.created", "case.closed", "case.evidence.added"];
const EVIDENCE_CATALOG_EVENT_TYPES: &[&str] = &["evidence.cataloged"];
const EVIDENCE_ACCESS_EVENT_TYPES: &[&str] = &[
    "evidence.access.requested",
    "evidence.access.approved",
    "evidence.access.denied",
];
const EVIDENCE_RETENTION_EVENT_TYPES: &[&str] = &[
    "evidence.purge_requested",
    "evidence.deleted",
    "evidence.purge_failed",
    "evidence.orphan.purge_requested",
    "evidence.orphan.deleted",
    "evidence.orphan.purge_failed",
    "evidence.hold.created",
    "evidence.hold.released",
];

#[derive(Clone, Copy)]
enum OutboxFamily {
    Case,
    EvidenceCatalog,
    EvidenceAccess,
    Calibration,
    Identity,
    Grant,
    ResponseGrant,
    ShareGrant,
    EvidenceRetention,
}

impl OutboxFamily {
    const fn event_types(self) -> &'static [&'static str] {
        match self {
            Self::Case => CASE_EVENT_TYPES,
            Self::EvidenceCatalog => EVIDENCE_CATALOG_EVENT_TYPES,
            Self::EvidenceAccess => EVIDENCE_ACCESS_EVENT_TYPES,
            Self::Calibration => calibration::EVENT_TYPES,
            Self::Identity => identity::EVENT_TYPES,
            Self::Grant => grant::EVENT_TYPES,
            Self::ResponseGrant => response_grant::EVENT_TYPES,
            Self::ShareGrant => share_grant::EVENT_TYPES,
            Self::EvidenceRetention => EVIDENCE_RETENTION_EVENT_TYPES,
        }
    }

    fn aggregate_field(self, event_type: &str) -> &'static str {
        match self {
            Self::Case => "case_id",
            Self::EvidenceCatalog | Self::EvidenceRetention => "artifact_id",
            Self::EvidenceAccess => "access_request_id",
            Self::Calibration => match event_type {
                "calibration.reported"
                | "calibration.report_retention.purge_requested"
                | "calibration.report_retention.deleted"
                | "calibration.report_retention.purge_failed"
                | "calibration.report_retention.orphan_purge_requested"
                | "calibration.report_retention.orphan_deleted"
                | "calibration.report_retention.orphan_purge_failed" => "report_id",
                "calibration.lineage_review_retention.purge_requested"
                | "calibration.lineage_review_retention.deleted"
                | "calibration.lineage_review_retention.purge_failed"
                | "calibration.lineage_review_retention.orphan_purge_requested"
                | "calibration.lineage_review_retention.orphan_deleted"
                | "calibration.lineage_review_retention.orphan_purge_failed"
                | "calibration.partition_lineage.reviewed" => "review_id",
                "calibration.read_capability.issued" | "calibration.read_batch.completed" => {
                    "capability_id"
                }
                _ => "",
            },
            Self::Identity => "binding_id",
            Self::Grant | Self::ResponseGrant => "grant_id",
            Self::ShareGrant => "share_id",
        }
    }
}

pub(super) fn supports(event_type: &str) -> bool {
    calibration::EVENT_TYPES.contains(&event_type)
        || identity::EVENT_TYPES.contains(&event_type)
        || grant::EVENT_TYPES.contains(&event_type)
        || response_grant::EVENT_TYPES.contains(&event_type)
        || share_grant::EVENT_TYPES.contains(&event_type)
        || retention::EVENT_TYPES.contains(&event_type)
        || hold::EVENT_TYPES.contains(&event_type)
        || matches!(
            event_type,
            "case.created"
                | "case.closed"
                | "case.evidence.added"
                | "evidence.cataloged"
                | "evidence.access.requested"
                | "evidence.access.approved"
                | "evidence.access.denied"
        )
}

/// Immutable settings for one bounded `PostgreSQL` outbox pass.
#[derive(Clone, Debug)]
pub struct OutboxPublisherConfig {
    table: String,
    metadata_retention: TimeDelta,
    lease: OutboxLeaseConfig,
    retry_after: Duration,
}

impl OutboxPublisherConfig {
    /// Validates the destination table, retention, lease, and retry bounds.
    ///
    /// # Errors
    /// Returns [`PublishError::InvalidConfig`] for an unsafe table name,
    /// unsupported retention, or an unbounded retry interval.
    pub fn new(
        table: impl Into<String>,
        metadata_retention_days: u16,
        lease: OutboxLeaseConfig,
        retry_after: Duration,
    ) -> Result<Self, PublishError> {
        let table = table.into();
        let metadata_retention = TimeDelta::try_days(i64::from(metadata_retention_days))
            .filter(|_| (1..=3_650).contains(&metadata_retention_days))
            .ok_or(PublishError::InvalidConfig)?;
        if OutboxLeaseConfig::new(lease.max_events, lease.max_bytes, lease.lease_for).is_err()
            || !valid_name(&table)
            || retry_after.as_secs() == 0
            || retry_after.as_secs() > MAX_RETRY_SECONDS
            || retry_after.subsec_nanos() != 0
        {
            return Err(PublishError::InvalidConfig);
        }
        Ok(Self {
            table,
            metadata_retention,
            lease,
            retry_after,
        })
    }

    /// Returns the `ClickHouse` destination table.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Returns the maximum rows/bytes and lease duration for one claim.
    #[must_use]
    pub const fn lease(&self) -> OutboxLeaseConfig {
        self.lease
    }
}

/// Counts committed and acknowledged rows in one outbox pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxPublishReport {
    /// Rows claimed from `PostgreSQL`.
    pub claimed: usize,
    /// Rows acknowledged after successful `ClickHouse` publication.
    pub published: usize,
}

/// Publishes one bounded batch of complete `case.*` outbox envelopes.
///
/// `PostgreSQL` owns the lease and publication acknowledgement. `ClickHouse` is
/// written before the acknowledgement, so retries are at-least-once and the
/// stable event ID/content digest conflict check remains authoritative. Other
/// outbox families are rejected without falling back to the journal adapter.
///
/// # Errors
/// Returns [`PublishError::InvalidEvent`] for a malformed or mismatched row,
/// [`PublishError::ClickHouse`] for an unavailable index,
/// [`PublishError::Postgres`] for lease operations, or
/// [`PublishError::OutboxLeaseLost`] when a concurrent worker owns the row.
pub async fn publish_case_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
) -> Result<OutboxPublishReport, PublishError> {
    publish_outbox_batch(store, client, scope, config, OutboxFamily::Case).await
}

/// Publishes one bounded batch of `evidence.cataloged` outbox envelopes.
///
/// Gateway capture and model evaluation use different producer identities but
/// the same strict catalog payload. The catalog row remains a reference only;
/// content access still requires the separate evidence authorization path.
///
/// # Errors
/// Returns the same lease, event, and index errors as
/// [`publish_case_outbox_batch`].
pub async fn publish_evidence_catalog_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
) -> Result<OutboxPublishReport, PublishError> {
    publish_outbox_batch(store, client, scope, config, OutboxFamily::EvidenceCatalog).await
}

/// Publishes one bounded batch of evidence-access request and decision events.
///
/// Requests and independent decisions use separate payload contracts but share
/// the authenticated control producer and access-request aggregate.
///
/// # Errors
/// Returns the same lease, event, and index errors as
/// [`publish_case_outbox_batch`].
pub async fn publish_evidence_access_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
) -> Result<OutboxPublishReport, PublishError> {
    publish_outbox_batch(store, client, scope, config, OutboxFamily::EvidenceAccess).await
}

/// Publishes one bounded batch of immutable offline calibration-report metadata.
///
/// The outbox event links a protected report artifact to frozen dataset, model,
/// and partition provenance. It records a completed offline report only; it
/// never reads evidence, changes thresholds, publishes policy, or grants access.
///
/// # Errors
/// Returns the same lease, event, and index errors as
/// [`publish_case_outbox_batch`].
pub async fn publish_calibration_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
) -> Result<OutboxPublishReport, PublishError> {
    publish_outbox_batch(store, client, scope, config, OutboxFamily::Calibration).await
}

/// Publishes one bounded batch of gateway identity lifecycle transactions.
///
/// Only complete v3 envelopes are accepted. Historical sparse records remain
/// unacknowledged with `OUTBOX_INVALID_EVENT`; timestamps and producer facts
/// are never inferred from current identity state. Identity references and
/// credential HMACs remain in the `SENSITIVE` payload, which public query
/// summaries do not expose; publication never grants authentication authority.
///
/// # Errors
/// Returns the same lease, event, and index errors as
/// [`publish_case_outbox_batch`].
pub async fn publish_identity_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
) -> Result<OutboxPublishReport, PublishError> {
    publish_outbox_batch(store, client, scope, config, OutboxFamily::Identity).await
}

/// Publishes generic gateway resource-grant issuance transactions.
///
/// Complete v3 envelopes bind one grant to its request, identity epoch,
/// approved action, policy revision, resource HMAC, constraints digest, and
/// frozen issuance time. Publication records history only; current
/// authorization remains in the transactional grant store.
///
/// # Errors
/// Returns the same lease, event, and index errors as
/// [`publish_case_outbox_batch`].
pub async fn publish_grant_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
) -> Result<OutboxPublishReport, PublishError> {
    publish_outbox_batch(store, client, scope, config, OutboxFamily::Grant).await
}

/// Publishes one bounded batch of gateway response-grant issuance transactions.
///
/// Complete v3 envelopes bind each grant to its request, identity epoch, target,
/// and frozen issuance time. Historical sparse records remain unacknowledged
/// with `OUTBOX_INVALID_EVENT`. Publication records issuance history only;
/// current authorization still requires the transactional grant store.
///
/// # Errors
/// Returns the same lease, event, and index errors as
/// [`publish_case_outbox_batch`].
pub async fn publish_response_grant_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
) -> Result<OutboxPublishReport, PublishError> {
    publish_outbox_batch(store, client, scope, config, OutboxFamily::ResponseGrant).await
}

/// Publishes one bounded batch of gateway share-grant issuance transactions.
///
/// Complete v3 envelopes bind event identity, issuer, target, and frozen issuance
/// time. Historical sparse records remain unacknowledged with
/// `OUTBOX_INVALID_EVENT`. This records issuance history; current authorization
/// still requires the transactional share store. Credentials are never indexed.
///
/// # Errors
/// Returns the same lease, event, and index errors as
/// [`publish_case_outbox_batch`].
pub async fn publish_share_grant_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
) -> Result<OutboxPublishReport, PublishError> {
    publish_outbox_batch(store, client, scope, config, OutboxFamily::ShareGrant).await
}

/// Publishes a bounded batch of evidence holds and catalog/orphan deletion facts.
///
/// Intent, completion and failed attempts retain their original evidence and
/// cause references. Index acknowledgement never performs physical removal,
/// changes retention, or creates content-read authority.
///
/// # Errors
/// Returns the same scoped lease, event and index errors as
/// [`publish_case_outbox_batch`].
pub async fn publish_evidence_retention_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
) -> Result<OutboxPublishReport, PublishError> {
    publish_outbox_batch(
        store,
        client,
        scope,
        config,
        OutboxFamily::EvidenceRetention,
    )
    .await
}

async fn publish_outbox_batch(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
    family: OutboxFamily,
) -> Result<OutboxPublishReport, PublishError> {
    let leases = store
        .claim_outbox_batch_for_types(scope, config.lease, family.event_types())
        .await?;
    let claimed = leases.len();
    let mut report = OutboxPublishReport {
        claimed,
        published: 0,
    };
    for lease in leases {
        if let Err(error) = publish_one(store, client, scope, config, family, &lease).await {
            if !matches!(
                error,
                PublishError::Postgres(_) | PublishError::OutboxLeaseLost
            ) {
                schedule_failure(store, scope, &lease, &error, config.retry_after).await?;
            }
            return Err(error);
        }
        report.published = report
            .published
            .checked_add(1)
            .ok_or(PublishError::InvalidEvent)?;
    }
    Ok(report)
}

async fn publish_one(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
    family: OutboxFamily,
    lease: &OutboxEvent,
) -> Result<(), PublishError> {
    if lease.tenant_id != *scope.tenant_id() || lease.site_id != *scope.site_id() {
        return Err(PublishError::InvalidEvent);
    }
    let bytes = serde_json::to_vec(&lease.envelope)?;
    if bytes.is_empty() || bytes.len() > MAX_OUTBOX_EVENT_BYTES {
        return Err(PublishError::InvalidEvent);
    }
    if !family
        .event_types()
        .iter()
        .any(|event_type| *event_type == lease.event_type)
    {
        return Err(PublishError::UnsupportedEventType);
    }
    let event: WireEvent = serde_json::from_slice(&bytes)?;
    let producer_boot_id = event.producer_boot_id.clone();
    let digest = hex(&sha256_digest(&bytes));
    let row = IndexRow::parse_outbox(
        &bytes,
        &lease.event_id,
        event.producer_seq,
        &producer_boot_id,
        digest.clone(),
        config.metadata_retention,
    )?;
    let aggregate_ref = lease
        .envelope
        .get("payload")
        .and_then(|payload| payload.get(family.aggregate_field(&lease.event_type)))
        .and_then(serde_json::Value::as_str);
    if row.event_id != lease.event_id.as_str()
        || row.tenant_id != scope.tenant_id().as_str()
        || row.site_id != scope.site_id().as_str()
        || row.event_type != lease.event_type
        || aggregate_ref != Some(lease.aggregate_ref.as_str())
    {
        return Err(PublishError::InvalidEvent);
    }
    let mut expected = BTreeMap::new();
    expected.insert(lease.event_id.as_str().to_owned(), digest);
    reject_remote_conflicts(client, config.table(), &expected).await?;
    insert_rows(
        client,
        config.table(),
        &format!("outbox-{}", lease.event_id.as_str()),
        std::slice::from_ref(&row),
    )
    .await?;
    reject_remote_conflicts(client, config.table(), &expected).await?;
    match store
        .ack_outbox_event(scope, &lease.event_id, &lease.lease_token)
        .await?
    {
        OutboxAckOutcome::Acknowledged => Ok(()),
        OutboxAckOutcome::Rejected => Err(PublishError::OutboxLeaseLost),
    }
}

async fn schedule_failure(
    store: &PostgresIdentityStore,
    scope: &OutboxScope,
    lease: &OutboxEvent,
    error: &PublishError,
    retry_after: Duration,
) -> Result<(), PublishError> {
    let error_code = match error {
        PublishError::IntegrityConflict => INTEGRITY_CONFLICT_CODE,
        PublishError::ClickHouse(_) => INDEX_UNAVAILABLE_CODE,
        _ => INVALID_EVENT_CODE,
    };
    match store
        .fail_outbox_event(
            scope,
            &lease.event_id,
            &lease.lease_token,
            error_code,
            retry_after,
        )
        .await?
    {
        OutboxFailureOutcome::Scheduled => Ok(()),
        OutboxFailureOutcome::Rejected => Err(PublishError::OutboxLeaseLost),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CasePayload {
    stage: String,
    case_id: String,
    artifact_id: Option<String>,
    subject_ref: String,
    request_digest: String,
    outcome: String,
    reason_code: String,
    proof_kind: Option<String>,
    confidence: Option<f64>,
    confidence_status: Option<String>,
}

pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    if calibration::EVENT_TYPES.contains(&event.event_type.as_str()) {
        return calibration::parse(event);
    }
    if retention::EVENT_TYPES.contains(&event.event_type.as_str()) {
        return retention::parse(event);
    }
    if hold::EVENT_TYPES.contains(&event.event_type.as_str()) {
        return hold::parse(event);
    }
    if grant::EVENT_TYPES.contains(&event.event_type.as_str()) {
        return grant::parse(event);
    }
    if share_grant::EVENT_TYPES.contains(&event.event_type.as_str()) {
        return share_grant::parse(event);
    }
    if response_grant::EVENT_TYPES.contains(&event.event_type.as_str()) {
        return response_grant::parse(event);
    }
    if identity::EVENT_TYPES.contains(&event.event_type.as_str()) {
        return identity::parse(event);
    }
    if event.event_type == "evidence.cataloged" {
        return parse_evidence_catalog(event);
    }
    if event.producer_id != "xshield-control"
        || event.policy_revision != "control-v1"
        || valid_prefixed_v7(&event.producer_boot_id, "req_").is_err()
        || event.request_id.as_deref() != Some(event.producer_boot_id.as_str())
        || event.request_seq != 1
        || event.producer_seq != 1
        || !event.cause_event_ids.is_empty()
        || event.sensitivity != "INTERNAL"
    {
        return Err(PublishError::InvalidEvent);
    }
    if EVIDENCE_ACCESS_EVENT_TYPES.contains(&event.event_type.as_str()) {
        return parse_evidence_access(event);
    }
    let payload: CasePayload = serde_json::from_str(event.payload.get())?;
    payload.validate(event)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceCatalogPayload {
    stage: String,
    outcome: String,
    reason_code: String,
    artifact_id: String,
}

fn parse_evidence_catalog(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    if !matches!(
        event.producer_id.as_str(),
        "gateway-evidence-catalog" | "model-eval"
    ) || valid_uuid_v7(&event.producer_boot_id).is_err()
        || event.request_id.is_none()
        || event.producer_seq != 1
        || event.sensitivity != "RESTRICTED"
        || event.cause_event_ids.len() != 1
    {
        return Err(PublishError::InvalidEvent);
    }
    let payload: EvidenceCatalogPayload = serde_json::from_str(event.payload.get())?;
    if payload.stage != "evidence_catalog"
        || payload.outcome != "PASS"
        || payload.reason_code != "EVIDENCE_CATALOG_PUBLISHED"
        || valid_prefixed_v7(&payload.artifact_id, "artifact_").is_err()
        || event.evidence_refs.len() != 1
        || event.evidence_refs[0] != payload.artifact_id
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(PayloadSummary {
        stage: payload.stage,
        outcome: payload.outcome,
        reason_code: payload.reason_code,
        proof_kind: "deterministic".to_owned(),
        confidence_status: "not_applicable".to_owned(),
        ..PayloadSummary::default()
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceAccessRequestPayload {
    access_request_id: String,
    case_id: String,
    artifact_id: String,
    subject_ref: String,
    access_kind: String,
    stage: String,
    request_digest: String,
    outcome: String,
    reason_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceAccessDecisionPayload {
    access_request_id: String,
    subject_ref: String,
    decision: String,
    #[serde(deserialize_with = "Option::deserialize")]
    ttl_seconds: Option<u32>,
    request_digest: String,
    stage: String,
    outcome: String,
    reason_code: String,
}

fn parse_evidence_access(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    if event.event_type == "evidence.access.requested" {
        let payload: EvidenceAccessRequestPayload = serde_json::from_str(event.payload.get())?;
        if payload.stage != "evidence_access"
            || payload.outcome != "PASS"
            || payload.reason_code != "EVIDENCE_ACCESS_REQUESTED"
            || payload.access_kind != "sensitive_raw"
            || valid_prefixed_v7(&payload.access_request_id, "access_").is_err()
            || valid_prefixed_v7(&payload.case_id, "case_").is_err()
            || valid_prefixed_v7(&payload.artifact_id, "artifact_").is_err()
            || !valid_subject(&payload.subject_ref)
            || !valid_lower_hex(&payload.request_digest, 64)
            || event.evidence_refs.len() != 1
            || event.evidence_refs[0] != payload.artifact_id
        {
            return Err(PublishError::InvalidEvent);
        }
        return Ok(PayloadSummary {
            stage: payload.stage,
            outcome: payload.outcome,
            reason_code: payload.reason_code,
            proof_kind: "deterministic".to_owned(),
            confidence_status: "not_applicable".to_owned(),
            ..PayloadSummary::default()
        });
    }
    if !matches!(
        event.event_type.as_str(),
        "evidence.access.approved" | "evidence.access.denied"
    ) {
        return Err(PublishError::UnsupportedEventType);
    }
    if !event.evidence_refs.is_empty() {
        return Err(PublishError::InvalidEvent);
    }
    let payload: EvidenceAccessDecisionPayload = serde_json::from_str(event.payload.get())?;
    let is_approved = event.event_type == "evidence.access.approved";
    if payload.stage != "evidence_access_decision"
        || payload.outcome != "PASS"
        || payload.reason_code
            != if is_approved {
                "EVIDENCE_ACCESS_APPROVED"
            } else {
                "EVIDENCE_ACCESS_DENIED"
            }
        || payload.decision != if is_approved { "approved" } else { "denied" }
        || valid_prefixed_v7(&payload.access_request_id, "access_").is_err()
        || !valid_subject(&payload.subject_ref)
        || !valid_lower_hex(&payload.request_digest, 64)
        || (is_approved != payload.ttl_seconds.is_some())
        || payload
            .ttl_seconds
            .is_some_and(|value| !(1..=86_400).contains(&value))
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(PayloadSummary {
        stage: payload.stage,
        outcome: payload.outcome,
        reason_code: payload.reason_code,
        proof_kind: "deterministic".to_owned(),
        confidence_status: "not_applicable".to_owned(),
        ..PayloadSummary::default()
    })
}

impl CasePayload {
    fn validate(self, event: &WireEvent) -> Result<PayloadSummary, PublishError> {
        let is_add = event.event_type == "case.evidence.added";
        let expected_reason = match event.event_type.as_str() {
            "case.created" => "CASE_CREATED",
            "case.closed" => "CASE_CLOSED",
            "case.evidence.added" => "CASE_EVIDENCE_ADDED",
            _ => return Err(PublishError::UnsupportedEventType),
        };
        if self.stage != "case_management"
            || valid_prefixed_v7(&self.case_id, "case_").is_err()
            || self
                .artifact_id
                .as_deref()
                .is_some_and(|value| valid_prefixed_v7(value, "artifact_").is_err())
            || (is_add != self.artifact_id.is_some())
            || !valid_subject(&self.subject_ref)
            || !valid_lower_hex(&self.request_digest, 64)
            || self.outcome != "PASS"
            || self.reason_code != expected_reason
            || !valid_proof_fields(
                self.proof_kind.as_deref(),
                self.confidence,
                self.confidence_status.as_deref(),
            )
            || !event.evidence_refs.iter().all(|value| {
                valid_prefixed_v7(value, "artifact_").is_ok()
                    && self.artifact_id.as_deref() == Some(value.as_str())
            })
            || (is_add && event.evidence_refs.len() != 1)
            || (!is_add && !event.evidence_refs.is_empty())
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(PayloadSummary {
            stage: self.stage,
            outcome: self.outcome,
            reason_code: self.reason_code,
            proof_kind: "deterministic".to_owned(),
            confidence_status: "not_applicable".to_owned(),
            ..PayloadSummary::default()
        })
    }
}

fn valid_proof_fields(
    proof_kind: Option<&str>,
    confidence: Option<f64>,
    confidence_status: Option<&str>,
) -> bool {
    match (proof_kind, confidence_status) {
        (None, None) | (Some("deterministic"), Some("not_applicable")) => confidence.is_none(),
        _ => false,
    }
}

fn valid_subject(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::super::{IndexRow, PublishError};
    use serde_json::{Value, json};
    use xshield_core::domain::EventId;

    const EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000001";
    const BOOT: &str = REQUEST;
    const CATALOG_BOOT: &str = "018f2a3b-4c5d-7000-8000-000000000006";
    const REQUEST: &str = "req_018f2a3b-4c5d-7000-8000-000000000003";
    const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000004";
    const ARTIFACT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000005";
    const CAUSE: &str = "ev_018f2a3b-4c5d-7000-8000-000000000007";
    const ACCESS: &str = "access_018f2a3b-4c5d-7000-8000-000000000008";

    pub(super) fn event(event_type: &str) -> Value {
        let artifact = (event_type == "case.evidence.added").then_some(ARTIFACT);
        json!({
            "schema_version": 3, "event_id": EVENT, "event_type": event_type,
            "tenant_id": "tenant_demo", "site_id": "site_demo", "request_id": REQUEST,
            "trace_id": "018f2a3b4c5d70008000000000000003", "span_id": "018f2a3b4c5d7000",
            "producer_id": "xshield-control", "producer_boot_id": BOOT,
            "producer_seq": 1, "request_seq": 1,
            "occurred_at": "2026-09-19T00:00:00.123Z", "observed_at": "2026-09-19T00:00:00.123Z",
            "policy_revision": "control-v1", "example_only": false,
            "evidence_refs": artifact.into_iter().collect::<Vec<_>>(), "cause_event_ids": [],
            "payload": {
                "stage": "case_management", "case_id": CASE,
                "artifact_id": artifact, "subject_ref": "investigator-1",
                "request_digest": "a".repeat(64), "outcome": "PASS",
                "reason_code": match event_type {
                    "case.created" => "CASE_CREATED",
                    "case.closed" => "CASE_CLOSED",
                    _ => "CASE_EVIDENCE_ADDED"
                }
            },
            "sensitivity": "INTERNAL",
            "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
        })
    }

    fn parse(event: &Value) -> Result<IndexRow, PublishError> {
        parse_with_boot(event, BOOT)
    }

    fn parse_with_boot(event: &Value, boot: &str) -> Result<IndexRow, PublishError> {
        IndexRow::parse_outbox(
            &serde_json::to_vec(event).unwrap(),
            &EventId::parse(EVENT).unwrap(),
            1,
            boot,
            "0".repeat(64),
            chrono::TimeDelta::days(30),
        )
    }

    pub(super) fn catalog_event(producer_id: &str) -> Value {
        json!({
            "schema_version": 3, "event_id": EVENT, "event_type": "evidence.cataloged",
            "tenant_id": "tenant_demo", "site_id": "site_demo", "request_id": REQUEST,
            "trace_id": "018f2a3b4c5d70008000000000000003", "span_id": "018f2a3b4c5d7000",
            "producer_id": producer_id, "producer_boot_id": CATALOG_BOOT,
            "producer_seq": 1, "request_seq": 2,
            "occurred_at": "2026-09-19T00:00:00.123Z", "observed_at": "2026-09-19T00:00:00.123Z",
            "policy_revision": "policy-r1", "example_only": false,
            "evidence_refs": [ARTIFACT], "cause_event_ids": [CAUSE],
            "payload": {
                "stage": "evidence_catalog", "outcome": "PASS",
                "reason_code": "EVIDENCE_CATALOG_PUBLISHED", "artifact_id": ARTIFACT
            },
            "sensitivity": "RESTRICTED",
            "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
        })
    }

    pub(super) fn access_request_event() -> Value {
        json!({
            "schema_version": 3, "event_id": EVENT, "event_type": "evidence.access.requested",
            "tenant_id": "tenant_demo", "site_id": "site_demo", "request_id": REQUEST,
            "trace_id": "018f2a3b4c5d70008000000000000003", "span_id": "018f2a3b4c5d7000",
            "producer_id": "xshield-control", "producer_boot_id": REQUEST,
            "producer_seq": 1, "request_seq": 1,
            "occurred_at": "2026-09-19T00:00:00.123Z", "observed_at": "2026-09-19T00:00:00.123Z",
            "policy_revision": "control-v1", "example_only": false,
            "evidence_refs": [ARTIFACT], "cause_event_ids": [],
            "payload": {
                "access_request_id": ACCESS, "case_id": CASE, "artifact_id": ARTIFACT,
                "subject_ref": "investigator-1", "access_kind": "sensitive_raw",
                "stage": "evidence_access", "request_digest": "b".repeat(64),
                "outcome": "PASS", "reason_code": "EVIDENCE_ACCESS_REQUESTED"
            },
            "sensitivity": "INTERNAL",
            "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
        })
    }

    pub(super) fn access_decision_event(event_type: &str) -> Value {
        let approved = event_type == "evidence.access.approved";
        json!({
            "schema_version": 3, "event_id": EVENT, "event_type": event_type,
            "tenant_id": "tenant_demo", "site_id": "site_demo", "request_id": REQUEST,
            "trace_id": "018f2a3b4c5d70008000000000000003", "span_id": "018f2a3b4c5d7000",
            "producer_id": "xshield-control", "producer_boot_id": REQUEST,
            "producer_seq": 1, "request_seq": 1,
            "occurred_at": "2026-09-19T00:00:00.123Z", "observed_at": "2026-09-19T00:00:00.123Z",
            "policy_revision": "control-v1", "example_only": false,
            "evidence_refs": [], "cause_event_ids": [],
            "payload": {
                "access_request_id": ACCESS, "subject_ref": "approver-1",
                "decision": if approved { "approved" } else { "denied" },
                "ttl_seconds": approved.then_some(300), "stage": "evidence_access_decision",
                "request_digest": "c".repeat(64), "outcome": "PASS",
                "reason_code": if approved { "EVIDENCE_ACCESS_APPROVED" } else { "EVIDENCE_ACCESS_DENIED" }
            },
            "sensitivity": "INTERNAL",
            "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
        })
    }

    #[test]
    fn accepts_the_three_complete_case_outbox_families() {
        for kind in ["case.created", "case.closed", "case.evidence.added"] {
            let row = parse(&event(kind)).unwrap();
            assert_eq!(row.stage, "case_management");
            assert_eq!(row.outcome, "PASS");
            assert_eq!(row.reason_code, kind.replace('.', "_").to_uppercase());
            assert_eq!(row.proof_kind, "deterministic");
            assert_eq!(row.confidence, None);
            assert_eq!(row.confidence_status, "not_applicable");
            assert_eq!(row.is_terminal, 0);
        }
    }

    #[test]
    fn rejects_wrong_targets_and_payload_contracts() {
        for (pointer, value) in [
            ("/event_type", json!("case.unknown")),
            ("/payload/stage", json!("evidence_access")),
            ("/payload/case_id", json!(ARTIFACT)),
            ("/payload/subject_ref", json!("operator\n1")),
            ("/payload/outcome", json!("DENY")),
            ("/payload/request_digest", json!("A".repeat(64))),
            ("/payload/reason_code", json!("CASE_CREATED_EXTRA")),
            ("/evidence_refs", json!([ARTIFACT])),
        ] {
            let mut value_to_reject = event("case.created");
            *value_to_reject.pointer_mut(pointer).unwrap() = value;
            assert!(parse(&value_to_reject).is_err(), "accepted {pointer}");
        }
        let mut missing_artifact = event("case.evidence.added");
        missing_artifact["payload"]["artifact_id"] = Value::Null;
        missing_artifact["evidence_refs"] = json!([]);
        assert!(parse(&missing_artifact).is_err());
    }

    #[test]
    fn rejects_unknown_duplicate_and_non_case_outbox_shapes() {
        let serialized = serde_json::to_string(&event("case.created")).unwrap();
        for (index, replacement) in [
            r#""reason_code":"CASE_CREATED","extra":1"#,
            r#""reason_code":"CASE_CREATED","reason_code":"CASE_CREATED""#,
        ]
        .into_iter()
        .enumerate()
        {
            let malformed = serialized.replace(r#""reason_code":"CASE_CREATED""#, replacement);
            assert!(
                IndexRow::parse_outbox(
                    malformed.as_bytes(),
                    &EventId::parse(EVENT).unwrap(),
                    1,
                    BOOT,
                    "0".repeat(64),
                    chrono::TimeDelta::days(30),
                )
                .is_err(),
                "accepted malformed case payload {index}"
            );
        }
        let mut management = event("case.created");
        management["payload"] = json!({
            "method": "GET", "path": "/control/v1/cases/{case_id}/items",
            "subject_ref": "investigator-1", "target_case_id": CASE,
            "outcome": "PASS", "reason_code": "CONTROL_CASE_READ"
        });
        assert!(parse(&management).is_err());
    }

    #[test]
    fn accepts_production_optional_case_shapes() {
        let mut created = event("case.created");
        created["payload"]
            .as_object_mut()
            .expect("payload object")
            .remove("artifact_id");
        assert!(parse(&created).is_ok());

        let mut closed = event("case.closed");
        closed["payload"] = json!({
            "stage": "case_management", "case_id": CASE,
            "subject_ref": "investigator-1", "request_digest": "a".repeat(64),
            "outcome": "PASS", "reason_code": "CASE_CLOSED",
            "proof_kind": "deterministic", "confidence": null,
            "confidence_status": "not_applicable"
        });
        closed["payload"]
            .as_object_mut()
            .expect("payload object")
            .remove("artifact_id");
        assert!(parse(&closed).is_ok());
    }

    #[test]
    fn accepts_gateway_and_model_evidence_catalog_shapes() {
        for producer in ["gateway-evidence-catalog", "model-eval"] {
            let row = parse_with_boot(&catalog_event(producer), CATALOG_BOOT).unwrap();
            assert_eq!(row.stage, "evidence_catalog");
            assert_eq!(row.outcome, "PASS");
            assert_eq!(row.reason_code, "EVIDENCE_CATALOG_PUBLISHED");
            assert_eq!(row.proof_kind, "deterministic");
            assert_eq!(row.confidence, None);
            assert_eq!(row.confidence_status, "not_applicable");
            assert_eq!(row.is_terminal, 0);
        }
    }

    #[test]
    fn rejects_evidence_catalog_contract_drift() {
        for (pointer, value) in [
            ("/producer_id", json!("xshield-control")),
            ("/producer_boot_id", json!(BOOT)),
            ("/sensitivity", json!("INTERNAL")),
            ("/cause_event_ids", json!([])),
            ("/evidence_refs", json!([])),
            ("/payload/artifact_id", json!(CASE)),
            (
                "/payload/reason_code",
                json!("EVIDENCE_CATALOG_PUBLISHED_EXTRA"),
            ),
        ] {
            let mut value_to_reject = catalog_event("gateway-evidence-catalog");
            *value_to_reject.pointer_mut(pointer).unwrap() = value;
            assert!(
                parse_with_boot(&value_to_reject, CATALOG_BOOT).is_err(),
                "accepted {pointer}"
            );
        }
        let mut unknown = catalog_event("model-eval");
        unknown["payload"]["extra"] = json!(true);
        assert!(parse_with_boot(&unknown, CATALOG_BOOT).is_err());
    }

    #[test]
    fn accepts_evidence_access_request_and_decision_families() {
        for event in [
            access_request_event(),
            access_decision_event("evidence.access.approved"),
            access_decision_event("evidence.access.denied"),
        ] {
            let row = parse_with_boot(&event, REQUEST).unwrap();
            assert_eq!(row.outcome, "PASS");
            assert_eq!(row.proof_kind, "deterministic");
            assert_eq!(row.confidence, None);
            assert_eq!(row.confidence_status, "not_applicable");
            assert_eq!(row.is_terminal, 0);
        }
    }

    #[test]
    fn rejects_evidence_access_contract_drift() {
        for (pointer, value) in [
            ("/payload/access_kind", json!("all_content")),
            ("/payload/access_request_id", json!(CASE)),
            ("/payload/case_id", json!(ACCESS)),
            (
                "/payload/artifact_id",
                json!("artifact_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            ("/payload/subject_ref", json!("actor\n1")),
            ("/payload/request_digest", json!("A".repeat(64))),
            ("/payload/reason_code", json!("EVIDENCE_ACCESS_APPROVED")),
            ("/payload/outcome", json!("DENY")),
            ("/evidence_refs", json!([])),
            ("/cause_event_ids", json!([CAUSE])),
            (
                "/request_id",
                json!("req_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            ("/producer_id", json!("model-eval")),
            ("/policy_revision", json!("control-v2")),
            ("/sensitivity", json!("PUBLIC")),
        ] {
            let mut request = access_request_event();
            *request.pointer_mut(pointer).unwrap() = value;
            assert!(
                parse_with_boot(&request, REQUEST).is_err(),
                "accepted {pointer}"
            );
        }
        for event_type in ["evidence.access.approved", "evidence.access.denied"] {
            let event = access_decision_event(event_type);
            for field in event["payload"].as_object().unwrap().keys() {
                let mut missing = event.clone();
                missing["payload"].as_object_mut().unwrap().remove(field);
                assert!(
                    parse_with_boot(&missing, REQUEST).is_err(),
                    "missing {field}"
                );
            }
            for value in [json!(0), json!(86_401), json!(-1), json!(1.5)] {
                let mut invalid = event.clone();
                invalid["payload"]["ttl_seconds"] = value;
                assert!(parse_with_boot(&invalid, REQUEST).is_err());
            }
            let mut wrong_reason = event.clone();
            wrong_reason["payload"]["reason_code"] = json!("EVIDENCE_ACCESS_REQUESTED");
            assert!(parse_with_boot(&wrong_reason, REQUEST).is_err());
            let mut unknown = event;
            unknown["payload"]["extra"] = json!(true);
            assert!(parse_with_boot(&unknown, REQUEST).is_err());
        }
        for ttl in [1, 86_400] {
            let mut approved = access_decision_event("evidence.access.approved");
            approved["payload"]["ttl_seconds"] = json!(ttl);
            assert!(parse_with_boot(&approved, REQUEST).is_ok());
            let mut denied = access_decision_event("evidence.access.denied");
            denied["payload"]["ttl_seconds"] = json!(ttl);
            assert!(parse_with_boot(&denied, REQUEST).is_err());
        }
    }

    #[test]
    fn evidence_access_journal_and_outbox_contracts_are_separate() {
        for (mut event, path) in [
            (
                access_request_event(),
                "/control/v1/artifacts/{artifact_id}/access",
            ),
            (
                access_decision_event("evidence.access.approved"),
                "/control/v1/evidence-access-requests/{access_request_id}/approve",
            ),
            (
                access_decision_event("evidence.access.denied"),
                "/control/v1/evidence-access-requests/{access_request_id}/deny",
            ),
        ] {
            let outbox = serde_json::to_vec(&event).unwrap();
            assert!(
                IndexRow::parse(
                    &outbox,
                    &EventId::parse(EVENT).unwrap(),
                    1,
                    REQUEST,
                    "0".repeat(64),
                    chrono::TimeDelta::days(30)
                )
                .is_err()
            );
            event["payload"] = json!({
                "method": "POST", "path": path, "subject_ref": "operator-1",
                "target_case_id": CASE, "target_artifact_id": ARTIFACT,
                "target_access_request_id": ACCESS, "outcome": "PASS",
                "reason_code": "CONTROL_EVIDENCE_ACCESS_REQUESTED"
            });
            event["evidence_refs"] = json!([ARTIFACT]);
            let journal = serde_json::to_vec(&event).unwrap();
            assert_eq!(
                IndexRow::parse(
                    &journal,
                    &EventId::parse(EVENT).unwrap(),
                    1,
                    REQUEST,
                    "0".repeat(64),
                    chrono::TimeDelta::days(30)
                )
                .unwrap()
                .stage,
                "control_access"
            );
            assert!(parse_with_boot(&event, REQUEST).is_err());
            let duplicate = String::from_utf8(outbox).unwrap().replace(
                r#""subject_ref":"#,
                r#""subject_ref":"duplicate","subject_ref":"#,
            );
            assert!(
                IndexRow::parse_outbox(
                    duplicate.as_bytes(),
                    &EventId::parse(EVENT).unwrap(),
                    1,
                    REQUEST,
                    "0".repeat(64),
                    chrono::TimeDelta::days(30)
                )
                .is_err()
            );
        }
    }
}
