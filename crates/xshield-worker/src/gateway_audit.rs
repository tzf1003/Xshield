//! Strict journal payloads the gateway writes beyond the generic stage shape.
//!
//! The publisher parses a whole sealed segment before it indexes any row, so a
//! record without a parser stops that segment and every segment after it. Each
//! shape here is the closed contract of one gateway emission: unknown or
//! missing members, impossible combinations and values outside the producer's
//! vocabulary are [`PublishError::InvalidEvent`]. A new gateway shape must
//! extend this module, and be reachable from the gateway's publishability
//! tests, before it ships.
//!
//! Nothing here is authorization truth. Browser observations are client claims
//! and are indexed as `observation` proof with no confidence; crypto and HTML
//! stages carry digests and coverage, never plaintext or key material.

use super::{
    PayloadSummary, PublishError, WireEvent, valid_lower_hex, valid_method, valid_name,
    valid_prefixed_v7,
};
use serde::Deserialize;
use xshield_core::domain::{AuthBindingId, PageEvidenceId, RequestId};

#[cfg(test)]
mod tests;

/// 2100-01-01: the ceiling every edge timestamp uses.
const UNIX_MAX: u64 = 4_102_444_800;
const CRYPTO_ALGORITHM: &str = "AES-256-GCM";
const MAX_CLIENT_TEXT_BYTES: usize = 256;
const MAX_CLIENT_EVENT_SEQUENCE: u32 = 64;
/// The `PostgreSQL` bigint ceiling every authentication epoch stays within.
const AUTH_EPOCH_MAX: u64 = 9_223_372_036_854_775_807;

#[derive(Clone, Copy)]
enum Family {
    RequestCrypto,
    ResponseCrypto,
    SensorHtml,
    EdgeResponse,
    EdgeUnknown,
    EvidenceCaptured,
    SensorObservation,
}

/// Reads only the stage name so the whole payload is parsed once, by the
/// parser that owns its shape.
#[derive(Deserialize)]
struct StageName {
    stage: String,
}

fn family(event: &WireEvent) -> Option<Family> {
    match event.event_type.as_str() {
        "edge.response" => Some(Family::EdgeResponse),
        "edge.unknown" => Some(Family::EdgeUnknown),
        "evidence.captured" => Some(Family::EvidenceCaptured),
        "sensor.observation" => Some(Family::SensorObservation),
        "stage.completed" | "stage.skipped" => {
            let name: StageName = serde_json::from_str(event.payload.get()).ok()?;
            match name.stage.as_str() {
                "crypto_decode" => Some(Family::RequestCrypto),
                "crypto_encode" => Some(Family::ResponseCrypto),
                "sensor_html_inject" => Some(Family::SensorHtml),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether this journal event has a dedicated gateway parser. Every other
/// stage keeps the generic shape.
pub(super) fn supports(event: &WireEvent) -> bool {
    family(event).is_some()
}

pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let json = event.payload.get();
    match family(event).ok_or(PublishError::UnsupportedEventType)? {
        Family::RequestCrypto => request_crypto(event, json),
        Family::ResponseCrypto => response_crypto(event, json),
        Family::SensorHtml => sensor_html(event, json),
        Family::EdgeResponse => edge(event, json, "response_served"),
        Family::EdgeUnknown => edge(event, json, "unknown"),
        Family::EvidenceCaptured => evidence_captured(event, json),
        Family::SensorObservation => sensor_observation(json),
    }
}

fn require_completed(event: &WireEvent) -> Result<(), PublishError> {
    if event.event_type == "stage.completed" {
        Ok(())
    } else {
        Err(PublishError::InvalidEvent)
    }
}

/// The members every deterministic gateway stage shares. `facts` and
/// `coverage` are the stage's own closed shapes; every member must be present.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeterministicStage<F, C> {
    stage: String,
    stage_execution_id: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    #[serde(deserialize_with = "Option::deserialize")]
    confidence: Option<f64>,
    confidence_status: String,
    duration_us: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    rule_revision: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    model_call_id: Option<String>,
    facts: F,
    coverage: C,
}

impl<F, C> DeterministicStage<F, C> {
    fn check_header(&self, stage: &str, outcomes: &[&str]) -> Result<(), PublishError> {
        if self.stage != stage
            || valid_prefixed_v7(&self.stage_execution_id, "stg_").is_err()
            || !outcomes.contains(&self.outcome.as_str())
            || !valid_name(&self.reason_code)
            || self.proof_kind != "deterministic"
            || self.confidence.is_some()
            || self.confidence_status != "not_applicable"
            || self.model_call_id.is_some()
            || self.rule_revision.as_deref().is_none_or(|v| !valid_name(v))
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(())
    }

    fn summary(self, operation_id: Option<String>) -> PayloadSummary {
        PayloadSummary {
            stage: self.stage,
            outcome: self.outcome,
            reason_code: self.reason_code,
            proof_kind: self.proof_kind,
            confidence: None,
            confidence_status: self.confidence_status,
            operation_id: operation_id.unwrap_or_default(),
            duration_us: self.duration_us,
            ..PayloadSummary::default()
        }
    }
}

/// Facts shared by the request-side decode and response-side encode stages.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CryptoFacts {
    #[serde(deserialize_with = "Option::deserialize")]
    operation_id: Option<String>,
    coverage_mode: String,
    #[serde(deserialize_with = "Option::deserialize")]
    algorithm: Option<String>,
    adapter_revision: String,
    #[serde(deserialize_with = "Option::deserialize")]
    key_id: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    approval_ref: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    source_evidence_ref: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    message_id: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    nonce_sha256: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    issued_at: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    expires_at: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    envelope_sha256: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    rebuilt_sha256: Option<String>,
}

fn optional_digest(value: Option<&str>) -> bool {
    value.is_none_or(|digest| valid_lower_hex(digest, 64))
}

impl CryptoFacts {
    /// Format checks only: which members a coverage mode requires is the
    /// stage's own rule.
    fn check_formats(&self) -> Result<(), PublishError> {
        let lifetime = match (self.issued_at, self.expires_at) {
            (None, None) => true,
            (Some(issued), Some(expires)) => issued < expires && expires <= UNIX_MAX,
            _ => false,
        };
        if self
            .operation_id
            .as_deref()
            .is_some_and(|value| !valid_name(value))
            || !valid_name(&self.adapter_revision)
            || self
                .algorithm
                .as_deref()
                .is_some_and(|v| v != CRYPTO_ALGORITHM)
            || self
                .key_id
                .as_deref()
                .is_some_and(|value| !valid_name(value))
            || self
                .approval_ref
                .as_deref()
                .is_some_and(|value| !valid_name(value))
            || self
                .source_evidence_ref
                .as_deref()
                .is_some_and(|value| PageEvidenceId::parse(value).is_err())
            || self
                .message_id
                .as_deref()
                .is_some_and(|value| valid_prefixed_v7(value, "msg_").is_err())
            || !optional_digest(self.nonce_sha256.as_deref())
            || !optional_digest(self.envelope_sha256.as_deref())
            || !optional_digest(self.rebuilt_sha256.as_deref())
            || !lifetime
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(())
    }

    fn carries_message(&self) -> bool {
        self.message_id.is_some()
            || self.nonce_sha256.is_some()
            || self.issued_at.is_some()
            || self.expires_at.is_some()
            || self.envelope_sha256.is_some()
            || self.rebuilt_sha256.is_some()
    }

    /// A PASS must carry the evidence that proves the transformation: the
    /// message identity, its lifetime and both digests.
    fn carries_complete_message(&self) -> bool {
        self.message_id.is_some()
            && self.nonce_sha256.is_some()
            && self.issued_at.is_some()
            && self.expires_at.is_some()
            && self.envelope_sha256.is_some()
            && self.rebuilt_sha256.is_some()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestCryptoCoverage {
    request_crypto_checked: bool,
    origin_entity_rebuilt: bool,
}

fn request_crypto(event: &WireEvent, json: &str) -> Result<PayloadSummary, PublishError> {
    require_completed(event)?;
    let stage: DeterministicStage<CryptoFacts, RequestCryptoCoverage> = serde_json::from_str(json)?;
    stage.check_header("crypto_decode", &["PASS", "DENY", "ERROR"])?;
    let facts = &stage.facts;
    facts.check_formats()?;
    let enforce = match facts.coverage_mode.as_str() {
        "ENFORCE" => true,
        "OBSERVE" | "COMPATIBILITY" => false,
        _ => return Err(PublishError::InvalidEvent),
    };
    let compatibility = facts.coverage_mode == "COMPATIBILITY";
    // Only ENFORCE names an algorithm and key and may carry a decoded message;
    // only COMPATIBILITY names the server approval and the page evidence it
    // leaned on. Coverage must not claim more than the facts show.
    if enforce != facts.algorithm.is_some()
        || enforce != facts.key_id.is_some()
        || compatibility != facts.approval_ref.is_some()
        || (!compatibility && facts.source_evidence_ref.is_some())
        || (!enforce && facts.carries_message())
        || stage.rule_revision.as_deref() != Some(facts.adapter_revision.as_str())
        || stage.coverage.request_crypto_checked != enforce
        || stage.coverage.origin_entity_rebuilt != facts.rebuilt_sha256.is_some()
        || (enforce && stage.outcome == "PASS" && !facts.carries_complete_message())
    {
        return Err(PublishError::InvalidEvent);
    }
    let operation_id = stage.facts.operation_id.clone();
    Ok(stage.summary(operation_id))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseCryptoCoverage {
    response_crypto_checked: bool,
    client_entity_rebuilt: bool,
}

fn response_crypto(event: &WireEvent, json: &str) -> Result<PayloadSummary, PublishError> {
    require_completed(event)?;
    let stage: DeterministicStage<CryptoFacts, ResponseCryptoCoverage> =
        serde_json::from_str(json)?;
    stage.check_header("crypto_encode", &["PASS", "DENY", "ERROR"])?;
    let facts = &stage.facts;
    facts.check_formats()?;
    if facts.coverage_mode != "ENFORCE"
        || facts.algorithm.as_deref() != Some(CRYPTO_ALGORITHM)
        || facts.key_id.is_none()
        || facts.approval_ref.is_some()
        || facts.source_evidence_ref.is_some()
        || stage.rule_revision.as_deref() != Some(facts.adapter_revision.as_str())
        || !stage.coverage.response_crypto_checked
        || stage.coverage.client_entity_rebuilt != facts.envelope_sha256.is_some()
        || (stage.outcome == "PASS" && !facts.carries_complete_message())
    {
        return Err(PublishError::InvalidEvent);
    }
    let operation_id = stage.facts.operation_id.clone();
    Ok(stage.summary(operation_id))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorHtmlFacts {
    #[serde(deserialize_with = "Option::deserialize")]
    operation_id: Option<String>,
    origin_sha256: String,
    injected_sha256: String,
    csp_nonce_applied: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorHtmlCoverage {
    origin_entity_verified: bool,
    sensor_scripts_injected: bool,
}

fn sensor_html(event: &WireEvent, json: &str) -> Result<PayloadSummary, PublishError> {
    require_completed(event)?;
    let stage: DeterministicStage<SensorHtmlFacts, SensorHtmlCoverage> =
        serde_json::from_str(json)?;
    // The edge records only a verified, injected page; a failed transformation
    // serves the origin body untouched and has no stage today.
    stage.check_header("sensor_html_inject", &["PASS"])?;
    let facts = &stage.facts;
    if facts
        .operation_id
        .as_deref()
        .is_some_and(|value| !valid_name(value))
        || !valid_lower_hex(&facts.origin_sha256, 64)
        || !valid_lower_hex(&facts.injected_sha256, 64)
        || facts.origin_sha256 == facts.injected_sha256
        || !stage.coverage.origin_entity_verified
        || !stage.coverage.sensor_scripts_injected
    {
        return Err(PublishError::InvalidEvent);
    }
    // Whether the CSP nonce was applied is recorded evidence, not a constraint:
    // pages without a script policy have none to apply.
    let _ = facts.csp_nonce_applied;
    let operation_id = stage.facts.operation_id.clone();
    Ok(stage.summary(operation_id))
}

/// A response the edge itself produced (denial, sensor asset, bootstrap) or
/// whose delivery ended in an unknown state; origin responses use `origin.*`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgePayload {
    method: String,
    #[serde(deserialize_with = "Option::deserialize")]
    operation_id: Option<String>,
    edge_state: String,
    reason_code: String,
    #[serde(deserialize_with = "Option::deserialize")]
    status: Option<u16>,
}

fn edge(
    event: &WireEvent,
    json: &str,
    expected_state: &str,
) -> Result<PayloadSummary, PublishError> {
    let payload: EdgePayload = serde_json::from_str(json)?;
    if !valid_method(&payload.method)
        || payload
            .operation_id
            .as_deref()
            .is_some_and(|value| !valid_name(value))
        || payload.edge_state != expected_state
        || !valid_name(&payload.reason_code)
        || payload
            .status
            .is_some_and(|status| !(100..=599).contains(&status))
        // A served response always has a status; an unknown delivery may not.
        || (event.event_type == "edge.response" && payload.status.is_none())
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(PayloadSummary {
        outcome: payload.edge_state,
        reason_code: payload.reason_code,
        method: payload.method,
        operation_id: payload.operation_id.unwrap_or_default(),
        http_status: payload.status,
        ..PayloadSummary::default()
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceCaptured {
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    #[serde(deserialize_with = "Option::deserialize")]
    confidence: Option<f64>,
    profile_revision: String,
}

fn evidence_captured(event: &WireEvent, json: &str) -> Result<PayloadSummary, PublishError> {
    let payload: EvidenceCaptured = serde_json::from_str(json)?;
    // One capture links exactly one cataloged artifact to the catalog event
    // that made it durable, within one request.
    if payload.stage != "evidence_capture"
        || payload.outcome != "PASS"
        || payload.reason_code != "EVIDENCE_CAPTURED"
        || payload.proof_kind != "deterministic"
        || payload.confidence.is_some()
        || !valid_name(&payload.profile_revision)
        || event.request_id.is_none()
        || event.evidence_refs.len() != 1
        || event.cause_event_ids.len() != 1
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(PayloadSummary {
        stage: payload.stage,
        outcome: payload.outcome,
        reason_code: payload.reason_code,
        proof_kind: payload.proof_kind,
        confidence_status: "not_applicable".to_owned(),
        ..PayloadSummary::default()
    })
}

/// One browser-reported lifecycle event. Every member except the server-side
/// binding facts is a client claim; it never changes an authorization result.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorObservation {
    binding_id: String,
    auth_epoch: u64,
    authenticated: bool,
    build_ref: String,
    page_handle: String,
    navigation_id: String,
    #[serde(deserialize_with = "Option::deserialize")]
    action_hint: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    client_request_id: Option<String>,
    client_event_seq: u32,
    visibility: String,
    sensor_event_type: String,
    #[serde(deserialize_with = "Option::deserialize")]
    callsite_fingerprint: Option<String>,
    claim_status: String,
    authorization_effect: String,
}

/// Client text is data: bounded printable ASCII that is never an action
/// reference, because references must not enter the journal or the index.
fn valid_client_hint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CLIENT_TEXT_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
        && !value.contains("action.")
}

fn sensor_observation(json: &str) -> Result<PayloadSummary, PublishError> {
    let payload: SensorObservation = serde_json::from_str(json)?;
    let page_ready = match payload.sensor_event_type.as_str() {
        "PAGE_READY" => true,
        "HEARTBEAT" | "VISIBILITY" => false,
        _ => return Err(PublishError::InvalidEvent),
    };
    if AuthBindingId::parse(payload.binding_id).is_err()
        || !(1..=AUTH_EPOCH_MAX).contains(&payload.auth_epoch)
        || !valid_lower_hex(&payload.build_ref, 64)
        || valid_prefixed_v7(&payload.page_handle, "pgh_").is_err()
        || valid_prefixed_v7(&payload.navigation_id, "nav_").is_err()
        || payload
            .action_hint
            .as_deref()
            .is_some_and(|hint| !valid_client_hint(hint))
        || payload
            .client_request_id
            .is_some_and(|value| RequestId::parse(value).is_err())
        || !(1..=MAX_CLIENT_EVENT_SEQUENCE).contains(&payload.client_event_seq)
        || page_ready != (payload.client_event_seq == 1)
        || !matches!(payload.visibility.as_str(), "visible" | "hidden")
        || payload
            .callsite_fingerprint
            .as_deref()
            .is_some_and(|value| !valid_lower_hex(value, 64))
        || payload.claim_status != "client_claimed"
        || payload.authorization_effect != "none"
    {
        return Err(PublishError::InvalidEvent);
    }
    let _ = payload.authenticated;
    Ok(PayloadSummary {
        proof_kind: "observation".to_owned(),
        confidence_status: "not_applicable".to_owned(),
        ..PayloadSummary::default()
    })
}
