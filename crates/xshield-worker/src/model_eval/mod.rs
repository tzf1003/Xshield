//! One-shot, operator-approved Jev evaluation with encrypted evidence and durable audit.
//!
//! This offline worker never writes authorization state. Run on a Tokio multi-thread
//! runtime: local durability barriers use `block_in_place`; provider and catalog I/O
//! have independent deadlines. A dedicated journal and exclusive evidence root bound
//! concurrency to one evaluation. Recovery closes interrupted attempts as unknown.

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    env,
    fs::File,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use uuid::Uuid;
use xshield_core::domain::{EventId, ModelCallId, PolicyRevision, RequestId, SiteId, TenantId};
use xshield_evidence::EvidenceFidelity;
use xshield_postgres::PostgresIdentityStore;
use zeroize::Zeroizing;

mod storage;
#[cfg(test)]
mod tests;
mod transport;
mod wire;

use storage::Storage;
use transport::{DIRECT_MODEL, GATEWAY_MODEL, JevClient, JevRoute, ModelPort};
use wire::{Input, Response};

const CONFIG: &str = "MODEL_CONFIG_INVALID";
const CATALOG_DEADLINE: Duration = Duration::from_secs(5);

/// Redacted terminal receipt. Detailed model content requires evidence authorization.
#[derive(Serialize)]
pub struct EvaluationReport {
    /// Server-generated request identity for the offline evaluation.
    pub request_id: String,
    /// Server-generated, single-attempt model identity.
    pub model_call_id: String,
    /// `success`, `error`, `timeout`, or `cancelled`; never an authorization decision.
    pub status: String,
    /// Stable evaluation or dependency outcome.
    pub reason_code: String,
    /// Actual sent request, when preparation completed.
    pub input_artifact_id: Option<String>,
    /// Captured provider bytes and explicit coverage, when available.
    pub output_artifact_id: Option<String>,
    /// Normalized model-call record, when durably cataloged.
    pub call_artifact_id: Option<String>,
}

/// Evaluates one explicitly approved, private UTF-8 JSON file using deployment secrets.
///
/// Input is capped at 8 KiB. The operator must approve external disclosure and redact
/// business secrets before invocation. No automatic retries, replay, or gateway writes
/// occur. Cancellation still awaits evidence capture and terminal journal durability.
///
/// # Errors
/// Stable reason codes contain no input, credentials, provider body, or storage paths.
/// Setup/validation errors prevent sending; a terminal audit failure returns an error
/// even if the provider responded. Next startup closes unfinished calls as unknown.
pub async fn evaluate_file(
    path: &Path,
    cancel: &mut oneshot::Receiver<()>,
) -> Result<EvaluationReport, &'static str> {
    if !matches!(
        tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()),
        Ok(tokio::runtime::RuntimeFlavor::MultiThread)
    ) {
        return Err("MODEL_RUNTIME_UNAVAILABLE");
    }
    let bytes = tokio::task::block_in_place(|| read_input(path))?;
    let input = Input::parse(&bytes)?;
    let route = JevRoute::from_environment()?;
    let api_key = secret(route.secret_name())?;
    let evidence_key = secret("XSHIELD_EVIDENCE_KEY_HEX")?;
    let journal_key = secret("XSHIELD_JOURNAL_KEY_HEX")?;
    if *api_key == *evidence_key || *api_key == *journal_key || *evidence_key == *journal_key {
        return Err(CONFIG);
    }
    let client = JevClient::new(route, api_key)?;
    if client.contains_secret(&bytes) {
        return Err("MODEL_SECRET_EXCLUDED");
    }
    let tenant =
        TenantId::parse(env::var("XSHIELD_TENANT_ID").map_err(|_| CONFIG)?).map_err(|_| CONFIG)?;
    let site =
        SiteId::parse(env::var("XSHIELD_SITE_ID").map_err(|_| CONFIG)?).map_err(|_| CONFIG)?;
    let mut storage = tokio::task::block_in_place(Storage::from_env)?;
    tokio::task::block_in_place(|| storage.recover())?;
    let database = secret("XSHIELD_DATABASE_URL")?;
    let store = tokio::time::timeout(
        CATALOG_DEADLINE,
        PostgresIdentityStore::connect(&database, 1, CATALOG_DEADLINE),
    )
    .await
    .map_err(|_| "MODEL_CATALOG_UNAVAILABLE")?
    .map_err(|_| "MODEL_CATALOG_UNAVAILABLE")?;
    evaluate(&input, &client, &mut storage, &store, tenant, site, cancel).await
}

fn secret(name: &str) -> Result<Zeroizing<String>, &'static str> {
    env::var(name).map(Zeroizing::new).map_err(|_| CONFIG)
}

fn read_input(path: &Path) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let expected = path.symlink_metadata().map_err(|_| "MODEL_INPUT_INVALID")?;
    if !expected.is_file() || expected.file_type().is_symlink() || expected.len() > 8192 {
        return Err("MODEL_INPUT_INVALID");
    }
    let file = File::open(path).map_err(|_| "MODEL_INPUT_INVALID")?;
    let metadata = file.metadata().map_err(|_| "MODEL_INPUT_INVALID")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.ino() != expected.ino()
            || metadata.dev() != expected.dev()
        {
            return Err("MODEL_INPUT_INVALID");
        }
    }
    if !metadata.is_file() {
        return Err("MODEL_INPUT_INVALID");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| "MODEL_INPUT_INVALID")?;
    if bytes.len() > 8192 {
        return Err("MODEL_INPUT_INVALID");
    }
    Ok(bytes)
}

struct Attempt {
    tenant: TenantId,
    site: SiteId,
    request: RequestId,
    call: ModelCallId,
    policy: PolicyRevision,
    trace: String,
    sequence: u32,
    cause: Option<String>,
    internal: Option<String>,
    input: Option<String>,
    output: Option<String>,
    record: Option<String>,
}

impl Attempt {
    fn new(input: &Input, tenant: TenantId, site: SiteId) -> Result<Self, &'static str> {
        Ok(Self {
            tenant,
            site,
            request: RequestId::parse(format!("req_{}", Uuid::now_v7())).map_err(|_| CONFIG)?,
            call: ModelCallId::parse(format!("mdl_{}", Uuid::now_v7())).map_err(|_| CONFIG)?,
            policy: PolicyRevision::parse(input.policy_revision()).map_err(|_| CONFIG)?,
            trace: Uuid::now_v7().simple().to_string(),
            sequence: 1,
            cause: None,
            internal: None,
            input: None,
            output: None,
            record: None,
        })
    }

    fn refs(&self) -> Vec<String> {
        [&self.internal, &self.input, &self.output, &self.record]
            .into_iter()
            .filter_map(Clone::clone)
            .collect()
    }

    fn envelope(
        &mut self,
        event_type: &str,
        payload: impl Serialize,
        refs: &[String],
    ) -> Result<(EventId, serde_json::Value), &'static str> {
        let event = EventId::parse(format!("ev_{}", Uuid::now_v7())).map_err(|_| CONFIG)?;
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
        let envelope = json!({
            "schema_version":3, "event_id":event.as_str(), "event_type":event_type,
            "tenant_id":self.tenant.as_str(), "site_id":self.site.as_str(),
            "request_id":self.request.as_str(), "trace_id":self.trace,
            "span_id":&Uuid::now_v7().simple().to_string()[..16],
            "producer_id":"model-eval", "producer_boot_id":Uuid::now_v7().to_string(),
            "producer_seq":1, "request_seq":self.sequence,
            "occurred_at":now, "observed_at":now, "policy_revision":self.policy.as_str(),
            "example_only":false, "evidence_refs":refs,
            "cause_event_ids":self.cause.iter().collect::<Vec<_>>(),
            "payload":payload, "sensitivity":"RESTRICTED",
            "integrity":{"state":"pending", "previous_hash":null, "event_hash":null}
        });
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("MODEL_AUDIT_UNAVAILABLE")?;
        Ok((event, envelope))
    }
}

async fn evaluate(
    input: &Input,
    client: &impl ModelPort,
    storage: &mut Storage,
    store: &PostgresIdentityStore,
    tenant: TenantId,
    site: SiteId,
    cancel: &mut oneshot::Receiver<()>,
) -> Result<EvaluationReport, &'static str> {
    let internal = Zeroizing::new(input.internal_bytes()?);
    if client.contains_secret(&internal) {
        return Err("MODEL_SECRET_EXCLUDED");
    }
    let mut attempt = Attempt::new(input, tenant, site)?;
    let mut event =
        ModelEvent::new_for_provider(&attempt, input, client.provider(), client.provider_model());
    storage.event(&mut attempt, "model.started", &event)?;
    let started = Instant::now();
    let result = execute(
        input,
        client,
        storage,
        store,
        &mut attempt,
        &internal,
        cancel,
    )
    .await;
    let (status, reason, response) = match result {
        Ok(result) => result,
        Err(reason) => ("error", reason, None),
    };
    event.status = status.to_owned();
    event.reason_code = reason.to_owned();
    event.duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    event.input_artifact_id.clone_from(&attempt.input);
    event.output_artifact_id.clone_from(&attempt.output);
    event.call_artifact_id.clone_from(&attempt.record);
    if let Some(response) = response {
        event.confidence = response.provider_confidence;
        response
            .confidence_status
            .clone_into(&mut event.confidence_status);
    }
    let event_type = match status {
        "success" => "model.responded",
        "timeout" => "model.timeout",
        "cancelled" => "model.cancelled",
        _ => "model.failed",
    };
    storage.event(&mut attempt, event_type, &event)?;
    Ok(EvaluationReport {
        request_id: attempt.request.as_str().to_owned(),
        model_call_id: attempt.call.as_str().to_owned(),
        status: status.to_owned(),
        reason_code: reason.to_owned(),
        input_artifact_id: attempt.input,
        output_artifact_id: attempt.output,
        call_artifact_id: attempt.record,
    })
}

// Keep the ordered input/send/output barriers together for durability review.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn execute(
    input: &Input,
    client: &impl ModelPort,
    storage: &mut Storage,
    store: &PostgresIdentityStore,
    attempt: &mut Attempt,
    internal: &[u8],
    cancel: &mut oneshot::Receiver<()>,
) -> Result<(&'static str, &'static str, Option<Response>), &'static str> {
    attempt.internal = Some(
        storage
            .capture(
                store,
                attempt,
                "model_internal_input",
                internal,
                EvidenceFidelity::Semantic,
                &[],
            )
            .await?,
    );
    let api = Zeroizing::new(
        input.api_bytes_for_model(
            attempt.request.as_str(),
            attempt.call.as_str(),
            attempt
                .internal
                .as_deref()
                .ok_or("MODEL_EVIDENCE_UNAVAILABLE")?,
            client.provider_model(),
        )?,
    );
    if client.contains_secret(&api) {
        return Err("MODEL_SECRET_EXCLUDED");
    }
    attempt.input = Some(
        storage
            .capture(
                store,
                attempt,
                "model_input",
                &api,
                EvidenceFidelity::EntityExact,
                &attempt.refs(),
            )
            .await?,
    );
    let mut requested =
        ModelEvent::new_for_provider(attempt, input, client.provider(), client.provider_model());
    "requested".clone_into(&mut requested.status);
    "MODEL_REQUESTED".clone_into(&mut requested.reason_code);
    requested.input_artifact_id.clone_from(&attempt.input);
    storage.event(attempt, "model.requested", &requested)?;
    let started = Instant::now();
    let exchange = client.send(&api, cancel).await;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let response = if let Some(failure) = exchange.failure {
        Err(failure)
    } else {
        Response::parse_for_model(&exchange.body, input, client.provider_model())
    };
    let (status, reason) = match &response {
        Ok(_) => ("success", "MODEL_EVALUATED"),
        Err("MODEL_TIMEOUT") => ("timeout", "MODEL_TIMEOUT"),
        Err("MODEL_CANCELLED") => ("cancelled", "MODEL_CANCELLED"),
        Err(reason) => ("error", *reason),
    };
    if !matches!(exchange.capture_status, "unavailable" | "excluded_policy") {
        // The object is a complete capture document; its body coverage is explicit.
        // An integer array preserves arbitrary provider bytes, including invalid UTF-8.
        let document = Zeroizing::new(
            serde_json::to_vec(&ModelOutputCapture {
                schema_version: 1,
                representation: "entity_bytes_array",
                capture_status: exchange.capture_status,
                http_status: exchange.status,
                bytes_observed: exchange.bytes_observed,
                bytes_saved: exchange.body.len(),
                body: &exchange.body,
            })
            .map_err(|_| "MODEL_EVIDENCE_UNAVAILABLE")?,
        );
        attempt.output = Some(
            storage
                .capture(
                    store,
                    attempt,
                    "model_output",
                    &document,
                    EvidenceFidelity::Semantic,
                    &attempt.refs(),
                )
                .await?,
        );
    }
    let parsed = response.as_ref().ok();
    let confidence_status = parsed.map_or_else(
        || {
            if input.question_type() == "noul" {
                "not_applicable"
            } else {
                "unavailable"
            }
        },
        |response| response.confidence_status,
    );
    let input_artifact_id = attempt.input.clone().ok_or("MODEL_EVIDENCE_UNAVAILABLE")?;
    let record = Zeroizing::new(
        serde_json::to_vec(&ModelCallRecord {
            schema_version: 3,
            model_call_id: attempt.call.as_str().to_owned(),
            request_id: attempt.request.as_str().to_owned(),
            example_only: false,
            provider: client.provider(),
            provider_model_id: client.provider_model(),
            model_revision: input.model_revision().to_owned(),
            resolved_model_revision: parsed
                .and_then(|response| response.resolved_model_revision.clone()),
            prompt_revision: input.prompt_revision().to_owned(),
            input_artifact_id,
            output_artifact_id: attempt.output.clone(),
            question_type: input.question_type(),
            result: parsed.map(|response| response.result.clone()),
            probabilities: parsed
                .map_or_else(BTreeMap::new, |response| response.probabilities.clone()),
            legend: parsed.and_then(|response| response.legend.clone()),
            provider_confidence: parsed.and_then(|response| response.provider_confidence),
            confidence_status,
            probability_semantics: "provider_reported_uncalibrated",
            usage: UsageRecord {
                input_tokens: parsed.and_then(|response| response.input_tokens),
                output_tokens: parsed.and_then(|response| response.output_tokens),
                source: parsed.map_or("unavailable", |response| response.usage_source),
            },
            duration_ms,
            status,
            reason_code: reason,
            http_status: exchange.status,
            capture_status: exchange.capture_status,
            retry_after_seconds: exchange.retry_after_seconds,
            provider_request_id: exchange.provider_request_id.clone(),
            schema_validation: if parsed.is_some() {
                "valid"
            } else if exchange.failure.is_none() {
                "invalid"
            } else {
                "unavailable"
            },
            provider_internal: "unavailable",
        })
        .map_err(|_| "MODEL_EVIDENCE_UNAVAILABLE")?,
    );
    attempt.record = Some(
        storage
            .capture(
                store,
                attempt,
                "model_call",
                &record,
                EvidenceFidelity::Semantic,
                &attempt.refs(),
            )
            .await?,
    );
    Ok((status, reason, response.ok()))
}

#[derive(Serialize)]
struct ModelOutputCapture<'a> {
    schema_version: u8,
    representation: &'static str,
    capture_status: &'static str,
    http_status: Option<u16>,
    bytes_observed: u64,
    bytes_saved: usize,
    body: &'a [u8],
}

#[derive(Serialize)]
struct ModelCallRecord {
    schema_version: u8,
    model_call_id: String,
    request_id: String,
    example_only: bool,
    provider: &'static str,
    provider_model_id: &'static str,
    model_revision: String,
    resolved_model_revision: Option<String>,
    prompt_revision: String,
    input_artifact_id: String,
    output_artifact_id: Option<String>,
    question_type: &'static str,
    result: Option<wire::ResultValue>,
    probabilities: BTreeMap<String, f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    legend: Option<BTreeMap<String, String>>,
    provider_confidence: Option<f64>,
    confidence_status: &'static str,
    probability_semantics: &'static str,
    usage: UsageRecord,
    duration_ms: u64,
    status: &'static str,
    reason_code: &'static str,
    http_status: Option<u16>,
    capture_status: &'static str,
    retry_after_seconds: Option<u32>,
    provider_request_id: Option<String>,
    schema_validation: &'static str,
    provider_internal: &'static str,
}

#[derive(Serialize)]
struct UsageRecord {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    source: &'static str,
}

/// Closed model lifecycle metadata. Kept typed at both journal boundaries.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelEvent {
    pub(crate) model_call_id: String,
    #[serde(default, deserialize_with = "deserialize_non_null_option")]
    pub(crate) provider: Option<String>,
    #[serde(default, deserialize_with = "deserialize_non_null_option")]
    pub(crate) provider_model_id: Option<String>,
    pub(crate) model_revision: String,
    pub(crate) prompt_revision: String,
    pub(crate) question_type: String,
    pub(crate) status: String,
    pub(crate) reason_code: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) confidence: Option<f64>,
    pub(crate) confidence_status: String,
    pub(crate) duration_us: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) input_artifact_id: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) output_artifact_id: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) call_artifact_id: Option<String>,
}

fn deserialize_non_null_option<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("null is not an absent provider field"))
}

impl ModelEvent {
    pub(crate) fn parse_query_event(
        payload: &str,
        event_type: &str,
    ) -> Result<Self, crate::PublishError> {
        let event: Self = serde_json::from_str(payload)?;
        event.clone().validate(event_type)?;
        Ok(event)
    }

    pub(super) fn validate_envelope(event: &crate::WireEvent) -> Result<(), crate::PublishError> {
        let payload: Self = serde_json::from_str(event.payload.get())?;
        if event.request_id.is_none()
            || [
                &payload.input_artifact_id,
                &payload.output_artifact_id,
                &payload.call_artifact_id,
            ]
            .into_iter()
            .flatten()
            .any(|id| !event.evidence_refs.contains(id))
        {
            return Err(crate::PublishError::InvalidEvent);
        }
        Ok(())
    }

    #[cfg(test)]
    fn new(attempt: &Attempt, input: &Input) -> Self {
        Self::new_for_provider(attempt, input, "typesafe", DIRECT_MODEL)
    }

    fn new_for_provider(
        attempt: &Attempt,
        input: &Input,
        provider: &str,
        provider_model_id: &str,
    ) -> Self {
        Self {
            model_call_id: attempt.call.as_str().to_owned(),
            provider: Some(provider.to_owned()),
            provider_model_id: Some(provider_model_id.to_owned()),
            model_revision: input.model_revision().to_owned(),
            prompt_revision: input.prompt_revision().to_owned(),
            question_type: input.question_type().to_owned(),
            status: "started".to_owned(),
            reason_code: "MODEL_EVALUATION_STARTED".to_owned(),
            confidence: None,
            confidence_status: if input.question_type() == "noul" {
                "not_applicable"
            } else {
                "unavailable"
            }
            .to_owned(),
            duration_us: 0,
            input_artifact_id: None,
            output_artifact_id: None,
            call_artifact_id: None,
        }
    }

    pub(super) fn validate(
        self,
        event_type: &str,
    ) -> Result<crate::PayloadSummary, crate::PublishError> {
        use crate::PublishError::InvalidEvent;
        ModelCallId::parse(&self.model_call_id).map_err(|_| InvalidEvent)?;
        match (&self.provider, &self.provider_model_id) {
            (None, None) => {}
            (Some(provider), Some(provider_model_id))
                if crate::valid_name(provider)
                    && ((provider == "typesafe" && provider_model_id == DIRECT_MODEL)
                        || (provider == "vercel_ai_gateway"
                            && provider_model_id == GATEWAY_MODEL)) => {}
            _ => return Err(InvalidEvent),
        }
        let outcome = match (event_type, self.status.as_str()) {
            ("model.started", "started") | ("model.requested", "requested") => "UNKNOWN",
            ("model.responded", "success") => "PASS",
            ("model.timeout", "timeout") | ("model.failed", "error") => "ERROR",
            ("model.cancelled", "cancelled") => "CANCELLED",
            _ => return Err(InvalidEvent),
        };
        if !crate::valid_name(&self.model_revision)
            || !crate::valid_name(&self.prompt_revision)
            || !crate::valid_name(&self.reason_code)
            || !matches!(self.question_type.as_str(), "choice" | "score" | "noul")
            || !crate::valid_confidence("model", outcome, self.confidence, &self.confidence_status)
            || (self.question_type == "noul" && self.confidence_status != "not_applicable")
            || (self.status != "success" && self.confidence.is_some())
            || (matches!(self.status.as_str(), "requested" | "success")
                && self.input_artifact_id.is_none())
            || (self.status == "success"
                && (self.output_artifact_id.is_none() || self.call_artifact_id.is_none()))
        {
            return Err(InvalidEvent);
        }
        for id in [
            &self.input_artifact_id,
            &self.output_artifact_id,
            &self.call_artifact_id,
        ]
        .into_iter()
        .flatten()
        {
            xshield_core::domain::ArtifactId::parse(id).map_err(|_| InvalidEvent)?;
        }
        Ok(crate::PayloadSummary {
            stage: "model_eval".to_owned(),
            outcome: outcome.to_owned(),
            reason_code: self.reason_code,
            proof_kind: "model".to_owned(),
            confidence: self.confidence,
            confidence_status: self.confidence_status,
            model_revision: self.model_revision,
            duration_us: self.duration_us,
            ..crate::PayloadSummary::default()
        })
    }
}
