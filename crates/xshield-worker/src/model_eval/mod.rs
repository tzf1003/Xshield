//! One-shot, operator-approved Jev evaluation with encrypted evidence and durable audit.
//!
//! This offline worker never writes authorization state. Run on a Tokio multi-thread
//! runtime: local durability barriers use `block_in_place`; provider and catalog I/O
//! have independent deadlines. A dedicated journal and exclusive evidence root bound
//! concurrency to one evaluation. Recovery closes interrupted attempts as unknown.

use chrono::{SecondsFormat, Timelike, Utc};
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
use xshield_core::{
    domain::{ArtifactId, EventId, ModelCallId, PolicyRevision, RequestId, SiteId, TenantId},
    model_evaluation_admission::{
        ModelEvaluationAdmissionAttempt, ModelEvaluationAdmissionReleaseState,
        ModelEvaluationAdmissionState,
    },
    ports::ModelEvaluationAdmissionPort,
};
use xshield_evidence::EvidenceFidelity;
use xshield_postgres::{
    ModelEvaluationAdmissionLease, ModelEvaluationCacheWrite, PostgresIdentityStore,
};
use zeroize::Zeroizing;

mod cache;
mod storage;
#[cfg(test)]
mod tests;
mod transport;
mod wire;

use storage::{CachedModelRecord, Storage};
use transport::{
    DIRECT_MODEL, GATEWAY_MODEL, JevClient, JevRoute, ModelPort, PROVIDER_SEND_DEADLINE,
};
use wire::{Input, Response};

const CONFIG: &str = "MODEL_CONFIG_INVALID";
const CATALOG_DEADLINE: Duration = Duration::from_secs(5);
const DEFAULT_EVALUATION_RUNNER: &str = "xshield-model-eval";
const ADMISSION_UNAVAILABLE: &str = "MODEL_EVALUATION_ADMISSION_UNAVAILABLE";
const ADMISSION_RELEASE_UNAVAILABLE: &str = "MODEL_EVALUATION_ADMISSION_RELEASE_UNAVAILABLE";

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
    let cache = cache::ModelCacheConfiguration::from_environment(&client)?;
    let cache_key = if let Some(cache) = &cache {
        // Derive once before setup proceeds, so a malformed cache configuration
        // cannot surface after local evidence/journal resources have been opened.
        let key = cache.key_for(&tenant, &site, &input)?;
        if cache.reuses_transport_secret(&client)
            || cache.matches_hex_secret(&evidence_key)
            || cache.matches_hex_secret(&journal_key)
        {
            return Err(CONFIG);
        }
        Some(key)
    } else {
        None
    };
    let runner_id = env::var("XSHIELD_MODEL_EVALUATION_RUNNER_ID")
        .unwrap_or_else(|_| DEFAULT_EVALUATION_RUNNER.to_owned());
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
    evaluate_with_cache(
        &input,
        &client,
        &mut storage,
        &store,
        tenant,
        site,
        &runner_id,
        cache.as_ref(),
        cache_key.as_ref(),
        cancel,
    )
    .await
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

enum ExecutionResult {
    Provider(Option<Box<Response>>),
    Cache(Box<CachedModelRecord>),
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

#[cfg(test)]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn evaluate(
    input: &Input,
    client: &impl ModelPort,
    storage: &mut Storage,
    store: &PostgresIdentityStore,
    tenant: TenantId,
    site: SiteId,
    runner_id: &str,
    cancel: &mut oneshot::Receiver<()>,
) -> Result<EvaluationReport, &'static str> {
    evaluate_with_cache(
        input, client, storage, store, tenant, site, runner_id, None, None, cancel,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity
)]
async fn evaluate_with_cache(
    input: &Input,
    client: &impl ModelPort,
    storage: &mut Storage,
    store: &PostgresIdentityStore,
    tenant: TenantId,
    site: SiteId,
    runner_id: &str,
    cache: Option<&cache::ModelCacheConfiguration>,
    cache_key: Option<&cache::ModelCacheKey>,
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
    let mut cache_hit = false;
    let (lease, result): (
        Option<ModelEvaluationAdmissionLease>,
        Result<(&'static str, &'static str, ExecutionResult), &'static str>,
    ) = if let (Some(cache), Some(cache_key)) = (cache, cache_key) {
        match tokio::time::timeout(
            CATALOG_DEADLINE,
            store.find_model_evaluation_cache(&attempt.tenant, &attempt.site, cache_key.as_bytes()),
        )
        .await
        {
            Ok(Ok(Some(source))) => {
                if source.provider != cache.provider()
                    || source.provider_model_id != cache.provider_model_id()
                    || source.model_revision != input.model_revision()
                    || source.prompt_revision != input.prompt_revision()
                    || source.resolved_model_revision.as_deref()
                        != Some(cache.resolved_model_revision())
                {
                    (None, Err("MODEL_CACHE_SOURCE_INVALID"))
                } else {
                    let result = tokio::time::timeout(
                        CATALOG_DEADLINE,
                        storage.execute_cached(
                            store,
                            input,
                            client,
                            &mut attempt,
                            &internal,
                            &source,
                        ),
                    )
                    .await
                    .map_err(|_| "MODEL_CACHE_SOURCE_UNAVAILABLE")
                    .and_then(|result| {
                        result.map(|cached| {
                            cache_hit = true;
                            (
                                "success",
                                "MODEL_CACHE_HIT",
                                ExecutionResult::Cache(Box::new(cached)),
                            )
                        })
                    });
                    (None, result)
                }
            }
            Ok(Ok(None)) => {
                run_provider_evaluation(
                    input,
                    client,
                    storage,
                    store,
                    &mut attempt,
                    &internal,
                    runner_id,
                    cancel,
                )
                .await
            }
            Ok(Err(_)) | Err(_) => (None, Err("MODEL_CACHE_UNAVAILABLE")),
        }
    } else {
        run_provider_evaluation(
            input,
            client,
            storage,
            store,
            &mut attempt,
            &internal,
            runner_id,
            cancel,
        )
        .await
    };
    let (status, reason, execution) = match result {
        Ok(result) => result,
        Err(reason) => ("error", reason, ExecutionResult::Provider(None)),
    };
    if !cache_hit
        && status == "success"
        && let (
            Some(cache),
            Some(cache_key),
            Some(internal_id),
            Some(input_id),
            Some(output_id),
            Some(call_id),
        ) = (
            cache,
            cache_key,
            attempt.internal.as_deref(),
            attempt.input.as_deref(),
            attempt.output.as_deref(),
            attempt.record.as_deref(),
        )
    {
        let source_request = attempt.request.clone();
        let source_model_call = attempt.call.clone();
        if let (Ok(internal_id), Ok(input_id), Ok(output_id), Ok(call_id)) = (
            ArtifactId::parse(internal_id),
            ArtifactId::parse(input_id),
            ArtifactId::parse(output_id),
            ArtifactId::parse(call_id),
        ) && let Ok(command) = ModelEvaluationCacheWrite::new(
            &attempt.tenant,
            &attempt.site,
            cache_key.as_bytes(),
            &source_request,
            &source_model_call,
            &internal_id,
            &input_id,
            &output_id,
            &call_id,
            cache.provider(),
            cache.provider_model_id(),
            input.model_revision(),
            input.prompt_revision(),
            Some(cache.resolved_model_revision()),
            {
                let expires_at = Utc::now() + chrono::TimeDelta::hours(24);
                expires_at
                    .with_nanosecond(expires_at.timestamp_subsec_millis() * 1_000_000)
                    .unwrap_or(expires_at)
            },
        ) {
            // Cache persistence is an optimization after the provider response
            // and complete source evidence are already durable. A failed or
            // racing insert must not rewrite a successful model outcome into a
            // dependency failure; the next exact evaluation can populate the
            // key again.
            let _ = tokio::time::timeout(
                CATALOG_DEADLINE,
                store.store_model_evaluation_cache(command),
            )
            .await;
        }
    }
    event.status = status.to_owned();
    event.reason_code = reason.to_owned();
    event.duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    event.input_artifact_id.clone_from(&attempt.input);
    event.output_artifact_id.clone_from(&attempt.output);
    event.call_artifact_id.clone_from(&attempt.record);
    match &execution {
        ExecutionResult::Provider(Some(response)) if status == "success" => {
            event.confidence = response.provider_confidence;
            response
                .confidence_status
                .clone_into(&mut event.confidence_status);
        }
        ExecutionResult::Cache(cached) if status == "success" => {
            event.confidence = cached.provider_confidence;
            cached
                .confidence_status
                .clone_into(&mut event.confidence_status);
        }
        ExecutionResult::Provider(None) => {}
        ExecutionResult::Provider(Some(_)) | ExecutionResult::Cache(_) => {
            event.confidence = None;
            let confidence_status = if input.question_type() == "noul" {
                "not_applicable"
            } else {
                "unavailable"
            };
            confidence_status.clone_into(&mut event.confidence_status);
        }
    }
    let event_type = match status {
        "success" => "model.responded",
        "timeout" => "model.timeout",
        "cancelled" => "model.cancelled",
        _ => "model.failed",
    };
    storage.event(&mut attempt, event_type, &event)?;
    let report = EvaluationReport {
        request_id: attempt.request.as_str().to_owned(),
        model_call_id: attempt.call.as_str().to_owned(),
        status: status.to_owned(),
        reason_code: reason.to_owned(),
        input_artifact_id: attempt.input,
        output_artifact_id: attempt.output,
        call_artifact_id: attempt.record,
    };
    if let Some(lease) = lease {
        let released = tokio::time::timeout(
            CATALOG_DEADLINE,
            ModelEvaluationAdmissionPort::release_model_evaluation_admission(store, &lease),
        )
        .await
        .map_err(|_| ADMISSION_RELEASE_UNAVAILABLE)?
        .map_err(|_| ADMISSION_RELEASE_UNAVAILABLE)?;
        if !matches!(
            released,
            ModelEvaluationAdmissionReleaseState::Released
                | ModelEvaluationAdmissionReleaseState::AlreadyReleased
        ) {
            return Err(ADMISSION_RELEASE_UNAVAILABLE);
        }
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
async fn run_provider_evaluation(
    input: &Input,
    client: &impl ModelPort,
    storage: &mut Storage,
    store: &PostgresIdentityStore,
    attempt: &mut Attempt,
    internal: &[u8],
    runner_id: &str,
    cancel: &mut oneshot::Receiver<()>,
) -> (
    Option<ModelEvaluationAdmissionLease>,
    Result<(&'static str, &'static str, ExecutionResult), &'static str>,
) {
    let admission_attempt = ModelEvaluationAdmissionAttempt::new(
        attempt.tenant.clone(),
        attempt.site.clone(),
        attempt.request.clone(),
        attempt.call.clone(),
        attempt.policy.clone(),
        runner_id,
    )
    .ok();
    // Admission happens after `model.started`, so local configuration and
    // authoritative-store failures still pass through the common terminal
    // event barrier instead of leaving a started-only lifecycle.
    match admission_attempt {
        None => (None, Err(CONFIG)),
        Some(admission_attempt) => match tokio::time::timeout(
            CATALOG_DEADLINE,
            ModelEvaluationAdmissionPort::acquire_model_evaluation_admission(
                store,
                &admission_attempt,
            ),
        )
        .await
        {
            Ok(Ok(ModelEvaluationAdmissionState::Admitted(lease))) => {
                let result = execute(
                    input, client, storage, store, attempt, internal, &lease, cancel,
                )
                .await;
                (Some(lease), result)
            }
            Ok(Ok(ModelEvaluationAdmissionState::Denied(denied))) => {
                (None, Err(denied.reason_code()))
            }
            Ok(Err(_)) | Err(_) => (None, Err(ADMISSION_UNAVAILABLE)),
        },
    }
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
    admission: &ModelEvaluationAdmissionLease,
    cancel: &mut oneshot::Receiver<()>,
) -> Result<(&'static str, &'static str, ExecutionResult), &'static str> {
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
    // The synchronous journal barrier comes before the final database-time
    // confirmation. The confirmation plus HTTP exchange share this one
    // monotonic budget: confirmation verifies a full provider window against
    // database time, and the client receives only the remainder. This makes a
    // scheduler or catalog delay shorten the call instead of letting it run
    // beyond its private lease.
    let send_budget_started = Instant::now();
    match tokio::time::timeout(
        CATALOG_DEADLINE,
        ModelEvaluationAdmissionPort::confirm_model_evaluation_admission(store, admission),
    )
    .await
    .map_err(|_| ADMISSION_UNAVAILABLE)?
    .map_err(|_| ADMISSION_UNAVAILABLE)?
    {
        ModelEvaluationAdmissionState::Admitted(()) => {}
        ModelEvaluationAdmissionState::Denied(denied) => return Err(denied.reason_code()),
    }
    let Some(send_timeout) = PROVIDER_SEND_DEADLINE
        .checked_sub(send_budget_started.elapsed())
        .filter(|deadline| !deadline.is_zero())
    else {
        return Err("MODEL_EVALUATION_ADMISSION_LEASE_EXPIRED");
    };
    let started = Instant::now();
    let exchange = client.send_with_deadline(&api, cancel, send_timeout).await;
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
            risk_projection: parsed.and_then(|response| response.risk_projection.clone()),
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
    Ok((
        status,
        reason,
        ExecutionResult::Provider(response.ok().map(Box::new)),
    ))
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
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_projection: Option<wire::RiskProjection>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cache_source_model_call_id: Option<String>,
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
            cache_source_model_call_id: None,
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
            ("model.started", "started") | ("model.requested" | "model.cache_hit", "requested") => {
                "UNKNOWN"
            }
            ("model.responded", "success") => "PASS",
            ("model.timeout", "timeout") | ("model.failed", "error") => "ERROR",
            ("model.cancelled", "cancelled") => "CANCELLED",
            _ => return Err(InvalidEvent),
        };
        if !crate::valid_name(&self.model_revision)
            || !crate::valid_name(&self.prompt_revision)
            || !crate::valid_name(&self.reason_code)
            || !matches!(self.question_type.as_str(), "choice" | "score" | "noul")
            || (event_type == "model.cache_hit"
                && (self.reason_code != "MODEL_CACHE_HIT"
                    || self.cache_source_model_call_id.is_none()))
            || (event_type != "model.cache_hit" && self.cache_source_model_call_id.is_some())
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
        if let Some(source) = &self.cache_source_model_call_id {
            ModelCallId::parse(source).map_err(|_| InvalidEvent)?;
        }
        Ok(crate::PayloadSummary {
            stage: "model_eval".to_owned(),
            outcome: outcome.to_owned(),
            reason_code: self.reason_code,
            proof_kind: "model".to_owned(),
            confidence: self.confidence,
            confidence_status: self.confidence_status,
            model_revision: self.model_revision,
            model_call_id: self.model_call_id,
            duration_us: self.duration_us,
            ..crate::PayloadSummary::default()
        })
    }
}
