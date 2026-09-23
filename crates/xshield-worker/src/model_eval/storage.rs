use super::{Attempt, CATALOG_DEADLINE, CONFIG, ModelEvent, secret};
use chrono::{TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File},
    path::Path,
};
use xshield_audit::{JournalError, JournalKey, JournalLimits, JournalRecord, LocalJournal};
use xshield_core::domain::{ArtifactId, ModelCallId, PolicyRevision, RequestId, SiteId, TenantId};
use xshield_evidence::{
    EvidenceClassification, EvidenceFidelity, EvidenceKey, EvidenceVaultConfig, EvidenceWrite,
    LocalEvidenceVault,
};
use xshield_postgres::{
    EvidenceCatalogArtifactQuery, EvidenceCatalogPublish, EvidenceCatalogWriteOutcome,
    ModelEvaluationCacheEntry, PostgresIdentityStore,
};

const DOCUMENT_MAX: usize = 512 * 1024;
const WRITE_OVERHEAD: u64 = 64 * 1024 + 61;
const RESERVATION: u64 = 4 * (DOCUMENT_MAX as u64 + WRITE_OVERHEAD);
const MAX_FILES: u64 = 100_000;
const AUDIT: &str = "MODEL_AUDIT_UNAVAILABLE";

/// Strict, owned representation of one successful source model-call record.
///
/// Cache reuse reserializes this record with a new call/request identity and a
/// `MODEL_CACHE_HIT` reason. The source record is never returned to callers.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CachedModelRecord {
    schema_version: u8,
    model_call_id: String,
    request_id: String,
    example_only: bool,
    provider: String,
    provider_model_id: String,
    model_revision: String,
    resolved_model_revision: Option<String>,
    prompt_revision: String,
    input_artifact_id: String,
    output_artifact_id: Option<String>,
    question_type: String,
    result: Option<Value>,
    probabilities: BTreeMap<String, f64>,
    legend: Option<BTreeMap<String, String>>,
    risk_projection: Option<Value>,
    pub(super) provider_confidence: Option<f64>,
    pub(super) confidence_status: String,
    probability_semantics: String,
    usage: CachedUsageRecord,
    duration_ms: u64,
    status: String,
    reason_code: String,
    http_status: Option<u16>,
    capture_status: String,
    retry_after_seconds: Option<u32>,
    provider_request_id: Option<String>,
    schema_validation: String,
    provider_internal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cache_source_model_call_id: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedUsageRecord {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    source: String,
}

pub(super) struct Storage {
    vault: LocalEvidenceVault,
    _root_lock: File,
    journal: LocalJournal,
    writes_remaining: u8,
}

impl Storage {
    pub(super) fn from_env() -> Result<Self, &'static str> {
        let root = env::var("XSHIELD_EVIDENCE_ROOT").map_err(|_| CONFIG)?;
        let evidence_key_id = env::var("XSHIELD_EVIDENCE_KEY_ID").map_err(|_| CONFIG)?;
        let evidence_key = secret("XSHIELD_EVIDENCE_KEY_HEX")?;
        let journal_root = env::var("XSHIELD_MODEL_JOURNAL_DIRECTORY").map_err(|_| CONFIG)?;
        let journal_key_id = env::var("XSHIELD_JOURNAL_KEY_ID").map_err(|_| CONFIG)?;
        let journal_key = secret("XSHIELD_JOURNAL_KEY_HEX")?;
        if *evidence_key == *journal_key {
            return Err(CONFIG);
        }
        let max_bytes = env::var("XSHIELD_EVIDENCE_MAX_TOTAL_BYTES")
            .map_err(|_| CONFIG)?
            .parse()
            .map_err(|_| CONFIG)?;
        let audit_bytes = env::var("XSHIELD_AUDIT_MAX_BYTES")
            .map_err(|_| CONFIG)?
            .parse::<u64>()
            .map_err(|_| CONFIG)?;
        if !(1024 * 1024..=1024 * 1024 * 1024).contains(&audit_bytes) {
            return Err(CONFIG);
        }
        let limits =
            JournalLimits::new(audit_bytes, audit_bytes * 9 / 10, 1).map_err(|_| CONFIG)?;
        let (journal, _) = LocalJournal::open(
            journal_root,
            journal_key_id,
            JournalKey::from_hex(&journal_key).map_err(|_| CONFIG)?,
            limits,
        )
        .map_err(|_| AUDIT)?;
        Self::open(
            Path::new(&root),
            &evidence_key_id,
            &evidence_key,
            max_bytes,
            journal,
        )
    }

    pub(super) fn open(
        root: &Path,
        key_id: &str,
        key: &str,
        max_bytes: u64,
        journal: LocalJournal,
    ) -> Result<Self, &'static str> {
        if !(RESERVATION..=1024 * 1024 * 1024 * 1024).contains(&max_bytes) {
            return Err(CONFIG);
        }
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(root, key_id, DOCUMENT_MAX, 1).map_err(|_| CONFIG)?,
            EvidenceKey::from_hex(key).map_err(|_| CONFIG)?,
        )
        .map_err(|_| "MODEL_EVIDENCE_UNAVAILABLE")?;
        // ponytail: one Unix directory lock bounds calls and reserves four objects;
        // a multi-worker service will need a shared quota and admission controller.
        let lock = File::open(root).map_err(|_| "MODEL_EVIDENCE_UNAVAILABLE")?;
        lock.try_lock().map_err(|_| "MODEL_EVALUATION_BUSY")?;
        let mut remaining = max_bytes;
        let mut files = MAX_FILES;
        for entry in fs::read_dir(root).map_err(|_| "MODEL_EVIDENCE_UNAVAILABLE")? {
            if files == 0 {
                return Err("MODEL_EVIDENCE_CAPACITY");
            }
            let metadata = entry
                .map_err(|_| "MODEL_EVIDENCE_UNAVAILABLE")?
                .path()
                .symlink_metadata()
                .map_err(|_| "MODEL_EVIDENCE_UNAVAILABLE")?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(CONFIG);
            }
            remaining = remaining.saturating_sub(metadata.len());
            files -= 1;
        }
        Ok(Self {
            vault,
            _root_lock: lock,
            journal,
            // Recovery only needs the journal. Exhausted evidence admission must
            // still allow interrupted calls and new capacity refusals to terminate.
            writes_remaining: if remaining >= RESERVATION && files >= 12 {
                4
            } else {
                0
            },
        })
    }

    pub(super) async fn capture(
        &mut self,
        store: &PostgresIdentityStore,
        attempt: &mut Attempt,
        kind: &str,
        bytes: &[u8],
        fidelity: EvidenceFidelity,
        parents: &[String],
    ) -> Result<String, &'static str> {
        if bytes.len() > DOCUMENT_MAX || self.writes_remaining == 0 {
            return Err("MODEL_EVIDENCE_CAPACITY");
        }
        // Charge failures as well: a failed catalog transaction can leave an orphan.
        self.writes_remaining -= 1;
        let manifest = tokio::task::block_in_place(|| {
            self.vault.write(&EvidenceWrite {
                tenant_id: &attempt.tenant,
                site_id: &attempt.site,
                request_id: &attempt.request,
                kind,
                content_type: "application/json",
                fidelity,
                classification: EvidenceClassification::Restricted,
                parent_refs: parents,
                expires_at: Utc::now() + TimeDelta::hours(24),
                plaintext: bytes,
            })
        })
        .map_err(|_| "MODEL_EVIDENCE_UNAVAILABLE")?;
        let artifact = manifest.manifest().artifact_id.clone();
        let (event, envelope) = attempt.envelope("evidence.cataloged", json!({
            "stage":"evidence_catalog", "outcome":"PASS", "reason_code":"EVIDENCE_CATALOG_PUBLISHED",
            "artifact_id":artifact
        }), std::slice::from_ref(&artifact))?;
        let command = EvidenceCatalogPublish::new(&manifest, &event, &envelope)
            .map_err(|_| "MODEL_CATALOG_UNAVAILABLE")?;
        let result =
            tokio::time::timeout(CATALOG_DEADLINE, store.publish_evidence_manifest(command))
                .await
                .map_err(|_| "MODEL_CATALOG_UNAVAILABLE")?
                .map_err(|_| "MODEL_CATALOG_UNAVAILABLE")?;
        if result == EvidenceCatalogWriteOutcome::Conflict {
            return Err("MODEL_CATALOG_CONFLICT");
        }
        Ok(artifact)
    }

    /// Revalidates and materializes one durable cache hit.
    ///
    /// Every source artifact is looked up in the exact `PostgreSQL` scope, its
    /// authenticated vault manifest is compared byte-for-byte with catalog
    /// metadata, and its content is parsed before any new model-call record is
    /// written. A hit reuses source evidence references but receives a fresh
    /// model-call artifact and lifecycle IDs.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) async fn execute_cached(
        &mut self,
        store: &PostgresIdentityStore,
        input: &super::Input,
        client: &impl super::ModelPort,
        attempt: &mut Attempt,
        internal: &[u8],
        source: &ModelEvaluationCacheEntry,
    ) -> Result<CachedModelRecord, &'static str> {
        let internal_bytes = self
            .read_cached_artifact(
                store,
                &attempt.tenant,
                &attempt.site,
                &source.internal_artifact,
                &source.source_request,
                "model_internal_input",
            )
            .await?;
        if internal_bytes.as_slice() != internal {
            return Err("MODEL_CACHE_SOURCE_INVALID");
        }
        let input_bytes = self
            .read_cached_artifact(
                store,
                &attempt.tenant,
                &attempt.site,
                &source.input_artifact,
                &source.source_request,
                "model_input",
            )
            .await?;
        let expected_input = input
            .api_bytes_for_model(
                source.source_request.as_str(),
                source.source_model_call.as_str(),
                source.internal_artifact.as_str(),
                client.provider_model(),
            )
            .map_err(|_| "MODEL_CACHE_SOURCE_INVALID")?;
        if input_bytes.as_slice() != expected_input.as_slice()
            || client.contains_secret(&expected_input)
        {
            return Err("MODEL_CACHE_SOURCE_INVALID");
        }
        validate_cached_input_document(&input_bytes, source)?;
        let output_bytes = self
            .read_cached_artifact(
                store,
                &attempt.tenant,
                &attempt.site,
                &source.output_artifact,
                &source.source_request,
                "model_output",
            )
            .await?;
        validate_cached_output_document(&output_bytes)?;
        let call_bytes = self
            .read_cached_artifact(
                store,
                &attempt.tenant,
                &attempt.site,
                &source.call_artifact,
                &source.source_request,
                "model_call",
            )
            .await?;
        let mut record: CachedModelRecord =
            serde_json::from_slice(&call_bytes).map_err(|_| "MODEL_CACHE_SOURCE_INVALID")?;
        validate_cached_record(&record, input, source)?;

        attempt.internal = Some(source.internal_artifact.as_str().to_owned());
        attempt.input = Some(source.input_artifact.as_str().to_owned());
        // The cache transition is the durable equivalent of model.requested;
        // it intentionally contains no provider request and no output ref yet.
        let mut cached_event = ModelEvent::new_for_provider(
            attempt,
            input,
            client.provider(),
            client.provider_model(),
        );
        "requested".clone_into(&mut cached_event.status);
        "MODEL_CACHE_HIT".clone_into(&mut cached_event.reason_code);
        cached_event.input_artifact_id = attempt.input.clone();
        cached_event.cache_source_model_call_id =
            Some(source.source_model_call.as_str().to_owned());
        self.event(attempt, "model.cache_hit", &cached_event)?;

        attempt.output = Some(source.output_artifact.as_str().to_owned());
        record.model_call_id = attempt.call.as_str().to_owned();
        record.request_id = attempt.request.as_str().to_owned();
        record.input_artifact_id = source.input_artifact.as_str().to_owned();
        record.output_artifact_id = Some(source.output_artifact.as_str().to_owned());
        "success".clone_into(&mut record.status);
        "MODEL_CACHE_HIT".clone_into(&mut record.reason_code);
        record.duration_ms = 0;
        record.http_status = None;
        "cached".clone_into(&mut record.capture_status);
        record.retry_after_seconds = None;
        record.provider_request_id = None;
        "cached".clone_into(&mut record.schema_validation);
        record.cache_source_model_call_id = Some(source.source_model_call.as_str().to_owned());
        let bytes = serde_json::to_vec(&record).map_err(|_| "MODEL_EVIDENCE_UNAVAILABLE")?;
        record.input_artifact_id = source.input_artifact.as_str().to_owned();
        attempt.record = Some(
            self.capture(
                store,
                attempt,
                "model_call",
                &bytes,
                EvidenceFidelity::Semantic,
                &attempt.refs(),
            )
            .await?,
        );
        Ok(record)
    }

    async fn read_cached_artifact(
        &self,
        store: &PostgresIdentityStore,
        tenant: &TenantId,
        site: &SiteId,
        artifact: &ArtifactId,
        source_request: &RequestId,
        expected_kind: &str,
    ) -> Result<Vec<u8>, &'static str> {
        let catalog = store
            .find_artifact(EvidenceCatalogArtifactQuery::new(tenant, site, artifact))
            .await
            .map_err(|_| "MODEL_CACHE_SOURCE_UNAVAILABLE")?
            .ok_or("MODEL_CACHE_SOURCE_INVALID")?;
        let manifest = catalog.manifest();
        if manifest.request_id != source_request.as_str()
            || manifest.kind != expected_kind
            || manifest.content_type != "application/json"
            || manifest.classification != EvidenceClassification::Restricted
        {
            return Err("MODEL_CACHE_SOURCE_INVALID");
        }
        let verified = tokio::task::block_in_place(|| {
            self.vault
                .read_manifest(tenant, site, artifact.as_str())
                .map_err(|_| "MODEL_CACHE_SOURCE_INVALID")
        })?;
        if verified.manifest() != manifest {
            return Err("MODEL_CACHE_SOURCE_INVALID");
        }
        let content = tokio::task::block_in_place(|| {
            self.vault
                .read_content_matching_manifest(tenant, site, &verified)
                .map_err(|_| "MODEL_CACHE_SOURCE_INVALID")
        })?;
        Ok(content.to_vec())
    }

    pub(super) fn event(
        &mut self,
        attempt: &mut Attempt,
        event_type: &str,
        payload: &ModelEvent,
    ) -> Result<(), &'static str> {
        if event_type == "model.started"
            && self
                .journal
                .status()
                .max_bytes
                .saturating_sub(self.journal.status().used_bytes)
                < 64 * 1024
        {
            return Err("MODEL_AUDIT_CAPACITY");
        }
        payload.clone().validate(event_type).map_err(|_| AUDIT)?;
        let (id, mut envelope) = attempt.envelope(event_type, payload, &attempt.refs())?;
        envelope["producer_boot_id"] = self.journal.producer_boot_id().into();
        envelope["producer_seq"] = self.journal.next_sequence().ok_or(AUDIT)?.into();
        let bytes = serde_json::to_vec(&envelope).map_err(|_| AUDIT)?;
        tokio::task::block_in_place(|| {
            self.journal.append_batch(&[JournalRecord {
                event_id: &id,
                plaintext: &bytes,
            }])
        })
        .map_err(|_| AUDIT)?;
        attempt.cause = Some(id.as_str().to_owned());
        Ok(())
    }

    /// Authenticate the dedicated history before accepting another provider call.
    /// Each one-record segment is closed immediately, so a completed CLI invocation
    /// is sealable without a later restart. No historical request body is replayed.
    pub(super) fn recover(&mut self) -> Result<(), &'static str> {
        let mut pending = BTreeMap::<String, (crate::WireEvent, ModelEvent)>::new();
        let mut seen = BTreeSet::new();
        // ponytail: bounded startup scan for the one-shot CLI; rotate the dedicated
        // journal root before 10,000 records, retaining old roots for publication.
        self.journal
            .visit_closed_records(10_000, |record| {
                let event: crate::WireEvent = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::Corrupt("model event"))?;
                crate::IndexRow::parse(
                    record.plaintext(),
                    record.event_id(),
                    record.producer_sequence(),
                    record.producer_boot_id(),
                    "0".repeat(64),
                    TimeDelta::days(1),
                )
                .map_err(|_| JournalError::Corrupt("model event"))?;
                let payload: ModelEvent = serde_json::from_str(event.payload.get())
                    .map_err(|_| JournalError::Corrupt("model event"))?;
                let old = pending.remove(&payload.model_call_id);
                match event.event_type.as_str() {
                    "model.started"
                        if old.is_none() && seen.insert(payload.model_call_id.clone()) =>
                    {
                        pending.insert(payload.model_call_id.clone(), (event, payload));
                    }
                    "model.requested" | "model.cache_hit" | "model.responded" | "model.failed"
                    | "model.timeout" | "model.cancelled" => {
                        let (previous, previous_payload) =
                            old.ok_or(JournalError::Corrupt("model lifecycle"))?;
                        if event.request_id != previous.request_id
                            || event.tenant_id != previous.tenant_id
                            || event.site_id != previous.site_id
                            || event.request_seq <= previous.request_seq
                            || event.policy_revision != previous.policy_revision
                            || event.trace_id != previous.trace_id
                            || payload.model_revision != previous_payload.model_revision
                            || payload.prompt_revision != previous_payload.prompt_revision
                            || payload.question_type != previous_payload.question_type
                            || event.cause_event_ids != [previous.event_id]
                            || (previous.event_type == "model.started"
                                && !matches!(
                                    event.event_type.as_str(),
                                    "model.requested" | "model.cache_hit" | "model.failed"
                                ))
                            || (matches!(
                                previous.event_type.as_str(),
                                "model.requested" | "model.cache_hit"
                            ) && (event.event_type == "model.requested"
                                || event.event_type == "model.cache_hit"
                                || payload.input_artifact_id != previous_payload.input_artifact_id))
                        {
                            return Err(JournalError::Corrupt("model lifecycle"));
                        }
                        if matches!(
                            event.event_type.as_str(),
                            "model.requested" | "model.cache_hit"
                        ) {
                            pending.insert(payload.model_call_id.clone(), (event, payload));
                        }
                    }
                    _ => return Err(JournalError::Corrupt("model lifecycle")),
                }
                Ok(())
            })
            .map_err(|_| "MODEL_RECOVERY_FAILED")?;
        for (_, (event, mut payload)) in pending {
            let mut attempt = Attempt {
                tenant: TenantId::parse(event.tenant_id).map_err(|_| AUDIT)?,
                site: SiteId::parse(event.site_id).map_err(|_| AUDIT)?,
                request: RequestId::parse(event.request_id.ok_or(AUDIT)?).map_err(|_| AUDIT)?,
                call: ModelCallId::parse(&payload.model_call_id).map_err(|_| AUDIT)?,
                policy: PolicyRevision::parse(event.policy_revision).map_err(|_| AUDIT)?,
                // Catalog transactions may have committed after the last journal
                // event. Skip the bounded four-object attempt's remaining slots.
                trace: event.trace_id,
                sequence: event.request_seq.checked_add(8).ok_or(AUDIT)?,
                cause: Some(event.event_id),
                internal: None,
                input: payload.input_artifact_id.clone(),
                output: None,
                record: None,
            };
            "error".clone_into(&mut payload.status);
            "MODEL_OUTCOME_UNKNOWN".clone_into(&mut payload.reason_code);
            payload.confidence = None;
            if payload.question_type == "noul" {
                "not_applicable"
            } else {
                "unavailable"
            }
            .clone_into(&mut payload.confidence_status);
            self.event(&mut attempt, "model.failed", &payload)?;
        }
        Ok(())
    }
}

fn validate_cached_input_document(
    bytes: &[u8],
    source: &ModelEvaluationCacheEntry,
) -> Result<(), &'static str> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "MODEL_CACHE_SOURCE_INVALID")?;
    let trace = value
        .get("state")
        .and_then(Value::as_object)
        .and_then(|state| state.get("trace_context"))
        .and_then(Value::as_object)
        .ok_or("MODEL_CACHE_SOURCE_INVALID")?;
    if value.get("model").and_then(Value::as_str) != Some(source.provider_model_id.as_str())
        || trace.get("request_id").and_then(Value::as_str) != Some(source.source_request.as_str())
        || trace.get("model_call_id").and_then(Value::as_str)
            != Some(source.source_model_call.as_str())
        || trace.get("input_artifact_id").and_then(Value::as_str)
            != Some(source.internal_artifact.as_str())
    {
        return Err("MODEL_CACHE_SOURCE_INVALID");
    }
    Ok(())
}

fn validate_cached_output_document(bytes: &[u8]) -> Result<(), &'static str> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "MODEL_CACHE_SOURCE_INVALID")?;
    let body = value
        .get("body")
        .and_then(Value::as_array)
        .ok_or("MODEL_CACHE_SOURCE_INVALID")?;
    let bytes_saved = value
        .get("bytes_saved")
        .and_then(Value::as_u64)
        .ok_or("MODEL_CACHE_SOURCE_INVALID")?;
    if value.get("representation").and_then(Value::as_str) != Some("entity_bytes_array")
        || value.get("capture_status").and_then(Value::as_str) != Some("complete")
        || bytes_saved != u64::try_from(body.len()).unwrap_or(u64::MAX)
    {
        return Err("MODEL_CACHE_SOURCE_INVALID");
    }
    Ok(())
}

fn validate_cached_record(
    record: &CachedModelRecord,
    input: &super::Input,
    source: &ModelEvaluationCacheEntry,
) -> Result<(), &'static str> {
    if record.schema_version != 3
        || record.model_call_id != source.source_model_call.as_str()
        || record.request_id != source.source_request.as_str()
        || record.example_only
        || record.provider != source.provider
        || record.provider_model_id != source.provider_model_id
        || record.model_revision != input.model_revision()
        || record.prompt_revision != input.prompt_revision()
        || record.resolved_model_revision != source.resolved_model_revision
        || record.input_artifact_id != source.input_artifact.as_str()
        || record.output_artifact_id.as_deref() != Some(source.output_artifact.as_str())
        || record.question_type != input.question_type()
        || record.status != "success"
        || record.reason_code != "MODEL_EVALUATED"
        || record.probability_semantics != "provider_reported_uncalibrated"
        || record.capture_status != "complete"
        || record.schema_validation != "valid"
        || record.cache_source_model_call_id.is_some()
        || !matches!(record.usage.source.as_str(), "provider" | "unavailable")
        || record
            .probabilities
            .values()
            .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
        || !crate::valid_confidence(
            "model",
            "PASS",
            record.provider_confidence,
            &record.confidence_status,
        )
    {
        return Err("MODEL_CACHE_SOURCE_INVALID");
    }
    if input.question_type() == "noul" {
        if record.confidence_status != "not_applicable" || !record.probabilities.is_empty() {
            return Err("MODEL_CACHE_SOURCE_INVALID");
        }
    } else if record.result.is_none() || record.probabilities.is_empty() {
        return Err("MODEL_CACHE_SOURCE_INVALID");
    }
    Ok(())
}
