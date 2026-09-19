use super::{Attempt, CATALOG_DEADLINE, CONFIG, ModelEvent, secret};
use chrono::{TimeDelta, Utc};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File},
    path::Path,
};
use xshield_audit::{JournalError, JournalKey, JournalLimits, JournalRecord, LocalJournal};
use xshield_core::domain::{ModelCallId, PolicyRevision, RequestId, SiteId, TenantId};
use xshield_evidence::{
    EvidenceClassification, EvidenceFidelity, EvidenceKey, EvidenceVaultConfig, EvidenceWrite,
    LocalEvidenceVault,
};
use xshield_postgres::{
    EvidenceCatalogPublish, EvidenceCatalogWriteOutcome, PostgresIdentityStore,
};

const DOCUMENT_MAX: usize = 512 * 1024;
const WRITE_OVERHEAD: u64 = 64 * 1024 + 61;
const RESERVATION: u64 = 4 * (DOCUMENT_MAX as u64 + WRITE_OVERHEAD);
const MAX_FILES: u64 = 100_000;
const AUDIT: &str = "MODEL_AUDIT_UNAVAILABLE";

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
                    "model.requested" | "model.responded" | "model.failed" | "model.timeout"
                    | "model.cancelled" => {
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
                                    "model.requested" | "model.failed"
                                ))
                            || (previous.event_type == "model.requested"
                                && (event.event_type == "model.requested"
                                    || payload.input_artifact_id
                                        != previous_payload.input_artifact_id))
                        {
                            return Err(JournalError::Corrupt("model lifecycle"));
                        }
                        if event.event_type == "model.requested" {
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
