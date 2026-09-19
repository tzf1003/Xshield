use chrono::{SecondsFormat, Utc};
use serde_json::json;
use std::{
    env,
    fs::{self, File},
    path::Path,
    sync::Mutex,
};
use tokio::sync::{Semaphore, SemaphorePermit};
use uuid::Uuid;
use xshield_core::{
    audit::ReasonCode,
    domain::{EventId, RequestId},
};
use xshield_evidence::{
    EvidenceClassification, EvidenceFidelity, EvidenceKey, EvidenceVaultConfig, EvidenceWrite,
    LocalEvidenceVault, VerifiedEvidenceManifest,
};
use xshield_gateway::{GatewayConfig, evidence_capture::EvidenceCaptureRule};
use xshield_postgres::{EvidenceCatalogPublish, EvidenceCatalogWriteOutcome};
use zeroize::Zeroizing;

use crate::{
    PostgresRuntime,
    durable_audit::{AdmissionAudit, DurableAudit},
};

const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILES: u64 = 100_000;
// Ciphertext framing, manifest's enforced maximum, and its authentication tag.
const WRITE_OVERHEAD: u64 = 64 * 1024 + 61;

pub(crate) struct EvidenceWriter {
    vault: LocalEvidenceVault,
    _root_lock: File,
    budget: Mutex<Budget>,
    capacity: Semaphore,
}

struct Budget {
    remaining_bytes: u64,
    remaining_files: u64,
}

impl EvidenceWriter {
    pub(crate) fn from_env(
        config: &GatewayConfig,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        if !config.requires_evidence_capture() {
            return Ok(None);
        }
        let root = env::var("XSHIELD_EVIDENCE_ROOT")?;
        let key_id = env::var("XSHIELD_EVIDENCE_KEY_ID")?;
        let key = Zeroizing::new(env::var("XSHIELD_EVIDENCE_KEY_HEX")?);
        for other in [
            "XSHIELD_JOURNAL_KEY_HEX",
            "XSHIELD_REQUEST_DECRYPTION_KEY_HEX",
            "XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX",
            "XSHIELD_FINGERPRINT_KEY_HEX",
        ] {
            if env::var(other)
                .ok()
                .map(Zeroizing::new)
                .is_some_and(|other| *other == *key)
            {
                return Err("evidence key must be independent".into());
            }
        }
        let max_bytes = env::var("XSHIELD_EVIDENCE_MAX_TOTAL_BYTES")?.parse()?;
        Self::open(Path::new(&root), &key_id, &key, max_bytes).map(Some)
    }

    fn open(
        root: &Path,
        key_id: &str,
        key: &str,
        max_bytes: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if !(MAX_DOCUMENT_BYTES as u64 + WRITE_OVERHEAD..=1024 * 1024 * 1024 * 1024)
            .contains(&max_bytes)
        {
            return Err("invalid evidence total capacity".into());
        }
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(root, key_id, MAX_DOCUMENT_BYTES, 1)?,
            EvidenceKey::from_hex(key)?,
        )?;
        // The private root is dedicated to this writer; control-plane readers
        // do not acquire the exclusive directory lock. Unix deployment only.
        let root_lock = File::open(root)?;
        root_lock.try_lock()?;
        let mut remaining_bytes = max_bytes;
        let mut remaining_files = MAX_FILES;
        for entry in fs::read_dir(root)? {
            let metadata = entry?.path().symlink_metadata()?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("invalid evidence root entry".into());
            }
            remaining_bytes = remaining_bytes
                .checked_sub(metadata.len())
                .ok_or("evidence capacity exhausted")?;
            remaining_files = remaining_files
                .checked_sub(1)
                .ok_or("evidence file capacity exhausted")?;
        }
        Ok(Self {
            vault,
            _root_lock: root_lock,
            budget: Mutex::new(Budget {
                remaining_bytes,
                remaining_files,
            }),
            capacity: Semaphore::new(1),
        })
    }

    /// Acquire before parsing, keep through vault/catalog/journal publication.
    /// No work queue retains additional response copies while the writer is busy.
    pub(crate) fn reserve(&self) -> Result<SemaphorePermit<'_>, ReasonCode> {
        self.capacity
            .try_acquire()
            .map_err(|_| ReasonCode::EvidenceCaptureCapacityExhausted)
    }

    fn write(
        &self,
        config: &GatewayConfig,
        request_id: &RequestId,
        rule: &EvidenceCaptureRule,
        body: &[u8],
    ) -> Result<VerifiedEvidenceManifest, ReasonCode> {
        let document = rule.capture(body)?;
        let mut budget = self
            .budget
            .lock()
            .map_err(|_| ReasonCode::EvidenceCaptureUnavailable)?;
        let reservation = document.len() as u64 + WRITE_OVERHEAD;
        if reservation > budget.remaining_bytes || budget.remaining_files < 3 {
            return Err(ReasonCode::EvidenceCaptureCapacityExhausted);
        }
        // ponytail: conservatively charge failed writes and maximum sidecar size
        // until restart; external retention cleanup + restart reclaims capacity.
        // This bounds orphans too, without a per-request directory scan.
        budget.remaining_bytes -= reservation;
        budget.remaining_files -= 3;
        self.vault
            .write(&EvidenceWrite {
                tenant_id: config.tenant_id(),
                site_id: config.site_id(),
                request_id,
                kind: "response_decoded",
                content_type: "application/vnd.xshield.captured-json+json",
                fidelity: EvidenceFidelity::Redacted,
                classification: EvidenceClassification::Restricted,
                parent_refs: &[],
                expires_at: Utc::now()
                    + chrono::TimeDelta::seconds(i64::from(rule.retention_seconds())),
                plaintext: &document,
            })
            .map_err(|_| ReasonCode::EvidenceCaptureUnavailable)
    }

    /// Blocking Pingora response barrier. Only metadata reaches catalog/audit;
    /// a failed dependency leaves the business body withheld, with bounded orphans.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture(
        &self,
        config: &GatewayConfig,
        postgres: &PostgresRuntime,
        audit: &DurableAudit,
        request_id: &str,
        trace_id: &str,
        admission: &mut AdmissionAudit,
        rule: &EvidenceCaptureRule,
        body: &[u8],
    ) -> Result<(), ReasonCode> {
        let _permit = self.reserve()?;
        let request =
            RequestId::parse(request_id).map_err(|_| ReasonCode::EvidenceCaptureInvalid)?;
        let next_sequence = admission
            .next_request_sequence
            .checked_add(2)
            .ok_or(ReasonCode::EvidenceCaptureUnavailable)?;
        let forward_event = admission
            .forward_intent_event_id
            .as_ref()
            .ok_or(ReasonCode::EvidenceCaptureUnavailable)?
            .clone();
        tokio::task::block_in_place(|| {
            let manifest = self.write(config, &request, rule, body)?;
            let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7()))
                .map_err(|_| ReasonCode::EvidenceCaptureUnavailable)?;
            let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            // Each transaction is its own outbox producer. The journal uses its
            // independent durable producer sequence; request_seq joins the two.
            let envelope = json!({
                "schema_version":3, "event_id":event_id.as_str(), "event_type":"evidence.cataloged",
                "tenant_id":config.tenant_id().as_str(), "site_id":config.site_id().as_str(),
                "request_id":request_id, "trace_id":trace_id,
                "span_id":&Uuid::now_v7().simple().to_string()[..16],
                "producer_id":"gateway-evidence-catalog", "producer_boot_id":Uuid::now_v7().to_string(),
                "producer_seq":1, "request_seq":admission.next_request_sequence,
                "occurred_at":now, "observed_at":now, "policy_revision":config.policy_revision().as_str(),
                "example_only":false, "evidence_refs":[manifest.manifest().artifact_id],
                "cause_event_ids":[forward_event],
                "payload":{"stage":"evidence_catalog", "outcome":"PASS", "reason_code":"EVIDENCE_CATALOG_PUBLISHED", "artifact_id":manifest.manifest().artifact_id},
                "sensitivity":"RESTRICTED", "integrity":{"state":"pending", "previous_hash":null, "event_hash":null}
            });
            tokio::runtime::Handle::current().block_on(async {
                // Reserve the sequence before the transaction: a commit whose
                // acknowledgment is lost must not collide with finalization.
                admission.next_request_sequence += 1;
                let command = EvidenceCatalogPublish::new(&manifest, &event_id, &envelope)
                    .map_err(|_| ReasonCode::EvidenceCaptureUnavailable)?;
                tokio::time::timeout(postgres.acquire_timeout, async {
                    let store = postgres
                        .store()
                        .await
                        .map_err(|_| ReasonCode::EvidenceCaptureUnavailable)?;
                    match store
                        .publish_evidence_manifest(command)
                        .await
                        .map_err(|_| ReasonCode::EvidenceCaptureUnavailable)?
                    {
                        EvidenceCatalogWriteOutcome::Published
                        | EvidenceCatalogWriteOutcome::Existing => {}
                        EvidenceCatalogWriteOutcome::Conflict => {
                            return Err(ReasonCode::EvidenceCaptureUnavailable);
                        }
                    }
                    Ok(())
                })
                .await
                .map_err(|_| ReasonCode::EvidenceCaptureUnavailable)??;
                audit
                    .record_evidence_capture(
                        request_id,
                        trace_id,
                        admission,
                        &manifest.manifest().artifact_id,
                        event_id.as_str(),
                        rule.profile_revision(),
                    )
                    .await
                    .map_err(|_| ReasonCode::AuditDurabilityFailed)?;
                admission.next_request_sequence = next_sequence;
                Ok(())
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_capacity_is_exclusive_and_counts_orphans_across_restarts() {
        let root = env::temp_dir().join(format!("xshield-capture-budget-{}", Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = "22".repeat(32);
        let limit = MAX_DOCUMENT_BYTES as u64 + WRITE_OVERHEAD;
        fs::write(root.join("orphan.xev"), b"orphan").unwrap();
        let writer = EvidenceWriter::open(&root, "evidence-r1", &key, limit).unwrap();
        assert_eq!(writer.budget.lock().unwrap().remaining_bytes, limit - 6);
        assert!(EvidenceWriter::open(&root, "evidence-r1", &key, limit).is_err());
        let permit = writer.reserve().unwrap();
        assert!(matches!(
            writer.reserve(),
            Err(ReasonCode::EvidenceCaptureCapacityExhausted)
        ));
        drop(permit);
        assert!(writer.reserve().is_ok());
        let config = GatewayConfig::from_json(&serde_json::to_vec(&json!({
            "listen":"127.0.0.1:6188", "origin":{"address":"127.0.0.1:8080", "server_name":"origin.local", "tls":false},
            "tenant_id":"tenant_capture", "site_id":"site_capture", "policy_revision":"policy-r1",
            "audit":{"directory":root.join("journal"), "key_id":"journal-r1", "producer_id":"edge-test", "max_bytes":1_048_576, "high_watermark_bytes":786_432, "segment_max_bytes":262_144},
            "identity_store":{"max_connections":1, "acquire_timeout_ms":1000},
            "operations":[{"operation_id":"data", "method":"GET", "path":"/data", "admission":"PUBLIC",
                "response":{"mode":"BUFFERED_JSON", "max_bytes":1024, "evidence_capture":{"profile_revision":"capture-r1", "max_bytes":1024, "retention_seconds":3600, "secret_pointers":[]}}}]
        })).unwrap()).unwrap();
        let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
        let rule = config.evidence_capture_rule("GET", "/data").unwrap();
        writer.budget.lock().unwrap().remaining_bytes = WRITE_OVERHEAD;
        assert!(matches!(
            writer.write(&config, &request, rule, b"{}"),
            Err(ReasonCode::EvidenceCaptureCapacityExhausted)
        ));
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        drop(writer);
        let writer = EvidenceWriter::open(&root, "evidence-r1", &key, limit).unwrap();
        writer.write(&config, &request, rule, b"{}").unwrap();
        drop(writer);
        let actual_bytes = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum::<u64>();
        let writer = EvidenceWriter::open(&root, "evidence-r1", &key, limit).unwrap();
        assert_eq!(
            writer.budget.lock().unwrap().remaining_bytes,
            limit - actual_bytes
        );
        assert_eq!(writer.budget.lock().unwrap().remaining_files, MAX_FILES - 4);
        drop(writer);
        fs::remove_dir_all(root).unwrap();
    }
}
