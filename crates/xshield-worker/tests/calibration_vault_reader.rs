//! Real `PostgreSQL` and local-vault regression for calibration plaintext release.
//!
//! The test owns one temporary database scope and private local directories.
//! It proves that the reader's specific capability path cannot release bytes
//! until the dedicated journal barrier succeeds; it never contacts a model or
//! uses a console approval.

use chrono::{TimeDelta, Utc};
use serde_json::{Value, json};
use std::{env, fs, path::PathBuf, time::Duration};
use uuid::Uuid;
use xshield_audit::{JournalKey, JournalLimits, LocalJournal, sha256_digest};
use xshield_core::{
    calibration::{
        GroundTruth, Probability, Signal, Thresholds,
        dataset::{DatasetSample, EvaluationProvenance, ModelIdentity, evaluate_dataset},
        read_capability::{
            CalibrationEvidenceBatchCompletion, CalibrationEvidenceReadCapability,
            CalibrationSampleReadScope,
        },
    },
    domain::{
        ApprovalRef, ArtifactId, CalibrationReadCapabilityId, DatasetRevision, EventId,
        LabelRevision, MappingRevision, ModelCallId, ModelRevision, PromptRevision, ProviderId,
        RequestId, SiteId, TaskRevision, TenantId, ThresholdPolicyRevision,
    },
    identity::UnixSeconds,
    ports::{
        CalibrationEvidenceReadPort, CalibrationEvidenceReadRequest, CalibrationEvidenceReadState,
    },
};
use xshield_evidence::{
    EvidenceClassification, EvidenceFidelity, EvidenceKey, EvidenceVaultConfig, EvidenceWrite,
    LocalEvidenceVault, VerifiedEvidenceManifest,
};
use xshield_postgres::{
    CalibrationEvidenceBatchBegin, CalibrationEvidenceBatchBeginOutcome,
    CalibrationEvidenceBatchComplete, CalibrationEvidenceBatchCompleteOutcome,
    CalibrationReadCapabilityIssue, CalibrationReadCapabilityIssueOutcome, EvidenceCatalogPublish,
    EvidenceCatalogWriteOutcome, PostgresIdentityStore,
};
use xshield_worker::{CalibrationEvidenceReadError, LocalCalibrationEvidenceReader};

const EVIDENCE_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const JOURNAL_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[tokio::test]
#[ignore = "requires script-owned XSHIELD_TEST_DATABASE_URL with migrations through 0024"]
async fn calibration_reader_requires_durable_journal_before_plaintext_and_completion() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let fixture = Fixture::open(&database_url).await;

    complete_reader_path(&fixture).await;
    tampered_ciphertext_is_audited_without_plaintext(&fixture).await;
    full_journal_withholds_plaintext(&fixture).await;
}

async fn complete_reader_path(fixture: &Fixture) {
    let (complete_capability, complete_lease) = fixture.issue_and_begin("reader-complete").await;
    let complete_session = complete_capability
        .bind_issued_batch_lease(complete_lease, Fixture::now())
        .expect("leased capability binds");
    let reader = LocalCalibrationEvidenceReader::new(
        fixture.store.clone(),
        fixture.vault(),
        fixture.journal(1_048_576),
    );
    for reference in complete_capability.evidence_refs() {
        let content = read(&reader, &complete_session, &complete_capability, &reference).await;
        assert_eq!(content.as_bytes(), fixture.plaintext_for(&reference));
    }
    drop(reader);
    let completion = CalibrationEvidenceBatchCompletion::from_successful_evaluation(
        complete_session,
        fixture.completed_report(),
    )
    .expect("exact complete report binds the leased capability");
    assert!(matches!(
        fixture
            .store
            .complete_calibration_evidence_batch(
                CalibrationEvidenceBatchComplete::new(&completion, "reader-complete")
                    .expect("runner is valid"),
            )
            .await
            .expect("completion resolves"),
        CalibrationEvidenceBatchCompleteOutcome::Completed
    ));
    let reader = LocalCalibrationEvidenceReader::new(
        fixture.store.clone(),
        fixture.vault(),
        fixture.journal(1_048_576),
    );
    let target = model_record(&complete_capability);
    let denied_request = CalibrationEvidenceReadRequest::new(
        completion.session(),
        &complete_capability,
        &target,
        &fixture.tenant,
        &fixture.site,
        Fixture::now(),
    )
    .expect("completed session remains locally shaped");
    assert!(matches!(
        reader.read_calibration_evidence(denied_request).await,
        Ok(CalibrationEvidenceReadState::Denied(_))
    ));
    drop(reader);

    let events = fixture.journal_events();
    assert_eq!(events.len(), 7);
    for event in events.iter().take(6) {
        assert_release_event(event, complete_capability.capability_id().as_str());
    }
    assert_eq!(events[6]["payload"]["outcome"], "DENY");
}

async fn tampered_ciphertext_is_audited_without_plaintext(fixture: &Fixture) {
    let (readable_capability, readable_lease) = fixture.issue_and_begin("reader-success").await;
    let readable_session = readable_capability
        .bind_issued_batch_lease(readable_lease, Fixture::now())
        .expect("leased capability binds");
    let target = model_record(&readable_capability);
    let reader = LocalCalibrationEvidenceReader::new(
        fixture.store.clone(),
        fixture.vault(),
        fixture.journal(1_048_576),
    );
    let content = read(&reader, &readable_session, &readable_capability, &target).await;
    assert_eq!(content.as_bytes(), fixture.plaintext_for(&target));
    drop(content);
    drop(reader);

    // Tampering occurs after the catalog and vault sidecars were both accepted.
    // The next attempt must fail during the authenticated ciphertext read and
    // must not emit another PASS or give a caller a content object.
    fixture.corrupt_envelope(&target);
    let reader = LocalCalibrationEvidenceReader::new(
        fixture.store.clone(),
        fixture.vault(),
        fixture.journal(1_048_576),
    );
    let error = match read_result(&reader, &readable_session, &readable_capability, &target).await {
        Ok(CalibrationEvidenceReadState::Read(_)) => {
            panic!("tampered ciphertext must not release plaintext")
        }
        Ok(CalibrationEvidenceReadState::Denied(_)) => {
            panic!("tampered ciphertext must reach the vault integrity check")
        }
        Err(error) => error,
    };
    assert!(matches!(error, CalibrationEvidenceReadError::Vault(_)));
    drop(reader);
    let events = fixture.journal_events();
    assert_eq!(
        events.last().expect("integrity event")["payload"]["outcome"],
        "ERROR"
    );
    assert_eq!(
        events.last().expect("integrity event")["payload"]["reason_code"],
        "CALIBRATION_EVIDENCE_READ_INTEGRITY_FAILED"
    );
    assert!(
        events.last().expect("integrity event")["payload"]
            .get("bytes_released")
            .is_none()
    );
}

async fn full_journal_withholds_plaintext(fixture: &Fixture) {
    let (blocked_capability, blocked_lease) = fixture.issue_and_begin("reader-audit-full").await;
    let blocked_session = blocked_capability
        .bind_issued_batch_lease(blocked_lease, Fixture::now())
        .expect("leased capability binds");
    let journal = Fixture::journal_at(&fixture.root.join("audit-full"), 128, 64, 128);
    let reader =
        LocalCalibrationEvidenceReader::new(fixture.store.clone(), fixture.vault(), journal);
    let error = match read_result(
        &reader,
        &blocked_session,
        &blocked_capability,
        &model_record(&blocked_capability),
    )
    .await
    {
        Ok(CalibrationEvidenceReadState::Read(_)) => {
            panic!("a full journal must block plaintext")
        }
        Ok(CalibrationEvidenceReadState::Denied(_)) => {
            panic!("a valid fixture must reach the audit barrier")
        }
        Err(error) => error,
    };
    assert!(matches!(error, CalibrationEvidenceReadError::Audit(_)));
}

struct Fixture {
    store: PostgresIdentityStore,
    tenant: TenantId,
    site: SiteId,
    request: RequestId,
    root: PathBuf,
    evidence_root: PathBuf,
    journal_root: PathBuf,
    artifacts: Vec<ArtifactId>,
    plaintexts: Vec<Vec<u8>>,
}

impl Fixture {
    async fn open(database_url: &str) -> Self {
        let root = private_directory("xshield-calibration-reader");
        let evidence_root = root.join("evidence");
        fs::create_dir(&evidence_root).expect("private evidence directory is created");
        set_private(&evidence_root);
        let fixture = Self {
            store: PostgresIdentityStore::connect(database_url, 4, Duration::from_secs(5))
                .await
                .expect("test store connects"),
            tenant: TenantId::parse(format!("tenant_reader_{}", Uuid::now_v7().simple()))
                .expect("tenant is bounded"),
            site: SiteId::parse("site_reader").expect("site is bounded"),
            request: RequestId::parse(format!("req_{}", Uuid::now_v7()))
                .expect("request id is valid"),
            journal_root: root.join("journal"),
            root,
            evidence_root,
            artifacts: Vec::new(),
            plaintexts: Vec::new(),
        };
        fixture.write_catalog().await
    }

    async fn write_catalog(mut self) -> Self {
        let vault = self.vault();
        for index in 0..6_u8 {
            let plaintext = format!("calibration-reader-{index}").into_bytes();
            let manifest = vault
                .write(&EvidenceWrite {
                    tenant_id: &self.tenant,
                    site_id: &self.site,
                    request_id: &self.request,
                    kind: "calibration_evidence",
                    content_type: "application/octet-stream",
                    fidelity: EvidenceFidelity::EntityExact,
                    classification: EvidenceClassification::Restricted,
                    parent_refs: &[],
                    expires_at: Utc::now() + TimeDelta::minutes(5),
                    plaintext: &plaintext,
                })
                .expect("vault write succeeds");
            let event = event_id();
            assert_eq!(
                self.store
                    .publish_evidence_manifest(
                        EvidenceCatalogPublish::new(
                            &manifest,
                            &event,
                            &catalog_envelope(&manifest, &event)
                        )
                        .expect("catalog command is coherent"),
                    )
                    .await
                    .expect("catalog transaction succeeds"),
                EvidenceCatalogWriteOutcome::Published
            );
            self.artifacts.push(
                ArtifactId::parse(&manifest.manifest().artifact_id)
                    .expect("vault artifact id is valid"),
            );
            self.plaintexts.push(plaintext);
        }
        self
    }

    fn vault(&self) -> LocalEvidenceVault {
        LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&self.evidence_root, "reader-evidence-r1", 1024, 1)
                .expect("vault configuration is valid"),
            EvidenceKey::from_hex(EVIDENCE_KEY).expect("evidence key is valid"),
        )
        .expect("vault opens")
    }

    fn journal(&self, max_bytes: u64) -> LocalJournal {
        self.journal_with_limits(max_bytes, max_bytes / 2, 1)
    }

    fn journal_with_limits(&self, max: u64, high_watermark: u64, segment_max: u64) -> LocalJournal {
        Self::journal_at(&self.journal_root, max, high_watermark, segment_max)
    }

    fn journal_at(
        directory: &PathBuf,
        max: u64,
        high_watermark: u64,
        segment_max: u64,
    ) -> LocalJournal {
        LocalJournal::open(
            directory,
            "reader-journal-r1",
            JournalKey::from_hex(JOURNAL_KEY).expect("journal key is valid"),
            JournalLimits::new(max, high_watermark, segment_max).expect("journal limits are valid"),
        )
        .expect("journal opens")
        .0
    }

    fn now() -> UnixSeconds {
        UnixSeconds::new(u64::try_from(Utc::now().timestamp()).expect("current time is positive"))
    }

    fn capability(&self) -> CalibrationEvidenceReadCapability {
        let now = Self::now().value();
        CalibrationEvidenceReadCapability::new(
            CalibrationReadCapabilityId::parse(format!("calcap_{}", Uuid::now_v7()))
                .expect("capability id is valid"),
            self.tenant.clone(),
            self.site.clone(),
            self.provenance(),
            vec![CalibrationSampleReadScope::new(
                self.artifacts[4].clone(),
                self.artifacts[5].clone(),
            )],
            UnixSeconds::new(now - 1),
            UnixSeconds::new(now + 120),
            1024,
        )
        .expect("capability is valid")
    }

    fn provenance(&self) -> EvaluationProvenance {
        EvaluationProvenance::new(
            ApprovalRef::parse("approval-r1").expect("approval is valid"),
            DatasetRevision::parse("dataset-r1").expect("dataset is valid"),
            LabelRevision::parse("labels-r1").expect("labels are valid"),
            TaskRevision::parse("task-r1").expect("task is valid"),
            ThresholdPolicyRevision::parse("threshold-r1").expect("threshold is valid"),
            MappingRevision::parse("risk-map-r1").expect("mapping is valid"),
            self.artifacts[0].clone(),
            self.artifacts[1].clone(),
            self.artifacts[2].clone(),
            self.artifacts[3].clone(),
            ModelIdentity::new(
                ProviderId::parse("vercel_ai_gateway").expect("provider is valid"),
                "typesafe-ai/jev",
                ModelRevision::parse("jev-1.13.0").expect("model revision is valid"),
                PromptRevision::parse("prompt-r1").expect("prompt revision is valid"),
                None,
            )
            .expect("model identity is valid"),
        )
        .expect("provenance is valid")
    }

    async fn issue_and_begin(
        &self,
        runner: &str,
    ) -> (
        CalibrationEvidenceReadCapability,
        xshield_core::calibration::read_capability::CalibrationEvidenceBatchLease,
    ) {
        let capability = self.capability();
        let event = event_id();
        // These values model an issuer's two independent retry identities. Reusing a
        // key for a later, distinct capability is deliberately rejected by the
        // durable uniqueness constraint, so each fixture batch derives fresh keys.
        let issuance_idempotency_digest =
            sha256_digest(capability.capability_id().as_str().as_bytes());
        let request_digest = sha256_digest(event.as_str().as_bytes());
        assert!(matches!(
            self.store
                .issue_calibration_read_capability(
                    CalibrationReadCapabilityIssue::new(
                        &capability,
                        "reader-fixture",
                        &issuance_idempotency_digest,
                        &request_digest,
                        &event,
                    )
                    .expect("issuance command is valid"),
                )
                .await
                .expect("issuance resolves"),
            CalibrationReadCapabilityIssueOutcome::Issued(_)
        ));
        let lease = match self
            .store
            .begin_calibration_evidence_batch(
                CalibrationEvidenceBatchBegin::new(&capability, runner, Duration::from_mins(1))
                    .expect("begin command is valid"),
            )
            .await
            .expect("batch begin resolves")
        {
            CalibrationEvidenceBatchBeginOutcome::Started(lease) => lease,
            other => panic!("unexpected lease outcome: {}", other.reason_code()),
        };
        (capability, lease)
    }

    fn plaintext_for(
        &self,
        reference: &xshield_core::calibration::read_capability::CalibrationEvidenceRef,
    ) -> &[u8] {
        let index = self
            .artifacts
            .iter()
            .position(|artifact| artifact == reference.artifact_id())
            .expect("reference belongs to fixture");
        &self.plaintexts[index]
    }

    fn corrupt_envelope(
        &self,
        reference: &xshield_core::calibration::read_capability::CalibrationEvidenceRef,
    ) {
        let path = self
            .evidence_root
            .join(format!("{}.xev", reference.artifact_id().as_str()));
        let mut bytes = fs::read(&path).expect("ciphertext is readable for fault injection");
        bytes[0] ^= 1;
        fs::write(path, bytes).expect("fault injection writes ciphertext");
    }

    fn completed_report(&self) -> xshield_core::calibration::dataset::EvaluationReport {
        let provenance = self.provenance();
        let sample = DatasetSample::new(
            ModelCallId::parse(format!("mdl_{}", Uuid::now_v7())).expect("model call is valid"),
            self.artifacts[4].clone(),
            self.artifacts[5].clone(),
            provenance.model().clone(),
            provenance.mapping_revision().clone(),
            GroundTruth::Benign,
            Signal::Risk(Probability::new(0.1).expect("probability is valid")),
        )
        .expect("sample is valid");
        evaluate_dataset(
            provenance,
            &[sample],
            Thresholds::new(
                Probability::new(0.2).expect("probability is valid"),
                Probability::new(0.8).expect("probability is valid"),
            )
            .expect("thresholds are valid"),
        )
        .expect("dataset report is valid")
    }

    fn journal_events(&self) -> Vec<Value> {
        let journal = self.journal(1_048_576);
        let mut events = Vec::new();
        journal
            .visit_closed_records(64, |record| {
                events.push(
                    serde_json::from_slice(record.plaintext())
                        .map_err(|_| xshield_audit::JournalError::InvalidEvent)?,
                );
                Ok(())
            })
            .expect("closed journal records authenticate");
        events
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn model_record(
    capability: &CalibrationEvidenceReadCapability,
) -> xshield_core::calibration::read_capability::CalibrationEvidenceRef {
    capability
        .evidence_refs()
        .into_iter()
        .find(|reference| reference.role().as_str() == "model_call_record")
        .expect("model record is present")
}

async fn read(
    reader: &LocalCalibrationEvidenceReader,
    session: &xshield_core::calibration::read_capability::CalibrationEvidenceReadSession<'_>,
    capability: &CalibrationEvidenceReadCapability,
    reference: &xshield_core::calibration::read_capability::CalibrationEvidenceRef,
) -> xshield_worker::CalibrationEvidenceContent {
    match read_result(reader, session, capability, reference)
        .await
        .expect("authorized evidence read succeeds")
    {
        CalibrationEvidenceReadState::Read(content) => content,
        CalibrationEvidenceReadState::Denied(_) => panic!("authorized fixture read was denied"),
    }
}

async fn read_result(
    reader: &LocalCalibrationEvidenceReader,
    session: &xshield_core::calibration::read_capability::CalibrationEvidenceReadSession<'_>,
    capability: &CalibrationEvidenceReadCapability,
    reference: &xshield_core::calibration::read_capability::CalibrationEvidenceRef,
) -> Result<
    CalibrationEvidenceReadState<xshield_worker::CalibrationEvidenceContent>,
    CalibrationEvidenceReadError,
> {
    let request = CalibrationEvidenceReadRequest::new(
        session,
        capability,
        reference,
        capability.tenant_id(),
        capability.site_id(),
        UnixSeconds::new(u64::try_from(Utc::now().timestamp()).expect("current time is positive")),
    )
    .expect("exact request is valid");
    reader.read_calibration_evidence(request).await
}

fn assert_release_event(event: &Value, capability_id: &str) {
    assert_eq!(event["event_type"], "calibration.evidence_read");
    assert_eq!(event["payload"]["outcome"], "PASS");
    assert_eq!(event["payload"]["capability_id"], capability_id);
    assert!(event["payload"]["bytes_released"].as_u64().is_some());
    for field in [
        "artifact_id",
        "role",
        "sample_index",
        "lease_id",
        "lease_token",
        "content",
    ] {
        assert!(
            event["payload"].get(field).is_none(),
            "payload exposes {field}"
        );
    }
}

fn private_directory(prefix: &str) -> PathBuf {
    let root = env::temp_dir().join(format!("{prefix}-{}", Uuid::now_v7()));
    fs::create_dir(&root).expect("private root is created");
    set_private(&root);
    root
}

fn set_private(path: &PathBuf) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("private permissions are applied");
    }
}

fn event_id() -> EventId {
    EventId::parse(format!("ev_{}", Uuid::now_v7())).expect("event id is valid")
}

fn catalog_envelope(verified: &VerifiedEvidenceManifest, event: &EventId) -> Value {
    let manifest = verified.manifest();
    json!({
        "schema_version": 3,
        "event_id": event.as_str(),
        "event_type": "evidence.cataloged",
        "tenant_id": manifest.tenant_id,
        "site_id": manifest.site_id,
        "request_id": manifest.request_id,
        "trace_id": "018f2a3b4c5d70008000000000000902",
        "span_id": "018f2a3b4c5d7000",
        "producer_id": "calibration-reader-test",
        "producer_boot_id": "boot-test",
        "producer_seq": 1,
        "request_seq": 1,
        "occurred_at": "2026-09-21T00:00:00.000Z",
        "observed_at": "2026-09-21T00:00:00.000Z",
        "policy_revision": "calibration-v1",
        "example_only": false,
        "evidence_refs": [manifest.artifact_id],
        "cause_event_ids": [],
        "payload": {
            "stage": "evidence_catalog",
            "outcome": "PASS",
            "reason_code": "EVIDENCE_CATALOG_PUBLISHED",
            "artifact_id": manifest.artifact_id
        },
        "sensitivity": "RESTRICTED",
        "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
    })
}
