//! `PostgreSQL` regressions for atomic calibration partition-lineage review.
//!
//! The encrypted review body is deliberately written and freshly attested
//! before each database command. These tests exercise the durable boundary,
//! not corpus independence or a plaintext evidence-read path.

use chrono::{TimeDelta, Utc};
use sqlx::PgPool;
use std::{env, fs, path::PathBuf, time::Duration};
use uuid::Uuid;
use xshield_core::{
    calibration::{
        dataset::{EvaluationProvenance, ModelIdentity},
        lineage_review::{
            CalibrationLineageReviewArtifact, LineageSourceDeclaration, LineageSourceKind,
            LineageSourceRef, PartitionLineageSubmission, PartitionManifestDeclaration,
            PartitionRole, review_partition_lineage,
        },
    },
    domain::{
        ApprovalRef, ArtifactId, CalibrationLineageReviewId, DatasetRevision, EventId,
        LabelRevision, MappingRevision, ModelRevision, PromptRevision, ProviderId, RequestId,
        SiteId, TaskRevision, TenantId, ThresholdPolicyRevision,
    },
};
use xshield_evidence::{
    CalibrationLineageReviewEvidenceWrite, EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault,
};
use xshield_postgres::{
    CalibrationLineageReviewCommit, CalibrationLineageReviewCommitOutcome, PostgresIdentityStore,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL with migrations through 0029"]
async fn lineage_review_commit_is_atomic_exact_and_closed() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 4, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let fixture = Fixture::new();
    let vault_root = private_temp_directory();
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&vault_root, "lineage-evidence-key-r1", 1024 * 1024, 1)
            .expect("vault configuration is valid"),
        EvidenceKey::from_hex("2222222222222222222222222222222222222222222222222222222222222222")
            .expect("test key is valid"),
    )
    .expect("vault opens");
    seed_manifest_catalog(&pool, &fixture).await;

    assert_commit_and_retention_safe_exact_retry(&pool, &store, &fixture, &vault).await;
    assert_catalog_drift_is_unavailable(&pool, &store, &fixture, &vault).await;
    assert_cross_family_artifact_collision_is_closed(&pool, &store, &fixture, &vault).await;

    fs::remove_dir_all(vault_root).expect("private vault root is removable");
}

struct Fixture {
    tenant: TenantId,
    site: SiteId,
    manifests: [ArtifactId; 4],
}

impl Fixture {
    fn new() -> Self {
        Self {
            tenant: TenantId::parse(format!("tenant_callineage_{}", Uuid::now_v7().simple()))
                .expect("tenant is bounded"),
            site: SiteId::parse("site_callineage").expect("site is bounded"),
            manifests: [artifact_id(), artifact_id(), artifact_id(), artifact_id()],
        }
    }

    fn provenance(&self) -> EvaluationProvenance {
        EvaluationProvenance::new(
            ApprovalRef::parse("approval-r1").expect("approval is valid"),
            DatasetRevision::parse("dataset-r1").expect("dataset is valid"),
            LabelRevision::parse("labels-r1").expect("labels are valid"),
            TaskRevision::parse("task-r1").expect("task is valid"),
            ThresholdPolicyRevision::parse("threshold-r1").expect("threshold is valid"),
            MappingRevision::parse("mapping-r1").expect("mapping is valid"),
            self.manifests[0].clone(),
            self.manifests[1].clone(),
            self.manifests[2].clone(),
            self.manifests[3].clone(),
            ModelIdentity::new(
                ProviderId::parse("vercel_ai_gateway").expect("provider is valid"),
                "typesafe-ai/jev",
                ModelRevision::parse("jev-1.13.0").expect("model is valid"),
                PromptRevision::parse("prompt-r1").expect("prompt is valid"),
                None,
            )
            .expect("model identity is valid"),
        )
        .expect("provenance is valid")
    }
}

async fn assert_commit_and_retention_safe_exact_retry(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    vault: &LocalEvidenceVault,
) {
    let review = review(fixture, artifact_id());
    let manifest = write_and_attest(vault, fixture, &review);
    let reviewed_event_id = event_id();
    let command = CalibrationLineageReviewCommit::new(&review, &manifest, &reviewed_event_id)
        .expect("commit command is valid");
    let record = match store
        .commit_calibration_lineage_review(command)
        .await
        .expect("review commit resolves")
    {
        CalibrationLineageReviewCommitOutcome::Committed(record) => record,
        outcome => panic!("expected committed review, got {}", outcome.reason_code()),
    };
    assert_eq!(record.review_id(), review.review_id());
    assert_eq!(record.review_artifact_id(), review.review_artifact_id());

    let persisted: (i64, i64, i64, serde_json::Value) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM xshield.calibration_lineage_review_artifacts
              WHERE tenant_id=$1 AND site_id=$2 AND review_id=$3),
             (SELECT count(*) FROM xshield.calibration_lineage_reviews
              WHERE tenant_id=$1 AND site_id=$2 AND review_id=$3),
             (SELECT count(*) FROM xshield.audit_outbox WHERE event_id=$4),
             (SELECT envelope FROM xshield.audit_outbox WHERE event_id=$4)",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(review.review_id().as_str())
    .bind(reviewed_event_id.as_str())
    .fetch_one(pool)
    .await
    .expect("atomic rows are queryable");
    assert_eq!((persisted.0, persisted.1, persisted.2), (1, 1, 1));
    let payload = &persisted.3["payload"];
    assert_eq!(
        persisted.3["event_type"],
        "calibration.partition_lineage.reviewed"
    );
    assert_eq!(payload["review_id"], review.review_id().as_str());
    assert!(payload.get("source_graph").is_none());
    assert!(payload.get("source_graph_digest").is_none());
    assert!(!persisted.3.to_string().contains("training-root"));

    // Exact recovery is historical: normal catalog retention after a durable
    // review must not change the already committed immutable result.
    sqlx::query(
        "UPDATE xshield.artifact_catalog
         SET status='deleted', deleted_at=clock_timestamp()
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.manifests[0].as_str())
    .execute(pool)
    .await
    .expect("fixture retention state applies");
    let retry = CalibrationLineageReviewCommit::new(&review, &manifest, &reviewed_event_id)
        .expect("exact retry command is valid");
    assert!(matches!(
        store
            .commit_calibration_lineage_review(retry)
            .await
            .expect("retained exact retry resolves"),
        CalibrationLineageReviewCommitOutcome::Existing(existing) if existing == record
    ));

    let conflicting_event = event_id();
    let conflict = CalibrationLineageReviewCommit::new(&review, &manifest, &conflicting_event)
        .expect("conflicting retry command is shaped");
    assert!(matches!(
        store
            .commit_calibration_lineage_review(conflict)
            .await
            .expect("conflicting retry resolves"),
        CalibrationLineageReviewCommitOutcome::Conflict
    ));
}

async fn assert_catalog_drift_is_unavailable(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    vault: &LocalEvidenceVault,
) {
    // Restore the fixture to create a new review, then make one frozen catalog
    // manifest semantically ineligible. The adapter must not register or
    // persist any new review identity on this failure path.
    sqlx::query(
        "UPDATE xshield.artifact_catalog
         SET status='active', deleted_at=NULL, fidelity='redacted'
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.manifests[0].as_str())
    .execute(pool)
    .await
    .expect("fixture catalog drift applies");
    let review = review(fixture, artifact_id());
    let manifest = write_and_attest(vault, fixture, &review);
    let event_id = event_id();
    let command = CalibrationLineageReviewCommit::new(&review, &manifest, &event_id)
        .expect("drift command is valid");
    assert!(matches!(
        store
            .commit_calibration_lineage_review(command)
            .await
            .expect("catalog drift resolves"),
        CalibrationLineageReviewCommitOutcome::Unavailable
    ));
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM xshield.calibration_lineage_review_artifacts WHERE review_id=$1),
             (SELECT count(*) FROM xshield.calibration_lineage_reviews WHERE review_id=$1),
             (SELECT count(*) FROM xshield.audit_outbox WHERE event_id=$2)",
    )
    .bind(review.review_id().as_str())
    .bind(event_id.as_str())
    .fetch_one(pool)
    .await
    .expect("unavailable state is queryable");
    assert_eq!(counts, (0, 0, 0));
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET fidelity='semantic'
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.manifests[0].as_str())
    .execute(pool)
    .await
    .expect("fixture catalog restores");
}

async fn assert_cross_family_artifact_collision_is_closed(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    vault: &LocalEvidenceVault,
) {
    let review = review(fixture, artifact_id());
    let manifest = write_and_attest(vault, fixture, &review);
    seed_catalog_collision(pool, fixture, review.review_artifact_id()).await;
    let event_id = event_id();
    let command = CalibrationLineageReviewCommit::new(&review, &manifest, &event_id)
        .expect("collision command is valid");
    assert!(matches!(
        store
            .commit_calibration_lineage_review(command)
            .await
            .expect("cross-family identity collision is closed"),
        CalibrationLineageReviewCommitOutcome::Conflict
    ));
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM xshield.calibration_lineage_review_artifacts WHERE review_id=$1),
             (SELECT count(*) FROM xshield.calibration_lineage_reviews WHERE review_id=$1),
             (SELECT count(*) FROM xshield.audit_outbox WHERE event_id=$2)",
    )
    .bind(review.review_id().as_str())
    .bind(event_id.as_str())
    .fetch_one(pool)
    .await
    .expect("conflict state is queryable");
    assert_eq!(counts, (0, 0, 0));
}

fn review(fixture: &Fixture, review_artifact_id: ArtifactId) -> CalibrationLineageReviewArtifact {
    let training = source_ref("training-root");
    let calibration = source_ref("calibration-root");
    let evaluation = source_ref("evaluation-root");
    let labels = source_ref("labels-root");
    let submission = PartitionLineageSubmission::new(
        vec![
            declaration(
                PartitionRole::Training,
                fixture.manifests[1].clone(),
                training.clone(),
            ),
            declaration(
                PartitionRole::Calibration,
                fixture.manifests[2].clone(),
                calibration.clone(),
            ),
            declaration(
                PartitionRole::Evaluation,
                fixture.manifests[0].clone(),
                evaluation.clone(),
            ),
            declaration(
                PartitionRole::Label,
                fixture.manifests[3].clone(),
                labels.clone(),
            ),
        ],
        vec![
            source(training, PartitionRole::Training, LineageSourceKind::Corpus),
            source(
                calibration,
                PartitionRole::Calibration,
                LineageSourceKind::Corpus,
            ),
            source(
                evaluation,
                PartitionRole::Evaluation,
                LineageSourceKind::Corpus,
            ),
            source(
                labels,
                PartitionRole::Label,
                LineageSourceKind::ReviewedLabel,
            ),
        ],
    )
    .expect("submission is valid");
    let review = review_partition_lineage(
        CalibrationLineageReviewId::parse(format!("calrev_{}", Uuid::now_v7()))
            .expect("review id is valid"),
        review_artifact_id,
        fixture.provenance(),
        &submission,
    )
    .expect("review is valid");
    CalibrationLineageReviewArtifact::from_review(&review).expect("artifact is canonical")
}

fn source_ref(value: &str) -> LineageSourceRef {
    LineageSourceRef::new(value, "revision-r1").expect("source reference is valid")
}

fn declaration(
    role: PartitionRole,
    artifact_id: ArtifactId,
    root: LineageSourceRef,
) -> PartitionManifestDeclaration {
    PartitionManifestDeclaration::new(role, artifact_id, vec![root])
        .expect("partition declaration is valid")
}

fn source(
    reference: LineageSourceRef,
    partition: PartitionRole,
    kind: LineageSourceKind,
) -> LineageSourceDeclaration {
    LineageSourceDeclaration::new(reference, partition, kind, Vec::new())
        .expect("source declaration is valid")
}

fn write_and_attest(
    vault: &LocalEvidenceVault,
    fixture: &Fixture,
    review: &CalibrationLineageReviewArtifact,
) -> xshield_evidence::AttestedCalibrationLineageReviewManifest {
    vault
        .write_calibration_lineage_review(&CalibrationLineageReviewEvidenceWrite {
            tenant_id: &fixture.tenant,
            site_id: &fixture.site,
            review,
            expires_at: Utc::now() + TimeDelta::minutes(5),
        })
        .expect("review artifact persists before database commit");
    vault
        .attest_calibration_lineage_review(&fixture.tenant, &fixture.site, review)
        .expect("review is freshly authenticated before database commit")
}

async fn seed_manifest_catalog(pool: &PgPool, fixture: &Fixture) {
    for (index, artifact) in fixture.manifests.iter().enumerate() {
        insert_catalog(
            pool,
            fixture,
            artifact,
            match index {
                0 => "evaluation_manifest",
                1 => "training_manifest",
                2 => "calibration_manifest",
                3 => "label_manifest",
                _ => unreachable!("fixture has four manifests"),
            },
        )
        .await;
    }
}

async fn seed_catalog_collision(pool: &PgPool, fixture: &Fixture, artifact: &ArtifactId) {
    insert_catalog(pool, fixture, artifact, "unrelated_fixture_artifact").await;
}

async fn insert_catalog(pool: &PgPool, fixture: &Fixture, artifact: &ArtifactId, kind: &str) {
    sqlx::query(
        "INSERT INTO xshield.artifact_catalog (
             tenant_id, site_id, artifact_id, request_id, schema_version, kind, content_type,
             capture_status, fidelity, bytes_observed, bytes_saved, classification,
             example_only, storage_profile, storage_locator, key_ref, integrity_algorithm,
             integrity_digest, parent_refs, recorded_at, expires_at, catalog_event_id, status,
             deleted_at
         ) VALUES (
             $1,$2,$3,$4,3,$5,'application/json','complete','semantic',64,64,'RESTRICTED',
             false,'aead_envelope_v1',$6,'key-r1','sha256_ciphertext',$7,'{}',clock_timestamp(),
             clock_timestamp() + interval '10 minutes',$8,'active',NULL
         )",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(artifact.as_str())
    .bind(request_id().as_str())
    .bind(kind)
    .bind(format!("{}.xev", artifact.as_str()))
    .bind("a".repeat(64))
    .bind(event_id().as_str())
    .execute(pool)
    .await
    .expect("catalog fixture inserts");
}

fn artifact_id() -> ArtifactId {
    ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).expect("artifact id is valid")
}

fn event_id() -> EventId {
    EventId::parse(format!("ev_{}", Uuid::now_v7())).expect("event id is valid")
}

fn request_id() -> RequestId {
    RequestId::parse(format!("req_{}", Uuid::now_v7())).expect("request id is valid")
}

fn private_temp_directory() -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("xshield-lineage-postgres-test-{}", Uuid::now_v7()));
    fs::create_dir(&root).expect("private directory creates");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private permissions apply");
    }
    root
}
