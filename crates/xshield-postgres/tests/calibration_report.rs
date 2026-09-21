//! `PostgreSQL` regressions for atomic calibration-report publication.
//!
//! These regressions deliberately use the encrypted vault before the database
//! commit. They verify that a report object stranded by a rejected transaction
//! cannot consume the purpose-limited batch lease; a privileged reconciliation
//! workflow owns any later treatment of that unreachable object.

use chrono::{TimeDelta, Utc};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, fs, path::PathBuf, time::Duration};
use tokio::time::sleep;
use uuid::Uuid;
use xshield_core::{
    calibration::{
        GroundTruth, Probability, Signal, Thresholds,
        dataset::{
            DatasetSample, EvaluationProvenance, EvaluationReport, ModelIdentity, evaluate_dataset,
        },
        lineage_review::{
            CalibrationLineageReviewArtifact, LineageSourceDeclaration, LineageSourceKind,
            LineageSourceRef, PartitionLineageSubmission, PartitionManifestDeclaration,
            PartitionRole, review_partition_lineage,
        },
        publication::{CalibrationReportArtifact, CalibrationReportPublication},
        read_capability::{
            CalibrationEvidenceBatchCompletion, CalibrationEvidenceReadCapability,
            CalibrationSampleReadScope,
        },
    },
    domain::{
        ApprovalRef, ArtifactId, CalibrationLineageReviewId, CalibrationReadCapabilityId,
        CalibrationReportId, DatasetRevision, EventId, LabelRevision, MappingRevision, ModelCallId,
        ModelRevision, PromptRevision, ProviderId, RequestId, SiteId, TaskRevision, TenantId,
        ThresholdPolicyRevision,
    },
    identity::UnixSeconds,
};
use xshield_evidence::{
    CalibrationLineageReviewEvidenceWrite, CalibrationReportEvidenceWrite, EvidenceKey,
    EvidenceVaultConfig, LocalEvidenceVault,
};
use xshield_postgres::{
    CalibrationEvidenceBatchBegin, CalibrationEvidenceBatchBeginOutcome,
    CalibrationLineageReviewCommit, CalibrationLineageReviewCommitOutcome,
    CalibrationReadCapabilityIssue, CalibrationReadCapabilityIssueOutcome, CalibrationReportCommit,
    CalibrationReportCommitOutcome, PostgresIdentityStore,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL with migrations through 0033"]
async fn calibration_report_commit_is_atomic_exact_and_closed_on_invalid_state() {
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
        EvidenceVaultConfig::new(&vault_root, "report-evidence-key-r1", 1024 * 1024, 1)
            .expect("vault configuration is valid"),
        EvidenceKey::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
            .expect("test key is valid"),
    )
    .expect("vault opens");
    let lineage_vault_root = private_temp_directory();
    let lineage_vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(
            &lineage_vault_root,
            "lineage-race-evidence-key-r1",
            1024 * 1024,
            1,
        )
        .expect("lineage vault configuration is valid"),
        EvidenceKey::from_hex("2222222222222222222222222222222222222222222222222222222222222222")
            .expect("lineage test key is valid"),
    )
    .expect("lineage vault opens");
    seed_catalog(&pool, &fixture).await;
    seed_committed_lineage_review(
        &pool,
        &fixture,
        &fixture.lineage_review_id,
        &fixture.lineage_review_artifact_id,
    )
    .await;

    assert_cross_family_artifact_conflict_keeps_lease_active(&pool, &store, &fixture, &vault).await;
    assert_concurrent_lineage_review_wins_report_artifact_identity(
        &database_url,
        &pool,
        &store,
        &fixture,
        &vault,
        &lineage_vault,
    )
    .await;
    assert_successful_commit_is_atomic_and_exact(&pool, &store, &fixture, &vault).await;
    assert_wrong_runner_catalog_drift_and_expiry_are_closed(&pool, &store, &fixture, &vault).await;

    cleanup(&pool, &fixture);
    fs::remove_dir_all(vault_root).expect("private vault root is removable");
    fs::remove_dir_all(lineage_vault_root).expect("private lineage vault root is removable");
}

struct Fixture {
    tenant: TenantId,
    site: SiteId,
    lineage_review_id: CalibrationLineageReviewId,
    lineage_review_artifact_id: ArtifactId,
    artifacts: Vec<ArtifactId>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            tenant: TenantId::parse(format!("tenant_calreport_{}", Uuid::now_v7().simple()))
                .expect("tenant is bounded"),
            site: SiteId::parse("site_calreport").expect("site is bounded"),
            lineage_review_id: CalibrationLineageReviewId::parse(format!(
                "calrev_{}",
                Uuid::now_v7()
            ))
            .expect("lineage review id is valid"),
            lineage_review_artifact_id: artifact_id(),
            artifacts: (0..6).map(|_| artifact_id()).collect(),
        }
    }

    fn capability(&self, expires_after: i64) -> CalibrationEvidenceReadCapability {
        let now = Utc::now().timestamp();
        CalibrationEvidenceReadCapability::new(
            CalibrationReadCapabilityId::parse(format!("calcap_{}", Uuid::now_v7()))
                .expect("capability id is valid"),
            self.lineage_review_id.clone(),
            self.tenant.clone(),
            self.site.clone(),
            self.provenance(),
            vec![CalibrationSampleReadScope::new(
                self.artifacts[4].clone(),
                self.artifacts[5].clone(),
            )],
            UnixSeconds::new(u64::try_from(now - 10).expect("time is positive")),
            UnixSeconds::new(u64::try_from(now + expires_after).expect("time is positive")),
            1_024,
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
                ModelRevision::parse("jev-1.13.0").expect("model is valid"),
                PromptRevision::parse("prompt-r1").expect("prompt is valid"),
                None,
            )
            .expect("model identity is valid"),
        )
        .expect("provenance is valid")
    }
}

async fn assert_cross_family_artifact_conflict_keeps_lease_active(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    vault: &LocalEvidenceVault,
) {
    let capability = fixture.capability(120);
    issue(store, &capability).await;
    let lease = begin(store, &capability, "runner-artifact-first").await;
    let session = capability
        .bind_issued_batch_lease(lease, now())
        .expect("issued lease binds capability");
    let evaluation = completed_report(fixture);
    let (publication, report) =
        report_artifact_with_id(&evaluation, fixture.lineage_review_artifact_id.clone());
    let manifest = write_report(vault, fixture, &report);
    let completion =
        CalibrationEvidenceBatchCompletion::from_successful_evaluation(session, evaluation)
            .expect("completion matches capability");
    let completion_event_id = event_id();
    let report_event_id = event_id();
    let command = CalibrationReportCommit::new(
        &completion,
        &report,
        &publication,
        &manifest,
        "runner-artifact-first",
        &completion_event_id,
        &report_event_id,
    )
    .expect("commit command is valid");
    let outcome = store
        .complete_and_publish_calibration_report(command)
        .await
        .expect("collision resolves");
    assert!(
        matches!(outcome, CalibrationReportCommitOutcome::Conflict),
        "expected report artifact collision, got {}",
        outcome.reason_code()
    );
    assert_state(pool, &capability, "leased", "active").await;
    let state: (i64, i64, String) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM xshield.calibration_report_artifacts
              WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3),
             (SELECT count(*) FROM xshield.calibration_reports
              WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$4),
             (SELECT family FROM xshield.artifact_identity_registry WHERE artifact_id=$3)",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.lineage_review_artifact_id.as_str())
    .bind(capability.capability_id().as_str())
    .fetch_one(pool)
    .await
    .expect("cross-family conflict state is queryable");
    assert_eq!(state, (0, 0, "calibration_lineage_review".to_owned()));
}

/// Holds the report capability header before the report can claim its artifact
/// identity. This makes the lineage-review commit win the shared registry ID
/// without depending on scheduler timing, then proves the unblocked report
/// returns the closed conflict instead of leaking a database uniqueness error.
#[allow(clippy::too_many_lines)]
async fn assert_concurrent_lineage_review_wins_report_artifact_identity(
    database_url: &str,
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    report_vault: &LocalEvidenceVault,
    lineage_vault: &LocalEvidenceVault,
) {
    let capability = fixture.capability(120);
    issue(store, &capability).await;
    let lease = begin(store, &capability, "runner-registry-race").await;
    let session = capability
        .bind_issued_batch_lease(lease, now())
        .expect("issued lease binds capability");
    let evaluation = completed_report(fixture);
    let shared_artifact_id = artifact_id();
    let (publication, report) = report_artifact_with_id(&evaluation, shared_artifact_id.clone());
    let report_manifest = write_report(report_vault, fixture, &report);
    let completion =
        CalibrationEvidenceBatchCompletion::from_successful_evaluation(session, evaluation)
            .expect("completion matches capability");
    let completion_event_id = event_id();
    let report_event_id = event_id();
    let report_command = CalibrationReportCommit::new(
        &completion,
        &report,
        &publication,
        &report_manifest,
        "runner-registry-race",
        &completion_event_id,
        &report_event_id,
    )
    .expect("report race command is valid");

    let lineage_review = lineage_review(fixture, shared_artifact_id);
    let lineage_manifest = write_and_attest_lineage_review(lineage_vault, fixture, &lineage_review);
    let lineage_event_id = event_id();
    let lineage_command =
        CalibrationLineageReviewCommit::new(&lineage_review, &lineage_manifest, &lineage_event_id)
            .expect("lineage race command is valid");

    let report_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("report race actor pool connects");
    let report_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&report_pool)
        .await
        .expect("report race actor pid is queryable");
    let report_store = PostgresIdentityStore::from_pool(report_pool.clone());

    let mut blocker = pool
        .begin()
        .await
        .expect("capability lock transaction starts");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .expect("capability lock pid is queryable");
    sqlx::query(
        "SELECT 1 FROM xshield.calibration_read_capabilities
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 FOR UPDATE",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .execute(&mut *blocker)
    .await
    .expect("capability header is locked before report race");

    let (report_outcome, lineage_outcome) = tokio::join!(
        report_store.complete_and_publish_calibration_report(report_command),
        async {
            wait_for_database_block(pool, report_pid, blocker_pid).await;
            let outcome = store
                .commit_calibration_lineage_review(lineage_command)
                .await;
            blocker
                .commit()
                .await
                .expect("capability header lock releases after lineage commit");
            outcome
        },
    );
    report_pool.close().await;

    assert!(
        matches!(
            lineage_outcome.expect("lineage race transaction resolves"),
            CalibrationLineageReviewCommitOutcome::Committed(_)
        ),
        "lineage review must win the deliberate registry ordering"
    );
    assert!(
        matches!(
            report_outcome.expect("report race transaction resolves"),
            CalibrationReportCommitOutcome::Conflict
        ),
        "report must map the committed lineage registry owner to Conflict"
    );
    assert_state(pool, &capability, "leased", "active").await;

    let state: (i64, i64, i64, i64, i64, i64, String) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM xshield.calibration_report_artifacts
              WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3),
             (SELECT count(*) FROM xshield.calibration_reports
              WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$4),
             (SELECT count(*) FROM xshield.calibration_lineage_review_artifacts
              WHERE tenant_id=$1 AND site_id=$2 AND review_id=$5 AND artifact_id=$3),
             (SELECT count(*) FROM xshield.calibration_lineage_reviews
              WHERE tenant_id=$1 AND site_id=$2 AND review_id=$5),
             (SELECT count(*) FROM xshield.audit_outbox WHERE event_id=ANY($6)),
             (SELECT count(*) FROM xshield.audit_outbox WHERE event_id=$7),
             (SELECT family FROM xshield.artifact_identity_registry WHERE artifact_id=$3)",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(publication.report_artifact_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(lineage_review.review_id().as_str())
    .bind(vec![completion_event_id.as_str(), report_event_id.as_str()])
    .bind(lineage_event_id.as_str())
    .fetch_one(pool)
    .await
    .expect("registry race terminal state is queryable");
    assert_eq!(
        state,
        (0, 0, 1, 1, 0, 1, "calibration_lineage_review".to_owned())
    );
}

#[allow(clippy::too_many_lines)]
async fn assert_successful_commit_is_atomic_and_exact(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    vault: &LocalEvidenceVault,
) {
    let capability = fixture.capability(120);
    issue(store, &capability).await;
    let lease = begin(store, &capability, "runner-success").await;
    let session = capability
        .bind_issued_batch_lease(lease, now())
        .expect("issued lease binds capability");
    let evaluation = completed_report(fixture);
    let (publication, report) = report_artifact(&evaluation);
    let manifest = write_report(vault, fixture, &report);
    let completion =
        CalibrationEvidenceBatchCompletion::from_successful_evaluation(session, evaluation)
            .expect("completion matches capability");
    let completion_event_id = event_id();
    let report_event_id = event_id();
    let command = CalibrationReportCommit::new(
        &completion,
        &report,
        &publication,
        &manifest,
        "runner-success",
        &completion_event_id,
        &report_event_id,
    )
    .expect("commit command is valid");
    let record = match store
        .complete_and_publish_calibration_report(command)
        .await
        .expect("report commit resolves")
    {
        CalibrationReportCommitOutcome::Committed(record) => record,
        outcome => panic!("expected committed report, got {}", outcome.reason_code()),
    };
    assert_state(pool, &capability, "consumed", "completed").await;
    let persisted: (i64, i64, i64, String, String) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM xshield.calibration_reports
              WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3),
             (SELECT count(*) FROM xshield.calibration_report_artifacts
              WHERE tenant_id=$1 AND site_id=$2 AND report_id=$4),
             (SELECT count(*) FROM xshield.audit_outbox
              WHERE event_id = ANY($5)),
             (SELECT completion_event_id FROM xshield.calibration_read_capabilities
              WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3),
             (SELECT reported_event_id FROM xshield.calibration_reports
              WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3)",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(capability.capability_id().as_str())
    .bind(publication.report_id().as_str())
    .bind(vec![completion_event_id.as_str(), report_event_id.as_str()])
    .fetch_one(pool)
    .await
    .expect("atomic rows are queryable");
    assert_eq!(persisted.0, 1);
    assert_eq!(persisted.1, 1);
    assert_eq!(persisted.2, 2);
    assert_eq!(persisted.3, completion_event_id.as_str());
    assert_eq!(persisted.4, report_event_id.as_str());
    assert_eq!(record.report_id(), publication.report_id());
    let persisted_lineage_review_id: String = sqlx::query_scalar(
        "SELECT lineage_review_id FROM xshield.calibration_reports
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(capability.capability_id().as_str())
    .fetch_one(pool)
    .await
    .expect("report persists its authorization review identity");
    assert_eq!(
        persisted_lineage_review_id,
        fixture.lineage_review_id.as_str()
    );

    let retry = CalibrationReportCommit::new(
        &completion,
        &report,
        &publication,
        &manifest,
        "runner-success",
        &completion_event_id,
        &report_event_id,
    )
    .expect("exact retry command is valid");
    assert!(matches!(
        store
            .complete_and_publish_calibration_report(retry)
            .await
            .expect("exact retry resolves"),
        CalibrationReportCommitOutcome::Existing(existing) if existing == record
    ));

    let conflicting_report_event_id = event_id();
    let conflicting_retry = CalibrationReportCommit::new(
        &completion,
        &report,
        &publication,
        &manifest,
        "runner-success",
        &completion_event_id,
        &conflicting_report_event_id,
    )
    .expect("conflicting retry command is shaped");
    assert!(matches!(
        store
            .complete_and_publish_calibration_report(conflicting_retry)
            .await
            .expect("conflicting retry resolves"),
        CalibrationReportCommitOutcome::Conflict
    ));

    let other_review_id = CalibrationLineageReviewId::parse(format!("calrev_{}", Uuid::now_v7()))
        .expect("alternate lineage review id is valid");
    let attempted_rebind = sqlx::query(
        "UPDATE xshield.calibration_reports SET lineage_review_id=$4
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(capability.capability_id().as_str())
    .bind(other_review_id.as_str())
    .execute(pool)
    .await
    .expect_err("committed report lineage review must not be rebound");
    assert_eq!(
        attempted_rebind
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("23514"))
    );
    let post_rebind_retry = CalibrationReportCommit::new(
        &completion,
        &report,
        &publication,
        &manifest,
        "runner-success",
        &completion_event_id,
        &report_event_id,
    )
    .expect("post-rebind retry is shaped");
    assert!(matches!(
        store
            .complete_and_publish_calibration_report(post_rebind_retry)
            .await
            .expect("post-rebind retry resolves"),
        CalibrationReportCommitOutcome::Existing(existing) if existing == record
    ));
}

#[allow(clippy::too_many_lines)]
async fn assert_wrong_runner_catalog_drift_and_expiry_are_closed(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    vault: &LocalEvidenceVault,
) {
    let wrong_runner_capability = fixture.capability(120);
    issue(store, &wrong_runner_capability).await;
    let lease = begin(store, &wrong_runner_capability, "runner-bound").await;
    let session = wrong_runner_capability
        .bind_issued_batch_lease(lease, now())
        .expect("issued lease binds capability");
    let evaluation = completed_report(fixture);
    let (publication, report) = report_artifact(&evaluation);
    let manifest = write_report(vault, fixture, &report);
    let completion =
        CalibrationEvidenceBatchCompletion::from_successful_evaluation(session, evaluation)
            .expect("completion matches capability");
    let wrong_runner_completion_event_id = event_id();
    let wrong_runner_report_event_id = event_id();
    let command = CalibrationReportCommit::new(
        &completion,
        &report,
        &publication,
        &manifest,
        "runner-other",
        &wrong_runner_completion_event_id,
        &wrong_runner_report_event_id,
    )
    .expect("command permits an independently configured runner identity");
    assert!(matches!(
        store
            .complete_and_publish_calibration_report(command)
            .await
            .expect("wrong runner resolves"),
        CalibrationReportCommitOutcome::Unavailable
    ));
    assert_state(pool, &wrong_runner_capability, "leased", "active").await;

    let drift_capability = fixture.capability(120);
    issue(store, &drift_capability).await;
    let lease = begin(store, &drift_capability, "runner-drift").await;
    let session = drift_capability
        .bind_issued_batch_lease(lease, now())
        .expect("issued lease binds capability");
    let evaluation = completed_report(fixture);
    let (publication, report) = report_artifact(&evaluation);
    let manifest = write_report(vault, fixture, &report);
    let completion =
        CalibrationEvidenceBatchCompletion::from_successful_evaluation(session, evaluation)
            .expect("completion matches capability");
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET integrity_digest=$4
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.artifacts[4].as_str())
    .bind("b".repeat(64))
    .execute(pool)
    .await
    .expect("fixture catalog drift applies");
    let drift_completion_event_id = event_id();
    let drift_report_event_id = event_id();
    let command = CalibrationReportCommit::new(
        &completion,
        &report,
        &publication,
        &manifest,
        "runner-drift",
        &drift_completion_event_id,
        &drift_report_event_id,
    )
    .expect("drift command is shaped");
    assert!(matches!(
        store
            .complete_and_publish_calibration_report(command)
            .await
            .expect("catalog drift resolves"),
        CalibrationReportCommitOutcome::Unavailable
    ));
    assert_state(pool, &drift_capability, "leased", "active").await;
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET integrity_digest=$4
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.artifacts[4].as_str())
    .bind("a".repeat(64))
    .execute(pool)
    .await
    .expect("fixture catalog drift restores");

    let expired_capability = fixture.capability(3);
    issue(store, &expired_capability).await;
    let lease = begin(store, &expired_capability, "runner-expired").await;
    let session = expired_capability
        .bind_issued_batch_lease(lease, now())
        .expect("issued lease binds capability");
    let evaluation = completed_report(fixture);
    let (publication, report) = report_artifact(&evaluation);
    let manifest = write_report(vault, fixture, &report);
    let completion =
        CalibrationEvidenceBatchCompletion::from_successful_evaluation(session, evaluation)
            .expect("completion matches capability");
    sleep(Duration::from_millis(3_100)).await;
    let expired_completion_event_id = event_id();
    let expired_report_event_id = event_id();
    let command = CalibrationReportCommit::new(
        &completion,
        &report,
        &publication,
        &manifest,
        "runner-expired",
        &expired_completion_event_id,
        &expired_report_event_id,
    )
    .expect("expired command is shaped");
    assert!(matches!(
        store
            .complete_and_publish_calibration_report(command)
            .await
            .expect("expired capability resolves"),
        CalibrationReportCommitOutcome::Unavailable
    ));
    assert_state(pool, &expired_capability, "leased", "active").await;
}

fn report_artifact(
    evaluation: &EvaluationReport,
) -> (CalibrationReportPublication, CalibrationReportArtifact) {
    report_artifact_with_id(evaluation, artifact_id())
}

fn report_artifact_with_id(
    evaluation: &EvaluationReport,
    report_artifact_id: ArtifactId,
) -> (CalibrationReportPublication, CalibrationReportArtifact) {
    let publication = CalibrationReportPublication::new(
        CalibrationReportId::parse(format!("calr_{}", Uuid::now_v7())).expect("report id is valid"),
        report_artifact_id,
        evaluation,
    )
    .expect("report artifact does not alias source evidence");
    let report = CalibrationReportArtifact::from_evaluation(&publication, evaluation)
        .expect("report artifact encodes the completed evaluation");
    (publication, report)
}

fn lineage_review(
    fixture: &Fixture,
    review_artifact_id: ArtifactId,
) -> CalibrationLineageReviewArtifact {
    let training = lineage_source_ref("report-race-training-root");
    let calibration = lineage_source_ref("report-race-calibration-root");
    let evaluation = lineage_source_ref("report-race-evaluation-root");
    let labels = lineage_source_ref("report-race-label-root");
    let submission = PartitionLineageSubmission::new(
        vec![
            lineage_declaration(
                PartitionRole::Training,
                fixture.artifacts[1].clone(),
                training.clone(),
            ),
            lineage_declaration(
                PartitionRole::Calibration,
                fixture.artifacts[2].clone(),
                calibration.clone(),
            ),
            lineage_declaration(
                PartitionRole::Evaluation,
                fixture.artifacts[0].clone(),
                evaluation.clone(),
            ),
            lineage_declaration(
                PartitionRole::Label,
                fixture.artifacts[3].clone(),
                labels.clone(),
            ),
        ],
        vec![
            lineage_source(training, PartitionRole::Training, LineageSourceKind::Corpus),
            lineage_source(
                calibration,
                PartitionRole::Calibration,
                LineageSourceKind::Corpus,
            ),
            lineage_source(
                evaluation,
                PartitionRole::Evaluation,
                LineageSourceKind::Corpus,
            ),
            lineage_source(
                labels,
                PartitionRole::Label,
                LineageSourceKind::ReviewedLabel,
            ),
        ],
    )
    .expect("race lineage submission is valid");
    let review = review_partition_lineage(
        CalibrationLineageReviewId::parse(format!("calrev_{}", Uuid::now_v7()))
            .expect("race lineage review id is valid"),
        review_artifact_id,
        fixture.provenance(),
        &submission,
    )
    .expect("race lineage review is valid");
    CalibrationLineageReviewArtifact::from_review(&review)
        .expect("race lineage artifact is canonical")
}

fn lineage_source_ref(value: &str) -> LineageSourceRef {
    LineageSourceRef::new(value, "revision-r1").expect("race lineage source reference is valid")
}

fn lineage_declaration(
    role: PartitionRole,
    artifact_id: ArtifactId,
    root: LineageSourceRef,
) -> PartitionManifestDeclaration {
    PartitionManifestDeclaration::new(role, artifact_id, vec![root])
        .expect("race lineage partition declaration is valid")
}

fn lineage_source(
    reference: LineageSourceRef,
    partition: PartitionRole,
    kind: LineageSourceKind,
) -> LineageSourceDeclaration {
    LineageSourceDeclaration::new(reference, partition, kind, Vec::new())
        .expect("race lineage source declaration is valid")
}

fn write_report(
    vault: &LocalEvidenceVault,
    fixture: &Fixture,
    report: &CalibrationReportArtifact,
) -> xshield_evidence::AttestedCalibrationReportManifest {
    vault
        .write_calibration_report(&CalibrationReportEvidenceWrite {
            tenant_id: &fixture.tenant,
            site_id: &fixture.site,
            report,
            expires_at: Utc::now() + TimeDelta::minutes(5),
        })
        .expect("report artifact persists before database commit");
    vault
        .attest_calibration_report(&fixture.tenant, &fixture.site, report)
        .expect("report is freshly authenticated before database commit")
}

fn write_and_attest_lineage_review(
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
        .expect("lineage review persists before race commit");
    vault
        .attest_calibration_lineage_review(&fixture.tenant, &fixture.site, review)
        .expect("lineage review is freshly authenticated before race commit")
}

async fn issue(store: &PostgresIdentityStore, capability: &CalibrationEvidenceReadCapability) {
    let digest = openssl::sha::sha256(capability.capability_id().as_str().as_bytes());
    let issued = store
        .issue_calibration_read_capability(
            CalibrationReadCapabilityIssue::new(
                capability,
                "calibration-report-fixture",
                &digest,
                &digest,
                &event_id(),
            )
            .expect("issue command is valid"),
        )
        .await
        .expect("issue resolves");
    assert!(matches!(
        issued,
        CalibrationReadCapabilityIssueOutcome::Issued(_)
    ));
}

async fn begin(
    store: &PostgresIdentityStore,
    capability: &CalibrationEvidenceReadCapability,
    runner_id: &str,
) -> xshield_core::calibration::read_capability::CalibrationEvidenceBatchLease {
    match store
        .begin_calibration_evidence_batch(
            CalibrationEvidenceBatchBegin::new(capability, runner_id, Duration::from_secs(30))
                .expect("begin command is valid"),
        )
        .await
        .expect("begin resolves")
    {
        CalibrationEvidenceBatchBeginOutcome::Started(lease) => lease,
        outcome => panic!("expected active lease, got {}", outcome.reason_code()),
    }
}

async fn assert_state(
    pool: &PgPool,
    capability: &CalibrationEvidenceReadCapability,
    expected_capability: &str,
    expected_lease: &str,
) {
    let state: (String, String) = sqlx::query_as(
        "SELECT capability.status, lease.status
         FROM xshield.calibration_read_capabilities capability
         JOIN xshield.calibration_read_capability_leases lease
           ON lease.tenant_id=capability.tenant_id AND lease.site_id=capability.site_id
          AND lease.capability_id=capability.capability_id
         WHERE capability.tenant_id=$1 AND capability.site_id=$2 AND capability.capability_id=$3
         ORDER BY lease.lease_generation DESC LIMIT 1",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .fetch_one(pool)
    .await
    .expect("capability state is queryable");
    assert_eq!(
        state,
        (expected_capability.to_owned(), expected_lease.to_owned())
    );
}

async fn wait_for_database_block(pool: &PgPool, waiter: i32, blocker: i32) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let queued: bool = sqlx::query_scalar("SELECT $2=ANY(pg_blocking_pids($1))")
                .bind(waiter)
                .bind(blocker)
                .fetch_one(pool)
                .await
                .expect("database lock graph is queryable");
            if queued {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("report transaction reached the locked capability header");
}

fn completed_report(fixture: &Fixture) -> EvaluationReport {
    let provenance = fixture.provenance();
    let sample = DatasetSample::new(
        ModelCallId::parse(format!("mdl_{}", Uuid::now_v7())).expect("model call is valid"),
        fixture.artifacts[4].clone(),
        fixture.artifacts[5].clone(),
        provenance.model().clone(),
        provenance.mapping_revision().clone(),
        GroundTruth::Benign,
        Signal::Risk(Probability::new(0.1).expect("probability is valid")),
    )
    .expect("dataset sample is valid");
    evaluate_dataset(
        provenance,
        &[sample],
        Thresholds::new(
            Probability::new(0.2).expect("probability is valid"),
            Probability::new(0.8).expect("probability is valid"),
        )
        .expect("thresholds are valid"),
    )
    .expect("evaluation succeeds")
}

async fn seed_catalog(pool: &PgPool, fixture: &Fixture) {
    for (index, artifact) in fixture.artifacts.iter().enumerate() {
        sqlx::query(
            "INSERT INTO xshield.artifact_catalog (
                 tenant_id, site_id, artifact_id, request_id, schema_version, kind, content_type,
                 capture_status, fidelity, bytes_observed, bytes_saved, classification,
                 example_only, storage_profile, storage_locator, key_ref, integrity_algorithm,
                 integrity_digest, parent_refs, recorded_at, expires_at, catalog_event_id, status,
                 deleted_at
             ) VALUES (
                 $1,$2,$3,$4,3,$5,'application/json','complete',
                 'semantic',64,64,'RESTRICTED',false,'aead_envelope_v1',$6,
                 'key-r1','sha256_ciphertext',$7,'{}',clock_timestamp(),
                 clock_timestamp() + interval '10 minutes',$8,'active',NULL
             )",
        )
        .bind(fixture.tenant.as_str())
        .bind(fixture.site.as_str())
        .bind(artifact.as_str())
        .bind(request_id().as_str())
        .bind(calibration_catalog_kind(index))
        .bind(format!("{}.xev", artifact.as_str()))
        .bind("a".repeat(64))
        .bind(event_id().as_str())
        .execute(pool)
        .await
        .expect("catalog fixture inserts");
    }
}

/// Seeds only the immutable review projection already produced by the dedicated
/// vault-attested review path. This report fixture exercises capability/report
/// state transitions, while `calibration_lineage_review` owns the vault-first
/// review commit regression.
async fn seed_committed_lineage_review(
    pool: &PgPool,
    fixture: &Fixture,
    review_id: &CalibrationLineageReviewId,
    review_artifact_id: &ArtifactId,
) {
    let provenance = fixture.provenance();
    let event = event_id();
    let mut transaction = pool.begin().await.expect("review seed transaction starts");
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
             (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1,$2,$3,$4,'calibration.partition_lineage.reviewed','{}')",
    )
    .bind(event.as_str())
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(review_id.as_str())
    .execute(&mut *transaction)
    .await
    .expect("review event seed inserts");
    sqlx::query(
        "INSERT INTO xshield.calibration_lineage_review_artifacts (
             tenant_id, site_id, review_id, artifact_id, schema_version, kind,
             content_type, canonical_body_encoding, capture_status, fidelity,
             bytes_observed, bytes_saved, classification, storage_profile,
             storage_locator, key_ref, integrity_algorithm, integrity_digest,
             recorded_at, reviewed_at, expires_at
         ) VALUES (
             $1,$2,$3,$4,1,'calibration_partition_lineage_review',
             'application/vnd.xshield.calibration-lineage-review+json',
             'xshield_calibration_lineage_review_canonical_json_v1','complete','entity_exact',
             1,1,'RESTRICTED','aead_envelope_v1',$5,'key-r1','sha256_ciphertext',$6,
             date_trunc('milliseconds', now()),date_trunc('milliseconds', now()),
             date_trunc('milliseconds', now() + interval '10 minutes')
         )",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(review_id.as_str())
    .bind(review_artifact_id.as_str())
    .bind(format!("{}.xev", review_artifact_id.as_str()))
    .bind("a".repeat(64))
    .execute(&mut *transaction)
    .await
    .expect("attested review artifact projection inserts");
    sqlx::query(
        "INSERT INTO xshield.calibration_lineage_reviews (
             tenant_id, site_id, review_id, review_artifact_id, schema_version, policy_revision,
             approval_ref, dataset_revision, label_revision, task_revision,
             threshold_policy_revision, mapping_revision, evaluation_manifest_artifact_id,
             training_manifest_artifact_id, calibration_manifest_artifact_id,
             label_manifest_artifact_id, provider, provider_model_id, model_revision,
             prompt_revision, resolved_model_revision, source_graph_digest, reviewed_event_id,
             reviewed_at
         ) VALUES (
             $1,$2,$3,$4,1,'calibration-lineage-v1',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
             $15,$16,$17,$18,$19,decode(repeat('a',64),'hex'),$20,date_trunc('milliseconds', now())
         )",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(review_id.as_str())
    .bind(review_artifact_id.as_str())
    .bind(provenance.approval_ref().as_str())
    .bind(provenance.dataset_revision().as_str())
    .bind(provenance.label_revision().as_str())
    .bind(provenance.task_revision().as_str())
    .bind(provenance.threshold_policy_revision().as_str())
    .bind(provenance.mapping_revision().as_str())
    .bind(provenance.evaluation_manifest_artifact_id().as_str())
    .bind(provenance.training_manifest_artifact_id().as_str())
    .bind(provenance.calibration_manifest_artifact_id().as_str())
    .bind(provenance.label_manifest_artifact_id().as_str())
    .bind(provenance.model().provider().as_str())
    .bind(provenance.model().provider_model_id())
    .bind(provenance.model().model_revision().as_str())
    .bind(provenance.model().prompt_revision().as_str())
    .bind(
        provenance
            .model()
            .resolved_model_revision()
            .map(ModelRevision::as_str),
    )
    .bind(event.as_str())
    .execute(&mut *transaction)
    .await
    .expect("committed lineage review projection inserts");
    transaction.commit().await.expect("review seed commits");
}

fn calibration_catalog_kind(index: usize) -> &'static str {
    match index {
        0 => "evaluation_manifest",
        1 => "training_manifest",
        2 => "calibration_manifest",
        3 => "label_manifest",
        4 => "model_call",
        5 => "reviewed_label",
        _ => "unrelated_calibration_evidence",
    }
}

fn cleanup(_pool: &PgPool, _fixture: &Fixture) {
    // Migration 0030 freezes committed review projections. Every integration
    // fixture uses a unique tenant and the harness drops its temporary database,
    // so deleting retained audit state here would test an invalid lifecycle.
}

fn now() -> UnixSeconds {
    UnixSeconds::new(u64::try_from(Utc::now().timestamp()).expect("time is positive"))
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
        std::env::temp_dir().join(format!("xshield-report-postgres-test-{}", Uuid::now_v7()));
    fs::create_dir(&root).expect("private directory creates");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private permissions apply");
    }
    root
}
