//! `PostgreSQL` regressions for frozen calibration batch capability issuance.
//!
//! These tests use a caller-provisioned migrated `PostgreSQL` database. They
//! verify persistence behavior only: no vault object is opened and no model is
//! called.

use chrono::Utc;
use serde_json::Value;
use sqlx::PgPool;
use std::{env, time::Duration};
use tokio::time::sleep;
use uuid::Uuid;
use xshield_core::{
    calibration::{
        GroundTruth, Probability, Signal, Thresholds,
        dataset::{
            DatasetSample, EvaluationProvenance, EvaluationReport, ModelIdentity, evaluate_dataset,
        },
        read_capability::{
            CalibrationEvidenceBatchCompletion, CalibrationEvidenceReadCapability,
            CalibrationSampleReadScope,
        },
    },
    domain::{
        ApprovalRef, ArtifactId, CalibrationLineageReviewId, CalibrationReadCapabilityId,
        DatasetRevision, EventId, LabelRevision, MappingRevision, ModelCallId, ModelRevision,
        PromptRevision, ProviderId, RequestId, SiteId, TaskRevision, TenantId,
        ThresholdPolicyRevision,
    },
    identity::UnixSeconds,
    ports::{CalibrationEvidenceReadDenied, CalibrationEvidenceReadRequest},
};
use xshield_postgres::{
    CalibrationEvidenceBatchBegin, CalibrationEvidenceBatchBeginOutcome,
    CalibrationEvidenceBatchComplete, CalibrationEvidenceBatchCompleteOutcome,
    CalibrationEvidenceReadAuthorizationOutcome, CalibrationEvidenceReleaseCommitOutcome,
    CalibrationEvidenceReleaseReservationOutcome, CalibrationReadCapabilityIssue,
    CalibrationReadCapabilityIssueOutcome, PostgresIdentityStore,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL with migrations through 0032"]
async fn calibration_read_capability_is_atomic_exact_and_recovery_safe() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 4, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let fixture = Fixture::new();
    seed_catalog(&pool, &fixture).await;
    seed_committed_lineage_review(&pool, &fixture).await;
    assert_unreserved_catalog_delete_is_not_suppressed(&pool, &fixture).await;
    assert_role_metadata_is_required_on_issue(&pool, &store, &fixture).await;

    assert_exact_issuance_and_drift_rejection(&pool, &store, &fixture).await;
    assert_single_lease_and_recovery(&pool, &store, &fixture).await;

    cleanup(&pool, &fixture);
}

async fn assert_unreserved_catalog_delete_is_not_suppressed(pool: &PgPool, fixture: &Fixture) {
    // The final fixture artifact is deliberately absent from every frozen
    // capability. A catalog DELETE is allowed when it has no live release
    // reservation; a BEFORE DELETE trigger must return OLD, not NEW, or
    // PostgreSQL silently reports zero affected rows.
    let deleted = sqlx::query(
        "DELETE FROM xshield.artifact_catalog
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.artifacts[7].as_str())
    .execute(pool)
    .await
    .expect("an unreserved catalog object is deletable")
    .rows_affected();
    assert_eq!(
        deleted, 1,
        "an unreserved catalog delete is never suppressed"
    );
}

async fn assert_role_metadata_is_required_on_issue(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    // Every role is backed by a purpose-specific catalog kind and the shared
    // restricted JSON shape. A syntactically valid but mismatched source must
    // be rejected before a capability header or issuance event is persisted.
    for (field, value) in [
        ("kind", "calibration_evidence"),
        ("content_type", "text/plain"),
        ("fidelity", "entity_exact"),
        ("classification", "INTERNAL"),
    ] {
        update_catalog_metadata(
            pool,
            fixture,
            4,
            if field == "kind" { value } else { "model_call" },
            if field == "content_type" {
                value
            } else {
                "application/json"
            },
            if field == "fidelity" {
                value
            } else {
                "semantic"
            },
            if field == "classification" {
                value
            } else {
                "RESTRICTED"
            },
        )
        .await;
        let capability = fixture.capability(1_024);
        assert!(matches!(
            issue_capability(store, &capability, &event_id(), 1, 2).await,
            CalibrationReadCapabilityIssueOutcome::SourceUnavailable
        ));
        let persisted: (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM xshield.calibration_read_capabilities
                  WHERE tenant_id=$1 AND site_id=$2),
                 (SELECT count(*) FROM xshield.audit_outbox
                  WHERE tenant_id=$1 AND site_id=$2
                    AND event_type='calibration.read_capability.issued')",
        )
        .bind(fixture.tenant.as_str())
        .bind(fixture.site.as_str())
        .fetch_one(pool)
        .await
        .expect("failed issuance leaves no durable capability or event");
        assert_eq!(persisted, (0, 0));
        update_catalog_metadata(
            pool,
            fixture,
            4,
            "model_call",
            "application/json",
            "semantic",
            "RESTRICTED",
        )
        .await;
    }
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
            tenant: TenantId::parse(format!("tenant_calcap_{}", Uuid::now_v7().simple()))
                .expect("tenant is bounded"),
            site: SiteId::parse("site_calcap").expect("site is bounded"),
            lineage_review_id: CalibrationLineageReviewId::parse(format!(
                "calrev_{}",
                Uuid::now_v7()
            ))
            .expect("lineage review id is valid"),
            lineage_review_artifact_id: artifact_id(),
            artifacts: (0..8).map(|_| artifact_id()).collect(),
        }
    }

    fn capability(&self, max_total_bytes: u64) -> CalibrationEvidenceReadCapability {
        let now = Utc::now().timestamp();
        let not_before = u64::try_from(now - 10).expect("current time is positive");
        let expires_at = u64::try_from(now + 120).expect("current time is positive");
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
            UnixSeconds::new(not_before),
            UnixSeconds::new(expires_at),
            max_total_bytes,
        )
        .expect("fixture capability is valid")
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

async fn assert_exact_issuance_and_drift_rejection(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    let capability = fixture.capability(1_024);
    let event = event_id();
    let issued = issue_capability(store, &capability, &event, 1, 2).await;
    let CalibrationReadCapabilityIssueOutcome::Issued(record) = issued else {
        panic!("first exact capability must be issued");
    };
    assert_eq!(record.member_count(), 6);
    assert_eq!(record.frozen_total_bytes(), 384);
    assert_issued_envelope(pool, fixture, &capability, &record).await;
    assert_issued_capability_review_is_immutable(pool, fixture, &capability).await;
    assert_exact_retries(store, &capability, &event, &record).await;
    assert_concurrent_conflicting_issuers_return_conflict(store, fixture).await;
    assert_exact_read_authorization_rechecks_lease_and_catalog(pool, store, fixture).await;
    assert_altered_capability_is_unavailable(store, fixture, &capability).await;
    assert_catalog_drift_is_unavailable(pool, store, fixture, &capability).await;
}

async fn assert_issued_capability_review_is_immutable(
    pool: &PgPool,
    fixture: &Fixture,
    capability: &CalibrationEvidenceReadCapability,
) {
    let other_review_id = CalibrationLineageReviewId::parse(format!("calrev_{}", Uuid::now_v7()))
        .expect("alternate lineage review id is valid");
    let attempted_rebind = sqlx::query(
        "UPDATE xshield.calibration_read_capabilities SET lineage_review_id=$4
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(capability.capability_id().as_str())
    .bind(other_review_id.as_str())
    .execute(pool)
    .await
    .expect_err("issued capability lineage review must not be rebound");
    assert_eq!(
        attempted_rebind
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("23514"))
    );
}

async fn assert_issued_envelope(
    pool: &PgPool,
    fixture: &Fixture,
    capability: &CalibrationEvidenceReadCapability,
    record: &xshield_postgres::CalibrationReadCapabilityRecord,
) {
    let stored: (String, Vec<u8>, i32, i64, Value) = sqlx::query_as(
        "SELECT outbox.aggregate_ref, capability.scope_digest, capability.member_count,
                capability.frozen_total_bytes, outbox.envelope
         FROM xshield.calibration_read_capabilities capability
         JOIN xshield.audit_outbox outbox ON outbox.event_id = capability.issued_event_id
         WHERE capability.tenant_id=$1 AND capability.site_id=$2 AND capability.capability_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(capability.capability_id().as_str())
    .fetch_one(pool)
    .await
    .expect("header and outbox are atomic");
    assert_eq!(stored.0, capability.capability_id().as_str());
    assert_eq!(stored.1.as_slice(), record.scope_digest());
    assert_eq!(stored.2, 6);
    assert_eq!(stored.3, 384);
    assert_eq!(stored.4["event_type"], "calibration.read_capability.issued");
    assert!(
        stored.4["evidence_refs"]
            .as_array()
            .expect("envelope evidence refs are an array")
            .is_empty()
    );
    assert_eq!(
        stored.4["payload"]["capability_id"],
        capability.capability_id().as_str()
    );
    assert_eq!(
        stored.4["payload"]["scope_digest"]
            .as_str()
            .expect("digest is string")
            .len(),
        64
    );
}

async fn assert_exact_retries(
    store: &PostgresIdentityStore,
    capability: &CalibrationEvidenceReadCapability,
    event: &EventId,
    record: &xshield_postgres::CalibrationReadCapabilityRecord,
) {
    assert!(matches!(
        issue_capability(store, capability, event, 1, 2).await,
        CalibrationReadCapabilityIssueOutcome::Existing(existing) if existing == *record
    ));
    assert!(matches!(
        issue_capability(store, capability, event, 1, 3).await,
        CalibrationReadCapabilityIssueOutcome::Conflict
    ));
}

async fn assert_concurrent_conflicting_issuers_return_conflict(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    let capability = fixture.capability(1_024);
    let first_store = store.clone();
    let second_store = store.clone();
    let first_event = event_id();
    let second_event = event_id();
    let (first, second) = tokio::join!(
        issue_capability_as(
            &first_store,
            &capability,
            &first_event,
            "calibration-fixture-one",
            3,
            4,
        ),
        issue_capability_as(
            &second_store,
            &capability,
            &second_event,
            "calibration-fixture-two",
            5,
            6,
        )
    );
    assert!(
        matches!(first, CalibrationReadCapabilityIssueOutcome::Issued(_))
            ^ matches!(second, CalibrationReadCapabilityIssueOutcome::Issued(_)),
        "one concurrent issuer must commit the frozen capability"
    );
    assert!(
        matches!(first, CalibrationReadCapabilityIssueOutcome::Conflict)
            || matches!(second, CalibrationReadCapabilityIssueOutcome::Conflict),
        "a conflicting concurrent issuer must receive the stable outcome"
    );
}

async fn assert_exact_read_authorization_rechecks_lease_and_catalog(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    let capability = fixture.capability(1_024);
    assert!(matches!(
        issue_capability(store, &capability, &event_id(), 11, 12).await,
        CalibrationReadCapabilityIssueOutcome::Issued(_)
    ));
    let lease = match store
        .begin_calibration_evidence_batch(
            CalibrationEvidenceBatchBegin::new(&capability, "runner-read", Duration::from_secs(30))
                .expect("read batch command is valid"),
        )
        .await
        .expect("read batch begins")
    {
        CalibrationEvidenceBatchBeginOutcome::Started(lease) => lease,
        outcome => panic!("expected read lease, got {}", outcome.reason_code()),
    };
    let now = UnixSeconds::new(u64::try_from(Utc::now().timestamp()).expect("current time"));
    let session = capability
        .bind_issued_batch_lease(lease, now)
        .expect("durable lease binds the exact capability");
    let reference = capability
        .evidence_refs()
        .into_iter()
        .find(|reference| reference.role().as_str() == "model_call_record")
        .expect("model record is present");
    let request = CalibrationEvidenceReadRequest::new(
        &session,
        &capability,
        &reference,
        &fixture.tenant,
        &fixture.site,
        now,
    )
    .expect("exact request is valid");
    let authorized = store
        .authorize_calibration_evidence_read(&request)
        .await
        .expect("authorization query succeeds");
    assert!(matches!(
        authorized,
        CalibrationEvidenceReadAuthorizationOutcome::Authorized(ref value)
            if value.artifact().artifact_id() == reference.artifact_id()
                && value.role() == reference.role()
                && value.sample_index() == reference.sample_index()
    ));
    assert_role_metadata_drift_denies_active_use(pool, store, fixture, &request).await;

    assert_fake_lease_is_denied(store, &capability, fixture, &reference, &session, now).await;
    assert_catalog_drift_denies_read(pool, store, fixture, &reference, &request).await;
    assert_release_reservation_blocks_catalog_drift(pool, store, &request).await;
    assert_release_reservation_denies_expired_lease(pool, store, &request).await;
    drop(request);

    assert_ordinary_read_does_not_consume_and_full_evaluation_completes(
        pool,
        store,
        fixture,
        &capability,
        session,
    )
    .await;
}

async fn assert_role_metadata_drift_denies_active_use(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    request: &CalibrationEvidenceReadRequest<'_>,
) {
    // A lease does not freeze permission to a changed source. Both ordinary
    // authorization and the release reservation must recheck the role shape.
    for (field, value) in [
        ("kind", "calibration_evidence"),
        ("content_type", "text/plain"),
        ("fidelity", "entity_exact"),
        ("classification", "INTERNAL"),
    ] {
        update_catalog_metadata(
            pool,
            fixture,
            4,
            if field == "kind" { value } else { "model_call" },
            if field == "content_type" {
                value
            } else {
                "application/json"
            },
            if field == "fidelity" {
                value
            } else {
                "semantic"
            },
            if field == "classification" {
                value
            } else {
                "RESTRICTED"
            },
        )
        .await;
        assert!(matches!(
            store
                .authorize_calibration_evidence_read(request)
                .await
                .expect("role drift read authorization resolves"),
            CalibrationEvidenceReadAuthorizationOutcome::Denied(
                CalibrationEvidenceReadDenied::EvidenceNotAuthorized
            )
        ));
        assert!(matches!(
            store
                .reserve_calibration_evidence_release(request)
                .await
                .expect("role drift release reservation resolves"),
            CalibrationEvidenceReleaseReservationOutcome::Denied(
                CalibrationEvidenceReadDenied::EvidenceNotAuthorized
            )
        ));
        update_catalog_metadata(
            pool,
            fixture,
            4,
            "model_call",
            "application/json",
            "semantic",
            "RESTRICTED",
        )
        .await;
    }
}

async fn assert_release_reservation_denies_expired_lease(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    request: &CalibrationEvidenceReadRequest<'_>,
) {
    let reservation = match store
        .reserve_calibration_evidence_release(request)
        .await
        .expect("release reservation resolves")
    {
        CalibrationEvidenceReleaseReservationOutcome::Reserved(reservation) => reservation,
        CalibrationEvidenceReleaseReservationOutcome::Denied(_) => {
            panic!("fresh authorization must reserve the release boundary")
        }
    };
    sqlx::query(
        "UPDATE xshield.calibration_read_capability_leases
         SET lease_until=date_trunc('milliseconds', clock_timestamp()) + interval '10 milliseconds'
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4",
    )
    .bind(request.tenant_id().as_str())
    .bind(request.site_id().as_str())
    .bind(request.capability().capability_id().as_str())
    .bind(request.session().lease().lease_id().as_str())
    .execute(pool)
    .await
    .expect("test lease is shortened after reservation");
    sleep(Duration::from_millis(25)).await;
    assert!(matches!(
        store
            .commit_calibration_evidence_release(request, reservation)
            .await
            .expect("expired release boundary resolves"),
        CalibrationEvidenceReleaseCommitOutcome::Denied(
            CalibrationEvidenceReadDenied::EvidenceNotAuthorized
        )
    ));
    sqlx::query(
        "UPDATE xshield.calibration_read_capability_leases
         SET lease_until=date_trunc('milliseconds', clock_timestamp()) + interval '30 seconds'
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4",
    )
    .bind(request.tenant_id().as_str())
    .bind(request.site_id().as_str())
    .bind(request.capability().capability_id().as_str())
    .bind(request.session().lease().lease_id().as_str())
    .execute(pool)
    .await
    .expect("test lease is restored after the denied release boundary");
    sqlx::query(
        "DELETE FROM xshield.calibration_evidence_release_reservations
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4
           AND artifact_id=$5",
    )
    .bind(request.tenant_id().as_str())
    .bind(request.site_id().as_str())
    .bind(request.capability().capability_id().as_str())
    .bind(request.session().lease().lease_id().as_str())
    .bind(request.evidence_ref().artifact_id().as_str())
    .execute(pool)
    .await
    .expect("denied test reservation is removed");
}

async fn assert_release_reservation_blocks_catalog_drift(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    request: &CalibrationEvidenceReadRequest<'_>,
) {
    let reservation = match store
        .reserve_calibration_evidence_release(request)
        .await
        .expect("release reservation resolves")
    {
        CalibrationEvidenceReleaseReservationOutcome::Reserved(reservation) => reservation,
        CalibrationEvidenceReleaseReservationOutcome::Denied(_) => {
            panic!("fresh authorization must reserve the release boundary")
        }
    };
    let drift = sqlx::query(
        "UPDATE xshield.artifact_catalog SET integrity_digest=integrity_digest
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(request.tenant_id().as_str())
    .bind(request.site_id().as_str())
    .bind(request.evidence_ref().artifact_id().as_str())
    .execute(pool)
    .await;
    assert!(
        drift.is_err(),
        "an active release reservation must reject a concurrent catalog mutation"
    );
    assert!(matches!(
        store
            .commit_calibration_evidence_release(request, reservation)
            .await
            .expect("reserved release commits"),
        CalibrationEvidenceReleaseCommitOutcome::Released
    ));
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET integrity_digest=integrity_digest
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(request.tenant_id().as_str())
    .bind(request.site_id().as_str())
    .bind(request.evidence_ref().artifact_id().as_str())
    .execute(pool)
    .await
    .expect("catalog mutation resumes after the release boundary commits");
}

async fn assert_ordinary_read_does_not_consume_and_full_evaluation_completes(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    capability: &CalibrationEvidenceReadCapability,
    session: xshield_core::calibration::read_capability::CalibrationEvidenceReadSession<'_>,
) {
    let states: (String, String) = sqlx::query_as(
        "SELECT capability.status, lease.status
         FROM xshield.calibration_read_capabilities capability
         JOIN xshield.calibration_read_capability_leases lease
           ON lease.tenant_id=capability.tenant_id AND lease.site_id=capability.site_id
          AND lease.capability_id=capability.capability_id
         WHERE capability.tenant_id=$1 AND capability.site_id=$2 AND capability.capability_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(capability.capability_id().as_str())
    .fetch_one(pool)
    .await
    .expect("ordinary read leaves the lease active");
    assert_eq!(states, ("leased".to_owned(), "active".to_owned()));

    let completion = CalibrationEvidenceBatchCompletion::from_successful_evaluation(
        session,
        completed_report(fixture),
    )
    .expect("the full evaluator result matches the frozen capability");
    assert!(matches!(
        store
            .complete_calibration_evidence_batch(
                CalibrationEvidenceBatchComplete::new(&completion, "other-runner")
                    .expect("bounded runner is valid"),
            )
            .await
            .expect("wrong runner completion resolves"),
        CalibrationEvidenceBatchCompleteOutcome::Unavailable
    ));
    assert!(matches!(
        store
            .complete_calibration_evidence_batch(
                CalibrationEvidenceBatchComplete::new(&completion, "runner-read")
                    .expect("bound runner is valid"),
            )
            .await
            .expect("full completion commits"),
        CalibrationEvidenceBatchCompleteOutcome::Completed
    ));
    assert!(matches!(
        store
            .complete_calibration_evidence_batch(
                CalibrationEvidenceBatchComplete::new(&completion, "runner-read")
                    .expect("retry command is valid"),
            )
            .await
            .expect("unknown-commit retry resolves"),
        CalibrationEvidenceBatchCompleteOutcome::AlreadyCompleted
    ));

    assert_completion_outbox_is_atomic(pool, fixture, capability).await;
    assert_completed_batch_denies_new_reads(store, fixture, capability, completion.session()).await;
}

async fn assert_completion_outbox_is_atomic(
    pool: &PgPool,
    fixture: &Fixture,
    capability: &CalibrationEvidenceReadCapability,
) {
    let states: (String, String, String, i64) = sqlx::query_as(
        "SELECT capability.status, lease.status, capability.completion_event_id,
                (SELECT count(*) FROM xshield.audit_outbox outbox
                 WHERE outbox.aggregate_ref=capability.capability_id)::bigint
         FROM xshield.calibration_read_capabilities capability
         JOIN xshield.calibration_read_capability_leases lease
           ON lease.tenant_id=capability.tenant_id AND lease.site_id=capability.site_id
          AND lease.capability_id=capability.capability_id
         WHERE capability.tenant_id=$1 AND capability.site_id=$2 AND capability.capability_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(capability.capability_id().as_str())
    .fetch_one(pool)
    .await
    .expect("completion state is queryable");
    assert_eq!(states.0, "consumed");
    assert_eq!(states.1, "completed");
    assert_eq!(states.3, 2);
    let completion_event: Value = sqlx::query_scalar(
        "SELECT envelope FROM xshield.audit_outbox
         WHERE event_id=$1 AND tenant_id=$2 AND site_id=$3
           AND aggregate_ref=$4 AND event_type='calibration.read_batch.completed'",
    )
    .bind(&states.2)
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(capability.capability_id().as_str())
    .fetch_one(pool)
    .await
    .expect("completion outbox is atomically retained");
    assert_eq!(
        completion_event["payload"],
        serde_json::json!({
            "stage": "calibration_read_batch",
            "outcome": "PASS",
            "reason_code": "CALIBRATION_READ_BATCH_COMPLETED",
            "capability_id": capability.capability_id().as_str()
        })
    );
    assert_eq!(completion_event["evidence_refs"], serde_json::json!([]));
    assert_eq!(completion_event["cause_event_ids"], serde_json::json!([]));
}

async fn assert_completed_batch_denies_new_reads(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    capability: &CalibrationEvidenceReadCapability,
    session: &xshield_core::calibration::read_capability::CalibrationEvidenceReadSession<'_>,
) {
    let now = UnixSeconds::new(u64::try_from(Utc::now().timestamp()).expect("current time"));
    let reference = capability
        .evidence_refs()
        .into_iter()
        .next()
        .expect("frozen manifest is present");
    let request = CalibrationEvidenceReadRequest::new(
        session,
        capability,
        &reference,
        &fixture.tenant,
        &fixture.site,
        now,
    )
    .expect("completed session remains locally shaped");
    assert!(matches!(
        store
            .authorize_calibration_evidence_read(&request)
            .await
            .expect("completed lease resolves to denial"),
        CalibrationEvidenceReadAuthorizationOutcome::Denied(
            CalibrationEvidenceReadDenied::EvidenceNotAuthorized
        )
    ));
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
    .expect("dataset evaluation succeeds")
}

async fn assert_fake_lease_is_denied(
    store: &PostgresIdentityStore,
    capability: &CalibrationEvidenceReadCapability,
    fixture: &Fixture,
    reference: &xshield_core::calibration::read_capability::CalibrationEvidenceRef,
    session: &xshield_core::calibration::read_capability::CalibrationEvidenceReadSession<'_>,
    now: UnixSeconds,
) {
    let fake_lease =
        xshield_core::calibration::read_capability::CalibrationEvidenceBatchLease::from_issued(
            session.lease().lease_id().clone(),
            capability.capability_id().clone(),
            fixture.tenant.clone(),
            fixture.site.clone(),
            session.lease().not_before(),
            session.lease().expires_at(),
            [9; 32],
        )
        .expect("fake lease has valid local shape");
    let fake_session = capability
        .bind_issued_batch_lease(fake_lease, now)
        .expect("fake session has valid local shape");
    let fake_request = CalibrationEvidenceReadRequest::new(
        &fake_session,
        capability,
        reference,
        &fixture.tenant,
        &fixture.site,
        now,
    )
    .expect("fake request is locally valid");
    assert!(matches!(
        store
            .authorize_calibration_evidence_read(&fake_request)
            .await
            .expect("fake lease resolves to denial"),
        CalibrationEvidenceReadAuthorizationOutcome::Denied(
            CalibrationEvidenceReadDenied::EvidenceNotAuthorized
        )
    ));
}

async fn assert_catalog_drift_denies_read(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    reference: &xshield_core::calibration::read_capability::CalibrationEvidenceRef,
    request: &CalibrationEvidenceReadRequest<'_>,
) {
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET integrity_digest=$4
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(reference.artifact_id().as_str())
    .bind("c".repeat(64))
    .execute(pool)
    .await
    .expect("catalog drift updates");
    assert!(matches!(
        store
            .authorize_calibration_evidence_read(request)
            .await
            .expect("drift resolves to denial"),
        CalibrationEvidenceReadAuthorizationOutcome::Denied(
            CalibrationEvidenceReadDenied::EvidenceNotAuthorized
        )
    ));
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET integrity_digest=$4
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(reference.artifact_id().as_str())
    .bind("a".repeat(64))
    .execute(pool)
    .await
    .expect("catalog drift restores");
}

async fn assert_altered_capability_is_unavailable(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    capability: &CalibrationEvidenceReadCapability,
) {
    let altered = CalibrationEvidenceReadCapability::new(
        capability.capability_id().clone(),
        capability.lineage_review_id().clone(),
        fixture.tenant.clone(),
        fixture.site.clone(),
        fixture.provenance(),
        vec![CalibrationSampleReadScope::new(
            fixture.artifacts[4].clone(),
            fixture.artifacts[5].clone(),
        )],
        capability.not_before(),
        capability.expires_at(),
        2_048,
    )
    .expect("altered test capability is syntactically valid");
    assert!(matches!(
        store
            .begin_calibration_evidence_batch(
                CalibrationEvidenceBatchBegin::new(
                    &altered,
                    "runner-altered",
                    Duration::from_secs(1)
                )
                .expect("begin command is valid"),
            )
            .await
            .expect("durable mismatch resolves"),
        CalibrationEvidenceBatchBeginOutcome::Unavailable
    ));
}

async fn assert_catalog_drift_is_unavailable(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    capability: &CalibrationEvidenceReadCapability,
) {
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
    .expect("catalog drift fixture updates");
    assert!(matches!(
        store
            .begin_calibration_evidence_batch(
                CalibrationEvidenceBatchBegin::new(
                    capability,
                    "runner-drift",
                    Duration::from_secs(1)
                )
                .expect("begin command is valid"),
            )
            .await
            .expect("catalog drift resolves"),
        CalibrationEvidenceBatchBeginOutcome::Unavailable
    ));
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
    .expect("catalog fixture is restored");
}

async fn assert_single_lease_and_recovery(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    let capability = fixture.capability(1_024);
    let event = event_id();
    assert!(matches!(
        issue_capability(store, &capability, &event, 8, 9).await,
        CalibrationReadCapabilityIssueOutcome::Issued(_)
    ));

    let first_store = store.clone();
    let second_store = store.clone();
    let (first, second) = tokio::join!(
        async {
            first_store
                .begin_calibration_evidence_batch(
                    CalibrationEvidenceBatchBegin::new(
                        &capability,
                        "runner-one",
                        Duration::from_secs(1),
                    )
                    .expect("begin command is valid"),
                )
                .await
                .expect("first begin resolves")
        },
        async {
            second_store
                .begin_calibration_evidence_batch(
                    CalibrationEvidenceBatchBegin::new(
                        &capability,
                        "runner-two",
                        Duration::from_secs(1),
                    )
                    .expect("begin command is valid"),
                )
                .await
                .expect("second begin resolves")
        }
    );
    assert!(
        matches!(first, CalibrationEvidenceBatchBeginOutcome::Started(_))
            ^ matches!(second, CalibrationEvidenceBatchBeginOutcome::Started(_)),
        "one concurrent claimant must receive the only active lease"
    );
    assert!(
        matches!(first, CalibrationEvidenceBatchBeginOutcome::Busy)
            || matches!(second, CalibrationEvidenceBatchBeginOutcome::Busy),
        "the losing concurrent claimant must observe a live lease"
    );

    sleep(Duration::from_millis(1_100)).await;
    assert!(matches!(
        store
            .begin_calibration_evidence_batch(
                CalibrationEvidenceBatchBegin::new(
                    &capability,
                    "runner-recovery",
                    Duration::from_secs(1)
                )
                .expect("recovery command is valid"),
            )
            .await
            .expect("expired lease recovery resolves"),
        CalibrationEvidenceBatchBeginOutcome::Started(_)
    ));
    let lease_states: Vec<(i32, String)> = sqlx::query_as(
        "SELECT lease_generation, status
         FROM xshield.calibration_read_capability_leases
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3
         ORDER BY lease_generation",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(capability.capability_id().as_str())
    .fetch_all(pool)
    .await
    .expect("lease history is queryable");
    assert_eq!(
        lease_states,
        vec![(1, "abandoned".to_owned()), (2, "active".to_owned())]
    );
}

async fn issue_capability(
    store: &PostgresIdentityStore,
    capability: &CalibrationEvidenceReadCapability,
    event: &EventId,
    idempotency: u8,
    request: u8,
) -> CalibrationReadCapabilityIssueOutcome {
    issue_capability_as(
        store,
        capability,
        event,
        "calibration-fixture",
        idempotency,
        request,
    )
    .await
}

async fn issue_capability_as(
    store: &PostgresIdentityStore,
    capability: &CalibrationEvidenceReadCapability,
    event: &EventId,
    issued_by: &str,
    idempotency: u8,
    request: u8,
) -> CalibrationReadCapabilityIssueOutcome {
    let idempotency_digest = [idempotency; 32];
    let request_digest = [request; 32];
    store
        .issue_calibration_read_capability(
            CalibrationReadCapabilityIssue::new(
                capability,
                issued_by,
                &idempotency_digest,
                &request_digest,
                event,
            )
            .expect("issue command is valid"),
        )
        .await
        .expect("issue resolves")
}

/// Seeds only the immutable database projection produced after vault attestation.
/// The dedicated review-commit regression owns end-to-end vault publication;
/// this batch fixture needs the projection so it can exercise the issuer gate.
async fn seed_committed_lineage_review(pool: &PgPool, fixture: &Fixture) {
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
    .bind(fixture.lineage_review_id.as_str())
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
             now() + interval '10 minutes'
         )",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.lineage_review_id.as_str())
    .bind(fixture.lineage_review_artifact_id.as_str())
    .bind(format!(
        "{}.xev",
        fixture.lineage_review_artifact_id.as_str()
    ))
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
    .bind(fixture.lineage_review_id.as_str())
    .bind(fixture.lineage_review_artifact_id.as_str())
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

async fn update_catalog_metadata(
    pool: &PgPool,
    fixture: &Fixture,
    index: usize,
    kind: &str,
    content_type: &str,
    fidelity: &str,
    classification: &str,
) {
    sqlx::query(
        "UPDATE xshield.artifact_catalog
         SET kind=$1, content_type=$2, fidelity=$3, classification=$4
         WHERE tenant_id=$5 AND site_id=$6 AND artifact_id=$7",
    )
    .bind(kind)
    .bind(content_type)
    .bind(fidelity)
    .bind(classification)
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.artifacts[index].as_str())
    .execute(pool)
    .await
    .expect("catalog metadata update succeeds");
}

fn cleanup(_pool: &PgPool, _fixture: &Fixture) {
    // Migration 0030 freezes committed review projections. Every integration
    // fixture uses a unique tenant and the harness drops its temporary database,
    // so deleting retained audit state here would test an invalid lifecycle.
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
