//! `PostgreSQL` regression for calibration-lineage-review expiry tombstones.

use chrono::{SecondsFormat, TimeDelta, Utc};
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{SiteId, TenantId};
use xshield_evidence::{CalibrationLineageReviewOrphanCandidate, EvidencePurgeOutcome};
use xshield_postgres::{
    CalibrationLineageReviewOrphanPurgeResult, CalibrationLineageReviewPurgeResult,
    PostgresIdentityStore,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL with migrations through 0033"]
async fn calibration_lineage_review_retention_is_intent_first_tombstoned_and_recoverable() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 2, Duration::from_secs(5))
        .await
        .expect("store connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let tenant = TenantId::parse(format!(
        "tenant_calreview_retention_{}",
        Uuid::now_v7().simple()
    ))
    .expect("tenant is valid");
    let site = SiteId::parse("site_calreview_retention").expect("site is valid");
    let review_id = format!("calrev_{}", Uuid::now_v7());
    let artifact_id = format!("artifact_{}", Uuid::now_v7());
    seed_expired_lineage_review(&pool, &tenant, &site, &review_id, &artifact_id).await;

    let jobs = store
        .prepare_calibration_lineage_review_purge(&tenant, &site, "lineage-review-retention-r1", 1)
        .await
        .expect("intent commits");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].manifest().review_id, review_id);
    let retried = store
        .prepare_calibration_lineage_review_purge(&tenant, &site, "lineage-review-retention-r1", 1)
        .await
        .expect("intent retry resolves");
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].intent_event_id(), jobs[0].intent_event_id());

    store
        .finish_calibration_lineage_review_purge(
            &jobs[0],
            CalibrationLineageReviewPurgeResult::Deleted(EvidencePurgeOutcome::AlreadyAbsent),
        )
        .await
        .expect("idempotent physical result tombstones lineage review");
    store
        .finish_calibration_lineage_review_purge(
            &jobs[0],
            CalibrationLineageReviewPurgeResult::Deleted(EvidencePurgeOutcome::AlreadyAbsent),
        )
        .await
        .expect("completion retry is idempotent");
    let terminal: (String, bool, i64) = sqlx::query_as(
        "SELECT retention_status, deleted_at IS NOT NULL,
                (SELECT count(*) FROM xshield.audit_outbox
                 WHERE tenant_id=$1 AND site_id=$2
                   AND event_type IN (
                     'calibration.lineage_review_retention.purge_requested',
                     'calibration.lineage_review_retention.deleted'
                   ))
         FROM xshield.calibration_lineage_review_artifacts
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(&artifact_id)
    .fetch_one(&pool)
    .await
    .expect("tombstone is queryable");
    assert_eq!(terminal, ("deleted".to_owned(), true, 2));

    sqlx::query(
        "DELETE FROM xshield.calibration_lineage_review_artifacts WHERE tenant_id=$1 AND site_id=$2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .execute(&pool)
    .await
    .expect("lineage-review fixture cleans up");
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE tenant_id=$1 AND site_id=$2")
        .bind(tenant.as_str())
        .bind(site.as_str())
        .execute(&pool)
        .await
        .expect("outbox fixture cleans up");
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL with migrations through 0033"]
async fn calibration_lineage_review_orphan_retention_is_intent_first_without_review_metadata() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 2, Duration::from_secs(5))
        .await
        .expect("store connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let tenant = TenantId::parse(format!(
        "tenant_calreview_orphan_{}",
        Uuid::now_v7().simple()
    ))
    .expect("tenant is valid");
    let site = SiteId::parse("site_calreview_orphan").expect("site is valid");
    let review_id = format!("calrev_{}", Uuid::now_v7());
    let artifact_id = format!("artifact_{}", Uuid::now_v7());
    let expires_at =
        (Utc::now() - TimeDelta::seconds(1)).to_rfc3339_opts(SecondsFormat::Millis, true);
    let candidate = CalibrationLineageReviewOrphanCandidate::from_observation(
        &review_id,
        &artifact_id,
        "b".repeat(64),
        expires_at,
        1,
        1_789_689_600,
        123,
    )
    .expect("candidate is valid");

    let jobs = store
        .prepare_calibration_lineage_review_orphan_purge(
            &tenant,
            &site,
            std::slice::from_ref(&candidate),
        )
        .await
        .expect("orphan intent commits");
    assert_eq!(jobs.len(), 1);
    let retried = store
        .prepare_calibration_lineage_review_orphan_purge(
            &tenant,
            &site,
            std::slice::from_ref(&candidate),
        )
        .await
        .expect("orphan intent retry resolves");
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].intent_event_id(), jobs[0].intent_event_id());

    store
        .finish_calibration_lineage_review_orphan_purge(
            &jobs[0],
            CalibrationLineageReviewOrphanPurgeResult::Deleted(EvidencePurgeOutcome::AlreadyAbsent),
        )
        .await
        .expect("already absent orphan tombstones");
    store
        .finish_calibration_lineage_review_orphan_purge(
            &jobs[0],
            CalibrationLineageReviewOrphanPurgeResult::Deleted(EvidencePurgeOutcome::AlreadyAbsent),
        )
        .await
        .expect("orphan completion retry is idempotent");

    let terminal: (String, bool, i64, bool) = sqlx::query_as(
        "SELECT orphan.status, orphan.completed_at IS NOT NULL,
                (SELECT count(*) FROM xshield.audit_outbox
                 WHERE tenant_id=$1 AND site_id=$2
                   AND event_type IN (
                     'calibration.lineage_review_retention.orphan_purge_requested',
                     'calibration.lineage_review_retention.orphan_deleted'
                   )),
                NOT EXISTS (SELECT 1 FROM xshield.calibration_lineage_review_artifacts
                            WHERE artifact_id=$3 OR review_id=$4)
         FROM xshield.calibration_lineage_review_orphan_purges orphan
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(&artifact_id)
    .bind(&review_id)
    .fetch_one(&pool)
    .await
    .expect("orphan tombstone is queryable");
    assert_eq!(terminal, ("deleted".to_owned(), true, 2, true));

    sqlx::query(
        "DELETE FROM xshield.calibration_lineage_review_orphan_purges WHERE tenant_id=$1 AND site_id=$2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .execute(&pool)
    .await
    .expect("orphan fixture cleans up");
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE tenant_id=$1 AND site_id=$2")
        .bind(tenant.as_str())
        .bind(site.as_str())
        .execute(&pool)
        .await
        .expect("outbox fixture cleans up");
}

async fn seed_expired_lineage_review(
    pool: &PgPool,
    tenant: &TenantId,
    site: &SiteId,
    review_id: &str,
    artifact_id: &str,
) {
    sqlx::query(
        "WITH fixture_clock AS (
             SELECT date_trunc('milliseconds', clock_timestamp() - interval '2 seconds') AS recorded_at
         )
         INSERT INTO xshield.calibration_lineage_review_artifacts (
             tenant_id, site_id, review_id, artifact_id, schema_version, kind,
             content_type, canonical_body_encoding, capture_status, fidelity,
             bytes_observed, bytes_saved, classification, storage_profile,
             storage_locator, key_ref, integrity_algorithm, integrity_digest,
             recorded_at, reviewed_at, expires_at
         ) SELECT $1,$2,$3,$4,1,'calibration_partition_lineage_review',
                   'application/vnd.xshield.calibration-lineage-review+json',
                   'xshield_calibration_lineage_review_canonical_json_v1','complete','entity_exact',
                   1,1,'RESTRICTED','aead_envelope_v1',$5,'lineage-review-retention-r1',
                   'sha256_ciphertext',$6,
                   fixture_clock.recorded_at,
                   fixture_clock.recorded_at,
                   fixture_clock.recorded_at + interval '1 second'
           FROM fixture_clock",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(review_id)
    .bind(artifact_id)
    .bind(format!("{artifact_id}.xev"))
    .bind("a".repeat(64))
    .execute(pool)
    .await
    .expect("expired lineage-review artifact inserts");
}
