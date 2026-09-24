//! `PostgreSQL` wire regression for the durable case-analysis job producer.

use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{CaseId, JobId, SiteId, TenantId};
use xshield_postgres::{CaseAnalysisJobCreate, ControlJobWriteOutcome, PostgresIdentityStore};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn case_analysis_job_is_atomic_idempotent_scoped_and_counted() {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let pool = PgPool::connect(&url).await.expect("test database connects");
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("database name is queryable");
    assert!(
        database.starts_with("xshield_test_"),
        "requires script-owned test database"
    );
    let store = PostgresIdentityStore::connect(&url, 3, Duration::from_secs(5))
        .await
        .expect("job store connects");
    let suffix = Uuid::now_v7().simple().to_string();
    let tenant = TenantId::parse(format!("tenant_job_{suffix}")).expect("tenant is valid");
    let site = SiteId::parse(format!("site_job_{suffix}")).expect("site is valid");
    let owner = "investigator-job";
    let case_id = CaseId::parse(format!("case_{}", Uuid::now_v7())).expect("case is valid");
    let job_id = JobId::parse(format!("job_{}", Uuid::now_v7())).expect("job is valid");
    seed_case(&pool, &tenant, &site, &case_id, owner).await;
    seed_artifact_item(&pool, &tenant, &site, &case_id, owner, "active", 1).await;
    seed_artifact_item(&pool, &tenant, &site, &case_id, owner, "expired", 2).await;
    seed_artifact_item(&pool, &tenant, &site, &case_id, owner, "deleted", 3).await;

    let idempotency = [11_u8; 32];
    let request = [12_u8; 32];
    let command = CaseAnalysisJobCreate::new(
        &tenant,
        &site,
        &case_id,
        owner,
        &job_id,
        &idempotency,
        &request,
    )
    .expect("analysis command is valid");
    let created = store
        .create_case_analysis_job(command)
        .await
        .expect("first job write succeeds");
    let record = match created {
        ControlJobWriteOutcome::Created(record) => record,
        other => panic!("expected created job, got {other:?}"),
    };
    assert_eq!(record.job_id(), &job_id);
    assert_eq!(record.case_id(), &case_id);
    assert_eq!(record.kind(), "case_analysis");
    assert_eq!(record.status(), "succeeded");
    assert_eq!(record.checkpoint(), "inventory_committed");
    assert_eq!(record.reason_code(), "CONTROL_CASE_ANALYSIS_COMPLETE");
    assert!(!record.retryable());
    assert_eq!(record.artifact_count(), 3);
    assert_eq!(record.active_artifact_count(), 1);
    assert!(record.completed_at().is_some());

    let replay = store
        .create_case_analysis_job(
            CaseAnalysisJobCreate::new(
                &tenant,
                &site,
                &case_id,
                owner,
                &job_id,
                &idempotency,
                &request,
            )
            .expect("replay command is valid"),
        )
        .await
        .expect("exact replay succeeds");
    assert_eq!(replay, ControlJobWriteOutcome::Existing(record.clone()));

    let conflict = store
        .create_case_analysis_job(
            CaseAnalysisJobCreate::new(
                &tenant,
                &site,
                &case_id,
                owner,
                &JobId::parse(format!("job_{}", Uuid::now_v7())).expect("job is valid"),
                &idempotency,
                &[13_u8; 32],
            )
            .expect("conflict command is valid"),
        )
        .await
        .expect("conflict lookup succeeds");
    assert_eq!(conflict, ControlJobWriteOutcome::Conflict);

    let wrong_owner = store
        .read_control_job(&tenant, &site, "other-investigator", &job_id)
        .await
        .expect("owner-scoped read succeeds");
    assert!(wrong_owner.is_none());
    let foreign_tenant =
        TenantId::parse(format!("tenant_foreign_{suffix}")).expect("tenant is valid");
    assert!(
        store
            .read_control_job(&foreign_tenant, &site, owner, &job_id)
            .await
            .expect("scope-scoped read succeeds")
            .is_none()
    );

    let missing_case = CaseId::parse(format!("case_{}", Uuid::now_v7())).expect("case is valid");
    let missing = store
        .create_case_analysis_job(
            CaseAnalysisJobCreate::new(
                &tenant,
                &site,
                &missing_case,
                owner,
                &JobId::parse(format!("job_{}", Uuid::now_v7())).expect("job is valid"),
                &[14_u8; 32],
                &[15_u8; 32],
            )
            .expect("missing target command is valid"),
        )
        .await
        .expect("missing target lookup succeeds");
    assert_eq!(missing, ControlJobWriteOutcome::TargetUnavailable);

    sqlx::query("DELETE FROM xshield.control_jobs WHERE tenant_id = $1 AND site_id = $2")
        .bind(tenant.as_str())
        .bind(site.as_str())
        .execute(&pool)
        .await
        .expect("job cleanup succeeds");
    sqlx::query("DELETE FROM xshield.case_items WHERE tenant_id = $1 AND site_id = $2")
        .bind(tenant.as_str())
        .bind(site.as_str())
        .execute(&pool)
        .await
        .expect("case item cleanup succeeds");
    sqlx::query("DELETE FROM xshield.artifact_catalog WHERE tenant_id = $1 AND site_id = $2")
        .bind(tenant.as_str())
        .bind(site.as_str())
        .execute(&pool)
        .await
        .expect("catalog cleanup succeeds");
    sqlx::query("DELETE FROM xshield.investigation_cases WHERE tenant_id = $1 AND site_id = $2")
        .bind(tenant.as_str())
        .bind(site.as_str())
        .execute(&pool)
        .await
        .expect("case cleanup succeeds");
    pool.close().await;
}

async fn seed_case(pool: &PgPool, tenant: &TenantId, site: &SiteId, case_id: &CaseId, owner: &str) {
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
             tenant_id, site_id, case_id, owner_ref, purpose, status,
             idempotency_digest, request_digest, created_event_id
         ) VALUES ($1, $2, $3, $4, 'Durable job regression', 'open', $5, $6, $7)",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(case_id.as_str())
    .bind(owner)
    .bind([1_u8; 32])
    .bind([2_u8; 32])
    .bind(format!("ev_{}", Uuid::now_v7()))
    .execute(pool)
    .await
    .expect("case seed succeeds");
}

async fn seed_artifact_item(
    pool: &PgPool,
    tenant: &TenantId,
    site: &SiteId,
    case_id: &CaseId,
    owner: &str,
    state: &str,
    nonce: u8,
) {
    let artifact = format!("artifact_{}", Uuid::now_v7());
    let request = format!("req_{}", Uuid::now_v7());
    let catalog_event = format!("ev_{}", Uuid::now_v7());
    let added_event = format!("ev_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO xshield.artifact_catalog (
             tenant_id, site_id, artifact_id, request_id, schema_version, kind,
             content_type, capture_status, fidelity, bytes_observed, bytes_saved,
             classification, example_only, storage_profile, storage_locator,
             key_ref, integrity_algorithm, integrity_digest, parent_refs,
             recorded_at, expires_at, catalog_event_id, status, deleted_at
         ) VALUES ($1, $2, $3, $4, 3, 'response_from_origin',
             'application/json', 'complete', 'entity_exact', 2, 2,
             'RESTRICTED', false, 'aead_envelope_v1', $3 || '.xev',
             'evidence-key-r1', 'sha256_ciphertext', repeat('a', 64), '{}',
             clock_timestamp(),
             CASE WHEN $6 = 'expired'
                  THEN clock_timestamp() - interval '1 hour'
                  ELSE clock_timestamp() + interval '1 hour' END,
             $5,
             CASE WHEN $6 = 'deleted' THEN 'deleted' ELSE 'active' END,
             CASE WHEN $6 = 'deleted' THEN clock_timestamp() ELSE NULL END)",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(&artifact)
    .bind(&request)
    .bind(&catalog_event)
    .bind(state)
    .execute(pool)
    .await
    .expect("catalog seed succeeds");
    sqlx::query(
        "INSERT INTO xshield.case_items (
             tenant_id, site_id, case_id, artifact_id, added_by,
             idempotency_digest, request_digest, added_event_id
         ) VALUES ($1, $2, $3, $4, $5, $6, $6, $7)",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(case_id.as_str())
    .bind(&artifact)
    .bind(owner)
    .bind([nonce; 32])
    .bind(&added_event)
    .execute(pool)
    .await
    .expect("case item seed succeeds");
}
