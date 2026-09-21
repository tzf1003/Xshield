//! `PostgreSQL` integration coverage for model provider capacity admission.
//!
//! These tests use the temporary `PostgreSQL` database owned by
//! `scripts/test_postgres.sh`. The tenant/site scopes are unique, so retained
//! scheduling history remains available for exact recovery assertions.

use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, time::Duration};
use tokio::time::sleep;
use uuid::Uuid;
use xshield_core::{
    domain::{ModelCallId, PolicyRevision, RequestId, SiteId, TenantId},
    model_evaluation_admission::{
        ModelEvaluationAdmissionAttempt, ModelEvaluationAdmissionDenied,
        ModelEvaluationAdmissionReleaseState, ModelEvaluationAdmissionState,
    },
};
use xshield_postgres::PostgresIdentityStore;

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn model_evaluation_admission_is_scoped_bounded_exact_and_recoverable() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL required");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let tenant = TenantId::parse(format!(
        "tenant_model_admission_{}",
        Uuid::now_v7().simple()
    ))
    .expect("tenant is valid");
    let site = SiteId::parse(format!("site_model_admission_{}", Uuid::now_v7().simple()))
        .expect("site is valid");
    let other_site = SiteId::parse(format!("site_model_admission_{}", Uuid::now_v7().simple()))
        .expect("isolated site is valid");
    provision_scope(&pool, &tenant, &site, 1, 45).await;
    provision_scope(&pool, &tenant, &other_site, 1, 45).await;

    let mismatched_policy = ModelEvaluationAdmissionAttempt::new(
        tenant.clone(),
        site.clone(),
        RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap(),
        ModelCallId::parse(format!("mdl_{}", Uuid::now_v7())).unwrap(),
        PolicyRevision::parse("model-evaluation-admission-r2").unwrap(),
        "runner-admission-r1",
    )
    .unwrap();
    assert_eq!(
        denied(
            &store
                .acquire_model_evaluation_admission(&mismatched_policy)
                .await
                .unwrap(),
        ),
        ModelEvaluationAdmissionDenied::PolicyRevisionMismatch
    );
    let mismatched_leases: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.model_evaluation_admission_leases
         WHERE tenant_id=$1 AND site_id=$2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(mismatched_leases, 0);

    let first = attempt(&tenant, &site, "runner-admission-r1");
    let first_lease = admitted(
        store
            .acquire_model_evaluation_admission(&first)
            .await
            .unwrap(),
    );
    assert!(matches!(
        store
            .confirm_model_evaluation_admission(&first_lease)
            .await
            .unwrap(),
        ModelEvaluationAdmissionState::Admitted(())
    ));

    let capacity = store
        .acquire_model_evaluation_admission(&attempt(&tenant, &site, "runner-admission-r1"))
        .await
        .unwrap();
    assert_eq!(
        denied(&capacity),
        ModelEvaluationAdmissionDenied::CapacityExhausted
    );
    let isolated = admitted(
        store
            .acquire_model_evaluation_admission(&attempt(
                &tenant,
                &other_site,
                "runner-admission-r1",
            ))
            .await
            .unwrap(),
    );
    assert_eq!(
        store
            .release_model_evaluation_admission(&isolated)
            .await
            .unwrap(),
        ModelEvaluationAdmissionReleaseState::Released
    );

    assert_eq!(
        store
            .release_model_evaluation_admission(&first_lease)
            .await
            .unwrap(),
        ModelEvaluationAdmissionReleaseState::Released
    );
    assert_eq!(
        store
            .release_model_evaluation_admission(&first_lease)
            .await
            .unwrap(),
        ModelEvaluationAdmissionReleaseState::AlreadyReleased
    );
    assert_eq!(
        denied(
            &store
                .acquire_model_evaluation_admission(&first)
                .await
                .unwrap(),
        ),
        ModelEvaluationAdmissionDenied::RecoveryRequired
    );

    let conflicting = ModelEvaluationAdmissionAttempt::new(
        tenant.clone(),
        site.clone(),
        RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap(),
        first.model_call_id().clone(),
        first.policy_revision().clone(),
        "runner-admission-r1",
    )
    .unwrap();
    assert_eq!(
        denied(
            &store
                .acquire_model_evaluation_admission(&conflicting)
                .await
                .unwrap(),
        ),
        ModelEvaluationAdmissionDenied::Conflict
    );

    let stale = admitted(
        store
            .acquire_model_evaluation_admission(&attempt(&tenant, &site, "runner-admission-r1"))
            .await
            .unwrap(),
    );
    sqlx::query(
        "UPDATE xshield.model_evaluation_admission_leases
         SET acquired_at=date_trunc('milliseconds', clock_timestamp() - interval '2 seconds'),
             lease_until=date_trunc('milliseconds', clock_timestamp() - interval '1 second')
         WHERE lease_id=$1",
    )
    .bind(stale.lease_id().as_str())
    .execute(&pool)
    .await
    .expect("test lease can be made stale");
    let recovered = admitted(
        store
            .acquire_model_evaluation_admission(&attempt(&tenant, &site, "runner-admission-r1"))
            .await
            .unwrap(),
    );
    assert_eq!(
        store
            .release_model_evaluation_admission(&stale)
            .await
            .unwrap(),
        ModelEvaluationAdmissionReleaseState::Expired
    );
    assert_eq!(
        store
            .release_model_evaluation_admission(&recovered)
            .await
            .unwrap(),
        ModelEvaluationAdmissionReleaseState::Released
    );
    let states: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status='active'),
                count(*) FILTER (WHERE status='released'),
                count(*) FILTER (WHERE status='expired')
         FROM xshield.model_evaluation_admission_leases
         WHERE tenant_id=$1 AND site_id=$2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .expect("lease state is queryable");
    assert_eq!(states, (0, 2, 1));
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn model_evaluation_admission_serializes_scope_capacity_with_database_locks() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL required");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let tenant = TenantId::parse(format!("tenant_model_lock_{}", Uuid::now_v7().simple()))
        .expect("tenant is valid");
    let site = SiteId::parse(format!("site_model_lock_{}", Uuid::now_v7().simple()))
        .expect("site is valid");
    provision_scope(&pool, &tenant, &site, 1, 45).await;
    let first = attempt(&tenant, &site, "runner-lock-r1");
    let second = attempt(&tenant, &site, "runner-lock-r1");
    let first_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("first actor pool connects");
    let first_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&first_pool)
        .await
        .expect("first actor pid is queryable");
    let second_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("second actor pool connects");
    let second_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&second_pool)
        .await
        .expect("second actor pid is queryable");
    let first_store = PostgresIdentityStore::from_pool(first_pool.clone());
    let second_store = PostgresIdentityStore::from_pool(second_pool.clone());
    let mut gate = pool.begin().await.expect("relation gate starts");
    let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *gate)
        .await
        .expect("gate pid is queryable");
    sqlx::query("LOCK TABLE xshield.model_evaluation_admission_leases IN SHARE MODE")
        .execute(&mut *gate)
        .await
        .expect("admission relation gate is held");

    let (first_result, second_result) = tokio::join!(
        first_store.acquire_model_evaluation_admission(&first),
        async {
            wait_for_database_block(&pool, first_pid, gate_pid).await;
            let (result, ()) = tokio::join!(
                second_store.acquire_model_evaluation_admission(&second),
                async {
                    wait_for_database_block(&pool, second_pid, first_pid).await;
                    gate.commit().await.expect("gate releases after both waits");
                },
            );
            result
        },
    );
    first_pool.close().await;
    second_pool.close().await;
    let first_lease = admitted(first_result.expect("first actor resolves"));
    assert_eq!(
        denied(&second_result.expect("second actor resolves")),
        ModelEvaluationAdmissionDenied::CapacityExhausted
    );
    assert_eq!(
        PostgresIdentityStore::from_pool(pool.clone())
            .release_model_evaluation_admission(&first_lease)
            .await
            .expect("lease release resolves"),
        ModelEvaluationAdmissionReleaseState::Released
    );
}

fn attempt(tenant: &TenantId, site: &SiteId, runner: &str) -> ModelEvaluationAdmissionAttempt {
    ModelEvaluationAdmissionAttempt::new(
        tenant.clone(),
        site.clone(),
        RequestId::parse(format!("req_{}", Uuid::now_v7())).expect("request id is valid"),
        ModelCallId::parse(format!("mdl_{}", Uuid::now_v7())).expect("model call id is valid"),
        PolicyRevision::parse("model-evaluation-admission-r1").expect("policy revision is valid"),
        runner,
    )
    .expect("admission attempt is valid")
}

fn admitted<T>(state: ModelEvaluationAdmissionState<T>) -> T {
    match state {
        ModelEvaluationAdmissionState::Admitted(value) => value,
        ModelEvaluationAdmissionState::Denied(denied) => {
            panic!("expected admission, got {}", denied.reason_code())
        }
    }
}

fn denied<T>(state: &ModelEvaluationAdmissionState<T>) -> ModelEvaluationAdmissionDenied {
    match state {
        ModelEvaluationAdmissionState::Admitted(_) => panic!("expected admission denial"),
        ModelEvaluationAdmissionState::Denied(denied) => *denied,
    }
}

async fn provision_scope(
    pool: &PgPool,
    tenant: &TenantId,
    site: &SiteId,
    max_active_calls: i32,
    lease_seconds: i32,
) {
    sqlx::query(
        "INSERT INTO xshield.model_evaluation_admission_scopes
             (tenant_id, site_id, policy_revision, max_active_calls, lease_seconds, configured_at)
         VALUES ($1,$2,'model-evaluation-admission-r1',$3,$4,
                 date_trunc('milliseconds', clock_timestamp()))",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(max_active_calls)
    .bind(lease_seconds)
    .execute(pool)
    .await
    .expect("admission scope provisions");
}

async fn wait_for_database_block(pool: &PgPool, waiter: i32, blocker: i32) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let queued: bool = sqlx::query_scalar("SELECT $2=ANY(pg_blocking_pids($1))")
                .bind(waiter)
                .bind(blocker)
                .fetch_one(pool)
                .await
                .expect("lock graph is queryable");
            if queued {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected database lock waiter to reach blocker");
}
