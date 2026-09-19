//! Real database regressions for scoped, bounded outbox delivery leases.

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{EventId, SiteId, TenantId};
use xshield_postgres::{
    OutboxAckOutcome as Ack, OutboxFailureOutcome as Failure, OutboxLease,
    OutboxLeaseConfig as Limits, OutboxScope as Scope, StoreError, ack_outbox_event as ack,
    claim_outbox_batch_for_types as claim, fail_outbox_event as fail,
};

const TYPES: &[&str] = &["case.created"];
const HOUR: Duration = Duration::from_hours(1);
const ERROR_CODE: &str = "OUTBOX_INDEX_UNAVAILABLE";

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn delivery_is_scoped_bounded_concurrent_and_token_bound() {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let pool = PgPool::connect(&url).await.unwrap();
    let tenant = TenantId::parse(format!("tenant_outbox_{}", Uuid::now_v7().simple())).unwrap();
    let foreign = TenantId::parse(format!("tenant_outbox_{}", Uuid::now_v7().simple())).unwrap();
    let site = SiteId::parse(format!("site_outbox_{}", Uuid::now_v7().simple())).unwrap();
    let other_site = SiteId::parse(format!("site_outbox_{}", Uuid::now_v7().simple())).unwrap();
    let scopes = [
        Scope::new(&tenant, &site),
        Scope::new(&foreign, &site),
        Scope::new(&tenant, &other_site),
    ];
    let test_pool = pool.clone();
    // Isolate assertion panics so this owner still cleans its synthetic rows.
    let result = tokio::spawn(async move {
        let leases = check_claims(&test_pool, &scopes).await;
        check_completion(&test_pool, &scopes, leases).await;
    })
    .await;
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE tenant_id IN ($1, $2)")
        .bind(tenant.as_str())
        .bind(foreign.as_str())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    result.unwrap();
}

async fn check_claims(pool: &PgPool, scopes: &[Scope; 3]) -> [OutboxLease; 2] {
    let scope = &scopes[0];
    let first = seed(pool, scope, "case.created", 1).await;
    let second = seed(pool, scope, "case.created", 2).await;
    let third = seed(pool, scope, "case.created", 3).await;
    let untouched = [
        seed(pool, scope, "case.closed", 0).await,
        seed(pool, scope, "evidence.cataloged", 0).await,
        seed(pool, &scopes[1], "case.created", 0).await,
        seed(pool, &scopes[2], "case.created", 0).await,
        third,
    ];
    let bytes: i64 = sqlx::query_scalar(
        "SELECT octet_length(envelope::text)::bigint FROM xshield.audit_outbox WHERE event_id = $1",
    )
    .bind(first.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    let bytes = u64::try_from(bytes).unwrap();
    let too_small = Limits::new(3, bytes - 1, HOUR).unwrap();
    assert!(
        claim(pool, scope, too_small, TYPES)
            .await
            .unwrap()
            .is_empty()
    );
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT event_id FROM xshield.audit_outbox WHERE event_id = $1 FOR UPDATE")
        .bind(first.as_str())
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    // This must finish while the earlier row remains locked by another worker.
    let limited = Limits::new(1, bytes * 3, HOUR).unwrap();
    let claimed = tokio::time::timeout(Duration::from_secs(5), claim(pool, scope, limited, TYPES))
        .await
        .expect("SKIP LOCKED must not wait for the held row")
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].event_id, second);
    lock.rollback().await.unwrap();
    let bounded = Limits::new(3, bytes * 2 - 1, HOUR).unwrap();
    let byte_limited = claim(pool, scope, bounded, TYPES).await.unwrap();
    assert_eq!(byte_limited.len(), 1);
    assert_eq!(byte_limited[0].event_id, first);
    let unchanged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.audit_outbox WHERE event_id = ANY($1)
         AND delivery_attempts = 0 AND lease_token IS NULL AND lease_until IS NULL
         AND published_at IS NULL AND last_error_code IS NULL",
    )
    .bind(untouched.iter().map(EventId::as_str).collect::<Vec<_>>())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(unchanged, 5);
    [byte_limited[0].clone(), claimed[0].clone()]
}

async fn check_completion(pool: &PgPool, scopes: &[Scope; 3], leases: [OutboxLease; 2]) {
    let scope = &scopes[0];
    let [old, retry] = leases;
    for foreign in &scopes[1..] {
        rejected(pool, foreign, &old).await;
    }
    sqlx::query(
        "UPDATE xshield.audit_outbox SET lease_until = clock_timestamp() - interval '1 second'
         WHERE event_id = $1",
    )
    .bind(old.event_id.as_str())
    .execute(pool)
    .await
    .unwrap();
    rejected(pool, scope, &old).await;
    let limits = Limits::new(1, 4096, HOUR).unwrap();
    let current = claim(pool, scope, limits, TYPES).await.unwrap().remove(0);
    assert_eq!(current.event_id, old.event_id);
    assert_eq!(current.delivery_attempts, 2);
    assert_ne!(current.lease_token, old.lease_token);
    rejected(pool, scope, &old).await;
    let outcome = ack(pool, scope, &current.event_id, &current.lease_token)
        .await
        .unwrap();
    assert_eq!(outcome, Ack::Acknowledged);
    rejected(pool, scope, &current).await;
    let published: bool = sqlx::query_scalar(
        "SELECT published_at IS NOT NULL AND lease_token IS NULL AND lease_until IS NULL
         FROM xshield.audit_outbox WHERE event_id = $1",
    )
    .bind(current.event_id.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(published);
    check_retry(pool, scope, &retry, limits).await;
}

async fn check_retry(pool: &PgPool, scope: &Scope, lease: &OutboxLease, limits: Limits) {
    for (code, delay) in [
        ("upstream response body", HOUR),
        (ERROR_CODE, Duration::ZERO),
        (ERROR_CODE, Duration::from_secs(3601)),
        (ERROR_CODE, Duration::from_millis(1001)),
    ] {
        let result = fail(
            pool,
            scope,
            &lease.event_id,
            &lease.lease_token,
            code,
            delay,
        )
        .await;
        assert!(matches!(result, Err(StoreError::InvalidCommand)));
    }
    let before: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    let outcome = fail(
        pool,
        scope,
        &lease.event_id,
        &lease.lease_token,
        ERROR_CODE,
        HOUR,
    )
    .await
    .unwrap();
    assert_eq!(outcome, Failure::Scheduled);
    let state: (DateTime<Utc>, DateTime<Utc>, String, bool) = sqlx::query_as(
        "SELECT next_attempt_at, clock_timestamp(), last_error_code,
         lease_token IS NULL AND lease_until IS NULL AND published_at IS NULL
         FROM xshield.audit_outbox WHERE event_id = $1",
    )
    .bind(lease.event_id.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(state.0 >= before + HOUR && state.0 <= state.1 + HOUR);
    assert_eq!(state.2, ERROR_CODE);
    assert!(state.3);
    rejected(pool, scope, lease).await;
    let remaining = claim(pool, scope, limits, TYPES).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_ne!(remaining[0].event_id, lease.event_id);
    assert!(claim(pool, scope, limits, TYPES).await.unwrap().is_empty());
    sqlx::query(
        "UPDATE xshield.audit_outbox SET next_attempt_at = clock_timestamp() - interval '1 second'
         WHERE event_id = $1",
    )
    .bind(lease.event_id.as_str())
    .execute(pool)
    .await
    .unwrap();
    let ready = claim(pool, scope, limits, TYPES).await.unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].event_id, lease.event_id);
    assert_eq!(ready[0].delivery_attempts, 2);
    assert_eq!(ready[0].last_error_code.as_deref(), Some(ERROR_CODE));
    assert_ne!(ready[0].lease_token, lease.lease_token);
    rejected(pool, scope, lease).await;
}

async fn rejected(pool: &PgPool, scope: &Scope, lease: &OutboxLease) {
    let result = ack(pool, scope, &lease.event_id, &lease.lease_token)
        .await
        .unwrap();
    assert_eq!(result, Ack::Rejected);
    let result = fail(
        pool,
        scope,
        &lease.event_id,
        &lease.lease_token,
        ERROR_CODE,
        HOUR,
    )
    .await
    .unwrap();
    assert_eq!(result, Failure::Rejected);
}

async fn seed(pool: &PgPool, scope: &Scope, kind: &str, ordinal: i32) -> EventId {
    let event = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope, created_at)
         VALUES ($1, $2, $3, 'synthetic-outbox', $4, $5,
                 '2000-01-01'::timestamptz + make_interval(secs => $6::double precision))",
    )
    .bind(event.as_str())
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(kind)
    .bind(json!({"example_only": true, "padding": "合成".repeat(8)}))
    .bind(f64::from(ordinal))
    .execute(pool)
    .await
    .unwrap();
    event
}
