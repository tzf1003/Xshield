use sqlx::{PgPool, Postgres, Transaction};
use std::{env, time::Duration};
use xshield_core::{
    domain::{RequestId, SiteId, TenantId},
    identity::UnixSeconds,
};
use xshield_postgres::{PostgresIdentityStore, RequestCryptoMessage, RequestCryptoMessageOutcome};

const TENANT: &str = "tenant_replay_clock";
const SITE: &str = "site_replay_clock";

async fn database_now(pool: &PgPool) -> u64 {
    u64::try_from(
        sqlx::query_scalar::<_, i64>("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(pool)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn consume(
    store: &PostgresIdentityStore,
    id: u64,
    nonce: u8,
    now: u64,
    expires_at: u64,
    capacity: u32,
) -> RequestCryptoMessageOutcome {
    let tenant = TenantId::parse(TENANT).unwrap();
    let site = SiteId::parse(SITE).unwrap();
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
    let message = format!("msg_018f2a3b-4c5d-7000-8000-{id:012}");
    store
        .consume_request_crypto_message(
            RequestCryptoMessage::new(
                &tenant,
                &site,
                "request-key-r1",
                &message,
                &[nonce; 12],
                &request,
                UnixSeconds::new(expires_at),
                UnixSeconds::new(now),
                capacity,
            )
            .unwrap(),
        )
        .await
        .unwrap()
}

async fn count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM xshield.request_crypto_messages WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(TENANT)
    .bind(SITE)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn release_after_expiry(
    pool: &PgPool,
    mut blocker: Transaction<'_, Postgres>,
    expires_at: u64,
) {
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    // Eventually-true observation of the lock queue: generous so a loaded machine
    // does not fail the test; a real regression still fails at the bound.
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("consumer must reach the held lock");
    sqlx::query(
        "SELECT pg_sleep(GREATEST(0, $1::double precision + 0.05 - extract(epoch FROM clock_timestamp())))",
    )
    .bind(i64::try_from(expires_at).unwrap())
    .execute(&mut *blocker)
    .await
    .unwrap();
    blocker.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn replay_consumption_respects_clocks_locks_and_atomic_cleanup() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL required");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let now = database_now(&pool).await;
    let expires = now + 300;
    assert_eq!(
        consume(&store, 1, 1, now, expires, 2).await,
        RequestCryptoMessageOutcome::Consumed
    );
    let (left, right) = tokio::join!(
        consume(&store, 2, 2, now, expires, 10),
        consume(&store, 2, 2, now, expires, 10),
    );
    assert!(matches!(
        (left, right),
        (
            RequestCryptoMessageOutcome::Consumed,
            RequestCryptoMessageOutcome::Replayed
        ) | (
            RequestCryptoMessageOutcome::Replayed,
            RequestCryptoMessageOutcome::Consumed
        )
    ));
    for (id, nonce) in [(3, 1), (1, 3)] {
        assert_eq!(
            consume(&store, id, nonce, now, expires, 10).await,
            RequestCryptoMessageOutcome::Replayed
        );
    }
    // The fast edge must not evict either live nonce to make capacity.
    assert_eq!(
        consume(&store, 4, 4, now + 400, now + 600, 2).await,
        RequestCryptoMessageOutcome::CapacityExceeded
    );
    assert_eq!(
        consume(&store, 1, 1, now, expires, 10).await,
        RequestCryptoMessageOutcome::Replayed
    );
    assert_eq!(
        consume(&store, 5, 5, now - 100, now - 1, 10).await,
        RequestCryptoMessageOutcome::Expired
    );
    assert_eq!(count(&pool).await, 2);

    for insert_wait in [false, true] {
        // This expired sentinel proves cleanup also rolls back on late expiry.
        sqlx::query(
            "INSERT INTO xshield.request_crypto_messages VALUES
             ($1, $2, 'request-key-r1', 'msg_018f2a3b-4c5d-7000-8000-000000000009',
              $3, 'req_018f2a3b-4c5d-7000-8000-000000000001', to_timestamp($4), to_timestamp($5))
             ON CONFLICT DO NOTHING",
        )
        .bind(TENANT)
        .bind(SITE)
        .bind([9_u8; 12].as_slice())
        .bind(i64::try_from(now - 1).unwrap())
        .bind(i64::try_from(now - 100).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        if insert_wait {
            sqlx::query(
                "INSERT INTO xshield.request_crypto_messages VALUES
                 ($1, $2, 'request-key-r1', 'msg_018f2a3b-4c5d-7000-8000-000000000008',
                  $3, 'req_018f2a3b-4c5d-7000-8000-000000000001', to_timestamp($4), to_timestamp($5))",
            )
            .bind(TENANT).bind(SITE).bind([8_u8; 12].as_slice())
            .bind(i64::try_from(expires).unwrap()).bind(i64::try_from(now).unwrap())
            .execute(&mut *blocker).await.unwrap();
        } else {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('xshield-request-crypto-v1:' || $1 || ':' || $2, 0))")
                .bind(TENANT).bind(SITE).execute(&mut *blocker).await.unwrap();
        }
        let deadline = database_now(&pool).await + 3;
        let (outcome, ()) = tokio::time::timeout(Duration::from_secs(8), async {
            tokio::join!(
                consume(&store, 8, 8, now, deadline, 10),
                release_after_expiry(&pool, blocker, deadline),
            )
        })
        .await
        .expect("expired consumer must finish after releasing the lock");
        assert_eq!(outcome, RequestCryptoMessageOutcome::Expired);
        assert_eq!(count(&pool).await, 3);
    }
    assert_eq!(
        consume(&store, 6, 6, now, expires, 3).await,
        RequestCryptoMessageOutcome::Consumed
    );
    assert_eq!(count(&pool).await, 3);
}
