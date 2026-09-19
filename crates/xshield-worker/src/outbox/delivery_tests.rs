//! Real `PostgreSQL` leases paired with a controlled `ClickHouse` HTTP protocol.

use super::{tests::*, *};
use crate::ExistingDigest;
use clickhouse::test;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use xshield_core::domain::{SiteId, TenantId};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn postgres_outbox_publishing_is_scoped_acknowledged_and_retryable() {
    let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    let scope = OutboxScope::new(
        &TenantId::parse(format!("tenant_outbox_{}", Uuid::now_v7().simple())).unwrap(),
        &SiteId::parse("site_outbox_worker").unwrap(),
    );
    let test_pool = pool.clone();
    let test_scope = scope.clone();
    let result =
        tokio::spawn(async move { exercise_delivery(&test_pool, &test_scope).await }).await;
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2")
        .bind(scope.tenant_id().as_str())
        .bind(scope.site_id().as_str())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    if let Err(error) = result {
        std::panic::resume_unwind(error.into_panic());
    }
}

// Keep the successful passes and subsequent failure/retry receipts in order.
#[allow(clippy::too_many_lines)]
async fn exercise_delivery(pool: &PgPool, scope: &OutboxScope) {
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let config = OutboxPublisherConfig::new(
        "audit_events",
        30,
        OutboxLeaseConfig::new(16, 64 * 1024, Duration::from_mins(1)).unwrap(),
        Duration::from_hours(1),
    )
    .unwrap();
    let mut expected = BTreeMap::new();
    for (family, envelopes) in [
        (
            OutboxFamily::Case,
            vec![
                event("case.created"),
                event("case.closed"),
                event("case.evidence.added"),
            ],
        ),
        (
            OutboxFamily::EvidenceCatalog,
            vec![
                catalog_event("gateway-evidence-catalog"),
                catalog_event("model-eval"),
            ],
        ),
        (
            OutboxFamily::EvidenceAccess,
            vec![
                access_request_event(),
                access_decision_event("evidence.access.approved"),
                access_decision_event("evidence.access.denied"),
            ],
        ),
    ] {
        for envelope in envelopes {
            let stored = insert_event(pool, scope, family, envelope).await;
            expected.insert(
                stored["event_id"].as_str().unwrap().to_owned(),
                hex(&sha256_digest(&serde_json::to_vec(&stored).unwrap())),
            );
        }
    }
    let other_id = format!("ev_{}", Uuid::now_v7());
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope) VALUES ($1,$2,$3,'anonymous','session.created','{}')")
        .bind(&other_id).bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str())
        .execute(pool).await.unwrap();

    for (family, count) in [
        (OutboxFamily::Case, 3),
        (OutboxFamily::EvidenceCatalog, 2),
        (OutboxFamily::EvidenceAccess, 3),
    ] {
        let mock = test::Mock::new();
        let mut insertions = Vec::new();
        for _ in 0..count {
            mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
            insertions.push(mock.add(test::handlers::record::<IndexRow>()));
            mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
        }
        let client = Client::default().with_mock(&mock);
        let report = publish_outbox_batch(&store, &client, scope, &config, family)
            .await
            .unwrap();
        assert_eq!(
            report,
            OutboxPublishReport {
                claimed: count,
                published: count
            }
        );
        for insertion in insertions {
            let rows: Vec<IndexRow> = insertion.collect().await;
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].content_digest.as_slice(),
                expected[&rows[0].event_id].as_bytes()
            );
            assert_eq!(rows[0].confidence, None);
            assert_eq!(rows[0].confidence_status, "not_applicable");
            assert_eq!(rows[0].is_terminal, 0);
        }
        assert_eq!(
            publish_outbox_batch(&store, &client, scope, &config, family)
                .await
                .unwrap()
                .claimed,
            0
        );
    }
    let published: i64 = sqlx::query_scalar("SELECT count(*) FROM xshield.audit_outbox WHERE tenant_id = $1 AND published_at IS NOT NULL AND lease_token IS NULL")
        .bind(scope.tenant_id().as_str()).fetch_one(pool).await.unwrap();
    assert_eq!(published, 8);
    let attempts: i32 = sqlx::query_scalar(
        "SELECT delivery_attempts FROM xshield.audit_outbox WHERE event_id = $1",
    )
    .bind(&other_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(attempts, 0);

    let retry = insert_event(
        pool,
        scope,
        OutboxFamily::EvidenceAccess,
        access_request_event(),
    )
    .await;
    let retry_id = retry["event_id"].as_str().unwrap();
    let mock = test::Mock::new();
    mock.add(test::handlers::exception(209));
    assert!(matches!(
        publish_evidence_access_outbox_batch(
            &store,
            &Client::default().with_mock(&mock),
            scope,
            &config
        )
        .await,
        Err(PublishError::ClickHouse(_))
    ));
    assert_failure(pool, retry_id, INDEX_UNAVAILABLE_CODE).await;
    sqlx::query("UPDATE xshield.audit_outbox SET next_attempt_at = clock_timestamp() - interval '1 second' WHERE event_id = $1")
        .bind(retry_id).execute(pool).await.unwrap();
    let mock = test::Mock::new();
    mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
    let insertion = mock.add(test::handlers::record::<IndexRow>());
    mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
    assert_eq!(
        publish_evidence_access_outbox_batch(
            &store,
            &Client::default().with_mock(&mock),
            scope,
            &config
        )
        .await
        .unwrap()
        .published,
        1
    );
    assert_eq!(
        insertion.collect::<Vec<IndexRow>>().await[0].event_id,
        retry_id
    );

    for after_insert in [false, true] {
        let envelope = insert_event(
            pool,
            scope,
            OutboxFamily::EvidenceAccess,
            access_decision_event("evidence.access.denied"),
        )
        .await;
        let id = envelope["event_id"].as_str().unwrap();
        let mock = test::Mock::new();
        let insertion = if after_insert {
            mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
            Some(mock.add(test::handlers::record::<IndexRow>()))
        } else {
            None
        };
        mock.add(test::handlers::provide([ExistingDigest {
            event_id: id.to_owned(),
            content_digest: [b'0'; 64],
            digest_count: 1,
        }]));
        assert!(matches!(
            publish_evidence_access_outbox_batch(
                &store,
                &Client::default().with_mock(&mock),
                scope,
                &config
            )
            .await,
            Err(PublishError::IntegrityConflict)
        ));
        if let Some(insertion) = insertion {
            assert_eq!(insertion.collect::<Vec<IndexRow>>().await.len(), 1);
        }
        assert_failure(pool, id, INTEGRITY_CONFLICT_CODE).await;
    }

    let invalid = insert_event(
        pool,
        scope,
        OutboxFamily::EvidenceCatalog,
        catalog_event("model-eval"),
    )
    .await;
    let invalid_id = invalid["event_id"].as_str().unwrap();
    sqlx::query("UPDATE xshield.audit_outbox SET aggregate_ref = $2 WHERE event_id = $1")
        .bind(invalid_id)
        .bind(format!("artifact_{}", Uuid::now_v7()))
        .execute(pool)
        .await
        .unwrap();
    let mock = test::Mock::new();
    assert!(matches!(
        publish_evidence_catalog_outbox_batch(
            &store,
            &Client::default().with_mock(&mock),
            scope,
            &config
        )
        .await,
        Err(PublishError::InvalidEvent)
    ));
    assert_failure(pool, invalid_id, INVALID_EVENT_CODE).await;
}

async fn insert_event(
    pool: &PgPool,
    scope: &OutboxScope,
    family: OutboxFamily,
    mut event: Value,
) -> Value {
    event["event_id"] = json!(format!("ev_{}", Uuid::now_v7()));
    event["tenant_id"] = json!(scope.tenant_id().as_str());
    event["site_id"] = json!(scope.site_id().as_str());
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(event["event_id"].as_str().unwrap()).bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str())
        .bind(event["payload"][family.aggregate_field()].as_str().unwrap()).bind(event["event_type"].as_str().unwrap())
        .bind(&event).execute(pool).await.unwrap();
    event
}

async fn assert_failure(pool: &PgPool, event_id: &str, code: &str) {
    let row = sqlx::query("SELECT published_at IS NULL AND lease_token IS NULL AND lease_until IS NULL AND next_attempt_at > clock_timestamp() AS retryable, last_error_code FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(event_id).fetch_one(pool).await.unwrap();
    assert!(row.get::<bool, _>("retryable"));
    assert_eq!(row.get::<String, _>("last_error_code"), code);
}
