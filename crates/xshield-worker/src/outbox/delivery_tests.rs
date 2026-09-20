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
        (
            OutboxFamily::Identity,
            identity::EVENT_TYPES
                .iter()
                .map(|kind| identity::tests::event(kind))
                .collect(),
        ),
        (OutboxFamily::Grant, vec![grant::tests::event()]),
        (
            OutboxFamily::ResponseGrant,
            vec![response_grant::tests::event()],
        ),
        (OutboxFamily::ShareGrant, vec![share_grant::tests::event()]),
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
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope) VALUES ($1,$2,$3,'binding','binding.revoked','{}')")
        .bind(&other_id).bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str())
        .execute(pool).await.unwrap();

    for (family, count) in [
        (OutboxFamily::Case, 3),
        (OutboxFamily::EvidenceCatalog, 2),
        (OutboxFamily::EvidenceAccess, 3),
        (OutboxFamily::Identity, 4),
        (OutboxFamily::Grant, 1),
        (OutboxFamily::ResponseGrant, 1),
        (OutboxFamily::ShareGrant, 1),
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
    assert_eq!(published, 15);
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

    for field in [
        "binding_id",
        "tenant_id",
        "site_id",
        "event_id",
        "event_type",
    ] {
        let mut envelope = identity::tests::event("binding.created");
        if field == "binding_id" {
            envelope["payload"]["binding_id"] = json!(format!("auth_{}", Uuid::now_v7()));
        }
        let stored = insert_event(pool, scope, OutboxFamily::Identity, envelope).await;
        let id = stored["event_id"].as_str().unwrap();
        let mut mismatched = stored.clone();
        if field == "binding_id" {
            mismatched["payload"][field] = json!(format!("auth_{}", Uuid::now_v7()));
        } else {
            mismatched[field] = match field {
                "event_id" => json!(format!("ev_{}", Uuid::now_v7())),
                "event_type" => json!("epoch.changed"),
                _ => json!("other_scope"),
            };
        }
        sqlx::query("UPDATE xshield.audit_outbox SET envelope = $2 WHERE event_id = $1")
            .bind(id)
            .bind(mismatched)
            .execute(pool)
            .await
            .unwrap();
        let mock = test::Mock::new();
        assert!(
            publish_identity_outbox_batch(
                &store,
                &Client::default().with_mock(&mock),
                scope,
                &config
            )
            .await
            .is_err()
        );
        assert_failure(pool, id, INVALID_EVENT_CODE).await;
    }

    let legacy_id = format!("ev_{}", Uuid::now_v7());
    let legacy = json!({"schema_version":3,"event_id":legacy_id,"event_type":"session.created","binding_id":"auth_018f2a3b-4c5d-7000-8000-000000000011"});
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope) VALUES ($1,$2,$3,$4,'session.created',$5)")
        .bind(&legacy_id).bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str())
        .bind(legacy["binding_id"].as_str().unwrap()).bind(&legacy).execute(pool).await.unwrap();
    let mock = test::Mock::new();
    assert!(
        publish_identity_outbox_batch(&store, &Client::default().with_mock(&mock), scope, &config)
            .await
            .is_err()
    );
    assert_failure(pool, &legacy_id, INVALID_EVENT_CODE).await;
    let preserved: Value =
        sqlx::query_scalar("SELECT envelope FROM xshield.audit_outbox WHERE event_id = $1")
            .bind(&legacy_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(preserved, legacy);

    for (family, envelope) in [
        (OutboxFamily::Grant, grant::tests::event()),
        (OutboxFamily::ResponseGrant, response_grant::tests::event()),
        (OutboxFamily::ShareGrant, share_grant::tests::event()),
    ] {
        for sparse in [false, true] {
            let stored = insert_event(pool, scope, family, envelope.clone()).await;
            let id = stored["event_id"].as_str().unwrap();
            let mut invalid = stored.clone();
            if sparse {
                invalid = json!({"schema_version": 3, "event_type": stored["event_type"],
                "event_id": id, family.aggregate_field(): stored["payload"][family.aggregate_field()]});
            } else {
                sqlx::query(
                    "UPDATE xshield.audit_outbox SET aggregate_ref = $2 WHERE event_id = $1",
                )
                .bind(id)
                .bind(format!("mismatched_{}", Uuid::now_v7()))
                .execute(pool)
                .await
                .unwrap();
            }
            sqlx::query("UPDATE xshield.audit_outbox SET envelope = $2 WHERE event_id = $1")
                .bind(id)
                .bind(&invalid)
                .execute(pool)
                .await
                .unwrap();
            let mock = test::Mock::new();
            assert!(
                publish_outbox_batch(
                    &store,
                    &Client::default().with_mock(&mock),
                    scope,
                    &config,
                    family
                )
                .await
                .is_err()
            );
            assert_failure(pool, id, INVALID_EVENT_CODE).await;
            let preserved: Value =
                sqlx::query_scalar("SELECT envelope FROM xshield.audit_outbox WHERE event_id = $1")
                    .bind(id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(preserved, invalid);
        }
    }

    for field in ["tenant_id", "site_id"] {
        let mut invalid =
            insert_event(pool, scope, OutboxFamily::Grant, grant::tests::event()).await;
        invalid[field] = json!("foreign_scope");
        let id = invalid["event_id"].as_str().unwrap();
        sqlx::query("UPDATE xshield.audit_outbox SET envelope = $2 WHERE event_id = $1")
            .bind(id)
            .bind(&invalid)
            .execute(pool)
            .await
            .unwrap();
        let mock = test::Mock::new();
        assert!(
            publish_grant_outbox_batch(
                &store,
                &Client::default().with_mock(&mock),
                scope,
                &config,
            )
            .await
            .is_err(),
            "accepted cross-scope {field}"
        );
        assert_failure(pool, id, INVALID_EVENT_CODE).await;
        let preserved: Value =
            sqlx::query_scalar("SELECT envelope FROM xshield.audit_outbox WHERE event_id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(preserved, invalid);
    }
}

/// Consumes the real synthetic transactions left by `test_gateway_identity.sh`.
#[tokio::test]
#[ignore = "requires the private database owned by scripts/test_gateway_identity.sh"]
async fn postgres_gateway_identity_outbox_publishing() {
    let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(database.starts_with("xshield_gateway_"));
    let scope = OutboxScope::new(
        &TenantId::parse("tenant_gateway").unwrap(),
        &SiteId::parse("site_gateway").unwrap(),
    );
    let envelopes: Vec<Value> = sqlx::query_scalar("SELECT envelope FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2 AND event_type = ANY($3) ORDER BY created_at, event_id")
        .bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str()).bind(identity::EVENT_TYPES)
        .fetch_all(&pool).await.unwrap();
    assert!((4..=256).contains(&envelopes.len()));
    for kind in identity::EVENT_TYPES {
        assert!(
            envelopes
                .iter()
                .any(|envelope| envelope["event_type"] == *kind),
            "missing {kind}"
        );
    }
    let expected = envelopes
        .iter()
        .map(|envelope| {
            (
                envelope["event_id"].as_str().unwrap().to_owned(),
                hex(&sha256_digest(&serde_json::to_vec(envelope).unwrap())),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mock = test::Mock::new();
    let mut insertions = Vec::new();
    for _ in &envelopes {
        mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
        insertions.push(mock.add(test::handlers::record::<IndexRow>()));
        mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
    }
    let config = OutboxPublisherConfig::new(
        "audit_events",
        30,
        OutboxLeaseConfig::new(256, 1_048_576, Duration::from_mins(1)).unwrap(),
        Duration::from_mins(1),
    )
    .unwrap();
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let report =
        publish_identity_outbox_batch(&store, &Client::default().with_mock(&mock), &scope, &config)
            .await
            .unwrap();
    assert_eq!(report.published, expected.len());
    for insertion in insertions {
        let rows = insertion.collect::<Vec<IndexRow>>().await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].content_digest.as_slice(),
            expected[&rows[0].event_id].as_bytes()
        );
        assert_eq!(rows[0].stage, "identity_lifecycle");
        assert_eq!(rows[0].is_terminal, 0);
        assert_eq!(rows[0].confidence, None);
    }
    assert_eq!(
        publish_identity_outbox_batch(&store, &Client::default().with_mock(&mock), &scope, &config)
            .await
            .unwrap()
            .claimed,
        0
    );
    let published: i64 = sqlx::query_scalar("SELECT count(*) FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2 AND event_type = ANY($3) AND published_at IS NOT NULL AND lease_token IS NULL")
        .bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str()).bind(identity::EVENT_TYPES)
        .fetch_one(&pool).await.unwrap();
    assert_eq!(published, i64::try_from(expected.len()).unwrap());
    pool.close().await;
}

pub(super) async fn insert_event(
    pool: &PgPool,
    scope: &OutboxScope,
    family: OutboxFamily,
    mut event: Value,
) -> Value {
    event["event_id"] = json!(format!("ev_{}", Uuid::now_v7()));
    event["tenant_id"] = json!(scope.tenant_id().as_str());
    event["site_id"] = json!(scope.site_id().as_str());
    if matches!(family, OutboxFamily::Grant | OutboxFamily::ShareGrant) {
        event["producer_boot_id"] = event["event_id"].clone();
    }
    if matches!(family, OutboxFamily::ShareGrant) {
        event["payload"]["share_id"] = json!(format!(
            "share_{}",
            event["event_id"]
                .as_str()
                .unwrap()
                .strip_prefix("ev_")
                .unwrap()
        ));
    }
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
