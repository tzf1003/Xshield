//! Publishes durable calibration facts through the production `ClickHouse` DDL.
//!
//! The preceding `scripts/test_postgres.sh` producer regressions leave only the
//! temporary database's immutable calibration facts. This test consumes those
//! facts without manufacturing an envelope, so it verifies the complete
//! `PostgreSQL` producer, strict outbox parser, index and acknowledgement path.

use super::{clickhouse_tests::with_clickhouse, *};
use chrono::{DateTime, Utc};
use clickhouse::sql::Identifier;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use xshield_core::domain::{SiteId, TenantId};

/// The user-facing calibration lifecycle has four event types from the
/// lineage-review, capability-issuance, and report-completion transactions.
/// They are the prerequisites a scope must have to be worth publishing here
/// and select the scopes under test. Everything else the publisher delivers
/// for the family (the report-retention events the report regression commits in
/// the same scope, for example) is checked too, through `calibration::EVENT_TYPES`,
/// because the publisher cannot tell them apart and claims the whole scope.
const LIFECYCLE_EVENT_TYPES: [&str; 4] = [
    "calibration.partition_lineage.reviewed",
    "calibration.read_capability.issued",
    "calibration.read_batch.completed",
    "calibration.reported",
];

#[tokio::test]
#[ignore = "requires scripts/test_postgres.sh and XSHIELD_TEST_CLICKHOUSE_URL"]
async fn real_calibration_outbox_clickhouse_delivery() {
    let pool = PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(database.starts_with("xshield_test_"));
    let scopes = committed_calibration_scopes(&pool).await;
    assert!(
        !scopes.is_empty(),
        "the producer regressions must commit a complete calibration lifecycle"
    );
    let task_pool = pool.clone();
    let result = with_clickhouse(move |client| async move {
        for (tenant, site) in scopes {
            publish_scope(&task_pool, &client, OutboxScope::new(&tenant, &site)).await;
        }
    })
    .await;
    pool.close().await;
    result.unwrap();
}

async fn committed_calibration_scopes(pool: &PgPool) -> Vec<(TenantId, SiteId)> {
    let rows = sqlx::query(
        "SELECT tenant_id, site_id
         FROM xshield.audit_outbox
         WHERE event_type = ANY($1::text[])
         GROUP BY tenant_id, site_id
         HAVING bool_or(event_type = 'calibration.partition_lineage.reviewed')
            AND bool_or(event_type = 'calibration.read_capability.issued')
            AND bool_or(event_type = 'calibration.read_batch.completed')
            AND bool_or(event_type = 'calibration.reported')
         ORDER BY tenant_id, site_id",
    )
    .bind(LIFECYCLE_EVENT_TYPES)
    .fetch_all(pool)
    .await
    .unwrap();
    rows.into_iter()
        .map(|row| {
            (
                TenantId::parse(row.get::<String, _>("tenant_id")).unwrap(),
                SiteId::parse(row.get::<String, _>("site_id")).unwrap(),
            )
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
async fn publish_scope(pool: &PgPool, client: &Client, scope: OutboxScope) {
    let expected = committed_envelopes(pool, &scope).await;
    let event_types = expected
        .values()
        .map(|event| event["event_type"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert!(
        LIFECYCLE_EVENT_TYPES
            .iter()
            .all(|event_type| event_types.contains(event_type))
    );
    // Retention events originate in the retention queue, which its own regression ties to
    // committed state; only the lifecycle facts are checked against their source rows here.
    let lifecycle: BTreeMap<String, Value> = expected
        .iter()
        .filter(|(_, event)| LIFECYCLE_EVENT_TYPES.contains(&event["event_type"].as_str().unwrap()))
        .map(|(id, event)| (id.clone(), event.clone()))
        .collect();
    assert_committed_source_rows(pool, &scope, &lifecycle).await;

    let store = PostgresIdentityStore::from_pool(pool.clone());
    let config = OutboxPublisherConfig::new(
        "audit_events",
        30,
        OutboxLeaseConfig::new(256, 1_048_576, Duration::from_mins(1)).unwrap(),
        Duration::from_mins(1),
    )
    .unwrap();
    let mut published = 0;
    loop {
        let report = publish_calibration_outbox_batch(&store, client, &scope, &config)
            .await
            .unwrap();
        assert_eq!(report.claimed, report.published);
        published += report.published;
        if report.claimed == 0 {
            break;
        }
    }
    assert_eq!(published, expected.len());
    assert_acknowledged(pool, &scope, expected.len()).await;
    assert_index_rows(client, &scope, &expected).await;
    assert_lost_ack_and_conflict(pool, client, &store, &scope, &config, &expected).await;
}

async fn committed_envelopes(pool: &PgPool, scope: &OutboxScope) -> BTreeMap<String, Value> {
    let rows = sqlx::query(
        "SELECT event_id, envelope
         FROM xshield.audit_outbox
         WHERE tenant_id=$1 AND site_id=$2 AND event_type = ANY($3::text[])
         ORDER BY created_at, event_id",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(calibration::EVENT_TYPES)
    .fetch_all(pool)
    .await
    .unwrap();
    let mut expected = BTreeMap::new();
    for row in rows {
        let event_id: String = row.get("event_id");
        let envelope: Value = row.get("envelope");
        assert_eq!(envelope["event_id"], event_id);
        assert_eq!(envelope["tenant_id"], scope.tenant_id().as_str());
        assert_eq!(envelope["site_id"], scope.site_id().as_str());
        assert!(
            expected.insert(event_id, envelope).is_none(),
            "calibration event IDs are unique within the outbox"
        );
    }
    expected
}

async fn assert_committed_source_rows(
    pool: &PgPool,
    scope: &OutboxScope,
    expected: &BTreeMap<String, Value>,
) {
    for (event_id, event) in expected {
        let found: bool = match event["event_type"].as_str().unwrap() {
            "calibration.partition_lineage.reviewed" => sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM xshield.calibration_lineage_reviews
                     WHERE tenant_id=$1 AND site_id=$2 AND reviewed_event_id=$3
                 )",
            )
            .bind(scope.tenant_id().as_str())
            .bind(scope.site_id().as_str())
            .bind(event_id)
            .fetch_one(pool)
            .await
            .unwrap(),
            "calibration.read_capability.issued" => sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM xshield.calibration_read_capabilities
                     WHERE tenant_id=$1 AND site_id=$2 AND issued_event_id=$3
                 )",
            )
            .bind(scope.tenant_id().as_str())
            .bind(scope.site_id().as_str())
            .bind(event_id)
            .fetch_one(pool)
            .await
            .unwrap(),
            "calibration.read_batch.completed" => sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM xshield.calibration_read_capabilities
                     WHERE tenant_id=$1 AND site_id=$2 AND completion_event_id=$3
                 )",
            )
            .bind(scope.tenant_id().as_str())
            .bind(scope.site_id().as_str())
            .bind(event_id)
            .fetch_one(pool)
            .await
            .unwrap(),
            "calibration.reported" => sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM xshield.calibration_reports
                     WHERE tenant_id=$1 AND site_id=$2 AND reported_event_id=$3
                 )",
            )
            .bind(scope.tenant_id().as_str())
            .bind(scope.site_id().as_str())
            .bind(event_id)
            .fetch_one(pool)
            .await
            .unwrap(),
            unexpected => panic!("unexpected calibration event type: {unexpected}"),
        };
        assert!(found, "outbox event must originate from committed state");
    }
}

async fn assert_acknowledged(pool: &PgPool, scope: &OutboxScope, count: usize) {
    let acknowledged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.audit_outbox
         WHERE tenant_id=$1 AND site_id=$2 AND event_type = ANY($3::text[])
           AND published_at IS NOT NULL AND lease_token IS NULL AND lease_until IS NULL
           AND delivery_attempts=1 AND last_error_code IS NULL",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(calibration::EVENT_TYPES)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(usize::try_from(acknowledged).unwrap(), count);
}

async fn assert_index_rows(
    client: &Client,
    scope: &OutboxScope,
    expected: &BTreeMap<String, Value>,
) {
    for table in [
        "audit_events",
        "events_by_time",
        "audit_events_active",
        "events_by_time_active",
    ] {
        let rows = client
            .query("SELECT ?fields FROM ? WHERE tenant_id=? AND site_id=?")
            .bind(Identifier(table))
            .bind(scope.tenant_id().as_str())
            .bind(scope.site_id().as_str())
            .fetch_all::<IndexRow>()
            .await
            .unwrap();
        assert_eq!(rows.len(), expected.len());
        for row in rows {
            let event = &expected[&row.event_id];
            assert_eq!(row.event_type, event["event_type"]);
            assert_eq!(row.stage, event["payload"]["stage"]);
            assert_eq!(row.outcome, event["payload"]["outcome"]);
            assert_eq!(row.reason_code, event["payload"]["reason_code"]);
            assert_eq!(row.producer_id, event["producer_id"]);
            assert_eq!(row.tenant_id, scope.tenant_id().as_str());
            assert_eq!(row.site_id, scope.site_id().as_str());
            assert_eq!(row.request_id, "");
            assert_eq!(row.confidence, None);
            assert_eq!(row.confidence_status, "not_applicable");
            assert_eq!(row.proof_kind, "deterministic");
            assert_eq!(row.is_terminal, 0);
            assert_eq!(
                serde_json::from_str::<Value>(&row.payload_json).unwrap(),
                event["payload"]
            );
            assert_restricted_payload(&row.payload_json);
            assert_eq!(
                serde_json::to_value(&row.evidence_refs).unwrap(),
                event["evidence_refs"]
            );
            assert_eq!(
                serde_json::to_value(&row.cause_event_ids).unwrap(),
                event["cause_event_ids"]
            );
            assert_eq!(
                row.occurred_at,
                DateTime::parse_from_rfc3339(event["occurred_at"].as_str().unwrap())
                    .unwrap()
                    .with_timezone(&Utc)
            );
            assert_eq!(row.observed_at, row.occurred_at);
            assert_eq!(
                row.retention_expires_at,
                row.occurred_at + TimeDelta::days(30)
            );
            let digest = hex(&sha256_digest(&serde_json::to_vec(event).unwrap()));
            assert_eq!(row.content_digest.as_slice(), digest.as_bytes());
            assert_eq!(row.event_hash, digest);
        }
    }
}

fn assert_restricted_payload(payload: &str) {
    let value: Value = serde_json::from_str(payload).unwrap();
    let object = value.as_object().unwrap();
    for forbidden in [
        "source_graph",
        "source_graph_digest",
        "samples",
        "labels",
        "metrics",
        "probabilities",
        "prompt",
        "body",
    ] {
        assert!(
            !object.contains_key(forbidden),
            "restricted calibration payload must not expose {forbidden}"
        );
    }
}

async fn assert_lost_ack_and_conflict(
    pool: &PgPool,
    client: &Client,
    store: &PostgresIdentityStore,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
    expected: &BTreeMap<String, Value>,
) {
    let (event_id, source) = expected
        .iter()
        .find(|(_, event)| event["event_type"] == "calibration.reported")
        .unwrap();
    sqlx::query(
        "UPDATE xshield.audit_outbox
         SET published_at=NULL, next_attempt_at=clock_timestamp()
         WHERE tenant_id=$1 AND site_id=$2 AND event_id=$3",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(event_id)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        publish_calibration_outbox_batch(store, client, scope, config)
            .await
            .unwrap(),
        OutboxPublishReport {
            claimed: 1,
            published: 1
        }
    );
    for (table, count) in [
        ("audit_events", 2),
        ("events_by_time", 2),
        ("audit_events_active", 1),
        ("events_by_time_active", 1),
    ] {
        let actual = client
            .query("SELECT count() FROM ? WHERE event_id=?")
            .bind(Identifier(table))
            .bind(event_id)
            .fetch_one::<u64>()
            .await
            .unwrap();
        assert_eq!(actual, count);
    }

    let mut changed = source.clone();
    changed["payload"]["approval_ref"] = json!("approval-conflict-r1");
    sqlx::query(
        "UPDATE xshield.audit_outbox
         SET envelope=$4, published_at=NULL, next_attempt_at=clock_timestamp()
         WHERE tenant_id=$1 AND site_id=$2 AND event_id=$3",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(event_id)
    .bind(&changed)
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        publish_calibration_outbox_batch(store, client, scope, config).await,
        Err(PublishError::IntegrityConflict)
    ));
    let retryable: bool = sqlx::query_scalar(
        "SELECT published_at IS NULL
            AND lease_token IS NULL
            AND lease_until IS NULL
            AND next_attempt_at > clock_timestamp()
            AND last_error_code = 'OUTBOX_INTEGRITY_CONFLICT'
            AND delivery_attempts = 3
         FROM xshield.audit_outbox
         WHERE tenant_id=$1 AND site_id=$2 AND event_id=$3",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(event_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(
        retryable,
        "conflicting retry remains unacknowledged and leased"
    );
    let conflicts = client
        .query("SELECT count() FROM audit_event_conflicts")
        .fetch_one::<u64>()
        .await
        .unwrap();
    assert_eq!(
        conflicts, 0,
        "conflicting retry must not create an index row"
    );
}
