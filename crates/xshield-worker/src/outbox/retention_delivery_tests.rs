//! Real retention and hold transactions delivered through the production index.

use super::{clickhouse_tests::with_clickhouse, *};
use chrono::DateTime;
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::collections::BTreeSet;
use uuid::Uuid;
use xshield_core::{
    domain::{EventId, SiteId, TenantId},
    identity::UnixSeconds,
    query::{QueryFilter, QueryPlan, QuerySort, QueryWindow},
};

#[tokio::test]
#[ignore = "requires scripts/test_postgres.sh and XSHIELD_TEST_CLICKHOUSE_URL"]
async fn real_retention_outbox_clickhouse_delivery() {
    let pool = PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(database.starts_with("xshield_test_"));
    let task_pool = pool.clone();
    let result = with_clickhouse(move |client| async move {
        exercise_delivery(&task_pool, &client).await;
    })
    .await;
    pool.close().await;
    result.unwrap();
}

#[allow(clippy::too_many_lines)]
async fn exercise_delivery(pool: &PgPool, client: &Client) {
    let scope = OutboxScope::new(
        &TenantId::parse("tenant_retention").unwrap(),
        &SiteId::parse("site_retention").unwrap(),
    );
    let records = sqlx::query("SELECT event_id, aggregate_ref, envelope FROM xshield.audit_outbox WHERE tenant_id=$1 AND site_id=$2 AND event_type=ANY($3::text[]) ORDER BY created_at,event_id")
        .bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str()).bind(EVIDENCE_RETENTION_EVENT_TYPES)
        .fetch_all(pool).await.unwrap();
    let expected: BTreeMap<String, Value> = records
        .iter()
        .map(|row| {
            let envelope: Value = row.get("envelope");
            assert_eq!(
                envelope["payload"]["artifact_id"].as_str().unwrap(),
                row.get::<&str, _>("aggregate_ref")
            );
            (row.get("event_id"), envelope)
        })
        .collect();
    assert_eq!(
        expected
            .values()
            .map(|event| event["event_type"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        EVIDENCE_RETENTION_EVENT_TYPES.iter().copied().collect()
    );
    let untouched = unrelated_rows(pool).await;
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let config = OutboxPublisherConfig::new(
        "audit_events",
        30,
        OutboxLeaseConfig::new(1, 64 * 1024, Duration::from_mins(1)).unwrap(),
        Duration::from_hours(1),
    )
    .unwrap();
    let unavailable = OutboxPublisherConfig {
        table: "unavailable_retention_index".to_owned(),
        ..config.clone()
    };
    assert!(matches!(
        publish_evidence_retention_outbox_batch(&store, client, &scope, &unavailable).await,
        Err(PublishError::ClickHouse(_))
    ));
    let failed: String = sqlx::query_scalar("SELECT event_id FROM xshield.audit_outbox WHERE tenant_id=$1 AND site_id=$2 AND last_error_code='OUTBOX_INDEX_UNAVAILABLE' AND published_at IS NULL AND lease_token IS NULL AND next_attempt_at>clock_timestamp()")
        .bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str()).fetch_one(pool).await.unwrap();
    make_ready(pool, &failed).await;
    let mut published = 0;
    for _ in 0..=expected.len() {
        let report = publish_evidence_retention_outbox_batch(&store, client, &scope, &config)
            .await
            .unwrap();
        assert_eq!(report.claimed, report.published);
        published += report.published;
        if report.claimed == 0 {
            break;
        }
    }
    assert_eq!(published, expected.len());
    let acknowledged: i64 = sqlx::query_scalar("SELECT count(*) FROM xshield.audit_outbox WHERE tenant_id=$1 AND site_id=$2 AND event_type=ANY($3::text[]) AND published_at IS NOT NULL AND lease_token IS NULL AND lease_until IS NULL")
        .bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str()).bind(EVIDENCE_RETENTION_EVENT_TYPES).fetch_one(pool).await.unwrap();
    assert_eq!(usize::try_from(acknowledged).unwrap(), expected.len());
    assert_eq!(unrelated_rows(pool).await, untouched);
    assert_index_and_query(client, &scope, &expected).await;

    // A lost ACK is recovered by the same immutable content and stable event ID.
    sqlx::query("UPDATE xshield.audit_outbox SET published_at=NULL,next_attempt_at=clock_timestamp() WHERE event_id=$1")
        .bind(&failed).execute(pool).await.unwrap();
    assert_eq!(
        publish_evidence_retention_outbox_batch(&store, client, &scope, &config)
            .await
            .unwrap()
            .published,
        1
    );
    for (table, count) in [("audit_events", 2), ("audit_events_active", 1)] {
        let actual = client
            .query("SELECT count() FROM ? WHERE event_id=?")
            .bind(clickhouse::sql::Identifier(table))
            .bind(&failed)
            .fetch_one::<u64>()
            .await
            .unwrap();
        assert_eq!(actual, count);
    }
    let deletion = expected
        .values()
        .find(|event| event["payload"]["stage"] == "evidence_retention")
        .unwrap();
    assert_scope_and_conflict(pool, client, &store, &scope, &config, deletion).await;
}

async fn unrelated_rows(pool: &PgPool) -> Vec<(String, i32)> {
    sqlx::query_as("SELECT event_id,delivery_attempts FROM xshield.audit_outbox WHERE event_type <> ALL($1::text[]) ORDER BY event_id")
        .bind(EVIDENCE_RETENTION_EVENT_TYPES).fetch_all(pool).await.unwrap()
}

async fn make_ready(pool: &PgPool, event_id: &str) {
    sqlx::query(
        "UPDATE xshield.audit_outbox SET next_attempt_at=clock_timestamp() WHERE event_id=$1",
    )
    .bind(event_id)
    .execute(pool)
    .await
    .unwrap();
}

#[allow(clippy::too_many_lines)]
async fn assert_index_and_query(
    client: &Client,
    scope: &OutboxScope,
    expected: &BTreeMap<String, Value>,
) {
    let rows = client
        .query("SELECT ?fields FROM audit_events_active")
        .fetch_all::<IndexRow>()
        .await
        .unwrap();
    assert_eq!(rows.len(), expected.len());
    let config = crate::PublisherConfig::new(
        "unused-journal",
        "unused-manifests",
        "unused-checkpoints",
        "retention-index",
        "audit_events",
        30,
        1024,
    )
    .unwrap();
    for row in rows {
        let event = &expected[&row.event_id];
        assert_eq!(row.event_type, event["event_type"]);
        assert_eq!(row.stage, event["payload"]["stage"]);
        assert_eq!(row.reason_code, event["payload"]["reason_code"]);
        assert_eq!(row.outcome, event["payload"]["outcome"]);
        assert_eq!(row.producer_id, event["producer_id"]);
        assert_eq!(row.tenant_id, scope.tenant_id().as_str());
        assert_eq!(row.site_id, scope.site_id().as_str());
        assert_eq!(row.request_id, "");
        assert_eq!(row.is_terminal, 0);
        assert_eq!(row.http_status, None);
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(
            serde_json::from_str::<Value>(&row.payload_json).unwrap(),
            event["payload"]
        );
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
            DateTime::parse_from_rfc3339(event["occurred_at"].as_str().unwrap()).unwrap()
        );
        assert_eq!(
            row.retention_expires_at,
            row.occurred_at + TimeDelta::days(30)
        );
        assert_eq!(
            row.event_hash,
            hex(&sha256_digest(&serde_json::to_vec(event).unwrap()))
        );
        let start = u64::try_from(row.occurred_at.timestamp()).unwrap();
        let plan = QueryPlan::new(
            QueryWindow::new(UnixSeconds::new(start), UnixSeconds::new(start + 1)).unwrap(),
            vec![QueryFilter::EventId(
                EventId::parse(row.event_id.clone()).unwrap(),
            )],
            QuerySort::OccurredAtAsc,
            1,
        )
        .unwrap();
        let found = crate::query_audit_events(
            &config,
            client,
            scope.tenant_id(),
            scope.site_id(),
            &plan,
            None,
        )
        .await
        .unwrap();
        assert_eq!(found.events.len(), 1);
        let summary = &found.events[0];
        assert_eq!(summary.request_id, None);
        assert_eq!(summary.stage.as_deref(), Some(row.stage.as_str()));
        assert_eq!(
            summary.reason_code.as_deref(),
            Some(row.reason_code.as_str())
        );
        assert_eq!(summary.evidence_refs, row.evidence_refs);
        assert_eq!(summary.cause_event_ids, row.cause_event_ids);
        assert!(
            !serde_json::to_string(summary)
                .unwrap()
                .contains("payload_json")
        );
        let foreign = crate::query_audit_events(
            &config,
            client,
            &TenantId::parse("tenant_retention_other").unwrap(),
            scope.site_id(),
            &plan,
            None,
        )
        .await
        .unwrap();
        assert!(foreign.events.is_empty());
    }
}

#[allow(clippy::too_many_lines)]
async fn assert_scope_and_conflict(
    pool: &PgPool,
    client: &Client,
    store: &PostgresIdentityStore,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
    source: &Value,
) {
    // Synthetic copies isolate lease scope and corrupted-source behavior from
    // the actual CLI deletion facts checked above.
    assert_eq!(source["payload"]["stage"], "evidence_retention");
    let mut foreign = source.clone();
    foreign["event_id"] = format!("ev_{}", Uuid::now_v7()).into();
    foreign["tenant_id"] = "tenant_retention_foreign".into();
    let foreign_id = foreign["event_id"].as_str().unwrap();
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(foreign_id).bind("tenant_retention_foreign").bind(scope.site_id().as_str()).bind(foreign["payload"]["artifact_id"].as_str().unwrap()).bind(foreign["event_type"].as_str().unwrap()).bind(&foreign).execute(pool).await.unwrap();
    assert_eq!(
        publish_evidence_retention_outbox_batch(store, client, scope, config)
            .await
            .unwrap()
            .claimed,
        0
    );
    let attempts: i32 =
        sqlx::query_scalar("SELECT delivery_attempts FROM xshield.audit_outbox WHERE event_id=$1")
            .bind(foreign_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(attempts, 0);
    let mut changed = source.clone();
    let id = changed["event_id"].as_str().unwrap().to_owned();
    changed["payload"]["source_request_id"] = format!("req_{}", Uuid::now_v7()).into();
    sqlx::query("UPDATE xshield.audit_outbox SET envelope=$2,published_at=NULL,next_attempt_at=clock_timestamp() WHERE event_id=$1")
        .bind(&id).bind(&changed).execute(pool).await.unwrap();
    assert!(matches!(
        publish_evidence_retention_outbox_batch(store, client, scope, config).await,
        Err(PublishError::IntegrityConflict)
    ));
    let pending:bool=sqlx::query_scalar("SELECT published_at IS NULL AND lease_token IS NULL AND last_error_code='OUTBOX_INTEGRITY_CONFLICT' FROM xshield.audit_outbox WHERE event_id=$1")
        .bind(&id).fetch_one(pool).await.unwrap();
    assert!(pending);
    let mut invalid = source.clone();
    invalid["payload"]["retained_metadata"] = false.into();
    sqlx::query("UPDATE xshield.audit_outbox SET envelope=$2,next_attempt_at=clock_timestamp() WHERE event_id=$1")
        .bind(&id).bind(&invalid).execute(pool).await.unwrap();
    assert!(matches!(
        publish_evidence_retention_outbox_batch(store, client, scope, config).await,
        Err(PublishError::InvalidEvent)
    ));
    let code: String =
        sqlx::query_scalar("SELECT last_error_code FROM xshield.audit_outbox WHERE event_id=$1")
            .bind(&id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(code, "OUTBOX_INVALID_EVENT");
    sqlx::query("UPDATE xshield.audit_outbox SET envelope=$2,next_attempt_at=clock_timestamp() WHERE event_id=$1")
        .bind(&id).bind(source).execute(pool).await.unwrap();
    assert_eq!(
        publish_evidence_retention_outbox_batch(store, client, scope, config)
            .await
            .unwrap()
            .published,
        1
    );
}
