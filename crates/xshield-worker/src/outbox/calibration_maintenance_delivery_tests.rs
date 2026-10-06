//! Publishes durable calibration-maintenance facts through production DDL.
//!
//! The script-owned report and lineage-retention regressions execute the real
//! intent and completion commands first. This test consumes their committed
//! metadata-only facts; it never opens an evidence object or alters retention.

use super::{clickhouse_tests::with_clickhouse, *};
use chrono::{DateTime, Utc};
use clickhouse::sql::Identifier;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use xshield_core::domain::{SiteId, TenantId};

const MAINTENANCE_EVENT_TYPES: [&str; 12] = [
    "calibration.report_retention.purge_requested",
    "calibration.report_retention.deleted",
    "calibration.report_retention.purge_failed",
    "calibration.report_retention.orphan_purge_requested",
    "calibration.report_retention.orphan_deleted",
    "calibration.report_retention.orphan_purge_failed",
    "calibration.lineage_review_retention.purge_requested",
    "calibration.lineage_review_retention.deleted",
    "calibration.lineage_review_retention.purge_failed",
    "calibration.lineage_review_retention.orphan_purge_requested",
    "calibration.lineage_review_retention.orphan_deleted",
    "calibration.lineage_review_retention.orphan_purge_failed",
];

#[derive(Clone, Copy)]
enum MaintenanceSource {
    ReportArtifact,
    ReportOrphan,
    LineageReviewArtifact,
    LineageReviewOrphan,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MaintenancePhase {
    Requested,
    Deleted,
    Failed,
}

struct MaintenanceEventContract {
    source: MaintenanceSource,
    phase: MaintenancePhase,
    aggregate_key: &'static str,
    artifact_key: &'static str,
}

struct DurableMaintenanceSource {
    requested_event_id: String,
    completed_event_id: Option<String>,
    retention_status: String,
}

#[tokio::test]
#[ignore = "requires scripts/test_postgres.sh and XSHIELD_TEST_CLICKHOUSE_URL"]
async fn real_calibration_maintenance_outbox_clickhouse_delivery() {
    let pool = PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(database.starts_with("xshield_test_"));
    let scopes = committed_maintenance_scopes(&pool).await;
    assert!(
        !scopes.is_empty(),
        "retention producer regressions must commit maintenance facts"
    );
    let task_pool = pool.clone();
    let result = with_clickhouse(move |client| async move {
        let mut all_event_types = BTreeSet::new();
        for (tenant, site) in scopes {
            all_event_types
                .extend(publish_scope(&task_pool, &client, OutboxScope::new(&tenant, &site)).await);
        }
        assert_eq!(
            all_event_types,
            MAINTENANCE_EVENT_TYPES
                .iter()
                .map(|event_type| (*event_type).to_owned())
                .collect()
        );
    })
    .await;
    pool.close().await;
    result.unwrap();
}

// Only scopes with maintenance facts still waiting: the report regression commits two of them
// in the scope the lifecycle delivery test drains, and the publisher delivers a whole scope.
// The dedicated retention scopes carry every maintenance event type between them.
async fn committed_maintenance_scopes(pool: &PgPool) -> Vec<(TenantId, SiteId)> {
    let rows = sqlx::query(
        "SELECT tenant_id, site_id
         FROM xshield.audit_outbox
         WHERE event_type = ANY($1::text[]) AND published_at IS NULL
           AND (tenant_id LIKE 'tenant_calreport_%' OR tenant_id LIKE 'tenant_calreview_%')
         GROUP BY tenant_id, site_id
         ORDER BY tenant_id, site_id",
    )
    .bind(MAINTENANCE_EVENT_TYPES)
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
async fn publish_scope(pool: &PgPool, client: &Client, scope: OutboxScope) -> BTreeSet<String> {
    let expected = committed_envelopes(pool, &scope).await;
    let event_types = expected
        .values()
        .map(|event| event["event_type"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert!(!event_types.is_empty());
    assert_durable_sources(pool, &scope, &expected).await;

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
    event_types
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
    .bind(MAINTENANCE_EVENT_TYPES)
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
        assert!(expected.insert(event_id, envelope).is_none());
    }
    expected
}

async fn assert_durable_sources(
    pool: &PgPool,
    scope: &OutboxScope,
    expected: &BTreeMap<String, Value>,
) {
    for (event_id, event) in expected {
        let contract = maintenance_event_contract(event["event_type"].as_str().unwrap());
        let payload = &event["payload"];
        assert_eq!(payload["retained_metadata"], true);
        let aggregate_ref = payload[contract.aggregate_key].as_str().unwrap();
        assert_eq!(
            durable_outbox_aggregate(pool, scope, event_id).await,
            aggregate_ref
        );
        let artifact_id = payload[contract.artifact_key].as_str().unwrap();
        assert_eq!(event["evidence_refs"], json!([artifact_id]));
        let source =
            durable_maintenance_source(pool, scope, contract.source, aggregate_ref, artifact_id)
                .await;
        match contract.phase {
            MaintenancePhase::Requested => {
                assert_eq!(source.requested_event_id, *event_id);
                assert_eq!(event["cause_event_ids"], json!([]));
            }
            MaintenancePhase::Deleted => {
                assert_eq!(
                    source.completed_event_id.as_deref(),
                    Some(event_id.as_str())
                );
                assert_eq!(source.retention_status, "deleted");
                assert_maintenance_intent_cause(event, &source.requested_event_id);
            }
            MaintenancePhase::Failed => {
                assert!(source.completed_event_id.is_none());
                assert_eq!(
                    source.retention_status,
                    retryable_maintenance_status(contract.source)
                );
                assert_maintenance_intent_cause(event, &source.requested_event_id);
            }
        }
    }
}

async fn durable_outbox_aggregate(pool: &PgPool, scope: &OutboxScope, event_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT aggregate_ref FROM xshield.audit_outbox
         WHERE tenant_id=$1 AND site_id=$2 AND event_id=$3",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(event_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn maintenance_event_contract(event_type: &str) -> MaintenanceEventContract {
    match event_type {
        "calibration.report_retention.purge_requested" => MaintenanceEventContract {
            source: MaintenanceSource::ReportArtifact,
            phase: MaintenancePhase::Requested,
            aggregate_key: "report_id",
            artifact_key: "report_artifact_id",
        },
        "calibration.report_retention.deleted" => MaintenanceEventContract {
            source: MaintenanceSource::ReportArtifact,
            phase: MaintenancePhase::Deleted,
            aggregate_key: "report_id",
            artifact_key: "report_artifact_id",
        },
        "calibration.report_retention.purge_failed" => MaintenanceEventContract {
            source: MaintenanceSource::ReportArtifact,
            phase: MaintenancePhase::Failed,
            aggregate_key: "report_id",
            artifact_key: "report_artifact_id",
        },
        "calibration.report_retention.orphan_purge_requested" => MaintenanceEventContract {
            source: MaintenanceSource::ReportOrphan,
            phase: MaintenancePhase::Requested,
            aggregate_key: "report_id",
            artifact_key: "report_artifact_id",
        },
        "calibration.report_retention.orphan_deleted" => MaintenanceEventContract {
            source: MaintenanceSource::ReportOrphan,
            phase: MaintenancePhase::Deleted,
            aggregate_key: "report_id",
            artifact_key: "report_artifact_id",
        },
        "calibration.report_retention.orphan_purge_failed" => MaintenanceEventContract {
            source: MaintenanceSource::ReportOrphan,
            phase: MaintenancePhase::Failed,
            aggregate_key: "report_id",
            artifact_key: "report_artifact_id",
        },
        "calibration.lineage_review_retention.purge_requested" => MaintenanceEventContract {
            source: MaintenanceSource::LineageReviewArtifact,
            phase: MaintenancePhase::Requested,
            aggregate_key: "review_id",
            artifact_key: "review_artifact_id",
        },
        "calibration.lineage_review_retention.deleted" => MaintenanceEventContract {
            source: MaintenanceSource::LineageReviewArtifact,
            phase: MaintenancePhase::Deleted,
            aggregate_key: "review_id",
            artifact_key: "review_artifact_id",
        },
        "calibration.lineage_review_retention.purge_failed" => MaintenanceEventContract {
            source: MaintenanceSource::LineageReviewArtifact,
            phase: MaintenancePhase::Failed,
            aggregate_key: "review_id",
            artifact_key: "review_artifact_id",
        },
        "calibration.lineage_review_retention.orphan_purge_requested" => MaintenanceEventContract {
            source: MaintenanceSource::LineageReviewOrphan,
            phase: MaintenancePhase::Requested,
            aggregate_key: "review_id",
            artifact_key: "review_artifact_id",
        },
        "calibration.lineage_review_retention.orphan_deleted" => MaintenanceEventContract {
            source: MaintenanceSource::LineageReviewOrphan,
            phase: MaintenancePhase::Deleted,
            aggregate_key: "review_id",
            artifact_key: "review_artifact_id",
        },
        "calibration.lineage_review_retention.orphan_purge_failed" => MaintenanceEventContract {
            source: MaintenanceSource::LineageReviewOrphan,
            phase: MaintenancePhase::Failed,
            aggregate_key: "review_id",
            artifact_key: "review_artifact_id",
        },
        _ => unreachable!("only the closed maintenance event family is queried"),
    }
}

fn assert_maintenance_intent_cause(event: &Value, expected_intent: &str) {
    assert_eq!(
        event["cause_event_ids"],
        json!([expected_intent]),
        "terminal maintenance events are bound to their own durable intent"
    );
}

const fn retryable_maintenance_status(source: MaintenanceSource) -> &'static str {
    match source {
        MaintenanceSource::ReportArtifact | MaintenanceSource::LineageReviewArtifact => "active",
        MaintenanceSource::ReportOrphan | MaintenanceSource::LineageReviewOrphan => "pending",
    }
}

async fn durable_maintenance_source(
    pool: &PgPool,
    scope: &OutboxScope,
    source: MaintenanceSource,
    aggregate_ref: &str,
    artifact_id: &str,
) -> DurableMaintenanceSource {
    let source = match source {
        MaintenanceSource::ReportArtifact => "report_artifact",
        MaintenanceSource::ReportOrphan => "report_orphan",
        MaintenanceSource::LineageReviewArtifact => "lineage_review_artifact",
        MaintenanceSource::LineageReviewOrphan => "lineage_review_orphan",
    };
    let row = sqlx::query(
        "WITH maintenance_sources AS (
             SELECT 'report_artifact' AS source, report_id AS aggregate_ref, artifact_id,
                    purge_requested_event_id AS requested_event_id,
                    purge_completed_event_id AS completed_event_id, retention_status
             FROM xshield.calibration_report_artifacts
             WHERE tenant_id=$1 AND site_id=$2
             UNION ALL
             SELECT 'report_orphan' AS source, report_id AS aggregate_ref, artifact_id,
                    requested_event_id, completed_event_id, status AS retention_status
             FROM xshield.calibration_report_orphan_purges
             WHERE tenant_id=$1 AND site_id=$2
             UNION ALL
             SELECT 'lineage_review_artifact' AS source, review_id AS aggregate_ref, artifact_id,
                    purge_requested_event_id AS requested_event_id,
                    purge_completed_event_id AS completed_event_id, retention_status
             FROM xshield.calibration_lineage_review_artifacts
             WHERE tenant_id=$1 AND site_id=$2
             UNION ALL
             SELECT 'lineage_review_orphan' AS source, review_id AS aggregate_ref, artifact_id,
                    requested_event_id, completed_event_id, status AS retention_status
             FROM xshield.calibration_lineage_review_orphan_purges
             WHERE tenant_id=$1 AND site_id=$2
         )
         SELECT requested_event_id, completed_event_id, retention_status
         FROM maintenance_sources
         WHERE source=$3 AND aggregate_ref=$4 AND artifact_id=$5",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(source)
    .bind(aggregate_ref)
    .bind(artifact_id)
    .fetch_one(pool)
    .await
    .unwrap();
    DurableMaintenanceSource {
        requested_event_id: row.get("requested_event_id"),
        completed_event_id: row.get("completed_event_id"),
        retention_status: row.get("retention_status"),
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
    .bind(MAINTENANCE_EVENT_TYPES)
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
        .find(|(_, event)| event["event_type"] == "calibration.report_retention.deleted")
        .or_else(|| expected.iter().next())
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
    changed["payload"]["expires_at"] = json!("2030-01-01T00:00:00.000Z");
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
    assert!(retryable);
    let conflicts = client
        .query("SELECT count() FROM audit_event_conflicts")
        .fetch_one::<u64>()
        .await
        .unwrap();
    assert_eq!(conflicts, 0);
}
