//! Publishes persisted generic grants produced by the script's issuance regression.

use super::{clickhouse_tests::with_clickhouse, *};
use crate::ExistingDigest;
use chrono::{DateTime, SecondsFormat, Utc};
use clickhouse::{sql::Identifier, test};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use xshield_core::domain::{SiteId, TenantId};

const TRACE: &str = "018f2a3b4c5d70008000000000000210";

#[tokio::test]
#[ignore = "requires the private database owned by scripts/test_postgres.sh"]
async fn postgres_outbox_publishing_generic_grant_producer() {
    let pool = PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(database.starts_with("xshield_test_"));
    let scope = OutboxScope::new(
        &TenantId::parse("tenant_grant").unwrap(),
        &SiteId::parse("site_grant").unwrap(),
    );
    let expected = persisted_envelopes(&pool, &scope).await;
    let test_pool = pool.clone();
    let outcome = if std::env::var("XSHIELD_TEST_CLICKHOUSE_URL").is_ok_and(|url| !url.is_empty()) {
        with_clickhouse(move |client| async move {
            publish_and_assert_ack(&test_pool, &client, &scope, expected.len()).await;
            for table in [
                "audit_events",
                "events_by_time",
                "audit_events_active",
                "events_by_time_active",
            ] {
                let rows = client
                    .query("SELECT ?fields FROM ?")
                    .bind(Identifier(table))
                    .fetch_all::<IndexRow>()
                    .await
                    .unwrap();
                assert_index_rows(&rows, &expected);
            }
        })
        .await
    } else {
        tokio::spawn(async move {
            let mock = test::Mock::new();
            let mut insertions = Vec::new();
            for _ in &expected {
                mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
                insertions.push(mock.add(test::handlers::record::<IndexRow>()));
                mock.add(test::handlers::provide(Vec::<ExistingDigest>::new()));
            }
            publish_and_assert_ack(
                &test_pool,
                &Client::default().with_mock(&mock),
                &scope,
                expected.len(),
            )
            .await;
            let mut rows = Vec::new();
            for insertion in insertions {
                let inserted = insertion.collect::<Vec<IndexRow>>().await;
                assert_eq!(inserted.len(), 1);
                rows.extend(inserted);
            }
            assert_index_rows(&rows, &expected);
        })
        .await
    };
    pool.close().await;
    outcome.unwrap();
}

// Compare the full producer contract with the committed authorization facts.
#[allow(clippy::too_many_lines)]
async fn persisted_envelopes(pool: &PgPool, scope: &OutboxScope) -> BTreeMap<String, Value> {
    let rows = sqlx::query(
        r"
        SELECT outbox.event_id, outbox.envelope, outbox.created_at,
          outbox.published_at IS NULL AND outbox.lease_token IS NULL
            AND outbox.lease_until IS NULL AND outbox.delivery_attempts = 0 AS pending,
          grant_row.constraints::text AS constraints_json,
          grant_row.issued_at, grant_row.expires_at,
          grant_row.policy_revision,
          action.source_request_id,
          jsonb_build_object(
            'stage', 'grant', 'outcome', 'PASS', 'reason_code', 'GRANT_ISSUED',
            'grant_id', grant_row.grant_id, 'binding_id', grant_row.binding_id,
            'auth_epoch', grant_row.auth_epoch, 'action_ref', grant_row.action_ref,
            'source_request_id', action.source_request_id,
            'resource_type', grant_row.resource_type,
            'resource_key_hmac', encode(grant_row.resource_key_hmac, 'hex'),
            'operation_id', grant_row.operation_id, 'view_profile', grant_row.view_id,
            'policy_revision', grant_row.policy_revision,
            'issued_at_unix', extract(epoch FROM grant_row.issued_at)::bigint,
            'expires_at_unix', extract(epoch FROM grant_row.expires_at)::bigint
          ) AS expected_payload
        FROM xshield.resource_grants grant_row
        JOIN xshield.audit_outbox outbox
          ON outbox.tenant_id = grant_row.tenant_id AND outbox.site_id = grant_row.site_id
         AND outbox.event_id = grant_row.source_event_id
         AND outbox.aggregate_ref = grant_row.grant_id
        JOIN xshield.ui_actions action
          ON action.tenant_id = grant_row.tenant_id AND action.site_id = grant_row.site_id
         AND action.action_ref = grant_row.action_ref
        WHERE outbox.tenant_id = $1 AND outbox.site_id = $2
          AND outbox.event_type = 'grant.issued'
        ORDER BY outbox.created_at, outbox.event_id
        LIMIT 257
        ",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .fetch_all(pool)
    .await
    .unwrap();
    assert!((1..=256).contains(&rows.len()));
    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.audit_outbox
         WHERE tenant_id = $1 AND site_id = $2 AND event_type = 'grant.issued'",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(outbox_count, i64::try_from(rows.len()).unwrap());
    let mut expected = BTreeMap::new();
    for row in rows {
        assert!(row.get::<bool, _>("pending"));
        let event_id: String = row.get("event_id");
        let issued_at: DateTime<Utc> = row.get("issued_at");
        assert_eq!(issued_at.timestamp_subsec_nanos(), 0);
        assert_eq!(
            row.get::<DateTime<Utc>, _>("expires_at")
                .timestamp_subsec_nanos(),
            0
        );
        assert!(row.get::<DateTime<Utc>, _>("created_at") >= issued_at);
        let constraints_json: String = row.get("constraints_json");
        let mut payload: Value = row.get("expected_payload");
        payload["constraints_digest"] = json!(hex(&sha256_digest(constraints_json.as_bytes())));
        let timestamp = issued_at.to_rfc3339_opts(SecondsFormat::Secs, true);
        let envelope = json!({
            "schema_version": 3, "event_id": event_id, "event_type": "grant.issued",
            "tenant_id": scope.tenant_id().as_str(), "site_id": scope.site_id().as_str(),
            "request_id": row.get::<String, _>("source_request_id"), "trace_id": TRACE,
            "span_id": &TRACE[..16], "producer_id": "gateway-grant",
            "producer_boot_id": event_id, "producer_seq": 1, "request_seq": 1,
            "occurred_at": timestamp, "observed_at": timestamp,
            "policy_revision": row.get::<String, _>("policy_revision"), "example_only": false,
            "sensitivity": "SENSITIVE", "evidence_refs": [], "cause_event_ids": [],
            "integrity": {"state": "pending", "previous_hash": null, "event_hash": null},
            "payload": payload
        });
        assert_eq!(row.get::<Value, _>("envelope"), envelope);
        assert!(expected.insert(event_id, envelope).is_none());
    }
    expected
}

async fn publish_and_assert_ack(pool: &PgPool, client: &Client, scope: &OutboxScope, count: usize) {
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let config = OutboxPublisherConfig::new(
        "audit_events",
        30,
        OutboxLeaseConfig::new(256, 1_048_576, Duration::from_mins(1)).unwrap(),
        Duration::from_mins(1),
    )
    .unwrap();
    assert_eq!(
        publish_grant_outbox_batch(&store, client, scope, &config)
            .await
            .unwrap(),
        OutboxPublishReport {
            claimed: count,
            published: count
        }
    );
    let acknowledged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.audit_outbox
         WHERE tenant_id = $1 AND site_id = $2 AND event_type = 'grant.issued'
           AND published_at IS NOT NULL AND lease_token IS NULL AND lease_until IS NULL
           AND delivery_attempts = 1 AND last_error_code IS NULL",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(acknowledged, i64::try_from(count).unwrap());
    assert_eq!(
        publish_grant_outbox_batch(&store, client, scope, &config)
            .await
            .unwrap(),
        OutboxPublishReport {
            claimed: 0,
            published: 0
        }
    );
}

fn assert_index_rows(rows: &[IndexRow], expected: &BTreeMap<String, Value>) {
    assert_eq!(rows.len(), expected.len());
    let mut remaining = expected.clone();
    for row in rows {
        let envelope = remaining.remove(&row.event_id).unwrap();
        let occurred_at = DateTime::parse_from_rfc3339(envelope["occurred_at"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc);
        let digest = hex(&sha256_digest(&serde_json::to_vec(&envelope).unwrap()));
        let expected_row = IndexRow {
            tenant_id: envelope["tenant_id"].as_str().unwrap().to_owned(),
            site_id: envelope["site_id"].as_str().unwrap().to_owned(),
            request_id: envelope["request_id"].as_str().unwrap().to_owned(),
            trace_id: TRACE.as_bytes().try_into().unwrap(),
            event_id: row.event_id.clone(),
            event_type: "grant.issued".to_owned(),
            stage: "grant".to_owned(),
            outcome: "PASS".to_owned(),
            reason_code: "GRANT_ISSUED".to_owned(),
            proof_kind: "deterministic".to_owned(),
            confidence: None,
            confidence_status: "not_applicable".to_owned(),
            occurred_at,
            observed_at: occurred_at,
            retention_expires_at: occurred_at + TimeDelta::days(30),
            producer_id: "gateway-grant".to_owned(),
            producer_boot_id: row.event_id.clone(),
            producer_seq: 1,
            request_seq: 1,
            method: String::new(),
            operation_id: envelope["payload"]["operation_id"]
                .as_str()
                .unwrap()
                .to_owned(),
            origin_state: String::new(),
            http_status: None,
            is_terminal: 0,
            duration_us: 0,
            policy_revision: envelope["policy_revision"].as_str().unwrap().to_owned(),
            model_revision: String::new(),
            evidence_refs: Vec::new(),
            cause_event_ids: Vec::new(),
            sensitivity: "SENSITIVE".to_owned(),
            payload_json: serde_json::to_string(&envelope["payload"]).unwrap(),
            content_digest: digest.as_bytes().try_into().unwrap(),
            ingest_revision: u64::from_str_radix(&digest[..16], 16).unwrap(),
            event_hash: digest,
        };
        assert_eq!(
            serde_json::to_value(row).unwrap(),
            serde_json::to_value(expected_row).unwrap()
        );
    }
    assert!(remaining.is_empty());
}
