//! Real transactional outbox delivery against the production `ClickHouse` DDL.

use super::{delivery_tests::insert_event, tests::*, *};
use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use clickhouse::sql::Identifier;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::future::Future;
use uuid::Uuid;
use xshield_core::{
    domain::{AuthBindingId, EventId, GrantId, RequestId, SiteId, TenantId},
    identity::UnixSeconds,
    query::{QueryFilter, QueryPlan, QuerySort, QueryWindow},
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL and XSHIELD_TEST_CLICKHOUSE_URL"]
async fn real_outbox_clickhouse_delivery() {
    let pool = PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let scope = OutboxScope::new(
        &TenantId::parse(format!("tenant_outbox_{}", Uuid::now_v7().simple())).unwrap(),
        &SiteId::parse("site_outbox_clickhouse").unwrap(),
    );
    let test_pool = pool.clone();
    let test_scope = scope.clone();
    let outcome = with_clickhouse(move |client| async move {
        exercise_delivery(&test_pool, &test_scope, &client).await;
    })
    .await;
    let cleanup =
        sqlx::query("DELETE FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2")
            .bind(scope.tenant_id().as_str())
            .bind(scope.site_id().as_str())
            .execute(&pool)
            .await;
    pool.close().await;
    cleanup.unwrap();
    outcome.unwrap();
}

// Each check owns a database and awaits cleanup even if DDL or assertions panic.
pub(super) async fn with_clickhouse<F: Future<Output = ()> + Send + 'static>(
    check: impl FnOnce(Client) -> F + Send + 'static,
) -> Result<(), tokio::task::JoinError> {
    let mut admin =
        Client::default().with_url(std::env::var("XSHIELD_TEST_CLICKHOUSE_URL").unwrap());
    if let Ok(user) = std::env::var("XSHIELD_TEST_CLICKHOUSE_USER") {
        admin = admin.with_user(user);
    }
    if let Ok(password) = std::env::var("XSHIELD_TEST_CLICKHOUSE_PASSWORD") {
        admin = admin.with_password(password);
    }
    let owner = Uuid::now_v7().simple().to_string();
    let database = format!("xshield_outbox_test_{owner}");
    admin
        .query("CREATE DATABASE ?")
        .bind(Identifier(&database))
        .execute()
        .await
        .unwrap();
    let client = admin.clone().with_database(database.clone());
    let schema_database = database.clone();
    let outcome = tokio::spawn(async move {
        let schema = include_str!("../../../../sql/clickhouse.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n")
            .replace("xshield.", &format!("{schema_database}."));
        for _ in 0..2 {
            for statement in schema.split(';').map(str::trim) {
                if !statement.is_empty() && statement != "CREATE DATABASE IF NOT EXISTS xshield" {
                    client.query(statement).execute().await.unwrap();
                }
            }
        }
        check(client).await;
    })
    .await;
    let clickhouse_cleanup = admin
        .query("DROP DATABASE ? SYNC")
        .bind(Identifier(&database))
        .execute()
        .await;
    assert!(
        clickhouse_cleanup.is_ok(),
        "owned ClickHouse database cleanup failed"
    );
    outcome
}

/// Publishes real gateway transactions from the script-owned `PostgreSQL` database.
#[tokio::test]
#[ignore = "requires scripts/test_gateway_identity.sh and XSHIELD_TEST_CLICKHOUSE_URL"]
async fn real_gateway_response_grant_outbox_delivery() {
    let pool = PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(database.starts_with("xshield_gateway_"));
    let test_pool = pool.clone();
    let outcome = with_clickhouse(move |client| async move {
        exercise_gateway_response_grants(&test_pool, &client).await;
    })
    .await;
    pool.close().await;
    outcome.unwrap();
}

// Keep source-row assertions and the ensuing publication/ACK in execution order.
#[allow(clippy::too_many_lines)]
async fn exercise_gateway_response_grants(pool: &PgPool, client: &Client) {
    let scope = OutboxScope::new(
        &TenantId::parse("tenant_gateway").unwrap(),
        &SiteId::parse("site_gateway").unwrap(),
    );
    let rows = sqlx::query(r"
        SELECT outbox.envelope, evidence.source_request_id, grant_row.policy_revision,
          jsonb_build_object(
            'stage', 'response_grant', 'outcome', 'PASS', 'reason_code', 'GRANT_ISSUED',
            'grant_id', grant_row.grant_id, 'binding_id', grant_row.binding_id,
            'auth_epoch', grant_row.auth_epoch, 'response_evidence_id', evidence.response_evidence_id,
            'action_ref', action.action_ref, 'action_id', action.source_action_ref,
            'source_operation_id', evidence.source_operation_id,
            'operation_id', grant_row.operation_id, 'method', action.method,
            'route_template', action.route_template, 'resource_type', grant_row.resource_type,
            'resource_key_hmac', encode(grant_row.resource_key_hmac, 'hex'),
            'view_profile', grant_row.view_id, 'fields', action.allowed_fields,
            'mapping_revision', action.mapping_revision, 'response_status', evidence.response_status,
            'response_body_sha256', substring(evidence.response_artifact_ref FROM 8),
            'candidate_count', evidence.candidate_count,
            'issued_at_unix', extract(epoch FROM grant_row.issued_at)::bigint,
            'expires_at_unix', extract(epoch FROM grant_row.expires_at)::bigint
          ) AS expected_payload
        FROM xshield.audit_outbox outbox
        JOIN xshield.resource_grants grant_row
          ON grant_row.tenant_id = outbox.tenant_id AND grant_row.site_id = outbox.site_id
         AND grant_row.source_event_id = outbox.event_id AND grant_row.grant_id = outbox.aggregate_ref
        JOIN xshield.ui_actions action
          ON action.tenant_id = grant_row.tenant_id AND action.site_id = grant_row.site_id
         AND action.action_ref = grant_row.action_ref
        JOIN xshield.response_evidence evidence
          ON evidence.tenant_id = action.tenant_id AND evidence.site_id = action.site_id
         AND evidence.response_evidence_id = action.response_evidence_id
        WHERE outbox.tenant_id = $1 AND outbox.site_id = $2
          AND outbox.event_type = 'response_grant.issued'
    ")
    .bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str())
    .fetch_all(pool).await.unwrap();
    // The script's grant-issuing lists: the account list (two grants, one request), the
    // refreshed list (one) and the three accepted pages of the paginated list (one each).
    assert_eq!(rows.len(), 6);
    let mut expected = BTreeMap::new();
    let mut batches: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for row in rows {
        let envelope: Value = row.get("envelope");
        assert_eq!(envelope["payload"], row.get::<Value, _>("expected_payload"));
        assert_eq!(
            envelope["request_id"],
            row.get::<String, _>("source_request_id")
        );
        assert_eq!(
            envelope["policy_revision"],
            row.get::<String, _>("policy_revision")
        );
        assert_eq!(
            envelope["span_id"],
            &envelope["trace_id"].as_str().unwrap()[..16]
        );
        batches
            .entry(envelope["request_id"].as_str().unwrap().to_owned())
            .or_default()
            .push(envelope["request_seq"].as_u64().unwrap());
        expected.insert(envelope["event_id"].as_str().unwrap().to_owned(), envelope);
    }
    assert_eq!(batches.len(), 5);
    for sequence in batches.values_mut() {
        sequence.sort_unstable();
        assert_eq!(
            *sequence,
            (1..=u64::try_from(sequence.len()).unwrap()).collect::<Vec<_>>()
        );
    }
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let config = OutboxPublisherConfig::new(
        "audit_events",
        30,
        OutboxLeaseConfig::new(16, 64 * 1024, Duration::from_mins(1)).unwrap(),
        Duration::from_hours(1),
    )
    .unwrap();
    assert_eq!(
        publish_response_grant_outbox_batch(&store, client, &scope, &config)
            .await
            .unwrap(),
        OutboxPublishReport {
            claimed: expected.len(),
            published: expected.len()
        }
    );
    assert_index_rows(client, &scope, &expected).await;
    for id in expected.keys() {
        assert_acknowledged(pool, id, 1).await;
    }
    assert_eq!(
        publish_response_grant_outbox_batch(&store, client, &scope, &config)
            .await
            .unwrap(),
        OutboxPublishReport {
            claimed: 0,
            published: 0
        }
    );
}

async fn exercise_delivery(pool: &PgPool, scope: &OutboxScope, client: &Client) {
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
            CASE_EVENT_TYPES.iter().map(|kind| event(kind)).collect(),
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
        (OutboxFamily::Calibration, vec![calibration::tests::event()]),
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
        (OutboxFamily::UiAction, vec![ui_action::tests::event()]),
    ] {
        for envelope in envelopes {
            let stored = insert_event(pool, scope, family, current_event(envelope)).await;
            expected.insert(stored["event_id"].as_str().unwrap().to_owned(), stored);
        }
    }
    for (family, count) in [
        (OutboxFamily::Case, 3),
        (OutboxFamily::EvidenceCatalog, 2),
        (OutboxFamily::EvidenceAccess, 3),
        (OutboxFamily::Calibration, 1),
        (OutboxFamily::Identity, 5),
        (OutboxFamily::Grant, 1),
        (OutboxFamily::ResponseGrant, 1),
        (OutboxFamily::ShareGrant, 1),
        (OutboxFamily::UiAction, 1),
    ] {
        assert_eq!(
            publish_family(&store, client, scope, &config, family).await,
            OutboxPublishReport {
                claimed: count,
                published: count
            }
        );
        assert_eq!(
            publish_family(&store, client, scope, &config, family).await,
            OutboxPublishReport {
                claimed: 0,
                published: 0
            }
        );
    }
    for id in expected.keys() {
        assert_acknowledged(pool, id, 1).await;
    }
    assert_index_rows(client, scope, &expected).await;
    let response = expected
        .values()
        .find(|value| value["event_type"] == "response_grant.issued")
        .unwrap();
    assert_source_request_summary(client, scope, response).await;
    exercise_retry_and_conflict(pool, scope, client, &store, &config).await;
}

async fn assert_source_request_summary(client: &Client, scope: &OutboxScope, response: &Value) {
    let config = crate::PublisherConfig::new(
        "unused-journal",
        "unused-manifests",
        "unused-checkpoints",
        "clickhouse-test",
        "audit_events",
        30,
        1024,
    )
    .unwrap();
    let request = RequestId::parse(response["request_id"].as_str().unwrap()).unwrap();
    let summary = crate::query_request_summary(
        &config,
        client,
        scope.tenant_id(),
        scope.site_id(),
        &request,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(summary.method, None);
    assert_eq!(summary.operation_id, None);

    let mut accepted = response.clone();
    accepted["event_id"] = json!(format!("ev_{}", Uuid::now_v7()));
    accepted["event_type"] = json!("request.accepted");
    accepted["producer_id"] = json!("edge-test");
    accepted["producer_boot_id"] = json!(Uuid::now_v7().to_string());
    accepted["payload"] =
        json!({"method": "POST", "operation_id": "resource.list", "origin_state": "not_sent"});
    // Both producers start at sequence one; the older target event must not win.
    assert!(accepted["event_id"].as_str() > response["event_id"].as_str());
    let bytes = serde_json::to_vec(&accepted).unwrap();
    let row = IndexRow::parse(
        &bytes,
        &EventId::parse(accepted["event_id"].as_str().unwrap()).unwrap(),
        1,
        accepted["producer_boot_id"].as_str().unwrap(),
        hex(&sha256_digest(&bytes)),
        TimeDelta::days(30),
    )
    .unwrap();
    insert_rows(client, "audit_events", "request-summary-source", &[row])
        .await
        .unwrap();
    for table in ["audit_events", "events_by_time"] {
        let config = crate::PublisherConfig::new(
            "unused-journal",
            "unused-manifests",
            "unused-checkpoints",
            "clickhouse-test",
            table,
            30,
            1024,
        )
        .unwrap();
        let summary = crate::query_request_summary(
            &config,
            client,
            scope.tenant_id(),
            scope.site_id(),
            &request,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(summary.method.as_deref(), Some("POST"));
        assert_eq!(summary.operation_id.as_deref(), Some("resource.list"));
    }
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
            .query("SELECT ?fields FROM ?")
            .bind(Identifier(table))
            .fetch_all::<IndexRow>()
            .await
            .unwrap();
        assert_eq!(rows.len(), expected.len());
        for row in rows {
            let envelope = &expected[&row.event_id];
            let digest = hex(&sha256_digest(&serde_json::to_vec(envelope).unwrap()));
            assert_eq!(row.content_digest.as_slice(), digest.as_bytes());
            assert_eq!(row.event_hash, digest);
            assert_eq!(row.tenant_id, scope.tenant_id().as_str());
            assert_eq!(row.site_id, scope.site_id().as_str());
            assert_eq!(row.event_type, envelope["event_type"]);
            assert_eq!(row.producer_id, envelope["producer_id"]);
            // The index stores an absent request as the empty string.
            assert_eq!(
                row.request_id,
                envelope["request_id"].as_str().unwrap_or_default()
            );
            assert_eq!(
                serde_json::to_value(&row.evidence_refs).unwrap(),
                envelope["evidence_refs"]
            );
            assert_eq!(
                serde_json::to_value(&row.cause_event_ids).unwrap(),
                envelope["cause_event_ids"]
            );
            assert_eq!(
                row.occurred_at,
                DateTime::parse_from_rfc3339(envelope["occurred_at"].as_str().unwrap()).unwrap()
            );
            assert_eq!(row.observed_at, row.occurred_at);
            let expected_micros = match envelope["event_type"].as_str() {
                Some(
                    "grant.issued" | "response_grant.issued" | "share.issued" | "ui_action.issued",
                ) => 0,
                Some(kind) if kind.starts_with("calibration.") => 123_000,
                _ => 123_456,
            };
            assert_eq!(row.occurred_at.timestamp_subsec_micros(), expected_micros);
            assert_eq!(
                row.retention_expires_at,
                row.occurred_at + TimeDelta::days(30)
            );
            assert_eq!(row.confidence, None);
            assert_eq!(row.confidence_status, "not_applicable");
            assert_eq!(row.proof_kind, "deterministic");
            assert_eq!(row.is_terminal, 0);
            assert_eq!(
                serde_json::from_str::<Value>(&row.payload_json).unwrap(),
                envelope["payload"]
            );
        }
    }
    for envelope in expected.values() {
        assert_linkage_queries(client, scope, envelope).await;
    }
}

async fn assert_linkage_queries(client: &Client, scope: &OutboxScope, envelope: &Value) {
    let (grant_key, binding_key) = match envelope["event_type"].as_str().unwrap() {
        "grant.issued" | "response_grant.issued" => (Some("grant_id"), "binding_id"),
        "share.issued" => (Some("issuer_grant_id"), "issuer_binding_id"),
        "session.created" | "binding.created" | "identity.refreshed" | "epoch.changed"
        | "binding.revoked" => (None, "binding_id"),
        _ => return,
    };
    let binding = AuthBindingId::parse(envelope["payload"][binding_key].as_str().unwrap()).unwrap();
    let mut filters = vec![QueryFilter::AuthBindingId(binding)];
    if let Some(key) = grant_key {
        filters.push(QueryFilter::GrantId(
            GrantId::parse(envelope["payload"][key].as_str().unwrap()).unwrap(),
        ));
    }
    let occurred_at =
        DateTime::parse_from_rfc3339(envelope["occurred_at"].as_str().unwrap()).unwrap();
    let start = u64::try_from(occurred_at.timestamp()).unwrap();
    let window = QueryWindow::new(UnixSeconds::new(start), UnixSeconds::new(start + 1)).unwrap();
    let config = crate::PublisherConfig::new(
        "unused-journal",
        "unused-manifests",
        "unused-checkpoints",
        "clickhouse-test",
        "audit_events",
        30,
        1024,
    )
    .unwrap();
    for filter in filters {
        let plan = QueryPlan::new(
            window,
            vec![
                filter,
                QueryFilter::EventId(
                    EventId::parse(envelope["event_id"].as_str().unwrap()).unwrap(),
                ),
            ],
            QuerySort::OccurredAtAsc,
            1,
        )
        .unwrap();
        let result = crate::query_audit_events(
            &config,
            client,
            scope.tenant_id(),
            scope.site_id(),
            &plan,
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.events.len(), 1);
        assert_eq!(
            result.events[0].event_id,
            envelope["event_id"].as_str().unwrap()
        );
        assert_eq!(
            result.events[0].request_id.as_deref(),
            envelope["request_id"].as_str()
        );
        assert!(!result.truncated);
    }
}

async fn publish_family(
    store: &PostgresIdentityStore,
    client: &Client,
    scope: &OutboxScope,
    config: &OutboxPublisherConfig,
    family: OutboxFamily,
) -> OutboxPublishReport {
    match family {
        OutboxFamily::Case => publish_case_outbox_batch(store, client, scope, config).await,
        OutboxFamily::EvidenceCatalog => {
            publish_evidence_catalog_outbox_batch(store, client, scope, config).await
        }
        OutboxFamily::EvidenceAccess => {
            publish_evidence_access_outbox_batch(store, client, scope, config).await
        }
        OutboxFamily::Calibration => {
            publish_calibration_outbox_batch(store, client, scope, config).await
        }
        OutboxFamily::Identity => publish_identity_outbox_batch(store, client, scope, config).await,
        OutboxFamily::Grant => publish_grant_outbox_batch(store, client, scope, config).await,
        OutboxFamily::ResponseGrant => {
            publish_response_grant_outbox_batch(store, client, scope, config).await
        }
        OutboxFamily::ShareGrant => {
            publish_share_grant_outbox_batch(store, client, scope, config).await
        }
        OutboxFamily::UiAction => {
            publish_ui_action_outbox_batch(store, client, scope, config).await
        }
        OutboxFamily::EvidenceRetention => {
            publish_evidence_retention_outbox_batch(store, client, scope, config).await
        }
    }
    .unwrap_or_else(|error| panic!("{:?} outbox: {error:?}", family.event_types()))
}

// Keep the lost-ack, retry, and conflict transitions in execution order.
#[allow(clippy::too_many_lines)]
async fn exercise_retry_and_conflict(
    pool: &PgPool,
    scope: &OutboxScope,
    client: &Client,
    store: &PostgresIdentityStore,
    config: &OutboxPublisherConfig,
) {
    let replay = insert_event(
        pool,
        scope,
        OutboxFamily::Case,
        current_event(event("case.created")),
    )
    .await;
    let id = replay["event_id"].as_str().unwrap();
    let leases = store
        .claim_outbox_batch_for_types(scope, config.lease, CASE_EVENT_TYPES)
        .await
        .unwrap();
    assert_eq!(leases.len(), 1);
    // Expiration before ACK models a completed index write whose lease was lost.
    sqlx::query("UPDATE xshield.audit_outbox SET lease_until = clock_timestamp() - interval '1 second' WHERE event_id = $1")
        .bind(id).execute(pool).await.unwrap();
    assert!(matches!(
        publish_one(store, client, scope, config, OutboxFamily::Case, &leases[0]).await,
        Err(PublishError::OutboxLeaseLost)
    ));
    let pending: bool = sqlx::query_scalar("SELECT published_at IS NULL AND lease_token = $2 AND delivery_attempts = 1 FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(id).bind(&leases[0].lease_token).fetch_one(pool).await.unwrap();
    assert!(pending);
    assert_eq!(
        store
            .ack_outbox_event(scope, &leases[0].event_id, &leases[0].lease_token)
            .await
            .unwrap(),
        OutboxAckOutcome::Rejected
    );
    assert_eq!(
        publish_case_outbox_batch(store, client, scope, config)
            .await
            .unwrap()
            .published,
        1
    );
    assert_acknowledged(pool, id, 2).await;
    for (table, count) in [
        ("audit_events", 2),
        ("events_by_time", 2),
        ("audit_events_active", 1),
        ("events_by_time_active", 1),
    ] {
        let actual = client
            .query("SELECT count() FROM ? WHERE event_id = ?")
            .bind(Identifier(table))
            .bind(id)
            .fetch_one::<u64>()
            .await
            .unwrap();
        assert_eq!(actual, count);
    }

    let retry = insert_event(
        pool,
        scope,
        OutboxFamily::Case,
        current_event(event("case.closed")),
    )
    .await;
    let retry_id = retry["event_id"].as_str().unwrap();
    let unavailable = OutboxPublisherConfig {
        table: "unavailable_audit_events".to_owned(),
        ..config.clone()
    };
    assert!(matches!(
        publish_case_outbox_batch(store, client, scope, &unavailable).await,
        Err(PublishError::ClickHouse(_))
    ));
    assert_failure(pool, retry_id, INDEX_UNAVAILABLE_CODE).await;
    assert_eq!(
        publish_case_outbox_batch(store, client, scope, config)
            .await
            .unwrap()
            .claimed,
        0
    );
    sqlx::query("UPDATE xshield.audit_outbox SET next_attempt_at = clock_timestamp() - interval '1 second' WHERE event_id = $1")
        .bind(retry_id).execute(pool).await.unwrap();
    assert_eq!(
        publish_case_outbox_batch(store, client, scope, config)
            .await
            .unwrap()
            .published,
        1
    );
    assert_acknowledged(pool, retry_id, 2).await;

    // Mutating this synthetic source row exercises immutable-ID conflict detection.
    let mut conflicting = replay;
    conflicting["payload"]["subject_ref"] = json!("investigator-conflict");
    let conflict_id = conflicting["event_id"].as_str().unwrap();
    sqlx::query("UPDATE xshield.audit_outbox SET published_at = NULL, envelope = $2, next_attempt_at = clock_timestamp() WHERE event_id = $1")
        .bind(conflict_id).bind(&conflicting).execute(pool).await.unwrap();
    assert!(matches!(
        publish_case_outbox_batch(store, client, scope, config).await,
        Err(PublishError::IntegrityConflict)
    ));
    assert_failure(pool, conflict_id, INTEGRITY_CONFLICT_CODE).await;
    for table in ["audit_events", "events_by_time"] {
        let counts = client
            .query("SELECT count(), uniqExact(content_digest) FROM ? WHERE event_id = ?")
            .bind(Identifier(table))
            .bind(conflict_id)
            .fetch_one::<(u64, u64)>()
            .await
            .unwrap();
        assert_eq!(counts, (2, 1));
    }
    assert_eq!(
        client
            .query("SELECT count() FROM audit_event_conflicts")
            .fetch_one::<u64>()
            .await
            .unwrap(),
        0
    );
}

fn current_event(mut envelope: Value) -> Value {
    if matches!(
        envelope["event_type"].as_str(),
        Some("grant.issued" | "response_grant.issued" | "share.issued" | "ui_action.issued")
    ) {
        let now = Utc::now();
        envelope["occurred_at"] = json!(now.to_rfc3339_opts(SecondsFormat::Secs, true));
        envelope["observed_at"] = envelope["occurred_at"].clone();
        envelope["payload"]["issued_at_unix"] = json!(now.timestamp());
        envelope["payload"]["expires_at_unix"] = json!(now.timestamp() + 3_600);
        if envelope["event_type"] == "ui_action.issued" {
            envelope["payload"]["page_expires_at_unix"] = json!(now.timestamp() + 3_600);
        }
        return envelope;
    }
    // Calibration events carry canonical millisecond clocks and are refused otherwise;
    // every other family here keeps the microsecond precision the index stores.
    let (nanos, precision) = if envelope["event_type"]
        .as_str()
        .is_some_and(|kind| kind.starts_with("calibration."))
    {
        (123_000_000, SecondsFormat::Millis)
    } else {
        (123_456_000, SecondsFormat::Micros)
    };
    let now = Utc::now()
        .with_nanosecond(nanos)
        .unwrap()
        .to_rfc3339_opts(precision, true);
    envelope["occurred_at"] = json!(now);
    envelope["observed_at"] = envelope["occurred_at"].clone();
    envelope
}

#[test]
fn grant_clickhouse_fixture_preserves_frozen_envelope_contract() {
    let original = grant::tests::event();
    let envelope = current_event(original.clone());
    let row = IndexRow::parse_outbox(
        &serde_json::to_vec(&envelope).unwrap(),
        &EventId::parse(envelope["event_id"].as_str().unwrap()).unwrap(),
        1,
        envelope["producer_boot_id"].as_str().unwrap(),
        "0".repeat(64),
        TimeDelta::days(30),
    )
    .unwrap();
    assert_eq!(row.occurred_at.timestamp_subsec_micros(), 0);
    assert_eq!(envelope["observed_at"], envelope["occurred_at"]);
    assert_eq!(envelope["producer_boot_id"], envelope["event_id"]);
    assert_eq!(
        envelope["payload"]["source_request_id"],
        envelope["request_id"]
    );
    assert_eq!(
        envelope["payload"]["issued_at_unix"],
        json!(row.occurred_at.timestamp())
    );
    assert_eq!(
        envelope["payload"]["expires_at_unix"],
        json!(row.occurred_at.timestamp() + 3_600)
    );
    let mut frozen = envelope;
    for field in ["occurred_at", "observed_at"] {
        frozen[field] = original[field].clone();
    }
    for field in ["issued_at_unix", "expires_at_unix"] {
        frozen["payload"][field] = original["payload"][field].clone();
    }
    assert_eq!(frozen, original);
}

async fn assert_acknowledged(pool: &PgPool, id: &str, attempts: i32) {
    let acknowledged: bool = sqlx::query_scalar("SELECT published_at IS NOT NULL AND lease_token IS NULL AND lease_until IS NULL AND delivery_attempts = $2 FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(id).bind(attempts).fetch_one(pool).await.unwrap();
    assert!(acknowledged);
}

async fn assert_failure(pool: &PgPool, id: &str, code: &str) {
    let retryable: bool = sqlx::query_scalar("SELECT published_at IS NULL AND lease_token IS NULL AND lease_until IS NULL AND next_attempt_at > clock_timestamp() AND last_error_code = $2 FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(id).bind(code).fetch_one(pool).await.unwrap();
    assert!(retryable);
}
