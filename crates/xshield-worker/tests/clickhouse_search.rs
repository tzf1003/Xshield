//! Real schema and `RowBinary` regression in an exclusively owned test database.

use chrono::{DateTime, TimeDelta, Utc};
use clickhouse::{Client, Row, sql::Identifier};
use serde::{Serialize, Serializer, ser::SerializeTuple};
use std::{env, panic::resume_unwind};
use uuid::Uuid;
use xshield_core::{
    domain::{EventId, RequestId, SiteId, TenantId},
    identity::UnixSeconds,
    query::{
        ConfidenceThreshold, QueryFilter, QueryOutcome, QueryPlan, QuerySort, QueryTextField,
        QueryWindow,
    },
};
use xshield_worker::{
    AuditSearchResult, PublishError, PublisherConfig, SearchEventSummary, query_audit_events,
};

const REQUEST_A: &str = "req_018f2a3b-4c5d-7000-8000-000000000001";
const REQUEST_B: &str = "req_018f2a3b-4c5d-7000-8000-000000000002";

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_CLICKHOUSE_URL"]
async fn real_schema_search_is_scoped_typed_paginated_and_retention_aware() {
    let url = env::var("XSHIELD_TEST_CLICKHOUSE_URL").unwrap_or_else(|_| {
        panic!("XSHIELD_TEST_CLICKHOUSE_URL must identify a test ClickHouse server")
    });
    let mut admin = Client::default().with_url(url);
    if let Ok(user) = env::var("XSHIELD_TEST_CLICKHOUSE_USER") {
        admin = admin.with_user(user);
    }
    if let Ok(password) = env::var("XSHIELD_TEST_CLICKHOUSE_PASSWORD") {
        admin = admin.with_password(password);
    }
    let database = format!("xshield_search_test_{}", Uuid::now_v7().simple());
    // Successful CREATE without IF NOT EXISTS establishes exclusive ownership.
    checked(
        admin
            .query("CREATE DATABASE ?")
            .bind(Identifier(&database))
            .execute()
            .await,
        "create isolated database",
    );
    let client = admin.clone().with_database(database.clone());
    let reader_name = format!("{database}_reader");
    let reader_password = Uuid::now_v7().to_string();
    let reader_creation = admin
        .query("CREATE USER ? IDENTIFIED BY ?")
        .bind(Identifier(&reader_name))
        .bind(&reader_password)
        .execute()
        .await;
    let owns_reader = reader_creation.is_ok();
    let reader = client
        .clone()
        .with_user(&reader_name)
        .with_password(reader_password);
    let schema_database = database.clone();
    let grant_reader = reader_name.clone();
    // Tokio captures assertions and setup panics so the owner can await cleanup.
    let outcome = tokio::spawn(async move {
        checked(reader_creation, "create isolated reader");
        apply_schema(&client, &schema_database).await;
        apply_schema(&client, &schema_database).await;
        let (window, expected) = insert_events(&client).await;
        for table in ["audit_events", "events_by_time"] {
            checked(
                client
                    .query("GRANT SELECT ON ?.? TO ?")
                    .bind(Identifier(&schema_database))
                    .bind(Identifier(&format!("{table}_active")))
                    .bind(Identifier(&grant_reader))
                    .execute()
                    .await,
                "grant active view to isolated reader",
            );
            let raw_read = reader
                .query("SELECT count() FROM ?")
                .bind(Identifier(table))
                .fetch_one::<u64>()
                .await;
            assert!(matches!(raw_read, Err(ref error) if server_code(error) == Some(497)));
            let config = PublisherConfig::new(
                "unused-journal",
                "unused-manifests",
                "unused-checkpoints",
                "clickhouse-test",
                table,
                30,
                1024,
            )
            .unwrap();
            assert_search(&reader, &config, window, &expected).await;
        }
    })
    .await;
    let cleanup = admin
        .query("DROP DATABASE ? SYNC")
        .bind(Identifier(&database))
        .execute()
        .await;
    let reader_cleanup = if owns_reader {
        admin
            .query("DROP USER ?")
            .bind(Identifier(&reader_name))
            .execute()
            .await
    } else {
        Ok(())
    };
    assert!(
        cleanup.is_ok(),
        "cleanup failed for owned database {database}"
    );
    assert!(
        reader_cleanup.is_ok(),
        "cleanup failed for owned reader {reader_name}"
    );
    if let Err(error) = outcome {
        if error.is_panic() {
            resume_unwind(error.into_panic());
        }
        panic!("ClickHouse regression task was cancelled");
    }
}

async fn apply_schema(client: &Client, database: &str) {
    let schema = include_str!("../../../sql/clickhouse.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .replace("xshield.", &format!("{database}."));
    // The checked-in DDL uses semicolon-separated statements and line comments.
    for (index, statement) in schema.split(';').map(str::trim).enumerate() {
        if statement.is_empty() || statement == "CREATE DATABASE IF NOT EXISTS xshield" {
            continue;
        }
        checked(
            client.query(statement).execute().await,
            &format!("apply repository schema statement {}", index + 1),
        );
    }
    // Keep expired physical rows present to exercise the active views' deadline.
    for table in ["audit_events", "events_by_time"] {
        checked(
            client
                .query("SYSTEM STOP TTL MERGES ?")
                .bind(Identifier(table))
                .execute()
                .await,
            "stop test-table TTL merges",
        );
    }
}

#[derive(Clone, Serialize, Row)]
struct TestEvent {
    tenant_id: &'static str,
    site_id: &'static str,
    request_id: &'static str,
    trace_id: [u8; 32],
    event_id: String,
    event_type: &'static str,
    stage: &'static str,
    outcome: &'static str,
    reason_code: &'static str,
    proof_kind: &'static str,
    confidence: Option<f64>,
    confidence_status: &'static str,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    occurred_at: DateTime<Utc>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    observed_at: DateTime<Utc>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    retention_expires_at: DateTime<Utc>,
    producer_id: &'static str,
    producer_boot_id: &'static str,
    producer_seq: u64,
    request_seq: u32,
    method: &'static str,
    operation_id: &'static str,
    origin_state: &'static str,
    http_status: Option<u16>,
    is_terminal: u8,
    duration_us: u64,
    policy_revision: &'static str,
    model_revision: &'static str,
    evidence_refs: Vec<String>,
    cause_event_ids: Vec<String>,
    sensitivity: &'static str,
    payload_json: &'static str,
    event_hash: String,
    #[serde(serialize_with = "serialize_digest")]
    content_digest: [u8; 64],
    ingest_revision: u64,
}

impl TestEvent {
    fn new(sequence: u32, occurred_at: DateTime<Utc>, expires_at: DateTime<Utc>) -> Self {
        Self {
            tenant_id: "tenant_search",
            site_id: "site_search",
            request_id: REQUEST_A,
            trace_id: [b'0'; 32],
            event_id: event_id(sequence),
            event_type: "stage.completed",
            stage: "admission",
            outcome: "PASS",
            reason_code: "POLICY_ALLOWED",
            proof_kind: "deterministic",
            confidence: None,
            confidence_status: "not_applicable",
            occurred_at,
            observed_at: occurred_at,
            retention_expires_at: expires_at,
            producer_id: "gateway-test",
            producer_boot_id: "018f2a3b-4c5d-7000-8000-000000000001",
            producer_seq: u64::from(sequence),
            request_seq: sequence,
            method: "GET",
            operation_id: "orders.list",
            origin_state: "not_sent",
            http_status: None,
            is_terminal: 0,
            duration_us: 42,
            policy_revision: "policy-r1",
            model_revision: "",
            evidence_refs: Vec::new(),
            cause_event_ids: Vec::new(),
            sensitivity: "INTERNAL",
            payload_json: "synthetic raw payload",
            event_hash: "0".repeat(64),
            content_digest: [b'0'; 64],
            ingest_revision: 1,
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn insert_events(client: &Client) -> (QueryWindow, Vec<TestEvent>) {
    let now_micros: i64 = checked(
        client
            .query("SELECT toUnixTimestamp64Micro(now64(6))")
            .fetch_one()
            .await,
        "read server clock",
    );
    let now = DateTime::from_timestamp_micros(now_micros).unwrap();
    let start = DateTime::from_timestamp(now.timestamp() - 60, 0).unwrap();
    let end = start + TimeDelta::seconds(2);
    let expires = now + TimeDelta::hours(1);
    let first = TestEvent::new(1, start, expires);
    let mut terminal = TestEvent::new(3, start + TimeDelta::microseconds(123_456), expires);
    terminal.event_type = "request.completed";
    terminal.outcome = "ALLOW";
    terminal.stage = "";
    terminal.proof_kind = "";
    terminal.confidence_status = "";
    terminal.operation_id = "orders.detail";
    terminal.is_terminal = 1;
    terminal.evidence_refs = vec!["artifact_018f2a3b-4c5d-7000-8000-000000000001".to_owned()];
    terminal.cause_event_ids = vec![first.event_id.clone()];
    let mut model = TestEvent::new(4, terminal.occurred_at, expires);
    model.stage = "judgement";
    model.outcome = "DENY";
    model.reason_code = "MODEL_DENIED";
    model.proof_kind = "model";
    model.confidence = Some(0.825);
    model.confidence_status = "provided";
    model.operation_id = "orders.detail";
    model.model_revision = "model-r1";
    let mut optional = TestEvent::new(2, model.occurred_at + TimeDelta::microseconds(1), expires);
    optional.request_id = "";
    optional.event_type = "audit.recovered";
    optional.stage = "";
    optional.outcome = "";
    optional.reason_code = "";
    optional.proof_kind = "";
    optional.confidence_status = "";
    optional.operation_id = "";
    let mut high_confidence = model.clone();
    high_confidence.event_id = event_id(5);
    high_confidence.request_id = REQUEST_B;
    high_confidence.request_seq = 5;
    high_confidence.occurred_at = end - TimeDelta::microseconds(1);
    high_confidence.confidence = Some(0.9);
    high_confidence.operation_id = "orders.export";
    let expected = vec![first, terminal, model, optional, high_confidence];
    let mut rows = expected.clone();
    rows.push(TestEvent::new(
        6,
        start - TimeDelta::microseconds(1),
        expires,
    ));
    rows.push(TestEvent::new(7, end, expires));
    let mut replayed = TestEvent::new(8, start, now - TimeDelta::hours(1));
    rows.push(replayed.clone());
    replayed.retention_expires_at = expires;
    rows.push(replayed);
    rows.push(TestEvent::new(9, start, now - TimeDelta::hours(1)));
    let mut other_tenant = TestEvent::new(10, start, expires);
    other_tenant.tenant_id = "tenant_other";
    rows.push(other_tenant);
    let mut other_site = TestEvent::new(11, start, expires);
    other_site.site_id = "site_other";
    rows.push(other_site);
    let mut duplicate = expected[2].clone();
    duplicate.retention_expires_at += TimeDelta::hours(1);
    rows.push(duplicate);
    // Insert out of result order; the view and keyset query determine ordering.
    rows.reverse();
    let mut insert = checked(
        client.insert::<TestEvent>("audit_events").await,
        "start insert",
    );
    for row in &rows {
        checked(insert.write(row).await, "write synthetic event");
    }
    checked(insert.end().await, "finish synchronous insert");
    for table in ["audit_events", "events_by_time"] {
        let count: u64 = checked(
            client
                .query("SELECT count() FROM ?")
                .bind(Identifier(table))
                .fetch_one()
                .await,
            "count raw events",
        );
        assert_eq!(count, u64::try_from(rows.len()).unwrap());
        let expired_count: u64 = checked(
            client
                .query("SELECT count() FROM ? WHERE retention_expires_at <= now64(6)")
                .bind(Identifier(table))
                .fetch_one()
                .await,
            "count expired physical events",
        );
        assert_eq!(expired_count, 2);
    }
    let window = QueryWindow::new(
        UnixSeconds::new(u64::try_from(start.timestamp()).unwrap()),
        UnixSeconds::new(u64::try_from(end.timestamp()).unwrap()),
    )
    .unwrap();
    (window, expected)
}

async fn assert_search(
    client: &Client,
    config: &PublisherConfig,
    window: QueryWindow,
    expected: &[TestEvent],
) {
    let tenant = TenantId::parse("tenant_search").unwrap();
    let site = SiteId::parse("site_search").unwrap();
    let plan = QueryPlan::new(window, Vec::new(), QuerySort::OccurredAtAsc, 100).unwrap();
    let result = queried(query_audit_events(config, client, &tenant, &site, &plan, None).await);
    assert_ids(&result, &[1, 3, 4, 2, 5]);
    assert!(!result.truncated);
    assert!(result.next_position.is_none());
    for (actual, expected) in result.events.iter().zip(expected) {
        assert_summary(actual, expected);
    }
    for (tenant, site, ids) in [
        ("tenant_other", "site_search", vec![10]),
        ("tenant_search", "site_other", vec![11]),
        ("tenant_other", "site_other", vec![]),
    ] {
        let result = queried(
            query_audit_events(
                config,
                client,
                &TenantId::parse(tenant).unwrap(),
                &SiteId::parse(site).unwrap(),
                &plan,
                None,
            )
            .await,
        );
        assert_ids(&result, &ids);
    }
    for sort in [QuerySort::OccurredAtAsc, QuerySort::OccurredAtDesc] {
        let plan = QueryPlan::new(window, Vec::new(), sort, 1).unwrap();
        let mut ordered: Vec<_> = expected.iter().collect();
        if sort == QuerySort::OccurredAtDesc {
            ordered.reverse();
        }
        let mut after = None;
        for (index, expected) in ordered.iter().enumerate() {
            let page = queried(
                query_audit_events(config, client, &tenant, &site, &plan, after.as_ref()).await,
            );
            assert_eq!(page.events.len(), 1);
            assert_summary(&page.events[0], expected);
            assert_eq!(page.truncated, index + 1 < ordered.len());
            assert_eq!(page.next_position.is_some(), page.truncated);
            if let Some(position) = &page.next_position {
                assert_eq!(position.event_id().as_str(), expected.event_id);
                assert_eq!(position.occurred_at(), expected.occurred_at);
            }
            after = page.next_position;
        }
    }
    assert_filters(client, config, window).await;
    let budget_client = client.clone().with_setting("max_result_rows", "1");
    assert!(matches!(
        query_audit_events(config, &budget_client, &tenant, &site, &plan, None).await,
        Err(PublishError::QueryBudgetExceeded)
    ));
}

#[allow(clippy::too_many_lines)]
async fn assert_filters(client: &Client, config: &PublisherConfig, window: QueryWindow) {
    let request = QueryFilter::RequestId(RequestId::parse(REQUEST_A).unwrap());
    let filters = [
        (vec![request.clone()], vec![1, 3, 4]),
        (
            vec![QueryFilter::EventId(EventId::parse(event_id(3)).unwrap())],
            vec![3],
        ),
        (
            vec![text(QueryTextField::EventType, "request.completed")],
            vec![3],
        ),
        (vec![text(QueryTextField::Stage, "judgement")], vec![4, 5]),
        (
            vec![text(QueryTextField::ReasonCode, "MODEL_DENIED")],
            vec![4, 5],
        ),
        (
            vec![text(QueryTextField::OperationId, "orders.detail")],
            vec![3, 4],
        ),
        (
            vec![text(QueryTextField::ModelRevision, "model-r1")],
            vec![4, 5],
        ),
        (vec![QueryFilter::Outcome(QueryOutcome::Allow)], vec![3]),
        (vec![confidence(8_250)], vec![4]),
        (vec![confidence(8_249)], vec![]),
        (vec![confidence(10_000)], vec![4, 5]),
        (
            vec![
                request.clone(),
                text(QueryTextField::Stage, "judgement"),
                QueryFilter::Outcome(QueryOutcome::Deny),
                confidence(8_250),
            ],
            vec![4],
        ),
        // These predicates match different events of the same request.
        (
            vec![
                request.clone(),
                text(QueryTextField::Stage, "judgement"),
                QueryFilter::Outcome(QueryOutcome::Allow),
            ],
            vec![],
        ),
        (
            vec![
                request,
                QueryFilter::EventId(EventId::parse(event_id(4)).unwrap()),
                text(QueryTextField::EventType, "stage.completed"),
                text(QueryTextField::Stage, "judgement"),
                text(QueryTextField::ReasonCode, "MODEL_DENIED"),
                text(QueryTextField::OperationId, "orders.detail"),
                text(QueryTextField::ModelRevision, "model-r1"),
                QueryFilter::Outcome(QueryOutcome::Deny),
            ],
            vec![4],
        ),
    ];
    for (filters, ids) in filters {
        let plan = QueryPlan::new(window, filters, QuerySort::OccurredAtAsc, 100).unwrap();
        let result = queried(
            query_audit_events(
                config,
                client,
                &TenantId::parse("tenant_search").unwrap(),
                &SiteId::parse("site_search").unwrap(),
                &plan,
                None,
            )
            .await,
        );
        assert_ids(&result, &ids);
    }
}

fn assert_summary(actual: &SearchEventSummary, expected: &TestEvent) {
    let optional = |value: &'static str| (!value.is_empty()).then_some(value);
    assert_eq!(actual.event_id, expected.event_id);
    assert_eq!(actual.event_type, expected.event_type);
    assert_eq!(actual.request_id.as_deref(), optional(expected.request_id));
    assert_eq!(actual.stage.as_deref(), optional(expected.stage));
    assert_eq!(actual.outcome.as_deref(), optional(expected.outcome));
    assert_eq!(
        actual.reason_code.as_deref(),
        optional(expected.reason_code)
    );
    assert_eq!(actual.proof_kind.as_deref(), optional(expected.proof_kind));
    assert_eq!(actual.confidence, expected.confidence);
    assert_eq!(
        actual.confidence_status.as_deref(),
        optional(expected.confidence_status)
    );
    assert_eq!(actual.occurred_at, expected.occurred_at);
    assert_eq!(actual.request_seq, expected.request_seq);
    assert_eq!(actual.duration_us, expected.duration_us);
    assert_eq!(actual.policy_revision, expected.policy_revision);
    assert_eq!(
        actual.model_revision.as_deref(),
        optional(expected.model_revision)
    );
    assert_eq!(actual.evidence_refs, expected.evidence_refs);
    assert_eq!(actual.cause_event_ids, expected.cause_event_ids);
    assert_eq!(actual.sensitivity, expected.sensitivity);
}

fn assert_ids(result: &AuditSearchResult, sequences: &[u32]) {
    let actual: Vec<_> = result
        .events
        .iter()
        .map(|row| row.event_id.clone())
        .collect();
    let expected: Vec<_> = sequences.iter().copied().map(event_id).collect();
    assert_eq!(actual, expected);
}

fn event_id(sequence: u32) -> String {
    format!("ev_018f2a3b-4c5d-7000-8000-{sequence:012x}")
}

fn text(field: QueryTextField, value: &str) -> QueryFilter {
    QueryFilter::Text {
        field,
        value: value.to_owned(),
    }
}

fn confidence(basis_points: u16) -> QueryFilter {
    QueryFilter::ConfidenceAtMost(ConfidenceThreshold::new(basis_points).unwrap())
}

fn serialize_digest<S: Serializer>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
    let mut tuple = serializer.serialize_tuple(value.len())?;
    for byte in value {
        tuple.serialize_element(byte)?;
    }
    tuple.end()
}

fn checked<T>(result: Result<T, clickhouse::error::Error>, operation: &str) -> T {
    // SDK diagnostics may contain the configured URL; credentials stay private.
    result.unwrap_or_else(|error| {
        if let clickhouse::error::Error::SchemaMismatch(details) = &error {
            panic!("ClickHouse could not {operation}; schema mismatch: {details}");
        }
        let code = server_code(&error);
        panic!("ClickHouse could not {operation}; server_code={code:?}")
    })
}

fn server_code(error: &clickhouse::error::Error) -> Option<u16> {
    match error {
        clickhouse::error::Error::BadResponse(body) => body
            .strip_prefix("Code: ")
            .and_then(|suffix| suffix.split('.').next())
            .and_then(|digits| digits.parse().ok()),
        _ => None,
    }
}

fn queried(result: Result<AuditSearchResult, PublishError>) -> AuditSearchResult {
    match result {
        Ok(result) => result,
        Err(PublishError::ClickHouse(error)) => checked(Err(error), "query audit events"),
        Err(error) => panic!("audit search failed: {error}"),
    }
}
