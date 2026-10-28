//! HTTP contract regressions for the observe → enforce exit report.

use super::*;
use crate::rollout_report::PATH;
use chrono::DateTime;

const WINDOW: &str =
    "revision=rollout-1&start=2026-09-19T00%3A00%3A00Z&end=2026-09-26T00%3A00%3A00Z";

fn request(query: &str) -> Request<Body> {
    Request::get(format!("{PATH}?{query}"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    let actual = response.status();
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(actual, status, "{body:?}");
    body
}

#[derive(Row, Serialize)]
struct Totals {
    completed: u64,
    observed: u64,
    unrouted: u64,
}

#[derive(Row, Serialize)]
struct Observation {
    operation_id: String,
    reason_code: String,
    count: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    last_seen: DateTime<Utc>,
}

fn audit(event: &Value, outcome: &str, code: &str) {
    assert_eq!(event["event_type"], "console.rollout_report.read");
    assert_eq!(event["payload"]["method"], "GET");
    assert_eq!(event["payload"]["path"], PATH);
    assert_eq!(event["payload"]["outcome"], outcome);
    assert_eq!(event["payload"]["reason_code"], code);
    assert_eq!(event["evidence_refs"], json!([]));
    assert!(!event.to_string().contains("rollout-1"));
}

#[tokio::test]
async fn the_report_states_counts_index_state_and_a_digest_and_is_audited() {
    let mock = test::Mock::new();
    mock.add(test::handlers::provide([Totals {
        completed: 40,
        observed: 3,
        unrouted: 2,
    }]));
    mock.add(test::handlers::provide([Observation {
        operation_id: "orders.list".to_owned(),
        reason_code: "UI_ACTION_NOT_AVAILABLE".to_owned(),
        count: 3,
        last_seen: DateTime::parse_from_rfc3339("2026-09-20T10:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
    }]));
    let fixture = Fixture::with_index(
        10,
        ManagementRole::Observer,
        Client::default().with_mock(&mock),
    );
    let access_directory = fixture.access_directory.clone();
    let body = response_json(
        router(fixture.control)
            .oneshot(request(WINDOW))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["tenant_id"], "tenant_a");
    assert_eq!(body["site_id"], "site_a");
    assert_eq!(body["rollout_revision"], "rollout-1");
    assert_eq!(body["start"], "2026-09-19T00:00:00Z");
    assert_eq!(body["end"], "2026-09-26T00:00:00Z");
    assert_eq!(body["completed_requests"], 40);
    assert_eq!(body["observed_requests"], 3);
    assert_eq!(body["unrouted_refusals"], 2);
    assert_eq!(body["truncated"], false);
    assert_eq!(body["observations"][0]["operation_id"], "orders.list");
    assert_eq!(body["observations"][0]["count"], 3);
    assert_eq!(
        body["observations"][0]["last_seen"],
        "2026-09-20T10:00:00.000000Z"
    );
    assert_eq!(body["watermark_scope"], "configured_journal");
    assert_eq!(
        body["index_complete"],
        body["has_gaps"] == false && body["pending_segments"] == 0
    );
    let digest = body["report_digest"].as_str().unwrap();
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    let events = read_access_events(&access_directory);
    assert_eq!(events.len(), 1);
    audit(&events[0], "PASS", "CONTROL_ROLLOUT_REPORT_READ");
    assert_eq!(events[0]["request_id"], body["request_id"]);
    fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn an_invalid_or_unindexed_report_is_refused_and_audited() {
    for scenario in ["invalid", "body", "index"] {
        let fixture = Fixture::with_index(10, ManagementRole::Observer, Client::default());
        let mut input = request(WINDOW);
        let (status, code, outcome) = match scenario {
            "invalid" => {
                input = request("revision=rollout-1&start=2026-09-19T00%3A00%3A00Z");
                (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_ROLLOUT_REPORT_REQUEST_INVALID",
                    "DENY",
                )
            }
            "body" => {
                *input.body_mut() = Body::from("unexpected");
                (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_ROLLOUT_REPORT_REQUEST_INVALID",
                    "DENY",
                )
            }
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_ROLLOUT_REPORT_INDEX_UNAVAILABLE",
                "ERROR",
            ),
        };
        let access_directory = fixture.access_directory.clone();
        let body = response_json(
            router(fixture.control).oneshot(input).await.unwrap(),
            status,
        )
        .await;
        assert_eq!(body["error_code"], code, "{scenario}");
        let events = read_access_events(&access_directory);
        assert_eq!(events.len(), 1);
        audit(&events[0], outcome, code);
        fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn the_report_requires_the_observer_role() {
    let mut fixture = Fixture::new(10, ManagementRole::Observer);
    fixture.control.config.principal = ManagementPrincipal::new(
        "operator-1",
        [ManagementRole::PolicyAuthor],
        [(
            TenantId::parse("tenant_a").unwrap(),
            SiteId::parse("site_a").unwrap(),
        )],
    )
    .unwrap();
    let access_directory = fixture.access_directory.clone();
    let body = response_json(
        router(fixture.control)
            .oneshot(request(WINDOW))
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(body["error_code"], "CONTROL_SCOPE_DENIED");
    let events = read_access_events(&access_directory);
    assert_eq!(events.len(), 1);
    audit(&events[0], "DENY", "CONTROL_SCOPE_DENIED");
    fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
}
