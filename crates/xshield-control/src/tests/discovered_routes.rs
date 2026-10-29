//! HTTP contract regressions for per-site unmatched-route discovery.

use super::*;
use crate::discovered_routes::PATH as TEMPLATE;

const SITE: &str = "site_a";
const WINDOW: &str = "start=2026-09-19T00%3A00%3A00Z&end=2026-09-20T00%3A00%3A00Z&limit=1";

fn path(site: &str) -> String {
    TEMPLATE.replace("{site_id}", site)
}

fn request(site: &str, query: &str) -> Request<Body> {
    Request::get(format!("{}?{query}", path(site)))
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
struct DiscoveredRouteRow {
    method: String,
    path_template: String,
    hits: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    first_seen: DateTime<Utc>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    last_seen: DateTime<Utc>,
}

fn group_row(method: &str, path_template: &str, hits: u64, second: u8) -> DiscoveredRouteRow {
    DiscoveredRouteRow {
        method: method.to_owned(),
        path_template: path_template.to_owned(),
        hits,
        first_seen: DateTime::parse_from_rfc3339("2026-09-19T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        last_seen: DateTime::parse_from_rfc3339(&format!("2026-09-19T00:00:{second:02}.000Z"))
            .unwrap()
            .with_timezone(&Utc),
    }
}

fn audit(event: &Value, outcome: &str, code: &str) {
    assert_eq!(event["event_type"], "console.site.routes.discover");
    assert_eq!(event["payload"]["method"], "GET");
    assert_eq!(event["payload"]["path"], TEMPLATE);
    assert_eq!(event["payload"]["outcome"], outcome);
    assert_eq!(event["payload"]["reason_code"], code);
    assert_eq!(event["evidence_refs"], json!([]));
    for (key, value) in event["payload"].as_object().unwrap() {
        if key.starts_with("target_") || matches!(key.as_str(), "query_digest" | "bytes_read") {
            assert!(value.is_null(), "{key}");
        }
    }
    assert!(!event.to_string().contains(TOKEN));
}

#[tokio::test]
async fn discovered_routes_requires_system_admin_scope_and_audits_validated_rejections() {
    for scenario in ["missing", "role", "site", "invalid", "body"] {
        let mut fixture = Fixture::new(100, ManagementRole::SystemAdmin);
        let mut input = request(SITE, WINDOW);
        let (status, code) = match scenario {
            "missing" => {
                input.headers_mut().remove(AUTHORIZATION);
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "role" => {
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [ManagementRole::Observer],
                    [(
                        TenantId::parse("tenant_a").unwrap(),
                        SiteId::parse("site_a").unwrap(),
                    )],
                )
                .unwrap();
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED")
            }
            "site" => {
                input = request("site_b", WINDOW);
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED")
            }
            "invalid" => {
                input = request(
                    SITE,
                    "start=2026-09-19T00%3A00%3A00Z&end=2026-09-20T00%3A00%3A00Z&limit=201",
                );
                (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_DISCOVERED_ROUTES_REQUEST_INVALID",
                )
            }
            _ => {
                *input.body_mut() = Body::from("unexpected body");
                (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_DISCOVERED_ROUTES_REQUEST_INVALID",
                )
            }
        };
        let access_directory = fixture.access_directory.clone();
        let body = response_json(
            router(fixture.control).oneshot(input).await.unwrap(),
            status,
        )
        .await;
        assert_eq!(body["error_code"], code, "{scenario}");
        let events = read_access_events(&access_directory);
        assert_eq!(events.len(), 1, "{scenario}");
        audit(&events[0], "DENY", code);
        fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn discovered_routes_returns_watermark_and_groups_most_frequent_first() {
    let mock = test::Mock::new();
    mock.add(test::handlers::provide_with_summary(
        [
            group_row("GET", "/orders/{id}", 40, 10),
            group_row("GET", "/orders", 5, 20),
        ],
        r#"{"read_rows":"42","read_bytes":"512"}"#,
    ));
    let fixture = Fixture::with_index(
        10,
        ManagementRole::SystemAdmin,
        Client::default().with_mock(&mock),
    );
    let access_directory = fixture.access_directory.clone();
    let response = response_json(
        router(fixture.control)
            .oneshot(request(SITE, WINDOW))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(response["schema_version"], 1);
    assert_eq!(response["tenant_id"], "tenant_a");
    assert_eq!(response["site_id"], "site_a");
    assert_eq!(response["start"], "2026-09-19T00:00:00Z");
    assert_eq!(response["end"], "2026-09-20T00:00:00Z");
    assert_eq!(response["watermark_scope"], "configured_journal");
    assert_eq!(response["scanned_rows"], 42);
    assert_eq!(response["scanned_bytes"], 512);
    assert!(response["truncated"].as_bool().unwrap());
    let routes = response["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0]["method"], "GET");
    assert_eq!(routes[0]["path_template"], "/orders/{id}");
    assert_eq!(routes[0]["hits"], 40);
    let events = read_access_events(&access_directory);
    assert_eq!(events.len(), 1);
    audit(&events[0], "PASS", "CONTROL_DISCOVERED_ROUTES_READ");
    assert_eq!(events[0]["request_id"], response["request_id"]);
    fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
}

fn poison_audit(control: &ControlPlane) {
    std::thread::scope(|scope| {
        let journal = &control.access_journal;
        assert!(
            scope
                .spawn(move || {
                    let _guard = journal.lock().unwrap();
                    panic!("simulate audit failure");
                })
                .join()
                .is_err()
        );
    });
}

#[tokio::test]
async fn discovered_routes_withholds_result_when_audit_or_index_is_unavailable() {
    for scenario in ["audit", "index", "busy"] {
        let fixture = Fixture::with_index(10, ManagementRole::SystemAdmin, Client::default());
        let permit = if scenario == "busy" {
            Some(
                fixture
                    .control
                    .search_capacity
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        if scenario == "audit" {
            poison_audit(&fixture.control);
        }
        let (status, code) = match scenario {
            "busy" => (
                StatusCode::TOO_MANY_REQUESTS,
                "CONTROL_QUERY_CAPACITY_EXHAUSTED",
            ),
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                if scenario == "audit" {
                    "AUDIT_DURABILITY_FAILED"
                } else {
                    "CONTROL_DISCOVERED_ROUTES_INDEX_UNAVAILABLE"
                },
            ),
        };
        let access_directory = fixture.access_directory.clone();
        let response = response_json(
            router(fixture.control)
                .oneshot(request(SITE, WINDOW))
                .await
                .unwrap(),
            status,
        )
        .await;
        assert_eq!(response["error_code"], code, "{scenario}");
        assert!(response.get("routes").is_none());
        if scenario != "audit" {
            let events = read_access_events(&access_directory);
            assert_eq!(events.len(), 1);
            audit(
                &events[0],
                if scenario == "busy" { "DENY" } else { "ERROR" },
                code,
            );
        }
        drop(permit);
        fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
    }
}
