//! HTTP contract regressions for redacted model-call discovery.

use super::*;
use crate::{CursorError, model_call_list::PATH};
use chrono::DateTime;
use xshield_core::{domain::ModelCallId, identity::UnixSeconds, query::QueryWindow};
use xshield_worker::{ModelCallListPlan, ModelCallListPosition};

const REQUEST: &str = "req_018f2a3b-4c5d-7000-8000-000000000001";
const MODEL: &str = "mdl_018f2a3b-4c5d-7000-8000-000000000001";
const OTHER_MODEL: &str = "mdl_018f2a3b-4c5d-7000-8000-000000000002";
const INPUT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000001";
const OUTPUT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000002";
const CALL: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000003";
const WINDOW: &str = "start=2026-09-19T00%3A00%3A00Z&end=2026-09-20T00%3A00%3A00Z&limit=1";

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
struct ModelListRow {
    model_call_id: String,
    request_id: String,
    event_type: String,
    #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
    occurred_at: DateTime<Utc>,
    evidence_refs: Vec<String>,
    payload_json: String,
}

fn lifecycle_row(model_call_id: &str, seconds: u8) -> ModelListRow {
    ModelListRow {
        model_call_id: model_call_id.to_owned(),
        event_type: "model.responded".to_owned(),
        request_id: REQUEST.to_owned(),
        occurred_at: DateTime::parse_from_rfc3339(&format!("2026-09-19T00:00:{seconds:02}.000Z"))
            .unwrap()
            .with_timezone(&Utc),
        evidence_refs: vec![INPUT.to_owned(), OUTPUT.to_owned(), CALL.to_owned()],
        payload_json: json!({
            "model_call_id": model_call_id,
            "provider": "vercel_ai_gateway",
            "provider_model_id": "typesafe-ai/jev",
            "model_revision": "jev-1.13.0",
            "prompt_revision": "evaluation-r1",
            "question_type": "choice",
            "status": "success",
            "reason_code": "MODEL_EVALUATED",
            "confidence": 0.8,
            "confidence_status": "provided",
            "duration_us": 1200,
            "input_artifact_id": INPUT,
            "output_artifact_id": OUTPUT,
            "call_artifact_id": CALL
        })
        .to_string(),
    }
}

fn plan(limit: u16) -> ModelCallListPlan {
    ModelCallListPlan::new(
        QueryWindow::new(
            UnixSeconds::new(1_789_776_000),
            UnixSeconds::new(1_789_862_400),
        )
        .unwrap(),
        limit,
    )
    .unwrap()
}

fn audit(event: &Value, outcome: &str, code: &str) {
    assert_eq!(event["event_type"], "console.model.list");
    assert_eq!(event["payload"]["method"], "GET");
    assert_eq!(event["payload"]["path"], PATH);
    assert_eq!(event["payload"]["outcome"], outcome);
    assert_eq!(event["payload"]["reason_code"], code);
    assert_eq!(event["evidence_refs"], json!([]));
    for (key, value) in event["payload"].as_object().unwrap() {
        if key.starts_with("target_") || matches!(key.as_str(), "query_digest" | "bytes_read") {
            assert!(value.is_null(), "{key}");
        }
    }
    for excluded in ["cursor=", MODEL, INPUT, OUTPUT, CALL, TOKEN] {
        assert!(!event.to_string().contains(excluded), "{excluded}");
    }
}

#[tokio::test]
async fn model_call_list_requires_observer_and_audits_validated_rejections() {
    for scenario in ["missing", "duplicate", "role", "invalid", "cursor", "body"] {
        let mut fixture = Fixture::new(100, ManagementRole::Observer);
        let mut input = request(WINDOW);
        let (status, code) = match scenario {
            "missing" => {
                input.headers_mut().remove(AUTHORIZATION);
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "duplicate" => {
                input
                    .headers_mut()
                    .append(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "role" => {
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [ManagementRole::Investigator],
                    [(
                        TenantId::parse("tenant_a").unwrap(),
                        SiteId::parse("site_a").unwrap(),
                    )],
                )
                .unwrap();
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED")
            }
            "invalid" => {
                input = request(
                    "start=2026-09-19T00%3A00%3A00Z&end=2026-09-20T00%3A00%3A00Z&limit=101",
                );
                (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_MODEL_CALLS_REQUEST_INVALID",
                )
            }
            "cursor" => {
                input = request(&format!("{WINDOW}&cursor=invalid"));
                (StatusCode::BAD_REQUEST, "CONTROL_CURSOR_INVALID")
            }
            _ => {
                *input.body_mut() = Body::from("unexpected body");
                (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_MODEL_CALLS_REQUEST_INVALID",
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
        assert_eq!(events.len(), 1);
        audit(&events[0], "DENY", code);
        fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn model_call_list_cursor_binds_subject_scope_window_limit_sort_and_position() {
    for binding in [
        "credential",
        "subject",
        "tenant",
        "site",
        "window",
        "limit",
        "key",
        "position",
        "family",
        "encoding",
    ] {
        let mut fixture = Fixture::new(10, ManagementRole::Observer);
        let position = ModelCallListPosition::new(
            DateTime::parse_from_rfc3339("2026-09-19T00:00:03.000Z")
                .unwrap()
                .with_timezone(&Utc),
            ModelCallId::parse(MODEL).unwrap(),
        )
        .unwrap();
        let mut cursor = fixture
            .control
            .encode_model_call_list_cursor("operator-1", &plan(1), &position)
            .unwrap();
        assert_eq!(
            fixture
                .control
                .decode_model_call_list_cursor("operator-1", &plan(1), &cursor),
            Ok(position.clone())
        );
        let mut subject = "operator-1";
        let mut decoded_plan = plan(1);
        match binding {
            "credential" => fixture.control.config.credential.token_digest[0] ^= 1,
            "subject" => subject = "operator-2",
            "tenant" => fixture.control.config.tenant_id = TenantId::parse("other").unwrap(),
            "site" => fixture.control.config.site_id = SiteId::parse("other").unwrap(),
            "window" => {
                decoded_plan = ModelCallListPlan::new(
                    QueryWindow::new(
                        UnixSeconds::new(1_789_776_001),
                        UnixSeconds::new(1_789_862_400),
                    )
                    .unwrap(),
                    1,
                )
                .unwrap();
            }
            "limit" => decoded_plan = plan(2),
            "key" => fixture.control.config.cursor_key.0[0] ^= 1,
            "position" => cursor = cursor.replace("000000000001", "000000000002"),
            "family" => cursor = cursor.replace("v1", "v2"),
            _ => cursor = cursor.to_uppercase(),
        }
        assert_eq!(
            fixture
                .control
                .decode_model_call_list_cursor(subject, &decoded_plan, &cursor),
            Err(CursorError::Invalid),
            "{binding}"
        );
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn model_call_list_projects_only_latest_window_metadata_and_requires_durable_audit() {
    let mock = test::Mock::new();
    mock.add(test::handlers::provide_with_summary(
        [lifecycle_row(OTHER_MODEL, 3), lifecycle_row(MODEL, 2)],
        r#"{"read_rows":"42","read_bytes":"512"}"#,
    ));
    let fixture = Fixture::with_index(
        10,
        ManagementRole::Observer,
        Client::default().with_mock(&mock),
    );
    let access_directory = fixture.access_directory.clone();
    let response = response_json(
        router(fixture.control)
            .oneshot(request(WINDOW))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(response["schema_version"], 3);
    assert_eq!(response["tenant_id"], "tenant_a");
    assert_eq!(response["site_id"], "site_a");
    assert_eq!(response["start"], "2026-09-19T00:00:00Z");
    assert_eq!(response["end"], "2026-09-20T00:00:00Z");
    assert_eq!(response["watermark_scope"], "configured_journal");
    assert_eq!(response["scanned_rows"], 42);
    assert_eq!(response["scanned_bytes"], 512);
    assert!(response["truncated"].as_bool().unwrap());
    let cursor = response["next_cursor"].as_str().unwrap();
    assert!(cursor.starts_with("v1."));
    assert_eq!(response["items"].as_array().unwrap().len(), 1);
    let item = &response["items"][0];
    assert_eq!(item["model_call_id"], OTHER_MODEL);
    assert_eq!(item["request_id"], REQUEST);
    assert_eq!(item["occurred_at"], "2026-09-19T00:00:03.000000Z");
    assert_eq!(item["latest_status"], "success");
    assert_eq!(item["latest_reason_code"], "MODEL_EVALUATED");
    assert_eq!(item["latest_confidence_status"], "provided");
    for absent in [
        "evidence_refs",
        "confidence",
        "input_artifact_id",
        "output_artifact_id",
        "call_artifact_id",
        "payload_json",
        "probabilities",
    ] {
        assert!(item.get(absent).is_none(), "{absent}");
    }
    let events = read_access_events(&access_directory);
    assert_eq!(events.len(), 1);
    audit(&events[0], "PASS", "CONTROL_MODEL_CALLS_READ");
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
async fn model_call_list_withholds_result_when_audit_or_index_is_unavailable() {
    for scenario in ["audit", "index", "busy"] {
        let fixture = Fixture::with_index(10, ManagementRole::Observer, Client::default());
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
                    "CONTROL_MODEL_CALLS_INDEX_UNAVAILABLE"
                },
            ),
        };
        let access_directory = fixture.access_directory.clone();
        let response = response_json(
            router(fixture.control)
                .oneshot(request(WINDOW))
                .await
                .unwrap(),
            status,
        )
        .await;
        assert_eq!(response["error_code"], code, "{scenario}");
        assert!(response.get("items").is_none());
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
