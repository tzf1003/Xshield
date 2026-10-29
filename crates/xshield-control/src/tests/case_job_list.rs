//! Case-scoped job listing refuses non-canonical input, invalid case
//! identifiers and foreign cursors before admission, and every refusal
//! writes exactly one `console.case.job.list` event.

use super::*;
use axum::body::Body;
use xshield_core::domain::{CaseId, JobId};

const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000981";
const OTHER_CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000982";
const JOB: &str = "job_018f2a3b-4c5d-7000-8000-000000000991";

fn path(case: &str) -> String {
    format!("/control/v1/cases/{case}/jobs")
}

fn request(case: &str, query: &str) -> Request<Body> {
    Request::get(format!("{}{query}", path(case)))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

// The journal keeps the caller, the case and the outcome, never the cursor,
// a listed job or another principal.
fn audit(event: &Value, outcome: &str, code: &str) {
    assert_eq!(event["event_type"], "console.case.job.list");
    assert_eq!(event["payload"]["method"], "GET");
    assert_eq!(event["payload"]["path"], "/control/v1/cases/{case_id}/jobs");
    assert_eq!(event["payload"]["outcome"], outcome);
    assert_eq!(event["payload"]["reason_code"], code);
    assert_eq!(event["evidence_refs"], json!([]));
    for (key, value) in event["payload"].as_object().unwrap() {
        if key.starts_with("target_") && key != "target_case_id" || key == "query_digest" {
            assert!(value.is_null(), "{key}");
        }
    }
    for private in ["cursor=", "\"cursor\"", "owner", "requested_by", TOKEN, JOB] {
        assert!(
            !event.to_string().contains(private),
            "audit leaked {private}"
        );
    }
}

#[tokio::test]
async fn case_job_list_rejects_noncanonical_input_before_admission() {
    let fixture = Fixture::new(100, ManagementRole::Investigator);
    let case_id = CaseId::parse(CASE).unwrap();
    let id = JobId::parse(JOB).unwrap();
    // A correctly signed cursor minted for another subject, or another case,
    // must not be replayable against this case.
    let foreign_subject = fixture
        .control
        .encode_case_job_list_cursor("operator-2", &case_id, &id)
        .unwrap();
    let foreign_case = fixture
        .control
        .encode_case_job_list_cursor("operator-1", &CaseId::parse(OTHER_CASE).unwrap(), &id)
        .unwrap();
    let permit = fixture
        .control
        .case_evidence_capacity
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let app = router(fixture.control);
    let oversized_cursor = format!("?cursor={}", "a".repeat(257));
    let mut attempts = Vec::new();
    for query in [
        "?",
        "?cursor=",
        "?cursor",
        "?view=mine",
        "?Cursor=a",
        "?cursor=a&limit=2",
        "?cursor=a&cursor=b",
        "?limit=2",
        oversized_cursor.as_str(),
    ] {
        attempts.push((
            request(CASE, query),
            "CONTROL_CASE_JOB_LIST_REQUEST_INVALID",
        ));
    }
    for body in ["x".to_owned(), "{}".to_owned(), "x".repeat(8192)] {
        let mut input = request(CASE, "");
        *input.body_mut() = Body::from(body);
        attempts.push((input, "CONTROL_CASE_JOB_LIST_REQUEST_INVALID"));
    }
    for bad_case in ["bad", "%FF", ""] {
        attempts.push((request(bad_case, ""), "CONTROL_CASE_ID_INVALID"));
    }
    attempts.push((request(CASE, "?cursor=invalid"), "CONTROL_CURSOR_INVALID"));
    attempts.push((
        request(CASE, &format!("?cursor={foreign_subject}")),
        "CONTROL_CURSOR_INVALID",
    ));
    attempts.push((
        request(CASE, &format!("?cursor={foreign_case}")),
        "CONTROL_CURSOR_INVALID",
    ));
    let mut expected = Vec::new();
    for (input, code) in attempts {
        let response = app.clone().oneshot(input).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{code}");
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body["error_code"], code);
        assert_eq!(body["retryable"], false);
        assert_eq!(body["next_action"], "restart_query");
        expected.push(code);
    }
    drop(app);
    drop(permit);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), expected.len());
    for (event, code) in events.iter().zip(expected) {
        audit(event, "DENY", code);
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn case_job_list_enforces_authentication_scope_role_and_rate() {
    for scenario in ["missing_auth", "role", "scope", "expired", "rate"] {
        let mut fixture = Fixture::new(1, ManagementRole::Investigator);
        let mut request = request(CASE, "");
        let (expected, code) = match scenario {
            "missing_auth" => {
                request.headers_mut().remove(AUTHORIZATION);
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
            "scope" => {
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [ManagementRole::Investigator],
                    [(
                        TenantId::parse("other").unwrap(),
                        SiteId::parse("site_a").unwrap(),
                    )],
                )
                .unwrap();
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED")
            }
            "expired" => {
                fixture.control.config.credential.expires_at = 1;
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            _ => {
                fixture.control.rate.lock().unwrap().used = 1;
                (StatusCode::TOO_MANY_REQUESTS, "CONTROL_RATE_LIMITED")
            }
        };
        let response = router(fixture.control).oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body["error_code"], code);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], "console.case.job.list");
        assert_eq!(events[0]["payload"]["target_case_id"], Value::Null);
        assert_eq!(events[0]["payload"]["reason_code"], code);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn case_job_list_cursor_binds_identity_case_scope_limit_and_purpose() {
    for binding in [
        "credential",
        "subject",
        "case",
        "tenant",
        "site",
        "limit",
        "key",
        "position",
    ] {
        let mut fixture = Fixture::new(10, ManagementRole::Investigator);
        let case_id = CaseId::parse(CASE).unwrap();
        let id = JobId::parse(JOB).unwrap();
        let mut cursor = fixture
            .control
            .encode_case_job_list_cursor("operator-1", &case_id, &id)
            .unwrap();
        let mut query_case = case_id.clone();
        let subject = match binding {
            "credential" => {
                fixture.control.config.credential.token_digest[0] ^= 1;
                "operator-1"
            }
            "subject" => "operator-2",
            "case" => {
                query_case = CaseId::parse(OTHER_CASE).unwrap();
                "operator-1"
            }
            "tenant" => {
                fixture.control.config.tenant_id = TenantId::parse("other").unwrap();
                "operator-1"
            }
            "site" => {
                fixture.control.config.site_id = SiteId::parse("other").unwrap();
                "operator-1"
            }
            "limit" => {
                fixture.control.config.limits.max_query_artifacts += 1;
                "operator-1"
            }
            "key" => {
                fixture.control.config.cursor_key.0[0] ^= 1;
                "operator-1"
            }
            _ => {
                cursor = cursor.replace("000000000991", "000000000992");
                "operator-1"
            }
        };
        assert_eq!(
            fixture
                .control
                .decode_case_job_list_cursor(subject, &query_case, &cursor),
            Err(crate::CursorError::Invalid),
            "{binding}"
        );
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn case_job_list_bounds_inflight_work_and_reports_store_failure() {
    for busy in [true, false] {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let fixture = Fixture::with_case_catalog(PostgresIdentityStore::from_pool(pool), 1);
        let permit = if busy {
            Some(
                fixture
                    .control
                    .case_evidence_capacity
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let response = router(fixture.control)
            .oneshot(request(CASE, ""))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if busy {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            }
        );
        let code = if busy {
            "CONTROL_CASE_JOB_LIST_BUSY"
        } else {
            "CONTROL_JOB_STORE_UNAVAILABLE"
        };
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body["error_code"], code);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], "console.case.job.list");
        assert_eq!(events[0]["payload"]["target_case_id"], CASE);
        assert_eq!(events[0]["payload"]["reason_code"], code);
        assert_eq!(events[0]["evidence_refs"], json!([]));
        drop(permit);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}
