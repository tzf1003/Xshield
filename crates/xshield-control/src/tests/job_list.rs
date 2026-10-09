//! Job listing refuses non-canonical input and foreign cursors before admission,
//! and every refusal writes exactly one `console.job.list` event.

use super::*;
use axum::body::Body;
use xshield_core::domain::JobId;

const PATH: &str = "/control/v1/jobs";
const JOB: &str = "job_018f2a3b-4c5d-7000-8000-000000000991";
const INVALID: &str = "CONTROL_JOB_LIST_REQUEST_INVALID";

fn request(query: &str) -> Request<Body> {
    Request::get(format!("{PATH}{query}"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

// The journal keeps the caller and the outcome, never the cursor, a listed job or
// another principal.
fn audit(event: &Value, outcome: &str, code: &str) {
    assert_eq!(event["event_type"], "console.job.list");
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
    for private in ["cursor=", "\"cursor\"", "owner", "requested_by", TOKEN, JOB] {
        assert!(
            !event.to_string().contains(private),
            "audit leaked {private}"
        );
    }
}

#[tokio::test]
async fn job_list_rejects_noncanonical_input_before_admission() {
    let fixture = Fixture::new(100, ManagementRole::Investigator);
    let id = JobId::parse(JOB).unwrap();
    // A correctly signed cursor minted for another subject must not be replayable.
    let foreign = fixture
        .control
        .encode_job_list_cursor("operator-2", &id)
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
        attempts.push((request(query), INVALID));
    }
    for body in ["x".to_owned(), "{}".to_owned(), "x".repeat(8192)] {
        let mut input = request("");
        *input.body_mut() = Body::from(body);
        attempts.push((input, INVALID));
    }
    attempts.push((request("?cursor=invalid"), "CONTROL_CURSOR_INVALID"));
    attempts.push((
        request(&format!("?cursor={foreign}")),
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
