//! Saved view refusals happen before any storage write, and each one writes exactly one
//! `console.saved_view.*` event that carries no view identity, name or search body.

use super::*;
use axum::body::Body;

const PATH: &str = "/control/v1/saved-views";
const VIEW: &str = "view_018f2a3b-4c5d-7000-8000-000000000991";
const SECRET_NAME: &str = "Private saved name";

fn auth(builder: axum::http::request::Builder) -> axum::http::request::Builder {
    builder.header(AUTHORIZATION, format!("Bearer {TOKEN}"))
}

fn audit(event: &Value, kind: &str, outcome: &str, code: &str) {
    assert_eq!(event["event_type"], kind);
    assert_eq!(event["payload"]["outcome"], outcome);
    assert_eq!(event["payload"]["reason_code"], code);
    assert_eq!(event["evidence_refs"], json!([]));
    let text = event.to_string();
    for private in [SECRET_NAME, VIEW, "cursor", "filters", TOKEN] {
        assert!(!text.contains(private), "audit leaked {private}");
    }
}

#[tokio::test]
async fn saved_view_refusals_are_audited_and_leak_nothing() {
    let fixture = Fixture::new(100, ManagementRole::Investigator);
    let permit = fixture
        .control
        .case_evidence_capacity
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let app = router(fixture.control);
    let body = |value: Value| {
        auth(Request::post(PATH))
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .unwrap()
    };
    let mut attempts: Vec<(Request<Body>, &str, &str, &str)> = vec![
        // Not a JSON object, a wrong schema version, an empty or control-bearing name.
        (
            body(json!(["x"])),
            "console.saved_view.create",
            "DENY",
            "CONTROL_SAVED_VIEW_REQUEST_INVALID",
        ),
        (
            body(json!({"schema_version": 2, "name": SECRET_NAME, "search": {}})),
            "console.saved_view.create",
            "DENY",
            "CONTROL_SAVED_VIEW_REQUEST_INVALID",
        ),
        (
            body(json!({"schema_version": 1, "name": "", "search": {}})),
            "console.saved_view.create",
            "DENY",
            "CONTROL_SAVED_VIEW_REQUEST_INVALID",
        ),
        // A search carrying a cursor is never stored, even if it is otherwise valid.
        (
            body(json!({"schema_version": 1, "name": SECRET_NAME, "search": {"cursor": "v1.x"}})),
            "console.saved_view.create",
            "DENY",
            "CONTROL_SAVED_VIEW_REQUEST_INVALID",
        ),
        (
            Request::get(format!("{PATH}?cursor=invalid"))
                .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
            "console.saved_view.list",
            "DENY",
            "CONTROL_CURSOR_INVALID",
        ),
        (
            Request::get(format!("{PATH}?view=mine"))
                .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
            "console.saved_view.list",
            "DENY",
            "CONTROL_SAVED_VIEW_REQUEST_INVALID",
        ),
        (
            auth(Request::delete(format!("{PATH}/view_not-a-uuid")))
                .body(Body::empty())
                .unwrap(),
            "console.saved_view.delete",
            "DENY",
            "CONTROL_SAVED_VIEW_ID_INVALID",
        ),
    ];
    let mut expected = Vec::new();
    for (request, kind, outcome, code) in attempts.drain(..) {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{code}");
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(value["error_code"], code);
        expected.push((kind, outcome, code));
    }
    drop(app);
    drop(permit);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), expected.len());
    for (event, (kind, outcome, code)) in events.iter().zip(expected) {
        audit(event, kind, outcome, code);
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}
