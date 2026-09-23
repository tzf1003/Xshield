use super::*;
use serde_json::{Value, json};
use tower::ServiceExt;
use xshield_core::admin::ManagementRole;

const ROOT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000201";
const PARENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000202";
const CHILD: &str = "ev_018f2a3b-4c5d-7000-8000-000000000203";
const GRANDPARENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000204";

fn request(body: &Value) -> Request<Body> {
    Request::post(crate::causality::PATH)
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn plan(root: &str) -> Value {
    json!({
        "schema_version": 3,
        "start": "1970-01-01T00:00:10Z",
        "end": "1970-01-01T00:01:40Z",
        "event_id": root,
        "direction": "both",
        "max_depth": 3,
        "max_nodes": 8
    })
}

async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn causality_rejects_invalid_requests_and_non_investigators() {
    let invalid = Fixture::new(10, ManagementRole::Investigator);
    let response = router(invalid.control)
        .oneshot(request(&json!({
            "schema_version": 3,
            "start": "1970-01-01T00:00:10Z",
            "end": "1970-01-01T00:01:40Z",
            "event_id": "not-an-event",
            "direction": "both",
            "max_depth": 3,
            "max_nodes": 8
        })))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let value = body(response).await;
    assert_eq!(value["error_code"], "CONTROL_CAUSALITY_REQUEST_INVALID");
    let events = read_access_events(&invalid.access_directory);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "console.causality.read");
    assert_eq!(events[0]["payload"]["outcome"], "DENY");
    assert_eq!(events[0]["payload"]["query_digest"], Value::Null);
    fs::remove_dir_all(invalid.access_directory.parent().unwrap()).unwrap();

    let forbidden = Fixture::new(10, ManagementRole::Observer);
    let response = router(forbidden.control)
        .oneshot(request(&plan(ROOT)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let events = read_access_events(&forbidden.access_directory);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "console.causality.read");
    fs::remove_dir_all(forbidden.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn causality_traverses_redacted_predecessors_and_successors_with_one_audit() {
    let mock = test::Mock::new();
    let mut root = search_event(ROOT, 20);
    root.cause_event_ids = vec![PARENT.to_owned()];
    let mut parent = search_event(PARENT, 30);
    parent.cause_event_ids = vec![GRANDPARENT.to_owned()];
    let mut child = search_event(CHILD, 40);
    child.cause_event_ids = vec![ROOT.to_owned()];
    let grandparent = search_event(GRANDPARENT, 10);
    mock.add(test::handlers::provide([root]));
    mock.add(test::handlers::provide([parent]));
    mock.add(test::handlers::provide([child]));
    mock.add(test::handlers::provide([grandparent]));
    mock.add(test::handlers::provide(Vec::<
        xshield_worker::SearchEventSummary,
    >::new()));
    let fixture = Fixture::with_index(
        10,
        ManagementRole::Investigator,
        Client::default().with_mock(&mock),
    );
    let app = router(fixture.control);
    let response = app.oneshot(request(&plan(ROOT))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    let value = body(response).await;
    assert_eq!(value["found"], true);
    assert_eq!(value["root_event_id"], ROOT);
    assert_eq!(value["truncated"], false);
    assert_eq!(value["nodes"].as_array().unwrap().len(), 3);
    assert_eq!(value["nodes"][0]["direction"], "predecessor");
    assert_eq!(value["nodes"][0]["depth"], 1);
    assert_eq!(value["nodes"][1]["direction"], "successor");
    assert_eq!(value["nodes"][2]["depth"], 2);
    assert!(value["nodes"][0]["event"].get("payload_json").is_none());
    assert!(!value.to_string().contains("query_digest"));

    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "console.causality.read");
    assert_eq!(events[0]["payload"]["outcome"], "PASS");
    assert_eq!(
        events[0]["payload"]["reason_code"],
        "CONTROL_CAUSALITY_READ"
    );
    assert!(events[0].to_string().contains("query_digest"));
    for id in [ROOT, PARENT, CHILD, GRANDPARENT] {
        assert!(!events[0].to_string().contains(id));
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}
