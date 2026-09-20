use super::*;
use xshield_core::{
    domain::{AuthBindingId, GrantId},
    query::QueryFilter,
};

const GRANT: &str = "grant_018f2a3b-4c5d-7000-8000-000000000101";
const BINDING: &str = "auth_018f2a3b-4c5d-7000-8000-000000000102";

pub(super) fn reference_payload() -> Value {
    let mut payload = search_payload();
    payload["filters"] = json!([
        {"kind": "grant_id", "value": GRANT},
        {"kind": "auth_binding_id", "value": BINDING}
    ]);
    payload
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn reference_search_returns_redacted_pages_and_audits_the_plan() {
    let mock = test::Mock::new();
    let first = "ev_018f2a3b-4c5d-7000-8000-000000000111";
    let second = "ev_018f2a3b-4c5d-7000-8000-000000000112";
    let mut issued = search_event(first, 20);
    issued.event_type = "response_grant.issued".to_owned();
    issued.stage = Some("response_grant".to_owned());
    issued.reason_code = Some("GRANT_ISSUED".to_owned());
    let mut shared = search_event(second, 30);
    shared.event_type = "share.issued".to_owned();
    shared.stage = Some("share_grant".to_owned());
    shared.reason_code = Some("SHARE_ISSUED".to_owned());
    mock.add(test::handlers::provide([issued, shared.clone()]));
    mock.add(test::handlers::provide([shared]));
    mock.add(test::handlers::provide(Vec::<
        xshield_worker::SearchEventSummary,
    >::new()));
    let fixture = Fixture::with_index(
        10,
        ManagementRole::Investigator,
        Client::default().with_mock(&mock),
    );
    let app = router(fixture.control);
    let mut payload = reference_payload();
    let first_page = response_json(
        app.clone()
            .oneshot(search_http_request(&payload))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(first_page["events"][0]["event_id"], first);
    assert_eq!(
        first_page["events"][0]["request_id"],
        "req_018f2a3b-4c5d-7000-8000-000000000001"
    );
    assert_eq!(first_page["tenant_id"], "tenant_a");
    assert_eq!(first_page["site_id"], "site_a");
    assert_eq!(first_page["truncated"], true);
    assert!(first_page["events"][0].get("payload_json").is_none());
    assert!(first_page["events"][0].get("grant_status").is_none());
    payload["cursor"] = first_page["next_cursor"].clone();
    let second_page = response_json(
        app.clone()
            .oneshot(search_http_request(&payload))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(second_page["events"][0]["event_id"], second);
    assert_eq!(second_page["query_digest"], first_page["query_digest"]);
    assert_eq!(second_page["truncated"], false);
    payload.as_object_mut().unwrap().remove("cursor");
    payload["filters"][0]["value"] = json!(GRANT.replace("101", "103"));
    let missing = response_json(
        app.clone()
            .oneshot(search_http_request(&payload))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(missing["events"], json!([]));
    assert_ne!(missing["query_digest"], first_page["query_digest"]);
    assert!(missing.get("index_watermark").is_some());
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 3);
    for event in &events {
        assert_eq!(event["event_type"], "console.query.executed");
        assert_eq!(event["payload"]["reason_code"], "CONTROL_QUERY_EXECUTED");
        assert!(event["payload"]["target_request_id"].is_null());
        assert!(event["payload"].get("filters").is_none());
        assert!(!event.to_string().contains(GRANT));
        assert!(!event.to_string().contains(BINDING));
    }
    let digests = events
        .iter()
        .map(|event| event["payload"]["query_digest"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        digests
            .iter()
            .filter(|digest| **digest == first_page["query_digest"])
            .count(),
        2
    );
    assert!(digests.contains(&missing["query_digest"]));
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn reference_search_rejects_invalid_ids_and_roles_before_index_access() {
    let fixture = Fixture::new(100, ManagementRole::Investigator);
    let app = router(fixture.control);
    let mut attempts = 0;
    for (kind, valid, other) in [
        ("grant_id", GRANT, BINDING),
        ("auth_binding_id", BINDING, GRANT),
    ] {
        for invalid in [
            json!(other),
            json!(valid.to_uppercase()),
            json!(valid.replace("7000", "4000")),
            json!(format!("{valid}' OR 1=1")),
            json!(""),
            json!(null),
            json!(123),
        ] {
            let mut payload = search_payload();
            payload["filters"] = json!([{"kind": kind, "value": invalid}]);
            let body = response_json(
                app.clone()
                    .oneshot(search_http_request(&payload))
                    .await
                    .unwrap(),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
            assert_eq!(body["error_code"], "CONTROL_QUERY_INVALID");
            attempts += 1;
        }
        for filter in [
            json!({"kind":kind}),
            json!({"kind":kind,"value":valid,"tenant_id":"tenant_b"}),
        ] {
            let mut payload = search_payload();
            payload["filters"] = json!([filter]);
            let body = response_json(
                app.clone()
                    .oneshot(search_http_request(&payload))
                    .await
                    .unwrap(),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
            assert_eq!(body["error_code"], "CONTROL_QUERY_INVALID");
            attempts += 1;
        }
    }
    drop(app);
    assert_access_events(
        &fixture.access_directory,
        attempts,
        "console.query.executed",
        None,
    );
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    for (role, authenticated, status) in [
        (ManagementRole::Observer, true, StatusCode::FORBIDDEN),
        (
            ManagementRole::Investigator,
            false,
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let fixture = Fixture::new(10, role);
        let mut request = search_http_request(&reference_payload());
        if !authenticated {
            request.headers_mut().remove(AUTHORIZATION);
        }
        response_json(
            router(fixture.control).oneshot(request).await.unwrap(),
            status,
        )
        .await;
        assert_access_events(&fixture.access_directory, 1, "console.query.executed", None);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn reference_search_cursor_binds_each_typed_reference() {
    let fixture = Fixture::new(10, ManagementRole::Investigator);
    let payload = reference_payload();
    let plan = serde_json::from_value::<SearchRequest>(payload.clone())
        .unwrap()
        .into_plan(1000)
        .unwrap();
    assert_eq!(
        plan.filters(),
        &[
            QueryFilter::GrantId(GrantId::parse(GRANT).unwrap()),
            QueryFilter::AuthBindingId(AuthBindingId::parse(BINDING).unwrap()),
        ]
    );
    let position = xshield_worker::SearchPosition::new(
        DateTime::from_timestamp_micros(20_123_456).unwrap(),
        EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
    )
    .unwrap();
    let cursor = fixture
        .control
        .encode_search_cursor("operator-1", &plan, &position)
        .unwrap();
    assert_eq!(
        fixture
            .control
            .decode_search_cursor("operator-1", &plan, &cursor)
            .unwrap(),
        position
    );
    let app = router(fixture.control);
    for filters in [
        json!([{"kind":"grant_id","value":GRANT.replace("101", "103")}, {"kind":"auth_binding_id","value":BINDING}]),
        json!([{"kind":"grant_id","value":GRANT}, {"kind":"auth_binding_id","value":BINDING.replace("102", "104")}]),
        json!([{"kind":"grant_id","value":GRANT}]),
        json!([{"kind":"auth_binding_id","value":BINDING}]),
        json!([]),
    ] {
        let mut altered = payload.clone();
        altered["filters"] = filters;
        altered["cursor"] = json!(cursor);
        let body = response_json(
            app.clone()
                .oneshot(search_http_request(&altered))
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(body["error_code"], "CONTROL_CURSOR_INVALID");
    }
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 5);
    assert!(
        events
            .iter()
            .all(|event| event["payload"]["reason_code"] == "CONTROL_CURSOR_INVALID")
    );
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}
