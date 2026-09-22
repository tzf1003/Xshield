use super::*;
use crate::lower_hex;
use openssl::sha::sha256;
use xshield_core::{
    domain::{ArtifactId, AuthBindingId, CalibrationReportId, CaseId, GrantId},
    query::QueryFilter,
};

const GRANT: &str = "grant_018f2a3b-4c5d-7000-8000-000000000101";
const BINDING: &str = "auth_018f2a3b-4c5d-7000-8000-000000000102";
const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000103";
const ARTIFACT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000104";
const REPORT: &str = "calr_018f2a3b-4c5d-7000-8000-000000000105";

pub(super) fn reference_payload() -> Value {
    let mut payload = search_payload();
    payload["filters"] = json!([
        {"kind": "grant_id", "value": GRANT},
        {"kind": "auth_binding_id", "value": BINDING}
    ]);
    payload
}

fn case_reference_payload() -> Value {
    let mut payload = search_payload();
    payload["filters"] = json!([
        {"kind": "case_id", "value": CASE},
        {"kind": "artifact_id", "value": ARTIFACT}
    ]);
    payload
}

fn calibration_report_reference_payload() -> Value {
    let mut payload = search_payload();
    payload["filters"] = json!([{"kind": "calibration_report_id", "value": REPORT}]);
    payload
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn reference_search_returns_redacted_pages_and_audits_the_plan() {
    for mut payload in [reference_payload(), case_reference_payload()] {
        let by_case = payload["filters"][0]["kind"] == "case_id";
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
        if by_case {
            issued.event_type = "evidence.hold.created".to_owned();
            issued.stage = Some("evidence_hold".to_owned());
            issued.reason_code = Some("EVIDENCE_HOLD_CREATED".to_owned());
            issued.evidence_refs = vec![ARTIFACT.to_owned()];
            shared.event_type = "console.evidence.hold.released".to_owned();
            shared.stage = Some("control_access".to_owned());
            shared.reason_code = Some("CONTROL_EVIDENCE_HOLD_RELEASED".to_owned());
            shared.evidence_refs = vec![ARTIFACT.to_owned()];
        }
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
        assert!(first_page["events"][0].get("target_case_id").is_none());
        let canonical = if by_case {
            format!("10|70|asc|1|case_id={CASE}|artifact_id={ARTIFACT}")
        } else {
            format!("10|70|asc|1|grant_id={GRANT}|auth_binding_id={BINDING}")
        };
        assert_eq!(
            first_page["query_digest"],
            lower_hex(&sha256(canonical.as_bytes()))
        );
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
        payload["filters"][0]["value"] = json!(if by_case {
            CASE.replace("103", "109")
        } else {
            GRANT.replace("101", "109")
        });
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
            for reference in [GRANT, BINDING, CASE, ARTIFACT] {
                assert!(!event.to_string().contains(reference));
            }
            assert!(event["payload"]["target_case_id"].is_null());
            assert!(event["payload"]["target_artifact_id"].is_null());
            assert_eq!(event["evidence_refs"], json!([]));
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
}

#[tokio::test]
async fn calibration_report_search_requires_audit_administrator_and_audits_the_plan() {
    let fixture = Fixture::new(10, ManagementRole::Investigator);
    let response = response_json(
        router(fixture.control)
            .oneshot(search_http_request(&calibration_report_reference_payload()))
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(
        response["error_code"],
        "CONTROL_CALIBRATION_REPORT_HISTORY_SCOPE_DENIED"
    );
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "console.query.executed");
    assert_eq!(events[0]["payload"]["outcome"], "DENY");
    assert_eq!(
        events[0]["payload"]["reason_code"],
        "CONTROL_CALIBRATION_REPORT_HISTORY_SCOPE_DENIED"
    );
    assert_eq!(
        events[0]["payload"]["query_digest"],
        lower_hex(&sha256(
            format!("10|70|asc|1|calibration_report_id={REPORT}").as_bytes()
        ))
    );
    assert!(!events[0].to_string().contains(REPORT));
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn calibration_report_search_binds_only_restricted_history() {
    let mock = test::Mock::new();
    let event = search_event("ev_018f2a3b-4c5d-7000-8000-000000000115", 20);
    mock.add(test::handlers::provide([event]));
    let mut fixture = Fixture::with_index(
        10,
        ManagementRole::Investigator,
        Client::default().with_mock(&mock),
    );
    fixture.control.config.principal = ManagementPrincipal::new(
        "operator-1",
        [
            ManagementRole::Investigator,
            ManagementRole::AuditAdministrator,
        ],
        [(
            fixture.control.config.tenant_id.clone(),
            fixture.control.config.site_id.clone(),
        )],
    )
    .unwrap();
    let app = router(fixture.control);
    let response = response_json(
        app.clone()
            .oneshot(search_http_request(&calibration_report_reference_payload()))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    let canonical = format!("10|70|asc|1|calibration_report_id={REPORT}");
    assert_eq!(
        response["query_digest"],
        lower_hex(&sha256(canonical.as_bytes()))
    );
    assert_eq!(response["events"].as_array().map(Vec::len), Some(1));
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "console.query.executed");
    assert!(!events[0].to_string().contains(REPORT));
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn reference_search_rejects_invalid_ids_and_roles_before_index_access() {
    let fixture = Fixture::new(100, ManagementRole::Investigator);
    let app = router(fixture.control);
    let mut attempts = 0;
    for (kind, valid, other) in [
        ("grant_id", GRANT, BINDING),
        ("auth_binding_id", BINDING, GRANT),
        ("case_id", CASE, ARTIFACT),
        ("artifact_id", ARTIFACT, CASE),
        ("calibration_report_id", REPORT, ARTIFACT),
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
        let duplicate = format!(r#"{{"kind":"{kind}","value":"{valid}","value":"{valid}"}}"#);
        let mut payload = search_payload();
        payload["filters"] = json!([]);
        let body = payload
            .to_string()
            .replace("\"filters\":[]", &format!("\"filters\":[{duplicate}]"));
        let response = app
            .clone()
            .oneshot(
                Request::post(super::super::search::SEARCH_PATH)
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response_json(response, StatusCode::UNPROCESSABLE_ENTITY).await["error_code"],
            "CONTROL_QUERY_INVALID"
        );
        attempts += 1;
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
    for (payload, filters) in [
        (
            reference_payload(),
            vec![
                QueryFilter::GrantId(GrantId::parse(GRANT).unwrap()),
                QueryFilter::AuthBindingId(AuthBindingId::parse(BINDING).unwrap()),
            ],
        ),
        (
            case_reference_payload(),
            vec![
                QueryFilter::CaseId(CaseId::parse(CASE).unwrap()),
                QueryFilter::ArtifactId(ArtifactId::parse(ARTIFACT).unwrap()),
            ],
        ),
    ] {
        let fixture = Fixture::new(10, ManagementRole::Investigator);
        let plan = serde_json::from_value::<SearchRequest>(payload.clone())
            .unwrap()
            .into_plan(1000)
            .unwrap();
        assert_eq!(plan.filters(), filters);
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
        let originals = payload["filters"].as_array().unwrap();
        let mut changed_first = originals.clone();
        let mut changed_second = originals.clone();
        for (changed, index) in [(&mut changed_first, 0), (&mut changed_second, 1)] {
            let value = originals[index]["value"].as_str().unwrap();
            changed[index]["value"] = json!(format!("{}f", &value[..value.len() - 1]));
        }
        for filters in [
            json!(changed_first),
            json!(changed_second),
            json!([originals[0]]),
            json!([originals[1]]),
            json!([]),
            json!([originals[1], originals[0]]),
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
        assert_eq!(events.len(), 6);
        assert!(
            events
                .iter()
                .all(|event| event["payload"]["reason_code"] == "CONTROL_CURSOR_INVALID")
        );
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn calibration_report_search_cursor_binds_the_exact_report_reference() {
    let mut fixture = Fixture::new(10, ManagementRole::Investigator);
    fixture.control.config.principal = ManagementPrincipal::new(
        "operator-1",
        [
            ManagementRole::Investigator,
            ManagementRole::AuditAdministrator,
        ],
        [(
            fixture.control.config.tenant_id.clone(),
            fixture.control.config.site_id.clone(),
        )],
    )
    .unwrap();
    let payload = calibration_report_reference_payload();
    let plan = serde_json::from_value::<SearchRequest>(payload.clone())
        .unwrap()
        .into_plan(1000)
        .unwrap();
    assert_eq!(
        plan.filters(),
        [QueryFilter::CalibrationReportId(
            CalibrationReportId::parse(REPORT).unwrap(),
        )]
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
    let mut altered = payload;
    altered["filters"][0]["value"] = json!(REPORT.replace("105", "106"));
    altered["cursor"] = json!(cursor);
    let body = response_json(
        router(fixture.control)
            .oneshot(search_http_request(&altered))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(body["error_code"], "CONTROL_CURSOR_INVALID");
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[test]
fn reference_search_keeps_the_eight_filter_budget() {
    let mut payload = case_reference_payload();
    let pair = payload["filters"].as_array().unwrap().clone();
    payload["filters"] = json!(pair.iter().cycle().take(8).cloned().collect::<Vec<_>>());
    assert_eq!(
        serde_json::from_value::<SearchRequest>(payload.clone())
            .unwrap()
            .into_plan(1000)
            .unwrap()
            .filters()
            .len(),
        8
    );
    payload["filters"]
        .as_array_mut()
        .unwrap()
        .push(pair[0].clone());
    assert!(
        serde_json::from_value::<SearchRequest>(payload)
            .unwrap()
            .into_plan(1000)
            .is_err()
    );
}
