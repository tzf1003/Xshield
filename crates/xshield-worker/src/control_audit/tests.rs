use crate::{IndexRow, PublishError};
use chrono::TimeDelta;
use serde_json::{Value, json};
use xshield_core::domain::EventId;

const EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000001";
const BOOT: &str = "018f2a3b-4c5d-7000-8000-000000000002";
const REQUEST: &str = "req_018f2a3b-4c5d-7000-8000-000000000003";
const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000004";
const ARTIFACT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000005";
const OTHER_ARTIFACT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000006";
const ACCESS: &str = "access_018f2a3b-4c5d-7000-8000-000000000007";
const MODEL: &str = "mdl_018f2a3b-4c5d-7000-8000-000000000008";
const GRANT: &str = "grant_018f2a3b-4c5d-7000-8000-000000000009";
const BINDING: &str = "auth_018f2a3b-4c5d-7000-8000-00000000000a";
const HOLD: &str = "ev_018f2a3b-4c5d-7000-8000-00000000000b";
const REPORT: &str = "calr_018f2a3b-4c5d-7000-8000-00000000000c";
const HOLD_ACTIONS: &[(&str, &str, &str, &str)] = &[
    (
        "console.evidence.hold.created",
        "POST",
        "/control/v1/cases/{case_id}/holds",
        "CONTROL_EVIDENCE_HOLD_CREATED",
    ),
    (
        "console.evidence.hold.released",
        "POST",
        "/control/v1/evidence-holds/{hold_id}/release",
        "CONTROL_EVIDENCE_HOLD_RELEASED",
    ),
    (
        "console.evidence.hold.read",
        "GET",
        "/control/v1/cases/{case_id}/holds",
        "CONTROL_EVIDENCE_HOLD_READ",
    ),
];

// This envelope represents one case-collection access attempt, including the
// null target fields emitted by the control producer before optional additions.
fn event() -> Value {
    json!({
        "schema_version": 3, "event_id": EVENT, "event_type": "console.case.read",
        "tenant_id": "tenant_demo", "site_id": "site_demo", "request_id": REQUEST,
        "trace_id": "018f2a3b4c5d70008000000000000003", "span_id": "018f2a3b4c5d7000",
        "producer_id": "xshield-control", "producer_boot_id": BOOT,
        "producer_seq": 1, "request_seq": 1,
        "occurred_at": "2026-09-19T00:00:00.123Z", "observed_at": "2026-09-19T00:00:00.123Z",
        "policy_revision": "control-v1", "example_only": false,
        "evidence_refs": [ARTIFACT], "cause_event_ids": [],
        "payload": {
            "method": "GET", "path": "/control/v1/cases/{case_id}/items",
            "subject_ref": "audit-operator", "target_request_id": null,
            "target_artifact_id": null, "target_case_id": CASE,
            "target_access_request_id": null, "outcome": "PASS",
            "reason_code": "CONTROL_CASE_EVIDENCE_READ"
        },
        "sensitivity": "INTERNAL",
        "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
    })
}

fn index_bytes(bytes: &[u8]) -> Result<IndexRow, PublishError> {
    IndexRow::parse(
        bytes,
        &EventId::parse(EVENT).unwrap(),
        1,
        BOOT,
        "1".repeat(64),
        TimeDelta::days(30),
    )
}

fn index(event: &Value) -> Result<IndexRow, PublishError> {
    index_bytes(&serde_json::to_vec(event).unwrap())
}

fn rejected(event: &Value, scenario: &str) {
    assert!(
        matches!(
            index(event),
            Err(PublishError::InvalidEvent | PublishError::Json(_))
        ),
        "accepted {scenario}"
    );
}

#[test]
fn management_success_denial_and_error_have_deterministic_nonterminal_summaries() {
    for outcome in ["PASS", "DENY", "ERROR"] {
        let mut event = event();
        event["payload"]["outcome"] = outcome.into();
        if outcome != "PASS" {
            event["payload"]["subject_ref"] = Value::Null;
            event["payload"]["target_case_id"] = Value::Null;
            event["evidence_refs"] = json!([]);
        }
        let row = index(&event).unwrap();
        assert_eq!(row.stage, "control_access");
        assert_eq!(row.method, "GET");
        assert_eq!(row.outcome, outcome);
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.is_terminal, 0);
        assert_eq!(row.http_status, None);
        assert!(row.origin_state.is_empty());
        assert!(row.operation_id.is_empty());
        assert!(row.model_revision.is_empty());
        assert_eq!(row.duration_us, 0);
    }
    let mut event = event();
    event["payload"]["subject_ref"] = "审计员".into();
    assert!(index(&event).is_ok());
}

#[test]
fn case_listing_publishes_only_scoped_access_facts() {
    let mut value = event();
    value["event_type"] = "console.case.list".into();
    value["payload"]["path"] = "/control/v1/cases".into();
    value["payload"]["target_case_id"] = Value::Null;
    value["payload"]["reason_code"] = "CONTROL_CASES_READ".into();
    value["evidence_refs"] = json!([]);
    let row = index(&value).unwrap();
    assert_eq!(row.stage, "control_access");
    assert_eq!(row.confidence, None);
    assert_eq!(row.is_terminal, 0);
    for (field, content) in [
        ("method", json!("POST")),
        ("path", json!("/control/v1/cases?cursor=opaque")),
        ("subject_ref", Value::Null),
        ("target_case_id", json!(CASE)),
        ("target_artifact_id", json!(ARTIFACT)),
        ("query_digest", json!("a".repeat(64))),
        ("bytes_read", json!(0)),
        ("reason_code", json!("CONTROL_CASE_CREATED")),
        ("purpose", json!("excluded")),
        ("cursor", json!("excluded")),
    ] {
        let mut invalid = value.clone();
        invalid["payload"][field] = content;
        rejected(&invalid, field);
    }
    let mut referenced = value.clone();
    referenced["evidence_refs"] = json!([ARTIFACT]);
    rejected(&referenced, "case listing has no evidence targets");
    for (outcome, reason) in [
        ("DENY", "CONTROL_SCOPE_DENIED"),
        ("ERROR", "CONTROL_CASE_STORE_UNAVAILABLE"),
    ] {
        value["payload"]["subject_ref"] = Value::Null;
        value["payload"]["outcome"] = outcome.into();
        value["payload"]["reason_code"] = reason.into();
        assert_eq!(index(&value).unwrap().outcome, outcome);
    }
}

#[test]
fn oidc_session_audit_contract_is_fixed_and_does_not_index_credentials() {
    for (kind, method, path, reason, subject) in [
        (
            "console.auth.login",
            "GET",
            "/control/v1/auth/oidc/start",
            "CONTROL_OIDC_LOGIN_STARTED",
            None,
        ),
        (
            "console.auth.callback",
            "GET",
            "/control/v1/auth/oidc/callback",
            "CONTROL_OIDC_LOGIN_COMPLETED",
            Some("oidc-subject-1"),
        ),
        (
            "console.auth.session.read",
            "GET",
            "/control/v1/session",
            "CONTROL_BROWSER_SESSION_READ",
            Some("oidc-subject-1"),
        ),
        (
            "console.auth.session.logout",
            "POST",
            "/control/v1/session/logout",
            "CONTROL_BROWSER_SESSION_REVOKED",
            Some("oidc-subject-1"),
        ),
    ] {
        let mut value = event();
        value["event_type"] = kind.into();
        value["payload"]["method"] = method.into();
        value["payload"]["path"] = path.into();
        value["payload"]["reason_code"] = reason.into();
        value["payload"]["subject_ref"] = subject.map_or(Value::Null, Value::from);
        value["payload"]["target_case_id"] = Value::Null;
        value["evidence_refs"] = json!([]);
        assert!(index(&value).is_ok(), "{kind}");

        value["payload"]["reason_code"] = "CONTROL_INVALID_INPUT".into();
        value["payload"]["outcome"] = "DENY".into();
        assert!(index(&value).is_ok(), "{kind} denial");
        value["payload"]["path"] = "/control/v1/other".into();
        rejected(&value, "OIDC audit with an unregistered path");
    }
}

#[test]
fn model_listing_publishes_only_scoped_access_facts() {
    let mut value = event();
    value["event_type"] = "console.model.list".into();
    value["payload"]["path"] = "/control/v1/model-calls".into();
    value["payload"]["target_case_id"] = Value::Null;
    value["payload"]["reason_code"] = "CONTROL_MODEL_CALLS_READ".into();
    value["evidence_refs"] = json!([]);
    let row = index(&value).unwrap();
    assert_eq!(row.stage, "control_access");
    assert_eq!(row.confidence, None);
    assert_eq!(row.is_terminal, 0);
    for (field, content) in [
        ("method", json!("POST")),
        ("path", json!("/control/v1/model-calls?cursor=opaque")),
        ("subject_ref", Value::Null),
        ("target_case_id", json!(CASE)),
        ("target_model_call_id", json!(MODEL)),
        ("target_artifact_id", json!(ARTIFACT)),
        ("query_digest", json!("a".repeat(64))),
        ("bytes_read", json!(0)),
        ("reason_code", json!("CONTROL_MODEL_CALL_READ")),
        ("start", json!("2026-09-19T00:00:00Z")),
    ] {
        let mut invalid = value.clone();
        invalid["payload"][field] = content;
        rejected(&invalid, field);
    }
    let mut referenced = value.clone();
    referenced["evidence_refs"] = json!([ARTIFACT]);
    rejected(&referenced, "model listing has no evidence targets");
    for (outcome, reason) in [
        ("DENY", "CONTROL_MODEL_CALLS_REQUEST_INVALID"),
        ("DENY", "CONTROL_CURSOR_INVALID"),
        ("DENY", "CONTROL_QUERY_CAPACITY_EXHAUSTED"),
        ("DENY", "CONTROL_QUERY_BUDGET_EXCEEDED"),
        ("ERROR", "CONTROL_CURSOR_UNAVAILABLE"),
        ("ERROR", "CONTROL_QUERY_TIMEOUT"),
        ("ERROR", "CONTROL_MODEL_CALLS_INDEX_UNAVAILABLE"),
        ("ERROR", "CONTROL_MODEL_CALLS_HEALTH_UNAVAILABLE"),
    ] {
        let mut terminal = value.clone();
        terminal["payload"]["subject_ref"] = Value::Null;
        terminal["payload"]["outcome"] = outcome.into();
        terminal["payload"]["reason_code"] = reason.into();
        assert_eq!(index(&terminal).unwrap().outcome, outcome);
    }
}

#[test]
fn calibration_report_read_requires_a_validated_target_after_path_parsing() {
    let mut value = event();
    value["event_type"] = "console.calibration.report.read".into();
    value["payload"]["path"] = "/control/v1/calibration-reports/{report_id}".into();
    value["payload"]["target_case_id"] = Value::Null;
    value["payload"]["target_calibration_report_id"] = REPORT.into();
    value["payload"]["reason_code"] = "CONTROL_CALIBRATION_REPORT_READ".into();
    value["evidence_refs"] = json!([]);
    assert_eq!(
        index(&value).unwrap().reason_code,
        "CONTROL_CALIBRATION_REPORT_READ"
    );

    for (outcome, reason) in [
        ("DENY", "CONTROL_CALIBRATION_REPORT_READ_REQUEST_INVALID"),
        ("DENY", "CONTROL_CALIBRATION_REPORT_BUSY"),
        ("ERROR", "CONTROL_CALIBRATION_REPORT_STORE_UNAVAILABLE"),
    ] {
        let mut terminal = value.clone();
        terminal["payload"]["outcome"] = outcome.into();
        terminal["payload"]["reason_code"] = reason.into();
        assert!(index(&terminal).is_ok(), "{reason}");
        terminal["payload"]["target_calibration_report_id"] = Value::Null;
        rejected(&terminal, "parsed report failure without target");
    }

    for (outcome, reason) in [
        ("DENY", "CONTROL_AUTH_REQUIRED"),
        ("DENY", "CONTROL_SCOPE_DENIED"),
        ("DENY", "CONTROL_RATE_LIMITED"),
        ("DENY", "CONTROL_CALIBRATION_REPORT_ID_INVALID"),
        ("ERROR", "CONTROL_RATE_UNAVAILABLE"),
        ("ERROR", "CONTROL_CLOCK_UNAVAILABLE"),
    ] {
        let mut terminal = value.clone();
        terminal["payload"]["outcome"] = outcome.into();
        terminal["payload"]["reason_code"] = reason.into();
        terminal["payload"]["target_calibration_report_id"] = Value::Null;
        if matches!(
            reason,
            "CONTROL_AUTH_REQUIRED" | "CONTROL_CLOCK_UNAVAILABLE"
        ) {
            terminal["payload"]["subject_ref"] = Value::Null;
        }
        assert!(index(&terminal).is_ok(), "{reason}");
        terminal["payload"]["target_calibration_report_id"] = REPORT.into();
        rejected(&terminal, "unparsed report failure with target");
    }

    for (field, content) in [
        ("method", json!("POST")),
        ("path", json!("/control/v1/calibration-reports/report")),
        ("target_request_id", json!(REQUEST)),
        ("target_artifact_id", json!(ARTIFACT)),
        ("target_case_id", json!(CASE)),
        ("target_model_call_id", json!(MODEL)),
        ("query_digest", json!("a".repeat(64))),
        ("bytes_read", json!(0)),
    ] {
        let mut invalid = value.clone();
        invalid["payload"][field] = content;
        rejected(&invalid, field);
    }
}

fn access_list_event() -> Value {
    let mut value = event();
    value["event_type"] = "console.evidence.access.list".into();
    value["payload"]["path"] = "/control/v1/evidence-access-requests".into();
    value["payload"]["target_case_id"] = Value::Null;
    value["payload"]["reason_code"] = "CONTROL_EVIDENCE_ACCESS_LIST_READ".into();
    value["evidence_refs"] = json!([]);
    value
}

#[test]
fn access_listing_publishes_scoped_facts_from_authenticated_journal() {
    let value = access_list_event();
    let row = index(&value).unwrap();
    assert_eq!(row.stage, "control_access");
    assert_eq!(row.method, "GET");
    assert_eq!(row.outcome, "PASS");
    assert_eq!(row.reason_code, "CONTROL_EVIDENCE_ACCESS_LIST_READ");
    assert_eq!(row.proof_kind, "deterministic");
    assert_eq!(row.confidence, None);
    assert_eq!(row.confidence_status, "not_applicable");
    assert_eq!(row.request_id, REQUEST);
    assert!(row.evidence_refs.is_empty());
    assert_eq!(row.is_terminal, 0);
    assert_eq!(row.http_status, None);
    assert!(row.origin_state.is_empty());
    assert!(
        IndexRow::parse_outbox(
            &serde_json::to_vec(&value).unwrap(),
            &EventId::parse(EVENT).unwrap(),
            1,
            BOOT,
            "1".repeat(64),
            TimeDelta::days(30),
        )
        .is_err()
    );
    for (field, content) in [
        ("producer_id", json!("evidence-access")),
        ("producer_boot_id", json!(REQUEST)),
        ("producer_seq", json!(2)),
        ("request_seq", json!(2)),
        ("request_id", Value::Null),
        ("policy_revision", json!("evidence-access-v1")),
        ("sensitivity", json!("RESTRICTED")),
        ("cause_event_ids", json!([EVENT])),
        ("example_only", json!(true)),
        ("connection_id", Value::Null),
        ("agent_run_id", Value::Null),
    ] {
        let mut invalid = value.clone();
        invalid[field] = content;
        rejected(&invalid, field);
    }
    let mut crossed = value;
    crossed["payload"] = json!({"stage": "evidence_access", "outcome": "PASS",
        "reason_code": "EVIDENCE_ACCESS_APPROVED", "access_request_id": ACCESS});
    rejected(&crossed, "outbox payload in listing journal");
}

#[test]
fn access_listing_rejects_page_data_targets_and_wrong_routes() {
    let value = access_list_event();
    for (field, content) in [
        ("method", json!("POST")),
        (
            "path",
            json!("/control/v1/evidence-access-requests?view=mine"),
        ),
        (
            "path",
            json!("/control/v1/evidence-access-requests/{access_request_id}"),
        ),
        ("subject_ref", Value::Null),
        ("subject_ref", json!("")),
        ("subject_ref", json!("actor\nname")),
        ("subject_ref", json!("a".repeat(257))),
        ("subject_ref", json!("界".repeat(86))),
        ("outcome", json!("UNKNOWN")),
        ("reason_code", json!("CONTROL_EVIDENCE_ACCESS_READ")),
        ("reason_code", json!("CONTROL_EVIDENCE_ACCESS_LIST_READ\n")),
        ("view", json!("mine")),
        ("cursor", json!("opaque")),
        ("rows", json!([])),
        ("items", json!([])),
        ("justification", json!("synthetic")),
        ("decision_reason", json!("synthetic")),
        ("requested_by", json!("other-actor")),
        ("decided_by", json!("other-actor")),
        ("confidence", Value::Null),
    ] {
        let mut invalid = value.clone();
        invalid["payload"][field] = content;
        rejected(&invalid, field);
    }
    for (field, content) in [
        ("target_request_id", json!(REQUEST)),
        ("target_artifact_id", json!(ARTIFACT)),
        ("target_case_id", json!(CASE)),
        ("target_access_request_id", json!(ACCESS)),
        ("target_model_call_id", json!(MODEL)),
        ("target_grant_id", json!(GRANT)),
        ("target_binding_id", json!(BINDING)),
        ("target_hold_id", json!(HOLD)),
        ("query_digest", json!("a".repeat(64))),
        ("bytes_read", json!(0)),
    ] {
        let mut nullable = value.clone();
        nullable["payload"][field] = Value::Null;
        assert!(index(&nullable).is_ok(), "{field}");
        nullable["payload"][field] = content;
        rejected(&nullable, field);
    }
    let mut invalid = value;
    invalid["evidence_refs"] = json!([ARTIFACT]);
    rejected(&invalid, "listing evidence reference");
}

#[test]
fn access_listing_failure_reasons_require_exact_outcome_and_empty_targets() {
    for (outcome, reason) in [
        ("DENY", "CONTROL_AUTH_REQUIRED"),
        ("DENY", "CONTROL_SCOPE_DENIED"),
        ("DENY", "CONTROL_RATE_LIMITED"),
        ("DENY", "CONTROL_CURSOR_INVALID"),
        ("DENY", "CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID"),
        ("DENY", "CONTROL_EVIDENCE_ACCESS_BUSY"),
        ("ERROR", "CONTROL_CURSOR_UNAVAILABLE"),
        ("ERROR", "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE"),
        ("ERROR", "CONTROL_RATE_UNAVAILABLE"),
        ("ERROR", "CONTROL_CLOCK_UNAVAILABLE"),
    ] {
        let mut value = access_list_event();
        value["payload"]["outcome"] = outcome.into();
        value["payload"]["reason_code"] = reason.into();
        for subject in [json!("audit-operator"), Value::Null] {
            value["payload"]["subject_ref"] = subject;
            assert_eq!(index(&value).unwrap().outcome, outcome);
        }
        value["payload"]
            .as_object_mut()
            .unwrap()
            .remove("subject_ref");
        assert!(index(&value).is_ok());
        for other in ["PASS", if outcome == "DENY" { "ERROR" } else { "DENY" }] {
            let mut invalid = value.clone();
            invalid["payload"]["subject_ref"] = "audit-operator".into();
            invalid["payload"]["outcome"] = other.into();
            rejected(&invalid, "crossed outcome");
        }
        for invalid_reason in [
            "CONTROL_EVIDENCE_ACCESS_LIST_READ",
            "CONTROL_UNKNOWN",
            "CONTROL_AUDIT_UNAVAILABLE",
        ] {
            let mut invalid = value.clone();
            invalid["payload"]["reason_code"] = invalid_reason.into();
            rejected(&invalid, "crossed reason");
        }
        for field in [
            "target_request_id",
            "target_artifact_id",
            "target_case_id",
            "target_access_request_id",
            "target_model_call_id",
            "target_grant_id",
            "target_binding_id",
            "target_hold_id",
            "query_digest",
            "bytes_read",
        ] {
            let mut invalid = value.clone();
            invalid["payload"][field] = if field == "bytes_read" {
                json!(0)
            } else {
                json!(ACCESS)
            };
            rejected(&invalid, field);
        }
        value["evidence_refs"] = json!([ARTIFACT]);
        rejected(&value, "failure evidence reference");
    }
}

#[test]
fn access_listing_duplicate_fields_fail_before_indexing() {
    let bytes = serde_json::to_string(&access_list_event()).unwrap();
    for addition in [
        r#""outcome":"PASS","outcome":"PASS""#,
        r#""outcome":"PASS","target_case_id":null"#,
        r#""outcome":"PASS","unknown":null"#,
    ] {
        let invalid = bytes.replace(r#""outcome":"PASS""#, addition);
        assert!(matches!(
            index_bytes(invalid.as_bytes()),
            Err(PublishError::Json(_))
        ));
    }
}

fn access_detail_event() -> Value {
    let mut value = event();
    value["event_type"] = "console.evidence.access.read".into();
    value["payload"]["path"] = "/control/v1/evidence-access-requests/{access_request_id}".into();
    value["payload"]["reason_code"] = "CONTROL_EVIDENCE_ACCESS_READ".into();
    value["payload"]["target_artifact_id"] = ARTIFACT.into();
    value["payload"]["target_access_request_id"] = ACCESS.into();
    value
}

#[test]
fn access_details_publish_scoped_metadata_only_from_the_management_journal() {
    let value = access_detail_event();
    for field in [
        "target_request_id",
        "target_model_call_id",
        "target_grant_id",
        "target_binding_id",
        "target_hold_id",
        "query_digest",
        "bytes_read",
    ] {
        let mut nullable = value.clone();
        nullable["payload"][field] = Value::Null;
        assert!(index(&nullable).is_ok(), "{field}");
    }
    let row = index(&value).unwrap();
    assert_eq!(row.stage, "control_access");
    assert_eq!(row.method, "GET");
    assert_eq!(row.reason_code, "CONTROL_EVIDENCE_ACCESS_READ");
    assert_eq!(row.proof_kind, "deterministic");
    assert_eq!(row.confidence, None);
    assert_eq!(row.confidence_status, "not_applicable");
    assert_eq!(row.request_id, REQUEST);
    assert_eq!(row.evidence_refs, [ARTIFACT]);
    assert_eq!(row.is_terminal, 0);
    assert_eq!(row.http_status, None);
    assert!(row.origin_state.is_empty());
    assert!(
        IndexRow::parse_outbox(
            &serde_json::to_vec(&value).unwrap(),
            &EventId::parse(EVENT).unwrap(),
            1,
            BOOT,
            "1".repeat(64),
            TimeDelta::days(30),
        )
        .is_err()
    );
    for (field, content) in [
        ("producer_id", json!("evidence-access")),
        ("request_id", Value::Null),
        ("request_seq", json!(2)),
        ("producer_seq", json!(2)),
        ("producer_boot_id", json!(REQUEST)),
        ("policy_revision", json!("evidence-access-v1")),
        ("sensitivity", json!("RESTRICTED")),
        ("cause_event_ids", json!([EVENT])),
        ("example_only", json!(true)),
        ("connection_id", Value::Null),
        ("agent_run_id", Value::Null),
    ] {
        let mut invalid = value.clone();
        invalid[field] = content;
        rejected(&invalid, field);
    }
    let mut crossed = value;
    crossed["payload"] = json!({
        "stage": "evidence_access", "outcome": "PASS", "reason_code": "EVIDENCE_ACCESS_APPROVED",
        "access_request_id": ACCESS, "case_id": CASE, "artifact_id": ARTIFACT,
        "subject_ref": "audit-operator"
    });
    rejected(&crossed, "transactional payload on approval detail access");
}

#[test]
fn access_details_require_exact_success_targets_route_and_evidence() {
    let value = access_detail_event();
    for field in [
        "method",
        "path",
        "outcome",
        "reason_code",
        "subject_ref",
        "target_access_request_id",
        "target_case_id",
        "target_artifact_id",
    ] {
        let mut invalid = value.clone();
        invalid["payload"].as_object_mut().unwrap().remove(field);
        rejected(&invalid, field);
        invalid["payload"][field] = Value::Null;
        rejected(&invalid, field);
    }
    for field in [
        "target_access_request_id",
        "target_case_id",
        "target_artifact_id",
    ] {
        let target = value["payload"][field].as_str().unwrap();
        for invalid_target in [
            json!(REQUEST),
            json!(target.to_uppercase()),
            json!(target.replace("-7000-", "-4000-")),
            json!(format!("{target}\n")),
            json!("invalid"),
        ] {
            let mut invalid = value.clone();
            invalid["payload"][field] = invalid_target;
            rejected(&invalid, field);
        }
    }
    for (field, content) in [
        ("method", json!("POST")),
        (
            "path",
            json!(format!("/control/v1/evidence-access-requests/{ACCESS}")),
        ),
        (
            "path",
            json!("/control/v1/evidence-access-requests/{access_request_id}/approve"),
        ),
        (
            "path",
            json!("/control/v1/evidence-access-requests/{access_request_id}?extra=1"),
        ),
        ("reason_code", json!("CONTROL_EVIDENCE_ACCESS_APPROVED")),
        (
            "reason_code",
            json!("CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE"),
        ),
        (
            "reason_code",
            json!("CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE"),
        ),
        ("subject_ref", json!("")),
        ("subject_ref", json!("中".repeat(86))),
        ("subject_ref", json!("actor\nname")),
        ("target_request_id", json!(REQUEST)),
        ("target_model_call_id", json!(MODEL)),
        ("target_grant_id", json!(GRANT)),
        ("target_binding_id", json!(BINDING)),
        ("target_hold_id", json!(HOLD)),
        ("query_digest", json!("a".repeat(64))),
        ("bytes_read", json!(0)),
        ("justification", json!("synthetic")),
        ("decision_reason", json!("synthetic")),
        ("requester_subject", json!("requester")),
        ("decided_by_subject", json!("approver")),
        ("status", json!("approved")),
        ("content", json!("synthetic")),
        ("confidence", Value::Null),
    ] {
        let mut invalid = value.clone();
        invalid["payload"][field] = content;
        rejected(&invalid, field);
    }
    for refs in [
        json!([]),
        json!([OTHER_ARTIFACT]),
        json!([ARTIFACT, OTHER_ARTIFACT]),
        json!([ARTIFACT, ARTIFACT]),
        json!([ACCESS]),
    ] {
        let mut invalid = value.clone();
        invalid["evidence_refs"] = refs;
        rejected(&invalid, "approval detail evidence binding");
    }
}

#[test]
fn access_detail_failures_bind_only_validated_access_ids_and_exact_reasons() {
    for (outcome, reason, before_target) in [
        ("DENY", "CONTROL_AUTH_REQUIRED", true),
        ("DENY", "CONTROL_SCOPE_DENIED", true),
        ("DENY", "CONTROL_RATE_LIMITED", true),
        ("ERROR", "CONTROL_RATE_UNAVAILABLE", true),
        ("ERROR", "CONTROL_CLOCK_UNAVAILABLE", true),
        ("DENY", "CONTROL_EVIDENCE_ACCESS_ID_INVALID", true),
        (
            "DENY",
            "CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID",
            false,
        ),
        ("DENY", "CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE", false),
        ("DENY", "CONTROL_EVIDENCE_ACCESS_BUSY", false),
        (
            "ERROR",
            "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE",
            false,
        ),
    ] {
        let mut value = access_detail_event();
        value["payload"]["outcome"] = outcome.into();
        value["payload"]["reason_code"] = reason.into();
        rejected(&value, "failure with success targets and evidence");
        value["evidence_refs"] = json!([]);
        value["payload"]["target_case_id"] = Value::Null;
        value["payload"]["target_artifact_id"] = Value::Null;
        assert_eq!(index(&value).is_ok(), !before_target, "{reason}");
        value["payload"]["target_access_request_id"] = Value::Null;
        assert_eq!(index(&value).unwrap().outcome, outcome);
        for field in ["target_case_id", "target_artifact_id"] {
            let mut invalid = value.clone();
            invalid["payload"][field] = access_detail_event()["payload"][field].clone();
            rejected(&invalid, "failure with resolved target");
        }
        for reason in [
            "CONTROL_EVIDENCE_ACCESS_READ",
            "CONTROL_UNKNOWN",
            "CONTROL_AUDIT_UNAVAILABLE",
        ] {
            let mut invalid = value.clone();
            invalid["payload"]["reason_code"] = reason.into();
            rejected(&invalid, "failure with invalid reason");
        }
        let mut crossed = value.clone();
        crossed["payload"]["outcome"] = if outcome == "ERROR" { "DENY" } else { "ERROR" }.into();
        rejected(&crossed, "failure outcome/reason mismatch");
        for target in [
            json!(REQUEST),
            json!(ACCESS.to_uppercase()),
            json!(ACCESS.replace("-7000-", "-4000-")),
        ] {
            value["payload"]["target_access_request_id"] = target;
            rejected(&value, "invalid failure target");
        }
        value["payload"]["target_access_request_id"] = Value::Null;
        for subject in [Value::Null, json!("audit-operator")] {
            value["payload"]["subject_ref"] = subject;
            assert!(index(&value).is_ok());
        }
        value["payload"]
            .as_object_mut()
            .unwrap()
            .remove("subject_ref");
        assert!(index(&value).is_ok());
        value["payload"]["target_access_request_id"] = ACCESS.into();
        rejected(&value, "target before authentication");
    }
}

#[test]
fn access_detail_duplicate_fields_fail_before_indexing() {
    let bytes = serde_json::to_string(&access_detail_event()).unwrap();
    for addition in [
        r#""outcome":"PASS","outcome":"PASS""#,
        r#""outcome":"PASS","target_access_request_id":null"#,
        r#""outcome":"PASS","unknown":null"#,
    ] {
        let invalid = bytes.replace(r#""outcome":"PASS""#, addition);
        assert!(matches!(
            index_bytes(invalid.as_bytes()),
            Err(PublishError::Json(_))
        ));
    }
}

#[test]
fn rejects_mismatched_actions_subjects_outcomes_and_reasons() {
    for (pointer, value) in [
        ("/event_type", json!("case.created")),
        ("/payload/method", json!("POST")),
        (
            "/payload/path",
            json!(format!("/control/v1/cases/{CASE}/items")),
        ),
        ("/payload/subject_ref", Value::Null),
        ("/payload/subject_ref", json!("")),
        ("/payload/subject_ref", json!("audit\noperator")),
        ("/payload/subject_ref", json!("x".repeat(257))),
        ("/payload/subject_ref", json!("中".repeat(86))),
        ("/payload/outcome", json!("ALLOW")),
        ("/payload/outcome", json!("pass")),
        ("/payload/reason_code", json!("")),
        ("/payload/reason_code", json!("control_read")),
        ("/payload/reason_code", json!("CONTROL-READ")),
        ("/payload/reason_code", json!("X".repeat(129))),
        ("/payload/target_request_id", json!(REQUEST)),
        ("/payload/target_artifact_id", json!(ARTIFACT)),
        ("/payload/target_access_request_id", json!(ACCESS)),
    ] {
        let mut event = event();
        *event.pointer_mut(pointer).unwrap() = value;
        rejected(&event, pointer);
    }
    let mut event = event();
    event["payload"]["target_model_call_id"] = MODEL.into();
    rejected(&event, "model target on a case route");
    let mut event = self::event();
    event["payload"]["target_grant_id"] = GRANT.into();
    rejected(&event, "grant target on a case route");
    let mut event = self::event();
    event["payload"]["target_binding_id"] = BINDING.into();
    rejected(&event, "binding target on a case route");
}

#[test]
fn required_target_ids_are_typed_canonical_and_bound_to_the_route() {
    let routes = [
        (
            "console.request.read",
            "GET",
            "/control/v1/requests/{request_id}",
            "target_request_id",
            REQUEST,
        ),
        (
            "console.events.read",
            "GET",
            "/control/v1/requests/{request_id}/events",
            "target_request_id",
            REQUEST,
        ),
        (
            "console.manifest.read",
            "GET",
            "/control/v1/requests/{request_id}/evidence",
            "target_request_id",
            REQUEST,
        ),
        (
            "console.manifest.read",
            "GET",
            "/control/v1/artifacts/{artifact_id}",
            "target_artifact_id",
            ARTIFACT,
        ),
        (
            "console.model.read",
            "GET",
            "/control/v1/model-calls/{model_call_id}",
            "target_model_call_id",
            MODEL,
        ),
        (
            "console.grant.read",
            "GET",
            "/control/v1/grants/{grant_id}",
            "target_grant_id",
            GRANT,
        ),
        (
            "console.binding.read",
            "GET",
            "/control/v1/auth-bindings/{binding_id}",
            "target_binding_id",
            BINDING,
        ),
        (
            "case.created",
            "POST",
            "/control/v1/cases",
            "target_case_id",
            CASE,
        ),
        (
            "case.closed",
            "POST",
            "/control/v1/cases/{case_id}/close",
            "target_case_id",
            CASE,
        ),
        (
            "console.case.read",
            "GET",
            "/control/v1/cases/{case_id}/items",
            "target_case_id",
            CASE,
        ),
    ];
    for (kind, method, path, target, valid) in routes {
        let mut event = event();
        event["event_type"] = kind.into();
        event["payload"]["method"] = method.into();
        event["payload"]["path"] = path.into();
        event["payload"]["target_case_id"] = Value::Null;
        event["payload"][target] = valid.into();
        event["evidence_refs"] = json!([]);
        assert!(index(&event).is_ok(), "valid {kind} {path}");
        for invalid in [
            Value::Null,
            json!(EVENT),
            json!(valid.replace("-7000-", "-4000-")),
            json!(valid.replace("2a3b", "2A3B")),
            json!("malformed"),
        ] {
            event["payload"][target] = invalid;
            rejected(&event, target);
        }
    }
}

#[test]
fn artifact_actions_require_all_targets_and_the_matching_evidence_reference() {
    for (kind, path) in [
        ("case.evidence.added", "/control/v1/cases/{case_id}/items"),
        (
            "evidence.access.requested",
            "/control/v1/artifacts/{artifact_id}/access",
        ),
        (
            "evidence.access.approved",
            "/control/v1/evidence-access-requests/{access_request_id}/approve",
        ),
        (
            "evidence.access.denied",
            "/control/v1/evidence-access-requests/{access_request_id}/deny",
        ),
    ] {
        let mut event = event();
        event["event_type"] = kind.into();
        event["payload"]["method"] = "POST".into();
        event["payload"]["path"] = path.into();
        event["payload"]["target_artifact_id"] = ARTIFACT.into();
        if kind != "case.evidence.added" {
            event["payload"]["target_access_request_id"] = ACCESS.into();
        }
        assert!(index(&event).is_ok(), "valid {kind}");
        for target in [
            "target_case_id",
            "target_artifact_id",
            "target_access_request_id",
        ] {
            if event["payload"][target].is_null() {
                continue;
            }
            for invalid in [
                Value::Null,
                json!(REQUEST),
                json!("access_018f2a3b-4c5d-4000-8000-000000000007"),
            ] {
                let mut bad = event.clone();
                bad["payload"][target] = invalid;
                rejected(&bad, target);
            }
        }
        for references in [
            json!([]),
            json!([OTHER_ARTIFACT]),
            json!([ARTIFACT, OTHER_ARTIFACT]),
            json!([EVENT]),
        ] {
            let mut bad = event.clone();
            bad["evidence_refs"] = references;
            rejected(&bad, "artifact action evidence binding");
        }
    }
}

#[test]
fn evidence_lists_obey_common_limits_and_management_result_semantics() {
    let mut event = event();
    for references in [json!([ARTIFACT, ARTIFACT]), json!([EVENT])] {
        event["evidence_refs"] = references;
        rejected(&event, "duplicate or non-artifact evidence reference");
    }
    let references = (0..256)
        .map(|index| format!("artifact_018f2a3b-4c5d-7000-8000-{index:012x}"))
        .collect::<Vec<_>>();
    event["evidence_refs"] = json!(references);
    assert!(index(&event).is_ok());
    event["evidence_refs"]
        .as_array_mut()
        .unwrap()
        .push(json!("artifact_018f2a3b-4c5d-7000-8000-000000000100"));
    rejected(
        &event,
        "257 evidence references at the common index boundary",
    );
    event["evidence_refs"] = json!([ARTIFACT]);
    for outcome in ["DENY", "ERROR"] {
        event["payload"]["outcome"] = outcome.into();
        rejected(&event, "failed access reporting returned evidence");
    }
    event["payload"]["outcome"] = "PASS".into();
    event["event_type"] = "console.manifest.read".into();
    event["payload"]["path"] = "/control/v1/artifacts/{artifact_id}".into();
    event["payload"]["target_case_id"] = Value::Null;
    event["payload"]["target_artifact_id"] = ARTIFACT.into();
    for references in [json!([]), json!([ARTIFACT])] {
        event["evidence_refs"] = references;
        assert!(index(&event).is_ok());
    }
    event["evidence_refs"] = json!([OTHER_ARTIFACT]);
    rejected(&event, "manifest target and returned artifact mismatch");
}

#[test]
fn content_bytes_are_bounded_and_only_describe_successful_content_reads() {
    let mut event = event();
    event["event_type"] = "evidence.read".into();
    event["payload"]["path"] = "/control/v1/artifacts/{artifact_id}/content".into();
    event["payload"]["target_artifact_id"] = ARTIFACT.into();
    event["payload"]["target_case_id"] = Value::Null;
    event["payload"]["target_access_request_id"] = ACCESS.into();
    rejected(&event, "content success missing byte count");
    for bytes in [0, 64 * 1024 * 1024] {
        event["payload"]["bytes_read"] = json!(bytes);
        assert!(index(&event).is_ok());
    }
    for bytes in [
        Value::Null,
        json!(64 * 1024 * 1024 + 1),
        json!(-1),
        json!("1"),
    ] {
        event["payload"]["bytes_read"] = bytes;
        rejected(&event, "invalid byte count");
    }
    event["evidence_refs"] = json!([]);
    for outcome in ["DENY", "ERROR"] {
        event["payload"]["outcome"] = outcome.into();
        event["payload"]["bytes_read"] = json!(0);
        rejected(&event, "failed content read with byte count");
        event["payload"]
            .as_object_mut()
            .unwrap()
            .remove("bytes_read");
        assert!(index(&event).is_ok());
    }
    let mut non_read = self::event();
    non_read["payload"]["bytes_read"] = json!(0);
    rejected(&non_read, "byte count on metadata access");
}

#[test]
fn query_digest_and_optional_request_target_are_bound_to_search() {
    let mut event = event();
    event["event_type"] = "console.query.executed".into();
    event["payload"]["method"] = "POST".into();
    event["payload"]["path"] = "/control/v1/search".into();
    event["payload"]["target_case_id"] = Value::Null;
    event["evidence_refs"] = json!([]);
    event["payload"]["reason_code"] = "CONTROL_QUERY_EXECUTED".into();
    rejected(&event, "successful search without query digest");
    event["payload"]["query_digest"] = json!("a".repeat(64));
    assert!(index(&event).is_ok());
    event["payload"]["target_request_id"] = REQUEST.into();
    assert!(index(&event).is_ok(), "search with an exact request filter");
    event["payload"]["target_request_id"] = Value::Null;
    event["payload"]["outcome"] = "DENY".into();
    event["payload"]["reason_code"] = "CONTROL_CALIBRATION_REPORT_HISTORY_SCOPE_DENIED".into();
    assert!(index(&event).is_ok(), "restricted report-history denial");
    event["payload"]["reason_code"] = "CONTROL_QUERY_UNRECOGNIZED".into();
    rejected(&event, "unknown search reason");
    event["payload"]["outcome"] = "PASS".into();
    event["payload"]["reason_code"] = "CONTROL_QUERY_EXECUTED".into();
    for digest in [
        Value::Null,
        json!("a".repeat(63)),
        json!("a".repeat(65)),
        json!("A".repeat(64)),
        json!("g".repeat(64)),
    ] {
        event["payload"]["query_digest"] = digest;
        rejected(&event, "invalid query digest");
    }
    event["payload"]
        .as_object_mut()
        .unwrap()
        .remove("query_digest");
    for (outcome, reason) in [
        ("DENY", "CONTROL_QUERY_BUDGET_EXCEEDED"),
        ("ERROR", "CONTROL_QUERY_TIMEOUT"),
    ] {
        event["payload"]["outcome"] = outcome.into();
        event["payload"]["reason_code"] = reason.into();
        assert!(index(&event).is_ok());
    }
    let mut non_query = self::event();
    non_query["payload"]["query_digest"] = json!("a".repeat(64));
    rejected(&non_query, "query digest on another management action");
}

#[test]
fn authenticated_envelope_and_management_origin_are_required() {
    for (field, value) in [
        ("schema_version", json!(2)),
        ("producer_id", json!("xshield-gateway")),
        ("policy_revision", json!("policy-r1")),
        ("request_id", Value::Null),
        ("request_id", json!(CASE)),
        ("request_seq", json!(2)),
        ("producer_seq", json!(2)),
        ("producer_boot_id", json!(REQUEST)),
        ("event_id", json!("ev_018f2a3b-4c5d-7000-8000-000000000009")),
        ("cause_event_ids", json!([EVENT])),
        ("sensitivity", json!("SENSITIVE")),
        ("example_only", json!(true)),
        ("target_case_id", json!(CASE)),
    ] {
        let mut event = event();
        event[field] = value;
        rejected(&event, field);
    }
}

#[test]
fn duplicate_and_unknown_payload_fields_are_rejected_before_indexing() {
    let event = serde_json::to_string(&event()).unwrap();
    for addition in [
        r#""outcome":"PASS","outcome":"PASS""#,
        r#""outcome":"PASS","stage":"case_management""#,
        r#""outcome":"PASS","confidence":null"#,
    ] {
        let malformed = event.replace(r#""outcome":"PASS""#, addition);
        assert!(matches!(
            index_bytes(malformed.as_bytes()),
            Err(PublishError::Json(_))
        ));
    }
    let duplicate = event.replace(
        r#""subject_ref":"audit-operator""#,
        r#""subject_ref":null,"subject_ref":"audit-operator""#,
    );
    assert!(matches!(
        index_bytes(duplicate.as_bytes()),
        Err(PublishError::Json(_))
    ));
}

#[test]
fn transactional_facts_do_not_parse_as_same_named_management_attempts() {
    for kind in [
        "case.created",
        "case.closed",
        "evidence.access.requested",
        "evidence.access.approved",
        "evidence.access.denied",
    ] {
        let mut event = event();
        event["event_type"] = kind.into();
        // Keep authenticated journal headers valid to isolate the distinct
        // transactional payload contract rather than its producer sequence.
        event["payload"] = json!({
            "stage": "case_management", "case_id": CASE,
            "subject_ref": "audit-operator", "request_digest": "a".repeat(64),
            "outcome": "PASS", "reason_code": "CASE_CREATED"
        });
        assert!(
            matches!(index(&event), Err(PublishError::Json(_))),
            "{kind}"
        );
    }
}

fn hold_event(kind: &str, method: &str, path: &str, reason: &str) -> Value {
    let mut event = event();
    event["event_type"] = kind.into();
    event["payload"]["method"] = method.into();
    event["payload"]["path"] = path.into();
    event["payload"]["reason_code"] = reason.into();
    if kind != "console.evidence.hold.read" {
        event["payload"]["target_hold_id"] = HOLD.into();
        event["payload"]["target_artifact_id"] = ARTIFACT.into();
    }
    event
}

#[test]
fn hold_management_successes_bind_targets_and_keep_journal_semantics() {
    for &(kind, method, path, reason) in HOLD_ACTIONS {
        let mut value = hold_event(kind, method, path, reason);
        for reason in [
            reason,
            match kind {
                "console.evidence.hold.created" => "CONTROL_EVIDENCE_HOLD_CREATE_REPLAYED",
                "console.evidence.hold.released" => "CONTROL_EVIDENCE_HOLD_RELEASE_REPLAYED",
                _ => reason,
            },
        ] {
            value["payload"]["reason_code"] = reason.into();
            let row = index(&value).unwrap();
            assert_eq!(row.stage, "control_access");
            assert_eq!(row.method, method);
            assert_eq!(row.reason_code, reason);
            assert_eq!(row.proof_kind, "deterministic");
            assert_eq!(row.confidence, None);
            assert_eq!(row.confidence_status, "not_applicable");
            assert_eq!(row.is_terminal, 0);
            assert_eq!(row.http_status, None);
            assert_eq!(row.request_id, REQUEST);
            assert_eq!(row.evidence_refs, [ARTIFACT]);
            assert!(row.origin_state.is_empty());
            assert!(row.operation_id.is_empty());
            assert!(
                IndexRow::parse_outbox(
                    &serde_json::to_vec(&value).unwrap(),
                    &EventId::parse(EVENT).unwrap(),
                    1,
                    BOOT,
                    "1".repeat(64),
                    TimeDelta::days(30),
                )
                .is_err()
            );
        }
    }
}

#[test]
fn hold_management_requires_exact_routes_targets_and_success_reasons() {
    for &(kind, method, path, reason) in HOLD_ACTIONS {
        let value = hold_event(kind, method, path, reason);
        let mut required = vec![
            "method",
            "path",
            "outcome",
            "reason_code",
            "subject_ref",
            "target_case_id",
        ];
        if kind != "console.evidence.hold.read" {
            required.extend(["target_artifact_id", "target_hold_id"]);
        }
        for field in required {
            let mut missing = value.clone();
            missing["payload"].as_object_mut().unwrap().remove(field);
            rejected(&missing, &format!("{kind} missing {field}"));
            missing["payload"][field] = Value::Null;
            rejected(&missing, &format!("{kind} null {field}"));
        }
        for (field, replacement) in [
            (
                "method",
                json!(if method == "POST" { "GET" } else { "POST" }),
            ),
            ("path", json!("/control/v1/cases/{case_id}/items")),
            ("reason_code", json!("CONTROL_EVIDENCE_HOLD_UNKNOWN")),
            ("target_case_id", json!(HOLD)),
            ("target_request_id", json!(REQUEST)),
            ("target_access_request_id", json!(ACCESS)),
            ("target_model_call_id", json!(MODEL)),
            ("target_grant_id", json!(GRANT)),
            ("target_binding_id", json!(BINDING)),
            ("bytes_read", json!(0)),
            ("query_digest", json!("a".repeat(64))),
            ("confidence", Value::Null),
            ("stage", json!("evidence_hold")),
            ("hold_until", json!("2026-09-20T00:00:00.123Z")),
        ] {
            let mut invalid = value.clone();
            invalid["payload"][field] = replacement;
            rejected(&invalid, &format!("{kind} {field}"));
        }
        for invalid_hold in [
            json!(CASE),
            json!(HOLD.to_uppercase()),
            json!(HOLD.replace("-7000-", "-4000-")),
            json!("invalid"),
        ] {
            let mut invalid = value.clone();
            invalid["payload"]["target_hold_id"] = invalid_hold;
            rejected(&invalid, "invalid hold target");
        }
        for refs in [json!([ARTIFACT, ARTIFACT]), json!([HOLD])] {
            let mut invalid = value.clone();
            invalid["evidence_refs"] = refs;
            rejected(&invalid, "hold management evidence shape");
        }
        for refs in [
            json!([]),
            json!([OTHER_ARTIFACT]),
            json!([ARTIFACT, OTHER_ARTIFACT]),
        ] {
            let mut changed = value.clone();
            changed["evidence_refs"] = refs;
            assert_eq!(
                index(&changed).is_ok(),
                kind == "console.evidence.hold.read"
            );
        }
        if kind == "console.evidence.hold.read" {
            for (field, target) in [("target_artifact_id", ARTIFACT), ("target_hold_id", HOLD)] {
                let mut invalid = value.clone();
                invalid["payload"][field] = target.into();
                rejected(&invalid, "list only binds its case target");
            }
        }
    }
}

#[test]
fn hold_management_failures_retain_only_validated_targets_and_no_evidence() {
    for &(kind, method, path, reason) in HOLD_ACTIONS {
        for outcome in ["DENY", "ERROR"] {
            let mut value = hold_event(kind, method, path, reason);
            value["payload"]["outcome"] = outcome.into();
            value["payload"]["reason_code"] = "CONTROL_INVALID_INPUT".into();
            rejected(&value, "failed hold attempt carrying evidence");
            value["evidence_refs"] = json!([]);
            assert!(index(&value).is_ok());
            for field in [
                "subject_ref",
                "target_case_id",
                "target_artifact_id",
                "target_hold_id",
            ] {
                value["payload"][field] = Value::Null;
                assert!(index(&value).is_ok(), "{kind} optional {field}");
                value["payload"].as_object_mut().unwrap().remove(field);
                assert!(index(&value).is_ok(), "{kind} omitted {field}");
            }
            value["payload"]["target_hold_id"] = json!(CASE);
            rejected(&value, "invalid failure hold target");
        }
    }
}

#[test]
fn existing_management_actions_accept_absent_or_null_hold_targets() {
    for (kind, method, path) in [
        ("console.health.read", "GET", "/control/v1/audit/health"),
        (
            "console.request.read",
            "GET",
            "/control/v1/requests/{request_id}",
        ),
        (
            "console.events.read",
            "GET",
            "/control/v1/requests/{request_id}/events",
        ),
        (
            "console.manifest.read",
            "GET",
            "/control/v1/requests/{request_id}/evidence",
        ),
        (
            "console.manifest.read",
            "GET",
            "/control/v1/artifacts/{artifact_id}",
        ),
        (
            "console.model.read",
            "GET",
            "/control/v1/model-calls/{model_call_id}",
        ),
        ("console.grant.read", "GET", "/control/v1/grants/{grant_id}"),
        (
            "console.binding.read",
            "GET",
            "/control/v1/auth-bindings/{binding_id}",
        ),
        ("console.query.executed", "POST", "/control/v1/search"),
        (
            "console.case.read",
            "GET",
            "/control/v1/cases/{case_id}/items",
        ),
        ("case.created", "POST", "/control/v1/cases"),
        ("case.closed", "POST", "/control/v1/cases/{case_id}/close"),
        (
            "case.evidence.added",
            "POST",
            "/control/v1/cases/{case_id}/items",
        ),
        (
            "evidence.access.requested",
            "POST",
            "/control/v1/artifacts/{artifact_id}/access",
        ),
        (
            "evidence.access.approved",
            "POST",
            "/control/v1/evidence-access-requests/{access_request_id}/approve",
        ),
        (
            "evidence.access.denied",
            "POST",
            "/control/v1/evidence-access-requests/{access_request_id}/deny",
        ),
        (
            "evidence.read",
            "GET",
            "/control/v1/artifacts/{artifact_id}/content",
        ),
    ] {
        let mut value = event();
        value["event_type"] = kind.into();
        value["payload"]["method"] = method.into();
        value["payload"]["path"] = path.into();
        value["payload"]["outcome"] = "DENY".into();
        value["payload"]["target_case_id"] = Value::Null;
        value["evidence_refs"] = json!([]);
        if kind == "console.query.executed" {
            value["payload"]["reason_code"] = "CONTROL_QUERY_BUDGET_EXCEEDED".into();
        }
        assert!(index(&value).is_ok(), "{kind} absent hold target");
        value["payload"]["target_hold_id"] = Value::Null;
        assert!(index(&value).is_ok(), "{kind} null hold target");
        value["payload"]["target_hold_id"] = HOLD.into();
        rejected(&value, &format!("{kind} unexpected hold target"));
    }
}

#[test]
fn hold_management_rejects_duplicate_fields_and_transactional_payloads() {
    for &(kind, method, path, reason) in HOLD_ACTIONS {
        let value = hold_event(kind, method, path, reason);
        let bytes = serde_json::to_string(&value).unwrap();
        let duplicate = bytes.replace(
            r#""outcome":"PASS""#,
            r#""target_hold_id":null,"outcome":"PASS","target_hold_id":null"#,
        );
        assert!(matches!(
            index_bytes(duplicate.as_bytes()),
            Err(PublishError::Json(_))
        ));
        let mut crossed = value;
        crossed["payload"] = json!({
            "stage":"evidence_hold", "outcome":"PASS", "reason_code":"EVIDENCE_HOLD_CREATED",
            "proof_kind":"deterministic", "confidence":null, "confidence_status":"not_applicable",
            "hold_id":HOLD, "case_id":CASE, "artifact_id":ARTIFACT, "subject_ref":"audit-operator",
            "request_digest":"a".repeat(64), "hold_until":"2026-09-20T00:00:00.123Z"
        });
        rejected(&crossed, "transactional payload on management event");
        crossed["payload"] = json!({"method":method, "path":path, "outcome":"DENY", "reason_code":"CONTROL_INVALID_INPUT"});
        crossed["event_type"] = "evidence.hold.created".into();
        crossed["evidence_refs"] = json!([]);
        assert!(index(&crossed).is_err());
    }
}
