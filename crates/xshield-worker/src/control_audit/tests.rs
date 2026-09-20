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
    rejected(&event, "successful search without query digest");
    event["payload"]["query_digest"] = json!("a".repeat(64));
    assert!(index(&event).is_ok());
    event["payload"]["target_request_id"] = REQUEST.into();
    assert!(index(&event).is_ok(), "search with an exact request filter");
    event["payload"]["target_request_id"] = Value::Null;
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
    for outcome in ["DENY", "ERROR"] {
        event["payload"]["outcome"] = outcome.into();
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
