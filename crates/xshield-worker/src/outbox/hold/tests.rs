//! Producer-shaped hold facts and rejection checks at the shared index boundary.

use super::EVENT_TYPES;
use crate::{IndexRow, PublishError};
use chrono::TimeDelta;
use serde_json::{Value, json};
use xshield_core::domain::EventId;

const EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000001";
const HOLD: &str = "ev_018f2a3b-4c5d-7000-8000-000000000002";
const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000004";
const ARTIFACT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000005";

/// Canonical hold fixture reusable by publication and lease tests.
pub(crate) fn event(event_type: &str) -> Value {
    let mut event = crate::outbox::tests::event("case.created");
    let created = event_type == "evidence.hold.created";
    event["event_type"] = json!(event_type);
    event["producer_id"] = json!("evidence-hold");
    event["producer_boot_id"] = json!(EVENT);
    event["request_id"] = Value::Null;
    event["trace_id"] = json!("018f2a3b4c5d70008000000000000001");
    event["policy_revision"] = json!("evidence-hold-v1");
    event["sensitivity"] = json!("RESTRICTED");
    event["evidence_refs"] = json!([ARTIFACT]);
    event["cause_event_ids"] = if created { json!([]) } else { json!([HOLD]) };
    event["payload"] = json!({
        "stage": "evidence_hold", "outcome": "PASS",
        "reason_code": if created { "EVIDENCE_HOLD_CREATED" } else { "EVIDENCE_HOLD_RELEASED" },
        "proof_kind": "deterministic", "confidence": null, "confidence_status": "not_applicable",
        "hold_id": if created { EVENT } else { HOLD }, "case_id": CASE, "artifact_id": ARTIFACT,
        "subject_ref": "investigator-1", "request_digest": "a".repeat(64),
        "hold_until": "2026-09-20T00:00:00.123Z"
    });
    event
}

fn row(value: &Value) -> Result<IndexRow, PublishError> {
    parse_bytes(&serde_json::to_vec(value).unwrap(), value)
}

fn parse_bytes(bytes: &[u8], value: &Value) -> Result<IndexRow, PublishError> {
    IndexRow::parse_outbox(
        bytes,
        &EventId::parse(EVENT).unwrap(),
        value["producer_seq"].as_u64().unwrap_or_default(),
        value["producer_boot_id"].as_str().unwrap_or_default(),
        "0".repeat(64),
        TimeDelta::days(30),
    )
}

#[test]
fn both_types_preserve_hold_facts_as_maintenance_summaries() {
    for kind in EVENT_TYPES {
        let value = event(kind);
        let row = row(&value).unwrap();
        assert_eq!(row.event_type, *kind);
        assert_eq!(row.stage, "evidence_hold");
        assert_eq!(row.outcome, "PASS");
        assert_eq!(row.reason_code, value["payload"]["reason_code"]);
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.sensitivity, "RESTRICTED");
        assert_eq!(row.producer_boot_id, EVENT);
        assert_eq!(row.evidence_refs, [ARTIFACT]);
        assert_eq!(json!(row.cause_event_ids), value["cause_event_ids"]);
        assert!(row.request_id.is_empty());
        assert_eq!(row.is_terminal, 0);
        assert_eq!(row.http_status, None);
        assert_eq!(row.duration_us, 0);
        assert!(row.method.is_empty());
        assert!(row.operation_id.is_empty());
        assert!(row.origin_state.is_empty());
        assert!(row.model_revision.is_empty());
        assert_eq!(
            serde_json::from_str::<Value>(&row.payload_json).unwrap(),
            value["payload"]
        );
        assert_eq!(
            row.retention_expires_at,
            row.occurred_at + TimeDelta::days(30)
        );
        assert!(
            IndexRow::parse(
                &serde_json::to_vec(&value).unwrap(),
                &EventId::parse(EVENT).unwrap(),
                1,
                EVENT,
                "0".repeat(64),
                TimeDelta::days(30),
            )
            .is_err()
        );
    }
}

#[test]
fn closed_shapes_require_fields_and_reject_duplicates() {
    for kind in EVENT_TYPES {
        let original = event(kind);
        for path in ["", "/payload", "/integrity"] {
            for field in original.pointer(path).unwrap().as_object().unwrap().keys() {
                let mut missing = original.clone();
                missing
                    .pointer_mut(path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
                let optional_hash = path == "/integrity"
                    && matches!(field.as_str(), "previous_hash" | "event_hash");
                assert_eq!(
                    row(&missing).is_ok(),
                    optional_hash,
                    "{kind} missing {path}/{field}"
                );
                let mut drift = original.clone();
                drift.pointer_mut(path).unwrap()[field] =
                    if original.pointer(path).unwrap()[field].is_array() {
                        json!("invalid")
                    } else {
                        json!([])
                    };
                assert!(row(&drift).is_err(), "{kind} wrong type {path}/{field}");
            }
            let mut unknown = original.clone();
            unknown.pointer_mut(path).unwrap()["extra"] = Value::Null;
            assert!(row(&unknown).is_err(), "{kind} unknown {path}");
        }
        let serialized = serde_json::to_string(&original).unwrap();
        for (needle, duplicate) in [
            (
                r#""confidence":null"#,
                r#""confidence":0,"confidence":null"#,
            ),
            (
                r#""producer_seq":1"#,
                r#""producer_seq":2,"producer_seq":1"#,
            ),
            (
                r#""state":"pending""#,
                r#""state":"sealed","state":"pending""#,
            ),
        ] {
            let bytes = serialized.replace(needle, duplicate);
            assert_ne!(bytes, serialized);
            assert!(
                parse_bytes(bytes.as_bytes(), &original).is_err(),
                "{kind} duplicate {needle}"
            );
        }
    }
}

#[test]
fn envelope_identity_proof_and_artifact_bindings_are_exact() {
    for kind in EVENT_TYPES {
        let original = event(kind);
        for (pointer, replacement) in [
            ("/schema_version", json!(2)),
            ("/event_id", json!(HOLD)),
            ("/producer_id", json!("evidence-retention")),
            ("/policy_revision", json!("evidence-retention-v1")),
            ("/producer_boot_id", json!(HOLD)),
            ("/producer_boot_id", json!(&EVENT[3..])),
            ("/producer_seq", json!(0)),
            ("/producer_seq", json!(2)),
            ("/request_seq", json!(0)),
            ("/request_seq", json!(2)),
            (
                "/request_id",
                json!("req_018f2a3b-4c5d-7000-8000-000000000003"),
            ),
            ("/tenant_id", json!("foreign/domain")),
            ("/site_id", json!("foreign/domain")),
            ("/sensitivity", json!("INTERNAL")),
            ("/example_only", json!(true)),
            ("/trace_id", json!("a".repeat(32))),
            ("/span_id", json!("a".repeat(16))),
            ("/integrity/state", json!("sealed")),
            ("/integrity/previous_hash", json!("a".repeat(64))),
            ("/integrity/event_hash", json!("a".repeat(64))),
            ("/evidence_refs", json!([])),
            ("/evidence_refs", json!([CASE])),
            ("/evidence_refs", json!([ARTIFACT, ARTIFACT])),
            (
                "/evidence_refs",
                json!(["artifact_018f2a3b-4c5d-7000-8000-000000000006"]),
            ),
            ("/payload/stage", json!("evidence_retention")),
            ("/payload/outcome", json!("ERROR")),
            (
                "/payload/reason_code",
                json!(if *kind == EVENT_TYPES[0] {
                    "EVIDENCE_HOLD_RELEASED"
                } else {
                    "EVIDENCE_HOLD_CREATED"
                }),
            ),
            ("/payload/proof_kind", json!("model")),
            ("/payload/confidence", json!(0.0)),
            ("/payload/confidence_status", json!("provided")),
            ("/payload/hold_id", json!(CASE)),
            ("/payload/case_id", json!(EVENT)),
            ("/payload/artifact_id", json!(CASE)),
            ("/cause_event_ids", json!([CASE])),
            ("/cause_event_ids", json!([HOLD, HOLD])),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            assert!(row(&invalid).is_err(), "{kind} accepted {pointer}");
        }
        for field in ["hold_id", "case_id", "artifact_id"] {
            for replacement in [
                original["payload"][field].as_str().unwrap().to_uppercase(),
                original["payload"][field]
                    .as_str()
                    .unwrap()
                    .replace("-7000-", "-4000-"),
            ] {
                let mut invalid = original.clone();
                invalid["payload"][field] = json!(replacement);
                assert!(row(&invalid).is_err(), "{kind} invalid ID {field}");
            }
        }
        let mut mismatched_trace = original;
        mismatched_trace["trace_id"] = json!("a".repeat(32));
        mismatched_trace["span_id"] = json!("a".repeat(16));
        assert!(row(&mismatched_trace).is_err());
    }
}

#[test]
fn hold_identity_and_causes_follow_creation_and_release() {
    for (kind, hold, causes) in [
        (EVENT_TYPES[0], HOLD, json!([])),
        (EVENT_TYPES[0], EVENT, json!([HOLD])),
        (EVENT_TYPES[1], EVENT, json!([EVENT])),
        (EVENT_TYPES[1], HOLD, json!([])),
        (EVENT_TYPES[1], HOLD, json!([EVENT])),
        (
            EVENT_TYPES[1],
            HOLD,
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000009"]),
        ),
    ] {
        let mut invalid = event(kind);
        invalid["payload"]["hold_id"] = json!(hold);
        invalid["cause_event_ids"] = causes;
        assert!(row(&invalid).is_err(), "{kind} mismatched hold/cause");
    }
    let mut invalid = event(EVENT_TYPES[0]);
    invalid["event_type"] = json!("evidence.hold.unknown");
    assert!(row(&invalid).is_err());
}

#[test]
fn subjects_and_request_digests_are_bounded() {
    for kind in EVENT_TYPES {
        for subject in [
            String::new(),
            "a".repeat(257),
            "界".repeat(86),
            " actor".to_owned(),
            "actor ".to_owned(),
            "\u{2003}actor".to_owned(),
            "actor\nname".to_owned(),
            "actor\u{0085}name".to_owned(),
        ] {
            let mut invalid = event(kind);
            invalid["payload"]["subject_ref"] = json!(subject);
            assert!(row(&invalid).is_err());
        }
        for subject in ["a".repeat(256), "界".repeat(85), "actor name".to_owned()] {
            let mut valid = event(kind);
            valid["payload"]["subject_ref"] = json!(subject);
            assert!(row(&valid).is_ok());
        }
        for digest in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            let mut invalid = event(kind);
            invalid["payload"]["request_digest"] = json!(digest);
            assert!(row(&invalid).is_err());
        }
    }
}

#[test]
fn clocks_and_creation_deadlines_keep_frozen_millisecond_bounds() {
    for kind in EVENT_TYPES {
        for timestamp in [
            "invalid",
            "2026-09-19T00:00:00Z",
            "2026-09-19T00:00:00.123456Z",
            "2026-09-19T00:00:00.123+00:00",
            "2026-09-19T08:00:00.123+08:00",
            "2026-09-19T00:00:00.123Z\n",
            "2026-02-30T00:00:00.123Z",
            "1969-12-31T23:59:59.999Z",
            "2263-01-01T00:00:00.000Z",
        ] {
            let mut invalid = event(kind);
            invalid["occurred_at"] = json!(timestamp);
            invalid["observed_at"] = json!(timestamp);
            assert!(row(&invalid).is_err(), "{kind} timestamp {timestamp}");
            let mut invalid = event(kind);
            invalid["payload"]["hold_until"] = json!(timestamp);
            assert!(row(&invalid).is_err(), "{kind} hold_until {timestamp}");
        }
        let mut invalid = event(kind);
        invalid["observed_at"] = json!("2026-09-19T00:00:00.124Z");
        assert!(row(&invalid).is_err());
        invalid = event(kind);
        invalid["payload"]["hold_until"] = json!("1969-12-31T23:59:59.999Z");
        assert!(row(&invalid).is_err());
    }
    for (until, accepted) in [
        ("2026-09-19T00:00:00.122Z", false),
        ("2026-09-19T00:00:00.123Z", false),
        ("2026-09-19T00:00:00.124Z", true),
        ("2026-10-19T00:00:00.123Z", true),
        ("2026-10-19T00:00:00.124Z", false),
    ] {
        let mut value = event(EVENT_TYPES[0]);
        value["payload"]["hold_until"] = json!(until);
        assert_eq!(row(&value).is_ok(), accepted, "creation deadline {until}");
    }
    for until in [
        "1970-01-01T00:00:00.000Z",
        "2026-09-18T00:00:00.123Z",
        "2026-09-19T00:00:00.123Z",
        "2026-11-19T00:00:00.123Z",
    ] {
        let mut value = event(EVENT_TYPES[1]);
        value["payload"]["hold_until"] = json!(until);
        assert!(row(&value).is_ok(), "released deadline {until}");
    }
}
