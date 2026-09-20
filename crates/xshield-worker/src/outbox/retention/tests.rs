//! Producer-shaped maintenance events and rejection checks at the index boundary.

use super::EVENT_TYPES;
use crate::{IndexRow, PublishError};
use chrono::TimeDelta;
use serde_json::{Value, json};
use xshield_core::domain::EventId;

const EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000001";
const BOOT: &str = "018f2a3b-4c5d-7000-8000-000000000031";
const ARTIFACT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000032";
const OTHER_ARTIFACT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000033";
const REQUEST: &str = "req_018f2a3b-4c5d-7000-8000-000000000034";
const CAUSE: &str = "ev_018f2a3b-4c5d-7000-8000-000000000035";
const VARIANTS: &[(&str, &str)] = &[
    ("evidence.purge_requested", "EVIDENCE_PURGE_REQUESTED"),
    ("evidence.deleted", "EVIDENCE_DELETED"),
    ("evidence.deleted", "EVIDENCE_DELETE_ALREADY_ABSENT"),
    ("evidence.purge_failed", "EVIDENCE_PURGE_REJECTED"),
    ("evidence.purge_failed", "EVIDENCE_PURGE_UNAVAILABLE"),
    (
        "evidence.orphan.purge_requested",
        "EVIDENCE_ORPHAN_PURGE_REQUESTED",
    ),
    ("evidence.orphan.deleted", "EVIDENCE_ORPHAN_DELETED"),
    (
        "evidence.orphan.deleted",
        "EVIDENCE_ORPHAN_DELETE_ALREADY_ABSENT",
    ),
    (
        "evidence.orphan.purge_failed",
        "EVIDENCE_ORPHAN_PURGE_REJECTED",
    ),
    (
        "evidence.orphan.purge_failed",
        "EVIDENCE_ORPHAN_PURGE_UNAVAILABLE",
    ),
];

/// Canonical maintenance fixture reusable by publication and lease tests.
pub(crate) fn event(event_type: &str) -> Value {
    let mut event = crate::outbox::tests::event("case.created");
    let orphan = event_type.starts_with("evidence.orphan.");
    event["event_type"] = json!(event_type);
    event["producer_id"] = json!("evidence-retention");
    event["producer_boot_id"] = json!(BOOT);
    event["request_id"] = Value::Null;
    event["policy_revision"] = json!("evidence-retention-v1");
    event["sensitivity"] = json!("RESTRICTED");
    event["evidence_refs"] = json!([ARTIFACT]);
    event["cause_event_ids"] = if event_type.ends_with("purge_requested") {
        json!([])
    } else {
        json!([CAUSE])
    };
    event["payload"] = json!({
        "stage": if orphan { "evidence_orphan_retention" } else { "evidence_retention" },
        "outcome": if event_type.ends_with("purge_failed") { "ERROR" } else { "PASS" },
        "reason_code": VARIANTS.iter().find(|(kind, _)| *kind == event_type).unwrap().1,
        "artifact_id": ARTIFACT, "proof_kind": "deterministic", "confidence": null,
        "confidence_status": "not_applicable"
    });
    if orphan {
        event["payload"]["authenticated_manifest"] = json!(true);
    } else {
        event["payload"]["source_request_id"] = json!(REQUEST);
        event["payload"]["expires_at"] = json!("2026-09-18T00:00:00.123Z");
        event["payload"]["retained_metadata"] = json!(true);
    }
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
fn all_six_types_and_ten_results_preserve_maintenance_facts() {
    for &(kind, reason) in VARIANTS {
        let mut value = event(kind);
        value["payload"]["reason_code"] = json!(reason);
        let row = row(&value).unwrap();
        assert_eq!(row.event_type, kind);
        assert_eq!(row.stage, value["payload"]["stage"]);
        assert_eq!(row.outcome, value["payload"]["outcome"]);
        assert_eq!(row.reason_code, reason);
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.sensitivity, "RESTRICTED");
        assert_eq!(row.producer_boot_id, BOOT);
        assert_eq!(row.evidence_refs, [ARTIFACT]);
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
    }
}

#[test]
fn missing_unknown_duplicate_and_wrong_type_fields_are_rejected() {
    for kind in EVENT_TYPES {
        let original = event(kind);
        for path in ["", "/payload"] {
            for field in original.pointer(path).unwrap().as_object().unwrap().keys() {
                let mut missing = original.clone();
                missing
                    .pointer_mut(path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
                assert!(row(&missing).is_err(), "{kind} missing {path}/{field}");
                let mut drift = original.clone();
                drift.pointer_mut(path).unwrap()[field] =
                    if original.pointer(path).unwrap()[field].is_array() {
                        json!("invalid")
                    } else {
                        json!([])
                    };
                assert!(row(&drift).is_err(), "{kind} type drift {path}/{field}");
            }
            let mut unknown = original.clone();
            unknown.pointer_mut(path).unwrap()["extra"] = Value::Null;
            assert!(row(&unknown).is_err(), "{kind} unknown {path}/extra");
        }
        let serialized = serde_json::to_string(&original).unwrap();
        // The shared integrity contract permits omitted pending hashes.
        let mut pending = original.clone();
        for field in ["previous_hash", "event_hash"] {
            pending["integrity"].as_object_mut().unwrap().remove(field);
            assert!(row(&pending).is_ok(), "{kind} optional integrity/{field}");
        }
        for (needle, duplicate) in [
            (
                r#""confidence":null"#,
                r#""confidence":1,"confidence":null"#,
            ),
            (
                r#""producer_seq":1"#,
                r#""producer_seq":2,"producer_seq":1"#,
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
fn event_type_reason_and_outcome_are_exactly_bound() {
    for &(kind, reason) in VARIANTS {
        let mut original = event(kind);
        original["payload"]["reason_code"] = json!(reason);
        for other in EVENT_TYPES.iter().copied().filter(|other| *other != kind) {
            let mut invalid = original.clone();
            invalid["event_type"] = json!(other);
            assert!(row(&invalid).is_err(), "{kind}/{reason} became {other}");
        }
        for (field, replacement) in [
            ("stage", json!("request_completed")),
            ("proof_kind", json!("model")),
            ("confidence", json!(0.0)),
            ("confidence_status", json!("available")),
            ("reason_code", json!("EVIDENCE_UNKNOWN")),
            ("outcome", json!("DENY")),
            (
                "outcome",
                json!(if kind.ends_with("purge_failed") {
                    "PASS"
                } else {
                    "ERROR"
                }),
            ),
            ("artifact_id", json!(REQUEST)),
        ] {
            let mut invalid = original.clone();
            invalid["payload"][field] = replacement;
            assert!(row(&invalid).is_err(), "{kind}/{reason} accepted {field}");
        }
    }
    let mut unknown = event(EVENT_TYPES[0]);
    unknown["event_type"] = json!("evidence.purge_unknown");
    assert!(row(&unknown).is_err());
}

#[test]
fn identity_evidence_and_cause_bindings_are_required() {
    for kind in EVENT_TYPES {
        let original = event(kind);
        for (pointer, replacement) in [
            ("/schema_version", json!(2)),
            ("/event_id", json!(CAUSE)),
            ("/tenant_id", json!("foreign/domain")),
            ("/site_id", json!("foreign/domain")),
            ("/producer_id", json!("xshield-control")),
            ("/policy_revision", json!("control-v1")),
            ("/producer_boot_id", json!(REQUEST)),
            (
                "/producer_boot_id",
                json!("018f2a3b-4c5d-4000-8000-000000000031"),
            ),
            ("/producer_boot_id", json!(BOOT.to_uppercase())),
            ("/producer_seq", json!(0)),
            ("/producer_seq", json!(2)),
            ("/request_seq", json!(0)),
            ("/request_seq", json!(2)),
            ("/request_id", json!(REQUEST)),
            ("/sensitivity", json!("INTERNAL")),
            ("/example_only", json!(true)),
            ("/trace_id", json!("a".repeat(31))),
            ("/span_id", json!("a".repeat(16))),
            ("/integrity/state", json!("verified")),
            ("/integrity/previous_hash", json!("a".repeat(64))),
            ("/integrity/event_hash", json!("a".repeat(64))),
            ("/evidence_refs", json!([])),
            ("/evidence_refs", json!([OTHER_ARTIFACT])),
            ("/evidence_refs", json!([ARTIFACT, OTHER_ARTIFACT])),
            ("/evidence_refs", json!([ARTIFACT, ARTIFACT])),
            ("/cause_event_ids", json!([EVENT])),
            ("/cause_event_ids", json!([ARTIFACT])),
            ("/cause_event_ids", json!([CAUSE, CAUSE])),
            ("/cause_event_ids", json!([CAUSE, EVENT])),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            assert!(row(&invalid).is_err(), "{kind} accepted {pointer}");
        }
        let mut invalid = original;
        invalid["cause_event_ids"] = if kind.ends_with("purge_requested") {
            json!([CAUSE])
        } else {
            json!([])
        };
        assert!(row(&invalid).is_err(), "{kind} wrong cause count");
    }
}

#[test]
fn catalog_and_orphan_payloads_reject_crossed_shapes() {
    for (kind, field, value) in [
        ("evidence.deleted", "authenticated_manifest", json!(true)),
        ("evidence.deleted", "source_request_id", json!(ARTIFACT)),
        ("evidence.deleted", "retained_metadata", json!(false)),
        (
            "evidence.orphan.deleted",
            "source_request_id",
            json!(REQUEST),
        ),
        (
            "evidence.orphan.deleted",
            "expires_at",
            json!("2026-09-18T00:00:00.123Z"),
        ),
        ("evidence.orphan.deleted", "retained_metadata", json!(true)),
    ] {
        let mut invalid = event(kind);
        invalid["payload"][field] = value;
        assert!(row(&invalid).is_err(), "{kind} accepted {field}");
    }
    for kind in EVENT_TYPES
        .iter()
        .filter(|kind| kind.starts_with("evidence.orphan."))
    {
        let mut value = event(kind);
        value["payload"]["authenticated_manifest"] = json!(false);
        assert!(row(&value).is_ok());
    }
}

#[test]
fn timestamps_follow_producer_precision_and_failed_attempts_allow_clock_rollback() {
    for kind in EVENT_TYPES {
        for timestamp in [
            "invalid",
            "2026-09-19T00:00:00Z",
            "2026-09-19T00:00:00.123456Z",
            "2026-09-19T00:00:00.123+00:00",
            "2026-09-19T01:00:00.123+01:00",
        ] {
            let mut invalid = event(kind);
            invalid["occurred_at"] = json!(timestamp);
            invalid["observed_at"] = json!(timestamp);
            assert!(row(&invalid).is_err(), "{kind} accepted time {timestamp}");
            if !kind.starts_with("evidence.orphan.") {
                let mut invalid = event(kind);
                invalid["payload"]["expires_at"] = json!(timestamp);
                assert!(row(&invalid).is_err(), "{kind} accepted expiry {timestamp}");
            }
        }
        let mut invalid = event(kind);
        invalid["observed_at"] = json!("2026-09-19T00:00:00.124Z");
        assert!(row(&invalid).is_err());
    }
    for reason in ["EVIDENCE_PURGE_REJECTED", "EVIDENCE_PURGE_UNAVAILABLE"] {
        let mut value = event("evidence.purge_failed");
        value["payload"]["reason_code"] = json!(reason);
        value["payload"]["expires_at"] = json!("2026-09-20T00:00:00.999Z");
        assert!(row(&value).is_ok());
    }
}

#[test]
fn independent_boots_are_accepted_and_journal_source_is_rejected() {
    for kind in EVENT_TYPES {
        let mut value = event(kind);
        for boot in [BOOT, "018f2a3b-4c5d-7000-8000-000000000036"] {
            value["producer_boot_id"] = json!(boot);
            assert!(row(&value).is_ok());
            assert!(
                IndexRow::parse(
                    &serde_json::to_vec(&value).unwrap(),
                    &EventId::parse(EVENT).unwrap(),
                    1,
                    boot,
                    "0".repeat(64),
                    TimeDelta::days(30),
                )
                .is_err()
            );
        }
    }
}
