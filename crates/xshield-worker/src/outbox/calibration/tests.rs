//! Calibration report parser fixtures and negative contract coverage.

use super::EVENT_TYPES;
use crate::{IndexRow, PublishError};
use chrono::TimeDelta;
use serde_json::{Value, json};
use xshield_core::domain::EventId;

const EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000001";
const REPORT: &str = "calr_018f2a3b-4c5d-7000-8000-000000000002";
const REPORT_ARTIFACT: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000003";
const EVALUATION_MANIFEST: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000004";
const TRAINING_MANIFEST: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000005";
const CALIBRATION_MANIFEST: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000006";
const LABEL_MANIFEST: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000007";

/// Canonical complete calibration report fixture for parser and lease tests.
pub(crate) fn event() -> Value {
    let mut event = crate::outbox::tests::event("case.created");
    event["event_type"] = json!(EVENT_TYPES[0]);
    event["producer_id"] = json!("calibration-evaluator");
    event["producer_boot_id"] = json!(EVENT);
    event["request_id"] = Value::Null;
    event["trace_id"] = json!("018f2a3b4c5d70008000000000000002");
    event["span_id"] = json!("018f2a3b4c5d7000");
    event["occurred_at"] = json!("2026-09-20T00:00:00.123Z");
    event["observed_at"] = event["occurred_at"].clone();
    event["policy_revision"] = json!("calibration-v1");
    event["sensitivity"] = json!("RESTRICTED");
    event["evidence_refs"] = json!([REPORT_ARTIFACT]);
    event["cause_event_ids"] = json!([]);
    event["payload"] = json!({
        "stage": "calibration_report", "outcome": "PASS",
        "reason_code": "CALIBRATION_REPORTED", "report_id": REPORT,
        "report_artifact_id": REPORT_ARTIFACT, "approval_ref": "approval-r1",
        "dataset_revision": "dataset-r1", "label_revision": "labels-r1",
        "task_revision": "task-r1", "threshold_policy_revision": "threshold-r1",
        "mapping_revision": "mapping-r1",
        "evaluation_manifest_artifact_id": EVALUATION_MANIFEST,
        "training_manifest_artifact_id": TRAINING_MANIFEST,
        "calibration_manifest_artifact_id": CALIBRATION_MANIFEST,
        "label_manifest_artifact_id": LABEL_MANIFEST,
        "provider": "vercel_ai_gateway", "provider_model_id": "typesafe-ai/jev",
        "model_revision": "jev-1.13.0", "prompt_revision": "prompt-r1",
        "resolved_model_revision": null
    });
    event
}

fn row(value: &Value) -> Result<IndexRow, PublishError> {
    let bytes = serde_json::to_vec(value).map_err(|_| PublishError::InvalidEvent)?;
    IndexRow::parse_outbox(
        &bytes,
        &EventId::parse(EVENT).map_err(|_| PublishError::InvalidEvent)?,
        value["producer_seq"]
            .as_u64()
            .ok_or(PublishError::InvalidEvent)?,
        value["producer_boot_id"]
            .as_str()
            .ok_or(PublishError::InvalidEvent)?,
        "0".repeat(64),
        TimeDelta::days(30),
    )
}

fn row_bytes(bytes: &[u8]) -> Result<IndexRow, PublishError> {
    IndexRow::parse_outbox(
        bytes,
        &EventId::parse(EVENT).map_err(|_| PublishError::InvalidEvent)?,
        1,
        EVENT,
        "0".repeat(64),
        TimeDelta::days(30),
    )
}

#[test]
fn canonical_report_is_a_non_terminal_deterministic_summary() {
    let value = event();
    let row = row(&value).unwrap();
    assert_eq!(row.event_type, "calibration.reported");
    assert_eq!(row.stage, "calibration_report");
    assert_eq!(row.outcome, "PASS");
    assert_eq!(row.reason_code, "CALIBRATION_REPORTED");
    assert_eq!(row.proof_kind, "deterministic");
    assert_eq!(row.confidence, None);
    assert_eq!(row.confidence_status, "not_applicable");
    assert_eq!(row.sensitivity, "RESTRICTED");
    assert_eq!(row.producer_boot_id, EVENT);
    assert_eq!(row.evidence_refs, [REPORT_ARTIFACT]);
    assert!(row.request_id.is_empty());
    assert!(row.cause_event_ids.is_empty());
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

#[test]
fn closed_payload_rejects_missing_unknown_and_duplicate_fields() {
    let original = event();
    for path in ["", "/payload", "/integrity"] {
        for field in original.pointer(path).unwrap().as_object().unwrap().keys() {
            let mut missing = original.clone();
            missing
                .pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            let optional_hash =
                path == "/integrity" && matches!(field.as_str(), "previous_hash" | "event_hash");
            assert_eq!(
                row(&missing).is_ok(),
                optional_hash,
                "missing {path}/{field}"
            );
        }
        let mut unknown = original.clone();
        unknown.pointer_mut(path).unwrap()["extra"] = Value::Null;
        assert!(row(&unknown).is_err(), "accepted unknown {path}");
    }
    let serialized = serde_json::to_string(&original).unwrap();
    for (needle, duplicate) in [
        (
            r#""report_id":"calr_018f2a3b-4c5d-7000-8000-000000000002""#,
            r#""report_id":"calr_018f2a3b-4c5d-7000-8000-000000000099","report_id":"calr_018f2a3b-4c5d-7000-8000-000000000002""#,
        ),
        (
            r#""producer_seq":1"#,
            r#""producer_seq":2,"producer_seq":1"#,
        ),
    ] {
        assert!(row_bytes(serialized.replace(needle, duplicate).as_bytes()).is_err());
    }
}

#[test]
fn identity_clock_and_report_artifact_bindings_are_exact() {
    let original = event();
    for (pointer, replacement) in [
        ("/event_type", json!("calibration.unknown")),
        ("/producer_id", json!("model-eval")),
        (
            "/producer_boot_id",
            json!("ev_018f2a3b-4c5d-7000-8000-000000000099"),
        ),
        (
            "/request_id",
            json!("req_018f2a3b-4c5d-7000-8000-000000000008"),
        ),
        ("/producer_seq", json!(2)),
        ("/request_seq", json!(2)),
        ("/policy_revision", json!("policy-r1")),
        ("/sensitivity", json!("SENSITIVE")),
        ("/example_only", json!(true)),
        ("/trace_id", json!("018f2a3b4c5d70008000000000000001")),
        ("/span_id", json!("018f2a3b4c5d7001")),
        ("/observed_at", json!("2026-09-20T00:00:00.124Z")),
        ("/integrity/state", json!("sealed")),
        ("/cause_event_ids", json!([EVENT])),
        ("/evidence_refs", json!([])),
        ("/evidence_refs", json!([EVALUATION_MANIFEST])),
        ("/evidence_refs", json!([REPORT_ARTIFACT, REPORT_ARTIFACT])),
        (
            "/payload/report_id",
            json!("calr_018f2a3b-4c5d-4000-8000-000000000002"),
        ),
        ("/payload/report_artifact_id", json!(EVALUATION_MANIFEST)),
        ("/payload/stage", json!("calibration")),
        ("/payload/outcome", json!("UNKNOWN")),
        (
            "/payload/reason_code",
            json!("CALIBRATION_DATASET_EVALUATED"),
        ),
    ] {
        let mut invalid = original.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        assert!(row(&invalid).is_err(), "accepted {pointer}");
    }
    for timestamp in [
        "invalid",
        "2026-09-20T00:00:00Z",
        "2026-09-20T00:00:00.123456Z",
        "2026-09-20T08:00:00.123+08:00",
        "2026-09-20T00:00:60.000Z",
        "1969-12-31T23:59:59.999Z",
    ] {
        let mut invalid = original.clone();
        invalid["occurred_at"] = json!(timestamp);
        invalid["observed_at"] = json!(timestamp);
        assert!(row(&invalid).is_err(), "accepted timestamp {timestamp}");
    }
    let mut non_rfc_variant = original.clone();
    non_rfc_variant["payload"]["report_id"] = json!("calr_018f2a3b-4c5d-7000-0000-000000000002");
    non_rfc_variant["trace_id"] = json!("018f2a3b4c5d70000000000000000002");
    non_rfc_variant["span_id"] = json!("018f2a3b4c5d7000");
    assert!(row(&non_rfc_variant).is_err());
}

#[test]
fn provenance_and_model_metadata_are_bounded_and_explicit() {
    let original = event();
    for field in [
        "approval_ref",
        "dataset_revision",
        "label_revision",
        "task_revision",
        "threshold_policy_revision",
        "mapping_revision",
        "provider",
        "model_revision",
        "prompt_revision",
    ] {
        for replacement in [json!(""), json!("bad value"), json!("x".repeat(129))] {
            let mut invalid = original.clone();
            invalid["payload"][field] = replacement;
            assert!(row(&invalid).is_err(), "accepted {field}");
        }
    }
    for field in [
        "evaluation_manifest_artifact_id",
        "training_manifest_artifact_id",
        "calibration_manifest_artifact_id",
        "label_manifest_artifact_id",
    ] {
        let mut invalid = original.clone();
        invalid["payload"][field] = json!(REPORT);
        assert!(row(&invalid).is_err(), "accepted invalid {field}");
    }
    for (field, duplicate) in [
        ("evaluation_manifest_artifact_id", REPORT_ARTIFACT),
        ("training_manifest_artifact_id", EVALUATION_MANIFEST),
        ("calibration_manifest_artifact_id", EVALUATION_MANIFEST),
        ("label_manifest_artifact_id", EVALUATION_MANIFEST),
    ] {
        let mut invalid = original.clone();
        invalid["payload"][field] = json!(duplicate);
        assert!(row(&invalid).is_err(), "accepted overlapping {field}");
    }
    for replacement in [
        json!("typesafe-ai/jev/extra"),
        json!("typesafe ai/jev"),
        json!("x".repeat(129)),
    ] {
        let mut invalid = original.clone();
        invalid["payload"]["provider_model_id"] = replacement;
        assert!(row(&invalid).is_err());
    }
    let mut known = original.clone();
    known["payload"]["resolved_model_revision"] = json!("jev-1.13.0");
    assert!(row(&known).is_ok());
    for replacement in [json!(""), json!("bad revision"), json!(true)] {
        let mut invalid = original.clone();
        invalid["payload"]["resolved_model_revision"] = replacement;
        assert!(row(&invalid).is_err());
    }
    assert!(
        IndexRow::parse(
            &serde_json::to_vec(&original).unwrap(),
            &EventId::parse(EVENT).unwrap(),
            1,
            EVENT,
            "0".repeat(64),
            TimeDelta::days(30),
        )
        .is_err()
    );
}
