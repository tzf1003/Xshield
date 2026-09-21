//! Calibration report parser fixtures and negative contract coverage.

use super::EVENT_TYPES;
use crate::{IndexRow, PublishError};
use chrono::TimeDelta;
use serde_json::{Value, json};
use xshield_core::domain::EventId;

const EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000001";
const CAPABILITY: &str = "calcap_018f2a3b-4c5d-7000-8000-000000000008";
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

/// Canonical restricted issuance fixture. It contains a digest and aggregate
/// bounds only: frozen member references and lease handles are never indexed.
fn capability_issuance_event() -> Value {
    let mut event = crate::outbox::tests::event("case.created");
    let trace_id = CAPABILITY.strip_prefix("calcap_").unwrap().replace('-', "");
    event["event_type"] = json!(EVENT_TYPES[1]);
    event["producer_id"] = json!("calibration-capability-issuer");
    event["producer_boot_id"] = json!(EVENT);
    event["request_id"] = Value::Null;
    event["trace_id"] = json!(trace_id);
    event["span_id"] = json!(&trace_id[..16]);
    event["occurred_at"] = json!("2026-09-20T00:00:00.123Z");
    event["observed_at"] = event["occurred_at"].clone();
    event["policy_revision"] = json!("calibration-v1");
    event["sensitivity"] = json!("RESTRICTED");
    event["evidence_refs"] = json!([]);
    event["cause_event_ids"] = json!([]);
    event["payload"] = json!({
        "stage": "calibration_read_capability", "outcome": "PASS",
        "reason_code": "CALIBRATION_READ_CAPABILITY_ISSUED",
        "capability_id": CAPABILITY, "scope_digest": "a".repeat(64),
        "member_count": 6, "frozen_total_bytes": 1,
        "not_before_unix": 1_789_689_600_u64,
        "expires_at_unix": 1_789_693_200_u64
    });
    event
}

fn batch_completion_event() -> Value {
    let mut event = crate::outbox::tests::event("case.created");
    let trace_id = CAPABILITY.strip_prefix("calcap_").unwrap().replace('-', "");
    event["event_type"] = json!(EVENT_TYPES[2]);
    event["producer_id"] = json!("calibration-evidence-batch-completer");
    event["producer_boot_id"] = json!(EVENT);
    event["request_id"] = Value::Null;
    event["trace_id"] = json!(trace_id);
    event["span_id"] = json!(&trace_id[..16]);
    event["occurred_at"] = json!("2026-09-20T00:00:00.123Z");
    event["observed_at"] = event["occurred_at"].clone();
    event["policy_revision"] = json!("calibration-v1");
    event["sensitivity"] = json!("RESTRICTED");
    event["evidence_refs"] = json!([]);
    event["cause_event_ids"] = json!([]);
    event["payload"] = json!({
        "stage": "calibration_read_batch", "outcome": "PASS",
        "reason_code": "CALIBRATION_READ_BATCH_COMPLETED",
        "capability_id": CAPABILITY
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
fn report_retention_facts_are_closed_and_report_bound() {
    for (event_type, outcome, reason_code, cause) in [
        (
            "calibration.report_retention.purge_requested",
            "PASS",
            "CALIBRATION_REPORT_PURGE_REQUESTED",
            json!([]),
        ),
        (
            "calibration.report_retention.deleted",
            "PASS",
            "CALIBRATION_REPORT_DELETED",
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000099"]),
        ),
        (
            "calibration.report_retention.deleted",
            "PASS",
            "CALIBRATION_REPORT_DELETE_ALREADY_ABSENT",
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000099"]),
        ),
        (
            "calibration.report_retention.purge_failed",
            "ERROR",
            "CALIBRATION_REPORT_PURGE_REJECTED",
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000099"]),
        ),
        (
            "calibration.report_retention.purge_failed",
            "ERROR",
            "CALIBRATION_REPORT_PURGE_UNAVAILABLE",
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000099"]),
        ),
    ] {
        let mut value = event();
        value["event_type"] = json!(event_type);
        value["producer_id"] = json!("calibration-report-retention");
        value["producer_boot_id"] = json!("018f2a3b-4c5d-7000-8000-000000000098");
        value["policy_revision"] = json!("calibration-retention-v1");
        value["cause_event_ids"] = cause;
        value["payload"] = json!({
            "stage":"calibration_report_retention", "outcome":outcome,
            "reason_code":reason_code, "proof_kind":"deterministic",
            "confidence":null, "confidence_status":"not_applicable",
            "report_id":REPORT, "report_artifact_id":REPORT_ARTIFACT,
            "expires_at":"2026-09-21T00:00:00.123Z", "retained_metadata":true
        });
        let parsed = row(&value).expect("retention fact is valid");
        assert_eq!(parsed.event_type, event_type);
        assert_eq!(parsed.stage, "calibration_report_retention");
        assert_eq!(parsed.outcome, outcome);
        assert_eq!(parsed.reason_code, reason_code);
        assert_eq!(parsed.evidence_refs, [REPORT_ARTIFACT]);

        value["payload"]["retained_metadata"] = json!(false);
        assert!(
            row(&value).is_err(),
            "retention metadata must remain explicit"
        );
    }
}

#[test]
fn report_orphan_retention_facts_are_closed_and_bound_to_the_recovery_intent() {
    for (event_type, outcome, reason_code, cause) in [
        (
            "calibration.report_retention.orphan_purge_requested",
            "PASS",
            "CALIBRATION_REPORT_ORPHAN_PURGE_REQUESTED",
            json!([]),
        ),
        (
            "calibration.report_retention.orphan_deleted",
            "PASS",
            "CALIBRATION_REPORT_ORPHAN_DELETED",
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000099"]),
        ),
        (
            "calibration.report_retention.orphan_deleted",
            "PASS",
            "CALIBRATION_REPORT_ORPHAN_DELETE_ALREADY_ABSENT",
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000099"]),
        ),
        (
            "calibration.report_retention.orphan_purge_failed",
            "ERROR",
            "CALIBRATION_REPORT_ORPHAN_PURGE_REJECTED",
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000099"]),
        ),
        (
            "calibration.report_retention.orphan_purge_failed",
            "ERROR",
            "CALIBRATION_REPORT_ORPHAN_PURGE_UNAVAILABLE",
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000099"]),
        ),
    ] {
        let mut value = event();
        value["event_type"] = json!(event_type);
        value["producer_id"] = json!("calibration-report-retention");
        value["producer_boot_id"] = json!("018f2a3b-4c5d-7000-8000-000000000098");
        value["policy_revision"] = json!("calibration-retention-v1");
        value["cause_event_ids"] = cause;
        value["payload"] = json!({
            "stage":"calibration_report_retention", "outcome":outcome,
            "reason_code":reason_code, "proof_kind":"deterministic",
            "confidence":null, "confidence_status":"not_applicable",
            "report_id":REPORT, "report_artifact_id":REPORT_ARTIFACT,
            "expires_at":"2026-09-21T00:00:00.123Z", "retained_metadata":true
        });
        assert!(row(&value).is_ok(), "valid orphan retention {event_type}");

        let mut missing = value.clone();
        missing["payload"]
            .as_object_mut()
            .unwrap()
            .remove("retained_metadata");
        assert!(row(&missing).is_err(), "accepted incomplete orphan payload");

        let mut unknown = value.clone();
        unknown["payload"]["source_request_id"] = json!(EVENT);
        assert!(
            row(&unknown).is_err(),
            "accepted catalog field in orphan payload"
        );
    }

    let mut terminal_without_intent = event();
    terminal_without_intent["event_type"] = json!("calibration.report_retention.orphan_deleted");
    terminal_without_intent["producer_id"] = json!("calibration-report-retention");
    terminal_without_intent["producer_boot_id"] = json!("018f2a3b-4c5d-7000-8000-000000000098");
    terminal_without_intent["policy_revision"] = json!("calibration-retention-v1");
    terminal_without_intent["cause_event_ids"] = json!([]);
    terminal_without_intent["payload"] = json!({
        "stage":"calibration_report_retention", "outcome":"PASS",
        "reason_code":"CALIBRATION_REPORT_ORPHAN_DELETED", "proof_kind":"deterministic",
        "confidence":null, "confidence_status":"not_applicable",
        "report_id":REPORT, "report_artifact_id":REPORT_ARTIFACT,
        "expires_at":"2026-09-21T00:00:00.123Z", "retained_metadata":true
    });
    assert!(row(&terminal_without_intent).is_err());
}

#[test]
fn canonical_capability_issuance_is_a_non_terminal_deterministic_summary() {
    let value = capability_issuance_event();
    let index_row = row(&value).unwrap();
    assert_eq!(index_row.event_type, "calibration.read_capability.issued");
    assert_eq!(index_row.stage, "calibration_read_capability");
    assert_eq!(index_row.outcome, "PASS");
    assert_eq!(index_row.reason_code, "CALIBRATION_READ_CAPABILITY_ISSUED");
    assert_eq!(index_row.proof_kind, "deterministic");
    assert_eq!(index_row.confidence, None);
    assert_eq!(index_row.confidence_status, "not_applicable");
    assert_eq!(index_row.sensitivity, "RESTRICTED");
    assert_eq!(index_row.producer_boot_id, EVENT);
    assert!(index_row.request_id.is_empty());
    assert!(index_row.evidence_refs.is_empty());
    assert!(index_row.cause_event_ids.is_empty());
    assert_eq!(index_row.is_terminal, 0);
    assert_eq!(index_row.http_status, None);
    assert_eq!(index_row.duration_us, 0);
    assert!(index_row.method.is_empty());
    assert!(index_row.operation_id.is_empty());
    assert!(index_row.origin_state.is_empty());
    assert!(index_row.model_revision.is_empty());
    assert_eq!(
        serde_json::from_str::<Value>(&index_row.payload_json).unwrap(),
        value["payload"]
    );
    assert_eq!(
        index_row.retention_expires_at,
        index_row.occurred_at + TimeDelta::days(30)
    );

    // A SHA-256 digest has no safe nonzero invariant; only its exact wire
    // shape belongs to this parser.
    let mut zero_digest = value;
    zero_digest["payload"]["scope_digest"] = json!("0".repeat(64));
    assert!(row(&zero_digest).is_ok());
}

#[test]
fn completion_is_a_restricted_non_terminal_without_sources_or_lease_material() {
    let original = batch_completion_event();
    let index_row = row(&original).unwrap();
    assert_eq!(index_row.event_type, "calibration.read_batch.completed");
    assert_eq!(index_row.stage, "calibration_read_batch");
    assert_eq!(index_row.outcome, "PASS");
    assert_eq!(index_row.reason_code, "CALIBRATION_READ_BATCH_COMPLETED");
    assert_eq!(index_row.proof_kind, "deterministic");
    assert_eq!(index_row.confidence, None);
    assert_eq!(index_row.confidence_status, "not_applicable");
    assert_eq!(index_row.sensitivity, "RESTRICTED");
    assert!(index_row.request_id.is_empty());
    assert!(index_row.evidence_refs.is_empty());
    assert!(index_row.cause_event_ids.is_empty());
    assert_eq!(index_row.is_terminal, 0);
    for (pointer, replacement) in [
        ("/producer_id", json!("calibration-evaluator")),
        ("/payload/stage", json!("calibration_report")),
        ("/payload/outcome", json!("DENY")),
        ("/payload/reason_code", json!("CALIBRATION_REPORTED")),
        ("/payload/capability_id", json!(REPORT)),
        ("/evidence_refs", json!([REPORT_ARTIFACT])),
        ("/cause_event_ids", json!([EVENT])),
    ] {
        let mut invalid = original.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        assert!(row(&invalid).is_err(), "accepted {pointer}");
    }
    let mut unknown = original;
    unknown["payload"]["lease_id"] = json!("callease_018f2a3b-4c5d-7000-8000-000000000009");
    assert!(row(&unknown).is_err(), "accepted lease identity");
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
fn issuance_rejects_missing_unknown_and_duplicate_fields() {
    let original = capability_issuance_event();
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
            r#""capability_id":"calcap_018f2a3b-4c5d-7000-8000-000000000008""#,
            r#""capability_id":"calcap_018f2a3b-4c5d-7000-8000-000000000099","capability_id":"calcap_018f2a3b-4c5d-7000-8000-000000000008""#,
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
fn issuance_identity_scope_and_lease_facts_are_exact() {
    let original = capability_issuance_event();
    for (pointer, replacement) in [
        ("/event_type", json!("calibration.unknown")),
        ("/producer_id", json!("calibration-evaluator")),
        (
            "/producer_boot_id",
            json!("ev_018f2a3b-4c5d-7000-8000-000000000099"),
        ),
        (
            "/request_id",
            json!("req_018f2a3b-4c5d-7000-8000-000000000009"),
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
        ("/evidence_refs", json!([REPORT_ARTIFACT])),
        ("/payload/stage", json!("calibration")),
        ("/payload/outcome", json!("UNKNOWN")),
        ("/payload/reason_code", json!("CALIBRATION_REPORTED")),
        (
            "/payload/capability_id",
            json!("calcap_018f2a3b-4c5d-4000-8000-000000000008"),
        ),
        ("/payload/scope_digest", json!("A".repeat(64))),
        ("/payload/member_count", json!(5)),
        ("/payload/member_count", json!(7)),
        ("/payload/member_count", json!(20_005)),
        ("/payload/frozen_total_bytes", json!(0)),
        ("/payload/frozen_total_bytes", json!(512 * 1024 * 1024 + 1)),
        ("/payload/not_before_unix", json!(i64::MAX as u64 + 1)),
        ("/payload/expires_at_unix", json!(i64::MAX as u64 + 1)),
        ("/payload/not_before_unix", json!(1.5)),
        ("/payload/expires_at_unix", json!(1.5)),
    ] {
        let mut invalid = original.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        assert!(row(&invalid).is_err(), "accepted {pointer}");
    }
    for (not_before_unix, expires_at_unix) in [
        (1_789_689_600_u64, 1_789_689_600_u64),
        (1_789_689_600_u64, 1_789_689_599_u64),
    ] {
        let mut invalid = original.clone();
        invalid["payload"]["not_before_unix"] = json!(not_before_unix);
        invalid["payload"]["expires_at_unix"] = json!(expires_at_unix);
        assert!(row(&invalid).is_err(), "accepted unordered lease clocks");
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
}

#[test]
fn calibration_aggregate_field_follows_the_event_contract() {
    assert_eq!(
        super::super::OutboxFamily::Calibration.aggregate_field("calibration.reported"),
        "report_id"
    );
    assert_eq!(
        super::super::OutboxFamily::Calibration
            .aggregate_field("calibration.read_capability.issued"),
        "capability_id"
    );
    assert_eq!(
        super::super::OutboxFamily::Calibration.aggregate_field("calibration.read_batch.completed"),
        "capability_id"
    );
    for event_type in [
        "calibration.report_retention.orphan_purge_requested",
        "calibration.report_retention.orphan_deleted",
        "calibration.report_retention.orphan_purge_failed",
    ] {
        assert_eq!(
            super::super::OutboxFamily::Calibration.aggregate_field(event_type),
            "report_id"
        );
    }
    assert!(
        super::super::OutboxFamily::Calibration
            .aggregate_field("calibration.unknown")
            .is_empty()
    );
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
