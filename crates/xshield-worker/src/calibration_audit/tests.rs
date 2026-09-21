//! Calibration plaintext-release journal fixtures and negative contract coverage.

use super::{CalibrationEvidenceReadAuditEvent, CalibrationEvidenceReadOutcome};
use crate::{IndexRow, PublishError};
use chrono::TimeDelta;
use serde_json::{Value, json};
use std::fs;
use uuid::Uuid;
use xshield_audit::{JournalKey, JournalLimits, LocalJournal};
use xshield_core::domain::{CalibrationReadCapabilityId, EventId, SiteId, TenantId};

const EVENT: &str = "ev_01234567-89ab-7cde-8f00-000000000001";
const BOOT: &str = "018f2a3b-4c5d-7000-8000-000000000002";
const CAPABILITY: &str = "calcap_018f2a3b-4c5d-7000-8000-000000000003";

fn event() -> Value {
    let trace_id = CAPABILITY.strip_prefix("calcap_").unwrap().replace('-', "");
    let event_span = EVENT.strip_prefix("ev_").unwrap().replace('-', "");
    json!({
        "schema_version": 3, "event_id": EVENT, "event_type": "calibration.evidence_read",
        "tenant_id": "tenant_demo", "site_id": "site_demo", "request_id": null,
        "trace_id": trace_id, "span_id": &event_span[..16],
        "producer_id": "calibration-evidence-reader", "producer_boot_id": BOOT,
        "producer_seq": 1, "request_seq": 1,
        "occurred_at": "2026-09-21T00:00:00.123Z", "observed_at": "2026-09-21T00:00:00.123Z",
        "policy_revision": "calibration-v1", "example_only": false,
        "evidence_refs": [], "cause_event_ids": [],
        "payload": {
            "stage": "calibration_evidence_read", "outcome": "PASS",
            "reason_code": "CALIBRATION_EVIDENCE_READ_RELEASED",
            "capability_id": CAPABILITY, "bytes_released": 17
        },
        "sensitivity": "RESTRICTED",
        "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
    })
}

fn index(value: &Value) -> Result<IndexRow, PublishError> {
    IndexRow::parse(
        &serde_json::to_vec(value).map_err(|_| PublishError::InvalidEvent)?,
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

fn index_bytes(bytes: &[u8]) -> Result<IndexRow, PublishError> {
    IndexRow::parse(
        bytes,
        &EventId::parse(EVENT).map_err(|_| PublishError::InvalidEvent)?,
        1,
        BOOT,
        "0".repeat(64),
        TimeDelta::days(30),
    )
}

fn rejected(value: &Value, scenario: &str) {
    assert!(
        matches!(
            index(value),
            Err(PublishError::InvalidEvent
                | PublishError::Json(_)
                | PublishError::UnsupportedEventType)
        ),
        "accepted {scenario}"
    );
}

#[test]
fn successful_plaintext_release_is_a_restricted_nonbusiness_fact() {
    let value = event();
    let row = index(&value).unwrap();
    assert_eq!(row.event_type, "calibration.evidence_read");
    assert_eq!(row.stage, "calibration_evidence_read");
    assert_eq!(row.outcome, "PASS");
    assert_eq!(row.reason_code, "CALIBRATION_EVIDENCE_READ_RELEASED");
    assert_eq!(row.proof_kind, "deterministic");
    assert_eq!(row.confidence, None);
    assert_eq!(row.confidence_status, "not_applicable");
    assert_eq!(row.sensitivity, "RESTRICTED");
    assert!(row.request_id.is_empty());
    assert!(row.evidence_refs.is_empty());
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
}

#[test]
fn reader_journal_fact_is_rejected_by_the_outbox_ingest_path() {
    let value = event();
    assert!(matches!(
        IndexRow::parse_outbox(
            &serde_json::to_vec(&value).unwrap(),
            &EventId::parse(EVENT).unwrap(),
            1,
            BOOT,
            "0".repeat(64),
            TimeDelta::days(30),
        ),
        Err(PublishError::UnsupportedEventType)
    ));
}

#[test]
fn denied_and_dependency_failed_reads_do_not_claim_plaintext_bytes() {
    for (outcome, reason) in [
        ("DENY", "CALIBRATION_EVIDENCE_READ_NOT_AUTHORIZED"),
        (
            "ERROR",
            "CALIBRATION_EVIDENCE_READ_AUTHORIZATION_UNAVAILABLE",
        ),
        ("ERROR", "CALIBRATION_EVIDENCE_READ_CAPACITY_UNAVAILABLE"),
        ("ERROR", "CALIBRATION_EVIDENCE_READ_INTEGRITY_FAILED"),
        ("ERROR", "CALIBRATION_EVIDENCE_READ_VAULT_UNAVAILABLE"),
        ("ERROR", "CALIBRATION_EVIDENCE_READ_CANCELLED"),
    ] {
        let mut value = event();
        value["payload"]["outcome"] = outcome.into();
        value["payload"]["reason_code"] = reason.into();
        value["payload"]
            .as_object_mut()
            .unwrap()
            .remove("bytes_released");
        let row = index(&value).unwrap();
        assert_eq!(row.outcome, outcome);
        assert_eq!(row.reason_code, reason);
        assert_eq!(row.is_terminal, 0);
    }
}

#[test]
fn contract_rejects_public_source_and_lease_identifiers() {
    let value = event();
    for (field, content) in [
        (
            "artifact_id",
            json!("artifact_018f2a3b-4c5d-7000-8000-000000000004"),
        ),
        ("role", json!("model_call_record")),
        ("sample_index", json!(0)),
        (
            "lease_id",
            json!("callease_018f2a3b-4c5d-7000-8000-000000000005"),
        ),
        ("lease_token", json!("opaque")),
        ("content", json!("plaintext")),
    ] {
        let mut invalid = value.clone();
        invalid["payload"][field] = content;
        rejected(&invalid, field);
    }
    for (field, content) in [
        (
            "evidence_refs",
            json!(["artifact_018f2a3b-4c5d-7000-8000-000000000004"]),
        ),
        (
            "cause_event_ids",
            json!(["ev_018f2a3b-4c5d-7000-8000-000000000005"]),
        ),
    ] {
        let mut invalid = value.clone();
        invalid[field] = content;
        rejected(&invalid, field);
    }
}

#[test]
fn identity_timing_and_outcome_bindings_are_exact() {
    let value = event();
    for (field, content) in [
        ("event_type", json!("calibration.read_capability.issued")),
        ("producer_id", json!("calibration-evaluator")),
        (
            "producer_boot_id",
            json!("018f2a3b-4c5d-6cde-8000-000000000002"),
        ),
        (
            "request_id",
            json!("req_018f2a3b-4c5d-7000-8000-000000000006"),
        ),
        ("request_seq", json!(2)),
        ("policy_revision", json!("calibration-v2")),
        ("sensitivity", json!("INTERNAL")),
        ("trace_id", json!("0".repeat(32))),
        ("span_id", json!("0".repeat(16))),
        ("observed_at", json!("2026-09-21T00:00:00.124Z")),
        ("occurred_at", json!("2026-09-21T00:00:00Z")),
    ] {
        let mut invalid = value.clone();
        invalid[field] = content;
        rejected(&invalid, field);
    }
    for (outcome, reason, bytes) in [
        ("PASS", "CALIBRATION_EVIDENCE_READ_RELEASED", Value::Null),
        (
            "PASS",
            "CALIBRATION_EVIDENCE_READ_NOT_AUTHORIZED",
            json!(17),
        ),
        ("DENY", "CALIBRATION_EVIDENCE_READ_RELEASED", Value::Null),
        (
            "DENY",
            "CALIBRATION_EVIDENCE_READ_NOT_AUTHORIZED",
            json!(17),
        ),
        (
            "ERROR",
            "CALIBRATION_EVIDENCE_READ_AUTHORIZATION_UNAVAILABLE",
            json!(17),
        ),
        ("ERROR", "CALIBRATION_EVIDENCE_READ_CORRUPT", Value::Null),
    ] {
        let mut invalid = value.clone();
        invalid["payload"]["outcome"] = outcome.into();
        invalid["payload"]["reason_code"] = reason.into();
        match bytes {
            Value::Null => {
                invalid["payload"]
                    .as_object_mut()
                    .unwrap()
                    .remove("bytes_released");
            }
            bytes => invalid["payload"]["bytes_released"] = bytes,
        }
        rejected(&invalid, reason);
    }
    for bytes in [json!(0), json!(512 * 1024 * 1024 + 1), json!(-1)] {
        let mut invalid = value.clone();
        invalid["payload"]["bytes_released"] = bytes;
        rejected(&invalid, "invalid released bytes");
    }
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
                index(&missing).is_ok(),
                optional_hash,
                "missing {path}/{field}"
            );
        }
        let mut unknown = original.clone();
        unknown.pointer_mut(path).unwrap()["extra"] = Value::Null;
        rejected(&unknown, "unknown field");
    }
    let serialized = serde_json::to_string(&original).unwrap();
    for (needle, duplicate) in [
        (
            r#""capability_id":"calcap_018f2a3b-4c5d-7000-8000-000000000003""#,
            r#""capability_id":"calcap_018f2a3b-4c5d-7000-8000-000000000099","capability_id":"calcap_018f2a3b-4c5d-7000-8000-000000000003""#,
        ),
        (
            r#""producer_seq":1"#,
            r#""producer_seq":2,"producer_seq":1"#,
        ),
    ] {
        assert!(index_bytes(serialized.replace(needle, duplicate).as_bytes()).is_err());
    }
}

#[test]
fn helper_freezes_and_durably_acknowledges_the_pre_release_event() {
    let directory =
        std::env::temp_dir().join(format!("xshield-calibration-audit-{}", Uuid::now_v7()));
    let limits = JournalLimits::new(1024 * 1024, 512 * 1024, 512 * 1024).unwrap();
    let (mut journal, _) = LocalJournal::open(
        &directory,
        "journal-key-r1",
        JournalKey::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap(),
        limits,
    )
    .unwrap();
    let event = CalibrationEvidenceReadAuditEvent::prepare(
        &journal,
        &TenantId::parse("tenant_demo").unwrap(),
        &SiteId::parse("site_demo").unwrap(),
        &CalibrationReadCapabilityId::parse(CAPABILITY).unwrap(),
        CalibrationEvidenceReadOutcome::Released { bytes_released: 17 },
    )
    .unwrap();
    let row = IndexRow::parse(
        &event.bytes,
        event.event_id(),
        1,
        &journal.producer_boot_id(),
        "0".repeat(64),
        TimeDelta::days(30),
    )
    .unwrap();
    assert_eq!(row.event_type, "calibration.evidence_read");
    assert_eq!(row.outcome, "PASS");
    let receipt = event.append(&mut journal).unwrap();
    assert_eq!(receipt.event_id, *event.event_id());
    assert_eq!(receipt.producer_sequence, 1);
    assert!(matches!(
        CalibrationEvidenceReadAuditEvent::prepare(
            &journal,
            &TenantId::parse("tenant_demo").unwrap(),
            &SiteId::parse("site_demo").unwrap(),
            &CalibrationReadCapabilityId::parse(CAPABILITY).unwrap(),
            CalibrationEvidenceReadOutcome::Released { bytes_released: 0 },
        ),
        Err(super::CalibrationAuditBuildError::ReleasedBytesOutOfRange)
    ));
    drop(journal);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn helper_rejects_an_event_when_its_frozen_sequence_is_stale() {
    let directory = std::env::temp_dir().join(format!(
        "xshield-calibration-audit-stale-{}",
        Uuid::now_v7()
    ));
    let limits = JournalLimits::new(1024 * 1024, 512 * 1024, 512 * 1024).unwrap();
    let (mut journal, _) = LocalJournal::open(
        &directory,
        "journal-key-r1",
        JournalKey::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap(),
        limits,
    )
    .unwrap();
    let tenant_id = TenantId::parse("tenant_demo").unwrap();
    let site_id = SiteId::parse("site_demo").unwrap();
    let capability_id = CalibrationReadCapabilityId::parse(CAPABILITY).unwrap();
    let stale = CalibrationEvidenceReadAuditEvent::prepare(
        &journal,
        &tenant_id,
        &site_id,
        &capability_id,
        CalibrationEvidenceReadOutcome::Released { bytes_released: 17 },
    )
    .unwrap();
    let current = CalibrationEvidenceReadAuditEvent::prepare(
        &journal,
        &tenant_id,
        &site_id,
        &capability_id,
        CalibrationEvidenceReadOutcome::Released { bytes_released: 18 },
    )
    .unwrap();
    current.append(&mut journal).unwrap();

    assert!(matches!(
        stale.append(&mut journal),
        Err(xshield_audit::JournalError::InvalidEvent)
    ));
    assert_eq!(journal.next_sequence(), Some(2));

    drop(journal);
    fs::remove_dir_all(directory).unwrap();
}
