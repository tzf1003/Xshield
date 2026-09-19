//! Producer-shaped identity events and their trust-boundary counterexamples.

use super::*;
use crate::IndexRow;
use serde_json::{Value, json};
use xshield_core::domain::EventId;

pub(crate) fn event(event_type: &str) -> Value {
    let mut event = crate::outbox::tests::event("case.created");
    event["event_type"] = json!(event_type);
    event["producer_id"] = json!("gateway-identity");
    event["policy_revision"] = json!("policy-r1");
    event["sensitivity"] = json!("SENSITIVE");
    event["payload"] = json!({
        "stage": "identity_lifecycle", "outcome": "PASS",
        "binding_id": "auth_018f2a3b-4c5d-7000-8000-000000000011",
        "auth_epoch": 1, "credential_generation": 1,
        "reason_code": match event_type {
            "session.created" => "SESSION_CREATED",
            "binding.created" => "BINDING_CREATED",
            "identity.refreshed" => "IDENTITY_REFRESHED",
            "epoch.changed" => "IDENTITY_CONTEXT_CHANGED",
            _ => unreachable!(),
        },
    });
    if event_type == "session.created" {
        event["payload"]["status"] = json!("anonymous");
        event["payload"]["auth_epoch"] = json!(0);
        event["payload"]["credential_generation"] = json!(0);
    } else {
        event["payload"]["principal_ref"] = json!("principal-new");
        event["payload"]["authorization_context_ref"] = json!("context-new");
    }
    if matches!(event_type, "identity.refreshed" | "epoch.changed") {
        event["payload"]["previous_credential_generation"] = json!(1);
        event["payload"]["credential_generation"] = json!(2);
        event["payload"]["previous_credentials"] =
            json!([{"kind": "bearer", "fingerprint": "a".repeat(64)}]);
        event["payload"]["credentials"] =
            json!([{"kind": "bearer", "fingerprint": "b".repeat(64)}]);
        event["payload"]["rotation_reason"] = json!(if event_type == "identity.refreshed" {
            "same_context_refresh"
        } else {
            "account_context_changed"
        });
    }
    if event_type == "epoch.changed" {
        event["payload"]["previous_auth_epoch"] = json!(1);
        event["payload"]["auth_epoch"] = json!(2);
        event["payload"]["previous_principal_ref"] = json!("principal-old");
        event["payload"]["previous_authorization_context_ref"] = json!("context-old");
    }
    event
}

fn row(value: &Value) -> Result<IndexRow, PublishError> {
    IndexRow::parse_outbox(
        &serde_json::to_vec(value).unwrap(),
        &EventId::parse(value["event_id"].as_str().unwrap()).unwrap(),
        1,
        value["request_id"].as_str().unwrap_or_default(),
        "0".repeat(64),
        chrono::TimeDelta::days(30),
    )
}

#[test]
fn identity_transactions_have_deterministic_nonterminal_summaries() {
    for event_type in EVENT_TYPES {
        let event = event(event_type);
        let row = row(&event).unwrap();
        assert_eq!(row.stage, "identity_lifecycle");
        assert_eq!(row.outcome, "PASS");
        assert_eq!(row.reason_code, event["payload"]["reason_code"]);
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.is_terminal, 0);
        assert_eq!(row.http_status, None);
        assert!(row.origin_state.is_empty());
        assert_eq!(row.sensitivity, "SENSITIVE");
        assert_eq!(
            serde_json::from_str::<Value>(&row.payload_json).unwrap(),
            event["payload"]
        );
        assert!(
            IndexRow::parse(
                &serde_json::to_vec(&event).unwrap(),
                &EventId::parse(event["event_id"].as_str().unwrap()).unwrap(),
                1,
                event["request_id"].as_str().unwrap(),
                "0".repeat(64),
                chrono::TimeDelta::days(30),
            )
            .is_err()
        );
    }
}

#[test]
fn identity_payloads_reject_missing_unknown_duplicate_and_sparse_fields() {
    for event_type in EVENT_TYPES {
        let original = event(event_type);
        for field in original["payload"].as_object().unwrap().keys() {
            let mut invalid = original.clone();
            invalid["payload"].as_object_mut().unwrap().remove(field);
            assert!(row(&invalid).is_err(), "{event_type} missing {field}");
        }
        for field in ["extra", "cookie", "bearer", "confidence"] {
            let mut invalid = original.clone();
            invalid["payload"][field] = Value::Null;
            assert!(row(&invalid).is_err(), "{event_type} accepted {field}");
        }
        let mut sparse = original["payload"].clone();
        for field in ["schema_version", "event_type", "event_id", "request_id"] {
            sparse[field] = original[field].clone();
        }
        assert!(row(&sparse).is_err());
        let duplicate = serde_json::to_string(&original).unwrap().replace(
            r#""binding_id":"#,
            r#""binding_id":"auth_018f2a3b-4c5d-7000-8000-000000000012","binding_id":"#,
        );
        assert!(
            IndexRow::parse_outbox(
                duplicate.as_bytes(),
                &EventId::parse(original["event_id"].as_str().unwrap()).unwrap(),
                1,
                original["request_id"].as_str().unwrap(),
                "0".repeat(64),
                chrono::TimeDelta::days(30),
            )
            .is_err()
        );
    }
}

#[test]
fn identity_source_and_state_constraints_fail_closed() {
    for event_type in EVENT_TYPES {
        for (path, replacement) in [
            ("/producer_id", json!("xshield-control")),
            (
                "/producer_boot_id",
                json!("req_018f2a3b-4c5d-7000-8000-000000000012"),
            ),
            ("/producer_seq", json!(2)),
            ("/request_seq", json!(2)),
            ("/request_id", Value::Null),
            ("/sensitivity", json!("INTERNAL")),
            (
                "/evidence_refs",
                json!(["artifact_018f2a3b-4c5d-7000-8000-000000000012"]),
            ),
            (
                "/cause_event_ids",
                json!(["ev_018f2a3b-4c5d-7000-8000-000000000012"]),
            ),
            (
                "/payload/binding_id",
                json!("req_018f2a3b-4c5d-7000-8000-000000000011"),
            ),
            ("/payload/stage", json!("identity")),
            ("/payload/outcome", json!("DENY")),
            ("/payload/reason_code", json!("AUTH_REQUIRED")),
            ("/payload/auth_epoch", json!(-1)),
            ("/payload/auth_epoch", json!(1.5)),
            ("/payload/auth_epoch", json!(u64::MAX)),
            ("/payload/credential_generation", json!(u64::MAX)),
        ] {
            let mut invalid = event(event_type);
            *invalid.pointer_mut(path).unwrap() = replacement;
            assert!(row(&invalid).is_err(), "{event_type} accepted {path}");
        }
        for field in ["auth_epoch", "credential_generation"] {
            let mut invalid = event(event_type);
            invalid["payload"][field] = json!(i32::from(event_type == &"session.created"));
            assert!(row(&invalid).is_err());
        }
    }
    for event_type in ["binding.created", "identity.refreshed", "epoch.changed"] {
        for field in ["principal_ref", "authorization_context_ref"] {
            for invalid_ref in [String::new(), "a".repeat(257), "bad\u{0085}ref".to_owned()] {
                let mut invalid = event(event_type);
                invalid["payload"][field] = json!(invalid_ref);
                assert!(row(&invalid).is_err());
            }
        }
    }
}

#[test]
fn identity_rotations_require_real_bounded_state_changes() {
    for event_type in ["identity.refreshed", "epoch.changed"] {
        for field in ["previous_credential_generation", "credential_generation"] {
            for invalid_value in [json!(0), json!(-1), json!(1.1), json!(4), json!(u64::MAX)] {
                let mut invalid = event(event_type);
                invalid["payload"][field] = invalid_value;
                assert!(row(&invalid).is_err());
            }
        }
        let mut reordered = event(event_type);
        let credentials = json!([
            {"kind":"bearer","fingerprint":"a".repeat(64)},
            {"kind":"cookie","fingerprint":"c".repeat(64)}
        ]);
        reordered["payload"]["previous_credentials"] = credentials.clone();
        reordered["payload"]["credentials"] = json!([credentials[1], credentials[0]]);
        assert!(row(&reordered).is_err());
        for field in ["previous_credentials", "credentials"] {
            for values in [
                json!([]),
                json!([{"kind":"bearer","fingerprint":"B".repeat(64)}]),
                json!([{"kind":"bearer","fingerprint":"a".repeat(63)}]),
                json!([{"kind":"unknown","fingerprint":"a".repeat(64)}]),
                json!([{"kind":"bearer","fingerprint":"a".repeat(64),"token":"raw"}]),
                json!([{"kind":"bearer","fingerprint":"a".repeat(64)}, {"kind":"bearer","fingerprint":"b".repeat(64)}]),
            ] {
                let mut invalid = event(event_type);
                invalid["payload"][field] = values;
                assert!(row(&invalid).is_err());
            }
        }
        let mut valid = event(event_type);
        valid["payload"]["previous_credential_generation"] = json!(i64::MAX - 1);
        valid["payload"]["credential_generation"] = json!(i64::MAX);
        assert!(row(&valid).is_ok());
        valid["payload"]["previous_credential_generation"] = json!(i64::MAX);
        valid["payload"]["credential_generation"] = json!((i64::MAX as u64) + 1);
        assert!(row(&valid).is_err());
    }
    let mut switched = event("epoch.changed");
    switched["payload"]["previous_principal_ref"] = switched["payload"]["principal_ref"].clone();
    assert!(row(&switched).is_ok()); // Same principal, new authorization context.
    switched["payload"]["previous_authorization_context_ref"] =
        switched["payload"]["authorization_context_ref"].clone();
    assert!(row(&switched).is_err());
    switched["payload"]["previous_principal_ref"] = json!("principal-old");
    assert!(row(&switched).is_ok()); // New principal, same authorization context.
    for value in [json!(0), json!(2), json!(u64::MAX)] {
        switched["payload"]["previous_auth_epoch"] = value;
        assert!(row(&switched).is_err());
    }
}
