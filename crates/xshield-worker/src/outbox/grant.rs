//! Strict generic resource-grant issuance facts; indexed history is not authorization.

use super::{PayloadSummary, PublishError, WireEvent, valid_lower_hex, valid_prefixed_v7};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use xshield_core::domain::{
    ActionRef, AuthBindingId, GrantId, OperationId, PolicyRevision, ResourceType, ViewProfile,
};

pub(super) const EVENT_TYPES: &[&str] = &["grant.issued"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantIssued {
    stage: String,
    outcome: String,
    reason_code: String,
    grant_id: String,
    binding_id: String,
    auth_epoch: i64,
    action_ref: String,
    source_request_id: String,
    resource_type: String,
    resource_key_hmac: String,
    operation_id: String,
    view_profile: String,
    policy_revision: String,
    constraints_digest: String,
    issued_at_unix: i64,
    expires_at_unix: i64,
}

pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: GrantIssued = serde_json::from_str(event.payload.get())?;
    if event.producer_id != "gateway-grant"
        || event.producer_boot_id != event.event_id
        || event.request_id.is_none()
        || event.request_id.as_deref() != Some(value.source_request_id.as_str())
        || valid_prefixed_v7(&value.source_request_id, "req_").is_err()
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.sensitivity != "SENSITIVE"
        || !event.evidence_refs.is_empty()
        || !event.cause_event_ids.is_empty()
        || value.stage != "grant"
        || value.outcome != "PASS"
        || value.reason_code != "GRANT_ISSUED"
        || GrantId::parse(value.grant_id).is_err()
        || AuthBindingId::parse(value.binding_id).is_err()
        || value.auth_epoch <= 0
        || ActionRef::parse(value.action_ref).is_err()
        || ResourceType::parse(value.resource_type).is_err()
        || !valid_lower_hex(&value.resource_key_hmac, 64)
        || OperationId::parse(value.operation_id.as_str()).is_err()
        || ViewProfile::parse(value.view_profile).is_err()
        || PolicyRevision::parse(value.policy_revision.as_str()).is_err()
        || value.policy_revision != event.policy_revision
        || !valid_lower_hex(&value.constraints_digest, 64)
        || value.issued_at_unix < 0
        || !value
            .expires_at_unix
            .checked_sub(value.issued_at_unix)
            .is_some_and(|ttl| (1..=86_400).contains(&ttl))
    {
        return Err(PublishError::InvalidEvent);
    }
    let issued_at = DateTime::<Utc>::from_timestamp(value.issued_at_unix, 0)
        .ok_or(PublishError::InvalidEvent)?
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    if issued_at.len() != 20 || event.occurred_at != issued_at || event.observed_at != issued_at {
        return Err(PublishError::InvalidEvent);
    }
    Ok(PayloadSummary {
        stage: value.stage,
        outcome: value.outcome,
        reason_code: value.reason_code,
        proof_kind: "deterministic".to_owned(),
        confidence_status: "not_applicable".to_owned(),
        operation_id: value.operation_id,
        ..PayloadSummary::default()
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{IndexRow, outbox::tests::event as base_event};
    use serde_json::{Value, json};
    use xshield_core::domain::EventId;

    const ISSUED_AT: i64 = 1_789_776_000;
    const EVENT_ID: &str = "ev_018f2a3b-4c5d-7000-8000-000000000001";

    /// Producer-shaped fixture shared with scoped outbox and `ClickHouse` tests.
    pub(crate) fn event() -> Value {
        let mut event = base_event("case.created");
        event["event_type"] = json!("grant.issued");
        event["producer_id"] = json!("gateway-grant");
        event["producer_boot_id"] = event["event_id"].clone();
        event["request_seq"] = json!(1);
        event["producer_seq"] = json!(1);
        event["occurred_at"] = json!("2026-09-19T00:00:00Z");
        event["observed_at"] = event["occurred_at"].clone();
        event["policy_revision"] = json!("policy-r1");
        event["sensitivity"] = json!("SENSITIVE");
        event["evidence_refs"] = json!([]);
        event["cause_event_ids"] = json!([]);
        event["payload"] = json!({
            "stage": "grant", "outcome": "PASS", "reason_code": "GRANT_ISSUED",
            "grant_id": "grant_018f2a3b-4c5d-7000-8000-000000000001",
            "binding_id": "auth_018f2a3b-4c5d-7000-8000-000000000002",
            "auth_epoch": 4,
            "action_ref": "action_order_read",
            "source_request_id": event["request_id"].clone(),
            "resource_type": "order", "resource_key_hmac": "b".repeat(64),
            "operation_id": "orders.read", "view_profile": "customer_detail",
            "policy_revision": "policy-r1", "constraints_digest": "c".repeat(64),
            "issued_at_unix": ISSUED_AT, "expires_at_unix": ISSUED_AT + 3_600
        });
        event
    }

    fn row(value: &Value) -> Result<IndexRow, PublishError> {
        row_bytes(&serde_json::to_vec(value).unwrap())
    }

    fn row_bytes(bytes: &[u8]) -> Result<IndexRow, PublishError> {
        IndexRow::parse_outbox(
            bytes,
            &EventId::parse(EVENT_ID).unwrap(),
            1,
            EVENT_ID,
            "0".repeat(64),
            chrono::TimeDelta::days(30),
        )
    }

    #[test]
    fn accepts_canonical_grant_summary_and_boundaries() {
        let row = row(&event()).unwrap();
        assert_eq!(row.stage, "grant");
        assert_eq!(row.outcome, "PASS");
        assert_eq!(row.reason_code, "GRANT_ISSUED");
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.operation_id, "orders.read");
        assert!(row.method.is_empty());
        assert_eq!(row.is_terminal, 0);
        assert_eq!(row.http_status, None);
        assert!(row.origin_state.is_empty());
        for ttl in [1, 86_400] {
            let mut value = event();
            value["payload"]["expires_at_unix"] = json!(ISSUED_AT + ttl);
            value["payload"]["auth_epoch"] = json!(i64::MAX);
            assert!(self::row(&value).is_ok());
        }
        for field in ["event_hash", "previous_hash"] {
            let mut value = event();
            value["integrity"].as_object_mut().unwrap().remove(field);
            assert!(self::row(&value).is_ok());
        }
    }

    #[test]
    fn rejects_missing_unknown_duplicate_and_journal_source() {
        let original = event();
        for payload in [false, true] {
            let object = if payload {
                &original["payload"]
            } else {
                &original
            };
            for field in object.as_object().unwrap().keys() {
                let mut missing = original.clone();
                let object = if payload {
                    &mut missing["payload"]
                } else {
                    &mut missing
                };
                object.as_object_mut().unwrap().remove(field);
                assert!(row(&missing).is_err(), "missing {payload}/{field}");
            }
        }
        for field in [
            "unknown",
            "constraints",
            "issuance_key",
            "credential",
            "token",
            "fingerprint",
            "proof_kind",
            "confidence",
        ] {
            let mut invalid = original.clone();
            invalid["payload"][field] = json!("forbidden");
            assert!(row(&invalid).is_err(), "accepted {field}");
        }
        for field in ["extra", "connection_id", "agent_run_id"] {
            let mut invalid = original.clone();
            invalid[field] = Value::Null;
            assert!(row(&invalid).is_err(), "accepted {field}");
        }
        let serialized = serde_json::to_string(&original).unwrap();
        for (old, new) in [
            (r#""auth_epoch":4"#, r#""auth_epoch":0,"auth_epoch":4"#),
            (
                r#""producer_seq":1"#,
                r#""producer_seq":2,"producer_seq":1"#,
            ),
            (
                r#""state":"pending""#,
                r#""state":"sealed","state":"pending""#,
            ),
        ] {
            assert!(serialized.contains(old));
            assert!(row_bytes(serialized.replace(old, new).as_bytes()).is_err());
        }
        assert!(
            IndexRow::parse(
                serialized.as_bytes(),
                &EventId::parse(EVENT_ID).unwrap(),
                1,
                EVENT_ID,
                "0".repeat(64),
                chrono::TimeDelta::days(30),
            )
            .is_err()
        );
        let sparse = json!({"schema_version": 3, "event_type": "grant.issued",
            "event_id": EVENT_ID, "grant_id": original["payload"]["grant_id"]});
        assert!(row(&sparse).is_err());
    }

    #[test]
    fn rejects_wrong_source_and_cross_field_drift() {
        let original = event();
        for (pointer, value) in [
            ("/producer_id", json!("gateway-response-grant")),
            ("/event_type", json!("grant.issued.spoofed")),
            ("/producer_boot_id", original["request_id"].clone()),
            (
                "/producer_boot_id",
                json!("ev_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            ("/request_id", Value::Null),
            (
                "/request_id",
                json!("req_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            (
                "/payload/source_request_id",
                json!("req_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            ("/payload/policy_revision", json!("policy-r2")),
            ("/policy_revision", json!("policy-r2")),
            ("/sensitivity", json!("INTERNAL")),
            ("/example_only", json!(true)),
            (
                "/evidence_refs",
                json!(["artifact_018f2a3b-4c5d-7000-8000-000000000001"]),
            ),
            ("/cause_event_ids", json!([EVENT_ID])),
            ("/integrity/state", json!("sealed")),
            ("/integrity/event_hash", json!("a".repeat(64))),
            ("/integrity/previous_hash", json!("a".repeat(64))),
            ("/payload/stage", json!("response_grant")),
            ("/payload/outcome", json!("DENY")),
            ("/payload/reason_code", json!("SHARE_ISSUED")),
            ("/payload/resource_key_hmac", json!("B".repeat(64))),
            ("/payload/resource_key_hmac", json!("b".repeat(63))),
            (
                "/payload/resource_key_hmac",
                json!(format!("{}\n", "b".repeat(64))),
            ),
            ("/payload/constraints_digest", json!("C".repeat(64))),
            ("/payload/constraints_digest", json!("c".repeat(63))),
            (
                "/payload/constraints_digest",
                json!(format!("{}\n", "c".repeat(64))),
            ),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(row(&invalid).is_err(), "accepted {pointer}");
        }
    }

    #[test]
    fn enforces_identity_and_sequence_independently_of_claim_metadata() {
        for field in ["producer_seq", "request_seq"] {
            for value in [json!(0), json!(2), json!(1.5), json!(u64::MAX)] {
                let mut invalid = event();
                invalid[field] = value;
                assert!(row(&invalid).is_err(), "accepted {field}");
                if let Ok(wire) =
                    serde_json::from_str::<WireEvent>(&serde_json::to_string(&invalid).unwrap())
                {
                    assert!(super::parse(&wire).is_err(), "accepted independent {field}");
                }
            }
        }
        let mut another = event();
        another["event_id"] = json!("ev_018f2a3b-4c5d-7000-8000-000000000099");
        let wire: WireEvent =
            serde_json::from_str(&serde_json::to_string(&another).unwrap()).unwrap();
        assert!(super::parse(&wire).is_err());
        // A second grant in one request keeps its own event/boot identity.
        another["producer_boot_id"] = another["event_id"].clone();
        let wire: WireEvent =
            serde_json::from_str(&serde_json::to_string(&another).unwrap()).unwrap();
        assert!(super::parse(&wire).is_ok());
    }

    #[test]
    fn rejects_invalid_ids_epochs_and_scoped_names() {
        for pointer in [
            "/event_id",
            "/producer_boot_id",
            "/request_id",
            "/payload/grant_id",
            "/payload/binding_id",
            "/payload/source_request_id",
        ] {
            let original = event();
            let id = original.pointer(pointer).unwrap().as_str().unwrap();
            for invalid_id in [
                String::new(),
                format!("other_{}", id.split_once('_').unwrap().1),
                id.replace("-7000-", "-4000-"),
                id.replace("-8000-", "-0000-"),
                id.to_uppercase(),
                format!("{id}\n"),
            ] {
                let mut invalid = original.clone();
                *invalid.pointer_mut(pointer).unwrap() = json!(invalid_id);
                assert!(row(&invalid).is_err(), "accepted {pointer}");
            }
        }
        for value in [json!(0), json!(-1), json!(i64::MAX as u64 + 1), json!(1.5)] {
            let mut invalid = event();
            invalid["payload"]["auth_epoch"] = value;
            assert!(row(&invalid).is_err());
        }
        for pointer in [
            "/tenant_id",
            "/site_id",
            "/policy_revision",
            "/payload/action_ref",
            "/payload/resource_type",
            "/payload/operation_id",
            "/payload/view_profile",
            "/payload/policy_revision",
        ] {
            for name in [
                String::new(),
                "a".repeat(129),
                "é".to_owned(),
                "bad\n".to_owned(),
            ] {
                let mut invalid = event();
                *invalid.pointer_mut(pointer).unwrap() = json!(name);
                assert!(row(&invalid).is_err(), "accepted {pointer}");
            }
            let mut valid = event();
            *valid.pointer_mut(pointer).unwrap() = json!("a".repeat(128));
            if pointer.ends_with("/policy_revision") {
                valid["policy_revision"] = json!("a".repeat(128));
                valid["payload"]["policy_revision"] = valid["policy_revision"].clone();
            }
            assert!(row(&valid).is_ok(), "rejected scoped name {pointer}");
        }
    }

    #[test]
    fn rejects_invalid_and_noncanonical_frozen_times() {
        for (issued, expires) in [
            (ISSUED_AT, ISSUED_AT),
            (ISSUED_AT, ISSUED_AT - 1),
            (ISSUED_AT, ISSUED_AT + 86_401),
            (-1, ISSUED_AT),
            (ISSUED_AT, i64::MIN),
            (i64::MAX - 1, i64::MAX),
            (253_402_300_800, 253_402_300_801),
        ] {
            let mut invalid = event();
            invalid["payload"]["issued_at_unix"] = json!(issued);
            invalid["payload"]["expires_at_unix"] = json!(expires);
            assert!(row(&invalid).is_err(), "accepted {issued}/{expires}");
        }
        for field in ["issued_at_unix", "expires_at_unix"] {
            for value in [json!(i64::MAX as u64 + 1), json!(1.5)] {
                let mut invalid = event();
                invalid["payload"][field] = value;
                assert!(row(&invalid).is_err());
            }
        }
        for field in ["occurred_at", "observed_at"] {
            for value in [
                "2026-09-19T00:00:00.0Z",
                "2026-09-19T02:00:00Z",
                "2026-09-19T00:00:00+00:00",
                "2026-09-19T08:00:00+08:00",
                "invalid",
            ] {
                let mut invalid = event();
                invalid[field] = json!(value);
                assert!(row(&invalid).is_err(), "accepted {field}/{value}");
            }
        }
        let mut epoch = event();
        epoch["occurred_at"] = json!("1970-01-01T00:00:00Z");
        epoch["observed_at"] = epoch["occurred_at"].clone();
        epoch["payload"]["issued_at_unix"] = json!(0);
        epoch["payload"]["expires_at_unix"] = json!(1);
        assert!(row(&epoch).is_ok());
    }
}
