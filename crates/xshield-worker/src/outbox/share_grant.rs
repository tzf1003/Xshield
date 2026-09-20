//! Strict share issuance facts; indexed history carries no authorization.

use super::{PayloadSummary, PublishError, WireEvent, valid_lower_hex};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use xshield_core::domain::{
    AuthBindingId, GrantId, OperationId, ResourceType, ShareGrantId, ShareIssuanceRuleId,
    ViewProfile,
};

pub(super) const EVENT_TYPES: &[&str] = &["share.issued"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareGrantIssued {
    stage: String,
    outcome: String,
    reason_code: String,
    share_id: String,
    issuer_binding_id: String,
    issuer_auth_epoch: i64,
    issuer_grant_id: String,
    issuance_rule_id: String,
    issuer_operation_id: String,
    issuer_view_profile: String,
    resource_type: String,
    resource_key_hmac: String,
    operation_id: String,
    view_profile: String,
    method: String,
    use_policy: String,
    issued_at_unix: i64,
    expires_at_unix: i64,
}

pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: ShareGrantIssued = serde_json::from_str(event.payload.get())?;
    if event.producer_id != "gateway-share-grant"
        || event.producer_boot_id != event.event_id
        || event.request_id.is_none()
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.sensitivity != "SENSITIVE"
        || !event.evidence_refs.is_empty()
        || !event.cause_event_ids.is_empty()
        || value.stage != "share_grant"
        || value.outcome != "PASS"
        || value.reason_code != "SHARE_ISSUED"
        || ShareGrantId::parse(value.share_id.as_str()).is_err()
        || value.share_id.strip_prefix("share_") != event.event_id.strip_prefix("ev_")
        || AuthBindingId::parse(value.issuer_binding_id).is_err()
        || value.issuer_auth_epoch <= 0
        || GrantId::parse(value.issuer_grant_id).is_err()
        || ShareIssuanceRuleId::parse(value.issuance_rule_id).is_err()
        || OperationId::parse(value.issuer_operation_id).is_err()
        || ViewProfile::parse(value.issuer_view_profile).is_err()
        || ResourceType::parse(value.resource_type).is_err()
        || !valid_lower_hex(&value.resource_key_hmac, 64)
        || OperationId::parse(value.operation_id.as_str()).is_err()
        || ViewProfile::parse(value.view_profile).is_err()
        || value.method != "GET"
        || value.use_policy != "reusable_read"
        || value.issued_at_unix < 0
        || !value
            .expires_at_unix
            .checked_sub(value.issued_at_unix)
            .is_some_and(|ttl| (1..=86_400).contains(&ttl))
    {
        return Err(PublishError::InvalidEvent);
    }
    // A share has its own stable event/boot identity even when a request issues
    // several shares. Frozen whole seconds preserve the original transaction
    // time on retries; neither sequence establishes order with journal events.
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
        method: value.method,
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

    /// Canonical producer-shaped fixture reused by delivery integration tests.
    pub(crate) fn event() -> Value {
        let mut event = base_event("case.created");
        event["event_type"] = json!("share.issued");
        event["producer_id"] = json!("gateway-share-grant");
        event["producer_boot_id"] = event["event_id"].clone();
        event["occurred_at"] = json!("2026-09-19T00:00:00Z");
        event["observed_at"] = event["occurred_at"].clone();
        event["sensitivity"] = json!("SENSITIVE");
        event["payload"] = json!({
            "stage": "share_grant", "outcome": "PASS", "reason_code": "SHARE_ISSUED",
            "share_id": "share_018f2a3b-4c5d-7000-8000-000000000001",
            "issuer_binding_id": "auth_018f2a3b-4c5d-7000-8000-000000000102",
            "issuer_auth_epoch": 1,
            "issuer_grant_id": "grant_018f2a3b-4c5d-7000-8000-000000000103",
            "issuance_rule_id": "record-share-r1",
            "issuer_operation_id": "record.read", "issuer_view_profile": "private",
            "resource_type": "record", "resource_key_hmac": "b".repeat(64),
            "operation_id": "record.share.read", "view_profile": "public",
            "method": "GET", "use_policy": "reusable_read",
            "issued_at_unix": ISSUED_AT, "expires_at_unix": ISSUED_AT + 3_600
        });
        event
    }

    fn row_bytes(bytes: &[u8]) -> Result<IndexRow, PublishError> {
        IndexRow::parse_outbox(
            bytes,
            &EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
            1,
            "ev_018f2a3b-4c5d-7000-8000-000000000001",
            "0".repeat(64),
            chrono::TimeDelta::days(30),
        )
    }

    fn row(value: &Value) -> Result<IndexRow, PublishError> {
        row_bytes(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn accepts_canonical_share_summary_and_boundary_ttl() {
        let row = row(&event()).unwrap();
        assert_eq!(row.stage, "share_grant");
        assert_eq!(row.outcome, "PASS");
        assert_eq!(row.reason_code, "SHARE_ISSUED");
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.method, "GET");
        assert_eq!(row.operation_id, "record.share.read");
        assert_eq!(row.is_terminal, 0);
        assert_eq!(row.http_status, None);
        assert!(row.origin_state.is_empty());
        for ttl in [1, 86_400] {
            let mut value = event();
            value["payload"]["expires_at_unix"] = json!(ISSUED_AT + ttl);
            value["payload"]["issuer_auth_epoch"] = json!(i64::MAX);
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
            "credential",
            "token",
            "fingerprint",
            "issuance_key",
            "proof_kind",
            "confidence",
        ] {
            let mut invalid = original.clone();
            invalid["payload"][field] = json!("forbidden");
            assert!(row(&invalid).is_err(), "accepted {field}");
        }
        for (old, new) in [
            (r#""method":"GET""#, r#""method":"POST","method":"GET""#),
            (
                r#""producer_seq":1"#,
                r#""producer_seq":2,"producer_seq":1"#,
            ),
        ] {
            let serialized = serde_json::to_string(&original).unwrap();
            assert!(row_bytes(serialized.replace(old, new).as_bytes()).is_err());
        }
        assert!(
            IndexRow::parse(
                &serde_json::to_vec(&original).unwrap(),
                &EventId::parse(original["event_id"].as_str().unwrap()).unwrap(),
                1,
                original["producer_boot_id"].as_str().unwrap(),
                "0".repeat(64),
                chrono::TimeDelta::days(30),
            )
            .is_err()
        );
        let sparse = json!({"schema_version": 3, "event_type": "share.issued", "share_id": original["payload"]["share_id"]});
        assert!(row(&sparse).is_err());
    }

    #[test]
    fn rejects_wrong_source_ids_bindings_and_ranges() {
        for (pointer, value) in [
            ("/producer_id", json!("gateway-response-grant")),
            ("/event_type", json!("share.issued.spoofed")),
            (
                "/producer_boot_id",
                json!("ev_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            ("/producer_boot_id", event()["request_id"].clone()),
            ("/request_id", Value::Null),
            ("/request_id", event()["event_id"].clone()),
            ("/producer_seq", json!(2)),
            ("/request_seq", json!(2)),
            ("/sensitivity", json!("INTERNAL")),
            ("/example_only", json!(true)),
            (
                "/evidence_refs",
                json!(["artifact_018f2a3b-4c5d-7000-8000-000000000001"]),
            ),
            (
                "/cause_event_ids",
                json!(["ev_018f2a3b-4c5d-7000-8000-000000000002"]),
            ),
            ("/integrity/state", json!("sealed")),
            ("/integrity/event_hash", json!("a".repeat(64))),
            ("/integrity/previous_hash", json!("a".repeat(64))),
            ("/payload/stage", json!("response_grant")),
            ("/payload/outcome", json!("DENY")),
            ("/payload/reason_code", json!("GRANT_ISSUED")),
            (
                "/payload/share_id",
                json!("share_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            (
                "/payload/share_id",
                json!("share_018f2a3b-4c5d-4000-8000-000000000001"),
            ),
            (
                "/payload/issuer_binding_id",
                json!("grant_018f2a3b-4c5d-7000-8000-000000000102"),
            ),
            (
                "/payload/issuer_grant_id",
                json!("auth_018f2a3b-4c5d-7000-8000-000000000103"),
            ),
            ("/payload/resource_key_hmac", json!("B".repeat(64))),
            ("/payload/resource_key_hmac", json!("b".repeat(63))),
            ("/payload/issuer_auth_epoch", json!(0)),
            ("/payload/issuer_auth_epoch", json!(-1)),
            ("/payload/issuer_auth_epoch", json!(i64::MAX as u64 + 1)),
            ("/payload/method", json!("POST")),
            ("/payload/use_policy", json!("single_use")),
        ] {
            let mut invalid = event();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(row(&invalid).is_err(), "accepted {pointer}");
        }
        for field in [
            "issuance_rule_id",
            "issuer_operation_id",
            "issuer_view_profile",
            "resource_type",
            "operation_id",
            "view_profile",
        ] {
            for value in [
                String::new(),
                "a".repeat(129),
                "é".to_owned(),
                "bad\n".to_owned(),
            ] {
                let mut invalid = event();
                invalid["payload"][field] = json!(value);
                assert!(row(&invalid).is_err(), "accepted {field}");
            }
            let mut valid = event();
            valid["payload"][field] = json!("a".repeat(128));
            assert!(row(&valid).is_ok());
        }
        for field in ["event_hash", "previous_hash"] {
            let mut valid = event();
            valid["integrity"].as_object_mut().unwrap().remove(field);
            assert!(row(&valid).is_ok());
        }
    }

    #[test]
    fn enforces_event_boot_identity_independently_of_claim_metadata() {
        for (field, value) in [
            ("producer_boot_id", event()["request_id"].clone()),
            (
                "producer_boot_id",
                json!("ev_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            ("producer_seq", json!(2)),
            ("request_seq", json!(2)),
        ] {
            let mut invalid = event();
            invalid[field] = value;
            let wire: WireEvent =
                serde_json::from_str(&serde_json::to_string(&invalid).unwrap()).unwrap();
            assert!(super::parse(&wire).is_err(), "accepted {field}");
        }
        // Another share in the same request has an independent event/boot;
        // publication does not require other rows or a request-wide sequence.
        let mut another = event();
        another["event_id"] = json!("ev_018f2a3b-4c5d-7000-8000-000000000099");
        another["producer_boot_id"] = another["event_id"].clone();
        another["payload"]["share_id"] = json!("share_018f2a3b-4c5d-7000-8000-000000000099");
        let wire: WireEvent =
            serde_json::from_str(&serde_json::to_string(&another).unwrap()).unwrap();
        assert!(super::parse(&wire).is_ok());
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
