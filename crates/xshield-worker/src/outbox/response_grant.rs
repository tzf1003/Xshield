//! Strict response-grant issuance facts; indexed history is not authorization.

use super::{PayloadSummary, PublishError, WireEvent, valid_lower_hex, valid_prefixed_v7};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use xshield_core::{
    domain::{
        ActionId, AuthBindingId, FieldName, GrantId, MappingRevision, OperationId, ResourceType,
        ResponseEvidenceId, ViewProfile,
    },
    provenance::RouteTemplate,
};

pub(super) const EVENT_TYPES: &[&str] = &["response_grant.issued"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseGrantIssued {
    stage: String,
    outcome: String,
    reason_code: String,
    grant_id: String,
    binding_id: String,
    auth_epoch: i64,
    response_evidence_id: String,
    action_ref: String,
    action_id: String,
    source_operation_id: String,
    operation_id: String,
    method: String,
    route_template: String,
    resource_type: String,
    resource_key_hmac: String,
    view_profile: String,
    fields: Vec<String>,
    mapping_revision: String,
    response_status: u16,
    response_body_sha256: String,
    candidate_count: u32,
    issued_at_unix: i64,
    expires_at_unix: i64,
}

pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: ResponseGrantIssued = serde_json::from_str(event.payload.get())?;
    if event.producer_id != "gateway-response-grant"
        || valid_prefixed_v7(&event.producer_boot_id, "req_").is_err()
        || event.request_id.as_deref() != Some(event.producer_boot_id.as_str())
        || event.producer_seq != u64::from(event.request_seq)
        || event.request_seq == 0
        || event.request_seq > value.candidate_count
        || !(1..=1_000).contains(&value.candidate_count)
        || event.sensitivity != "SENSITIVE"
        || !event.evidence_refs.is_empty()
        || !event.cause_event_ids.is_empty()
        || value.stage != "response_grant"
        || value.outcome != "PASS"
        || value.reason_code != "GRANT_ISSUED"
        || GrantId::parse(value.grant_id).is_err()
        || AuthBindingId::parse(value.binding_id).is_err()
        || value.auth_epoch <= 0
        || ResponseEvidenceId::parse(value.response_evidence_id).is_err()
        || !value
            .action_ref
            .strip_prefix("action.")
            .is_some_and(|suffix| valid_lower_hex(suffix, 64))
        || ActionId::parse(value.action_id).is_err()
        || OperationId::parse(value.source_operation_id).is_err()
        || OperationId::parse(value.operation_id.as_str()).is_err()
        || value.method != "GET"
        || RouteTemplate::parse(value.route_template).is_err()
        || ResourceType::parse(value.resource_type).is_err()
        || !valid_lower_hex(&value.resource_key_hmac, 64)
        || ViewProfile::parse(value.view_profile).is_err()
        || value.fields.len() != 1
        || FieldName::parse(value.fields[0].as_str()).is_err()
        || MappingRevision::parse(value.mapping_revision).is_err()
        || !(200..=299).contains(&value.response_status)
        || value.response_status == 204
        || !valid_lower_hex(&value.response_body_sha256, 64)
        || value.issued_at_unix < 0
        || !value
            .expires_at_unix
            .checked_sub(value.issued_at_unix)
            .is_some_and(|ttl| (1..=86_400).contains(&ttl))
    {
        return Err(PublishError::InvalidEvent);
    }
    // The producer freezes whole Unix seconds before its transaction. Exact
    // UTC encoding rejects offset/subsecond drift during retries or indexing.
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
    const GRANT: &str = "grant_018f2a3b-4c5d-7000-8000-000000000101";
    const BINDING: &str = "auth_018f2a3b-4c5d-7000-8000-000000000102";
    const EVIDENCE: &str = "response_018f2a3b-4c5d-7000-8000-000000000103";

    /// Canonical producer-shaped fixture reused by outbox delivery tests.
    pub(crate) fn event() -> Value {
        let mut event = base_event("case.created");
        event["event_type"] = json!("response_grant.issued");
        event["producer_id"] = json!("gateway-response-grant");
        event["producer_boot_id"] = event["request_id"].clone();
        event["request_seq"] = json!(1);
        event["producer_seq"] = json!(1);
        event["occurred_at"] = json!("2026-09-19T00:00:00Z");
        event["observed_at"] = event["occurred_at"].clone();
        event["sensitivity"] = json!("SENSITIVE");
        event["evidence_refs"] = json!([]);
        event["cause_event_ids"] = json!([]);
        event["payload"] = json!({
            "stage": "response_grant",
            "outcome": "PASS",
            "reason_code": "GRANT_ISSUED",
            "grant_id": GRANT,
            "binding_id": BINDING,
            "auth_epoch": 1,
            "response_evidence_id": EVIDENCE,
            "action_ref": format!("action.{}", "a".repeat(64)),
            "action_id": "resource.read",
            "source_operation_id": "resource.list",
            "operation_id": "resource.read",
            "method": "GET",
            "route_template": "/api/v1/resources/{resource_id}",
            "resource_type": "record",
            "resource_key_hmac": "b".repeat(64),
            "view_profile": "summary",
            "fields": ["name"],
            "mapping_revision": "mapping-r1",
            "response_status": 200,
            "response_body_sha256": "c".repeat(64),
            "candidate_count": 1,
            "issued_at_unix": ISSUED_AT,
            "expires_at_unix": ISSUED_AT + 3_600
        });
        event
    }

    fn row(value: &Value) -> Result<IndexRow, PublishError> {
        let bytes = serde_json::to_vec(value).map_err(|_| PublishError::InvalidEvent)?;
        let event_id = EventId::parse(
            value["event_id"]
                .as_str()
                .ok_or(PublishError::InvalidEvent)?,
        )
        .map_err(|_| PublishError::InvalidEvent)?;
        IndexRow::parse_outbox(
            &bytes,
            &event_id,
            value["producer_seq"]
                .as_u64()
                .ok_or(PublishError::InvalidEvent)?,
            value["producer_boot_id"]
                .as_str()
                .ok_or(PublishError::InvalidEvent)?,
            "0".repeat(64),
            chrono::TimeDelta::days(30),
        )
    }

    #[test]
    fn accepts_canonical_response_grant_summary() {
        let row = row(&event()).unwrap();
        assert_eq!(row.stage, "response_grant");
        assert_eq!(row.outcome, "PASS");
        assert_eq!(row.reason_code, "GRANT_ISSUED");
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.method, "GET");
        assert_eq!(row.operation_id, "resource.read");
        assert_eq!(row.is_terminal, 0);
        assert_eq!(row.http_status, None);
        assert!(row.origin_state.is_empty());
    }

    #[test]
    fn accepts_batch_positions_and_rejects_journal_source() {
        for count in [2, 1_000] {
            let mut value = event();
            value["producer_seq"] = json!(count);
            value["request_seq"] = json!(count);
            value["payload"]["candidate_count"] = json!(count);
            assert!(row(&value).is_ok());
        }
        let value = event();
        assert!(
            IndexRow::parse(
                &serde_json::to_vec(&value).unwrap(),
                &EventId::parse(value["event_id"].as_str().unwrap()).unwrap(),
                1,
                value["producer_boot_id"].as_str().unwrap(),
                "0".repeat(64),
                chrono::TimeDelta::days(30),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_unknown_duplicate_and_wrong_source_fields() {
        let original = event();
        for field in original["payload"].as_object().unwrap().keys() {
            let mut invalid = original.clone();
            invalid["payload"].as_object_mut().unwrap().remove(field);
            assert!(row(&invalid).is_err(), "missing {field}");
        }
        let mut unknown = original.clone();
        unknown["payload"]["extra"] = json!(true);
        assert!(row(&unknown).is_err());
        let serialized = serde_json::to_string(&original).unwrap();
        let duplicate =
            serialized.replace(r#""method":"GET""#, r#""method":"POST","method":"GET""#);
        let event_id = EventId::parse(original["event_id"].as_str().unwrap()).unwrap();
        assert!(
            IndexRow::parse_outbox(
                duplicate.as_bytes(),
                &event_id,
                1,
                original["producer_boot_id"].as_str().unwrap(),
                "0".repeat(64),
                chrono::TimeDelta::days(30),
            )
            .is_err()
        );
        for (pointer, value) in [
            ("/producer_id", json!("gateway-identity")),
            ("/event_type", json!("response_grant.issued.spoofed")),
            ("/producer_seq", json!(2)),
            ("/request_seq", json!(2)),
            ("/sensitivity", json!("INTERNAL")),
            (
                "/producer_boot_id",
                json!("req_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            ("/payload/outcome", json!("DENY")),
            ("/payload/reason_code", json!("GRANT_DENIED")),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(row(&invalid).is_err(), "accepted {pointer}");
        }
    }

    #[test]
    fn rejects_ids_hmac_ranges_times_and_binding_mismatches() {
        let original = event();
        for (pointer, value) in [
            ("/payload/grant_id", json!(BINDING)),
            ("/payload/binding_id", json!(GRANT)),
            ("/payload/response_evidence_id", json!(GRANT)),
            (
                "/payload/action_ref",
                json!("action.A".to_owned() + &"a".repeat(63)),
            ),
            ("/payload/resource_key_hmac", json!("A".repeat(64))),
            ("/payload/response_body_sha256", json!("c".repeat(63))),
            ("/payload/auth_epoch", json!(0)),
            ("/payload/auth_epoch", json!(-1)),
            ("/payload/auth_epoch", json!(i64::MAX as u64 + 1)),
            ("/payload/candidate_count", json!(0)),
            ("/payload/candidate_count", json!(1001)),
            ("/payload/response_status", json!(199)),
            ("/payload/response_status", json!(204)),
            ("/payload/response_status", json!(300)),
            ("/payload/fields", json!([])),
            ("/payload/fields", json!(["name", "id"])),
            ("/payload/method", json!("POST")),
            ("/payload/route_template", json!("/bad?query")),
            ("/payload/route_template", json!("/bad\n")),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(row(&invalid).is_err(), "accepted {pointer}");
        }
        for (issued, expires) in [
            (ISSUED_AT, ISSUED_AT),
            (ISSUED_AT, ISSUED_AT - 1),
            (ISSUED_AT, ISSUED_AT + 86_401),
            (-1, ISSUED_AT),
            (i64::MAX, i64::MAX),
        ] {
            let mut invalid = original.clone();
            invalid["payload"]["issued_at_unix"] = json!(issued);
            invalid["payload"]["expires_at_unix"] = json!(expires);
            assert!(row(&invalid).is_err(), "accepted {issued}/{expires}");
        }
        for (pointer, value) in [
            ("/occurred_at", json!("2026-09-19T00:00:00.123456Z")),
            ("/observed_at", json!("2026-09-19T02:00:00Z")),
            ("/occurred_at", json!("2026-09-19T00:00:00+00:00")),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(row(&invalid).is_err(), "accepted {pointer}");
        }
    }
}
