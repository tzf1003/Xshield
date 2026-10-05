//! Strict page-issued UI action facts; indexed history is not authorization.
//!
//! `ui_action.issued` is written by the gateway's page-delivery issuance in
//! the same transaction as the page evidence and action rows. Only that
//! producer's closed shape is accepted: page-issued actions target nothing
//! and expose no fields. A future producer (principal targets, fields) must
//! extend this parser before it ships, because an unparsable row stops the
//! whole family at its position.

use super::{PayloadSummary, PublishError, WireEvent, valid_lower_hex, valid_prefixed_v7};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use xshield_core::{
    domain::{
        ActionId, AuthBindingId, MappingRevision, OperationId, PageEvidenceId, PageTemplate,
        ViewProfile,
    },
    provenance::RouteTemplate,
};

pub(super) const EVENT_TYPES: &[&str] = &["ui_action.issued"];
const MAX_PAGE_ACTIONS: u32 = 16;
const MAX_LEASE_SECONDS: i64 = 86_400;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UiActionIssued {
    stage: String,
    outcome: String,
    reason_code: String,
    action_ref: String,
    action_id: String,
    binding_id: String,
    auth_epoch: i64,
    page_evidence_id: String,
    page_template: String,
    build_fingerprint: String,
    operation_id: String,
    method: String,
    route_template: String,
    field_profile: String,
    fields: Vec<String>,
    target_kind: String,
    mapping_revision: String,
    action_count: u32,
    issued_at_unix: i64,
    expires_at_unix: i64,
    page_expires_at_unix: i64,
}

fn valid_lease(issued_at: i64, expires_at: i64) -> bool {
    expires_at
        .checked_sub(issued_at)
        .is_some_and(|ttl| (1..=MAX_LEASE_SECONDS).contains(&ttl))
}

pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: UiActionIssued = serde_json::from_str(event.payload.get())?;
    if event.producer_id != "gateway-ui-action"
        || valid_prefixed_v7(&event.producer_boot_id, "req_").is_err()
        || event.request_id.as_deref() != Some(event.producer_boot_id.as_str())
        || event.producer_seq != u64::from(event.request_seq)
        || event.request_seq == 0
        || event.request_seq > value.action_count
        || !(1..=MAX_PAGE_ACTIONS).contains(&value.action_count)
        || event.sensitivity != "SENSITIVE"
        || !event.evidence_refs.is_empty()
        || !event.cause_event_ids.is_empty()
        || value.stage != "ui_action"
        || value.outcome != "PASS"
        || value.reason_code != "UI_ACTION_ISSUED"
        || !value
            .action_ref
            .strip_prefix("action.")
            .is_some_and(|suffix| valid_lower_hex(suffix, 64))
        || ActionId::parse(value.action_id).is_err()
        || AuthBindingId::parse(value.binding_id).is_err()
        || value.auth_epoch <= 0
        || PageEvidenceId::parse(value.page_evidence_id).is_err()
        || PageTemplate::parse(value.page_template).is_err()
        || !valid_lower_hex(&value.build_fingerprint, 64)
        || OperationId::parse(value.operation_id.as_str()).is_err()
        || !matches!(
            value.method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
        )
        || RouteTemplate::parse(value.route_template).is_err()
        || ViewProfile::parse(value.field_profile).is_err()
        || !value.fields.is_empty()
        || value.target_kind != "none"
        || MappingRevision::parse(value.mapping_revision).is_err()
        || value.issued_at_unix < 0
        || !valid_lease(value.issued_at_unix, value.expires_at_unix)
        || !valid_lease(value.issued_at_unix, value.page_expires_at_unix)
        || value.page_expires_at_unix < value.expires_at_unix
    {
        return Err(PublishError::InvalidEvent);
    }
    // Issuance freezes whole Unix seconds before its transaction. Exact UTC
    // encoding rejects offset/subsecond drift in a retried or indexed copy.
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
    const BINDING: &str = "auth_018f2a3b-4c5d-7000-8000-000000000201";
    const PAGE: &str = "page_018f2a3b-4c5d-7000-8000-000000000202";

    /// Canonical producer-shaped fixture (`gateway-ui-action`).
    pub(crate) fn event() -> Value {
        let mut event = base_event("case.created");
        event["event_type"] = json!("ui_action.issued");
        event["producer_id"] = json!("gateway-ui-action");
        event["producer_boot_id"] = event["request_id"].clone();
        event["request_seq"] = json!(1);
        event["producer_seq"] = json!(1);
        event["occurred_at"] = json!("2026-09-19T00:00:00Z");
        event["observed_at"] = event["occurred_at"].clone();
        event["sensitivity"] = json!("SENSITIVE");
        event["evidence_refs"] = json!([]);
        event["cause_event_ids"] = json!([]);
        event["payload"] = json!({
            "stage": "ui_action",
            "outcome": "PASS",
            "reason_code": "UI_ACTION_ISSUED",
            "action_ref": format!("action.{}", "a".repeat(64)),
            "action_id": "app.orders.list",
            "binding_id": BINDING,
            "auth_epoch": 1,
            "page_evidence_id": PAGE,
            "page_template": "app.page",
            "build_fingerprint": "b".repeat(64),
            "operation_id": "orders.list",
            "method": "GET",
            "route_template": "/orders",
            "field_profile": "none",
            "fields": [],
            "target_kind": "none",
            "mapping_revision": "mapping-r1",
            "action_count": 1,
            "issued_at_unix": ISSUED_AT,
            "expires_at_unix": ISSUED_AT + 600,
            "page_expires_at_unix": ISSUED_AT + 900
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
    fn accepts_canonical_page_action_summary() {
        let row = row(&event()).unwrap();
        assert_eq!(row.stage, "ui_action");
        assert_eq!(row.outcome, "PASS");
        assert_eq!(row.reason_code, "UI_ACTION_ISSUED");
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.method, "GET");
        assert_eq!(row.operation_id, "orders.list");
        assert_eq!(row.is_terminal, 0);
        assert_eq!(row.http_status, None);
    }

    #[test]
    fn accepts_batch_positions_and_rejects_journal_source() {
        for count in [2, 16] {
            let mut value = event();
            value["producer_seq"] = json!(count);
            value["request_seq"] = json!(count);
            value["payload"]["action_count"] = json!(count);
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
            ("/producer_id", json!("gateway-response-grant")),
            ("/producer_seq", json!(2)),
            ("/request_seq", json!(2)),
            ("/sensitivity", json!("INTERNAL")),
            (
                "/producer_boot_id",
                json!("req_018f2a3b-4c5d-7000-8000-000000000099"),
            ),
            (
                "/evidence_refs",
                json!(["artifact_018f2a3b-4c5d-7000-8000-000000000001"]),
            ),
            ("/payload/stage", json!("response_grant")),
            ("/payload/outcome", json!("DENY")),
            ("/payload/reason_code", json!("UI_ACTION_ALREADY_ISSUED")),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(row(&invalid).is_err(), "accepted {pointer}");
        }
    }

    #[test]
    fn rejects_ids_targets_fields_counts_and_times() {
        let original = event();
        for (pointer, value) in [
            ("/payload/binding_id", json!(PAGE)),
            ("/payload/page_evidence_id", json!(BINDING)),
            (
                "/payload/action_ref",
                json!("action.".to_owned() + &"A".repeat(64)),
            ),
            (
                "/payload/action_ref",
                json!("action.".to_owned() + &"a".repeat(63)),
            ),
            ("/payload/action_ref", json!("a".repeat(71))),
            ("/payload/build_fingerprint", json!("B".repeat(64))),
            ("/payload/auth_epoch", json!(0)),
            ("/payload/auth_epoch", json!(-1)),
            ("/payload/action_count", json!(0)),
            ("/payload/action_count", json!(17)),
            ("/payload/fields", json!(["order_id"])),
            ("/payload/target_kind", json!("resource")),
            ("/payload/method", json!("TRACE")),
            ("/payload/route_template", json!("/orders?x=1")),
            ("/payload/page_template", json!("app/page")),
            ("/payload/mapping_revision", json!("")),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(row(&invalid).is_err(), "accepted {pointer}");
        }
        for (expires, page_expires) in [
            (ISSUED_AT, ISSUED_AT + 900),
            (ISSUED_AT + 86_401, ISSUED_AT + 86_401),
            (ISSUED_AT + 900, ISSUED_AT + 600),
            (ISSUED_AT + 600, ISSUED_AT + 86_401),
        ] {
            let mut invalid = original.clone();
            invalid["payload"]["expires_at_unix"] = json!(expires);
            invalid["payload"]["page_expires_at_unix"] = json!(page_expires);
            assert!(row(&invalid).is_err(), "accepted {expires}/{page_expires}");
        }
        for (pointer, value) in [
            ("/occurred_at", json!("2026-09-19T00:00:00.5Z")),
            ("/observed_at", json!("2026-09-19T00:00:01Z")),
            ("/payload/issued_at_unix", json!(-1)),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(row(&invalid).is_err(), "accepted {pointer}");
        }
    }

    /// Contract check over the rows a real gateway committed during
    /// `scripts/test_browser_loop.sh`: every one must publish, or the family
    /// would stall at its position.
    #[test]
    #[ignore = "run by scripts/test_browser_loop.sh with XSHIELD_BROWSER_LOOP_OUTBOX"]
    fn browser_loop_outbox_rows_parse_under_the_family_contract() {
        let path = std::env::var("XSHIELD_BROWSER_LOOP_OUTBOX").expect("outbox dump path");
        let rows: Vec<Value> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(
            !rows.is_empty(),
            "the run committed no ui_action.issued row"
        );
        for stored in &rows {
            let envelope = &stored["envelope"];
            let parsed = row(envelope).unwrap_or_else(|error| panic!("{error:?}: {envelope}"));
            assert_eq!(parsed.event_type, "ui_action.issued");
            // The publisher binds the outbox aggregate to the payload member.
            assert_eq!(stored["event_id"], envelope["event_id"]);
            assert_eq!(stored["aggregate_ref"], envelope["payload"]["action_ref"]);
        }
    }
}
