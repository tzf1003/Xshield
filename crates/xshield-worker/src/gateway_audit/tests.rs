//! The gateway's own tests feed every real emission through
//! `check_journal_record`; these cases pin the contract itself, including what
//! must be refused.

use super::*;
use crate::IndexRow;
use chrono::TimeDelta;
use serde_json::{Value, json};
use xshield_core::domain::EventId;

const EVENT_ID: &str = "ev_018f2a3b-4c5d-7000-8000-000000000301";
const CAUSE_ID: &str = "ev_018f2a3b-4c5d-7000-8000-000000000305";
const REQUEST_ID: &str = "req_018f2a3b-4c5d-7000-8000-000000000302";
const STAGE_ID: &str = "stg_018f2a3b-4c5d-7000-8000-000000000303";
const MESSAGE_ID: &str = "msg_018f2a3b-4c5d-7000-8000-000000000901";
const PAGE_EVIDENCE: &str = "page_018f2a3b-4c5d-7000-8000-000000000902";
const BINDING: &str = "auth_018f2a3b-4c5d-7000-8000-000000000201";
const BOOT: &str = "boot-018f2a3b";

fn digest(fill: char) -> String {
    fill.to_string().repeat(64)
}

fn event(event_type: &str, payload: Value) -> Value {
    let mut value = json!({
        "schema_version": 3,
        "event_id": EVENT_ID,
        "event_type": event_type,
        "tenant_id": "tenant_demo",
        "site_id": "site_demo",
        "request_id": REQUEST_ID,
        "trace_id": "01a0afa63320758a9554d0d3b561b8c6",
        "span_id": "01a0afa63320758a",
        "producer_id": "gateway-1",
        "producer_boot_id": BOOT,
        "producer_seq": 7,
        "request_seq": 3,
        "occurred_at": "2026-09-18T00:00:00.123Z",
        "observed_at": "2026-09-18T00:00:00.123Z",
        "policy_revision": "policy-r1",
        "example_only": false,
        "evidence_refs": [],
        "cause_event_ids": [CAUSE_ID],
        "payload": null,
        "sensitivity": "INTERNAL",
        "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
    });
    value["payload"] = payload;
    value
}

fn row(value: &Value) -> Result<IndexRow, PublishError> {
    IndexRow::parse(
        &serde_json::to_vec(value).unwrap(),
        &EventId::parse(EVENT_ID).unwrap(),
        7,
        BOOT,
        "0".repeat(64),
        TimeDelta::days(30),
    )
}

fn stage(
    stage: &str,
    outcome: &str,
    reason: &str,
    revision: &str,
    facts: Value,
    coverage: Value,
) -> Value {
    let mut value = json!({
        "stage": stage,
        "stage_execution_id": STAGE_ID,
        "outcome": outcome,
        "reason_code": reason,
        "proof_kind": "deterministic",
        "confidence": null,
        "confidence_status": "not_applicable",
        "duration_us": 420,
        "rule_revision": revision,
        "model_call_id": null,
        "facts": null,
        "coverage": null
    });
    value["facts"] = facts;
    value["coverage"] = coverage;
    value
}

fn decode_facts(mode: &str) -> Value {
    json!({
        "operation_id": "orders.create",
        "coverage_mode": mode,
        "algorithm": null,
        "adapter_revision": "orders-crypto-r1",
        "key_id": null,
        "approval_ref": null,
        "source_evidence_ref": null,
        "message_id": null,
        "nonce_sha256": null,
        "issued_at": null,
        "expires_at": null,
        "envelope_sha256": null,
        "rebuilt_sha256": null
    })
}

fn decode_event(outcome: &str, reason: &str, facts: Value, checked: bool, rebuilt: bool) -> Value {
    event(
        "stage.completed",
        stage(
            "crypto_decode",
            outcome,
            reason,
            "orders-crypto-r1",
            facts,
            json!({"request_crypto_checked": checked, "origin_entity_rebuilt": rebuilt}),
        ),
    )
}

/// An enforced decode that proved the whole message.
fn enforced_pass() -> Value {
    let mut facts = decode_facts("ENFORCE");
    facts["algorithm"] = json!("AES-256-GCM");
    facts["key_id"] = json!("orders-key-1");
    facts["message_id"] = json!(MESSAGE_ID);
    facts["nonce_sha256"] = json!(digest('a'));
    facts["issued_at"] = json!(1_800_000_000_u64);
    facts["expires_at"] = json!(1_800_000_300_u64);
    facts["envelope_sha256"] = json!(digest('b'));
    facts["rebuilt_sha256"] = json!(digest('c'));
    decode_event("PASS", "REQUEST_CRYPTO_DECODED", facts, true, true)
}

fn enforced_denial() -> Value {
    let mut facts = decode_facts("ENFORCE");
    facts["algorithm"] = json!("AES-256-GCM");
    facts["key_id"] = json!("orders-key-1");
    decode_event(
        "DENY",
        "REQUEST_CRYPTO_AUTHENTICATION_FAILED",
        facts,
        true,
        false,
    )
}

fn observed() -> Value {
    decode_event(
        "PASS",
        "REQUEST_CRYPTO_OBSERVED_OPAQUE",
        decode_facts("OBSERVE"),
        false,
        false,
    )
}

fn compatible() -> Value {
    let mut facts = decode_facts("COMPATIBILITY");
    facts["approval_ref"] = json!("approval-42");
    facts["source_evidence_ref"] = json!(PAGE_EVIDENCE);
    decode_event(
        "PASS",
        "REQUEST_CRYPTO_COMPATIBILITY_OPAQUE",
        facts,
        false,
        false,
    )
}

fn encode_event(outcome: &str, reason: &str, facts: Value, rebuilt: bool) -> Value {
    event(
        "stage.completed",
        stage(
            "crypto_encode",
            outcome,
            reason,
            "orders-crypto-r1",
            facts,
            json!({"response_crypto_checked": true, "client_entity_rebuilt": rebuilt}),
        ),
    )
}

fn encode_facts() -> Value {
    let mut facts = decode_facts("ENFORCE");
    facts["algorithm"] = json!("AES-256-GCM");
    facts["key_id"] = json!("orders-key-1");
    facts
}

fn encoded_pass() -> Value {
    let mut facts = encode_facts();
    facts["message_id"] = json!(MESSAGE_ID);
    facts["nonce_sha256"] = json!(digest('a'));
    facts["issued_at"] = json!(1_800_000_000_u64);
    facts["expires_at"] = json!(1_800_000_300_u64);
    facts["envelope_sha256"] = json!(digest('b'));
    facts["rebuilt_sha256"] = json!(digest('c'));
    encode_event("PASS", "RESPONSE_CRYPTO_ENCODED", facts, true)
}

fn html_event() -> Value {
    event(
        "stage.completed",
        stage(
            "sensor_html_inject",
            "PASS",
            "SENSOR_HTML_INJECTED",
            "home-r1",
            json!({
                "operation_id": "home.read",
                "origin_sha256": digest('a'),
                "injected_sha256": digest('b'),
                "csp_nonce_applied": false
            }),
            json!({"origin_entity_verified": true, "sensor_scripts_injected": true}),
        ),
    )
}

fn edge_event(event_type: &str, state: &str, status: Option<u16>) -> Value {
    event(
        event_type,
        json!({
            "method": "GET",
            "operation_id": "home.read",
            "edge_state": state,
            "reason_code": "UI_ACTION_NOT_AVAILABLE",
            "status": status
        }),
    )
}

fn captured_event() -> Value {
    let mut value = event(
        "evidence.captured",
        json!({
            "stage": "evidence_capture",
            "outcome": "PASS",
            "reason_code": "EVIDENCE_CAPTURED",
            "proof_kind": "deterministic",
            "confidence": null,
            "profile_revision": "evidence-profile-r1"
        }),
    );
    value["evidence_refs"] = json!(["ev_018f2a3b-4c5d-7000-8000-000000000306"]);
    value
}

fn observation_event() -> Value {
    event(
        "sensor.observation",
        json!({
            "binding_id": BINDING,
            "auth_epoch": 3,
            "authenticated": true,
            "build_ref": digest('a'),
            "page_handle": "pgh_018f2a3b-4c5d-7000-8000-000000000101",
            "navigation_id": "nav_018f2a3b-4c5d-7000-8000-000000000102",
            "action_hint": null,
            "client_request_id": null,
            "client_event_seq": 1,
            "visibility": "visible",
            "sensor_event_type": "PAGE_READY",
            "callsite_fingerprint": null,
            "claim_status": "client_claimed",
            "authorization_effect": "none"
        }),
    )
}

/// One named way to break an otherwise valid event.
type Mutation = (&'static str, fn(&mut Value));

fn assert_all_rejected(base: &Value, mutations: &[Mutation]) {
    for (name, mutate) in mutations {
        let mut value = base.clone();
        mutate(&mut value);
        assert!(row(&value).is_err(), "accepted despite: {name}");
    }
}

#[test]
fn request_crypto_stages_keep_the_gateway_vocabulary() {
    for (value, outcome, reason) in [
        (enforced_pass(), "PASS", "REQUEST_CRYPTO_DECODED"),
        (
            enforced_denial(),
            "DENY",
            "REQUEST_CRYPTO_AUTHENTICATION_FAILED",
        ),
        (observed(), "PASS", "REQUEST_CRYPTO_OBSERVED_OPAQUE"),
        (compatible(), "PASS", "REQUEST_CRYPTO_COMPATIBILITY_OPAQUE"),
    ] {
        let row = row(&value).unwrap();
        assert_eq!(row.event_type, "stage.completed");
        assert_eq!(row.stage, "crypto_decode");
        assert_eq!(row.outcome, outcome);
        assert_eq!(row.reason_code, reason);
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.operation_id, "orders.create");
        assert_eq!(row.duration_us, 420);
        assert_eq!(row.is_terminal, 0);
    }
    let mut failed = decode_facts("COMPATIBILITY");
    failed["approval_ref"] = json!("approval-42");
    let value = decode_event("DENY", "PAGE_EVIDENCE_REQUIRED", failed, false, false);
    assert_eq!(row(&value).unwrap().outcome, "DENY");
    let mut error = enforced_denial();
    error["payload"]["outcome"] = json!("ERROR");
    assert_eq!(row(&error).unwrap().outcome, "ERROR");
}

#[test]
fn request_crypto_refuses_every_departure_from_the_closed_shape() {
    assert_all_rejected(
        &enforced_pass(),
        &[
            ("an extra fact", |v| {
                v["payload"]["facts"]["extra"] = json!(1);
            }),
            ("a missing fact", |v| {
                v["payload"]["facts"]
                    .as_object_mut()
                    .unwrap()
                    .remove("rebuilt_sha256");
            }),
            ("an extra coverage member", |v| {
                v["payload"]["coverage"]["extra"] = json!(true);
            }),
            ("a skipped stage", |v| {
                v["event_type"] = json!("stage.skipped");
            }),
            ("an outcome outside the vocabulary", |v| {
                v["payload"]["outcome"] = json!("UNKNOWN");
            }),
            ("a malformed reason code", |v| {
                v["payload"]["reason_code"] = json!("not a code");
            }),
            ("a confidence value", |v| {
                v["payload"]["confidence"] = json!(0.9);
            }),
            ("a provided confidence status", |v| {
                v["payload"]["confidence_status"] = json!("provided");
            }),
            ("a model proof", |v| {
                v["payload"]["proof_kind"] = json!("model");
            }),
            ("a model call", |v| {
                v["payload"]["model_call_id"] = json!("mdl_018f2a3b-4c5d-7000-8000-000000000999");
            }),
            ("a revision that is not the adapter", |v| {
                v["payload"]["rule_revision"] = json!("another-revision");
            }),
            ("an unknown coverage mode", |v| {
                v["payload"]["facts"]["coverage_mode"] = json!("SHADOW");
            }),
            ("another algorithm", |v| {
                v["payload"]["facts"]["algorithm"] = json!("AES-128-GCM");
            }),
            ("an enforced pass without its envelope digest", |v| {
                v["payload"]["facts"]["envelope_sha256"] = Value::Null;
            }),
            ("coverage that denies the enforcement", |v| {
                v["payload"]["coverage"]["request_crypto_checked"] = json!(false);
            }),
            ("a rebuilt claim without a rebuilt digest", |v| {
                v["payload"]["facts"]["rebuilt_sha256"] = Value::Null;
            }),
            ("an enforced decode with an approval", |v| {
                v["payload"]["facts"]["approval_ref"] = json!("approval-42");
            }),
            ("enforcement without a key", |v| {
                v["payload"]["facts"]["key_id"] = Value::Null;
            }),
            ("an uppercase nonce digest", |v| {
                v["payload"]["facts"]["nonce_sha256"] = json!("A".repeat(64));
            }),
            ("a short digest", |v| {
                v["payload"]["facts"]["envelope_sha256"] = json!("ab");
            }),
            ("a message id of the wrong family", |v| {
                v["payload"]["facts"]["message_id"] =
                    json!("req_018f2a3b-4c5d-7000-8000-000000000901");
            }),
            ("a lifetime that ends before it starts", |v| {
                v["payload"]["facts"]["expires_at"] = json!(1_799_999_999_u64);
            }),
            ("a lifetime with one end", |v| {
                v["payload"]["facts"]["issued_at"] = Value::Null;
            }),
            ("an expiry past the supported horizon", |v| {
                v["payload"]["facts"]["expires_at"] = json!(5_000_000_000_u64);
            }),
            ("a duration that is not a number", |v| {
                v["payload"]["duration_us"] = json!("fast");
            }),
        ],
    );
}

#[test]
fn request_crypto_observation_and_compatibility_never_claim_a_decode() {
    assert_all_rejected(
        &observed(),
        &[
            ("an observed decode that carries a message", |v| {
                v["payload"]["facts"]["message_id"] = json!(MESSAGE_ID);
            }),
            ("an observed decode that names a key", |v| {
                v["payload"]["facts"]["key_id"] = json!("orders-key-1");
            }),
            ("an observed decode that claims enforcement", |v| {
                v["payload"]["coverage"]["request_crypto_checked"] = json!(true);
            }),
            ("an observed decode that cites page evidence", |v| {
                v["payload"]["facts"]["source_evidence_ref"] = json!(PAGE_EVIDENCE);
            }),
        ],
    );
    assert_all_rejected(
        &compatible(),
        &[
            ("compatibility without a server approval", |v| {
                v["payload"]["facts"]["approval_ref"] = Value::Null;
            }),
            ("compatibility with a malformed page evidence id", |v| {
                v["payload"]["facts"]["source_evidence_ref"] = json!("page_x");
            }),
        ],
    );
}

#[test]
fn response_crypto_stages_keep_the_gateway_vocabulary() {
    let passed = row(&encoded_pass()).unwrap();
    assert_eq!(passed.stage, "crypto_encode");
    assert_eq!(passed.outcome, "PASS");
    assert_eq!(passed.reason_code, "RESPONSE_CRYPTO_ENCODED");
    assert_eq!(passed.operation_id, "orders.create");
    let failed = row(&encode_event(
        "ERROR",
        "RESPONSE_CRYPTO_KEY_UNAVAILABLE",
        encode_facts(),
        false,
    ))
    .unwrap();
    assert_eq!(failed.outcome, "ERROR");
}

#[test]
fn response_crypto_refuses_every_departure_from_the_closed_shape() {
    assert_all_rejected(
        &encoded_pass(),
        &[
            ("an extra fact", |v| {
                v["payload"]["facts"]["extra"] = json!(1);
            }),
            ("a request-side coverage member", |v| {
                v["payload"]["coverage"]["request_crypto_checked"] = json!(true);
            }),
            ("a non-enforced response", |v| {
                v["payload"]["facts"]["coverage_mode"] = json!("OBSERVE");
            }),
            ("an approval on a response", |v| {
                v["payload"]["facts"]["approval_ref"] = json!("approval-42");
            }),
            ("page evidence on a response", |v| {
                v["payload"]["facts"]["source_evidence_ref"] = json!(PAGE_EVIDENCE);
            }),
            ("coverage that denies the check", |v| {
                v["payload"]["coverage"]["response_crypto_checked"] = json!(false);
            }),
            ("a client rebuild claim without an envelope", |v| {
                v["payload"]["facts"]["envelope_sha256"] = Value::Null;
            }),
            ("a pass without the origin digest", |v| {
                v["payload"]["facts"]["rebuilt_sha256"] = Value::Null;
            }),
            ("a skipped stage", |v| {
                v["event_type"] = json!("stage.skipped");
            }),
        ],
    );
}

#[test]
fn sensor_html_stage_is_one_verified_injection() {
    let row = row(&html_event()).unwrap();
    assert_eq!(row.stage, "sensor_html_inject");
    assert_eq!(row.outcome, "PASS");
    assert_eq!(row.reason_code, "SENSOR_HTML_INJECTED");
    assert_eq!(row.operation_id, "home.read");
    assert_eq!(row.proof_kind, "deterministic");
    assert_all_rejected(
        &html_event(),
        &[
            ("an extra fact", |v| {
                v["payload"]["facts"]["extra"] = json!(1);
            }),
            ("a denied injection", |v| {
                v["payload"]["outcome"] = json!("DENY");
            }),
            ("a skipped stage", |v| {
                v["event_type"] = json!("stage.skipped");
            }),
            ("an unchanged body", |v| {
                v["payload"]["facts"]["injected_sha256"] =
                    v["payload"]["facts"]["origin_sha256"].clone();
            }),
            ("an origin digest that is not hex", |v| {
                v["payload"]["facts"]["origin_sha256"] = json!("z".repeat(64));
            }),
            ("a page whose origin was not verified", |v| {
                v["payload"]["coverage"]["origin_entity_verified"] = json!(false);
            }),
            ("a page whose scripts were not injected", |v| {
                v["payload"]["coverage"]["sensor_scripts_injected"] = json!(false);
            }),
            ("a missing nonce flag", |v| {
                v["payload"]["facts"]
                    .as_object_mut()
                    .unwrap()
                    .remove("csp_nonce_applied");
            }),
            ("a missing adapter revision", |v| {
                v["payload"]["rule_revision"] = Value::Null;
            }),
        ],
    );
}

#[test]
fn edge_responses_record_status_and_delivery_state() {
    let served = row(&edge_event("edge.response", "response_served", Some(403))).unwrap();
    assert_eq!(served.event_type, "edge.response");
    assert_eq!(served.outcome, "response_served");
    assert_eq!(served.reason_code, "UI_ACTION_NOT_AVAILABLE");
    assert_eq!(served.method, "GET");
    assert_eq!(served.operation_id, "home.read");
    assert_eq!(served.http_status, Some(403));
    assert_eq!(served.is_terminal, 0);
    let unknown = row(&edge_event("edge.unknown", "unknown", None)).unwrap();
    assert_eq!(unknown.outcome, "unknown");
    assert_eq!(unknown.http_status, None);
    assert!(row(&edge_event("edge.unknown", "unknown", Some(502))).is_ok());
    for (event_type, state, status) in [
        ("edge.response", "response_served", None),
        ("edge.response", "response_served", Some(99)),
        ("edge.response", "response_served", Some(600)),
        ("edge.response", "unknown", Some(200)),
        ("edge.unknown", "response_served", Some(200)),
        ("edge.unknown", "unknown", Some(700)),
        ("edge.response", "not_sent", Some(200)),
    ] {
        assert!(
            row(&edge_event(event_type, state, status)).is_err(),
            "{event_type} {state} {status:?}"
        );
    }
    assert_all_rejected(
        &edge_event("edge.response", "response_served", Some(200)),
        &[
            ("an extra member", |v| {
                v["payload"]["origin_state"] = json!("not_sent");
            }),
            ("a lowercase method", |v| {
                v["payload"]["method"] = json!("get");
            }),
            ("a malformed operation", |v| {
                v["payload"]["operation_id"] = json!("a b");
            }),
            ("a malformed reason code", |v| {
                v["payload"]["reason_code"] = json!("");
            }),
            ("a missing status member", |v| {
                v["payload"].as_object_mut().unwrap().remove("status");
            }),
        ],
    );
}

#[test]
fn evidence_capture_links_one_artifact_to_one_catalog_event() {
    let row = row(&captured_event()).unwrap();
    assert_eq!(row.event_type, "evidence.captured");
    assert_eq!(row.stage, "evidence_capture");
    assert_eq!(row.outcome, "PASS");
    assert_eq!(row.reason_code, "EVIDENCE_CAPTURED");
    assert_eq!(row.proof_kind, "deterministic");
    assert_eq!(row.confidence_status, "not_applicable");
    assert_eq!(
        row.evidence_refs,
        ["ev_018f2a3b-4c5d-7000-8000-000000000306"]
    );
    assert_all_rejected(
        &captured_event(),
        &[
            ("no artifact", |v| v["evidence_refs"] = json!([])),
            ("two artifacts", |v| {
                v["evidence_refs"] = json!([
                    "ev_018f2a3b-4c5d-7000-8000-000000000306",
                    "ev_018f2a3b-4c5d-7000-8000-000000000307"
                ]);
            }),
            ("no catalog cause", |v| v["cause_event_ids"] = json!([])),
            ("no request", |v| v["request_id"] = Value::Null),
            ("another reason", |v| {
                v["payload"]["reason_code"] = json!("EVIDENCE_CAPTURE_UNAVAILABLE");
            }),
            ("another outcome", |v| {
                v["payload"]["outcome"] = json!("DENY");
            }),
            ("a confidence value", |v| {
                v["payload"]["confidence"] = json!(1.0);
            }),
            ("an extra member", |v| {
                v["payload"]["artifact_id"] = json!("ev_x");
            }),
            ("a malformed profile revision", |v| {
                v["payload"]["profile_revision"] = json!("a b");
            }),
        ],
    );
}

#[test]
fn sensor_observations_are_client_claims_that_authorize_nothing() {
    let ready = row(&observation_event()).unwrap();
    assert_eq!(ready.event_type, "sensor.observation");
    assert_eq!(ready.proof_kind, "observation");
    assert_eq!(ready.confidence, None);
    assert_eq!(ready.confidence_status, "not_applicable");
    assert_eq!(ready.outcome, "");
    assert_eq!(ready.is_terminal, 0);
    let mut heartbeat = observation_event();
    heartbeat["payload"]["sensor_event_type"] = json!("HEARTBEAT");
    heartbeat["payload"]["client_event_seq"] = json!(2);
    heartbeat["payload"]["client_request_id"] = json!(REQUEST_ID);
    heartbeat["payload"]["callsite_fingerprint"] = json!(digest('d'));
    heartbeat["payload"]["action_hint"] = json!("orders.submit");
    heartbeat["payload"]["visibility"] = json!("hidden");
    heartbeat["payload"]["authenticated"] = json!(false);
    assert!(row(&heartbeat).is_ok());
    assert_all_rejected(
        &observation_event(),
        &[
            ("a claim that authorizes", |v| {
                v["payload"]["authorization_effect"] = json!("granted");
            }),
            ("a claim presented as verified", |v| {
                v["payload"]["claim_status"] = json!("verified");
            }),
            ("a first event that is not PAGE_READY", |v| {
                v["payload"]["sensor_event_type"] = json!("HEARTBEAT");
            }),
            ("a later PAGE_READY", |v| {
                v["payload"]["client_event_seq"] = json!(2);
            }),
            ("sequence zero", |v| {
                v["payload"]["client_event_seq"] = json!(0);
            }),
            ("a sequence past the batch ceiling", |v| {
                v["payload"]["sensor_event_type"] = json!("VISIBILITY");
                v["payload"]["client_event_seq"] = json!(65);
            }),
            ("an unknown lifecycle event", |v| {
                v["payload"]["sensor_event_type"] = json!("CLICK");
            }),
            ("an unknown visibility", |v| {
                v["payload"]["visibility"] = json!("prerender");
            }),
            ("epoch zero", |v| v["payload"]["auth_epoch"] = json!(0)),
            ("an epoch beyond bigint", |v| {
                v["payload"]["auth_epoch"] = json!(9_223_372_036_854_775_808_u64);
            }),
            ("a binding of another family", |v| {
                v["payload"]["binding_id"] = json!("page_018f2a3b-4c5d-7000-8000-000000000201");
            }),
            ("a page handle without its prefix", |v| {
                v["payload"]["page_handle"] = json!("018f2a3b-4c5d-7000-8000-000000000101");
            }),
            ("a navigation id with a version-4 uuid", |v| {
                v["payload"]["navigation_id"] = json!("nav_018f2a3b-4c5d-4000-8000-000000000102");
            }),
            ("a build reference that is not a digest", |v| {
                v["payload"]["build_ref"] = json!("build-1");
            }),
            ("a malformed client request", |v| {
                v["payload"]["client_request_id"] = json!("req_1");
            }),
            ("a malformed callsite fingerprint", |v| {
                v["payload"]["callsite_fingerprint"] = json!("ABC");
            }),
            ("a hint that is an action reference", |v| {
                v["payload"]["action_hint"] = json!(format!("action.{}", digest('a')));
            }),
            ("a hint that embeds an action reference", |v| {
                v["payload"]["action_hint"] = json!(format!("try action.{}", digest('a')));
            }),
            ("a hint with a space", |v| {
                v["payload"]["action_hint"] = json!("two words");
            }),
            ("an oversized hint", |v| {
                v["payload"]["action_hint"] = json!("h".repeat(257));
            }),
            ("an empty hint", |v| v["payload"]["action_hint"] = json!("")),
            ("an extra member", |v| {
                v["payload"]["user_agent"] = json!("x");
            }),
            ("a missing member", |v| {
                v["payload"]
                    .as_object_mut()
                    .unwrap()
                    .remove("navigation_id");
            }),
        ],
    );
    let mut longest = observation_event();
    longest["payload"]["action_hint"] = json!("h".repeat(256));
    assert!(row(&longest).is_ok());
}

#[test]
fn only_the_gateway_families_are_claimed_and_never_from_the_outbox() {
    for value in [
        enforced_pass(),
        encoded_pass(),
        html_event(),
        edge_event("edge.response", "response_served", Some(200)),
        edge_event("edge.unknown", "unknown", None),
        captured_event(),
        observation_event(),
    ] {
        let bytes = serde_json::to_vec(&value).unwrap();
        let wire: WireEvent = serde_json::from_slice(&bytes).unwrap();
        assert!(supports(&wire), "{}", value["event_type"]);
        // The outbox is a different producer contract: naming a journal-only
        // type there must stay unsupported.
        let outbox = IndexRow::parse_outbox(
            &bytes,
            &EventId::parse(EVENT_ID).unwrap(),
            7,
            BOOT,
            "0".repeat(64),
            TimeDelta::days(30),
        );
        assert!(matches!(outbox, Err(PublishError::UnsupportedEventType)));
    }
    // Stages that keep the generic shape stay with the generic parser.
    let generic = event(
        "stage.completed",
        stage(
            "ui_action_issue",
            "PASS",
            "UI_ACTION_ISSUED",
            "app-map-r1",
            json!({"operation_id": "app.page"}),
            json!({"admission_checked": true}),
        ),
    );
    let wire: WireEvent = serde_json::from_slice(&serde_json::to_vec(&generic).unwrap()).unwrap();
    assert!(!supports(&wire));
    assert!(row(&generic).is_ok());
}

#[test]
fn a_gateway_stage_cannot_borrow_the_weaker_generic_shape() {
    for name in ["crypto_decode", "crypto_encode", "sensor_html_inject"] {
        let value = event(
            "stage.completed",
            stage(
                name,
                "PASS",
                "ANY_CODE",
                "r1",
                json!({"operation_id": "orders.create"}),
                json!({"admission_checked": true}),
            ),
        );
        assert!(row(&value).is_err(), "{name} parsed as a generic stage");
    }
}

/// Deterministic xorshift, so a failure reproduces from its seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
}

/// Every object member and array element under `value`, as a path of keys.
fn paths(value: &Value, here: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                here.push(key.clone());
                out.push(here.clone());
                paths(child, here, out);
                here.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                here.push(index.to_string());
                out.push(here.clone());
                paths(child, here, out);
                here.pop();
            }
        }
        _ => {}
    }
}

fn at<'a>(value: &'a mut Value, path: &[String]) -> Option<&'a mut Value> {
    let mut current = value;
    for step in path {
        current = match current {
            Value::Object(map) => map.get_mut(step)?,
            Value::Array(items) => items.get_mut(step.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Replaces, removes or retypes one member anywhere in the event.
fn mutate(value: &mut Value, rng: &mut Rng) {
    let mut all = Vec::new();
    paths(value, &mut Vec::new(), &mut all);
    let Some(path) = all.get(rng.below(all.len())).cloned() else {
        return;
    };
    let (last, parent_path) = path.split_last().unwrap();
    let swap_with = all.get(rng.below(all.len())).cloned();
    let donor = swap_with.and_then(|other| at(&mut value.clone(), &other).map(|v| v.clone()));
    let Some(parent) = at(value, parent_path) else {
        return;
    };
    let words = [
        "", "x", "ENFORCE", "OBSERVE", "PASS", "action.", "\u{0}", "msg_", "é",
    ];
    let long = "A".repeat(300);
    let numbers = [0_u64, 1, 2, 64, 65, 999, u64::from(u32::MAX), u64::MAX];
    let replacement = match rng.below(9) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 0),
        2 => json!(numbers[rng.below(numbers.len())]),
        3 => json!(-1),
        4 => json!(words[rng.below(words.len())]),
        5 => json!(long),
        6 => json!([]),
        7 => json!({}),
        _ => donor.unwrap_or(Value::Null),
    };
    match parent {
        Value::Object(map) => {
            if rng.below(4) == 0 {
                map.remove(last);
            } else {
                map.insert(last.clone(), replacement);
            }
        }
        Value::Array(items) => {
            if let Ok(index) = last.parse::<usize>()
                && index < items.len()
            {
                items[index] = replacement;
            }
        }
        _ => {}
    }
}

fn text<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .try_fold(value, |current, key| current.get(key))?
        .as_str()
}

fn flag(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .try_fold(value, |current, key| current.get(key))?
        .as_bool()
}

fn present(value: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .try_fold(value, |current, key| current.get(key))
        .is_some_and(|found| !found.is_null())
}

/// What an accepted event must still say, read straight from its JSON rather
/// than from the parser, so a lenient parser cannot satisfy its own check.
fn assert_accepted_event_is_coherent(event: &Value) {
    let payload = &event["payload"];
    match event["event_type"].as_str().unwrap() {
        "sensor.observation" => {
            assert_eq!(text(payload, &["authorization_effect"]), Some("none"));
            assert_eq!(text(payload, &["claim_status"]), Some("client_claimed"));
            if let Some(hint) = text(payload, &["action_hint"]) {
                assert!(!hint.contains("action.") && hint.len() <= 256 && !hint.is_empty());
            }
            let sequence = payload["client_event_seq"].as_u64().unwrap();
            assert!((1..=64).contains(&sequence));
            assert_eq!(
                text(payload, &["sensor_event_type"]) == Some("PAGE_READY"),
                sequence == 1
            );
        }
        "edge.response" => {
            assert_eq!(text(payload, &["edge_state"]), Some("response_served"));
            assert!((100..=599).contains(&payload["status"].as_u64().unwrap()));
        }
        "edge.unknown" => assert_eq!(text(payload, &["edge_state"]), Some("unknown")),
        "evidence.captured" => {
            assert_eq!(event["evidence_refs"].as_array().unwrap().len(), 1);
            assert_eq!(event["cause_event_ids"].as_array().unwrap().len(), 1);
            assert_eq!(text(payload, &["reason_code"]), Some("EVIDENCE_CAPTURED"));
        }
        "stage.completed" => {
            assert_eq!(text(payload, &["proof_kind"]), Some("deterministic"));
            assert!(payload["confidence"].is_null());
            assert!(payload["model_call_id"].is_null());
            match text(payload, &["stage"]).unwrap() {
                "crypto_decode" => {
                    let mode = text(payload, &["facts", "coverage_mode"]).unwrap();
                    assert!(matches!(mode, "ENFORCE" | "OBSERVE" | "COMPATIBILITY"));
                    assert_eq!(
                        flag(payload, &["coverage", "request_crypto_checked"]),
                        Some(mode == "ENFORCE")
                    );
                    assert_eq!(
                        flag(payload, &["coverage", "origin_entity_rebuilt"]),
                        Some(present(payload, &["facts", "rebuilt_sha256"]))
                    );
                    if mode == "ENFORCE" && text(payload, &["outcome"]) == Some("PASS") {
                        for key in [
                            "message_id",
                            "nonce_sha256",
                            "envelope_sha256",
                            "rebuilt_sha256",
                        ] {
                            assert!(present(payload, &["facts", key]), "{key}");
                        }
                    }
                    if mode != "ENFORCE" {
                        assert!(!present(payload, &["facts", "message_id"]));
                    }
                }
                "crypto_encode" => {
                    assert_eq!(text(payload, &["facts", "coverage_mode"]), Some("ENFORCE"));
                    assert_eq!(
                        flag(payload, &["coverage", "response_crypto_checked"]),
                        Some(true)
                    );
                    assert!(!present(payload, &["facts", "approval_ref"]));
                    assert_eq!(
                        flag(payload, &["coverage", "client_entity_rebuilt"]),
                        Some(present(payload, &["facts", "envelope_sha256"]))
                    );
                }
                "sensor_html_inject" => {
                    assert_eq!(text(payload, &["outcome"]), Some("PASS"));
                    assert_eq!(
                        flag(payload, &["coverage", "origin_entity_verified"]),
                        Some(true)
                    );
                    assert_eq!(
                        flag(payload, &["coverage", "sensor_scripts_injected"]),
                        Some(true)
                    );
                    assert_ne!(
                        text(payload, &["facts", "origin_sha256"]),
                        text(payload, &["facts", "injected_sha256"])
                    );
                }
                other => panic!("accepted by a gateway parser under stage {other}"),
            }
        }
        other => panic!("unexpected event type {other}"),
    }
}

/// Anything the parsers accept after arbitrary damage still holds the
/// invariants they exist to protect, and nothing panics.
#[test]
fn damaged_events_are_refused_or_still_coherent() {
    let bases = [
        enforced_pass(),
        enforced_denial(),
        observed(),
        compatible(),
        encoded_pass(),
        html_event(),
        edge_event("edge.response", "response_served", Some(403)),
        edge_event("edge.unknown", "unknown", None),
        captured_event(),
        observation_event(),
    ];
    let mut accepted = 0_u32;
    for (index, base) in bases.iter().enumerate() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ u64::try_from(index + 1).unwrap());
        for _ in 0..4_000 {
            let mut damaged = base.clone();
            for _ in 0..=rng.below(3) {
                mutate(&mut damaged, &mut rng);
            }
            if row(&damaged).is_ok() {
                accepted += 1;
                assert_accepted_event_is_coherent(&damaged);
            }
        }
    }
    // Some damage is harmless (a replaced fact with an equal value, a swapped
    // identical digest), so the sweep must have exercised acceptance too.
    assert!(accepted > 0);
}
