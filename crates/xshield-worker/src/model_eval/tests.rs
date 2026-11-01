use super::ModelEvent;
use serde_json::json;

const SAMPLE_MODEL_CALL_ID: &str = "mdl_01a0afa6-3320-7791-8f45-b4d5a34ffb58";
const SAMPLE_INPUT_ARTIFACT_ID: &str = "artifact_01a0afa6-3320-7791-8f45-b4d5a34ffb59";
const SAMPLE_OUTPUT_ARTIFACT_ID: &str = "artifact_01a0afa6-3320-7791-8f45-b4d5a34ffb5a";
const SAMPLE_CALL_ARTIFACT_ID: &str = "artifact_01a0afa6-3320-7791-8f45-b4d5a34ffb5b";
const SAMPLE_CACHE_SOURCE_MODEL_CALL_ID: &str = "mdl_01a0afa6-3320-7791-8f45-b4d5a34ffb5c";

fn started_event() -> ModelEvent {
    ModelEvent {
        model_call_id: SAMPLE_MODEL_CALL_ID.to_owned(),
        cache_source_model_call_id: None,
        provider: Some("typesafe".to_owned()),
        provider_model_id: Some("jev-1.13.0".to_owned()),
        model_revision: "jev-1.13.0".to_owned(),
        prompt_revision: "prompt-r1".to_owned(),
        question_type: "choice".to_owned(),
        status: "started".to_owned(),
        reason_code: "MODEL_EVALUATION_STARTED".to_owned(),
        confidence: None,
        confidence_status: "unavailable".to_owned(),
        duration_us: 0,
        input_artifact_id: None,
        output_artifact_id: None,
        call_artifact_id: None,
    }
}

#[test]
fn model_event_contract_rejects_confidence_and_lifecycle_contradictions() {
    let event = started_event();
    assert!(event.clone().validate("model.started").is_ok());
    assert!(event.clone().validate("model.responded").is_err());
    let mut bad = event.clone();
    bad.confidence = Some(0.9);
    assert!(bad.validate("model.started").is_err());
    let mut bad = event.clone();
    "requested".clone_into(&mut bad.status);
    assert!(bad.validate("model.requested").is_err());
    let mut bad = started_event();
    bad.provider_model_id = None;
    assert!(bad.validate("model.started").is_err());
    let mut bad = started_event();
    bad.provider_model_id = Some("untrusted/model".to_owned());
    assert!(bad.validate("model.started").is_err());
    let mut bad = started_event();
    bad.provider = Some("vercel_ai_gateway".to_owned());
    assert!(bad.validate("model.started").is_err());
    let mut null_fields = serde_json::to_value(started_event()).unwrap();
    null_fields["provider"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ModelEvent>(null_fields).is_err());
}

#[test]
fn model_cache_hit_event_binds_the_source_call_without_changing_lifecycle_shape() {
    let mut event = started_event();
    event.status = "requested".to_owned();
    event.reason_code = "MODEL_CACHE_HIT".to_owned();
    event.input_artifact_id = Some(SAMPLE_INPUT_ARTIFACT_ID.to_owned());
    event.cache_source_model_call_id = Some(SAMPLE_CACHE_SOURCE_MODEL_CALL_ID.to_owned());
    assert!(event.clone().validate("model.cache_hit").is_ok());

    event.cache_source_model_call_id = None;
    assert!(event.validate("model.cache_hit").is_err());
}

fn envelope_with_payload(payload: &ModelEvent, evidence_refs: &[String]) -> crate::WireEvent {
    let value = json!({
        "schema_version": 3,
        "event_id": "ev_01a0afa6-3320-7791-8f45-b4d5a34ffb5d",
        "event_type": "model.requested",
        "tenant_id": "tenant_model_eval",
        "site_id": "site_model_eval",
        "request_id": "req_01a0afa6-3320-7791-8f45-b4d5a34ffb57",
        "trace_id": "0".repeat(32),
        "span_id": "0".repeat(16),
        "producer_id": "model-eval",
        "producer_boot_id": "018f2a3b-4c5d-7000-8000-000000000002",
        "producer_seq": 1,
        "request_seq": 1,
        "occurred_at": "2026-01-01T00:00:00.000000Z",
        "observed_at": "2026-01-01T00:00:00.000000Z",
        "policy_revision": "policy-r1",
        "example_only": false,
        "evidence_refs": evidence_refs,
        "cause_event_ids": Vec::<String>::new(),
        "payload": payload,
        "sensitivity": "RESTRICTED",
        "integrity": {"state": "pending", "previous_hash": null, "event_hash": null},
    });
    serde_json::from_value(value).unwrap()
}

#[test]
fn model_event_envelope_requires_every_artifact_in_evidence_refs() {
    let mut event = started_event();
    event.status = "requested".to_owned();
    event.input_artifact_id = Some(SAMPLE_INPUT_ARTIFACT_ID.to_owned());

    let envelope = envelope_with_payload(&event, &[]);
    assert!(ModelEvent::validate_envelope(&envelope).is_err());

    let refs = vec![SAMPLE_INPUT_ARTIFACT_ID.to_owned()];
    let envelope = envelope_with_payload(&event, &refs);
    assert!(ModelEvent::validate_envelope(&envelope).is_ok());

    let mut missing_request = envelope_with_payload(&event, &refs);
    missing_request.request_id = None;
    assert!(ModelEvent::validate_envelope(&missing_request).is_err());
}

#[test]
fn model_event_parse_query_event_round_trips_through_json() {
    let mut event = started_event();
    event.status = "success".to_owned();
    event.reason_code = "MODEL_EVALUATED".to_owned();
    event.confidence = Some(0.5);
    event.confidence_status = "provided".to_owned();
    event.input_artifact_id = Some(SAMPLE_INPUT_ARTIFACT_ID.to_owned());
    event.output_artifact_id = Some(SAMPLE_OUTPUT_ARTIFACT_ID.to_owned());
    event.call_artifact_id = Some(SAMPLE_CALL_ARTIFACT_ID.to_owned());
    let payload = serde_json::to_string(&event).unwrap();
    let parsed = ModelEvent::parse_query_event(&payload, "model.responded").unwrap();
    assert_eq!(parsed.model_call_id, SAMPLE_MODEL_CALL_ID);
    assert_eq!(
        parsed.output_artifact_id.as_deref(),
        Some(SAMPLE_OUTPUT_ARTIFACT_ID)
    );

    assert!(ModelEvent::parse_query_event(&payload, "model.timeout").is_err());
}
