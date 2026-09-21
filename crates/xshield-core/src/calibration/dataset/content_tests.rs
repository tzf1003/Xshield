use super::content::{CalibrationContentError, decode_dataset_sample};
use super::{EvaluationProvenance, ModelIdentity};
use crate::{
    calibration::{GroundTruth, Probability, Signal, read_capability::CalibrationSampleReadScope},
    domain::{
        ApprovalRef, ArtifactId, DatasetRevision, LabelRevision, MappingRevision, ModelRevision,
        PromptRevision, ProviderId, TaskRevision, ThresholdPolicyRevision,
    },
};
use serde_json::{Value, json};

fn artifact(index: usize) -> ArtifactId {
    ArtifactId::parse(format!("artifact_018f2a3b-4c5d-7000-8000-{index:012x}")).unwrap()
}

fn source() -> CalibrationSampleReadScope {
    CalibrationSampleReadScope::new(artifact(10), artifact(11))
}

fn model() -> ModelIdentity {
    ModelIdentity::new(
        ProviderId::parse("vercel_ai_gateway").unwrap(),
        "typesafe-ai/jev",
        ModelRevision::parse("jev-1.13.0").unwrap(),
        PromptRevision::parse("prompt-r1").unwrap(),
        None,
    )
    .unwrap()
}

fn provenance() -> EvaluationProvenance {
    EvaluationProvenance::new(
        ApprovalRef::parse("approval-r1").unwrap(),
        DatasetRevision::parse("dataset-r1").unwrap(),
        LabelRevision::parse("labels-r1").unwrap(),
        TaskRevision::parse("task-r1").unwrap(),
        ThresholdPolicyRevision::parse("threshold-r1").unwrap(),
        MappingRevision::parse("risk-map-r1").unwrap(),
        artifact(1),
        artifact(2),
        artifact(3),
        artifact(4),
        model(),
    )
    .unwrap()
}

fn model_json() -> Value {
    json!({
        "provider": "vercel_ai_gateway",
        "provider_model_id": "typesafe-ai/jev",
        "model_revision": "jev-1.13.0",
        "prompt_revision": "prompt-r1",
        "resolved_model_revision": null,
    })
}

fn provenance_json() -> Value {
    json!({
        "approval_ref": "approval-r1",
        "dataset_revision": "dataset-r1",
        "label_revision": "labels-r1",
        "task_revision": "task-r1",
        "threshold_policy_revision": "threshold-r1",
        "mapping_revision": "risk-map-r1",
        "evaluation_manifest_artifact_id": artifact(1).as_str(),
        "training_manifest_artifact_id": artifact(2).as_str(),
        "calibration_manifest_artifact_id": artifact(3).as_str(),
        "label_manifest_artifact_id": artifact(4).as_str(),
        "model": model_json(),
    })
}

fn record_json() -> Value {
    json!({
        "schema_version": 3,
        "model_call_id": "mdl_018f2a3b-4c5d-7000-8000-000000000010",
        "request_id": "req_018f2a3b-4c5d-7000-8000-000000000009",
        "example_only": false,
        "provider": "vercel_ai_gateway",
        "provider_model_id": "typesafe-ai/jev",
        "model_revision": "jev-1.13.0",
        "resolved_model_revision": null,
        "prompt_revision": "prompt-r1",
        "input_artifact_id": artifact(12).as_str(),
        "output_artifact_id": artifact(13).as_str(),
        "question_type": "choice",
        "result": "RISK",
        "probabilities": {"NONE": 0.1, "RISK": 0.9},
        "legend": null,
        "risk_projection": {
            "mapping_revision": "risk-map-r1",
            "malicious_probability": 0.9,
            "benign_probability": 0.1,
            "unknown_probability": 0.0,
            "abstained": false,
            "reason_code": "MODEL_RISK_PROJECTED"
        },
        "provider_confidence": null,
        "confidence_status": "not_provided",
        "probability_semantics": "provider_reported_uncalibrated",
        "usage": {"input_tokens": null, "output_tokens": null, "source": "unavailable"},
        "duration_ms": 10,
        "status": "success",
        "reason_code": "MODEL_EVALUATION_COMPLETED",
        "http_status": 200,
        "capture_status": "complete",
        "retry_after_seconds": null,
        "provider_request_id": null,
        "schema_validation": "valid",
        "provider_internal": "unavailable"
    })
}

fn label_json() -> Value {
    json!({
        "schema_version": 1,
        "kind": "calibration_reviewed_label",
        "model_call_id": "mdl_018f2a3b-4c5d-7000-8000-000000000010",
        "provenance": provenance_json(),
        "ground_truth": "malicious",
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn decode(record: &Value, label: &Value) -> Result<super::DatasetSample, CalibrationContentError> {
    decode_dataset_sample(&provenance(), &source(), &bytes(record), &bytes(label))
}

#[test]
fn decodes_a_closed_role_bound_pair_into_a_dataset_sample() {
    let sample = decode(&record_json(), &label_json()).unwrap();
    assert_eq!(
        sample.sample().model_call_id.as_str(),
        "mdl_018f2a3b-4c5d-7000-8000-000000000010"
    );
    assert_eq!(sample.model_call_artifact_id(), &artifact(10));
    assert_eq!(sample.label_artifact_id(), &artifact(11));
    assert_eq!(sample.model(), &model());
    assert_eq!(
        sample.mapping_revision(),
        &MappingRevision::parse("risk-map-r1").unwrap()
    );
    assert_eq!(sample.sample().ground_truth, GroundTruth::Malicious);
    assert_eq!(
        sample.sample().signal,
        Signal::Risk(Probability::new(0.9).unwrap())
    );
}

#[test]
fn rejects_non_success_or_unmapped_model_records_without_inventing_risk() {
    let mut failed = record_json();
    failed["status"] = json!("timeout");
    assert_eq!(
        decode(&failed, &label_json()),
        Err(CalibrationContentError::ModelStatusIneligible)
    );
    let mut missing_projection = record_json();
    missing_projection["risk_projection"] = Value::Null;
    assert_eq!(
        decode(&missing_projection, &label_json()),
        Err(CalibrationContentError::MappingProjectionMissing)
    );
}

#[test]
fn preserves_unknown_projection_mass_as_an_explicit_unavailable_signal() {
    let mut record = record_json();
    record["risk_projection"]["malicious_probability"] = json!(0.8);
    record["risk_projection"]["unknown_probability"] = json!(0.1);
    record["risk_projection"]["abstained"] = json!(true);
    record["risk_projection"]["reason_code"] = json!("MODEL_RISK_ABSTAINED");
    let sample = decode(&record, &label_json()).unwrap();
    assert_eq!(
        sample.sample().signal,
        Signal::Unavailable(crate::calibration::UnavailableReason::ProbabilityMissing)
    );
}

#[test]
fn rejects_unknown_prohibited_and_duplicate_fields_at_every_depth() {
    let mut unknown = record_json();
    unknown["extension"] = Value::Null;
    assert_eq!(
        decode(&unknown, &label_json()),
        Err(CalibrationContentError::UnknownField)
    );

    let mut prohibited = record_json();
    prohibited["prompt"] = json!("untrusted content must stay out of the DTO");
    assert_eq!(
        decode(&prohibited, &label_json()),
        Err(CalibrationContentError::ProhibitedField)
    );

    let mut nested_prohibited = label_json();
    nested_prohibited["provenance"]["model"]["credentials"] = Value::Null;
    assert_eq!(
        decode(&record_json(), &nested_prohibited),
        Err(CalibrationContentError::ProhibitedField)
    );

    let duplicate = String::from_utf8(bytes(&record_json())).unwrap().replacen(
        "\"schema_version\":3",
        "\"schema_version\":3,\"schema_version\":3",
        1,
    );
    assert_eq!(
        decode_dataset_sample(
            &provenance(),
            &source(),
            duplicate.as_bytes(),
            &bytes(&label_json())
        ),
        Err(CalibrationContentError::DuplicateField)
    );

    let deep_json = format!("{}null{}", "[".repeat(33), "]".repeat(33));
    assert_eq!(
        decode_dataset_sample(
            &provenance(),
            &source(),
            deep_json.as_bytes(),
            &bytes(&label_json()),
        ),
        Err(CalibrationContentError::NestingTooDeep)
    );
}

#[test]
fn rejects_model_mapping_and_full_provenance_drift() {
    let mut wrong_model = record_json();
    wrong_model["provider"] = json!("typesafe");
    assert_eq!(
        decode(&wrong_model, &label_json()),
        Err(CalibrationContentError::ModelIdentityMismatch)
    );

    let mut wrong_mapping = record_json();
    wrong_mapping["risk_projection"]["mapping_revision"] = json!("risk-map-r2");
    assert_eq!(
        decode(&wrong_mapping, &label_json()),
        Err(CalibrationContentError::MappingRevisionMismatch)
    );

    let mut wrong_provenance = label_json();
    wrong_provenance["provenance"]["dataset_revision"] = json!("dataset-r2");
    assert_eq!(
        decode(&record_json(), &wrong_provenance),
        Err(CalibrationContentError::ProvenanceMismatch)
    );
}

#[test]
fn rejects_label_call_mismatch_bad_probabilities_and_source_aliases() {
    let mut wrong_call = label_json();
    wrong_call["model_call_id"] = json!("mdl_018f2a3b-4c5d-7000-8000-000000000012");
    assert_eq!(
        decode(&record_json(), &wrong_call),
        Err(CalibrationContentError::LabelModelCallMismatch)
    );

    let mut invalid_probability = record_json();
    invalid_probability["risk_projection"]["malicious_probability"] = json!(2.0);
    assert_eq!(
        decode(&invalid_probability, &label_json()),
        Err(CalibrationContentError::InvalidProbability)
    );

    let aliased_source = CalibrationSampleReadScope::new(artifact(10), artifact(10));
    assert_eq!(
        decode_dataset_sample(
            &provenance(),
            &aliased_source,
            &bytes(&record_json()),
            &bytes(&label_json()),
        ),
        Err(CalibrationContentError::SampleEvidenceAliased)
    );
}

#[test]
fn reason_codes_are_stable_and_content_free() {
    let cases = [
        (
            CalibrationContentError::TooLarge,
            "CALIBRATION_SAMPLE_CONTENT_LIMIT_EXCEEDED",
        ),
        (
            CalibrationContentError::InvalidJson,
            "CALIBRATION_SAMPLE_CONTENT_JSON_INVALID",
        ),
        (
            CalibrationContentError::DuplicateField,
            "CALIBRATION_SAMPLE_CONTENT_FIELD_DUPLICATE",
        ),
        (
            CalibrationContentError::MissingField,
            "CALIBRATION_SAMPLE_CONTENT_FIELD_MISSING",
        ),
        (
            CalibrationContentError::UnknownField,
            "CALIBRATION_SAMPLE_CONTENT_FIELD_UNKNOWN",
        ),
        (
            CalibrationContentError::ProhibitedField,
            "CALIBRATION_SAMPLE_CONTENT_FIELD_PROHIBITED",
        ),
        (
            CalibrationContentError::InvalidSchema,
            "CALIBRATION_SAMPLE_CONTENT_SCHEMA_INVALID",
        ),
        (
            CalibrationContentError::InvalidValue,
            "CALIBRATION_SAMPLE_CONTENT_VALUE_INVALID",
        ),
        (
            CalibrationContentError::InvalidProbability,
            "CALIBRATION_SAMPLE_CONTENT_PROBABILITY_INVALID",
        ),
        (
            CalibrationContentError::ModelIdentityMismatch,
            "CALIBRATION_SAMPLE_CONTENT_MODEL_IDENTITY_MISMATCH",
        ),
        (
            CalibrationContentError::MappingRevisionMismatch,
            "CALIBRATION_SAMPLE_CONTENT_MAPPING_REVISION_MISMATCH",
        ),
        (
            CalibrationContentError::ProvenanceMismatch,
            "CALIBRATION_SAMPLE_CONTENT_PROVENANCE_MISMATCH",
        ),
        (
            CalibrationContentError::LabelModelCallMismatch,
            "CALIBRATION_SAMPLE_CONTENT_LABEL_CALL_MISMATCH",
        ),
        (
            CalibrationContentError::SampleEvidenceAliased,
            "CALIBRATION_SAMPLE_CONTENT_EVIDENCE_ALIASED",
        ),
        (
            CalibrationContentError::MappingProjectionMissing,
            "CALIBRATION_SAMPLE_CONTENT_MAPPING_PROJECTION_MISSING",
        ),
        (
            CalibrationContentError::ModelStatusIneligible,
            "CALIBRATION_SAMPLE_CONTENT_MODEL_STATUS_INELIGIBLE",
        ),
        (
            CalibrationContentError::NestingTooDeep,
            "CALIBRATION_SAMPLE_CONTENT_NESTING_TOO_DEEP",
        ),
    ];
    for (error, reason_code) in cases {
        assert_eq!(error.reason_code(), reason_code);
        assert_eq!(error.to_string(), reason_code);
    }
}
