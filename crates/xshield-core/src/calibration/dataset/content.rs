//! Strict, content-minimising calibration sample DTOs.
//!
//! This module is an integrity boundary between already-authorized evidence
//! bytes and [`super::DatasetSample`]. It accepts the existing schema-v3
//! `model_call` record and a reviewed-label DTO with frozen evaluation
//! provenance. It deliberately does not decode manifests or decide that two
//! external artifacts are content independent. A worker must authenticate
//! artifact identity, role, and slot through the calibration reader before
//! calling this pure decoder.

use super::{DatasetError, DatasetSample, EvaluationProvenance, ModelIdentity};
use crate::{
    calibration::read_capability::CalibrationSampleReadScope,
    calibration::{GroundTruth, Probability, Signal, UnavailableReason},
    domain::{
        ApprovalRef, ArtifactId, DatasetRevision, FieldName, LabelRevision, MappingRevision,
        ModelCallId, ModelRevision, PromptRevision, ProviderId, RequestId, TaskRevision,
        ThresholdPolicyRevision,
    },
};
use serde::{Deserialize, Deserializer, de};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeSet, fmt};

/// Immutable schema version accepted from existing `model_call` evidence.
pub const CALIBRATION_MODEL_CALL_RECORD_SCHEMA_VERSION: u8 = 3;
/// Immutable schema version for a reviewed-label calibration DTO.
pub const CALIBRATION_REVIEWED_LABEL_SCHEMA_VERSION: u8 = 1;
/// Fixed kind carried by a reviewed-label calibration DTO.
pub const CALIBRATION_REVIEWED_LABEL_KIND: &str = "calibration_reviewed_label";

const MAX_CALIBRATION_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_JSON_NESTING: usize = 32;
const MAX_PROVIDER_REQUEST_ID_BYTES: usize = 256;
const MAX_SCORE_LEVELS: usize = 10;
const MAX_SCORE_VALUE: f64 = 9.0;
const MAX_MAPPING_OUTCOMES: usize = 32;

/// Decodes one role-bound source pair into a provenance-bound dataset sample.
///
/// `source` identifies the two artifact IDs that an already-authorized reader
/// authenticated for one capability sample slot. `model_call_record_bytes` and
/// `reviewed_label_bytes` must be the corresponding plaintext in that order.
/// The model record is the existing schema-v3 `model_call` evidence, whose
/// role is established by the capability rather than an in-body kind field.
/// Its fixed metadata is validated then discarded; no request bodies, prompts,
/// credentials, provider payloads, or lease data enter the returned sample.
///
/// This verifies the model record's identity and mapping against `provenance`,
/// and the reviewed label's entire frozen provenance against the same value.
/// It cannot establish that the two objects were independently authored or
/// that manifests and samples have no overlapping external content.
///
/// # Errors
/// Returns [`CalibrationContentError`] for malformed, oversized, duplicate,
/// unknown, prohibited, drifting, or inconsistent input. It performs no I/O,
/// audit, authorization, model, policy, or persistence side effect, and its
/// errors contain no evidence content.
pub fn decode_dataset_sample(
    provenance: &EvaluationProvenance,
    source: &CalibrationSampleReadScope,
    model_call_record_bytes: &[u8],
    reviewed_label_bytes: &[u8],
) -> Result<DatasetSample, CalibrationContentError> {
    let record = decode_model_call_record(model_call_record_bytes)?;
    decode_dataset_sample_from_model_call(provenance, source, record, reviewed_label_bytes)
}

/// Content-minimising, validated state from a schema-v3 model-call record.
///
/// This value deliberately retains only the typed call identity, frozen model
/// identity, mapping revision, and projected signal needed to join one
/// reviewed label. It has no accessor for request, provider, or evidence-body
/// fields. A reader may drop the plaintext after constructing it.
pub struct DecodedModelCall(ModelCallRecordDto);

/// Decodes one schema-v3 model-call record into a bounded, content-free join state.
///
/// # Errors
/// Returns [`CalibrationContentError`] if the record is malformed, not a
/// successful call, or lacks an approved risk projection. It performs no I/O
/// or authorization and does not retain the supplied plaintext.
pub fn decode_model_call_record(
    model_call_record_bytes: &[u8],
) -> Result<DecodedModelCall, CalibrationContentError> {
    parse_model_call_record(model_call_record_bytes).map(DecodedModelCall)
}

/// Decodes one reviewed label and creates a sample from a validated model-call state.
///
/// The opaque `record` must have been decoded from the model-call object for
/// `source`; callers can release that object's plaintext before invoking this
/// function. `reviewed_label_bytes` is read only for this call and is not
/// retained afterwards.
///
/// # Errors
/// Returns [`CalibrationContentError`] when the record or label drifts from
/// frozen provenance, the label targets another call, or the source aliases
/// its evidence roles. It performs no I/O, audit, or persistence side effect.
pub fn decode_dataset_sample_from_model_call(
    provenance: &EvaluationProvenance,
    source: &CalibrationSampleReadScope,
    record: DecodedModelCall,
    reviewed_label_bytes: &[u8],
) -> Result<DatasetSample, CalibrationContentError> {
    let record = record.0;
    if record.model != *provenance.model() {
        return Err(CalibrationContentError::ModelIdentityMismatch);
    }
    if record.mapping_revision != *provenance.mapping_revision() {
        return Err(CalibrationContentError::MappingRevisionMismatch);
    }

    let label = parse_reviewed_label(reviewed_label_bytes)?;
    if label.provenance != *provenance {
        return Err(CalibrationContentError::ProvenanceMismatch);
    }
    if label.model_call_id != record.model_call_id {
        return Err(CalibrationContentError::LabelModelCallMismatch);
    }

    DatasetSample::new(
        record.model_call_id,
        source.model_call_artifact_id().clone(),
        source.label_artifact_id().clone(),
        record.model,
        record.mapping_revision,
        label.ground_truth,
        record.signal,
    )
    .map_err(|error| match error {
        DatasetError::SampleEvidenceAliased => CalibrationContentError::SampleEvidenceAliased,
        _ => CalibrationContentError::InvalidValue,
    })
}

struct ModelCallRecordDto {
    model_call_id: ModelCallId,
    model: ModelIdentity,
    mapping_revision: MappingRevision,
    signal: Signal,
}

struct ReviewedLabelDto {
    model_call_id: ModelCallId,
    provenance: EvaluationProvenance,
    ground_truth: GroundTruth,
}

fn parse_model_call_record(bytes: &[u8]) -> Result<ModelCallRecordDto, CalibrationContentError> {
    let mut fields = object_fields(
        parse_document(bytes)?,
        &[
            "capture_status",
            "confidence_status",
            "duration_ms",
            "example_only",
            "http_status",
            "input_artifact_id",
            "legend",
            "model_call_id",
            "model_revision",
            "output_artifact_id",
            "probabilities",
            "probability_semantics",
            "prompt_revision",
            "provider",
            "provider_confidence",
            "provider_internal",
            "provider_model_id",
            "provider_request_id",
            "question_type",
            "reason_code",
            "request_id",
            "resolved_model_revision",
            "result",
            "retry_after_seconds",
            "risk_projection",
            "schema_version",
            "schema_validation",
            "status",
            "usage",
        ],
    )?;
    if take_u8(&mut fields, "schema_version")? != CALIBRATION_MODEL_CALL_RECORD_SCHEMA_VERSION {
        return Err(CalibrationContentError::InvalidSchema);
    }
    let model_call_id = ModelCallId::parse(take_string(&mut fields, "model_call_id")?)
        .map_err(|_| CalibrationContentError::InvalidValue)?;
    RequestId::parse(take_string(&mut fields, "request_id")?)
        .map_err(|_| CalibrationContentError::InvalidValue)?;
    if take_bool(&mut fields, "example_only")? {
        return Err(CalibrationContentError::InvalidValue);
    }
    let model = parse_model_identity(&mut fields)?;
    parse_artifact_id(&mut fields, "input_artifact_id")?;
    parse_optional_artifact_id(&mut fields, "output_artifact_id")?;
    let question_type = parse_question_type(&take_string(&mut fields, "question_type")?)?;
    parse_result(take_value(&mut fields, "result")?, question_type)?;
    parse_probabilities(take_value(&mut fields, "probabilities")?, question_type)?;
    parse_legend(take_value(&mut fields, "legend")?, question_type)?;
    let projection = parse_risk_projection(take_value(&mut fields, "risk_projection")?)?;
    let provider_confidence = take_value(&mut fields, "provider_confidence")?;
    parse_optional_probability(&provider_confidence)?;
    parse_confidence_status(
        &take_string(&mut fields, "confidence_status")?,
        question_type,
    )?;
    if take_string(&mut fields, "probability_semantics")? != "provider_reported_uncalibrated"
        || take_string(&mut fields, "provider_internal")? != "unavailable"
    {
        return Err(CalibrationContentError::InvalidValue);
    }
    parse_usage(take_value(&mut fields, "usage")?)?;
    let status = take_string(&mut fields, "status")?;
    if !matches!(
        status.as_str(),
        "success" | "error" | "timeout" | "cancelled"
    ) {
        return Err(CalibrationContentError::InvalidValue);
    }
    FieldName::parse(take_string(&mut fields, "reason_code")?)
        .map_err(|_| CalibrationContentError::InvalidValue)?;
    take_u64(&mut fields, "duration_ms")?;
    parse_optional_http_status(take_value(&mut fields, "http_status")?)?;
    parse_capture_status(&take_string(&mut fields, "capture_status")?)?;
    parse_optional_u32(take_value(&mut fields, "retry_after_seconds")?)?;
    parse_optional_provider_request_id(take_value(&mut fields, "provider_request_id")?)?;
    if !matches!(
        take_string(&mut fields, "schema_validation")?.as_str(),
        "valid" | "invalid" | "unavailable"
    ) {
        return Err(CalibrationContentError::InvalidValue);
    }
    if status != "success" {
        return Err(CalibrationContentError::ModelStatusIneligible);
    }
    let projection = projection.ok_or(CalibrationContentError::MappingProjectionMissing)?;
    Ok(ModelCallRecordDto {
        model_call_id,
        model,
        mapping_revision: projection.mapping_revision,
        signal: projection.signal,
    })
}

fn parse_reviewed_label(bytes: &[u8]) -> Result<ReviewedLabelDto, CalibrationContentError> {
    let mut fields = object_fields(
        parse_document(bytes)?,
        &[
            "ground_truth",
            "kind",
            "model_call_id",
            "provenance",
            "schema_version",
        ],
    )?;
    if take_u8(&mut fields, "schema_version")? != CALIBRATION_REVIEWED_LABEL_SCHEMA_VERSION
        || take_string(&mut fields, "kind")? != CALIBRATION_REVIEWED_LABEL_KIND
    {
        return Err(CalibrationContentError::InvalidSchema);
    }
    let ground_truth = match take_string(&mut fields, "ground_truth")?.as_str() {
        "benign" => GroundTruth::Benign,
        "malicious" => GroundTruth::Malicious,
        "unknown" => GroundTruth::Unknown,
        _ => return Err(CalibrationContentError::InvalidValue),
    };
    Ok(ReviewedLabelDto {
        model_call_id: ModelCallId::parse(take_string(&mut fields, "model_call_id")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        provenance: parse_provenance(take_value(&mut fields, "provenance")?)?,
        ground_truth,
    })
}

fn parse_model(value: Value) -> Result<ModelIdentity, CalibrationContentError> {
    let mut fields = object_fields(
        value,
        &[
            "model_revision",
            "prompt_revision",
            "provider",
            "provider_model_id",
            "resolved_model_revision",
        ],
    )?;
    parse_model_identity(&mut fields)
}

fn parse_model_identity(
    fields: &mut Map<String, Value>,
) -> Result<ModelIdentity, CalibrationContentError> {
    let resolved_model_revision = match take_value(fields, "resolved_model_revision")? {
        Value::Null => None,
        Value::String(value) => {
            Some(ModelRevision::parse(value).map_err(|_| CalibrationContentError::InvalidValue)?)
        }
        _ => return Err(CalibrationContentError::InvalidValue),
    };
    ModelIdentity::new(
        ProviderId::parse(take_string(fields, "provider")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        take_string(fields, "provider_model_id")?,
        ModelRevision::parse(take_string(fields, "model_revision")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        PromptRevision::parse(take_string(fields, "prompt_revision")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        resolved_model_revision,
    )
    .map_err(|_| CalibrationContentError::InvalidValue)
}

struct RiskProjectionDto {
    mapping_revision: MappingRevision,
    signal: Signal,
}

#[derive(Clone, Copy)]
enum QuestionType {
    Choice,
    Score,
    Noul,
}

fn parse_question_type(value: &str) -> Result<QuestionType, CalibrationContentError> {
    match value {
        "choice" => Ok(QuestionType::Choice),
        "score" => Ok(QuestionType::Score),
        "noul" => Ok(QuestionType::Noul),
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn parse_result(value: Value, question_type: QuestionType) -> Result<(), CalibrationContentError> {
    match (value, question_type) {
        (Value::String(value), QuestionType::Choice) => FieldName::parse(value)
            .map(|_| ())
            .map_err(|_| CalibrationContentError::InvalidValue),
        (Value::Number(value), QuestionType::Score) => value
            .as_f64()
            .filter(|value| value.is_finite() && (0.0..=MAX_SCORE_VALUE).contains(value))
            .map(|_| ())
            .ok_or(CalibrationContentError::InvalidValue),
        (Value::Number(value), QuestionType::Noul) => value
            .as_f64()
            .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))
            .map(|_| ())
            .ok_or(CalibrationContentError::InvalidProbability),
        (Value::Null, _) => Ok(()),
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn parse_probabilities(
    value: Value,
    question_type: QuestionType,
) -> Result<(), CalibrationContentError> {
    let Value::Object(values) = value else {
        return Err(CalibrationContentError::InvalidValue);
    };
    let permitted_count = match question_type {
        QuestionType::Choice => (2..=MAX_MAPPING_OUTCOMES).contains(&values.len()),
        QuestionType::Score => (2..=MAX_SCORE_LEVELS).contains(&values.len()),
        QuestionType::Noul => values.is_empty(),
    };
    if !permitted_count
        || values.iter().any(|(name, value)| {
            FieldName::parse(name.clone()).is_err() || parse_probability_value(value).is_err()
        })
        || (!values.is_empty()
            && (values.values().filter_map(Value::as_f64).sum::<f64>() - 1.0).abs() > 1e-6)
    {
        return Err(CalibrationContentError::InvalidValue);
    }
    Ok(())
}

fn parse_legend(value: Value, question_type: QuestionType) -> Result<(), CalibrationContentError> {
    match value {
        Value::Null if !matches!(question_type, QuestionType::Score) => Ok(()),
        Value::Object(values) if matches!(question_type, QuestionType::Score) => {
            if values.is_empty() || values.len() > MAX_SCORE_LEVELS {
                return Err(CalibrationContentError::InvalidValue);
            }
            for (level, label) in values {
                FieldName::parse(level).map_err(|_| CalibrationContentError::InvalidValue)?;
                let Value::String(label) = label else {
                    return Err(CalibrationContentError::InvalidValue);
                };
                if label.trim().is_empty() || label.chars().count() > 512 {
                    return Err(CalibrationContentError::InvalidValue);
                }
            }
            Ok(())
        }
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn parse_risk_projection(
    value: Value,
) -> Result<Option<RiskProjectionDto>, CalibrationContentError> {
    let Value::Object(mut fields) = value else {
        return if matches!(value, Value::Null) {
            Ok(None)
        } else {
            Err(CalibrationContentError::InvalidValue)
        };
    };
    reject_prohibited_fields(&fields)?;
    require_exact_fields(
        &fields,
        &[
            "abstained",
            "benign_probability",
            "malicious_probability",
            "mapping_revision",
            "reason_code",
            "unknown_probability",
        ],
    )?;
    let mapping_revision = MappingRevision::parse(take_string(&mut fields, "mapping_revision")?)
        .map_err(|_| CalibrationContentError::InvalidValue)?;
    let benign = parse_probability_value(&take_value(&mut fields, "benign_probability")?)?;
    let malicious = parse_probability_value(&take_value(&mut fields, "malicious_probability")?)?;
    let unknown = parse_probability_value(&take_value(&mut fields, "unknown_probability")?)?;
    if ((benign + malicious + unknown) - 1.0).abs() > 1e-6 {
        return Err(CalibrationContentError::InvalidProbability);
    }
    let abstained = take_bool(&mut fields, "abstained")?;
    let reason_code = take_string(&mut fields, "reason_code")?;
    let signal = match (abstained, unknown > 0.0, reason_code.as_str()) {
        (true, true, "MODEL_RISK_ABSTAINED") => {
            Signal::Unavailable(UnavailableReason::ProbabilityMissing)
        }
        (false, false, "MODEL_RISK_PROJECTED") => Signal::Risk(
            Probability::new(malicious).map_err(|_| CalibrationContentError::InvalidProbability)?,
        ),
        _ => return Err(CalibrationContentError::InvalidValue),
    };
    Ok(Some(RiskProjectionDto {
        mapping_revision,
        signal,
    }))
}

fn parse_provenance(value: Value) -> Result<EvaluationProvenance, CalibrationContentError> {
    let mut fields = object_fields(
        value,
        &[
            "approval_ref",
            "calibration_manifest_artifact_id",
            "dataset_revision",
            "evaluation_manifest_artifact_id",
            "label_manifest_artifact_id",
            "label_revision",
            "mapping_revision",
            "model",
            "task_revision",
            "threshold_policy_revision",
            "training_manifest_artifact_id",
        ],
    )?;
    let model = parse_model(take_value(&mut fields, "model")?)?;
    EvaluationProvenance::new(
        ApprovalRef::parse(take_string(&mut fields, "approval_ref")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        DatasetRevision::parse(take_string(&mut fields, "dataset_revision")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        LabelRevision::parse(take_string(&mut fields, "label_revision")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        TaskRevision::parse(take_string(&mut fields, "task_revision")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        ThresholdPolicyRevision::parse(take_string(&mut fields, "threshold_policy_revision")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        MappingRevision::parse(take_string(&mut fields, "mapping_revision")?)
            .map_err(|_| CalibrationContentError::InvalidValue)?,
        parse_artifact_id(&mut fields, "evaluation_manifest_artifact_id")?,
        parse_artifact_id(&mut fields, "training_manifest_artifact_id")?,
        parse_artifact_id(&mut fields, "calibration_manifest_artifact_id")?,
        parse_artifact_id(&mut fields, "label_manifest_artifact_id")?,
        model,
    )
    .map_err(|_| CalibrationContentError::InvalidValue)
}

fn parse_artifact_id(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<ArtifactId, CalibrationContentError> {
    ArtifactId::parse(take_string(fields, field)?)
        .map_err(|_| CalibrationContentError::InvalidValue)
}

fn parse_optional_artifact_id(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<(), CalibrationContentError> {
    match take_value(fields, field)? {
        Value::Null => Ok(()),
        Value::String(value) => ArtifactId::parse(value)
            .map(|_| ())
            .map_err(|_| CalibrationContentError::InvalidValue),
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn parse_optional_probability(value: &Value) -> Result<(), CalibrationContentError> {
    if value.is_null() {
        Ok(())
    } else {
        parse_probability_value(value).map(|_| ())
    }
}

fn parse_probability_value(value: &Value) -> Result<f64, CalibrationContentError> {
    let number = value
        .as_f64()
        .filter(|number| number.is_finite() && (0.0..=1.0).contains(number))
        .ok_or(CalibrationContentError::InvalidProbability)?;
    Ok(number)
}

fn parse_confidence_status(
    value: &str,
    question_type: QuestionType,
) -> Result<(), CalibrationContentError> {
    match value {
        "provided" | "not_provided" if !matches!(question_type, QuestionType::Noul) => Ok(()),
        "not_applicable" if matches!(question_type, QuestionType::Noul) => Ok(()),
        "unavailable" => Ok(()),
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn parse_usage(value: Value) -> Result<(), CalibrationContentError> {
    let mut fields = object_fields(value, &["input_tokens", "output_tokens", "source"])?;
    parse_optional_u64(take_value(&mut fields, "input_tokens")?)?;
    parse_optional_u64(take_value(&mut fields, "output_tokens")?)?;
    if !matches!(
        take_string(&mut fields, "source")?.as_str(),
        "provider" | "unavailable"
    ) {
        return Err(CalibrationContentError::InvalidValue);
    }
    Ok(())
}

fn parse_capture_status(value: &str) -> Result<(), CalibrationContentError> {
    if matches!(
        value,
        "complete"
            | "unavailable"
            | "excluded_policy"
            | "partial_timeout"
            | "partial_limit"
            | "partial_transport"
    ) {
        Ok(())
    } else {
        Err(CalibrationContentError::InvalidValue)
    }
}

fn parse_optional_http_status(value: Value) -> Result<(), CalibrationContentError> {
    match value {
        Value::Null => Ok(()),
        Value::Number(number)
            if number
                .as_u64()
                .is_some_and(|value| (100..=599).contains(&value)) =>
        {
            Ok(())
        }
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn parse_optional_provider_request_id(value: Value) -> Result<(), CalibrationContentError> {
    match value {
        Value::Null => Ok(()),
        Value::String(value)
            if !value.is_empty() && value.len() <= MAX_PROVIDER_REQUEST_ID_BYTES =>
        {
            Ok(())
        }
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn parse_optional_u32(value: Value) -> Result<(), CalibrationContentError> {
    match value {
        Value::Null => Ok(()),
        Value::Number(number)
            if number
                .as_u64()
                .is_some_and(|value| u32::try_from(value).is_ok()) =>
        {
            Ok(())
        }
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn parse_optional_u64(value: Value) -> Result<(), CalibrationContentError> {
    match value {
        Value::Null => Ok(()),
        Value::Number(number) if number.as_u64().is_some() => Ok(()),
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn parse_document(bytes: &[u8]) -> Result<Value, CalibrationContentError> {
    if bytes.len() > MAX_CALIBRATION_CONTENT_BYTES {
        return Err(CalibrationContentError::TooLarge);
    }
    if exceeds_nesting_limit(bytes) {
        return Err(CalibrationContentError::NestingTooDeep);
    }
    match serde_json::from_slice::<UniqueJson>(bytes) {
        Ok(value) => Ok(value.0),
        Err(error) if error.to_string().contains("duplicate JSON object key") => {
            Err(CalibrationContentError::DuplicateField)
        }
        Err(_) => Err(CalibrationContentError::InvalidJson),
    }
}

fn exceeds_nesting_limit(bytes: &[u8]) -> bool {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_NESTING {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

fn object_fields(
    value: Value,
    expected: &[&str],
) -> Result<Map<String, Value>, CalibrationContentError> {
    let Value::Object(fields) = value else {
        return Err(CalibrationContentError::InvalidValue);
    };
    reject_prohibited_fields(&fields)?;
    require_exact_fields(&fields, expected)?;
    Ok(fields)
}

fn reject_prohibited_fields(fields: &Map<String, Value>) -> Result<(), CalibrationContentError> {
    if fields.keys().any(|field| prohibited_field(field)) {
        return Err(CalibrationContentError::ProhibitedField);
    }
    Ok(())
}

fn require_exact_fields(
    fields: &Map<String, Value>,
    expected: &[&str],
) -> Result<(), CalibrationContentError> {
    if fields
        .keys()
        .any(|field| !expected.contains(&field.as_str()))
    {
        return Err(CalibrationContentError::UnknownField);
    }
    if expected.iter().any(|field| !fields.contains_key(*field)) {
        return Err(CalibrationContentError::MissingField);
    }
    Ok(())
}

fn prohibited_field(value: &str) -> bool {
    matches!(
        value,
        "access_token"
            | "api_key"
            | "authorization"
            | "body"
            | "cookie"
            | "cookies"
            | "credential"
            | "credentials"
            | "lease_handle"
            | "lease_id"
            | "model_output"
            | "password"
            | "prompt"
            | "provider_output"
            | "provider_response"
            | "reader_receipt"
            | "secret"
            | "secrets"
            | "token"
            | "tokens"
            | "untrusted_content"
    )
}

fn take_value(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<Value, CalibrationContentError> {
    fields
        .remove(field)
        .ok_or(CalibrationContentError::MissingField)
}

fn take_string(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<String, CalibrationContentError> {
    match take_value(fields, field)? {
        Value::String(value) => Ok(value),
        _ => Err(CalibrationContentError::InvalidValue),
    }
}

fn take_u8(fields: &mut Map<String, Value>, field: &str) -> Result<u8, CalibrationContentError> {
    take_value(fields, field)?
        .as_u64()
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(CalibrationContentError::InvalidValue)
}

fn take_u64(fields: &mut Map<String, Value>, field: &str) -> Result<u64, CalibrationContentError> {
    take_value(fields, field)?
        .as_u64()
        .ok_or(CalibrationContentError::InvalidValue)
}

fn take_bool(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<bool, CalibrationContentError> {
    take_value(fields, field)?
        .as_bool()
        .ok_or(CalibrationContentError::InvalidValue)
}

/// Closed, content-free failures for calibration sample DTO decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationContentError {
    /// A record or label exceeded the per-object plaintext ceiling.
    TooLarge,
    /// Bytes were not valid JSON.
    InvalidJson,
    /// An object contained the same JSON member name more than once.
    DuplicateField,
    /// A required fixed-schema field was absent.
    MissingField,
    /// A field was outside the fixed schema.
    UnknownField,
    /// A field name could carry secrets or raw evidence outside this DTO boundary.
    ProhibitedField,
    /// The schema version or fixed kind was not accepted.
    InvalidSchema,
    /// A scalar, identifier, enum, or nested object was invalid.
    InvalidValue,
    /// A projected probability was nonfinite, out of range, or noncanonical.
    InvalidProbability,
    /// The selected model record differed from frozen model provenance.
    ModelIdentityMismatch,
    /// The selected model record differed from frozen mapping provenance.
    MappingRevisionMismatch,
    /// The reviewed label differed from the evaluation's frozen provenance.
    ProvenanceMismatch,
    /// The reviewed label was not for the selected model call.
    LabelModelCallMismatch,
    /// The selected source pair reused one artifact for both semantic roles.
    SampleEvidenceAliased,
    /// A schema-v3 record has no approved risk projection to bind its mapping.
    MappingProjectionMissing,
    /// A non-success model terminal is not a complete calibration sample.
    ModelStatusIneligible,
    /// JSON nesting exceeded the bounded decoder budget.
    NestingTooDeep,
}

impl CalibrationContentError {
    /// Returns the stable, payload-free reason code for caller-owned audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::TooLarge => "CALIBRATION_SAMPLE_CONTENT_LIMIT_EXCEEDED",
            Self::InvalidJson => "CALIBRATION_SAMPLE_CONTENT_JSON_INVALID",
            Self::DuplicateField => "CALIBRATION_SAMPLE_CONTENT_FIELD_DUPLICATE",
            Self::MissingField => "CALIBRATION_SAMPLE_CONTENT_FIELD_MISSING",
            Self::UnknownField => "CALIBRATION_SAMPLE_CONTENT_FIELD_UNKNOWN",
            Self::ProhibitedField => "CALIBRATION_SAMPLE_CONTENT_FIELD_PROHIBITED",
            Self::InvalidSchema => "CALIBRATION_SAMPLE_CONTENT_SCHEMA_INVALID",
            Self::InvalidValue => "CALIBRATION_SAMPLE_CONTENT_VALUE_INVALID",
            Self::InvalidProbability => "CALIBRATION_SAMPLE_CONTENT_PROBABILITY_INVALID",
            Self::ModelIdentityMismatch => "CALIBRATION_SAMPLE_CONTENT_MODEL_IDENTITY_MISMATCH",
            Self::MappingRevisionMismatch => "CALIBRATION_SAMPLE_CONTENT_MAPPING_REVISION_MISMATCH",
            Self::ProvenanceMismatch => "CALIBRATION_SAMPLE_CONTENT_PROVENANCE_MISMATCH",
            Self::LabelModelCallMismatch => "CALIBRATION_SAMPLE_CONTENT_LABEL_CALL_MISMATCH",
            Self::SampleEvidenceAliased => "CALIBRATION_SAMPLE_CONTENT_EVIDENCE_ALIASED",
            Self::MappingProjectionMissing => {
                "CALIBRATION_SAMPLE_CONTENT_MAPPING_PROJECTION_MISSING"
            }
            Self::ModelStatusIneligible => "CALIBRATION_SAMPLE_CONTENT_MODEL_STATUS_INELIGIBLE",
            Self::NestingTooDeep => "CALIBRATION_SAMPLE_CONTENT_NESTING_TOO_DEEP",
        }
    }
}

impl fmt::Display for CalibrationContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for CalibrationContentError {}

/// JSON tree decoder that rejects duplicate names at every object depth.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> de::Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(UniqueJson(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            values.push(value.0);
        }
        Ok(UniqueJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut seen = BTreeSet::new();
        while let Some((key, value)) = map.next_entry::<String, UniqueJson>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            values.insert(key, value.0);
        }
        Ok(UniqueJson(Value::Object(values)))
    }
}
