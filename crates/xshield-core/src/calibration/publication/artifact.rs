//! Canonical protected body for one offline calibration report artifact.
//!
//! The public publication event deliberately contains only a small provenance
//! projection. This module contains the separately encrypted report body: it
//! retains aggregate metrics and the ordered opaque source tuple set, but never
//! labels, probability samples, model payloads, prompts, credentials, or lease
//! material. Its JSON representation is canonical so a storage adapter can bind
//! exact plaintext bytes to the report artifact it persists.

use super::CalibrationReportPublication;
use crate::{
    calibration::{
        ConfusionCounts, Probability, RELIABILITY_BIN_COUNT, Rate, ReliabilityBin, Report,
        Thresholds, UnavailableCounts,
        dataset::{EvaluationProvenance, EvaluationReport, ModelIdentity},
    },
    domain::{
        ApprovalRef, ArtifactId, CalibrationReportId, DatasetRevision, LabelRevision,
        MappingRevision, ModelCallId, ModelRevision, PromptRevision, ProviderId, TaskRevision,
        ThresholdPolicyRevision,
    },
};
use serde::{Deserialize, Deserializer, de};
use serde_json::{Map, Number, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Immutable schema version for a protected calibration report artifact.
pub const CALIBRATION_REPORT_ARTIFACT_SCHEMA_VERSION: u8 = 1;
/// Fixed evidence kind for a protected calibration report artifact.
pub const CALIBRATION_REPORT_ARTIFACT_KIND: &str = "calibration_evaluation_report";
/// Fixed media type for a protected calibration report artifact.
pub const CALIBRATION_REPORT_ARTIFACT_CONTENT_TYPE: &str =
    "application/vnd.xshield.calibration-report+json";

const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// A source tuple retained by the protected report in evaluated sample order.
///
/// This DTO contains opaque identifiers only. The model-call record and label
/// object stay behind their own evidence access controls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationReportArtifactSource {
    sample_index: u32,
    model_call_id: ModelCallId,
    model_call_artifact_id: ArtifactId,
    label_artifact_id: ArtifactId,
}

impl CalibrationReportArtifactSource {
    /// Returns the zero-based position frozen by the completed evaluation.
    #[must_use]
    pub const fn sample_index(&self) -> u32 {
        self.sample_index
    }

    /// Returns the opaque model-call identity selected for this evaluation.
    #[must_use]
    pub const fn model_call_id(&self) -> &ModelCallId {
        &self.model_call_id
    }

    /// Returns the encrypted model-call-record artifact reference.
    #[must_use]
    pub const fn model_call_artifact_id(&self) -> &ArtifactId {
        &self.model_call_artifact_id
    }

    /// Returns the encrypted reviewed-label artifact reference.
    #[must_use]
    pub const fn label_artifact_id(&self) -> &ArtifactId {
        &self.label_artifact_id
    }
}

/// Protected, deterministic body for one completed offline calibration report.
///
/// The body has no authorization, vault, journal, database, outbox, model, or
/// policy-publication side effect. A worker must only construct it after the
/// controlled reader has completed its plaintext-release audit boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct CalibrationReportArtifact {
    report_id: CalibrationReportId,
    report_artifact_id: ArtifactId,
    provenance: EvaluationProvenance,
    thresholds: Thresholds,
    sources: Vec<CalibrationReportArtifactSource>,
    metrics: Report,
}

impl CalibrationReportArtifact {
    /// Constructs the protected report body from the frozen domain result.
    ///
    /// The publication projection must describe this exact report provenance,
    /// and its report artifact must be distinct from every manifest and source
    /// reference. Floating values are normalized before retention: finite
    /// negative zero becomes positive zero and all other finite IEEE-754 bits
    /// remain unchanged. This constructor performs no I/O.
    ///
    /// # Errors
    /// Returns [`CalibrationReportArtifactError`] when publication metadata does
    /// not match the report, source references violate the report boundary, or
    /// an otherwise unrepresentable metric value is encountered.
    pub fn from_evaluation(
        publication: &CalibrationReportPublication,
        report: &EvaluationReport,
    ) -> Result<Self, CalibrationReportArtifactError> {
        if !publication_matches_report(publication, report) {
            return Err(CalibrationReportArtifactError::PublicationMismatch);
        }
        let sources = report
            .sources()
            .iter()
            .enumerate()
            .map(|(index, source)| {
                Ok(CalibrationReportArtifactSource {
                    sample_index: u32::try_from(index)
                        .map_err(|_| CalibrationReportArtifactError::SourceSetInvalid)?,
                    model_call_id: source.model_call_id().clone(),
                    model_call_artifact_id: source.model_call_artifact_id().clone(),
                    label_artifact_id: source.label_artifact_id().clone(),
                })
            })
            .collect::<Result<Vec<_>, CalibrationReportArtifactError>>()?;
        let thresholds = canonical_thresholds(report.thresholds())?;
        let metrics = canonical_metrics(report.metrics().clone())?;
        let artifact = Self {
            report_id: publication.report_id().clone(),
            report_artifact_id: publication.report_artifact_id().clone(),
            provenance: report.provenance().clone(),
            thresholds,
            sources,
            metrics,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Decodes only the exact canonical JSON representation of a report body.
    ///
    /// The parser rejects duplicate, unknown, and prohibited fields before it
    /// accepts the document. It also reserializes the typed DTO and compares
    /// exact bytes, so alternate field order, float spellings, escaped strings,
    /// or noncanonical negative-zero encodings cannot enter durable storage.
    ///
    /// # Errors
    /// Returns [`CalibrationReportArtifactError`] for malformed, oversized, or
    /// noncanonical bytes. Error values contain no evidence content.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, CalibrationReportArtifactError> {
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(CalibrationReportArtifactError::TooLarge);
        }
        let value = match serde_json::from_slice::<UniqueJson>(bytes) {
            Ok(value) => value.0,
            Err(error) if error.to_string().contains("duplicate JSON object key") => {
                return Err(CalibrationReportArtifactError::DuplicateField);
            }
            Err(_) => return Err(CalibrationReportArtifactError::InvalidJson),
        };
        let artifact = parse_document(value)?;
        if artifact.to_canonical_json()? != bytes {
            return Err(CalibrationReportArtifactError::NonCanonicalEncoding);
        }
        Ok(artifact)
    }

    /// Serializes the report into its only accepted UTF-8 representation.
    ///
    /// Object keys are emitted in bytewise lexical order. All finite floating
    /// values are represented as fixed-width lowercase IEEE-754 bit strings;
    /// this avoids formatter-dependent decimal output and canonicalizes `-0.0`.
    ///
    /// # Errors
    /// Returns [`CalibrationReportArtifactError::TooLarge`] if the bounded
    /// protected document would exceed its vault admission ceiling.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, CalibrationReportArtifactError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&self.as_json())
            .map_err(|_| CalibrationReportArtifactError::Serialization)?;
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(CalibrationReportArtifactError::TooLarge);
        }
        Ok(bytes)
    }

    /// Returns the immutable report identity.
    #[must_use]
    pub const fn report_id(&self) -> &CalibrationReportId {
        &self.report_id
    }

    /// Returns the independently encrypted report artifact identity.
    #[must_use]
    pub const fn report_artifact_id(&self) -> &ArtifactId {
        &self.report_artifact_id
    }

    /// Returns frozen dataset and model provenance.
    #[must_use]
    pub const fn provenance(&self) -> &EvaluationProvenance {
        &self.provenance
    }

    /// Returns the fixed descriptive thresholds used by the evaluation.
    #[must_use]
    pub const fn thresholds(&self) -> Thresholds {
        self.thresholds
    }

    /// Returns opaque source tuples in their original evaluation order.
    #[must_use]
    pub fn sources(&self) -> &[CalibrationReportArtifactSource] {
        &self.sources
    }

    /// Returns aggregate metrics with explicit denominators.
    #[must_use]
    pub const fn metrics(&self) -> &Report {
        &self.metrics
    }

    fn validate(&self) -> Result<(), CalibrationReportArtifactError> {
        let thresholds = canonical_thresholds(self.thresholds)?;
        if thresholds != self.thresholds {
            return Err(CalibrationReportArtifactError::FloatNotCanonical);
        }
        let metrics = canonical_metrics(self.metrics.clone())?;
        if metrics != self.metrics {
            return Err(CalibrationReportArtifactError::FloatNotCanonical);
        }
        validate_sources(&self.sources, &self.provenance, &self.report_artifact_id)?;
        validate_metrics(&self.metrics, self.sources.len())
    }

    fn as_json(&self) -> Value {
        object([
            (
                "kind",
                Value::String(CALIBRATION_REPORT_ARTIFACT_KIND.to_owned()),
            ),
            ("metrics", metrics_json(&self.metrics)),
            ("provenance", provenance_json(&self.provenance)),
            (
                "report_artifact_id",
                Value::String(self.report_artifact_id.as_str().to_owned()),
            ),
            (
                "report_id",
                Value::String(self.report_id.as_str().to_owned()),
            ),
            (
                "schema_version",
                Value::Number(Number::from(CALIBRATION_REPORT_ARTIFACT_SCHEMA_VERSION)),
            ),
            (
                "sources",
                Value::Array(self.sources.iter().map(source_json).collect()),
            ),
            ("thresholds", thresholds_json(self.thresholds)),
        ])
    }
}

/// Closed validation failures for a protected calibration report body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationReportArtifactError {
    /// Input could not be parsed as a bounded JSON value.
    InvalidJson,
    /// The document schema version or fixed kind was not accepted.
    InvalidSchema,
    /// A required field was absent from a fixed object shape.
    MissingField,
    /// A field appeared more than once in a JSON object.
    DuplicateField,
    /// A field was not part of the fixed report schema.
    UnknownField,
    /// A field name identifies protected data forbidden from the report body.
    ProhibitedField,
    /// A typed identifier or bounded scalar was malformed.
    InvalidValue,
    /// A floating-point bit representation was malformed, nonfinite, or invalid.
    InvalidFloat,
    /// A finite floating-point value used a noncanonical representation.
    FloatNotCanonical,
    /// Source tuples were incomplete, aliased, duplicated, or out of order.
    SourceSetInvalid,
    /// Aggregate counts, denominators, or reliability bins were inconsistent.
    MetricsInvalid,
    /// The publication projection did not describe the supplied evaluation.
    PublicationMismatch,
    /// Parsed bytes differ from the DTO's fixed canonical representation.
    NonCanonicalEncoding,
    /// The report body exceeded the bounded artifact ceiling.
    TooLarge,
    /// Canonical JSON encoding unexpectedly failed.
    Serialization,
}

impl CalibrationReportArtifactError {
    /// Returns the stable, content-free reason code for caller-owned audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidJson => "CALIBRATION_REPORT_ARTIFACT_JSON_INVALID",
            Self::InvalidSchema => "CALIBRATION_REPORT_ARTIFACT_SCHEMA_INVALID",
            Self::MissingField => "CALIBRATION_REPORT_ARTIFACT_FIELD_MISSING",
            Self::DuplicateField => "CALIBRATION_REPORT_ARTIFACT_FIELD_DUPLICATE",
            Self::UnknownField => "CALIBRATION_REPORT_ARTIFACT_FIELD_UNKNOWN",
            Self::ProhibitedField => "CALIBRATION_REPORT_ARTIFACT_FIELD_PROHIBITED",
            Self::InvalidValue => "CALIBRATION_REPORT_ARTIFACT_VALUE_INVALID",
            Self::InvalidFloat => "CALIBRATION_REPORT_ARTIFACT_FLOAT_INVALID",
            Self::FloatNotCanonical => "CALIBRATION_REPORT_ARTIFACT_FLOAT_NONCANONICAL",
            Self::SourceSetInvalid => "CALIBRATION_REPORT_ARTIFACT_SOURCES_INVALID",
            Self::MetricsInvalid => "CALIBRATION_REPORT_ARTIFACT_METRICS_INVALID",
            Self::PublicationMismatch => "CALIBRATION_REPORT_ARTIFACT_PUBLICATION_MISMATCH",
            Self::NonCanonicalEncoding => "CALIBRATION_REPORT_ARTIFACT_ENCODING_NONCANONICAL",
            Self::TooLarge => "CALIBRATION_REPORT_ARTIFACT_LIMIT_EXCEEDED",
            Self::Serialization => "CALIBRATION_REPORT_ARTIFACT_SERIALIZATION_FAILED",
        }
    }
}

impl fmt::Display for CalibrationReportArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for CalibrationReportArtifactError {}

fn publication_matches_report(
    publication: &CalibrationReportPublication,
    report: &EvaluationReport,
) -> bool {
    let provenance = report.provenance();
    publication.approval_ref() == provenance.approval_ref()
        && publication.dataset_revision() == provenance.dataset_revision()
        && publication.label_revision() == provenance.label_revision()
        && publication.task_revision() == provenance.task_revision()
        && publication.threshold_policy_revision() == provenance.threshold_policy_revision()
        && publication.mapping_revision() == provenance.mapping_revision()
        && publication.evaluation_manifest_artifact_id()
            == provenance.evaluation_manifest_artifact_id()
        && publication.training_manifest_artifact_id() == provenance.training_manifest_artifact_id()
        && publication.calibration_manifest_artifact_id()
            == provenance.calibration_manifest_artifact_id()
        && publication.label_manifest_artifact_id() == provenance.label_manifest_artifact_id()
        && publication.model() == provenance.model()
}

fn canonical_thresholds(
    thresholds: Thresholds,
) -> Result<Thresholds, CalibrationReportArtifactError> {
    let allow = Probability::new(canonical_float(thresholds.allow_below_or_equal().value())?)
        .map_err(|_| CalibrationReportArtifactError::InvalidFloat)?;
    let deny = Probability::new(canonical_float(thresholds.deny_above_or_equal().value())?)
        .map_err(|_| CalibrationReportArtifactError::InvalidFloat)?;
    Thresholds::new(allow, deny).map_err(|_| CalibrationReportArtifactError::InvalidValue)
}

fn canonical_metrics(mut metrics: Report) -> Result<Report, CalibrationReportArtifactError> {
    for bin in &mut metrics.reliability {
        bin.mean_probability = bin.mean_probability.map(canonical_float).transpose()?;
    }
    metrics.brier_score = metrics.brier_score.map(canonical_float).transpose()?;
    Ok(metrics)
}

fn canonical_float(value: f64) -> Result<f64, CalibrationReportArtifactError> {
    if !value.is_finite() {
        return Err(CalibrationReportArtifactError::InvalidFloat);
    }
    Ok(if value == 0.0 { 0.0 } else { value })
}

fn validate_sources(
    sources: &[CalibrationReportArtifactSource],
    provenance: &EvaluationProvenance,
    report_artifact_id: &ArtifactId,
) -> Result<(), CalibrationReportArtifactError> {
    if sources.is_empty() || sources.len() > super::super::MAX_SAMPLES {
        return Err(CalibrationReportArtifactError::SourceSetInvalid);
    }
    let manifests = [
        provenance.evaluation_manifest_artifact_id(),
        provenance.training_manifest_artifact_id(),
        provenance.calibration_manifest_artifact_id(),
        provenance.label_manifest_artifact_id(),
    ];
    let mut model_calls = BTreeSet::new();
    let mut model_artifacts = BTreeSet::new();
    let mut label_artifacts = BTreeSet::new();
    for (expected_index, source) in sources.iter().enumerate() {
        if source.sample_index
            != u32::try_from(expected_index)
                .map_err(|_| CalibrationReportArtifactError::SourceSetInvalid)?
            || source.model_call_artifact_id == source.label_artifact_id
            || source.model_call_artifact_id == *report_artifact_id
            || source.label_artifact_id == *report_artifact_id
            || manifests.iter().any(|manifest| {
                **manifest == source.model_call_artifact_id
                    || **manifest == source.label_artifact_id
            })
            || !model_calls.insert(&source.model_call_id)
            || !model_artifacts.insert(&source.model_call_artifact_id)
            || !label_artifacts.insert(&source.label_artifact_id)
            || model_artifacts.contains(&source.label_artifact_id)
            || label_artifacts.contains(&source.model_call_artifact_id)
        {
            return Err(CalibrationReportArtifactError::SourceSetInvalid);
        }
    }
    Ok(())
}

fn validate_metrics(
    metrics: &Report,
    source_count: usize,
) -> Result<(), CalibrationReportArtifactError> {
    let total =
        u32::try_from(source_count).map_err(|_| CalibrationReportArtifactError::MetricsInvalid)?;
    let counts = metrics.counts;
    let benign = checked_sum([
        counts.benign_allow,
        counts.benign_deny,
        counts.benign_abstain,
    ])?;
    let malicious = checked_sum([
        counts.malicious_allow,
        counts.malicious_deny,
        counts.malicious_abstain,
    ])?;
    let unknown = checked_sum([
        counts.unknown_allow,
        counts.unknown_deny,
        counts.unknown_abstain,
    ])?;
    let abstained = checked_sum([
        counts.benign_abstain,
        counts.malicious_abstain,
        counts.unknown_abstain,
    ])?;
    if metrics.total_samples != total
        || checked_sum([metrics.available_samples, metrics.missing_samples])? != total
        || checked_sum([benign, malicious, unknown])? != total
        || metrics.unknown_label_samples != unknown
        || checked_sum([
            metrics.unavailable_counts.model_failed,
            metrics.unavailable_counts.model_timed_out,
            metrics.unavailable_counts.model_cancelled,
            metrics.unavailable_counts.probability_missing,
        ])? != metrics.missing_samples
        || metrics.false_allow_rate
            != (Rate {
                numerator: counts.malicious_allow,
                denominator: malicious,
            })
        || metrics.false_deny_rate
            != (Rate {
                numerator: counts.benign_deny,
                denominator: benign,
            })
        || metrics.coverage
            != (Rate {
                numerator: total
                    .checked_sub(abstained)
                    .ok_or(CalibrationReportArtifactError::MetricsInvalid)?,
                denominator: total,
            })
        || metrics.unknown_rate
            != (Rate {
                numerator: abstained,
                denominator: total,
            })
    {
        return Err(CalibrationReportArtifactError::MetricsInvalid);
    }
    let reliability_count = metrics.reliability.iter().try_fold(0_u32, |total, bin| {
        if bin.observed_positives > bin.count
            || (bin.count == 0) != bin.mean_probability.is_none()
            || bin
                .mean_probability
                .is_some_and(|value| !(0.0..=1.0).contains(&value))
        {
            return Err(CalibrationReportArtifactError::MetricsInvalid);
        }
        total
            .checked_add(bin.count)
            .ok_or(CalibrationReportArtifactError::MetricsInvalid)
    })?;
    if reliability_count != metrics.scored_samples
        || metrics.scored_samples > metrics.available_samples
        || metrics.scored_samples > checked_sum([benign, malicious])?
        || metrics
            .brier_score
            .is_some_and(|value| !(0.0..=1.0).contains(&value))
        || (metrics.scored_samples == 0) != metrics.brier_score.is_none()
    {
        return Err(CalibrationReportArtifactError::MetricsInvalid);
    }
    Ok(())
}

fn checked_sum<const N: usize>(values: [u32; N]) -> Result<u32, CalibrationReportArtifactError> {
    values.into_iter().try_fold(0_u32, |total, value| {
        total
            .checked_add(value)
            .ok_or(CalibrationReportArtifactError::MetricsInvalid)
    })
}

fn source_json(source: &CalibrationReportArtifactSource) -> Value {
    object([
        (
            "label_artifact_id",
            Value::String(source.label_artifact_id.as_str().to_owned()),
        ),
        (
            "model_call_artifact_id",
            Value::String(source.model_call_artifact_id.as_str().to_owned()),
        ),
        (
            "model_call_id",
            Value::String(source.model_call_id.as_str().to_owned()),
        ),
        (
            "sample_index",
            Value::Number(Number::from(source.sample_index)),
        ),
    ])
}

fn provenance_json(provenance: &EvaluationProvenance) -> Value {
    object([
        (
            "approval_ref",
            Value::String(provenance.approval_ref().as_str().to_owned()),
        ),
        (
            "calibration_manifest_artifact_id",
            Value::String(
                provenance
                    .calibration_manifest_artifact_id()
                    .as_str()
                    .to_owned(),
            ),
        ),
        (
            "dataset_revision",
            Value::String(provenance.dataset_revision().as_str().to_owned()),
        ),
        (
            "evaluation_manifest_artifact_id",
            Value::String(
                provenance
                    .evaluation_manifest_artifact_id()
                    .as_str()
                    .to_owned(),
            ),
        ),
        (
            "label_manifest_artifact_id",
            Value::String(provenance.label_manifest_artifact_id().as_str().to_owned()),
        ),
        (
            "label_revision",
            Value::String(provenance.label_revision().as_str().to_owned()),
        ),
        (
            "mapping_revision",
            Value::String(provenance.mapping_revision().as_str().to_owned()),
        ),
        ("model", model_json(provenance.model())),
        (
            "task_revision",
            Value::String(provenance.task_revision().as_str().to_owned()),
        ),
        (
            "threshold_policy_revision",
            Value::String(provenance.threshold_policy_revision().as_str().to_owned()),
        ),
        (
            "training_manifest_artifact_id",
            Value::String(
                provenance
                    .training_manifest_artifact_id()
                    .as_str()
                    .to_owned(),
            ),
        ),
    ])
}

fn model_json(model: &ModelIdentity) -> Value {
    object([
        (
            "model_revision",
            Value::String(model.model_revision().as_str().to_owned()),
        ),
        (
            "prompt_revision",
            Value::String(model.prompt_revision().as_str().to_owned()),
        ),
        (
            "provider",
            Value::String(model.provider().as_str().to_owned()),
        ),
        (
            "provider_model_id",
            Value::String(model.provider_model_id().to_owned()),
        ),
        (
            "resolved_model_revision",
            model
                .resolved_model_revision()
                .map_or(Value::Null, |revision| {
                    Value::String(revision.as_str().to_owned())
                }),
        ),
    ])
}

fn thresholds_json(thresholds: Thresholds) -> Value {
    object([
        (
            "allow_below_or_equal_bits",
            float_json(thresholds.allow_below_or_equal().value()),
        ),
        (
            "deny_above_or_equal_bits",
            float_json(thresholds.deny_above_or_equal().value()),
        ),
    ])
}

fn metrics_json(metrics: &Report) -> Value {
    object([
        ("available_samples", u32_json(metrics.available_samples)),
        ("brier_score_bits", optional_float_json(metrics.brier_score)),
        ("counts", counts_json(metrics.counts)),
        ("coverage", rate_json(metrics.coverage)),
        ("false_allow_rate", rate_json(metrics.false_allow_rate)),
        ("false_deny_rate", rate_json(metrics.false_deny_rate)),
        ("missing_samples", u32_json(metrics.missing_samples)),
        (
            "reliability",
            Value::Array(metrics.reliability.iter().map(reliability_json).collect()),
        ),
        ("scored_samples", u32_json(metrics.scored_samples)),
        ("total_samples", u32_json(metrics.total_samples)),
        (
            "unavailable_counts",
            unavailable_counts_json(metrics.unavailable_counts),
        ),
        (
            "unknown_label_samples",
            u32_json(metrics.unknown_label_samples),
        ),
        ("unknown_rate", rate_json(metrics.unknown_rate)),
    ])
}

fn counts_json(counts: ConfusionCounts) -> Value {
    object([
        ("benign_abstain", u32_json(counts.benign_abstain)),
        ("benign_allow", u32_json(counts.benign_allow)),
        ("benign_deny", u32_json(counts.benign_deny)),
        ("malicious_abstain", u32_json(counts.malicious_abstain)),
        ("malicious_allow", u32_json(counts.malicious_allow)),
        ("malicious_deny", u32_json(counts.malicious_deny)),
        ("unknown_abstain", u32_json(counts.unknown_abstain)),
        ("unknown_allow", u32_json(counts.unknown_allow)),
        ("unknown_deny", u32_json(counts.unknown_deny)),
    ])
}

fn unavailable_counts_json(counts: UnavailableCounts) -> Value {
    object([
        ("model_cancelled", u32_json(counts.model_cancelled)),
        ("model_failed", u32_json(counts.model_failed)),
        ("model_timed_out", u32_json(counts.model_timed_out)),
        ("probability_missing", u32_json(counts.probability_missing)),
    ])
}

fn rate_json(rate: Rate) -> Value {
    object([
        ("denominator", u32_json(rate.denominator)),
        ("numerator", u32_json(rate.numerator)),
    ])
}

fn reliability_json(bin: &ReliabilityBin) -> Value {
    object([
        ("count", u32_json(bin.count)),
        (
            "mean_probability_bits",
            optional_float_json(bin.mean_probability),
        ),
        ("observed_positives", u32_json(bin.observed_positives)),
    ])
}

fn u32_json(value: u32) -> Value {
    Value::Number(Number::from(value))
}

fn float_json(value: f64) -> Value {
    Value::String(format!("{:016x}", canonical_float_bits(value)))
}

fn optional_float_json(value: Option<f64>) -> Value {
    value.map_or(Value::Null, float_json)
}

fn canonical_float_bits(value: f64) -> u64 {
    if value == 0.0 { 0 } else { value.to_bits() }
}

fn object<const N: usize>(fields: [(&'static str, Value); N]) -> Value {
    let fields = fields
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect::<BTreeMap<_, _>>();
    Value::Object(fields.into_iter().collect())
}

fn parse_document(
    value: Value,
) -> Result<CalibrationReportArtifact, CalibrationReportArtifactError> {
    let mut fields = object_fields(
        value,
        &[
            "kind",
            "metrics",
            "provenance",
            "report_artifact_id",
            "report_id",
            "schema_version",
            "sources",
            "thresholds",
        ],
    )?;
    if take_u32(&mut fields, "schema_version")?
        != u32::from(CALIBRATION_REPORT_ARTIFACT_SCHEMA_VERSION)
        || take_string(&mut fields, "kind")? != CALIBRATION_REPORT_ARTIFACT_KIND
    {
        return Err(CalibrationReportArtifactError::InvalidSchema);
    }
    let report_id = CalibrationReportId::parse(take_string(&mut fields, "report_id")?)
        .map_err(|_| CalibrationReportArtifactError::InvalidValue)?;
    let report_artifact_id = ArtifactId::parse(take_string(&mut fields, "report_artifact_id")?)
        .map_err(|_| CalibrationReportArtifactError::InvalidValue)?;
    let provenance = parse_provenance(take_value(&mut fields, "provenance")?)?;
    let thresholds = parse_thresholds(take_value(&mut fields, "thresholds")?)?;
    let sources = parse_sources(take_value(&mut fields, "sources")?)?;
    let metrics = parse_metrics(take_value(&mut fields, "metrics")?)?;
    let artifact = CalibrationReportArtifact {
        report_id,
        report_artifact_id,
        provenance,
        thresholds,
        sources,
        metrics,
    };
    artifact.validate()?;
    Ok(artifact)
}

fn parse_provenance(value: Value) -> Result<EvaluationProvenance, CalibrationReportArtifactError> {
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
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        DatasetRevision::parse(take_string(&mut fields, "dataset_revision")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        LabelRevision::parse(take_string(&mut fields, "label_revision")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        TaskRevision::parse(take_string(&mut fields, "task_revision")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        ThresholdPolicyRevision::parse(take_string(&mut fields, "threshold_policy_revision")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        MappingRevision::parse(take_string(&mut fields, "mapping_revision")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        ArtifactId::parse(take_string(&mut fields, "evaluation_manifest_artifact_id")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        ArtifactId::parse(take_string(&mut fields, "training_manifest_artifact_id")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        ArtifactId::parse(take_string(
            &mut fields,
            "calibration_manifest_artifact_id",
        )?)
        .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        ArtifactId::parse(take_string(&mut fields, "label_manifest_artifact_id")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        model,
    )
    .map_err(|_| CalibrationReportArtifactError::SourceSetInvalid)
}

fn parse_model(value: Value) -> Result<ModelIdentity, CalibrationReportArtifactError> {
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
    let resolved_model_revision = match take_value(&mut fields, "resolved_model_revision")? {
        Value::Null => None,
        Value::String(value) => Some(
            ModelRevision::parse(value)
                .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        ),
        _ => return Err(CalibrationReportArtifactError::InvalidValue),
    };
    ModelIdentity::new(
        ProviderId::parse(take_string(&mut fields, "provider")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        take_string(&mut fields, "provider_model_id")?,
        ModelRevision::parse(take_string(&mut fields, "model_revision")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        PromptRevision::parse(take_string(&mut fields, "prompt_revision")?)
            .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
        resolved_model_revision,
    )
    .map_err(|_| CalibrationReportArtifactError::InvalidValue)
}

fn parse_thresholds(value: Value) -> Result<Thresholds, CalibrationReportArtifactError> {
    let mut fields = object_fields(
        value,
        &["allow_below_or_equal_bits", "deny_above_or_equal_bits"],
    )?;
    let allow = Probability::new(take_float(&mut fields, "allow_below_or_equal_bits")?)
        .map_err(|_| CalibrationReportArtifactError::InvalidFloat)?;
    let deny = Probability::new(take_float(&mut fields, "deny_above_or_equal_bits")?)
        .map_err(|_| CalibrationReportArtifactError::InvalidFloat)?;
    Thresholds::new(allow, deny).map_err(|_| CalibrationReportArtifactError::InvalidValue)
}

fn parse_sources(
    value: Value,
) -> Result<Vec<CalibrationReportArtifactSource>, CalibrationReportArtifactError> {
    let Value::Array(values) = value else {
        return Err(CalibrationReportArtifactError::InvalidValue);
    };
    if values.is_empty() || values.len() > super::super::MAX_SAMPLES {
        return Err(CalibrationReportArtifactError::SourceSetInvalid);
    }
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let mut fields = object_fields(
                value,
                &[
                    "label_artifact_id",
                    "model_call_artifact_id",
                    "model_call_id",
                    "sample_index",
                ],
            )?;
            let sample_index = take_u32(&mut fields, "sample_index")?;
            if sample_index
                != u32::try_from(index)
                    .map_err(|_| CalibrationReportArtifactError::SourceSetInvalid)?
            {
                return Err(CalibrationReportArtifactError::SourceSetInvalid);
            }
            Ok(CalibrationReportArtifactSource {
                sample_index,
                model_call_id: ModelCallId::parse(take_string(&mut fields, "model_call_id")?)
                    .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
                model_call_artifact_id: ArtifactId::parse(take_string(
                    &mut fields,
                    "model_call_artifact_id",
                )?)
                .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
                label_artifact_id: ArtifactId::parse(take_string(
                    &mut fields,
                    "label_artifact_id",
                )?)
                .map_err(|_| CalibrationReportArtifactError::InvalidValue)?,
            })
        })
        .collect()
}

fn parse_metrics(value: Value) -> Result<Report, CalibrationReportArtifactError> {
    let mut fields = object_fields(
        value,
        &[
            "available_samples",
            "brier_score_bits",
            "counts",
            "coverage",
            "false_allow_rate",
            "false_deny_rate",
            "missing_samples",
            "reliability",
            "scored_samples",
            "total_samples",
            "unavailable_counts",
            "unknown_label_samples",
            "unknown_rate",
        ],
    )?;
    let reliability = parse_reliability(take_value(&mut fields, "reliability")?)?;
    let report = Report {
        total_samples: take_u32(&mut fields, "total_samples")?,
        available_samples: take_u32(&mut fields, "available_samples")?,
        missing_samples: take_u32(&mut fields, "missing_samples")?,
        unknown_label_samples: take_u32(&mut fields, "unknown_label_samples")?,
        scored_samples: take_u32(&mut fields, "scored_samples")?,
        counts: parse_counts(take_value(&mut fields, "counts")?)?,
        unavailable_counts: parse_unavailable_counts(take_value(
            &mut fields,
            "unavailable_counts",
        )?)?,
        false_allow_rate: parse_rate(take_value(&mut fields, "false_allow_rate")?)?,
        false_deny_rate: parse_rate(take_value(&mut fields, "false_deny_rate")?)?,
        coverage: parse_rate(take_value(&mut fields, "coverage")?)?,
        unknown_rate: parse_rate(take_value(&mut fields, "unknown_rate")?)?,
        reliability,
        brier_score: take_optional_float(&mut fields, "brier_score_bits")?,
    };
    Ok(report)
}

fn parse_counts(value: Value) -> Result<ConfusionCounts, CalibrationReportArtifactError> {
    let mut fields = object_fields(
        value,
        &[
            "benign_abstain",
            "benign_allow",
            "benign_deny",
            "malicious_abstain",
            "malicious_allow",
            "malicious_deny",
            "unknown_abstain",
            "unknown_allow",
            "unknown_deny",
        ],
    )?;
    Ok(ConfusionCounts {
        benign_allow: take_u32(&mut fields, "benign_allow")?,
        benign_deny: take_u32(&mut fields, "benign_deny")?,
        benign_abstain: take_u32(&mut fields, "benign_abstain")?,
        malicious_allow: take_u32(&mut fields, "malicious_allow")?,
        malicious_deny: take_u32(&mut fields, "malicious_deny")?,
        malicious_abstain: take_u32(&mut fields, "malicious_abstain")?,
        unknown_allow: take_u32(&mut fields, "unknown_allow")?,
        unknown_deny: take_u32(&mut fields, "unknown_deny")?,
        unknown_abstain: take_u32(&mut fields, "unknown_abstain")?,
    })
}

fn parse_unavailable_counts(
    value: Value,
) -> Result<UnavailableCounts, CalibrationReportArtifactError> {
    let mut fields = object_fields(
        value,
        &[
            "model_cancelled",
            "model_failed",
            "model_timed_out",
            "probability_missing",
        ],
    )?;
    Ok(UnavailableCounts {
        model_failed: take_u32(&mut fields, "model_failed")?,
        model_timed_out: take_u32(&mut fields, "model_timed_out")?,
        model_cancelled: take_u32(&mut fields, "model_cancelled")?,
        probability_missing: take_u32(&mut fields, "probability_missing")?,
    })
}

fn parse_rate(value: Value) -> Result<Rate, CalibrationReportArtifactError> {
    let mut fields = object_fields(value, &["denominator", "numerator"])?;
    Ok(Rate {
        numerator: take_u32(&mut fields, "numerator")?,
        denominator: take_u32(&mut fields, "denominator")?,
    })
}

fn parse_reliability(
    value: Value,
) -> Result<[ReliabilityBin; RELIABILITY_BIN_COUNT], CalibrationReportArtifactError> {
    let Value::Array(values) = value else {
        return Err(CalibrationReportArtifactError::InvalidValue);
    };
    if values.len() != RELIABILITY_BIN_COUNT {
        return Err(CalibrationReportArtifactError::MetricsInvalid);
    }
    let bins = values
        .into_iter()
        .map(|value| {
            let mut fields = object_fields(
                value,
                &["count", "mean_probability_bits", "observed_positives"],
            )?;
            Ok(ReliabilityBin {
                count: take_u32(&mut fields, "count")?,
                observed_positives: take_u32(&mut fields, "observed_positives")?,
                mean_probability: take_optional_float(&mut fields, "mean_probability_bits")?,
            })
        })
        .collect::<Result<Vec<_>, CalibrationReportArtifactError>>()?;
    bins.try_into()
        .map_err(|_| CalibrationReportArtifactError::MetricsInvalid)
}

fn object_fields(
    value: Value,
    expected: &[&str],
) -> Result<Map<String, Value>, CalibrationReportArtifactError> {
    let Value::Object(fields) = value else {
        return Err(CalibrationReportArtifactError::InvalidValue);
    };
    for field in fields.keys() {
        if prohibited_field(field) {
            return Err(CalibrationReportArtifactError::ProhibitedField);
        }
        if !expected.contains(&field.as_str()) {
            return Err(CalibrationReportArtifactError::UnknownField);
        }
    }
    if expected.iter().any(|field| !fields.contains_key(*field)) {
        return Err(CalibrationReportArtifactError::MissingField);
    }
    Ok(fields)
}

fn prohibited_field(value: &str) -> bool {
    matches!(
        value,
        "capability_id"
            | "cookie"
            | "cookies"
            | "credential"
            | "credentials"
            | "ground_truth"
            | "label"
            | "labels"
            | "lease_handle"
            | "lease_id"
            | "model_output"
            | "probabilities"
            | "probability"
            | "prompt"
            | "provider_output"
            | "provider_response"
            | "reader_receipt"
            | "request_id"
            | "secret"
            | "secrets"
    )
}

fn take_value(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<Value, CalibrationReportArtifactError> {
    fields
        .remove(field)
        .ok_or(CalibrationReportArtifactError::MissingField)
}

fn take_string(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<String, CalibrationReportArtifactError> {
    match take_value(fields, field)? {
        Value::String(value) => Ok(value),
        _ => Err(CalibrationReportArtifactError::InvalidValue),
    }
}

fn take_u32(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<u32, CalibrationReportArtifactError> {
    take_value(fields, field)?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(CalibrationReportArtifactError::InvalidValue)
}

fn take_float(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<f64, CalibrationReportArtifactError> {
    parse_float_bits(&take_string(fields, field)?)
}

fn take_optional_float(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<f64>, CalibrationReportArtifactError> {
    match take_value(fields, field)? {
        Value::Null => Ok(None),
        Value::String(value) => parse_float_bits(&value).map(Some),
        _ => Err(CalibrationReportArtifactError::InvalidFloat),
    }
}

fn parse_float_bits(value: &str) -> Result<f64, CalibrationReportArtifactError> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CalibrationReportArtifactError::InvalidFloat);
    }
    let bits =
        u64::from_str_radix(value, 16).map_err(|_| CalibrationReportArtifactError::InvalidFloat)?;
    let number = f64::from_bits(bits);
    if !number.is_finite() {
        return Err(CalibrationReportArtifactError::InvalidFloat);
    }
    if number == 0.0 && bits != 0 {
        return Err(CalibrationReportArtifactError::FloatNotCanonical);
    }
    Ok(number)
}

/// JSON tree decoder which rejects duplicate names at every object depth.
///
/// `serde_json::Value` normally keeps only the last duplicate key. Artifact
/// input is an integrity boundary, so the intermediate tree retains this check
/// before the fixed-schema parser examines field names.
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
