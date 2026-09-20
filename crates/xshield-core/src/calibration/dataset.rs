//! Provenance-bound inputs for an offline threshold evaluation.
//!
//! This module joins caller-approved labels and model-call record references to
//! the pure metrics engine. It validates identity, scope-independent references,
//! versions, partitions, and bounded cardinality, but cannot prove that external
//! datasets have no content overlap. The worker assembling these values must use
//! authorized evidence reads and retain its durable audit receipt.

use super::{
    CalibrationError, GroundTruth, MAX_SAMPLES, Report, Sample, Signal, Thresholds, evaluate,
};
use crate::domain::{
    ApprovalRef, ArtifactId, DatasetRevision, LabelRevision, MappingRevision, ModelCallId,
    ModelRevision, PromptRevision, ProviderId, TaskRevision, ThresholdPolicyRevision,
};
use std::{collections::BTreeSet, fmt};

/// One model route and template family frozen for a dataset evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelIdentity {
    provider: ProviderId,
    provider_model_id: String,
    model_revision: ModelRevision,
    prompt_revision: PromptRevision,
    resolved_model_revision: Option<ModelRevision>,
}

impl ModelIdentity {
    /// Validates immutable provider and template identity for one evaluation.
    ///
    /// `resolved_model_revision` is absent when a provider alias cannot prove an
    /// exact implementation revision. That state is retained in reports rather
    /// than inferred from the current provider route.
    ///
    /// # Errors
    /// Returns [`DatasetError::InvalidProviderModel`] for an empty, oversized,
    /// or unsupported wire model name. No I/O or provider call occurs.
    pub fn new(
        provider: ProviderId,
        provider_model_id: impl Into<String>,
        model_revision: ModelRevision,
        prompt_revision: PromptRevision,
        resolved_model_revision: Option<ModelRevision>,
    ) -> Result<Self, DatasetError> {
        let provider_model_id = provider_model_id.into();
        if !valid_provider_model_id(&provider_model_id) {
            return Err(DatasetError::InvalidProviderModel);
        }
        Ok(Self {
            provider,
            provider_model_id,
            model_revision,
            prompt_revision,
            resolved_model_revision,
        })
    }

    /// Returns the configured provider route identity.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the exact provider wire model identifier.
    #[must_use]
    pub fn provider_model_id(&self) -> &str {
        &self.provider_model_id
    }

    /// Returns the pinned internal model revision.
    #[must_use]
    pub const fn model_revision(&self) -> &ModelRevision {
        &self.model_revision
    }

    /// Returns the pinned prompt revision.
    #[must_use]
    pub const fn prompt_revision(&self) -> &PromptRevision {
        &self.prompt_revision
    }

    /// Returns the exact resolved provider revision, if the provider supplied it.
    #[must_use]
    pub const fn resolved_model_revision(&self) -> Option<&ModelRevision> {
        self.resolved_model_revision.as_ref()
    }

    /// Indicates whether byte-level provider revision provenance is available.
    #[must_use]
    pub const fn exact_provider_revision_known(&self) -> bool {
        self.resolved_model_revision.is_some()
    }
}

/// Immutable references describing an approved held-out evaluation partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationProvenance {
    approval_ref: ApprovalRef,
    dataset_revision: DatasetRevision,
    label_revision: LabelRevision,
    task_revision: TaskRevision,
    threshold_policy_revision: ThresholdPolicyRevision,
    mapping_revision: MappingRevision,
    evaluation_manifest_artifact_id: ArtifactId,
    training_manifest_artifact_id: ArtifactId,
    calibration_manifest_artifact_id: ArtifactId,
    label_manifest_artifact_id: ArtifactId,
    model: ModelIdentity,
}

impl EvaluationProvenance {
    /// Binds the approved revisions and distinct partition manifests.
    ///
    /// Each manifest reference must be different. This prevents a caller from
    /// claiming the same declared manifest is both training/calibration and
    /// held-out evaluation. It does not inspect manifest content, so callers
    /// still need independent dataset-leakage review.
    ///
    /// # Errors
    /// Returns [`DatasetError::OverlappingPartitionManifest`] for any repeated
    /// manifest reference. Construction has no storage, authorization, model, or
    /// policy-publication side effect.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        approval_ref: ApprovalRef,
        dataset_revision: DatasetRevision,
        label_revision: LabelRevision,
        task_revision: TaskRevision,
        threshold_policy_revision: ThresholdPolicyRevision,
        mapping_revision: MappingRevision,
        evaluation_manifest_artifact_id: ArtifactId,
        training_manifest_artifact_id: ArtifactId,
        calibration_manifest_artifact_id: ArtifactId,
        label_manifest_artifact_id: ArtifactId,
        model: ModelIdentity,
    ) -> Result<Self, DatasetError> {
        let manifests = [
            &evaluation_manifest_artifact_id,
            &training_manifest_artifact_id,
            &calibration_manifest_artifact_id,
            &label_manifest_artifact_id,
        ];
        if manifests.iter().collect::<BTreeSet<_>>().len() != manifests.len() {
            return Err(DatasetError::OverlappingPartitionManifest);
        }
        Ok(Self {
            approval_ref,
            dataset_revision,
            label_revision,
            task_revision,
            threshold_policy_revision,
            mapping_revision,
            evaluation_manifest_artifact_id,
            training_manifest_artifact_id,
            calibration_manifest_artifact_id,
            label_manifest_artifact_id,
            model,
        })
    }

    /// Returns the caller-approved external disclosure and evaluation reference.
    #[must_use]
    pub const fn approval_ref(&self) -> &ApprovalRef {
        &self.approval_ref
    }

    /// Returns the held-out dataset revision.
    #[must_use]
    pub const fn dataset_revision(&self) -> &DatasetRevision {
        &self.dataset_revision
    }

    /// Returns the reviewed label revision.
    #[must_use]
    pub const fn label_revision(&self) -> &LabelRevision {
        &self.label_revision
    }

    /// Returns the task semantics revision.
    #[must_use]
    pub const fn task_revision(&self) -> &TaskRevision {
        &self.task_revision
    }

    /// Returns the frozen threshold policy revision.
    #[must_use]
    pub const fn threshold_policy_revision(&self) -> &ThresholdPolicyRevision {
        &self.threshold_policy_revision
    }

    /// Returns the frozen approved risk-mapping revision.
    #[must_use]
    pub const fn mapping_revision(&self) -> &MappingRevision {
        &self.mapping_revision
    }

    /// Returns the held-out evaluation partition manifest reference.
    #[must_use]
    pub const fn evaluation_manifest_artifact_id(&self) -> &ArtifactId {
        &self.evaluation_manifest_artifact_id
    }

    /// Returns the training partition manifest reference.
    #[must_use]
    pub const fn training_manifest_artifact_id(&self) -> &ArtifactId {
        &self.training_manifest_artifact_id
    }

    /// Returns the calibration partition manifest reference.
    #[must_use]
    pub const fn calibration_manifest_artifact_id(&self) -> &ArtifactId {
        &self.calibration_manifest_artifact_id
    }

    /// Returns the label set manifest reference.
    #[must_use]
    pub const fn label_manifest_artifact_id(&self) -> &ArtifactId {
        &self.label_manifest_artifact_id
    }

    /// Returns the frozen model identity.
    #[must_use]
    pub const fn model(&self) -> &ModelIdentity {
        &self.model
    }
}

/// A labelled model-call record selected into an approved held-out dataset.
#[derive(Clone, Debug, PartialEq)]
pub struct DatasetSample {
    sample: Sample,
    model_call_artifact_id: ArtifactId,
    label_artifact_id: ArtifactId,
    model: ModelIdentity,
    mapping_revision: MappingRevision,
}

impl DatasetSample {
    /// Binds a threshold sample to separately retained model-call and label evidence.
    ///
    /// # Errors
    /// Returns [`DatasetError::SampleEvidenceAliased`] when a model-call record
    /// and its label use the same evidence object. This prevents one opaque
    /// artifact being asserted as both prediction record and independent label.
    pub fn new(
        model_call_id: ModelCallId,
        model_call_artifact_id: ArtifactId,
        label_artifact_id: ArtifactId,
        model: ModelIdentity,
        mapping_revision: MappingRevision,
        ground_truth: GroundTruth,
        signal: Signal,
    ) -> Result<Self, DatasetError> {
        if model_call_artifact_id == label_artifact_id {
            return Err(DatasetError::SampleEvidenceAliased);
        }
        Ok(Self {
            sample: Sample {
                model_call_id,
                ground_truth,
                signal,
            },
            model_call_artifact_id,
            label_artifact_id,
            model,
            mapping_revision,
        })
    }

    /// Returns the pure threshold sample.
    #[must_use]
    pub const fn sample(&self) -> &Sample {
        &self.sample
    }

    /// Returns the encrypted normalized model-call record reference.
    #[must_use]
    pub const fn model_call_artifact_id(&self) -> &ArtifactId {
        &self.model_call_artifact_id
    }

    /// Returns the separate approved label evidence reference.
    #[must_use]
    pub const fn label_artifact_id(&self) -> &ArtifactId {
        &self.label_artifact_id
    }

    /// Returns the model identity observed in the selected call record.
    #[must_use]
    pub const fn model(&self) -> &ModelIdentity {
        &self.model
    }

    /// Returns the risk-mapping revision verified from selected input evidence.
    #[must_use]
    pub const fn mapping_revision(&self) -> &MappingRevision {
        &self.mapping_revision
    }
}

/// One selected input tuple retained without labels, probabilities, or raw payloads.
///
/// The tuple preserves the exact model-call ID and the two separately authorized
/// evidence references so a caller-owned durable report can audit the evaluated
/// record-to-label relationship without reassembling it from positional lists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSampleEvidence {
    model_call: ModelCallId,
    model_call_artifact: ArtifactId,
    label_artifact: ArtifactId,
}

impl SourceSampleEvidence {
    /// Returns the unique model-call identity selected for this evaluation.
    #[must_use]
    pub const fn model_call_id(&self) -> &ModelCallId {
        &self.model_call
    }

    /// Returns the encrypted normalized model-call record reference.
    #[must_use]
    pub const fn model_call_artifact_id(&self) -> &ArtifactId {
        &self.model_call_artifact
    }

    /// Returns the separately approved label evidence reference.
    #[must_use]
    pub const fn label_artifact_id(&self) -> &ArtifactId {
        &self.label_artifact
    }
}

/// A provenance-bound threshold result suitable for caller-owned persistence.
#[derive(Clone, Debug, PartialEq)]
pub struct EvaluationReport {
    provenance: EvaluationProvenance,
    thresholds: Thresholds,
    sources: Vec<SourceSampleEvidence>,
    metrics: Report,
}

impl EvaluationReport {
    /// Returns frozen provenance and declared partition references.
    #[must_use]
    pub const fn provenance(&self) -> &EvaluationProvenance {
        &self.provenance
    }

    /// Returns the fixed descriptive thresholds used in this report.
    #[must_use]
    pub const fn thresholds(&self) -> Thresholds {
        self.thresholds
    }

    /// Returns the selected evidence tuples in the original sample order.
    ///
    /// The collection contains no raw labels, probabilities, or payloads. Its
    /// entries retain the model-call ID and its exact record/label pairing for
    /// caller-owned durable audit.
    #[must_use]
    pub fn sources(&self) -> &[SourceSampleEvidence] {
        &self.sources
    }

    /// Returns descriptive threshold metrics with explicit denominators.
    #[must_use]
    pub const fn metrics(&self) -> &Report {
        &self.metrics
    }

    /// Returns the stable successful reason for caller-owned durable audit.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        "CALIBRATION_DATASET_EVALUATED"
    }
}

/// Builds a provenance-bound held-out evaluation report without I/O.
///
/// The source record and label references are checked for one-to-one model call
/// selection and may not alias a declared partition manifest. Reference equality
/// only proves the submitted ID set is distinct; it cannot prove external
/// contents are independent. The caller must verify scope, retention, evidence
/// authorization, record model identity, risk mapping, label review, and dataset
/// contents.
///
/// # Errors
/// Returns a stable [`DatasetError`] for empty/oversized, duplicate, or aliased
/// references, and wraps pure metric validation failures. No model invocation,
/// policy publication, authorization mutation, storage, or audit write occurs.
pub fn evaluate_dataset(
    provenance: EvaluationProvenance,
    samples: &[DatasetSample],
    thresholds: Thresholds,
) -> Result<EvaluationReport, DatasetError> {
    if samples.is_empty() {
        return Err(DatasetError::Metrics(CalibrationError::EmptySamples));
    }
    if samples.len() > MAX_SAMPLES {
        return Err(DatasetError::Metrics(CalibrationError::TooManySamples));
    }
    let mut call_artifacts = BTreeSet::new();
    let mut label_artifacts = BTreeSet::new();
    let mut model_calls = BTreeSet::new();
    let manifests = [
        &provenance.evaluation_manifest_artifact_id,
        &provenance.training_manifest_artifact_id,
        &provenance.calibration_manifest_artifact_id,
        &provenance.label_manifest_artifact_id,
    ];
    for sample in samples {
        if sample.model != provenance.model {
            return Err(DatasetError::SampleModelIdentityMismatch);
        }
        if sample.mapping_revision != provenance.mapping_revision {
            return Err(DatasetError::SampleMappingRevisionMismatch);
        }
        if manifests.iter().any(|manifest| {
            *manifest == &sample.model_call_artifact_id || *manifest == &sample.label_artifact_id
        }) {
            return Err(DatasetError::ManifestSourceEvidenceAliased);
        }
        if call_artifacts.contains(&sample.label_artifact_id)
            || label_artifacts.contains(&sample.model_call_artifact_id)
        {
            return Err(DatasetError::CrossRoleEvidenceAliased);
        }
        if !call_artifacts.insert(sample.model_call_artifact_id.clone()) {
            return Err(DatasetError::DuplicateModelCallArtifact);
        }
        if !label_artifacts.insert(sample.label_artifact_id.clone()) {
            return Err(DatasetError::DuplicateLabelArtifact);
        }
        if !model_calls.insert(sample.sample.model_call_id.clone()) {
            return Err(DatasetError::Metrics(
                CalibrationError::DuplicateModelCallId,
            ));
        }
    }
    let pure_samples = samples
        .iter()
        .map(DatasetSample::sample)
        .cloned()
        .collect::<Vec<_>>();
    let metrics = evaluate(&pure_samples, thresholds).map_err(DatasetError::Metrics)?;
    Ok(EvaluationReport {
        provenance,
        thresholds,
        sources: samples
            .iter()
            .map(|sample| SourceSampleEvidence {
                model_call: sample.sample.model_call_id.clone(),
                model_call_artifact: sample.model_call_artifact_id.clone(),
                label_artifact: sample.label_artifact_id.clone(),
            })
            .collect(),
        metrics,
    })
}

/// Closed validation failures that reveal no model, label, or evidence content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatasetError {
    /// Provider model wire ID is not a bounded local or `provider/model` identifier.
    InvalidProviderModel,
    /// Declared train/calibration/evaluation/label manifests overlap by ID.
    OverlappingPartitionManifest,
    /// A model-call record and label artifact are the same object.
    SampleEvidenceAliased,
    /// More than one sample selected the same model-call record artifact.
    DuplicateModelCallArtifact,
    /// More than one sample selected the same label evidence artifact.
    DuplicateLabelArtifact,
    /// A source artifact was assigned a model-record and label role across samples.
    CrossRoleEvidenceAliased,
    /// A source record or label artifact aliases a declared partition manifest.
    ManifestSourceEvidenceAliased,
    /// A selected model record differs from the frozen report model identity.
    SampleModelIdentityMismatch,
    /// A selected input record differs from the frozen risk-mapping revision.
    SampleMappingRevisionMismatch,
    /// The pure bounded metric engine rejected its sample collection.
    Metrics(CalibrationError),
}

impl DatasetError {
    /// Returns a stable machine-readable reason code for caller-owned audit.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidProviderModel => "CALIBRATION_PROVIDER_MODEL_INVALID",
            Self::OverlappingPartitionManifest => "CALIBRATION_PARTITION_MANIFEST_OVERLAP",
            Self::SampleEvidenceAliased => "CALIBRATION_SAMPLE_EVIDENCE_ALIASED",
            Self::DuplicateModelCallArtifact => "CALIBRATION_MODEL_CALL_ARTIFACT_DUPLICATE",
            Self::DuplicateLabelArtifact => "CALIBRATION_LABEL_ARTIFACT_DUPLICATE",
            Self::CrossRoleEvidenceAliased => "CALIBRATION_CROSS_ROLE_EVIDENCE_ALIASED",
            Self::ManifestSourceEvidenceAliased => "CALIBRATION_MANIFEST_SOURCE_EVIDENCE_ALIASED",
            Self::SampleModelIdentityMismatch => "CALIBRATION_SAMPLE_MODEL_IDENTITY_MISMATCH",
            Self::SampleMappingRevisionMismatch => "CALIBRATION_SAMPLE_MAPPING_REVISION_MISMATCH",
            Self::Metrics(error) => error.reason_code(),
        }
    }
}

impl fmt::Display for DatasetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for DatasetError {}

fn valid_provider_model_id(value: &str) -> bool {
    let Some((provider, model)) = value.split_once('/') else {
        return valid_component(value);
    };
    !model.contains('/') && valid_component(provider) && valid_component(model)
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
#[path = "dataset/tests.rs"]
mod tests;
