//! Minimal immutable metadata for publishing an offline calibration report.
//!
//! The report artifact retains detailed metrics and source tuples under the
//! evidence access boundary. This domain projection carries only frozen
//! provenance and its report artifact, so an index event cannot expose labels,
//! probabilities, source artifacts, or model payloads.

use super::dataset::{EvaluationReport, ModelIdentity};
use crate::domain::{
    ApprovalRef, ArtifactId, CalibrationReportId, DatasetRevision, LabelRevision, MappingRevision,
    TaskRevision, ThresholdPolicyRevision,
};
use std::fmt;

mod artifact;

pub use artifact::{
    CALIBRATION_REPORT_ARTIFACT_CONTENT_TYPE, CALIBRATION_REPORT_ARTIFACT_KIND,
    CALIBRATION_REPORT_ARTIFACT_SCHEMA_VERSION, CalibrationReportArtifact,
    CalibrationReportArtifactError, CalibrationReportArtifactSource,
};

/// Immutable, non-content metadata for one independently durable report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationReportPublication {
    report_id: CalibrationReportId,
    report_artifact_id: ArtifactId,
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

impl CalibrationReportPublication {
    /// Projects a completed report into metadata suitable for a separate audit chain.
    ///
    /// The report artifact must not reuse a partition manifest or any selected
    /// model-record/label artifact. The projection has no I/O, publication,
    /// authorization, or policy effect; callers persist the protected report
    /// and its independent terminal atomically in their application layer.
    ///
    /// # Errors
    /// Returns [`PublicationError::ReportEvidenceAliased`] when the proposed
    /// report artifact collides with a frozen provenance or source reference.
    pub fn new(
        report_id: CalibrationReportId,
        report_artifact_id: ArtifactId,
        report: &EvaluationReport,
    ) -> Result<Self, PublicationError> {
        let provenance = report.provenance();
        let manifest_alias = [
            provenance.evaluation_manifest_artifact_id(),
            provenance.training_manifest_artifact_id(),
            provenance.calibration_manifest_artifact_id(),
            provenance.label_manifest_artifact_id(),
        ]
        .into_iter()
        .any(|artifact| artifact == &report_artifact_id);
        let source_alias = report.sources().iter().any(|source| {
            source.model_call_artifact_id() == &report_artifact_id
                || source.label_artifact_id() == &report_artifact_id
        });
        if manifest_alias || source_alias {
            return Err(PublicationError::ReportEvidenceAliased);
        }
        Ok(Self {
            report_id,
            report_artifact_id,
            approval_ref: provenance.approval_ref().clone(),
            dataset_revision: provenance.dataset_revision().clone(),
            label_revision: provenance.label_revision().clone(),
            task_revision: provenance.task_revision().clone(),
            threshold_policy_revision: provenance.threshold_policy_revision().clone(),
            mapping_revision: provenance.mapping_revision().clone(),
            evaluation_manifest_artifact_id: provenance.evaluation_manifest_artifact_id().clone(),
            training_manifest_artifact_id: provenance.training_manifest_artifact_id().clone(),
            calibration_manifest_artifact_id: provenance.calibration_manifest_artifact_id().clone(),
            label_manifest_artifact_id: provenance.label_manifest_artifact_id().clone(),
            model: provenance.model().clone(),
        })
    }

    /// Returns the independently generated immutable report identity.
    #[must_use]
    pub const fn report_id(&self) -> &CalibrationReportId {
        &self.report_id
    }

    /// Returns the protected report artifact reference.
    #[must_use]
    pub const fn report_artifact_id(&self) -> &ArtifactId {
        &self.report_artifact_id
    }

    /// Returns the approved external-disclosure reference.
    #[must_use]
    pub const fn approval_ref(&self) -> &ApprovalRef {
        &self.approval_ref
    }

    /// Returns the frozen held-out dataset revision.
    #[must_use]
    pub const fn dataset_revision(&self) -> &DatasetRevision {
        &self.dataset_revision
    }

    /// Returns the reviewed label revision.
    #[must_use]
    pub const fn label_revision(&self) -> &LabelRevision {
        &self.label_revision
    }

    /// Returns the frozen task semantics revision.
    #[must_use]
    pub const fn task_revision(&self) -> &TaskRevision {
        &self.task_revision
    }

    /// Returns the frozen threshold-policy revision.
    #[must_use]
    pub const fn threshold_policy_revision(&self) -> &ThresholdPolicyRevision {
        &self.threshold_policy_revision
    }

    /// Returns the frozen approved risk-mapping revision.
    #[must_use]
    pub const fn mapping_revision(&self) -> &MappingRevision {
        &self.mapping_revision
    }

    /// Returns the held-out evaluation manifest reference.
    #[must_use]
    pub const fn evaluation_manifest_artifact_id(&self) -> &ArtifactId {
        &self.evaluation_manifest_artifact_id
    }

    /// Returns the training manifest reference.
    #[must_use]
    pub const fn training_manifest_artifact_id(&self) -> &ArtifactId {
        &self.training_manifest_artifact_id
    }

    /// Returns the calibration manifest reference.
    #[must_use]
    pub const fn calibration_manifest_artifact_id(&self) -> &ArtifactId {
        &self.calibration_manifest_artifact_id
    }

    /// Returns the label manifest reference.
    #[must_use]
    pub const fn label_manifest_artifact_id(&self) -> &ArtifactId {
        &self.label_manifest_artifact_id
    }

    /// Returns the frozen provider, model, and prompt identity.
    #[must_use]
    pub const fn model(&self) -> &ModelIdentity {
        &self.model
    }

    /// Returns the stable successful reason for the separate audit terminal.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        "CALIBRATION_REPORTED"
    }
}

/// Closed failures for the report-publication metadata projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationError {
    /// The proposed report artifact reuses a manifest or selected source artifact.
    ReportEvidenceAliased,
}

impl PublicationError {
    /// Returns the stable machine-readable reason code for caller-owned audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::ReportEvidenceAliased => "CALIBRATION_REPORT_EVIDENCE_ALIASED",
        }
    }
}

impl fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for PublicationError {}

#[cfg(test)]
#[path = "publication/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "publication/artifact_tests.rs"]
mod artifact_tests;
