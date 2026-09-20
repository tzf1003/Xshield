use super::*;
use crate::{
    calibration::{
        GroundTruth, Probability, Signal, Thresholds,
        dataset::{DatasetSample, EvaluationProvenance, ModelIdentity, evaluate_dataset},
    },
    domain::{
        ApprovalRef, ArtifactId, CalibrationReportId, DatasetRevision, LabelRevision,
        MappingRevision, ModelCallId, ModelRevision, PromptRevision, ProviderId, TaskRevision,
        ThresholdPolicyRevision,
    },
};

fn artifact(index: usize) -> ArtifactId {
    ArtifactId::parse(format!("artifact_018f2a3b-4c5d-7000-8000-{index:012x}")).unwrap()
}

fn report() -> EvaluationReport {
    let model = ModelIdentity::new(
        ProviderId::parse("vercel_ai_gateway").unwrap(),
        "typesafe-ai/jev",
        ModelRevision::parse("jev-1.13.0").unwrap(),
        PromptRevision::parse("prompt-r1").unwrap(),
        None,
    )
    .unwrap();
    let provenance = EvaluationProvenance::new(
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
        model.clone(),
    )
    .unwrap();
    let sample = DatasetSample::new(
        ModelCallId::parse("mdl_018f2a3b-4c5d-7000-8000-000000000010").unwrap(),
        artifact(10),
        artifact(11),
        model,
        MappingRevision::parse("risk-map-r1").unwrap(),
        GroundTruth::Benign,
        Signal::Risk(Probability::new(0.1).unwrap()),
    )
    .unwrap();
    evaluate_dataset(
        provenance,
        &[sample],
        Thresholds::new(
            Probability::new(0.2).unwrap(),
            Probability::new(0.8).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn report_id() -> CalibrationReportId {
    CalibrationReportId::parse("calr_018f2a3b-4c5d-7000-8000-000000000099").unwrap()
}

#[test]
fn publication_preserves_frozen_metadata_and_explicit_unknown_revision() {
    let publication =
        CalibrationReportPublication::new(report_id(), artifact(99), &report()).unwrap();
    assert_eq!(publication.reason_code(), "CALIBRATION_REPORTED");
    assert_eq!(
        publication.report_id().as_str(),
        "calr_018f2a3b-4c5d-7000-8000-000000000099"
    );
    assert_eq!(publication.report_artifact_id(), &artifact(99));
    assert_eq!(publication.dataset_revision().as_str(), "dataset-r1");
    assert_eq!(publication.evaluation_manifest_artifact_id(), &artifact(1));
    assert!(!publication.model().exact_provider_revision_known());
}

#[test]
fn publication_rejects_report_artifact_aliases_without_exposing_sources() {
    for index in [1, 2, 3, 4, 10, 11] {
        assert_eq!(
            CalibrationReportPublication::new(report_id(), artifact(index), &report()).err(),
            Some(PublicationError::ReportEvidenceAliased)
        );
    }
    let error = PublicationError::ReportEvidenceAliased;
    assert_eq!(error.reason_code(), "CALIBRATION_REPORT_EVIDENCE_ALIASED");
    assert_eq!(error.to_string(), "CALIBRATION_REPORT_EVIDENCE_ALIASED");
}
