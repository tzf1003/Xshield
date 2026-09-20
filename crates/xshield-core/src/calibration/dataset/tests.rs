use super::*;
use crate::calibration::{Probability, UnavailableReason};

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

fn artifact(index: usize) -> ArtifactId {
    ArtifactId::parse(format!("artifact_018f2a3b-4c5d-7000-8000-{index:012x}")).unwrap()
}

fn call(index: usize) -> ModelCallId {
    ModelCallId::parse(format!("mdl_018f2a3b-4c5d-7000-8000-{index:012x}")).unwrap()
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

fn sample(index: usize, label: GroundTruth, signal: Signal) -> DatasetSample {
    DatasetSample::new(
        call(index),
        artifact(index * 2 + 10),
        artifact(index * 2 + 11),
        model(),
        MappingRevision::parse("risk-map-r1").unwrap(),
        label,
        signal,
    )
    .unwrap()
}

fn thresholds() -> Thresholds {
    Thresholds::new(
        Probability::new(0.2).unwrap(),
        Probability::new(0.8).unwrap(),
    )
    .unwrap()
}

#[test]
fn report_preserves_frozen_provenance_and_source_order() {
    let samples = [
        sample(
            0,
            GroundTruth::Benign,
            Signal::Risk(Probability::new(0.1).unwrap()),
        ),
        sample(
            1,
            GroundTruth::Malicious,
            Signal::Unavailable(UnavailableReason::ModelTimedOut),
        ),
        sample(
            2,
            GroundTruth::Unknown,
            Signal::Risk(Probability::new(0.9).unwrap()),
        ),
    ];
    let report = evaluate_dataset(provenance(), &samples, thresholds()).unwrap();
    assert_eq!(report.reason_code(), "CALIBRATION_DATASET_EVALUATED");
    assert_eq!(report.provenance().approval_ref().as_str(), "approval-r1");
    assert!(!report.provenance().model().exact_provider_revision_known());
    assert_eq!(report.metrics().total_samples, 3);
    assert_eq!(report.metrics().available_samples, 2);
    assert_eq!(report.metrics().scored_samples, 1);
    assert_eq!(report.metrics().unknown_label_samples, 1);
    let sources = report.sources();
    assert_eq!(sources.len(), 3);
    assert_eq!(sources[0].model_call_id(), &call(0));
    assert_eq!(sources[0].model_call_artifact_id(), &artifact(10));
    assert_eq!(sources[0].label_artifact_id(), &artifact(11));
    assert_eq!(sources[1].model_call_id(), &call(1));
    assert_eq!(sources[1].model_call_artifact_id(), &artifact(12));
    assert_eq!(sources[1].label_artifact_id(), &artifact(13));
    assert_eq!(sources[2].model_call_id(), &call(2));
    assert_eq!(sources[2].model_call_artifact_id(), &artifact(14));
    assert_eq!(sources[2].label_artifact_id(), &artifact(15));
}

#[test]
fn identity_and_provenance_reject_invalid_model_or_overlapping_partitions() {
    for provider_model in [
        "",
        "provider/",
        "/model",
        "a/b/c",
        "model space",
        &"x".repeat(129),
        &format!("{}/{}", "p".repeat(64), "m".repeat(64)),
    ] {
        assert_eq!(
            ModelIdentity::new(
                ProviderId::parse("provider").unwrap(),
                provider_model,
                ModelRevision::parse("model-r1").unwrap(),
                PromptRevision::parse("prompt-r1").unwrap(),
                None,
            )
            .err(),
            Some(DatasetError::InvalidProviderModel)
        );
    }
    assert!(
        ModelIdentity::new(
            ProviderId::parse("vercel_ai_gateway").unwrap(),
            "jev",
            ModelRevision::parse("jev-1.13.0").unwrap(),
            PromptRevision::parse("prompt-r1").unwrap(),
            None,
        )
        .is_ok()
    );
    assert!(
        ModelIdentity::new(
            ProviderId::parse("provider").unwrap(),
            format!("{}/{}", "p".repeat(63), "m".repeat(64)),
            ModelRevision::parse("model-r1").unwrap(),
            PromptRevision::parse("prompt-r1").unwrap(),
            None,
        )
        .is_ok()
    );
    let mut duplicate = provenance();
    duplicate.evaluation_manifest_artifact_id = artifact(2);
    assert_eq!(
        EvaluationProvenance::new(
            duplicate.approval_ref,
            duplicate.dataset_revision,
            duplicate.label_revision,
            duplicate.task_revision,
            duplicate.threshold_policy_revision,
            duplicate.mapping_revision,
            duplicate.evaluation_manifest_artifact_id,
            duplicate.training_manifest_artifact_id,
            duplicate.calibration_manifest_artifact_id,
            duplicate.label_manifest_artifact_id,
            duplicate.model,
        )
        .err(),
        Some(DatasetError::OverlappingPartitionManifest)
    );
}

#[test]
fn dataset_rejects_manifest_aliases_for_every_source_role() {
    for (index, manifest_artifact) in [artifact(1), artifact(2), artifact(3), artifact(4)]
        .into_iter()
        .enumerate()
    {
        let record_alias = DatasetSample::new(
            call(index),
            manifest_artifact.clone(),
            artifact(index + 100),
            model(),
            MappingRevision::parse("risk-map-r1").unwrap(),
            GroundTruth::Benign,
            Signal::Risk(Probability::new(0.1).unwrap()),
        )
        .unwrap();
        assert_eq!(
            evaluate_dataset(provenance(), &[record_alias], thresholds()).err(),
            Some(DatasetError::ManifestSourceEvidenceAliased)
        );

        let label_alias = DatasetSample::new(
            call(index + 10),
            artifact(index + 200),
            manifest_artifact,
            model(),
            MappingRevision::parse("risk-map-r1").unwrap(),
            GroundTruth::Benign,
            Signal::Risk(Probability::new(0.1).unwrap()),
        )
        .unwrap();
        assert_eq!(
            evaluate_dataset(provenance(), &[label_alias], thresholds()).err(),
            Some(DatasetError::ManifestSourceEvidenceAliased)
        );
    }
}

#[test]
fn dataset_wrapper_rejects_empty_and_oversized_inputs_with_stable_reasons() {
    let empty = evaluate_dataset(provenance(), &[], thresholds()).unwrap_err();
    assert_eq!(empty, DatasetError::Metrics(CalibrationError::EmptySamples));
    assert_eq!(empty.reason_code(), "CALIBRATION_SAMPLES_EMPTY");

    let signal = Signal::Risk(Probability::new(0.1).unwrap());
    let oversized = (0..=MAX_SAMPLES)
        .map(|index| sample(index, GroundTruth::Benign, signal))
        .collect::<Vec<_>>();
    let too_many = evaluate_dataset(provenance(), &oversized, thresholds()).unwrap_err();
    assert_eq!(
        too_many,
        DatasetError::Metrics(CalibrationError::TooManySamples)
    );
    assert_eq!(too_many.reason_code(), "CALIBRATION_SAMPLE_LIMIT_EXCEEDED");
}

#[test]
fn dataset_rejects_aliases_duplicate_artifacts_and_duplicate_model_calls() {
    assert_eq!(
        DatasetSample::new(
            call(1),
            artifact(1),
            artifact(1),
            model(),
            MappingRevision::parse("risk-map-r1").unwrap(),
            GroundTruth::Benign,
            Signal::Risk(Probability::new(0.1).unwrap()),
        )
        .err(),
        Some(DatasetError::SampleEvidenceAliased)
    );

    let first = sample(
        0,
        GroundTruth::Benign,
        Signal::Risk(Probability::new(0.1).unwrap()),
    );
    let duplicate_record = DatasetSample::new(
        call(1),
        artifact(10),
        artifact(99),
        model(),
        MappingRevision::parse("risk-map-r1").unwrap(),
        GroundTruth::Malicious,
        Signal::Risk(Probability::new(0.9).unwrap()),
    )
    .unwrap();
    assert_eq!(
        evaluate_dataset(
            provenance(),
            &[first.clone(), duplicate_record],
            thresholds()
        )
        .err(),
        Some(DatasetError::DuplicateModelCallArtifact)
    );
    let duplicate_label = DatasetSample::new(
        call(1),
        artifact(98),
        artifact(11),
        model(),
        MappingRevision::parse("risk-map-r1").unwrap(),
        GroundTruth::Malicious,
        Signal::Risk(Probability::new(0.9).unwrap()),
    )
    .unwrap();
    assert_eq!(
        evaluate_dataset(
            provenance(),
            &[first.clone(), duplicate_label],
            thresholds()
        )
        .err(),
        Some(DatasetError::DuplicateLabelArtifact)
    );
    let duplicate_call = DatasetSample::new(
        call(0),
        artifact(98),
        artifact(99),
        model(),
        MappingRevision::parse("risk-map-r1").unwrap(),
        GroundTruth::Malicious,
        Signal::Risk(Probability::new(0.9).unwrap()),
    )
    .unwrap();
    assert_eq!(
        evaluate_dataset(provenance(), &[first, duplicate_call], thresholds()).err(),
        Some(DatasetError::Metrics(
            CalibrationError::DuplicateModelCallId
        ))
    );
}

#[test]
fn dataset_requires_each_record_identity_mapping_and_evidence_roles_to_match() {
    let first = sample(
        0,
        GroundTruth::Benign,
        Signal::Risk(Probability::new(0.1).unwrap()),
    );
    let mismatched_model = DatasetSample::new(
        call(1),
        artifact(12),
        artifact(13),
        ModelIdentity::new(
            ProviderId::parse("typesafe").unwrap(),
            "jev-1.13.0",
            ModelRevision::parse("jev-1.13.0").unwrap(),
            PromptRevision::parse("prompt-r1").unwrap(),
            Some(ModelRevision::parse("jev-1.13.0").unwrap()),
        )
        .unwrap(),
        MappingRevision::parse("risk-map-r1").unwrap(),
        GroundTruth::Malicious,
        Signal::Risk(Probability::new(0.9).unwrap()),
    )
    .unwrap();
    assert_eq!(
        evaluate_dataset(
            provenance(),
            &[first.clone(), mismatched_model],
            thresholds()
        )
        .err(),
        Some(DatasetError::SampleModelIdentityMismatch)
    );
    let mismatched_mapping = DatasetSample::new(
        call(1),
        artifact(12),
        artifact(13),
        model(),
        MappingRevision::parse("risk-map-r2").unwrap(),
        GroundTruth::Malicious,
        Signal::Risk(Probability::new(0.9).unwrap()),
    )
    .unwrap();
    assert_eq!(
        evaluate_dataset(
            provenance(),
            &[first.clone(), mismatched_mapping],
            thresholds()
        )
        .err(),
        Some(DatasetError::SampleMappingRevisionMismatch)
    );
    let cross_role = DatasetSample::new(
        call(1),
        artifact(11),
        artifact(99),
        model(),
        MappingRevision::parse("risk-map-r1").unwrap(),
        GroundTruth::Malicious,
        Signal::Risk(Probability::new(0.9).unwrap()),
    )
    .unwrap();
    assert_eq!(
        evaluate_dataset(provenance(), &[first, cross_role], thresholds()).err(),
        Some(DatasetError::CrossRoleEvidenceAliased)
    );
}

#[test]
fn dataset_reason_codes_do_not_expose_references_or_labels() {
    let cases = [
        (
            DatasetError::InvalidProviderModel,
            "CALIBRATION_PROVIDER_MODEL_INVALID",
        ),
        (
            DatasetError::OverlappingPartitionManifest,
            "CALIBRATION_PARTITION_MANIFEST_OVERLAP",
        ),
        (
            DatasetError::SampleEvidenceAliased,
            "CALIBRATION_SAMPLE_EVIDENCE_ALIASED",
        ),
        (
            DatasetError::DuplicateModelCallArtifact,
            "CALIBRATION_MODEL_CALL_ARTIFACT_DUPLICATE",
        ),
        (
            DatasetError::DuplicateLabelArtifact,
            "CALIBRATION_LABEL_ARTIFACT_DUPLICATE",
        ),
        (
            DatasetError::CrossRoleEvidenceAliased,
            "CALIBRATION_CROSS_ROLE_EVIDENCE_ALIASED",
        ),
        (
            DatasetError::ManifestSourceEvidenceAliased,
            "CALIBRATION_MANIFEST_SOURCE_EVIDENCE_ALIASED",
        ),
        (
            DatasetError::SampleModelIdentityMismatch,
            "CALIBRATION_SAMPLE_MODEL_IDENTITY_MISMATCH",
        ),
        (
            DatasetError::SampleMappingRevisionMismatch,
            "CALIBRATION_SAMPLE_MAPPING_REVISION_MISMATCH",
        ),
    ];
    for (error, reason) in cases {
        assert_eq!(error.reason_code(), reason);
        assert_eq!(error.to_string(), reason);
    }
}
