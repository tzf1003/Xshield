use super::*;
use crate::{
    calibration::{
        GroundTruth, Probability, Signal, Thresholds,
        dataset::{DatasetSample, EvaluationProvenance, evaluate_dataset},
    },
    domain::{
        ApprovalRef, ArtifactId, CalibrationReportId, DatasetRevision, LabelRevision,
        MappingRevision, ModelCallId, ModelRevision, PromptRevision, ProviderId, TaskRevision,
        ThresholdPolicyRevision,
    },
};
use serde_json::{Value, json};

fn artifact(index: usize) -> ArtifactId {
    ArtifactId::parse(format!("artifact_018f2a3b-4c5d-7000-8000-{index:012x}")).unwrap()
}

fn report_id() -> CalibrationReportId {
    CalibrationReportId::parse("calr_018f2a3b-4c5d-7000-8000-000000000099").unwrap()
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
    let samples = [
        DatasetSample::new(
            ModelCallId::parse("mdl_018f2a3b-4c5d-7000-8000-000000000010").unwrap(),
            artifact(10),
            artifact(11),
            model.clone(),
            MappingRevision::parse("risk-map-r1").unwrap(),
            GroundTruth::Benign,
            Signal::Risk(Probability::new(0.1).unwrap()),
        )
        .unwrap(),
        DatasetSample::new(
            ModelCallId::parse("mdl_018f2a3b-4c5d-7000-8000-000000000012").unwrap(),
            artifact(12),
            artifact(13),
            model,
            MappingRevision::parse("risk-map-r1").unwrap(),
            GroundTruth::Malicious,
            Signal::Risk(Probability::new(0.9).unwrap()),
        )
        .unwrap(),
    ];
    evaluate_dataset(
        provenance,
        &samples,
        Thresholds::new(
            Probability::new(-0.0).unwrap(),
            Probability::new(1.0).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn artifact_document() -> CalibrationReportArtifact {
    let report = report();
    let publication =
        CalibrationReportPublication::new(report_id(), artifact(99), &report).unwrap();
    CalibrationReportArtifact::from_evaluation(&publication, &report).unwrap()
}

fn parsed(document: &CalibrationReportArtifact) -> Value {
    serde_json::from_slice(&document.to_canonical_json().unwrap()).unwrap()
}

#[test]
fn artifact_round_trips_to_fixed_bytes_and_canonicalizes_negative_zero() {
    let document = artifact_document();
    let bytes = document.to_canonical_json().unwrap();
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("\"allow_below_or_equal_bits\":\"0000000000000000\"")
    );
    let decoded = CalibrationReportArtifact::from_canonical_json(&bytes).unwrap();
    assert_eq!(decoded, document);
    assert_eq!(decoded.to_canonical_json().unwrap(), bytes);
    assert_eq!(
        decoded
            .sources()
            .iter()
            .map(CalibrationReportArtifactSource::sample_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
}

#[test]
fn artifact_rejects_unknown_prohibited_and_duplicate_fields() {
    let document = artifact_document();
    let mut unknown = parsed(&document);
    unknown["extension"] = Value::Null;
    assert_eq!(
        CalibrationReportArtifact::from_canonical_json(&serde_json::to_vec(&unknown).unwrap()),
        Err(CalibrationReportArtifactError::UnknownField)
    );

    let mut prohibited = parsed(&document);
    prohibited["request_id"] = json!("req_018f2a3b-4c5d-7000-8000-000000000001");
    assert_eq!(
        CalibrationReportArtifact::from_canonical_json(&serde_json::to_vec(&prohibited).unwrap()),
        Err(CalibrationReportArtifactError::ProhibitedField)
    );

    let bytes = String::from_utf8(document.to_canonical_json().unwrap()).unwrap();
    let duplicate = bytes.replacen(
        "\"kind\":\"calibration_evaluation_report\"",
        "\"kind\":\"calibration_evaluation_report\",\"kind\":\"calibration_evaluation_report\"",
        1,
    );
    assert_eq!(
        CalibrationReportArtifact::from_canonical_json(duplicate.as_bytes()),
        Err(CalibrationReportArtifactError::DuplicateField)
    );

    for field in ["label", "ground_truth", "probability"] {
        let mut nested_prohibited = parsed(&document);
        nested_prohibited["sources"][0][field] = Value::Null;
        assert_eq!(
            CalibrationReportArtifact::from_canonical_json(
                &serde_json::to_vec(&nested_prohibited).unwrap()
            ),
            Err(CalibrationReportArtifactError::ProhibitedField),
            "{field}",
        );
    }
}

#[test]
fn artifact_rejects_noncanonical_float_and_source_reordering() {
    let document = artifact_document();
    let mut negative_zero = parsed(&document);
    negative_zero["thresholds"]["allow_below_or_equal_bits"] = json!("8000000000000000");
    assert_eq!(
        CalibrationReportArtifact::from_canonical_json(
            &serde_json::to_vec(&negative_zero).unwrap()
        ),
        Err(CalibrationReportArtifactError::FloatNotCanonical)
    );

    let mut reordered = parsed(&document);
    let sources = reordered["sources"].as_array_mut().unwrap();
    sources.swap(0, 1);
    assert_eq!(
        CalibrationReportArtifact::from_canonical_json(&serde_json::to_vec(&reordered).unwrap()),
        Err(CalibrationReportArtifactError::SourceSetInvalid)
    );

    let mut cross_role_alias = parsed(&document);
    let label_artifact = cross_role_alias["sources"][1]["label_artifact_id"].clone();
    cross_role_alias["sources"][0]["model_call_artifact_id"] = label_artifact;
    assert_eq!(
        CalibrationReportArtifact::from_canonical_json(
            &serde_json::to_vec(&cross_role_alias).unwrap()
        ),
        Err(CalibrationReportArtifactError::SourceSetInvalid)
    );

    let bytes = String::from_utf8(document.to_canonical_json().unwrap()).unwrap();
    let without_kind = bytes.replacen("\"kind\":\"calibration_evaluation_report\",", "", 1);
    let reordered_keys = without_kind.replacen(
        "\"schema_version\":1,",
        "\"schema_version\":1,\"kind\":\"calibration_evaluation_report\",",
        1,
    );
    assert_eq!(
        CalibrationReportArtifact::from_canonical_json(reordered_keys.as_bytes()),
        Err(CalibrationReportArtifactError::NonCanonicalEncoding)
    );
}
