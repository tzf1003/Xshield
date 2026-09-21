use super::*;
use crate::{
    calibration::{
        GroundTruth, Probability, Signal, Thresholds,
        dataset::{DatasetSample, EvaluationProvenance, ModelIdentity, evaluate_dataset},
    },
    domain::{
        ApprovalRef, ArtifactId, CalibrationReadCapabilityId, CalibrationReadLeaseId,
        DatasetRevision, LabelRevision, MappingRevision, ModelCallId, ModelRevision,
        PromptRevision, ProviderId, TaskRevision, ThresholdPolicyRevision,
    },
    ports::{CalibrationEvidenceReadDenied, CalibrationEvidenceReadRequest},
};

fn artifact(index: usize) -> ArtifactId {
    ArtifactId::parse(format!("artifact_018f2a3b-4c5d-7000-8000-{index:012x}")).unwrap()
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
        ModelIdentity::new(
            ProviderId::parse("vercel_ai_gateway").unwrap(),
            "typesafe-ai/jev",
            ModelRevision::parse("jev-1.13.0").unwrap(),
            PromptRevision::parse("prompt-r1").unwrap(),
            None,
        )
        .unwrap(),
    )
    .unwrap()
}

fn capability(
    sources: Vec<CalibrationSampleReadScope>,
) -> Result<CalibrationEvidenceReadCapability, CalibrationReadCapabilityError> {
    capability_with_id(
        CalibrationReadCapabilityId::parse("calcap_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
        sources,
    )
}

fn capability_with_id(
    capability_id: CalibrationReadCapabilityId,
    sources: Vec<CalibrationSampleReadScope>,
) -> Result<CalibrationEvidenceReadCapability, CalibrationReadCapabilityError> {
    CalibrationEvidenceReadCapability::new(
        capability_id,
        TenantId::parse("tenant_demo").unwrap(),
        SiteId::parse("site_demo").unwrap(),
        provenance(),
        sources,
        UnixSeconds::new(100),
        UnixSeconds::new(200),
        1024,
    )
}

#[test]
fn read_request_requires_current_scope_lease_and_exact_capability_reference() {
    let capability = capability(vec![source(10, 11)]).unwrap();
    let tenant = TenantId::parse("tenant_demo").unwrap();
    let site = SiteId::parse("site_demo").unwrap();
    let own_ref = capability.evidence_refs().pop().unwrap();
    let session = session(&capability, 110, 190, [7; 32], 150).unwrap();

    let request = CalibrationEvidenceReadRequest::new(
        &session,
        &capability,
        &own_ref,
        &tenant,
        &site,
        UnixSeconds::new(150),
    )
    .unwrap();
    assert_eq!(
        request.capability().capability_id(),
        capability.capability_id()
    );
    assert_eq!(request.session().capability(), &capability);
    assert_eq!(request.session().lease().lease_id(), &lease_id(1));
    assert_eq!(request.evidence_ref(), &own_ref);
    assert_eq!(request.tenant_id(), &tenant);
    assert_eq!(request.site_id(), &site);
    assert_eq!(request.now(), UnixSeconds::new(150));

    for (wrong_tenant, wrong_site, now) in [
        (TenantId::parse("tenant_other").unwrap(), site.clone(), 150),
        (tenant.clone(), site.clone(), 99),
        (tenant.clone(), site.clone(), 200),
    ] {
        assert!(matches!(
            CalibrationEvidenceReadRequest::new(
                &session,
                &capability,
                &own_ref,
                &wrong_tenant,
                &wrong_site,
                UnixSeconds::new(now),
            ),
            Err(CalibrationEvidenceReadDenied::EvidenceNotAuthorized)
        ));
    }

    let other_capability = capability_with_id(
        CalibrationReadCapabilityId::parse("calcap_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
        vec![source(10, 11)],
    )
    .unwrap();
    let other_ref = other_capability.evidence_refs().pop().unwrap();
    assert_eq!(own_ref.artifact_id(), other_ref.artifact_id());
    assert_eq!(own_ref.role(), other_ref.role());
    assert_eq!(own_ref.sample_index(), other_ref.sample_index());
    assert!(matches!(
        CalibrationEvidenceReadRequest::new(
            &session,
            &capability,
            &other_ref,
            &tenant,
            &site,
            UnixSeconds::new(150),
        ),
        Err(CalibrationEvidenceReadDenied::EvidenceNotAuthorized)
    ));
    assert_eq!(
        CalibrationEvidenceReadDenied::EvidenceNotAuthorized.reason_code(),
        "CALIBRATION_EVIDENCE_NOT_AUTHORIZED"
    );
}

fn session(
    capability: &CalibrationEvidenceReadCapability,
    not_before: u64,
    expires_at: u64,
    token: [u8; 32],
    now: u64,
) -> Result<CalibrationEvidenceReadSession<'_>, CalibrationReadCapabilityError> {
    capability.bind_issued_batch_lease(
        CalibrationEvidenceBatchLease::from_issued(
            lease_id(1),
            capability.capability_id().clone(),
            capability.tenant_id().clone(),
            capability.site_id().clone(),
            UnixSeconds::new(not_before),
            UnixSeconds::new(expires_at),
            token,
        )?,
        UnixSeconds::new(now),
    )
}

fn lease_id(index: usize) -> CalibrationReadLeaseId {
    CalibrationReadLeaseId::parse(format!("callease_018f2a3b-4c5d-7000-8000-{index:012x}")).unwrap()
}

#[test]
fn read_request_requires_an_exact_issued_batch_session() {
    let batch_capability = capability(vec![source(10, 11)]).unwrap();
    let tenant = TenantId::parse("tenant_demo").unwrap();
    let site = SiteId::parse("site_demo").unwrap();
    let own_ref = batch_capability.evidence_refs().pop().unwrap();
    let batch_session = session(&batch_capability, 110, 190, [7; 32], 150).unwrap();

    let same_identity_different_value = capability(vec![source(10, 11)]).unwrap();
    assert_eq!(
        same_identity_different_value.capability_id(),
        batch_capability.capability_id()
    );
    assert!(matches!(
        CalibrationEvidenceReadRequest::new(
            &batch_session,
            &same_identity_different_value,
            &own_ref,
            &tenant,
            &site,
            UnixSeconds::new(150),
        ),
        Err(CalibrationEvidenceReadDenied::EvidenceNotAuthorized)
    ));

    let other_capability = capability_with_id(
        CalibrationReadCapabilityId::parse("calcap_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
        vec![source(10, 11)],
    )
    .unwrap();
    let other_session = session(&other_capability, 110, 190, [8; 32], 150).unwrap();
    assert!(matches!(
        CalibrationEvidenceReadRequest::new(
            &other_session,
            &batch_capability,
            &own_ref,
            &tenant,
            &site,
            UnixSeconds::new(150),
        ),
        Err(CalibrationEvidenceReadDenied::EvidenceNotAuthorized)
    ));
    let other_ref = other_capability.evidence_refs().pop().unwrap();
    assert!(matches!(
        CalibrationEvidenceReadRequest::new(
            &batch_session,
            &batch_capability,
            &other_ref,
            &tenant,
            &site,
            UnixSeconds::new(150),
        ),
        Err(CalibrationEvidenceReadDenied::EvidenceNotAuthorized)
    ));
}

#[test]
fn batch_session_rejects_invalid_mismatched_or_out_of_scope_issued_leases() {
    let capability = capability(vec![source(10, 11)]).unwrap();
    assert!(matches!(
        CalibrationEvidenceBatchLease::from_issued(
            lease_id(1),
            capability.capability_id().clone(),
            capability.tenant_id().clone(),
            capability.site_id().clone(),
            UnixSeconds::new(110),
            UnixSeconds::new(110),
            [7; 32],
        ),
        Err(CalibrationReadCapabilityError::BatchLeaseInvalid)
    ));
    assert!(matches!(
        CalibrationEvidenceBatchLease::from_issued(
            lease_id(1),
            capability.capability_id().clone(),
            capability.tenant_id().clone(),
            capability.site_id().clone(),
            UnixSeconds::new(110),
            UnixSeconds::new(190),
            [0; 32],
        ),
        Err(CalibrationReadCapabilityError::BatchLeaseInvalid)
    ));
    let wrong_scope = CalibrationEvidenceBatchLease::from_issued(
        lease_id(1),
        capability.capability_id().clone(),
        TenantId::parse("tenant_other").unwrap(),
        capability.site_id().clone(),
        UnixSeconds::new(110),
        UnixSeconds::new(190),
        [7; 32],
    )
    .unwrap();
    assert!(matches!(
        capability.bind_issued_batch_lease(wrong_scope, UnixSeconds::new(150)),
        Err(CalibrationReadCapabilityError::BatchLeaseMismatch)
    ));
    for (not_before, expires_at, now) in [(99, 190, 150), (110, 201, 150), (110, 190, 109)] {
        assert!(matches!(
            session(&capability, not_before, expires_at, [7; 32], now),
            Err(CalibrationReadCapabilityError::BatchLeaseOutsideCapability)
        ));
    }
}

fn source(model: usize, label: usize) -> CalibrationSampleReadScope {
    CalibrationSampleReadScope::new(artifact(model), artifact(label))
}

fn completed_report(
    provenance: EvaluationProvenance,
    sources: &[CalibrationSampleReadScope],
) -> EvaluationReport {
    let samples = sources
        .iter()
        .enumerate()
        .map(|(index, source)| {
            DatasetSample::new(
                ModelCallId::parse(format!("mdl_018f2a3b-4c5d-7000-8000-{index:012x}")).unwrap(),
                source.model_call_artifact_id().clone(),
                source.label_artifact_id().clone(),
                provenance.model().clone(),
                provenance.mapping_revision().clone(),
                GroundTruth::Benign,
                Signal::Risk(Probability::new(0.1).unwrap()),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    evaluate_dataset(
        provenance,
        &samples,
        Thresholds::new(
            Probability::new(0.2).unwrap(),
            Probability::new(0.8).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn completion_consumes_only_a_full_evaluator_result_for_the_exact_session() {
    let sources = vec![source(10, 11), source(12, 13)];
    let capability = capability(sources.clone()).unwrap();
    let issued_session = session(&capability, 110, 190, [7; 32], 150).unwrap();
    let completion = CalibrationEvidenceBatchCompletion::from_successful_evaluation(
        issued_session,
        completed_report(capability.provenance().clone(), &sources),
    )
    .unwrap();
    assert_eq!(
        completion.session().lease().capability_id(),
        capability.capability_id()
    );
    assert_eq!(completion.report().sources().len(), 2);

    let source_mismatch = CalibrationEvidenceBatchCompletion::from_successful_evaluation(
        session(&capability, 110, 190, [8; 32], 150).unwrap(),
        completed_report(
            capability.provenance().clone(),
            &[source(10, 11), source(14, 15)],
        ),
    )
    .err()
    .expect("partial or substituted result is rejected");
    assert_eq!(
        source_mismatch,
        CalibrationEvidenceBatchCompletionError::SourceSetMismatch
    );

    let mismatched_provenance = EvaluationProvenance::new(
        ApprovalRef::parse("approval-r2").unwrap(),
        DatasetRevision::parse("dataset-r1").unwrap(),
        LabelRevision::parse("labels-r1").unwrap(),
        TaskRevision::parse("task-r1").unwrap(),
        ThresholdPolicyRevision::parse("threshold-r1").unwrap(),
        MappingRevision::parse("risk-map-r1").unwrap(),
        artifact(1),
        artifact(2),
        artifact(3),
        artifact(4),
        capability.provenance().model().clone(),
    )
    .unwrap();
    let provenance_mismatch = CalibrationEvidenceBatchCompletion::from_successful_evaluation(
        session(&capability, 110, 190, [9; 32], 150).unwrap(),
        completed_report(mismatched_provenance, &sources),
    )
    .err()
    .expect("different evaluator provenance is rejected");
    assert_eq!(
        provenance_mismatch,
        CalibrationEvidenceBatchCompletionError::ProvenanceMismatch
    );
    assert_eq!(
        source_mismatch.reason_code(),
        "CALIBRATION_READ_BATCH_COMPLETION_SOURCE_SET_MISMATCH"
    );
    assert_eq!(
        provenance_mismatch.reason_code(),
        "CALIBRATION_READ_BATCH_COMPLETION_PROVENANCE_MISMATCH"
    );
}

#[test]
fn capability_freezes_complete_ordered_batch_without_console_authority() {
    let capability = capability(vec![source(10, 11), source(12, 13)]).unwrap();
    assert_eq!(
        capability.capability_id().as_str(),
        "calcap_018f2a3b-4c5d-7000-8000-000000000001"
    );
    assert_eq!(
        capability.provenance().approval_ref().as_str(),
        "approval-r1"
    );
    assert_eq!(capability.sources(), [source(10, 11), source(12, 13)]);
    assert_eq!(capability.max_total_bytes(), 1024);
    let refs = capability.evidence_refs();
    assert_eq!(refs.len(), 8);
    assert_eq!(refs[0].role(), CalibrationEvidenceRole::TrainingManifest);
    assert_eq!(refs[3].role(), CalibrationEvidenceRole::LabelManifest);
    assert_eq!(refs[4].role(), CalibrationEvidenceRole::ModelCallRecord);
    assert_eq!(refs[4].sample_index(), Some(0));
    assert_eq!(refs[7].role(), CalibrationEvidenceRole::ReviewedLabel);
    assert_eq!(refs[7].sample_index(), Some(1));
    assert_eq!(refs[7].artifact_id(), &artifact(13));
    assert_eq!(
        CalibrationEvidenceRole::ReviewedLabel.as_str(),
        "reviewed_label"
    );
}

#[test]
fn capability_rechecks_exact_scope_and_exclusive_lease() {
    let capability = capability(vec![source(10, 11)]).unwrap();
    let tenant = TenantId::parse("tenant_demo").unwrap();
    let site = SiteId::parse("site_demo").unwrap();
    assert_eq!(
        capability.verify_read_scope(&tenant, &site, UnixSeconds::new(100)),
        Ok(())
    );
    assert_eq!(
        capability.verify_read_scope(&tenant, &site, UnixSeconds::new(199)),
        Ok(())
    );
    assert_eq!(
        capability.verify_read_scope(&tenant, &site, UnixSeconds::new(99)),
        Err(CalibrationReadCapabilityError::NotYetValid)
    );
    assert_eq!(
        capability.verify_read_scope(&tenant, &site, UnixSeconds::new(200)),
        Err(CalibrationReadCapabilityError::Expired)
    );
    assert_eq!(
        capability.verify_read_scope(
            &TenantId::parse("tenant_other").unwrap(),
            &site,
            UnixSeconds::new(150)
        ),
        Err(CalibrationReadCapabilityError::ScopeMismatch)
    );
}

#[test]
fn capability_rejects_unbounded_or_aliased_source_sets() {
    assert_eq!(
        capability(vec![]),
        Err(CalibrationReadCapabilityError::EmptySamples)
    );
    assert_eq!(
        capability(vec![source(10, 10)]),
        Err(CalibrationReadCapabilityError::SampleEvidenceAliased)
    );
    for sources in [
        vec![source(1, 11)],
        vec![source(10, 2)],
        vec![source(10, 11), source(10, 12)],
    ] {
        assert_eq!(
            capability(sources),
            Err(CalibrationReadCapabilityError::EvidenceReferenceAliased)
        );
    }
    let capability_id =
        CalibrationReadCapabilityId::parse("calcap_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
    let tenant = TenantId::parse("tenant_demo").unwrap();
    let site = SiteId::parse("site_demo").unwrap();
    for (not_before, expires_at, bytes, error) in [
        (100, 100, 1024, CalibrationReadCapabilityError::LeaseInvalid),
        (
            100,
            200,
            0,
            CalibrationReadCapabilityError::ByteLimitInvalid,
        ),
        (
            100,
            200,
            MAX_CALIBRATION_BATCH_BYTES + 1,
            CalibrationReadCapabilityError::ByteLimitInvalid,
        ),
    ] {
        assert_eq!(
            CalibrationEvidenceReadCapability::new(
                capability_id.clone(),
                tenant.clone(),
                site.clone(),
                provenance(),
                vec![source(10, 11)],
                UnixSeconds::new(not_before),
                UnixSeconds::new(expires_at),
                bytes,
            ),
            Err(error)
        );
    }
    assert_eq!(
        capability(vec![source(10, 11); MAX_SAMPLES + 1]),
        Err(CalibrationReadCapabilityError::TooManySamples)
    );
}

#[test]
fn capability_errors_are_stable_and_payload_free() {
    for (error, reason) in [
        (
            CalibrationReadCapabilityError::EmptySamples,
            "CALIBRATION_READ_SAMPLES_EMPTY",
        ),
        (
            CalibrationReadCapabilityError::TooManySamples,
            "CALIBRATION_READ_SAMPLES_EXCEEDED",
        ),
        (
            CalibrationReadCapabilityError::ByteLimitInvalid,
            "CALIBRATION_READ_BYTES_INVALID",
        ),
        (
            CalibrationReadCapabilityError::LeaseInvalid,
            "CALIBRATION_READ_LEASE_INVALID",
        ),
        (
            CalibrationReadCapabilityError::SampleEvidenceAliased,
            "CALIBRATION_READ_SAMPLE_EVIDENCE_ALIASED",
        ),
        (
            CalibrationReadCapabilityError::EvidenceReferenceAliased,
            "CALIBRATION_READ_EVIDENCE_ALIASED",
        ),
        (
            CalibrationReadCapabilityError::ScopeMismatch,
            "CALIBRATION_READ_SCOPE_MISMATCH",
        ),
        (
            CalibrationReadCapabilityError::NotYetValid,
            "CALIBRATION_READ_NOT_YET_VALID",
        ),
        (
            CalibrationReadCapabilityError::Expired,
            "CALIBRATION_READ_EXPIRED",
        ),
    ] {
        assert_eq!(error.reason_code(), reason);
        assert_eq!(error.to_string(), reason);
    }
}
