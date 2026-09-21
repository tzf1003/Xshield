use super::{
    LineageReviewError, LineageSourceDeclaration, LineageSourceKind, LineageSourceRef,
    PartitionLineageSubmission, PartitionManifestDeclaration, PartitionRole,
    review_partition_lineage,
};
use crate::{
    calibration::dataset::{EvaluationProvenance, ModelIdentity},
    domain::{
        ApprovalRef, ArtifactId, CalibrationLineageReviewId, DatasetRevision, LabelRevision,
        MappingRevision, ModelRevision, PromptRevision, ProviderId, TaskRevision,
        ThresholdPolicyRevision,
    },
};

fn artifact(index: u8) -> ArtifactId {
    ArtifactId::parse(format!(
        "artifact_018f2a3b-4c5d-7000-8000-0000000000{index:02}"
    ))
    .unwrap()
}

fn provenance() -> EvaluationProvenance {
    EvaluationProvenance::new(
        ApprovalRef::parse("approval-r1").unwrap(),
        DatasetRevision::parse("dataset-r1").unwrap(),
        LabelRevision::parse("labels-r1").unwrap(),
        TaskRevision::parse("task-r1").unwrap(),
        ThresholdPolicyRevision::parse("threshold-r1").unwrap(),
        MappingRevision::parse("mapping-r1").unwrap(),
        artifact(1),
        artifact(2),
        artifact(3),
        artifact(4),
        ModelIdentity::new(
            ProviderId::parse("vercel_ai_gateway").unwrap(),
            "typesafe-ai/jev",
            ModelRevision::parse("jev-r1").unwrap(),
            PromptRevision::parse("prompt-r1").unwrap(),
            None,
        )
        .unwrap(),
    )
    .unwrap()
}

fn review_id() -> CalibrationLineageReviewId {
    CalibrationLineageReviewId::parse("calrev_018f2a3b-4c5d-7000-8000-000000000099").unwrap()
}

fn source_ref(source_id: &str) -> LineageSourceRef {
    let revision = if source_id == "train-derived" {
        "revision-r2"
    } else {
        "revision-r1"
    };
    LineageSourceRef::new(source_id, revision).unwrap()
}

fn declaration(
    role: PartitionRole,
    artifact_id: ArtifactId,
    source: &str,
) -> PartitionManifestDeclaration {
    PartitionManifestDeclaration::new(role, artifact_id, vec![source_ref(source)]).unwrap()
}

fn source(
    source_id: &str,
    partition: PartitionRole,
    kind: LineageSourceKind,
    parents: &[&str],
) -> LineageSourceDeclaration {
    LineageSourceDeclaration::new(
        source_ref(source_id),
        partition,
        kind,
        parents.iter().map(|parent| source_ref(parent)).collect(),
    )
    .unwrap()
}

fn valid_submission() -> PartitionLineageSubmission {
    PartitionLineageSubmission::new(
        vec![
            declaration(PartitionRole::Training, artifact(2), "train-derived"),
            declaration(PartitionRole::Calibration, artifact(3), "calibration-root"),
            declaration(PartitionRole::Evaluation, artifact(1), "evaluation-root"),
            declaration(PartitionRole::Label, artifact(4), "label-root"),
        ],
        vec![
            source(
                "train-derived",
                PartitionRole::Training,
                LineageSourceKind::Corpus,
                &["train-root"],
            ),
            source(
                "train-root",
                PartitionRole::Training,
                LineageSourceKind::Corpus,
                &[],
            ),
            source(
                "calibration-root",
                PartitionRole::Calibration,
                LineageSourceKind::Corpus,
                &[],
            ),
            source(
                "evaluation-root",
                PartitionRole::Evaluation,
                LineageSourceKind::Corpus,
                &[],
            ),
            source(
                "label-root",
                PartitionRole::Label,
                LineageSourceKind::ReviewedLabel,
                &[],
            ),
        ],
    )
    .unwrap()
}

#[test]
fn reviews_exact_manifest_bindings_and_a_declaration_only_graph() {
    let review =
        review_partition_lineage(review_id(), artifact(99), provenance(), &valid_submission())
            .unwrap();
    assert_eq!(
        review.reason_code(),
        "CALIBRATION_PARTITION_LINEAGE_REVIEWED"
    );
    assert_eq!(review.schema_version(), 1);
    assert_eq!(review.policy_revision(), "calibration-lineage-v1");
    assert_eq!(review.partitions().len(), 4);
    assert_eq!(review.sources().len(), 5);
    assert_eq!(review.partitions()[0].role(), PartitionRole::Training);
    assert_eq!(review.sources()[0].source_id(), "calibration-root");
}

#[test]
fn rejects_review_artifact_or_manifest_role_drift() {
    assert_eq!(
        review_partition_lineage(review_id(), artifact(1), provenance(), &valid_submission()),
        Err(LineageReviewError::ReviewArtifactAliased)
    );
    let mut submission = valid_submission();
    submission.declarations[0] = declaration(PartitionRole::Training, artifact(5), "train-derived");
    assert_eq!(
        review_partition_lineage(review_id(), artifact(99), provenance(), &submission),
        Err(LineageReviewError::ManifestProvenanceMismatch)
    );
}

#[test]
fn rejects_cross_partition_parentage_and_label_substitution() {
    let mut submission = valid_submission();
    submission.sources[2] = source(
        "calibration-root",
        PartitionRole::Calibration,
        LineageSourceKind::Corpus,
        &["evaluation-root"],
    );
    assert_eq!(
        review_partition_lineage(review_id(), artifact(99), provenance(), &submission),
        Err(LineageReviewError::CrossPartitionLineageDeclared)
    );

    let mut submission = valid_submission();
    submission.sources[4] = source(
        "label-root",
        PartitionRole::Label,
        LineageSourceKind::Corpus,
        &[],
    );
    assert_eq!(
        review_partition_lineage(review_id(), artifact(99), provenance(), &submission),
        Err(LineageReviewError::SourceKindPartitionMismatch)
    );
}

#[test]
fn rejects_unknown_cycles_and_unreachable_declarations() {
    let mut submission = valid_submission();
    submission.sources[0] = source(
        "train-derived",
        PartitionRole::Training,
        LineageSourceKind::Corpus,
        &["missing"],
    );
    assert_eq!(
        review_partition_lineage(review_id(), artifact(99), provenance(), &submission),
        Err(LineageReviewError::UnknownParentSource)
    );

    let mut submission = valid_submission();
    submission.sources[0] = source(
        "train-derived",
        PartitionRole::Training,
        LineageSourceKind::Corpus,
        &["train-root"],
    );
    submission.sources[1] = source(
        "train-root",
        PartitionRole::Training,
        LineageSourceKind::Corpus,
        &["train-derived"],
    );
    assert_eq!(
        review_partition_lineage(review_id(), artifact(99), provenance(), &submission),
        Err(LineageReviewError::LineageCycle)
    );

    let mut submission = valid_submission();
    submission.sources.push(source(
        "unused-root",
        PartitionRole::Training,
        LineageSourceKind::Corpus,
        &[],
    ));
    assert_eq!(
        review_partition_lineage(review_id(), artifact(99), provenance(), &submission),
        Err(LineageReviewError::UnreachableSource)
    );
}

#[test]
fn constructors_reject_ambiguous_local_declarations() {
    assert_eq!(
        PartitionManifestDeclaration::new(PartitionRole::Training, artifact(1), Vec::new()),
        Err(LineageReviewError::PartitionSourcesEmpty)
    );
    assert_eq!(
        LineageSourceDeclaration::new(
            source_ref("same"),
            PartitionRole::Training,
            LineageSourceKind::Corpus,
            vec![source_ref("same")],
        ),
        Err(LineageReviewError::SourceSelfReference)
    );
}

#[test]
fn source_revisions_and_reference_order_are_part_of_the_canonical_graph() {
    let root_v1 = LineageSourceRef::new("same-source", "revision-r1").unwrap();
    let root_v2 = LineageSourceRef::new("same-source", "revision-r2").unwrap();
    let parent_a = LineageSourceRef::new("parent-a", "revision-r1").unwrap();
    let parent_b = LineageSourceRef::new("parent-b", "revision-r1").unwrap();
    let node = LineageSourceRef::new("child", "revision-r1").unwrap();
    let first = LineageSourceDeclaration::new(
        node.clone(),
        PartitionRole::Training,
        LineageSourceKind::Corpus,
        vec![parent_b.clone(), parent_a.clone()],
    )
    .unwrap();
    let second = LineageSourceDeclaration::new(
        node,
        PartitionRole::Training,
        LineageSourceKind::Corpus,
        vec![parent_a.clone(), parent_b.clone()],
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.parent_sources(), [parent_a, parent_b]);

    let mut submission = valid_submission();
    submission.sources[0] = LineageSourceDeclaration::new(
        source_ref("train-derived"),
        PartitionRole::Training,
        LineageSourceKind::Corpus,
        vec![root_v2],
    )
    .unwrap();
    assert_eq!(
        review_partition_lineage(review_id(), artifact(99), provenance(), &submission),
        Err(LineageReviewError::UnknownParentSource)
    );
    assert_ne!(
        root_v1,
        LineageSourceRef::new("same-source", "revision-r2").unwrap()
    );
}

#[test]
fn submission_rejects_incomplete_partition_declarations_at_the_boundary() {
    let submission = valid_submission();
    assert_eq!(
        PartitionLineageSubmission::new(
            submission.declarations()[..3].to_vec(),
            submission.sources().to_vec(),
        ),
        Err(LineageReviewError::PartitionCountInvalid)
    );
}
