//! Declarative partition and lineage review for offline calibration inputs.
//!
//! This pure domain boundary validates a bounded declaration supplied for the
//! four frozen calibration manifests. It checks that declared source graphs
//! are complete, acyclic, role-bound, and free of declared cross-partition
//! ancestry. It records only what the submitter declared. It does not inspect
//! a corpus, deduplicate content, authorize evidence access, call a model, or
//! publish a threshold or policy. Consequently, a successful review is a
//! declaration-review fact, not evidence that external corpus contents are
//! independent.

use super::dataset::EvaluationProvenance;
use crate::domain::{ArtifactId, CalibrationLineageReviewId};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

mod artifact;

pub use artifact::{
    CALIBRATION_LINEAGE_REVIEW_ARTIFACT_CONTENT_TYPE, CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND,
    CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SCHEMA_VERSION, CalibrationLineageReviewArtifact,
    CalibrationLineageReviewArtifactError,
};

/// Maximum declared source nodes admitted to one review before allocation.
pub const MAX_LINEAGE_SOURCES: usize = 256;
/// Maximum direct declared sources for one partition manifest.
pub const MAX_PARTITION_SOURCES: usize = 128;
/// Maximum parent references for one declared lineage source.
pub const MAX_LINEAGE_PARENTS: usize = 32;
/// Immutable schema version for a canonical lineage-review artifact.
pub const CALIBRATION_LINEAGE_REVIEW_SCHEMA_VERSION: u8 = 1;
/// Fixed policy revision recorded with each lineage-review artifact and event.
pub const CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION: &str = "calibration-lineage-v1";

/// The four immutable roles in a calibration partition declaration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PartitionRole {
    /// Corpus selected to produce or train a model revision.
    Training,
    /// Corpus used to select descriptive calibration thresholds.
    Calibration,
    /// Held-out corpus selected for this report's evaluation.
    Evaluation,
    /// Reviewed-label declaration associated with the evaluation task.
    Label,
}

impl PartitionRole {
    /// Returns the stable wire label used by typed DTO boundaries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Training => "training",
            Self::Calibration => "calibration",
            Self::Evaluation => "evaluation",
            Self::Label => "label",
        }
    }

    /// Parses one stable partition role without accepting aliases.
    ///
    /// # Errors
    /// Returns [`LineageReviewError::InvalidPartitionRole`] for an unknown role.
    pub fn parse(value: &str) -> Result<Self, LineageReviewError> {
        match value {
            "training" => Ok(Self::Training),
            "calibration" => Ok(Self::Calibration),
            "evaluation" => Ok(Self::Evaluation),
            "label" => Ok(Self::Label),
            _ => Err(LineageReviewError::InvalidPartitionRole),
        }
    }

    const fn expected_source_kind(self) -> LineageSourceKind {
        match self {
            Self::Label => LineageSourceKind::ReviewedLabel,
            Self::Training | Self::Calibration | Self::Evaluation => LineageSourceKind::Corpus,
        }
    }
}

/// Declared semantic kind for one lineage node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineageSourceKind {
    /// A declared corpus source for exactly one data partition.
    Corpus,
    /// A declared reviewed-label source for the label partition only.
    ReviewedLabel,
}

impl LineageSourceKind {
    /// Returns the stable DTO label for this declared source kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Corpus => "corpus",
            Self::ReviewedLabel => "reviewed_label",
        }
    }

    /// Parses one stable source kind without accepting aliases.
    ///
    /// # Errors
    /// Returns [`LineageReviewError::InvalidSourceKind`] for an unknown kind.
    pub fn parse(value: &str) -> Result<Self, LineageReviewError> {
        match value {
            "corpus" => Ok(Self::Corpus),
            "reviewed_label" => Ok(Self::ReviewedLabel),
            _ => Err(LineageReviewError::InvalidSourceKind),
        }
    }
}

/// A version-specific opaque source reference in a lineage declaration.
///
/// A source name by itself is not enough to identify one declared graph node:
/// a declaration may name distinct revisions of the same source. Every root,
/// parent edge, and graph key therefore carries this exact pair.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LineageSourceRef {
    source_id: String,
    source_revision: String,
}

impl LineageSourceRef {
    /// Validates one opaque source identity and immutable revision.
    ///
    /// # Errors
    /// Returns [`LineageReviewError::InvalidSourceId`] or
    /// [`LineageReviewError::InvalidSourceRevision`] for malformed or oversized
    /// fields. Construction has no I/O or review side effect.
    pub fn new(
        source_id: impl Into<String>,
        source_revision: impl Into<String>,
    ) -> Result<Self, LineageReviewError> {
        let source_id = source_id.into();
        let source_revision = source_revision.into();
        if !valid_identifier(&source_id) {
            return Err(LineageReviewError::InvalidSourceId);
        }
        if !valid_identifier(&source_revision) {
            return Err(LineageReviewError::InvalidSourceRevision);
        }
        Ok(Self {
            source_id,
            source_revision,
        })
    }

    /// Returns the opaque source identity.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Returns the immutable source revision.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }
}

/// One declared source node and its direct declared ancestry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageSourceDeclaration {
    source: LineageSourceRef,
    partition: PartitionRole,
    kind: LineageSourceKind,
    parent_sources: Vec<LineageSourceRef>,
}

impl LineageSourceDeclaration {
    /// Validates one bounded opaque source declaration without side effects.
    ///
    /// Parent references are checked for duplication and self-links here, then
    /// stored in lexical `(source_id, source_revision)` order. Resolution, role
    /// agreement, cycle detection, and reachability are performed only after
    /// the complete submitted graph is available.
    ///
    /// # Errors
    /// Returns a stable [`LineageReviewError`] for malformed or oversized
    /// identifiers, duplicate parents, or a direct self-reference.
    pub fn new(
        source: LineageSourceRef,
        partition: PartitionRole,
        kind: LineageSourceKind,
        parent_sources: Vec<LineageSourceRef>,
    ) -> Result<Self, LineageReviewError> {
        if parent_sources.len() > MAX_LINEAGE_PARENTS {
            return Err(LineageReviewError::ParentLimitExceeded);
        }
        let mut parents = BTreeSet::new();
        for parent in parent_sources {
            if parent == source {
                return Err(LineageReviewError::SourceSelfReference);
            }
            if !parents.insert(parent) {
                return Err(LineageReviewError::DuplicateSourceParent);
            }
        }
        Ok(Self {
            source,
            partition,
            kind,
            parent_sources: parents.into_iter().collect(),
        })
    }

    /// Returns the opaque source identity declared by the submitter.
    #[must_use]
    pub fn source_id(&self) -> &str {
        self.source.source_id()
    }

    /// Returns the submitter-declared source revision.
    #[must_use]
    pub fn source_revision(&self) -> &str {
        self.source.source_revision()
    }

    /// Returns the exact version-specific node reference.
    #[must_use]
    pub const fn source(&self) -> &LineageSourceRef {
        &self.source
    }

    /// Returns the one partition this source declaration belongs to.
    #[must_use]
    pub const fn partition(&self) -> PartitionRole {
        self.partition
    }

    /// Returns the declared source category.
    #[must_use]
    pub const fn kind(&self) -> LineageSourceKind {
        self.kind
    }

    /// Returns direct declared parent nodes in canonical reference order.
    #[must_use]
    pub fn parent_sources(&self) -> &[LineageSourceRef] {
        &self.parent_sources
    }
}

/// One manifest's declared direct source roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionManifestDeclaration {
    role: PartitionRole,
    manifest_artifact_id: ArtifactId,
    direct_sources: Vec<LineageSourceRef>,
}

impl PartitionManifestDeclaration {
    /// Validates one manifest role, identity, and bounded source-root list.
    ///
    /// Artifact-to-provenance binding and source resolution need the complete
    /// review submission and happen in [`review_partition_lineage`].
    ///
    /// # Errors
    /// Returns a stable [`LineageReviewError`] for an empty, duplicate, or
    /// oversized source-root list. Roots are stored in canonical reference
    /// order. No I/O occurs.
    pub fn new(
        role: PartitionRole,
        manifest_artifact_id: ArtifactId,
        direct_sources: Vec<LineageSourceRef>,
    ) -> Result<Self, LineageReviewError> {
        if direct_sources.is_empty() {
            return Err(LineageReviewError::PartitionSourcesEmpty);
        }
        if direct_sources.len() > MAX_PARTITION_SOURCES {
            return Err(LineageReviewError::PartitionSourceLimitExceeded);
        }
        let mut sources = BTreeSet::new();
        for source in direct_sources {
            if !sources.insert(source) {
                return Err(LineageReviewError::DuplicatePartitionSource);
            }
        }
        Ok(Self {
            role,
            manifest_artifact_id,
            direct_sources: sources.into_iter().collect(),
        })
    }

    /// Returns this declaration's immutable partition role.
    #[must_use]
    pub const fn role(&self) -> PartitionRole {
        self.role
    }

    /// Returns the catalog manifest artifact to bind to this role.
    #[must_use]
    pub const fn manifest_artifact_id(&self) -> &ArtifactId {
        &self.manifest_artifact_id
    }

    /// Returns the declared direct lineage roots in canonical reference order.
    #[must_use]
    pub fn direct_sources(&self) -> &[LineageSourceRef] {
        &self.direct_sources
    }
}

/// A complete declared graph over the four frozen calibration partitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionLineageSubmission {
    declarations: Vec<PartitionManifestDeclaration>,
    sources: Vec<LineageSourceDeclaration>,
}

impl PartitionLineageSubmission {
    /// Bounds the submitted declaration graph before semantic review.
    ///
    /// # Errors
    /// Returns [`LineageReviewError::PartitionCountInvalid`] or
    /// [`LineageReviewError::DuplicatePartitionRole`] when the four partition
    /// declarations are incomplete or ambiguous, and
    /// [`LineageReviewError::SourceLimitExceeded`] when the graph has too many
    /// nodes. Cross-reference validation occurs during review.
    pub fn new(
        declarations: Vec<PartitionManifestDeclaration>,
        sources: Vec<LineageSourceDeclaration>,
    ) -> Result<Self, LineageReviewError> {
        if declarations.len() != PartitionRole::all().len() {
            return Err(LineageReviewError::PartitionCountInvalid);
        }
        let mut roles = BTreeSet::new();
        for declaration in &declarations {
            if !roles.insert(declaration.role()) {
                return Err(LineageReviewError::DuplicatePartitionRole);
            }
        }
        if sources.is_empty() || sources.len() > MAX_LINEAGE_SOURCES {
            return Err(LineageReviewError::SourceLimitExceeded);
        }
        Ok(Self {
            declarations,
            sources,
        })
    }

    /// Returns each submitted partition-manifest declaration.
    #[must_use]
    pub fn declarations(&self) -> &[PartitionManifestDeclaration] {
        &self.declarations
    }

    /// Returns each submitted lineage source declaration.
    #[must_use]
    pub fn sources(&self) -> &[LineageSourceDeclaration] {
        &self.sources
    }
}

/// Immutable reviewed manifest declaration preserved in a review artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedPartitionDeclaration {
    role: PartitionRole,
    manifest_artifact_id: ArtifactId,
    direct_sources: Vec<LineageSourceRef>,
}

impl ReviewedPartitionDeclaration {
    /// Returns the reviewed partition role.
    #[must_use]
    pub const fn role(&self) -> PartitionRole {
        self.role
    }

    /// Returns the reviewed manifest artifact identity.
    #[must_use]
    pub const fn manifest_artifact_id(&self) -> &ArtifactId {
        &self.manifest_artifact_id
    }

    /// Returns reviewed direct roots in stable reference order.
    #[must_use]
    pub fn direct_sources(&self) -> &[LineageSourceRef] {
        &self.direct_sources
    }
}

/// A successful bounded review of submitted partition and lineage declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionLineageReview {
    review_id: CalibrationLineageReviewId,
    review_artifact_id: ArtifactId,
    provenance: EvaluationProvenance,
    partitions: Vec<ReviewedPartitionDeclaration>,
    sources: Vec<LineageSourceDeclaration>,
}

impl PartitionLineageReview {
    /// Returns the canonical review-artifact schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        CALIBRATION_LINEAGE_REVIEW_SCHEMA_VERSION
    }

    /// Returns the fixed declaration-review policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> &'static str {
        CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION
    }

    /// Returns the independent immutable review identity.
    #[must_use]
    pub const fn review_id(&self) -> &CalibrationLineageReviewId {
        &self.review_id
    }

    /// Returns the separately retained review-artifact identity.
    #[must_use]
    pub const fn review_artifact_id(&self) -> &ArtifactId {
        &self.review_artifact_id
    }

    /// Returns the frozen calibration provenance this declaration review bound.
    #[must_use]
    pub const fn provenance(&self) -> &EvaluationProvenance {
        &self.provenance
    }

    /// Returns four reviewed partition declarations in stable role order.
    #[must_use]
    pub fn partitions(&self) -> &[ReviewedPartitionDeclaration] {
        &self.partitions
    }

    /// Returns the complete reviewed source graph in stable reference order.
    #[must_use]
    pub fn sources(&self) -> &[LineageSourceDeclaration] {
        &self.sources
    }

    /// Returns the successful declaration-review reason for durable audit.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        "CALIBRATION_PARTITION_LINEAGE_REVIEWED"
    }
}

/// Reviews submitted partition and lineage relationships without I/O.
///
/// The review requires exactly one declaration for each frozen manifest in
/// [`EvaluationProvenance`]. Every declared source has one partition and must
/// be reachable from that partition's manifest roots. Parent links resolve to
/// same-partition sources, which rejects a submitter-declared common lineage
/// path between the training, calibration, evaluation, and label partitions.
/// The returned review does not assert anything about unsubmitted source data,
/// semantic equivalence, hidden lineage, or external corpus contents.
///
/// # Errors
/// Returns a stable [`LineageReviewError`] for graph, role, artifact, or
/// provenance binding violations. It has no authorization, storage, model,
/// audit, or policy-publication side effect.
pub fn review_partition_lineage(
    review_id: CalibrationLineageReviewId,
    review_artifact_id: ArtifactId,
    provenance: EvaluationProvenance,
    submission: &PartitionLineageSubmission,
) -> Result<PartitionLineageReview, LineageReviewError> {
    let manifests = expected_manifests(&provenance);
    if manifests
        .values()
        .any(|artifact| *artifact == &review_artifact_id)
    {
        return Err(LineageReviewError::ReviewArtifactAliased);
    }
    let declarations = declarations_by_role(submission.declarations(), &manifests)?;
    let sources = sources_by_ref(submission.sources())?;
    validate_direct_sources(&declarations, &sources)?;
    validate_parent_graph(&sources)?;
    validate_reachability(&declarations, &sources)?;

    let mut partitions = Vec::with_capacity(PartitionRole::all().len());
    for role in PartitionRole::all() {
        let declaration = declarations
            .get(&role)
            .ok_or(LineageReviewError::PartitionCountInvalid)?;
        partitions.push(ReviewedPartitionDeclaration {
            role,
            manifest_artifact_id: declaration.manifest_artifact_id.clone(),
            direct_sources: declaration.direct_sources.clone(),
        });
    }
    Ok(PartitionLineageReview {
        review_id,
        review_artifact_id,
        provenance,
        partitions,
        sources: sources.into_values().collect(),
    })
}

impl PartitionRole {
    const fn all() -> [Self; 4] {
        [
            Self::Training,
            Self::Calibration,
            Self::Evaluation,
            Self::Label,
        ]
    }
}

fn expected_manifests(provenance: &EvaluationProvenance) -> BTreeMap<PartitionRole, &ArtifactId> {
    BTreeMap::from([
        (
            PartitionRole::Training,
            provenance.training_manifest_artifact_id(),
        ),
        (
            PartitionRole::Calibration,
            provenance.calibration_manifest_artifact_id(),
        ),
        (
            PartitionRole::Evaluation,
            provenance.evaluation_manifest_artifact_id(),
        ),
        (
            PartitionRole::Label,
            provenance.label_manifest_artifact_id(),
        ),
    ])
}

fn declarations_by_role<'a>(
    declarations: &'a [PartitionManifestDeclaration],
    manifests: &BTreeMap<PartitionRole, &ArtifactId>,
) -> Result<BTreeMap<PartitionRole, &'a PartitionManifestDeclaration>, LineageReviewError> {
    if declarations.len() != PartitionRole::all().len() {
        return Err(LineageReviewError::PartitionCountInvalid);
    }
    let mut by_role = BTreeMap::new();
    for declaration in declarations {
        if by_role.insert(declaration.role, declaration).is_some() {
            return Err(LineageReviewError::DuplicatePartitionRole);
        }
        if manifests.get(&declaration.role) != Some(&&declaration.manifest_artifact_id) {
            return Err(LineageReviewError::ManifestProvenanceMismatch);
        }
    }
    if by_role.len() != PartitionRole::all().len() {
        return Err(LineageReviewError::PartitionCountInvalid);
    }
    Ok(by_role)
}

fn sources_by_ref(
    sources: &[LineageSourceDeclaration],
) -> Result<BTreeMap<LineageSourceRef, LineageSourceDeclaration>, LineageReviewError> {
    let mut by_ref = BTreeMap::new();
    for source in sources {
        if by_ref
            .insert(source.source.clone(), source.clone())
            .is_some()
        {
            return Err(LineageReviewError::DuplicateSourceReference);
        }
    }
    Ok(by_ref)
}

fn validate_direct_sources(
    declarations: &BTreeMap<PartitionRole, &PartitionManifestDeclaration>,
    sources: &BTreeMap<LineageSourceRef, LineageSourceDeclaration>,
) -> Result<(), LineageReviewError> {
    for role in PartitionRole::all() {
        let declaration = declarations
            .get(&role)
            .ok_or(LineageReviewError::PartitionCountInvalid)?;
        for source_ref in &declaration.direct_sources {
            let source = sources
                .get(source_ref)
                .ok_or(LineageReviewError::UnknownSource)?;
            if source.partition != role {
                return Err(LineageReviewError::SourcePartitionMismatch);
            }
            if source.kind != role.expected_source_kind() {
                return Err(LineageReviewError::SourceKindPartitionMismatch);
            }
        }
    }
    Ok(())
}

fn validate_parent_graph(
    sources: &BTreeMap<LineageSourceRef, LineageSourceDeclaration>,
) -> Result<(), LineageReviewError> {
    for source in sources.values() {
        if source.kind != source.partition.expected_source_kind() {
            return Err(LineageReviewError::SourceKindPartitionMismatch);
        }
        for parent_ref in &source.parent_sources {
            let parent = sources
                .get(parent_ref)
                .ok_or(LineageReviewError::UnknownParentSource)?;
            if parent.partition != source.partition {
                return Err(LineageReviewError::CrossPartitionLineageDeclared);
            }
        }
    }
    let mut states = BTreeMap::new();
    for source_ref in sources.keys() {
        visit_source(source_ref, sources, &mut states)?;
    }
    Ok(())
}

fn visit_source(
    source_ref: &LineageSourceRef,
    sources: &BTreeMap<LineageSourceRef, LineageSourceDeclaration>,
    states: &mut BTreeMap<LineageSourceRef, VisitState>,
) -> Result<(), LineageReviewError> {
    match states.get(source_ref) {
        Some(VisitState::Visiting) => return Err(LineageReviewError::LineageCycle),
        Some(VisitState::Visited) => return Ok(()),
        None => {}
    }
    states.insert(source_ref.clone(), VisitState::Visiting);
    let source = sources
        .get(source_ref)
        .ok_or(LineageReviewError::UnknownParentSource)?;
    for parent in &source.parent_sources {
        visit_source(parent, sources, states)?;
    }
    states.insert(source_ref.clone(), VisitState::Visited);
    Ok(())
}

#[derive(Clone, Copy)]
enum VisitState {
    Visiting,
    Visited,
}

fn validate_reachability(
    declarations: &BTreeMap<PartitionRole, &PartitionManifestDeclaration>,
    sources: &BTreeMap<LineageSourceRef, LineageSourceDeclaration>,
) -> Result<(), LineageReviewError> {
    let mut reachable = BTreeSet::new();
    for declaration in declarations.values() {
        for source_ref in &declaration.direct_sources {
            mark_reachable(source_ref, sources, &mut reachable)?;
        }
    }
    if reachable.len() != sources.len() {
        return Err(LineageReviewError::UnreachableSource);
    }
    Ok(())
}

fn mark_reachable(
    source_ref: &LineageSourceRef,
    sources: &BTreeMap<LineageSourceRef, LineageSourceDeclaration>,
    reachable: &mut BTreeSet<LineageSourceRef>,
) -> Result<(), LineageReviewError> {
    if !reachable.insert(source_ref.clone()) {
        return Ok(());
    }
    let source = sources
        .get(source_ref)
        .ok_or(LineageReviewError::UnknownSource)?;
    for parent in &source.parent_sources {
        mark_reachable(parent, sources, reachable)?;
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// Closed declaration-review failures with stable content-free reason codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineageReviewError {
    /// A typed partition role was not one of the fixed four labels.
    InvalidPartitionRole,
    /// A source kind was not accepted by this contract version.
    InvalidSourceKind,
    /// A source identity was malformed or exceeded its fixed bound.
    InvalidSourceId,
    /// A source revision was malformed or exceeded its fixed bound.
    InvalidSourceRevision,
    /// The submission did not declare exactly all four partition roles.
    PartitionCountInvalid,
    /// More than one manifest declaration used the same partition role.
    DuplicatePartitionRole,
    /// A declaration's artifact did not match frozen evaluation provenance.
    ManifestProvenanceMismatch,
    /// The independent review artifact aliases a declared partition manifest.
    ReviewArtifactAliased,
    /// A partition was submitted without direct declared lineage roots.
    PartitionSourcesEmpty,
    /// A partition exceeded its direct-source bound.
    PartitionSourceLimitExceeded,
    /// A direct source identity repeated within one partition declaration.
    DuplicatePartitionSource,
    /// The submitted source graph was empty or exceeded its source bound.
    SourceLimitExceeded,
    /// A version-specific source reference appeared more than once in the submitted graph.
    DuplicateSourceReference,
    /// A source exceeded its parent-reference bound.
    ParentLimitExceeded,
    /// A source declared the same parent more than once.
    DuplicateSourceParent,
    /// A source directly named itself as a parent.
    SourceSelfReference,
    /// A partition root did not resolve to a submitted source declaration.
    UnknownSource,
    /// A declared parent did not resolve to a submitted source declaration.
    UnknownParentSource,
    /// A source was assigned to a different partition than its manifest root.
    SourcePartitionMismatch,
    /// A source kind did not match the role-bound partition contract.
    SourceKindPartitionMismatch,
    /// A declared source parent crossed a partition boundary.
    CrossPartitionLineageDeclared,
    /// The submitted source graph contained a directed cycle.
    LineageCycle,
    /// A submitted source was unrelated to all reviewed manifest roots.
    UnreachableSource,
}

impl LineageReviewError {
    /// Returns the stable reason code for an audit or terminal response.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidPartitionRole => "CALIBRATION_LINEAGE_PARTITION_ROLE_INVALID",
            Self::InvalidSourceKind => "CALIBRATION_LINEAGE_SOURCE_KIND_INVALID",
            Self::InvalidSourceId => "CALIBRATION_LINEAGE_SOURCE_ID_INVALID",
            Self::InvalidSourceRevision => "CALIBRATION_LINEAGE_SOURCE_REVISION_INVALID",
            Self::PartitionCountInvalid => "CALIBRATION_LINEAGE_PARTITION_SET_INVALID",
            Self::DuplicatePartitionRole => "CALIBRATION_LINEAGE_PARTITION_ROLE_DUPLICATE",
            Self::ManifestProvenanceMismatch => "CALIBRATION_LINEAGE_MANIFEST_PROVENANCE_MISMATCH",
            Self::ReviewArtifactAliased => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_ALIASED",
            Self::PartitionSourcesEmpty => "CALIBRATION_LINEAGE_PARTITION_SOURCES_EMPTY",
            Self::PartitionSourceLimitExceeded => {
                "CALIBRATION_LINEAGE_PARTITION_SOURCE_LIMIT_EXCEEDED"
            }
            Self::DuplicatePartitionSource => "CALIBRATION_LINEAGE_PARTITION_SOURCE_DUPLICATE",
            Self::SourceLimitExceeded => "CALIBRATION_LINEAGE_SOURCE_LIMIT_EXCEEDED",
            Self::DuplicateSourceReference => "CALIBRATION_LINEAGE_SOURCE_REFERENCE_DUPLICATE",
            Self::ParentLimitExceeded => "CALIBRATION_LINEAGE_PARENT_LIMIT_EXCEEDED",
            Self::DuplicateSourceParent => "CALIBRATION_LINEAGE_PARENT_DUPLICATE",
            Self::SourceSelfReference => "CALIBRATION_LINEAGE_SOURCE_SELF_REFERENCE",
            Self::UnknownSource => "CALIBRATION_LINEAGE_SOURCE_UNKNOWN",
            Self::UnknownParentSource => "CALIBRATION_LINEAGE_PARENT_UNKNOWN",
            Self::SourcePartitionMismatch => "CALIBRATION_LINEAGE_SOURCE_PARTITION_MISMATCH",
            Self::SourceKindPartitionMismatch => {
                "CALIBRATION_LINEAGE_SOURCE_KIND_PARTITION_MISMATCH"
            }
            Self::CrossPartitionLineageDeclared => "CALIBRATION_LINEAGE_CROSS_PARTITION_DECLARED",
            Self::LineageCycle => "CALIBRATION_LINEAGE_CYCLE",
            Self::UnreachableSource => "CALIBRATION_LINEAGE_SOURCE_UNREACHABLE",
        }
    }
}

impl fmt::Display for LineageReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LineageReviewError {}

#[cfg(test)]
#[path = "lineage_review/tests.rs"]
mod tests;
