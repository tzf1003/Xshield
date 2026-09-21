//! Canonical protected body for one declarative calibration lineage review.
//!
//! The durable review artifact preserves the submitted, validated graph and
//! frozen evaluation provenance. It is deliberately distinct from a report
//! artifact: it asserts only that a bounded declaration passed this contract,
//! never that corpus contents are independent or that any model is accurate.

use super::{
    CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION, LineageReviewError, LineageSourceDeclaration,
    LineageSourceKind, LineageSourceRef, PartitionLineageReview, PartitionLineageSubmission,
    PartitionManifestDeclaration, PartitionRole, ReviewedPartitionDeclaration,
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
use serde::{Deserialize, Deserializer, de};
use serde_json::{Map, Number, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Immutable schema version for a protected lineage-review artifact.
pub const CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SCHEMA_VERSION: u8 = 1;
/// Fixed evidence kind for a protected lineage-review artifact.
pub const CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND: &str = "calibration_partition_lineage_review";
/// Fixed media type for a protected lineage-review artifact.
pub const CALIBRATION_LINEAGE_REVIEW_ARTIFACT_CONTENT_TYPE: &str =
    "application/vnd.xshield.calibration-lineage-review+json";

const MAX_ARTIFACT_BYTES: usize = 512 * 1024;

/// Protected, deterministic body for one reviewed partition lineage graph.
///
/// This object carries opaque source identities and revisions, rather than
/// source contents. Its construction and parsing have no vault, database,
/// outbox, authorization, model, or policy-publication effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationLineageReviewArtifact {
    review_id: CalibrationLineageReviewId,
    review_artifact_id: ArtifactId,
    provenance: EvaluationProvenance,
    partitions: Vec<ReviewedPartitionDeclaration>,
    sources: Vec<LineageSourceDeclaration>,
}

impl CalibrationLineageReviewArtifact {
    /// Projects one successful pure-domain review into its protected body.
    ///
    /// The input is revalidated through the review boundary so a future caller
    /// cannot construct a durable artifact from manually altered internals.
    /// This does not establish content independence, persist an audit fact, or
    /// grant evidence access.
    ///
    /// # Errors
    /// Returns [`CalibrationLineageReviewArtifactError::ReviewMismatch`] when
    /// the supplied review cannot be reconstructed under the current fixed
    /// contract, or [`CalibrationLineageReviewArtifactError::GraphInvalid`]
    /// when its bounded graph cannot be reconstituted.
    pub fn from_review(
        review: &PartitionLineageReview,
    ) -> Result<Self, CalibrationLineageReviewArtifactError> {
        let artifact = Self {
            review_id: review.review_id().clone(),
            review_artifact_id: review.review_artifact_id().clone(),
            provenance: review.provenance().clone(),
            partitions: review.partitions().to_vec(),
            sources: review.sources().to_vec(),
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Decodes only the exact canonical JSON representation of a review body.
    ///
    /// The parser rejects duplicate names, unknown or prohibited fields, and
    /// alternate encodings before rechecking every role, manifest, source, and
    /// parent relationship through the pure review boundary.
    ///
    /// # Errors
    /// Returns a stable content-free
    /// [`CalibrationLineageReviewArtifactError`] when the input is malformed,
    /// exceeds the fixed limit, or differs from the canonical representation.
    pub fn from_canonical_json(
        bytes: &[u8],
    ) -> Result<Self, CalibrationLineageReviewArtifactError> {
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(CalibrationLineageReviewArtifactError::TooLarge);
        }
        let value = match serde_json::from_slice::<UniqueJson>(bytes) {
            Ok(value) => value.0,
            Err(error) if error.to_string().contains("duplicate JSON object key") => {
                return Err(CalibrationLineageReviewArtifactError::DuplicateField);
            }
            Err(_) => return Err(CalibrationLineageReviewArtifactError::InvalidJson),
        };
        let artifact = parse_document(value)?;
        if artifact.to_canonical_json()? != bytes {
            return Err(CalibrationLineageReviewArtifactError::NonCanonicalEncoding);
        }
        Ok(artifact)
    }

    /// Serializes this review into its only accepted UTF-8 representation.
    ///
    /// Object keys and graph references are lexical and source graph order is
    /// fixed by the reviewed declaration. The result contains no plaintext
    /// corpus, label, credential, lease, request, or model response data.
    ///
    /// # Errors
    /// Returns a stable content-free
    /// [`CalibrationLineageReviewArtifactError`] when validation fails or the
    /// bounded document cannot be serialized.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, CalibrationLineageReviewArtifactError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&self.as_json())
            .map_err(|_| CalibrationLineageReviewArtifactError::Serialization)?;
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(CalibrationLineageReviewArtifactError::TooLarge);
        }
        Ok(bytes)
    }

    /// Alias for the canonical body required by the dedicated evidence vault.
    ///
    /// # Errors
    /// Propagates the same bounded-validation failures as
    /// [`Self::to_canonical_json`].
    pub fn canonical_json(&self) -> Result<Vec<u8>, CalibrationLineageReviewArtifactError> {
        self.to_canonical_json()
    }

    /// Returns the immutable declaration-review identity.
    #[must_use]
    pub const fn review_id(&self) -> &CalibrationLineageReviewId {
        &self.review_id
    }

    /// Returns the independently retained review-artifact identity.
    #[must_use]
    pub const fn review_artifact_id(&self) -> &ArtifactId {
        &self.review_artifact_id
    }

    /// Returns the frozen evaluation provenance bound by this review.
    #[must_use]
    pub const fn provenance(&self) -> &EvaluationProvenance {
        &self.provenance
    }

    /// Returns four reviewed manifest declarations in stable role order.
    #[must_use]
    pub fn partitions(&self) -> &[ReviewedPartitionDeclaration] {
        &self.partitions
    }

    /// Returns the complete reviewed source graph in stable reference order.
    #[must_use]
    pub fn sources(&self) -> &[LineageSourceDeclaration] {
        &self.sources
    }

    /// Returns the schema recorded in the canonical artifact.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SCHEMA_VERSION
    }

    /// Returns the immutable declaration-review policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> &'static str {
        CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION
    }

    fn validate(&self) -> Result<(), CalibrationLineageReviewArtifactError> {
        let declarations = self
            .partitions
            .iter()
            .map(|partition| {
                PartitionManifestDeclaration::new(
                    partition.role(),
                    partition.manifest_artifact_id().clone(),
                    partition.direct_sources().to_vec(),
                )
            })
            .collect::<Result<Vec<_>, LineageReviewError>>()
            .map_err(|_| CalibrationLineageReviewArtifactError::GraphInvalid)?;
        let submission = PartitionLineageSubmission::new(declarations, self.sources.clone())
            .map_err(|_| CalibrationLineageReviewArtifactError::GraphInvalid)?;
        let rebuilt = review_partition_lineage(
            self.review_id.clone(),
            self.review_artifact_id.clone(),
            self.provenance.clone(),
            &submission,
        )
        .map_err(|_| CalibrationLineageReviewArtifactError::GraphInvalid)?;
        if rebuilt.partitions() != self.partitions || rebuilt.sources() != self.sources {
            return Err(CalibrationLineageReviewArtifactError::ReviewMismatch);
        }
        Ok(())
    }

    fn as_json(&self) -> Value {
        object([
            (
                "kind",
                Value::String(CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND.to_owned()),
            ),
            (
                "partitions",
                Value::Array(self.partitions.iter().map(partition_json).collect()),
            ),
            (
                "policy_revision",
                Value::String(CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION.to_owned()),
            ),
            ("provenance", provenance_json(&self.provenance)),
            (
                "review_artifact_id",
                Value::String(self.review_artifact_id.as_str().to_owned()),
            ),
            (
                "review_id",
                Value::String(self.review_id.as_str().to_owned()),
            ),
            (
                "schema_version",
                Value::Number(Number::from(
                    CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SCHEMA_VERSION,
                )),
            ),
            (
                "sources",
                Value::Array(self.sources.iter().map(source_json).collect()),
            ),
        ])
    }
}

/// Closed failures for a protected declaration-review artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationLineageReviewArtifactError {
    /// Input could not be parsed as bounded JSON.
    InvalidJson,
    /// A field appeared more than once in a JSON object.
    DuplicateField,
    /// A required field was absent from a fixed object shape.
    MissingField,
    /// A field was not part of the fixed artifact schema.
    UnknownField,
    /// A field identifies data forbidden from this review artifact.
    ProhibitedField,
    /// The schema version, kind, or policy revision was not accepted.
    InvalidSchema,
    /// A typed identifier, role, kind, or bounded scalar was malformed.
    InvalidValue,
    /// The reviewed graph did not meet the current pure-domain contract.
    GraphInvalid,
    /// Reconstruction changed an ostensibly reviewed graph.
    ReviewMismatch,
    /// Parsed bytes differ from the DTO's exact canonical representation.
    NonCanonicalEncoding,
    /// The protected document exceeded its admission ceiling.
    TooLarge,
    /// Canonical JSON encoding unexpectedly failed.
    Serialization,
}

impl CalibrationLineageReviewArtifactError {
    /// Returns a stable content-free reason code for caller-owned audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidJson => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_JSON_INVALID",
            Self::DuplicateField => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_FIELD_DUPLICATE",
            Self::MissingField => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_FIELD_MISSING",
            Self::UnknownField => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_FIELD_UNKNOWN",
            Self::ProhibitedField => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_FIELD_PROHIBITED",
            Self::InvalidSchema => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SCHEMA_INVALID",
            Self::InvalidValue => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_VALUE_INVALID",
            Self::GraphInvalid => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_GRAPH_INVALID",
            Self::ReviewMismatch => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_REVIEW_MISMATCH",
            Self::NonCanonicalEncoding => {
                "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_ENCODING_NONCANONICAL"
            }
            Self::TooLarge => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_LIMIT_EXCEEDED",
            Self::Serialization => "CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SERIALIZATION_FAILED",
        }
    }
}

impl fmt::Display for CalibrationLineageReviewArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for CalibrationLineageReviewArtifactError {}

fn partition_json(partition: &ReviewedPartitionDeclaration) -> Value {
    object([
        (
            "direct_sources",
            Value::Array(
                partition
                    .direct_sources()
                    .iter()
                    .map(source_ref_json)
                    .collect(),
            ),
        ),
        (
            "manifest_artifact_id",
            Value::String(partition.manifest_artifact_id().as_str().to_owned()),
        ),
        ("role", Value::String(partition.role().as_str().to_owned())),
    ])
}

fn source_json(source: &LineageSourceDeclaration) -> Value {
    object([
        ("kind", Value::String(source.kind().as_str().to_owned())),
        (
            "parent_sources",
            Value::Array(
                source
                    .parent_sources()
                    .iter()
                    .map(source_ref_json)
                    .collect(),
            ),
        ),
        (
            "partition",
            Value::String(source.partition().as_str().to_owned()),
        ),
        ("source", source_ref_json(source.source())),
    ])
}

fn source_ref_json(source: &LineageSourceRef) -> Value {
    object([
        ("source_id", Value::String(source.source_id().to_owned())),
        (
            "source_revision",
            Value::String(source.source_revision().to_owned()),
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
                .map_or(Value::Null, |value| {
                    Value::String(value.as_str().to_owned())
                }),
        ),
    ])
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
) -> Result<CalibrationLineageReviewArtifact, CalibrationLineageReviewArtifactError> {
    let mut fields = object_fields(
        value,
        &[
            "kind",
            "partitions",
            "policy_revision",
            "provenance",
            "review_artifact_id",
            "review_id",
            "schema_version",
            "sources",
        ],
    )?;
    if take_u32(&mut fields, "schema_version")?
        != u32::from(CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SCHEMA_VERSION)
        || take_string(&mut fields, "kind")? != CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND
        || take_string(&mut fields, "policy_revision")?
            != CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION
    {
        return Err(CalibrationLineageReviewArtifactError::InvalidSchema);
    }
    let review_id = CalibrationLineageReviewId::parse(take_string(&mut fields, "review_id")?)
        .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?;
    let review_artifact_id = ArtifactId::parse(take_string(&mut fields, "review_artifact_id")?)
        .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?;
    let provenance = parse_provenance(take_value(&mut fields, "provenance")?)?;
    let partitions = parse_partitions(take_value(&mut fields, "partitions")?)?;
    let sources = parse_sources(take_value(&mut fields, "sources")?)?;
    let artifact = CalibrationLineageReviewArtifact {
        review_id,
        review_artifact_id,
        provenance,
        partitions,
        sources,
    };
    artifact.validate()?;
    Ok(artifact)
}

fn parse_partitions(
    value: Value,
) -> Result<Vec<ReviewedPartitionDeclaration>, CalibrationLineageReviewArtifactError> {
    let Value::Array(values) = value else {
        return Err(CalibrationLineageReviewArtifactError::InvalidValue);
    };
    if values.len() != 4 {
        return Err(CalibrationLineageReviewArtifactError::GraphInvalid);
    }
    values
        .into_iter()
        .map(|value| {
            let mut fields =
                object_fields(value, &["direct_sources", "manifest_artifact_id", "role"])?;
            let role = PartitionRole::parse(&take_string(&mut fields, "role")?)
                .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?;
            let manifest_artifact_id =
                ArtifactId::parse(take_string(&mut fields, "manifest_artifact_id")?)
                    .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?;
            let direct_sources = parse_source_refs(take_value(&mut fields, "direct_sources")?)?;
            let validated =
                PartitionManifestDeclaration::new(role, manifest_artifact_id, direct_sources)
                    .map_err(|_| CalibrationLineageReviewArtifactError::GraphInvalid)?;
            Ok(ReviewedPartitionDeclaration {
                role: validated.role,
                manifest_artifact_id: validated.manifest_artifact_id,
                direct_sources: validated.direct_sources,
            })
        })
        .collect()
}

fn parse_sources(
    value: Value,
) -> Result<Vec<LineageSourceDeclaration>, CalibrationLineageReviewArtifactError> {
    let Value::Array(values) = value else {
        return Err(CalibrationLineageReviewArtifactError::InvalidValue);
    };
    if values.is_empty() || values.len() > super::MAX_LINEAGE_SOURCES {
        return Err(CalibrationLineageReviewArtifactError::GraphInvalid);
    }
    values
        .into_iter()
        .map(|value| {
            let mut fields =
                object_fields(value, &["kind", "parent_sources", "partition", "source"])?;
            let source = parse_source_ref(take_value(&mut fields, "source")?)?;
            let partition = PartitionRole::parse(&take_string(&mut fields, "partition")?)
                .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?;
            let kind = LineageSourceKind::parse(&take_string(&mut fields, "kind")?)
                .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?;
            let parent_sources = parse_source_refs(take_value(&mut fields, "parent_sources")?)?;
            LineageSourceDeclaration::new(source, partition, kind, parent_sources)
                .map_err(|_| CalibrationLineageReviewArtifactError::GraphInvalid)
        })
        .collect()
}

fn parse_source_refs(
    value: Value,
) -> Result<Vec<LineageSourceRef>, CalibrationLineageReviewArtifactError> {
    let Value::Array(values) = value else {
        return Err(CalibrationLineageReviewArtifactError::InvalidValue);
    };
    values.into_iter().map(parse_source_ref).collect()
}

fn parse_source_ref(
    value: Value,
) -> Result<LineageSourceRef, CalibrationLineageReviewArtifactError> {
    let mut fields = object_fields(value, &["source_id", "source_revision"])?;
    LineageSourceRef::new(
        take_string(&mut fields, "source_id")?,
        take_string(&mut fields, "source_revision")?,
    )
    .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)
}

fn parse_provenance(
    value: Value,
) -> Result<EvaluationProvenance, CalibrationLineageReviewArtifactError> {
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
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        DatasetRevision::parse(take_string(&mut fields, "dataset_revision")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        LabelRevision::parse(take_string(&mut fields, "label_revision")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        TaskRevision::parse(take_string(&mut fields, "task_revision")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        ThresholdPolicyRevision::parse(take_string(&mut fields, "threshold_policy_revision")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        MappingRevision::parse(take_string(&mut fields, "mapping_revision")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        ArtifactId::parse(take_string(&mut fields, "evaluation_manifest_artifact_id")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        ArtifactId::parse(take_string(&mut fields, "training_manifest_artifact_id")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        ArtifactId::parse(take_string(
            &mut fields,
            "calibration_manifest_artifact_id",
        )?)
        .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        ArtifactId::parse(take_string(&mut fields, "label_manifest_artifact_id")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        model,
    )
    .map_err(|_| CalibrationLineageReviewArtifactError::GraphInvalid)
}

fn parse_model(value: Value) -> Result<ModelIdentity, CalibrationLineageReviewArtifactError> {
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
                .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        ),
        _ => return Err(CalibrationLineageReviewArtifactError::InvalidValue),
    };
    ModelIdentity::new(
        ProviderId::parse(take_string(&mut fields, "provider")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        take_string(&mut fields, "provider_model_id")?,
        ModelRevision::parse(take_string(&mut fields, "model_revision")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        PromptRevision::parse(take_string(&mut fields, "prompt_revision")?)
            .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)?,
        resolved_model_revision,
    )
    .map_err(|_| CalibrationLineageReviewArtifactError::InvalidValue)
}

fn object_fields(
    value: Value,
    expected: &[&str],
) -> Result<Map<String, Value>, CalibrationLineageReviewArtifactError> {
    let Value::Object(fields) = value else {
        return Err(CalibrationLineageReviewArtifactError::InvalidValue);
    };
    for field in fields.keys() {
        if prohibited_field(field) {
            return Err(CalibrationLineageReviewArtifactError::ProhibitedField);
        }
        if !expected.contains(&field.as_str()) {
            return Err(CalibrationLineageReviewArtifactError::UnknownField);
        }
    }
    if expected.iter().any(|field| !fields.contains_key(*field)) {
        return Err(CalibrationLineageReviewArtifactError::MissingField);
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
            | "lease_handle"
            | "lease_id"
            | "model_output"
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
) -> Result<Value, CalibrationLineageReviewArtifactError> {
    fields
        .remove(field)
        .ok_or(CalibrationLineageReviewArtifactError::MissingField)
}

fn take_string(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<String, CalibrationLineageReviewArtifactError> {
    match take_value(fields, field)? {
        Value::String(value) => Ok(value),
        _ => Err(CalibrationLineageReviewArtifactError::InvalidValue),
    }
}

fn take_u32(
    fields: &mut Map<String, Value>,
    field: &str,
) -> Result<u32, CalibrationLineageReviewArtifactError> {
    take_value(fields, field)?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(CalibrationLineageReviewArtifactError::InvalidValue)
}

/// JSON tree decoder which rejects duplicate object keys at every depth.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        calibration::dataset::ModelIdentity,
        domain::{
            ApprovalRef, ArtifactId, DatasetRevision, LabelRevision, MappingRevision,
            ModelRevision, PromptRevision, ProviderId, TaskRevision, ThresholdPolicyRevision,
        },
    };
    use serde_json::{Value, json};

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

    fn source_ref(source_id: &str) -> LineageSourceRef {
        LineageSourceRef::new(source_id, "revision-r1").unwrap()
    }

    fn review() -> PartitionLineageReview {
        let declarations = vec![
            PartitionManifestDeclaration::new(
                PartitionRole::Training,
                artifact(2),
                vec![source_ref("training")],
            )
            .unwrap(),
            PartitionManifestDeclaration::new(
                PartitionRole::Calibration,
                artifact(3),
                vec![source_ref("calibration")],
            )
            .unwrap(),
            PartitionManifestDeclaration::new(
                PartitionRole::Evaluation,
                artifact(1),
                vec![source_ref("evaluation")],
            )
            .unwrap(),
            PartitionManifestDeclaration::new(
                PartitionRole::Label,
                artifact(4),
                vec![source_ref("labels")],
            )
            .unwrap(),
        ];
        let sources = vec![
            LineageSourceDeclaration::new(
                source_ref("training"),
                PartitionRole::Training,
                LineageSourceKind::Corpus,
                Vec::new(),
            )
            .unwrap(),
            LineageSourceDeclaration::new(
                source_ref("calibration"),
                PartitionRole::Calibration,
                LineageSourceKind::Corpus,
                Vec::new(),
            )
            .unwrap(),
            LineageSourceDeclaration::new(
                source_ref("evaluation"),
                PartitionRole::Evaluation,
                LineageSourceKind::Corpus,
                Vec::new(),
            )
            .unwrap(),
            LineageSourceDeclaration::new(
                source_ref("labels"),
                PartitionRole::Label,
                LineageSourceKind::ReviewedLabel,
                Vec::new(),
            )
            .unwrap(),
        ];
        let submission = PartitionLineageSubmission::new(declarations, sources).unwrap();
        review_partition_lineage(
            CalibrationLineageReviewId::parse("calrev_018f2a3b-4c5d-7000-8000-000000000099")
                .unwrap(),
            artifact(99),
            provenance(),
            &submission,
        )
        .unwrap()
    }

    fn document() -> CalibrationLineageReviewArtifact {
        CalibrationLineageReviewArtifact::from_review(&review()).unwrap()
    }

    fn parsed(document: &CalibrationLineageReviewArtifact) -> Value {
        serde_json::from_slice(&document.to_canonical_json().unwrap()).unwrap()
    }

    #[test]
    fn artifact_round_trips_the_reviewed_graph_to_fixed_bytes() {
        let document = document();
        let bytes = document.to_canonical_json().unwrap();
        let decoded = CalibrationLineageReviewArtifact::from_canonical_json(&bytes).unwrap();
        assert_eq!(decoded, document);
        assert_eq!(decoded.canonical_json().unwrap(), bytes);
        assert_eq!(decoded.partitions()[0].role(), PartitionRole::Training);
        assert_eq!(decoded.sources()[0].source_id(), "calibration");
    }

    #[test]
    fn artifact_rejects_unknown_prohibited_duplicate_and_noncanonical_fields() {
        let document = document();
        let mut unknown = parsed(&document);
        unknown["extension"] = Value::Null;
        assert_eq!(
            CalibrationLineageReviewArtifact::from_canonical_json(
                &serde_json::to_vec(&unknown).unwrap()
            ),
            Err(CalibrationLineageReviewArtifactError::UnknownField)
        );

        let mut prohibited = parsed(&document);
        prohibited["request_id"] = json!("req_018f2a3b-4c5d-7000-8000-000000000001");
        assert_eq!(
            CalibrationLineageReviewArtifact::from_canonical_json(
                &serde_json::to_vec(&prohibited).unwrap()
            ),
            Err(CalibrationLineageReviewArtifactError::ProhibitedField)
        );

        let bytes = String::from_utf8(document.to_canonical_json().unwrap()).unwrap();
        let duplicate = bytes.replacen(
            "\"kind\":\"calibration_partition_lineage_review\"",
            "\"kind\":\"calibration_partition_lineage_review\",\"kind\":\"calibration_partition_lineage_review\"",
            1,
        );
        assert_eq!(
            CalibrationLineageReviewArtifact::from_canonical_json(duplicate.as_bytes()),
            Err(CalibrationLineageReviewArtifactError::DuplicateField)
        );

        let reordered = bytes.replacen("\"kind\":\"calibration_partition_lineage_review\",", "", 1);
        let reordered = reordered.replacen(
            "\"schema_version\":1,",
            "\"schema_version\":1,\"kind\":\"calibration_partition_lineage_review\",",
            1,
        );
        assert_eq!(
            CalibrationLineageReviewArtifact::from_canonical_json(reordered.as_bytes()),
            Err(CalibrationLineageReviewArtifactError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn artifact_revalidates_partition_and_parent_graph_bindings() {
        let document = document();
        let mut invalid = parsed(&document);
        invalid["sources"][0]["partition"] = json!("label");
        assert_eq!(
            CalibrationLineageReviewArtifact::from_canonical_json(
                &serde_json::to_vec(&invalid).unwrap()
            ),
            Err(CalibrationLineageReviewArtifactError::GraphInvalid)
        );

        let mut cross_partition = parsed(&document);
        cross_partition["sources"][0]["parent_sources"] = json!([{
            "source_id": "training",
            "source_revision": "revision-r1"
        }]);
        assert_eq!(
            CalibrationLineageReviewArtifact::from_canonical_json(
                &serde_json::to_vec(&cross_partition).unwrap()
            ),
            Err(CalibrationLineageReviewArtifactError::GraphInvalid)
        );
    }
}
