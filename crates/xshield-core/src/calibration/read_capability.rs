//! Frozen authorization input for an offline calibration evidence batch.
//!
//! A calibration evaluator needs a purpose-specific batch capability because a
//! console's single-artifact evidence download approval cannot authorize bulk
//! processing. This module only validates that frozen scope; a persistence
//! adapter must still verify its issuance, current catalog state, object
//! integrity, lease use, and each vault read.

use super::{
    MAX_SAMPLES,
    dataset::{EvaluationProvenance, EvaluationReport},
};
use crate::{
    domain::{ArtifactId, CalibrationReadCapabilityId, CalibrationReadLeaseId, SiteId, TenantId},
    identity::UnixSeconds,
};
use std::{collections::BTreeSet, fmt};

/// Hard ceiling for encrypted source objects read by one calibration batch.
///
/// Deployment policy may impose a smaller limit. The evaluator accounts for
/// verified catalog byte lengths before opening any source object.
pub const MAX_CALIBRATION_BATCH_BYTES: u64 = 512 * 1024 * 1024;

/// One frozen model-record and reviewed-label artifact pair for a sample slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationSampleReadScope {
    model_call_artifact_id: ArtifactId,
    label_artifact_id: ArtifactId,
}

impl CalibrationSampleReadScope {
    /// Binds the two source artifacts selected for one calibration sample.
    ///
    /// Alias and batch-wide uniqueness checks occur when the enclosing
    /// [`CalibrationEvidenceReadCapability`] is constructed.
    #[must_use]
    pub const fn new(model_call_artifact_id: ArtifactId, label_artifact_id: ArtifactId) -> Self {
        Self {
            model_call_artifact_id,
            label_artifact_id,
        }
    }

    /// Returns the frozen normalized model-call record artifact.
    #[must_use]
    pub const fn model_call_artifact_id(&self) -> &ArtifactId {
        &self.model_call_artifact_id
    }

    /// Returns the frozen reviewed-label artifact.
    #[must_use]
    pub const fn label_artifact_id(&self) -> &ArtifactId {
        &self.label_artifact_id
    }
}

/// The semantic role under which an evaluator may open one frozen artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationEvidenceRole {
    /// The approved training-partition manifest.
    TrainingManifest,
    /// The approved calibration-partition manifest.
    CalibrationManifest,
    /// The approved held-out evaluation-partition manifest.
    EvaluationManifest,
    /// The approved reviewed-label manifest.
    LabelManifest,
    /// One normalized model-call record selected for a sample slot.
    ModelCallRecord,
    /// One reviewed label selected for a sample slot.
    ReviewedLabel,
}

impl CalibrationEvidenceRole {
    /// Returns the stable storage-facing role discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrainingManifest => "training_manifest",
            Self::CalibrationManifest => "calibration_manifest",
            Self::EvaluationManifest => "evaluation_manifest",
            Self::LabelManifest => "label_manifest",
            Self::ModelCallRecord => "model_call_record",
            Self::ReviewedLabel => "reviewed_label",
        }
    }
}

/// A read-only artifact reference returned from a frozen batch capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationEvidenceRef {
    capability_id: CalibrationReadCapabilityId,
    artifact_id: ArtifactId,
    role: CalibrationEvidenceRole,
    sample_index: Option<u16>,
}

impl CalibrationEvidenceRef {
    /// Returns the exact artifact that the evaluator may attempt to read.
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Returns the role that the evaluator must validate after decoding.
    #[must_use]
    pub const fn role(&self) -> CalibrationEvidenceRole {
        self.role
    }

    /// Returns the source-pair index, absent for partition manifests.
    #[must_use]
    pub const fn sample_index(&self) -> Option<u16> {
        self.sample_index
    }
}

/// Opaque lease material returned by an authoritative calibration batch issuer.
///
/// A persistence adapter creates this handle only after its `begin_batch`
/// transaction has frozen and claimed the complete capability. The core type
/// binds that durable claim to a capability and keeps the lease token out of
/// `Clone` and `Debug`; it does not itself prove that the claim was persisted
/// or consumed. Adapters must revalidate the token and state before every
/// object read.
pub struct CalibrationEvidenceBatchLease {
    lease_id: CalibrationReadLeaseId,
    capability_id: CalibrationReadCapabilityId,
    tenant_id: TenantId,
    site_id: SiteId,
    not_before: UnixSeconds,
    expires_at: UnixSeconds,
    token: [u8; 32],
}

impl CalibrationEvidenceBatchLease {
    /// Wraps one lease returned by a durable, authoritative batch issuer.
    ///
    /// The caller must have already atomically recorded the exact frozen
    /// capability set and lease token. This constructor validates only local
    /// shape and has no persistence, authorization, or audit side effects.
    ///
    /// # Errors
    /// Returns [`CalibrationReadCapabilityError::BatchLeaseInvalid`] for an
    /// empty lease interval or all-zero token.
    pub fn from_issued(
        lease_id: CalibrationReadLeaseId,
        capability_id: CalibrationReadCapabilityId,
        tenant_id: TenantId,
        site_id: SiteId,
        not_before: UnixSeconds,
        expires_at: UnixSeconds,
        token: [u8; 32],
    ) -> Result<Self, CalibrationReadCapabilityError> {
        if not_before >= expires_at || token == [0; 32] {
            return Err(CalibrationReadCapabilityError::BatchLeaseInvalid);
        }
        Ok(Self {
            lease_id,
            capability_id,
            tenant_id,
            site_id,
            not_before,
            expires_at,
            token,
        })
    }

    /// Returns the durable lease identity used for recovery and conditional updates.
    #[must_use]
    pub const fn lease_id(&self) -> &CalibrationReadLeaseId {
        &self.lease_id
    }

    /// Returns the capability identity that the issuer bound to this lease.
    #[must_use]
    pub const fn capability_id(&self) -> &CalibrationReadCapabilityId {
        &self.capability_id
    }

    /// Returns the tenant scope frozen by the issuer.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the site scope frozen by the issuer.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the first instant at which the issuer permits the batch.
    #[must_use]
    pub const fn not_before(&self) -> UnixSeconds {
        self.not_before
    }

    /// Returns the exclusive issuer lease deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    /// Borrows the opaque token for a persistence adapter's revalidation query.
    ///
    /// The token is intentionally neither cloneable nor formattable. Callers
    /// must not log, serialize, or use it as an evidence or user-facing ID.
    #[must_use]
    pub const fn token(&self) -> &[u8; 32] {
        &self.token
    }
}

impl Drop for CalibrationEvidenceBatchLease {
    fn drop(&mut self) {
        self.token.fill(0);
    }
}

/// A non-duplicable in-memory session binding a capability to one batch lease.
///
/// It is created by [`CalibrationEvidenceReadCapability::bind_issued_batch_lease`]
/// after a storage adapter has durably begun a batch. It cannot be forged from
/// a console approval and is intentionally neither `Clone` nor `Debug`.
pub struct CalibrationEvidenceReadSession<'a> {
    capability: &'a CalibrationEvidenceReadCapability,
    lease: CalibrationEvidenceBatchLease,
}

impl<'a> CalibrationEvidenceReadSession<'a> {
    /// Returns the exact in-memory capability bound to this session.
    #[must_use]
    pub const fn capability(&self) -> &'a CalibrationEvidenceReadCapability {
        self.capability
    }

    /// Returns the opaque lease for adapter-owned durable revalidation.
    #[must_use]
    pub const fn lease(&self) -> &CalibrationEvidenceBatchLease {
        &self.lease
    }

    pub(crate) fn authorizes_request(
        &self,
        capability: &CalibrationEvidenceReadCapability,
        evidence_ref: &CalibrationEvidenceRef,
        tenant_id: &TenantId,
        site_id: &SiteId,
        now: UnixSeconds,
    ) -> bool {
        std::ptr::eq(self.capability, capability)
            && self.lease.capability_id == capability.capability_id
            && self.lease.tenant_id == *tenant_id
            && self.lease.site_id == *site_id
            && now >= self.lease.not_before
            && now < self.lease.expires_at
            && capability
                .verify_read_scope(tenant_id, site_id, now)
                .is_ok()
            && capability.permits_evidence_ref(evidence_ref)
    }
}

/// An evaluator-owned proof that one complete frozen batch produced a report.
///
/// This type consumes the non-duplicable read session, so a successful
/// evaluator cannot subsequently hand the same lease to another completion
/// attempt. It is deliberately distinct from an individual read request:
/// one opened artifact, a console approval, or a partial source list cannot
/// construct this proof. The persistence adapter still authenticates the
/// durable active lease and uses its database clock before consuming it.
pub struct CalibrationEvidenceBatchCompletion<'a> {
    session: CalibrationEvidenceReadSession<'a>,
    report: EvaluationReport,
}

impl<'a> CalibrationEvidenceBatchCompletion<'a> {
    /// Binds a successful full evaluation to the exact batch session it used.
    ///
    /// A valid [`EvaluationReport`] is only a full-batch proof when its
    /// frozen provenance and ordered model-record/label source pairs exactly
    /// match the capability. This constructor has no persistence, audit,
    /// publication, or policy side effect. The evaluator owns the obligation
    /// to obtain every source via the controlled reader before it builds the
    /// report; a storage adapter consumes the durable lease only after this
    /// type has been constructed.
    ///
    /// # Errors
    /// Returns [`CalibrationEvidenceBatchCompletionError`] when the report was
    /// formed from another provenance or omits, reorders, or substitutes a
    /// frozen source pair. It never exposes evidence content.
    pub fn from_successful_evaluation(
        session: CalibrationEvidenceReadSession<'a>,
        report: EvaluationReport,
    ) -> Result<Self, CalibrationEvidenceBatchCompletionError> {
        let capability = session.capability();
        if report.provenance() != capability.provenance() {
            return Err(CalibrationEvidenceBatchCompletionError::ProvenanceMismatch);
        }
        if report.sources().len() != capability.sources().len()
            || !report.sources().iter().zip(capability.sources()).all(
                |(report_source, capability_source)| {
                    report_source.model_call_artifact_id()
                        == capability_source.model_call_artifact_id()
                        && report_source.label_artifact_id()
                            == capability_source.label_artifact_id()
                },
            )
        {
            return Err(CalibrationEvidenceBatchCompletionError::SourceSetMismatch);
        }
        Ok(Self { session, report })
    }

    /// Returns the consumed-in-memory session for durable lease comparison.
    ///
    /// This borrows the opaque token only for a purpose-specific persistence
    /// adapter. Callers must not serialize, log, or turn it into a public ID.
    #[must_use]
    pub const fn session(&self) -> &CalibrationEvidenceReadSession<'a> {
        &self.session
    }

    /// Returns the complete evaluation result whose source tuples were bound.
    #[must_use]
    pub const fn report(&self) -> &EvaluationReport {
        &self.report
    }
}

/// Closed failures for binding an evaluator result to a batch completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationEvidenceBatchCompletionError {
    /// The result preserved a different approval/revision/model provenance.
    ProvenanceMismatch,
    /// The result did not cover the frozen source pairs in their exact order.
    SourceSetMismatch,
}

impl CalibrationEvidenceBatchCompletionError {
    /// Returns the stable, payload-free reason code for caller-owned audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::ProvenanceMismatch => "CALIBRATION_READ_BATCH_COMPLETION_PROVENANCE_MISMATCH",
            Self::SourceSetMismatch => "CALIBRATION_READ_BATCH_COMPLETION_SOURCE_SET_MISMATCH",
        }
    }
}

impl fmt::Display for CalibrationEvidenceBatchCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for CalibrationEvidenceBatchCompletionError {}

/// A server-issued, exact-scope capability for one offline calibration batch.
///
/// It intentionally has no `EvidenceAccessRequestId`, case reference, or
/// management role. Those values belong to the console's one-object download
/// flow and cannot authorize this batch. An [`crate::ports`] adapter must
/// verify that this capability was independently issued and has not been used
/// outside its recovery policy before each content read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationEvidenceReadCapability {
    capability_id: CalibrationReadCapabilityId,
    tenant_id: TenantId,
    site_id: SiteId,
    provenance: EvaluationProvenance,
    sources: Vec<CalibrationSampleReadScope>,
    not_before: UnixSeconds,
    expires_at: UnixSeconds,
    max_total_bytes: u64,
}

impl CalibrationEvidenceReadCapability {
    /// Freezes the complete, purpose-specific source set for one evaluation.
    ///
    /// Every partition manifest and every source artifact must be distinct.
    /// The capability carries a configured aggregate byte ceiling, not a claim
    /// that any object is available or readable. Construction has no issuance,
    /// storage, authorization, audit, or object-read side effects.
    ///
    /// # Errors
    /// Returns [`CalibrationReadCapabilityError`] when the sample set, source
    /// identities, byte ceiling, or lease bounds cannot form an exact batch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_id: CalibrationReadCapabilityId,
        tenant_id: TenantId,
        site_id: SiteId,
        provenance: EvaluationProvenance,
        sources: Vec<CalibrationSampleReadScope>,
        not_before: UnixSeconds,
        expires_at: UnixSeconds,
        max_total_bytes: u64,
    ) -> Result<Self, CalibrationReadCapabilityError> {
        if sources.is_empty() {
            return Err(CalibrationReadCapabilityError::EmptySamples);
        }
        if sources.len() > MAX_SAMPLES {
            return Err(CalibrationReadCapabilityError::TooManySamples);
        }
        if !(1..=MAX_CALIBRATION_BATCH_BYTES).contains(&max_total_bytes) {
            return Err(CalibrationReadCapabilityError::ByteLimitInvalid);
        }
        if not_before >= expires_at {
            return Err(CalibrationReadCapabilityError::LeaseInvalid);
        }
        let mut seen = BTreeSet::from([
            provenance.training_manifest_artifact_id(),
            provenance.calibration_manifest_artifact_id(),
            provenance.evaluation_manifest_artifact_id(),
            provenance.label_manifest_artifact_id(),
        ]);
        for source in &sources {
            if source.model_call_artifact_id == source.label_artifact_id {
                return Err(CalibrationReadCapabilityError::SampleEvidenceAliased);
            }
            if !seen.insert(source.model_call_artifact_id())
                || !seen.insert(source.label_artifact_id())
            {
                return Err(CalibrationReadCapabilityError::EvidenceReferenceAliased);
            }
        }
        Ok(Self {
            capability_id,
            tenant_id,
            site_id,
            provenance,
            sources,
            not_before,
            expires_at,
            max_total_bytes,
        })
    }

    /// Rechecks the exact server scope and capability lease before a read.
    ///
    /// A successful result only permits a port to continue its own issuer,
    /// catalog, integrity, and one-batch-use checks; it does not authorize a
    /// caller to read an artifact omitted from [`Self::evidence_refs`].
    ///
    /// # Errors
    /// Returns [`CalibrationReadCapabilityError::ScopeMismatch`],
    /// [`CalibrationReadCapabilityError::NotYetValid`], or
    /// [`CalibrationReadCapabilityError::Expired`] for a rejected read.
    pub fn verify_read_scope(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        now: UnixSeconds,
    ) -> Result<(), CalibrationReadCapabilityError> {
        if &self.tenant_id != tenant_id || &self.site_id != site_id {
            return Err(CalibrationReadCapabilityError::ScopeMismatch);
        }
        if now < self.not_before {
            return Err(CalibrationReadCapabilityError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(CalibrationReadCapabilityError::Expired);
        }
        Ok(())
    }

    /// Binds an authoritative batch lease to this exact in-memory capability.
    ///
    /// A persistence adapter must call this only after an atomic `begin_batch`
    /// operation has validated and claimed the complete frozen set. This method
    /// checks that the issuer's lease has the same identity and scope, is fully
    /// contained in the capability lease, and is current at `now`; it cannot
    /// replace durable issuance, single-use consumption, or recovery checks.
    ///
    /// # Errors
    /// Returns [`CalibrationReadCapabilityError::BatchLeaseMismatch`] when the
    /// capability identity or scope differs, and
    /// [`CalibrationReadCapabilityError::BatchLeaseOutsideCapability`] when the
    /// issuer lease extends outside the frozen capability lease or is not
    /// current. No evidence object is read on either path.
    pub fn bind_issued_batch_lease(
        &self,
        lease: CalibrationEvidenceBatchLease,
        now: UnixSeconds,
    ) -> Result<CalibrationEvidenceReadSession<'_>, CalibrationReadCapabilityError> {
        if lease.capability_id != self.capability_id
            || lease.tenant_id != self.tenant_id
            || lease.site_id != self.site_id
        {
            return Err(CalibrationReadCapabilityError::BatchLeaseMismatch);
        }
        if lease.not_before < self.not_before
            || lease.expires_at > self.expires_at
            || now < lease.not_before
            || now >= lease.expires_at
        {
            return Err(CalibrationReadCapabilityError::BatchLeaseOutsideCapability);
        }
        Ok(CalibrationEvidenceReadSession {
            capability: self,
            lease,
        })
    }

    /// Returns the server-issued batch capability identity.
    #[must_use]
    pub const fn capability_id(&self) -> &CalibrationReadCapabilityId {
        &self.capability_id
    }

    /// Returns the frozen tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the frozen site scope.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the approval and revision provenance the reader must preserve.
    #[must_use]
    pub const fn provenance(&self) -> &EvaluationProvenance {
        &self.provenance
    }

    /// Returns the ordered model-record and reviewed-label artifact pairs.
    #[must_use]
    pub fn sources(&self) -> &[CalibrationSampleReadScope] {
        &self.sources
    }

    /// Returns the first instant at which a read may begin.
    #[must_use]
    pub const fn not_before(&self) -> UnixSeconds {
        self.not_before
    }

    /// Returns the exclusive server-side read deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    /// Returns the configured aggregate catalog-byte ceiling for this batch.
    #[must_use]
    pub const fn max_total_bytes(&self) -> u64 {
        self.max_total_bytes
    }

    /// Materializes the complete and non-expandable set of permitted reads.
    #[must_use]
    pub fn evidence_refs(&self) -> Vec<CalibrationEvidenceRef> {
        let mut refs = vec![
            CalibrationEvidenceRef {
                capability_id: self.capability_id.clone(),
                artifact_id: self.provenance.training_manifest_artifact_id().clone(),
                role: CalibrationEvidenceRole::TrainingManifest,
                sample_index: None,
            },
            CalibrationEvidenceRef {
                capability_id: self.capability_id.clone(),
                artifact_id: self.provenance.calibration_manifest_artifact_id().clone(),
                role: CalibrationEvidenceRole::CalibrationManifest,
                sample_index: None,
            },
            CalibrationEvidenceRef {
                capability_id: self.capability_id.clone(),
                artifact_id: self.provenance.evaluation_manifest_artifact_id().clone(),
                role: CalibrationEvidenceRole::EvaluationManifest,
                sample_index: None,
            },
            CalibrationEvidenceRef {
                capability_id: self.capability_id.clone(),
                artifact_id: self.provenance.label_manifest_artifact_id().clone(),
                role: CalibrationEvidenceRole::LabelManifest,
                sample_index: None,
            },
        ];
        for (sample_index, source) in (0_u16..).zip(&self.sources) {
            refs.extend([
                CalibrationEvidenceRef {
                    capability_id: self.capability_id.clone(),
                    artifact_id: source.model_call_artifact_id.clone(),
                    role: CalibrationEvidenceRole::ModelCallRecord,
                    sample_index: Some(sample_index),
                },
                CalibrationEvidenceRef {
                    capability_id: self.capability_id.clone(),
                    artifact_id: source.label_artifact_id.clone(),
                    role: CalibrationEvidenceRole::ReviewedLabel,
                    sample_index: Some(sample_index),
                },
            ]);
        }
        refs
    }

    /// Checks whether an exported reference belongs to this exact frozen batch.
    ///
    /// The opaque capability identity prevents a reference cloned from an
    /// otherwise identical batch from being mixed into this one. This is only
    /// an in-memory shape check: a reader must independently revalidate the
    /// issued capability and every persisted object before returning content.
    #[must_use]
    pub fn permits_evidence_ref(&self, evidence_ref: &CalibrationEvidenceRef) -> bool {
        if evidence_ref.capability_id != self.capability_id {
            return false;
        }

        match (evidence_ref.role, evidence_ref.sample_index) {
            (CalibrationEvidenceRole::TrainingManifest, None) => {
                evidence_ref.artifact_id == *self.provenance.training_manifest_artifact_id()
            }
            (CalibrationEvidenceRole::CalibrationManifest, None) => {
                evidence_ref.artifact_id == *self.provenance.calibration_manifest_artifact_id()
            }
            (CalibrationEvidenceRole::EvaluationManifest, None) => {
                evidence_ref.artifact_id == *self.provenance.evaluation_manifest_artifact_id()
            }
            (CalibrationEvidenceRole::LabelManifest, None) => {
                evidence_ref.artifact_id == *self.provenance.label_manifest_artifact_id()
            }
            (CalibrationEvidenceRole::ModelCallRecord, Some(index)) => self
                .sources
                .get(usize::from(index))
                .is_some_and(|source| evidence_ref.artifact_id == source.model_call_artifact_id),
            (CalibrationEvidenceRole::ReviewedLabel, Some(index)) => self
                .sources
                .get(usize::from(index))
                .is_some_and(|source| evidence_ref.artifact_id == source.label_artifact_id),
            _ => false,
        }
    }
}

/// Closed failures for a calibration batch evidence capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationReadCapabilityError {
    /// The capability has no selected model-record and label pair.
    EmptySamples,
    /// The capability exceeds the evaluator's fixed sample ceiling.
    TooManySamples,
    /// The aggregate catalog-byte limit is absent or above the hard cap.
    ByteLimitInvalid,
    /// The read lease has no non-empty server-time interval.
    LeaseInvalid,
    /// A model-record and label artifact are the same within one sample.
    SampleEvidenceAliased,
    /// A source duplicates another source or a partition manifest.
    EvidenceReferenceAliased,
    /// The caller did not present the frozen tenant/site scope.
    ScopeMismatch,
    /// The capability lease has not begun.
    NotYetValid,
    /// The capability lease has ended.
    Expired,
    /// A supposedly issued batch lease has an empty interval or empty token.
    BatchLeaseInvalid,
    /// A batch lease does not identify this capability or its tenant/site scope.
    BatchLeaseMismatch,
    /// A batch lease is outside the capability lease or is not currently valid.
    BatchLeaseOutsideCapability,
}

impl CalibrationReadCapabilityError {
    /// Returns the stable, payload-free reason code for caller-owned audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::EmptySamples => "CALIBRATION_READ_SAMPLES_EMPTY",
            Self::TooManySamples => "CALIBRATION_READ_SAMPLES_EXCEEDED",
            Self::ByteLimitInvalid => "CALIBRATION_READ_BYTES_INVALID",
            Self::LeaseInvalid => "CALIBRATION_READ_LEASE_INVALID",
            Self::SampleEvidenceAliased => "CALIBRATION_READ_SAMPLE_EVIDENCE_ALIASED",
            Self::EvidenceReferenceAliased => "CALIBRATION_READ_EVIDENCE_ALIASED",
            Self::ScopeMismatch => "CALIBRATION_READ_SCOPE_MISMATCH",
            Self::NotYetValid => "CALIBRATION_READ_NOT_YET_VALID",
            Self::Expired => "CALIBRATION_READ_EXPIRED",
            Self::BatchLeaseInvalid => "CALIBRATION_READ_BATCH_LEASE_INVALID",
            Self::BatchLeaseMismatch => "CALIBRATION_READ_BATCH_LEASE_MISMATCH",
            Self::BatchLeaseOutsideCapability => "CALIBRATION_READ_BATCH_LEASE_OUTSIDE_CAPABILITY",
        }
    }
}

impl fmt::Display for CalibrationReadCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for CalibrationReadCapabilityError {}

#[cfg(test)]
#[path = "read_capability/tests.rs"]
mod tests;
