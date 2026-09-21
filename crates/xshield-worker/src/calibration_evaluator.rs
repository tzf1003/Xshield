//! Worker-side orchestration for a complete offline calibration evaluation.
//!
//! This module owns the ordering boundary between the purpose-specific evidence
//! reader and the already implemented domain, vault, and `PostgreSQL` contracts.
//! It reads every capability reference in its fixed order and passes each
//! zeroizing object directly to a role-bound decoder before the next object is
//! opened. The decoder supplies pure [`DatasetSample`] values; this module then
//! calls the domain evaluator, persists and freshly attests the protected
//! report, and asks one committer for the atomic terminal transaction.
//!
//! No tracing event in this module contains plaintext, artifact identifiers,
//! labels, probabilities, or lease material. The failure-audit port likewise
//! receives only a capability ID and a stable reason code.

use chrono::{DateTime, Utc};
use std::{error::Error, fmt, future::Future, sync::Arc};
use xshield_core::{
    calibration::{
        Thresholds,
        dataset::{
            DatasetError, DatasetSample, EvaluationProvenance,
            content::{
                CalibrationContentError, DecodedModelCall, decode_dataset_sample_from_model_call,
                decode_model_call_record,
            },
            evaluate_dataset,
        },
        publication::{
            CalibrationReportArtifact, CalibrationReportArtifactError,
            CalibrationReportPublication, PublicationError,
        },
        read_capability::{
            CalibrationEvidenceBatchCompletion, CalibrationEvidenceBatchCompletionError,
            CalibrationEvidenceReadCapability, CalibrationEvidenceReadSession,
            CalibrationEvidenceRef, CalibrationEvidenceRole, CalibrationSampleReadScope,
        },
    },
    domain::{
        ArtifactId, CalibrationReadCapabilityId, CalibrationReportId, EventId, SiteId, TenantId,
    },
    identity::UnixSeconds,
    ports::{
        CalibrationEvidenceReadDenied, CalibrationEvidenceReadPort, CalibrationEvidenceReadRequest,
        CalibrationEvidenceReadState,
    },
};
use xshield_evidence::{
    AttestedCalibrationReportManifest, CalibrationReportEvidenceWrite, EvidenceError,
    LocalEvidenceVault,
};
use xshield_postgres::{
    CalibrationReportCommit, CalibrationReportCommitOutcome, PostgresIdentityStore, StoreError,
};

/// Minimal metadata exposed by a controlled calibration-evidence reader.
///
/// The reader keeps ownership of any secret buffer. A decoder receives the
/// bytes only by borrow and must derive bounded typed values before returning;
/// it must not log, clone, or retain the plaintext.
pub trait CalibrationEvidenceContentView {
    /// Returns the authenticated artifact identity for this buffer.
    fn artifact_id(&self) -> &ArtifactId;

    /// Returns the authenticated semantic role for this buffer.
    fn role(&self) -> CalibrationEvidenceRole;

    /// Returns the authenticated source-pair position, when this is a source.
    fn sample_index(&self) -> Option<u16>;

    /// Borrows authenticated plaintext until this content value is dropped.
    fn as_bytes(&self) -> &[u8];
}

impl CalibrationEvidenceContentView for crate::CalibrationEvidenceContent {
    fn artifact_id(&self) -> &ArtifactId {
        self.artifact_id()
    }

    fn role(&self) -> CalibrationEvidenceRole {
        self.role()
    }

    fn sample_index(&self) -> Option<u16> {
        self.sample_index()
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// One exact, authenticated evidence object offered to a calibration decoder.
///
/// Values are constructed only after the worker has compared the reader's
/// content metadata to the matching frozen capability reference. The wrapper
/// makes the role and source position available with the bytes, so decoder
/// implementations cannot infer a role from an artifact name or caller input.
pub struct CalibrationEvidenceInput<'a, Content> {
    reference: &'a CalibrationEvidenceRef,
    content: &'a Content,
}

impl<'a, Content> CalibrationEvidenceInput<'a, Content> {
    fn new(reference: &'a CalibrationEvidenceRef, content: &'a Content) -> Self {
        Self { reference, content }
    }

    /// Returns the frozen reference whose metadata was checked against content.
    #[must_use]
    pub const fn reference(&self) -> &CalibrationEvidenceRef {
        self.reference
    }

    /// Returns the role required for decoding this object.
    #[must_use]
    pub const fn role(&self) -> CalibrationEvidenceRole {
        self.reference.role()
    }

    /// Returns the source-pair position required for a source object.
    #[must_use]
    pub const fn sample_index(&self) -> Option<u16> {
        self.reference.sample_index()
    }

    /// Borrows plaintext while the reader-owned buffer is still alive.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    where
        Content: CalibrationEvidenceContentView,
    {
        self.content.as_bytes()
    }
}

/// Decodes one fully controlled evidence stream into pure domain samples.
///
/// `begin`, `accept`, and `finish` execute without I/O. The worker invokes
/// `accept` exactly once for each value returned by
/// [`CalibrationEvidenceReadCapability::evidence_refs`] and drops that content
/// before continuing. Implementations must validate their own wire schemas,
/// ensure manifests agree with the frozen provenance, and construct samples
/// only from a matching model-record/reviewed-label pair.
pub trait CalibrationEvidenceDecoder<Content> {
    /// Decoder-specific non-content validation failure.
    type Error;

    /// Initializes one decoder with the immutable batch capability.
    ///
    /// # Errors
    /// Returns the decoder's stable, content-free validation error.
    fn begin(&mut self, capability: &CalibrationEvidenceReadCapability) -> Result<(), Self::Error>;

    /// Accepts one role-bound controlled evidence object.
    ///
    /// # Errors
    /// Returns the decoder's stable, content-free validation error.
    fn accept(
        &mut self,
        evidence: CalibrationEvidenceInput<'_, Content>,
    ) -> Result<(), Self::Error>;

    /// Produces the selected source samples after all required inputs arrived.
    ///
    /// # Errors
    /// Returns the decoder's stable, content-free validation error.
    fn finish(&mut self) -> Result<Vec<DatasetSample>, Self::Error>;
}

/// Production decoder for a schema-v3 model-call and reviewed-label batch.
///
/// It accepts the capability's closed read sequence only. Partition manifests
/// are deliberately not parsed as claims of content independence: their
/// authenticated catalog role, identity, and retention are enforced by the
/// reader, while a later lineage-review boundary must evaluate their declared
/// relationships. A model-call record is reduced to an opaque, content-free
/// join state before its reader buffer is dropped; the following label creates
/// the pure [`DatasetSample`] immediately.
#[derive(Default)]
pub struct SchemaV3CalibrationEvidenceDecoder {
    provenance: Option<EvaluationProvenance>,
    sources: Vec<CalibrationSampleReadScope>,
    expected_refs: Vec<CalibrationEvidenceRef>,
    next_reference: usize,
    pending_records: Vec<Option<DecodedModelCall>>,
    samples: Vec<Option<DatasetSample>>,
}

/// Content-free decoder failure for a closed calibration evidence batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaV3CalibrationEvidenceDecoderError {
    /// A controlled model record or label violated its strict DTO contract.
    Content(CalibrationContentError),
    /// The caller offered a role, slot, or artifact outside the frozen sequence.
    EvidenceSequenceMismatch,
    /// The decoder was reused before finishing or without a successful begin.
    LifecycleMismatch,
}

impl fmt::Display for SchemaV3CalibrationEvidenceDecoderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl Error for SchemaV3CalibrationEvidenceDecoderError {}

impl SchemaV3CalibrationEvidenceDecoderError {
    /// Returns a stable reason code suitable for the content-free evaluator audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Content(error) => error.reason_code(),
            Self::EvidenceSequenceMismatch => "CALIBRATION_EVALUATOR_EVIDENCE_SEQUENCE_MISMATCH",
            Self::LifecycleMismatch => "CALIBRATION_EVALUATOR_DECODER_LIFECYCLE_MISMATCH",
        }
    }
}

impl<Content> CalibrationEvidenceDecoder<Content> for SchemaV3CalibrationEvidenceDecoder
where
    Content: CalibrationEvidenceContentView,
{
    type Error = SchemaV3CalibrationEvidenceDecoderError;

    fn begin(&mut self, capability: &CalibrationEvidenceReadCapability) -> Result<(), Self::Error> {
        if self.provenance.is_some() {
            return Err(SchemaV3CalibrationEvidenceDecoderError::LifecycleMismatch);
        }
        self.provenance = Some(capability.provenance().clone());
        self.sources = capability.sources().to_vec();
        self.expected_refs = capability.evidence_refs();
        self.next_reference = 0;
        self.pending_records = (0..self.sources.len()).map(|_| None).collect();
        self.samples = (0..self.sources.len()).map(|_| None).collect();
        Ok(())
    }

    fn accept(
        &mut self,
        evidence: CalibrationEvidenceInput<'_, Content>,
    ) -> Result<(), Self::Error> {
        let Some(expected) = self.expected_refs.get(self.next_reference) else {
            return Err(SchemaV3CalibrationEvidenceDecoderError::EvidenceSequenceMismatch);
        };
        if expected != evidence.reference() {
            return Err(SchemaV3CalibrationEvidenceDecoderError::EvidenceSequenceMismatch);
        }
        match evidence.role() {
            CalibrationEvidenceRole::TrainingManifest
            | CalibrationEvidenceRole::CalibrationManifest
            | CalibrationEvidenceRole::EvaluationManifest
            | CalibrationEvidenceRole::LabelManifest => {}
            CalibrationEvidenceRole::ModelCallRecord => {
                let index = sample_index(evidence.sample_index())?;
                let record = decode_model_call_record(evidence.as_bytes())
                    .map_err(SchemaV3CalibrationEvidenceDecoderError::Content)?;
                let Some(pending) = self.pending_records.get_mut(index) else {
                    return Err(SchemaV3CalibrationEvidenceDecoderError::EvidenceSequenceMismatch);
                };
                if pending.is_some() {
                    return Err(SchemaV3CalibrationEvidenceDecoderError::EvidenceSequenceMismatch);
                }
                *pending = Some(record);
            }
            CalibrationEvidenceRole::ReviewedLabel => {
                let index = sample_index(evidence.sample_index())?;
                let Some(record) = self.pending_records.get_mut(index).and_then(Option::take)
                else {
                    return Err(SchemaV3CalibrationEvidenceDecoderError::EvidenceSequenceMismatch);
                };
                let Some(provenance) = self.provenance.as_ref() else {
                    return Err(SchemaV3CalibrationEvidenceDecoderError::LifecycleMismatch);
                };
                let Some(source) = self.sources.get(index) else {
                    return Err(SchemaV3CalibrationEvidenceDecoderError::EvidenceSequenceMismatch);
                };
                let sample = decode_dataset_sample_from_model_call(
                    provenance,
                    source,
                    record,
                    evidence.as_bytes(),
                )
                .map_err(SchemaV3CalibrationEvidenceDecoderError::Content)?;
                let Some(slot) = self.samples.get_mut(index) else {
                    return Err(SchemaV3CalibrationEvidenceDecoderError::EvidenceSequenceMismatch);
                };
                if slot.is_some() {
                    return Err(SchemaV3CalibrationEvidenceDecoderError::EvidenceSequenceMismatch);
                }
                *slot = Some(sample);
            }
        }
        self.next_reference = self
            .next_reference
            .checked_add(1)
            .ok_or(SchemaV3CalibrationEvidenceDecoderError::LifecycleMismatch)?;
        Ok(())
    }

    fn finish(&mut self) -> Result<Vec<DatasetSample>, Self::Error> {
        if self.provenance.is_none()
            || self.next_reference != self.expected_refs.len()
            || self.pending_records.iter().any(Option::is_some)
            || self.samples.iter().any(Option::is_none)
        {
            return Err(SchemaV3CalibrationEvidenceDecoderError::LifecycleMismatch);
        }
        let samples = self
            .samples
            .iter_mut()
            .map(|sample| {
                sample
                    .take()
                    .ok_or(SchemaV3CalibrationEvidenceDecoderError::LifecycleMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.provenance = None;
        self.sources.clear();
        self.expected_refs.clear();
        self.next_reference = 0;
        self.pending_records.clear();
        Ok(samples)
    }
}

fn sample_index(
    sample_index: Option<u16>,
) -> Result<usize, SchemaV3CalibrationEvidenceDecoderError> {
    sample_index
        .map(usize::from)
        .ok_or(SchemaV3CalibrationEvidenceDecoderError::EvidenceSequenceMismatch)
}

/// A content-free failure fact required before a pre-commit batch is abandoned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationEvaluationFailure {
    capability_id: CalibrationReadCapabilityId,
    reason_code: &'static str,
}

impl CalibrationEvaluationFailure {
    fn new(capability_id: CalibrationReadCapabilityId, reason_code: &'static str) -> Self {
        Self {
            capability_id,
            reason_code,
        }
    }

    /// Returns the capability whose active lease remains unconsumed.
    #[must_use]
    pub const fn capability_id(&self) -> &CalibrationReadCapabilityId {
        &self.capability_id
    }

    /// Returns the stable non-content terminal reason.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }
}

/// Appends a durable evaluator-owned failure terminal fact.
///
/// The successful terminal facts are part of the atomic report commit. This
/// port covers failures before that commit; an implementation must not put
/// plaintext, identities, artifact IDs, labels, probabilities, or lease tokens
/// in its durable event or logs.
pub trait CalibrationEvaluationFailureAudit {
    /// Durable-audit dependency failure.
    type Error;

    /// Records one pre-commit terminal failure.
    fn record_failure(
        &self,
        failure: CalibrationEvaluationFailure,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + '_;
}

/// Inputs selected by trusted worker assembly for one evaluation attempt.
pub struct CalibrationEvaluationRun<'a> {
    now: UnixSeconds,
    thresholds: Thresholds,
    report_id: &'a CalibrationReportId,
    report_artifact_id: &'a ArtifactId,
    report_expires_at: DateTime<Utc>,
    runner_id: &'a str,
    completion_event_id: &'a EventId,
    report_event_id: &'a EventId,
}

impl<'a> CalibrationEvaluationRun<'a> {
    /// Groups immutable attempt settings supplied by trusted worker assembly.
    ///
    /// The report and event IDs must stay stable if a caller retries an unknown
    /// commit outcome. Database commit validation checks the runner and event
    /// bindings again; this constructor has no side effects.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        now: UnixSeconds,
        thresholds: Thresholds,
        report_id: &'a CalibrationReportId,
        report_artifact_id: &'a ArtifactId,
        report_expires_at: DateTime<Utc>,
        runner_id: &'a str,
        completion_event_id: &'a EventId,
        report_event_id: &'a EventId,
    ) -> Self {
        Self {
            now,
            thresholds,
            report_id,
            report_artifact_id,
            report_expires_at,
            runner_id,
            completion_event_id,
            report_event_id,
        }
    }
}

/// Report persistence boundary that returns a fresh vault attestation.
pub trait CalibrationReportVault {
    /// Fresh authenticated manifest type passed directly to the committer.
    type Attestation;
    /// Vault or local-execution failure.
    type Error;

    /// Writes and freshly attests one protected report body.
    ///
    /// # Errors
    /// Returns a non-content vault or local-execution failure.
    fn write_and_attest<'a>(
        &'a self,
        command: CalibrationReportVaultCommand<'a>,
    ) -> impl Future<Output = Result<Self::Attestation, Self::Error>> + Send + 'a;
}

/// Typed report persistence input built after a complete domain evaluation.
pub struct CalibrationReportVaultCommand<'a> {
    tenant_id: &'a TenantId,
    site_id: &'a SiteId,
    report: &'a CalibrationReportArtifact,
    expires_at: DateTime<Utc>,
}

impl<'a> CalibrationReportVaultCommand<'a> {
    fn new(
        tenant_id: &'a TenantId,
        site_id: &'a SiteId,
        report: &'a CalibrationReportArtifact,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            tenant_id,
            site_id,
            report,
            expires_at,
        }
    }

    /// Returns the report selected for write and fresh authentication.
    #[must_use]
    pub const fn report(&self) -> &CalibrationReportArtifact {
        self.report
    }

    /// Returns the trusted tenant scope bound to the report write.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.tenant_id
    }

    /// Returns the trusted site scope bound to the report write.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        self.site_id
    }

    /// Returns the exclusive retention deadline selected by worker assembly.
    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

/// Atomic report-commit boundary.
pub trait CalibrationReportCommitter<Attestation> {
    /// Commit dependency failure.
    type Error;
    /// Durable commit or exact-retry receipt.
    type Receipt;

    /// Atomically binds the report, capability/lease terminal states, and outbox facts.
    ///
    /// # Errors
    /// Returns the commit dependency's non-content failure. A database
    /// transport failure may be retried with the exact same command identity.
    fn commit<'command>(
        &'command self,
        command: CalibrationReportCommitCommand<'command, '_, Attestation>,
    ) -> impl Future<Output = Result<Self::Receipt, Self::Error>> + Send + 'command;
}

/// Fully bound command passed from fresh report attestation to the committer.
pub struct CalibrationReportCommitCommand<'command, 'capability, Attestation> {
    completion: &'command CalibrationEvidenceBatchCompletion<'capability>,
    report: &'command CalibrationReportArtifact,
    publication: &'command CalibrationReportPublication,
    attestation: &'command Attestation,
    runner_id: &'command str,
    completion_event_id: &'command EventId,
    report_event_id: &'command EventId,
}

impl<'command, 'capability, Attestation>
    CalibrationReportCommitCommand<'command, 'capability, Attestation>
{
    fn new(
        completion: &'command CalibrationEvidenceBatchCompletion<'capability>,
        report: &'command CalibrationReportArtifact,
        publication: &'command CalibrationReportPublication,
        attestation: &'command Attestation,
        runner_id: &'command str,
        completion_event_id: &'command EventId,
        report_event_id: &'command EventId,
    ) -> Self {
        Self {
            completion,
            report,
            publication,
            attestation,
            runner_id,
            completion_event_id,
            report_event_id,
        }
    }

    /// Returns the consumed in-memory batch proof.
    #[must_use]
    pub const fn completion(&self) -> &CalibrationEvidenceBatchCompletion<'capability> {
        self.completion
    }

    /// Returns the protected deterministic report body.
    #[must_use]
    pub const fn report(&self) -> &CalibrationReportArtifact {
        self.report
    }

    /// Returns the matching restricted publication projection.
    #[must_use]
    pub const fn publication(&self) -> &CalibrationReportPublication {
        self.publication
    }

    /// Returns the fresh vault attestation.
    #[must_use]
    pub const fn attestation(&self) -> &Attestation {
        self.attestation
    }

    /// Returns the configured evaluator runner identity.
    #[must_use]
    pub const fn runner_id(&self) -> &str {
        self.runner_id
    }

    /// Returns the frozen batch-completion event identity.
    #[must_use]
    pub const fn completion_event_id(&self) -> &EventId {
        self.completion_event_id
    }

    /// Returns the frozen report-publication event identity.
    #[must_use]
    pub const fn report_event_id(&self) -> &EventId {
        self.report_event_id
    }
}

/// Durable result of one complete evaluator run.
#[derive(Debug)]
pub struct CalibrationEvaluationRunOutcome<Receipt> {
    receipt: Receipt,
}

impl<Receipt> CalibrationEvaluationRunOutcome<Receipt> {
    /// Returns the atomic commit or exact-retry receipt.
    #[must_use]
    pub const fn receipt(&self) -> &Receipt {
        &self.receipt
    }
}

/// Stable, non-content result of an evaluator orchestration failure.
#[derive(Debug)]
pub enum CalibrationEvaluatorError<ReaderError, DecoderError, VaultError, CommitError, AuditError> {
    /// A locally constructed exact capability request was denied.
    ReadDenied(CalibrationEvidenceReadDenied),
    /// The purpose-specific reader failed before exposing an object.
    Reader(ReaderError),
    /// Reader metadata differed from the exact frozen reference.
    ContentBindingMismatch,
    /// The typed record/label/manifest decoder rejected controlled input.
    Decoder(DecoderError),
    /// The pure domain dataset evaluator rejected its typed samples.
    Dataset(DatasetError),
    /// The complete report did not cover the frozen batch in exact order.
    Completion(CalibrationEvidenceBatchCompletionError),
    /// The report projection would alias protected source evidence.
    Publication(PublicationError),
    /// The canonical protected report body could not be constructed.
    Artifact(CalibrationReportArtifactError),
    /// Report write or fresh vault attestation failed.
    Vault(VaultError),
    /// The atomic report commit dependency failed.
    Commit(CommitError),
    /// A pre-commit failure could not be made durable in the evaluator audit.
    Audit(AuditError),
}

impl<ReaderError, DecoderError, VaultError, CommitError, AuditError>
    CalibrationEvaluatorError<ReaderError, DecoderError, VaultError, CommitError, AuditError>
{
    /// Returns the stable terminal reason code without evidence content.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::ReadDenied(error) => error.reason_code(),
            Self::Reader(_) => "CALIBRATION_EVALUATOR_READER_UNAVAILABLE",
            Self::ContentBindingMismatch => "CALIBRATION_EVALUATOR_CONTENT_BINDING_MISMATCH",
            Self::Decoder(_) => "CALIBRATION_EVALUATOR_DECODER_REJECTED",
            Self::Dataset(error) => error.reason_code(),
            Self::Completion(error) => error.reason_code(),
            Self::Publication(error) => error.reason_code(),
            Self::Artifact(_) => "CALIBRATION_REPORT_ARTIFACT_INVALID",
            Self::Vault(_) => "CALIBRATION_REPORT_VAULT_UNAVAILABLE",
            Self::Commit(_) => "CALIBRATION_REPORT_COMMIT_DEPENDENCY_UNAVAILABLE",
            Self::Audit(_) => "CALIBRATION_EVALUATOR_AUDIT_UNAVAILABLE",
        }
    }
}

impl<ReaderError, DecoderError, VaultError, CommitError, AuditError> fmt::Display
    for CalibrationEvaluatorError<ReaderError, DecoderError, VaultError, CommitError, AuditError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl<ReaderError, DecoderError, VaultError, CommitError, AuditError> Error
    for CalibrationEvaluatorError<ReaderError, DecoderError, VaultError, CommitError, AuditError>
where
    ReaderError: fmt::Debug,
    DecoderError: fmt::Debug,
    VaultError: fmt::Debug,
    CommitError: fmt::Debug,
    AuditError: fmt::Debug,
{
}

/// Runs one full, exact-scope calibration evaluation.
///
/// The session is consumed only after all controlled reads, typed decoding, and
/// pure domain evaluation have succeeded. A report is written and freshly
/// attested only after that full-batch proof exists, and the committer is the
/// sole operation permitted to consume the durable lease. Every pre-commit
/// failure records a content-free terminal audit and leaves the lease active.
///
/// # Errors
/// Returns a stable, content-free error when a read, decoder, domain
/// evaluation, vault, commit, or required failure audit cannot complete.
// This function is the single linearization boundary for the evaluator:
// splitting each fail-closed stage would make the audit-before-return order
// and reader-buffer lifetime harder to verify.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn run_calibration_evaluation<Reader, Decoder, Vault, Committer, Audit>(
    reader: &Reader,
    decoder: &mut Decoder,
    vault: &Vault,
    committer: &Committer,
    audit: &Audit,
    session: CalibrationEvidenceReadSession<'_>,
    input: CalibrationEvaluationRun<'_>,
) -> Result<
    CalibrationEvaluationRunOutcome<Committer::Receipt>,
    CalibrationEvaluatorError<
        Reader::Error,
        Decoder::Error,
        Vault::Error,
        Committer::Error,
        Audit::Error,
    >,
>
where
    Reader: CalibrationEvidenceReadPort,
    Reader::Content: CalibrationEvidenceContentView,
    Decoder: CalibrationEvidenceDecoder<Reader::Content>,
    Vault: CalibrationReportVault,
    Committer: CalibrationReportCommitter<Vault::Attestation>,
    Audit: CalibrationEvaluationFailureAudit,
{
    type RunError<Reader, Decoder, Vault, Committer, Audit> =
        CalibrationEvaluatorError<
            <Reader as CalibrationEvidenceReadPort>::Error,
            <Decoder as CalibrationEvidenceDecoder<
                <Reader as CalibrationEvidenceReadPort>::Content,
            >>::Error,
            <Vault as CalibrationReportVault>::Error,
            <Committer as CalibrationReportCommitter<
                <Vault as CalibrationReportVault>::Attestation,
            >>::Error,
            <Audit as CalibrationEvaluationFailureAudit>::Error,
        >;

    let capability = session.capability();
    let capability_id = capability.capability_id().clone();
    let tenant_id = capability.tenant_id().clone();
    let site_id = capability.site_id().clone();

    macro_rules! fail {
        ($error:expr) => {{
            let error: RunError<Reader, Decoder, Vault, Committer, Audit> = $error;
            audit
                .record_failure(CalibrationEvaluationFailure::new(
                    capability_id.clone(),
                    error.reason_code(),
                ))
                .await
                .map_err(CalibrationEvaluatorError::Audit)?;
            return Err(error);
        }};
    }

    if let Err(error) = decoder.begin(capability) {
        fail!(CalibrationEvaluatorError::Decoder(error));
    }
    for reference in capability.evidence_refs() {
        let request = match CalibrationEvidenceReadRequest::new(
            &session, capability, &reference, &tenant_id, &site_id, input.now,
        ) {
            Ok(request) => request,
            Err(error) => fail!(CalibrationEvaluatorError::ReadDenied(error)),
        };
        let state = match reader.read_calibration_evidence(request).await {
            Ok(state) => state,
            Err(error) => fail!(CalibrationEvaluatorError::Reader(error)),
        };
        let content = match state {
            CalibrationEvidenceReadState::Read(content) => content,
            CalibrationEvidenceReadState::Denied(error) => {
                fail!(CalibrationEvaluatorError::ReadDenied(error));
            }
        };
        if !content_matches_reference(&content, &reference) {
            fail!(CalibrationEvaluatorError::ContentBindingMismatch);
        }
        if let Err(error) = decoder.accept(CalibrationEvidenceInput::new(&reference, &content)) {
            fail!(CalibrationEvaluatorError::Decoder(error));
        }
        // `content` drops here, before the next reader call. This preserves the
        // LocalCalibrationEvidenceReader one-buffer release invariant.
    }
    let samples = match decoder.finish() {
        Ok(samples) => samples,
        Err(error) => fail!(CalibrationEvaluatorError::Decoder(error)),
    };
    let evaluation =
        match evaluate_dataset(capability.provenance().clone(), &samples, input.thresholds) {
            Ok(evaluation) => evaluation,
            Err(error) => fail!(CalibrationEvaluatorError::Dataset(error)),
        };
    let completion =
        match CalibrationEvidenceBatchCompletion::from_successful_evaluation(session, evaluation) {
            Ok(completion) => completion,
            Err(error) => fail!(CalibrationEvaluatorError::Completion(error)),
        };
    let publication = match CalibrationReportPublication::new(
        input.report_id.clone(),
        input.report_artifact_id.clone(),
        completion.report(),
    ) {
        Ok(publication) => publication,
        Err(error) => fail!(CalibrationEvaluatorError::Publication(error)),
    };
    let report = match CalibrationReportArtifact::from_evaluation(&publication, completion.report())
    {
        Ok(report) => report,
        Err(error) => fail!(CalibrationEvaluatorError::Artifact(error)),
    };
    let attestation = match vault
        .write_and_attest(CalibrationReportVaultCommand::new(
            &tenant_id,
            &site_id,
            &report,
            input.report_expires_at,
        ))
        .await
    {
        Ok(attestation) => attestation,
        Err(error) => fail!(CalibrationEvaluatorError::Vault(error)),
    };
    let receipt = match committer
        .commit(CalibrationReportCommitCommand::new(
            &completion,
            &report,
            &publication,
            &attestation,
            input.runner_id,
            input.completion_event_id,
            input.report_event_id,
        ))
        .await
    {
        Ok(receipt) => receipt,
        // The PostgreSQL transaction is the successful terminal audit. A
        // transport/dependency error leaves retry handling to the same frozen
        // report and event identities, so it still receives a failure audit.
        Err(error) => fail!(CalibrationEvaluatorError::Commit(error)),
    };
    Ok(CalibrationEvaluationRunOutcome { receipt })
}

fn content_matches_reference<Content: CalibrationEvidenceContentView>(
    content: &Content,
    reference: &CalibrationEvidenceRef,
) -> bool {
    content.artifact_id() == reference.artifact_id()
        && content.role() == reference.role()
        && content.sample_index() == reference.sample_index()
}

/// Local vault adapter that keeps blocking report durability off Tokio workers.
pub struct LocalCalibrationReportVault {
    vault: Arc<LocalEvidenceVault>,
}

impl LocalCalibrationReportVault {
    /// Wraps a local report vault for worker orchestration.
    #[must_use]
    pub fn new(vault: LocalEvidenceVault) -> Self {
        Self {
            vault: Arc::new(vault),
        }
    }
}

/// Non-content failure from [`LocalCalibrationReportVault`].
#[derive(Debug)]
pub enum LocalCalibrationReportVaultError {
    /// The local vault rejected report persistence or fresh authentication.
    Vault(EvidenceError),
    /// The blocking vault task did not complete.
    Cancelled(tokio::task::JoinError),
}

impl fmt::Display for LocalCalibrationReportVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CALIBRATION_REPORT_VAULT_UNAVAILABLE")
    }
}

impl Error for LocalCalibrationReportVaultError {}

impl CalibrationReportVault for LocalCalibrationReportVault {
    type Attestation = AttestedCalibrationReportManifest;
    type Error = LocalCalibrationReportVaultError;

    async fn write_and_attest(
        &self,
        command: CalibrationReportVaultCommand<'_>,
    ) -> Result<Self::Attestation, Self::Error> {
        let vault = Arc::clone(&self.vault);
        let tenant_id = command.tenant_id.clone();
        let site_id = command.site_id.clone();
        let report = command.report.clone();
        let expires_at = command.expires_at;
        tokio::task::spawn_blocking(move || {
            vault
                .write_calibration_report(&CalibrationReportEvidenceWrite {
                    tenant_id: &tenant_id,
                    site_id: &site_id,
                    report: &report,
                    expires_at,
                })
                .map_err(LocalCalibrationReportVaultError::Vault)?;
            vault
                .attest_calibration_report(&tenant_id, &site_id, &report)
                .map_err(LocalCalibrationReportVaultError::Vault)
        })
        .await
        .map_err(LocalCalibrationReportVaultError::Cancelled)?
    }
}

impl CalibrationReportCommitter<AttestedCalibrationReportManifest> for PostgresIdentityStore {
    type Error = StoreError;
    type Receipt = CalibrationReportCommitOutcome;

    async fn commit<'command>(
        &'command self,
        command: CalibrationReportCommitCommand<'command, '_, AttestedCalibrationReportManifest>,
    ) -> Result<Self::Receipt, Self::Error> {
        let build_command = || {
            CalibrationReportCommit::new(
                command.completion,
                command.report,
                command.publication,
                command.attestation,
                command.runner_id(),
                command.completion_event_id(),
                command.report_event_id(),
            )
        };
        match self
            .complete_and_publish_calibration_report(build_command()?)
            .await
        {
            Ok(outcome) => Ok(outcome),
            Err(first @ StoreError::Database(_)) => {
                // A transport failure may occur after PostgreSQL committed.
                // Rebuild the exact command with the same report/artifact/event
                // identities; the adapter resolves a committed retry as
                // `Existing` and rejects any identity drift.
                match self
                    .complete_and_publish_calibration_report(build_command()?)
                    .await
                {
                    Ok(outcome) => Ok(outcome),
                    Err(_) => Err(first),
                }
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use serde_json::json;
    use std::sync::Mutex;
    use xshield_core::{
        calibration::{
            GroundTruth, Probability, Signal,
            dataset::{EvaluationProvenance, ModelIdentity},
            read_capability::{CalibrationEvidenceBatchLease, CalibrationSampleReadScope},
        },
        domain::{
            CalibrationLineageReviewId, DatasetRevision, LabelRevision, MappingRevision,
            ModelCallId, ModelRevision, PromptRevision, ProviderId, TaskRevision,
            ThresholdPolicyRevision,
        },
    };

    #[derive(Clone)]
    struct TestContent {
        artifact_id: ArtifactId,
        role: CalibrationEvidenceRole,
        sample_index: Option<u16>,
        bytes: Vec<u8>,
    }

    impl CalibrationEvidenceContentView for TestContent {
        fn artifact_id(&self) -> &ArtifactId {
            &self.artifact_id
        }

        fn role(&self) -> CalibrationEvidenceRole {
            self.role
        }

        fn sample_index(&self) -> Option<u16> {
            self.sample_index
        }

        fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    #[derive(Debug)]
    struct TestReadError;

    struct TestReader {
        seen: Mutex<Vec<(ArtifactId, CalibrationEvidenceRole, Option<u16>)>>,
        mismatch: bool,
        deny: bool,
    }

    impl CalibrationEvidenceReadPort for TestReader {
        type Content = TestContent;
        type Error = TestReadError;

        async fn read_calibration_evidence<'a>(
            &'a self,
            request: CalibrationEvidenceReadRequest<'a>,
        ) -> Result<CalibrationEvidenceReadState<Self::Content>, Self::Error> {
            let reference = request.evidence_ref();
            self.seen.lock().expect("test lock").push((
                reference.artifact_id().clone(),
                reference.role(),
                reference.sample_index(),
            ));
            if self.deny {
                return Ok(CalibrationEvidenceReadState::Denied(
                    CalibrationEvidenceReadDenied::EvidenceNotAuthorized,
                ));
            }
            let role = if self.mismatch {
                CalibrationEvidenceRole::ReviewedLabel
            } else {
                reference.role()
            };
            Ok(CalibrationEvidenceReadState::Read(TestContent {
                artifact_id: reference.artifact_id().clone(),
                role,
                sample_index: reference.sample_index(),
                bytes: vec![1],
            }))
        }
    }

    #[derive(Debug)]
    struct TestDecodeError;

    struct TestDecoder {
        provenance: EvaluationProvenance,
        accepted: Vec<CalibrationEvidenceRole>,
    }

    impl CalibrationEvidenceDecoder<TestContent> for TestDecoder {
        type Error = TestDecodeError;

        fn begin(&mut self, _: &CalibrationEvidenceReadCapability) -> Result<(), Self::Error> {
            Ok(())
        }

        fn accept(
            &mut self,
            evidence: CalibrationEvidenceInput<'_, TestContent>,
        ) -> Result<(), Self::Error> {
            assert_eq!(evidence.as_bytes(), [1]);
            self.accepted.push(evidence.role());
            Ok(())
        }

        fn finish(&mut self) -> Result<Vec<DatasetSample>, Self::Error> {
            let source = CalibrationSampleReadScope::new(artifact(5), artifact(6));
            Ok(vec![
                DatasetSample::new(
                    model_call(1),
                    source.model_call_artifact_id().clone(),
                    source.label_artifact_id().clone(),
                    self.provenance.model().clone(),
                    self.provenance.mapping_revision().clone(),
                    GroundTruth::Benign,
                    Signal::Risk(Probability::new(0.1).expect("probability")),
                )
                .expect("sample"),
            ])
        }
    }

    #[derive(Debug)]
    struct TestVaultError;

    struct TestVault {
        reports: Mutex<Vec<CalibrationReportArtifact>>,
    }

    impl CalibrationReportVault for TestVault {
        type Attestation = ();
        type Error = TestVaultError;

        async fn write_and_attest(
            &self,
            command: CalibrationReportVaultCommand<'_>,
        ) -> Result<Self::Attestation, Self::Error> {
            self.reports
                .lock()
                .expect("test lock")
                .push(command.report().clone());
            Ok(())
        }
    }

    #[derive(Debug)]
    struct TestCommitError;

    struct TestCommitter {
        commits: Mutex<usize>,
    }

    impl CalibrationReportCommitter<()> for TestCommitter {
        type Error = TestCommitError;
        type Receipt = &'static str;

        async fn commit<'command>(
            &'command self,
            command: CalibrationReportCommitCommand<'command, '_, ()>,
        ) -> Result<Self::Receipt, Self::Error> {
            assert_eq!(command.report().sources().len(), 1);
            assert_eq!(command.completion().report().sources().len(), 1);
            *self.commits.lock().expect("test lock") += 1;
            Ok("committed")
        }
    }

    #[derive(Debug)]
    struct TestAuditError;

    struct TestAudit {
        failures: Mutex<Vec<CalibrationEvaluationFailure>>,
    }

    impl CalibrationEvaluationFailureAudit for TestAudit {
        type Error = TestAuditError;

        async fn record_failure(
            &self,
            failure: CalibrationEvaluationFailure,
        ) -> Result<(), Self::Error> {
            self.failures.lock().expect("test lock").push(failure);
            Ok(())
        }
    }

    #[tokio::test]
    async fn evaluates_every_exact_reference_then_attests_and_commits() {
        let fixture = fixture();
        let reader = TestReader {
            seen: Mutex::new(Vec::new()),
            mismatch: false,
            deny: false,
        };
        let mut decoder = TestDecoder {
            provenance: fixture.capability.provenance().clone(),
            accepted: Vec::new(),
        };
        let vault = TestVault {
            reports: Mutex::new(Vec::new()),
        };
        let committer = TestCommitter {
            commits: Mutex::new(0),
        };
        let audit = TestAudit {
            failures: Mutex::new(Vec::new()),
        };

        let outcome = run_calibration_evaluation(
            &reader,
            &mut decoder,
            &vault,
            &committer,
            &audit,
            fixture.session(),
            fixture.run(),
        )
        .await
        .expect("complete controlled evaluation");

        assert_eq!(*outcome.receipt(), "committed");
        assert_eq!(
            reader.seen.lock().expect("test lock").as_slice(),
            fixture
                .capability
                .evidence_refs()
                .iter()
                .map(|reference| (
                    reference.artifact_id().clone(),
                    reference.role(),
                    reference.sample_index(),
                ))
                .collect::<Vec<_>>()
                .as_slice()
        );
        assert_eq!(decoder.accepted.len(), 6);
        assert_eq!(vault.reports.lock().expect("test lock").len(), 1);
        assert_eq!(*committer.commits.lock().expect("test lock"), 1);
        assert!(audit.failures.lock().expect("test lock").is_empty());
    }

    #[test]
    fn schema_v3_decoder_releases_model_plaintext_before_joining_its_label() {
        let fixture = fixture();
        let mut decoder = SchemaV3CalibrationEvidenceDecoder::default();
        <SchemaV3CalibrationEvidenceDecoder as CalibrationEvidenceDecoder<TestContent>>::begin(
            &mut decoder,
            &fixture.capability,
        )
        .expect("closed capability begins decoder");
        for reference in fixture.capability.evidence_refs() {
            let bytes = match reference.role() {
                CalibrationEvidenceRole::ModelCallRecord => schema_v3_model_call_record(),
                CalibrationEvidenceRole::ReviewedLabel => {
                    schema_v3_reviewed_label(fixture.capability.provenance())
                }
                CalibrationEvidenceRole::TrainingManifest
                | CalibrationEvidenceRole::CalibrationManifest
                | CalibrationEvidenceRole::EvaluationManifest
                | CalibrationEvidenceRole::LabelManifest => b"{}".to_vec(),
            };
            let content = TestContent {
                artifact_id: reference.artifact_id().clone(),
                role: reference.role(),
                sample_index: reference.sample_index(),
                bytes,
            };
            <SchemaV3CalibrationEvidenceDecoder as CalibrationEvidenceDecoder<TestContent>>::accept(
                &mut decoder,
                CalibrationEvidenceInput::new(&reference, &content),
            )
            .expect("closed evidence sequence decodes");
            // `content` is dropped before the next reference. The decoder's
            // pending state contains only DecodedModelCall, never these bytes.
        }
        let samples = <SchemaV3CalibrationEvidenceDecoder as CalibrationEvidenceDecoder<
            TestContent,
        >>::finish(&mut decoder)
        .expect("one v3 sample is complete");
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].sample().model_call_id, model_call(1));
        assert_eq!(
            samples[0].sample().signal,
            Signal::Risk(Probability::new(0.9).expect("probability"))
        );
    }

    #[tokio::test]
    async fn rejects_reader_metadata_substitution_before_decoder_or_commit() {
        let fixture = fixture();
        let reader = TestReader {
            seen: Mutex::new(Vec::new()),
            mismatch: true,
            deny: false,
        };
        let mut decoder = TestDecoder {
            provenance: fixture.capability.provenance().clone(),
            accepted: Vec::new(),
        };
        let vault = TestVault {
            reports: Mutex::new(Vec::new()),
        };
        let committer = TestCommitter {
            commits: Mutex::new(0),
        };
        let audit = TestAudit {
            failures: Mutex::new(Vec::new()),
        };

        let error = run_calibration_evaluation(
            &reader,
            &mut decoder,
            &vault,
            &committer,
            &audit,
            fixture.session(),
            fixture.run(),
        )
        .await
        .expect_err("mismatched reader content must stop evaluation");

        assert_eq!(
            error.reason_code(),
            "CALIBRATION_EVALUATOR_CONTENT_BINDING_MISMATCH"
        );
        assert!(decoder.accepted.is_empty());
        assert!(vault.reports.lock().expect("test lock").is_empty());
        assert_eq!(*committer.commits.lock().expect("test lock"), 0);
        assert_eq!(
            audit.failures.lock().expect("test lock")[0].reason_code(),
            "CALIBRATION_EVALUATOR_CONTENT_BINDING_MISMATCH"
        );
    }

    #[tokio::test]
    async fn records_denied_read_without_publishing_a_report() {
        let fixture = fixture();
        let reader = TestReader {
            seen: Mutex::new(Vec::new()),
            mismatch: false,
            deny: true,
        };
        let mut decoder = TestDecoder {
            provenance: fixture.capability.provenance().clone(),
            accepted: Vec::new(),
        };
        let vault = TestVault {
            reports: Mutex::new(Vec::new()),
        };
        let committer = TestCommitter {
            commits: Mutex::new(0),
        };
        let audit = TestAudit {
            failures: Mutex::new(Vec::new()),
        };

        let error = run_calibration_evaluation(
            &reader,
            &mut decoder,
            &vault,
            &committer,
            &audit,
            fixture.session(),
            fixture.run(),
        )
        .await
        .expect_err("denied controlled read must stop evaluation");

        assert_eq!(error.reason_code(), "CALIBRATION_EVIDENCE_NOT_AUTHORIZED");
        assert!(vault.reports.lock().expect("test lock").is_empty());
        assert_eq!(*committer.commits.lock().expect("test lock"), 0);
        assert_eq!(audit.failures.lock().expect("test lock").len(), 1);
    }

    struct Fixture {
        capability: CalibrationEvidenceReadCapability,
        report_id: CalibrationReportId,
        report_artifact_id: ArtifactId,
        completion_event_id: EventId,
        report_event_id: EventId,
    }

    impl Fixture {
        fn session(&self) -> CalibrationEvidenceReadSession<'_> {
            self.capability
                .bind_issued_batch_lease(
                    CalibrationEvidenceBatchLease::from_issued(
                        lease_id(),
                        capability_id(),
                        tenant(),
                        site(),
                        UnixSeconds::new(100),
                        UnixSeconds::new(200),
                        [1; 32],
                    )
                    .expect("lease"),
                    UnixSeconds::new(101),
                )
                .expect("session")
        }

        fn run(&self) -> CalibrationEvaluationRun<'_> {
            CalibrationEvaluationRun::new(
                UnixSeconds::new(101),
                Thresholds::new(
                    Probability::new(0.2).expect("probability"),
                    Probability::new(0.8).expect("probability"),
                )
                .expect("thresholds"),
                &self.report_id,
                &self.report_artifact_id,
                Utc::now() + TimeDelta::days(1),
                "calibration-evaluator",
                &self.completion_event_id,
                &self.report_event_id,
            )
        }
    }

    fn fixture() -> Fixture {
        let provenance = EvaluationProvenance::new(
            scoped("approval-r1"),
            scoped("dataset-r1"),
            scoped("labels-r1"),
            scoped("task-r1"),
            scoped("threshold-r1"),
            scoped("mapping-r1"),
            artifact(1),
            artifact(2),
            artifact(3),
            artifact(4),
            ModelIdentity::new(
                scoped("provider-r1"),
                "provider/model",
                scoped("model-r1"),
                scoped("prompt-r1"),
                None,
            )
            .expect("model"),
        )
        .expect("provenance");
        Fixture {
            capability: CalibrationEvidenceReadCapability::new(
                capability_id(),
                lineage_review_id(),
                tenant(),
                site(),
                provenance,
                vec![CalibrationSampleReadScope::new(artifact(5), artifact(6))],
                UnixSeconds::new(100),
                UnixSeconds::new(200),
                1024,
            )
            .expect("capability"),
            report_id: report_id(),
            report_artifact_id: artifact(7),
            completion_event_id: event_id(8),
            report_event_id: event_id(9),
        }
    }

    fn tenant() -> TenantId {
        TenantId::parse("tenant-calibration").expect("tenant")
    }

    fn site() -> SiteId {
        SiteId::parse("site-calibration").expect("site")
    }

    fn capability_id() -> CalibrationReadCapabilityId {
        CalibrationReadCapabilityId::parse("calcap_018f2a3b-4c5d-7000-8000-000000000001")
            .expect("capability id")
    }

    fn lineage_review_id() -> CalibrationLineageReviewId {
        CalibrationLineageReviewId::parse("calrev_018f2a3b-4c5d-7000-8000-000000000001")
            .expect("lineage review id")
    }

    fn lease_id() -> xshield_core::domain::CalibrationReadLeaseId {
        xshield_core::domain::CalibrationReadLeaseId::parse(
            "callease_018f2a3b-4c5d-7000-8000-000000000002",
        )
        .expect("lease id")
    }

    fn report_id() -> CalibrationReportId {
        CalibrationReportId::parse("calr_018f2a3b-4c5d-7000-8000-000000000007").expect("report id")
    }

    fn artifact(index: u8) -> ArtifactId {
        ArtifactId::parse(format!("artifact_018f2a3b-4c5d-7000-8000-{index:012x}"))
            .expect("artifact id")
    }

    fn event_id(index: u8) -> EventId {
        EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{index:012x}")).expect("event id")
    }

    fn model_call(index: u8) -> ModelCallId {
        ModelCallId::parse(format!("mdl_018f2a3b-4c5d-7000-8000-{index:012x}")).expect("model call")
    }

    fn schema_v3_model_call_record() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema_version": 3,
            "model_call_id": model_call(1).as_str(),
            "request_id": "req_018f2a3b-4c5d-7000-8000-000000000001",
            "example_only": false,
            "provider": "provider-r1",
            "provider_model_id": "provider/model",
            "model_revision": "model-r1",
            "resolved_model_revision": null,
            "prompt_revision": "prompt-r1",
            "input_artifact_id": artifact(10).as_str(),
            "output_artifact_id": artifact(11).as_str(),
            "question_type": "choice",
            "result": "RISK",
            "probabilities": {"NONE": 0.1, "RISK": 0.9},
            "legend": null,
            "risk_projection": {
                "mapping_revision": "mapping-r1",
                "malicious_probability": 0.9,
                "benign_probability": 0.1,
                "unknown_probability": 0.0,
                "abstained": false,
                "reason_code": "MODEL_RISK_PROJECTED"
            },
            "provider_confidence": null,
            "confidence_status": "not_provided",
            "probability_semantics": "provider_reported_uncalibrated",
            "usage": {"input_tokens": null, "output_tokens": null, "source": "unavailable"},
            "duration_ms": 10,
            "status": "success",
            "reason_code": "MODEL_EVALUATION_COMPLETED",
            "http_status": 200,
            "capture_status": "complete",
            "retry_after_seconds": null,
            "provider_request_id": null,
            "schema_validation": "valid",
            "provider_internal": "unavailable"
        }))
        .expect("v3 fixture serializes")
    }

    fn schema_v3_reviewed_label(provenance: &EvaluationProvenance) -> Vec<u8> {
        let model = provenance.model();
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "kind": "calibration_reviewed_label",
            "model_call_id": model_call(1).as_str(),
            "ground_truth": "malicious",
            "provenance": {
                "approval_ref": provenance.approval_ref().as_str(),
                "dataset_revision": provenance.dataset_revision().as_str(),
                "label_revision": provenance.label_revision().as_str(),
                "task_revision": provenance.task_revision().as_str(),
                "threshold_policy_revision": provenance.threshold_policy_revision().as_str(),
                "mapping_revision": provenance.mapping_revision().as_str(),
                "evaluation_manifest_artifact_id": provenance.evaluation_manifest_artifact_id().as_str(),
                "training_manifest_artifact_id": provenance.training_manifest_artifact_id().as_str(),
                "calibration_manifest_artifact_id": provenance.calibration_manifest_artifact_id().as_str(),
                "label_manifest_artifact_id": provenance.label_manifest_artifact_id().as_str(),
                "model": {
                    "provider": model.provider().as_str(),
                    "provider_model_id": model.provider_model_id(),
                    "model_revision": model.model_revision().as_str(),
                    "prompt_revision": model.prompt_revision().as_str(),
                    "resolved_model_revision": model.resolved_model_revision().map(ModelRevision::as_str),
                }
            }
        }))
        .expect("reviewed label fixture serializes")
    }

    fn scoped<T>(value: &str) -> T
    where
        T: FromScopedName,
    {
        T::parse_scoped(value)
    }

    trait FromScopedName: Sized {
        fn parse_scoped(value: &str) -> Self;
    }

    macro_rules! scoped_name {
        ($($name:ty),+ $(,)?) => {
            $(
                impl FromScopedName for $name {
                    fn parse_scoped(value: &str) -> Self {
                        Self::parse(value).expect("scoped name")
                    }
                }
            )+
        };
    }

    scoped_name!(
        xshield_core::domain::ApprovalRef,
        DatasetRevision,
        LabelRevision,
        TaskRevision,
        ThresholdPolicyRevision,
        MappingRevision,
        ProviderId,
        ModelRevision,
        PromptRevision,
    );
}
