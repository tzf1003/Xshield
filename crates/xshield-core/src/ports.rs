//! Side-effect boundaries used by the request application service.

use crate::{
    access::{
        AccessDenied, ServiceCredentialFingerprint, ServiceIdentity, ShareGrant,
        ShareTokenFingerprint,
    },
    audit::AuditEvent,
    calibration::read_capability::{
        CalibrationEvidenceReadCapability, CalibrationEvidenceReadSession, CalibrationEvidenceRef,
    },
    domain::{
        ActionRef, EventId, OperationId, PolicyRevision, ResourceType, SiteId, StageExecutionId,
        TenantId, ViewProfile, WafSessionId,
    },
    grant::{GrantDenied, GrantLedger, ResourceKeyHmac},
    identity::{
        AuthBinding, AuthSnapshot, CredentialFingerprint, CredentialSlot, IdentityDenied,
        UnixSeconds,
    },
    model_evaluation_admission::{
        ModelEvaluationAdmissionAttempt, ModelEvaluationAdmissionReleaseState,
        ModelEvaluationAdmissionState,
    },
    provenance::{ActionGrant, ProvenanceError},
};
use std::{cell::RefCell, collections::BTreeMap, fmt, future::Future};

/// Authoritative cross-instance capacity boundary for model provider calls.
///
/// Implementations reserve capacity only. They must not grant a business
/// operation, issue a UI action, open evidence, approve disclosure, or publish
/// a policy. A worker acquires before evidence output, confirms immediately
/// before network send, and closes only after its terminal audit barrier.
pub trait ModelEvaluationAdmissionPort {
    /// Opaque, non-serializable adapter lease type.
    type Lease;
    /// Adapter dependency or persistence error.
    type Error;

    /// Acquires one tenant/site scoped capacity lease.
    fn acquire_model_evaluation_admission<'a>(
        &'a self,
        attempt: &'a ModelEvaluationAdmissionAttempt,
    ) -> impl Future<Output = Result<ModelEvaluationAdmissionState<Self::Lease>, Self::Error>> + Send + 'a;

    /// Rechecks an already acquired lease immediately before provider send.
    fn confirm_model_evaluation_admission<'a>(
        &'a self,
        lease: &'a Self::Lease,
    ) -> impl Future<Output = Result<ModelEvaluationAdmissionState<()>, Self::Error>> + Send + 'a;

    /// Closes one private lease after the caller's durable terminal boundary.
    fn release_model_evaluation_admission<'a>(
        &'a self,
        lease: &'a Self::Lease,
    ) -> impl Future<Output = Result<ModelEvaluationAdmissionReleaseState, Self::Error>> + Send + 'a;
}

/// A validated request to read exactly one artifact in a calibration batch.
///
/// This request can only be constructed from a
/// [`CalibrationEvidenceReadSession`], its exact
/// [`CalibrationEvidenceReadCapability`], and one of its exact exported
/// [`CalibrationEvidenceRef`] values. It deliberately has no console
/// `EvidenceAccessRequestId`, `ApprovalRef`, case, or management role: the
/// control-plane single-artifact download flow cannot authorize an offline
/// calibration batch.
///
/// Construction only rejects local session, scope, lease, or reference shape;
/// it performs no storage, evidence, issuance, audit, or authorization side
/// effects. The session must have been bound after an authoritative adapter
/// began the batch, and callers supply `now` from a trusted server clock.
pub struct CalibrationEvidenceReadRequest<'a> {
    session: &'a CalibrationEvidenceReadSession<'a>,
    capability: &'a CalibrationEvidenceReadCapability,
    evidence_ref: &'a CalibrationEvidenceRef,
    tenant_id: TenantId,
    site_id: SiteId,
    now: UnixSeconds,
}

impl<'a> CalibrationEvidenceReadRequest<'a> {
    /// Validates the local, non-expandable batch scope for one future read.
    ///
    /// A reference or session from another capability is rejected even when its
    /// artifact, role, and sample position are otherwise identical. To avoid
    /// turning this boundary into an evidence-enumeration oracle, every local
    /// mismatch maps to [`CalibrationEvidenceReadDenied::EvidenceNotAuthorized`].
    ///
    /// # Errors
    /// Returns [`CalibrationEvidenceReadDenied::EvidenceNotAuthorized`] when
    /// the session, tenant/site, lease, capability identity, or exact
    /// role/reference membership does not match. No reader is called on this
    /// path.
    pub fn new(
        session: &'a CalibrationEvidenceReadSession<'a>,
        capability: &'a CalibrationEvidenceReadCapability,
        evidence_ref: &'a CalibrationEvidenceRef,
        tenant_id: &'a TenantId,
        site_id: &'a SiteId,
        now: UnixSeconds,
    ) -> Result<Self, CalibrationEvidenceReadDenied> {
        if !session.authorizes_request(capability, evidence_ref, tenant_id, site_id, now) {
            return Err(CalibrationEvidenceReadDenied::EvidenceNotAuthorized);
        }
        Ok(Self {
            session,
            capability,
            evidence_ref,
            tenant_id: tenant_id.clone(),
            site_id: site_id.clone(),
            now,
        })
    }

    /// Returns the independently issued batch capability to revalidate.
    #[must_use]
    pub const fn capability(&self) -> &CalibrationEvidenceReadCapability {
        self.capability
    }

    /// Returns the non-duplicable batch session selected for this read.
    #[must_use]
    pub const fn session(&self) -> &CalibrationEvidenceReadSession<'a> {
        self.session
    }

    /// Returns the exact frozen artifact and semantic role to read.
    #[must_use]
    pub const fn evidence_ref(&self) -> &CalibrationEvidenceRef {
        self.evidence_ref
    }

    /// Returns the trusted tenant scope for this attempt.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the trusted site scope for this attempt.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the trusted server time at which the attempt was admitted.
    #[must_use]
    pub const fn now(&self) -> UnixSeconds {
        self.now
    }
}

/// A closed authorization denial for calibration evidence reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationEvidenceReadDenied {
    /// The exact batch capability cannot authorize this artifact read.
    EvidenceNotAuthorized,
}

impl CalibrationEvidenceReadDenied {
    /// Returns the stable, payload-free reason code for the caller-owned audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::EvidenceNotAuthorized => "CALIBRATION_EVIDENCE_NOT_AUTHORIZED",
        }
    }
}

impl fmt::Display for CalibrationEvidenceReadDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for CalibrationEvidenceReadDenied {}

/// The explicit result of one calibration evidence read attempt.
#[derive(Debug)]
pub enum CalibrationEvidenceReadState<Content> {
    /// Content authenticated as the requested artifact by the implementing adapter.
    Read(Content),
    /// The batch capability does not authorize the requested read.
    Denied(CalibrationEvidenceReadDenied),
}

/// Reads one exact calibration artifact through a purpose-specific batch capability.
///
/// This port is separate from the console's `EvidenceReadPort`: a console
/// approval, `ApprovalRef`, or management role cannot be adapted into this
/// request or authorize a batch read. Each request also requires an exact,
/// non-duplicable batch session bound after an authoritative `begin_batch`.
/// The port does not issue a capability, persist a report, publish a threshold
/// or policy, or itself produce a durable audit.
///
/// Before returning [`CalibrationEvidenceReadState::Read`], an adapter MUST
/// independently revalidate the capability issuance, current tenant/site
/// scope, and active batch lease; verify active catalog entries and the
/// aggregate catalog-byte budget; authenticate each typed manifest and
/// requested role; and verify the persisted object digest and AEAD before
/// exposing content. The adapter MUST treat any failed recheck as a
/// non-content result and durably record its reader-owned terminal audit
/// before returning plaintext. A separate evaluator-owned completion command
/// may consume the batch only after it constructs the exact complete report;
/// an individual artifact read never consumes the lease.
pub trait CalibrationEvidenceReadPort {
    /// Adapter-specific content representation. Implementations should retain
    /// secret-buffer ownership and zeroization until the evaluator consumes it.
    type Content;
    /// Adapter-specific dependency, integrity, or cancellation failure.
    type Error;

    /// Reads the one artifact selected by a prevalidated exact batch request.
    ///
    /// # Errors
    /// Returns `Error` only for dependency, integrity, deadline, cancellation,
    /// or other adapter failures. An authorization denial is returned as
    /// [`CalibrationEvidenceReadState::Denied`] with its stable reason code.
    fn read_calibration_evidence<'a>(
        &'a self,
        request: CalibrationEvidenceReadRequest<'a>,
    ) -> impl Future<Output = Result<CalibrationEvidenceReadState<Self::Content>, Self::Error>> + Send + 'a;
}

/// Scoped request for an authoritative identity and exact credential combination.
pub struct IdentityProofQuery<'a> {
    /// Tenant fixed by the trusted listener configuration.
    pub tenant_id: &'a TenantId,
    /// Site fixed by the trusted listener configuration.
    pub site_id: &'a SiteId,
    /// Opaque WAF session identifier presented by the client.
    pub session_id: &'a WafSessionId,
    /// Tenant-isolated HMAC of the presented WAF session value.
    pub session_fingerprint: &'a [u8; 32],
    /// Complete credential set selected by the site authentication profile.
    pub credentials: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
    /// Trusted server time frozen for this request.
    pub now: UnixSeconds,
}

/// Authoritative result of loading and verifying one request identity.
#[derive(Debug)]
pub enum IdentityProofState {
    /// Binding and immutable request snapshot passed exact verification.
    Verified {
        /// Current binding used for later epoch checks.
        binding: Box<AuthBinding>,
        /// Immutable identity captured for the request.
        snapshot: AuthSnapshot,
    },
    /// Missing, stale, expired, revoked, or mismatched identity state.
    Denied(IdentityDenied),
}

/// Reads identity state only from an authoritative scoped store.
pub trait IdentityProofStore {
    /// Adapter-specific lookup failure.
    type Error;

    /// Loads and verifies the complete session and business credential combination.
    ///
    /// # Errors
    /// Returns the adapter error when authoritative state cannot be read safely.
    fn load_identity<'a>(
        &'a self,
        query: IdentityProofQuery<'a>,
    ) -> impl Future<Output = Result<IdentityProofState, Self::Error>> + Send + 'a;
}

/// Scoped request for one authoritative UI action grant.
pub struct UiActionProofQuery<'a> {
    /// Current binding loaded for this same request.
    pub binding: &'a AuthBinding,
    /// Immutable current identity snapshot.
    pub snapshot: &'a AuthSnapshot,
    /// Opaque server-issued action reference presented by the client.
    pub action_ref: &'a ActionRef,
    /// Policy revision fixed by trusted gateway configuration.
    pub policy_revision: &'a PolicyRevision,
    /// Trusted server time frozen for this request.
    pub now: UnixSeconds,
}

/// Authoritative result of loading one exact UI action grant.
#[derive(Debug)]
pub enum UiActionProofState {
    /// Persisted state revalidated through the domain issuance rules.
    Verified(Box<ActionGrant>),
    /// Missing, stale, revoked, mismatched, or ineligible action state.
    Denied(ProvenanceError),
}

/// Reads UI action state only from an authoritative scoped store.
pub trait UiActionProofStore {
    /// Adapter-specific lookup failure.
    type Error;

    /// Loads an exact action reference and revalidates its complete provenance chain.
    ///
    /// # Errors
    /// Returns the adapter error when authoritative state cannot be read safely.
    fn load_ui_action<'a>(
        &'a self,
        query: UiActionProofQuery<'a>,
    ) -> impl Future<Output = Result<UiActionProofState, Self::Error>> + Send + 'a;
}

/// Scoped request for one exact persisted resource qualification.
pub struct ResourceProofQuery<'a> {
    /// Current binding loaded for this same request.
    pub binding: &'a AuthBinding,
    /// Immutable current identity snapshot.
    pub snapshot: &'a AuthSnapshot,
    /// UI action that introduced this resource operation.
    pub action_ref: &'a ActionRef,
    /// Canonical resource type fixed by trusted operation configuration.
    pub resource_type: &'a ResourceType,
    /// Tenant-isolated HMAC derived from the actual request resource value.
    pub resource_key: &'a ResourceKeyHmac,
    /// Exact operation fixed by trusted route matching.
    pub operation_id: &'a OperationId,
    /// Exact view fixed by trusted operation configuration.
    pub view_profile: &'a ViewProfile,
    /// Policy revision fixed by trusted gateway configuration.
    pub policy_revision: &'a PolicyRevision,
    /// Trusted server time frozen for this request.
    pub now: UnixSeconds,
}

/// Authoritative result of loading one exact resource qualification.
#[derive(Debug)]
pub enum ResourceProofState {
    /// Persisted state revalidated through the domain grant rules.
    Verified(Box<GrantLedger>),
    /// No current exact qualification exists.
    Denied(GrantDenied),
}

/// Reads resource qualification state only from an authoritative scoped store.
pub trait ResourceProofStore {
    /// Adapter-specific lookup failure.
    type Error;

    /// Loads an exact resource, operation, view, action, and identity-epoch grant.
    ///
    /// # Errors
    /// Returns the adapter error when authoritative state cannot be read safely.
    fn load_resource_grant<'a>(
        &'a self,
        query: ResourceProofQuery<'a>,
    ) -> impl Future<Output = Result<ResourceProofState, Self::Error>> + Send + 'a;
}

/// Scoped request for one authoritative service identity.
pub struct ServiceIdentityProofQuery<'a> {
    /// Tenant fixed by the trusted listener configuration.
    pub tenant_id: &'a TenantId,
    /// Site fixed by the trusted listener configuration.
    pub site_id: &'a SiteId,
    /// Tenant- and site-isolated digest of the presented edge credential.
    pub credential_fingerprint: &'a ServiceCredentialFingerprint,
    /// Trusted server time frozen for this request.
    pub now: UnixSeconds,
}

/// Authoritative service-identity lookup result.
#[derive(Debug)]
pub enum ServiceIdentityProofState {
    /// Active identity with its complete finite operation set.
    Verified(Box<ServiceIdentity>),
    /// No active identity matches the exact scoped credential.
    Denied(AccessDenied),
}

/// Reads service identities only from an authoritative scoped store.
pub trait ServiceIdentityProofStore {
    /// Adapter-specific lookup failure.
    type Error;

    /// Loads an active service identity for the exact tenant, site, and credential.
    ///
    /// # Errors
    /// Returns the adapter error when authoritative state cannot be read safely.
    fn load_service_identity<'a>(
        &'a self,
        query: ServiceIdentityProofQuery<'a>,
    ) -> impl Future<Output = Result<ServiceIdentityProofState, Self::Error>> + Send + 'a;
}

/// Scoped request for one exact persisted limited-share grant.
pub struct ShareGrantProofQuery<'a> {
    /// Tenant fixed by the trusted listener configuration.
    pub tenant_id: &'a TenantId,
    /// Site fixed by the trusted listener configuration.
    pub site_id: &'a SiteId,
    /// Tenant- and site-isolated digest of the presented share token.
    pub token_fingerprint: &'a ShareTokenFingerprint,
    /// Resource type fixed by the trusted operation configuration.
    pub resource_type: &'a ResourceType,
    /// Resource digest derived from the actual request target.
    pub resource_key: &'a ResourceKeyHmac,
    /// Exact operation fixed by route selection.
    pub operation_id: &'a OperationId,
    /// Exact response view fixed by policy.
    pub view_profile: &'a ViewProfile,
    /// Trusted server time frozen for this request.
    pub now: UnixSeconds,
}

/// Authoritative limited-share lookup result.
#[derive(Debug)]
pub enum ShareGrantProofState {
    /// Active reusable read grant matching every requested scope dimension.
    Verified(Box<ShareGrant>),
    /// No active exact limited-share grant exists.
    Denied(AccessDenied),
}

/// Reads limited-share grants only from an authoritative scoped store.
pub trait ShareGrantProofStore {
    /// Adapter-specific lookup failure.
    type Error;

    /// Loads a reusable read grant for the exact token and resource scope.
    ///
    /// # Errors
    /// Returns the adapter error when authoritative state cannot be read safely.
    fn load_share_grant<'a>(
        &'a self,
        query: ShareGrantProofQuery<'a>,
    ) -> impl Future<Output = Result<ShareGrantProofState, Self::Error>> + Send + 'a;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Runtime activation state implemented by M0.
pub enum SiteActivation {
    /// Traffic must stop before protected-origin dispatch.
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Minimal trusted site policy needed by M0 orchestration.
pub struct SiteProfile {
    /// Server-selected activation state.
    pub activation: SiteActivation,
}

/// Reads a tenant-scoped site profile. Implementations must not fall back to a
/// profile from another scope.
pub trait SiteConfigStore {
    /// Adapter-specific lookup failure.
    type Error;

    /// # Errors
    /// Returns the adapter's typed failure when the scoped lookup is unavailable.
    fn find(&self, tenant: &TenantId, site: &SiteId) -> Result<Option<SiteProfile>, Self::Error>;
}

/// Commits required audit facts in request order.
pub trait AuditSink {
    /// Adapter-specific durability failure.
    type Error;

    /// # Errors
    /// Returns the adapter's typed failure when the event is not accepted durably.
    fn append(&self, event: AuditEvent) -> Result<(), Self::Error>;
}

/// Supplies opaque identifiers. Production implementations must generate
/// `UUIDv7` values; deterministic mocks are used by M0 tests and examples.
pub trait IdGenerator {
    /// Generates an immutable audit event ID.
    fn event_id(&self) -> EventId;
    /// Generates an ID for one stage attempt.
    fn stage_execution_id(&self) -> StageExecutionId;
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Failure injected by an M0 mock port.
pub struct MockError;

impl fmt::Display for MockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mock port failure")
    }
}

impl std::error::Error for MockError {}

/// In-memory M0 audit adapter. It can inject a durability failure before an
/// event is accepted.
#[derive(Debug, Default)]
pub struct MockAuditSink {
    events: RefCell<Vec<AuditEvent>>,
    fail_at: Option<usize>,
}

impl MockAuditSink {
    #[must_use]
    /// Creates an empty, successful in-memory sink.
    pub const fn new() -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            fail_at: None,
        }
    }

    #[must_use]
    /// Creates a sink that rejects the zero-based event index.
    pub const fn failing_at(event_index: usize) -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            fail_at: Some(event_index),
        }
    }

    #[must_use]
    /// Returns a snapshot of accepted events in request order.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.borrow().clone()
    }
}

impl AuditSink for MockAuditSink {
    type Error = MockError;

    fn append(&self, event: AuditEvent) -> Result<(), Self::Error> {
        if self.fail_at == Some(self.events.borrow().len()) {
            return Err(MockError);
        }
        self.events.borrow_mut().push(event);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
/// M0 configuration adapter that always returns a disabled scoped site.
pub struct DisabledSiteStore;

impl SiteConfigStore for DisabledSiteStore {
    type Error = MockError;

    fn find(&self, _tenant: &TenantId, _site: &SiteId) -> Result<Option<SiteProfile>, Self::Error> {
        Ok(Some(SiteProfile {
            activation: SiteActivation::Disabled,
        }))
    }
}

#[derive(Clone, Copy, Debug, Default)]
/// M0 configuration adapter that injects a lookup failure.
pub struct FailingSiteStore;

impl SiteConfigStore for FailingSiteStore {
    type Error = MockError;

    fn find(&self, _tenant: &TenantId, _site: &SiteId) -> Result<Option<SiteProfile>, Self::Error> {
        Err(MockError)
    }
}

#[derive(Debug, Default)]
/// Deterministic ID source for tests and synthetic examples only.
pub struct MockIds {
    next: RefCell<u64>,
}

impl MockIds {
    fn next(&self, prefix: &str) -> String {
        let value = *self.next.borrow();
        *self.next.borrow_mut() = value + 1;
        format!("{prefix}018f2a3b-4c5d-7000-8000-{value:012x}")
    }
}

impl IdGenerator for MockIds {
    fn event_id(&self) -> EventId {
        EventId::parse(self.next("ev_")).expect("mock generates a valid UUIDv7")
    }

    fn stage_execution_id(&self) -> StageExecutionId {
        StageExecutionId::parse(self.next("stg_")).expect("mock generates a valid UUIDv7")
    }
}
