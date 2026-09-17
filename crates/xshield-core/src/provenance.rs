//! Verified page evidence and exact UI action grants.

use crate::{
    audit::ReasonCode,
    domain::{
        ActionId, ActionRef, FieldName, MappingRevision, OperationId, PageEvidenceId, PageTemplate,
        PolicyRevision, RequestId, ResourceType, ResponseEvidenceId, ViewProfile,
    },
    grant::ResourceKeyHmac,
    identity::{AuthBinding, AuthSnapshot, IdentityDenied, UnixSeconds},
};
use std::{collections::BTreeSet, fmt};

/// HTTP method frozen by an approved action mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    /// GET request.
    Get,
    /// POST request.
    Post,
    /// PUT request.
    Put,
    /// PATCH request.
    Patch,
    /// DELETE request.
    Delete,
}

impl HttpMethod {
    /// Returns the canonical wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// Validated route template owned by the policy compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteTemplate(String);

impl RouteTemplate {
    /// Validates a bounded absolute-path template without query or fragment text.
    ///
    /// # Errors
    /// Returns [`ProvenanceError::ActionUnavailable`] for an invalid template.
    pub fn parse(value: impl Into<String>) -> Result<Self, ProvenanceError> {
        let value = value.into();
        if value.starts_with('/')
            && value.len() <= 512
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#'))
        {
            Ok(Self(value))
        } else {
            Err(ProvenanceError::ActionUnavailable)
        }
    }

    /// Returns the validated policy value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Server-verifiable page build fingerprint.
#[derive(Clone, Eq, PartialEq)]
pub struct BuildFingerprint([u8; 32]);

impl BuildFingerprint {
    /// Parses a canonical lowercase SHA-256 fingerprint.
    ///
    /// # Errors
    /// Returns [`ProvenanceError::EvidenceUnverified`] for malformed input.
    pub fn parse(value: &str) -> Result<Self, ProvenanceError> {
        crate::domain::parse_lower_hex_32(value)
            .map(Self)
            .ok_or(ProvenanceError::EvidenceUnverified)
    }

    /// Borrows the fingerprint for persistence.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BuildFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BuildFingerprint([REDACTED])")
    }
}

/// Lifecycle state of verified page evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStatus {
    /// Origin, content, build, and mapping checks passed.
    Verified,
    /// Evidence was revoked and cannot issue new actions.
    Revoked,
}

/// Immutable proof that an approved page was returned in one identity context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageEvidence {
    evidence_id: PageEvidenceId,
    snapshot: AuthSnapshot,
    source_request_id: RequestId,
    page_template: PageTemplate,
    build_fingerprint: BuildFingerprint,
    policy_revision: PolicyRevision,
    mapping_revision: MappingRevision,
    verified_at: UnixSeconds,
    expires_at: UnixSeconds,
    status: EvidenceStatus,
}

/// Immutable proof that one approved source response was fully verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseEvidence {
    evidence_id: ResponseEvidenceId,
    snapshot: AuthSnapshot,
    source_request_id: RequestId,
    source_operation_id: OperationId,
    target_operation_id: OperationId,
    response_status: u16,
    policy_revision: PolicyRevision,
    verified_at: UnixSeconds,
    expires_at: UnixSeconds,
    status: EvidenceStatus,
}

impl ResponseEvidence {
    /// Creates response evidence after complete origin, status, and shape validation.
    ///
    /// # Errors
    /// Returns [`ProvenanceError::EvidenceUnverified`] for stale identity or a
    /// lease outside the active authentication session.
    #[allow(clippy::too_many_arguments)]
    pub fn verified(
        evidence_id: ResponseEvidenceId,
        binding: &AuthBinding,
        snapshot: AuthSnapshot,
        source_request_id: RequestId,
        source_operation_id: OperationId,
        target_operation_id: OperationId,
        response_status: u16,
        policy_revision: PolicyRevision,
        expires_at: UnixSeconds,
        now: UnixSeconds,
    ) -> Result<Self, ProvenanceError> {
        binding.validate_epoch(&snapshot, now)?;
        if expires_at <= now
            || expires_at > binding.absolute_expires_at()
            || !(200..=299).contains(&response_status)
            || response_status == 204
        {
            return Err(ProvenanceError::EvidenceUnverified);
        }
        Ok(Self {
            evidence_id,
            snapshot,
            source_request_id,
            source_operation_id,
            target_operation_id,
            response_status,
            policy_revision,
            verified_at: now,
            expires_at,
            status: EvidenceStatus::Verified,
        })
    }

    /// Revokes future action issuance while retaining the response fact.
    pub fn revoke(&mut self) {
        self.status = EvidenceStatus::Revoked;
    }

    /// Returns the response evidence identifier.
    #[must_use]
    pub const fn evidence_id(&self) -> &ResponseEvidenceId {
        &self.evidence_id
    }

    /// Returns the frozen identity snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthSnapshot {
        &self.snapshot
    }

    /// Returns the request whose response produced this evidence.
    #[must_use]
    pub const fn source_request_id(&self) -> &RequestId {
        &self.source_request_id
    }

    /// Returns the approved source operation.
    #[must_use]
    pub const fn source_operation_id(&self) -> &OperationId {
        &self.source_operation_id
    }

    /// Returns the exact operation the response may qualify.
    #[must_use]
    pub const fn target_operation_id(&self) -> &OperationId {
        &self.target_operation_id
    }

    /// Returns the configured business-success status observed on the response.
    #[must_use]
    pub const fn response_status(&self) -> u16 {
        self.response_status
    }

    /// Returns the frozen policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> &PolicyRevision {
        &self.policy_revision
    }

    /// Returns the response verification time.
    #[must_use]
    pub const fn verified_at(&self) -> UnixSeconds {
        self.verified_at
    }

    /// Returns the evidence expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    fn validate(&self, snapshot: &AuthSnapshot, now: UnixSeconds) -> Result<(), ProvenanceError> {
        if self.status != EvidenceStatus::Verified || now >= self.expires_at {
            return Err(ProvenanceError::EvidenceUnverified);
        }
        if self.snapshot.tenant_id() != snapshot.tenant_id()
            || self.snapshot.site_id() != snapshot.site_id()
            || self.snapshot.binding_id() != snapshot.binding_id()
            || self.snapshot.epoch() != snapshot.epoch()
            || self.snapshot.principal_ref() != snapshot.principal_ref()
        {
            return Err(ProvenanceError::EvidenceUnverified);
        }
        Ok(())
    }
}

impl PageEvidence {
    /// Creates evidence after the application verified origin response and build mapping.
    ///
    /// # Errors
    /// Returns [`ProvenanceError::EvidenceUnverified`] for stale identity or a
    /// lease outside the active authentication session.
    #[allow(clippy::too_many_arguments)]
    pub fn verified(
        evidence_id: PageEvidenceId,
        binding: &AuthBinding,
        snapshot: AuthSnapshot,
        source_request_id: RequestId,
        page_template: PageTemplate,
        build_fingerprint: BuildFingerprint,
        policy_revision: PolicyRevision,
        mapping_revision: MappingRevision,
        expires_at: UnixSeconds,
        now: UnixSeconds,
    ) -> Result<Self, ProvenanceError> {
        binding.validate_epoch(&snapshot, now)?;
        if expires_at <= now || expires_at > binding.absolute_expires_at() {
            return Err(ProvenanceError::EvidenceUnverified);
        }
        Ok(Self {
            evidence_id,
            snapshot,
            source_request_id,
            page_template,
            build_fingerprint,
            policy_revision,
            mapping_revision,
            verified_at: now,
            expires_at,
            status: EvidenceStatus::Verified,
        })
    }

    /// Revokes future action issuance while retaining the evidence record.
    pub fn revoke(&mut self) {
        self.status = EvidenceStatus::Revoked;
    }

    /// Returns the evidence ID.
    #[must_use]
    pub const fn evidence_id(&self) -> &PageEvidenceId {
        &self.evidence_id
    }

    /// Returns the identity snapshot frozen at verification.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthSnapshot {
        &self.snapshot
    }

    /// Returns the request whose verified response produced this evidence.
    #[must_use]
    pub const fn source_request_id(&self) -> &RequestId {
        &self.source_request_id
    }

    /// Returns the approved page template.
    #[must_use]
    pub const fn page_template(&self) -> &PageTemplate {
        &self.page_template
    }

    /// Returns the verified build fingerprint.
    #[must_use]
    pub const fn build_fingerprint(&self) -> &BuildFingerprint {
        &self.build_fingerprint
    }

    /// Returns the frozen policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> &PolicyRevision {
        &self.policy_revision
    }

    /// Returns the frozen action mapping revision.
    #[must_use]
    pub const fn mapping_revision(&self) -> &MappingRevision {
        &self.mapping_revision
    }

    /// Returns the verification time.
    #[must_use]
    pub const fn verified_at(&self) -> UnixSeconds {
        self.verified_at
    }

    /// Returns the server-side evidence expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    fn validate(&self, snapshot: &AuthSnapshot, now: UnixSeconds) -> Result<(), ProvenanceError> {
        if self.status != EvidenceStatus::Verified || now >= self.expires_at {
            return Err(ProvenanceError::EvidenceUnverified);
        }
        if self.snapshot.tenant_id() != snapshot.tenant_id()
            || self.snapshot.site_id() != snapshot.site_id()
            || self.snapshot.binding_id() != snapshot.binding_id()
            || self.snapshot.epoch() != snapshot.epoch()
            || self.snapshot.principal_ref() != snapshot.principal_ref()
        {
            return Err(ProvenanceError::EvidenceUnverified);
        }
        Ok(())
    }
}

/// Target family an approved action may address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionTargetRule {
    /// The action carries no business-resource target.
    None,
    /// The action target must equal the verified principal.
    VerifiedPrincipal,
    /// The action targets one exact resource of this type.
    Resource(ResourceType),
}

/// Exact target captured when issuing an action grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionTarget {
    /// No target.
    None,
    /// A business principal reference.
    Principal(String),
    /// One tenant-isolated resource reference.
    Resource {
        /// Canonical resource type.
        resource_type: ResourceType,
        /// Tenant-isolated HMAC of the resource identifier.
        resource_key: ResourceKeyHmac,
    },
}

impl ActionTarget {
    fn matches_rule(&self, rule: &ActionTargetRule, snapshot: &AuthSnapshot) -> bool {
        match (rule, self) {
            (ActionTargetRule::None, Self::None) => true,
            (ActionTargetRule::VerifiedPrincipal, Self::Principal(principal)) => {
                !principal.is_empty()
                    && principal.len() <= 256
                    && principal.bytes().all(|byte| !byte.is_ascii_control())
                    && principal == snapshot.principal_ref()
            }
            (ActionTargetRule::Resource(expected), Self::Resource { resource_type, .. }) => {
                expected == resource_type
            }
            _ => false,
        }
    }
}

/// Approved immutable action mapping compiled from one signed policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionDescriptor {
    action_id: ActionId,
    page_template: PageTemplate,
    operation_id: OperationId,
    method: HttpMethod,
    route: RouteTemplate,
    target_rule: ActionTargetRule,
    allowed_fields: BTreeSet<FieldName>,
    field_profile: ViewProfile,
    policy_revision: PolicyRevision,
    mapping_revision: MappingRevision,
    active: bool,
}

impl ActionDescriptor {
    /// Creates an approved action mapping from a validated policy artifact.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn approved(
        action_id: ActionId,
        page_template: PageTemplate,
        operation_id: OperationId,
        method: HttpMethod,
        route: RouteTemplate,
        target_rule: ActionTargetRule,
        allowed_fields: BTreeSet<FieldName>,
        field_profile: ViewProfile,
        policy_revision: PolicyRevision,
        mapping_revision: MappingRevision,
    ) -> Self {
        Self {
            action_id,
            page_template,
            operation_id,
            method,
            route,
            target_rule,
            allowed_fields,
            field_profile,
            policy_revision,
            mapping_revision,
            active: true,
        }
    }

    /// Retires this mapping for future issuance.
    pub fn retire(&mut self) {
        self.active = false;
    }

    /// Returns the policy action ID.
    #[must_use]
    pub const fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    /// Returns the exact operation.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the exact HTTP method.
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// Returns the exact policy route template.
    #[must_use]
    pub const fn route(&self) -> &RouteTemplate {
        &self.route
    }

    /// Returns the exact response or field profile.
    #[must_use]
    pub const fn field_profile(&self) -> &ViewProfile {
        &self.field_profile
    }
}

/// Requested action grant contents after route and response extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGrantDraft {
    /// Server-generated action grant reference.
    pub action_ref: ActionRef,
    /// Exact target produced by the verified mapping.
    pub target: ActionTarget,
    /// Exact request fields exposed by the action.
    pub fields: BTreeSet<FieldName>,
    /// Lease bounded by identity and page evidence.
    pub expires_at: UnixSeconds,
}

/// Verified source record that authorized one action grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionEvidenceRef {
    /// An approved page/build mapping exposed the action.
    Page(PageEvidenceId),
    /// A fully verified source response qualified the action target.
    Response(ResponseEvidenceId),
}

/// Persistable action grant bound to one immutable identity epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGrant {
    draft: ActionGrantDraft,
    action_id: ActionId,
    snapshot: AuthSnapshot,
    source_request_id: RequestId,
    evidence_ref: ActionEvidenceRef,
    operation_id: OperationId,
    method: HttpMethod,
    route: RouteTemplate,
    field_profile: ViewProfile,
    policy_revision: PolicyRevision,
    mapping_revision: MappingRevision,
    issued_at: UnixSeconds,
    active: bool,
}

impl ActionGrant {
    /// Validates verified evidence, mapping scope, target, fields, and lease.
    ///
    /// # Errors
    /// Returns [`ProvenanceError`] for stale identity/evidence, unapproved
    /// mapping, target or field expansion, or invalid expiry.
    pub fn issue(
        binding: &AuthBinding,
        snapshot: &AuthSnapshot,
        evidence: &PageEvidence,
        descriptor: &ActionDescriptor,
        draft: ActionGrantDraft,
        now: UnixSeconds,
    ) -> Result<Self, ProvenanceError> {
        binding.validate_epoch(snapshot, now)?;
        evidence.validate(snapshot, now)?;
        if !descriptor.active
            || descriptor.page_template != evidence.page_template
            || descriptor.policy_revision != evidence.policy_revision
            || descriptor.mapping_revision != evidence.mapping_revision
        {
            return Err(ProvenanceError::ActionUnavailable);
        }
        if !draft.target.matches_rule(&descriptor.target_rule, snapshot) {
            return Err(ProvenanceError::TargetScopeMismatch);
        }
        if !draft.fields.is_subset(&descriptor.allowed_fields) {
            return Err(ProvenanceError::FieldNotAllowed);
        }
        if draft.expires_at <= now
            || draft.expires_at > evidence.expires_at
            || draft.expires_at > binding.absolute_expires_at()
        {
            return Err(ProvenanceError::ExpiryInvalid);
        }
        Ok(Self {
            draft,
            action_id: descriptor.action_id.clone(),
            snapshot: snapshot.clone(),
            source_request_id: evidence.source_request_id.clone(),
            evidence_ref: ActionEvidenceRef::Page(evidence.evidence_id.clone()),
            operation_id: descriptor.operation_id.clone(),
            method: descriptor.method,
            route: descriptor.route.clone(),
            field_profile: descriptor.field_profile.clone(),
            policy_revision: descriptor.policy_revision.clone(),
            mapping_revision: descriptor.mapping_revision.clone(),
            issued_at: now,
            active: true,
        })
    }

    /// Issues one action from a completely verified source response.
    ///
    /// # Errors
    /// Returns [`ProvenanceError`] for stale response evidence, descriptor,
    /// target or field expansion, or a lease outside the response/session.
    pub fn issue_from_response(
        binding: &AuthBinding,
        snapshot: &AuthSnapshot,
        evidence: &ResponseEvidence,
        descriptor: &ActionDescriptor,
        draft: ActionGrantDraft,
        now: UnixSeconds,
    ) -> Result<Self, ProvenanceError> {
        binding.validate_epoch(snapshot, now)?;
        evidence.validate(snapshot, now)?;
        if !descriptor.active
            || descriptor.policy_revision != evidence.policy_revision
            || descriptor.operation_id != evidence.target_operation_id
        {
            return Err(ProvenanceError::ActionUnavailable);
        }
        if !draft.target.matches_rule(&descriptor.target_rule, snapshot) {
            return Err(ProvenanceError::TargetScopeMismatch);
        }
        if !draft.fields.is_subset(&descriptor.allowed_fields) {
            return Err(ProvenanceError::FieldNotAllowed);
        }
        if draft.expires_at <= now
            || draft.expires_at > evidence.expires_at
            || draft.expires_at > binding.absolute_expires_at()
        {
            return Err(ProvenanceError::ExpiryInvalid);
        }
        Ok(Self {
            draft,
            action_id: descriptor.action_id.clone(),
            snapshot: snapshot.clone(),
            source_request_id: evidence.source_request_id.clone(),
            evidence_ref: ActionEvidenceRef::Response(evidence.evidence_id.clone()),
            operation_id: descriptor.operation_id.clone(),
            method: descriptor.method,
            route: descriptor.route.clone(),
            field_profile: descriptor.field_profile.clone(),
            policy_revision: descriptor.policy_revision.clone(),
            mapping_revision: descriptor.mapping_revision.clone(),
            issued_at: now,
            active: true,
        })
    }

    /// Revokes future use while retaining the grant for audit.
    pub fn revoke(&mut self) {
        self.active = false;
    }

    /// Checks one exact downstream request against this action grant.
    ///
    /// # Errors
    /// Returns [`ProvenanceError`] for stale identity, inactive/expired grant,
    /// or any operation, target, field, method, or route expansion.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        binding: &AuthBinding,
        snapshot: &AuthSnapshot,
        operation_id: &OperationId,
        method: HttpMethod,
        route: &RouteTemplate,
        target: &ActionTarget,
        fields: &BTreeSet<FieldName>,
        now: UnixSeconds,
    ) -> Result<(), ProvenanceError> {
        binding.validate_epoch(snapshot, now)?;
        if !self.active
            || now >= self.draft.expires_at
            || self.snapshot.tenant_id() != snapshot.tenant_id()
            || self.snapshot.site_id() != snapshot.site_id()
            || self.snapshot.binding_id() != snapshot.binding_id()
            || self.snapshot.epoch() != snapshot.epoch()
            || &self.operation_id != operation_id
            || self.method != method
            || &self.route != route
        {
            return Err(ProvenanceError::ActionUnavailable);
        }
        if &self.draft.target != target {
            return Err(ProvenanceError::TargetScopeMismatch);
        }
        if !fields.is_subset(&self.draft.fields) {
            return Err(ProvenanceError::FieldNotAllowed);
        }
        Ok(())
    }

    /// Returns the action grant reference.
    #[must_use]
    pub const fn action_ref(&self) -> &ActionRef {
        &self.draft.action_ref
    }

    /// Returns the approved descriptor ID.
    #[must_use]
    pub const fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    /// Returns the identity snapshot frozen at issuance.
    #[must_use]
    pub const fn snapshot(&self) -> &AuthSnapshot {
        &self.snapshot
    }

    /// Returns the source request ID.
    #[must_use]
    pub const fn source_request_id(&self) -> &RequestId {
        &self.source_request_id
    }

    /// Returns the verified evidence record that produced this action.
    #[must_use]
    pub const fn evidence_ref(&self) -> &ActionEvidenceRef {
        &self.evidence_ref
    }

    /// Returns the page evidence ID for page-derived actions.
    #[must_use]
    pub const fn page_evidence_id(&self) -> Option<&PageEvidenceId> {
        match &self.evidence_ref {
            ActionEvidenceRef::Page(value) => Some(value),
            ActionEvidenceRef::Response(_) => None,
        }
    }

    /// Returns the exact operation.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the exact HTTP method.
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// Returns the exact route template.
    #[must_use]
    pub const fn route(&self) -> &RouteTemplate {
        &self.route
    }

    /// Returns the exact target.
    #[must_use]
    pub const fn target(&self) -> &ActionTarget {
        &self.draft.target
    }

    /// Returns the allowed request fields.
    #[must_use]
    pub const fn fields(&self) -> &BTreeSet<FieldName> {
        &self.draft.fields
    }

    /// Returns the field profile.
    #[must_use]
    pub const fn field_profile(&self) -> &ViewProfile {
        &self.field_profile
    }

    /// Returns the policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> &PolicyRevision {
        &self.policy_revision
    }

    /// Returns the mapping revision.
    #[must_use]
    pub const fn mapping_revision(&self) -> &MappingRevision {
        &self.mapping_revision
    }

    /// Returns the issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixSeconds {
        self.issued_at
    }

    /// Returns the expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.draft.expires_at
    }
}

/// Deterministic UI provenance rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenanceError {
    /// Page response or build mapping is not verified and current.
    EvidenceUnverified,
    /// No active exact action descriptor or grant is available.
    ActionUnavailable,
    /// Action target exceeds the approved scope.
    TargetScopeMismatch,
    /// Request fields exceed the approved field set.
    FieldNotAllowed,
    /// Action lease is empty or exceeds evidence/session bounds.
    ExpiryInvalid,
    /// The authentication context is no longer current.
    Identity(IdentityDenied),
}

impl ProvenanceError {
    /// Maps the rejection to its stable audit reason.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::EvidenceUnverified => ReasonCode::UiEvidenceUnverified,
            Self::ActionUnavailable => ReasonCode::UiActionNotAvailable,
            Self::TargetScopeMismatch => ReasonCode::TargetScopeMismatch,
            Self::FieldNotAllowed => ReasonCode::FieldNotAllowed,
            Self::ExpiryInvalid => ReasonCode::UiActionExpiryInvalid,
            Self::Identity(error) => error.reason_code(),
        }
    }
}

impl From<IdentityDenied> for ProvenanceError {
    fn from(value: IdentityDenied) -> Self {
        Self::Identity(value)
    }
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code().as_str())
    }
}

impl std::error::Error for ProvenanceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{AuthBindingId, SiteId, TenantId, WafSessionId},
        identity::{AuthEpoch, CredentialFingerprint, CredentialGeneration, CredentialSlot},
    };
    use std::collections::BTreeMap;

    const CREDENTIAL_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CREDENTIAL_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Fixture {
        binding: AuthBinding,
        snapshot: AuthSnapshot,
        evidence: PageEvidence,
        descriptor: ActionDescriptor,
    }

    fn credentials(value: &str) -> BTreeMap<CredentialSlot, CredentialFingerprint> {
        BTreeMap::from([(
            CredentialSlot::Cookie,
            CredentialFingerprint::parse(value).unwrap(),
        )])
    }

    fn fixture() -> Fixture {
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let session = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000302").unwrap();
        let binding = AuthBinding::new(
            AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000301").unwrap(),
            session.clone(),
            tenant.clone(),
            site.clone(),
            "principal_a",
            AuthEpoch::new(4),
            CredentialGeneration::new(2),
            credentials(CREDENTIAL_A),
            UnixSeconds::new(300),
        )
        .unwrap();
        let snapshot = binding
            .verify(
                &tenant,
                &site,
                &session,
                &credentials(CREDENTIAL_A),
                UnixSeconds::new(100),
            )
            .unwrap();
        let evidence = PageEvidence::verified(
            PageEvidenceId::parse("page_018f2a3b-4c5d-7000-8000-000000000303").unwrap(),
            &binding,
            snapshot.clone(),
            RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000304").unwrap(),
            PageTemplate::parse("settings_page").unwrap(),
            BuildFingerprint::parse(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .unwrap(),
            PolicyRevision::parse("policy-r1").unwrap(),
            MappingRevision::parse("mapping-r1").unwrap(),
            UnixSeconds::new(250),
            UnixSeconds::new(100),
        )
        .unwrap();
        let descriptor = ActionDescriptor::approved(
            ActionId::parse("settings.change_self_password").unwrap(),
            PageTemplate::parse("settings_page").unwrap(),
            OperationId::parse("user.password.change_self").unwrap(),
            HttpMethod::Post,
            RouteTemplate::parse("/api/password/change").unwrap(),
            ActionTargetRule::VerifiedPrincipal,
            BTreeSet::from([
                FieldName::parse("current_password").unwrap(),
                FieldName::parse("new_password").unwrap(),
            ]),
            ViewProfile::parse("self_password_fields").unwrap(),
            PolicyRevision::parse("policy-r1").unwrap(),
            MappingRevision::parse("mapping-r1").unwrap(),
        );
        Fixture {
            binding,
            snapshot,
            evidence,
            descriptor,
        }
    }

    fn draft(target: &str, fields: &[&str]) -> ActionGrantDraft {
        ActionGrantDraft {
            action_ref: ActionRef::parse("action_grant_self_password").unwrap(),
            target: ActionTarget::Principal(target.to_owned()),
            fields: fields
                .iter()
                .map(|field| FieldName::parse(*field).unwrap())
                .collect(),
            expires_at: UnixSeconds::new(200),
        }
    }

    fn issue(fixture: &Fixture, draft: ActionGrantDraft) -> Result<ActionGrant, ProvenanceError> {
        ActionGrant::issue(
            &fixture.binding,
            &fixture.snapshot,
            &fixture.evidence,
            &fixture.descriptor,
            draft,
            UnixSeconds::new(100),
        )
    }

    #[test]
    fn exact_action_survives_same_context_credential_refresh() {
        let mut fixture = fixture();
        let grant = issue(
            &fixture,
            draft("principal_a", &["current_password", "new_password"]),
        )
        .unwrap();
        fixture
            .binding
            .refresh_same_context(
                &fixture.snapshot,
                credentials(CREDENTIAL_B),
                UnixSeconds::new(110),
            )
            .unwrap();
        let current = fixture
            .binding
            .verify(
                fixture.snapshot.tenant_id(),
                fixture.snapshot.site_id(),
                &WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000302").unwrap(),
                &credentials(CREDENTIAL_B),
                UnixSeconds::new(110),
            )
            .unwrap();
        assert_eq!(
            grant.authorize(
                &fixture.binding,
                &current,
                &OperationId::parse("user.password.change_self").unwrap(),
                HttpMethod::Post,
                &RouteTemplate::parse("/api/password/change").unwrap(),
                &ActionTarget::Principal("principal_a".to_owned()),
                &BTreeSet::from([FieldName::parse("new_password").unwrap()]),
                UnixSeconds::new(110),
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_target_field_method_and_route_expansion() {
        let fixture = fixture();
        assert_eq!(
            issue(&fixture, draft("principal_b", &["new_password"])),
            Err(ProvenanceError::TargetScopeMismatch)
        );
        assert_eq!(
            issue(&fixture, draft("principal_a", &["new_password", "role"]),),
            Err(ProvenanceError::FieldNotAllowed)
        );
        let grant = issue(&fixture, draft("principal_a", &["new_password"])).unwrap();
        let no_fields = BTreeSet::new();
        assert_eq!(
            grant.authorize(
                &fixture.binding,
                &fixture.snapshot,
                &OperationId::parse("user.password.change_self").unwrap(),
                HttpMethod::Get,
                &RouteTemplate::parse("/api/password/change").unwrap(),
                &ActionTarget::Principal("principal_a".to_owned()),
                &no_fields,
                UnixSeconds::new(110),
            ),
            Err(ProvenanceError::ActionUnavailable)
        );
        assert_eq!(
            grant.authorize(
                &fixture.binding,
                &fixture.snapshot,
                &OperationId::parse("user.password.change_self").unwrap(),
                HttpMethod::Post,
                &RouteTemplate::parse("/api/password/reset").unwrap(),
                &ActionTarget::Principal("principal_a".to_owned()),
                &no_fields,
                UnixSeconds::new(110),
            ),
            Err(ProvenanceError::ActionUnavailable)
        );
    }

    #[test]
    fn revoked_evidence_retired_mapping_and_epoch_change_fail_closed() {
        let mut revoked = fixture();
        revoked.evidence.revoke();
        assert_eq!(
            issue(&revoked, draft("principal_a", &["new_password"])),
            Err(ProvenanceError::EvidenceUnverified)
        );

        let mut retired = fixture();
        retired.descriptor.retire();
        assert_eq!(
            issue(&retired, draft("principal_a", &["new_password"])),
            Err(ProvenanceError::ActionUnavailable)
        );

        let mut changed = fixture();
        let grant = issue(&changed, draft("principal_a", &["new_password"])).unwrap();
        changed
            .binding
            .switch_context(
                &changed.snapshot,
                "principal_b",
                credentials(CREDENTIAL_B),
                UnixSeconds::new(110),
            )
            .unwrap();
        assert_eq!(
            grant.authorize(
                &changed.binding,
                &changed.snapshot,
                &OperationId::parse("user.password.change_self").unwrap(),
                HttpMethod::Post,
                &RouteTemplate::parse("/api/password/change").unwrap(),
                &ActionTarget::Principal("principal_a".to_owned()),
                &BTreeSet::new(),
                UnixSeconds::new(110),
            ),
            Err(ProvenanceError::Identity(IdentityDenied::EpochChanged))
        );
    }

    #[test]
    fn evidence_lease_cannot_exceed_session() {
        let fixture = fixture();
        assert_eq!(
            PageEvidence::verified(
                PageEvidenceId::parse("page_018f2a3b-4c5d-7000-8000-000000000305").unwrap(),
                &fixture.binding,
                fixture.snapshot.clone(),
                fixture.evidence.source_request_id().clone(),
                fixture.evidence.page_template().clone(),
                fixture.evidence.build_fingerprint().clone(),
                fixture.evidence.policy_revision().clone(),
                fixture.evidence.mapping_revision().clone(),
                UnixSeconds::new(301),
                UnixSeconds::new(100),
            ),
            Err(ProvenanceError::EvidenceUnverified)
        );
    }

    #[test]
    fn verified_response_issues_only_its_exact_target_action() {
        let mut fixture = fixture();
        let evidence = ResponseEvidence::verified(
            ResponseEvidenceId::parse("response_018f2a3b-4c5d-7000-8000-000000000306").unwrap(),
            &fixture.binding,
            fixture.snapshot.clone(),
            RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000307").unwrap(),
            OperationId::parse("users.list").unwrap(),
            fixture.descriptor.operation_id().clone(),
            200,
            fixture.descriptor.policy_revision.clone(),
            UnixSeconds::new(200),
            UnixSeconds::new(100),
        )
        .unwrap();
        let grant = ActionGrant::issue_from_response(
            &fixture.binding,
            &fixture.snapshot,
            &evidence,
            &fixture.descriptor,
            draft("principal_a", &["new_password"]),
            UnixSeconds::new(100),
        )
        .unwrap();
        assert!(matches!(
            grant.evidence_ref(),
            ActionEvidenceRef::Response(_)
        ));

        fixture.descriptor.operation_id = OperationId::parse("user.password.reset").unwrap();
        assert_eq!(
            ActionGrant::issue_from_response(
                &fixture.binding,
                &fixture.snapshot,
                &evidence,
                &fixture.descriptor,
                draft("principal_a", &["new_password"]),
                UnixSeconds::new(100),
            ),
            Err(ProvenanceError::ActionUnavailable)
        );
    }
}
