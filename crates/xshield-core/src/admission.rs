//! Deterministic operation-entry admission composed from existing identity and grant domains.

use crate::{
    access::{
        AccessDenied, ServiceCredentialFingerprint, ServiceIdentity, ShareGrant,
        ShareTokenFingerprint,
    },
    audit::ReasonCode,
    domain::{ActionId, FieldName, OperationId, ResourceType, SiteId, TenantId, ViewProfile},
    grant::{GrantDenied, GrantLedger, GrantQuery, ResourceKeyHmac},
    identity::{AuthBinding, AuthSnapshot, IdentityDenied, UnixSeconds},
    provenance::{ActionGrant, ActionTarget, HttpMethod, ProvenanceError, RouteTemplate},
};
use std::{collections::BTreeSet, fmt};

/// Server-configured entry classification for one exact operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionClass {
    /// Explicitly public operation and view.
    Public,
    /// Login, code exchange, or authentication callback.
    AuthenticationEntry,
    /// Explicit root available to a current authenticated identity.
    AuthenticatedRoot,
    /// Operation requiring a verified UI action source.
    UiActionRequired,
    /// Operation requiring an exact limited-share proof.
    ShareEntry,
    /// Operation requiring an exact service identity scope.
    ServiceIdentity,
}

/// Resource qualification required in addition to an action grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityPolicy {
    /// The approved action itself supplies the complete target and field scope.
    None,
    /// One exact resource grant must match this resource type and view.
    ExactResource {
        /// Canonical resource type.
        resource_type: ResourceType,
        /// Exact response or field view.
        view_profile: ViewProfile,
    },
}

/// Frozen policy for one already-resolved operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPolicy {
    operation_id: OperationId,
    method: HttpMethod,
    route: RouteTemplate,
    admission: AdmissionClass,
    source_action: Option<ActionId>,
    capability: CapabilityPolicy,
}

impl OperationPolicy {
    /// Returns the stable operation identifier compiled into this policy.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the configured proof class for this operation.
    #[must_use]
    pub const fn admission_class(&self) -> AdmissionClass {
        self.admission
    }

    /// Validates cross-field admission policy invariants.
    ///
    /// # Errors
    /// Returns [`OperationPolicyError`] when UI provenance requirements are
    /// missing or attached to an entry class that cannot consume them.
    pub fn new(
        operation_id: OperationId,
        method: HttpMethod,
        route: RouteTemplate,
        admission: AdmissionClass,
        source_action: Option<ActionId>,
        capability: CapabilityPolicy,
    ) -> Result<Self, OperationPolicyError> {
        let source_valid =
            (admission == AdmissionClass::UiActionRequired) == source_action.is_some();
        let capability_valid = match admission {
            AdmissionClass::UiActionRequired => true,
            AdmissionClass::ShareEntry => {
                matches!(capability, CapabilityPolicy::ExactResource { .. })
            }
            AdmissionClass::Public
            | AdmissionClass::AuthenticationEntry
            | AdmissionClass::AuthenticatedRoot
            | AdmissionClass::ServiceIdentity => capability == CapabilityPolicy::None,
        };
        if !source_valid || !capability_valid {
            return Err(OperationPolicyError);
        }
        Ok(Self {
            operation_id,
            method,
            route,
            admission,
            source_action,
            capability,
        })
    }

    /// Applies hard entry, identity, UI action, and resource checks.
    ///
    /// This function performs no storage or network access. Callers must load
    /// proof state from authoritative ports before invoking it.
    ///
    /// # Errors
    /// Returns [`AdmissionError`] for any missing, stale, mismatched, or
    /// unsupported proof.
    pub fn admit(
        &self,
        request: AdmissionRequest<'_>,
        proof: AdmissionProof<'_>,
    ) -> Result<AdmissionDecision, AdmissionError> {
        if request.method != self.method || request.route != &self.route {
            return Err(AdmissionError::OperationNotMatched);
        }
        let reason_code = match self.admission {
            AdmissionClass::Public => ReasonCode::PublicEntryAllowed,
            AdmissionClass::AuthenticationEntry => ReasonCode::AuthEntryAllowed,
            AdmissionClass::AuthenticatedRoot => {
                let AdmissionProof::Authenticated { binding, snapshot } = proof else {
                    return Err(AdmissionError::AuthRequired);
                };
                binding.validate_epoch(snapshot, request.now)?;
                ReasonCode::FlowRootAllowed
            }
            AdmissionClass::UiActionRequired => {
                let AdmissionProof::UiAction {
                    binding,
                    snapshot,
                    action,
                    grants,
                } = proof
                else {
                    return Err(AdmissionError::UiActionRequired);
                };
                if self.source_action.as_ref() != Some(action.action_id()) {
                    return Err(AdmissionError::UiActionRequired);
                }
                action.authorize(
                    binding,
                    snapshot,
                    &self.operation_id,
                    request.method,
                    request.route,
                    request.target,
                    request.fields,
                    request.now,
                )?;
                self.authorize_resource(binding, snapshot, grants, &request)?;
                ReasonCode::UiActionAllowed
            }
            AdmissionClass::ShareEntry => {
                let AdmissionProof::Share {
                    grant,
                    token_fingerprint,
                } = proof
                else {
                    return Err(AdmissionError::ShareScopeMismatch);
                };
                let CapabilityPolicy::ExactResource {
                    resource_type,
                    view_profile,
                } = &self.capability
                else {
                    return Err(AdmissionError::ShareScopeMismatch);
                };
                let Some(resource) = request.resource else {
                    return Err(AdmissionError::ShareScopeMismatch);
                };
                grant.authorize(
                    request.tenant_id,
                    request.site_id,
                    token_fingerprint,
                    resource_type,
                    resource.resource_key,
                    &self.operation_id,
                    view_profile,
                    request.method,
                    request.now,
                )?;
                if resource.resource_type != resource_type {
                    return Err(AdmissionError::ShareScopeMismatch);
                }
                ReasonCode::ShareEntryAllowed
            }
            AdmissionClass::ServiceIdentity => {
                let AdmissionProof::Service {
                    identity,
                    credential_fingerprint,
                } = proof
                else {
                    return Err(AdmissionError::ServiceIdentityMismatch);
                };
                identity.authorize(
                    request.tenant_id,
                    request.site_id,
                    credential_fingerprint,
                    &self.operation_id,
                    request.now,
                )?;
                ReasonCode::ServiceIdentityAllowed
            }
        };
        Ok(AdmissionDecision {
            operation_id: self.operation_id.clone(),
            admission: self.admission,
            reason_code,
        })
    }

    fn authorize_resource(
        &self,
        binding: &AuthBinding,
        snapshot: &AuthSnapshot,
        grants: Option<&GrantLedger>,
        request: &AdmissionRequest<'_>,
    ) -> Result<(), AdmissionError> {
        let CapabilityPolicy::ExactResource {
            resource_type,
            view_profile,
        } = &self.capability
        else {
            return Ok(());
        };
        let Some(resource) = request.resource else {
            return Err(AdmissionError::Capability(GrantDenied::CapabilityMissing));
        };
        if resource.resource_type != resource_type {
            return Err(AdmissionError::Capability(GrantDenied::CapabilityMissing));
        }
        let Some(grants) = grants else {
            return Err(AdmissionError::Capability(GrantDenied::CapabilityMissing));
        };
        grants.authorize(
            binding,
            GrantQuery {
                snapshot,
                resource_type,
                resource_key: resource.resource_key,
                operation_id: &self.operation_id,
                view_profile,
                now: request.now,
            },
        )?;
        Ok(())
    }
}

/// Request facts produced by trusted routing and DTO validation.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionRequest<'a> {
    /// Tenant selected by trusted edge configuration.
    pub tenant_id: &'a TenantId,
    /// Site selected by trusted edge configuration.
    pub site_id: &'a SiteId,
    /// Canonical method selected by the route adapter.
    pub method: HttpMethod,
    /// Matched canonical route template, not an attacker-provided policy key.
    pub route: &'a RouteTemplate,
    /// Exact UI action target.
    pub target: &'a ActionTarget,
    /// Exact body/query fields used by the operation.
    pub fields: &'a BTreeSet<FieldName>,
    /// Exact resource reference when the operation requires a resource grant.
    pub resource: Option<ResourceAccess<'a>>,
    /// Trusted server time frozen for this decision.
    pub now: UnixSeconds,
}

/// Exact resource extracted by a versioned site route adapter.
#[derive(Clone, Copy, Debug)]
pub struct ResourceAccess<'a> {
    /// Canonical resource type.
    pub resource_type: &'a ResourceType,
    /// Tenant-isolated HMAC of the canonical resource reference.
    pub resource_key: &'a ResourceKeyHmac,
}

/// Authoritative proof bundle loaded for the configured entry class.
#[derive(Clone, Copy, Debug)]
pub enum AdmissionProof<'a> {
    /// No identity-dependent proof is supplied.
    None,
    /// Current authenticated identity for an approved root.
    Authenticated {
        /// Current binding state.
        binding: &'a AuthBinding,
        /// Immutable request snapshot.
        snapshot: &'a AuthSnapshot,
    },
    /// Exact UI action and optional resource-grant ledger.
    UiAction {
        /// Current binding state.
        binding: &'a AuthBinding,
        /// Immutable request snapshot.
        snapshot: &'a AuthSnapshot,
        /// Action grant selected by exact reference.
        action: &'a ActionGrant,
        /// Resource grant ledger when required by policy.
        grants: Option<&'a GrantLedger>,
    },
    /// Exact limited-share grant and presented token fingerprint.
    Share {
        /// Server-side limited-share record.
        grant: &'a ShareGrant,
        /// Fingerprint of the presented share token.
        token_fingerprint: &'a ShareTokenFingerprint,
    },
    /// Exact service identity and presented credential fingerprint.
    Service {
        /// Server-side service identity record.
        identity: &'a ServiceIdentity,
        /// Fingerprint of the presented service credential.
        credential_fingerprint: &'a ServiceCredentialFingerprint,
    },
}

/// Successful deterministic entry decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionDecision {
    /// Exact operation admitted.
    pub operation_id: OperationId,
    /// Configured entry classification.
    pub admission: AdmissionClass,
    /// Stable reason for stage audit.
    pub reason_code: ReasonCode,
}

/// Invalid cross-field operation configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationPolicyError;

impl fmt::Display for OperationPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid operation admission policy")
    }
}

impl std::error::Error for OperationPolicyError {}

/// Deterministic operation admission rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    /// Method or route differs from the frozen operation policy.
    OperationNotMatched,
    /// Authenticated root has no current identity proof.
    AuthRequired,
    /// UI action proof is absent or references another approved descriptor.
    UiActionRequired,
    /// Limited-share proof is absent or out of scope.
    ShareScopeMismatch,
    /// Service identity proof is absent or out of scope.
    ServiceIdentityMismatch,
    /// Current identity is stale or mismatched.
    Identity(IdentityDenied),
    /// UI action target, fields, route, or lifecycle is invalid.
    Provenance(ProvenanceError),
    /// Exact resource operation grant is absent or out of scope.
    Capability(GrantDenied),
    /// Dedicated share or service proof is outside its exact scope.
    Access(AccessDenied),
}

impl AdmissionError {
    /// Maps the rejection to its stable audit reason.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::OperationNotMatched => ReasonCode::OperationNotMatched,
            Self::AuthRequired => ReasonCode::AuthRequired,
            Self::UiActionRequired => ReasonCode::UiActionNotAvailable,
            Self::ShareScopeMismatch => ReasonCode::ShareScopeMismatch,
            Self::ServiceIdentityMismatch => ReasonCode::ServiceIdentityMismatch,
            Self::Identity(error) => error.reason_code(),
            Self::Provenance(error) => error.reason_code(),
            Self::Capability(error) => error.reason_code(),
            Self::Access(error) => error.reason_code(),
        }
    }
}

impl From<IdentityDenied> for AdmissionError {
    fn from(value: IdentityDenied) -> Self {
        Self::Identity(value)
    }
}

impl From<ProvenanceError> for AdmissionError {
    fn from(value: ProvenanceError) -> Self {
        Self::Provenance(value)
    }
}

impl From<GrantDenied> for AdmissionError {
    fn from(value: GrantDenied) -> Self {
        Self::Capability(value)
    }
}

impl From<AccessDenied> for AdmissionError {
    fn from(value: AccessDenied) -> Self {
        Self::Access(value)
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code().as_str())
    }
}

impl std::error::Error for AdmissionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{
            ActionRef, AuthBindingId, GrantId, IssuanceKey, MappingRevision, PageEvidenceId,
            PageTemplate, PolicyRevision, RequestId, ServiceIdentityId, ShareGrantId, SiteId,
            TenantId, WafSessionId,
        },
        grant::{GrantDraft, GrantLedger},
        identity::{AuthEpoch, CredentialFingerprint, CredentialGeneration, CredentialSlot},
        provenance::{
            ActionDescriptor, ActionGrantDraft, ActionTargetRule, BuildFingerprint, PageEvidence,
        },
    };
    use std::collections::BTreeMap;

    const RESOURCE_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const RESOURCE_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    struct Fixture {
        binding: AuthBinding,
        snapshot: AuthSnapshot,
        action: ActionGrant,
        grants: GrantLedger,
        route: RouteTemplate,
        target: ActionTarget,
        resource_type: ResourceType,
        resource_a: ResourceKeyHmac,
        fields: BTreeSet<FieldName>,
    }

    fn identity() -> (AuthBinding, AuthSnapshot) {
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let session = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000502").unwrap();
        let credentials = BTreeMap::from([(
            CredentialSlot::Cookie,
            CredentialFingerprint::parse(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
        )]);
        let binding = AuthBinding::new(
            AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000501").unwrap(),
            session.clone(),
            tenant.clone(),
            site.clone(),
            "principal_a",
            crate::identity::AuthorizationContextRef::parse("context_a").unwrap(),
            AuthEpoch::new(4),
            CredentialGeneration::new(2),
            credentials.clone(),
            UnixSeconds::new(200),
        )
        .unwrap();
        let snapshot = binding
            .verify(
                &tenant,
                &site,
                &session,
                &credentials,
                UnixSeconds::new(100),
            )
            .unwrap();
        (binding, snapshot)
    }

    fn fixture() -> Fixture {
        let (binding, snapshot) = identity();
        let source_request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000503").unwrap();
        let policy = PolicyRevision::parse("policy-r1").unwrap();
        let evidence = PageEvidence::verified(
            PageEvidenceId::parse("page_018f2a3b-4c5d-7000-8000-000000000504").unwrap(),
            &binding,
            snapshot.clone(),
            source_request.clone(),
            PageTemplate::parse("orders_page").unwrap(),
            BuildFingerprint::parse(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            policy.clone(),
            MappingRevision::parse("mapping-r1").unwrap(),
            UnixSeconds::new(190),
            UnixSeconds::new(100),
        )
        .unwrap();
        let resource_type = ResourceType::parse("order").unwrap();
        let resource_a = ResourceKeyHmac::parse(RESOURCE_A).unwrap();
        let operation = OperationId::parse("orders.read").unwrap();
        let route = RouteTemplate::parse("/api/orders/{id}").unwrap();
        let descriptor = ActionDescriptor::approved(
            ActionId::parse("orders_list.open_order").unwrap(),
            PageTemplate::parse("orders_page").unwrap(),
            operation.clone(),
            HttpMethod::Get,
            route.clone(),
            ActionTargetRule::Resource(resource_type.clone()),
            BTreeSet::new(),
            ViewProfile::parse("customer_detail").unwrap(),
            policy.clone(),
            MappingRevision::parse("mapping-r1").unwrap(),
        );
        let target = ActionTarget::Resource {
            resource_type: resource_type.clone(),
            resource_key: resource_a.clone(),
        };
        let action = ActionGrant::issue(
            &binding,
            &snapshot,
            &evidence,
            &descriptor,
            ActionGrantDraft {
                action_ref: ActionRef::parse("action_order_a").unwrap(),
                target: target.clone(),
                fields: BTreeSet::new(),
                expires_at: UnixSeconds::new(180),
            },
            UnixSeconds::new(100),
        )
        .unwrap();
        let mut grants = GrantLedger::new(2).unwrap();
        grants
            .issue(
                &binding,
                &snapshot,
                GrantDraft {
                    grant_id: GrantId::parse("grant_018f2a3b-4c5d-7000-8000-000000000505").unwrap(),
                    issuance_key: IssuanceKey::parse("issue-order-a").unwrap(),
                    resource_type: resource_type.clone(),
                    resource_key: resource_a.clone(),
                    operation_id: operation,
                    view_profile: ViewProfile::parse("customer_detail").unwrap(),
                    source_request_id: source_request,
                    policy_revision: policy,
                    expires_at: UnixSeconds::new(180),
                },
                UnixSeconds::new(100),
            )
            .unwrap();
        Fixture {
            binding,
            snapshot,
            action,
            grants,
            route,
            target,
            resource_type,
            resource_a,
            fields: BTreeSet::new(),
        }
    }

    fn request<'a>(fixture: &'a Fixture, resource: &'a ResourceKeyHmac) -> AdmissionRequest<'a> {
        AdmissionRequest {
            tenant_id: fixture.snapshot.tenant_id(),
            site_id: fixture.snapshot.site_id(),
            method: HttpMethod::Get,
            route: &fixture.route,
            target: &fixture.target,
            fields: &fixture.fields,
            resource: Some(ResourceAccess {
                resource_type: &fixture.resource_type,
                resource_key: resource,
            }),
            now: UnixSeconds::new(110),
        }
    }

    fn policy(class: AdmissionClass, capability: CapabilityPolicy) -> OperationPolicy {
        OperationPolicy::new(
            OperationId::parse("orders.read").unwrap(),
            HttpMethod::Get,
            RouteTemplate::parse("/api/orders/{id}").unwrap(),
            class,
            (class == AdmissionClass::UiActionRequired)
                .then(|| ActionId::parse("orders_list.open_order").unwrap()),
            capability,
        )
        .unwrap()
    }

    #[test]
    fn policy_rejects_incoherent_entry_requirements() {
        assert!(
            OperationPolicy::new(
                OperationId::parse("orders.read").unwrap(),
                HttpMethod::Get,
                RouteTemplate::parse("/api/orders/{id}").unwrap(),
                AdmissionClass::UiActionRequired,
                None,
                CapabilityPolicy::None,
            )
            .is_err()
        );
        assert!(
            OperationPolicy::new(
                OperationId::parse("orders.read").unwrap(),
                HttpMethod::Get,
                RouteTemplate::parse("/api/orders/{id}").unwrap(),
                AdmissionClass::Public,
                None,
                CapabilityPolicy::ExactResource {
                    resource_type: ResourceType::parse("order").unwrap(),
                    view_profile: ViewProfile::parse("customer_detail").unwrap(),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn public_and_authenticated_roots_enforce_their_entry_class() {
        let fixture = fixture();
        let public = policy(AdmissionClass::Public, CapabilityPolicy::None);
        assert_eq!(
            public
                .admit(request(&fixture, &fixture.resource_a), AdmissionProof::None)
                .unwrap()
                .reason_code,
            ReasonCode::PublicEntryAllowed
        );
        let mut wrong_method = request(&fixture, &fixture.resource_a);
        wrong_method.method = HttpMethod::Post;
        assert_eq!(
            public.admit(wrong_method, AdmissionProof::None),
            Err(AdmissionError::OperationNotMatched)
        );
        let root = policy(AdmissionClass::AuthenticatedRoot, CapabilityPolicy::None);
        assert_eq!(
            root.admit(request(&fixture, &fixture.resource_a), AdmissionProof::None),
            Err(AdmissionError::AuthRequired)
        );
        assert_eq!(
            root.admit(
                request(&fixture, &fixture.resource_a),
                AdmissionProof::Authenticated {
                    binding: &fixture.binding,
                    snapshot: &fixture.snapshot,
                },
            )
            .unwrap()
            .reason_code,
            ReasonCode::FlowRootAllowed
        );
    }

    #[test]
    fn ui_entry_requires_exact_action_and_resource_grants() {
        let fixture = fixture();
        let operation = policy(
            AdmissionClass::UiActionRequired,
            CapabilityPolicy::ExactResource {
                resource_type: fixture.resource_type.clone(),
                view_profile: ViewProfile::parse("customer_detail").unwrap(),
            },
        );
        let proof = AdmissionProof::UiAction {
            binding: &fixture.binding,
            snapshot: &fixture.snapshot,
            action: &fixture.action,
            grants: Some(&fixture.grants),
        };
        assert_eq!(
            operation
                .admit(request(&fixture, &fixture.resource_a), proof)
                .unwrap()
                .reason_code,
            ReasonCode::UiActionAllowed
        );
        let resource_b = ResourceKeyHmac::parse(RESOURCE_B).unwrap();
        assert_eq!(
            operation.admit(request(&fixture, &resource_b), proof),
            Err(AdmissionError::Capability(GrantDenied::CapabilityMissing))
        );
        assert_eq!(
            operation.admit(request(&fixture, &fixture.resource_a), AdmissionProof::None),
            Err(AdmissionError::UiActionRequired)
        );
    }

    #[test]
    fn share_and_service_entries_require_dedicated_proof() {
        let fixture = fixture();
        let share_token = ShareTokenFingerprint::parse(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )
        .unwrap();
        let share = ShareGrant::new_read_only(
            ShareGrantId::parse("share_018f2a3b-4c5d-7000-8000-000000000506").unwrap(),
            fixture.snapshot.tenant_id().clone(),
            fixture.snapshot.site_id().clone(),
            share_token.clone(),
            fixture.resource_type.clone(),
            fixture.resource_a.clone(),
            OperationId::parse("orders.read").unwrap(),
            ViewProfile::parse("customer_detail").unwrap(),
            UnixSeconds::new(180),
            UnixSeconds::new(100),
        )
        .unwrap();
        let share_policy = policy(
            AdmissionClass::ShareEntry,
            CapabilityPolicy::ExactResource {
                resource_type: fixture.resource_type.clone(),
                view_profile: ViewProfile::parse("customer_detail").unwrap(),
            },
        );
        assert_eq!(
            share_policy
                .admit(
                    request(&fixture, &fixture.resource_a),
                    AdmissionProof::Share {
                        grant: &share,
                        token_fingerprint: &share_token,
                    },
                )
                .unwrap()
                .reason_code,
            ReasonCode::ShareEntryAllowed
        );
        let wrong_share_token = ShareTokenFingerprint::parse(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();
        assert_eq!(
            share_policy.admit(
                request(&fixture, &fixture.resource_a),
                AdmissionProof::Share {
                    grant: &share,
                    token_fingerprint: &wrong_share_token,
                },
            ),
            Err(AdmissionError::Access(AccessDenied::ShareScopeMismatch))
        );

        let service_credential = ServiceCredentialFingerprint::parse(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        )
        .unwrap();
        let service = ServiceIdentity::new(
            ServiceIdentityId::parse("svc_018f2a3b-4c5d-7000-8000-000000000507").unwrap(),
            fixture.snapshot.tenant_id().clone(),
            fixture.snapshot.site_id().clone(),
            service_credential.clone(),
            BTreeSet::from([OperationId::parse("orders.read").unwrap()]),
            UnixSeconds::new(180),
            UnixSeconds::new(100),
        )
        .unwrap();
        let service_policy = policy(AdmissionClass::ServiceIdentity, CapabilityPolicy::None);
        assert_eq!(
            service_policy
                .admit(
                    request(&fixture, &fixture.resource_a),
                    AdmissionProof::Service {
                        identity: &service,
                        credential_fingerprint: &service_credential,
                    },
                )
                .unwrap()
                .reason_code,
            ReasonCode::ServiceIdentityAllowed
        );
        assert_eq!(
            service_policy.admit(request(&fixture, &fixture.resource_a), AdmissionProof::None),
            Err(AdmissionError::ServiceIdentityMismatch)
        );
    }
}
