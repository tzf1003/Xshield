//! Exact resource-operation grants bound to an immutable authentication epoch.

use crate::{
    audit::ReasonCode,
    domain::{
        GrantId, IssuanceKey, OperationId, PolicyRevision, RequestId, ResourceType, ViewProfile,
        parse_lower_hex_32,
    },
    identity::{AuthBinding, AuthEpoch, AuthSnapshot, IdentityDenied, UnixSeconds},
};
use std::fmt;

/// Tenant-isolated HMAC of a canonical business resource reference.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceKeyHmac([u8; 32]);

impl ResourceKeyHmac {
    /// Parses a canonical lowercase 64-character hexadecimal HMAC.
    ///
    /// # Errors
    /// Returns [`GrantError::ResourceKeyInvalid`] for malformed input.
    pub fn parse(value: &str) -> Result<Self, GrantError> {
        parse_lower_hex_32(value)
            .map(Self)
            .ok_or(GrantError::ResourceKeyInvalid)
    }
}

impl fmt::Debug for ResourceKeyHmac {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceKeyHmac([REDACTED])")
    }
}

/// Mutable lifecycle state of a persisted grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantStatus {
    /// Grant may authorize exact matching requests before expiry.
    Active,
    /// Grant remains auditable but cannot authorize requests.
    Revoked,
}

/// Validated input for one grant issued from an approved source response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantDraft {
    /// Server-generated grant ID.
    pub grant_id: GrantId,
    /// Idempotency key derived from source, rule, resource, and operation.
    pub issuance_key: IssuanceKey,
    /// Canonical business resource type.
    pub resource_type: ResourceType,
    /// Tenant-isolated HMAC of the resource identifier.
    pub resource_key: ResourceKeyHmac,
    /// Exact operation being granted.
    pub operation_id: OperationId,
    /// Exact response or field view being granted.
    pub view_profile: ViewProfile,
    /// Approved request whose response produced the resource.
    pub source_request_id: RequestId,
    /// Frozen policy revision that approved issuance.
    pub policy_revision: PolicyRevision,
    /// Server-side expiry bounded by the authentication session.
    pub expires_at: UnixSeconds,
}

/// Persistable resource grant. Authorization fields are immutable after issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceGrant {
    draft: GrantDraft,
    binding_id: crate::domain::AuthBindingId,
    auth_epoch: AuthEpoch,
    tenant_id: crate::domain::TenantId,
    site_id: crate::domain::SiteId,
    issued_at: UnixSeconds,
    status: GrantStatus,
}

impl ResourceGrant {
    /// Returns the immutable grant ID.
    #[must_use]
    pub const fn grant_id(&self) -> &GrantId {
        &self.draft.grant_id
    }

    /// Returns the idempotent issuance key.
    #[must_use]
    pub const fn issuance_key(&self) -> &IssuanceKey {
        &self.draft.issuance_key
    }

    fn same_issuance(&self, draft: &GrantDraft, snapshot: &AuthSnapshot) -> bool {
        self.binding_id == *snapshot.binding_id()
            && self.auth_epoch == snapshot.epoch()
            && self.draft.resource_type == draft.resource_type
            && self.draft.resource_key == draft.resource_key
            && self.draft.operation_id == draft.operation_id
            && self.draft.view_profile == draft.view_profile
            && self.draft.source_request_id == draft.source_request_id
            && self.draft.policy_revision == draft.policy_revision
            && self.draft.expires_at == draft.expires_at
    }

    /// Revokes authorization while retaining audit history.
    pub fn revoke(&mut self) {
        self.status = GrantStatus::Revoked;
    }

    fn authorize(&self, query: &GrantQuery<'_>) -> Result<(), GrantDenied> {
        if &self.tenant_id != query.snapshot.tenant_id()
            || &self.site_id != query.snapshot.site_id()
            || &self.binding_id != query.snapshot.binding_id()
            || self.auth_epoch != query.snapshot.epoch()
            || &self.draft.resource_type != query.resource_type
            || &self.draft.resource_key != query.resource_key
        {
            return Err(GrantDenied::CapabilityMissing);
        }
        if self.status != GrantStatus::Active || query.now >= self.draft.expires_at {
            return Err(GrantDenied::CapabilityMissing);
        }
        if &self.draft.operation_id != query.operation_id
            || &self.draft.view_profile != query.view_profile
        {
            return Err(GrantDenied::OperationNotGranted);
        }
        Ok(())
    }
}

/// Exact authorization query constructed from a checked route and identity snapshot.
#[derive(Clone, Copy, Debug)]
pub struct GrantQuery<'a> {
    /// Immutable identity captured for this request.
    pub snapshot: &'a AuthSnapshot,
    /// Canonical resource type from the route adapter.
    pub resource_type: &'a ResourceType,
    /// Tenant-isolated HMAC of the requested resource.
    pub resource_key: &'a ResourceKeyHmac,
    /// Exact requested operation.
    pub operation_id: &'a OperationId,
    /// Exact requested view or field profile.
    pub view_profile: &'a ViewProfile,
    /// Trusted server time.
    pub now: UnixSeconds,
}

/// Bounded in-memory aggregate used before persistence and by domain tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantLedger {
    grants: Vec<ResourceGrant>,
    capacity: usize,
}

impl GrantLedger {
    /// Creates an empty ledger with a non-zero hard capacity.
    ///
    /// # Errors
    /// Returns [`GrantError::CapacityInvalid`] when capacity is zero.
    pub fn new(capacity: usize) -> Result<Self, GrantError> {
        if capacity == 0 {
            return Err(GrantError::CapacityInvalid);
        }
        Ok(Self {
            grants: Vec::new(),
            capacity,
        })
    }

    /// Issues a grant after revalidating the original request snapshot.
    ///
    /// Repeated issuance keys return the original grant without extending its
    /// lifetime. The caller persists the grant and audit outbox atomically.
    ///
    /// # Errors
    /// Returns [`GrantError`] when identity changed, expiry is invalid, or the
    /// configured capacity is exhausted.
    pub fn issue(
        &mut self,
        binding: &AuthBinding,
        snapshot: &AuthSnapshot,
        draft: GrantDraft,
        now: UnixSeconds,
    ) -> Result<GrantIssue, GrantError> {
        binding.validate_epoch(snapshot, now)?;
        if let Some(existing) = self.grants.iter().find(|grant| {
            &grant.tenant_id == snapshot.tenant_id()
                && &grant.site_id == snapshot.site_id()
                && grant.issuance_key() == &draft.issuance_key
        }) {
            if !existing.same_issuance(&draft, snapshot) {
                return Err(GrantError::IssuanceConflict);
            }
            return Ok(GrantIssue {
                grant_id: existing.grant_id().clone(),
                created: false,
            });
        }
        if draft.expires_at <= now || draft.expires_at > binding.absolute_expires_at() {
            return Err(GrantError::ExpiryInvalid);
        }
        if self.grants.len() >= self.capacity {
            return Err(GrantError::CapacityExceeded);
        }
        let issue = GrantIssue {
            grant_id: draft.grant_id.clone(),
            created: true,
        };
        self.grants.push(ResourceGrant {
            draft,
            binding_id: snapshot.binding_id().clone(),
            auth_epoch: snapshot.epoch(),
            tenant_id: snapshot.tenant_id().clone(),
            site_id: snapshot.site_id().clone(),
            issued_at: now,
            status: GrantStatus::Active,
        });
        Ok(issue)
    }

    /// Authorizes only an exact active resource, operation, view, and epoch match.
    ///
    /// # Errors
    /// Returns [`GrantDenied`] when no exact active grant is present.
    pub fn authorize(
        &self,
        binding: &AuthBinding,
        query: GrantQuery<'_>,
    ) -> Result<(), GrantDenied> {
        binding.validate_epoch(query.snapshot, query.now)?;
        // ponytail: bounded in-memory scan; the PostgreSQL adapter uses the exact composite index.
        let mut operation_mismatch = false;
        for grant in &self.grants {
            match grant.authorize(&query) {
                Ok(()) => return Ok(()),
                Err(GrantDenied::OperationNotGranted) => operation_mismatch = true,
                Err(GrantDenied::CapabilityMissing) => {}
                Err(GrantDenied::Identity(error)) => return Err(GrantDenied::Identity(error)),
            }
        }
        Err(if operation_mismatch {
            GrantDenied::OperationNotGranted
        } else {
            GrantDenied::CapabilityMissing
        })
    }

    /// Revokes a grant by ID and reports whether it existed.
    pub fn revoke(&mut self, grant_id: &GrantId) -> bool {
        let Some(grant) = self
            .grants
            .iter_mut()
            .find(|grant| grant.grant_id() == grant_id)
        else {
            return false;
        };
        grant.revoke();
        true
    }

    /// Returns the number of historical grants retained by this aggregate.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Reports whether the ledger contains no historical grants.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
}

/// Result of idempotent grant issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantIssue {
    /// Existing or newly created grant ID.
    pub grant_id: GrantId,
    /// True only when a new grant was appended.
    pub created: bool,
}

/// Invalid issuance input or state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantError {
    /// Canonical resource HMAC is malformed.
    ResourceKeyInvalid,
    /// Ledger capacity must be greater than zero.
    CapacityInvalid,
    /// Grant expiry is not after issuance or exceeds the session lease.
    ExpiryInvalid,
    /// Ledger reached its configured hard capacity.
    CapacityExceeded,
    /// An idempotency key was reused with different grant semantics.
    IssuanceConflict,
    /// Original request identity is no longer current.
    Identity(IdentityDenied),
}

impl From<IdentityDenied> for GrantError {
    fn from(value: IdentityDenied) -> Self {
        Self::Identity(value)
    }
}

impl fmt::Display for GrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResourceKeyInvalid => "invalid resource key HMAC",
            Self::CapacityInvalid => "grant ledger capacity must be positive",
            Self::ExpiryInvalid => ReasonCode::GrantExpiryInvalid.as_str(),
            Self::CapacityExceeded => ReasonCode::GrantCapacityExceeded.as_str(),
            Self::IssuanceConflict => ReasonCode::GrantIssuanceConflict.as_str(),
            Self::Identity(error) => return error.fmt(formatter),
        })
    }
}

impl std::error::Error for GrantError {}

/// Deterministic grant authorization rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantDenied {
    /// No active grant matches the resource and identity epoch.
    CapabilityMissing,
    /// The exact resource is known but operation or view is not granted.
    OperationNotGranted,
    /// The request identity is no longer current.
    Identity(IdentityDenied),
}

impl From<IdentityDenied> for GrantDenied {
    fn from(value: IdentityDenied) -> Self {
        Self::Identity(value)
    }
}

impl GrantDenied {
    /// Maps this denial to its stable audit reason code.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::CapabilityMissing => ReasonCode::CapabilityMissing,
            Self::OperationNotGranted => ReasonCode::OperationNotGranted,
            Self::Identity(error) => error.reason_code(),
        }
    }
}

impl fmt::Display for GrantDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code().as_str())
    }
}

impl std::error::Error for GrantDenied {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{AuthBindingId, SiteId, TenantId, WafSessionId},
        identity::{AuthEpoch, CredentialFingerprint, CredentialGeneration, CredentialSlot},
    };
    use std::collections::BTreeMap;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const R1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const R2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn setup() -> (AuthBinding, AuthSnapshot) {
        let binding = AuthBinding::new(
            AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
            WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
            TenantId::parse("tenant_a").unwrap(),
            SiteId::parse("site_a").unwrap(),
            "principal_a",
            AuthEpoch::new(4),
            CredentialGeneration::new(2),
            BTreeMap::from([(
                CredentialSlot::Cookie,
                CredentialFingerprint::parse(A).unwrap(),
            )]),
            UnixSeconds::new(200),
        )
        .unwrap();
        let snapshot = binding
            .verify(
                &TenantId::parse("tenant_a").unwrap(),
                &SiteId::parse("site_a").unwrap(),
                &WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
                &BTreeMap::from([(
                    CredentialSlot::Cookie,
                    CredentialFingerprint::parse(A).unwrap(),
                )]),
                UnixSeconds::new(100),
            )
            .unwrap();
        (binding, snapshot)
    }

    fn draft(id: u64, issuance: &str, resource: &str) -> GrantDraft {
        GrantDraft {
            grant_id: GrantId::parse(format!("grant_018f2a3b-4c5d-7000-8000-{id:012x}")).unwrap(),
            issuance_key: IssuanceKey::parse(issuance).unwrap(),
            resource_type: ResourceType::parse("order").unwrap(),
            resource_key: ResourceKeyHmac::parse(resource).unwrap(),
            operation_id: OperationId::parse("orders.read").unwrap(),
            view_profile: ViewProfile::parse("customer_detail").unwrap(),
            source_request_id: RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000010")
                .unwrap(),
            policy_revision: PolicyRevision::parse("demo-r3").unwrap(),
            expires_at: UnixSeconds::new(180),
        }
    }

    fn query<'a>(
        snapshot: &'a AuthSnapshot,
        resource_type: &'a ResourceType,
        resource: &'a ResourceKeyHmac,
        operation: &'a OperationId,
        view: &'a ViewProfile,
        now: u64,
    ) -> GrantQuery<'a> {
        GrantQuery {
            snapshot,
            resource_type,
            resource_key: resource,
            operation_id: operation,
            view_profile: view,
            now: UnixSeconds::new(now),
        }
    }

    #[test]
    fn exact_grant_allows_and_duplicate_issue_is_idempotent() {
        let (binding, snapshot) = setup();
        let mut ledger = GrantLedger::new(2).unwrap();
        let first = ledger
            .issue(
                &binding,
                &snapshot,
                draft(1, "source-1", R1),
                UnixSeconds::new(100),
            )
            .unwrap();
        let duplicate = ledger
            .issue(
                &binding,
                &snapshot,
                draft(2, "source-1", R1),
                UnixSeconds::new(110),
            )
            .unwrap();
        assert!(first.created);
        assert!(!duplicate.created);
        assert_eq!(first.grant_id, duplicate.grant_id);
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.issue(
                &binding,
                &snapshot,
                draft(3, "source-1", R2),
                UnixSeconds::new(110),
            ),
            Err(GrantError::IssuanceConflict)
        );

        let resource = ResourceKeyHmac::parse(R1).unwrap();
        let resource_type = ResourceType::parse("order").unwrap();
        let operation = OperationId::parse("orders.read").unwrap();
        let view = ViewProfile::parse("customer_detail").unwrap();
        assert_eq!(
            ledger.authorize(
                &binding,
                query(&snapshot, &resource_type, &resource, &operation, &view, 179,)
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_resource_operation_view_expiry_and_revocation() {
        let (binding, snapshot) = setup();
        let mut ledger = GrantLedger::new(2).unwrap();
        let issued = ledger
            .issue(
                &binding,
                &snapshot,
                draft(1, "source-1", R1),
                UnixSeconds::new(100),
            )
            .unwrap();
        let r1 = ResourceKeyHmac::parse(R1).unwrap();
        let r2 = ResourceKeyHmac::parse(R2).unwrap();
        let resource_type = ResourceType::parse("order").unwrap();
        let read = OperationId::parse("orders.read").unwrap();
        let update = OperationId::parse("orders.update").unwrap();
        let detail = ViewProfile::parse("customer_detail").unwrap();
        let full = ViewProfile::parse("admin_full").unwrap();

        assert_eq!(
            ledger.authorize(
                &binding,
                query(&snapshot, &resource_type, &r2, &read, &detail, 100,)
            ),
            Err(GrantDenied::CapabilityMissing)
        );
        assert_eq!(
            ledger.authorize(
                &binding,
                query(&snapshot, &resource_type, &r1, &update, &detail, 100,)
            ),
            Err(GrantDenied::OperationNotGranted)
        );
        assert_eq!(
            ledger.authorize(
                &binding,
                query(&snapshot, &resource_type, &r1, &read, &full, 100,)
            ),
            Err(GrantDenied::OperationNotGranted)
        );
        assert_eq!(
            ledger.authorize(
                &binding,
                query(&snapshot, &resource_type, &r1, &read, &detail, 180,)
            ),
            Err(GrantDenied::CapabilityMissing)
        );
        assert!(ledger.revoke(&issued.grant_id));
        assert_eq!(
            ledger.authorize(
                &binding,
                query(&snapshot, &resource_type, &r1, &read, &detail, 100,)
            ),
            Err(GrantDenied::CapabilityMissing)
        );
    }

    #[test]
    fn identity_change_capacity_and_expiry_fail_closed() {
        let (mut binding, snapshot) = setup();
        let mut ledger = GrantLedger::new(1).unwrap();
        ledger
            .issue(
                &binding,
                &snapshot,
                draft(1, "source-1", R1),
                UnixSeconds::new(100),
            )
            .unwrap();
        assert_eq!(
            ledger.issue(
                &binding,
                &snapshot,
                draft(2, "source-2", R2),
                UnixSeconds::new(100)
            ),
            Err(GrantError::CapacityExceeded)
        );

        let mut invalid = draft(3, "source-3", R2);
        invalid.expires_at = UnixSeconds::new(201);
        let mut fresh_ledger = GrantLedger::new(1).unwrap();
        assert_eq!(
            fresh_ledger.issue(&binding, &snapshot, invalid, UnixSeconds::new(100)),
            Err(GrantError::ExpiryInvalid)
        );

        binding
            .refresh_same_context(
                &snapshot,
                BTreeMap::from([(
                    CredentialSlot::Cookie,
                    CredentialFingerprint::parse(C).unwrap(),
                )]),
                UnixSeconds::new(100),
            )
            .unwrap();
        fresh_ledger
            .issue(
                &binding,
                &snapshot,
                draft(4, "source-4", R2),
                UnixSeconds::new(100),
            )
            .unwrap();
        let current_snapshot = binding
            .verify(
                &TenantId::parse("tenant_a").unwrap(),
                &SiteId::parse("site_a").unwrap(),
                &WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
                &BTreeMap::from([(
                    CredentialSlot::Cookie,
                    CredentialFingerprint::parse(C).unwrap(),
                )]),
                UnixSeconds::new(100),
            )
            .unwrap();
        binding
            .switch_context(
                &current_snapshot,
                "principal_b",
                BTreeMap::from([(
                    CredentialSlot::Cookie,
                    CredentialFingerprint::parse(B).unwrap(),
                )]),
                UnixSeconds::new(100),
            )
            .unwrap();
        assert_eq!(
            fresh_ledger.issue(
                &binding,
                &snapshot,
                draft(5, "source-5", R2),
                UnixSeconds::new(100),
            ),
            Err(GrantError::Identity(IdentityDenied::EpochChanged))
        );
        let resource_type = ResourceType::parse("order").unwrap();
        let resource = ResourceKeyHmac::parse(R2).unwrap();
        let operation = OperationId::parse("orders.read").unwrap();
        let view = ViewProfile::parse("customer_detail").unwrap();
        assert_eq!(
            fresh_ledger.authorize(
                &binding,
                query(&snapshot, &resource_type, &resource, &operation, &view, 100,),
            ),
            Err(GrantDenied::Identity(IdentityDenied::EpochChanged))
        );
    }
}
