//! Exact limited-share and service-identity proofs for dedicated entry classes.

use crate::{
    audit::ReasonCode,
    domain::{
        OperationId, ResourceType, ServiceIdentityId, ShareGrantId, SiteId, TenantId, ViewProfile,
        parse_lower_hex_32,
    },
    grant::ResourceKeyHmac,
    identity::UnixSeconds,
    provenance::HttpMethod,
};
use std::{collections::BTreeSet, fmt};

macro_rules! fingerprint {
    ($name:ident, $error:ident) => {
        #[derive(Clone, Eq, PartialEq)]
        /// Tenant-isolated HMAC fingerprint of a presented access credential.
        pub struct $name([u8; 32]);

        impl $name {
            /// Parses a canonical lowercase 64-character hexadecimal fingerprint.
            ///
            /// # Errors
            /// Returns [`AccessInputError`] for malformed input.
            pub fn parse(value: &str) -> Result<Self, AccessInputError> {
                parse_lower_hex_32(value)
                    .map(Self)
                    .ok_or(AccessInputError::$error)
            }

            /// Borrows the fingerprint for persistence adapters.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

fingerprint!(ShareTokenFingerprint, ShareTokenFingerprint);
fingerprint!(ServiceCredentialFingerprint, ServiceCredentialFingerprint);

/// Limited share bound to one exact read operation, resource, and view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareGrant {
    share_id: ShareGrantId,
    tenant_id: TenantId,
    site_id: SiteId,
    token_fingerprint: ShareTokenFingerprint,
    resource_type: ResourceType,
    resource_key: ResourceKeyHmac,
    operation_id: OperationId,
    view_profile: ViewProfile,
    expires_at: UnixSeconds,
    active: bool,
}

impl ShareGrant {
    /// Creates a reusable read-only share after issuer authorization is verified.
    ///
    /// # Errors
    /// Returns [`AccessInputError::ExpiryInvalid`] for an elapsed lease.
    #[allow(clippy::too_many_arguments)]
    pub fn new_read_only(
        share_id: ShareGrantId,
        tenant_id: TenantId,
        site_id: SiteId,
        token_fingerprint: ShareTokenFingerprint,
        resource_type: ResourceType,
        resource_key: ResourceKeyHmac,
        operation_id: OperationId,
        view_profile: ViewProfile,
        expires_at: UnixSeconds,
        now: UnixSeconds,
    ) -> Result<Self, AccessInputError> {
        if expires_at <= now {
            return Err(AccessInputError::ExpiryInvalid);
        }
        Ok(Self {
            share_id,
            tenant_id,
            site_id,
            token_fingerprint,
            resource_type,
            resource_key,
            operation_id,
            view_profile,
            expires_at,
            active: true,
        })
    }

    /// Revokes future redemption while retaining audit history.
    pub fn revoke(&mut self) {
        self.active = false;
    }

    /// Verifies the exact read-only share scope.
    ///
    /// # Errors
    /// Returns [`AccessDenied::ShareScopeMismatch`] for any mismatch or expiry.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        token_fingerprint: &ShareTokenFingerprint,
        resource_type: &ResourceType,
        resource_key: &ResourceKeyHmac,
        operation_id: &OperationId,
        view_profile: &ViewProfile,
        method: HttpMethod,
        now: UnixSeconds,
    ) -> Result<(), AccessDenied> {
        if !self.active
            || now >= self.expires_at
            || method != HttpMethod::Get
            || &self.tenant_id != tenant_id
            || &self.site_id != site_id
            || &self.token_fingerprint != token_fingerprint
            || &self.resource_type != resource_type
            || &self.resource_key != resource_key
            || &self.operation_id != operation_id
            || &self.view_profile != view_profile
        {
            return Err(AccessDenied::ShareScopeMismatch);
        }
        Ok(())
    }

    /// Returns the share grant ID.
    #[must_use]
    pub const fn share_id(&self) -> &ShareGrantId {
        &self.share_id
    }

    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the site scope.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the credential fingerprint.
    #[must_use]
    pub const fn token_fingerprint(&self) -> &ShareTokenFingerprint {
        &self.token_fingerprint
    }

    /// Returns the expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }
}

/// Service identity bound to a finite operation set and credential lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceIdentity {
    identity_id: ServiceIdentityId,
    tenant_id: TenantId,
    site_id: SiteId,
    credential_fingerprint: ServiceCredentialFingerprint,
    operations: BTreeSet<OperationId>,
    expires_at: UnixSeconds,
    active: bool,
}

impl ServiceIdentity {
    /// Creates a service identity from a verified service credential.
    ///
    /// # Errors
    /// Returns [`AccessInputError`] for an empty operation set or elapsed lease.
    pub fn new(
        identity_id: ServiceIdentityId,
        tenant_id: TenantId,
        site_id: SiteId,
        credential_fingerprint: ServiceCredentialFingerprint,
        operations: BTreeSet<OperationId>,
        expires_at: UnixSeconds,
        now: UnixSeconds,
    ) -> Result<Self, AccessInputError> {
        if operations.is_empty() {
            return Err(AccessInputError::EmptyServiceOperations);
        }
        if expires_at <= now {
            return Err(AccessInputError::ExpiryInvalid);
        }
        Ok(Self {
            identity_id,
            tenant_id,
            site_id,
            credential_fingerprint,
            operations,
            expires_at,
            active: true,
        })
    }

    /// Revokes future service requests while retaining the identity record.
    pub fn revoke(&mut self) {
        self.active = false;
    }

    /// Verifies tenant, site, credential, operation, status, and expiry.
    ///
    /// # Errors
    /// Returns [`AccessDenied::ServiceIdentityMismatch`] for any mismatch.
    pub fn authorize(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        credential_fingerprint: &ServiceCredentialFingerprint,
        operation_id: &OperationId,
        now: UnixSeconds,
    ) -> Result<(), AccessDenied> {
        if !self.active
            || now >= self.expires_at
            || &self.tenant_id != tenant_id
            || &self.site_id != site_id
            || &self.credential_fingerprint != credential_fingerprint
            || !self.operations.contains(operation_id)
        {
            return Err(AccessDenied::ServiceIdentityMismatch);
        }
        Ok(())
    }

    /// Returns the service identity ID.
    #[must_use]
    pub const fn identity_id(&self) -> &ServiceIdentityId {
        &self.identity_id
    }

    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the site scope.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the credential fingerprint.
    #[must_use]
    pub const fn credential_fingerprint(&self) -> &ServiceCredentialFingerprint {
        &self.credential_fingerprint
    }

    /// Returns the allowed operations.
    #[must_use]
    pub const fn operations(&self) -> &BTreeSet<OperationId> {
        &self.operations
    }

    /// Returns the expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }
}

/// Invalid limited-share or service-identity construction input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessInputError {
    /// Share token fingerprint is malformed.
    ShareTokenFingerprint,
    /// Service credential fingerprint is malformed.
    ServiceCredentialFingerprint,
    /// Service identity must allow at least one operation.
    EmptyServiceOperations,
    /// Server-side access lease is already elapsed.
    ExpiryInvalid,
}

impl fmt::Display for AccessInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ShareTokenFingerprint => "invalid share token fingerprint",
            Self::ServiceCredentialFingerprint => "invalid service credential fingerprint",
            Self::EmptyServiceOperations => "service operation scope is empty",
            Self::ExpiryInvalid => "access lease is expired",
        })
    }
}

impl std::error::Error for AccessInputError {}

/// Deterministic dedicated-entry rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessDenied {
    /// Limited-share proof does not match the exact read scope.
    ShareScopeMismatch,
    /// Service credential does not match the exact operation scope.
    ServiceIdentityMismatch,
}

impl AccessDenied {
    /// Returns the stable audit reason code.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::ShareScopeMismatch => ReasonCode::ShareScopeMismatch,
            Self::ServiceIdentityMismatch => ReasonCode::ServiceIdentityMismatch,
        }
    }
}

impl fmt::Display for AccessDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code().as_str())
    }
}

impl std::error::Error for AccessDenied {}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RESOURCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn share() -> ShareGrant {
        ShareGrant::new_read_only(
            ShareGrantId::parse("share_018f2a3b-4c5d-7000-8000-000000000601").unwrap(),
            TenantId::parse("tenant_a").unwrap(),
            SiteId::parse("site_a").unwrap(),
            ShareTokenFingerprint::parse(TOKEN).unwrap(),
            ResourceType::parse("record").unwrap(),
            ResourceKeyHmac::parse(RESOURCE).unwrap(),
            OperationId::parse("records.share.read").unwrap(),
            ViewProfile::parse("shared_summary").unwrap(),
            UnixSeconds::new(200),
            UnixSeconds::new(100),
        )
        .unwrap()
    }

    #[test]
    fn limited_share_is_exact_and_read_only() {
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let token = ShareTokenFingerprint::parse(TOKEN).unwrap();
        let resource_type = ResourceType::parse("record").unwrap();
        let resource = ResourceKeyHmac::parse(RESOURCE).unwrap();
        let operation = OperationId::parse("records.share.read").unwrap();
        let view = ViewProfile::parse("shared_summary").unwrap();
        let share = share();
        assert_eq!(
            share.authorize(
                &tenant,
                &site,
                &token,
                &resource_type,
                &resource,
                &operation,
                &view,
                HttpMethod::Get,
                UnixSeconds::new(150),
            ),
            Ok(())
        );
        assert_eq!(
            share.authorize(
                &tenant,
                &site,
                &token,
                &resource_type,
                &resource,
                &operation,
                &view,
                HttpMethod::Post,
                UnixSeconds::new(150),
            ),
            Err(AccessDenied::ShareScopeMismatch)
        );
    }
}
