//! Management identities are distinct from protected-site credentials.

use crate::domain::{InvalidValue, SiteId, TenantId};
use std::collections::BTreeSet;

/// Management roles defined by the v3 control-plane contract.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ManagementRole {
    /// Reads redacted summaries.
    Observer,
    /// Runs scoped investigations and requests evidence.
    Investigator,
    /// Reads approved sensitive evidence.
    SensitiveEvidenceReader,
    /// Approves or denies sensitive-evidence access for another subject.
    SensitiveEvidenceApprover,
    /// Submits policy candidates.
    PolicyAuthor,
    /// Approves policy candidates authored by another subject.
    PolicyApprover,
    /// Publishes approved signed releases.
    ReleaseOperator,
    /// Manages audit retention and integrity.
    AuditAdministrator,
    /// Manages keys without implied evidence-read permission.
    KeyAdministrator,
    /// Manages system configuration without implied evidence-read permission.
    SystemAdmin,
}

/// An authenticated control-plane subject and its server-derived scope.
///
/// This type cannot be built from a protected site's browser cookie. The
/// control-plane authenticator must provide the subject, roles, and scopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementPrincipal {
    subject: String,
    roles: BTreeSet<ManagementRole>,
    scopes: BTreeSet<(TenantId, SiteId)>,
    tenant_scopes: BTreeSet<TenantId>,
}

impl ManagementPrincipal {
    /// Builds a management principal from independently authenticated claims.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for an empty, oversized, control-bearing, or
    /// edge-whitespace subject. Identity text is never silently normalized.
    pub fn new(
        subject: impl Into<String>,
        roles: impl IntoIterator<Item = ManagementRole>,
        scopes: impl IntoIterator<Item = (TenantId, SiteId)>,
    ) -> Result<Self, InvalidValue> {
        let subject = subject.into();
        if subject.is_empty()
            || subject.len() > 256
            || subject.trim() != subject
            || subject.chars().any(char::is_control)
        {
            return Err(InvalidValue::new("management_subject"));
        }
        Ok(Self {
            subject,
            roles: roles.into_iter().collect(),
            scopes: scopes.into_iter().collect(),
            tenant_scopes: BTreeSet::new(),
        })
    }

    /// Builds a management principal that is scoped to every site in the
    /// supplied tenant set. Existing exact site scopes remain available for
    /// endpoints that intentionally require a single site.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] when the subject or tenant scope is invalid.
    pub fn new_tenant_scoped(
        subject: impl Into<String>,
        roles: impl IntoIterator<Item = ManagementRole>,
        tenants: impl IntoIterator<Item = TenantId>,
    ) -> Result<Self, InvalidValue> {
        let mut principal = Self::new(subject, roles, [])?;
        principal.tenant_scopes = tenants.into_iter().collect();
        if principal.tenant_scopes.is_empty() {
            return Err(InvalidValue::new("management_tenant_scope"));
        }
        Ok(principal)
    }

    /// Retains an exact site scope alongside a tenant-wide management scope.
    /// This keeps legacy single-site handlers available while new tenant-wide
    /// site-management endpoints enumerate the same tenant.
    #[must_use]
    pub fn with_exact_site_scope(mut self, tenant: TenantId, site: SiteId) -> Self {
        self.scopes.insert((tenant, site));
        self
    }

    /// Checks both role and tenant/site scope. It has no external effects.
    #[must_use]
    pub fn authorizes(&self, role: ManagementRole, tenant: &TenantId, site: &SiteId) -> bool {
        self.roles.contains(&role) && self.scopes.contains(&(tenant.clone(), site.clone()))
    }

    /// Checks a role against either an exact site scope or a tenant-wide scope.
    #[must_use]
    pub fn authorizes_site(&self, role: ManagementRole, tenant: &TenantId, site: &SiteId) -> bool {
        self.roles.contains(&role)
            && (self.scopes.contains(&(tenant.clone(), site.clone()))
                || self.tenant_scopes.contains(tenant))
    }

    /// Checks whether the principal can enumerate the whole tenant.
    #[must_use]
    pub fn authorizes_tenant(&self, role: ManagementRole, tenant: &TenantId) -> bool {
        self.roles.contains(&role) && self.tenant_scopes.contains(tenant)
    }

    #[must_use]
    /// Returns the independently authenticated management subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the server-derived role set for internal authentication adapters.
    #[must_use]
    pub fn roles(&self) -> &BTreeSet<ManagementRole> {
        &self.roles
    }

    /// Returns whether this principal has a tenant-wide scope.
    #[must_use]
    pub fn has_tenant_scope(&self, tenant: &TenantId) -> bool {
        self.tenant_scopes.contains(tenant)
    }

    /// Returns one exact site scope for request assertion projection.
    #[must_use]
    pub fn first_exact_site_scope(&self) -> Option<(&TenantId, &SiteId)> {
        self.scopes
            .iter()
            .next()
            .map(|(tenant, site)| (tenant, site))
    }

    /// Returns all exact site scopes for signed request projection.
    pub fn exact_site_scopes(&self) -> impl Iterator<Item = (&TenantId, &SiteId)> {
        self.scopes.iter().map(|(tenant, site)| (tenant, site))
    }
}

#[cfg(test)]
mod tests {
    use super::{ManagementPrincipal, ManagementRole};
    use crate::domain::{SiteId, TenantId};

    #[test]
    fn subject_is_canonical_without_changing_identity() {
        for subject in [
            "",
            " ",
            " operator",
            "operator ",
            "\u{2003}operator",
            "operator\n",
        ] {
            assert!(ManagementPrincipal::new(subject, [], []).is_err());
        }
        assert!(ManagementPrincipal::new("界".repeat(86), [], []).is_err());
        for subject in ["operator", "operator name", "管理主体"] {
            let principal = ManagementPrincipal::new(subject, [], []).unwrap();
            assert_eq!(principal.subject(), subject);
        }
    }

    #[test]
    fn requires_role_and_exact_scope() {
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let principal = ManagementPrincipal::new(
            "operator-1",
            [ManagementRole::Observer],
            [(tenant.clone(), site.clone())],
        )
        .unwrap();

        assert!(principal.authorizes(ManagementRole::Observer, &tenant, &site));
        assert!(!principal.authorizes(ManagementRole::Investigator, &tenant, &site));
        assert!(!principal.authorizes(
            ManagementRole::Observer,
            &TenantId::parse("tenant_b").unwrap(),
            &site
        ));
    }
}
