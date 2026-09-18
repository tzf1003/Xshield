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
}

impl ManagementPrincipal {
    /// Builds a management principal from independently authenticated claims.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] when the subject is empty or oversized.
    pub fn new(
        subject: impl Into<String>,
        roles: impl IntoIterator<Item = ManagementRole>,
        scopes: impl IntoIterator<Item = (TenantId, SiteId)>,
    ) -> Result<Self, InvalidValue> {
        let subject = subject.into();
        if subject.is_empty() || subject.len() > 256 || subject.chars().any(char::is_control) {
            return Err(InvalidValue::new("management_subject"));
        }
        Ok(Self {
            subject,
            roles: roles.into_iter().collect(),
            scopes: scopes.into_iter().collect(),
        })
    }

    /// Checks both role and tenant/site scope. It has no external effects.
    #[must_use]
    pub fn authorizes(&self, role: ManagementRole, tenant: &TenantId, site: &SiteId) -> bool {
        self.roles.contains(&role) && self.scopes.contains(&(tenant.clone(), site.clone()))
    }

    #[must_use]
    /// Returns the independently authenticated management subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

#[cfg(test)]
mod tests {
    use super::{ManagementPrincipal, ManagementRole};
    use crate::domain::{SiteId, TenantId};

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
