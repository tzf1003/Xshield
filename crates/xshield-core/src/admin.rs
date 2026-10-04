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

/// Site-management capability a management API key can hold on one scope row.
///
/// Each capability unlocks a fixed set of control-plane routes and nothing
/// else. None implies another and none maps onto a human [`ManagementRole`]:
/// a key principal carries no roles, so no role-gated route (investigation,
/// evidence, key administration) is ever reachable with a key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApiKeyCapability {
    /// List, read configuration, status and revisions of one site.
    SiteRead,
    /// Create new sites. Not tied to any existing site, so it is granted only
    /// with the tenant-wide marker ([`API_KEY_TENANT_WIDE_MARKER`]).
    SiteCreate,
    /// Write (`PUT`/`PATCH`) the configuration of one existing site.
    SiteConfigWrite,
    /// Validate the persisted configuration of one site.
    SiteConfigValidate,
    /// Apply one site's desired revision without an independent approver.
    SiteConfigApplyDirect,
    /// Read the health observation of one site.
    SiteHealthRead,
    /// Roll one site back to a confirmed snapshot.
    SiteRollback,
}

/// Wire and storage marker that scopes `site.create` to the whole tenant.
///
/// A scope row stores a concrete site id for every other capability. The marker
/// is a syntactically valid site id so the existing storage constraints accept
/// it; [`ApiKeyGrant::from_scope_row`] reserves it so that a site with this
/// name can never be granted any capability.
pub const API_KEY_TENANT_WIDE_MARKER: &str = "__tenant__";

impl ApiKeyCapability {
    /// Every capability, in documentation order.
    pub const ALL: [Self; 7] = [
        Self::SiteRead,
        Self::SiteCreate,
        Self::SiteConfigWrite,
        Self::SiteConfigValidate,
        Self::SiteConfigApplyDirect,
        Self::SiteHealthRead,
        Self::SiteRollback,
    ];

    /// Returns the stable wire name stored in scope rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SiteRead => "site.read",
            Self::SiteCreate => "site.create",
            Self::SiteConfigWrite => "site.config.write",
            Self::SiteConfigValidate => "site.config.validate",
            Self::SiteConfigApplyDirect => "site.config.apply_direct",
            Self::SiteHealthRead => "site.health.read",
            Self::SiteRollback => "site.rollback",
        }
    }

    /// Parses an exact wire name; unknown names are never guessed.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.as_str() == value)
    }

    /// Whether the capability applies to the tenant rather than to one site.
    #[must_use]
    pub const fn is_tenant_wide(self) -> bool {
        matches!(self, Self::SiteCreate)
    }
}

/// One exact `(tenant, site, capability)` authority carried by a key.
///
/// `site` is `None` only for the tenant-wide capability, and a tenant-wide
/// capability never has a site: the combination is enforced at construction so
/// an authority can neither silently widen nor be silently narrowed.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ApiKeyGrant {
    tenant: TenantId,
    site: Option<SiteId>,
    capability: ApiKeyCapability,
}

impl ApiKeyGrant {
    /// Builds a grant from already typed parts.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] when a tenant-wide capability names a site or a
    /// site capability names none.
    pub fn new(
        tenant: TenantId,
        site: Option<SiteId>,
        capability: ApiKeyCapability,
    ) -> Result<Self, InvalidValue> {
        if capability.is_tenant_wide() != site.is_none() {
            return Err(InvalidValue::new("api_key_grant"));
        }
        Ok(Self {
            tenant,
            site,
            capability,
        })
    }

    /// Builds a grant from a stored or requested scope row.
    ///
    /// The tenant-wide capability requires [`API_KEY_TENANT_WIDE_MARKER`] and
    /// every other capability requires a concrete site that is not the marker.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for any other combination or an invalid site id.
    pub fn from_scope_row(
        tenant: TenantId,
        site_id: &str,
        capability: ApiKeyCapability,
    ) -> Result<Self, InvalidValue> {
        let marker = site_id == API_KEY_TENANT_WIDE_MARKER;
        if marker != capability.is_tenant_wide() {
            return Err(InvalidValue::new("api_key_grant"));
        }
        let site = if marker {
            None
        } else {
            Some(SiteId::parse(site_id)?)
        };
        Self::new(tenant, site, capability)
    }

    /// Returns the tenant the authority is bound to.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Returns the site, or `None` for the tenant-wide capability.
    #[must_use]
    pub fn site(&self) -> Option<&SiteId> {
        self.site.as_ref()
    }

    /// Returns the granted capability.
    #[must_use]
    pub fn capability(&self) -> ApiKeyCapability {
        self.capability
    }

    /// Returns the value stored in a scope row's `site_id` column.
    #[must_use]
    pub fn scope_site_id(&self) -> &str {
        self.site
            .as_ref()
            .map_or(API_KEY_TENANT_WIDE_MARKER, SiteId::as_str)
    }
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
    /// `Some` only for API-key principals: their exact authorities. Such a
    /// principal has no roles and no role-style scope, so every role check
    /// below is false for it by construction.
    api_key_grants: Option<BTreeSet<ApiKeyGrant>>,
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
            api_key_grants: None,
        })
    }

    /// Builds the principal of an authenticated management API key.
    ///
    /// It carries exactly the supplied authorities and no role, no role-style
    /// site scope and no tenant scope, so `authorizes*` and every role-gated
    /// route deny it. Only [`Self::authorizes_capability`] and
    /// [`Self::holds_capability_in_tenant`] can accept it.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for an invalid subject or an empty grant set.
    pub fn new_api_key(
        subject: impl Into<String>,
        grants: impl IntoIterator<Item = ApiKeyGrant>,
    ) -> Result<Self, InvalidValue> {
        let mut principal = Self::new(subject, [], [])?;
        let grants: BTreeSet<ApiKeyGrant> = grants.into_iter().collect();
        if grants.is_empty() {
            return Err(InvalidValue::new("api_key_grants"));
        }
        principal.api_key_grants = Some(grants);
        Ok(principal)
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

    /// Returns whether this principal is an API key rather than a person or
    /// the static machine credential.
    #[must_use]
    pub fn is_api_key(&self) -> bool {
        self.api_key_grants.is_some()
    }

    /// Returns the exact authorities of an API-key principal (empty otherwise).
    pub fn api_key_grants(&self) -> impl Iterator<Item = &ApiKeyGrant> {
        self.api_key_grants.iter().flatten()
    }

    /// Checks one `(site, capability)` pair against the scope rows that name
    /// that exact site. A tenant-wide capability matches any site of its
    /// tenant; every other capability matches only its own site, never the
    /// union of a key's sites and never another capability.
    #[must_use]
    pub fn authorizes_capability(
        &self,
        capability: ApiKeyCapability,
        tenant: &TenantId,
        site: &SiteId,
    ) -> bool {
        self.api_key_grants().any(|grant| {
            grant.capability == capability
                && grant.tenant == *tenant
                && (capability.is_tenant_wide() || grant.site.as_ref() == Some(site))
        })
    }

    /// Whether the key holds the capability for the tenant at all (for a
    /// site-bound capability: on at least one of its sites). Used for routes
    /// that enumerate and then filter by [`Self::capability_sites`].
    #[must_use]
    pub fn holds_capability_in_tenant(
        &self,
        capability: ApiKeyCapability,
        tenant: &TenantId,
    ) -> bool {
        self.api_key_grants()
            .any(|grant| grant.capability == capability && grant.tenant == *tenant)
    }

    /// Returns the sites on which the key holds a site-bound capability.
    #[must_use]
    pub fn capability_sites(
        &self,
        capability: ApiKeyCapability,
        tenant: &TenantId,
    ) -> BTreeSet<SiteId> {
        self.api_key_grants()
            .filter(|grant| grant.capability == capability && grant.tenant == *tenant)
            .filter_map(|grant| grant.site.clone())
            .collect()
    }

    /// Returns the sites on which the role holds an exact (non-tenant-wide)
    /// scope; used to bound projections for principals that are not
    /// tenant-scoped.
    #[must_use]
    pub fn exact_scope_sites(&self, role: ManagementRole, tenant: &TenantId) -> BTreeSet<SiteId> {
        if !self.roles.contains(&role) {
            return BTreeSet::new();
        }
        self.scopes
            .iter()
            .filter(|(scope_tenant, _)| scope_tenant == tenant)
            .map(|(_, site)| site.clone())
            .collect()
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
    use super::{
        API_KEY_TENANT_WIDE_MARKER, ApiKeyCapability, ApiKeyGrant, ManagementPrincipal,
        ManagementRole,
    };
    use crate::domain::{SiteId, TenantId};

    fn tenant() -> TenantId {
        TenantId::parse("tenant_a").unwrap()
    }

    fn site(value: &str) -> SiteId {
        SiteId::parse(value).unwrap()
    }

    fn grant(site_id: &str, capability: ApiKeyCapability) -> ApiKeyGrant {
        ApiKeyGrant::from_scope_row(tenant(), site_id, capability).unwrap()
    }

    #[test]
    fn capability_names_round_trip_and_unknown_names_are_refused() {
        for capability in ApiKeyCapability::ALL {
            assert_eq!(
                ApiKeyCapability::parse(capability.as_str()),
                Some(capability)
            );
        }
        for unknown in [
            "",
            "site",
            "site.read ",
            "SITE.READ",
            "site.delete",
            "site.*",
        ] {
            assert_eq!(ApiKeyCapability::parse(unknown), None, "{unknown:?}");
        }
        assert_eq!(
            ApiKeyCapability::ALL
                .into_iter()
                .filter(|capability| capability.is_tenant_wide())
                .collect::<Vec<_>>(),
            [ApiKeyCapability::SiteCreate]
        );
    }

    #[test]
    fn only_site_create_may_and_must_use_the_tenant_wide_marker() {
        let marker = API_KEY_TENANT_WIDE_MARKER;
        for capability in ApiKeyCapability::ALL {
            let with_marker = ApiKeyGrant::from_scope_row(tenant(), marker, capability);
            let with_site = ApiKeyGrant::from_scope_row(tenant(), "site_a", capability);
            assert_eq!(
                with_marker.is_ok(),
                capability == ApiKeyCapability::SiteCreate,
                "{capability:?}"
            );
            assert_eq!(
                with_site.is_ok(),
                capability != ApiKeyCapability::SiteCreate,
                "{capability:?}"
            );
        }
        // The grant keeps the marker out of `SiteId` space and round-trips it.
        let create = grant(marker, ApiKeyCapability::SiteCreate);
        assert!(create.site().is_none());
        assert_eq!(create.scope_site_id(), marker);
        assert!(
            ApiKeyGrant::new(tenant(), Some(site("site_a")), ApiKeyCapability::SiteCreate).is_err()
        );
        assert!(ApiKeyGrant::new(tenant(), None, ApiKeyCapability::SiteRead).is_err());
        assert!(
            ApiKeyGrant::from_scope_row(tenant(), "bad site", ApiKeyCapability::SiteRead).is_err()
        );
    }

    #[test]
    fn key_authority_is_per_site_and_per_capability_without_union_or_roles() {
        let principal = ManagementPrincipal::new_api_key(
            "apikey:key_x:agent",
            [
                grant("site_a", ApiKeyCapability::SiteConfigWrite),
                grant("site_b", ApiKeyCapability::SiteRead),
            ],
        )
        .unwrap();
        assert!(principal.is_api_key());
        let (a, b, c) = (site("site_a"), site("site_b"), site("site_c"));
        assert!(principal.authorizes_capability(ApiKeyCapability::SiteConfigWrite, &tenant(), &a));
        assert!(!principal.authorizes_capability(ApiKeyCapability::SiteConfigWrite, &tenant(), &b));
        assert!(principal.authorizes_capability(ApiKeyCapability::SiteRead, &tenant(), &b));
        assert!(!principal.authorizes_capability(ApiKeyCapability::SiteRead, &tenant(), &a));
        assert!(!principal.authorizes_capability(ApiKeyCapability::SiteRead, &tenant(), &c));
        // A different tenant never matches.
        let other = TenantId::parse("tenant_b").unwrap();
        assert!(!principal.authorizes_capability(ApiKeyCapability::SiteRead, &other, &b));
        assert!(!principal.holds_capability_in_tenant(ApiKeyCapability::SiteRead, &other));
        assert_eq!(
            principal.capability_sites(ApiKeyCapability::SiteRead, &tenant()),
            [b.clone()].into_iter().collect()
        );
        assert!(principal.holds_capability_in_tenant(ApiKeyCapability::SiteConfigWrite, &tenant()));
        assert!(!principal.holds_capability_in_tenant(ApiKeyCapability::SiteCreate, &tenant()));
        // No role of any kind, so every role-gated check refuses it.
        for role in [
            ManagementRole::Observer,
            ManagementRole::Investigator,
            ManagementRole::KeyAdministrator,
            ManagementRole::SystemAdmin,
            ManagementRole::ReleaseOperator,
        ] {
            assert!(!principal.authorizes(role, &tenant(), &a));
            assert!(!principal.authorizes_site(role, &tenant(), &a));
            assert!(!principal.authorizes_tenant(role, &tenant()));
        }
        assert!(principal.roles().is_empty());
    }

    #[test]
    fn tenant_wide_create_matches_any_site_of_its_tenant_only() {
        let principal = ManagementPrincipal::new_api_key(
            "apikey:key_x:agent",
            [grant(
                API_KEY_TENANT_WIDE_MARKER,
                ApiKeyCapability::SiteCreate,
            )],
        )
        .unwrap();
        assert!(principal.authorizes_capability(
            ApiKeyCapability::SiteCreate,
            &tenant(),
            &site("anything")
        ));
        assert!(!principal.authorizes_capability(
            ApiKeyCapability::SiteCreate,
            &TenantId::parse("tenant_b").unwrap(),
            &site("anything")
        ));
        // Creating a site grants no read or write on any site.
        assert!(!principal.authorizes_capability(
            ApiKeyCapability::SiteRead,
            &tenant(),
            &site("anything")
        ));
        assert!(!principal.authorizes_capability(
            ApiKeyCapability::SiteConfigWrite,
            &tenant(),
            &site("anything")
        ));
    }

    #[test]
    fn a_key_principal_needs_grants_and_a_canonical_subject() {
        assert!(ManagementPrincipal::new_api_key("apikey:key_x:agent", []).is_err());
        assert!(
            ManagementPrincipal::new_api_key(
                " apikey",
                [grant("site_a", ApiKeyCapability::SiteRead)]
            )
            .is_err()
        );
        assert!(
            !ManagementPrincipal::new("operator", [ManagementRole::Observer], [])
                .unwrap()
                .is_api_key()
        );
        let exact_scope_principal = ManagementPrincipal::new(
            "operator",
            [ManagementRole::SystemAdmin],
            [(tenant(), site("site_a"))],
        )
        .unwrap();
        assert_eq!(
            exact_scope_principal.exact_scope_sites(ManagementRole::SystemAdmin, &tenant()),
            [site("site_a")].into_iter().collect()
        );
        assert!(
            exact_scope_principal
                .exact_scope_sites(ManagementRole::Observer, &tenant())
                .is_empty()
        );
    }

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
