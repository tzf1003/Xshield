//! Authorization of management API keys.
//!
//! People and the static machine credential are authorized by role. A key
//! principal carries no roles, so every role-gated route denies it; the only
//! way a key is accepted is through the exact `(site, capability)` rules in
//! this module. The table below is the single place that says which route
//! needs which capability, and anything not listed is closed to keys.

use super::{AccessAction, ControlPlane, EndpointResult, identity, site_config};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::{collections::BTreeSet, sync::Arc};
use xshield_core::{
    admin::{ApiKeyCapability, ApiKeyGrant, ManagementPrincipal, ManagementRole},
    domain::{SiteId, TenantId},
};
use xshield_postgres::{ProtectedSiteConfigListItem, StoreError};

/// Capability a key must hold, for the addressed site, to reach `action`.
///
/// `None` closes the route to keys altogether: site deletion, approval and
/// every route outside site management. Matching is on the exact method and
/// route constant of the action, so a route added later is denied to keys
/// until it is listed here.
pub(crate) fn capability_for(action: &AccessAction) -> Option<ApiKeyCapability> {
    use ApiKeyCapability as Capability;
    match (action.method, action.path) {
        (
            "GET",
            site_config::SITES_PATH
            | site_config::SITE_PATH
            | site_config::SITE_CONFIG_PATH
            | site_config::SITE_STATUS_PATH
            | site_config::SITE_REVISIONS_PATH
            | site_config::PATH,
        ) => Some(Capability::SiteRead),
        ("POST", site_config::SITES_PATH) => Some(Capability::SiteCreate),
        ("PUT", site_config::SITE_CONFIG_PATH | site_config::PATH)
        | ("PATCH", site_config::SITE_PATH) => Some(Capability::SiteConfigWrite),
        ("GET", site_config::SITE_HEALTH_PATH) => Some(Capability::SiteHealthRead),
        ("POST", site_config::SITE_VALIDATE_PATH) => Some(Capability::SiteConfigValidate),
        ("POST", site_config::SITE_APPLY_PATH) => Some(Capability::SiteConfigApplyDirect),
        ("POST", site_config::SITE_ROLLBACK_PATH) => Some(Capability::SiteRollback),
        _ => None,
    }
}

/// Roles an issuer must hold on the target site to hand out `capability`.
///
/// A key must never exceed the authority of whoever issued it, so each entry
/// is the set of roles gating every route the capability unlocks. Direct apply
/// skips the independent approval, which makes it equivalent to approving and
/// publishing: the issuer needs both authorities.
pub(crate) fn issuer_roles(capability: ApiKeyCapability) -> &'static [ManagementRole] {
    match capability {
        ApiKeyCapability::SiteRead => &[ManagementRole::SystemAdmin, ManagementRole::Observer],
        ApiKeyCapability::SiteHealthRead => &[ManagementRole::Observer],
        ApiKeyCapability::SiteCreate | ApiKeyCapability::SiteConfigWrite => {
            &[ManagementRole::SystemAdmin]
        }
        ApiKeyCapability::SiteConfigValidate => &[ManagementRole::PolicyAuthor],
        ApiKeyCapability::SiteConfigApplyDirect => &[
            ManagementRole::ReleaseOperator,
            ManagementRole::PolicyApprover,
        ],
        ApiKeyCapability::SiteRollback => &[ManagementRole::ReleaseOperator],
    }
}

/// Whether `issuer` could itself exercise `grant` (same site, or tenant-wide
/// for the tenant-wide capability).
pub(crate) fn issuer_may_grant(issuer: &ManagementPrincipal, grant: &ApiKeyGrant) -> bool {
    if issuer.is_api_key() {
        return false;
    }
    issuer_roles(grant.capability())
        .iter()
        .all(|role| match grant.site() {
            Some(site) => issuer.authorizes_site(*role, grant.tenant(), site),
            None => issuer.authorizes_tenant(*role, grant.tenant()),
        })
}

/// Site id addressed by `POST /control/v1/sites/{site_id}/apply`, if `path` is
/// exactly that route. Used to bind the direct-apply flag to one site; an
/// unparseable or percent-encoded id yields `None`, which keeps the approval
/// requirement in force.
pub(crate) fn apply_target_site(path: &str) -> Option<SiteId> {
    let site = path
        .strip_prefix("/control/v1/sites/")?
        .strip_suffix("/apply")?;
    SiteId::parse(site).ok()
}

/// Sites a principal may see in a listing or projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SiteVisibility {
    /// Every site of the tenant (tenant-scoped administrators).
    Tenant,
    /// Exactly these sites.
    Sites(BTreeSet<SiteId>),
}

impl SiteVisibility {
    pub(crate) fn allows(&self, site_id: &str) -> bool {
        match self {
            Self::Tenant => true,
            Self::Sites(sites) => sites.iter().any(|site| site.as_str() == site_id),
        }
    }
}

/// Sites a principal may project: the sites its key can read, the whole tenant
/// for a tenant-scoped administrator, otherwise only its exact scoped sites.
/// `None` when the principal has no standing to see sites at all.
pub(crate) fn projected_sites(
    principal: &ManagementPrincipal,
    tenant: &TenantId,
    admin_role: ManagementRole,
) -> Option<SiteVisibility> {
    if principal.is_api_key() {
        return principal
            .holds_capability_in_tenant(ApiKeyCapability::SiteRead, tenant)
            .then(|| {
                SiteVisibility::Sites(
                    principal.capability_sites(ApiKeyCapability::SiteRead, tenant),
                )
            });
    }
    if principal.authorizes_tenant(admin_role, tenant) {
        return Some(SiteVisibility::Tenant);
    }
    let exact = principal.exact_scope_sites(admin_role, tenant);
    (!exact.is_empty()).then_some(SiteVisibility::Sites(exact))
}

/// Rows scanned per page and pages scanned per request when a scoped principal
/// lists sites. The scan is bounded so a tenant with many sites cannot turn a
/// key's listing into an unbounded table walk.
const SCAN_PAGE: u16 = 128;
const SCAN_PAGES_MAX: usize = 16;

/// Lists up to `limit` visible site configurations after `after`.
///
/// Tenant-wide visibility is a single store read. A scoped principal's pages
/// are filtered inside the store scan so a cursor can only ever name a site
/// the principal may see.
pub(crate) async fn list_visible_site_configs(
    control: &ControlPlane,
    visibility: &SiteVisibility,
    after: Option<&str>,
    limit: u16,
) -> Result<Vec<ProtectedSiteConfigListItem>, StoreError> {
    let SiteVisibility::Sites(sites) = visibility else {
        return control
            .catalog
            .list_protected_site_configs(&control.config.tenant_id, after, limit)
            .await;
    };
    let wanted = usize::from(limit);
    let mut visible = Vec::new();
    let mut cursor = after.map(str::to_owned);
    for _ in 0..SCAN_PAGES_MAX {
        let page = control
            .catalog
            .list_protected_site_configs(&control.config.tenant_id, cursor.as_deref(), SCAN_PAGE)
            .await?;
        let exhausted = page.len() < usize::from(SCAN_PAGE);
        cursor = page.last().map(|item| item.site_id.clone());
        visible.extend(
            page.into_iter()
                .filter(|item| visibility.allows(&item.site_id)),
        );
        if visible.len() >= wanted || exhausted || visible.len() >= sites.len() {
            break;
        }
    }
    visible.truncate(wanted);
    Ok(visible)
}

fn forbidden(
    control: &ControlPlane,
    request_id: &str,
    subject: &str,
    action: AccessAction,
) -> Box<EndpointResult> {
    Box::new(control.audited_error(
        request_id,
        Some(subject),
        action,
        None,
        StatusCode::FORBIDDEN,
        "CONTROL_SCOPE_DENIED",
        "management operation forbidden",
        false,
        "request_scope",
    ))
}

impl ControlPlane {
    /// Authorizes a tenant-level route (listing, creation) and reports which
    /// sites the caller may see. Roles decide for people; for a key the route's
    /// capability must be held, tenant-wide for creation and on at least one
    /// site for listing.
    pub(crate) fn authorize_tenant_with_visibility(
        &self,
        authorization: Option<&str>,
        request_id: &str,
        action: AccessAction,
    ) -> Result<(String, SiteVisibility), Box<EndpointResult>> {
        let identity = self.authenticate_request(authorization, request_id, action)?;
        let principal = &identity.principal;
        let tenant = &self.config.tenant_id;
        let visibility = if principal.is_api_key() {
            capability_for(&action)
                .filter(|capability| principal.holds_capability_in_tenant(*capability, tenant))
                .map(|capability| {
                    SiteVisibility::Sites(principal.capability_sites(capability, tenant))
                })
        } else {
            principal
                .authorizes_tenant(action.role, tenant)
                .then_some(SiteVisibility::Tenant)
        };
        match visibility {
            Some(visibility) => Ok((principal.subject().to_owned(), visibility)),
            None => Err(forbidden(self, request_id, principal.subject(), action)),
        }
    }

    /// Like `authorize_any_identity`, but a key is accepted only when it holds
    /// `capability` (on at least one site); it is never matched by role.
    pub(crate) fn authorize_any_identity_or_capability(
        &self,
        authorization: Option<&str>,
        request_id: &str,
        action: AccessAction,
        roles: &[ManagementRole],
        capability: ApiKeyCapability,
    ) -> Result<identity::VerifiedRequestIdentity, Box<EndpointResult>> {
        let identity = self.authenticate_request(authorization, request_id, action)?;
        let principal = &identity.principal;
        let allowed = if principal.is_api_key() {
            principal.holds_capability_in_tenant(capability, &self.config.tenant_id)
        } else {
            roles.iter().any(|role| {
                principal.authorizes(*role, &self.config.tenant_id, &self.config.site_id)
            })
        };
        if allowed {
            Ok(identity)
        } else {
            Err(forbidden(self, request_id, principal.subject(), action))
        }
    }

    /// Extra rules for a key's site write that `(site, capability)` cannot
    /// express, because the write handlers are idempotent upserts:
    ///
    /// * `POST /sites` (creation) must not overwrite a site that exists unless
    ///   the key could also write it, otherwise `site.create` would be a
    ///   backdoor to every site's configuration;
    /// * a `PUT` must not create a site, which needs the tenant-wide
    ///   `site.create`.
    ///
    /// People and the static credential are unaffected. Returns the response to
    /// send when the write must not proceed.
    pub(crate) async fn guard_api_key_site_write(
        self: &Arc<Self>,
        authorization: Option<&str>,
        request_id: &str,
        subject: &str,
        action: AccessAction,
        site_id: &SiteId,
    ) -> Option<Response> {
        let principal = self
            .auth_context_key
            .as_deref()
            .zip(authorization)
            .and_then(|(key, value)| identity::verify_request_assertion(value, key))
            .map(|identity| identity.principal)
            .filter(ManagementPrincipal::is_api_key)?;
        // PATCH merges into an existing site and the handler already answers
        // 404 for a missing one, so only POST and PUT can create.
        if !matches!(action.method, "POST" | "PUT") {
            return None;
        }
        let tenant = &self.config.tenant_id;
        let exists = match self
            .catalog
            .read_protected_site_config(tenant, site_id)
            .await
        {
            Ok(record) => record.is_some(),
            Err(_) => {
                return Some(
                    self.audited_error_async(
                        request_id.to_owned(),
                        Some(subject.to_owned()),
                        action,
                        None,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_API_KEY_UNAVAILABLE",
                        "management service unavailable",
                        true,
                        "retry_later",
                    )
                    .await
                    .into_response(),
                );
            }
        };
        if action.method == "POST" && exists {
            if principal.authorizes_capability(ApiKeyCapability::SiteConfigWrite, tenant, site_id) {
                return None;
            }
            return Some(
                self.audited_error_async(
                    request_id.to_owned(),
                    Some(subject.to_owned()),
                    action,
                    None,
                    StatusCode::CONFLICT,
                    "CONTROL_API_KEY_SITE_EXISTS",
                    "site already exists",
                    false,
                    "correct_request",
                )
                .await
                .into_response(),
            );
        }
        if action.method == "PUT"
            && !exists
            && !principal.authorizes_capability(ApiKeyCapability::SiteCreate, tenant, site_id)
        {
            return Some(
                self.audited_error_async(
                    request_id.to_owned(),
                    Some(subject.to_owned()),
                    action,
                    None,
                    StatusCode::FORBIDDEN,
                    "CONTROL_SCOPE_DENIED",
                    "management operation forbidden",
                    false,
                    "request_scope",
                )
                .await
                .into_response(),
            );
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::admin::API_KEY_TENANT_WIDE_MARKER;

    fn action(method: &'static str, path: &'static str) -> AccessAction {
        AccessAction {
            event_type: "console.test",
            method,
            path,
            role: ManagementRole::Observer,
        }
    }

    #[test]
    fn every_site_route_maps_to_exactly_the_documented_capability() {
        use ApiKeyCapability as C;
        for (method, path, expected) in [
            ("GET", site_config::SITES_PATH, Some(C::SiteRead)),
            ("POST", site_config::SITES_PATH, Some(C::SiteCreate)),
            ("GET", site_config::SITE_PATH, Some(C::SiteRead)),
            ("PATCH", site_config::SITE_PATH, Some(C::SiteConfigWrite)),
            ("DELETE", site_config::SITE_PATH, None),
            ("GET", site_config::SITE_CONFIG_PATH, Some(C::SiteRead)),
            (
                "PUT",
                site_config::SITE_CONFIG_PATH,
                Some(C::SiteConfigWrite),
            ),
            ("GET", site_config::SITE_STATUS_PATH, Some(C::SiteRead)),
            ("GET", site_config::SITE_REVISIONS_PATH, Some(C::SiteRead)),
            (
                "GET",
                site_config::SITE_HEALTH_PATH,
                Some(C::SiteHealthRead),
            ),
            (
                "POST",
                site_config::SITE_VALIDATE_PATH,
                Some(C::SiteConfigValidate),
            ),
            (
                "POST",
                site_config::SITE_APPLY_PATH,
                Some(C::SiteConfigApplyDirect),
            ),
            ("POST", site_config::SITE_APPROVE_PATH, None),
            (
                "POST",
                site_config::SITE_ROLLBACK_PATH,
                Some(C::SiteRollback),
            ),
            ("GET", site_config::PATH, Some(C::SiteRead)),
            ("PUT", site_config::PATH, Some(C::SiteConfigWrite)),
            // Wrong method for a known route, and routes outside site management.
            ("PUT", site_config::SITE_STATUS_PATH, None),
            ("POST", site_config::SITE_CONFIG_PATH, None),
            ("GET", "/control/v1/agent-api-keys", None),
            ("POST", "/control/v1/agent-api-keys", None),
            ("GET", "/control/v1/grants/{grant_id}", None),
            ("GET", "/control/v1/workbench/overview", None),
            ("GET", "/control/v1/*", None),
        ] {
            assert_eq!(
                capability_for(&action(method, path)),
                expected,
                "{method} {path}"
            );
        }
    }

    #[test]
    fn issuers_must_hold_every_role_that_gates_what_they_grant() {
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let person = |roles: &[ManagementRole]| {
            ManagementPrincipal::new_tenant_scoped(
                "person",
                roles.iter().copied(),
                [tenant.clone()],
            )
            .unwrap()
        };
        let grant = |capability: ApiKeyCapability| {
            let site_id = if capability.is_tenant_wide() {
                API_KEY_TENANT_WIDE_MARKER
            } else {
                site.as_str()
            };
            ApiKeyGrant::from_scope_row(tenant.clone(), site_id, capability).unwrap()
        };
        let admin_only = person(&[
            ManagementRole::SystemAdmin,
            ManagementRole::KeyAdministrator,
        ]);
        assert!(issuer_may_grant(
            &admin_only,
            &grant(ApiKeyCapability::SiteConfigWrite)
        ));
        assert!(issuer_may_grant(
            &admin_only,
            &grant(ApiKeyCapability::SiteCreate)
        ));
        for refused in [
            ApiKeyCapability::SiteConfigApplyDirect,
            ApiKeyCapability::SiteRollback,
            ApiKeyCapability::SiteConfigValidate,
            ApiKeyCapability::SiteHealthRead,
            ApiKeyCapability::SiteRead,
        ] {
            assert!(
                !issuer_may_grant(&admin_only, &grant(refused)),
                "{refused:?}"
            );
        }
        let releaser = person(&[
            ManagementRole::ReleaseOperator,
            ManagementRole::PolicyApprover,
        ]);
        assert!(issuer_may_grant(
            &releaser,
            &grant(ApiKeyCapability::SiteConfigApplyDirect)
        ));
        assert!(issuer_may_grant(
            &releaser,
            &grant(ApiKeyCapability::SiteRollback)
        ));
        let key_admin_only = person(&[ManagementRole::KeyAdministrator]);
        for capability in ApiKeyCapability::ALL {
            assert!(!issuer_may_grant(&key_admin_only, &grant(capability)));
        }
        // An issuer with only an exact site scope cannot grant tenant-wide creation
        // nor another site.
        let scoped = ManagementPrincipal::new(
            "scoped",
            [ManagementRole::SystemAdmin],
            [(tenant.clone(), site.clone())],
        )
        .unwrap();
        assert!(issuer_may_grant(
            &scoped,
            &grant(ApiKeyCapability::SiteConfigWrite)
        ));
        assert!(!issuer_may_grant(
            &scoped,
            &grant(ApiKeyCapability::SiteCreate)
        ));
        let other = ApiKeyGrant::from_scope_row(
            tenant.clone(),
            "site_b",
            ApiKeyCapability::SiteConfigWrite,
        )
        .unwrap();
        assert!(!issuer_may_grant(&scoped, &other));
        // A key can never issue.
        let key =
            ManagementPrincipal::new_api_key("apikey:key_x:a", [grant(ApiKeyCapability::SiteRead)])
                .unwrap();
        assert!(!issuer_may_grant(&key, &grant(ApiKeyCapability::SiteRead)));
    }

    #[test]
    fn direct_apply_is_bound_to_the_site_in_the_apply_route_only() {
        assert_eq!(
            apply_target_site("/control/v1/sites/site_a/apply")
                .map(|site| site.as_str().to_owned()),
            Some("site_a".to_owned())
        );
        for path in [
            "/control/v1/sites/site_a/apply/",
            "/control/v1/sites/site_a/applyx",
            "/control/v1/sites/site_a/validate",
            "/control/v1/sites//apply",
            "/control/v1/sites/a/b/apply",
            "/control/v1/sites/site%5Fa/apply",
            "/control/v1/sites/site_a",
            "/other/control/v1/sites/site_a/apply",
        ] {
            assert!(apply_target_site(path).is_none(), "{path}");
        }
    }

    #[test]
    fn projections_never_widen_beyond_what_the_principal_may_see() {
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = |value: &str| SiteId::parse(value).unwrap();
        let grant = |site_id: &str, capability: ApiKeyCapability| {
            ApiKeyGrant::from_scope_row(tenant.clone(), site_id, capability).unwrap()
        };
        let reader = ManagementPrincipal::new_api_key(
            "apikey:key_x:a",
            [
                grant("site_a", ApiKeyCapability::SiteRead),
                grant("site_b", ApiKeyCapability::SiteConfigWrite),
            ],
        )
        .unwrap();
        assert_eq!(
            projected_sites(&reader, &tenant, ManagementRole::SystemAdmin),
            Some(SiteVisibility::Sites(
                [site("site_a")].into_iter().collect()
            ))
        );
        let writer = ManagementPrincipal::new_api_key(
            "apikey:key_x:a",
            [grant("site_b", ApiKeyCapability::SiteConfigWrite)],
        )
        .unwrap();
        assert_eq!(
            projected_sites(&writer, &tenant, ManagementRole::SystemAdmin),
            None
        );
        let tenant_admin = ManagementPrincipal::new_tenant_scoped(
            "p",
            [ManagementRole::SystemAdmin],
            [tenant.clone()],
        )
        .unwrap();
        assert_eq!(
            projected_sites(&tenant_admin, &tenant, ManagementRole::SystemAdmin),
            Some(SiteVisibility::Tenant)
        );
        let exact_admin = ManagementPrincipal::new(
            "p",
            [ManagementRole::SystemAdmin],
            [(tenant.clone(), site("site_default"))],
        )
        .unwrap();
        assert_eq!(
            projected_sites(&exact_admin, &tenant, ManagementRole::SystemAdmin),
            Some(SiteVisibility::Sites(
                [site("site_default")].into_iter().collect()
            ))
        );
        let observer = ManagementPrincipal::new_tenant_scoped(
            "p",
            [ManagementRole::Observer],
            [tenant.clone()],
        )
        .unwrap();
        assert_eq!(
            projected_sites(&observer, &tenant, ManagementRole::SystemAdmin),
            None
        );
        assert!(SiteVisibility::Tenant.allows("anything"));
        let only = SiteVisibility::Sites([site("site_a")].into_iter().collect());
        assert!(only.allows("site_a"));
        assert!(!only.allows("site_b"));
    }
}
