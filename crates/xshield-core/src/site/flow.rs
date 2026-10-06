//! Typed route blocks of the browser UI-action provenance flow (docs/05
//! §5.3.1) and the edge rules that bind them together.
//!
//! These are the control-plane spelling of what the edge compiler accepts as
//! `operations[].issued_by` and `operations[].response.{auth_binding,
//! auth_revoke, page_actions, resource_grant}` plus the `SENSOR_HTML` adapter.
//! Every rule here mirrors a rule of `xshield-gateway` (`compile_response`,
//! `compile_response_kind`, `validate_response_contracts`,
//! `page_actions::compile` and `page_actions::sensor_routes`): the edge
//! applies a tenant snapshot all-or-nothing, so one site that the control
//! plane accepts but the edge refuses would fail every site of the tenant. The
//! gateway parity test (`crates/xshield-gateway/tests/site_config_parity.rs`)
//! feeds the projection of these values through the real edge compiler and
//! fails when the two drift.
//!
//! Where the edge is lenient only because a check runs late or not at all for
//! some configurations, this module is deliberately stricter; see
//! `validate_route_set` for the one such rule (action-descriptor meaning).
//!
//! Trust boundary: the values are operator configuration, validated here
//! before persistence and again by the edge; nothing is derived from traffic.
//! The module is pure: no I/O, no clock.
//!
//! Gateway features this module does not model (`share_issue`,
//! `auth_refresh`, `auth_context_switch`, `evidence_capture`, `COMPATIBILITY`
//! request crypto, `SHARE_ENTRY`/`SERVICE_IDENTITY` admissions) cannot be
//! stored: the typed configuration rejects unknown members, and
//! [`super::unsupported`] names the feature so the control plane can refuse it
//! with a stable reason instead of a generic parse error.

use super::{SecurityEntry, SiteRouteConfig, edge_scoped_value};
use crate::domain::{FieldName, InvalidValue, MappingRevision, OperationId, parse_lower_hex_32};
use crate::query_pagination::QUERY_PAGINATION_INVALID;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, btree_map::Entry};

/// [`InvalidValue`] field for identity establishment and revocation rules
/// (`auth_entry` admission, `auth_binding`, `auth_revoke`).
pub const AUTH_FLOW_INVALID: &str = "site_policy.route.auth_flow";
/// [`InvalidValue`] field for `SENSOR_HTML` adapter rules.
pub const SENSOR_HTML_INVALID: &str = "site_policy.route.sensor_html";
/// [`InvalidValue`] field for page issuance rules (`page_actions`,
/// `issued_by`).
pub const PAGE_ACTIONS_INVALID: &str = "site_policy.route.page_actions";
/// [`InvalidValue`] field for response-derived resource qualification rules.
pub const RESOURCE_GRANT_INVALID: &str = "site_policy.route.resource_grant";
/// [`InvalidValue`] field when one `(action, mapping revision)` would carry
/// two meanings.
pub const ACTION_DESCRIPTOR_CONFLICT: &str = "site_policy.routes.action_descriptor";

/// Gateway `page_actions::MAX_PAGE_ACTIONS`: actions one page delivery issues.
pub const EDGE_MAX_PAGE_ACTIONS: usize = 16;
/// Gateway `page_actions::MAX_ACTIVE_PAGES`: live page instances per binding.
pub const EDGE_MAX_ACTIVE_PAGES: u32 = 1_000;
/// Gateway limit on `additional_adapters` (16 approved builds in total).
const EDGE_MAX_ADDITIONAL_ADAPTERS: usize = 15;
/// Gateway `page_actions::MAX_HARVEST_RULES`, which bounds both the harvest
/// hints and the identity-change routes the browser sensor receives.
const EDGE_MAX_SENSOR_ROUTES: usize = 64;
/// Longest lease or session the edge accepts for any flow block.
const MAX_TTL_SECONDS: u64 = 86_400;
/// Longest JSON Pointer the edge accepts.
const MAX_JSON_POINTER_BYTES: usize = 512;
/// Field profile the edge records for page-issued actions, which expose no
/// request fields.
const PAGE_ACTION_FIELD_PROFILE: &str = "none";

/// Identity establishment on an `auth_entry` route (edge
/// `response.auth_binding`).
///
/// A strict JSON success response must carry the principal, the authorization
/// context and the bearer at the three pointers; the edge then commits a new
/// binding before it releases the body. The pointers must be distinct and the
/// credential may not outlive the session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteAuthBinding {
    /// 2xx status that establishes identity; 204 has no body and is refused.
    pub success_status: u16,
    /// JSON Pointer to the principal.
    pub principal_pointer: String,
    /// JSON Pointer to the authorization context reference.
    pub authorization_context_pointer: String,
    /// JSON Pointer to the business bearer credential.
    pub bearer_pointer: String,
    /// Credential lease, 1–86400 seconds and at most the session lease.
    pub credential_ttl_seconds: u64,
    /// Session lease, 1–86400 seconds.
    pub session_ttl_seconds: u64,
}

/// Binding revocation on an `authenticated_root` logout route (edge
/// `response.auth_revoke`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteAuthRevoke {
    /// 2xx status that revokes; 204–206 are refused because the edge must
    /// see a complete body before it commits the revocation.
    pub success_status: u16,
}

/// One approved page build the sensor adapter may inject into.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteSensorHtmlAdapter {
    /// Scoped adapter revision (letters, digits, `_ - .`, at most 128).
    pub adapter_revision: String,
    /// SHA-256 of the exact origin bytes, 64 lowercase hexadecimal digits.
    pub origin_sha256: String,
    /// Byte offset of `</head>` in those bytes; below the response limit.
    pub injection_offset: usize,
}

/// `SENSOR_HTML` response adapter: the approved builds of a static page.
///
/// The edge only releases an origin page whose complete SHA-256 matches one of
/// these builds, injects the sensor at that build's offset and refuses
/// anything else before the body is released.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteSensorHtml {
    /// Primary build's scoped adapter revision.
    pub adapter_revision: String,
    /// Primary build's SHA-256, 64 lowercase hexadecimal digits.
    pub origin_sha256: String,
    /// Primary build's injection offset.
    pub injection_offset: usize,
    /// Up to 15 further builds; revisions and digests are unique across all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_adapters: Vec<SiteSensorHtmlAdapter>,
}

impl SiteSensorHtml {
    /// Every approved build, primary first.
    fn builds(&self) -> impl Iterator<Item = (&str, &str, usize)> {
        std::iter::once((
            self.adapter_revision.as_str(),
            self.origin_sha256.as_str(),
            self.injection_offset,
        ))
        .chain(self.additional_adapters.iter().map(|adapter| {
            (
                adapter.adapter_revision.as_str(),
                adapter.origin_sha256.as_str(),
                adapter.injection_offset,
            )
        }))
    }
}

/// Page issuance settings of an approved `SENSOR_HTML` page root (edge
/// `response.page_actions`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SitePageActions {
    /// Mapping revision shared by the page evidence and every issued action.
    pub mapping_revision: String,
    /// Live page instances one binding may hold for this page, 1–1000.
    pub max_active_pages: u32,
}

/// Declares that a page root issues this `ui_action_required` operation on
/// every verified delivery (edge `operations[].issued_by`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteIssuedBy {
    /// Operation ID of a route that declares `page_actions`.
    pub page_operation_id: String,
    /// Action lease before session and evidence bounds, 1–86400 seconds.
    pub ttl_seconds: u64,
}

/// Response-derived resource qualification (edge `response.resource_grant`).
///
/// A verified list response qualifies each listed resource for exactly one
/// `ui_action_required` resource route; the edge injects an opaque reference
/// into each item only after it committed the grants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteResourceGrant {
    /// 2xx status of a qualifying response; 204 has no body and is refused.
    pub success_status: u16,
    /// JSON Pointer to the item array.
    pub items_pointer: String,
    /// JSON Pointer, relative to one item, to the resource value.
    pub resource_pointer: String,
    /// Item member that receives the edge-issued reference.
    pub action_ref_field: String,
    /// The `ui_action_required` resource route the grant qualifies.
    pub target_operation_id: String,
    /// Mapping revision of the target's action descriptor.
    pub target_mapping_revision: String,
    /// Reference lease, 1–86400 seconds.
    pub ttl_seconds: u64,
    /// Items one response may qualify, 1–1000.
    pub max_items: usize,
    /// Live grants per binding, 1–5000.
    pub max_active_grants: u32,
}

/// Per-route flow rules; `validate_route_set` holds the cross-route ones.
///
/// Called after the generic route rules, so method, path, admission/source
/// coherence and resource-field shape are already valid.
///
/// # Errors
/// Returns [`InvalidValue`] named by one of this module's field constants.
pub(super) fn validate_route(route: &SiteRouteConfig) -> Result<(), InvalidValue> {
    validate_auth_blocks(route)?;
    validate_sensor_html(route)?;
    validate_page_blocks(route)?;
    validate_resource_grant(route)?;
    validate_query_pagination(route)?;
    // The edge allows at most one identity or issuance effect per response.
    // `auth_binding` and `resource_grant` cannot meet (their admissions
    // differ), so only a logout that also qualifies resources reaches this.
    if usize::from(route.resource_grant.is_some())
        + usize::from(route.auth_binding.is_some())
        + usize::from(route.auth_revoke.is_some())
        > 1
    {
        return Err(InvalidValue::new(AUTH_FLOW_INVALID));
    }
    Ok(())
}

fn validate_auth_blocks(route: &SiteRouteConfig) -> Result<(), InvalidValue> {
    if let Some(binding) = &route.auth_binding
        && (route.security_entry != SecurityEntry::AuthEntry
            || !(200..=299).contains(&binding.success_status)
            || binding.success_status == 204
            || !valid_auth_pointers(
                &binding.principal_pointer,
                &binding.authorization_context_pointer,
                &binding.bearer_pointer,
            )
            || !(1..=MAX_TTL_SECONDS).contains(&binding.credential_ttl_seconds)
            || !(1..=MAX_TTL_SECONDS).contains(&binding.session_ttl_seconds)
            || binding.credential_ttl_seconds > binding.session_ttl_seconds)
    {
        return Err(InvalidValue::new(AUTH_FLOW_INVALID));
    }
    if let Some(revoke) = &route.auth_revoke
        && (route.security_entry != SecurityEntry::AuthenticatedRoot
            || !(200..=299).contains(&revoke.success_status)
            || (204..=206).contains(&revoke.success_status))
    {
        return Err(InvalidValue::new(AUTH_FLOW_INVALID));
    }
    Ok(())
}

fn validate_sensor_html(route: &SiteRouteConfig) -> Result<(), InvalidValue> {
    let invalid = || InvalidValue::new(SENSOR_HTML_INVALID);
    // The mode and the adapter block describe one thing; either without the
    // other cannot be projected faithfully.
    let adapter = match (&route.sensor_html, route.response_mode.as_str()) {
        (None, mode) if mode != "SENSOR_HTML" => return Ok(()),
        (Some(adapter), "SENSOR_HTML") => adapter,
        _ => return Err(invalid()),
    };
    // Injection rewrites a static GET page; it cannot be combined with
    // encryption or any identity or issuance effect.
    if route.method != "GET"
        || route.response_crypto.is_some()
        || route.resource_grant.is_some()
        || route.auth_binding.is_some()
        || route.auth_revoke.is_some()
        || adapter.additional_adapters.len() > EDGE_MAX_ADDITIONAL_ADAPTERS
    {
        return Err(invalid());
    }
    let mut revisions = std::collections::BTreeSet::new();
    let mut digests = std::collections::BTreeSet::new();
    for (revision, digest, offset) in adapter.builds() {
        if !edge_scoped_value(revision)
            || parse_lower_hex_32(digest).is_none()
            || offset >= route.max_response_bytes
            || !revisions.insert(revision)
            || !digests.insert(digest)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_page_blocks(route: &SiteRouteConfig) -> Result<(), InvalidValue> {
    let invalid = || InvalidValue::new(PAGE_ACTIONS_INVALID);
    // A page root is an exact authenticated GET that injects the sensor;
    // `authenticated_root` routes carry no resource binding, so it is exact.
    if let Some(page) = &route.page_actions
        && (route.response_mode != "SENSOR_HTML"
            || route.method != "GET"
            || route.security_entry != SecurityEntry::AuthenticatedRoot
            || MappingRevision::parse(page.mapping_revision.clone()).is_err()
            || !(1..=EDGE_MAX_ACTIVE_PAGES).contains(&page.max_active_pages))
    {
        return Err(invalid());
    }
    // A page issues first-hop actions only: a UI action without a resource
    // binding (and therefore on an exact path).
    if let Some(issued) = &route.issued_by
        && (route.security_entry != SecurityEntry::UiActionRequired
            || route.source_action.is_none()
            || route.resource_type.is_some()
            || route.view_profile.is_some()
            || route.resource_query_parameter.is_some()
            || route.resource_path_parameter.is_some()
            || OperationId::parse(issued.page_operation_id.clone()).is_err()
            || !(1..=MAX_TTL_SECONDS).contains(&issued.ttl_seconds))
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_resource_grant(route: &SiteRouteConfig) -> Result<(), InvalidValue> {
    let Some(grant) = &route.resource_grant else {
        return Ok(());
    };
    if !matches!(
        route.security_entry,
        SecurityEntry::AuthenticatedRoot | SecurityEntry::UiActionRequired
    ) || !(200..=299).contains(&grant.success_status)
        || grant.success_status == 204
        || !valid_json_pointer(&grant.items_pointer)
        || !valid_json_pointer(&grant.resource_pointer)
        || FieldName::parse(grant.action_ref_field.clone()).is_err()
        || OperationId::parse(grant.target_operation_id.clone()).is_err()
        || MappingRevision::parse(grant.target_mapping_revision.clone()).is_err()
        || !(1..=MAX_TTL_SECONDS).contains(&grant.ttl_seconds)
        || !(1..=1_000).contains(&grant.max_items)
        || !(1..=5_000).contains(&grant.max_active_grants)
    {
        return Err(InvalidValue::new(RESOURCE_GRANT_INVALID));
    }
    Ok(())
}

/// `query_pagination` opts a route out of the default "no query string"
/// rule, which only exists where the edge enforces it: a grant-issuing
/// `authenticated_root` list and a `ui_action_required` route without a
/// resource binding. Anywhere else the block would promise an allowlist the
/// edge never applies, so it is refused (gateway `compile_operation`).
fn validate_query_pagination(route: &SiteRouteConfig) -> Result<(), InvalidValue> {
    let Some(block) = &route.query_pagination else {
        return Ok(());
    };
    let applicable = route.method == "GET"
        && match route.security_entry {
            SecurityEntry::AuthenticatedRoot => route.resource_grant.is_some(),
            SecurityEntry::UiActionRequired => {
                route.resource_type.is_none()
                    && route.view_profile.is_none()
                    && route.resource_query_parameter.is_none()
                    && route.resource_path_parameter.is_none()
            }
            _ => false,
        };
    if !applicable {
        return Err(InvalidValue::new(QUERY_PAGINATION_INVALID));
    }
    block.validate()
}

/// What the edge stores for one `(action, mapping revision)` key; two routes
/// deriving different meanings for one key are a conflict.
#[derive(Debug, Eq, PartialEq)]
struct DescriptorMeaning<'a> {
    page_template: &'a str,
    operation_id: &'a str,
    method: &'a str,
    route: &'a str,
    target_resource_type: Option<&'a str>,
    field: Option<&'a str>,
    field_profile: &'a str,
}

/// Cross-route flow rules of the edge compiler.
///
/// Requires unique operation IDs and per-route validity (both checked by the
/// caller first). Pages and issued actions must reference each other with
/// 1–16 actions per page; a resource grant must name an existing
/// `ui_action_required` resource route; the sensor learns at most 64 harvest
/// and 64 identity-change routes.
///
/// One rule is stricter than the edge: the edge derives action descriptors,
/// and refuses one `(action, mapping revision)` with two meanings, only when
/// some page declares `page_actions`. Descriptor rows are keyed by that pair
/// whoever provisions them, so a second meaning is a misconfiguration either
/// way and is refused here unconditionally.
///
/// # Errors
/// Returns [`InvalidValue`] named by one of this module's field constants.
pub(super) fn validate_route_set(routes: &[SiteRouteConfig]) -> Result<(), InvalidValue> {
    let by_id = routes
        .iter()
        .map(|route| (route.operation_id.as_str(), route))
        .collect::<BTreeMap<_, _>>();

    let mut issued_per_page = routes
        .iter()
        .filter(|route| route.page_actions.is_some())
        .map(|page| (page.operation_id.as_str(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for route in routes {
        let Some(issued) = &route.issued_by else {
            continue;
        };
        let count = issued_per_page
            .get_mut(issued.page_operation_id.as_str())
            .ok_or_else(|| InvalidValue::new(PAGE_ACTIONS_INVALID))?;
        *count += 1;
    }
    // An unused `page_actions` is refused like an overfull page.
    if issued_per_page
        .values()
        .any(|count| !(1..=EDGE_MAX_PAGE_ACTIONS).contains(count))
    {
        return Err(InvalidValue::new(PAGE_ACTIONS_INVALID));
    }

    // A pagination name must never double as a resource selector of any
    // route: the caller could then pick the object a "page" parameter names.
    let resource_parameters = routes
        .iter()
        .flat_map(|route| {
            [
                route.resource_query_parameter.as_deref(),
                route.resource_path_parameter.as_deref(),
            ]
        })
        .flatten()
        .collect::<Vec<_>>();
    if routes.iter().any(|route| {
        route
            .query_pagination
            .as_ref()
            .is_some_and(|block| block.collides_with(resource_parameters.iter().copied()))
    }) {
        return Err(InvalidValue::new(QUERY_PAGINATION_INVALID));
    }

    let mut harvest_rules = 0_usize;
    for route in routes {
        let Some(grant) = &route.resource_grant else {
            continue;
        };
        let target = by_id
            .get(grant.target_operation_id.as_str())
            .ok_or_else(|| InvalidValue::new(RESOURCE_GRANT_INVALID))?;
        if target.security_entry != SecurityEntry::UiActionRequired
            || target.source_action.is_none()
            || target.resource_type.is_none()
        {
            return Err(InvalidValue::new(RESOURCE_GRANT_INVALID));
        }
        harvest_rules += 1;
    }
    if harvest_rules > EDGE_MAX_SENSOR_ROUTES {
        return Err(InvalidValue::new(RESOURCE_GRANT_INVALID));
    }
    let identity_change_routes = routes
        .iter()
        .filter(|route| route.auth_binding.is_some() || route.auth_revoke.is_some())
        .count();
    if identity_change_routes > EDGE_MAX_SENSOR_ROUTES {
        return Err(InvalidValue::new(AUTH_FLOW_INVALID));
    }
    validate_descriptor_meanings(routes, &by_id)
}

/// Derives the descriptors the edge would provision and refuses one key with
/// two meanings. Page-issued actions take the page's mapping revision and the
/// page operation as template, expose no fields and no target; a grant target
/// takes the grant's mapping revision, its own operation as template, its
/// resource type as target and its one resource field.
fn validate_descriptor_meanings<'a>(
    routes: &'a [SiteRouteConfig],
    by_id: &BTreeMap<&'a str, &'a SiteRouteConfig>,
) -> Result<(), InvalidValue> {
    let mut descriptors = BTreeMap::<(&str, &str), DescriptorMeaning<'_>>::new();
    let mut insert =
        |key: (&'a str, &'a str), meaning: DescriptorMeaning<'a>| match descriptors.entry(key) {
            Entry::Occupied(existing) if *existing.get() != meaning => {
                Err(InvalidValue::new(ACTION_DESCRIPTOR_CONFLICT))
            }
            Entry::Occupied(_) => Ok(()),
            Entry::Vacant(slot) => {
                slot.insert(meaning);
                Ok(())
            }
        };
    for route in routes {
        let (Some(issued), Some(action)) = (&route.issued_by, &route.source_action) else {
            continue;
        };
        let page = by_id
            .get(issued.page_operation_id.as_str())
            .ok_or_else(|| InvalidValue::new(PAGE_ACTIONS_INVALID))?;
        let mapping = page
            .page_actions
            .as_ref()
            .ok_or_else(|| InvalidValue::new(PAGE_ACTIONS_INVALID))?;
        insert(
            (action.as_str(), mapping.mapping_revision.as_str()),
            DescriptorMeaning {
                page_template: page.operation_id.as_str(),
                operation_id: route.operation_id.as_str(),
                method: route.method.as_str(),
                route: route.path.as_str(),
                target_resource_type: None,
                field: None,
                field_profile: PAGE_ACTION_FIELD_PROFILE,
            },
        )?;
    }
    for route in routes {
        let Some(grant) = &route.resource_grant else {
            continue;
        };
        let target = by_id
            .get(grant.target_operation_id.as_str())
            .ok_or_else(|| InvalidValue::new(RESOURCE_GRANT_INVALID))?;
        let (Some(action), Some(view_profile)) = (&target.source_action, &target.view_profile)
        else {
            return Err(InvalidValue::new(RESOURCE_GRANT_INVALID));
        };
        insert(
            (action.as_str(), grant.target_mapping_revision.as_str()),
            DescriptorMeaning {
                page_template: target.operation_id.as_str(),
                operation_id: target.operation_id.as_str(),
                method: target.method.as_str(),
                route: target.path.as_str(),
                target_resource_type: target.resource_type.as_deref(),
                field: target
                    .resource_query_parameter
                    .as_deref()
                    .or(target.resource_path_parameter.as_deref()),
                field_profile: view_profile.as_str(),
            },
        )?;
    }
    Ok(())
}

/// Gateway `valid_auth_pointers`: three valid, pairwise distinct pointers.
fn valid_auth_pointers(principal: &str, context: &str, bearer: &str) -> bool {
    valid_json_pointer(principal)
        && valid_json_pointer(context)
        && valid_json_pointer(bearer)
        && principal != context
        && principal != bearer
        && context != bearer
}

/// Gateway `valid_json_pointer`: rooted, bounded, no ASCII control byte and
/// every `~` escape is `~0` or `~1`. Non-ASCII text is allowed, as on the edge.
fn valid_json_pointer(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAX_JSON_POINTER_BYTES
        && value.bytes().all(|byte| !byte.is_ascii_control())
        && value
            .as_bytes()
            .windows(2)
            .filter(|pair| pair[0] == b'~')
            .all(|pair| matches!(pair[1], b'0' | b'1'))
        && value.as_bytes().last().is_none_or(|byte| *byte != b'~')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::{SiteConfig, SiteRequestCrypto, SiteResponseCrypto};

    const BROWSER_LOOP: &str = include_str!("../../../../tests/site-config/browser-loop.json");

    type Mutation = fn(&mut SiteConfig);

    /// The real-browser loop topology as the control plane stores it.
    fn flow() -> SiteConfig {
        serde_json::from_str(BROWSER_LOOP).unwrap()
    }

    fn route<'a>(config: &'a mut SiteConfig, id: &str) -> &'a mut SiteRouteConfig {
        config
            .policy
            .routes
            .iter_mut()
            .find(|route| route.operation_id == id)
            .unwrap()
    }

    /// Validates the loop topology after `mutate`; the error names its rule.
    fn verdict(mutate: impl FnOnce(&mut SiteConfig)) -> Result<(), &'static str> {
        let mut config = flow();
        mutate(&mut config);
        config.validate().map_err(|error| error.field())
    }

    fn binding(config: &mut SiteConfig) -> &mut SiteAuthBinding {
        route(config, "auth.login").auth_binding.as_mut().unwrap()
    }

    fn grant(config: &mut SiteConfig) -> &mut SiteResourceGrant {
        route(config, "orders.list")
            .resource_grant
            .as_mut()
            .unwrap()
    }

    fn sensor(config: &mut SiteConfig) -> &mut SiteSensorHtml {
        route(config, "app.page").sensor_html.as_mut().unwrap()
    }

    fn page(config: &mut SiteConfig) -> &mut SitePageActions {
        route(config, "app.page").page_actions.as_mut().unwrap()
    }

    fn issued(config: &mut SiteConfig) -> &mut SiteIssuedBy {
        route(config, "orders.list").issued_by.as_mut().unwrap()
    }

    /// An `auth_entry` POST route with a valid binding.
    fn login_route(id: &str, path: &str) -> SiteRouteConfig {
        let mut config = flow();
        let mut login = route(&mut config, "auth.login").clone();
        login.operation_id = id.to_owned();
        login.path = path.to_owned();
        login
    }

    /// A first-hop UI action route issued by `app.page`.
    fn issued_route(id: &str, path: &str, action: &str) -> SiteRouteConfig {
        let mut config = flow();
        let mut issued = route(&mut config, "orders.list").clone();
        issued.operation_id = id.to_owned();
        issued.path = path.to_owned();
        issued.source_action = Some(action.to_owned());
        issued.resource_grant = None;
        issued
    }

    /// A UI list route (not page-issued) granting `target` under `mapping`.
    fn list_route(id: &str, path: &str, target: &str, mapping: &str) -> SiteRouteConfig {
        let mut config = flow();
        let mut list = route(&mut config, "orders.list").clone();
        list.operation_id = id.to_owned();
        list.path = path.to_owned();
        list.source_action = Some(format!("{id}.open"));
        list.issued_by = None;
        if let Some(grant) = list.resource_grant.as_mut() {
            target.clone_into(&mut grant.target_operation_id);
            mapping.clone_into(&mut grant.target_mapping_revision);
        }
        list
    }

    fn check(cases: Vec<(&str, Mutation, Result<(), &'static str>)>) {
        for (label, mutate, expected) in cases {
            assert_eq!(verdict(mutate), expected, "{label}");
        }
    }

    #[test]
    fn the_loop_topology_is_valid() {
        assert_eq!(verdict(|_| {}), Ok(()));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn identity_establishment_and_revocation_follow_the_edge() {
        let auth = Err(AUTH_FLOW_INVALID);
        check(vec![
            (
                "binding on a root",
                |c| route(c, "auth.login").security_entry = SecurityEntry::AuthenticatedRoot,
                auth,
            ),
            ("status 204", |c| binding(c).success_status = 204, auth),
            ("status 199", |c| binding(c).success_status = 199, auth),
            ("status 300", |c| binding(c).success_status = 300, auth),
            ("status 201", |c| binding(c).success_status = 201, Ok(())),
            (
                "unrooted pointer",
                |c| binding(c).principal_pointer = "identity/id".to_owned(),
                auth,
            ),
            (
                "shared pointer",
                |c| binding(c).bearer_pointer = "/identity/id".to_owned(),
                auth,
            ),
            (
                "bad escape",
                |c| binding(c).bearer_pointer = "/a~2b".to_owned(),
                auth,
            ),
            (
                "trailing tilde",
                |c| binding(c).bearer_pointer = "/a~".to_owned(),
                auth,
            ),
            (
                "valid escapes and non-ASCII",
                |c| binding(c).bearer_pointer = "/a~0b/~1c/\u{e9}".to_owned(),
                Ok(()),
            ),
            (
                "control byte",
                |c| binding(c).bearer_pointer = "/a\u{1}".to_owned(),
                auth,
            ),
            (
                "pointer of 513 bytes",
                |c| binding(c).bearer_pointer = format!("/{}", "a".repeat(512)),
                auth,
            ),
            (
                "pointer of 512 bytes",
                |c| binding(c).bearer_pointer = format!("/{}", "a".repeat(511)),
                Ok(()),
            ),
            (
                "credential 0",
                |c| binding(c).credential_ttl_seconds = 0,
                auth,
            ),
            (
                "credential above session",
                |c| binding(c).credential_ttl_seconds = 3_601,
                auth,
            ),
            (
                "session above a day",
                |c| binding(c).session_ttl_seconds = 86_401,
                auth,
            ),
            (
                "revoke on an auth entry",
                |c| {
                    route(c, "auth.login").auth_revoke = Some(SiteAuthRevoke {
                        success_status: 200,
                    });
                },
                auth,
            ),
            (
                "revoke on a public route",
                |c| route(c, "auth.logout").security_entry = SecurityEntry::Public,
                auth,
            ),
            (
                "revoke status 205",
                |c| {
                    route(c, "auth.logout")
                        .auth_revoke
                        .as_mut()
                        .unwrap()
                        .success_status = 205;
                },
                auth,
            ),
            (
                "revoke status 299",
                |c| {
                    route(c, "auth.logout")
                        .auth_revoke
                        .as_mut()
                        .unwrap()
                        .success_status = 299;
                },
                Ok(()),
            ),
            (
                "logout that also grants",
                |c| {
                    let grant = route(c, "orders.list").resource_grant.clone();
                    route(c, "auth.logout").resource_grant = grant;
                },
                auth,
            ),
            (
                "auth entry without a binding",
                |c| {
                    c.policy.routes.push(SiteRouteConfig {
                        auth_binding: None,
                        ..login_route("auth.reset", "/api/reset")
                    });
                },
                Ok(()),
            ),
            (
                "an observed body cannot feed identity",
                |c| {
                    route(c, "auth.login").request_crypto = Some(SiteRequestCrypto::Observe {
                        adapter_revision: "observe-v1".to_owned(),
                    });
                },
                Err("site_policy.route"),
            ),
        ]);
        // The browser sensor learns at most 64 identity-change routes; the
        // loop already has two (login and logout).
        let with_logins = |count: usize| {
            verdict(|c| {
                for index in 0..count {
                    c.policy.routes.push(login_route(
                        &format!("login.{index}"),
                        &format!("/l/{index}"),
                    ));
                }
            })
        };
        assert_eq!(with_logins(62), Ok(()));
        assert_eq!(with_logins(63), auth);
    }

    fn builds(count: usize) -> Vec<SiteSensorHtmlAdapter> {
        (1..=count)
            .map(|build| SiteSensorHtmlAdapter {
                adapter_revision: format!("app-r{}", build + 1),
                origin_sha256: format!("{build:064x}"),
                injection_offset: 10,
            })
            .collect()
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn sensor_pages_follow_the_edge() {
        let invalid = Err(SENSOR_HTML_INVALID);
        check(vec![
            (
                "mode without adapter",
                |c| route(c, "app.page").sensor_html = None,
                invalid,
            ),
            (
                "adapter without mode",
                |c| route(c, "app.page").response_mode = "BUFFERED_JSON".to_owned(),
                invalid,
            ),
            (
                "POST page",
                |c| route(c, "app.page").method = "POST".to_owned(),
                invalid,
            ),
            (
                "encrypted page",
                |c| {
                    route(c, "app.page").response_crypto = Some(SiteResponseCrypto {
                        mode: "DIRECT_ENCRYPT".to_owned(),
                        adapter_revision: "rev-1".to_owned(),
                        key_id: "key-r".to_owned(),
                        key_not_before: 1,
                        key_expires_at: 2,
                        message_ttl_seconds: 60,
                        max_envelope_bytes: 65_536,
                    });
                },
                invalid,
            ),
            (
                "uppercase digest",
                |c| sensor(c).origin_sha256 = "F".repeat(64),
                invalid,
            ),
            (
                "short digest",
                |c| sensor(c).origin_sha256 = "f".repeat(63),
                invalid,
            ),
            (
                "unscoped revision",
                |c| sensor(c).adapter_revision = "app r1".to_owned(),
                invalid,
            ),
            (
                "offset at the limit",
                |c| sensor(c).injection_offset = 16_384,
                invalid,
            ),
            (
                "offset below the limit",
                |c| sensor(c).injection_offset = 16_383,
                Ok(()),
            ),
            (
                "fifteen more builds",
                |c| sensor(c).additional_adapters = builds(15),
                Ok(()),
            ),
            (
                "sixteen more builds",
                |c| sensor(c).additional_adapters = builds(16),
                invalid,
            ),
            (
                "repeated revision",
                |c| {
                    sensor(c).additional_adapters = vec![SiteSensorHtmlAdapter {
                        adapter_revision: "app-r1".to_owned(),
                        origin_sha256: "b".repeat(64),
                        injection_offset: 10,
                    }];
                },
                invalid,
            ),
            (
                "repeated digest",
                |c| {
                    let digest = sensor(c).origin_sha256.clone();
                    sensor(c).additional_adapters = vec![SiteSensorHtmlAdapter {
                        adapter_revision: "app-r2".to_owned(),
                        origin_sha256: digest,
                        injection_offset: 10,
                    }];
                },
                invalid,
            ),
            (
                "public page without issuance",
                |c| {
                    let page = route(c, "login.page");
                    page.response_mode = "SENSOR_HTML".to_owned();
                    page.sensor_html = Some(SiteSensorHtml {
                        adapter_revision: "login-r1".to_owned(),
                        origin_sha256: "c".repeat(64),
                        injection_offset: 10,
                        additional_adapters: Vec::new(),
                    });
                },
                Ok(()),
            ),
            ("sensor disabled", |c| c.sensor_enabled = false, invalid),
        ]);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn page_issuance_follows_the_edge() {
        let invalid = Err(PAGE_ACTIONS_INVALID);
        check(vec![
            (
                "page actions on a JSON route",
                |c| {
                    route(c, "orders.list").page_actions = Some(SitePageActions {
                        mapping_revision: "x".to_owned(),
                        max_active_pages: 1,
                    });
                },
                invalid,
            ),
            (
                "public page root",
                |c| route(c, "app.page").security_entry = SecurityEntry::Public,
                invalid,
            ),
            (
                "unscoped mapping",
                |c| page(c).mapping_revision = "map r1".to_owned(),
                invalid,
            ),
            ("no live pages", |c| page(c).max_active_pages = 0, invalid),
            (
                "a thousand live pages",
                |c| page(c).max_active_pages = 1_000,
                Ok(()),
            ),
            (
                "too many live pages",
                |c| page(c).max_active_pages = 1_001,
                invalid,
            ),
            (
                "issued resource route",
                |c| {
                    route(c, "orders.read").issued_by = Some(SiteIssuedBy {
                        page_operation_id: "app.page".to_owned(),
                        ttl_seconds: 60,
                    });
                },
                invalid,
            ),
            (
                "issued root route",
                |c| {
                    let list = route(c, "orders.list");
                    list.security_entry = SecurityEntry::AuthenticatedRoot;
                    list.source_action = None;
                    list.resource_grant = None;
                },
                invalid,
            ),
            ("zero lease", |c| issued(c).ttl_seconds = 0, invalid),
            (
                "lease above a day",
                |c| issued(c).ttl_seconds = 86_401,
                invalid,
            ),
            (
                "page id outside the edge alphabet",
                |c| issued(c).page_operation_id = "app:page".to_owned(),
                invalid,
            ),
            (
                "unknown page",
                |c| issued(c).page_operation_id = "missing.page".to_owned(),
                invalid,
            ),
            (
                "page without page actions",
                |c| issued(c).page_operation_id = "login.page".to_owned(),
                invalid,
            ),
            (
                "unused page actions",
                |c| route(c, "orders.list").issued_by = None,
                invalid,
            ),
        ]);
        // At most 16 actions per page delivery; the loop page issues one.
        let with_actions = |extra: usize| {
            verdict(|c| {
                for index in 0..extra {
                    c.policy.routes.push(issued_route(
                        &format!("extra.{index}"),
                        &format!("/extra/{index}"),
                        &format!("app.extra.{index}"),
                    ));
                }
            })
        };
        assert_eq!(with_actions(15), Ok(()));
        assert_eq!(with_actions(16), invalid);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn resource_grants_follow_the_edge() {
        let invalid = Err(RESOURCE_GRANT_INVALID);
        check(vec![
            (
                "grant on a public route",
                |c| {
                    let list = route(c, "orders.list");
                    list.security_entry = SecurityEntry::Public;
                    list.source_action = None;
                    list.issued_by = None;
                },
                invalid,
            ),
            (
                "grant on an auth entry",
                |c| {
                    let grant = route(c, "orders.list").resource_grant.clone();
                    let login = route(c, "auth.login");
                    login.auth_binding = None;
                    login.resource_grant = grant;
                },
                invalid,
            ),
            ("status 204", |c| grant(c).success_status = 204, invalid),
            ("status 300", |c| grant(c).success_status = 300, invalid),
            (
                "unrooted items",
                |c| grant(c).items_pointer = "orders".to_owned(),
                invalid,
            ),
            (
                "empty resource pointer",
                |c| grant(c).resource_pointer = String::new(),
                invalid,
            ),
            (
                "unscoped reference field",
                |c| grant(c).action_ref_field = "action ref".to_owned(),
                invalid,
            ),
            (
                "target outside the edge alphabet",
                |c| grant(c).target_operation_id = "orders:read".to_owned(),
                invalid,
            ),
            (
                "unscoped mapping",
                |c| grant(c).target_mapping_revision = "orders map".to_owned(),
                invalid,
            ),
            ("zero lease", |c| grant(c).ttl_seconds = 0, invalid),
            (
                "lease above a day",
                |c| grant(c).ttl_seconds = 86_401,
                invalid,
            ),
            ("no items", |c| grant(c).max_items = 0, invalid),
            ("a thousand items", |c| grant(c).max_items = 1_000, Ok(())),
            ("too many items", |c| grant(c).max_items = 1_001, invalid),
            ("no grants", |c| grant(c).max_active_grants = 0, invalid),
            (
                "five thousand grants",
                |c| grant(c).max_active_grants = 5_000,
                Ok(()),
            ),
            (
                "too many grants",
                |c| grant(c).max_active_grants = 5_001,
                invalid,
            ),
            (
                "missing target",
                |c| grant(c).target_operation_id = "orders.gone".to_owned(),
                invalid,
            ),
            (
                "target is not a UI action",
                |c| grant(c).target_operation_id = "login.page".to_owned(),
                invalid,
            ),
            (
                "target has no resource",
                |c| grant(c).target_operation_id = "orders.list".to_owned(),
                invalid,
            ),
            (
                "an observed body cannot feed a grant",
                |c| {
                    let grant = route(c, "orders.list").resource_grant.clone();
                    let logout = route(c, "auth.logout");
                    logout.auth_revoke = None;
                    logout.resource_grant = grant;
                    logout.request_crypto = Some(SiteRequestCrypto::Observe {
                        adapter_revision: "observe-v1".to_owned(),
                    });
                },
                Err("site_policy.route"),
            ),
        ]);
        // The browser sensor learns at most 64 harvest rules; the loop has one.
        let with_lists = |extra: usize| {
            verdict(|c| {
                for index in 0..extra {
                    c.policy.routes.push(list_route(
                        &format!("list.{index}"),
                        &format!("/lists/{index}"),
                        "orders.read",
                        "orders-map-r1",
                    ));
                }
            })
        };
        assert_eq!(with_lists(63), Ok(()));
        assert_eq!(with_lists(64), invalid);
    }

    /// A second resource route sharing `orders.read`'s action, and a list
    /// qualifying it under the same mapping revision.
    fn paging(names: &[&str]) -> crate::query_pagination::SiteQueryPagination {
        use crate::query_pagination::{PaginationKind, SiteQueryPagination, SiteQueryParameter};
        SiteQueryPagination {
            parameters: names
                .iter()
                .map(|name| SiteQueryParameter {
                    name: (*name).to_owned(),
                    kind: PaginationKind::Page,
                    max_value: None,
                })
                .collect(),
        }
    }

    /// An `authenticated_root` GET list that issues grants.
    fn root_list(config: &mut SiteConfig, with_grant: bool) {
        let mut list = list_route(
            "orders.root",
            "/orders-root",
            "orders.read",
            "orders-map-r1",
        );
        list.security_entry = SecurityEntry::AuthenticatedRoot;
        list.source_action = None;
        if !with_grant {
            list.resource_grant = None;
        }
        config.policy.routes.push(list);
    }

    #[test]
    fn query_pagination_follows_the_edge() {
        let invalid = Err(QUERY_PAGINATION_INVALID);
        check(vec![
            (
                "non-resource UI action list",
                |c| route(c, "orders.list").query_pagination = Some(paging(&["page"])),
                Ok(()),
            ),
            (
                "all four parameters",
                |c| {
                    route(c, "orders.list").query_pagination =
                        Some(paging(&["page", "size", "skip", "n"]));
                },
                Ok(()),
            ),
            (
                "grant-issuing authenticated root list",
                |c| {
                    root_list(c, true);
                    route(c, "orders.root").query_pagination = Some(paging(&["page"]));
                },
                Ok(()),
            ),
            (
                "authenticated root without a grant",
                |c| {
                    root_list(c, false);
                    route(c, "orders.root").query_pagination = Some(paging(&["page"]));
                },
                invalid,
            ),
            (
                "resource route",
                |c| route(c, "orders.read").query_pagination = Some(paging(&["page"])),
                invalid,
            ),
            (
                "page root",
                |c| route(c, "app.page").query_pagination = Some(paging(&["page"])),
                invalid,
            ),
            (
                "public route",
                |c| route(c, "login.page").query_pagination = Some(paging(&["page"])),
                invalid,
            ),
            (
                "auth entry",
                |c| route(c, "auth.login").query_pagination = Some(paging(&["page"])),
                invalid,
            ),
            (
                "not a GET",
                |c| {
                    let list = route(c, "orders.list");
                    list.method = "POST".to_owned();
                    list.query_pagination = Some(paging(&["page"]));
                },
                invalid,
            ),
            (
                "empty list",
                |c| route(c, "orders.list").query_pagination = Some(paging(&[])),
                invalid,
            ),
            (
                "five parameters",
                |c| {
                    route(c, "orders.list").query_pagination =
                        Some(paging(&["a", "b", "c", "d", "e"]));
                },
                invalid,
            ),
            (
                "duplicate names",
                |c| route(c, "orders.list").query_pagination = Some(paging(&["p", "p"])),
                invalid,
            ),
            (
                "uppercase name",
                |c| route(c, "orders.list").query_pagination = Some(paging(&["Page"])),
                invalid,
            ),
            (
                "name equal to a path resource parameter of another route",
                |c| route(c, "orders.list").query_pagination = Some(paging(&["order_id"])),
                invalid,
            ),
            (
                "name equal to a query resource parameter of another route",
                |c| {
                    let read = route(c, "orders.read");
                    read.resource_path_parameter = None;
                    read.path = "/order".to_owned();
                    read.resource_query_parameter = Some("Order_Id".to_owned());
                    route(c, "orders.list").query_pagination = Some(paging(&["order_id"]));
                },
                invalid,
            ),
        ]);
    }

    fn add_second_target(config: &mut SiteConfig) {
        let mut target = route(config, "orders.read").clone();
        target.operation_id = "orders.read.v2".to_owned();
        target.path = "/v2/orders/{order_id}".to_owned();
        config.policy.routes.push(target);
        config.policy.routes.push(list_route(
            "orders.list.v2",
            "/v2/orders",
            "orders.read.v2",
            "orders-map-r1",
        ));
    }

    #[test]
    fn one_action_and_mapping_has_one_meaning() {
        let conflict = Err(ACTION_DESCRIPTOR_CONFLICT);
        check(vec![
            (
                "a second issued route under the same action",
                |c| {
                    c.policy.routes.push(issued_route(
                        "orders.list.shadow",
                        "/orders-shadow",
                        "app.orders.list",
                    ));
                },
                conflict,
            ),
            (
                "a second list qualifying the same target",
                |c| {
                    c.policy.routes.push(list_route(
                        "orders.list.b",
                        "/orders-b",
                        "orders.read",
                        "orders-map-r1",
                    ));
                },
                Ok(()),
            ),
            (
                "a second target sharing the action",
                add_second_target,
                conflict,
            ),
            (
                "a page action reusing a target's action and mapping",
                |c| {
                    page(c).mapping_revision = "orders-map-r1".to_owned();
                    c.policy.routes.push(issued_route(
                        "orders.shortcut",
                        "/orders-latest",
                        "orders.open",
                    ));
                },
                conflict,
            ),
            // Stricter than the edge, which derives descriptors only when some
            // page declares `page_actions`.
            (
                "two meanings without page actions",
                |c| {
                    route(c, "app.page").page_actions = None;
                    route(c, "orders.list").issued_by = None;
                    add_second_target(c);
                },
                conflict,
            ),
        ]);
    }
}
