//! Page-issued UI actions, edge-managed action descriptors and sensor routes.
//!
//! Trust boundary: every value here is compiled from trusted, startup-validated
//! configuration. Nothing is derived from page bytes, client telemetry or
//! response bodies: a page issues exactly the actions an operator declared with
//! `issued_by`, and a response qualifies exactly the target its
//! `resource_grant` names. The compiled descriptor set is what the edge writes
//! to `xshield.action_descriptors` before a configuration serves traffic, so the
//! issuance transactions and the per-request admission recheck compare against
//! rows that the configuration itself produced.
//!
//! Main types:
//! - [`PageActionPlan`]: the actions one approved page root issues on delivery.
//! - [`EdgeDescriptorSet`]: the digest-bound descriptor set for one policy
//!   revision.
//! - [`SensorRoutes`]: non-secret routing hints the browser sensor needs to
//!   attach server-issued references (never the references themselves).
//!
//! External effects: none; this module is pure compilation.

use crate::{
    CompiledOperation, CompiledResourceLocation, CompiledRouteMatch, ConfigError, ResponseKind,
};
use openssl::sha::Sha256;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use xshield_core::{
    admission::AdmissionClass,
    domain::{
        ActionId, FieldName, MappingRevision, OperationId, PageTemplate, PolicyRevision,
        ViewProfile,
    },
    provenance::{ActionDescriptor, ActionTargetRule, HttpMethod},
};

/// Maximum actions one page delivery may issue; bounds the issuance
/// transaction, the bootstrap document and the sensor's reference table.
pub const MAX_PAGE_ACTIONS: usize = 16;
/// Maximum live page instances one binding may hold for one page template.
pub const MAX_ACTIVE_PAGES: u32 = 1_000;
/// Field profile recorded for page-issued actions, which expose no fields.
const PAGE_ACTION_FIELD_PROFILE: &str = "none";
/// Domain-separation tag of the descriptor-set digest; bump on any encoding change.
const DESCRIPTOR_DIGEST_TAG: &[u8] = b"xshield-edge-descriptors-v1";
/// Upper bound on harvest rules exposed to the sensor.
const MAX_HARVEST_RULES: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssuedByDto {
    page_operation_id: String,
    ttl_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PageActionsDto {
    mapping_revision: String,
    max_active_pages: u32,
}

/// Declares that one `UI_ACTION_REQUIRED` operation is issued by a page root.
#[derive(Clone, Debug)]
pub(crate) struct IssuedByRule {
    page_operation_id: OperationId,
    ttl_seconds: u64,
}

/// Page-level issuance settings on an approved `SENSOR_HTML` page root.
#[derive(Clone, Debug)]
pub(crate) struct PageActionsRule {
    mapping_revision: MappingRevision,
    max_active_pages: u32,
}

pub(crate) fn compile_issued_by(dto: IssuedByDto) -> Result<IssuedByRule, ConfigError> {
    if !(1..=86_400).contains(&dto.ttl_seconds) {
        return Err(ConfigError::Invalid("operations.issued_by.ttl_seconds"));
    }
    Ok(IssuedByRule {
        page_operation_id: OperationId::parse(dto.page_operation_id)
            .map_err(ConfigError::Domain)?,
        ttl_seconds: dto.ttl_seconds,
    })
}

pub(crate) fn compile_page_actions(dto: PageActionsDto) -> Result<PageActionsRule, ConfigError> {
    if !(1..=MAX_ACTIVE_PAGES).contains(&dto.max_active_pages) {
        return Err(ConfigError::Invalid(
            "operations.response.page_actions.max_active_pages",
        ));
    }
    Ok(PageActionsRule {
        mapping_revision: MappingRevision::parse(dto.mapping_revision)
            .map_err(ConfigError::Domain)?,
        max_active_pages: dto.max_active_pages,
    })
}

/// One action a page root issues on every verified delivery.
#[derive(Clone, Debug)]
pub struct PageAction {
    descriptor: ActionDescriptor,
    ttl_seconds: u64,
}

impl PageAction {
    /// Returns the approved descriptor the issued action must match.
    #[must_use]
    pub const fn descriptor(&self) -> &ActionDescriptor {
        &self.descriptor
    }

    /// Returns the configured action lease before session/evidence bounds.
    #[must_use]
    pub const fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
}

/// The complete, ordered set of actions one approved page root issues.
#[derive(Clone, Debug)]
pub struct PageActionPlan {
    page_operation_id: OperationId,
    page_template: PageTemplate,
    mapping_revision: MappingRevision,
    max_active_pages: u32,
    actions: Vec<PageAction>,
}

impl PageActionPlan {
    /// Returns the page root operation whose delivery issues the actions.
    #[must_use]
    pub const fn page_operation_id(&self) -> &OperationId {
        &self.page_operation_id
    }

    /// Returns the page template recorded on page evidence (the page operation ID).
    #[must_use]
    pub const fn page_template(&self) -> &PageTemplate {
        &self.page_template
    }

    /// Returns the mapping revision shared by evidence and descriptors.
    #[must_use]
    pub const fn mapping_revision(&self) -> &MappingRevision {
        &self.mapping_revision
    }

    /// Returns the live page-instance bound per binding.
    #[must_use]
    pub const fn max_active_pages(&self) -> u32 {
        self.max_active_pages
    }

    /// Returns the issued actions ordered by action ID.
    #[must_use]
    pub fn actions(&self) -> &[PageAction] {
        &self.actions
    }
}

/// Digest-bound descriptors derived from one configuration and policy revision.
///
/// The digest covers every descriptor field in a canonical order and is stored
/// as the policy revision's `content_digest`. A different set under the same
/// revision therefore refuses to activate instead of silently changing what
/// existing references mean.
#[derive(Clone, Debug)]
pub struct EdgeDescriptorSet {
    descriptors: Vec<ActionDescriptor>,
    content_digest: [u8; 32],
}

impl EdgeDescriptorSet {
    /// Returns descriptors ordered by action ID and mapping revision.
    #[must_use]
    pub fn descriptors(&self) -> &[ActionDescriptor] {
        &self.descriptors
    }

    /// Returns the canonical SHA-256 of the descriptor set.
    #[must_use]
    pub const fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    /// Returns the digest as lowercase hexadecimal.
    #[must_use]
    pub fn content_digest_hex(&self) -> String {
        lower_hex(&self.content_digest)
    }
}

/// Where a response-derived reference may be presented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarvestTarget {
    /// The resource value is the final path segment after this fixed prefix.
    PathSegment {
        /// Fixed raw path prefix ending in `/`.
        prefix: String,
    },
    /// The resource value is one query parameter on an exact path.
    Query {
        /// Exact target path.
        path: String,
        /// Query parameter carrying the resource value.
        parameter: FieldName,
    },
}

/// Where the source list lives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarvestSource {
    /// An exact source path.
    Exact(String),
    /// A final-segment resource route; any single segment after the prefix.
    Prefix(String),
}

/// Non-secret extraction hint for one approved `resource_grant` list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarvestRule {
    /// Source list method.
    pub source_method: HttpMethod,
    /// Source list route.
    pub source: HarvestSource,
    /// JSON Pointer to the item array.
    pub items_pointer: String,
    /// JSON Pointer, relative to one item, to the resource value.
    pub resource_pointer: String,
    /// Object member carrying the edge-injected reference.
    pub ref_field: FieldName,
    /// Method of the exact target operation.
    pub target_method: HttpMethod,
    /// Location of the resource value on the target request.
    pub target: HarvestTarget,
    /// Configured reference lease, an upper bound only.
    pub ttl_seconds: u64,
    /// Maximum items one response may qualify.
    pub max_items: usize,
}

/// Routing hints for the browser sensor. Contains no reference or identity.
#[derive(Clone, Debug, Default)]
pub struct SensorRoutes {
    harvest: Vec<HarvestRule>,
    invalidate: Vec<(HttpMethod, String)>,
}

impl SensorRoutes {
    /// Returns the response-harvest rules.
    #[must_use]
    pub fn harvest(&self) -> &[HarvestRule] {
        &self.harvest
    }

    /// Returns identity-changing routes after which held references are dropped.
    #[must_use]
    pub fn invalidate(&self) -> &[(HttpMethod, String)] {
        &self.invalidate
    }
}

/// Compiled page issuance and edge-managed descriptors for one configuration.
#[derive(Clone, Debug)]
pub(crate) struct PageProvenance {
    plans: BTreeMap<OperationId, PageActionPlan>,
    descriptors: EdgeDescriptorSet,
}

impl PageProvenance {
    pub(crate) fn plan(&self, page_operation_id: &OperationId) -> Option<&PageActionPlan> {
        self.plans.get(page_operation_id)
    }

    pub(crate) const fn descriptors(&self) -> &EdgeDescriptorSet {
        &self.descriptors
    }
}

/// Validates every page/issued-action contract and derives the descriptor set.
///
/// Returns `None` when no page declares `page_actions`; such configurations
/// keep externally provisioned descriptors. When any page declares them the
/// edge owns the whole policy revision: page-issued and response-target
/// descriptors are derived together and bound to one digest.
pub(crate) fn compile(
    operations: &[&CompiledOperation],
    policy_revision: &PolicyRevision,
) -> Result<Option<PageProvenance>, ConfigError> {
    let mut plans = page_plans(operations)?;
    attach_issued_actions(operations, policy_revision, &mut plans)?;
    if plans.is_empty() {
        return Ok(None);
    }
    for plan in plans.values_mut() {
        if plan.actions.is_empty() || plan.actions.len() > MAX_PAGE_ACTIONS {
            return Err(ConfigError::Invalid("operations.response.page_actions"));
        }
        plan.actions.sort_by(|left, right| {
            left.descriptor
                .action_id()
                .cmp(right.descriptor.action_id())
        });
    }
    let page_descriptors = plans
        .values()
        .flat_map(|plan| plan.actions.iter().map(|action| action.descriptor.clone()));
    let descriptors = unique_descriptors(
        page_descriptors.chain(response_target_descriptors(operations, policy_revision)?),
    )?;
    let content_digest = descriptor_digest(&descriptors);
    Ok(Some(PageProvenance {
        plans,
        descriptors: EdgeDescriptorSet {
            descriptors,
            content_digest,
        },
    }))
}

fn page_plans(
    operations: &[&CompiledOperation],
) -> Result<BTreeMap<OperationId, PageActionPlan>, ConfigError> {
    let mut plans = BTreeMap::new();
    for page in operations {
        let Some(rule) = page.response.as_ref().and_then(|r| r.page_actions.as_ref()) else {
            continue;
        };
        if page.method != HttpMethod::Get
            || page.policy.admission_class() != AdmissionClass::AuthenticatedRoot
            || !matches!(page.route_match, CompiledRouteMatch::Exact(_))
            || !page
                .response
                .as_ref()
                .is_some_and(|response| matches!(response.kind, ResponseKind::SensorHtml(_)))
        {
            return Err(ConfigError::Invalid("operations.response.page_actions"));
        }
        let page_operation_id = page.policy.operation_id().clone();
        let page_template =
            PageTemplate::parse(page_operation_id.as_str()).map_err(ConfigError::Domain)?;
        plans.insert(
            page_operation_id.clone(),
            PageActionPlan {
                page_operation_id,
                page_template,
                mapping_revision: rule.mapping_revision.clone(),
                max_active_pages: rule.max_active_pages,
                actions: Vec::new(),
            },
        );
    }
    Ok(plans)
}

fn attach_issued_actions(
    operations: &[&CompiledOperation],
    policy_revision: &PolicyRevision,
    plans: &mut BTreeMap<OperationId, PageActionPlan>,
) -> Result<(), ConfigError> {
    for operation in operations {
        let Some(issued_by) = operation.issued_by.as_ref() else {
            continue;
        };
        let (Some(action_id), CompiledRouteMatch::Exact(_)) =
            (operation.source_action.as_ref(), &operation.route_match)
        else {
            return Err(ConfigError::Invalid("operations.issued_by"));
        };
        if operation.policy.admission_class() != AdmissionClass::UiActionRequired
            || operation.resource.is_some()
        {
            return Err(ConfigError::Invalid("operations.issued_by"));
        }
        let plan = plans
            .get_mut(&issued_by.page_operation_id)
            .ok_or(ConfigError::Invalid(
                "operations.issued_by.page_operation_id",
            ))?;
        let descriptor = ActionDescriptor::approved(
            action_id.clone(),
            plan.page_template.clone(),
            operation.policy.operation_id().clone(),
            operation.method,
            operation.route.clone(),
            ActionTargetRule::None,
            BTreeSet::new(),
            ViewProfile::parse(PAGE_ACTION_FIELD_PROFILE).map_err(ConfigError::Domain)?,
            policy_revision.clone(),
            plan.mapping_revision.clone(),
        );
        plan.actions.push(PageAction {
            descriptor,
            ttl_seconds: issued_by.ttl_seconds,
        });
    }
    Ok(())
}

/// Collapses identical derivations and rejects one `(action, mapping)` key
/// with two meanings, ordered for the canonical digest.
fn unique_descriptors(
    candidates: impl Iterator<Item = ActionDescriptor>,
) -> Result<Vec<ActionDescriptor>, ConfigError> {
    let mut descriptors = BTreeMap::<(ActionId, MappingRevision), ActionDescriptor>::new();
    for descriptor in candidates {
        let key = (
            descriptor.action_id().clone(),
            descriptor.mapping_revision().clone(),
        );
        match descriptors.get(&key) {
            Some(existing) if existing != &descriptor => {
                return Err(ConfigError::Invalid("operations.source_action"));
            }
            Some(_) => {}
            None => {
                descriptors.insert(key, descriptor);
            }
        }
    }
    Ok(descriptors.into_values().collect())
}

fn response_target_descriptors(
    operations: &[&CompiledOperation],
    policy_revision: &PolicyRevision,
) -> Result<Vec<ActionDescriptor>, ConfigError> {
    let mut descriptors = Vec::new();
    for source in operations {
        let Some(rule) = source.response.as_ref().and_then(|r| r.grant.as_ref()) else {
            continue;
        };
        let target = operations
            .iter()
            .find(|operation| operation.policy.operation_id() == rule.target_operation_id())
            .ok_or(ConfigError::Invalid(
                "operations.response.target_operation_id",
            ))?;
        let (Some(action_id), Some(resource)) =
            (target.source_action.as_ref(), target.resource.as_ref())
        else {
            return Err(ConfigError::Invalid(
                "operations.response.target_operation_id",
            ));
        };
        let field = match &resource.location {
            CompiledResourceLocation::Query(parameter)
            | CompiledResourceLocation::FinalPathSegment { parameter, .. } => parameter.clone(),
        };
        descriptors.push(ActionDescriptor::approved(
            action_id.clone(),
            // Response evidence never compares page templates; the target
            // operation keeps one descriptor per action and mapping revision
            // even when several approved lists qualify the same target.
            PageTemplate::parse(target.policy.operation_id().as_str())
                .map_err(ConfigError::Domain)?,
            target.policy.operation_id().clone(),
            target.method,
            target.route.clone(),
            ActionTargetRule::Resource(resource.resource_type.clone()),
            BTreeSet::from([field]),
            resource.view_profile.clone(),
            policy_revision.clone(),
            rule.target_mapping_revision().clone(),
        ));
    }
    Ok(descriptors)
}

/// Builds the non-secret routing hints the browser sensor receives.
pub(crate) fn sensor_routes(
    operations: &[&CompiledOperation],
) -> Result<SensorRoutes, ConfigError> {
    let mut routes = SensorRoutes::default();
    for source in operations {
        let response = source.response.as_ref();
        if response.is_some_and(|response| {
            response.auth_binding.is_some()
                || response.auth_revoke.is_some()
                || response.auth_context_switch.is_some()
        }) && let CompiledRouteMatch::Exact(path) = &source.route_match
        {
            routes.invalidate.push((source.method, path.clone()));
        }
        let Some(rule) = response.and_then(|response| response.grant.as_ref()) else {
            continue;
        };
        let Some(target) = operations
            .iter()
            .find(|operation| operation.policy.operation_id() == rule.target_operation_id())
        else {
            continue;
        };
        let Some(resource) = target.resource.as_ref() else {
            continue;
        };
        let source_route = match &source.route_match {
            CompiledRouteMatch::Exact(path) => HarvestSource::Exact(path.clone()),
            CompiledRouteMatch::FinalResourceSegment { prefix } => {
                HarvestSource::Prefix(prefix.clone())
            }
        };
        let target_route = match (&resource.location, &target.route_match) {
            (CompiledResourceLocation::FinalPathSegment { prefix, .. }, _) => {
                HarvestTarget::PathSegment {
                    prefix: prefix.clone(),
                }
            }
            (CompiledResourceLocation::Query(parameter), CompiledRouteMatch::Exact(path)) => {
                HarvestTarget::Query {
                    path: path.clone(),
                    parameter: parameter.clone(),
                }
            }
            (
                CompiledResourceLocation::Query(_),
                CompiledRouteMatch::FinalResourceSegment { .. },
            ) => {
                continue;
            }
        };
        routes.harvest.push(HarvestRule {
            source_method: source.method,
            source: source_route,
            items_pointer: rule.items_pointer.clone(),
            resource_pointer: rule.resource_pointer.clone(),
            ref_field: rule.action_ref_field.clone(),
            target_method: target.method,
            target: target_route,
            ttl_seconds: rule.ttl_seconds(),
            max_items: rule.max_items,
        });
    }
    if routes.harvest.len() > MAX_HARVEST_RULES || routes.invalidate.len() > MAX_HARVEST_RULES {
        return Err(ConfigError::Invalid("operations.response.resource_grant"));
    }
    Ok(routes)
}

fn descriptor_digest(descriptors: &[ActionDescriptor]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut field = |value: &[u8]| {
        // Every encoded value is a validated name, route or decimal count and
        // can never contain NUL, so the separator keeps the encoding injective.
        hasher.update(value);
        hasher.update(&[0]);
    };
    field(DESCRIPTOR_DIGEST_TAG);
    field(descriptors.len().to_string().as_bytes());
    for descriptor in descriptors {
        field(descriptor.action_id().as_str().as_bytes());
        field(descriptor.mapping_revision().as_str().as_bytes());
        field(descriptor.page_template().as_str().as_bytes());
        field(descriptor.operation_id().as_str().as_bytes());
        field(descriptor.method().as_str().as_bytes());
        field(descriptor.route().as_str().as_bytes());
        match descriptor.target_rule() {
            ActionTargetRule::None => field(b"none"),
            ActionTargetRule::VerifiedPrincipal => field(b"verified_principal"),
            ActionTargetRule::Resource(resource_type) => {
                field(b"resource");
                field(resource_type.as_str().as_bytes());
            }
        }
        field(descriptor.allowed_fields().len().to_string().as_bytes());
        for allowed in descriptor.allowed_fields() {
            field(allowed.as_str().as_bytes());
        }
        field(descriptor.field_profile().as_str().as_bytes());
    }
    hasher.finish()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::{ConfigError, GatewayConfig, page_actions::HarvestTarget};
    use serde_json::{Value, json};
    use xshield_core::provenance::{ActionTargetRule, HttpMethod};

    fn config(operations: Value) -> Value {
        let mut config = json!({
            "listen": "127.0.0.1:6188",
            "origin": {"address": "127.0.0.1:8080", "server_name": "origin.example", "tls": false},
            "tenant_id": "tenant_demo",
            "site_id": "site_demo",
            "policy_revision": "policy-r1",
            "audit": {"directory": "target/xshield-audit-test", "key_id": "journal-key-r1",
                      "producer_id": "edge-test", "max_bytes": 1_048_576,
                      "high_watermark_bytes": 786_432, "segment_max_bytes": 262_144},
            "identity_store": {"max_connections": 4, "acquire_timeout_ms": 1000},
            "sensor": {"origin": "https://app.example", "build_ref": "a".repeat(64),
                       "heartbeat_seconds": 15},
        });
        config["operations"] = operations;
        config
    }

    fn page() -> Value {
        json!({"operation_id": "app.page", "method": "GET", "path": "/app",
               "admission": "AUTHENTICATED_ROOT",
               "response": {"mode": "SENSOR_HTML", "max_bytes": 4096,
                            "adapter_revision": "app-r1", "origin_sha256": "c".repeat(64),
                            "injection_offset": 10,
                            "page_actions": {"mapping_revision": "mapping-r1",
                                             "max_active_pages": 8}}})
    }

    fn login() -> Value {
        json!({"operation_id": "auth.login", "method": "POST", "path": "/api/login",
               "admission": "AUTH_ENTRY",
               "response": {"mode": "BUFFERED_JSON", "max_bytes": 512,
                            "auth_binding": {"success_status": 200,
                                             "principal_pointer": "/user",
                                             "authorization_context_pointer": "/context",
                                             "bearer_pointer": "/token",
                                             "credential_ttl_seconds": 600,
                                             "session_ttl_seconds": 600}}})
    }

    fn list() -> Value {
        json!({"operation_id": "orders.list", "method": "GET", "path": "/orders",
               "admission": "UI_ACTION_REQUIRED", "source_action": "app.orders.list",
               "issued_by": {"page_operation_id": "app.page", "ttl_seconds": 600},
               "response": {"mode": "BUFFERED_JSON", "max_bytes": 4096,
                            "resource_grant": {"success_status": 200, "items_pointer": "/orders",
                                               "resource_pointer": "/id",
                                               "action_ref_field": "_xshield_action_ref",
                                               "target_operation_id": "orders.read",
                                               "target_mapping_revision": "mapping-r2",
                                               "ttl_seconds": 900, "max_items": 10,
                                               "max_active_grants": 100}}})
    }

    fn detail() -> Value {
        json!({"operation_id": "orders.read", "method": "GET", "path": "/orders/{order_id}",
               "admission": "UI_ACTION_REQUIRED", "source_action": "orders.open",
               "resource_type": "order", "view_profile": "customer_detail",
               "resource_path_parameter": "order_id"})
    }

    fn compile(operations: Value) -> Result<GatewayConfig, ConfigError> {
        GatewayConfig::from_json(config(operations).to_string().as_bytes())
    }

    fn invalid(operations: Value) -> &'static str {
        match compile(operations) {
            Err(ConfigError::Invalid(field)) => field,
            other => panic!("expected an invalid-field error, got {other:?}"),
        }
    }

    #[test]
    fn page_issues_exactly_its_declared_actions_and_derives_all_descriptors() {
        let config = compile(json!([page(), login(), list(), detail()])).unwrap();
        let plan = config.page_action_plan("GET", "/app").unwrap();
        assert_eq!(plan.page_operation_id().as_str(), "app.page");
        assert_eq!(plan.page_template().as_str(), "app.page");
        assert_eq!(plan.mapping_revision().as_str(), "mapping-r1");
        assert_eq!(plan.max_active_pages(), 8);
        assert_eq!(plan.actions().len(), 1);
        let action = &plan.actions()[0];
        assert_eq!(action.ttl_seconds(), 600);
        assert_eq!(action.descriptor().action_id().as_str(), "app.orders.list");
        assert_eq!(action.descriptor().operation_id().as_str(), "orders.list");
        assert_eq!(action.descriptor().route().as_str(), "/orders");
        assert_eq!(action.descriptor().target_rule(), &ActionTargetRule::None);
        assert!(action.descriptor().allowed_fields().is_empty());
        assert!(config.page_action_plan("GET", "/orders").is_none());
        assert!(config.page_action_plan("POST", "/app").is_none());

        let descriptors = config.edge_descriptors().unwrap();
        let summary = descriptors
            .descriptors()
            .iter()
            .map(|descriptor| {
                (
                    descriptor.action_id().as_str(),
                    descriptor.page_template().as_str(),
                    descriptor.mapping_revision().as_str(),
                    descriptor.field_profile().as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            summary,
            [
                ("app.orders.list", "app.page", "mapping-r1", "none"),
                (
                    "orders.open",
                    "orders.read",
                    "mapping-r2",
                    "customer_detail"
                ),
            ]
        );
        assert_eq!(descriptors.content_digest_hex().len(), 64);
    }

    #[test]
    fn descriptor_digest_tracks_descriptor_content_not_issuance_leases() {
        let digest = |operations: Value| {
            compile(operations)
                .unwrap()
                .edge_descriptors()
                .unwrap()
                .content_digest_hex()
        };
        let base = digest(json!([page(), list(), detail()]));
        assert_eq!(base, digest(json!([detail(), list(), page()])));
        let mut longer_lease = list();
        longer_lease["issued_by"]["ttl_seconds"] = json!(1200);
        assert_eq!(base, digest(json!([page(), longer_lease, detail()])));
        let mut moved = list();
        moved["path"] = json!("/orders-all");
        assert_ne!(base, digest(json!([page(), moved, detail()])));
        let mut remapped = page();
        remapped["response"]["page_actions"]["mapping_revision"] = json!("mapping-r9");
        assert_ne!(base, digest(json!([remapped, list(), detail()])));
    }

    #[test]
    fn configurations_without_page_actions_keep_external_descriptors() {
        let mut list = list();
        list.as_object_mut().unwrap().remove("issued_by");
        let mut root = page();
        root["response"]
            .as_object_mut()
            .unwrap()
            .remove("page_actions");
        let config = compile(json!([root, list, detail()])).unwrap();
        assert!(config.edge_descriptors().is_none());
        assert!(config.page_action_plan("GET", "/app").is_none());
        // Harvest hints do not depend on page issuance.
        assert_eq!(config.sensor_routes().harvest().len(), 1);
    }

    #[test]
    fn rejects_incoherent_page_and_issued_action_declarations() {
        let mut unknown_page = list();
        unknown_page["issued_by"]["page_operation_id"] = json!("missing.page");
        assert_eq!(
            invalid(json!([page(), unknown_page, detail()])),
            "operations.issued_by.page_operation_id"
        );
        let mut root_issued = list();
        root_issued["admission"] = json!("AUTHENTICATED_ROOT");
        root_issued.as_object_mut().unwrap().remove("source_action");
        root_issued["response"]
            .as_object_mut()
            .unwrap()
            .remove("resource_grant");
        assert_eq!(
            invalid(json!([page(), root_issued, detail()])),
            "operations.issued_by"
        );
        let mut resource_issued = detail();
        resource_issued["issued_by"] = json!({"page_operation_id": "app.page", "ttl_seconds": 60});
        assert_eq!(
            invalid(json!([page(), list(), resource_issued])),
            "operations.issued_by"
        );
        let mut public_page = page();
        public_page["admission"] = json!("PUBLIC");
        assert_eq!(
            invalid(json!([public_page, list(), detail()])),
            "operations.response.page_actions"
        );
        let mut unused = list();
        unused.as_object_mut().unwrap().remove("issued_by");
        assert_eq!(
            invalid(json!([page(), unused, detail()])),
            "operations.response.page_actions"
        );
        let mut json_page = page();
        json_page["response"] = json!({"mode": "BUFFERED_JSON", "max_bytes": 64,
            "page_actions": {"mapping_revision": "mapping-r1", "max_active_pages": 1}});
        assert_eq!(
            invalid(json!([json_page, list(), detail()])),
            "operations.response"
        );
    }

    #[test]
    fn rejects_unbounded_leases_capacities_and_action_counts() {
        for ttl in [0, 86_401] {
            let mut list = list();
            list["issued_by"]["ttl_seconds"] = json!(ttl);
            assert_eq!(
                invalid(json!([page(), list, detail()])),
                "operations.issued_by.ttl_seconds"
            );
        }
        for capacity in [0, 1_001] {
            let mut root = page();
            root["response"]["page_actions"]["max_active_pages"] = json!(capacity);
            assert_eq!(
                invalid(json!([root, list(), detail()])),
                "operations.response.page_actions.max_active_pages"
            );
        }
        let mut operations = vec![page(), list(), detail()];
        for index in 0..super::MAX_PAGE_ACTIONS {
            operations.push(json!({
                "operation_id": format!("extra.{index}"), "method": "POST",
                "path": format!("/extra/{index}"), "admission": "UI_ACTION_REQUIRED",
                "source_action": format!("app.extra.{index}"),
                "issued_by": {"page_operation_id": "app.page", "ttl_seconds": 60}}));
        }
        assert_eq!(
            invalid(Value::Array(operations)),
            "operations.response.page_actions"
        );
    }

    #[test]
    fn rejects_one_action_mapping_with_two_meanings() {
        let mut shadow = list();
        shadow["operation_id"] = json!("orders.list.shadow");
        shadow["path"] = json!("/orders-shadow");
        shadow["response"]
            .as_object_mut()
            .unwrap()
            .remove("resource_grant");
        assert_eq!(
            invalid(json!([page(), list(), shadow, detail()])),
            "operations.source_action"
        );
        let mut unknown_field = list();
        unknown_field["issued_by"]["scope"] = json!("all");
        assert!(matches!(
            compile(json!([page(), unknown_field, detail()])),
            Err(ConfigError::Json(_))
        ));
    }

    #[test]
    fn sensor_routes_expose_harvest_and_identity_change_hints_only() {
        let config = compile(json!([page(), login(), list(), detail()])).unwrap();
        let routes = config.sensor_routes();
        assert_eq!(
            routes.invalidate(),
            [(HttpMethod::Post, "/api/login".to_owned())]
        );
        let [rule] = routes.harvest() else {
            panic!("one harvest rule expected");
        };
        assert_eq!(rule.source_method, HttpMethod::Get);
        assert_eq!(rule.items_pointer, "/orders");
        assert_eq!(rule.resource_pointer, "/id");
        assert_eq!(rule.ref_field.as_str(), "_xshield_action_ref");
        assert_eq!(
            rule.target,
            HarvestTarget::PathSegment {
                prefix: "/orders/".to_owned()
            }
        );
        assert_eq!((rule.ttl_seconds, rule.max_items), (900, 10));
    }
}
