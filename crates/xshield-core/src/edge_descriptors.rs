//! Edge-managed UI-action descriptors derived from one site's operations.
//!
//! # Purpose
//! A site configuration that declares page issuance (`page_actions` on an
//! approved page root, `issued_by` on the operations it issues) makes the edge
//! the owner of that configuration's policy revision: the action descriptors
//! that issued references point at are derived from the configuration itself
//! and written to `PostgreSQL` before the configuration serves traffic. This
//! module is the single definition of that derivation: [`derive`] turns the
//! typed operation facts into
//! - the actions each approved page root issues on every verified delivery
//!   ([`PageActionPlan`]), and
//! - the complete descriptor set of the policy revision, bound to one canonical
//!   SHA-256 digest ([`EdgeDescriptorSet`]).
//!
//! The edge calls it whenever it compiles a configuration (startup, a signed
//! apply, restoring a persisted snapshot); a control plane can call it on the
//! configuration it is about to send to learn the digest the edge will supply.
//!
//! # Trust boundary
//! Inputs are values the caller already parsed and validated (identifiers,
//! route templates, admission classes). Nothing here reads page bytes, client
//! telemetry or response bodies: a page issues exactly the actions an operator
//! declared with `issued_by`, and a response qualifies exactly the target its
//! `resource_grant` names.
//!
//! # Invariants
//! - A page root is a `GET`, `AUTHENTICATED_ROOT`, exact-route operation whose
//!   response is `SENSOR_HTML`; it issues 1..=[`MAX_PAGE_ACTIONS`] actions,
//!   ordered by action ID.
//! - An issued operation is `UI_ACTION_REQUIRED`, has a source action and an
//!   exact route, addresses no resource, and names a declared page root. Its
//!   descriptor has no target and no fields; its field profile is `none`.
//! - A `resource_grant` target is a resource operation with a source action;
//!   its descriptor uses the target operation as page template (response
//!   evidence never compares page templates).
//! - One `(action_id, mapping_revision)` key has exactly one meaning in the
//!   set; identical derivations collapse.
//! - The digest covers every descriptor field that gives an issued reference
//!   its meaning, in canonical order, and nothing else: issuance leases and
//!   capacities are not part of it. The encoding is versioned by its
//!   domain-separation tag; changing it changes every digest, so every edge
//!   would refuse revisions supplied by an older one. Bump the tag instead of
//!   editing the encoding in place.
//!
//! # Errors
//! [`DescriptorError`] names the configuration field that is incoherent. A
//! failed derivation produces no partial result.
//!
//! # Audit and resources
//! Pure computation: no I/O, no clock, no audit side effects. Callers turn a
//! refusal into their own stable reason (a refused start, or a refused apply).
//! Work and memory are linear in the number of operations the caller passes.

use crate::{
    admission::AdmissionClass,
    domain::{
        ActionId, FieldName, InvalidValue, MappingRevision, OperationId, PageTemplate,
        PolicyRevision, ResourceType, ViewProfile,
    },
    provenance::{ActionDescriptor, ActionTargetRule, HttpMethod, RouteTemplate},
};
use openssl::sha::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Maximum actions one page delivery may issue; bounds the issuance
/// transaction, the bootstrap document and the sensor's reference table.
pub const MAX_PAGE_ACTIONS: usize = 16;
/// Maximum live page instances one binding may hold for one page template.
pub const MAX_ACTIVE_PAGES: u32 = 1_000;
/// Longest lease, in seconds, a page-issued action may be configured with.
pub const MAX_ISSUED_ACTION_TTL_SECONDS: u64 = 86_400;
/// Field profile recorded for page-issued actions, which expose no fields.
const PAGE_ACTION_FIELD_PROFILE: &str = "none";
/// Domain-separation tag of the descriptor-set digest; bump on any encoding change.
const DESCRIPTOR_DIGEST_TAG: &[u8] = b"xshield-edge-descriptors-v1";

/// Why a configuration cannot derive its edge-managed descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    /// `issued_by.ttl_seconds` is outside `1..=MAX_ISSUED_ACTION_TTL_SECONDS`.
    IssuedActionLease,
    /// `page_actions.max_active_pages` is outside `1..=MAX_ACTIVE_PAGES`.
    PageCapacity,
    /// `page_actions` is declared on an operation that is not an approved page
    /// root (`GET`, `AUTHENTICATED_ROOT`, exact route, `SENSOR_HTML` response).
    PageRoot,
    /// A page root issues no action, or more than [`MAX_PAGE_ACTIONS`].
    PageActionCount,
    /// `issued_by` is declared on an operation a page cannot issue: no source
    /// action, a parameterized route, another admission class or a resource.
    IssuedAction,
    /// `issued_by.page_operation_id` names no page root declaring `page_actions`.
    UnknownPage,
    /// A `resource_grant` target is absent or is not a resource action.
    GrantTarget,
    /// One `(action_id, mapping_revision)` key was derived with two meanings.
    AmbiguousAction,
    /// A derived identifier failed domain validation.
    Domain(InvalidValue),
}

impl DescriptorError {
    /// Returns the stable configuration path of the rejected field, the same
    /// path the edge configuration compiler reports for it.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        match self {
            Self::IssuedActionLease => "operations.issued_by.ttl_seconds",
            Self::PageCapacity => "operations.response.page_actions.max_active_pages",
            Self::PageRoot | Self::PageActionCount => "operations.response.page_actions",
            Self::IssuedAction => "operations.issued_by",
            Self::UnknownPage => "operations.issued_by.page_operation_id",
            Self::GrantTarget => "operations.response.target_operation_id",
            Self::AmbiguousAction => "operations.source_action",
            Self::Domain(value) => value.field(),
        }
    }
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}", self.field())
    }
}

impl std::error::Error for DescriptorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Domain(value) => Some(value),
            _ => None,
        }
    }
}

/// `issued_by`: one `UI_ACTION_REQUIRED` operation is issued by a page root on
/// every verified delivery of that page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedBy {
    page_operation_id: OperationId,
    ttl_seconds: u64,
}

impl IssuedBy {
    /// Validates the configured lease, then the page operation identifier.
    ///
    /// # Errors
    /// [`DescriptorError::IssuedActionLease`] for a lease outside
    /// `1..=MAX_ISSUED_ACTION_TTL_SECONDS`, and [`DescriptorError::Domain`] for
    /// an invalid operation identifier.
    pub fn parse(page_operation_id: String, ttl_seconds: u64) -> Result<Self, DescriptorError> {
        if !(1..=MAX_ISSUED_ACTION_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(DescriptorError::IssuedActionLease);
        }
        Ok(Self {
            page_operation_id: OperationId::parse(page_operation_id)
                .map_err(DescriptorError::Domain)?,
            ttl_seconds,
        })
    }

    /// Returns the page root operation whose delivery issues the action.
    #[must_use]
    pub const fn page_operation_id(&self) -> &OperationId {
        &self.page_operation_id
    }

    /// Returns the configured action lease, before session and evidence bounds.
    #[must_use]
    pub const fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
}

/// `page_actions`: issuance settings of one approved page root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageActions {
    mapping_revision: MappingRevision,
    max_active_pages: u32,
}

impl PageActions {
    /// Validates the page-instance bound, then the mapping revision.
    ///
    /// # Errors
    /// [`DescriptorError::PageCapacity`] for a bound outside
    /// `1..=MAX_ACTIVE_PAGES`, and [`DescriptorError::Domain`] for an invalid
    /// mapping revision.
    pub fn parse(mapping_revision: String, max_active_pages: u32) -> Result<Self, DescriptorError> {
        if !(1..=MAX_ACTIVE_PAGES).contains(&max_active_pages) {
            return Err(DescriptorError::PageCapacity);
        }
        Ok(Self {
            mapping_revision: MappingRevision::parse(mapping_revision)
                .map_err(DescriptorError::Domain)?,
            max_active_pages,
        })
    }

    /// Returns the mapping revision shared by page evidence and descriptors.
    #[must_use]
    pub const fn mapping_revision(&self) -> &MappingRevision {
        &self.mapping_revision
    }

    /// Returns the live page-instance bound per binding.
    #[must_use]
    pub const fn max_active_pages(&self) -> u32 {
        self.max_active_pages
    }
}

/// How an operation's route matches request paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteMatch {
    /// One exact path.
    Exact,
    /// Any single final path segment after a fixed prefix.
    FinalSegment,
}

/// The resource an operation addresses.
#[derive(Clone, Copy, Debug)]
pub struct ResourceFacts<'a> {
    /// Canonical resource type.
    pub resource_type: &'a ResourceType,
    /// View or field profile the operation exposes.
    pub view_profile: &'a ViewProfile,
    /// Request field carrying the resource value (query parameter or final
    /// path segment parameter).
    pub field: &'a FieldName,
}

/// A `response.resource_grant` rule: which operation its list qualifies.
#[derive(Clone, Copy, Debug)]
pub struct GrantTargetFacts<'a> {
    /// Operation each extracted resource is granted for.
    pub target_operation_id: &'a OperationId,
    /// Mapping revision the issued references are bound to.
    pub target_mapping_revision: &'a MappingRevision,
}

/// One configured operation, reduced to the facts the derivation reads.
///
/// Every field is already a validated domain value; [`derive`] checks only the
/// cross-operation coherence of page issuance.
#[derive(Clone, Copy, Debug)]
pub struct OperationFacts<'a> {
    /// Operation identifier, unique within the configuration.
    pub operation_id: &'a OperationId,
    /// Exact HTTP method.
    pub method: HttpMethod,
    /// Route template as configured.
    pub route: &'a RouteTemplate,
    /// How the route matches request paths.
    pub route_match: RouteMatch,
    /// Admission class the operation requires.
    pub admission: AdmissionClass,
    /// Source action of a `UI_ACTION_REQUIRED` operation.
    pub source_action: Option<&'a ActionId>,
    /// Resource the operation addresses, if any.
    pub resource: Option<ResourceFacts<'a>>,
    /// `issued_by`, if a page root issues this operation.
    pub issued_by: Option<&'a IssuedBy>,
    /// `response.page_actions`, if declared.
    pub page_actions: Option<&'a PageActions>,
    /// Whether the operation's response is rewritten as `SENSOR_HTML`.
    pub sensor_html: bool,
    /// `response.resource_grant`, if declared.
    pub resource_grant: Option<GrantTargetFacts<'a>>,
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

    /// Returns the digest as lowercase hexadecimal, the form stored in
    /// `policy_revisions.content_digest`.
    #[must_use]
    pub fn content_digest_hex(&self) -> String {
        lower_hex(&self.content_digest)
    }
}

/// Page issuance plans and the edge-managed descriptor set of one configuration.
#[derive(Clone, Debug)]
pub struct PageProvenance {
    plans: BTreeMap<OperationId, PageActionPlan>,
    descriptors: EdgeDescriptorSet,
}

impl PageProvenance {
    /// Returns the plan of one page root, or `None` for any other operation.
    #[must_use]
    pub fn plan(&self, page_operation_id: &OperationId) -> Option<&PageActionPlan> {
        self.plans.get(page_operation_id)
    }

    /// Returns every page root's plan, ordered by page operation ID.
    pub fn plans(&self) -> impl Iterator<Item = &PageActionPlan> {
        self.plans.values()
    }

    /// Returns the digest-bound descriptor set of the policy revision.
    #[must_use]
    pub const fn descriptors(&self) -> &EdgeDescriptorSet {
        &self.descriptors
    }
}

/// Validates every page/issued-action contract and derives the descriptor set.
///
/// Returns `Ok(None)` when no operation declares `page_actions`: such a
/// configuration keeps externally provisioned descriptors and the edge supplies
/// nothing for it. When any page declares them the edge owns the whole policy
/// revision: page-issued and `resource_grant` target descriptors are derived
/// together and bound to one digest.
///
/// `operations` must be the configuration's complete operation list; the
/// result does not depend on its order except for which of several equally
/// invalid declarations is reported.
///
/// # Errors
/// [`DescriptorError`] for the first incoherent declaration, in this order:
/// page roots, issued operations, action counts per page, `resource_grant`
/// targets, then ambiguous `(action, mapping)` keys.
pub fn derive(
    operations: &[OperationFacts<'_>],
    policy_revision: &PolicyRevision,
) -> Result<Option<PageProvenance>, DescriptorError> {
    let mut plans = page_plans(operations)?;
    attach_issued_actions(operations, policy_revision, &mut plans)?;
    if plans.is_empty() {
        return Ok(None);
    }
    for plan in plans.values_mut() {
        if plan.actions.is_empty() || plan.actions.len() > MAX_PAGE_ACTIONS {
            return Err(DescriptorError::PageActionCount);
        }
        plan.actions.sort_by(|left, right| {
            left.descriptor
                .action_id()
                .cmp(right.descriptor.action_id())
        });
    }
    let targets = response_target_descriptors(operations, policy_revision)?;
    let page_descriptors = plans
        .values()
        .flat_map(|plan| plan.actions.iter().map(|action| action.descriptor.clone()));
    let descriptors = unique_descriptors(page_descriptors.chain(targets))?;
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
    operations: &[OperationFacts<'_>],
) -> Result<BTreeMap<OperationId, PageActionPlan>, DescriptorError> {
    let mut plans = BTreeMap::new();
    for page in operations {
        let Some(rule) = page.page_actions else {
            continue;
        };
        if page.method != HttpMethod::Get
            || page.admission != AdmissionClass::AuthenticatedRoot
            || page.route_match != RouteMatch::Exact
            || !page.sensor_html
        {
            return Err(DescriptorError::PageRoot);
        }
        let page_template =
            PageTemplate::parse(page.operation_id.as_str()).map_err(DescriptorError::Domain)?;
        plans.insert(
            page.operation_id.clone(),
            PageActionPlan {
                page_operation_id: page.operation_id.clone(),
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
    operations: &[OperationFacts<'_>],
    policy_revision: &PolicyRevision,
    plans: &mut BTreeMap<OperationId, PageActionPlan>,
) -> Result<(), DescriptorError> {
    for operation in operations {
        let Some(issued_by) = operation.issued_by else {
            continue;
        };
        let (Some(action_id), RouteMatch::Exact) = (operation.source_action, operation.route_match)
        else {
            return Err(DescriptorError::IssuedAction);
        };
        if operation.admission != AdmissionClass::UiActionRequired || operation.resource.is_some() {
            return Err(DescriptorError::IssuedAction);
        }
        let plan = plans
            .get_mut(&issued_by.page_operation_id)
            .ok_or(DescriptorError::UnknownPage)?;
        let descriptor = ActionDescriptor::approved(
            action_id.clone(),
            plan.page_template.clone(),
            operation.operation_id.clone(),
            operation.method,
            operation.route.clone(),
            ActionTargetRule::None,
            BTreeSet::new(),
            ViewProfile::parse(PAGE_ACTION_FIELD_PROFILE).map_err(DescriptorError::Domain)?,
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
) -> Result<Vec<ActionDescriptor>, DescriptorError> {
    let mut descriptors = BTreeMap::<(ActionId, MappingRevision), ActionDescriptor>::new();
    for descriptor in candidates {
        let key = (
            descriptor.action_id().clone(),
            descriptor.mapping_revision().clone(),
        );
        match descriptors.get(&key) {
            Some(existing) if existing != &descriptor => {
                return Err(DescriptorError::AmbiguousAction);
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
    operations: &[OperationFacts<'_>],
    policy_revision: &PolicyRevision,
) -> Result<Vec<ActionDescriptor>, DescriptorError> {
    let mut descriptors = Vec::new();
    for source in operations {
        let Some(rule) = source.resource_grant else {
            continue;
        };
        let target = operations
            .iter()
            .find(|operation| operation.operation_id == rule.target_operation_id)
            .ok_or(DescriptorError::GrantTarget)?;
        let (Some(action_id), Some(resource)) = (target.source_action, target.resource) else {
            return Err(DescriptorError::GrantTarget);
        };
        descriptors.push(ActionDescriptor::approved(
            action_id.clone(),
            // Response evidence never compares page templates; the target
            // operation keeps one descriptor per action and mapping revision
            // even when several approved lists qualify the same target.
            PageTemplate::parse(target.operation_id.as_str()).map_err(DescriptorError::Domain)?,
            target.operation_id.clone(),
            target.method,
            target.route.clone(),
            ActionTargetRule::Resource(resource.resource_type.clone()),
            BTreeSet::from([resource.field.clone()]),
            resource.view_profile.clone(),
            policy_revision.clone(),
            rule.target_mapping_revision.clone(),
        ));
    }
    Ok(descriptors)
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
#[path = "edge_descriptors/tests.rs"]
mod tests;
