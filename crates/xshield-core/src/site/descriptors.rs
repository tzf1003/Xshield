//! The UI-action descriptor set a site configuration binds its
//! `policy_revision` label to, and the rule that keeps one label to one set.
//!
//! # Purpose
//! A configuration that declares page issuance (`page_actions`) makes the
//! edge supply the action descriptors derived from it under
//! `(tenant, site, policy_revision)` before it serves that configuration, and
//! from then on the edge binds the label to the set's canonical digest: a
//! different set under the same label is refused (`EDGE_APPLY_DESCRIPTOR_*`),
//! and because an apply is atomic per tenant the refusal holds back every
//! site of the tenant (docs/19 §19.2). Approval treats the label as cosmetic,
//! so nothing else stops an operator who edits a page action and keeps the
//! label. This module lets the control plane refuse that edit itself:
//! - [`SiteConfig::edge_descriptor_digest`] computes, from the typed
//!   configuration, the digest the edge derives from its projection: the same
//!   pure [`crate::edge_descriptors::derive`], fed the facts the edge compiler
//!   reads back from `SiteConfig::gateway_config`;
//! - [`check_label_binding`] is the rule: a candidate digest may use a label
//!   only when every binding already known for that label names that digest.
//!
//! Which revisions bind a label, where bindings are recorded and under which
//! lock they are checked is the store's part (`xshield-postgres`,
//! `site_config`); docs/29 "策略修订号与动作描述集合的绑定" is the contract.
//!
//! # Trust boundary
//! Inputs are operator configuration that already passed validation, and
//! binding rows the store read under the tenant lock. Nothing is derived from
//! traffic, page bytes or edge responses.
//!
//! # Invariants
//! - The facts mirror the gateway compiler (`compile_operation` and
//!   `page_actions::operation_facts`) applied to the projection;
//!   `crates/xshield-gateway/tests/site_config_parity.rs` asserts the two
//!   digests are equal for every configuration both sides accept.
//! - The digest covers the descriptor set only: the label itself, issuance
//!   leases and capacities do not enter it, so restoring an earlier set under
//!   its own label reproduces the digest the edge already holds for it.
//! - No `page_actions` means no digest and no binding: the edge supplies
//!   nothing for such a configuration, so it never conflicts.
//!
//! # Errors
//! A configuration with page issuance that the derivation cannot accept
//! (validation refuses all of them first) is reported under
//! [`super::flow::PAGE_ACTIONS_INVALID`].
//!
//! # Audit and resources
//! Pure: no I/O, no clock, no audit. Work and memory are linear in the routes
//! (at most quadratic through `resource_grant` target lookups, as in the
//! derivation); routes are bounded by policy validation.

use super::{SecurityEntry, SiteConfig, SiteRouteConfig, flow::PAGE_ACTIONS_INVALID};
use crate::{
    admission::AdmissionClass,
    domain::{
        ActionId, FieldName, InvalidValue, MappingRevision, OperationId, PolicyRevision,
        ResourceType, ViewProfile,
    },
    edge_descriptors::{
        self, GrantTargetFacts, IssuedBy, OperationFacts, PageActions, ResourceFacts, RouteMatch,
    },
    provenance::{HttpMethod, RouteTemplate},
};
use std::fmt::Write as _;

/// [`InvalidValue`] field when a descriptor set may not use the configured
/// `policy_revision` because the label already denotes something else.
pub const POLICY_REVISION_REUSED: &str = "policy_revision.descriptor_binding";

/// Canonical SHA-256 of one edge-managed descriptor set (the value the edge
/// stores as `policy_revisions.content_digest`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DescriptorDigest([u8; 32]);

impl DescriptorDigest {
    /// Wraps a digest read back from storage; the bytes are not re-derived.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the digest as 64 lowercase hexadecimal digits, the form the
    /// edge stores and compares.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0
            .iter()
            .fold(String::with_capacity(64), |mut hex, byte| {
                // Writing to a String cannot fail.
                let _ = write!(hex, "{byte:02x}");
                hex
            })
    }
}

impl SiteConfig {
    /// The digest of the action-descriptor set the edge derives from this
    /// configuration's projection and supplies under `policy_revision`, or
    /// `None` when no route declares `page_actions` (the edge then supplies
    /// nothing and the label binds nothing).
    ///
    /// Call it on configurations that passed [`SiteConfig::validate_for_site`]
    /// (or that the edge already accepted); it re-parses only what the
    /// derivation reads.
    ///
    /// # Errors
    /// [`InvalidValue`] named [`PAGE_ACTIONS_INVALID`] when a configuration
    /// with page issuance cannot be derived, which validation refuses first.
    pub fn edge_descriptor_digest(&self) -> Result<Option<DescriptorDigest>, InvalidValue> {
        let policy = self.effective_policy();
        // The edge derives (and supplies) nothing unless a page root issues;
        // answering before parsing keeps a plain site free of every rule
        // below, including ones a stored legacy route might not meet.
        if !policy
            .routes
            .iter()
            .any(|route| route.page_actions.is_some())
        {
            return Ok(None);
        }
        let invalid = |_| InvalidValue::new(PAGE_ACTIONS_INVALID);
        let parsed = policy
            .routes
            .iter()
            .map(RouteFacts::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let facts = parsed.iter().map(RouteFacts::facts).collect::<Vec<_>>();
        let revision = PolicyRevision::parse(self.policy_revision.clone()).map_err(invalid)?;
        let provenance = edge_descriptors::derive(&facts, &revision)
            .map_err(|_| InvalidValue::new(PAGE_ACTIONS_INVALID))?;
        Ok(provenance
            .map(|provenance| DescriptorDigest(*provenance.descriptors().content_digest())))
    }
}

/// One route reduced to the owned, parsed values the derivation borrows,
/// exactly as the gateway compiler reads them from the projected operation.
struct RouteFacts {
    operation_id: OperationId,
    method: HttpMethod,
    route: RouteTemplate,
    route_match: RouteMatch,
    admission: AdmissionClass,
    source_action: Option<ActionId>,
    resource: Option<(ResourceType, ViewProfile, FieldName)>,
    issued_by: Option<IssuedBy>,
    page_actions: Option<PageActions>,
    sensor_html: bool,
    resource_grant: Option<(OperationId, MappingRevision)>,
}

impl RouteFacts {
    fn parse(route: &SiteRouteConfig) -> Result<Self, InvalidValue> {
        let invalid = || InvalidValue::new(PAGE_ACTIONS_INVALID);
        let method = match route.method.as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            _ => return Err(invalid()),
        };
        // The edge binds a resource by a query parameter on an exact path or
        // by the final path segment; anything else does not compile there.
        let resource = match (
            &route.resource_type,
            &route.view_profile,
            &route.resource_query_parameter,
            &route.resource_path_parameter,
        ) {
            (None, None, None, None) => None,
            (Some(resource_type), Some(view_profile), Some(field), None)
            | (Some(resource_type), Some(view_profile), None, Some(field)) => Some((
                ResourceType::parse(resource_type.clone()).map_err(|_| invalid())?,
                ViewProfile::parse(view_profile.clone()).map_err(|_| invalid())?,
                FieldName::parse(field.clone()).map_err(|_| invalid())?,
            )),
            _ => return Err(invalid()),
        };
        Ok(Self {
            operation_id: OperationId::parse(route.operation_id.clone()).map_err(|_| invalid())?,
            method,
            route: RouteTemplate::parse(route.path.clone()).map_err(|_| invalid())?,
            route_match: if route.resource_path_parameter.is_some() {
                RouteMatch::FinalSegment
            } else {
                RouteMatch::Exact
            },
            admission: match route.security_entry {
                SecurityEntry::Public => AdmissionClass::Public,
                SecurityEntry::AuthEntry => AdmissionClass::AuthenticationEntry,
                SecurityEntry::AuthenticatedRoot => AdmissionClass::AuthenticatedRoot,
                SecurityEntry::UiActionRequired => AdmissionClass::UiActionRequired,
                SecurityEntry::ShareEntry => AdmissionClass::ShareEntry,
            },
            source_action: route
                .source_action
                .clone()
                .map(ActionId::parse)
                .transpose()
                .map_err(|_| invalid())?,
            resource,
            issued_by: route
                .issued_by
                .as_ref()
                .map(|issued| IssuedBy::parse(issued.page_operation_id.clone(), issued.ttl_seconds))
                .transpose()
                .map_err(|_| invalid())?,
            page_actions: route
                .page_actions
                .as_ref()
                .map(|page| {
                    PageActions::parse(page.mapping_revision.clone(), page.max_active_pages)
                })
                .transpose()
                .map_err(|_| invalid())?,
            // The projection emits the route's response mode verbatim, and the
            // edge compiles exactly `SENSOR_HTML` into a sensor page.
            sensor_html: route.response_mode == "SENSOR_HTML",
            resource_grant: route
                .resource_grant
                .as_ref()
                .map(|grant| {
                    Ok::<_, InvalidValue>((
                        OperationId::parse(grant.target_operation_id.clone())?,
                        MappingRevision::parse(grant.target_mapping_revision.clone())?,
                    ))
                })
                .transpose()
                .map_err(|_| invalid())?,
        })
    }

    fn facts(&self) -> OperationFacts<'_> {
        OperationFacts {
            operation_id: &self.operation_id,
            method: self.method,
            route: &self.route,
            route_match: self.route_match,
            admission: self.admission,
            source_action: self.source_action.as_ref(),
            resource: self
                .resource
                .as_ref()
                .map(|(resource_type, view_profile, field)| ResourceFacts {
                    resource_type,
                    view_profile,
                    field,
                }),
            issued_by: self.issued_by.as_ref(),
            page_actions: self.page_actions.as_ref(),
            sensor_html: self.sensor_html,
            resource_grant: self.resource_grant.as_ref().map(|(target, mapping)| {
                GrantTargetFacts {
                    target_operation_id: target,
                    target_mapping_revision: mapping,
                }
            }),
        }
    }
}

/// What is already known to be bound under one label of one site.
#[derive(Clone, Copy, Debug)]
pub enum LabelBinding<'a> {
    /// The control plane recorded this digest when a revision under the
    /// label became eligible to reach the edge.
    Recorded(DescriptorDigest),
    /// The edge's own policy-revision row: what the edge supplied, or what
    /// was provisioned for it outside the control plane. `content_digest` is
    /// lowercase hexadecimal, as stored.
    Edge {
        /// Row status; the edge supplies only under an `active` revision.
        status: &'a str,
        /// Digest the row binds the label to.
        content_digest: &'a str,
    },
}

/// Why a descriptor set may not use a label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelReuse {
    /// The label already denotes a different descriptor set.
    OtherDescriptors,
    /// The edge holds the label in a status other than `active` (retired by
    /// an operator, or provisioned unapproved); the edge never reactivates
    /// such a revision, so no set can use the label any more.
    InactiveAtEdge,
}

impl LabelReuse {
    /// The [`InvalidValue`] field both refusals are reported under; they need
    /// the same remedy, a new `policy_revision`.
    #[must_use]
    pub const fn field(self) -> &'static str {
        POLICY_REVISION_REUSED
    }
}

/// Whether a configuration whose descriptor digest is `candidate` may be
/// supplied under a label for which `known` bindings exist.
///
/// A configuration without page issuance (`None`) never conflicts: the edge
/// supplies nothing for it. Otherwise every known binding must name the same
/// digest, and an edge row must also be `active`, which is exactly when the
/// edge's own supply answers `Created` or `Existing`.
///
/// # Errors
/// The first [`LabelReuse`] in the order of `known`.
pub fn check_label_binding(
    candidate: Option<&DescriptorDigest>,
    known: &[LabelBinding<'_>],
) -> Result<(), LabelReuse> {
    let Some(candidate) = candidate else {
        return Ok(());
    };
    let candidate_hex = candidate.to_hex();
    for binding in known {
        match binding {
            LabelBinding::Recorded(digest) if digest != candidate => {
                return Err(LabelReuse::OtherDescriptors);
            }
            LabelBinding::Edge { status, .. } if *status != "active" => {
                return Err(LabelReuse::InactiveAtEdge);
            }
            LabelBinding::Edge { content_digest, .. } if *content_digest != candidate_hex => {
                return Err(LabelReuse::OtherDescriptors);
            }
            LabelBinding::Recorded(_) | LabelBinding::Edge { .. } => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The control-plane spelling of the real-browser loop.
    const BROWSER_LOOP: &str = include_str!("../../../../tests/site-config/browser-loop.json");
    /// The digest the edge derives for the loop's projection. Recomputed
    /// independently with Python's hashlib over the documented encoding of
    /// its two descriptors; the gateway parity test asserts that the
    /// gateway's own derivation equals the control-side one.
    const BROWSER_LOOP_DIGEST: &str =
        "2c988679b06f60fadc1fe174812260dac85323bfef3a1e0350dd9214284171fd";

    fn browser_loop() -> SiteConfig {
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

    fn digest(config: &SiteConfig) -> DescriptorDigest {
        config.edge_descriptor_digest().unwrap().unwrap()
    }

    #[test]
    fn the_browser_loop_digest_is_the_one_the_edge_derives() {
        assert_eq!(digest(&browser_loop()).to_hex(), BROWSER_LOOP_DIGEST);
    }

    #[test]
    fn a_configuration_without_page_issuance_has_no_digest_and_never_conflicts() {
        let mut plain = browser_loop();
        for route in &mut plain.policy.routes {
            route.page_actions = None;
            route.issued_by = None;
        }
        assert_eq!(plain.edge_descriptor_digest().unwrap(), None);
        // A resource grant alone keeps externally provisioned descriptors.
        assert!(route(&mut plain, "orders.list").resource_grant.is_some());
        let mut entry_only = plain.clone();
        entry_only.policy.routes.clear();
        assert_eq!(entry_only.edge_descriptor_digest().unwrap(), None);
        let other = LabelBinding::Recorded(digest(&browser_loop()));
        let retired = LabelBinding::Edge {
            status: "retired",
            content_digest: BROWSER_LOOP_DIGEST,
        };
        assert_eq!(check_label_binding(None, &[other, retired]), Ok(()));
    }

    #[test]
    fn the_digest_ignores_the_label_leases_and_capacities() {
        let base = digest(&browser_loop());
        let mut relabelled = browser_loop();
        relabelled.policy_revision = "loop-r9".to_owned();
        relabelled.display_name = "Renamed".to_owned();
        assert_eq!(digest(&relabelled), base);
        let mut leases = browser_loop();
        route(&mut leases, "orders.list")
            .issued_by
            .as_mut()
            .unwrap()
            .ttl_seconds = 1_200;
        let grant = route(&mut leases, "orders.list")
            .resource_grant
            .as_mut()
            .unwrap();
        grant.ttl_seconds = 60;
        grant.max_items = 20;
        grant.max_active_grants = 50;
        route(&mut leases, "app.page")
            .page_actions
            .as_mut()
            .unwrap()
            .max_active_pages = 4;
        assert_eq!(digest(&leases), base);
    }

    #[test]
    fn a_query_pagination_block_does_not_change_the_descriptor_digest() {
        // Pagination parameters never reach an action descriptor: the edge
        // derives descriptors from path, action, mapping and resource facts
        // only, so the block needs independent approval (QUERY_PAGINATION_CHANGED)
        // but must not force a new policy revision label.
        let base = digest(&browser_loop());
        let mut paged = browser_loop();
        route(&mut paged, "orders.list").query_pagination =
            Some(crate::query_pagination::SiteQueryPagination {
                parameters: vec![crate::query_pagination::SiteQueryParameter {
                    name: "page".to_owned(),
                    kind: crate::query_pagination::PaginationKind::Page,
                    max_value: None,
                }],
            });
        paged.validate().unwrap();
        assert_eq!(digest(&paged), base);
    }

    #[test]
    fn a_share_scope_does_not_change_the_descriptor_digest_but_its_issuer_route_does() {
        // The credential an issuer mints and the `share_entry` route that
        // redeems it carry no action descriptor: the edge derives descriptors
        // from page actions and grant targets only. So the share block needs
        // independent approval (SHARE_ISSUE_CHANGED) without forcing a new
        // policy revision label, while the issuer route *as a grant target*
        // is a descriptor like any other and moving it does.
        let share_flow = || -> SiteConfig {
            serde_json::from_str(include_str!(
                "../../../../tests/site-config/share-flow.json"
            ))
            .unwrap()
        };
        let base = digest(&share_flow());
        let mut stripped = share_flow();
        route(&mut stripped, "records.share.issue").share_issue = None;
        stripped
            .policy
            .routes
            .retain(|route| route.operation_id != "records.share.read");
        stripped.validate().unwrap();
        assert_eq!(digest(&stripped), base);
        let mut retuned = share_flow();
        let share = route(&mut retuned, "records.share.issue")
            .share_issue
            .as_mut()
            .unwrap();
        share.ttl_seconds = 60;
        share.max_active_shares = 7;
        "another-rule".clone_into(&mut share.issuance_rule_id);
        "token".clone_into(&mut share.token_field);
        route(&mut retuned, "records.share.read").path = "/shared".to_owned();
        retuned.validate().unwrap();
        assert_eq!(digest(&retuned), base);
        // The issuer is the grant target: its path and view are descriptor
        // facts, so changing them needs a new label.
        let mut moved = share_flow();
        route(&mut moved, "records.share.issue").path = "/share-issue-v2".to_owned();
        moved.validate().unwrap();
        assert_ne!(digest(&moved), base);
        let mut reviewed = share_flow();
        route(&mut reviewed, "records.share.issue").view_profile =
            Some("share_controls_v2".to_owned());
        reviewed.validate().unwrap();
        assert_ne!(digest(&reviewed), base);
    }

    #[test]
    fn a_credential_transition_does_not_change_the_descriptor_digest() {
        // A refresh or an account switch carries no action descriptor: the
        // edge derives descriptors from page actions and grant targets only.
        // The blocks need independent approval (AUTH_TRANSITION_CHANGED) but
        // must not force a new policy revision label.
        let with: SiteConfig = serde_json::from_str(include_str!(
            "../../../../tests/site-config/auth-transition-flow.json"
        ))
        .unwrap();
        let mut without = with.clone();
        without
            .policy
            .routes
            .retain(|route| route.auth_refresh.is_none() && route.auth_context_switch.is_none());
        with.validate().unwrap();
        without.validate().unwrap();
        assert_eq!(digest(&with), digest(&without));
        assert_eq!(digest(&with), digest(&browser_loop()));
        let mut retuned = with.clone();
        for route in &mut retuned.policy.routes {
            for block in [&mut route.auth_refresh, &mut route.auth_context_switch]
                .into_iter()
                .flatten()
            {
                block.credential_ttl_seconds = 60;
                "/token".clone_into(&mut block.bearer_pointer);
            }
        }
        retuned.validate().unwrap();
        assert_eq!(digest(&retuned), digest(&with));
    }

    type Edit = fn(&mut SiteConfig);

    #[test]
    fn the_digest_tracks_every_descriptor_field() {
        let base = digest(&browser_loop());
        let edits: [(&str, Edit); 6] = [
            ("issued action path", |c| {
                route(c, "orders.list").path = "/orders-all".to_owned();
            }),
            ("issued action source", |c| {
                route(c, "orders.list").source_action = Some("app.orders.all".to_owned());
            }),
            ("page mapping revision", |c| {
                route(c, "app.page")
                    .page_actions
                    .as_mut()
                    .unwrap()
                    .mapping_revision = "app-map-r2".to_owned();
            }),
            ("grant target mapping revision", |c| {
                route(c, "orders.list")
                    .resource_grant
                    .as_mut()
                    .unwrap()
                    .target_mapping_revision = "orders-map-r2".to_owned();
            }),
            ("grant target view", |c| {
                route(c, "orders.read").view_profile = Some("customer_summary".to_owned());
            }),
            ("grant target route", |c| {
                let target = route(c, "orders.read");
                target.path = "/order/{order_id}".to_owned();
            }),
        ];
        for (label, edit) in edits {
            let mut changed = browser_loop();
            edit(&mut changed);
            changed
                .validate()
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_ne!(digest(&changed), base, "{label}");
        }
    }

    #[test]
    fn one_label_denotes_one_digest() {
        let original = digest(&browser_loop());
        let mut moved = browser_loop();
        route(&mut moved, "orders.list").path = "/orders-all".to_owned();
        let moved = digest(&moved);
        let recorded = LabelBinding::Recorded(original);
        let edge = LabelBinding::Edge {
            status: "active",
            content_digest: BROWSER_LOOP_DIGEST,
        };
        // A new label: nothing is known yet.
        assert_eq!(check_label_binding(Some(&moved), &[]), Ok(()));
        // The same label and the same set, as recorded and as the edge holds it.
        assert_eq!(
            check_label_binding(Some(&original), &[recorded, edge]),
            Ok(())
        );
        // The same label for another set, wherever the binding is known.
        assert_eq!(
            check_label_binding(Some(&moved), &[recorded]),
            Err(LabelReuse::OtherDescriptors)
        );
        assert_eq!(
            check_label_binding(Some(&moved), &[edge]),
            Err(LabelReuse::OtherDescriptors)
        );
        // A label the edge no longer holds as active is unusable for any set.
        let retired = LabelBinding::Edge {
            status: "retired",
            content_digest: BROWSER_LOOP_DIGEST,
        };
        assert_eq!(
            check_label_binding(Some(&original), &[recorded, retired]),
            Err(LabelReuse::InactiveAtEdge)
        );
        assert_eq!(LabelReuse::InactiveAtEdge.field(), POLICY_REVISION_REUSED);
    }

    /// Restoring an earlier set reproduces its digest exactly, so a rollback
    /// under the label that set was bound to is accepted, like the edge's
    /// `Existing` answer.
    #[test]
    fn a_rollback_to_an_identical_earlier_set_reuses_its_label() {
        let first = browser_loop();
        let mut second = browser_loop();
        route(&mut second, "orders.list").path = "/orders-all".to_owned();
        second.policy_revision = "loop-r2".to_owned();
        assert_ne!(digest(&second), digest(&first));
        let restored: SiteConfig =
            serde_json::from_value(serde_json::to_value(&first).unwrap()).unwrap();
        assert_eq!(
            check_label_binding(
                Some(&digest(&restored)),
                &[LabelBinding::Recorded(digest(&first))]
            ),
            Ok(())
        );
    }

    #[test]
    fn digests_render_as_lowercase_hex() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0x0f;
        let digest = DescriptorDigest::from_bytes(bytes);
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("ab00") && hex.ends_with("0f"));
        assert_eq!(digest.as_bytes(), &bytes);
    }
}
