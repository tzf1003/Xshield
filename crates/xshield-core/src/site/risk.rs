//! Which configuration changes need independent approval.
//!
//! Approval exists so that one account cannot change what the edge serves
//! without a second pair of eyes. The decision is therefore a pure function of
//! *what the edge is serving now* (the baseline: the configuration of the
//! active revision) and the desired revision. It never looks at the previous
//! *desired* revision: that value is rewritten by every save, so a rule based
//! on it can be cleared by re-submitting equal content, which is exactly how an
//! unapproved change used to reach the edge.
//!
//! Every difference between baseline and desired counts except two cosmetic
//! labels. The rule is deliberately a whitelist of what may change freely
//! rather than a list of what is dangerous: a field added to the configuration
//! later is risky until someone decides otherwise. Changing the
//! `policy_revision` label needs no approval, but the label is not free: for a
//! configuration with page issuance it names one action-descriptor set, and
//! reusing it for another set is refused outright (see
//! [`super::descriptors`]), whoever approves.
//!
//! Routes of the browser provenance flow (authentication entries, sensor
//! pages, page-issued actions and response-derived resource grants) decide
//! who obtains identity and which UI actions exist at all. Changes to them get
//! dedicated reasons on top of `ROUTES_CHANGED`, also when a site goes live
//! with them, and those reasons can only be cleared by an independent
//! approver: the `site.config.apply_direct` capability does not waive them
//! (see [`direct_apply_may_waive`]).

use super::{SiteConfig, SitePolicyConfig, SiteRouteConfig};
use std::collections::BTreeSet;

/// Why a configuration change needs independent approval.
///
/// The tokens are stored with the apply intent and returned to operators, so
/// they are stable API.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ChangeRisk {
    /// The site starts being served: it is new, was a draft, or was paused.
    Activation,
    /// A served site stops being served (paused or turned back into a draft).
    Takedown,
    /// Upstream address, server name or TLS mode.
    UpstreamChanged,
    /// Public origin used for host routing and the sensor.
    OriginChanged,
    /// Internal edge listener port.
    ListenPortChanged,
    /// Top-level entry path or entry admission.
    EntryChanged,
    /// Any route added, removed or changed: admission, source action, resource
    /// binding, crypto, response mode or size.
    RoutesChanged,
    /// Identity binding settings.
    IdentityChanged,
    /// Site-level crypto adapter, failure strategy or protocol.
    CryptoChanged,
    /// WAF enablement, blocked headers or fragments, cookie cap.
    WafChanged,
    /// Request/response size and rate limits, in either direction.
    LimitsChanged,
    /// Upstream health probe settings.
    HealthCheckChanged,
    /// Secret references.
    SecretRefsChanged,
    /// Browser sensor injection.
    SensorChanged,
    /// Static-asset fallback depth.
    StaticAssetPolicyChanged,
    /// Trusted object-access marker toward the origin.
    ObjectAccessChanged,
    /// A route with the `auth_entry` admission, an `auth_binding` or an
    /// `auth_revoke` was added, removed or changed in any field: who obtains
    /// or loses an identity binding.
    AuthEntryChanged,
    /// A `SENSOR_HTML` route was added, removed or changed in any field:
    /// which exact page builds the edge injects into and releases.
    SensorHtmlChanged,
    /// A page root with `page_actions` or an `issued_by` route was added,
    /// removed or changed in any field: which first-hop UI actions a page
    /// issues.
    PageActionsChanged,
    /// A route with a `resource_grant` or a route such a grant targets was
    /// added, removed or changed in any field: which resources a response
    /// qualifies for which action.
    ResourceGrantChanged,
    /// A route with a `query_pagination` block was added, removed or changed
    /// in any field: which query parameters a list that issues grants (or a
    /// UI-action route) may carry to the origin.
    QueryPaginationChanged,
    /// A route with a `share_issue` or a `share_entry` admission was added,
    /// removed or changed in any field: which responses mint a reusable
    /// read-only credential and which route redeems it without identity.
    ShareIssueChanged,
    /// A difference that no category above names; risky by default.
    OtherChange,
}

impl ChangeRisk {
    /// Every reason, in token order of declaration.
    pub const ALL: [Self; 23] = [
        Self::Activation,
        Self::Takedown,
        Self::UpstreamChanged,
        Self::OriginChanged,
        Self::ListenPortChanged,
        Self::EntryChanged,
        Self::RoutesChanged,
        Self::IdentityChanged,
        Self::CryptoChanged,
        Self::WafChanged,
        Self::LimitsChanged,
        Self::HealthCheckChanged,
        Self::SecretRefsChanged,
        Self::SensorChanged,
        Self::StaticAssetPolicyChanged,
        Self::ObjectAccessChanged,
        Self::AuthEntryChanged,
        Self::SensorHtmlChanged,
        Self::PageActionsChanged,
        Self::ResourceGrantChanged,
        Self::QueryPaginationChanged,
        Self::ShareIssueChanged,
        Self::OtherChange,
    ];

    /// Parses a stored token; `None` for a token this version does not know.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|risk| risk.as_str() == token)
    }

    /// Whether only an independent `PolicyApprover` may clear this reason.
    ///
    /// The provenance-flow reasons decide who obtains identity and which UI
    /// actions and resource grants exist; a single principal holding
    /// `site.config.apply_direct` must not be able to introduce or alter them
    /// without a second pair of eyes.
    #[must_use]
    pub const fn requires_independent_approval(self) -> bool {
        matches!(
            self,
            Self::AuthEntryChanged
                | Self::SensorHtmlChanged
                | Self::PageActionsChanged
                | Self::ResourceGrantChanged
                | Self::QueryPaginationChanged
                | Self::ShareIssueChanged
        )
    }

    /// Returns the stable upper-case token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activation => "ACTIVATION",
            Self::Takedown => "TAKEDOWN",
            Self::UpstreamChanged => "UPSTREAM_CHANGED",
            Self::OriginChanged => "ORIGIN_CHANGED",
            Self::ListenPortChanged => "LISTEN_PORT_CHANGED",
            Self::EntryChanged => "ENTRY_CHANGED",
            Self::RoutesChanged => "ROUTES_CHANGED",
            Self::IdentityChanged => "IDENTITY_CHANGED",
            Self::CryptoChanged => "CRYPTO_CHANGED",
            Self::WafChanged => "WAF_CHANGED",
            Self::LimitsChanged => "LIMITS_CHANGED",
            Self::HealthCheckChanged => "HEALTH_CHECK_CHANGED",
            Self::SecretRefsChanged => "SECRET_REFS_CHANGED",
            Self::SensorChanged => "SENSOR_CHANGED",
            Self::StaticAssetPolicyChanged => "STATIC_ASSET_POLICY_CHANGED",
            Self::ObjectAccessChanged => "OBJECT_ACCESS_CHANGED",
            Self::AuthEntryChanged => "AUTH_ENTRY_CHANGED",
            Self::SensorHtmlChanged => "SENSOR_HTML_CHANGED",
            Self::PageActionsChanged => "PAGE_ACTIONS_CHANGED",
            Self::ResourceGrantChanged => "RESOURCE_GRANT_CHANGED",
            Self::QueryPaginationChanged => "QUERY_PAGINATION_CHANGED",
            Self::ShareIssueChanged => "SHARE_ISSUE_CHANGED",
            Self::OtherChange => "OTHER_CHANGE",
        }
    }
}

/// Whether the `site.config.apply_direct` capability may stand in for the
/// independent approval these stored reasons require.
///
/// `false` as soon as one reason requires an independent approver, and also
/// for a token this version does not recognize: a reason written by a newer
/// release is never waived by an older one.
#[must_use]
pub fn direct_apply_may_waive<S: AsRef<str>>(reasons: &[S]) -> bool {
    reasons.iter().all(|reason| {
        ChangeRisk::from_token(reason.as_ref())
            .is_some_and(|risk| !risk.requires_independent_approval())
    })
}

/// The provenance-flow facets: which routes of a policy take part in each.
///
/// A facet compares its member routes whole, not only the block that makes
/// them members: a page root's path or approved build is as much part of what
/// its issued actions mean as its `page_actions`. A route can belong to
/// several facets (the loop's page root is a sensor page and a page root), and
/// a change to it names each; every flow reason needs the same independent
/// approval, so naming one more never weakens anything.
/// Whether a route of a policy takes part in a facet.
type FacetMember = fn(&SitePolicyConfig, &SiteRouteConfig) -> bool;

const FLOW_FACETS: [(ChangeRisk, FacetMember); 6] = [
    (ChangeRisk::AuthEntryChanged, |_, route| {
        route.security_entry == super::SecurityEntry::AuthEntry
            || route.auth_binding.is_some()
            || route.auth_revoke.is_some()
    }),
    (ChangeRisk::SensorHtmlChanged, |_, route| {
        route.response_mode == "SENSOR_HTML" || route.sensor_html.is_some()
    }),
    (ChangeRisk::PageActionsChanged, |_, route| {
        route.page_actions.is_some() || route.issued_by.is_some()
    }),
    // Which query parameters reach the origin on a route that otherwise
    // admits none; widening it is a change to what a caller may influence.
    (ChangeRisk::QueryPaginationChanged, |_, route| {
        route.query_pagination.is_some()
    }),
    // A share issuer mints a reusable credential for one resource and its
    // `share_entry` target redeems it without any identity; either end
    // changing changes who can read what.
    (ChangeRisk::ShareIssueChanged, |_, route| {
        route.share_issue.is_some() || route.security_entry == super::SecurityEntry::ShareEntry
    }),
    // A grant's meaning depends on its target route as much as on the grant.
    (ChangeRisk::ResourceGrantChanged, |policy, route| {
        route.resource_grant.is_some()
            || policy.routes.iter().any(|source| {
                source
                    .resource_grant
                    .as_ref()
                    .is_some_and(|grant| grant.target_operation_id == route.operation_id)
            })
    }),
];

/// The routes of `policy` that take part in a facet, ordered by operation.
fn facet_routes(policy: &SitePolicyConfig, member: FacetMember) -> Vec<&SiteRouteConfig> {
    let mut routes = policy
        .routes
        .iter()
        .filter(|route| member(policy, route))
        .collect::<Vec<_>>();
    routes.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    routes
}

/// The flow facets whose participating routes differ between `before` (what
/// is served, or nothing) and `after`.
fn changed_flow_facets(
    before: Option<&SitePolicyConfig>,
    after: &SitePolicyConfig,
) -> impl Iterator<Item = ChangeRisk> {
    FLOW_FACETS
        .into_iter()
        .filter(move |(_, member)| {
            let served = before.map(|policy| facet_routes(policy, *member));
            served.unwrap_or_default() != facet_routes(after, *member)
        })
        .map(|(risk, _)| risk)
}

/// The configuration with every cosmetic field neutralized and every
/// order-insensitive collection sorted, so equality means "same behaviour".
fn comparable(config: &SiteConfig) -> SiteConfig {
    let mut normalized = config.clone();
    normalized.display_name.clear();
    normalized.policy_revision.clear();
    normalized.policy = config.effective_policy();
    normalized
        .policy
        .routes
        .sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    normalized
        .policy
        .secret_refs
        .sort_by(|left, right| left.kind.cmp(&right.kind));
    normalized
}

/// Classifies the change from `baseline` (what the edge serves) to `desired`.
///
/// `baseline` is the configuration of the site's active revision, or `None`
/// when the site has never been applied. A baseline that is not itself served
/// (draft or paused) is the same as no baseline: nothing is being served.
/// `desired.listen_port` must be the resolved port, not the request for `0`.
///
/// An empty result means the change may be applied without approval.
#[must_use]
pub fn assess_change_risk(baseline: Option<&SiteConfig>, desired: &SiteConfig) -> Vec<ChangeRisk> {
    let served = baseline.filter(|baseline| baseline.is_serving());
    if !desired.is_serving() {
        // Nothing is exposed by a draft or paused configuration; taking down
        // what was served is the only change that matters.
        return if served.is_some() {
            vec![ChangeRisk::Takedown]
        } else {
            Vec::new()
        };
    }
    // Going live is the change an approver exists for, whatever else differs:
    // for a never-served site there is no baseline to compare against, and
    // comparing against the last *desired* draft would let a second save clear
    // the requirement. Flow routes it goes live with are new as well, and are
    // named so that a direct apply cannot introduce them unreviewed.
    let Some(before) = served else {
        return std::iter::once(ChangeRisk::Activation)
            .chain(changed_flow_facets(None, &desired.effective_policy()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    };

    let (old, new) = (before.effective_policy(), desired.effective_policy());
    let mut routes_old = old.routes.clone();
    let mut routes_new = new.routes.clone();
    routes_old.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    routes_new.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    let mut secrets_old = old.secret_refs.clone();
    let mut secrets_new = new.secret_refs.clone();
    secrets_old.sort_by(|left, right| left.kind.cmp(&right.kind));
    secrets_new.sort_by(|left, right| left.kind.cmp(&right.kind));

    let mut risks = BTreeSet::new();
    for (changed, risk) in [
        (
            before.upstream_address != desired.upstream_address
                || before.upstream_server_name != desired.upstream_server_name
                || before.upstream_tls != desired.upstream_tls,
            ChangeRisk::UpstreamChanged,
        ),
        (
            before.public_origin != desired.public_origin,
            ChangeRisk::OriginChanged,
        ),
        (
            before.listen_port != desired.listen_port,
            ChangeRisk::ListenPortChanged,
        ),
        (
            before.entry_path != desired.entry_path
                || before.security_entry != desired.security_entry,
            ChangeRisk::EntryChanged,
        ),
        (routes_old != routes_new, ChangeRisk::RoutesChanged),
        (old.identity != new.identity, ChangeRisk::IdentityChanged),
        (old.crypto != new.crypto, ChangeRisk::CryptoChanged),
        (old.waf != new.waf, ChangeRisk::WafChanged),
        (old.limits != new.limits, ChangeRisk::LimitsChanged),
        (
            old.health_check != new.health_check,
            ChangeRisk::HealthCheckChanged,
        ),
        (secrets_old != secrets_new, ChangeRisk::SecretRefsChanged),
        (
            before.sensor_enabled != desired.sensor_enabled,
            ChangeRisk::SensorChanged,
        ),
        (
            old.static_asset_max_path_depth != new.static_asset_max_path_depth,
            ChangeRisk::StaticAssetPolicyChanged,
        ),
        (
            old.origin_object_access_enforced != new.origin_object_access_enforced,
            ChangeRisk::ObjectAccessChanged,
        ),
    ] {
        if changed {
            risks.insert(risk);
        }
    }
    risks.extend(changed_flow_facets(Some(&old), &new));
    // Anything the categories above do not name (a field added later) is
    // still a change to what the edge serves.
    if risks.is_empty() && comparable(before) != comparable(desired) {
        risks.insert(ChangeRisk::OtherChange);
    }
    risks.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SecurityEntry, SitePolicyConfig, SiteRequestCrypto, SiteResponseCrypto, SiteRouteConfig,
        SiteSecretReference,
    };

    fn route(id: &str, path: &str, entry: SecurityEntry) -> SiteRouteConfig {
        SiteRouteConfig {
            operation_id: id.to_owned(),
            method: "GET".to_owned(),
            path: path.to_owned(),
            security_entry: entry,
            source_action: (entry == SecurityEntry::UiActionRequired).then(|| format!("{id}.open")),
            resource_type: None,
            view_profile: None,
            resource_query_parameter: None,
            resource_path_parameter: None,
            request_crypto: None,
            response_crypto: None,
            response_mode: String::new(),
            max_response_bytes: 1_048_576,
            auth_binding: None,
            auth_revoke: None,
            sensor_html: None,
            page_actions: None,
            issued_by: None,
            resource_grant: None,
            query_pagination: None,
            share_issue: None,
        }
    }

    fn base() -> SiteConfig {
        SiteConfig {
            display_name: "Demo".to_owned(),
            public_origin: "https://demo.example.test".to_owned(),
            upstream_address: "8.8.8.8:9000".to_owned(),
            upstream_server_name: "origin.example.test".to_owned(),
            upstream_tls: false,
            listen_port: 6100,
            entry_path: "/".to_owned(),
            security_entry: "ui_action_required".to_owned(),
            sensor_enabled: false,
            policy_revision: "policy-v1".to_owned(),
            status: "active".to_owned(),
            policy: SitePolicyConfig {
                routes: vec![
                    route("home", "/", SecurityEntry::UiActionRequired),
                    route("docs", "/docs", SecurityEntry::Public),
                ],
                secret_refs: vec![SiteSecretReference {
                    kind: "tls".to_owned(),
                    secret_ref: "secret://tls/demo".to_owned(),
                    key_id: "tls-v1".to_owned(),
                    state: "active".to_owned(),
                }],
                ..SitePolicyConfig::default()
            },
        }
    }

    type Mutation = fn(&mut SiteConfig);

    fn first_route(config: &mut SiteConfig) -> &mut SiteRouteConfig {
        &mut config.policy.routes[0]
    }

    /// Every trigger, as `(name, change, expected reasons)`. Each is applied
    /// forwards (base to changed) and backwards (changed to base): the rule
    /// is "any change", so tightening needs approval just like loosening.
    #[allow(clippy::too_many_lines)]
    fn triggers() -> Vec<(&'static str, Mutation, Vec<ChangeRisk>)> {
        use ChangeRisk::*;
        vec![
            (
                "upstream address",
                |c| c.upstream_address = "8.8.4.4:9000".to_owned(),
                vec![UpstreamChanged],
            ),
            (
                "upstream port",
                |c| c.upstream_address = "8.8.8.8:9001".to_owned(),
                vec![UpstreamChanged],
            ),
            (
                "upstream server name",
                |c| c.upstream_server_name = "other.example.test".to_owned(),
                vec![UpstreamChanged],
            ),
            (
                "upstream tls",
                |c| c.upstream_tls = true,
                vec![UpstreamChanged],
            ),
            (
                "public origin",
                |c| c.public_origin = "https://other.example.test".to_owned(),
                vec![OriginChanged],
            ),
            (
                "listen port",
                |c| c.listen_port = 6101,
                vec![ListenPortChanged],
            ),
            (
                "entry path",
                |c| c.entry_path = "/start".to_owned(),
                vec![EntryChanged],
            ),
            (
                "entry admission",
                |c| c.security_entry = "public".to_owned(),
                vec![EntryChanged],
            ),
            (
                "route added",
                |c| {
                    c.policy
                        .routes
                        .push(route("extra", "/extra", SecurityEntry::Public));
                },
                vec![RoutesChanged],
            ),
            (
                "route removed",
                |c| {
                    c.policy.routes.pop();
                },
                vec![RoutesChanged],
            ),
            (
                "route admission downgraded to authenticated",
                |c| {
                    let route = first_route(c);
                    route.security_entry = SecurityEntry::AuthenticatedRoot;
                    route.source_action = None;
                },
                vec![RoutesChanged],
            ),
            (
                "route widened to public",
                |c| {
                    let route = first_route(c);
                    route.security_entry = SecurityEntry::Public;
                    route.source_action = None;
                },
                vec![RoutesChanged],
            ),
            (
                "route source action",
                |c| first_route(c).source_action = Some("home.view".to_owned()),
                vec![RoutesChanged],
            ),
            (
                "route path",
                |c| first_route(c).path = "/home".to_owned(),
                vec![RoutesChanged],
            ),
            (
                "route method",
                |c| first_route(c).method = "POST".to_owned(),
                vec![RoutesChanged],
            ),
            (
                "route resource binding",
                |c| {
                    let route = first_route(c);
                    route.resource_type = Some("orders".to_owned());
                    route.view_profile = Some("summary".to_owned());
                    route.resource_query_parameter = Some("order_id".to_owned());
                },
                vec![RoutesChanged],
            ),
            (
                "route request crypto",
                |c| {
                    first_route(c).request_crypto = Some(SiteRequestCrypto::Observe {
                        adapter_revision: "observe-v1".to_owned(),
                    });
                },
                vec![RoutesChanged],
            ),
            (
                "route response crypto",
                |c| {
                    first_route(c).response_crypto = Some(SiteResponseCrypto {
                        mode: "DIRECT_ENCRYPT".to_owned(),
                        adapter_revision: "rev-1".to_owned(),
                        key_id: "key-r".to_owned(),
                        key_not_before: 1,
                        key_expires_at: 2,
                        message_ttl_seconds: 60,
                        max_envelope_bytes: 4_194_304,
                    });
                },
                vec![RoutesChanged],
            ),
            (
                "route response mode",
                |c| first_route(c).response_mode = "BUFFERED_JSON".to_owned(),
                vec![RoutesChanged],
            ),
            (
                "route response size",
                |c| first_route(c).max_response_bytes = 2_048,
                vec![RoutesChanged],
            ),
            (
                "identity enabled",
                |c| c.policy.identity.enabled = true,
                vec![IdentityChanged],
            ),
            (
                "identity ttl",
                |c| c.policy.identity.session_ttl_seconds = 60,
                vec![IdentityChanged],
            ),
            (
                "identity generation",
                |c| c.policy.identity.generation = 2,
                vec![IdentityChanged],
            ),
            (
                "crypto adapter",
                |c| c.policy.crypto.adapter_revision = "observe-v2".to_owned(),
                vec![CryptoChanged],
            ),
            (
                "crypto failure strategy",
                |c| c.policy.crypto.failure_strategy = "observe".to_owned(),
                vec![CryptoChanged],
            ),
            (
                "crypto protocol",
                |c| c.policy.crypto.protocol_version = Some("p1".to_owned()),
                vec![CryptoChanged],
            ),
            (
                "waf disabled",
                |c| c.policy.waf.enabled = false,
                vec![WafChanged],
            ),
            (
                "waf blocked headers",
                |c| c.policy.waf.blocked_headers = vec!["X-Evil".to_owned()],
                vec![WafChanged],
            ),
            (
                "waf fragments",
                |c| c.policy.waf.blocked_query_fragments = vec!["<script".to_owned()],
                vec![WafChanged],
            ),
            (
                "waf cookie cap",
                |c| c.policy.waf.max_cookie_bytes = 16_384,
                vec![WafChanged],
            ),
            (
                "request body limit",
                |c| c.policy.limits.max_request_body_bytes = 2_097_152,
                vec![LimitsChanged],
            ),
            (
                "response body limit",
                |c| c.policy.limits.max_response_body_bytes = 1_048_576,
                vec![LimitsChanged],
            ),
            (
                "requests per second",
                |c| c.policy.limits.requests_per_second = 2_000,
                vec![LimitsChanged],
            ),
            (
                "burst",
                |c| c.policy.limits.burst = 4_000,
                vec![LimitsChanged],
            ),
            (
                "health path",
                |c| c.policy.health_check.path = "/status".to_owned(),
                vec![HealthCheckChanged],
            ),
            (
                "health interval",
                |c| c.policy.health_check.interval_seconds = 30,
                vec![HealthCheckChanged],
            ),
            (
                "health timeout",
                |c| c.policy.health_check.timeout_ms = 500,
                vec![HealthCheckChanged],
            ),
            (
                "health status",
                |c| c.policy.health_check.expected_status = 204,
                vec![HealthCheckChanged],
            ),
            (
                "secret reference added",
                |c| {
                    c.policy.secret_refs.push(SiteSecretReference {
                        kind: "session_hmac".to_owned(),
                        secret_ref: "secret://hmac/demo".to_owned(),
                        key_id: "hmac-v1".to_owned(),
                        state: "active".to_owned(),
                    });
                },
                vec![SecretRefsChanged],
            ),
            (
                "secret reference rotated",
                |c| c.policy.secret_refs[0].key_id = "tls-v2".to_owned(),
                vec![SecretRefsChanged],
            ),
            (
                "secret reference removed",
                |c| c.policy.secret_refs.clear(),
                vec![SecretRefsChanged],
            ),
            ("sensor", |c| c.sensor_enabled = true, vec![SensorChanged]),
            (
                "static asset depth",
                |c| c.policy.static_asset_max_path_depth = 3,
                vec![StaticAssetPolicyChanged],
            ),
            (
                "origin object access",
                |c| c.policy.origin_object_access_enforced = true,
                vec![ObjectAccessChanged],
            ),
            (
                "several categories at once",
                |c| {
                    c.upstream_tls = true;
                    c.policy.waf.enabled = false;
                    c.sensor_enabled = true;
                },
                vec![UpstreamChanged, WafChanged, SensorChanged],
            ),
        ]
    }

    fn sorted(mut risks: Vec<ChangeRisk>) -> Vec<ChangeRisk> {
        risks.sort();
        risks
    }

    #[test]
    fn every_trigger_requires_approval_in_both_directions() {
        for (name, mutate, expected) in triggers() {
            let before = base();
            let mut after = base();
            mutate(&mut after);
            assert_ne!(before, after, "{name} must change the configuration");
            let expected = sorted(expected);
            assert_eq!(
                assess_change_risk(Some(&before), &after),
                expected,
                "{name}, forwards"
            );
            assert_eq!(
                assess_change_risk(Some(&after), &before),
                expected,
                "{name}, backwards"
            );
        }
    }

    /// The reviewer's missed weakenings are triggers, not special cases:
    /// a route downgraded from a UI action to authenticated, WAF protections
    /// cleared, object-access enforcement turned off and limits raised.
    #[test]
    fn weakening_changes_the_old_predicate_missed_require_approval() {
        let mut weakened = base();
        weakened.policy.waf.blocked_headers = Vec::new();
        weakened.policy.waf.blocked_query_fragments = Vec::new();
        let mut hardened = base();
        hardened.policy.waf.blocked_headers = vec!["X-Evil".to_owned()];
        hardened.policy.waf.blocked_query_fragments = vec!["<script".to_owned()];
        assert_eq!(
            assess_change_risk(Some(&hardened), &weakened),
            vec![ChangeRisk::WafChanged],
            "clearing WAF fragments and blocked headers"
        );
        let mut enforced = base();
        enforced.policy.origin_object_access_enforced = true;
        assert_eq!(
            assess_change_risk(Some(&enforced), &base()),
            vec![ChangeRisk::ObjectAccessChanged]
        );
        let mut raised = base();
        raised.policy.limits.requests_per_second = 900_000;
        raised.policy.limits.burst = 1_900_000;
        assert_eq!(
            assess_change_risk(Some(&base()), &raised),
            vec![ChangeRisk::LimitsChanged]
        );
    }

    #[test]
    fn cosmetic_and_order_only_changes_do_not_require_approval() {
        let before = base();
        assert_eq!(assess_change_risk(Some(&before), &before), Vec::new());
        let mut relabelled = base();
        relabelled.display_name = "Renamed demo".to_owned();
        relabelled.policy_revision = "policy-v2".to_owned();
        assert_eq!(assess_change_risk(Some(&before), &relabelled), Vec::new());
        let mut reordered = base();
        reordered.policy.routes.reverse();
        assert_eq!(assess_change_risk(Some(&before), &reordered), Vec::new());
        let mut two_secrets = base();
        two_secrets.policy.secret_refs.push(SiteSecretReference {
            kind: "session_hmac".to_owned(),
            secret_ref: "secret://hmac/demo".to_owned(),
            key_id: "hmac-v1".to_owned(),
            state: "active".to_owned(),
        });
        let mut secrets_reordered = two_secrets.clone();
        secrets_reordered.policy.secret_refs.reverse();
        assert_eq!(
            assess_change_risk(Some(&two_secrets), &secrets_reordered),
            Vec::new()
        );
    }

    /// With no routes configured the entry path and admission *are* the route;
    /// spelling the same default route out is not a change.
    #[test]
    fn the_default_entry_route_and_its_explicit_spelling_are_equivalent() {
        let mut implicit = base();
        implicit.policy.routes.clear();
        let mut explicit = implicit.clone();
        explicit.policy.routes = explicit.effective_policy().routes;
        assert_eq!(assess_change_risk(Some(&implicit), &explicit), Vec::new());
        let mut moved = implicit.clone();
        moved.entry_path = "/start".to_owned();
        assert_eq!(
            assess_change_risk(Some(&implicit), &moved),
            vec![ChangeRisk::EntryChanged, ChangeRisk::RoutesChanged],
            "the effective route moved as well"
        );
    }

    #[test]
    fn going_live_always_requires_approval_and_a_second_save_cannot_clear_it() {
        // No baseline: whatever the configuration, activation is the change.
        assert_eq!(
            assess_change_risk(None, &base()),
            vec![ChangeRisk::Activation]
        );
        let mut paused = base();
        paused.status = "paused".to_owned();
        let mut draft = base();
        draft.status = "draft".to_owned();
        // A baseline that is not served is no baseline at all, so unpausing or
        // promoting a draft needs approval even if nothing else changed...
        assert_eq!(
            assess_change_risk(Some(&paused), &base()),
            vec![ChangeRisk::Activation]
        );
        assert_eq!(
            assess_change_risk(Some(&draft), &base()),
            vec![ChangeRisk::Activation]
        );
        // ...and the verdict is a function of the baseline only: saving the
        // same desired configuration again (a "new revision" of equal
        // content) is evaluated against the same baseline and gives the same
        // answer.
        let first = assess_change_risk(None, &base());
        let resubmitted = assess_change_risk(None, &base());
        assert_eq!(first, resubmitted);
        let served = base();
        let mut risky = base();
        risky.upstream_address = "8.8.4.4:9000".to_owned();
        assert_eq!(
            assess_change_risk(Some(&served), &risky),
            assess_change_risk(Some(&served), &risky.clone())
        );
    }

    #[test]
    fn taking_a_served_site_down_requires_approval_but_unserved_edits_do_not() {
        let mut paused = base();
        paused.status = "paused".to_owned();
        let mut draft = base();
        draft.status = "draft".to_owned();
        assert_eq!(
            assess_change_risk(Some(&base()), &paused),
            vec![ChangeRisk::Takedown]
        );
        assert_eq!(
            assess_change_risk(Some(&base()), &draft),
            vec![ChangeRisk::Takedown]
        );
        // Nothing is served on either side: not an exposure change.
        let mut edited = paused.clone();
        edited.upstream_address = "1.1.1.1:9000".to_owned();
        assert_eq!(assess_change_risk(Some(&paused), &edited), Vec::new());
        assert_eq!(assess_change_risk(None, &paused), Vec::new());
        assert_eq!(assess_change_risk(None, &draft), Vec::new());
        assert_eq!(assess_change_risk(Some(&draft), &paused), Vec::new());
    }

    #[test]
    fn tokens_are_unique_and_stable() {
        let all = ChangeRisk::ALL;
        let tokens = all
            .iter()
            .map(|risk| risk.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(tokens.len(), all.len());
        assert!(tokens.iter().all(|token| {
            token
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        }));
        for risk in all {
            assert_eq!(ChangeRisk::from_token(risk.as_str()), Some(risk));
        }
        assert_eq!(ChangeRisk::from_token("activation"), None);
        // `ALL` is declared in `Ord` order, which is the order of every result.
        assert!(all.windows(2).all(|pair| pair[0] < pair[1]));
    }

    /// The real-browser loop topology as the control plane stores it.
    fn flow() -> SiteConfig {
        serde_json::from_str(include_str!(
            "../../../../tests/site-config/browser-loop.json"
        ))
        .unwrap()
    }

    fn flow_route<'a>(config: &'a mut SiteConfig, id: &str) -> &'a mut SiteRouteConfig {
        config
            .policy
            .routes
            .iter_mut()
            .find(|route| route.operation_id == id)
            .unwrap()
    }

    /// Each flow facet fires for its own blocks and for the routes they
    /// depend on, in both directions, always together with `ROUTES_CHANGED`.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn flow_route_changes_name_their_facet_in_both_directions() {
        use ChangeRisk::*;
        let cases: Vec<(&str, Mutation, Vec<ChangeRisk>)> = vec![
            (
                "credential lease",
                |c| {
                    flow_route(c, "auth.login")
                        .auth_binding
                        .as_mut()
                        .unwrap()
                        .credential_ttl_seconds = 900;
                },
                vec![RoutesChanged, AuthEntryChanged],
            ),
            (
                "logout no longer revokes",
                |c| flow_route(c, "auth.logout").auth_revoke = None,
                vec![RoutesChanged, AuthEntryChanged],
            ),
            (
                "login path",
                |c| flow_route(c, "auth.login").path = "/api/signin".to_owned(),
                vec![RoutesChanged, AuthEntryChanged],
            ),
            (
                "approved page build",
                |c| {
                    flow_route(c, "app.page")
                        .sensor_html
                        .as_mut()
                        .unwrap()
                        .origin_sha256 = "a".repeat(64);
                },
                // The page root is a sensor page and a page root.
                vec![RoutesChanged, SensorHtmlChanged, PageActionsChanged],
            ),
            (
                "page capacity",
                |c| {
                    flow_route(c, "app.page")
                        .page_actions
                        .as_mut()
                        .unwrap()
                        .max_active_pages = 8;
                },
                vec![RoutesChanged, SensorHtmlChanged, PageActionsChanged],
            ),
            (
                "issued action lease",
                |c| {
                    flow_route(c, "orders.list")
                        .issued_by
                        .as_mut()
                        .unwrap()
                        .ttl_seconds = 60;
                },
                // The list is page-issued and qualifies resources.
                vec![RoutesChanged, PageActionsChanged, ResourceGrantChanged],
            ),
            (
                "grant item bound",
                |c| {
                    flow_route(c, "orders.list")
                        .resource_grant
                        .as_mut()
                        .unwrap()
                        .max_items = 50;
                },
                vec![RoutesChanged, PageActionsChanged, ResourceGrantChanged],
            ),
            (
                "pagination added to the grant-issuing list",
                |c| {
                    flow_route(c, "orders.list").query_pagination =
                        Some(crate::query_pagination::SiteQueryPagination {
                            parameters: vec![crate::query_pagination::SiteQueryParameter {
                                name: "page".to_owned(),
                                kind: crate::query_pagination::PaginationKind::Page,
                                max_value: None,
                            }],
                        });
                },
                vec![
                    RoutesChanged,
                    PageActionsChanged,
                    ResourceGrantChanged,
                    QueryPaginationChanged,
                ],
            ),
            (
                "grant target view",
                |c| flow_route(c, "orders.read").view_profile = Some("full".to_owned()),
                vec![RoutesChanged, ResourceGrantChanged],
            ),
            (
                "issued list moved",
                |c| flow_route(c, "orders.list").path = "/orders-v2".to_owned(),
                vec![RoutesChanged, PageActionsChanged, ResourceGrantChanged],
            ),
            (
                "page root moved",
                |c| flow_route(c, "app.page").path = "/home".to_owned(),
                vec![RoutesChanged, SensorHtmlChanged, PageActionsChanged],
            ),
            (
                "an unrelated public route",
                |c| {
                    c.policy
                        .routes
                        .push(route("docs", "/docs", SecurityEntry::Public));
                },
                vec![RoutesChanged],
            ),
            (
                "the public login page",
                |c| flow_route(c, "login.page").max_response_bytes = 4_096,
                vec![RoutesChanged],
            ),
        ];
        for (name, mutate, expected) in cases {
            let before = flow();
            let mut after = flow();
            mutate(&mut after);
            assert_ne!(before, after, "{name} must change the configuration");
            let expected = sorted(expected);
            assert_eq!(
                assess_change_risk(Some(&before), &after),
                expected,
                "{name}, forwards"
            );
            assert_eq!(
                assess_change_risk(Some(&after), &before),
                expected,
                "{name}, backwards"
            );
        }
        // Reordering flow routes is still cosmetic.
        let mut reordered = flow();
        reordered.policy.routes.reverse();
        assert_eq!(assess_change_risk(Some(&flow()), &reordered), Vec::new());
    }

    /// The loop topology with a share scope, as the control plane stores it.
    fn share_flow() -> SiteConfig {
        serde_json::from_str(include_str!(
            "../../../../tests/site-config/share-flow.json"
        ))
        .unwrap()
    }

    /// Either end of a share scope changing needs an independent approver,
    /// in both directions, and a direct apply must not be able to waive it.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn share_issuance_changes_name_their_facet_in_both_directions() {
        use ChangeRisk::*;
        let cases: Vec<(&str, Mutation, Vec<ChangeRisk>)> = vec![
            (
                "share lease",
                |c| {
                    flow_route(c, "records.share.issue")
                        .share_issue
                        .as_mut()
                        .unwrap()
                        .ttl_seconds = 600;
                },
                vec![RoutesChanged, ResourceGrantChanged, ShareIssueChanged],
            ),
            (
                "live share budget",
                |c| {
                    flow_route(c, "records.share.issue")
                        .share_issue
                        .as_mut()
                        .unwrap()
                        .max_active_shares = 50;
                },
                vec![RoutesChanged, ResourceGrantChanged, ShareIssueChanged],
            ),
            (
                "issuance rule",
                |c| {
                    "other-rule".clone_into(
                        &mut flow_route(c, "records.share.issue")
                            .share_issue
                            .as_mut()
                            .unwrap()
                            .issuance_rule_id,
                    );
                },
                vec![RoutesChanged, ResourceGrantChanged, ShareIssueChanged],
            ),
            (
                "issuer no longer issues",
                |c| flow_route(c, "records.share.issue").share_issue = None,
                vec![RoutesChanged, ResourceGrantChanged, ShareIssueChanged],
            ),
            (
                "redeeming route view",
                |c| {
                    flow_route(c, "records.share.read").view_profile =
                        Some("shared_detail".to_owned());
                },
                vec![RoutesChanged, ShareIssueChanged],
            ),
            (
                "redeeming route path",
                |c| flow_route(c, "records.share.read").path = "/shared".to_owned(),
                vec![RoutesChanged, ShareIssueChanged],
            ),
            (
                "redeeming route made public",
                |c| {
                    let route = flow_route(c, "records.share.read");
                    route.security_entry = SecurityEntry::Public;
                    route.resource_type = None;
                    route.view_profile = None;
                    route.resource_query_parameter = None;
                    flow_route(c, "records.share.issue").share_issue = None;
                },
                vec![RoutesChanged, ResourceGrantChanged, ShareIssueChanged],
            ),
        ];
        for (name, mutate, expected) in cases {
            let before = share_flow();
            let mut after = share_flow();
            mutate(&mut after);
            assert_ne!(before, after, "{name} must change the configuration");
            let expected = sorted(expected);
            assert_eq!(
                assess_change_risk(Some(&before), &after),
                expected,
                "{name}, forwards"
            );
            assert_eq!(
                assess_change_risk(Some(&after), &before),
                expected,
                "{name}, backwards"
            );
            let reasons = expected
                .iter()
                .map(|risk| risk.as_str())
                .collect::<Vec<_>>();
            assert!(!direct_apply_may_waive(&reasons), "{name}");
        }
        // Going live names the facet as well, so a direct apply cannot
        // introduce a share scope unreviewed.
        assert!(assess_change_risk(None, &share_flow()).contains(&ShareIssueChanged));
        assert!(!assess_change_risk(None, &flow()).contains(&ShareIssueChanged));
        // A route that is not part of the share scope stays outside the facet.
        let mut unrelated = share_flow();
        unrelated
            .policy
            .routes
            .push(route("docs", "/docs", SecurityEntry::Public));
        assert_eq!(
            assess_change_risk(Some(&share_flow()), &unrelated),
            vec![RoutesChanged]
        );
    }

    #[test]
    fn going_live_with_flow_routes_names_every_facet() {
        use ChangeRisk::*;
        assert_eq!(
            assess_change_risk(None, &flow()),
            vec![
                Activation,
                AuthEntryChanged,
                SensorHtmlChanged,
                PageActionsChanged,
                ResourceGrantChanged
            ]
        );
        let mut paused = flow();
        paused.status = "paused".to_owned();
        assert_eq!(
            assess_change_risk(Some(&paused), &flow()).first(),
            Some(&Activation)
        );
        // Taking a flow site down is a takedown only.
        assert_eq!(assess_change_risk(Some(&flow()), &paused), vec![Takedown]);
    }

    #[test]
    fn direct_apply_never_waives_a_flow_reason_or_an_unknown_one() {
        assert!(direct_apply_may_waive::<&str>(&[]));
        assert!(direct_apply_may_waive(&["ACTIVATION", "UPSTREAM_CHANGED"]));
        for risk in ChangeRisk::ALL {
            assert_eq!(
                direct_apply_may_waive(&[risk.as_str()]),
                !risk.requires_independent_approval(),
                "{risk:?}"
            );
        }
        assert!(!direct_apply_may_waive(&[
            "ACTIVATION",
            "PAGE_ACTIONS_CHANGED"
        ]));
        assert!(!direct_apply_may_waive(&["A_REASON_FROM_A_NEWER_RELEASE"]));
        let flow_reasons = ChangeRisk::ALL
            .into_iter()
            .filter(|risk| risk.requires_independent_approval())
            .collect::<Vec<_>>();
        assert_eq!(
            flow_reasons,
            [
                ChangeRisk::AuthEntryChanged,
                ChangeRisk::SensorHtmlChanged,
                ChangeRisk::PageActionsChanged,
                ChangeRisk::ResourceGrantChanged,
                ChangeRisk::QueryPaginationChanged,
                ChangeRisk::ShareIssueChanged
            ]
        );
        assert_eq!(
            ChangeRisk::from_token("QUERY_PAGINATION_CHANGED"),
            Some(ChangeRisk::QueryPaginationChanged)
        );
        assert_eq!(
            ChangeRisk::from_token("SHARE_ISSUE_CHANGED"),
            Some(ChangeRisk::ShareIssueChanged)
        );
    }
}
