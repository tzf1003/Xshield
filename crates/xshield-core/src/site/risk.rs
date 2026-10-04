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
//! later is risky until someone decides otherwise.

use super::SiteConfig;
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
    /// A difference that no category above names; risky by default.
    OtherChange,
}

impl ChangeRisk {
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
            Self::OtherChange => "OTHER_CHANGE",
        }
    }
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
    // the requirement.
    let Some(before) = served else {
        return vec![ChangeRisk::Activation];
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
                |c| c.policy.static_asset_max_path_depth = 0,
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
        let all = [
            ChangeRisk::Activation,
            ChangeRisk::Takedown,
            ChangeRisk::UpstreamChanged,
            ChangeRisk::OriginChanged,
            ChangeRisk::ListenPortChanged,
            ChangeRisk::EntryChanged,
            ChangeRisk::RoutesChanged,
            ChangeRisk::IdentityChanged,
            ChangeRisk::CryptoChanged,
            ChangeRisk::WafChanged,
            ChangeRisk::LimitsChanged,
            ChangeRisk::HealthCheckChanged,
            ChangeRisk::SecretRefsChanged,
            ChangeRisk::SensorChanged,
            ChangeRisk::StaticAssetPolicyChanged,
            ChangeRisk::ObjectAccessChanged,
            ChangeRisk::OtherChange,
        ];
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
    }
}
