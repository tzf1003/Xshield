//! Control-plane validation must never accept a site configuration that the
//! edge compiler rejects.
//!
//! The snapshot sent to the edge is all-or-nothing, so one site that passes
//! `SiteConfig::validate_for_site` but fails the edge compile used to make
//! every apply for the whole tenant return 422. Each sample here is projected
//! with the same `SiteConfig::gateway_config` the control plane uses, wrapped
//! in an apply request, and fed through `GatewaySnapshot::from_apply_request`.
//! The implication "core accepts => edge accepts" is asserted for every
//! sample; a new edge rule or a new control field that breaks it fails this
//! test. Every sample both accept must also derive the same action-descriptor
//! digest on both sides (`Tally::digest`): the control plane binds each
//! `policy_revision` label to that digest before it sends anything, so drift
//! would refuse labels the edge accepts or let a reused label through.

use xshield_core::{
    GatewayApplyRequest, GatewayApplySite, SecurityEntry, SiteConfig, SitePolicyConfig,
    SiteRequestCrypto, SiteResponseCrypto, SiteRouteConfig, domain::SiteId,
};
use xshield_gateway::{ConfigError, GatewayConfig, multi_site::GatewaySnapshot};

const TENANT: &str = "tenant_parity";
const SITE: &str = "site_parity";

fn base() -> SiteConfig {
    SiteConfig {
        display_name: "Parity site".to_owned(),
        public_origin: "https://parity.example.test".to_owned(),
        upstream_address: "8.8.8.8:9000".to_owned(),
        upstream_server_name: "origin.example.test".to_owned(),
        upstream_tls: false,
        listen_port: 6100,
        entry_path: "/".to_owned(),
        security_entry: "ui_action_required".to_owned(),
        sensor_enabled: false,
        policy_revision: "policy-v1".to_owned(),
        status: "active".to_owned(),
        policy: SitePolicyConfig::default(),
    }
}

fn exact(id: &str, method: &str, path: &str, entry: SecurityEntry) -> SiteRouteConfig {
    SiteRouteConfig {
        operation_id: id.to_owned(),
        method: method.to_owned(),
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
        auth_refresh: None,
        auth_context_switch: None,
    }
}

fn path_resource(id: &str, path: &str, parameter: &str) -> SiteRouteConfig {
    let mut route = exact(id, "GET", path, SecurityEntry::UiActionRequired);
    route.resource_type = Some("orders".to_owned());
    route.view_profile = Some("summary".to_owned());
    route.resource_path_parameter = Some(parameter.to_owned());
    route
}

fn query_resource(id: &str, path: &str, parameter: &str) -> SiteRouteConfig {
    let mut route = exact(id, "GET", path, SecurityEntry::UiActionRequired);
    route.resource_type = Some("orders".to_owned());
    route.view_profile = Some("summary".to_owned());
    route.resource_query_parameter = Some(parameter.to_owned());
    route
}

fn with_routes(routes: Vec<SiteRouteConfig>) -> SiteConfig {
    let mut config = base();
    config.policy.routes = routes;
    config
}

fn site() -> SiteId {
    SiteId::parse(SITE).unwrap()
}

/// What the edge does with a sample.
#[derive(Debug)]
enum Edge {
    /// The complete snapshot is accepted.
    Accepted,
    /// Refused for the given reason.
    Rejected(String),
}

/// The control-plane validation the write path and the apply plan use.
fn core_verdict(config: &SiteConfig) -> Result<(), String> {
    config
        .validate_for_site(&site())
        .map_err(|error| error.to_string())
}

/// Compiles the sample exactly as an edge apply would.
fn snapshot_verdict(config: &SiteConfig) -> Result<(), ConfigError> {
    let gateway_config = config
        .gateway_config(TENANT, &site())
        .map_err(|_| ConfigError::Invalid("projection"))?;
    let request = GatewayApplyRequest {
        protocol_version: 1,
        tenant_id: TENANT.to_owned(),
        apply_id: format!("apply_{}", uuid::Uuid::now_v7()),
        snapshot_revision: 1,
        sites: vec![GatewayApplySite {
            site_id: SITE.to_owned(),
            listen_port: config.listen_port,
            public_origin: config.public_origin.clone(),
            gateway_config,
            revision: 1,
        }],
    };
    GatewaySnapshot::from_apply_request(request).map(|_| ())
}

fn edge_verdict(config: &SiteConfig) -> Edge {
    match snapshot_verdict(config) {
        Ok(()) => Edge::Accepted,
        Err(error) => Edge::Rejected(error.to_string()),
    }
}

/// What a sample demonstrates about the two validators.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expect {
    /// Both validators accept; guards against over-rejecting a real feature.
    BothAccept,
    /// The edge rejects it, so core must reject it too.
    CoreMustReject,
}

struct Tally {
    core_accepted: usize,
    core_rejected: usize,
    /// Accepted samples with page issuance whose descriptor digest the control
    /// plane and the edge derived identically.
    digests: usize,
    failures: Vec<String>,
}

impl Tally {
    fn new() -> Self {
        Self {
            core_accepted: 0,
            core_rejected: 0,
            digests: 0,
            failures: Vec::new(),
        }
    }

    /// Records the implication `core accepts => edge accepts` for one sample.
    fn implication(&mut self, label: &str, config: &SiteConfig) {
        match (core_verdict(config), edge_verdict(config)) {
            (Ok(()), Edge::Rejected(edge)) => self.failures.push(format!(
                "core accepted but the edge rejected `{label}`: {edge}"
            )),
            (Ok(()), Edge::Accepted) => {
                self.core_accepted += 1;
                self.digest(label, config);
            }
            (Err(_), _) => self.core_rejected += 1,
        }
    }

    /// For a sample both sides accept, the digest the control plane binds the
    /// `policy_revision` label to must be the one the edge derives and
    /// supplies (or both must have none). Drift would refuse labels the edge
    /// accepts, or let a reused label reach the edge and block the tenant.
    fn digest(&mut self, label: &str, config: &SiteConfig) {
        let control = config
            .edge_descriptor_digest()
            .map(|digest| digest.map(|digest| digest.to_hex()));
        let edge = config
            .gateway_config(TENANT, &site())
            .ok()
            .and_then(|value| serde_json::to_vec(&value).ok())
            .and_then(|bytes| GatewayConfig::from_json(&bytes).ok())
            .map(|compiled| {
                compiled
                    .edge_descriptors()
                    .map(xshield_gateway::page_actions::EdgeDescriptorSet::content_digest_hex)
            });
        match (control, edge) {
            (Ok(control), Some(edge)) if control == edge => {
                self.digests += usize::from(control.is_some());
            }
            (control, edge) => self.failures.push(format!(
                "descriptor digest drift for `{label}`: control {control:?}, edge {edge:?}"
            )),
        }
    }

    fn expect(&mut self, label: &str, config: &SiteConfig, expect: Expect) {
        let core = core_verdict(config);
        let edge = edge_verdict(config);
        match expect {
            Expect::BothAccept => {
                if let Err(error) = &core {
                    self.failures
                        .push(format!("core wrongly rejected `{label}`: {error}"));
                }
                if let Edge::Rejected(error) = &edge {
                    self.failures
                        .push(format!("edge rejected the `{label}` baseline: {error}"));
                }
            }
            Expect::CoreMustReject => {
                if !matches!(edge, Edge::Rejected(_)) {
                    self.failures.push(format!(
                        "table entry `{label}` is not an edge rejection; the table is stale"
                    ));
                }
                if core.is_ok() {
                    self.failures.push(format!(
                        "core accepted `{label}` which the edge rejects: {edge:?}"
                    ));
                }
            }
        }
        self.implication(label, config);
    }

    fn finish(self, min_accepted: usize, min_rejected: usize) {
        assert!(
            self.failures.is_empty(),
            "{} parity violation(s):\n{}",
            self.failures.len(),
            self.failures.join("\n")
        );
        assert!(
            self.core_accepted >= min_accepted && self.core_rejected >= min_rejected,
            "the corpus must exercise both outcomes (accepted {}, rejected {})",
            self.core_accepted,
            self.core_rejected
        );
    }
}

#[test]
fn route_shape_rules_match_the_edge_compiler() {
    let mut tally = Tally::new();
    tally.expect("baseline", &base(), Expect::BothAccept);
    let public = |path: &str| exact("a", "GET", path, SecurityEntry::Public);

    // Paths the edge refuses: anything outside printable ASCII, and the
    // namespace the edge itself serves.
    for (label, path) in [
        ("space", "/search results"),
        ("non-ascii", "/caf\u{e9}"),
        ("cjk", "/\u{65e5}\u{672c}"),
        ("reserved prefix", "/__xshield/v1/x"),
        ("reserved sensor path", "/__xshield/v1/bootstrap"),
        ("reserved prefix directory", "/__xshield/"),
        ("del byte", "/a\u{7f}b"),
    ] {
        tally.expect(
            label,
            &with_routes(vec![public(path)]),
            Expect::CoreMustReject,
        );
    }
    // Paths the edge accepts, including near misses of the rules above.
    for (label, path) in [
        ("root", "/"),
        ("nested", "/a/b/c"),
        ("trailing slash", "/a/"),
        ("percent escape", "/a%20b"),
        ("punctuation", "/a;b:c@d*e,f"),
        ("not the reserved prefix", "/__xshield"),
        ("similar prefix", "/__xshield_x/y"),
        ("case differs", "/__XSHIELD/x"),
        ("max length", &format!("/{}", "a".repeat(255))),
    ] {
        tally.expect(label, &with_routes(vec![public(path)]), Expect::BothAccept);
    }

    // Same path shape as an entry path when no route is configured.
    for (label, entry_path) in [
        ("entry with space", "/a b"),
        ("entry non-ascii", "/caf\u{e9}"),
        ("entry reserved", "/__xshield/v1/x"),
    ] {
        let mut config = base();
        config.entry_path = entry_path.to_owned();
        tally.expect(label, &config, Expect::CoreMustReject);
    }
    tally.finish(8, 6);
}

#[test]
fn resource_route_ambiguity_matches_the_edge_compiler() {
    let mut tally = Tally::new();
    let orders = || path_resource("o1", "/orders/{order_id}", "order_id");

    tally.expect(
        "single resource route",
        &with_routes(vec![orders()]),
        Expect::BothAccept,
    );
    // Same method and fixed prefix with different parameter names is one route
    // matched twice.
    tally.expect(
        "same prefix, different parameter name",
        &with_routes(vec![orders(), path_resource("o2", "/orders/{id}", "id")]),
        Expect::CoreMustReject,
    );
    // An exact route that a resource route also matches is shadowed, in either
    // order of declaration.
    for (label, routes) in [
        (
            "exact shadowed by later resource route",
            vec![
                exact("n", "GET", "/orders/new", SecurityEntry::Public),
                orders(),
            ],
        ),
        (
            "exact shadowed by earlier resource route",
            vec![
                orders(),
                exact("n", "GET", "/orders/new", SecurityEntry::Public),
            ],
        ),
        (
            "query resource shadowed by path resource",
            vec![orders(), query_resource("q", "/orders/latest", "order_id")],
        ),
    ] {
        tally.expect(label, &with_routes(routes), Expect::CoreMustReject);
    }
    // Routes the resource route does not match stay legal.
    for (label, routes) in [
        (
            "other method",
            vec![
                exact("n", "POST", "/orders/new", SecurityEntry::Public),
                orders(),
            ],
        ),
        (
            "empty final segment",
            vec![
                exact("n", "GET", "/orders/", SecurityEntry::Public),
                orders(),
            ],
        ),
        (
            "deeper path",
            vec![
                exact("n", "GET", "/orders/new/x", SecurityEntry::Public),
                orders(),
            ],
        ),
        (
            "different prefix",
            vec![
                exact("n", "GET", "/order/new", SecurityEntry::Public),
                orders(),
            ],
        ),
        (
            "nested prefixes",
            vec![
                orders(),
                path_resource("o2", "/orders/archived/{order_id}", "order_id"),
            ],
        ),
        (
            "query resource on the same path as a plain route",
            vec![query_resource("q", "/orders", "order_id")],
        ),
    ] {
        tally.expect(label, &with_routes(routes), Expect::BothAccept);
    }

    // The edge compiles at most 64 path-resource operations per site.
    for (count, expect) in [(64, Expect::BothAccept), (65, Expect::CoreMustReject)] {
        let routes = (0..count)
            .map(|index| {
                path_resource(
                    &format!("r{index}"),
                    &format!("/r{index}/{{order_id}}"),
                    "order_id",
                )
            })
            .collect();
        tally.expect(
            &format!("{count} path resource routes"),
            &with_routes(routes),
            expect,
        );
    }
    tally.finish(6, 3);
}

fn observe(revision: &str) -> SiteRequestCrypto {
    SiteRequestCrypto::Observe {
        adapter_revision: revision.to_owned(),
    }
}

fn decrypt(key_id: &str) -> SiteRequestCrypto {
    SiteRequestCrypto::DirectDecrypt {
        adapter_revision: "rev-1".to_owned(),
        key_id: key_id.to_owned(),
        key_not_before: 1_000,
        key_expires_at: 2_000,
        max_envelope_bytes: 8_192,
        max_plaintext_bytes: 4_096,
        max_message_age_seconds: 300,
        max_future_skew_seconds: 30,
        max_active_messages: 1_000,
    }
}

fn response_crypto(key_id: &str, max_envelope_bytes: usize) -> SiteResponseCrypto {
    SiteResponseCrypto {
        mode: "DIRECT_ENCRYPT".to_owned(),
        adapter_revision: "rev-1".to_owned(),
        key_id: key_id.to_owned(),
        key_not_before: 1_000,
        key_expires_at: 2_000,
        message_ttl_seconds: 300,
        max_envelope_bytes,
    }
}

fn post(id: &str, entry: SecurityEntry) -> SiteRouteConfig {
    exact(id, "POST", &format!("/{id}"), entry)
}

#[test]
#[allow(clippy::too_many_lines)]
fn crypto_rules_match_the_edge_compiler() {
    let mut tally = Tally::new();
    let mut with = |label: &str, mutate: &dyn Fn(&mut SiteRouteConfig), expect: Expect| {
        let mut route = post("p", SecurityEntry::Public);
        mutate(&mut route);
        tally.expect(label, &with_routes(vec![route]), expect);
    };
    with("plain POST", &|_| {}, Expect::BothAccept);
    with(
        "observe on POST",
        &|route| route.request_crypto = Some(observe("observe-v1")),
        Expect::BothAccept,
    );
    with(
        "decrypt on POST",
        &|route| route.request_crypto = Some(decrypt("key-a")),
        Expect::BothAccept,
    );
    // The edge only accepts request crypto on bodies that can carry one.
    for method in ["GET", "DELETE"] {
        with(
            &format!("observe on {method}"),
            &|route| {
                route.method = method.to_owned();
                route.request_crypto = Some(observe("observe-v1"));
            },
            Expect::CoreMustReject,
        );
    }
    // Scoped values: letters, digits, `_`, `-` and `.` only, at most 128.
    for revision in ["bad rev", "bad/rev", "r\u{e9}v", &"r".repeat(129), ""] {
        with(
            &format!("observe revision {revision:?}"),
            &|route| route.request_crypto = Some(observe(revision)),
            Expect::CoreMustReject,
        );
    }
    with(
        "observe revision with dots",
        &|route| route.request_crypto = Some(observe("observe.v1_a-b")),
        Expect::BothAccept,
    );
    for key in ["bad key", "k/1", ""] {
        with(
            &format!("decrypt key {key:?}"),
            &|route| route.request_crypto = Some(decrypt(key)),
            Expect::CoreMustReject,
        );
    }
    // Plaintext must fit in half the envelope; message age is capped at 1h.
    with(
        "plaintext above half the envelope",
        &|route| {
            route.request_crypto = Some(SiteRequestCrypto::DirectDecrypt {
                adapter_revision: "rev-1".to_owned(),
                key_id: "key-a".to_owned(),
                key_not_before: 1_000,
                key_expires_at: 2_000,
                max_envelope_bytes: 8_192,
                max_plaintext_bytes: 8_192,
                max_message_age_seconds: 300,
                max_future_skew_seconds: 30,
                max_active_messages: 1_000,
            });
        },
        Expect::CoreMustReject,
    );
    with(
        "message age above one hour",
        &|route| {
            route.request_crypto = Some(SiteRequestCrypto::DirectDecrypt {
                adapter_revision: "rev-1".to_owned(),
                key_id: "key-a".to_owned(),
                key_not_before: 1_000,
                key_expires_at: 2_000,
                max_envelope_bytes: 8_192,
                max_plaintext_bytes: 4_096,
                max_message_age_seconds: 7_200,
                max_future_skew_seconds: 30,
                max_active_messages: 1_000,
            });
        },
        Expect::CoreMustReject,
    );
    // UI-sourced operations cannot be encrypted or observed at the edge.
    with(
        "observe on a UI action",
        &|route| {
            *route = post("p", SecurityEntry::UiActionRequired);
            route.request_crypto = Some(observe("observe-v1"));
        },
        Expect::CoreMustReject,
    );
    with(
        "decrypt on a UI action",
        &|route| {
            *route = post("p", SecurityEntry::UiActionRequired);
            route.request_crypto = Some(decrypt("key-a"));
        },
        Expect::CoreMustReject,
    );
    // Observing a request whose response is encrypted is not supported.
    with(
        "observe request with encrypted response",
        &|route| {
            route.request_crypto = Some(observe("observe-v1"));
            route.response_crypto = Some(response_crypto("key-r", 4_194_304));
        },
        Expect::CoreMustReject,
    );
    // Response crypto: the envelope must hold twice the plaintext plus slack,
    // and the edge limits the serialized envelope size.
    with(
        "response envelope below twice the plaintext",
        &|route| {
            route.response_crypto = Some(response_crypto("key-r", 1_048_576));
        },
        Expect::CoreMustReject,
    );
    with(
        "response envelope exactly twice plus slack",
        &|route| {
            route.response_crypto = Some(response_crypto("key-r", 2_097_152 + 1_024));
        },
        Expect::BothAccept,
    );
    with(
        "response key with a space",
        &|route| {
            route.response_crypto = Some(response_crypto("key r", 4_194_304));
        },
        Expect::CoreMustReject,
    );
    // The sensor rewriting mode needs its adapter block and a GET page; the
    // accepted form is covered by `provenance_flow_rules_match_the_edge`.
    with(
        "sensor html mode without adapter",
        &|route| route.response_mode = "SENSOR_HTML".to_owned(),
        Expect::CoreMustReject,
    );
    with(
        "buffered json mode",
        &|route| route.response_mode = "BUFFERED_JSON".to_owned(),
        Expect::BothAccept,
    );

    // Key reuse across routes: one request key and one response key per site,
    // and a key cannot serve both directions.
    let two_request_keys = vec![
        {
            let mut route = post("a", SecurityEntry::Public);
            route.request_crypto = Some(decrypt("key-a"));
            route
        },
        {
            let mut route = post("b", SecurityEntry::Public);
            route.request_crypto = Some(decrypt("key-b"));
            route
        },
    ];
    tally.expect(
        "two distinct request keys",
        &with_routes(two_request_keys),
        Expect::CoreMustReject,
    );
    let shared_key = vec![
        {
            let mut route = post("a", SecurityEntry::Public);
            route.request_crypto = Some(decrypt("key-a"));
            route
        },
        {
            let mut route = post("b", SecurityEntry::Public);
            route.response_crypto = Some(response_crypto("key-a", 4_194_304));
            route
        },
    ];
    tally.expect(
        "one key for both directions",
        &with_routes(shared_key),
        Expect::CoreMustReject,
    );
    let two_response_keys = vec![
        {
            let mut route = post("a", SecurityEntry::Public);
            route.response_crypto = Some(response_crypto("key-a", 4_194_304));
            route
        },
        {
            let mut route = post("b", SecurityEntry::Public);
            route.response_crypto = Some(response_crypto("key-b", 4_194_304));
            route
        },
    ];
    tally.expect(
        "two distinct response keys",
        &with_routes(two_response_keys),
        Expect::CoreMustReject,
    );
    let same_key_twice = vec![
        {
            let mut route = post("a", SecurityEntry::Public);
            route.request_crypto = Some(decrypt("key-a"));
            route
        },
        {
            let mut route = post("b", SecurityEntry::Public);
            route.request_crypto = Some(decrypt("key-a"));
            route
        },
    ];
    tally.expect(
        "the same request key on two routes",
        &with_routes(same_key_twice),
        Expect::BothAccept,
    );
    tally.finish(6, 12);
}

#[test]
fn site_level_projection_matches_the_edge_compiler() {
    let mut tally = Tally::new();

    // The anonymous-session capacity model on the edge bounds how long a
    // session may live for a fixed creation rate; the projection must stay
    // inside it for every TTL the policy allows.
    for ttl in [1, 60, 3_600, 5_940, 5_941, 7_200, 43_200, 86_400] {
        let mut config = base();
        config.policy.identity.session_ttl_seconds = ttl;
        tally.implication(&format!("identity ttl {ttl}"), &config);
    }
    // An edge identity store exists whenever any route needs identity or the
    // request path decrypts, regardless of the top-level entry mode.
    for (label, entry, identity_enabled) in [
        ("public entry, identity off", "public", false),
        ("public entry, identity on", "public", true),
        ("authenticated entry", "authenticated_root", false),
    ] {
        let mut config = with_routes(vec![
            exact("pub", "GET", "/", SecurityEntry::Public),
            exact("ui", "GET", "/ui", SecurityEntry::UiActionRequired),
        ]);
        config.security_entry = entry.to_owned();
        config.policy.identity.enabled = identity_enabled;
        tally.implication(label, &config);
    }
    {
        let mut config = with_routes(vec![{
            let mut route = post("enc", SecurityEntry::Public);
            route.request_crypto = Some(observe("observe-v1"));
            route
        }]);
        config.security_entry = "public".to_owned();
        tally.implication("public entry with request crypto", &config);
    }
    {
        let mut config = with_routes(vec![exact(
            "auth",
            "GET",
            "/",
            SecurityEntry::AuthenticatedRoot,
        )]);
        config.security_entry = "public".to_owned();
        tally.implication("authenticated route under a public entry", &config);
    }

    // Site identifiers feed the edge's audit producer name, which is capped.
    for length in [1, 64, 120, 123, 124, 128] {
        let site = "s".repeat(length);
        let config = base();
        let site_id = SiteId::parse(&site).unwrap();
        let request = GatewayApplyRequest {
            protocol_version: 1,
            tenant_id: TENANT.to_owned(),
            apply_id: format!("apply_{}", uuid::Uuid::now_v7()),
            snapshot_revision: 1,
            sites: vec![GatewayApplySite {
                site_id: site.clone(),
                listen_port: config.listen_port,
                public_origin: config.public_origin.clone(),
                gateway_config: config.gateway_config(TENANT, &site_id).unwrap(),
                revision: 1,
            }],
        };
        let edge = GatewaySnapshot::from_apply_request(request);
        let core = config.validate_for_site(&site_id);
        if core.is_ok() && edge.is_err() {
            tally.failures.push(format!(
                "core accepted a {length}-character site id the edge rejects"
            ));
        }
    }

    // The sensor origin must be a bare `scheme://authority`, and plain HTTP is
    // limited to the literal loopback names the sensor knows.
    for (label, origin) in [
        ("https", "https://parity.example.test"),
        ("https with port", "https://parity.example.test:8443"),
        ("localhost", "http://localhost:8080"),
        ("localhost trailing slash", "http://localhost:8080/"),
        ("127.0.0.1", "http://127.0.0.1:8080"),
        ("other loopback", "http://127.0.0.2:8080"),
        ("ipv6 loopback", "http://[::1]:8080"),
        ("uppercase host", "https://Parity.Example.Test"),
    ] {
        let mut config = base();
        config.sensor_enabled = true;
        config.public_origin = origin.to_owned();
        tally.implication(&format!("sensor with origin {label}"), &config);
    }
    for (label, status) in [("draft", "draft"), ("paused", "paused")] {
        let mut config = base();
        config.status = status.to_owned();
        tally.implication(label, &config);
    }
    tally.finish(8, 0);
}

/// A deterministic sweep over route shapes. It is not exhaustive; it exists so
/// that a new edge rule that a hand-written case above does not mention is
/// still found as soon as any combination here trips it.
#[test]
fn generated_route_sets_never_pass_core_and_fail_the_edge() {
    let mut tally = Tally::new();
    let paths = [
        "/",
        "/a",
        "/a/b",
        "/orders/new",
        "/orders/",
        "/orders",
        "/a b",
        "/caf\u{e9}",
        "/__xshield/x",
        "/a%2fb",
        "/a//b",
        "/a/./b",
        "/{x}",
        "/a{b",
        "/a?b",
        "/a\\b",
    ];
    let resource_paths = [
        ("/orders/{order_id}", "order_id"),
        ("/orders/{id}", "id"),
        ("/orders/x{order_id}", "order_id"),
        ("/orders/{order_id}/y", "order_id"),
        ("/{order_id}", "order_id"),
        ("//{order_id}", "order_id"),
        ("/o%41/{order_id}", "order_id"),
        ("/o b/{order_id}", "order_id"),
        ("/__xshield/{order_id}", "order_id"),
        ("/a/b/{order_id}", "order_id"),
    ];
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    let entries = [
        SecurityEntry::Public,
        SecurityEntry::AuthEntry,
        SecurityEntry::AuthenticatedRoot,
        SecurityEntry::UiActionRequired,
    ];
    let mut index = 0_usize;
    for method in methods {
        for entry in entries {
            for path in paths {
                let route = exact("x", method, path, entry);
                tally.implication(
                    &format!("{method} {entry:?} {path:?}"),
                    &with_routes(vec![route]),
                );
                for (resource_path, parameter) in resource_paths {
                    index += 1;
                    let resource = path_resource("y", resource_path, parameter);
                    let mut other = exact("x", method, path, entry);
                    other.operation_id = format!("x{index}");
                    tally.implication(
                        &format!("{method} {entry:?} {path:?} + {resource_path:?}"),
                        &with_routes(vec![other, resource]),
                    );
                }
            }
        }
    }
    for (first, first_parameter) in resource_paths {
        for (second, second_parameter) in resource_paths {
            let routes = vec![
                path_resource("p1", first, first_parameter),
                path_resource("p2", second, second_parameter),
            ];
            tally.implication(&format!("{first:?} + {second:?}"), &with_routes(routes));
        }
    }
    tally.finish(200, 200);
}

/// Boundary values of every numeric and textual crypto parameter, combined
/// with each method and admission, so that an edge limit nobody wrote a case
/// for is still found.
#[test]
#[allow(clippy::too_many_lines)]
fn generated_crypto_parameters_never_pass_core_and_fail_the_edge() {
    let mut tally = Tally::new();
    let methods = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    let entries = [
        SecurityEntry::Public,
        SecurityEntry::AuthEntry,
        SecurityEntry::AuthenticatedRoot,
        SecurityEntry::UiActionRequired,
    ];
    let mut request_options: Vec<(String, Option<SiteRequestCrypto>)> = vec![
        ("none".to_owned(), None),
        ("observe".to_owned(), Some(observe("observe-v1"))),
        ("observe bad".to_owned(), Some(observe("bad rev"))),
        ("decrypt".to_owned(), Some(decrypt("key-a"))),
    ];
    for envelope in [0, 1, 4_096, 65_536, 65_537] {
        for plaintext in [0, 1, envelope / 2, envelope / 2 + 1, envelope] {
            for age in [0, 1, 3_600, 3_601, 86_400, 86_401] {
                for (skew, active) in [(0, 1), (300, 1_000_000), (301, 1), (0, 0), (0, 1_000_001)] {
                    request_options.push((
                        format!(
                            "decrypt e={envelope} p={plaintext} age={age} skew={skew} n={active}"
                        ),
                        Some(SiteRequestCrypto::DirectDecrypt {
                            adapter_revision: "rev-1".to_owned(),
                            key_id: "key-a".to_owned(),
                            key_not_before: 1_000,
                            key_expires_at: 2_000,
                            max_envelope_bytes: envelope,
                            max_plaintext_bytes: plaintext,
                            max_message_age_seconds: age,
                            max_future_skew_seconds: skew,
                            max_active_messages: active,
                        }),
                    ));
                }
            }
        }
    }
    for method in methods {
        for entry in entries {
            for (label, crypto) in &request_options {
                let mut route = exact("c", method, "/c", entry);
                route.request_crypto = crypto.clone();
                tally.implication(
                    &format!("{method} {entry:?} {label}"),
                    &with_routes(vec![route]),
                );
            }
        }
    }

    let mut response_options = Vec::new();
    for response_bytes in [0, 1, 1_024, 1_048_576, 16_777_216, 16_777_217] {
        let twice = response_bytes * 2;
        for envelope in [
            0,
            response_bytes,
            twice + 1_023,
            twice + 1_024,
            33_558_528,
            33_558_529,
        ] {
            for ttl in [0, 1, 3_600, 3_601] {
                for (mode, mode_label) in [("DIRECT_ENCRYPT", "ok"), ("OTHER", "mode")] {
                    for response_mode in ["", "BUFFERED_JSON", "SENSOR_HTML", "OTHER"] {
                        response_options.push((
                            format!(
                                "bytes={response_bytes} env={envelope} ttl={ttl} {mode_label} rm={response_mode:?}"
                            ),
                            response_bytes,
                            Some(SiteResponseCrypto {
                                mode: mode.to_owned(),
                                adapter_revision: "rev-1".to_owned(),
                                key_id: "key-r".to_owned(),
                                key_not_before: 1_000,
                                key_expires_at: 2_000,
                                message_ttl_seconds: ttl,
                                max_envelope_bytes: envelope,
                            }),
                            response_mode,
                        ));
                    }
                }
            }
        }
        for response_mode in ["", "BUFFERED_JSON", "SENSOR_HTML", "OTHER"] {
            response_options.push((
                format!("bytes={response_bytes} no crypto rm={response_mode:?}"),
                response_bytes,
                None,
                response_mode,
            ));
        }
    }
    for method in methods {
        for entry in entries {
            for (label, bytes, crypto, response_mode) in &response_options {
                let mut route = exact("r", method, "/r", entry);
                route.max_response_bytes = *bytes;
                route.response_crypto = crypto.clone();
                route.response_mode = (*response_mode).to_owned();
                let mut config = with_routes(vec![route]);
                config.policy.limits.max_response_body_bytes = 16_777_216;
                tally.implication(&format!("{method} {entry:?} {label}"), &config);
            }
        }
    }
    tally.finish(500, 500);
}

/// Origin, entry mode, identity, sensor and TTL combinations: the parts of the
/// projection that depend on more than one field.
#[test]
fn generated_site_level_combinations_never_pass_core_and_fail_the_edge() {
    let mut tally = Tally::new();
    let origins = [
        "https://parity.example.test",
        "https://parity.example.test:8443",
        "https://parity.example.test/",
        "https://[::1]",
        "https://127.0.0.1",
        "http://localhost",
        "http://localhost:8080",
        "http://localhost:8080/",
        "http://127.0.0.1:8080",
        "http://127.0.0.2:8080",
        "http://[::1]:8080",
        "http://parity.example.test",
        "https://Parity.Example.Test",
        "https://-bad.example.test",
        "https://parity..example.test",
        "https://parity.example.test:0",
        "https://parity.example.test:99999",
        "ftp://parity.example.test",
        "https://user@parity.example.test",
        "https://parity.example.test/path",
    ];
    let routes_options: Vec<(&str, Vec<SiteRouteConfig>)> = vec![
        ("default route", Vec::new()),
        (
            "public only",
            vec![exact("a", "GET", "/", SecurityEntry::Public)],
        ),
        (
            "ui and public",
            vec![
                exact("a", "GET", "/", SecurityEntry::Public),
                exact("b", "GET", "/ui", SecurityEntry::UiActionRequired),
            ],
        ),
        (
            "authenticated",
            vec![exact("a", "GET", "/", SecurityEntry::AuthenticatedRoot)],
        ),
        (
            "public with request crypto",
            vec![{
                let mut route = post("a", SecurityEntry::Public);
                route.request_crypto = Some(observe("observe-v1"));
                route
            }],
        ),
    ];
    for origin in origins {
        for sensor in [false, true] {
            for entry in ["public", "authenticated_root", "ui_action_required"] {
                for identity in [false, true] {
                    for (routes_label, routes) in &routes_options {
                        for ttl in [1, 3_600, 5_941, 86_400] {
                            let mut config = with_routes(routes.clone());
                            config.public_origin = origin.to_owned();
                            config.sensor_enabled = sensor;
                            config.security_entry = entry.to_owned();
                            config.policy.identity.enabled = identity;
                            config.policy.identity.session_ttl_seconds = ttl;
                            tally.implication(
                                &format!(
                                    "{origin} sensor={sensor} entry={entry} identity={identity} {routes_label} ttl={ttl}"
                                ),
                                &config,
                            );
                        }
                    }
                }
            }
        }
    }
    tally.finish(300, 300);
}

/// The parity constants core mirrors from the edge must keep their values.
#[test]
fn mirrored_edge_limits_have_not_drifted() {
    assert_eq!(xshield_gateway::MAX_BUFFERED_JSON_BYTES, 16 * 1024 * 1024);
    assert_eq!(
        xshield_gateway::MAX_ENCRYPTED_RESPONSE_ENVELOPE_BYTES,
        16 * 1024 * 1024 * 2 + 4096
    );
    assert_eq!(
        xshield_gateway::MAX_ENCRYPTED_REQUEST_ENVELOPE_BYTES,
        64 * 1024
    );
    assert_eq!(
        xshield_gateway::MAX_BUFFERED_BODY_IN_FLIGHT_BYTES,
        16 * 1024 * 1024 * 2 + (16 * 1024 * 1024 * 2 + 4096) + 4096 + 16
    );
    assert_eq!(xshield_core::site::EDGE_MAX_PATH_RESOURCE_ROUTES, 64);
    assert_eq!(
        xshield_core::site::EDGE_MAX_CONFIG_BYTES,
        xshield_gateway::MAX_CONFIG_BYTES
    );
    assert_eq!(
        xshield_core::site::flow::EDGE_MAX_PAGE_ACTIONS,
        xshield_gateway::page_actions::MAX_PAGE_ACTIONS
    );
    assert_eq!(
        xshield_core::site::flow::EDGE_MAX_ACTIVE_PAGES,
        xshield_gateway::page_actions::MAX_ACTIVE_PAGES
    );
}

// ---- Browser provenance flow -------------------------------------------------

/// The control-plane spelling of the real-browser loop topology.
const BROWSER_LOOP: &str = include_str!("../../../tests/site-config/browser-loop.json");
/// Its projection for `tenant_loop`/`site_loop`, without `site_policy`.
const BROWSER_LOOP_GATEWAY: &str =
    include_str!("../../../tests/site-config/browser-loop.gateway.json");
/// The script that runs the real-browser loop against the real edge.
const BROWSER_LOOP_SCRIPT: &str = include_str!("../../../scripts/test_browser_loop.sh");
/// The page the loop approves by digest.
const BROWSER_LOOP_PAGE: &[u8] = include_bytes!("../../../tests/browser-loop/app.html");

fn browser_loop() -> SiteConfig {
    let mut config: SiteConfig = serde_json::from_str(BROWSER_LOOP).unwrap();
    config.listen_port = 6100;
    config
}

fn loop_route<'a>(config: &'a mut SiteConfig, id: &str) -> &'a mut SiteRouteConfig {
    config
        .policy
        .routes
        .iter_mut()
        .find(|route| route.operation_id == id)
        .unwrap()
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut hex, byte| {
        use std::fmt::Write as _;
        write!(hex, "{byte:02x}").unwrap();
        hex
    })
}

/// The loop script's edge configuration with its shell variables filled in
/// the way the script fills them (page digest and `</head>` offset of the
/// real page; ports and the scratch directory are arbitrary).
fn script_gateway_config() -> serde_json::Value {
    let start = BROWSER_LOOP_SCRIPT
        .find("cat >\"$test_dir/site.json\" <<JSON\n")
        .expect("the loop script writes site.json from a heredoc");
    let body = &BROWSER_LOOP_SCRIPT[start..];
    let body = &body[body.find('\n').unwrap() + 1..];
    let body = &body[..body.find("\nJSON\n").unwrap()];
    let offset = BROWSER_LOOP_PAGE
        .windows(b"</head>".len())
        .position(|window| window == b"</head>")
        .unwrap();
    let filled = body
        .replace(
            "$app_sha256",
            &lower_hex(&openssl::sha::sha256(BROWSER_LOOP_PAGE)),
        )
        .replace("$app_offset", &offset.to_string())
        .replace("$edge_port", "6201")
        .replace("$origin_port", "9000")
        .replace("$test_dir", "target/browser-loop");
    assert!(!filled.contains('$'), "an unfilled shell variable is left");
    serde_json::from_str(&filled).unwrap()
}

/// The control plane can express the real-browser loop exactly: its projection
/// is the golden configuration, whose operations are the loop script's, and
/// both compile to the same page plan, descriptors and sensor routes.
#[test]
fn the_browser_loop_projects_to_the_loop_scripts_edge_operations() {
    let config: SiteConfig = serde_json::from_str(BROWSER_LOOP).unwrap();
    let loop_site = SiteId::parse("site_loop").unwrap();
    config.validate_for_site(&loop_site).unwrap();

    // The fixture approves the loop's real page.
    let page = config
        .policy
        .routes
        .iter()
        .find(|route| route.operation_id == "app.page")
        .and_then(|route| route.sensor_html.as_ref())
        .unwrap();
    assert_eq!(
        page.origin_sha256,
        lower_hex(&openssl::sha::sha256(BROWSER_LOOP_PAGE))
    );

    let projection = config.gateway_config("tenant_loop", &loop_site).unwrap();
    let mut without_policy = projection.clone();
    without_policy
        .as_object_mut()
        .unwrap()
        .remove("site_policy");
    let golden: serde_json::Value = serde_json::from_str(BROWSER_LOOP_GATEWAY).unwrap();
    assert_eq!(
        without_policy, golden,
        "the projection drifted from the golden"
    );
    let script = script_gateway_config();
    assert_eq!(
        script["operations"], golden["operations"],
        "the golden operations drifted from scripts/test_browser_loop.sh"
    );
    assert_eq!(script["policy_revision"], golden["policy_revision"]);

    let compile = |value: &serde_json::Value| {
        GatewayConfig::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
    };
    let (projected, scripted) = (compile(&projection), compile(&script));
    assert_eq!(
        projected.edge_descriptors().unwrap().content_digest_hex(),
        scripted.edge_descriptors().unwrap().content_digest_hex(),
        "the control plane would provision different action descriptors"
    );
    // The digest the control plane binds the label to before it sends
    // anything is the one the edge derives from the golden projection (and
    // from the loop script's configuration, asserted just above).
    let control = config.edge_descriptor_digest().unwrap().unwrap().to_hex();
    assert_eq!(
        control,
        compile(&golden)
            .edge_descriptors()
            .unwrap()
            .content_digest_hex(),
        "the control plane would bind the label to a digest the edge does not supply"
    );
    assert_eq!(
        control,
        projected.edge_descriptors().unwrap().content_digest_hex()
    );
    let plan = |config: &GatewayConfig| {
        let plan = config.page_action_plan("GET", "/app").unwrap();
        (
            plan.mapping_revision().as_str().to_owned(),
            plan.max_active_pages(),
            plan.actions()
                .iter()
                .map(|action| {
                    (
                        action.descriptor().action_id().as_str().to_owned(),
                        action.ttl_seconds(),
                    )
                })
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(plan(&projected), plan(&scripted));
    assert_eq!(
        projected.sensor_routes().harvest(),
        scripted.sensor_routes().harvest()
    );
    assert_eq!(
        projected.sensor_routes().invalidate(),
        scripted.sensor_routes().invalidate()
    );
    // The live snapshot path accepts the loop: the edge supplies its
    // descriptors when it applies the snapshot.
    assert!(matches!(edge_verdict(&browser_loop()), Edge::Accepted));
}

/// Judges the loop topology after `mutate`.
fn check(tally: &mut Tally, label: &str, mutate: fn(&mut SiteConfig), expect: Expect) {
    let mut config = browser_loop();
    mutate(&mut config);
    tally.expect(label, &config, expect);
}

/// Judges the share topology after `mutate`.
fn check_share(tally: &mut Tally, label: &str, mutate: fn(&mut SiteConfig), expect: Expect) {
    let mut config = share_flow();
    mutate(&mut config);
    tally.expect(label, &config, expect);
}

/// Every flow rule core mirrors, as an accepted or a refused sample that the
/// edge judges the same way, including the cross-route rules.
#[test]
#[allow(clippy::too_many_lines)]
fn provenance_flow_rules_match_the_edge() {
    let mut tally = Tally::new();
    let both = Expect::BothAccept;
    let reject = Expect::CoreMustReject;

    check(&mut tally, "the loop topology", |_| {}, both);
    // Authentication entries, identity establishment and revocation.
    check(
        &mut tally,
        "auth entry without a binding",
        |c| loop_route(c, "auth.login").auth_binding = None,
        both,
    );
    check(
        &mut tally,
        "binding on a root",
        |c| loop_route(c, "auth.login").security_entry = SecurityEntry::AuthenticatedRoot,
        reject,
    );
    for (label, status) in [("binding status 204", 204), ("binding status 300", 300)] {
        let mut config = browser_loop();
        loop_route(&mut config, "auth.login")
            .auth_binding
            .as_mut()
            .unwrap()
            .success_status = status;
        tally.expect(label, &config, reject);
    }
    check(
        &mut tally,
        "shared pointer",
        |c| {
            loop_route(c, "auth.login")
                .auth_binding
                .as_mut()
                .unwrap()
                .bearer_pointer = "/identity/id".to_owned();
        },
        reject,
    );
    check(
        &mut tally,
        "bad pointer escape",
        |c| {
            loop_route(c, "auth.login")
                .auth_binding
                .as_mut()
                .unwrap()
                .bearer_pointer = "/a~2".to_owned();
        },
        reject,
    );
    check(
        &mut tally,
        "credential outlives session",
        |c| {
            loop_route(c, "auth.login")
                .auth_binding
                .as_mut()
                .unwrap()
                .credential_ttl_seconds = 3_601;
        },
        reject,
    );
    check(
        &mut tally,
        "revoke on a public route",
        |c| loop_route(c, "auth.logout").security_entry = SecurityEntry::Public,
        reject,
    );
    check(
        &mut tally,
        "revoke status 206",
        |c| {
            loop_route(c, "auth.logout")
                .auth_revoke
                .as_mut()
                .unwrap()
                .success_status = 206;
        },
        reject,
    );
    check(
        &mut tally,
        "logout that also grants",
        |c| {
            let grant = loop_route(c, "orders.list").resource_grant.clone();
            loop_route(c, "auth.logout").resource_grant = grant;
        },
        reject,
    );
    check(
        &mut tally,
        "observed login body",
        |c| {
            loop_route(c, "auth.login").request_crypto = Some(SiteRequestCrypto::Observe {
                adapter_revision: "observe-v1".to_owned(),
            });
        },
        reject,
    );
    check(
        &mut tally,
        "decrypted login body",
        |c| loop_route(c, "auth.login").request_crypto = Some(decrypt("key-a")),
        both,
    );
    // Sensor pages.
    check(
        &mut tally,
        "sensor page without adapter",
        |c| loop_route(c, "app.page").sensor_html = None,
        reject,
    );
    check(
        &mut tally,
        "adapter on a JSON route",
        |c| loop_route(c, "app.page").response_mode = "BUFFERED_JSON".to_owned(),
        reject,
    );
    check(
        &mut tally,
        "sensor page on POST",
        |c| loop_route(c, "app.page").method = "POST".to_owned(),
        reject,
    );
    check(
        &mut tally,
        "encrypted sensor page",
        |c| {
            loop_route(c, "app.page").response_crypto = Some(response_crypto("key-r", 65_536));
        },
        reject,
    );
    check(
        &mut tally,
        "sensor digest in upper case",
        |c| {
            loop_route(c, "app.page")
                .sensor_html
                .as_mut()
                .unwrap()
                .origin_sha256 = "F".repeat(64);
        },
        reject,
    );
    check(
        &mut tally,
        "injection offset at the limit",
        |c| {
            loop_route(c, "app.page")
                .sensor_html
                .as_mut()
                .unwrap()
                .injection_offset = 16_384;
        },
        reject,
    );
    check(
        &mut tally,
        "fifteen further builds",
        |c| {
            loop_route(c, "app.page")
                .sensor_html
                .as_mut()
                .unwrap()
                .additional_adapters = builds(15);
        },
        both,
    );
    check(
        &mut tally,
        "sixteen further builds",
        |c| {
            loop_route(c, "app.page")
                .sensor_html
                .as_mut()
                .unwrap()
                .additional_adapters = builds(16);
        },
        reject,
    );
    check(
        &mut tally,
        "repeated build revision",
        |c| {
            let mut repeated = builds(1);
            "app-r1".clone_into(&mut repeated[0].adapter_revision);
            loop_route(c, "app.page")
                .sensor_html
                .as_mut()
                .unwrap()
                .additional_adapters = repeated;
        },
        reject,
    );
    check(
        &mut tally,
        "sensor disabled",
        |c| c.sensor_enabled = false,
        reject,
    );
    check(
        &mut tally,
        "public sensor page without issuance",
        |c| {
            let page = loop_route(c, "login.page");
            page.response_mode = "SENSOR_HTML".to_owned();
            page.sensor_html = Some(xshield_core::SiteSensorHtml {
                adapter_revision: "login-r1".to_owned(),
                origin_sha256: "c".repeat(64),
                injection_offset: 10,
                additional_adapters: Vec::new(),
            });
        },
        both,
    );
    // Page issuance.
    check(
        &mut tally,
        "public page root",
        |c| loop_route(c, "app.page").security_entry = SecurityEntry::Public,
        reject,
    );
    check(
        &mut tally,
        "page actions on a JSON route",
        |c| {
            loop_route(c, "orders.list").page_actions = Some(xshield_core::SitePageActions {
                mapping_revision: "x".to_owned(),
                max_active_pages: 1,
            });
        },
        reject,
    );
    for (label, pages, expect) in [
        ("no live pages", 0, reject),
        ("a thousand live pages", 1_000, both),
        ("too many live pages", 1_001, reject),
    ] {
        let mut config = browser_loop();
        loop_route(&mut config, "app.page")
            .page_actions
            .as_mut()
            .unwrap()
            .max_active_pages = pages;
        tally.expect(label, &config, expect);
    }
    for (label, ttl, expect) in [
        ("zero action lease", 0, reject),
        ("one day action lease", 86_400, both),
        ("action lease above a day", 86_401, reject),
    ] {
        let mut config = browser_loop();
        loop_route(&mut config, "orders.list")
            .issued_by
            .as_mut()
            .unwrap()
            .ttl_seconds = ttl;
        tally.expect(label, &config, expect);
    }
    check(
        &mut tally,
        "issued resource route",
        |c| {
            loop_route(c, "orders.read").issued_by = Some(xshield_core::SiteIssuedBy {
                page_operation_id: "app.page".to_owned(),
                ttl_seconds: 60,
            });
        },
        reject,
    );
    check(
        &mut tally,
        "unknown page",
        |c| {
            loop_route(c, "orders.list")
                .issued_by
                .as_mut()
                .unwrap()
                .page_operation_id = "missing.page".to_owned();
        },
        reject,
    );
    check(
        &mut tally,
        "issued by a page without page actions",
        |c| {
            loop_route(c, "orders.list")
                .issued_by
                .as_mut()
                .unwrap()
                .page_operation_id = "login.page".to_owned();
        },
        reject,
    );
    check(
        &mut tally,
        "unused page actions",
        |c| loop_route(c, "orders.list").issued_by = None,
        reject,
    );
    for (label, extra, expect) in [
        ("sixteen page actions", 15, both),
        ("seventeen", 16, reject),
    ] {
        let mut config = browser_loop();
        for index in 0..extra {
            let mut issued = loop_route(&mut config, "orders.list").clone();
            issued.operation_id = format!("extra.{index}");
            issued.path = format!("/extra/{index}");
            issued.source_action = Some(format!("app.extra.{index}"));
            issued.resource_grant = None;
            config.policy.routes.push(issued);
        }
        tally.expect(label, &config, expect);
    }
    check(
        &mut tally,
        "one page action with two meanings",
        |c| {
            let mut shadow = loop_route(c, "orders.list").clone();
            shadow.operation_id = "orders.list.shadow".to_owned();
            shadow.path = "/orders-shadow".to_owned();
            shadow.resource_grant = None;
            c.policy.routes.push(shadow);
        },
        reject,
    );
    // Resource grants.
    check(
        &mut tally,
        "grant on a public route",
        |c| {
            let list = loop_route(c, "orders.list");
            list.security_entry = SecurityEntry::Public;
            list.source_action = None;
            list.issued_by = None;
            loop_route(c, "app.page").page_actions = None;
        },
        reject,
    );
    check(
        &mut tally,
        "missing grant target",
        |c| {
            loop_route(c, "orders.list")
                .resource_grant
                .as_mut()
                .unwrap()
                .target_operation_id = "orders.gone".to_owned();
        },
        reject,
    );
    check(
        &mut tally,
        "grant target without a resource",
        |c| {
            loop_route(c, "orders.list")
                .resource_grant
                .as_mut()
                .unwrap()
                .target_operation_id = "orders.list".to_owned();
        },
        reject,
    );
    for (label, items, grants, expect) in [
        ("no items", 0, 200, reject),
        ("a thousand items", 1_000, 200, both),
        ("too many items", 1_001, 200, reject),
        ("five thousand grants", 10, 5_000, both),
        ("too many grants", 10, 5_001, reject),
    ] {
        let mut config = browser_loop();
        let grant = loop_route(&mut config, "orders.list")
            .resource_grant
            .as_mut()
            .unwrap();
        grant.max_items = items;
        grant.max_active_grants = grants;
        tally.expect(label, &config, expect);
    }
    check(
        &mut tally,
        "unrooted items pointer",
        |c| {
            loop_route(c, "orders.list")
                .resource_grant
                .as_mut()
                .unwrap()
                .items_pointer = "orders".to_owned();
        },
        reject,
    );
    check(
        &mut tally,
        "grant target with two meanings",
        |c| {
            let mut target = loop_route(c, "orders.read").clone();
            target.operation_id = "orders.read.v2".to_owned();
            target.path = "/v2/orders/{order_id}".to_owned();
            c.policy.routes.push(target);
            let mut list = loop_route(c, "orders.list").clone();
            list.operation_id = "orders.list.v2".to_owned();
            list.path = "/v2/orders".to_owned();
            list.source_action = Some("orders.list.v2.open".to_owned());
            list.issued_by = None;
            list.resource_grant.as_mut().unwrap().target_operation_id = "orders.read.v2".to_owned();
            c.policy.routes.push(list);
        },
        reject,
    );
    check(
        &mut tally,
        "a second list qualifying the same target",
        |c| {
            let mut list = loop_route(c, "orders.list").clone();
            list.operation_id = "orders.list.b".to_owned();
            list.path = "/orders-b".to_owned();
            list.source_action = Some("orders.list.b.open".to_owned());
            list.issued_by = None;
            c.policy.routes.push(list);
        },
        both,
    );
    // Every accepted sample with page issuance compared its descriptor digest.
    assert!(
        tally.digests >= 11,
        "only {} digests compared",
        tally.digests
    );
    tally.finish(10, 30);
}

fn paging(names: &[&str]) -> xshield_core::query_pagination::SiteQueryPagination {
    use xshield_core::query_pagination::{PaginationKind, SiteQueryPagination, SiteQueryParameter};
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

/// A grant-issuing `authenticated_root` list next to the loop topology.
fn root_list(config: &mut SiteConfig, with_grant: bool) {
    let mut list = loop_route(config, "orders.list").clone();
    "orders.root".clone_into(&mut list.operation_id);
    "/orders-root".clone_into(&mut list.path);
    list.security_entry = SecurityEntry::AuthenticatedRoot;
    list.source_action = None;
    list.issued_by = None;
    if !with_grant {
        list.resource_grant = None;
    }
    config.policy.routes.push(list);
}

/// `query_pagination` rules, judged by the control plane and the real edge
/// compiler alike: where the block applies, its shape and its collision with
/// resource parameters.
#[test]
#[allow(clippy::too_many_lines)]
fn query_pagination_rules_match_the_edge() {
    let mut tally = Tally::new();
    let both = Expect::BothAccept;
    let reject = Expect::CoreMustReject;

    check(
        &mut tally,
        "paged non-resource UI list",
        |c| loop_route(c, "orders.list").query_pagination = Some(paging(&["page"])),
        both,
    );
    check(
        &mut tally,
        "four parameters",
        |c| {
            loop_route(c, "orders.list").query_pagination =
                Some(paging(&["page", "size", "skip", "n"]));
        },
        both,
    );
    check(
        &mut tally,
        "paged grant-issuing root list",
        |c| {
            root_list(c, true);
            loop_route(c, "orders.root").query_pagination = Some(paging(&["page"]));
        },
        both,
    );
    check(
        &mut tally,
        "root list without a grant",
        |c| {
            root_list(c, false);
            loop_route(c, "orders.root").query_pagination = Some(paging(&["page"]));
        },
        reject,
    );
    check(
        &mut tally,
        "resource route",
        |c| loop_route(c, "orders.read").query_pagination = Some(paging(&["page"])),
        reject,
    );
    check(
        &mut tally,
        "page root",
        |c| loop_route(c, "app.page").query_pagination = Some(paging(&["page"])),
        reject,
    );
    check(
        &mut tally,
        "auth entry",
        |c| loop_route(c, "auth.login").query_pagination = Some(paging(&["page"])),
        reject,
    );
    check(
        &mut tally,
        "public route",
        |c| loop_route(c, "login.page").query_pagination = Some(paging(&["page"])),
        reject,
    );
    check(
        &mut tally,
        "not a GET",
        |c| {
            let list = loop_route(c, "orders.list");
            list.method = "POST".to_owned();
            list.query_pagination = Some(paging(&["page"]));
        },
        reject,
    );
    for (label, names) in [
        ("empty list", &[][..]),
        ("five parameters", &["a", "b", "c", "d", "e"][..]),
        ("duplicate names", &["p", "p"][..]),
        ("uppercase", &["Page"][..]),
        ("digit", &["page1"][..]),
        ("empty name", &[""][..]),
        ("collides with a resource parameter", &["order_id"][..]),
    ] {
        let mut config = browser_loop();
        loop_route(&mut config, "orders.list").query_pagination = Some(paging(names));
        tally.expect(label, &config, reject);
    }
    let long = "a".repeat(33);
    let mut config = browser_loop();
    loop_route(&mut config, "orders.list").query_pagination = Some(paging(&[&long]));
    tally.expect("name of 33 bytes", &config, reject);
    let max = "a".repeat(32);
    let mut config = browser_loop();
    loop_route(&mut config, "orders.list").query_pagination = Some(paging(&[&max]));
    tally.expect("name of 32 bytes", &config, both);
    // `page_size` bounds, and bounds on kinds that have fixed ranges.
    for (label, kind, bound, expect) in [
        ("page size 1000", "page_size", Some(1_000), both),
        ("page size 1", "page_size", Some(1), both),
        ("page size 1001", "page_size", Some(1_001), reject),
        ("page size 0", "page_size", Some(0), reject),
        ("bound on a page", "page", Some(5), reject),
        ("bound on an offset", "offset", Some(5), reject),
        ("default page size", "page_size", None, both),
    ] {
        let mut config = browser_loop();
        let mut block = paging(&["n"]);
        block.parameters[0].kind = serde_json::from_value(serde_json::json!(kind)).unwrap();
        block.parameters[0].max_value = bound;
        loop_route(&mut config, "orders.list").query_pagination = Some(block);
        tally.expect(label, &config, expect);
    }
    // A resource parameter in a query-located resource route collides too.
    let mut config = browser_loop();
    {
        let read = loop_route(&mut config, "orders.read");
        read.path = "/order".to_owned();
        read.resource_path_parameter = None;
        read.resource_query_parameter = Some("Order_Id".to_owned());
    }
    loop_route(&mut config, "orders.list").query_pagination = Some(paging(&["order_id"]));
    tally.expect("case-folded query resource parameter", &config, reject);
    tally.finish(5, 14);
}

/// Every combination of admission, method and neighbouring blocks with a
/// pagination block: core may be stricter than the edge, never looser.
#[test]
fn generated_query_pagination_routes_never_pass_core_and_fail_the_edge() {
    let mut tally = Tally::new();
    let template = browser_loop();
    let list = loop_route(&mut browser_loop(), "orders.list").clone();
    let entries = [
        SecurityEntry::Public,
        SecurityEntry::AuthEntry,
        SecurityEntry::AuthenticatedRoot,
        SecurityEntry::UiActionRequired,
    ];
    let blocks = [
        paging(&["page"]),
        paging(&["page", "page"]),
        paging(&["order_id"]),
        paging(&[]),
    ];
    for entry in entries {
        for method in ["GET", "POST"] {
            for with_grant in [false, true] {
                for with_resource in [false, true] {
                    for block in &blocks {
                        let mut probe = exact("probe", method, "/probe", entry);
                        probe.response_mode = "BUFFERED_JSON".to_owned();
                        probe.max_response_bytes = 16_384;
                        if with_grant {
                            probe.resource_grant.clone_from(&list.resource_grant);
                        }
                        if with_resource {
                            probe.resource_type = Some("order".to_owned());
                            probe.view_profile = Some("summary".to_owned());
                            probe.resource_query_parameter = Some("record".to_owned());
                        }
                        probe.query_pagination = Some(block.clone());
                        let mut config = template.clone();
                        config.listen_port = 6100;
                        config.policy.routes.push(probe);
                        tally.implication(
                            &format!(
                                "{entry:?} {method} grant={with_grant} resource={with_resource} {block:?}"
                            ),
                            &config,
                        );
                    }
                }
            }
        }
    }
    tally.finish(1, 50);
}

/// The identity script's share scope: a fixed `share_entry` read and the UI
/// action that issues credentials for it (`scripts/test_gateway_identity.sh`).
fn share_read() -> SiteRouteConfig {
    let mut route = exact(
        "records.share.read",
        "GET",
        "/shared-record",
        SecurityEntry::ShareEntry,
    );
    route.resource_type = Some("record".to_owned());
    route.view_profile = Some("shared_summary".to_owned());
    route.resource_query_parameter = Some("record_id".to_owned());
    route
}

fn share_issuer() -> SiteRouteConfig {
    let mut route = exact(
        "records.share.issue",
        "GET",
        "/share-issue",
        SecurityEntry::UiActionRequired,
    );
    route.source_action = Some("records.share".to_owned());
    route.resource_type = Some("record".to_owned());
    route.view_profile = Some("share_controls".to_owned());
    route.resource_query_parameter = Some("record_id".to_owned());
    "BUFFERED_JSON".clone_into(&mut route.response_mode);
    route.max_response_bytes = 512;
    route.share_issue = Some(xshield_core::SiteShareIssue {
        success_status: 200,
        token_field: "share_token".to_owned(),
        target_operation_id: "records.share.read".to_owned(),
        issuance_rule_id: "record-share-r1".to_owned(),
        ttl_seconds: 300,
        max_active_shares: 1,
    });
    route
}

/// The loop topology with the share pair next to it.
fn share_flow() -> SiteConfig {
    let mut config = browser_loop();
    config.policy.routes.push(share_read());
    config.policy.routes.push(share_issuer());
    config
}

fn share_block(config: &mut SiteConfig) -> &mut xshield_core::SiteShareIssue {
    loop_route(config, "records.share.issue")
        .share_issue
        .as_mut()
        .unwrap()
}

/// The script that runs the real edge binary against a real database.
const GATEWAY_IDENTITY_SCRIPT: &str = include_str!("../../../scripts/test_gateway_identity.sh");

/// The operations of the real-binary identity script whose id starts with
/// `prefix`, without the explicit `null` members its heredoc spells out.
fn script_operations(prefix: &str) -> Vec<serde_json::Value> {
    fn strip_nulls(value: &mut serde_json::Value) {
        if let Some(object) = value.as_object_mut() {
            object.retain(|_, member| !member.is_null());
            object.values_mut().for_each(strip_nulls);
        }
    }
    let needle = format!("\"operation_id\":\"{prefix}");
    let mut operations = GATEWAY_IDENTITY_SCRIPT
        .lines()
        .filter(|line| line.trim_start().starts_with('{') && line.contains(&needle))
        .map(|line| {
            let mut value: serde_json::Value =
                serde_json::from_str(line.trim().trim_end_matches(',')).unwrap();
            strip_nulls(&mut value);
            value
        })
        .collect::<Vec<_>>();
    operations.sort_by_key(|operation| operation["operation_id"].as_str().map(str::to_owned));
    operations
}

/// The share scope the real-binary identity script exercises is exactly what
/// the control plane projects from its typed model.
#[test]
fn the_identity_scripts_share_scope_is_what_the_control_plane_projects() {
    let scripted = script_operations("records.share.");
    assert_eq!(scripted.len(), 2, "the script's share operations moved");
    let mut projected = vec![
        xshield_core::site::gateway_operation(&share_read()).unwrap(),
        xshield_core::site::gateway_operation(&share_issuer()).unwrap(),
    ];
    projected.sort_by_key(|operation| operation["operation_id"].as_str().map(str::to_owned));
    assert_eq!(projected, scripted);
}

/// `share_issue` and the `share_entry` admission, judged by the control plane
/// and the real edge compiler alike.
#[test]
#[allow(clippy::too_many_lines)]
fn share_issue_rules_match_the_edge() {
    let mut tally = Tally::new();
    let both = Expect::BothAccept;
    let reject = Expect::CoreMustReject;

    tally.expect("the share pair", &share_flow(), both);
    check(
        &mut tally,
        "share entry alone",
        |c| c.policy.routes.push(share_read()),
        both,
    );
    check(
        &mut tally,
        "share entry located by a path segment, no issuer",
        |c| {
            let mut entry = share_read();
            entry.path = "/shared/{record_id}".to_owned();
            entry.resource_query_parameter = None;
            entry.resource_path_parameter = Some("record_id".to_owned());
            c.policy.routes.push(entry);
        },
        both,
    );
    for (label, status, expect) in [
        ("status 200", 200, both),
        ("status 201", 201, both),
        ("status 299", 299, both),
        ("status 199", 199, reject),
        ("status 204", 204, reject),
        ("status 205", 205, reject),
        ("status 206", 206, reject),
        ("status 300", 300, reject),
    ] {
        let mut config = share_flow();
        share_block(&mut config).success_status = status;
        tally.expect(&format!("share {label}"), &config, expect);
    }
    for (label, ttl, expect) in [
        ("ttl 1", 1, both),
        ("ttl 86400", 86_400, both),
        ("ttl 0", 0, reject),
        ("ttl 86401", 86_401, reject),
    ] {
        let mut config = share_flow();
        share_block(&mut config).ttl_seconds = ttl;
        tally.expect(&format!("share {label}"), &config, expect);
    }
    for (label, active, expect) in [
        ("active shares 1", 1, both),
        ("active shares 5000", 5_000, both),
        ("active shares 0", 0, reject),
        ("active shares 5001", 5_001, reject),
    ] {
        let mut config = share_flow();
        share_block(&mut config).max_active_shares = active;
        tally.expect(&format!("share {label}"), &config, expect);
    }
    let long = "f".repeat(129);
    let max = "f".repeat(128);
    for (label, field, value, expect) in [
        ("token field of 128", "token_field", max.as_str(), both),
        ("token field of 129", "token_field", long.as_str(), reject),
        ("empty token field", "token_field", "", reject),
        ("token field with a space", "token_field", "a b", reject),
        ("token field with a slash", "token_field", "a/b", reject),
        ("rule id of 128", "issuance_rule_id", max.as_str(), both),
        ("rule id of 129", "issuance_rule_id", long.as_str(), reject),
        ("empty rule id", "issuance_rule_id", "", reject),
        ("rule id with a colon", "issuance_rule_id", "a:b", reject),
        (
            "unknown target",
            "target_operation_id",
            "records.gone",
            reject,
        ),
        ("empty target", "target_operation_id", "", reject),
        (
            "target is not a share entry",
            "target_operation_id",
            "orders.read",
            reject,
        ),
        (
            "target is a page",
            "target_operation_id",
            "app.page",
            reject,
        ),
        (
            "target is the issuer",
            "target_operation_id",
            "records.share.issue",
            reject,
        ),
    ] {
        let mut config = share_flow();
        let block = share_block(&mut config);
        match field {
            "token_field" => value.clone_into(&mut block.token_field),
            "issuance_rule_id" => value.clone_into(&mut block.issuance_rule_id),
            _ => value.clone_into(&mut block.target_operation_id),
        }
        tally.expect(label, &config, expect);
    }
    // The issuer must be a UI action GET bound to a resource.
    check_share(
        &mut tally,
        "issuer without a resource binding",
        |c| {
            let issuer = loop_route(c, "records.share.issue");
            issuer.resource_type = None;
            issuer.view_profile = None;
            issuer.resource_query_parameter = None;
        },
        reject,
    );
    for (label, entry) in [
        (
            "issuer on an authenticated root",
            SecurityEntry::AuthenticatedRoot,
        ),
        ("issuer on a public route", SecurityEntry::Public),
        ("issuer on an auth entry", SecurityEntry::AuthEntry),
        ("issuer on a share entry", SecurityEntry::ShareEntry),
    ] {
        let mut config = share_flow();
        let issuer = loop_route(&mut config, "records.share.issue");
        issuer.security_entry = entry;
        issuer.source_action = None;
        tally.expect(label, &config, reject);
    }
    check_share(
        &mut tally,
        "issuer as a path-located resource route",
        |c| {
            let issuer = loop_route(c, "records.share.issue");
            issuer.path = "/share-issue/{record_id}".to_owned();
            issuer.resource_query_parameter = None;
            issuer.resource_path_parameter = Some("record_id".to_owned());
        },
        both,
    );
    // The redeeming route.
    check_share(
        &mut tally,
        "target of another resource type",
        |c| loop_route(c, "records.share.read").resource_type = Some("other".to_owned()),
        reject,
    );
    check_share(
        &mut tally,
        "target located by a path segment",
        |c| {
            let entry = loop_route(c, "records.share.read");
            entry.path = "/shared/{record_id}".to_owned();
            entry.resource_query_parameter = None;
            entry.resource_path_parameter = Some("record_id".to_owned());
        },
        reject,
    );
    check_share(
        &mut tally,
        "share entry without a resource",
        |c| {
            let entry = loop_route(c, "records.share.read");
            entry.resource_type = None;
            entry.view_profile = None;
            entry.resource_query_parameter = None;
        },
        reject,
    );
    check_share(
        &mut tally,
        "share entry with a source action",
        |c| loop_route(c, "records.share.read").source_action = Some("records.read".to_owned()),
        reject,
    );
    check_share(
        &mut tally,
        "share entry that is not a GET",
        |c| loop_route(c, "records.share.read").method = "POST".to_owned(),
        reject,
    );
    check_share(
        &mut tally,
        "paginated share entry",
        |c| loop_route(c, "records.share.read").query_pagination = Some(paging(&["page"])),
        reject,
    );
    check_share(
        &mut tally,
        "share entry carrying a grant",
        |c| {
            let grant = loop_route(c, "orders.list").resource_grant.clone();
            loop_route(c, "records.share.read").resource_grant = grant;
        },
        reject,
    );
    // Neighbouring effects on the issuer.
    check_share(
        &mut tally,
        "issuer that also qualifies resources",
        |c| {
            let grant = loop_route(c, "orders.list").resource_grant.clone();
            loop_route(c, "records.share.issue").resource_grant = grant;
        },
        reject,
    );
    check_share(
        &mut tally,
        "issuer with response encryption",
        |c| {
            loop_route(c, "records.share.issue").response_crypto =
                Some(response_crypto("rk", 4_096));
        },
        reject,
    );
    check_share(
        &mut tally,
        "issuer served as SENSOR_HTML",
        |c| {
            let mut sensor = loop_route(c, "app.page").sensor_html.clone().unwrap();
            "share-page-r1".clone_into(&mut sensor.adapter_revision);
            sensor.origin_sha256 = "d".repeat(64);
            let issuer = loop_route(c, "records.share.issue");
            issuer.response_mode = "SENSOR_HTML".to_owned();
            issuer.sensor_html = Some(sensor);
        },
        reject,
    );
    check_share(
        &mut tally,
        "issuer without a response mode",
        |c| loop_route(c, "records.share.issue").response_mode = String::new(),
        both,
    );
    // The issuer is also a grant target, as in the real flow: the descriptor
    // the grant provisions is the same on both sides.
    check_share(
        &mut tally,
        "issuer reached through a page-issued grant",
        |c| {
            let mut list = loop_route(c, "orders.list").clone();
            "records.list".clone_into(&mut list.operation_id);
            "/records".clone_into(&mut list.path);
            "records.list.open".clone_into(list.source_action.as_mut().unwrap());
            let grant = list.resource_grant.as_mut().unwrap();
            "records.share.issue".clone_into(&mut grant.target_operation_id);
            "share-map-r1".clone_into(&mut grant.target_mapping_revision);
            c.policy.routes.push(list);
        },
        both,
    );
    tally.finish(12, 30);
}

/// The control-plane spelling of the loop with a share scope.
const SHARE_FLOW_FIXTURE: &str = include_str!("../../../tests/site-config/share-flow.json");

/// The share fixture compiles on the edge, both sides derive one descriptor
/// digest for it, and the share blocks themselves leave that digest alone:
/// the edge derives descriptors from page actions and grant targets only, so
/// a share change must not demand a new `policy_revision` label (the issuer
/// route, as a grant target, is the one part that does).
#[test]
fn the_share_fixture_compiles_and_the_share_blocks_leave_the_descriptor_set_alone() {
    let mut full: SiteConfig = serde_json::from_str(SHARE_FLOW_FIXTURE).unwrap();
    full.listen_port = 6100;
    let mut tally = Tally::new();
    tally.expect("the share fixture", &full, Expect::BothAccept);
    let edge_digest = |config: &SiteConfig| {
        let value = config.gateway_config(TENANT, &site()).unwrap();
        GatewayConfig::from_json(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .edge_descriptors()
            .unwrap()
            .content_digest_hex()
    };
    let mut bare = full.clone();
    loop_route(&mut bare, "records.share.issue").share_issue = None;
    bare.policy
        .routes
        .retain(|route| route.operation_id != "records.share.read");
    tally.expect(
        "the fixture without its share scope",
        &bare,
        Expect::BothAccept,
    );
    assert_eq!(edge_digest(&full), edge_digest(&bare));
    tally.finish(2, 0);
}

/// Every combination of admission, method, resource binding and neighbouring
/// blocks with a `share_issue` or a `share_entry` admission: core may be
/// stricter than the edge, never looser.
#[test]
fn generated_share_routes_never_pass_core_and_fail_the_edge() {
    let mut tally = Tally::new();
    let entries = [
        SecurityEntry::Public,
        SecurityEntry::AuthEntry,
        SecurityEntry::AuthenticatedRoot,
        SecurityEntry::UiActionRequired,
        SecurityEntry::ShareEntry,
    ];
    let issuer = share_issuer();
    let grant = loop_route(&mut browser_loop(), "orders.list")
        .resource_grant
        .clone();
    let revoke = loop_route(&mut browser_loop(), "auth.logout")
        .auth_revoke
        .clone();
    for entry in entries {
        for method in ["GET", "POST"] {
            for mode in ["", "BUFFERED_JSON"] {
                for blocks in 0_u8..64 {
                    let mut probe = exact("probe", method, "/probe", entry);
                    probe.response_mode = mode.to_owned();
                    probe.max_response_bytes = 16_384;
                    if blocks & 1 != 0 {
                        probe.share_issue.clone_from(&issuer.share_issue);
                    }
                    if blocks & 2 != 0 {
                        probe.resource_type = Some("record".to_owned());
                        probe.view_profile = Some("share_controls".to_owned());
                        probe.resource_query_parameter = Some("record_id".to_owned());
                    }
                    if blocks & 4 != 0 {
                        probe.response_crypto = Some(response_crypto("rk", 40_000));
                    }
                    if blocks & 8 != 0 {
                        probe.resource_grant.clone_from(&grant);
                    }
                    if blocks & 16 != 0 {
                        probe.auth_revoke.clone_from(&revoke);
                    }
                    if blocks & 32 != 0 {
                        probe.request_crypto = Some(observe("probe-observe-r1"));
                    }
                    // The probe stands next to a valid pair, and is also the
                    // target of the issuer, so that both ends of the
                    // cross-route rule are exercised.
                    let mut config = share_flow();
                    config.policy.routes.push(probe.clone());
                    tally.implication(
                        &format!("{entry:?} {method} {mode:?} blocks={blocks:06b}"),
                        &config,
                    );
                    let mut retargeted = share_flow();
                    share_block(&mut retargeted).target_operation_id = "probe".to_owned();
                    retargeted.policy.routes.push(probe);
                    tally.implication(
                        &format!("{entry:?} {method} {mode:?} blocks={blocks:06b} retargeted"),
                        &retargeted,
                    );
                }
            }
        }
    }
    tally.finish(20, 500);
}

/// The identity script's credential refresh and account switch routes.
fn transition_route(id: &str, path: &str) -> SiteRouteConfig {
    let mut route = exact(id, "POST", path, SecurityEntry::AuthenticatedRoot);
    "BUFFERED_JSON".clone_into(&mut route.response_mode);
    route.max_response_bytes = 512;
    route
}

fn transition_block() -> xshield_core::SiteAuthTransition {
    xshield_core::SiteAuthTransition {
        success_status: 200,
        principal_pointer: "/identity/id".to_owned(),
        authorization_context_pointer: "/identity/authorization_context".to_owned(),
        bearer_pointer: "/access_token".to_owned(),
        credential_ttl_seconds: 1_800,
    }
}

fn refresh_route() -> SiteRouteConfig {
    let mut route = transition_route("auth.refresh", "/refresh");
    route.auth_refresh = Some(transition_block());
    route
}

fn switch_route() -> SiteRouteConfig {
    let mut route = transition_route("auth.context.switch", "/account-switch");
    route.auth_context_switch = Some(transition_block());
    route
}

/// The loop topology with a refresh and an account switch next to it.
fn transition_flow() -> SiteConfig {
    let mut config = browser_loop();
    config.policy.routes.push(refresh_route());
    config.policy.routes.push(switch_route());
    config
}

/// Judges the transition topology after `mutate`.
fn check_transition(tally: &mut Tally, label: &str, mutate: fn(&mut SiteConfig), expect: Expect) {
    let mut config = transition_flow();
    mutate(&mut config);
    tally.expect(label, &config, expect);
}

/// Both transition blocks of a route, for rules that hold for either.
fn transitions(route: &mut SiteRouteConfig) -> [&mut Option<xshield_core::SiteAuthTransition>; 2] {
    [&mut route.auth_refresh, &mut route.auth_context_switch]
}

/// The credential refresh and account switch routes the real-binary identity
/// script exercises are exactly what the control plane projects.
#[test]
fn the_identity_scripts_transition_routes_are_what_the_control_plane_projects() {
    let mut scripted = script_operations("auth.refresh");
    scripted.extend(script_operations("auth.context.switch"));
    scripted.sort_by_key(|operation| operation["operation_id"].as_str().map(str::to_owned));
    assert_eq!(
        scripted.len(),
        4,
        "the script's transition operations moved"
    );
    // The script gives the two refresh routes and the two switch routes one
    // shape each; project the same shapes under its operation ids and paths.
    let mut projected = Vec::new();
    for (id, path) in [
        ("auth.refresh", "/refresh"),
        ("auth.refresh.switch", "/refresh-switch"),
    ] {
        let mut route = transition_route(id, path);
        route.auth_refresh = Some(transition_block());
        projected.push(xshield_core::site::gateway_operation(&route).unwrap());
    }
    for (id, path) in [
        ("auth.context.switch", "/account-switch"),
        ("auth.context.switch.same", "/account-switch-same"),
    ] {
        let mut route = transition_route(id, path);
        route.auth_context_switch = Some(transition_block());
        projected.push(xshield_core::site::gateway_operation(&route).unwrap());
    }
    projected.sort_by_key(|operation| operation["operation_id"].as_str().map(str::to_owned));
    assert_eq!(projected, scripted);
}

/// `auth_refresh` and `auth_context_switch`, judged by the control plane and
/// the real edge compiler alike.
#[test]
#[allow(clippy::too_many_lines)]
fn auth_transition_rules_match_the_edge() {
    let mut tally = Tally::new();
    let both = Expect::BothAccept;
    let reject = Expect::CoreMustReject;

    tally.expect("the transition pair", &transition_flow(), both);
    for (label, status, expect) in [
        ("status 200", 200, both),
        ("status 201", 201, both),
        ("status 205", 205, both),
        ("status 299", 299, both),
        ("status 199", 199, reject),
        ("status 204", 204, reject),
        ("status 300", 300, reject),
    ] {
        for name in ["refresh", "switch"] {
            let mut config = transition_flow();
            let route = loop_route(
                &mut config,
                if name == "refresh" {
                    "auth.refresh"
                } else {
                    "auth.context.switch"
                },
            );
            for block in transitions(route).into_iter().flatten() {
                block.success_status = status;
            }
            tally.expect(&format!("{name} {label}"), &config, expect);
        }
    }
    for (label, ttl, expect) in [
        ("ttl 1", 1, both),
        ("ttl 86400", 86_400, both),
        ("ttl 0", 0, reject),
        ("ttl 86401", 86_401, reject),
    ] {
        let mut config = transition_flow();
        for id in ["auth.refresh", "auth.context.switch"] {
            for block in transitions(loop_route(&mut config, id))
                .into_iter()
                .flatten()
            {
                block.credential_ttl_seconds = ttl;
            }
        }
        tally.expect(&format!("transition {label}"), &config, expect);
    }
    let long = format!("/{}", "a".repeat(512));
    let max = format!("/{}", "a".repeat(511));
    for (label, pointer, expect) in [
        ("rooted pointer of 512", max.as_str(), both),
        ("pointer of 513", long.as_str(), reject),
        ("unrooted pointer", "access_token", reject),
        ("empty pointer", "", reject),
        ("bad escape", "/a~2b", reject),
        ("trailing tilde", "/a~", reject),
        ("escaped slash", "/a~1b", both),
        ("control byte", "/a\u{7}b", reject),
        ("non-ascii", "/名前", both),
        ("same as the principal", "/identity/id", reject),
        (
            "same as the context",
            "/identity/authorization_context",
            reject,
        ),
    ] {
        for field in ["bearer", "context", "principal"] {
            let mut config = transition_flow();
            for id in ["auth.refresh", "auth.context.switch"] {
                for block in transitions(loop_route(&mut config, id))
                    .into_iter()
                    .flatten()
                {
                    match field {
                        "bearer" => pointer.clone_into(&mut block.bearer_pointer),
                        "context" => pointer.clone_into(&mut block.authorization_context_pointer),
                        _ => pointer.clone_into(&mut block.principal_pointer),
                    }
                }
            }
            // A pointer equal to another member's is only a violation in
            // the fields where it makes two members the same; every other
            // sample has one verdict on both sides.
            if label.starts_with("same as") {
                tally.implication(&format!("{field} {label}"), &config);
            } else {
                tally.expect(&format!("{field} {label}"), &config, expect);
            }
        }
    }
    // Admission.
    for (label, entry) in [
        ("on a public route", SecurityEntry::Public),
        ("on an auth entry", SecurityEntry::AuthEntry),
        ("on a UI action", SecurityEntry::UiActionRequired),
    ] {
        for id in ["auth.refresh", "auth.context.switch"] {
            let mut config = transition_flow();
            let route = loop_route(&mut config, id);
            route.security_entry = entry;
            route.source_action =
                (entry == SecurityEntry::UiActionRequired).then(|| "transition.open".to_owned());
            tally.expect(&format!("{id} {label}"), &config, reject);
        }
    }
    // One effect per response.
    check_transition(
        &mut tally,
        "refresh and switch on one route",
        |c| {
            let switch = loop_route(c, "auth.context.switch")
                .auth_context_switch
                .clone();
            loop_route(c, "auth.refresh").auth_context_switch = switch;
        },
        reject,
    );
    check_transition(
        &mut tally,
        "refresh that also revokes",
        |c| {
            let revoke = loop_route(c, "auth.logout").auth_revoke.clone();
            loop_route(c, "auth.refresh").auth_revoke = revoke;
        },
        reject,
    );
    check_transition(
        &mut tally,
        "switch that also qualifies resources",
        |c| {
            let grant = loop_route(c, "orders.list").resource_grant.clone();
            loop_route(c, "auth.context.switch").resource_grant = grant;
        },
        reject,
    );
    check_transition(
        &mut tally,
        "refresh served as SENSOR_HTML",
        |c| {
            let mut sensor = loop_route(c, "app.page").sensor_html.clone().unwrap();
            "refresh-page-r1".clone_into(&mut sensor.adapter_revision);
            sensor.origin_sha256 = "c".repeat(64);
            let route = loop_route(c, "auth.refresh");
            route.method = "GET".to_owned();
            "SENSOR_HTML".clone_into(&mut route.response_mode);
            route.sensor_html = Some(sensor);
        },
        reject,
    );
    check_transition(
        &mut tally,
        "refresh without a response mode",
        |c| loop_route(c, "auth.refresh").response_mode = String::new(),
        both,
    );
    check_transition(
        &mut tally,
        "refresh as a GET",
        |c| loop_route(c, "auth.refresh").method = "GET".to_owned(),
        both,
    );
    check_transition(
        &mut tally,
        "refresh behind an observed request body",
        |c| loop_route(c, "auth.refresh").request_crypto = Some(observe("refresh-observe-r1")),
        reject,
    );
    check_transition(
        &mut tally,
        "switch behind an observed request body",
        |c| {
            loop_route(c, "auth.context.switch").request_crypto =
                Some(observe("switch-observe-r1"));
        },
        reject,
    );
    check_transition(
        &mut tally,
        "switch behind a decrypted request body",
        |c| loop_route(c, "auth.context.switch").request_crypto = Some(decrypt("switch-key")),
        both,
    );
    // The sensor learns at most 64 identity-change routes: binding,
    // revocation and context switch count; a refresh does not.
    for (label, count, expect) in [
        ("62 switch routes next to the loop's two", 62, both),
        ("63 switch routes next to the loop's two", 63, reject),
    ] {
        let mut config = browser_loop();
        for index in 0..count {
            let mut route = switch_route();
            route.operation_id = format!("auth.switch.{index}");
            route.path = format!("/switch/{index}");
            config.policy.routes.push(route);
        }
        tally.expect(label, &config, expect);
    }
    let mut config = browser_loop();
    for index in 0..80 {
        let mut route = refresh_route();
        route.operation_id = format!("auth.refresh.{index}");
        route.path = format!("/refresh/{index}");
        config.policy.routes.push(route);
    }
    tally.expect("80 refresh routes", &config, both);
    tally.finish(20, 30);
}

/// A transition never changes the action-descriptor set: the edge derives
/// descriptors from page actions and grant targets only, so adding, removing
/// or retuning a refresh or a switch must not demand a new label.
#[test]
fn transition_blocks_leave_the_descriptor_set_alone() {
    let mut tally = Tally::new();
    let edge_digest = |config: &SiteConfig| {
        let value = config.gateway_config(TENANT, &site()).unwrap();
        GatewayConfig::from_json(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .edge_descriptors()
            .unwrap()
            .content_digest_hex()
    };
    let with = transition_flow();
    tally.expect("loop with transitions", &with, Expect::BothAccept);
    let without = browser_loop();
    tally.expect("loop without them", &without, Expect::BothAccept);
    assert_eq!(edge_digest(&with), edge_digest(&without));
    tally.finish(2, 0);
}

/// Every combination of admission, method, neighbouring blocks and request
/// crypto with the transition blocks: core may be stricter than the edge,
/// never looser.
#[test]
fn generated_transition_routes_never_pass_core_and_fail_the_edge() {
    let mut tally = Tally::new();
    let template = transition_flow();
    let grant = loop_route(&mut browser_loop(), "orders.list")
        .resource_grant
        .clone();
    let revoke = loop_route(&mut browser_loop(), "auth.logout")
        .auth_revoke
        .clone();
    let binding = loop_route(&mut browser_loop(), "auth.login")
        .auth_binding
        .clone();
    let entries = [
        SecurityEntry::Public,
        SecurityEntry::AuthEntry,
        SecurityEntry::AuthenticatedRoot,
        SecurityEntry::UiActionRequired,
        SecurityEntry::ShareEntry,
    ];
    for entry in entries {
        for method in ["GET", "POST"] {
            for mode in ["", "BUFFERED_JSON"] {
                for blocks in 0_u16..256 {
                    let mut probe = exact("probe", method, "/probe", entry);
                    probe.response_mode = mode.to_owned();
                    probe.max_response_bytes = 16_384;
                    if blocks & 1 != 0 {
                        probe.auth_refresh = Some(transition_block());
                    }
                    if blocks & 2 != 0 {
                        probe.auth_context_switch = Some(transition_block());
                    }
                    if blocks & 4 != 0 {
                        probe.auth_revoke.clone_from(&revoke);
                    }
                    if blocks & 8 != 0 {
                        probe.auth_binding.clone_from(&binding);
                    }
                    if blocks & 16 != 0 {
                        probe.resource_grant.clone_from(&grant);
                    }
                    if blocks & 32 != 0 {
                        probe.request_crypto = Some(observe("probe-observe-r1"));
                    }
                    if blocks & 64 != 0 {
                        probe.request_crypto = Some(decrypt("probe-key"));
                    }
                    if blocks & 128 != 0 {
                        probe.response_crypto = Some(response_crypto("probe-response", 40_000));
                    }
                    let mut config = template.clone();
                    config.policy.routes.push(probe);
                    tally.implication(
                        &format!("{entry:?} {method} {mode:?} blocks={blocks:08b}"),
                        &config,
                    );
                }
            }
        }
    }
    tally.finish(20, 500);
}

fn builds(count: usize) -> Vec<xshield_core::SiteSensorHtmlAdapter> {
    (1..=count)
        .map(|build| xshield_core::SiteSensorHtmlAdapter {
            adapter_revision: format!("app-r{}", build + 1),
            origin_sha256: format!("{build:064x}"),
            injection_offset: 10,
        })
        .collect()
}

/// A probe route with every combination of admission, method, response mode
/// and flow block, added to the loop topology so that cross-route references
/// resolve. Not exhaustive; it finds edge rules no hand-written case names.
#[test]
fn generated_flow_routes_never_pass_core_and_fail_the_edge() {
    let mut tally = Tally::new();
    let template = browser_loop();
    let block = |id: &str| {
        template
            .policy
            .routes
            .iter()
            .find(|route| route.operation_id == id)
            .unwrap()
            .clone()
    };
    let (login, page, list, logout) = (
        block("auth.login"),
        block("app.page"),
        block("orders.list"),
        block("auth.logout"),
    );
    let entries = [
        SecurityEntry::Public,
        SecurityEntry::AuthEntry,
        SecurityEntry::AuthenticatedRoot,
        SecurityEntry::UiActionRequired,
    ];
    for entry in entries {
        for method in ["GET", "POST"] {
            for mode in ["", "BUFFERED_JSON", "SENSOR_HTML"] {
                for blocks in 0_u8..64 {
                    let mut probe = exact("probe", method, "/probe", entry);
                    probe.response_mode = mode.to_owned();
                    probe.max_response_bytes = 16_384;
                    if blocks & 1 != 0 {
                        probe.auth_binding.clone_from(&login.auth_binding);
                    }
                    if blocks & 2 != 0 {
                        probe.auth_revoke.clone_from(&logout.auth_revoke);
                    }
                    if blocks & 4 != 0 {
                        let mut sensor = page.sensor_html.clone().unwrap();
                        "probe-r1".clone_into(&mut sensor.adapter_revision);
                        sensor.origin_sha256 = "e".repeat(64);
                        probe.sensor_html = Some(sensor);
                    }
                    if blocks & 8 != 0 {
                        let mut actions = page.page_actions.clone().unwrap();
                        "probe-map-r1".clone_into(&mut actions.mapping_revision);
                        probe.page_actions = Some(actions);
                    }
                    if blocks & 16 != 0 {
                        probe.issued_by.clone_from(&list.issued_by);
                    }
                    if blocks & 32 != 0 {
                        probe.resource_grant.clone_from(&list.resource_grant);
                    }
                    let mut config = template.clone();
                    config.listen_port = 6100;
                    config.policy.routes.push(probe.clone());
                    tally.implication(
                        &format!("{entry:?} {method} {mode:?} blocks={blocks:06b}"),
                        &config,
                    );
                    // The same probe as a page root that issues itself.
                    if blocks & 8 != 0 {
                        let mut issuing = template.clone();
                        issuing.listen_port = 6100;
                        let mut issued = exact(
                            "probe.action",
                            "POST",
                            "/probe-action",
                            SecurityEntry::UiActionRequired,
                        );
                        issued.issued_by = Some(xshield_core::SiteIssuedBy {
                            page_operation_id: "probe".to_owned(),
                            ttl_seconds: 60,
                        });
                        issuing.policy.routes.push(probe);
                        issuing.policy.routes.push(issued);
                        tally.implication(
                            &format!("{entry:?} {method} {mode:?} blocks={blocks:06b} issuing"),
                            &issuing,
                        );
                    }
                }
            }
        }
    }
    assert!(
        tally.digests >= 46,
        "only {} digests compared",
        tally.digests
    );
    tally.finish(20, 500);
}

/// The edge parses at most 1 MiB per site; core refuses larger projections.
#[test]
fn projections_above_the_edge_size_limit_are_refused_by_both() {
    let mut tally = Tally::new();
    let pages = |count: usize| {
        let mut config = base();
        config.sensor_enabled = true;
        config.security_entry = "public".to_owned();
        config.policy.routes = (0..count)
            .map(|index| {
                let mut route = exact(
                    &format!("page.{index}"),
                    "GET",
                    &format!("/p{index}"),
                    SecurityEntry::Public,
                );
                route.response_mode = "SENSOR_HTML".to_owned();
                let revision = |build: usize| format!("{build:x}{}", "r".repeat(126));
                let digest = |build: usize| format!("{:064x}", index * 100 + build);
                route.sensor_html = Some(xshield_core::SiteSensorHtml {
                    adapter_revision: revision(0),
                    origin_sha256: digest(0),
                    injection_offset: 10,
                    additional_adapters: (1..16)
                        .map(|build| xshield_core::SiteSensorHtmlAdapter {
                            adapter_revision: revision(build),
                            origin_sha256: digest(build),
                            injection_offset: 10,
                        })
                        .collect(),
                });
                route
            })
            .collect();
        config
    };
    tally.expect("64 large sensor pages", &pages(64), Expect::BothAccept);
    tally.expect(
        "200 large sensor pages",
        &pages(200),
        Expect::CoreMustReject,
    );
    tally.finish(1, 1);
}
