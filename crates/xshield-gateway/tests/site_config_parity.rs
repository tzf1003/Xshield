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
//! test.
//!
//! One edge refusal is not a validation rule: a live snapshot that declares
//! `page_actions` is refused (`apply page_actions`) until the edge can supply
//! the derived action descriptors on apply, which is being built separately.
//! [`edge_verdict`] reports that barrier as its own outcome, and only after
//! proving that the edge compiler accepts the configuration and that the
//! snapshot is accepted once the page issuance is taken out. When the edge
//! starts accepting such snapshots the barrier simply stops occurring.

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
    /// Refused only because live snapshots cannot carry `page_actions` yet;
    /// the edge compiler accepts the configuration itself.
    DescriptorBarrier,
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
        Err(ConfigError::Invalid("apply page_actions")) => {
            // The barrier is checked right after the per-site compile, before
            // the snapshot-level checks. Classify it as the barrier only when
            // the compiler accepts the configuration with its page issuance
            // and the whole snapshot is accepted without it.
            let compiled = config
                .gateway_config(TENANT, &site())
                .map_err(|error| error.to_string())
                .and_then(|value| serde_json::to_vec(&value).map_err(|error| error.to_string()))
                .and_then(|bytes| {
                    GatewayConfig::from_json(&bytes).map_err(|error| error.to_string())
                });
            let mut without_issuance = config.clone();
            for route in &mut without_issuance.policy.routes {
                route.page_actions = None;
                route.issued_by = None;
            }
            match (compiled, snapshot_verdict(&without_issuance)) {
                (Ok(compiled), Ok(())) if compiled.edge_descriptors().is_some() => {
                    Edge::DescriptorBarrier
                }
                (Err(error), _) => Edge::Rejected(error),
                (_, Err(error)) => Edge::Rejected(error.to_string()),
                (Ok(_), Ok(())) => Edge::Rejected("barrier without page actions".to_owned()),
            }
        }
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
    /// Samples accepted by both but held at the descriptor-supply barrier.
    barrier: usize,
    failures: Vec<String>,
}

impl Tally {
    fn new() -> Self {
        Self {
            core_accepted: 0,
            core_rejected: 0,
            barrier: 0,
            failures: Vec::new(),
        }
    }

    /// Records the implication `core accepts => edge accepts` for one sample.
    fn implication(&mut self, label: &str, config: &SiteConfig) {
        match (core_verdict(config), edge_verdict(config)) {
            (Ok(()), Edge::Rejected(edge)) => self.failures.push(format!(
                "core accepted but the edge rejected `{label}`: {edge}"
            )),
            (Ok(()), Edge::Accepted) => self.core_accepted += 1,
            (Ok(()), Edge::DescriptorBarrier) => {
                self.core_accepted += 1;
                self.barrier += 1;
            }
            (Err(_), _) => self.core_rejected += 1,
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
        .find("cat >\"$test_dir/gateway.json\" <<JSON\n")
        .expect("the loop script writes gateway.json from a heredoc");
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
    // Until the edge supplies descriptors on apply, the live snapshot path
    // holds the loop at the barrier; nothing else refuses it.
    assert!(matches!(
        edge_verdict(&browser_loop()),
        Edge::Accepted | Edge::DescriptorBarrier
    ));
}

/// Judges the loop topology after `mutate`.
fn check(tally: &mut Tally, label: &str, mutate: fn(&mut SiteConfig), expect: Expect) {
    let mut config = browser_loop();
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
    tally.finish(10, 30);
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
