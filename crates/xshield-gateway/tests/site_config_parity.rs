//! Control-plane validation must never accept a site configuration that the
//! edge compiler rejects.
//!
//! The snapshot sent to the edge is all-or-nothing, so one site that passes
//! `SiteConfig::validate` but fails the edge compile used to make every apply
//! for the whole tenant return 422. Each sample here is projected with the same
//! `SiteConfig::gateway_config` the control plane uses, wrapped in an apply
//! request, and fed through `GatewaySnapshot::from_apply_request`. The
//! implication "core accepts => edge accepts" is asserted for every sample; a
//! new edge rule or a new control field that breaks it fails this test.

use xshield_core::{
    GatewayApplyRequest, GatewayApplySite, SecurityEntry, SiteConfig, SitePolicyConfig,
    SiteRequestCrypto, SiteResponseCrypto, SiteRouteConfig, domain::SiteId,
};
use xshield_gateway::multi_site::GatewaySnapshot;

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

/// Compiles the sample exactly as an edge apply would.
fn edge_verdict(config: &SiteConfig) -> Result<(), String> {
    let site = SiteId::parse(SITE).unwrap();
    let request = GatewayApplyRequest {
        protocol_version: 1,
        tenant_id: TENANT.to_owned(),
        apply_id: format!("apply_{}", uuid::Uuid::now_v7()),
        snapshot_revision: 1,
        sites: vec![GatewayApplySite {
            site_id: SITE.to_owned(),
            listen_port: config.listen_port,
            public_origin: config.public_origin.clone(),
            gateway_config: config.gateway_config(TENANT, &site),
            revision: 1,
        }],
    };
    GatewaySnapshot::from_apply_request(request)
        .map(|_| ())
        .map_err(|error| error.to_string())
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
    failures: Vec<String>,
}

impl Tally {
    fn new() -> Self {
        Self {
            core_accepted: 0,
            core_rejected: 0,
            failures: Vec::new(),
        }
    }

    /// Records the implication `core accepts => edge accepts` for one sample.
    fn implication(&mut self, label: &str, config: &SiteConfig) {
        match (config.validate(), edge_verdict(config)) {
            (Ok(()), Err(edge)) => self.failures.push(format!(
                "core accepted but the edge rejected `{label}`: {edge}"
            )),
            (Ok(()), Ok(())) => self.core_accepted += 1,
            (Err(_), _) => self.core_rejected += 1,
        }
    }

    fn expect(&mut self, label: &str, config: &SiteConfig, expect: Expect) {
        let core = config.validate();
        let edge = edge_verdict(config);
        match expect {
            Expect::BothAccept => {
                if let Err(error) = &core {
                    self.failures
                        .push(format!("core wrongly rejected `{label}`: {error}"));
                }
                if let Err(error) = &edge {
                    self.failures
                        .push(format!("edge rejected the `{label}` baseline: {error}"));
                }
            }
            Expect::CoreMustReject => {
                if edge.is_ok() {
                    self.failures.push(format!(
                        "table entry `{label}` is not an edge rejection; the table is stale"
                    ));
                }
                if core.is_ok() {
                    self.failures.push(format!(
                        "core accepted `{label}` which the edge rejects: {}",
                        edge.err().unwrap_or_default()
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
    // The sensor rewriting mode needs adapter metadata the control plane cannot
    // express, so the edge always rejects it.
    with(
        "sensor html mode",
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
                gateway_config: config.gateway_config(TENANT, &site_id),
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
}
