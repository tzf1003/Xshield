//! Typed configuration of one protected site and its projection to the edge.
//!
//! The control plane stores, diffs, validates and publishes this value; the
//! edge compiles the JSON projection produced by [`SiteConfig::gateway_config`].
//! Keeping the value, its validation and the projection in this pure module is
//! what lets a gateway-side test feed the *same* projection through the edge
//! compiler and fail the build when control-side validation drifts from it.

use super::{
    RouteOperation, SecurityEntry, SitePolicyConfig, SiteRouteConfig, UpstreamEndpoint,
    route_path_is_edge_compilable,
};
use crate::domain::{InvalidValue, SiteId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::Ipv4Addr;

/// Prefix of the audit producer identity the edge derives for a site; the edge
/// caps the whole identity at 128 bytes.
const AUDIT_PRODUCER_PREFIX: &str = "edge-";
const AUDIT_PRODUCER_MAX_BYTES: usize = 128;

/// Everything an operator configures for one site, excluding identity and
/// revision metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    /// Operator label; cosmetic.
    pub display_name: String,
    /// Public origin used for Host/SNI route selection and the sensor.
    pub public_origin: String,
    /// Literal `ip:port` upstream socket.
    pub upstream_address: String,
    /// DNS name used as upstream SNI and `Host`.
    pub upstream_server_name: String,
    /// Whether the upstream connection uses TLS.
    pub upstream_tls: bool,
    /// Internal edge listener port; `0` asks the store to allocate one.
    pub listen_port: u16,
    /// Path of the default entry route used when `policy.routes` is empty.
    pub entry_path: String,
    /// Admission of the default entry route (`public`, `authenticated_root`
    /// or `ui_action_required`).
    pub security_entry: String,
    /// Whether the browser sensor is injected.
    pub sensor_enabled: bool,
    /// Operator-chosen policy label; cosmetic.
    pub policy_revision: String,
    /// `draft`, `active` or `paused`; only `active` sites are served.
    pub status: String,
    /// Typed policy surface.
    #[serde(default)]
    pub policy: SitePolicyConfig,
}

impl SiteConfig {
    /// Reads a configuration stored in `site_policy_revisions.config_json`.
    ///
    /// Revisions written by earlier versions lack `policy_revision` (it lives
    /// in its own column) and, for the oldest backfilled rows, `policy`; both
    /// are filled in. A `site_id` key left by the former rollback path is
    /// ignored. Anything else unexpected is rejected rather than guessed at.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] when the value is not a complete site
    /// configuration.
    pub fn from_stored(
        mut value: serde_json::Value,
        policy_revision: &str,
    ) -> Result<Self, InvalidValue> {
        let object = value
            .as_object_mut()
            .ok_or_else(|| InvalidValue::new("stored_site_config"))?;
        object.remove("site_id");
        object
            .entry("policy_revision")
            .or_insert_with(|| serde_json::Value::String(policy_revision.to_owned()));
        serde_json::from_value(value).map_err(|_| InvalidValue::new("stored_site_config"))
    }

    /// Returns whether the edge serves this configuration.
    #[must_use]
    pub fn is_serving(&self) -> bool {
        self.status == "active"
    }

    /// Returns the policy the edge compiles: when no route is configured the
    /// entry path and admission become the single `protected.entry` route.
    #[must_use]
    pub fn effective_policy(&self) -> SitePolicyConfig {
        let mut policy = self.policy.clone();
        if policy.routes.is_empty() {
            policy.routes.push(SiteRouteConfig {
                operation_id: "protected.entry".to_owned(),
                method: "GET".to_owned(),
                path: self.entry_path.clone(),
                security_entry: SecurityEntry::parse(&self.security_entry)
                    .unwrap_or(SecurityEntry::UiActionRequired),
                source_action: (self.security_entry == "ui_action_required")
                    .then(|| "protected.entry".to_owned()),
                resource_type: None,
                view_profile: None,
                resource_query_parameter: None,
                resource_path_parameter: None,
                request_crypto: None,
                response_crypto: None,
                response_mode: String::new(),
                max_response_bytes: 1_048_576,
            });
        }
        policy
    }

    /// Validates every invariant that does not depend on the deployment's
    /// network policy or on who is asking.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] whose field name identifies the offending
    /// area (`upstream_*` for the origin, `site_policy*` for the policy and
    /// routes, anything else for the remaining scalar fields).
    pub fn validate(&self) -> Result<(), InvalidValue> {
        UpstreamEndpoint::parse(
            self.upstream_address.clone(),
            self.upstream_server_name.clone(),
            self.upstream_tls,
        )
        .map_err(|_| InvalidValue::new("upstream_endpoint"))?;
        if self.display_name.is_empty()
            || self.display_name.len() > 128
            || self.display_name.trim() != self.display_name
            || self.display_name.chars().any(char::is_control)
            || (self.listen_port != 0 && !(6100..=65535).contains(&self.listen_port))
            || !matches!(
                self.security_entry.as_str(),
                "public" | "authenticated_root" | "ui_action_required"
            )
            || !matches!(self.status.as_str(), "draft" | "active" | "paused")
            || self.policy_revision.is_empty()
            || self.policy_revision.len() > 128
            || !self
                .policy_revision
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(InvalidValue::new("site_config"));
        }
        let security_entry = SecurityEntry::parse(&self.security_entry)?;
        RouteOperation::new(
            "protected.entry",
            "GET",
            self.entry_path.clone(),
            security_entry,
        )
        .map_err(|_| InvalidValue::new("site_config"))?;
        // The entry path is the default route's path whenever `policy.routes`
        // is empty, so it is held to the edge's route-path rules at all times.
        if !route_path_is_edge_compilable(&self.entry_path) {
            return Err(InvalidValue::new("site_config"));
        }
        validate_public_origin(&self.public_origin, self.sensor_enabled)?;
        self.effective_policy().validate()
    }

    /// Validates the configuration as it will be published for `site_id`.
    ///
    /// The site identifier is part of what the edge derives (the audit
    /// producer identity), so an identifier that makes the projection
    /// unacceptable is rejected here instead of failing the whole tenant
    /// snapshot at apply time.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] named `site_id` for an identifier the edge
    /// cannot use, otherwise the error of [`SiteConfig::validate`].
    pub fn validate_for_site(&self, site_id: &SiteId) -> Result<(), InvalidValue> {
        if AUDIT_PRODUCER_PREFIX.len() + site_id.as_str().len() > AUDIT_PRODUCER_MAX_BYTES {
            return Err(InvalidValue::new("site_id"));
        }
        self.validate()
    }

    /// Projects the configuration to the strict JSON the edge compiler
    /// consumes for one site.
    #[must_use]
    pub fn gateway_config(&self, tenant_id: &str, site_id: &SiteId) -> serde_json::Value {
        let policy = self.effective_policy();
        let operations = policy
            .routes
            .iter()
            .map(gateway_operation)
            .collect::<Vec<_>>();
        let mut gateway_config = json!({
            "listen": format!("127.0.0.1:{}", self.listen_port),
            "origin": {
                "address": self.upstream_address,
                "server_name": self.upstream_server_name,
                "tls": self.upstream_tls
            },
            "tenant_id": tenant_id,
            "site_id": site_id.as_str(),
            "policy_revision": self.policy_revision,
            "site_policy": policy.clone(),
            "audit": {
                "directory": format!("target/xshield-audit-{}", site_id.as_str()),
                "key_id": "deployment-managed",
                "producer_id": format!("edge-{}", site_id.as_str()),
                "max_bytes": 16_777_216_u64,
                "high_watermark_bytes": 12_582_912_u64,
                "segment_max_bytes": 4_194_304_u64
            },
            "operations": operations
        });
        if let Some(object) = gateway_config.as_object_mut() {
            // The edge refuses any route that needs identity, any request
            // crypto and the sensor without an identity store, so the store is
            // derived from what the effective routes actually need.
            let needs_identity_store = policy.identity.enabled
                || self.security_entry != "public"
                || self.sensor_enabled
                || policy.routes.iter().any(|route| {
                    route.security_entry != SecurityEntry::Public || route.request_crypto.is_some()
                });
            if needs_identity_store {
                object.insert(
                    "identity_store".to_owned(),
                    identity_store(policy.identity.session_ttl_seconds),
                );
            }
            if self.sensor_enabled {
                object.insert(
                    "sensor".to_owned(),
                    json!({
                        // The edge requires a bare `scheme://authority` origin.
                        "origin": self
                            .public_origin
                            .strip_suffix('/')
                            .unwrap_or(&self.public_origin),
                        "build_ref": "0000000000000000000000000000000000000000000000000000000000000000",
                        "heartbeat_seconds": 15
                    }),
                );
            }
        }
        gateway_config
    }
}

/// Anonymous-session settings for the edge identity store.
///
/// Sessions created in one rate window all live for the TTL, so the number
/// alive at once is the per-site creation rate times the windows the TTL
/// spans (plus one); the edge rejects a store whose product exceeds the
/// active-session budget. The creation rate is therefore derived from the TTL
/// instead of being fixed, which keeps every TTL the policy allows applicable.
fn identity_store(session_ttl_seconds: u64) -> serde_json::Value {
    const WINDOW_SECONDS: u64 = 60;
    const MAX_ACTIVE_SESSIONS: u64 = 100_000;
    const SITE_RATE: u64 = 1_000;
    const SOURCE_RATE: u64 = 10;
    let windows = session_ttl_seconds
        .div_ceil(WINDOW_SECONDS)
        .saturating_add(1);
    let per_site = SITE_RATE.min(MAX_ACTIVE_SESSIONS / windows).max(1);
    let per_source = SOURCE_RATE.min(per_site);
    json!({
        "max_connections": 8,
        "acquire_timeout_ms": 2000,
        "anonymous_session_ttl_seconds": session_ttl_seconds,
        "max_active_anonymous_sessions": MAX_ACTIVE_SESSIONS,
        "anonymous_session_rate_window_seconds": WINDOW_SECONDS,
        "max_anonymous_session_creations_per_source": per_source,
        "max_anonymous_session_creations_per_site": per_site
    })
}

/// Public origin rules shared by the control plane and the edge router.
///
/// Only an HTTPS origin or a plain-HTTP loopback origin (local lab) is
/// accepted, with an optional port and, for HTTP, one trailing slash. The edge
/// routes by host name and cannot route a bracketed IPv6 literal, so those are
/// refused here. With the sensor enabled, plain HTTP is further limited to the
/// two literal loopback names the sensor knows.
fn validate_public_origin(origin: &str, sensor_enabled: bool) -> Result<(), InvalidValue> {
    let invalid = || InvalidValue::new("public_origin");
    let (scheme, rest) = origin.split_once("://").ok_or_else(invalid)?;
    let https = match scheme {
        "https" => true,
        "http" => false,
        _ => return Err(invalid()),
    };
    let (authority, trailing_slash) = match rest.strip_suffix('/') {
        Some(authority) => (authority, true),
        None => (rest, false),
    };
    if authority.is_empty()
        || origin.len() > 512
        || !authority.bytes().all(|byte| byte.is_ascii_graphic())
        || authority.contains(['/', '?', '#', '@', '\\', '[', ']', '%'])
        || (https && trailing_slash)
    {
        return Err(invalid());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let valid_label = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    if host.is_empty()
        || host.contains(':')
        || host.len() > 253
        || !host.split('.').all(valid_label)
        || port.is_some_and(|port| {
            port.len() > 5
                || !port.bytes().all(|byte| byte.is_ascii_digit())
                || port.parse::<u16>().map_or(true, |value| value == 0)
        })
    {
        return Err(invalid());
    }
    if !https {
        // The URL parser the previous check used lower-cased host names.
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback());
        let sensor_loopback = matches!(host, "localhost" | "127.0.0.1");
        if !loopback || (sensor_enabled && !sensor_loopback) {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Projects one route to the edge's operation DTO.
#[must_use]
pub fn gateway_operation(route: &SiteRouteConfig) -> serde_json::Value {
    let admission = match route.security_entry {
        SecurityEntry::Public => "PUBLIC",
        SecurityEntry::AuthenticatedRoot => "AUTHENTICATED_ROOT",
        SecurityEntry::UiActionRequired => "UI_ACTION_REQUIRED",
    };
    let mut operation = json!({
        "operation_id": route.operation_id,
        "method": route.method,
        "path": route.path,
        "admission": admission,
        "source_action": route.source_action,
        "resource_type": route.resource_type,
        "view_profile": route.view_profile,
        "resource_query_parameter": route.resource_query_parameter,
        "resource_path_parameter": route.resource_path_parameter,
    });
    if let Some(request_crypto) = &route.request_crypto {
        operation["request_crypto"] = serde_json::to_value(request_crypto)
            .unwrap_or_else(|_| json!({ "mode": "OBSERVE", "adapter_revision": "invalid" }));
    }
    if route.response_crypto.is_some() || !route.response_mode.is_empty() {
        let mode = if route.response_mode.is_empty() {
            "BUFFERED_JSON"
        } else {
            route.response_mode.as_str()
        };
        let mut response = json!({ "mode": mode, "max_bytes": route.max_response_bytes });
        if let Some(crypto) = &route.response_crypto {
            response["crypto"] = serde_json::to_value(crypto).unwrap_or_else(|_| json!({}));
        }
        operation["response"] = response;
    }
    operation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SiteConfig {
        SiteConfig {
            display_name: "Demo".to_owned(),
            public_origin: "https://demo.example.test".to_owned(),
            upstream_address: "8.8.8.8:9000".to_owned(),
            upstream_server_name: "origin.example.test".to_owned(),
            upstream_tls: false,
            listen_port: 0,
            entry_path: "/".to_owned(),
            security_entry: "ui_action_required".to_owned(),
            sensor_enabled: false,
            policy_revision: "policy-v1".to_owned(),
            status: "active".to_owned(),
            policy: SitePolicyConfig::default(),
        }
    }

    fn site(value: &str) -> SiteId {
        SiteId::parse(value).unwrap()
    }

    #[test]
    fn public_origins_are_https_or_literal_loopback_http_without_ipv6() {
        for origin in [
            "https://demo.example.test",
            "https://demo.example.test:8443",
            "https://Demo.Example.Test",
            "http://localhost",
            "http://localhost:8080",
            "http://localhost:8080/",
            "http://127.0.0.1:8080",
            "http://127.0.0.2:8080",
        ] {
            assert!(validate_public_origin(origin, false).is_ok(), "{origin}");
        }
        for origin in [
            "",
            "demo.example.test",
            "ftp://demo.example.test",
            "http://demo.example.test",
            "https://demo.example.test/",
            "https://demo.example.test/path",
            "https://demo.example.test?x=1",
            "https://user@demo.example.test",
            "https://demo_example.test",
            "https://-demo.example.test",
            "https://demo..example.test",
            "https://demo.example.test:0",
            "https://demo.example.test:99999",
            "https://demo.example.test:",
            // The edge routes by host name and cannot route bracketed IPv6.
            "https://[::1]",
            "http://[::1]:8080",
        ] {
            assert!(validate_public_origin(origin, false).is_err(), "{origin:?}");
        }
        // The sensor only knows the two literal loopback names.
        assert!(validate_public_origin("http://localhost:8080", true).is_ok());
        assert!(validate_public_origin("http://127.0.0.1:8080", true).is_ok());
        assert!(validate_public_origin("http://127.0.0.2:8080", true).is_err());
        assert!(validate_public_origin("https://demo.example.test", true).is_ok());
    }

    #[test]
    fn site_identifiers_must_fit_the_edge_audit_producer_name() {
        let longest = "s".repeat(AUDIT_PRODUCER_MAX_BYTES - AUDIT_PRODUCER_PREFIX.len());
        assert!(config().validate_for_site(&site(&longest)).is_ok());
        let too_long = "s".repeat(AUDIT_PRODUCER_MAX_BYTES - AUDIT_PRODUCER_PREFIX.len() + 1);
        let error = config().validate_for_site(&site(&too_long)).unwrap_err();
        assert_eq!(error.field(), "site_id");
    }

    #[test]
    fn identity_store_stays_inside_the_edge_capacity_model_for_every_ttl() {
        for ttl in [1_u64, 59, 60, 61, 3_600, 5_940, 5_941, 43_200, 86_400] {
            let store = identity_store(ttl);
            let per_site = store["max_anonymous_session_creations_per_site"]
                .as_u64()
                .unwrap();
            let per_source = store["max_anonymous_session_creations_per_source"]
                .as_u64()
                .unwrap();
            let active = store["max_active_anonymous_sessions"].as_u64().unwrap();
            let windows = ttl.div_ceil(60) + 1;
            assert!(per_site * windows <= active, "ttl {ttl}");
            assert!(per_source >= 1 && per_source <= per_site, "ttl {ttl}");
        }
        // TTLs that already fit keep the original, unreduced rates.
        let default = identity_store(3_600);
        assert_eq!(default["max_anonymous_session_creations_per_site"], 1_000);
        assert_eq!(default["max_anonymous_session_creations_per_source"], 10);
    }

    #[test]
    fn identity_store_follows_the_effective_routes_not_only_the_entry_mode() {
        let mut config = config();
        config.security_entry = "public".to_owned();
        config.policy.routes = vec![SiteRouteConfig {
            security_entry: SecurityEntry::AuthenticatedRoot,
            source_action: None,
            ..config.effective_policy().routes[0].clone()
        }];
        let projection = config.gateway_config("tenant_a", &site("site_a"));
        assert!(projection.get("identity_store").is_some());
        let public_only = SiteConfig {
            security_entry: "public".to_owned(),
            policy: SitePolicyConfig {
                routes: vec![SiteRouteConfig {
                    security_entry: SecurityEntry::Public,
                    source_action: None,
                    ..config.effective_policy().routes[0].clone()
                }],
                ..SitePolicyConfig::default()
            },
            ..config
        };
        let projection = public_only.gateway_config("tenant_a", &site("site_a"));
        assert!(projection.get("identity_store").is_none());
    }

    #[test]
    fn effective_policy_adds_the_entry_route_only_when_no_route_is_configured() {
        let config = config();
        let effective = config.effective_policy();
        assert_eq!(effective.routes.len(), 1);
        assert_eq!(effective.routes[0].operation_id, "protected.entry");
        assert_eq!(effective.routes[0].path, "/");
        assert_eq!(
            effective.routes[0].source_action.as_deref(),
            Some("protected.entry")
        );
        let mut explicit = config;
        explicit.policy.routes = effective.routes;
        explicit.policy.routes[0].operation_id = "home".to_owned();
        assert_eq!(explicit.effective_policy().routes.len(), 1);
        assert_eq!(explicit.effective_policy().routes[0].operation_id, "home");
    }

    #[test]
    fn stored_json_round_trips_and_rejects_unknown_fields() {
        let config = config();
        let value = serde_json::to_value(&config).unwrap();
        assert_eq!(serde_json::from_value::<SiteConfig>(value).unwrap(), config);
        let mut tampered = serde_json::to_value(&config).unwrap();
        tampered["unexpected"] = json!(true);
        assert!(serde_json::from_value::<SiteConfig>(tampered).is_err());
    }
}
