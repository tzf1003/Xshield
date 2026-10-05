//! Typed configuration of one protected site and its projection to the edge.
//!
//! The control plane stores, diffs, validates and publishes this value; the
//! edge compiles the JSON projection produced by [`SiteConfig::gateway_config`].
//! Keeping the value, its validation and the projection in this pure module is
//! what lets a gateway-side test feed the *same* projection through the edge
//! compiler and fail the build when control-side validation drifts from it.

use super::{
    RouteOperation, SecurityEntry, SitePolicyConfig, SiteRouteConfig, UpstreamEndpoint,
    flow::SENSOR_HTML_INVALID,
    projection::{self, EDGE_MAX_CONFIG_BYTES},
    route_path_is_edge_compilable,
};
use crate::domain::{InvalidValue, SiteId};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Prefix of the audit producer identity the edge derives for a site; the edge
/// caps the whole identity at 128 bytes.
const AUDIT_PRODUCER_PREFIX: &str = "edge-";
const AUDIT_PRODUCER_MAX_BYTES: usize = 128;
/// Length of the longest tenant identifier (`TenantId`), used to bound the
/// projection size before the tenant is known.
const MAX_TENANT_ID_BYTES: usize = 128;

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
                auth_binding: None,
                auth_revoke: None,
                sensor_html: None,
                page_actions: None,
                issued_by: None,
                resource_grant: None,
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
        let policy = self.effective_policy();
        policy.validate()?;
        // The edge only injects into pages when the site projects a sensor
        // block, which it does exactly when the sensor is enabled.
        if !self.sensor_enabled
            && policy
                .routes
                .iter()
                .any(|route| route.response_mode == "SENSOR_HTML")
        {
            return Err(InvalidValue::new(SENSOR_HTML_INVALID));
        }
        Ok(())
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
    /// cannot use, `site_policy.size` when the projection would exceed the
    /// edge's configuration size limit, otherwise the error of
    /// [`SiteConfig::validate`].
    pub fn validate_for_site(&self, site_id: &SiteId) -> Result<(), InvalidValue> {
        if AUDIT_PRODUCER_PREFIX.len() + site_id.as_str().len() > AUDIT_PRODUCER_MAX_BYTES {
            return Err(InvalidValue::new("site_id"));
        }
        self.validate()?;
        // The edge refuses a site configuration above its size limit, which
        // would fail every site of the tenant. The tenant only appears once
        // in the projection, so projecting with the longest possible tenant
        // identifier bounds the real size from above.
        let longest_tenant = "t".repeat(MAX_TENANT_ID_BYTES);
        let projected = serde_json::to_vec(&self.gateway_config(&longest_tenant, site_id)?)
            .map_err(|_| InvalidValue::new("gateway_config"))?;
        if projected.len() > EDGE_MAX_CONFIG_BYTES {
            return Err(InvalidValue::new("site_policy.size"));
        }
        Ok(())
    }

    /// Projects the configuration to the strict JSON the edge compiler
    /// consumes for one site.
    ///
    /// The projection never validates, drops or defaults anything (see
    /// the `projection` module); callers publish only configurations that
    /// passed [`SiteConfig::validate_for_site`], or that the edge already
    /// accepted.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] named `gateway_config` when the projection
    /// cannot be serialized; nothing partial is ever returned.
    pub fn gateway_config(
        &self,
        tenant_id: &str,
        site_id: &SiteId,
    ) -> Result<serde_json::Value, InvalidValue> {
        projection::gateway_config(self, tenant_id, site_id)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn identity_store_follows_the_effective_routes_not_only_the_entry_mode() {
        let mut config = config();
        config.security_entry = "public".to_owned();
        config.policy.routes = vec![SiteRouteConfig {
            security_entry: SecurityEntry::AuthenticatedRoot,
            source_action: None,
            ..config.effective_policy().routes[0].clone()
        }];
        let projection = config.gateway_config("tenant_a", &site("site_a")).unwrap();
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
        let projection = public_only
            .gateway_config("tenant_a", &site("site_a"))
            .unwrap();
        assert!(projection.get("identity_store").is_none());
    }

    /// The control-plane spelling of the real-browser loop
    /// (`scripts/test_browser_loop.sh`), shared with the gateway golden test,
    /// the control-plane apply test and the console round-trip test.
    const BROWSER_LOOP: &str = include_str!("../../../../tests/site-config/browser-loop.json");
    /// Its projection for `tenant_loop`/`site_loop`, without `site_policy`.
    const BROWSER_LOOP_GATEWAY: &str =
        include_str!("../../../../tests/site-config/browser-loop.gateway.json");
    /// A stored configuration exactly as written before the flow fields.
    const PRE_FLOW: &str = include_str!("../../../../tests/site-config/pre-flow.json");

    fn browser_loop() -> SiteConfig {
        serde_json::from_str(BROWSER_LOOP).unwrap()
    }

    #[test]
    fn the_browser_loop_fixture_is_the_canonical_stored_form_and_valid() {
        let config = browser_loop();
        // Byte equality pins the field order and the omission of unset
        // blocks, which the console round-trip test relies on as well.
        assert_eq!(
            serde_json::to_string_pretty(&config).unwrap(),
            BROWSER_LOOP.trim_end()
        );
        config.validate_for_site(&site("site_loop")).unwrap();
    }

    #[test]
    fn the_browser_loop_projects_to_the_golden_edge_configuration() {
        let config = browser_loop();
        let mut projection = config
            .gateway_config("tenant_loop", &site("site_loop"))
            .unwrap();
        let site_policy = projection
            .as_object_mut()
            .unwrap()
            .remove("site_policy")
            .unwrap();
        assert_eq!(site_policy, serde_json::to_value(&config.policy).unwrap());
        let golden: serde_json::Value = serde_json::from_str(BROWSER_LOOP_GATEWAY).unwrap();
        assert_eq!(projection, golden);
    }

    /// Optional flow blocks are omitted when unset, so a configuration stored
    /// before they existed re-serializes to the same bytes: its stored digest,
    /// idempotent replays and "same content" comparisons all stay stable.
    #[test]
    fn configurations_written_before_the_flow_fields_keep_their_bytes() {
        let config: SiteConfig = serde_json::from_str(PRE_FLOW).unwrap();
        assert_eq!(serde_json::to_string(&config).unwrap(), PRE_FLOW.trim_end());
        config.validate().unwrap();
    }

    #[test]
    fn a_sensor_page_needs_the_sensor() {
        let mut config = browser_loop();
        config.sensor_enabled = false;
        assert_eq!(
            config.validate().unwrap_err().field(),
            crate::site::flow::SENSOR_HTML_INVALID
        );
    }

    /// The edge refuses a site configuration above 1 MiB, which would fail
    /// every site of the tenant; the projection size is checked up front.
    #[test]
    fn a_projection_the_edge_would_refuse_for_its_size_is_rejected() {
        let pages = |count: usize| {
            let mut config = config();
            config.sensor_enabled = true;
            config.security_entry = "public".to_owned();
            config.policy.routes = (0..count)
                .map(|index| {
                    let digest = |build: usize| format!("{:064x}", index * 100 + build);
                    let revision = |build: usize| format!("{build:x}{}", "r".repeat(126));
                    let mut route = config.effective_policy().routes[0].clone();
                    route.operation_id = format!("page.{index}");
                    route.path = format!("/p{index}");
                    route.security_entry = SecurityEntry::Public;
                    route.source_action = None;
                    route.response_mode = "SENSOR_HTML".to_owned();
                    route.sensor_html = Some(crate::site::SiteSensorHtml {
                        adapter_revision: revision(0),
                        origin_sha256: digest(0),
                        injection_offset: 10,
                        additional_adapters: (1..16)
                            .map(|build| crate::site::SiteSensorHtmlAdapter {
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
        let fits = pages(64);
        fits.validate_for_site(&site("site_a")).unwrap();
        let too_large = pages(200);
        too_large.validate().unwrap();
        assert_eq!(
            too_large
                .validate_for_site(&site("site_a"))
                .unwrap_err()
                .field(),
            "site_policy.size"
        );
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
