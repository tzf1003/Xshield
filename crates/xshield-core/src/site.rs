//! Validated control-plane values shared by site management and edge apply.
#![allow(missing_docs)]

use crate::domain::{
    ActionId, FieldName, InvalidValue, OperationId, ResourceType, SiteId, TenantId, ViewProfile,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod config;
pub mod flow;
mod projection;
pub mod risk;
pub mod unsupported;
pub mod upstream;

pub use config::SiteConfig;
pub use flow::{
    SiteAuthBinding, SiteAuthRevoke, SiteIssuedBy, SitePageActions, SiteResourceGrant,
    SiteSensorHtml, SiteSensorHtmlAdapter,
};
pub use projection::{EDGE_MAX_CONFIG_BYTES, gateway_operation};
pub use risk::{ChangeRisk, assess_change_risk, direct_apply_may_waive};
pub use unsupported::{UnsupportedEdgeFeature, find_unsupported_edge_feature};

/// An internal edge listener port.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PortNumber(u16);

impl PortNumber {
    /// Creates a private listener port in the configured edge pool.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] outside the internal listener pool.
    pub fn parse(value: u16) -> Result<Self, InvalidValue> {
        (6100..=65535)
            .contains(&value)
            .then_some(Self(value))
            .ok_or_else(|| InvalidValue::new("listen_port"))
    }

    /// Returns the numeric port.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A public HTTPS origin with no query or fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicOrigin(String);

impl PublicOrigin {
    /// Validates an origin boundary without resolving network names.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for non-HTTPS, malformed, or ambiguous origins.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidValue> {
        let value = value.into();
        let Some((scheme, authority)) = value.split_once("://") else {
            return Err(InvalidValue::new("public_origin"));
        };
        if scheme != "https" || authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
            return Err(InvalidValue::new("public_origin"));
        }
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let Some((host, suffix)) = rest.split_once(']') else {
                return Err(InvalidValue::new("public_origin"));
            };
            if !suffix.is_empty() && !suffix.starts_with(':') {
                return Err(InvalidValue::new("public_origin"));
            }
            (host, suffix.strip_prefix(':'))
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if host.contains(':') {
                return Err(InvalidValue::new("public_origin"));
            }
            (host, Some(port))
        } else {
            (authority, None)
        };
        let valid_ip = host.parse::<std::net::IpAddr>().is_ok();
        if host.is_empty()
            || (!valid_ip
                && (host.len() > 253
                    || host.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    })))
            || port
                .is_some_and(|port| port.is_empty() || port.parse::<u16>().is_err() || port == "0")
        {
            return Err(InvalidValue::new("public_origin"));
        }
        Ok(Self(value))
    }

    /// Returns the exact validated origin.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An approved upstream address and SNI name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamEndpoint {
    address: String,
    server_name: String,
    tls: bool,
}

impl UpstreamEndpoint {
    /// Validates a host:port endpoint and TLS server name.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for malformed addresses or server names.
    pub fn parse(
        address: impl Into<String>,
        server_name: impl Into<String>,
        tls: bool,
    ) -> Result<Self, InvalidValue> {
        let address = address.into();
        let server_name = server_name.into();
        let (host, port) = if let Some(rest) = address.strip_prefix('[') {
            let Some((host, suffix)) = rest.split_once(']') else {
                return Err(InvalidValue::new("upstream_address"));
            };
            if !suffix.is_empty() && !suffix.starts_with(':') {
                return Err(InvalidValue::new("upstream_address"));
            }
            (host, suffix.strip_prefix(':'))
        } else if let Some((host, port)) = address.rsplit_once(':') {
            if host.contains(':') {
                return Err(InvalidValue::new("upstream_address"));
            }
            (host, Some(port))
        } else {
            (address.as_str(), None)
        };
        let Some(port) = port else {
            return Err(InvalidValue::new("upstream_address"));
        };
        if host.is_empty()
            || port.is_empty()
            || port.parse::<u16>().is_err()
            || port == "0"
            || host
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || server_name.is_empty()
            || server_name.len() > 253
            || server_name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(InvalidValue::new("upstream_endpoint"));
        }
        Ok(Self {
            address,
            server_name,
            tls,
        })
    }

    /// Returns the approved address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
    /// Returns the approved SNI name.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
    /// Returns whether upstream TLS is required.
    #[must_use]
    pub const fn tls(&self) -> bool {
        self.tls
    }
}

/// Deterministic security entry mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEntry {
    /// No identity gate.
    Public,
    /// An approved authentication entry (edge `AUTH_ENTRY`): admitted without
    /// identity, and with an `auth_binding` the only route that may establish
    /// one. A route-level admission only; the top-level site entry is never
    /// `auth_entry`.
    AuthEntry,
    /// A valid authenticated root is required.
    AuthenticatedRoot,
    /// A valid UI operation source is required.
    UiActionRequired,
}

/// A route-level request encryption policy accepted by the site compiler.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SiteRequestCrypto {
    /// Decrypts a bounded request envelope with a deployment-managed key.
    DirectDecrypt {
        adapter_revision: String,
        key_id: String,
        key_not_before: u64,
        key_expires_at: u64,
        max_envelope_bytes: usize,
        max_plaintext_bytes: usize,
        max_message_age_seconds: u64,
        max_future_skew_seconds: u64,
        max_active_messages: u32,
    },
    /// Records an opaque envelope without changing its bytes.
    Observe { adapter_revision: String },
}

/// A route-level response encryption policy accepted by the site compiler.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteResponseCrypto {
    #[serde(default = "default_response_crypto_mode")]
    pub mode: String,
    pub adapter_revision: String,
    pub key_id: String,
    pub key_not_before: u64,
    pub key_expires_at: u64,
    pub message_ttl_seconds: u64,
    pub max_envelope_bytes: usize,
}

fn default_response_crypto_mode() -> String {
    "DIRECT_ENCRYPT".to_owned()
}

/// One complete operation entry configured for a protected site.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteRouteConfig {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub security_entry: SecurityEntry,
    #[serde(default)]
    pub source_action: Option<String>,
    #[serde(default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub view_profile: Option<String>,
    #[serde(default)]
    pub resource_query_parameter: Option<String>,
    #[serde(default)]
    pub resource_path_parameter: Option<String>,
    #[serde(default)]
    pub request_crypto: Option<SiteRequestCrypto>,
    #[serde(default)]
    pub response_crypto: Option<SiteResponseCrypto>,
    #[serde(default = "default_route_response_mode")]
    pub response_mode: String,
    #[serde(default = "default_route_max_response_bytes")]
    pub max_response_bytes: usize,
    // The provenance-flow blocks below are absent from every configuration
    // written before they existed. They are skipped when unset so such a
    // configuration re-serializes byte for byte, which keeps its stored
    // digest, idempotency replays and "same content" comparisons stable.
    /// Identity establishment; only on an `auth_entry` route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_binding: Option<flow::SiteAuthBinding>,
    /// Binding revocation; only on an `authenticated_root` route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_revoke: Option<flow::SiteAuthRevoke>,
    /// Approved builds; present exactly when `response_mode` is `SENSOR_HTML`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor_html: Option<flow::SiteSensorHtml>,
    /// Page issuance settings; only on a `SENSOR_HTML` page root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_actions: Option<flow::SitePageActions>,
    /// The page root that issues this first-hop UI action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_by: Option<flow::SiteIssuedBy>,
    /// Response-derived resource qualification for one resource route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_grant: Option<flow::SiteResourceGrant>,
}

impl SiteRouteConfig {
    /// Whether releasing this route's response commits an edge side effect
    /// (encryption, identity change or resource qualification); the edge
    /// refuses to merely observe the request body of such a route.
    #[must_use]
    pub const fn response_has_side_effects(&self) -> bool {
        self.response_crypto.is_some()
            || self.resource_grant.is_some()
            || self.auth_binding.is_some()
            || self.auth_revoke.is_some()
    }
}

fn default_route_response_mode() -> String {
    String::new()
}

const fn default_route_max_response_bytes() -> usize {
    1_048_576
}

/// Identity binding settings for authenticated and UI sourced entries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteIdentityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_credential_header")]
    pub credential_header: String,
    #[serde(default = "default_identity_profile")]
    pub profile: String,
    #[serde(default = "default_session_ttl_seconds")]
    pub session_ttl_seconds: u64,
    #[serde(default = "default_identity_generation")]
    pub generation: u64,
}

fn default_cookie_name() -> String {
    "__Host-xshield_sid".to_owned()
}

fn default_credential_header() -> String {
    "Authorization".to_owned()
}

fn default_identity_profile() -> String {
    "default".to_owned()
}

const fn default_session_ttl_seconds() -> u64 {
    3_600
}

const fn default_identity_generation() -> u64 {
    1
}

/// Request/response adapter metadata for a site.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteCryptoConfig {
    #[serde(default = "default_crypto_adapter")]
    pub adapter_revision: String,
    #[serde(default = "default_crypto_failure_strategy")]
    pub failure_strategy: String,
    #[serde(default)]
    pub protocol_version: Option<String>,
}

fn default_crypto_adapter() -> String {
    "observe-v1".to_owned()
}

fn default_crypto_failure_strategy() -> String {
    "fail_closed".to_owned()
}

/// Basic deterministic WAF rules for a site.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteWafConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub blocked_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_query_fragments: Vec<String>,
    #[serde(default)]
    pub max_cookie_bytes: u32,
}

/// Site-wide request and response limits.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteLimitsConfig {
    #[serde(default = "default_request_limit")]
    pub max_request_body_bytes: usize,
    #[serde(default = "default_response_limit")]
    pub max_response_body_bytes: usize,
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
}

const fn default_request_limit() -> usize {
    1_048_576
}

const fn default_response_limit() -> usize {
    16_777_216
}

const fn default_requests_per_second() -> u32 {
    1_000
}

const fn default_burst() -> u32 {
    2_000
}

/// Upstream health probe settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteHealthCheckConfig {
    #[serde(default = "default_health_path")]
    pub path: String,
    #[serde(default = "default_health_interval")]
    pub interval_seconds: u32,
    #[serde(default = "default_health_timeout")]
    pub timeout_ms: u32,
    #[serde(default = "default_health_status")]
    pub expected_status: u16,
}

fn default_health_path() -> String {
    "/health".to_owned()
}

const fn default_health_interval() -> u32 {
    15
}

const fn default_health_timeout() -> u32 {
    2_000
}

const fn default_health_status() -> u16 {
    200
}

/// Reference to a deployment-managed secret. The secret value never crosses
/// the control-plane API or enters a gateway snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteSecretReference {
    pub kind: String,
    pub secret_ref: String,
    pub key_id: String,
    #[serde(default = "default_secret_state")]
    pub state: String,
}

fn default_secret_state() -> String {
    String::new()
}

/// Complete typed policy surface for one protected site.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SitePolicyConfig {
    #[serde(default)]
    pub routes: Vec<SiteRouteConfig>,
    #[serde(default)]
    pub identity: SiteIdentityConfig,
    #[serde(default)]
    pub crypto: SiteCryptoConfig,
    #[serde(default)]
    pub waf: SiteWafConfig,
    #[serde(default)]
    pub limits: SiteLimitsConfig,
    #[serde(default)]
    pub health_check: SiteHealthCheckConfig,
    #[serde(default)]
    pub secret_refs: Vec<SiteSecretReference>,
    /// Maximum path depth for the opt-in public static-asset fallback
    /// (JavaScript, CSS, fonts and images). The fallback admits requests with
    /// no identity and no exact operation, so it is off unless a site asks for
    /// it: zero, and an omitted field, disable it. See
    /// [`SitePolicyConfig::allows_static_asset`] for what it can match.
    #[serde(default = "default_static_asset_max_path_depth")]
    pub static_asset_max_path_depth: u8,
    /// Requests forwarded through the edge may ask a compatible origin to
    /// enforce object ownership before returning or mutating a resource.
    #[serde(default)]
    pub origin_object_access_enforced: bool,
}

impl Default for SitePolicyConfig {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            identity: SiteIdentityConfig::default(),
            crypto: SiteCryptoConfig::default(),
            waf: SiteWafConfig::default(),
            limits: SiteLimitsConfig::default(),
            health_check: SiteHealthCheckConfig::default(),
            secret_refs: Vec::new(),
            static_asset_max_path_depth: default_static_asset_max_path_depth(),
            origin_object_access_enforced: false,
        }
    }
}

const fn default_static_asset_max_path_depth() -> u8 {
    0
}

impl Default for SiteIdentityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cookie_name: "__Host-xshield_sid".to_owned(),
            credential_header: "Authorization".to_owned(),
            profile: "default".to_owned(),
            session_ttl_seconds: 3_600,
            generation: 1,
        }
    }
}

impl Default for SiteCryptoConfig {
    fn default() -> Self {
        Self {
            adapter_revision: "observe-v1".to_owned(),
            failure_strategy: "fail_closed".to_owned(),
            protocol_version: None,
        }
    }
}

impl Default for SiteWafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            blocked_headers: Vec::new(),
            blocked_query_fragments: Vec::new(),
            max_cookie_bytes: 8_192,
        }
    }
}

impl Default for SiteLimitsConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: default_request_limit(),
            max_response_body_bytes: default_response_limit(),
            requests_per_second: default_requests_per_second(),
            burst: default_burst(),
        }
    }
}

impl Default for SiteHealthCheckConfig {
    fn default() -> Self {
        Self {
            path: "/health".to_owned(),
            interval_seconds: default_health_interval(),
            timeout_ms: default_health_timeout(),
            expected_status: default_health_status(),
        }
    }
}

impl Default for SiteSecretReference {
    fn default() -> Self {
        Self {
            kind: "session_hmac".to_owned(),
            secret_ref: "secret://unset".to_owned(),
            key_id: "unset".to_owned(),
            state: "unavailable".to_owned(),
        }
    }
}

impl SitePolicyConfig {
    /// Validates bounds and route ambiguity before persistence or edge apply.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] when a route, identity, limit, health, WAF or
    /// secret reference violates the bounded policy contract.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), InvalidValue> {
        if self.routes.len() > 256
            || self.identity.session_ttl_seconds == 0
            || self.identity.session_ttl_seconds > 86_400
            || self.identity.generation == 0
            || self.identity.cookie_name != "__Host-xshield_sid"
            || self.identity.credential_header != "Authorization"
            || self.identity.profile.is_empty()
            || self.identity.cookie_name.len() > 128
            || self.identity.credential_header.len() > 128
            || self.identity.profile.len() > 128
            || self.limits.max_request_body_bytes == 0
            || self.limits.max_request_body_bytes > 16 * 1024 * 1024
            || self.limits.max_response_body_bytes == 0
            || self.limits.max_response_body_bytes > 16 * 1024 * 1024
            || self.limits.requests_per_second == 0
            || self.limits.requests_per_second > 1_000_000
            || self.limits.burst < self.limits.requests_per_second
            || self.limits.burst > 2_000_000
            || self.health_check.path.is_empty()
            || !self.health_check.path.starts_with('/')
            || self.health_check.path.contains(['?', '#'])
            || self
                .health_check
                .path
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\')
            || self
                .health_check
                .path
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
            || !(1..=3_600).contains(&self.health_check.interval_seconds)
            || !(100..=30_000).contains(&self.health_check.timeout_ms)
            || !(100..=599).contains(&self.health_check.expected_status)
            || self.waf.max_cookie_bytes == 0
            || self.waf.max_cookie_bytes > 1_048_576
            || self.secret_refs.len() > 32
            || self.static_asset_max_path_depth > 16
        {
            return Err(InvalidValue::new("site_policy"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut operation_ids = std::collections::BTreeSet::new();
        for route_config in &self.routes {
            let validation_path = validate_site_route_path(route_config)?;
            let route = RouteOperation::new(
                route_config.operation_id.clone(),
                route_config.method.clone(),
                validation_path,
                route_config.security_entry,
            )?;
            // The edge parses every operation ID as an `OperationId`, whose
            // alphabet has no `:`; `RouteOperation` alone would admit one and
            // fail the whole tenant snapshot at apply time.
            OperationId::parse(route_config.operation_id.clone())
                .map_err(|_| InvalidValue::new("site_policy.route"))?;
            let key = (route_config.method.clone(), route_config.path.clone());
            if !seen.insert(key) {
                return Err(InvalidValue::new("site_policy.routes"));
            }
            if !operation_ids.insert(route.operation_id().to_owned()) {
                return Err(InvalidValue::new("site_policy.routes"));
            }
            if (route_config.security_entry == SecurityEntry::UiActionRequired)
                != route_config.source_action.is_some()
            {
                return Err(InvalidValue::new("site_policy.route"));
            }
            if let Some(source_action) = route_config.source_action.as_ref() {
                ActionId::parse(source_action.clone())
                    .map_err(|_| InvalidValue::new("site_policy.route"))?;
            }
            let has_resource_fields = route_config.resource_type.is_some()
                || route_config.view_profile.is_some()
                || route_config.resource_query_parameter.is_some()
                || route_config.resource_path_parameter.is_some();
            if has_resource_fields {
                if route_config.method != "GET"
                    || route_config.security_entry != SecurityEntry::UiActionRequired
                    || route_config.resource_type.is_none()
                    || route_config.view_profile.is_none()
                    || (route_config.resource_query_parameter.is_some()
                        == route_config.resource_path_parameter.is_some())
                {
                    return Err(InvalidValue::new("site_policy.route"));
                }
                ResourceType::parse(
                    route_config
                        .resource_type
                        .clone()
                        .ok_or_else(|| InvalidValue::new("site_policy.route"))?,
                )
                .map_err(|_| InvalidValue::new("site_policy.route"))?;
                ViewProfile::parse(
                    route_config
                        .view_profile
                        .clone()
                        .ok_or_else(|| InvalidValue::new("site_policy.route"))?,
                )
                .map_err(|_| InvalidValue::new("site_policy.route"))?;
                if let Some(parameter) = route_config.resource_query_parameter.as_ref() {
                    FieldName::parse(parameter.clone())
                        .map_err(|_| InvalidValue::new("site_policy.route"))?;
                }
                if let Some(parameter) = route_config.resource_path_parameter.as_ref() {
                    FieldName::parse(parameter.clone())
                        .map_err(|_| InvalidValue::new("site_policy.route"))?;
                }
            }
            if !route_field_bounds_hold(route_config, &self.limits)
                || !route_response_contract_holds(route_config)
                || !route_request_crypto_contract_holds(route_config, &self.limits)
            {
                return Err(InvalidValue::new("site_policy.route"));
            }
            flow::validate_route(route_config)?;
        }
        validate_route_set(&self.routes)?;
        flow::validate_route_set(&self.routes)?;
        if self.waf.blocked_headers.len() > 64
            || self.waf.blocked_headers.iter().any(|header| {
                header.is_empty()
                    || header.len() > 128
                    || !header
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
            || self
                .waf
                .blocked_headers
                .iter()
                .map(|header| header.to_ascii_lowercase())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.waf.blocked_headers.len()
            || self.waf.blocked_query_fragments.len() > 32
            || self.waf.blocked_query_fragments.iter().any(|fragment| {
                fragment.len() < 3
                    || fragment.len() > 128
                    || !fragment.is_ascii()
                    || fragment.bytes().any(|byte| byte.is_ascii_control())
            })
            || self
                .waf
                .blocked_query_fragments
                .iter()
                .map(|fragment| fragment.to_ascii_lowercase())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.waf.blocked_query_fragments.len()
            || !matches!(
                self.crypto.failure_strategy.as_str(),
                "fail_closed" | "observe"
            )
            || self.crypto.adapter_revision.is_empty()
            || self.crypto.adapter_revision.len() > 128
        {
            return Err(InvalidValue::new("site_policy"));
        }
        let mut secret_kinds = std::collections::BTreeSet::new();
        for secret in &self.secret_refs {
            if !matches!(
                secret.kind.as_str(),
                "tls" | "session_hmac" | "request_crypto" | "response_crypto" | "model"
            ) || !matches!(
                secret.state.as_str(),
                "active" | "pending_rotation" | "retired" | "unavailable"
            ) || !secret.secret_ref.starts_with("secret://")
                || secret.secret_ref.len() == "secret://".len()
                || secret.secret_ref.len() > 512
                || secret
                    .secret_ref
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
                || secret.key_id.is_empty()
                || secret.key_id.len() > 128
                || secret
                    .key_id
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
                || !secret_kinds.insert(secret.kind.as_str())
            {
                return Err(InvalidValue::new("site_policy.secret_refs"));
            }
        }
        Ok(())
    }

    /// Returns whether a public GET may use the opt-in static-asset fallback.
    ///
    /// The fallback exists for hashed bundle and font names that cannot be
    /// listed route by route, and it is deliberately narrow because it admits a
    /// request without identity or an exact operation:
    ///
    /// * the site must opt in with a non-zero `static_asset_max_path_depth`,
    ///   which also bounds how many path segments may be matched;
    /// * the path is percent-decoded once, strictly, and the decoded text is
    ///   what is judged, since that is what an origin will route; anything an
    ///   origin could read as structure rather than a file name is refused:
    ///   `;` (path parameters such as `/admin/users;.js`), `\`, encoded
    ///   slashes, dot and empty segments, controls, `?`, `#`, a decoded `%`
    ///   (double encoding), spaces and non-ASCII bytes;
    /// * the last segment needs a real dot, a non-empty stem and an extension
    ///   from [`STATIC_ASSET_EXTENSIONS`], so `/api/json` or `/css` can never
    ///   pass for a `.json` or `.css` file.
    ///
    /// `.json` and `.map` are not in the list: they are how APIs and source
    /// maps are routinely spelled, so admitting them would let anyone name an
    /// API response as an asset. Such files need an explicit route.
    #[must_use]
    pub fn allows_static_asset(&self, method: &str, path: &str) -> bool {
        if method != "GET" || self.static_asset_max_path_depth == 0 {
            return false;
        }
        let Some(decoded) = decode_static_asset_path(path) else {
            return false;
        };
        let mut depth = 0_usize;
        let mut name = "";
        for segment in decoded[1..].split('/') {
            if matches!(segment, "" | "." | "..") {
                return false;
            }
            depth += 1;
            name = segment;
        }
        if depth > usize::from(self.static_asset_max_path_depth) {
            return false;
        }
        let Some((stem, extension)) = name.rsplit_once('.') else {
            return false;
        };
        !stem.is_empty()
            && STATIC_ASSET_EXTENSIONS
                .iter()
                .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    }
}

/// Namespace the edge serves itself (sensor assets, bootstrap, preparation).
const EDGE_INTERNAL_PATH_PREFIX: &str = "/__xshield/";
/// The edge compiles at most this many `{parameter}` routes per site
/// (`MAX_PATH_RESOURCE_OPERATIONS` in the gateway); pinned by the gateway
/// parity test.
pub const EDGE_MAX_PATH_RESOURCE_ROUTES: usize = 64;
/// Gateway `MAX_BUFFERED_JSON_BYTES`.
const EDGE_MAX_BUFFERED_JSON_BYTES: usize = 16 * 1024 * 1024;
/// Gateway `MAX_ENCRYPTED_RESPONSE_ENVELOPE_BYTES`.
const EDGE_MAX_ENCRYPTED_RESPONSE_ENVELOPE_BYTES: usize = EDGE_MAX_BUFFERED_JSON_BYTES * 2 + 4096;
/// Gateway `MAX_ENCRYPTED_REQUEST_ENVELOPE_BYTES`.
const EDGE_MAX_ENCRYPTED_REQUEST_ENVELOPE_BYTES: usize = 64 * 1024;
/// Gateway `MAX_BUFFERED_BODY_IN_FLIGHT_BYTES`.
const EDGE_MAX_BUFFERED_BODY_IN_FLIGHT_BYTES: usize =
    EDGE_MAX_BUFFERED_JSON_BYTES * 2 + EDGE_MAX_ENCRYPTED_RESPONSE_ENVELOPE_BYTES + 4096 + 16;

/// Whether the edge compiler accepts `path` as a route template: printable
/// ASCII only (no space, control byte, DEL or non-ASCII), no query or fragment
/// text, and outside the namespace the edge serves itself.
pub(crate) fn route_path_is_edge_compilable(path: &str) -> bool {
    path.starts_with('/')
        && path.bytes().all(|byte| byte.is_ascii_graphic())
        && !path.contains(['?', '#'])
        && !path.starts_with(EDGE_INTERNAL_PATH_PREFIX)
}

/// Scoped identifiers (adapter revisions, key ids) as the edge reads them.
fn edge_scoped_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn route_field_bounds_hold(route: &SiteRouteConfig, limits: &SiteLimitsConfig) -> bool {
    [
        &route.source_action,
        &route.resource_type,
        &route.view_profile,
        &route.resource_query_parameter,
        &route.resource_path_parameter,
    ]
    .iter()
    .all(|value| value.as_ref().is_none_or(|value| value.len() <= 128))
        && route.max_response_bytes != 0
        && route.max_response_bytes <= limits.max_response_body_bytes
}

/// Response handling the edge can compile from what a route can express.
fn route_response_contract_holds(route: &SiteRouteConfig) -> bool {
    // `SENSOR_HTML` carries its adapter in `sensor_html`; whether the two
    // agree, and every adapter rule, is checked by `flow::validate_route`.
    if !matches!(
        route.response_mode.as_str(),
        "" | "BUFFERED_JSON" | "SENSOR_HTML"
    ) || route.max_response_bytes > EDGE_MAX_BUFFERED_JSON_BYTES
    {
        return false;
    }
    route.response_crypto.as_ref().is_none_or(|crypto| {
        // The envelope must hold twice the plaintext plus fixed overhead.
        let minimum_envelope = route
            .max_response_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(1_024));
        let in_flight = route
            .max_response_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(crypto.max_envelope_bytes))
            .and_then(|bytes| bytes.checked_add(4_096 + 16));
        crypto.mode == "DIRECT_ENCRYPT"
            && edge_scoped_value(&crypto.adapter_revision)
            && edge_scoped_value(&crypto.key_id)
            && crypto.key_not_before < crypto.key_expires_at
            && (1..=3_600).contains(&crypto.message_ttl_seconds)
            && minimum_envelope.is_some_and(|minimum| crypto.max_envelope_bytes >= minimum)
            && crypto.max_envelope_bytes <= EDGE_MAX_ENCRYPTED_RESPONSE_ENVELOPE_BYTES
            && in_flight.is_some_and(|bytes| bytes <= EDGE_MAX_BUFFERED_BODY_IN_FLIGHT_BYTES)
    })
}

/// Request-body handling the edge can compile.
fn route_request_crypto_contract_holds(route: &SiteRouteConfig, limits: &SiteLimitsConfig) -> bool {
    let Some(crypto) = route.request_crypto.as_ref() else {
        return true;
    };
    // Only bodies can be decrypted or observed, never for UI-sourced
    // operations, whose authority comes from the page action instead.
    if !matches!(route.method.as_str(), "POST" | "PUT" | "PATCH")
        || route.security_entry == SecurityEntry::UiActionRequired
    {
        return false;
    }
    match crypto {
        // An opaque, observed body cannot feed a response that encrypts,
        // changes identity or qualifies resources: the edge would act on
        // content it never verified.
        SiteRequestCrypto::Observe { adapter_revision } => {
            !route.response_has_side_effects() && edge_scoped_value(adapter_revision)
        }
        SiteRequestCrypto::DirectDecrypt {
            adapter_revision,
            key_id,
            key_not_before,
            key_expires_at,
            max_envelope_bytes,
            max_plaintext_bytes,
            max_message_age_seconds,
            max_future_skew_seconds,
            max_active_messages,
        } => {
            edge_scoped_value(adapter_revision)
                && edge_scoped_value(key_id)
                && key_not_before < key_expires_at
                && (1..=EDGE_MAX_ENCRYPTED_REQUEST_ENVELOPE_BYTES).contains(max_envelope_bytes)
                && *max_envelope_bytes <= limits.max_request_body_bytes
                && *max_plaintext_bytes != 0
                // Validated plaintext must fit in half the envelope.
                && *max_plaintext_bytes <= *max_envelope_bytes / 2
                && *max_plaintext_bytes <= limits.max_request_body_bytes
                && (1..=3_600).contains(max_message_age_seconds)
                && *max_future_skew_seconds <= 300
                && (1..=1_000_000).contains(max_active_messages)
        }
    }
}

/// Cross-route rules of the edge compiler: unambiguous matching, a bounded
/// number of `{parameter}` routes and one key per direction.
fn validate_route_set(routes: &[SiteRouteConfig]) -> Result<(), InvalidValue> {
    let invalid = || InvalidValue::new("site_policy.routes");
    // `(method, fixed prefix)` of every `{parameter}` route. The prefix is what
    // the edge matches: a final segment after it, non-empty, without a slash.
    let path_resources = routes
        .iter()
        .filter_map(|route| {
            let parameter = route.resource_path_parameter.as_ref()?;
            let prefix = route.path.strip_suffix(&format!("{{{parameter}}}"))?;
            Some((route.method.as_str(), prefix))
        })
        .collect::<Vec<_>>();
    if path_resources.len() > EDGE_MAX_PATH_RESOURCE_ROUTES {
        return Err(invalid());
    }
    for (index, (method, prefix)) in path_resources.iter().enumerate() {
        // Two routes with one method and prefix are the same route matched
        // twice, whatever the parameter is called.
        if path_resources[index + 1..]
            .iter()
            .any(|(other_method, other_prefix)| other_method == method && other_prefix == prefix)
        {
            return Err(invalid());
        }
        // A fixed-path route (including query-resource routes) that a
        // `{parameter}` route of the same method also matches is shadowed.
        if routes.iter().any(|route| {
            route.resource_path_parameter.is_none()
                && route.method == *method
                && route
                    .path
                    .strip_prefix(prefix)
                    .is_some_and(|segment| !segment.is_empty() && !segment.contains('/'))
        }) {
            return Err(invalid());
        }
    }
    // One decryption key and one encryption key per site, never shared.
    let request_keys = routes
        .iter()
        .filter_map(|route| match &route.request_crypto {
            Some(SiteRequestCrypto::DirectDecrypt { key_id, .. }) => Some(key_id.as_str()),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let response_keys = routes
        .iter()
        .filter_map(|route| route.response_crypto.as_ref())
        .map(|crypto| crypto.key_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if request_keys.len() > 1
        || response_keys.len() > 1
        || !request_keys.is_disjoint(&response_keys)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Extensions the static-asset fallback may admit. `json` and `map` are absent
/// on purpose; see [`SitePolicyConfig::allows_static_asset`].
const STATIC_ASSET_EXTENSIONS: &[&str] = &[
    "js", "css", "ico", "png", "jpg", "jpeg", "gif", "svg", "webp", "woff", "woff2", "ttf",
];

/// Longest request path the static-asset fallback will consider.
const STATIC_ASSET_PATH_MAX: usize = 512;

/// Percent-decodes `raw` once and keeps only paths made of file-name
/// characters; `None` for anything else.
///
/// Allowed after decoding: ASCII letters and digits, `. _ ~ @ + -` and `/`.
/// A `/` is accepted only as a literal separator, never from `%2F`, and a
/// decoded `%` (a double-encoded escape) is refused, so one decoding step by
/// the origin cannot produce a different path than the one judged here.
fn decode_static_asset_path(raw: &str) -> Option<String> {
    fn hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    if raw.len() > STATIC_ASSET_PATH_MAX || !raw.starts_with('/') {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut decoded = String::with_capacity(raw.len());
    let mut index = 0;
    while index < bytes.len() {
        let (byte, escaped) = if bytes[index] == b'%' {
            let pair = bytes.get(index + 1..index + 3)?;
            index += 3;
            ((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?, true)
        } else {
            index += 1;
            (bytes[index - 1], false)
        };
        let allowed = byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b'~' | b'@' | b'+' | b'-')
            || (byte == b'/' && !escaped);
        if !allowed {
            return None;
        }
        decoded.push(char::from(byte));
    }
    Some(decoded)
}

fn validate_site_route_path(route: &SiteRouteConfig) -> Result<String, InvalidValue> {
    let path = route.path.as_str();
    if path.is_empty()
        || path.len() > 256
        || !route_path_is_edge_compilable(path)
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
    {
        return Err(InvalidValue::new("site_policy.route"));
    }
    let Some(parameter) = route.resource_path_parameter.as_ref() else {
        if path.contains(['{', '}']) {
            return Err(InvalidValue::new("site_policy.route"));
        }
        return Ok(path.to_owned());
    };
    FieldName::parse(parameter.clone()).map_err(|_| InvalidValue::new("site_policy.route"))?;
    let marker = format!("{{{parameter}}}");
    let Some(prefix) = path.strip_suffix(&marker) else {
        return Err(InvalidValue::new("site_policy.route"));
    };
    if prefix.is_empty()
        || !prefix.ends_with('/')
        || prefix.contains(['{', '}', '%'])
        || prefix.contains("//")
    {
        return Err(InvalidValue::new("site_policy.route"));
    }
    Ok(format!("{prefix}resource"))
}

impl SecurityEntry {
    /// Parses the top-level site entry admission (`SiteConfig::security_entry`).
    ///
    /// Only the three admissions a default entry route may have are accepted:
    /// that route is a bodiless GET, so it can never carry the `auth_binding`
    /// an `auth_entry` exists for. Route-level `auth_entry` is read by serde.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for an unknown or route-only wire value.
    pub fn parse(value: &str) -> Result<Self, InvalidValue> {
        match value {
            "public" => Ok(Self::Public),
            "authenticated_root" => Ok(Self::AuthenticatedRoot),
            "ui_action_required" => Ok(Self::UiActionRequired),
            _ => Err(InvalidValue::new("security_entry")),
        }
    }

    /// The edge's admission class name for this entry (gateway
    /// `AdmissionDto`), as projected to the edge and recorded in
    /// `site_routes.admission`.
    #[must_use]
    pub const fn edge_admission(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::AuthEntry => "AUTH_ENTRY",
            Self::AuthenticatedRoot => "AUTHENTICATED_ROOT",
            Self::UiActionRequired => "UI_ACTION_REQUIRED",
        }
    }
}

/// A route operation bound to one exact path and method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteOperation {
    operation_id: String,
    method: String,
    path: String,
    security_entry: SecurityEntry,
}

impl RouteOperation {
    /// Validates an operation without compiling site-specific policy.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for unsupported methods or ambiguous paths.
    pub fn new(
        operation_id: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        security_entry: SecurityEntry,
    ) -> Result<Self, InvalidValue> {
        let operation_id = operation_id.into();
        let method = method.into();
        let path = path.into();
        if operation_id.is_empty()
            || operation_id.len() > 128
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b':')
            })
            || path.is_empty()
            || path.len() > 256
            || !path.starts_with('/')
            || path.contains(['?', '#'])
            || path.contains(['{', '}'])
            || path
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\')
            || path.split('/').any(|segment| matches!(segment, "." | ".."))
            || !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE")
        {
            return Err(InvalidValue::new("route_operation"));
        }
        Ok(Self {
            operation_id,
            method,
            path,
            security_entry,
        })
    }

    /// Returns the stable operation identifier.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    /// Returns the HTTP method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
    /// Returns the exact route path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Returns the entry policy.
    #[must_use]
    pub const fn security_entry(&self) -> SecurityEntry {
        self.security_entry
    }
}

/// Durable identity of one protected site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedSite {
    tenant_id: TenantId,
    site_id: SiteId,
    display_name: String,
    listen_port: PortNumber,
}

impl ProtectedSite {
    /// Creates a bounded site registry record.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for an empty or oversized display name.
    pub fn new(
        tenant_id: TenantId,
        site_id: SiteId,
        display_name: impl Into<String>,
        listen_port: PortNumber,
    ) -> Result<Self, InvalidValue> {
        let display_name = display_name.into();
        if display_name.is_empty() || display_name.len() > 128 {
            return Err(InvalidValue::new("display_name"));
        }
        Ok(Self {
            tenant_id,
            site_id,
            display_name,
            listen_port,
        })
    }

    /// Returns the tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    /// Returns the site scope.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }
    /// Returns the listener port.
    #[must_use]
    pub const fn listen_port(&self) -> PortNumber {
        self.listen_port
    }
}

/// A durable request to apply one desired policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyIntent {
    /// Target site.
    pub site_id: SiteId,
    /// Desired policy revision.
    pub desired_revision: u64,
    /// Idempotent apply identity.
    pub apply_id: String,
}

/// A signed edge acknowledgment for one apply intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyAck {
    /// Target site.
    pub site_id: SiteId,
    /// Desired revision acknowledged by the edge.
    pub desired_revision: u64,
    /// Active revision after atomic replacement.
    pub active_revision: u64,
    /// Idempotent apply identity.
    pub apply_id: String,
}

/// Signed control-to-edge snapshot envelope. The signature is carried in the
/// transport header so the canonical JSON body is the value being verified.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayApplyRequest {
    /// Wire protocol version.
    pub protocol_version: u16,
    /// Tenant scope injected by the control plane.
    pub tenant_id: String,
    /// Idempotent apply operation identifier.
    pub apply_id: String,
    /// Monotonic snapshot revision.
    pub snapshot_revision: u64,
    /// Complete replacement set for the edge.
    pub sites: Vec<GatewayApplySite>,
}

/// One site in a complete edge snapshot.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayApplySite {
    /// Site scope.
    pub site_id: String,
    /// Internal listener port copied from the compiled configuration.
    pub listen_port: u16,
    /// Public origin used only for Host/SNI route selection.
    pub public_origin: String,
    /// Strict gateway configuration consumed by the edge compiler.
    pub gateway_config: serde_json::Value,
    /// Desired site revision.
    pub revision: u64,
}

/// Edge acknowledgement returned only after validation and atomic replacement.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayApplyAck {
    /// Apply identifier echoed from the request.
    pub apply_id: String,
    /// Active complete-snapshot revision.
    pub active_revision: u64,
    /// Stable acknowledgement state.
    pub apply_state: String,
    /// Stable reason code.
    pub reason_code: String,
}

/// A durable internal listener lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortLease {
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Site scope.
    pub site_id: SiteId,
    /// Reserved listener port.
    pub port: PortNumber,
}

impl fmt::Display for PortNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_values_are_strictly_bounded() {
        assert!(PortNumber::parse(6100).is_ok());
        assert!(PortNumber::parse(6099).is_err());
        assert!(PublicOrigin::parse("https://example.com").is_ok());
        assert!(PublicOrigin::parse("https://example.com/?x=1").is_err());
        assert!(PublicOrigin::parse("https://example.com:bad").is_err());
        assert!(PublicOrigin::parse("https://[::1]:443").is_ok());
        assert!(UpstreamEndpoint::parse("127.0.0.1:8080", "origin.local", false).is_ok());
        assert!(UpstreamEndpoint::parse("[::1]:8080", "origin.local", false).is_ok());
        assert!(UpstreamEndpoint::parse("127.0.0.1:0", "origin.local", false).is_err());
        assert!(RouteOperation::new("entry", "GET", "/", SecurityEntry::UiActionRequired).is_ok());
        assert!(
            RouteOperation::new(
                "entry",
                "GET",
                "/users/{id}",
                SecurityEntry::UiActionRequired
            )
            .is_err()
        );

        let mut resource_policy = SitePolicyConfig::default();
        resource_policy.routes.push(SiteRouteConfig {
            operation_id: "orders.open".to_owned(),
            method: "GET".to_owned(),
            path: "/orders/{order_id}".to_owned(),
            security_entry: SecurityEntry::UiActionRequired,
            source_action: Some("orders.open".to_owned()),
            resource_type: Some("orders".to_owned()),
            view_profile: Some("summary".to_owned()),
            resource_query_parameter: None,
            resource_path_parameter: Some("order_id".to_owned()),
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
        assert!(resource_policy.validate().is_ok());
        resource_policy.routes[0].source_action = None;
        assert!(resource_policy.validate().is_err());

        let mut policy = SitePolicyConfig::default();
        policy.health_check.path = "/../health".to_owned();
        assert!(policy.validate().is_err());
        policy = SitePolicyConfig::default();
        policy.secret_refs.push(SiteSecretReference {
            kind: "tls".to_owned(),
            secret_ref: "secret://".to_owned(),
            key_id: "tls-v1".to_owned(),
            state: "active".to_owned(),
        });
        assert!(policy.validate().is_err());
    }

    #[test]
    fn waf_query_fragments_are_explicit_and_bounded() {
        let mut policy = SitePolicyConfig::default();
        let previous_shape = serde_json::to_value(&policy).unwrap();
        assert!(
            previous_shape["waf"]
                .get("blocked_query_fragments")
                .is_none()
        );
        policy.waf.blocked_query_fragments = vec!["' or 1=1--".to_owned(), "<script".to_owned()];
        assert!(policy.validate().is_ok());

        policy
            .waf
            .blocked_query_fragments
            .push("<SCRIPT".to_owned());
        assert!(policy.validate().is_err());
        policy.waf.blocked_query_fragments = vec!["ab".to_owned()];
        assert!(policy.validate().is_err());
        policy.waf.blocked_query_fragments = vec!["évil".to_owned()];
        assert!(policy.validate().is_err());
    }

    fn opted_in(depth: u8) -> SitePolicyConfig {
        SitePolicyConfig {
            static_asset_max_path_depth: depth,
            ..SitePolicyConfig::default()
        }
    }

    // The fallback admits requests without identity or an exact operation, so
    // a site must ask for it. This test used to assert the opposite default
    // (depth 5 for every site), which is the hole it now guards against.
    #[test]
    fn static_asset_fallback_is_off_unless_a_site_opts_in() {
        let default = SitePolicyConfig::default();
        assert_eq!(default.static_asset_max_path_depth, 0);
        assert!(!default.allows_static_asset("GET", "/assets/app.js"));
        // An omitted field in a stored or submitted policy means off, not five.
        let parsed: SitePolicyConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.static_asset_max_path_depth, 0);
        assert!(!parsed.allows_static_asset("GET", "/assets/app.js"));
        let explicit: SitePolicyConfig =
            serde_json::from_str(r#"{"static_asset_max_path_depth":3}"#).unwrap();
        assert!(explicit.validate().is_ok());
        assert!(explicit.allows_static_asset("GET", "/assets/app.js"));
        let too_deep: SitePolicyConfig =
            serde_json::from_str(r#"{"static_asset_max_path_depth":17}"#).unwrap();
        assert!(too_deep.validate().is_err());
    }

    #[test]
    fn static_assets_use_a_bounded_depth_and_extension_allowlist() {
        let policy = opted_in(5);
        assert!(policy.allows_static_asset("GET", "/chunk.js"));
        assert!(policy.allows_static_asset("GET", "/assets/js/chunk.js"));
        assert!(policy.allows_static_asset("GET", "/a/b/c/d/style.css"));
        assert!(!policy.allows_static_asset("GET", "/a/b/c/d/e/style.css"));
        assert!(!policy.allows_static_asset("GET", "/a/b/c/d/e/f/style.css"));
        assert!(!policy.allows_static_asset("POST", "/chunk.js"));
        assert!(!policy.allows_static_asset("HEAD", "/chunk.js"));
        assert!(!policy.allows_static_asset("GET", "/api/users"));
        assert!(!opted_in(0).allows_static_asset("GET", "/chunk.js"));
        assert!(!opted_in(1).allows_static_asset("GET", "/assets/chunk.js"));
        assert!(opted_in(1).allows_static_asset("GET", "/chunk.js"));
    }

    // Reviewer reproductions: with the fallback on at depth 5 each of these
    // was admitted without identity because the extension check looked at the
    // whole last segment (`rsplit('.')` returns the entire name when there is
    // no dot) or ignored characters that origins read as structure.
    #[test]
    fn static_asset_fallback_never_admits_apis_or_origin_path_tricks() {
        let policy = opted_in(5);
        for (path, expected) in [
            ("/assets/app.js", true),
            ("/orders/123.json", false),
            ("/api/v1/users/42.json", false),
            ("/admin/export.json", false),
            ("/assets/app.js.map", false),
            ("/api/json", false),
            ("/api/v1/map", false),
            ("/css", false),
            ("/js", false),
            ("/search/png", false),
            ("/admin/users;.js", false),
            ("/admin/dashboard;.css", false),
            ("/api/accounts/..;/x.js", false),
            ("/api/users", false),
            ("/orders/123.xml", false),
            // Extension rules: a real dot with a non-empty stem, case-insensitive.
            ("/assets/.js", false),
            ("/assets/app.", false),
            ("/assets/app.JS", true),
            ("/assets/logo.SVG", true),
            ("/assets/app.mjs", false),
            ("/assets/app.js.php", false),
            ("/assets/app.js/", false),
            ("/assets/@scope/pkg/font.woff2", true),
            ("/assets/chunk-DBPdFzgj.js", true),
            ("/assets/vendor~main.css", true),
            ("/", false),
            ("", false),
            ("assets/app.js", false),
            // Structure an origin may interpret differently from this check.
            ("/a//b.js", false),
            ("/a/./b.js", false),
            ("/a/../b.js", false),
            ("/a\\b.js", false),
            ("/a/b.js;v=1", false),
            ("/a/b.js::$DATA", false),
            ("/a/b.js?x", false),
            ("/a/b.js#x", false),
            ("/a b/c.js", false),
            ("/caf\u{e9}.js", false),
        ] {
            assert_eq!(
                policy.allows_static_asset("GET", path),
                expected,
                "GET {path}"
            );
        }
    }

    #[test]
    fn static_asset_fallback_decodes_strictly_and_refuses_encoded_tricks() {
        let policy = opted_in(5);
        for (path, expected) in [
            // Decoding is applied once; the decoded name is what the origin sees.
            ("/assets/app%2ejs", true),
            ("/assets/app%2Ejs", true),
            ("/assets/%61pp.js", true),
            ("/assets/app%2e", false),
            // Encoded `;`, slash, backslash, dot segments, controls, query and
            // percent signs are refused outright.
            ("/admin/users%3b.js", false),
            ("/admin/users%3B.js", false),
            ("/a%2fb.js", false),
            ("/a%2Fb.js", false),
            ("/a%5cb.js", false),
            ("/a/%2e%2e/b.js", false),
            ("/a/%2E%2E/b.js", false),
            ("/a/%2e/b.js", false),
            ("/a/..%2fb.js", false),
            ("/a/b%00.js", false),
            ("/a/b%0a.js", false),
            ("/a/b%0d%0a.js", false),
            ("/a/b%7f.js", false),
            ("/a/b%3f.js", false),
            ("/a/b%23.js", false),
            ("/a/b%20.js", false),
            ("/a/b%252ejs", false),
            ("/a/b%25.js", false),
            ("/a/b%c3%a9.js", false),
            ("/a/b%ff.js", false),
            // Malformed escapes are never guessed.
            ("/a/b%.js", false),
            ("/a/b%2.js", false),
            ("/a/b%zz.js", false),
            ("/a/b.js%", false),
        ] {
            assert_eq!(
                policy.allows_static_asset("GET", path),
                expected,
                "GET {path}"
            );
        }
        // Unreasonably long paths are not asset requests.
        let long = format!("/{}.js", "a".repeat(600));
        assert!(!policy.allows_static_asset("GET", &long));
    }

    fn route(id: &str, method: &str, path: &str) -> SiteRouteConfig {
        SiteRouteConfig {
            operation_id: id.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            security_entry: SecurityEntry::Public,
            source_action: None,
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

    fn orders(id: &str, path: &str, parameter: &str) -> SiteRouteConfig {
        let mut route = route(id, "GET", path);
        route.security_entry = SecurityEntry::UiActionRequired;
        route.source_action = Some(format!("{id}.open"));
        route.resource_type = Some("orders".to_owned());
        route.view_profile = Some("summary".to_owned());
        route.resource_path_parameter = Some(parameter.to_owned());
        route
    }

    fn policy_of(routes: Vec<SiteRouteConfig>) -> SitePolicyConfig {
        SitePolicyConfig {
            routes,
            ..SitePolicyConfig::default()
        }
    }

    /// The edge compiler refuses these paths, so one site holding such a route
    /// used to make every apply for the tenant fail with 422.
    #[test]
    fn route_paths_must_be_printable_ascii_outside_the_edge_namespace() {
        for path in [
            "/search results",
            "/caf\u{e9}",
            "/__xshield/v1/bootstrap",
            "/__xshield/",
            "/a\u{7f}b",
            "/a\tb",
        ] {
            assert!(
                policy_of(vec![route("a", "GET", path)]).validate().is_err(),
                "{path:?}"
            );
        }
        for path in [
            "/",
            "/a%20b",
            "/__xshield",
            "/__xshield_x/y",
            "/__XSHIELD/x",
        ] {
            assert!(
                policy_of(vec![route("a", "GET", path)]).validate().is_ok(),
                "{path:?}"
            );
        }
    }

    #[test]
    fn path_resource_routes_may_not_collide_or_shadow() {
        let ok = |routes| policy_of(routes).validate().is_ok();
        let one = || orders("o1", "/orders/{order_id}", "order_id");
        assert!(ok(vec![one()]));
        // The parameter's name does not make a second route on the same prefix
        // a different route.
        assert!(!ok(vec![one(), orders("o2", "/orders/{id}", "id")]));
        assert!(!ok(vec![route("n", "GET", "/orders/new"), one()]));
        assert!(!ok(vec![one(), route("n", "GET", "/orders/new")]));
        // Not matched by the resource route: other method, empty final
        // segment, deeper path, other prefix.
        assert!(ok(vec![route("n", "POST", "/orders/new"), one()]));
        assert!(ok(vec![route("n", "GET", "/orders/"), one()]));
        assert!(ok(vec![route("n", "GET", "/orders/new/x"), one()]));
        assert!(ok(vec![route("n", "GET", "/order/new"), one()]));
    }

    #[test]
    fn at_most_the_edge_limit_of_path_resource_routes_is_accepted() {
        let routes = |count: usize| {
            (0..count)
                .map(|index| {
                    orders(
                        &format!("r{index}"),
                        &format!("/r{index}/{{order_id}}"),
                        "order_id",
                    )
                })
                .collect::<Vec<_>>()
        };
        assert!(
            policy_of(routes(EDGE_MAX_PATH_RESOURCE_ROUTES))
                .validate()
                .is_ok()
        );
        assert!(
            policy_of(routes(EDGE_MAX_PATH_RESOURCE_ROUTES + 1))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn crypto_must_fit_what_the_edge_can_compile() {
        let post = |id: &str| route(id, "POST", &format!("/{id}"));
        let observe = |revision: &str| SiteRequestCrypto::Observe {
            adapter_revision: revision.to_owned(),
        };
        let valid = |route: SiteRouteConfig| policy_of(vec![route]).validate().is_ok();

        let mut route = post("a");
        route.request_crypto = Some(observe("observe-v1"));
        assert!(valid(route.clone()));
        route.method = "GET".to_owned();
        assert!(!valid(route.clone()), "no body to observe");
        route.method = "POST".to_owned();
        route.request_crypto = Some(observe("bad revision"));
        assert!(!valid(route.clone()), "scoped values have no spaces");
        route.request_crypto = Some(observe("observe-v1"));
        route.security_entry = SecurityEntry::UiActionRequired;
        route.source_action = Some("a.open".to_owned());
        assert!(!valid(route), "UI-sourced operations are not encrypted");

        let response = |envelope: usize| {
            let mut route = post("b");
            route.response_crypto = Some(SiteResponseCrypto {
                mode: "DIRECT_ENCRYPT".to_owned(),
                adapter_revision: "rev-1".to_owned(),
                key_id: "key-r".to_owned(),
                key_not_before: 1,
                key_expires_at: 2,
                message_ttl_seconds: 60,
                max_envelope_bytes: envelope,
            });
            route
        };
        assert!(!valid(response(1_048_576 * 2 + 1_023)));
        assert!(valid(response(1_048_576 * 2 + 1_024)));

        let mut sensor = post("c");
        sensor.response_mode = "SENSOR_HTML".to_owned();
        assert!(!valid(sensor), "a sensor page needs its adapter and GET");
    }

    #[test]
    fn operation_ids_use_the_edge_alphabet() {
        // `:` passed `RouteOperation` but the edge's `OperationId` refuses it.
        assert!(
            policy_of(vec![route("a:b", "GET", "/")])
                .validate()
                .is_err()
        );
        assert!(
            policy_of(vec![route("a.b-c_d", "GET", "/")])
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn one_key_per_direction_and_never_shared() {
        let decrypting = |id: &str, key: &str| {
            let mut route = route(id, "POST", &format!("/{id}"));
            route.request_crypto = Some(SiteRequestCrypto::DirectDecrypt {
                adapter_revision: "rev-1".to_owned(),
                key_id: key.to_owned(),
                key_not_before: 1,
                key_expires_at: 2,
                max_envelope_bytes: 8_192,
                max_plaintext_bytes: 4_096,
                max_message_age_seconds: 60,
                max_future_skew_seconds: 5,
                max_active_messages: 10,
            });
            route
        };
        let encrypting = |id: &str, key: &str| {
            let mut route = route(id, "POST", &format!("/{id}"));
            route.response_crypto = Some(SiteResponseCrypto {
                mode: "DIRECT_ENCRYPT".to_owned(),
                adapter_revision: "rev-1".to_owned(),
                key_id: key.to_owned(),
                key_not_before: 1,
                key_expires_at: 2,
                message_ttl_seconds: 60,
                max_envelope_bytes: 4_194_304,
            });
            route
        };
        let ok = |routes| policy_of(routes).validate().is_ok();
        assert!(ok(vec![decrypting("a", "k1"), decrypting("b", "k1")]));
        assert!(!ok(vec![decrypting("a", "k1"), decrypting("b", "k2")]));
        assert!(!ok(vec![encrypting("a", "k1"), encrypting("b", "k2")]));
        assert!(!ok(vec![decrypting("a", "k1"), encrypting("b", "k1")]));
        assert!(ok(vec![decrypting("a", "k1"), encrypting("b", "k2")]));
    }
}
