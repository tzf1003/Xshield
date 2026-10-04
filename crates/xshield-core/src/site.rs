//! Validated control-plane values shared by site management and edge apply.
#![allow(missing_docs)]

use crate::domain::{
    ActionId, FieldName, InvalidValue, ResourceType, SiteId, TenantId, ViewProfile,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod upstream;

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
    /// Maximum path depth for public static assets such as JavaScript and CSS.
    /// A zero value disables the static-asset fallback; the default is five.
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
    5
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
            if route_config.source_action.is_some()
                && route_config
                    .source_action
                    .as_ref()
                    .is_some_and(|v| v.len() > 128)
                || route_config
                    .resource_type
                    .as_ref()
                    .is_some_and(|v| v.len() > 128)
                || route_config
                    .view_profile
                    .as_ref()
                    .is_some_and(|v| v.len() > 128)
                || route_config
                    .resource_query_parameter
                    .as_ref()
                    .is_some_and(|v| v.len() > 128)
                || route_config
                    .resource_path_parameter
                    .as_ref()
                    .is_some_and(|v| v.len() > 128)
                || route_config.max_response_bytes == 0
                || route_config.max_response_bytes > self.limits.max_response_body_bytes
                || !matches!(
                    route_config.response_mode.as_str(),
                    "" | "BUFFERED_JSON" | "SENSOR_HTML"
                )
                || route_config.response_crypto.as_ref().is_some_and(|crypto| {
                    crypto.mode != "DIRECT_ENCRYPT"
                        || crypto.adapter_revision.is_empty()
                        || crypto.adapter_revision.len() > 128
                        || crypto.key_id.is_empty()
                        || crypto.key_id.len() > 128
                        || crypto.key_not_before >= crypto.key_expires_at
                        || !(1..=3_600).contains(&crypto.message_ttl_seconds)
                        || crypto.max_envelope_bytes < route_config.max_response_bytes
                })
                || route_config
                    .request_crypto
                    .as_ref()
                    .is_some_and(|crypto| match crypto {
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
                            adapter_revision.is_empty()
                                || adapter_revision.len() > 128
                                || key_id.is_empty()
                                || key_id.len() > 128
                                || key_not_before >= key_expires_at
                                || *max_envelope_bytes == 0
                                || *max_envelope_bytes > 65_536
                                || *max_envelope_bytes > self.limits.max_request_body_bytes
                                || *max_plaintext_bytes == 0
                                || *max_plaintext_bytes > self.limits.max_request_body_bytes
                                || *max_message_age_seconds == 0
                                || *max_message_age_seconds > 86_400
                                || *max_future_skew_seconds > 300
                                || *max_active_messages == 0
                                || *max_active_messages > 1_000_000
                        }
                        SiteRequestCrypto::Observe { adapter_revision } => {
                            adapter_revision.is_empty() || adapter_revision.len() > 128
                        }
                    })
            {
                return Err(InvalidValue::new("site_policy.route"));
            }
        }
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

    /// Returns whether a public GET may use the bounded static-asset fallback.
    /// This is intentionally limited to browser asset extensions and a finite
    /// path depth so it cannot turn the site policy into a catch-all route.
    #[must_use]
    pub fn allows_static_asset(&self, method: &str, path: &str) -> bool {
        if method != "GET" || self.static_asset_max_path_depth == 0 || !path.starts_with('/') {
            return false;
        }
        let depth = path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .count();
        if depth == 0 || depth > usize::from(self.static_asset_max_path_depth) {
            return false;
        }
        let Some(extension) = path
            .rsplit('/')
            .next()
            .and_then(|name| name.rsplit('.').next())
        else {
            return false;
        };
        matches!(
            extension.to_ascii_lowercase().as_str(),
            "js" | "css"
                | "map"
                | "ico"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "svg"
                | "webp"
                | "woff"
                | "woff2"
                | "ttf"
                | "json"
        )
    }
}

fn validate_site_route_path(route: &SiteRouteConfig) -> Result<String, InvalidValue> {
    let path = route.path.as_str();
    if path.is_empty()
        || path.len() > 256
        || !path.starts_with('/')
        || path.contains(['?', '#'])
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
    /// Parses the stable wire value.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for an unknown wire value.
    pub fn parse(value: &str) -> Result<Self, InvalidValue> {
        match value {
            "public" => Ok(Self::Public),
            "authenticated_root" => Ok(Self::AuthenticatedRoot),
            "ui_action_required" => Ok(Self::UiActionRequired),
            _ => Err(InvalidValue::new("security_entry")),
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

    #[test]
    fn static_assets_use_a_bounded_depth_and_extension_allowlist() {
        let policy = SitePolicyConfig::default();
        assert_eq!(policy.static_asset_max_path_depth, 5);
        assert!(policy.allows_static_asset("GET", "/chunk.js"));
        assert!(policy.allows_static_asset("GET", "/assets/js/chunk.js"));
        assert!(policy.allows_static_asset("GET", "/a/b/c/d/style.css"));
        assert!(!policy.allows_static_asset("GET", "/a/b/c/d/e/f/style.css"));
        assert!(!policy.allows_static_asset("POST", "/chunk.js"));
        assert!(!policy.allows_static_asset("GET", "/api/users"));
    }
}
