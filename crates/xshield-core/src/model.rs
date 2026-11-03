//! Model settings the console owns: the Jev judgement model and the learning
//! agent's model (docs/03 section 3.3, and the model tab of the system page).
//!
//! This module holds the shapes and the rules only. Storage and the encryption
//! of keys live in `xshield-postgres`; the HTTP calls live in `xshield-judge`.
//! A key is never printed: [`ApiKey`] has no `Display` and no `Serialize`, and
//! its `Debug` output is a placeholder.

use std::fmt;
use std::ops::RangeInclusive;

use zeroize::Zeroizing;

/// Vercel AI Gateway address of the Jev protocol, the default route.
pub const GATEWAY_JEV_ENDPOINT: &str = "https://ai-gateway.vercel.sh/typesafe/v1/systemone";
/// `TypeSafe` address of the direct route.
pub const DIRECT_JEV_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
/// Model name behind the Vercel AI Gateway route.
pub const GATEWAY_JEV_MODEL: &str = "typesafe-ai/jev";
/// Model name of the direct `TypeSafe` route.
pub const DIRECT_JEV_MODEL: &str = "jev-1.13.0";
/// Base address of the Vercel AI Gateway for OpenAI-compatible calls, as the
/// console shows it. Calls go to `{base}/chat/completions`.
pub const GATEWAY_AGENT_ENDPOINT: &str = "https://ai-gateway.vercel.sh/v1";
/// Default time allowed for one Jev call (docs/02 section 2.5).
pub const JEV_TIMEOUT_MS: u32 = 2_000;
/// Allowed Jev timeouts, in milliseconds.
pub const JEV_TIMEOUT_MS_RANGE: RangeInclusive<u32> = 100..=30_000;
/// Default time allowed for one learning agent call.
pub const AGENT_TIMEOUT_MS: u32 = 30_000;
/// Allowed learning agent timeouts, in milliseconds.
pub const AGENT_TIMEOUT_MS_RANGE: RangeInclusive<u32> = 5_000..=120_000;
/// Longest address accepted, in bytes.
pub const ENDPOINT_MAX_BYTES: usize = 2_048;
/// Longest model name accepted, in bytes.
pub const MODEL_MAX_BYTES: usize = 200;
/// Longest API key accepted, in bytes.
pub const KEY_MAX_BYTES: usize = 512;

/// Why a setting was refused. The codes are stable: the API and the console show them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// The Jev route is not `gateway`, `direct` or `custom`.
    Route,
    /// The learning agent provider is not `gateway` or `custom`.
    Provider,
    /// The address is missing, is not https (or loopback http), or carries
    /// credentials, a query or a fragment.
    Endpoint,
    /// The model name is missing where one is required, too long, or has
    /// characters outside `A-Za-z0-9._:/@-`.
    Model,
    /// The timeout is outside its range.
    Timeout,
    /// The API key is empty, too long, or contains whitespace.
    Key,
    /// Sharing the key with Jev needs both sides on the Vercel AI Gateway.
    Share,
}

impl ConfigError {
    /// The stable code of the refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Route => "MODEL_ROUTE_INVALID",
            Self::Provider => "MODEL_PROVIDER_INVALID",
            Self::Endpoint => "MODEL_ENDPOINT_INVALID",
            Self::Model => "MODEL_NAME_INVALID",
            Self::Timeout => "MODEL_TIMEOUT_INVALID",
            Self::Key => "MODEL_KEY_INVALID",
            Self::Share => "MODEL_KEY_SHARE_INVALID",
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ConfigError {}

/// The API key of a model. It cannot be displayed or serialised; the only way
/// out is [`ApiKey::expose`], for an authorisation header.
pub struct ApiKey(Zeroizing<String>);

impl ApiKey {
    /// Checks a key typed or pasted by an operator. Surrounding whitespace is
    /// dropped; anything else outside printable ASCII is refused.
    ///
    /// # Errors
    /// [`ConfigError::Key`] when the key is empty, too long, or contains
    /// whitespace or control characters.
    pub fn new(text: &str) -> Result<Self, ConfigError> {
        let text = text.trim();
        if text.is_empty()
            || text.len() > KEY_MAX_BYTES
            || !text.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ConfigError::Key);
        }
        Ok(Self(Zeroizing::new(text.to_owned())))
    }

    /// The key itself. Use it for an `Authorization` header and nothing else.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The last four characters, for display. They are kept next to the
    /// encrypted key so the console can show which key is in use.
    #[must_use]
    pub fn last4(&self) -> String {
        let length = self.0.len();
        self.0[length.saturating_sub(4)..].to_owned()
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKey(<redacted>)")
    }
}

/// The Jev routes. `gateway` is the default; `direct` talks to `TypeSafe`; `custom`
/// names a private deployment (docs/02 section 2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JevRoute {
    /// Vercel AI Gateway, the default.
    Gateway,
    /// `TypeSafe` directly. Some regions get HTTP 451 here.
    Direct,
    /// A private deployment at an address the operator names.
    Custom,
}

impl JevRoute {
    /// Reads the stored name of a route.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "gateway" => Some(Self::Gateway),
            "direct" => Some(Self::Direct),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    /// The stored name of the route.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Direct => "direct",
            Self::Custom => "custom",
        }
    }

    /// The fixed address of a preset route; `None` for `custom`.
    #[must_use]
    pub const fn preset_endpoint(self) -> Option<&'static str> {
        match self {
            Self::Gateway => Some(GATEWAY_JEV_ENDPOINT),
            Self::Direct => Some(DIRECT_JEV_ENDPOINT),
            Self::Custom => None,
        }
    }

    /// The default model name of a preset route; `None` for `custom`.
    #[must_use]
    pub const fn preset_model(self) -> Option<&'static str> {
        match self {
            Self::Gateway => Some(GATEWAY_JEV_MODEL),
            Self::Direct => Some(DIRECT_JEV_MODEL),
            Self::Custom => None,
        }
    }
}

/// The console's Jev settings, checked. Preset routes take their address from
/// the route; only `custom` stores an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JevSpec {
    route: JevRoute,
    endpoint: Option<String>,
    model: Option<String>,
    timeout_ms: u32,
}

impl JevSpec {
    /// Checks the operator's values. `model` of `None` means the route's default.
    ///
    /// # Errors
    /// The first refused field: the timeout, the model name, or, for `custom`,
    /// a missing or invalid address or model.
    pub fn new(
        route: JevRoute,
        endpoint: Option<&str>,
        model: Option<&str>,
        timeout_ms: u32,
    ) -> Result<Self, ConfigError> {
        if !JEV_TIMEOUT_MS_RANGE.contains(&timeout_ms) {
            return Err(ConfigError::Timeout);
        }
        let model = model
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .map(check_model)
            .transpose()?;
        let endpoint = match route {
            JevRoute::Custom => Some(check_endpoint(endpoint.ok_or(ConfigError::Endpoint)?)?),
            JevRoute::Gateway | JevRoute::Direct => None,
        };
        if route == JevRoute::Custom && model.is_none() {
            return Err(ConfigError::Model);
        }
        Ok(Self {
            route,
            endpoint,
            model,
            timeout_ms,
        })
    }

    /// The route.
    #[must_use]
    pub const fn route(&self) -> JevRoute {
        self.route
    }

    /// The address calls go to.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        self.endpoint
            .as_deref()
            .or(self.route.preset_endpoint())
            .unwrap_or_default()
    }

    /// The model name sent with each call.
    #[must_use]
    pub fn model(&self) -> &str {
        self.model
            .as_deref()
            .or(self.route.preset_model())
            .unwrap_or_default()
    }

    /// The default time allowed for a call; a site may set its own.
    #[must_use]
    pub const fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    /// The fields as they are shown and compared in the history, in a fixed order.
    #[must_use]
    pub fn values(&self) -> Vec<(&'static str, String)> {
        vec![
            ("route", self.route.as_str().to_owned()),
            ("endpoint", self.endpoint().to_owned()),
            ("model", self.model().to_owned()),
            ("timeout_ms", self.timeout_ms.to_string()),
        ]
    }
}

/// The learning agent's provider. Both speak the `OpenAI` chat completions protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentProvider {
    /// Vercel AI Gateway, the default.
    Gateway,
    /// Any other OpenAI-compatible address the operator names.
    Custom,
}

impl AgentProvider {
    /// Reads the stored name of a provider.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "gateway" => Some(Self::Gateway),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    /// The stored name of the provider.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Custom => "custom",
        }
    }

    /// The fixed base address of a preset provider; `None` for `custom`.
    #[must_use]
    pub const fn preset_endpoint(self) -> Option<&'static str> {
        match self {
            Self::Gateway => Some(GATEWAY_AGENT_ENDPOINT),
            Self::Custom => None,
        }
    }
}

/// The learning agent's model settings, checked. The model name may be absent:
/// the agent then stays unconfigured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpec {
    provider: AgentProvider,
    endpoint: Option<String>,
    model: Option<String>,
    timeout_ms: u32,
    share_key_with_jev: bool,
}

impl AgentSpec {
    /// Checks the operator's values.
    ///
    /// # Errors
    /// The timeout, the model name, or, for `custom`, a missing or invalid address.
    pub fn new(
        provider: AgentProvider,
        endpoint: Option<&str>,
        model: Option<&str>,
        timeout_ms: u32,
        share_key_with_jev: bool,
    ) -> Result<Self, ConfigError> {
        if !AGENT_TIMEOUT_MS_RANGE.contains(&timeout_ms) {
            return Err(ConfigError::Timeout);
        }
        let model = model
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .map(check_model)
            .transpose()?;
        let endpoint = match provider {
            AgentProvider::Custom => Some(check_endpoint(endpoint.ok_or(ConfigError::Endpoint)?)?),
            AgentProvider::Gateway => None,
        };
        Ok(Self {
            provider,
            endpoint,
            model,
            timeout_ms,
            share_key_with_jev,
        })
    }

    /// The provider.
    #[must_use]
    pub const fn provider(&self) -> AgentProvider {
        self.provider
    }

    /// The base address calls go to, `{base}/chat/completions` being the URL.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        self.endpoint
            .as_deref()
            .or(self.provider.preset_endpoint())
            .unwrap_or_default()
    }

    /// The model name, or `None` while none is configured.
    #[must_use]
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// The time allowed for one call.
    #[must_use]
    pub const fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    /// Whether the agent uses the Jev key rather than its own.
    #[must_use]
    pub const fn share_key_with_jev(&self) -> bool {
        self.share_key_with_jev
    }

    /// Sharing a key is allowed only when both sides are on the Vercel AI Gateway.
    ///
    /// # Errors
    /// [`ConfigError::Share`] when the agent shares the key but one side is not
    /// on the gateway.
    pub fn check_share(&self, jev: &JevSpec) -> Result<(), ConfigError> {
        let both_gateway =
            self.provider == AgentProvider::Gateway && jev.route() == JevRoute::Gateway;
        if self.share_key_with_jev && !both_gateway {
            return Err(ConfigError::Share);
        }
        Ok(())
    }

    /// The fields as they are shown and compared in the history, in a fixed order.
    #[must_use]
    pub fn values(&self) -> Vec<(&'static str, String)> {
        vec![
            ("provider", self.provider.as_str().to_owned()),
            ("endpoint", self.endpoint().to_owned()),
            ("model", self.model.clone().unwrap_or_default()),
            ("timeout_ms", self.timeout_ms.to_string()),
            ("share_key_with_jev", self.share_key_with_jev.to_string()),
        ]
    }
}

/// What the learning agent needs to make one call.
#[derive(Debug)]
pub struct ModelEndpoint {
    /// Base address, as the console shows it, for example
    /// `https://ai-gateway.vercel.sh/v1`.
    pub base_url: String,
    /// Model name sent with each call.
    pub model: String,
    /// The key that authorises the calls.
    pub api_key: ApiKey,
    /// Time allowed for one call, in milliseconds.
    pub timeout_ms: u32,
}

impl ModelEndpoint {
    /// The URL of one OpenAI-compatible chat completions call.
    #[must_use]
    pub fn chat_completions_url(&self) -> String {
        format!("{}/chat/completions", self.base_url)
    }
}

/// One field that differs between two saved versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldChange {
    /// The field name, as the history shows it.
    pub field: &'static str,
    /// The value before, or an empty string for a first save.
    pub from: String,
    /// The value after.
    pub to: String,
}

/// The fields whose values differ between `before` and `after`, in the order of
/// `after`. A field missing from `before` counts as empty there.
#[must_use]
pub fn changed_fields(
    before: &[(&'static str, String)],
    after: &[(&'static str, String)],
) -> Vec<FieldChange> {
    after
        .iter()
        .filter_map(|(field, to)| {
            let from = before
                .iter()
                .find(|(name, _)| name == field)
                .map_or_else(String::new, |(_, value)| value.clone());
            (from != *to).then(|| FieldChange {
                field,
                from,
                to: to.clone(),
            })
        })
        .collect()
}

fn check_model(text: &str) -> Result<String, ConfigError> {
    let valid = !text.is_empty()
        && text.len() <= MODEL_MAX_BYTES
        && text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        });
    if valid {
        Ok(text.to_owned())
    } else {
        Err(ConfigError::Model)
    }
}

/// Checks an address and returns it without trailing slashes: https, or http
/// on a loopback host, with no credentials, query or fragment.
///
/// # Errors
/// [`ConfigError::Endpoint`] for any other address.
pub fn check_endpoint(text: &str) -> Result<String, ConfigError> {
    let text = text.trim().trim_end_matches('/');
    let printable = text.bytes().all(|byte| byte.is_ascii_graphic());
    if text.is_empty()
        || text.len() > ENDPOINT_MAX_BYTES
        || !printable
        || text.contains(['?', '#', '@'])
    {
        return Err(ConfigError::Endpoint);
    }
    let (scheme, rest) = text.split_once("://").ok_or(ConfigError::Endpoint)?;
    let host = host_of(rest.split('/').next().unwrap_or_default());
    if host.is_empty() {
        return Err(ConfigError::Endpoint);
    }
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
    match scheme {
        "https" => Ok(text.to_owned()),
        "http" if loopback => Ok(text.to_owned()),
        _ => Err(ConfigError::Endpoint),
    }
}

/// The host of an authority: the bracketed address of an IPv6 literal, or the
/// name before the port.
fn host_of(authority: &str) -> &str {
    if authority.starts_with('[') {
        authority
            .find(']')
            .map_or(authority, |end| &authority[..=end])
    } else {
        authority.split(':').next().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_need_https_or_a_loopback_http_host() {
        assert_eq!(
            check_endpoint("https://ai-gateway.vercel.sh/v1/").as_deref(),
            Ok("https://ai-gateway.vercel.sh/v1")
        );
        assert!(check_endpoint("http://127.0.0.1:8080/v1").is_ok());
        assert!(check_endpoint("http://localhost/x").is_ok());
        assert!(check_endpoint("http://[::1]:9/x").is_ok());
        for bad in [
            "http://example.com/v1",
            "ftp://example.com",
            "https://",
            "https://user:pw@example.com/v1",
            "https://example.com/v1?key=1",
            "https://example.com/v1#frag",
            "example.com/v1",
            "https://exa mple.com",
            "",
            "https://example.com/\u{7}",
        ] {
            assert_eq!(check_endpoint(bad), Err(ConfigError::Endpoint), "{bad}");
        }
    }

    #[test]
    fn model_names_use_the_allowed_characters_only() {
        assert!(check_model("typesafe-ai/jev").is_ok());
        assert!(check_model("vendor/model-3.5_mini:beta@1").is_ok());
        assert_eq!(check_model("a b"), Err(ConfigError::Model));
        assert_eq!(check_model("a;drop"), Err(ConfigError::Model));
        assert_eq!(
            check_model(&"a".repeat(MODEL_MAX_BYTES + 1)),
            Err(ConfigError::Model)
        );
    }

    #[test]
    fn timeouts_stay_in_their_ranges() {
        assert_eq!(
            JevSpec::new(JevRoute::Gateway, None, None, 99),
            Err(ConfigError::Timeout)
        );
        assert!(JevSpec::new(JevRoute::Gateway, None, None, 30_000).is_ok());
        assert_eq!(
            AgentSpec::new(AgentProvider::Gateway, None, None, 4_999, false),
            Err(ConfigError::Timeout)
        );
        assert!(AgentSpec::new(AgentProvider::Gateway, None, None, 120_000, false).is_ok());
    }

    #[test]
    fn keys_are_trimmed_and_never_printed() {
        let key = ApiKey::new("  sk-live-a91f  ").expect("valid key");
        assert_eq!(key.expose(), "sk-live-a91f");
        assert_eq!(key.last4(), "a91f");
        assert_eq!(format!("{key:?}"), "ApiKey(<redacted>)");
        assert_eq!(ApiKey::new("two words").err(), Some(ConfigError::Key));
        assert_eq!(ApiKey::new("   ").err(), Some(ConfigError::Key));
        assert_eq!(ApiKey::new("tab\tkey").err(), Some(ConfigError::Key));
    }

    #[test]
    fn preset_routes_take_their_address_and_model_from_the_route() {
        let gateway = JevSpec::new(
            JevRoute::Gateway,
            Some("https://evil.example/x"),
            None,
            2_000,
        )
        .expect("gateway");
        assert_eq!(gateway.endpoint(), GATEWAY_JEV_ENDPOINT);
        assert_eq!(gateway.model(), GATEWAY_JEV_MODEL);
        let direct = JevSpec::new(JevRoute::Direct, None, Some("jev-next"), 2_000).expect("direct");
        assert_eq!(direct.endpoint(), DIRECT_JEV_ENDPOINT);
        assert_eq!(direct.model(), "jev-next");
    }

    #[test]
    fn custom_jev_needs_an_address_and_a_model() {
        assert_eq!(
            JevSpec::new(JevRoute::Custom, None, Some("m"), 2_000),
            Err(ConfigError::Endpoint)
        );
        assert_eq!(
            JevSpec::new(
                JevRoute::Custom,
                Some("https://jev.internal:8443/v1/systemone"),
                None,
                2_000
            ),
            Err(ConfigError::Model)
        );
        let custom = JevSpec::new(
            JevRoute::Custom,
            Some("https://jev.internal:8443/v1/systemone"),
            Some("jev-private"),
            2_000,
        )
        .expect("custom");
        assert_eq!(custom.endpoint(), "https://jev.internal:8443/v1/systemone");
        assert_eq!(custom.model(), "jev-private");
    }

    #[test]
    fn the_agent_shares_a_key_only_between_two_gateways() {
        let jev = JevSpec::new(JevRoute::Gateway, None, None, 2_000).expect("jev");
        let agent =
            AgentSpec::new(AgentProvider::Gateway, None, Some("x/y"), 30_000, true).expect("agent");
        assert!(agent.check_share(&jev).is_ok());
        let direct = JevSpec::new(JevRoute::Direct, None, None, 2_000).expect("direct");
        assert_eq!(agent.check_share(&direct), Err(ConfigError::Share));
        let custom_agent = AgentSpec::new(
            AgentProvider::Custom,
            Some("https://llm.internal/v1"),
            Some("x/y"),
            30_000,
            true,
        )
        .expect("custom agent");
        assert_eq!(custom_agent.check_share(&jev), Err(ConfigError::Share));
    }

    #[test]
    fn the_agent_calls_chat_completions_under_its_base_address() {
        let endpoint = ModelEndpoint {
            base_url: GATEWAY_AGENT_ENDPOINT.to_owned(),
            model: "x/y".to_owned(),
            api_key: ApiKey::new("k1234").expect("key"),
            timeout_ms: AGENT_TIMEOUT_MS,
        };
        assert_eq!(
            endpoint.chat_completions_url(),
            "https://ai-gateway.vercel.sh/v1/chat/completions"
        );
    }

    #[test]
    fn changed_fields_lists_only_what_differs() {
        let before = JevSpec::new(JevRoute::Gateway, None, None, 2_000).expect("before");
        let after =
            JevSpec::new(JevRoute::Gateway, None, Some("typesafe-ai/jev-2"), 2_000).expect("after");
        let changes = changed_fields(&before.values(), &after.values());
        assert_eq!(
            changes,
            vec![FieldChange {
                field: "model",
                from: GATEWAY_JEV_MODEL.to_owned(),
                to: "typesafe-ai/jev-2".to_owned(),
            }]
        );
        assert_eq!(changed_fields(&[], &after.values()).len(), 4);
    }
}
