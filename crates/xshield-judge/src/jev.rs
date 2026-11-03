//! The Jev HTTP client (docs/02 sections 2.1 and 2.5), the settings it is built
//! from, and the slot the gateway judges with.
//!
//! One bounded POST per judgement. Requests carry the Bearer key; the key and
//! response bodies have no `Debug` output. Redirects are never followed.
//! Settings come from the console's model page (`xshield-postgres`
//! `model_config_store`) and fall back to the environment (docs/03 section 3.3).

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Uri, Version, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::Client, client::legacy::connect::HttpConnector, rt::TokioExecutor,
};
use xshield_core::model::{
    ApiKey, ConfigError, GATEWAY_JEV_MODEL, JEV_TIMEOUT_MS, JevRoute, JevSpec,
};
use zeroize::Zeroizing;

use crate::state::RESPONSE_BYTES_MAX;

/// Default time allowed for one Jev call when no settings are loaded (docs/02 section 2.5).
pub const TIMEOUT: Duration = Duration::from_secs(2);
/// Most bytes of a provider reply kept in the decision log (docs/07 section 7.5.1).
pub const REPLY_BYTES_MAX: usize = 8 * 1024;

/// Why a Jev call produced no usable body. The network detail stays out; the
/// provider's own reply to a refused call is kept, capped, for the trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JevFailure {
    /// The deadline passed.
    Timeout,
    /// The provider answered 429, with the start of its reply.
    RateLimited {
        /// The reply body, at most [`REPLY_BYTES_MAX`] bytes.
        body: Vec<u8>,
    },
    /// Connection, TLS or protocol failure.
    Transport,
    /// A non-200 status other than 429, with the start of its reply.
    Http {
        /// The status the provider answered.
        status: u16,
        /// The reply body, at most [`REPLY_BYTES_MAX`] bytes.
        body: Vec<u8>,
    },
    /// The response exceeded the size limit.
    TooLarge,
    /// No settings are loaded: neither the console nor the environment holds a usable
    /// configuration. No call is made.
    NotConfigured,
}

/// The stable code of a failure, as the decision log and the console show it.
#[must_use]
pub fn failure_code(failure: &JevFailure) -> &'static str {
    match failure {
        JevFailure::Timeout => "JEV_TIMEOUT",
        JevFailure::RateLimited { .. } => "JEV_RATE_LIMITED",
        JevFailure::Transport => "JEV_TRANSPORT",
        JevFailure::Http { .. } => "JEV_HTTP_ERROR",
        JevFailure::TooLarge => "JEV_RESPONSE_TOO_LARGE",
        JevFailure::NotConfigured => "JEV_NOT_CONFIGURED",
    }
}

/// Configuration errors, as stable codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JevConfigError {
    /// `XSHIELD_JEV_ROUTE` is neither `gateway` nor `direct`.
    Route,
    /// The API key is missing or not a plain header-safe token.
    Key,
    /// The endpoint is not https (or loopback http) with a host.
    Endpoint,
    /// `XSHIELD_JEV_TIMEOUT_MS` is not a number between 100 and 30000.
    Timeout,
    /// The model name is missing or not allowed.
    Model,
}

impl std::fmt::Display for JevConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Route => "JEV_CONFIG_ROUTE_INVALID",
            Self::Key => "JEV_CONFIG_KEY_INVALID",
            Self::Endpoint => "JEV_CONFIG_ENDPOINT_INVALID",
            Self::Timeout => "JEV_CONFIG_TIMEOUT_INVALID",
            Self::Model => "JEV_CONFIG_MODEL_INVALID",
        })
    }
}

impl std::error::Error for JevConfigError {}

fn config_error(error: ConfigError) -> JevConfigError {
    match error {
        ConfigError::Route | ConfigError::Provider => JevConfigError::Route,
        ConfigError::Endpoint => JevConfigError::Endpoint,
        ConfigError::Model => JevConfigError::Model,
        ConfigError::Timeout => JevConfigError::Timeout,
        ConfigError::Key | ConfigError::Share => JevConfigError::Key,
    }
}

/// Sends one prepared request body and returns the response body.
#[async_trait]
pub trait JevPort: Send + Sync {
    /// The wire model name in the request. Empty while nothing is loaded.
    fn model(&self) -> String;
    /// The route the calls take: `gateway`, `direct`, `custom`, or `none` while
    /// nothing is loaded.
    fn route(&self) -> String;
    /// The full address calls go to, without any key. Empty while nothing is loaded.
    fn endpoint(&self) -> String;
    /// The host name of the endpoint, for the console's configuration view.
    fn endpoint_host(&self) -> String;
    /// The timeout a site gets when its `advanced` section sets none.
    fn default_timeout(&self) -> Duration;
    /// Performs the exchange within `timeout`.
    async fn ask(&self, body: Vec<u8>, timeout: Duration) -> Result<Vec<u8>, JevFailure>;
}

type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// The HTTPS client for model calls. One connection pool serves every call made
/// through it.
pub struct Transport {
    client: HttpClient,
}

impl Transport {
    /// Builds the client with the bundled web PKI roots.
    #[must_use]
    pub fn new() -> Self {
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
        }
    }

    /// POSTs `body` as JSON to `endpoint` with `api_key` as a Bearer token, and
    /// returns the reply's body. Redirects are not followed. The caller applies the
    /// deadline.
    ///
    /// # Errors
    /// [`JevFailure`] for transport failures, refused statuses and oversized replies.
    pub async fn post(
        &self,
        endpoint: &Uri,
        api_key: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, JevFailure> {
        let bearer = Zeroizing::new(format!("Bearer {api_key}"));
        let mut authorization =
            HeaderValue::from_str(&bearer).map_err(|_| JevFailure::Transport)?;
        authorization.set_sensitive(true);
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri(endpoint.clone())
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| JevFailure::Transport)?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|_| JevFailure::Transport)?;
        let status = response.status().as_u16();
        let mut incoming = response.into_body();
        if status != 200 {
            // The start of a refused reply is evidence for the trace; a reply
            // that cannot be read adds nothing and keeps its status.
            let (body, _) = read_capped(&mut incoming, REPLY_BYTES_MAX)
                .await
                .unwrap_or_default();
            return Err(match status {
                429 => JevFailure::RateLimited { body },
                other => JevFailure::Http {
                    status: other,
                    body,
                },
            });
        }
        let (body, overflow) = read_capped(&mut incoming, RESPONSE_BYTES_MAX).await?;
        if overflow {
            return Err(JevFailure::TooLarge);
        }
        Ok(body)
    }
}

impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}

/// The production client: one endpoint, one key, one model.
pub struct JevClient {
    transport: Transport,
    endpoint: Uri,
    endpoint_text: String,
    host: String,
    api_key: Zeroizing<String>,
    model: String,
    route: &'static str,
    timeout: Duration,
}

impl JevClient {
    /// Builds a client from explicit settings.
    ///
    /// # Errors
    /// [`JevConfigError`] for a bad key, endpoint, model or timeout.
    pub fn new(
        endpoint: &str,
        api_key: &str,
        model: &str,
        timeout: Duration,
    ) -> Result<Self, JevConfigError> {
        if api_key.is_empty() || !api_key.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(JevConfigError::Key);
        }
        let uri: Uri = endpoint.parse().map_err(|_| JevConfigError::Endpoint)?;
        let host = uri.host().ok_or(JevConfigError::Endpoint)?;
        let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
        let scheme_ok = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => loopback,
            _ => false,
        };
        if !scheme_ok
            || uri.authority().is_some_and(|a| a.as_str().contains('@'))
            || timeout.is_zero()
            || model.is_empty()
        {
            return Err(JevConfigError::Endpoint);
        }
        Ok(Self {
            transport: Transport::new(),
            host: host.to_owned(),
            endpoint_text: endpoint.to_owned(),
            endpoint: uri,
            api_key: Zeroizing::new(api_key.to_owned()),
            model: model.to_owned(),
            route: "custom",
            timeout,
        })
    }

    /// Builds a client from checked settings and the key that goes with them.
    ///
    /// # Errors
    /// [`JevConfigError`] when the endpoint cannot be used as a call target.
    pub fn from_spec(spec: &JevSpec, api_key: &ApiKey) -> Result<Self, JevConfigError> {
        let mut client = Self::new(
            spec.endpoint(),
            api_key.expose(),
            spec.model(),
            Duration::from_millis(u64::from(spec.timeout_ms())),
        )?;
        client.route = spec.route().as_str();
        Ok(client)
    }

    /// Builds a client from the environment alone (the live tests use it). Use
    /// [`environment_settings`] when the console may hold the settings instead.
    ///
    /// # Errors
    /// [`JevConfigError::Key`] when the environment names no key, or the error of
    /// the settings it does name.
    pub fn from_environment() -> Result<Self, JevConfigError> {
        match environment_settings().loaded? {
            Some((spec, key)) => Self::from_spec(&spec, &key),
            None => Err(JevConfigError::Key),
        }
    }
}

/// Reads at most `limit` bytes of a body; `true` when more followed.
async fn read_capped(
    incoming: &mut hyper::body::Incoming,
    limit: usize,
) -> Result<(Vec<u8>, bool), JevFailure> {
    let mut out = Vec::new();
    while let Some(frame) = incoming.frame().await {
        let frame = frame.map_err(|_| JevFailure::Transport)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if out.len() + data.len() > limit {
            out.extend_from_slice(&data[..limit - out.len()]);
            return Ok((out, true));
        }
        out.extend_from_slice(&data);
    }
    Ok((out, false))
}

#[async_trait]
impl JevPort for JevClient {
    fn model(&self) -> String {
        self.model.clone()
    }

    fn route(&self) -> String {
        self.route.to_owned()
    }

    fn endpoint(&self) -> String {
        self.endpoint_text.clone()
    }

    fn endpoint_host(&self) -> String {
        self.host.clone()
    }

    fn default_timeout(&self) -> Duration {
        self.timeout
    }

    async fn ask(&self, body: Vec<u8>, timeout: Duration) -> Result<Vec<u8>, JevFailure> {
        tokio::time::timeout(
            timeout,
            self.transport.post(&self.endpoint, &self.api_key, body),
        )
        .await
        .unwrap_or(Err(JevFailure::Timeout))
    }
}

/// What the environment says about Jev (docs/03 section 3.3). Read once, at start-up,
/// and used only while the console holds no key for Jev.
#[derive(Debug)]
pub struct EnvSettings {
    /// The settings and the key, when the environment names a key. `None` when it
    /// does not; an error when a variable is malformed.
    pub loaded: Result<Option<(JevSpec, ApiKey)>, JevConfigError>,
    /// The key variable of the route in use, by name, if the route is known.
    pub key_var: Option<&'static str>,
    /// The Jev variables that are set, by name. Never their values.
    pub present: Vec<&'static str>,
}

/// The Jev variables the environment fallback reads.
pub const ENV_VARS: [&str; 6] = [
    "XSHIELD_JEV_ROUTE",
    "AI_GATEWAY_API_KEY",
    "XSHIELD_JEV_API_KEY",
    "XSHIELD_JEV_ENDPOINT",
    "XSHIELD_JEV_MODEL",
    "XSHIELD_JEV_TIMEOUT_MS",
];

/// Reads the Jev variables of the process environment.
#[must_use]
pub fn environment_settings() -> EnvSettings {
    environment_settings_from(|name| std::env::var(name).ok())
}

/// Reads the Jev variables through `lookup`. `XSHIELD_JEV_ROUTE` picks the route
/// (`gateway` by default, or `direct`), which names the key variable
/// (`AI_GATEWAY_API_KEY` or `XSHIELD_JEV_API_KEY`). `XSHIELD_JEV_ENDPOINT` makes the
/// route `custom`. `XSHIELD_JEV_MODEL` and `XSHIELD_JEV_TIMEOUT_MS` override the
/// defaults.
#[must_use]
pub fn environment_settings_from(lookup: impl Fn(&str) -> Option<String>) -> EnvSettings {
    let present = ENV_VARS
        .iter()
        .copied()
        .filter(|name| lookup(name).is_some())
        .collect();
    let (route, key_var) = match lookup("XSHIELD_JEV_ROUTE").as_deref().unwrap_or("gateway") {
        "gateway" => (Some(JevRoute::Gateway), Some("AI_GATEWAY_API_KEY")),
        "direct" => (Some(JevRoute::Direct), Some("XSHIELD_JEV_API_KEY")),
        _ => (None, None),
    };
    let loaded = match route {
        Some(route) => read_environment(&lookup, route, key_var.unwrap_or_default()),
        None => Err(JevConfigError::Route),
    };
    EnvSettings {
        loaded,
        key_var,
        present,
    }
}

fn read_environment(
    lookup: &impl Fn(&str) -> Option<String>,
    route: JevRoute,
    key_var: &str,
) -> Result<Option<(JevSpec, ApiKey)>, JevConfigError> {
    let Some(key_text) = lookup(key_var) else {
        return Ok(None);
    };
    let key = ApiKey::new(&key_text).map_err(config_error)?;
    let endpoint = lookup("XSHIELD_JEV_ENDPOINT");
    let route = if endpoint.is_some() {
        JevRoute::Custom
    } else {
        route
    };
    let model = match (route, lookup("XSHIELD_JEV_MODEL")) {
        (JevRoute::Custom, None) => Some(GATEWAY_JEV_MODEL.to_owned()),
        (_, model) => model,
    };
    let timeout = match lookup("XSHIELD_JEV_TIMEOUT_MS") {
        Some(text) => text.parse::<u32>().map_err(|_| JevConfigError::Timeout)?,
        None => JEV_TIMEOUT_MS,
    };
    let spec = JevSpec::new(route, endpoint.as_deref(), model.as_deref(), timeout)
        .map_err(config_error)?;
    Ok(Some((spec, key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve(
        reply: &'static str,
        delay: Duration,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = socket.read(&mut chunk).await.unwrap();
                seen.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&seen);
                if let Some(split) = text.find("\r\n\r\n") {
                    let length = text[..split]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if seen.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            tokio::time::sleep(delay).await;
            socket.write_all(reply.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&seen).into_owned()
        });
        (url, task)
    }

    fn client(url: &str, timeout: Duration) -> JevClient {
        JevClient::new(url, "secret-key", "m", timeout).unwrap()
    }

    #[tokio::test]
    async fn posts_the_body_with_bearer_and_returns_the_reply() {
        let (url, task) = serve(
            "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
            Duration::ZERO,
        )
        .await;
        let reply = client(&url, Duration::from_secs(2))
            .ask(b"{\"q\":1}".to_vec(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(reply, b"{}");
        let request = task.await.unwrap();
        assert!(request.starts_with("POST /v1/systemone HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer secret-key")
        );
        assert!(request.ends_with("{\"q\":1}"));
    }

    #[tokio::test]
    async fn failures_are_mapped() {
        for (reply, expected) in [
            (
                "HTTP/1.1 429 Too Many\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                JevFailure::RateLimited { body: vec![] },
            ),
            (
                "HTTP/1.1 500 Err\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                JevFailure::Http {
                    status: 500,
                    body: vec![],
                },
            ),
            (
                "HTTP/1.1 302 Found\r\nlocation: http://evil/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                JevFailure::Http {
                    status: 302,
                    body: vec![],
                },
            ),
        ] {
            let (url, _task) = serve(reply, Duration::ZERO).await;
            assert_eq!(
                client(&url, Duration::from_secs(2))
                    .ask(vec![], Duration::from_secs(2))
                    .await
                    .unwrap_err(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn slow_providers_time_out() {
        let (url, _task) = serve(
            "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(
            client(&url, Duration::from_secs(2))
                .ask(vec![], Duration::from_millis(100))
                .await
                .unwrap_err(),
            JevFailure::Timeout
        );
    }

    #[tokio::test]
    async fn unreachable_providers_are_transport_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
        drop(listener);
        assert_eq!(
            client(&url, Duration::from_secs(2))
                .ask(vec![], Duration::from_secs(2))
                .await
                .unwrap_err(),
            JevFailure::Transport
        );
    }

    #[test]
    fn endpoints_and_keys_are_validated() {
        let key = || "k";
        for endpoint in [
            "http://example.com/x",
            "ftp://x/y",
            "https://user@h/x",
            "not a url",
            "/relative",
        ] {
            assert_eq!(
                JevClient::new(endpoint, key(), "m", TIMEOUT).err(),
                Some(JevConfigError::Endpoint),
                "{endpoint}"
            );
        }
        assert!(
            JevClient::new(
                "https://jev.internal:8443/v1/systemone",
                key(),
                "m",
                TIMEOUT
            )
            .is_ok()
        );
        assert!(JevClient::new("http://127.0.0.1:9/x", key(), "m", TIMEOUT).is_ok());
        assert_eq!(
            JevClient::new("https://h/x", "", "m", TIMEOUT).err(),
            Some(JevConfigError::Key)
        );
        assert_eq!(
            JevClient::new("https://h/x", "a b", "m", TIMEOUT).err(),
            Some(JevConfigError::Key)
        );
        assert_eq!(
            JevClient::new("https://h/x", key(), "m", Duration::ZERO).err(),
            Some(JevConfigError::Endpoint)
        );
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        move |name: &str| {
            owned
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn no_key_in_the_environment_means_not_configured_not_an_error() {
        let settings = environment_settings_from(env(&[]));
        assert!(matches!(settings.loaded, Ok(None)));
        assert_eq!(settings.key_var, Some("AI_GATEWAY_API_KEY"));
        assert!(settings.present.is_empty());
    }

    #[test]
    fn the_gateway_route_is_the_default_and_takes_its_key_from_its_variable() {
        let settings = environment_settings_from(env(&[("AI_GATEWAY_API_KEY", "sk-gw-1234")]));
        let (spec, key) = settings.loaded.expect("loads").expect("configured");
        assert_eq!(spec.route(), JevRoute::Gateway);
        assert_eq!(spec.endpoint(), xshield_core::model::GATEWAY_JEV_ENDPOINT);
        assert_eq!(spec.model(), GATEWAY_JEV_MODEL);
        assert_eq!(spec.timeout_ms(), JEV_TIMEOUT_MS);
        assert_eq!(key.last4(), "1234");
        assert_eq!(settings.present, vec!["AI_GATEWAY_API_KEY"]);
    }

    #[test]
    fn an_endpoint_variable_makes_the_route_custom_and_keeps_the_gateway_model() {
        let settings = environment_settings_from(env(&[
            ("AI_GATEWAY_API_KEY", "sk-gw-1234"),
            (
                "XSHIELD_JEV_ENDPOINT",
                "https://jev.internal:8443/v1/systemone",
            ),
            ("XSHIELD_JEV_TIMEOUT_MS", "5000"),
        ]));
        let (spec, _) = settings.loaded.expect("loads").expect("configured");
        assert_eq!(spec.route(), JevRoute::Custom);
        assert_eq!(spec.model(), GATEWAY_JEV_MODEL);
        assert_eq!(spec.timeout_ms(), 5_000);
    }

    #[test]
    fn malformed_variables_are_reported_by_code() {
        assert!(matches!(
            environment_settings_from(env(&[("XSHIELD_JEV_ROUTE", "sideways")])).loaded,
            Err(JevConfigError::Route)
        ));
        assert!(matches!(
            environment_settings_from(env(&[
                ("AI_GATEWAY_API_KEY", "sk-gw-1234"),
                ("XSHIELD_JEV_TIMEOUT_MS", "5")
            ]))
            .loaded,
            Err(JevConfigError::Timeout)
        ));
    }

    #[test]
    fn the_direct_route_reads_its_own_key_variable() {
        let settings = environment_settings_from(env(&[
            ("XSHIELD_JEV_ROUTE", "direct"),
            ("AI_GATEWAY_API_KEY", "sk-gw-1234"),
            ("XSHIELD_JEV_API_KEY", "sk-direct-9999"),
        ]));
        assert_eq!(settings.key_var, Some("XSHIELD_JEV_API_KEY"));
        let (spec, key) = settings.loaded.expect("loads").expect("configured");
        assert_eq!(spec.route(), JevRoute::Direct);
        assert_eq!(key.last4(), "9999");
    }

    #[test]
    fn a_not_configured_failure_has_its_own_code() {
        assert_eq!(
            failure_code(&JevFailure::NotConfigured),
            "JEV_NOT_CONFIGURED"
        );
        assert_eq!(failure_code(&JevFailure::Timeout), "JEV_TIMEOUT");
    }
}
