//! The Jev HTTP client (docs/02 sections 2.1 and 2.5).
//!
//! One bounded POST per judgement. Requests carry the Bearer key; the key and
//! response bodies have no `Debug` output. Redirects are never followed.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Uri, Version, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::Client, client::legacy::connect::HttpConnector, rt::TokioExecutor,
};
use zeroize::Zeroizing;

use crate::state::RESPONSE_BYTES_MAX;

/// Wire model behind the Vercel AI Gateway route (the default).
pub const GATEWAY_MODEL: &str = "typesafe-ai/jev";
/// Wire model of the direct `TypeSafe` route.
pub const DIRECT_MODEL: &str = "jev-1.13.0";
const GATEWAY_ENDPOINT: &str = "https://ai-gateway.vercel.sh/typesafe/v1/systemone";
const DIRECT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
/// Default time allowed for one Jev call (docs/02 section 2.5).
pub const TIMEOUT: Duration = Duration::from_secs(2);

/// Why a Jev call produced no usable body. Carries no network detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JevFailure {
    /// The deadline passed.
    Timeout,
    /// The provider answered 429.
    RateLimited,
    /// Connection, TLS or protocol failure.
    Transport,
    /// A non-200 status other than 429.
    Http(u16),
    /// The response exceeded the size limit.
    TooLarge,
}

/// Configuration errors, as stable codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JevConfigError {
    /// `XSHIELD_JEV_ROUTE` is neither `gateway` nor `direct`.
    Route,
    /// The API key variable is missing or not a plain header-safe token.
    Key,
    /// The endpoint is not https (or loopback http) with a host.
    Endpoint,
    /// `XSHIELD_JEV_TIMEOUT_MS` is not a number between 100 and 30000.
    Timeout,
}

impl std::fmt::Display for JevConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Route => "JEV_CONFIG_ROUTE_INVALID",
            Self::Key => "JEV_CONFIG_KEY_INVALID",
            Self::Endpoint => "JEV_CONFIG_ENDPOINT_INVALID",
            Self::Timeout => "JEV_CONFIG_TIMEOUT_INVALID",
        })
    }
}

impl std::error::Error for JevConfigError {}

/// Sends one prepared request body and returns the response body.
#[async_trait]
pub trait JevPort: Send + Sync {
    /// The wire model name to put in the request.
    fn model(&self) -> &str;
    /// Performs the exchange within the configured deadline.
    async fn ask(&self, body: Vec<u8>) -> Result<Vec<u8>, JevFailure>;
}

type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// The production client.
pub struct JevClient {
    client: HttpClient,
    endpoint: Uri,
    bearer: Zeroizing<String>,
    model: String,
    timeout: Duration,
}

impl JevClient {
    /// Builds a client from explicit settings.
    ///
    /// # Errors
    /// [`JevConfigError`] for a bad key or endpoint.
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
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            endpoint: uri,
            bearer: Zeroizing::new(format!("Bearer {api_key}")),
            model: model.to_owned(),
            timeout,
        })
    }

    /// Reads `XSHIELD_JEV_ROUTE` (`gateway` default, or `direct`), the matching
    /// key variable, and the optional `XSHIELD_JEV_ENDPOINT` / `XSHIELD_JEV_MODEL`
    /// overrides used for a private deployment, and `XSHIELD_JEV_TIMEOUT_MS`
    /// (100 to 30000, default 2000) for slow links.
    ///
    /// # Errors
    /// [`JevConfigError`] for an unknown route, missing key or bad endpoint.
    pub fn from_environment() -> Result<Self, JevConfigError> {
        let (default_endpoint, default_model, key_name) = match std::env::var("XSHIELD_JEV_ROUTE")
            .ok()
            .as_deref()
            .unwrap_or("gateway")
        {
            "gateway" => (GATEWAY_ENDPOINT, GATEWAY_MODEL, "AI_GATEWAY_API_KEY"),
            "direct" => (DIRECT_ENDPOINT, DIRECT_MODEL, "XSHIELD_JEV_API_KEY"),
            _ => return Err(JevConfigError::Route),
        };
        let key = Zeroizing::new(std::env::var(key_name).map_err(|_| JevConfigError::Key)?);
        let endpoint =
            std::env::var("XSHIELD_JEV_ENDPOINT").unwrap_or_else(|_| default_endpoint.to_owned());
        let model = std::env::var("XSHIELD_JEV_MODEL").unwrap_or_else(|_| default_model.to_owned());
        let timeout = match std::env::var("XSHIELD_JEV_TIMEOUT_MS") {
            Ok(text) => text
                .parse::<u64>()
                .ok()
                .filter(|millis| (100..=30_000).contains(millis))
                .map(Duration::from_millis)
                .ok_or(JevConfigError::Timeout)?,
            Err(_) => TIMEOUT,
        };
        Self::new(&endpoint, &key, &model, timeout)
    }

    async fn exchange(&self, body: Vec<u8>) -> Result<Vec<u8>, JevFailure> {
        let mut authorization =
            HeaderValue::from_str(&self.bearer).map_err(|_| JevFailure::Transport)?;
        authorization.set_sensitive(true);
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri(self.endpoint.clone())
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
        match response.status().as_u16() {
            200 => {}
            429 => return Err(JevFailure::RateLimited),
            other => return Err(JevFailure::Http(other)),
        }
        let mut incoming = response.into_body();
        let mut out = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| JevFailure::Transport)?;
            if let Ok(data) = frame.into_data() {
                if out.len() + data.len() > RESPONSE_BYTES_MAX {
                    return Err(JevFailure::TooLarge);
                }
                out.extend_from_slice(&data);
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl JevPort for JevClient {
    fn model(&self) -> &str {
        &self.model
    }

    async fn ask(&self, body: Vec<u8>) -> Result<Vec<u8>, JevFailure> {
        tokio::time::timeout(self.timeout, self.exchange(body))
            .await
            .unwrap_or(Err(JevFailure::Timeout))
    }
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
            .ask(b"{\"q\":1}".to_vec())
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
                JevFailure::RateLimited,
            ),
            (
                "HTTP/1.1 500 Err\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                JevFailure::Http(500),
            ),
            (
                "HTTP/1.1 302 Found\r\nlocation: http://evil/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                JevFailure::Http(302),
            ),
        ] {
            let (url, _task) = serve(reply, Duration::ZERO).await;
            assert_eq!(
                client(&url, Duration::from_secs(2))
                    .ask(vec![])
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
            client(&url, Duration::from_millis(100))
                .ask(vec![])
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
                .ask(vec![])
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
}
