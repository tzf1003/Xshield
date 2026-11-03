//! The learning agent's model: one OpenAI-compatible chat completions call per question.
//! Only the control plane calls it, and only from the learning pass; the gateway never
//! does. The key is sent as a bearer token and is never logged, printed or stored here.
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Uri, Version, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde_json::{Value, json};
use sqlx::PgPool;
use zeroize::Zeroizing;

/// Most bytes of a reply read. An answer is one small JSON object.
const REPLY_BYTES_MAX: usize = 64 * 1024;
/// Most tokens the model may write for one answer.
const MAX_TOKENS: u32 = 400;

/// Why a question got no answer from the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The model did not answer within the time allowed.
    Timeout,
    /// The call failed: a refused request, a bad reply or no connection. The text is a
    /// short reason for the console, such as `HTTP 401`, and never the reply itself.
    Failed(String),
}

/// The model a question is asked of.
#[async_trait]
pub trait AgentModel: Send + Sync {
    /// The model's name, for the record of each question.
    fn name(&self) -> &str;
    /// The model's reply to `user` under `system`.
    ///
    /// # Errors
    /// Returns [`CallError`] when no reply came back.
    async fn ask(&self, system: &str, user: &str) -> Result<String, CallError>;
}

type Http = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// An OpenAI-compatible chat completions endpoint.
pub struct ChatModel {
    client: Http,
    url: Uri,
    bearer: Zeroizing<String>,
    name: String,
    timeout: Duration,
}

impl ChatModel {
    /// Builds the client for `base_url` (the origin and any path prefix, including its
    /// `/v1`), the model's name and the key. The endpoint must be `https`, or `http` to a
    /// loopback host, and carry no user information.
    ///
    /// # Errors
    /// Returns a reason when the endpoint, the key, the name or the timeout is unusable.
    #[expect(
        dead_code,
        reason = "built once the model configuration is read from the store"
    )]
    pub fn new(
        base_url: &str,
        api_key: &str,
        name: &str,
        timeout: Duration,
    ) -> Result<Self, &'static str> {
        if api_key.is_empty() || !api_key.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err("the key is not usable");
        }
        if name.is_empty() || timeout.is_zero() {
            return Err("the model or the timeout is not usable");
        }
        let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
        let uri: Uri = url.parse().map_err(|_| "the endpoint is not a URL")?;
        let host = uri.host().ok_or("the endpoint has no host")?;
        let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
        let scheme_ok = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => loopback,
            _ => false,
        };
        if !scheme_ok
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err("the endpoint must be https");
        }
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            url: uri,
            bearer: Zeroizing::new(format!("Bearer {api_key}")),
            name: name.to_owned(),
            timeout,
        })
    }

    async fn exchange(&self, body: Vec<u8>) -> Result<String, CallError> {
        let mut authorization = HeaderValue::from_str(&self.bearer)
            .map_err(|_| CallError::Failed("the key is not usable".to_owned()))?;
        authorization.set_sensitive(true);
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri(self.url.clone())
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| CallError::Failed("the request could not be built".to_owned()))?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|_| CallError::Failed("no connection".to_owned()))?;
        let status = response.status().as_u16();
        let mut incoming = response.into_body();
        if status != 200 {
            return Err(CallError::Failed(format!("HTTP {status}")));
        }
        let mut reply = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| CallError::Failed("the reply broke off".to_owned()))?;
            if let Ok(data) = frame.into_data() {
                if reply.len() + data.len() > REPLY_BYTES_MAX {
                    return Err(CallError::Failed("the reply is too large".to_owned()));
                }
                reply.extend_from_slice(&data);
            }
        }
        let value: Value = serde_json::from_slice(&reply)
            .map_err(|_| CallError::Failed("the reply is not JSON".to_owned()))?;
        value
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| CallError::Failed("the reply has no message".to_owned()))
    }
}

#[async_trait]
impl AgentModel for ChatModel {
    fn name(&self) -> &str {
        &self.name
    }

    async fn ask(&self, system: &str, user: &str) -> Result<String, CallError> {
        let body = json!({
            "model": self.name,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
            "max_tokens": MAX_TOKENS,
            "stream": false,
        });
        let bytes = serde_json::to_vec(&body)
            .map_err(|_| CallError::Failed("the request could not be encoded".to_owned()))?;
        tokio::time::timeout(self.timeout, self.exchange(bytes))
            .await
            .unwrap_or(Err(CallError::Timeout))
    }
}

/// The learning agent's model as the console configured it, when one is configured and
/// usable. The configuration is read from the control plane's store, so the pass never
/// depends on environment variables.
#[expect(
    clippy::unused_async,
    reason = "reads the store once the model configuration lands"
)]
pub async fn configured(_pool: &PgPool) -> Option<ChatModel> {
    None
}
