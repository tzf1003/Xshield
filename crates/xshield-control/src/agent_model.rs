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
use xshield_core::model::ModelEndpoint;
use xshield_postgres::key_seal::KeySealer;
use xshield_postgres::model_config_store::{self, ModelConfigError};
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
        if uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err("the endpoint carries user information");
        }
        if !scheme_ok {
            return Err("the endpoint must be https, or http to a loopback host");
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
/// depends on environment variables. A key that is stored but cannot be opened counts as
/// not configured, as does a store that cannot be read; the models page reports both.
pub async fn configured(pool: &PgPool, sealer: Option<&KeySealer>) -> Option<ChatModel> {
    match model_config_store::load_agent(pool, sealer).await {
        Ok(Some(endpoint)) => model_of(&endpoint),
        Ok(None) | Err(ModelConfigError::KeyUnavailable | ModelConfigError::KeyUnreadable) => None,
        Err(error) => {
            eprintln!("xshield-control: reading the learning agent's model failed: {error}");
            None
        }
    }
}

/// The client for one stored endpoint, or `None` when the stored values are not usable.
fn model_of(endpoint: &ModelEndpoint) -> Option<ChatModel> {
    let timeout = Duration::from_millis(u64::from(endpoint.timeout_ms));
    match ChatModel::new(
        &endpoint.base_url,
        endpoint.api_key.expose(),
        &endpoint.model,
        timeout,
    ) {
        Ok(model) => Some(model),
        Err(reason) => {
            eprintln!("xshield-control: the learning agent's model is not usable: {reason}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };
    use xshield_core::model::ApiKey;

    use super::*;

    const ANSWER: &str = r#"{"choice":"existing","confidence":90}"#;

    /// The offset of the blank line that ends a request or response head.
    fn head_end(raw: &[u8]) -> Option<usize> {
        raw.windows(4).position(|window| window == b"\r\n\r\n")
    }

    /// Reads one request: its head, then the body that the head's `Content-Length` names.
    async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut raw = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await.unwrap_or(0);
            if read == 0 {
                return raw;
            }
            raw.extend_from_slice(&chunk[..read]);
            if let Some(end) = head_end(&raw) {
                let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                let body_len = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if raw.len() >= end + 4 + body_len {
                    return raw;
                }
            }
        }
    }

    /// A fake endpoint on a loopback port. It answers the first request with `status` and
    /// `body`, and sends back the raw request it read.
    async fn serve(status: StatusCode, body: Vec<u8>) -> (String, oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        let (sent, received) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = sent.send(read_request(&mut stream).await);
            let head = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status.as_str(),
                status.canonical_reason().unwrap_or(""),
                body.len(),
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.shutdown().await;
        });
        (base, received)
    }

    /// A fake endpoint that reads the request and never answers.
    async fn serve_silently() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut stream).await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        base
    }

    /// Splits a raw request into its head and its JSON body.
    fn split(raw: &[u8]) -> (String, Value) {
        let end = head_end(raw).unwrap();
        let body = serde_json::from_slice(&raw[end + 4..]).unwrap();
        (String::from_utf8_lossy(&raw[..end]).into_owned(), body)
    }

    fn model(base: &str, timeout: Duration) -> ChatModel {
        ChatModel::new(base, "test-key", "test-model", timeout).unwrap()
    }

    fn failed(reason: &str) -> Result<String, CallError> {
        Err(CallError::Failed(reason.to_owned()))
    }

    #[tokio::test]
    async fn posts_the_question_and_returns_the_answer() {
        let reply = json!({"choices": [{"message": {"role": "assistant", "content": ANSWER}}]});
        let (base, request) = serve(StatusCode::OK, reply.to_string().into_bytes()).await;

        let got = model(&base, Duration::from_secs(5))
            .ask("the system words", "the user words")
            .await;

        assert_eq!(got, Ok(ANSWER.to_owned()));
        let (head, body) = split(&request.await.unwrap());
        assert_eq!(
            head.lines().next(),
            Some("POST /v1/chat/completions HTTP/1.1")
        );
        let authorization = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_owned())
        });
        assert_eq!(authorization.as_deref(), Some("Bearer test-key"));
        assert_eq!(body["model"], "test-model");
        assert_eq!(
            body["messages"][0],
            json!({"role": "system", "content": "the system words"})
        );
        assert_eq!(
            body["messages"][1],
            json!({"role": "user", "content": "the user words"})
        );
        assert_eq!(body["response_format"], json!({"type": "json_object"}));
        assert_eq!(body["temperature"], 0);
        assert_eq!(body["max_tokens"], 400);
        assert_eq!(body["stream"], json!(false));
    }

    #[tokio::test]
    async fn refuses_an_answer_with_another_status() {
        let (base, _) = serve(StatusCode::UNAUTHORIZED, b"{}".to_vec()).await;

        let got = model(&base, Duration::from_secs(5)).ask("s", "u").await;

        assert_eq!(got, failed("HTTP 401"));
    }

    #[tokio::test]
    async fn refuses_a_reply_that_is_not_json() {
        let (base, _) = serve(StatusCode::OK, b"<html>".to_vec()).await;

        let got = model(&base, Duration::from_secs(5)).ask("s", "u").await;

        assert_eq!(got, failed("the reply is not JSON"));
    }

    #[tokio::test]
    async fn refuses_a_reply_without_a_message() {
        let (base, _) = serve(StatusCode::OK, br#"{"choices":[]}"#.to_vec()).await;

        let got = model(&base, Duration::from_secs(5)).ask("s", "u").await;

        assert_eq!(got, failed("the reply has no message"));
    }

    #[tokio::test]
    async fn refuses_a_reply_over_the_size_limit() {
        let (base, _) = serve(StatusCode::OK, vec![b' '; REPLY_BYTES_MAX + 1]).await;

        let got = model(&base, Duration::from_secs(5)).ask("s", "u").await;

        assert_eq!(got, failed("the reply is too large"));
    }

    #[tokio::test]
    async fn gives_up_when_the_answer_is_late() {
        let base = serve_silently().await;

        let got = model(&base, Duration::from_millis(200)).ask("s", "u").await;

        assert_eq!(got, Err(CallError::Timeout));
    }

    #[tokio::test]
    async fn reports_no_connection_when_nothing_listens() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        drop(listener);

        let got = model(&base, Duration::from_secs(5)).ask("s", "u").await;

        assert_eq!(got, failed("no connection"));
    }

    #[test]
    fn refuses_an_endpoint_key_or_name_that_is_not_usable() {
        let one_second = Duration::from_secs(1);
        let refusal = |base: &str, key: &str, name: &str, timeout: Duration| {
            ChatModel::new(base, key, name, timeout).err()
        };

        assert!(ChatModel::new("https://example.com/v1", "key", "model", one_second).is_ok());
        assert!(ChatModel::new("http://localhost:8080/v1", "key", "model", one_second).is_ok());
        assert_eq!(
            refusal("http://example.com/v1", "key", "model", one_second),
            Some("the endpoint must be https, or http to a loopback host")
        );
        assert_eq!(
            refusal(
                "https://user:secret@example.com/v1",
                "key",
                "model",
                one_second
            ),
            Some("the endpoint carries user information")
        );
        assert_eq!(
            refusal("https://example.com/v1", "", "model", one_second),
            Some("the key is not usable")
        );
        assert_eq!(
            refusal("https://example.com/v1", "two words", "model", one_second),
            Some("the key is not usable")
        );
        assert_eq!(
            refusal("https://example.com/v1", "key", "", one_second),
            Some("the model or the timeout is not usable")
        );
        assert_eq!(
            refusal("https://example.com/v1", "key", "model", Duration::ZERO),
            Some("the model or the timeout is not usable")
        );
    }

    #[test]
    fn a_stored_endpoint_builds_the_client_and_an_unusable_one_does_not() {
        let endpoint = ModelEndpoint {
            base_url: "https://example.com/v1".to_owned(),
            model: "model".to_owned(),
            api_key: ApiKey::new("sk-test-key").expect("a printable key"),
            timeout_ms: 20_000,
        };
        assert!(model_of(&endpoint).is_some());
        let plain = ModelEndpoint {
            base_url: "http://example.com/v1".to_owned(),
            ..endpoint
        };
        assert!(model_of(&plain).is_none());
    }
}
