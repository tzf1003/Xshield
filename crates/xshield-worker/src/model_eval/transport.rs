//! Bounded Jev HTTP exchange. Only the caller's frozen payload crosses the
//! network boundary; returned bytes require the caller's evidence/audit barrier.

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Uri, Version, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::Client, client::legacy::connect::HttpConnector, rt::TokioExecutor,
};
use std::{future::Future, time::Duration};
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

pub(super) const DIRECT_MODEL: &str = "jev-1.13.0";
pub(super) const GATEWAY_MODEL: &str = "typesafe-ai/jev";
const DIRECT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
const GATEWAY_ENDPOINT: &str = "https://ai-gateway.vercel.sh/typesafe/v1/systemone";
const DEADLINE: Duration = Duration::from_secs(10);
const RESPONSE_LIMIT: usize = 65_536;
type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// One attempt's bounded raw response. Failure codes contain no network details.
/// A partial capture retains its observed prefix and cannot become `complete`.
pub(super) struct Exchange {
    pub(super) status: Option<u16>,
    pub(super) body: Zeroizing<Vec<u8>>,
    pub(super) capture_status: &'static str,
    pub(super) failure: Option<&'static str>,
    pub(super) retry_after_seconds: Option<u32>,
    pub(super) provider_request_id: Option<String>,
    pub(super) bytes_observed: u64,
}

impl Exchange {
    fn unavailable() -> Self {
        Self {
            status: None,
            body: Zeroizing::new(Vec::new()),
            capture_status: "unavailable",
            failure: None,
            retry_after_seconds: None,
            provider_request_id: None,
            bytes_observed: 0,
        }
    }

    fn interrupted(&mut self, failure: &'static str) {
        self.failure = Some(failure);
        self.capture_status = match (self.status, failure) {
            (None, _) => "unavailable",
            (_, "MODEL_TIMEOUT") => "partial_timeout",
            (_, "MODEL_RESPONSE_TOO_LARGE") => "partial_limit",
            _ => "partial_transport",
        };
    }
}

/// A single, cancellable attempt without retries. The caller owns durable input,
/// output and terminal audit records; dropping a sender alone does not cancel.
pub(super) trait ModelPort {
    fn send<'a>(
        &'a self,
        payload: &'a [u8],
        cancel: &'a mut oneshot::Receiver<()>,
    ) -> impl Future<Output = Exchange> + Send + 'a;

    /// Detect literal or JSON-escaped keys before any evidence capture.
    fn contains_secret(&self, bytes: &[u8]) -> bool;

    /// Fixed audit/provider identity selected by the validated route.
    fn provider(&self) -> &'static str {
        "typesafe"
    }

    /// Fixed wire model identifier; never comes from operator input.
    fn provider_model(&self) -> &'static str {
        DIRECT_MODEL
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum JevRoute {
    Gateway,
    Direct,
}

impl JevRoute {
    pub(super) fn from_environment() -> Result<Self, &'static str> {
        Self::parse(std::env::var("XSHIELD_JEV_ROUTE").ok().as_deref())
    }

    fn parse(value: Option<&str>) -> Result<Self, &'static str> {
        match value.unwrap_or("gateway") {
            "gateway" => Ok(Self::Gateway),
            "direct" => Ok(Self::Direct),
            _ => Err("MODEL_CONFIG_INVALID"),
        }
    }

    fn endpoint(self) -> &'static str {
        match self {
            Self::Gateway => GATEWAY_ENDPOINT,
            Self::Direct => DIRECT_ENDPOINT,
        }
    }

    #[allow(dead_code)]
    fn provider(self) -> &'static str {
        match self {
            Self::Gateway => "vercel_ai_gateway",
            Self::Direct => "typesafe",
        }
    }

    #[allow(dead_code)]
    fn provider_model(self) -> &'static str {
        match self {
            Self::Gateway => GATEWAY_MODEL,
            Self::Direct => DIRECT_MODEL,
        }
    }

    pub(super) fn secret_name(self) -> &'static str {
        match self {
            Self::Gateway => "AI_GATEWAY_API_KEY",
            Self::Direct => "XSHIELD_JEV_API_KEY",
        }
    }
}

/// Fixed HTTPS destination with verified native TLS roots. Secrets and response
/// bodies intentionally have no `Debug`/`Display` or tracing representation.
pub(super) struct JevClient {
    client: HttpClient,
    api_key: Zeroizing<String>,
    endpoint: Uri,
    timeout: Duration,
    #[allow(dead_code)]
    route: JevRoute,
}

impl JevClient {
    /// Validate the injected key and native trust store without network I/O.
    /// Failures are stable configuration codes; credentials are never returned.
    pub(super) fn new(route: JevRoute, api_key: Zeroizing<String>) -> Result<Self, &'static str> {
        validate_key(&api_key)?;
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| "MODEL_TLS_ROOTS_UNAVAILABLE")?
            .https_only()
            .enable_http1()
            .build();
        Ok(Self {
            client: build_client(connector),
            api_key,
            endpoint: Uri::from_static(route.endpoint()),
            timeout: DEADLINE,
            route,
        })
    }

    /// Test-only HTTP transport restricted to canonical IPv4 loopback URLs.
    #[cfg(test)]
    pub(super) fn for_test(
        api_key: Zeroizing<String>,
        endpoint: &str,
        timeout: Duration,
    ) -> Result<Self, &'static str> {
        Self::for_test_with_route(JevRoute::Direct, api_key, endpoint, timeout)
    }

    #[cfg(test)]
    pub(super) fn for_test_with_route(
        route: JevRoute,
        api_key: Zeroizing<String>,
        endpoint: &str,
        timeout: Duration,
    ) -> Result<Self, &'static str> {
        validate_key(&api_key)?;
        let uri: Uri = endpoint.parse().map_err(|_| "MODEL_ENDPOINT_INVALID")?;
        let port = uri.port_u16().ok_or("MODEL_ENDPOINT_INVALID")?;
        if port == 0
            || endpoint != format!("http://127.0.0.1:{port}/v1/systemone")
            || timeout.is_zero()
        {
            return Err("MODEL_ENDPOINT_INVALID");
        }
        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| "MODEL_TLS_ROOTS_UNAVAILABLE")?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            client: build_client(connector),
            api_key,
            endpoint: uri,
            timeout,
            route,
        })
    }

    async fn receive(&self, payload: &[u8], exchange: &mut Exchange) -> Result<(), &'static str> {
        let bearer = Zeroizing::new(format!("Bearer {}", self.api_key.as_str()));
        let mut authorization = HeaderValue::from_str(&bearer).map_err(|_| "MODEL_KEY_INVALID")?;
        authorization.set_sensitive(true);
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_11)
            .uri(self.endpoint.clone())
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Full::new(Bytes::copy_from_slice(payload)))
            .map_err(|_| "MODEL_TRANSPORT_ERROR")?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|_| "MODEL_TRANSPORT_ERROR")?;
        let status = response.status().as_u16();
        exchange.status = Some(status);
        exchange.retry_after_seconds = single_header(response.headers(), header::RETRY_AFTER)
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|seconds| *seconds <= 86_400);
        exchange.provider_request_id = single_header(response.headers(), "x-request-id")
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
            })
            .map(str::to_owned);
        let valid_headers = identity_encoding(response.headers())
            && (status != 200 || json_content_type(response.headers()));
        let mut body = response.into_body();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| "MODEL_TRANSPORT_ERROR")?;
            if let Ok(data) = frame.into_data() {
                exchange.bytes_observed = exchange.bytes_observed.saturating_add(data.len() as u64);
                // Inspect before clipping: a key spanning the capture boundary
                // must not leave a secret prefix in durable evidence.
                let key = self.api_key.as_bytes();
                if secret_in_bytes(&data, key, false)
                    || (1..key.len()).any(|split| {
                        exchange.body.ends_with(&key[..split]) && data.starts_with(&key[split..])
                    })
                {
                    Self::discard_response(exchange);
                    return Ok(());
                }
                let retained = data.len().min(RESPONSE_LIMIT - exchange.body.len());
                exchange.body.extend_from_slice(&data[..retained]);
                if retained < data.len() {
                    return Err("MODEL_RESPONSE_TOO_LARGE");
                }
            }
        }
        exchange.capture_status = "complete";
        exchange.failure = match (valid_headers, status) {
            (false, _) => Some("MODEL_RESPONSE_INVALID"),
            (_, 200) => None,
            (_, 429) => Some("MODEL_RATE_LIMITED"),
            (_, 529) => Some("MODEL_OVERLOADED"),
            _ => Some("MODEL_HTTP_ERROR"),
        };
        Ok(())
    }

    fn exclude_secret(&self, exchange: &mut Exchange) {
        if secret_in_bytes(
            &exchange.body,
            self.api_key.as_bytes(),
            exchange.capture_status != "complete" || unclosed_json_string(&exchange.body),
        ) || exchange
            .provider_request_id
            .as_ref()
            .is_some_and(|value| self.contains_secret(value.as_bytes()))
        {
            Self::discard_response(exchange);
        }
    }

    fn discard_response(exchange: &mut Exchange) {
        exchange.body.zeroize();
        if let Some(request_id) = &mut exchange.provider_request_id {
            request_id.zeroize();
        }
        exchange.provider_request_id = None;
        exchange.capture_status = "excluded_policy";
        exchange.failure = Some("MODEL_SECRET_EXCLUDED");
    }
}

impl ModelPort for JevClient {
    async fn send<'a>(
        &'a self,
        payload: &'a [u8],
        cancel: &'a mut oneshot::Receiver<()>,
    ) -> Exchange {
        let mut exchange = Exchange::unavailable();
        // Pattern mismatch disables the cancellation branch when its sender
        // closes. The receive future owns every network/body operation.
        let result = tokio::select! {
            biased;
            Ok(()) = cancel => Err("MODEL_CANCELLED"),
            result = tokio::time::timeout(self.timeout, self.receive(payload, &mut exchange)) => {
                match result {
                    Ok(result) => result,
                    Err(_) => Err("MODEL_TIMEOUT"),
                }
            }
        };
        if let Err(failure) = result {
            exchange.interrupted(failure);
        }
        self.exclude_secret(&mut exchange);
        exchange
    }

    fn contains_secret(&self, bytes: &[u8]) -> bool {
        secret_in_bytes(bytes, self.api_key.as_bytes(), unclosed_json_string(bytes))
    }

    fn provider(&self) -> &'static str {
        self.route.provider()
    }

    fn provider_model(&self) -> &'static str {
        self.route.provider_model()
    }
}

fn unclosed_json_string(bytes: &[u8]) -> bool {
    let (mut inside, mut escaped) = (false, false);
    for &byte in bytes {
        if escaped {
            escaped = false;
        } else if inside && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            inside = !inside;
        }
    }
    inside
}

/// Keys are printable ASCII, so their JSON representations need only exact byte
/// and escape matching. Scanning individual spans also covers malformed JSON.
/// Partial captures exclude any matching suffix that could complete the key.
fn secret_in_bytes(bytes: &[u8], key: &[u8], partial: bool) -> bool {
    if bytes.windows(key.len()).any(|window| window == key)
        || (partial && (1..key.len()).any(|length| bytes.ends_with(&key[..length])))
    {
        return true;
    }
    if !bytes.contains(&b'\\') {
        return false;
    }
    for start in 0..bytes.len() {
        let mut remaining = &bytes[start..];
        for (index, expected) in key.iter().copied().enumerate() {
            match encoded_byte(remaining, expected) {
                EncodedByte::Matched(length) => {
                    remaining = &remaining[length..];
                    if index + 1 == key.len() {
                        return true;
                    }
                }
                EncodedByte::Incomplete if partial => return true,
                EncodedByte::Incomplete | EncodedByte::Different => break,
            }
        }
    }
    false
}

enum EncodedByte {
    Matched(usize),
    Incomplete,
    Different,
}

fn encoded_byte(bytes: &[u8], expected: u8) -> EncodedByte {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let Some(&first) = bytes.first() else {
        return EncodedByte::Incomplete;
    };
    if first != b'\\' {
        return if first == expected {
            EncodedByte::Matched(1)
        } else {
            EncodedByte::Different
        };
    }
    let unicode = [
        b'\\',
        b'u',
        b'0',
        b'0',
        HEX[usize::from(expected >> 4)],
        HEX[usize::from(expected & 15)],
    ];
    let compared = bytes.len().min(unicode.len());
    if bytes[..compared].eq_ignore_ascii_case(&unicode[..compared]) {
        return if bytes.len() < unicode.len() {
            EncodedByte::Incomplete
        } else {
            EncodedByte::Matched(unicode.len())
        };
    }
    if b"\"\\/".contains(&expected) && bytes.starts_with(&[b'\\', expected]) {
        EncodedByte::Matched(2)
    } else {
        EncodedByte::Different
    }
}

fn validate_key(api_key: &str) -> Result<(), &'static str> {
    if !(16..=512).contains(&api_key.len()) || !api_key.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err("MODEL_KEY_INVALID");
    }
    Ok(())
}

fn build_client(connector: HttpsConnector<HttpConnector>) -> HttpClient {
    // Hyper's direct connector neither consumes proxy environment variables nor
    // follows redirects. Disable its internal cancelled-request retry as well.
    Client::builder(TokioExecutor::new())
        .retry_canceled_requests(false)
        .pool_max_idle_per_host(0)
        .http1_max_headers(32)
        .http1_max_buf_size(16 * 1024)
        .build(connector)
}

fn single_header(headers: &HeaderMap, name: impl http::header::AsHeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

fn identity_encoding(headers: &HeaderMap) -> bool {
    !headers.contains_key(header::CONTENT_ENCODING)
        || single_header(headers, header::CONTENT_ENCODING)
            .is_some_and(|value| value.eq_ignore_ascii_case("identity"))
}

fn json_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = single_header(headers, header::CONTENT_TYPE) else {
        return false;
    };
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    match parts.next() {
        None => true,
        Some(parameter) => {
            parts.next().is_none()
                && parameter.split_once('=').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("charset")
                        && value.trim().eq_ignore_ascii_case("utf-8")
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    const KEY: &str = "test-key-for-jev-only";

    async fn server(response: Vec<u8>, pause: bool) -> (String, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..end]).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                .map(|(_, length)| length.trim().parse().unwrap())
                        })
                        .unwrap();
                    if request.len() == end + 4 + length {
                        break;
                    }
                }
            }
            stream.write_all(&response).await.unwrap();
            if pause {
                let mut byte = [0];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err()
            );
            request
        });
        (endpoint, task)
    }

    fn response(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut bytes = format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n{headers}\r\n",
            body.len()
        )
        .into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    async fn exchange(response: Vec<u8>, closed_cancel: bool) -> Exchange {
        exchange_with_key(response, closed_cancel, KEY).await
    }

    async fn exchange_with_key(response: Vec<u8>, closed_cancel: bool, key: &str) -> Exchange {
        let (endpoint, server) = server(response, false).await;
        let client =
            JevClient::for_test(Zeroizing::new(key.to_owned()), &endpoint, DEADLINE).unwrap();
        let (sender, mut cancel) = oneshot::channel();
        if closed_cancel {
            drop(sender);
        }
        let result = client.send(b"{\"frozen\":true}", &mut cancel).await;
        let request = server.await.unwrap();
        let headers = std::str::from_utf8(&request).unwrap();
        assert!(headers.starts_with("POST /v1/systemone HTTP/1.1\r\n"));
        assert!(headers.contains(&format!("authorization: Bearer {key}\r\n")));
        assert!(headers.ends_with("\r\n\r\n{\"frozen\":true}"));
        result
    }

    #[tokio::test]
    async fn preserves_exact_payload_and_ignores_closed_cancel_channel() {
        let result = exchange(response(200, "Content-Type: application/json; charset=UTF-8\r\nx-request-id: req_1.a-b\r\nRetry-After: 42\r\nSet-Cookie: private=yes\r\n", b"{}"), true).await;
        assert_eq!(result.status, Some(200));
        assert_eq!(result.body.as_slice(), b"{}");
        assert_eq!(result.capture_status, "complete");
        assert_eq!(result.failure, None);
        assert_eq!(result.provider_request_id.as_deref(), Some("req_1.a-b"));
        assert_eq!(result.retry_after_seconds, Some(42));
        assert_eq!(result.bytes_observed, 2);
    }

    #[tokio::test]
    async fn gateway_loopback_request_keeps_alias_and_bearer_binding() {
        let response = response(200, "Content-Type: application/json\r\n", b"{}");
        let (endpoint, server) = server(response, false).await;
        let client = JevClient::for_test_with_route(
            JevRoute::Gateway,
            Zeroizing::new(KEY.to_owned()),
            &endpoint,
            DEADLINE,
        )
        .unwrap();
        let (sender, mut cancel) = oneshot::channel();
        let result = client
            .send(
                format!(r#"{{"model":"{GATEWAY_MODEL}"}}"#).as_bytes(),
                &mut cancel,
            )
            .await;
        drop(sender);
        let request = server.await.unwrap();
        let headers = std::str::from_utf8(&request).unwrap();
        assert!(headers.starts_with("POST /v1/systemone HTTP/1.1\r\n"));
        assert!(headers.contains(&format!("authorization: Bearer {KEY}\r\n")));
        assert!(headers.ends_with(&format!(r#"{{"model":"{GATEWAY_MODEL}"}}"#)));
        assert_eq!(result.failure, None);
    }

    #[tokio::test]
    async fn error_status_and_redirect_have_one_attempt_and_bounded_metadata() {
        for (status, failure) in [
            (429, "MODEL_RATE_LIMITED"),
            (529, "MODEL_OVERLOADED"),
            (302, "MODEL_HTTP_ERROR"),
        ] {
            let result = exchange(response(status, "Location: http://127.0.0.1:1/\r\nx-request-id: not valid\r\nRetry-After: 86401\r\n", b"error"), false).await;
            assert_eq!(result.status, Some(status));
            assert_eq!(result.failure, Some(failure));
            assert_eq!(result.capture_status, "complete");
            assert_eq!(result.body.as_slice(), b"error");
            assert_eq!(result.provider_request_id, None);
            assert_eq!(result.retry_after_seconds, None);
        }
    }

    #[tokio::test]
    async fn response_limit_retains_only_the_bounded_prefix() {
        for size in [RESPONSE_LIMIT, RESPONSE_LIMIT + 1] {
            let result = exchange(
                response(200, "Content-Type: application/json\r\n", &vec![b'x'; size]),
                false,
            )
            .await;
            let oversized = size > RESPONSE_LIMIT;
            assert_eq!(
                result.failure,
                oversized.then_some("MODEL_RESPONSE_TOO_LARGE")
            );
            assert_eq!(
                result.capture_status,
                if oversized {
                    "partial_limit"
                } else {
                    "complete"
                }
            );
            assert_eq!(result.body.len(), RESPONSE_LIMIT);
            assert_eq!(result.bytes_observed, size as u64);
        }
    }

    #[tokio::test]
    async fn timeout_and_cancel_preserve_received_status_and_prefix() {
        for cancel_request in [false, true] {
            let (endpoint, server) = server(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nx-request-id: partial_1\r\n\r\n{\"prefix\":".to_vec(), true).await;
            let timeout = if cancel_request {
                DEADLINE
            } else {
                Duration::from_millis(100)
            };
            let client =
                JevClient::for_test(Zeroizing::new(KEY.to_owned()), &endpoint, timeout).unwrap();
            let (sender, mut cancel) = oneshot::channel();
            let cancellation = tokio::spawn(async move {
                if cancel_request {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    sender.send(()).unwrap();
                }
            });
            let result = client.send(b"{}", &mut cancel).await;
            cancellation.await.unwrap();
            server.await.unwrap();
            assert_eq!(result.status, Some(200));
            assert_eq!(result.body.as_slice(), b"{\"prefix\":");
            assert_eq!(result.provider_request_id.as_deref(), Some("partial_1"));
            assert_eq!(
                result.failure,
                Some(if cancel_request {
                    "MODEL_CANCELLED"
                } else {
                    "MODEL_TIMEOUT"
                })
            );
            assert_eq!(
                result.capture_status,
                if cancel_request {
                    "partial_transport"
                } else {
                    "partial_timeout"
                }
            );
        }
    }

    #[tokio::test]
    async fn rejects_encoding_and_invalid_json_media_types_after_capture() {
        for headers in [
            "Content-Type: text/plain\r\n",
            "Content-Type: application/json; charset=ascii\r\n",
            "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
            "Content-Type: application/json\r\nContent-Type: application/json\r\n",
        ] {
            let result = exchange(response(200, headers, b"{}"), false).await;
            assert_eq!(result.failure, Some("MODEL_RESPONSE_INVALID"));
            assert_eq!(result.capture_status, "complete");
            assert_eq!(result.body.as_slice(), b"{}");
        }
    }

    #[tokio::test]
    async fn transport_error_preserves_prefix_and_header_timeout_is_unavailable() {
        let result = exchange(
            b"HTTP/1.1 429 Test\r\nContent-Length: 100\r\nRetry-After: 12\r\n\r\nprefix".to_vec(),
            false,
        )
        .await;
        assert_eq!(result.failure, Some("MODEL_TRANSPORT_ERROR"));
        assert_eq!(result.capture_status, "partial_transport");
        assert_eq!(result.status, Some(429));
        assert_eq!(result.retry_after_seconds, Some(12));
        assert_eq!(result.body.as_slice(), b"prefix");
        let (endpoint, server) = server(Vec::new(), true).await;
        let client = JevClient::for_test(
            Zeroizing::new(KEY.to_owned()),
            &endpoint,
            Duration::from_millis(50),
        )
        .unwrap();
        let (_sender, mut cancel) = oneshot::channel();
        let result = client.send(b"{}", &mut cancel).await;
        server.await.unwrap();
        assert_eq!(result.failure, Some("MODEL_TIMEOUT"));
        assert_eq!(result.capture_status, "unavailable");
        assert_eq!(result.status, None);
        assert!(result.body.is_empty());
    }

    #[tokio::test]
    async fn excludes_key_echo_from_body_and_allowed_metadata() {
        for (headers, body) in [
            (String::new(), format!("failure: {KEY}")),
            (format!("x-request-id: {KEY}\r\n"), "failure".to_owned()),
            (
                String::new(),
                format!("{}{KEY}", "x".repeat(RESPONSE_LIMIT - KEY.len() / 2)),
            ),
        ] {
            let result = exchange(response(429, &headers, body.as_bytes()), false).await;
            assert_eq!(result.failure, Some("MODEL_SECRET_EXCLUDED"));
            assert_eq!(result.capture_status, "excluded_policy");
            assert!(result.body.is_empty());
            assert_eq!(result.provider_request_id, None);
        }
        let (left, right) = KEY.split_at(KEY.len() / 2);
        let chunked = format!(
            "HTTP/1.1 429 Test\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{left}\r\n{:x}\r\n{right}\r\n0\r\n\r\n",
            left.len(),
            right.len()
        );
        let result = exchange(chunked.into_bytes(), false).await;
        assert_eq!(result.failure, Some("MODEL_SECRET_EXCLUDED"));
        assert!(result.body.is_empty());
    }

    #[test]
    fn request_secret_scan_decodes_json_escapes_and_retains_safe_prefixes() {
        let mut client = JevClient::new(JevRoute::Direct, Zeroizing::new(KEY.to_owned())).unwrap();
        for bytes in [
            br#"{"state":"test-key-\u0066or-jev-only"}"#.as_slice(),
            br#"invalid JSON "test-key-\u0066or-jev-only""#.as_slice(),
            br#"{"state":"test-key-\u0066or-jev-only"#.as_slice(),
            br#"{"state":"test-key-\u00"#.as_slice(),
            br#"{"state":"test-key-\u0066or"#.as_slice(),
        ] {
            assert!(client.contains_secret(bytes));
        }
        let mut escaped = String::new();
        for byte in KEY.bytes() {
            write!(escaped, "\\u{byte:04X}").unwrap();
        }
        assert!(client.contains_secret(escaped.as_bytes()));
        for safe in [
            br#"{"state":"test-key-\u0066or-jev-onlX"}"#.as_slice(),
            br#"{"state":"test-key-\\u0066or-jev-only"}"#.as_slice(),
            br#"{"state":"test-key-"}"#.as_slice(),
        ] {
            assert!(!client.contains_secret(safe));
        }
        client.api_key = Zeroizing::new(r#"test-"key\for/jev-only"#.to_owned());
        let escaped =
            serde_json::to_vec(&format!("prefix:{}:suffix", client.api_key.as_str())).unwrap();
        assert!(client.contains_secret(&escaped));
        assert!(client.contains_secret(br#""test-\u0022key\u005Cfor\/jev-only""#));
    }

    #[tokio::test]
    async fn excludes_escaped_response_keys_before_body_or_metadata_capture() {
        for body in [
            br#"{"error":"test-key-\u0066or-jev-only"}"#.as_slice(),
            br#"invalid JSON "test-key-\u0066or-jev-only""#.as_slice(),
            br#"{"error":"test-key-\u00"#.as_slice(),
        ] {
            let result = exchange(response(429, "x-request-id: req_safe\r\n", body), false).await;
            assert_eq!(result.failure, Some("MODEL_SECRET_EXCLUDED"));
            assert_eq!(result.capture_status, "excluded_policy");
            assert!(result.body.is_empty());
            assert_eq!(result.provider_request_id, None);
        }
        let key = r#"test-"key\for/jev-only"#;
        let body = serde_json::to_vec(&format!("failure: {key}")).unwrap();
        let result = exchange_with_key(response(429, "", &body), false, key).await;
        assert_eq!(result.failure, Some("MODEL_SECRET_EXCLUDED"));
        assert!(result.body.is_empty());
        let result = exchange(
            response(
                429,
                "x-request-id: test-key-\\u0066or-jev-only\r\n",
                b"failure",
            ),
            false,
        )
        .await;
        assert_eq!(result.provider_request_id, None);
        assert_eq!(result.body.as_slice(), b"failure");
    }

    #[tokio::test]
    async fn excludes_escaped_keys_across_frames_capture_limit_and_timeout() {
        let left = br#"{"error":"test-key-\u00"#;
        let right = br#"66or-jev-only"}"#;
        for padding in [0, RESPONSE_LIMIT - left.len()] {
            let first = format!(
                "{}{left}",
                "x".repeat(padding),
                left = std::str::from_utf8(left).unwrap()
            );
            let second = std::str::from_utf8(right).unwrap();
            let chunked = format!(
                "HTTP/1.1 429 Test\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
                first.len(),
                second.len()
            );
            let result = exchange(chunked.into_bytes(), false).await;
            assert_eq!(result.failure, Some("MODEL_SECRET_EXCLUDED"));
            assert_eq!(result.capture_status, "excluded_policy");
            assert!(result.body.is_empty());
        }
        let mut stalled = b"HTTP/1.1 429 Test\r\nContent-Length: 1000\r\n\r\n".to_vec();
        stalled.extend_from_slice(left);
        let (endpoint, server) = server(stalled, true).await;
        let client = JevClient::for_test(
            Zeroizing::new(KEY.to_owned()),
            &endpoint,
            Duration::from_millis(50),
        )
        .unwrap();
        let (_sender, mut cancel) = oneshot::channel();
        let result = client.send(b"{}", &mut cancel).await;
        server.await.unwrap();
        assert_eq!(result.failure, Some("MODEL_SECRET_EXCLUDED"));
        assert_eq!(result.capture_status, "excluded_policy");
        assert_eq!(result.status, Some(429));
        assert!(result.body.is_empty());
    }

    #[tokio::test]
    async fn configuration_keeps_https_and_rejects_input_destination_or_invalid_key() {
        let mut client = JevClient::new(JevRoute::Direct, Zeroizing::new(KEY.to_owned())).unwrap();
        assert_eq!(client.endpoint, DIRECT_ENDPOINT);
        assert_eq!(client.timeout, DEADLINE);
        assert!(client.contains_secret(format!("before{KEY}after").as_bytes()));
        assert!(!client.contains_secret(b"a different value"));
        let gateway = JevClient::new(JevRoute::Gateway, Zeroizing::new(KEY.to_owned())).unwrap();
        assert_eq!(gateway.endpoint, GATEWAY_ENDPOINT);
        assert_eq!(gateway.provider(), "vercel_ai_gateway");
        assert_eq!(gateway.provider_model(), GATEWAY_MODEL);
        assert_eq!(JevRoute::Gateway.secret_name(), "AI_GATEWAY_API_KEY");
        assert_eq!(JevRoute::Direct.secret_name(), "XSHIELD_JEV_API_KEY");
        assert_eq!(JevRoute::parse(None), Ok(JevRoute::Gateway));
        assert_eq!(JevRoute::parse(Some("direct")), Ok(JevRoute::Direct));
        assert_eq!(JevRoute::parse(Some("other")), Err("MODEL_CONFIG_INVALID"));
        for key in [
            "short".to_owned(),
            "x".repeat(513),
            "key contains whitespace".to_owned(),
            "key-with-newline\n".to_owned(),
            "非ASCII-key-key-key".to_owned(),
        ] {
            assert!(JevClient::new(JevRoute::Direct, Zeroizing::new(key)).is_err());
        }
        for endpoint in [
            "https://127.0.0.1:8080/v1/systemone",
            "http://localhost:8080/v1/systemone",
            "http://127.0.0.1/v1/systemone",
            "http://127.0.0.1:0/v1/systemone",
            "http://127.0.0.1:8080/v1/systemone?other=1",
            "http://127.0.0.1:8080/other",
            "http://127.0.0.2:8080/v1/systemone",
        ] {
            assert!(
                JevClient::for_test(Zeroizing::new(KEY.to_owned()), endpoint, DEADLINE).is_err()
            );
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        client.endpoint = format!("http://{}/v1/systemone", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let (_sender, mut cancel) = oneshot::channel();
        let result = client.send(b"{}", &mut cancel).await;
        assert_eq!(result.failure, Some("MODEL_TRANSPORT_ERROR"));
        assert_eq!(result.capture_status, "unavailable");
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        let client = JevClient::for_test(
            Zeroizing::new(KEY.to_owned()),
            &client.endpoint.to_string(),
            DEADLINE,
        )
        .unwrap();
        let (sender, mut cancel) = oneshot::channel();
        sender.send(()).unwrap();
        let result = client.send(b"{}", &mut cancel).await;
        assert_eq!(result.failure, Some("MODEL_CANCELLED"));
        assert_eq!(result.capture_status, "unavailable");
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }
}
