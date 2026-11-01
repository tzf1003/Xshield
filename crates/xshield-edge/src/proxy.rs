//! The Pingora `ProxyHttp` implementation: judge before forwarding, observe
//! after the origin answers, log when the exchange ends (docs/01 section 1.4).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use pingora::{Error, ErrorType, Result};
use xshield_core::context::{DecisionRecord, SessionCredential, SiteSpec};
use xshield_judge::engine::{Judge, Observation, RequestFacts};
use xshield_judge::jev::JevPort;
use xshield_judge::values::RESPONSE_PARSE_MAX;

use crate::sink::DecisionSink;
use crate::sites::{EdgeSite, SiteTable};

/// Largest request body the edge buffers to judge it. Larger or unsized
/// bodies on judged paths are refused; upload endpoints belong in `bypass`.
pub const REQUEST_BODY_MAX: usize = 48 * 1024;
const ORIGIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ORIGIN_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The proxy: one per process, shared by all listeners.
pub struct EdgeProxy<J: JevPort + 'static> {
    sites: Arc<SiteTable>,
    judge: Arc<Judge<J>>,
    sink: DecisionSink,
}

impl<J: JevPort + 'static> EdgeProxy<J> {
    /// Wires the proxy to its site table, judge and decision log.
    #[must_use]
    pub fn new(sites: Arc<SiteTable>, judge: Arc<Judge<J>>, sink: DecisionSink) -> Self {
        Self { sites, judge, sink }
    }
}

/// Per-request state.
pub struct RequestContext {
    request_id: String,
    site: Option<Arc<EdgeSite>>,
    credential: Option<String>,
    client: String,
    record: Option<DecisionRecord>,
    capture: Option<Capture>,
    issued: Option<String>,
    status: u16,
}

/// A response body being copied for observation while it streams through.
struct Capture {
    bytes: Vec<u8>,
    overflow: bool,
    content_type: Option<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn header_text<'a>(header: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    header.get(name).and_then(|value| value.to_str().ok())
}

/// All `Cookie` headers joined, since HTTP/2 clients may split them.
fn cookie_header(header: &http::HeaderMap) -> Option<String> {
    let joined = header
        .get_all("cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    (!joined.is_empty()).then_some(joined)
}

fn request_host(request: &RequestHeader) -> Option<String> {
    header_text(&request.headers, "host")
        .map(str::to_owned)
        .or_else(|| {
            request
                .uri
                .authority()
                .map(|authority| authority.as_str().to_owned())
        })
}

/// The value of the configured credential in a response, if it issues one.
fn issued_credential(site: &SiteSpec, response: &ResponseHeader) -> Option<String> {
    match site.session() {
        SessionCredential::Header(name) => response
            .headers
            .get(name.as_str())
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        SessionCredential::Cookie(name) => response
            .headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|cookie| {
                let (key, rest) = cookie.split_once('=')?;
                let value = rest.split(';').next()?.trim();
                (key.trim() == name && !value.is_empty()).then(|| value.to_owned())
            }),
    }
}

fn observable_type(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    lower.contains("json") || lower.starts_with("text/html")
}

async fn refuse(session: &mut Session, status: u16, request_id: &str, error: &str) -> Result<()> {
    let body = Bytes::from(format!(
        "{{\"error\":\"{error}\",\"request_id\":\"{request_id}\"}}"
    ));
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header("Content-Type", "application/json")?;
    response.insert_header("Cache-Control", "private, no-store")?;
    response.insert_header("X-Xshield-Request-Id", request_id)?;
    response.insert_header("Content-Length", body.len().to_string())?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(Some(body), true).await
}

/// Reads the whole request body if it is small enough to judge.
///
/// `Ok(None)` means the body is too large or of unknown size.
async fn buffer_body(session: &mut Session) -> Result<Option<Bytes>> {
    if session.as_downstream_mut().is_body_empty() {
        return Ok(Some(Bytes::new()));
    }
    let length: Option<usize> = header_text(&session.req_header().headers, "content-length")
        .and_then(|value| value.trim().parse().ok());
    let chunked = session
        .req_header()
        .headers
        .contains_key("transfer-encoding");
    let Some(length) = length.filter(|length| !chunked && *length <= REQUEST_BODY_MAX) else {
        return Ok(None);
    };
    // Pingora replays what was read through the retry buffer, which is how
    // the origin still receives the body after the edge consumed it.
    session.as_downstream_mut().enable_retry_buffering();
    let mut body = Vec::with_capacity(length);
    while let Some(chunk) = session.as_downstream_mut().read_request_body().await? {
        body.extend_from_slice(&chunk);
        if body.len() > REQUEST_BODY_MAX {
            return Ok(None);
        }
    }
    if session.as_downstream().retry_buffer_truncated() || body.len() != length {
        return Ok(None);
    }
    Ok(Some(Bytes::from(body)))
}

#[async_trait]
impl<J: JevPort + 'static> ProxyHttp for EdgeProxy<J> {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            request_id: format!("req_{}", uuid::Uuid::now_v7().simple()),
            site: None,
            credential: None,
            client: String::new(),
            record: None,
            capture: None,
            issued: None,
            status: 0,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let Some(site) = request_host(session.req_header()).and_then(|host| self.sites.find(&host))
        else {
            refuse(session, 404, &ctx.request_id, "unknown_site").await?;
            return Ok(true);
        };
        ctx.site = Some(Arc::clone(&site));
        ctx.client = session
            .client_addr()
            .and_then(|address| address.as_inet())
            .map_or_else(String::new, |address| address.ip().to_string());

        let Some(body) = buffer_body(session).await? else {
            if site.spec().is_bypass(session.req_header().uri.path()) {
                return Ok(false);
            }
            refuse(session, 413, &ctx.request_id, "body_not_inspectable").await?;
            return Ok(true);
        };

        let header = session.req_header();
        let cookies = cookie_header(&header.headers);
        let named = match site.spec().session() {
            SessionCredential::Header(name) => header_text(&header.headers, name),
            SessionCredential::Cookie(_) => None,
        };
        let credential =
            Judge::<J>::credential_from(site.spec(), cookies.as_deref(), named).map(str::to_owned);
        let method = header.method.as_str().to_owned();
        let path = header.uri.path().to_owned();
        let query = header.uri.query().map(str::to_owned);
        let content_type = header_text(&header.headers, "content-type").map(str::to_owned);
        let judgement = self
            .judge
            .judge(
                site.spec(),
                &RequestFacts {
                    request_id: &ctx.request_id,
                    method: &method,
                    path: &path,
                    query: query.as_deref(),
                    content_type: content_type.as_deref(),
                    body: &body,
                    credential: credential.as_deref(),
                    client: &ctx.client,
                    now_ms: now_ms(),
                },
            )
            .await;
        ctx.credential = credential;
        ctx.record = judgement.record;
        if judgement.forward {
            return Ok(false);
        }
        let error = if judgement.refuse_status == 401 {
            "unauthenticated"
        } else {
            "forbidden"
        };
        refuse(session, judgement.refuse_status, &ctx.request_id, error).await?;
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let site = ctx
            .site
            .as_ref()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "request without a site"))?;
        let (host, port) = site.address();
        let address = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| Error::because(ErrorType::ConnectNoRoute, "origin lookup", error))?
            .next()
            .ok_or_else(|| Error::explain(ErrorType::ConnectNoRoute, "origin has no address"))?;
        let mut peer = Box::new(HttpPeer::new(address, site.tls(), host.to_owned()));
        peer.options.connection_timeout = Some(ORIGIN_CONNECT_TIMEOUT);
        peer.options.read_timeout = Some(ORIGIN_READ_TIMEOUT);
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Compressed responses cannot be read for observation; static paths,
        // which are never observed, keep their compression.
        let bypass = ctx
            .site
            .as_ref()
            .is_some_and(|site| site.spec().is_bypass(upstream.uri.path()));
        if !bypass {
            upstream.remove_header("Accept-Encoding");
        }
        if !ctx.client.is_empty() {
            let forwarded = match header_text(&upstream.headers, "x-forwarded-for") {
                Some(chain) => format!("{chain}, {}", ctx.client),
                None => ctx.client.clone(),
            };
            upstream.insert_header("X-Forwarded-For", forwarded)?;
        }
        upstream.insert_header("X-Xshield-Request-Id", &ctx.request_id)?;
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        response.insert_header("X-Xshield-Request-Id", &ctx.request_id)?;
        let Some(site) = ctx.site.as_ref() else {
            return Ok(());
        };
        ctx.status = response.status.as_u16();
        ctx.issued = issued_credential(site.spec(), response);
        let content_type = header_text(&response.headers, "content-type").map(str::to_owned);
        let sized = header_text(&response.headers, "content-length")
            .and_then(|value| value.trim().parse::<usize>().ok());
        let readable = !response.headers.contains_key("content-encoding")
            && content_type.as_deref().is_some_and(observable_type)
            && sized.is_none_or(|length| length <= RESPONSE_PARSE_MAX)
            && session.req_header().method != http::Method::HEAD
            && (200..300).contains(&ctx.status);
        if readable {
            ctx.capture = Some(Capture {
                bytes: Vec::new(),
                overflow: false,
                content_type,
            });
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        if let (Some(capture), Some(chunk)) = (ctx.capture.as_mut(), body.as_ref())
            && !capture.overflow
        {
            if capture.bytes.len() + chunk.len() > RESPONSE_PARSE_MAX {
                capture.overflow = true;
                capture.bytes = Vec::new();
            } else {
                capture.bytes.extend_from_slice(chunk);
            }
        }
        if end_of_stream {
            self.observe(session, ctx);
        }
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, _error: Option<&Error>, ctx: &mut Self::CTX) {
        let Some(mut record) = ctx.record.take() else {
            return;
        };
        record.status = session
            .response_written()
            .map(|response| response.status.as_u16());
        self.sink.send(record);
    }
}

impl<J: JevPort + 'static> EdgeProxy<J> {
    /// Hands the finished response to the judge (docs/01 section 1.4 step 8).
    fn observe(&self, session: &Session, ctx: &mut RequestContext) {
        let Some(site) = ctx.site.as_ref() else {
            return;
        };
        let capture = ctx.capture.take();
        let (body, content_type) = match &capture {
            Some(capture) if !capture.overflow => {
                (capture.bytes.as_slice(), capture.content_type.as_deref())
            }
            _ => (&[][..], None),
        };
        let request = session.req_header();
        self.judge.observe(
            site.spec(),
            &Observation {
                credential: ctx.credential.as_deref(),
                client: &ctx.client,
                issued_credential: ctx.issued.as_deref(),
                method: request.method.as_str(),
                path: request.uri.path(),
                status: ctx.status,
                content_type,
                body,
                now_ms: now_ms(),
            },
        );
    }
}
