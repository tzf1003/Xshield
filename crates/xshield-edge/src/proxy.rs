//! The Pingora `ProxyHttp` implementation: judge before forwarding, observe
//! after the origin answers, log when the exchange ends (docs/01 section 1.4).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use pingora::proxy::FailToProxy;
use pingora::{Error, ErrorSource, ErrorType, Result};
use xshield_core::context::{
    DecisionPath, DecisionRecord, ObservationSummary, Outcome, SessionCredential, SiteSpec, Skip,
};
use xshield_judge::context::Digest16;
use xshield_judge::engine::{Judge, Observation, RequestFacts, refused_row};
use xshield_judge::jev::JevPort;
use xshield_judge::values::RESPONSE_PARSE_MAX;

use crate::sink::DecisionSink;
use crate::sites::{EdgeSite, SiteTable};

/// Largest request body the edge buffers to judge it. Larger or unsized
/// bodies on judged paths are refused; upload endpoints belong in `bypass`.
pub const REQUEST_BODY_MAX: usize = 48 * 1024;
const ORIGIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ORIGIN_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest `Host` value a decision row keeps (docs/07 section 7.4.2).
const HOST_CHARS_MAX: usize = 253;

/// The proxy: one per process, shared by all listeners.
pub struct EdgeProxy<J: JevPort + 'static> {
    sites: Arc<SiteTable>,
    judge: Arc<Judge<J>>,
    sink: DecisionSink,
    edge: String,
}

impl<J: JevPort + 'static> EdgeProxy<J> {
    /// Wires the proxy to its site table, judge and decision log. `edge` names
    /// this gateway instance in every row it writes.
    #[must_use]
    pub fn new(
        sites: Arc<SiteTable>,
        judge: Arc<Judge<J>>,
        sink: DecisionSink,
        edge: String,
    ) -> Self {
        Self {
            sites,
            judge,
            sink,
            edge,
        }
    }
}

/// Per-request state.
pub struct RequestContext {
    request_id: String,
    started: Instant,
    site: Option<Arc<EdgeSite>>,
    host: String,
    credential: Option<String>,
    client: String,
    record: Option<DecisionRecord>,
    origin_started: Option<Instant>,
    origin_ms: Option<u32>,
    capture: Option<Capture>,
    unread: Option<Skip>,
    content_type: Option<String>,
    issued: Option<String>,
    status: u16,
    observed: bool,
    /// Digests of the request values the judge found unseen, handed to the
    /// judge with the response (see `Judgement::sent`).
    sent: Vec<Digest16>,
}

/// A response body being copied for observation while it streams through.
struct Capture {
    bytes: Vec<u8>,
    overflow: bool,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn millis_since(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
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

/// The `Host` a row keeps: lower case, at most [`HOST_CHARS_MAX`] characters.
fn host_label(host: &str) -> String {
    host.to_ascii_lowercase()
        .chars()
        .take(HOST_CHARS_MAX)
        .collect()
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

/// The reason an upstream failure is logged under (docs/07 section 7.4.3).
fn upstream_error_label(error: &Error) -> &'static str {
    match error.etype() {
        ErrorType::ConnectRefused => "connect_refused",
        ErrorType::ConnectTimedout => "connect_timeout",
        ErrorType::ReadTimedout => "read_timeout",
        ErrorType::TLSHandshakeFailure
        | ErrorType::TLSHandshakeTimedout
        | ErrorType::InvalidCert
        | ErrorType::HandshakeError => "tls",
        _ => "other",
    }
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

impl<J: JevPort + 'static> EdgeProxy<J> {
    /// The row of a request refused before judging (docs/07 section 7.4.1): no
    /// site owns its host, or its body cannot be inspected. Nothing was judged,
    /// so no Jev call was made.
    fn refusal(
        &self,
        session: &Session,
        ctx: &RequestContext,
        site: Option<&SiteSpec>,
        decision_path: DecisionPath,
        status: u16,
    ) -> DecisionRecord {
        let header = session.req_header();
        let facts = RequestFacts {
            request_id: &ctx.request_id,
            method: header.method.as_str(),
            path: header.uri.path(),
            query: header.uri.query(),
            content_type: header_text(&header.headers, "content-type"),
            body: &[],
            credential: None,
            client: &ctx.client,
            now_ms: now_ms(),
        };
        let mut record = refused_row(site, &facts, decision_path, status);
        record.edge.clone_from(&self.edge);
        record.host.clone_from(&ctx.host);
        record
    }

    /// Hands the finished response to the judge (docs/01 section 1.4 step 8),
    /// once per request. The summary goes into the row.
    fn observe(&self, session: &Session, ctx: &mut RequestContext) -> Option<ObservationSummary> {
        if ctx.observed {
            return None;
        }
        ctx.observed = true;
        let site = ctx.site.clone()?;
        let capture = ctx.capture.take();
        let overflow = capture.as_ref().is_some_and(|capture| capture.overflow);
        let body: &[u8] = match &capture {
            Some(capture) if !capture.overflow => &capture.bytes,
            _ => &[],
        };
        let unread = ctx.unread.or(overflow.then_some(Skip::TooLarge));
        let would_block = ctx
            .record
            .as_ref()
            .is_some_and(|record| record.outcome == Outcome::WouldBlock);
        let request = session.req_header();
        Some(self.judge.observe(
            site.spec(),
            &Observation {
                request_id: &ctx.request_id,
                credential: ctx.credential.as_deref(),
                client: &ctx.client,
                issued_credential: ctx.issued.as_deref(),
                method: request.method.as_str(),
                path: request.uri.path(),
                status: ctx.status,
                content_type: ctx.content_type.as_deref(),
                body,
                unread,
                would_block,
                now_ms: now_ms(),
                sent: &ctx.sent,
            },
        ))
    }
}

#[async_trait]
impl<J: JevPort + 'static> ProxyHttp for EdgeProxy<J> {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            request_id: format!("req_{}", uuid::Uuid::now_v7().simple()),
            started: Instant::now(),
            site: None,
            host: String::new(),
            credential: None,
            client: String::new(),
            record: None,
            origin_started: None,
            origin_ms: None,
            capture: None,
            unread: None,
            content_type: None,
            issued: None,
            status: 0,
            observed: false,
            sent: Vec::new(),
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        ctx.client = session
            .client_addr()
            .and_then(|address| address.as_inet())
            .map_or_else(String::new, |address| address.ip().to_string());
        let host = request_host(session.req_header());
        ctx.host = host.as_deref().map(host_label).unwrap_or_default();
        let Some(site) = host.as_deref().and_then(|host| self.sites.find(host)) else {
            let record = self.refusal(session, ctx, None, DecisionPath::UnknownSite, 404);
            ctx.record = Some(record);
            refuse(session, 404, &ctx.request_id, "unknown_site").await?;
            return Ok(true);
        };
        ctx.site = Some(Arc::clone(&site));

        // A bypassed path is forwarded as it arrives: its body is never read,
        // so an upload of any size reaches the origin untouched.
        let bypass = site.spec().is_bypass(session.req_header().uri.path());
        let body = if bypass {
            Bytes::new()
        } else if let Some(body) = buffer_body(session).await? {
            body
        } else {
            let mut record = self.refusal(
                session,
                ctx,
                Some(site.spec()),
                DecisionPath::BodyNotInspectable,
                413,
            );
            record.site_version = Some(site.version());
            ctx.record = Some(record);
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
        ctx.sent = judgement.sent;
        let mut record = judgement.record;
        record.edge.clone_from(&self.edge);
        record.host.clone_from(&ctx.host);
        record.site_version = Some(site.version());
        let refuse_status = judgement.refuse_status;
        ctx.record = Some(record);
        if judgement.forward {
            return Ok(false);
        }
        let error = if refuse_status == 401 {
            "unauthenticated"
        } else {
            "forbidden"
        };
        refuse(session, refuse_status, &ctx.request_id, error).await?;
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
        ctx.origin_started = Some(Instant::now());
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
        ctx.origin_ms = ctx.origin_started.map(millis_since);
        let Some(site) = ctx.site.as_ref() else {
            return Ok(());
        };
        ctx.status = response.status.as_u16();
        ctx.issued = issued_credential(site.spec(), response);
        let content_type = header_text(&response.headers, "content-type").map(str::to_owned);
        let sized = header_text(&response.headers, "content-length")
            .and_then(|value| value.trim().parse::<usize>().ok());
        let request = session.req_header();
        let unread = if site.spec().is_bypass(request.uri.path()) {
            Some(Skip::Bypass)
        } else if request.method == http::Method::HEAD {
            Some(Skip::Head)
        } else if response.headers.contains_key("content-encoding") {
            Some(Skip::Compressed)
        } else if sized.is_some_and(|length| length > RESPONSE_PARSE_MAX) {
            Some(Skip::TooLarge)
        } else {
            None
        };
        let readable = unread.is_none()
            && content_type.as_deref().is_some_and(observable_type)
            && (200..300).contains(&ctx.status);
        if readable {
            ctx.capture = Some(Capture {
                bytes: Vec::new(),
                overflow: false,
            });
        }
        // A response with no body may never reach the body filter, so it is
        // observed here, before its header is written: the client's next request
        // must already see what this response taught (docs/01 section 1.4 step 8).
        let bodiless = request.method == http::Method::HEAD
            || matches!(ctx.status, 204 | 304)
            || sized == Some(0);
        ctx.unread = unread;
        ctx.content_type = content_type;
        if bodiless
            && let Some(summary) = self.observe(session, ctx)
            && let Some(record) = ctx.record.as_mut()
        {
            record.trace.response = Some(summary);
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
        if end_of_stream
            && let Some(summary) = self.observe(session, ctx)
            && let Some(record) = ctx.record.as_mut()
        {
            record.trace.response = Some(summary);
        }
        Ok(None)
    }

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        let Some(mut record) = ctx.record.take() else {
            return;
        };
        record.status = session
            .response_written()
            .map(|response| response.status.as_u16());
        record.trace.timing.total_ms = Some(millis_since(ctx.started));
        record.trace.timing.origin_ms = ctx.origin_ms;
        record.trace.upstream_error = error.map(|error| upstream_error_label(error).to_owned());
        self.sink.send(record);
    }

    /// Writes the answer to a failed forward. Pingora's default answer carries no
    /// request id, so the client could not match its error to the row; this one
    /// does. The codes follow Pingora's defaults, with timeouts answered as 504.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        error: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let code = match (error.esource(), error.etype()) {
            (_, ErrorType::HTTPStatus(code)) => *code,
            (
                ErrorSource::Upstream,
                ErrorType::ConnectTimedout | ErrorType::ReadTimedout | ErrorType::WriteTimedout,
            ) => 504,
            (ErrorSource::Upstream, _) => 502,
            (
                ErrorSource::Downstream,
                ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed,
            ) => 0,
            (ErrorSource::Downstream, _) => 400,
            (ErrorSource::Internal | ErrorSource::Unset, _) => 500,
        };
        if code > 0 {
            let reason = match code {
                400 => "bad_request",
                500 => "internal_error",
                502 => "bad_gateway",
                504 => "gateway_timeout",
                _ => "error",
            };
            // The client may already be gone; the row is written either way.
            let _ = refuse(session, code, &ctx.request_id, reason).await;
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}
