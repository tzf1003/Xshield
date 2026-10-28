//! Buffered routes exchange with the origin in an in-process subrequest.
//!
//! Pingora writes a response header to the client as soon as its header
//! filter returns, before any body filter runs. A buffered route validates and
//! commits the whole origin reply in the body filter, so a refusal after the
//! header was written could only cut the connection behind a `200`. Running the
//! origin exchange as a subrequest keeps every byte of its reply on this side:
//! the client sees the final header and body only after the subrequest has
//! finished cleanly, and a clean `502` otherwise.

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::protocols::http::v1::client::http_req_header_to_wire;
use pingora::protocols::http::{HttpTask, ServerSession};
use pingora::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType, raw_connect::ProxyDigest,
};
use pingora::proxy::Session;
use pingora::{Error as PingoraError, ErrorType, Result as PingoraResult};
use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

/// The parent request's context, parked for the subrequest that serves it.
///
/// The subrequest takes the context in its request filter and gives it back
/// from its logging hook. If the subrequest never took it, dropping the
/// handoff returns it, so the parent can still finalize its audit.
pub(crate) struct Handoff<C: Send + 'static> {
    context: Mutex<Option<C>>,
    returned: Mutex<Option<oneshot::Sender<C>>>,
}

impl<C: Send + 'static> Handoff<C> {
    pub(crate) fn new(context: C) -> (Self, oneshot::Receiver<C>) {
        let (sender, receiver) = oneshot::channel();
        (
            Self {
                context: Mutex::new(Some(context)),
                returned: Mutex::new(Some(sender)),
            },
            receiver,
        )
    }

    pub(crate) fn take_context(&self) -> Option<C> {
        self.context.lock().ok().and_then(|mut slot| slot.take())
    }

    pub(crate) fn give_back(&self, context: C) {
        let sender = self.returned.lock().ok().and_then(|mut slot| slot.take());
        if let Some(sender) = sender {
            // The parent only stops listening once it has given up on the request.
            let _ = sender.send(context);
        }
    }
}

impl<C: Send + 'static> Drop for Handoff<C> {
    fn drop(&mut self) {
        if let Some(context) = self.take_context() {
            self.give_back(context);
        }
    }
}

/// The handoff this session serves, when it is a buffered-route subrequest.
pub(crate) fn handoff<C: Send + Sync + 'static>(session: &Session) -> Option<&Handoff<C>> {
    session
        .subrequest_ctx
        .as_ref()?
        .user_ctx()?
        .downcast_ref::<Handoff<C>>()
}

/// The session a subrequest is built from, when the parent's own will not do.
///
/// Pingora builds a subrequest by re-parsing the parent's request head as
/// HTTP/1. An HTTP/2 head serialises with an `HTTP/2` request line, which that
/// parser refuses, so it is restated as HTTP/1.1 with its authority as `Host`
/// (admission already required the two to agree). A body without a declared
/// length is framed as chunked so the subrequest reads the piped body to its end.
pub(crate) async fn restated_head(
    parent: &ServerSession,
    body_pending: bool,
) -> PingoraResult<Option<ServerSession>> {
    if parent.req_header().version != http::Version::HTTP_2 {
        return Ok(None);
    }
    let mut head = parent.req_header().clone();
    head.set_version(http::Version::HTTP_11);
    if !head.headers.contains_key(http::header::HOST)
        && let Some(authority) = head
            .uri
            .authority()
            .map(|authority| authority.as_str().to_owned())
    {
        head.insert_header(http::header::HOST, authority)?;
    }
    if body_pending && !head.headers.contains_key(http::header::CONTENT_LENGTH) {
        head.insert_header(http::header::TRANSFER_ENCODING, "chunked")?;
    }
    let wire = http_req_header_to_wire(&head).ok_or_else(|| {
        PingoraError::explain(
            ErrorType::InvalidHTTPHeader,
            "request head cannot be restated",
        )
    })?;
    let mut session = ServerSession::new_http1(Box::new(RequestHead(Cursor::new(wire.to_vec()))));
    if !session.read_request().await? {
        return Err(PingoraError::explain(
            ErrorType::InvalidHTTPHeader,
            "restated request head did not parse",
        ));
    }
    Ok(Some(session))
}

/// A stream that yields one request head and discards whatever is written.
#[derive(Debug)]
struct RequestHead(Cursor<Vec<u8>>);

impl AsyncRead for RequestHead {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let cursor = &mut self.get_mut().0;
        if cursor.position() < cursor.get_ref().len() as u64 {
            Pin::new(cursor).poll_read(context, buffer)
        } else {
            // A finished stream would read as a closed connection.
            Poll::Pending
        }
    }
}

impl AsyncWrite for RequestHead {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl Shutdown for RequestHead {
    async fn shutdown(&mut self) {}
}

impl UniqueID for RequestHead {
    fn id(&self) -> UniqueIDType {
        0
    }
}

impl Ssl for RequestHead {}

impl GetTimingDigest for RequestHead {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        Vec::new()
    }
}

impl GetProxyDigest for RequestHead {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        None
    }
}

impl GetSocketDigest for RequestHead {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        None
    }
}

impl Peek for RequestHead {}

/// What the subrequest wrote, held until the parent decides to release it.
#[derive(Default)]
pub(crate) struct Collected {
    header: Option<Box<ResponseHeader>>,
    body: Vec<Bytes>,
    ended: bool,
    failed: bool,
}

impl Collected {
    /// Holds one task back from the client. Interim `1xx` headers are dropped:
    /// the request body has already been read in full by the time anything is
    /// released, so they carry nothing the client still needs.
    pub(crate) fn hold(&mut self, task: HttpTask) {
        match task {
            HttpTask::Header(header, end) => {
                if header.status.is_informational() {
                    return;
                }
                if self.header.is_some() {
                    self.failed = true;
                    return;
                }
                self.header = Some(header);
                self.ended |= end;
            }
            HttpTask::Body(data, end) => {
                if let Some(data) = data.filter(|data| !data.is_empty()) {
                    self.body.push(data);
                }
                self.ended |= end;
            }
            HttpTask::Done => self.ended = true,
            // Buffered routes refuse trailers and upgrades upstream of here;
            // seeing one means the exchange did not end the expected way.
            HttpTask::Trailer(_) | HttpTask::UpgradedBody(..) | HttpTask::Failed(_) => {
                self.failed = true;
            }
        }
    }

    /// The complete reply, or `None` when the subrequest did not finish one.
    pub(crate) fn into_tasks(self) -> Option<Vec<HttpTask>> {
        if self.failed {
            return None;
        }
        let header = self.header?;
        let mut tasks = Vec::with_capacity(self.body.len() + 2);
        tasks.push(HttpTask::Header(header, false));
        tasks.extend(
            self.body
                .into_iter()
                .map(|data| HttpTask::Body(Some(data), false)),
        );
        tasks.push(HttpTask::Body(None, true));
        Some(tasks)
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.ended && !self.failed && self.header.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(status: u16) -> Box<ResponseHeader> {
        Box::new(ResponseHeader::build(status, None).expect("static header"))
    }

    #[test]
    fn releases_only_a_finished_reply() {
        let mut collected = Collected::default();
        collected.hold(HttpTask::Header(header(200), false));
        collected.hold(HttpTask::Body(Some(Bytes::from_static(b"{}")), false));
        assert!(!collected.is_complete());
        collected.hold(HttpTask::Done);
        assert!(collected.is_complete());
        let tasks = collected.into_tasks().expect("complete reply");
        assert_eq!(tasks.len(), 3);
        assert!(matches!(&tasks[0], HttpTask::Header(header, false) if header.status == 200));
    }

    #[test]
    fn interim_headers_are_dropped_and_a_second_final_header_fails() {
        let mut collected = Collected::default();
        collected.hold(HttpTask::Header(header(100), false));
        collected.hold(HttpTask::Header(header(200), false));
        collected.hold(HttpTask::Done);
        assert!(collected.is_complete());
        collected.hold(HttpTask::Header(header(200), false));
        assert!(!collected.is_complete());
        assert!(collected.into_tasks().is_none());
    }

    #[test]
    fn a_failed_task_withholds_everything() {
        let mut collected = Collected::default();
        collected.hold(HttpTask::Header(header(200), false));
        collected.hold(HttpTask::Body(Some(Bytes::from_static(b"partial")), false));
        collected.hold(HttpTask::Failed(pingora::Error::new_str("cut")));
        collected.hold(HttpTask::Done);
        assert!(!collected.is_complete());
        assert!(collected.into_tasks().is_none());
    }

    #[test]
    fn a_reply_without_a_header_is_not_complete() {
        let mut collected = Collected::default();
        collected.hold(HttpTask::Body(None, true));
        assert!(!collected.is_complete());
        assert!(collected.into_tasks().is_none());
    }

    #[test]
    fn an_untaken_context_returns_on_drop() {
        let (handoff, mut receiver) = Handoff::new(7_u32);
        drop(handoff);
        assert_eq!(receiver.try_recv().ok(), Some(7));
    }

    #[test]
    fn a_taken_context_returns_once() {
        let (handoff, mut receiver) = Handoff::new(7_u32);
        let context = handoff.take_context().expect("parked context");
        handoff.give_back(context + 1);
        handoff.give_back(0);
        drop(handoff);
        assert_eq!(receiver.try_recv().ok(), Some(8));
    }
}
