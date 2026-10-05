//! A deadline for the first application byte on a freshly handshaken stream.
//!
//! Pingora bounds the HTTP/1 request-header read, but its HTTP/2 path waits
//! for the client connection preface without a deadline. A client could
//! finish TLS, select `h2` and then stay silent, holding a socket forever.
//! This wrapper fails the first read once the deadline passes, and is inert
//! after the first byte arrives (HTTP/2 idle connections are then bounded by
//! the server's idle timeout). Everything else forwards to the inner stream,
//! including ALPN and the socket digest Pingora reads.

use async_trait::async_trait;
use pingora::protocols::{
    ALPN, GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType, raw_connect::ProxyDigest, tls::SslDigest, tls::TlsRef,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Sleep,
};

#[derive(Debug)]
pub(super) struct FirstReadDeadline<S> {
    inner: S,
    /// Armed until the first byte is read.
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<S> FirstReadDeadline<S> {
    pub(super) fn new(inner: S, limit: Duration) -> Self {
        Self {
            inner,
            deadline: Some(Box::pin(tokio::time::sleep(limit))),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstReadDeadline<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(result) => {
                if buffer.filled().len() > before {
                    this.deadline = None;
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                let expired = this
                    .deadline
                    .as_mut()
                    .is_some_and(|deadline| deadline.as_mut().poll(context).is_ready());
                if expired {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no request after the TLS handshake",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstReadDeadline<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[async_trait]
impl<S: Shutdown + Send> Shutdown for FirstReadDeadline<S> {
    async fn shutdown(&mut self) {
        self.inner.shutdown().await;
    }
}

impl<S: UniqueID> UniqueID for FirstReadDeadline<S> {
    fn id(&self) -> UniqueIDType {
        self.inner.id()
    }
}

impl<S: Ssl> Ssl for FirstReadDeadline<S> {
    fn get_ssl(&self) -> Option<&TlsRef> {
        self.inner.get_ssl()
    }

    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.inner.get_ssl_digest()
    }

    fn selected_alpn_proto(&self) -> Option<ALPN> {
        self.inner.selected_alpn_proto()
    }
}

impl<S: GetTimingDigest> GetTimingDigest for FirstReadDeadline<S> {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.inner.get_timing_digest()
    }

    fn get_read_pending_time(&self) -> Duration {
        self.inner.get_read_pending_time()
    }

    fn get_write_pending_time(&self) -> Duration {
        self.inner.get_write_pending_time()
    }
}

impl<S: GetProxyDigest> GetProxyDigest for FirstReadDeadline<S> {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.inner.get_proxy_digest()
    }

    fn set_proxy_digest(&mut self, digest: ProxyDigest) {
        self.inner.set_proxy_digest(digest);
    }
}

impl<S: GetSocketDigest> GetSocketDigest for FirstReadDeadline<S> {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.inner.get_socket_digest()
    }

    fn set_socket_digest(&mut self, digest: SocketDigest) {
        self.inner.set_socket_digest(digest);
    }
}

#[async_trait]
impl<S: Peek + Send> Peek for FirstReadDeadline<S> {
    async fn try_peek(&mut self, buffer: &mut [u8]) -> io::Result<bool> {
        self.inner.try_peek(buffer).await
    }
}
