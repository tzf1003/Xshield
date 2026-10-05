//! Connection setup for data-plane listeners: an optional PROXY header from a
//! trusted balancer, optional native TLS, and the socket metadata Pingora
//! reads for every request.
//!
//! Trust boundary. Whether a connection may start with a PROXY header is
//! decided from the accepted socket's real peer address
//! ([`TrustedProxies::contains`]) before any byte is read; nothing a client
//! sends can turn the check on or change its answer. The client address the
//! rest of the edge sees (rate-limit key, anonymous-source fingerprint) is
//! written exactly once, here, into the connection's Pingora [`SocketDigest`]
//! (the mechanism Pingora documents for its own `PreTlsProcess` hook), which
//! `Session::client_addr()` reads for HTTP/1 and HTTP/2 alike. When TLS is on,
//! the PROXY header precedes the handshake, as a TCP-mode balancer sends it.
//!
//! Resource bounds. Pre-HTTP work (header read, TLS handshake) runs in the
//! connection's own task and holds one slot from its listener's budget and one
//! from the process budget; a connection that finds no free slot is closed at
//! accept time, so a flood of half-open connections cannot grow memory or
//! tasks without bound. Every phase has a deadline.
//!
//! Failures. A connection that fails setup never reaches admission, so it has
//! no request and produces no per-request audit event. Failures are counted in
//! process memory and reported by the authenticated health endpoint; nothing
//! from a failed connection (bytes, certificate or key material) is logged.

mod first_read;
mod tls;

use crate::proxy_protocol::{AdvertisedClient, TrustedProxies, TrustedProxiesError, read_header};
use first_read::FirstReadDeadline;
use openssl::ssl::SslAcceptor;
use pingora::{
    apps::HttpServerOptions,
    protocols::{
        GetSocketDigest, SocketDigest, Stream, l4::socket::SocketAddr as PingoraSocketAddr,
        l4::stream::Stream as L4Stream, tls::server::handshake,
    },
};
use std::{
    ffi::OsString,
    fmt,
    net::SocketAddr,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

/// PEM certificate chain (leaf first) served on every data-plane listener.
pub const TLS_CERT_PATH_ENV: &str = "XSHIELD_EDGE_TLS_CERT_PATH";
/// PEM private key of the leaf certificate; must not be group/other accessible.
pub const TLS_KEY_PATH_ENV: &str = "XSHIELD_EDGE_TLS_KEY_PATH";
/// Comma-separated addresses/CIDR blocks of balancers that must send a PROXY
/// header; unset or empty leaves the PROXY protocol off.
pub const PROXY_PROTOCOL_TRUSTED_ENV: &str = "XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED";

/// How long a trusted balancer has to deliver its PROXY header.
pub const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a TLS handshake may take after the TCP accept (and PROXY header).
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a TLS connection may stay silent after its handshake. HTTP/1 has
/// the same bound from Pingora's request-header read timeout; HTTP/2 waits for
/// its client preface without one, so this keeps it from holding a socket.
pub const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_mins(1);
/// Idle time after which a downstream HTTP/2 connection with no open stream is
/// closed, matching the HTTP/1 keep-alive Pingora applies.
pub const H2_IDLE_TIMEOUT: Duration = Duration::from_mins(1);
/// Connections in pre-HTTP setup across the whole process.
pub const MAX_PENDING_SETUPS: usize = 1024;
/// Connections in pre-HTTP setup on one listener, so a flood against one
/// site's port cannot take every setup slot from the others.
pub const MAX_PENDING_SETUPS_PER_LISTENER: usize = 256;

/// Most bytes read from a certificate or key file.
const MAX_PEM_BYTES: u64 = 1 << 20;

/// Validated process-wide transport configuration.
#[derive(Clone)]
pub struct TransportConfig {
    tls: Option<SslAcceptor>,
    trusted_proxies: Option<TrustedProxies>,
}

/// Why the transport configuration was refused. Startup stops on every
/// variant: in particular TLS never silently degrades to plaintext. Messages
/// name variables and paths only, never file contents.
#[derive(Debug)]
pub enum TransportConfigError {
    /// One TLS variable is set without the other.
    TlsPartiallyConfigured {
        /// The variable that is missing.
        missing: &'static str,
    },
    /// A variable is present but empty.
    EmptyValue {
        /// The empty variable.
        variable: &'static str,
    },
    /// A variable that must hold text is not valid Unicode.
    NotUnicode {
        /// The offending variable.
        variable: &'static str,
    },
    /// A file cannot be opened or read.
    Unreadable {
        /// The variable naming the file.
        variable: &'static str,
        /// The configured path.
        path: PathBuf,
    },
    /// A path does not name a regular file of at most 1 MiB.
    NotRegularFile {
        /// The variable naming the file.
        variable: &'static str,
        /// The configured path.
        path: PathBuf,
    },
    /// The private key file is readable or writable by group or other.
    KeyPermissions {
        /// The configured path.
        path: PathBuf,
        /// The file's permission bits.
        mode: u32,
    },
    /// The certificate file holds no parsable PEM certificate chain.
    InvalidCertificate {
        /// The configured path.
        path: PathBuf,
    },
    /// The leaf certificate is expired or not yet valid.
    CertificateNotCurrentlyValid {
        /// The configured path.
        path: PathBuf,
    },
    /// The key file holds no parsable unencrypted PEM private key, or the TLS
    /// library refused it (for example as too weak).
    InvalidPrivateKey {
        /// The configured path.
        path: PathBuf,
    },
    /// The private key does not belong to the leaf certificate.
    KeyMismatch,
    /// The TLS library could not build the acceptor profile.
    TlsBackend,
    /// The trusted-balancer list is invalid.
    TrustedProxies(TrustedProxiesError),
}

impl fmt::Display for TransportConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsPartiallyConfigured { missing } => write!(
                formatter,
                "{TLS_CERT_PATH_ENV} and {TLS_KEY_PATH_ENV} must be set together ({missing} is missing)"
            ),
            Self::EmptyValue { variable } => write!(
                formatter,
                "{variable} is set but empty; unset it instead (TLS never falls back to plaintext)"
            ),
            Self::NotUnicode { variable } => write!(formatter, "{variable} is not valid Unicode"),
            Self::Unreadable { variable, path } => {
                write!(formatter, "{variable}: cannot read {}", path.display())
            }
            Self::NotRegularFile { variable, path } => write!(
                formatter,
                "{variable}: {} is not a regular file of at most 1 MiB",
                path.display()
            ),
            Self::KeyPermissions { path, mode } => write!(
                formatter,
                "{TLS_KEY_PATH_ENV}: {} has mode {:o}; the private key must not be accessible by group or other (chmod 600)",
                path.display(),
                mode & 0o777
            ),
            Self::InvalidCertificate { path } => write!(
                formatter,
                "{TLS_CERT_PATH_ENV}: {} holds no PEM certificate chain",
                path.display()
            ),
            Self::CertificateNotCurrentlyValid { path } => write!(
                formatter,
                "{TLS_CERT_PATH_ENV}: the leaf certificate in {} is expired or not yet valid",
                path.display()
            ),
            Self::InvalidPrivateKey { path } => write!(
                formatter,
                "{TLS_KEY_PATH_ENV}: {} holds no usable unencrypted PEM private key",
                path.display()
            ),
            Self::KeyMismatch => write!(
                formatter,
                "{TLS_KEY_PATH_ENV} does not match the certificate in {TLS_CERT_PATH_ENV}"
            ),
            Self::TlsBackend => write!(formatter, "the TLS acceptor could not be configured"),
            Self::TrustedProxies(error) => {
                write!(formatter, "{PROXY_PROTOCOL_TRUSTED_ENV}: {error}")
            }
        }
    }
}

impl std::error::Error for TransportConfigError {}

impl TransportConfig {
    /// Plaintext listeners without PROXY protocol: the behaviour when no
    /// transport variable is set.
    #[must_use]
    pub fn plaintext() -> Self {
        Self {
            tls: None,
            trusted_proxies: None,
        }
    }

    /// Reads the transport variables through `lookup` (the process
    /// environment in production) and validates them completely, loading the
    /// certificate and key when TLS is configured.
    ///
    /// # Errors
    /// [`TransportConfigError`] for a partial or empty TLS configuration, an
    /// unreadable, invalid, mismatched or over-permissive certificate/key, or
    /// an invalid trusted-balancer list.
    pub fn from_lookup<F>(lookup: F) -> Result<Self, TransportConfigError>
    where
        F: Fn(&str) -> Option<OsString>,
    {
        let certificate = configured_path(TLS_CERT_PATH_ENV, lookup(TLS_CERT_PATH_ENV))?;
        let key = configured_path(TLS_KEY_PATH_ENV, lookup(TLS_KEY_PATH_ENV))?;
        let tls = match (certificate, key) {
            (None, None) => None,
            (Some(_), None) => {
                return Err(TransportConfigError::TlsPartiallyConfigured {
                    missing: TLS_KEY_PATH_ENV,
                });
            }
            (None, Some(_)) => {
                return Err(TransportConfigError::TlsPartiallyConfigured {
                    missing: TLS_CERT_PATH_ENV,
                });
            }
            (Some(certificate), Some(key)) => Some(tls::load_acceptor(&certificate, &key)?),
        };
        let trusted_proxies = match lookup(PROXY_PROTOCOL_TRUSTED_ENV) {
            None => None,
            Some(value) => {
                let value = value
                    .into_string()
                    .map_err(|_| TransportConfigError::NotUnicode {
                        variable: PROXY_PROTOCOL_TRUSTED_ENV,
                    })?;
                TrustedProxies::parse(&value).map_err(TransportConfigError::TrustedProxies)?
            }
        };
        Ok(Self {
            tls,
            trusted_proxies,
        })
    }

    /// Whether every data-plane listener terminates TLS.
    #[must_use]
    pub const fn tls_enabled(&self) -> bool {
        self.tls.is_some()
    }

    /// Whether trusted balancers must send a PROXY header.
    #[must_use]
    pub const fn proxy_protocol_enabled(&self) -> bool {
        self.trusted_proxies.is_some()
    }
}

fn configured_path(
    variable: &'static str,
    value: Option<OsString>,
) -> Result<Option<PathBuf>, TransportConfigError> {
    match value {
        None => Ok(None),
        Some(value) if value.is_empty() => Err(TransportConfigError::EmptyValue { variable }),
        Some(value) => Ok(Some(PathBuf::from(value))),
    }
}

/// HTTP server options for the data-plane proxy: Pingora's defaults plus an
/// idle bound for downstream HTTP/2 connections (see [`H2_IDLE_TIMEOUT`]).
#[must_use]
pub fn http_server_options() -> HttpServerOptions {
    let mut options = HttpServerOptions::default();
    options.h2_idle_timeout = Some(H2_IDLE_TIMEOUT);
    options
}

/// Point-in-time transport state reported by the edge health endpoint.
/// Counters are process-lifetime totals and reset on restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportStatus {
    /// Every data-plane listener terminates TLS.
    pub tls_enabled: bool,
    /// TLS handshakes that failed or exceeded their deadline.
    pub tls_handshake_failures: u64,
    /// Trusted balancers must send a PROXY header.
    pub proxy_protocol_enabled: bool,
    /// Trusted-peer connections closed for a missing, malformed, oversized,
    /// unsupported or late PROXY header.
    pub proxy_header_rejections: u64,
    /// Connections closed at accept time because every setup slot was busy.
    pub setup_shed: u64,
}

/// The per-listener share of the setup budget. One per listening socket.
pub struct ListenerSetupSlots(Arc<Semaphore>);

impl ListenerSetupSlots {
    /// A budget of [`MAX_PENDING_SETUPS_PER_LISTENER`] slots.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Semaphore::new(MAX_PENDING_SETUPS_PER_LISTENER)))
    }
}

impl Default for ListenerSetupSlots {
    fn default() -> Self {
        Self::new()
    }
}

/// An accepted connection that may proceed to [`EdgeTransport::establish`].
/// Holds its setup slots until setup ends.
pub struct PendingSetup {
    peer: SocketAddr,
    expects_proxy_header: bool,
    _slots: Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)>,
}

#[derive(Clone, Copy)]
struct TransportLimits {
    proxy_header: Duration,
    tls_handshake: Duration,
    first_request: Duration,
}

impl TransportLimits {
    const PRODUCTION: Self = Self {
        proxy_header: PROXY_HEADER_TIMEOUT,
        tls_handshake: TLS_HANDSHAKE_TIMEOUT,
        first_request: FIRST_REQUEST_TIMEOUT,
    };
}

/// Turns accepted TCP sockets into Pingora streams. Shared by all listeners.
pub struct EdgeTransport {
    config: TransportConfig,
    limits: TransportLimits,
    setup_slots: Arc<Semaphore>,
    tls_handshake_failures: AtomicU64,
    proxy_header_rejections: AtomicU64,
    setup_shed: AtomicU64,
}

impl EdgeTransport {
    /// A transport with the production deadlines and setup budget.
    #[must_use]
    pub fn new(config: TransportConfig) -> Self {
        Self::with_limits(config, TransportLimits::PRODUCTION, MAX_PENDING_SETUPS)
    }

    fn with_limits(config: TransportConfig, limits: TransportLimits, setup_slots: usize) -> Self {
        Self {
            config,
            limits,
            setup_slots: Arc::new(Semaphore::new(setup_slots)),
            tls_handshake_failures: AtomicU64::new(0),
            proxy_header_rejections: AtomicU64::new(0),
            setup_shed: AtomicU64::new(0),
        }
    }

    /// Current configuration flags and failure counters.
    #[must_use]
    pub fn status(&self) -> TransportStatus {
        TransportStatus {
            tls_enabled: self.config.tls_enabled(),
            tls_handshake_failures: self.tls_handshake_failures.load(Ordering::Relaxed),
            proxy_protocol_enabled: self.config.proxy_protocol_enabled(),
            proxy_header_rejections: self.proxy_header_rejections.load(Ordering::Relaxed),
            setup_shed: self.setup_shed.load(Ordering::Relaxed),
        }
    }

    /// Decides, at accept time and from the socket's real peer address,
    /// whether the connection must start with a PROXY header, and reserves
    /// setup slots when it needs pre-HTTP work.
    ///
    /// Returns `None` (the caller drops the socket) when no slot is free; the
    /// refusal is counted. Plain connections need no slot.
    #[must_use]
    pub fn admit(&self, peer: SocketAddr, listener: &ListenerSetupSlots) -> Option<PendingSetup> {
        let expects_proxy_header = self
            .config
            .trusted_proxies
            .as_ref()
            .is_some_and(|trusted| trusted.contains(peer.ip()));
        let slots = if expects_proxy_header || self.config.tls_enabled() {
            let reserved = Arc::clone(&listener.0)
                .try_acquire_owned()
                .ok()
                .zip(Arc::clone(&self.setup_slots).try_acquire_owned().ok());
            if reserved.is_none() {
                self.setup_shed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            reserved
        } else {
            None
        };
        Some(PendingSetup {
            peer,
            expects_proxy_header,
            _slots: slots,
        })
    }

    /// Runs the connection's pre-HTTP setup: the PROXY header when
    /// [`Self::admit`] required one, the socket metadata, then the TLS
    /// handshake when TLS is on. Setup slots are released on return.
    ///
    /// Returns `None` when the connection must be closed; a failed header or
    /// handshake is counted, never logged.
    pub async fn establish(&self, tcp: TcpStream, setup: PendingSetup) -> Option<Stream> {
        let local = tcp.local_addr().ok()?;
        // Pingora's own listeners disable Nagle as well: small TLS records and
        // HTTP/2 frames would otherwise wait for delayed ACKs. Failing to set
        // it costs latency only.
        let _nagle_disabled = tcp.set_nodelay(true).is_ok();
        let mut stream = L4Stream::from(tcp);
        let mut client = canonical(setup.peer);
        if setup.expects_proxy_header {
            let Ok(Ok((advertised, surplus))) =
                timeout(self.limits.proxy_header, read_header(&mut stream)).await
            else {
                self.proxy_header_rejections.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            if let AdvertisedClient::Address(address) = advertised {
                client = canonical(address);
            }
            // Bytes read past the header belong to TLS or HTTP.
            stream.rewind(&surplus);
        }
        attach_addresses(&mut stream, client, local)?;
        let Some(acceptor) = self.config.tls.as_ref() else {
            return Some(Box::new(stream));
        };
        let Ok(Ok(tls)) = timeout(self.limits.tls_handshake, handshake(acceptor, stream)).await
        else {
            self.tls_handshake_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        Some(Box::new(FirstReadDeadline::new(
            tls,
            self.limits.first_request,
        )))
    }
}

/// IPv4 clients seen through IPv4-mapped IPv6 addresses are keyed as IPv4:
/// rate limiting meters IPv6 per /64, which would put every mapped IPv4
/// client into one bucket.
fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// Records the addresses every request on this connection is attributed to.
/// Both cells are filled before Pingora can read them, so its lazy
/// `getpeername` fallback never runs.
fn attach_addresses(stream: &mut L4Stream, client: SocketAddr, local: SocketAddr) -> Option<()> {
    let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
    digest
        .peer_addr
        .set(Some(PingoraSocketAddr::Inet(client)))
        .ok()?;
    digest
        .local_addr
        .set(Some(PingoraSocketAddr::Inet(local)))
        .ok()?;
    stream.set_socket_digest(digest);
    Some(())
}

/// Reads at most [`MAX_PEM_BYTES`] from a regular file, checked on the opened
/// handle. `private` additionally refuses group/other permission bits.
fn read_pem_file(
    variable: &'static str,
    path: &Path,
    private: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>, TransportConfigError> {
    use std::{io::Read, os::unix::fs::PermissionsExt};
    let unreadable = || TransportConfigError::Unreadable {
        variable,
        path: path.to_path_buf(),
    };
    let not_regular = || TransportConfigError::NotRegularFile {
        variable,
        path: path.to_path_buf(),
    };
    // Checked before opening so a FIFO cannot block startup in open().
    if !std::fs::metadata(path).map_err(|_| unreadable())?.is_file() {
        return Err(not_regular());
    }
    let file = std::fs::File::open(path).map_err(|_| unreadable())?;
    let metadata = file.metadata().map_err(|_| unreadable())?;
    if !metadata.is_file() || metadata.len() > MAX_PEM_BYTES {
        return Err(not_regular());
    }
    let mode = metadata.permissions().mode();
    if private && mode & 0o077 != 0 {
        return Err(TransportConfigError::KeyPermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    // Sized up front so the key bytes are not copied by reallocation before
    // the buffer is wiped on drop.
    let capacity = usize::try_from(metadata.len()).map_err(|_| not_regular())? + 1;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    file.take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_PEM_BYTES) {
        return Err(not_regular());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
