use super::*;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
};
use pingora::protocols::{ALPN, tls::SslStream};
use std::{
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const DAY: i64 = 86_400;

fn key_pair() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

/// A self-signed leaf valid from `from` to `until` days relative to now.
fn certificate(key: &PKey<Private>, from: i64, until: i64) -> X509 {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "site-a.example").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(now + from * DAY).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(now + until * DAY).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("site-a.example")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(san).unwrap();
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build()
}

/// Scratch directory under the system temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "xshield-edge-transport-{}-{name}",
            std::process::id()
        ));
        drop(std::fs::remove_dir_all(&path));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

fn lookup(entries: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
    move |name| {
        entries
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
    }
}

/// A valid certificate and 0600 key written to `scratch`.
fn valid_pair(scratch: &Scratch) -> (PathBuf, PathBuf) {
    let key = key_pair();
    let cert = scratch.write(
        "cert.pem",
        &certificate(&key, -1, 30).to_pem().unwrap(),
        0o644,
    );
    let key = scratch.write("key.pem", &key.private_key_to_pem_pkcs8().unwrap(), 0o600);
    (cert, key)
}

fn tls_config(scratch: &Scratch, trusted: Option<&str>) -> TransportConfig {
    let (cert, key) = valid_pair(scratch);
    let mut entries = vec![
        (TLS_CERT_PATH_ENV, cert.into_os_string()),
        (TLS_KEY_PATH_ENV, key.into_os_string()),
    ];
    if let Some(trusted) = trusted {
        entries.push((PROXY_PROTOCOL_TRUSTED_ENV, OsString::from(trusted)));
    }
    TransportConfig::from_lookup(lookup(entries)).unwrap()
}

fn plain_config(trusted: &str) -> TransportConfig {
    TransportConfig::from_lookup(lookup(vec![(
        PROXY_PROTOCOL_TRUSTED_ENV,
        OsString::from(trusted),
    )]))
    .unwrap()
}

const FAST: TransportLimits = TransportLimits {
    proxy_header: Duration::from_millis(200),
    tls_handshake: Duration::from_millis(400),
    first_request: Duration::from_millis(300),
};

/// Accepts one connection on loopback and runs it through the transport.
async fn serve_one(transport: Arc<EdgeTransport>) -> (SocketAddr, JoinHandle<Option<Stream>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.unwrap();
        let setup = transport.admit(peer, &ListenerSetupSlots::new())?;
        transport.establish(tcp, setup).await
    });
    (address, task)
}

fn client_address(stream: &Stream) -> SocketAddr {
    match stream.get_socket_digest().unwrap().peer_addr() {
        Some(PingoraSocketAddr::Inet(address)) => *address,
        other => panic!("no inet peer address: {other:?}"),
    }
}

fn connector(version: SslVersion) -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_min_proto_version(Some(version)).unwrap();
    builder.set_max_proto_version(Some(version)).unwrap();
    builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
    builder.build()
}

async fn tls_client(tcp: TcpStream, version: SslVersion) -> SslStream<TcpStream> {
    let ssl = connector(version)
        .configure()
        .unwrap()
        .into_ssl("site-a.example")
        .unwrap();
    let mut stream = SslStream::new(ssl, tcp).unwrap();
    stream.connect().await.unwrap();
    stream
}

#[test]
fn no_variables_mean_plaintext_without_proxy_protocol() {
    let config = TransportConfig::from_lookup(|_| None).unwrap();
    assert!(!config.tls_enabled());
    assert!(!config.proxy_protocol_enabled());
    let config = plain_config("  ");
    assert!(!config.proxy_protocol_enabled(), "empty list leaves it off");
    let status = EdgeTransport::new(TransportConfig::plaintext()).status();
    assert_eq!(
        status,
        TransportStatus {
            tls_enabled: false,
            tls_handshake_failures: 0,
            proxy_protocol_enabled: false,
            proxy_header_rejections: 0,
            setup_shed: 0,
        }
    );
}

#[test]
fn partial_or_empty_tls_configuration_never_falls_back_to_plaintext() {
    let scratch = Scratch::new("partial");
    let (cert, key) = valid_pair(&scratch);
    let only_cert = TransportConfig::from_lookup(lookup(vec![(
        TLS_CERT_PATH_ENV,
        cert.clone().into_os_string(),
    )]));
    assert!(matches!(
        only_cert,
        Err(TransportConfigError::TlsPartiallyConfigured {
            missing: TLS_KEY_PATH_ENV
        })
    ));
    let only_key = TransportConfig::from_lookup(lookup(vec![(
        TLS_KEY_PATH_ENV,
        key.clone().into_os_string(),
    )]));
    assert!(matches!(
        only_key,
        Err(TransportConfigError::TlsPartiallyConfigured {
            missing: TLS_CERT_PATH_ENV
        })
    ));
    let empty_key = TransportConfig::from_lookup(lookup(vec![
        (TLS_CERT_PATH_ENV, cert.into_os_string()),
        (TLS_KEY_PATH_ENV, OsString::new()),
    ]));
    assert!(matches!(
        empty_key,
        Err(TransportConfigError::EmptyValue {
            variable: TLS_KEY_PATH_ENV
        })
    ));
}

#[test]
fn key_files_open_to_group_or_other_stop_startup() {
    let scratch = Scratch::new("modes");
    let (cert, key) = valid_pair(&scratch);
    let load = || {
        TransportConfig::from_lookup(lookup(vec![
            (TLS_CERT_PATH_ENV, cert.clone().into_os_string()),
            (TLS_KEY_PATH_ENV, key.clone().into_os_string()),
        ]))
    };
    for mode in [0o644, 0o640, 0o604, 0o620, 0o602, 0o660] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = load().err().unwrap();
        assert!(
            matches!(error, TransportConfigError::KeyPermissions { mode: found, .. } if found & 0o777 == mode),
            "mode {mode:o}: {error}"
        );
        assert!(error.to_string().contains("chmod 600"));
    }
    for mode in [0o600, 0o400] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(load().unwrap().tls_enabled(), "mode {mode:o}");
    }
}

#[test]
fn unusable_certificate_material_stops_startup_without_echoing_it() {
    let scratch = Scratch::new("material");
    let key = key_pair();
    let other_key = key_pair();
    let good_cert = scratch.write(
        "good.pem",
        &certificate(&key, -1, 30).to_pem().unwrap(),
        0o644,
    );
    let expired = scratch.write(
        "expired.pem",
        &certificate(&key, -10, -1).to_pem().unwrap(),
        0o644,
    );
    let future = scratch.write(
        "future.pem",
        &certificate(&key, 2, 30).to_pem().unwrap(),
        0o644,
    );
    let garbage = scratch.write(
        "garbage.pem",
        b"-----BEGIN CERTIFICATE-----\nnot base64\n",
        0o644,
    );
    let key_pem = key.private_key_to_pem_pkcs8().unwrap();
    let good_key = scratch.write("key.pem", &key_pem, 0o600);
    let wrong_key = scratch.write(
        "wrong.pem",
        &other_key.private_key_to_pem_pkcs8().unwrap(),
        0o600,
    );
    let garbage_key = scratch.write(
        "garbage-key.pem",
        b"secret-material-that-must-not-leak",
        0o600,
    );
    let missing = scratch.0.join("missing.pem");
    let load = |cert: &Path, key: &Path| {
        TransportConfig::from_lookup(lookup(vec![
            (TLS_CERT_PATH_ENV, cert.as_os_str().to_owned()),
            (TLS_KEY_PATH_ENV, key.as_os_str().to_owned()),
        ]))
        .err()
        .unwrap()
    };
    assert!(matches!(
        load(&good_cert, &wrong_key),
        TransportConfigError::KeyMismatch
    ));
    assert!(matches!(
        load(&expired, &good_key),
        TransportConfigError::CertificateNotCurrentlyValid { .. }
    ));
    assert!(matches!(
        load(&future, &good_key),
        TransportConfigError::CertificateNotCurrentlyValid { .. }
    ));
    assert!(matches!(
        load(&garbage, &good_key),
        TransportConfigError::InvalidCertificate { .. }
    ));
    let error = load(&good_cert, &garbage_key);
    assert!(matches!(
        error,
        TransportConfigError::InvalidPrivateKey { .. }
    ));
    assert!(!error.to_string().contains("secret-material"));
    assert!(matches!(
        load(&missing, &good_key),
        TransportConfigError::Unreadable {
            variable: TLS_CERT_PATH_ENV,
            ..
        }
    ));
    assert!(matches!(
        load(&good_cert, &scratch.0),
        TransportConfigError::NotRegularFile {
            variable: TLS_KEY_PATH_ENV,
            ..
        }
    ));
}

#[test]
fn invalid_trusted_balancer_lists_stop_startup() {
    for value in [
        "10.0.0.0/8,",
        "0.0.0.0/0",
        "10.0.0.1/8",
        "balancer.internal",
    ] {
        let error = TransportConfig::from_lookup(lookup(vec![(
            PROXY_PROTOCOL_TRUSTED_ENV,
            OsString::from(value),
        )]))
        .err()
        .unwrap();
        assert!(
            matches!(error, TransportConfigError::TrustedProxies(_)),
            "{value}"
        );
        assert!(error.to_string().starts_with(PROXY_PROTOCOL_TRUSTED_ENV));
    }
}

#[tokio::test]
async fn tls_negotiates_h2_or_http11_on_tls13_and_tls12_and_records_the_peer() {
    let scratch = Scratch::new("handshake");
    let transport = Arc::new(EdgeTransport::new(tls_config(&scratch, None)));
    for (version, name) in [
        (SslVersion::TLS1_3, "TLSv1.3"),
        (SslVersion::TLS1_2, "TLSv1.2"),
    ] {
        let (address, server) = serve_one(Arc::clone(&transport)).await;
        let tcp = TcpStream::connect(address).await.unwrap();
        let local = tcp.local_addr().unwrap();
        let client = tls_client(tcp, version).await;
        assert_eq!(client.ssl().version_str(), name);
        assert_eq!(client.ssl().selected_alpn_protocol(), Some(&b"h2"[..]));
        let stream = server.await.unwrap().expect("handshake succeeds");
        assert_eq!(stream.selected_alpn_proto(), Some(ALPN::H2));
        assert_eq!(client_address(&stream), local);
        assert_eq!(
            stream.get_socket_digest().unwrap().local_addr().cloned(),
            Some(PingoraSocketAddr::Inet(address))
        );
    }
    // A client offering only HTTP/1.1 gets it.
    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_alpn_protos(b"\x08http/1.1").unwrap();
    let ssl = builder
        .build()
        .configure()
        .unwrap()
        .into_ssl("site-a.example")
        .unwrap();
    let mut client = SslStream::new(ssl, TcpStream::connect(address).await.unwrap()).unwrap();
    client.connect().await.unwrap();
    let stream = server.await.unwrap().unwrap();
    assert_eq!(stream.selected_alpn_proto(), Some(ALPN::H1));
    assert_eq!(transport.status().tls_handshake_failures, 0);
}

/// A TLS 1.1 `ClientHello` without extensions, built by hand so the refusal
/// is the server's and not the local TLS library's policy.
fn tls11_client_hello() -> Vec<u8> {
    let mut body = vec![0x03, 0x02];
    body.extend_from_slice(&[0x5a; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x04, 0xc0, 0x13, 0x00, 0x2f]);
    body.extend_from_slice(&[0x01, 0x00]);
    let mut handshake = vec![0x01, 0x00, 0x00, u8::try_from(body.len()).unwrap()];
    handshake.extend_from_slice(&body);
    let mut record = vec![
        0x16,
        0x03,
        0x01,
        0x00,
        u8::try_from(handshake.len()).unwrap(),
    ];
    record.extend_from_slice(&handshake);
    record
}

#[tokio::test]
async fn tls11_plaintext_and_silent_clients_are_refused_and_counted() {
    let scratch = Scratch::new("refusals");
    let transport = Arc::new(EdgeTransport::with_limits(
        tls_config(&scratch, None),
        FAST,
        MAX_PENDING_SETUPS,
    ));
    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(&tls11_client_hello()).await.unwrap();
    let mut reply = Vec::new();
    tcp.read_to_end(&mut reply).await.unwrap();
    // A fatal protocol_version alert, never a ServerHello.
    assert_eq!(reply.first(), Some(&0x15), "{reply:?}");
    assert_eq!(reply.get(5..7), Some(&[0x02, 0x46][..]), "{reply:?}");
    assert!(server.await.unwrap().is_none());
    assert_eq!(transport.status().tls_handshake_failures, 1);

    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: site-a.example\r\n\r\n")
        .await
        .unwrap();
    assert!(server.await.unwrap().is_none());
    assert_eq!(transport.status().tls_handshake_failures, 2);

    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let _silent = TcpStream::connect(address).await.unwrap();
    let started = std::time::Instant::now();
    assert!(server.await.unwrap().is_none());
    assert!(started.elapsed() >= FAST.tls_handshake);
    assert_eq!(transport.status().tls_handshake_failures, 3);
}

fn proxy_v2_tcp(source: [u8; 4], port: u16) -> Vec<u8> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0c".to_vec();
    header.extend_from_slice(&source);
    header.extend_from_slice(&[127, 0, 0, 1]);
    header.extend_from_slice(&port.to_be_bytes());
    header.extend_from_slice(&443_u16.to_be_bytes());
    header
}

fn proxy_v2_tcp6(source: std::net::Ipv6Addr, port: u16) -> Vec<u8> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n\x21\x21\x00\x24".to_vec();
    header.extend_from_slice(&source.octets());
    header.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    header.extend_from_slice(&port.to_be_bytes());
    header.extend_from_slice(&443_u16.to_be_bytes());
    header
}

async fn read_some(stream: &mut Stream, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await.unwrap();
    bytes
}

#[tokio::test]
async fn trusted_balancer_headers_set_the_client_address() {
    let transport = Arc::new(EdgeTransport::with_limits(
        plain_config("127.0.0.1/32"),
        FAST,
        MAX_PENDING_SETUPS,
    ));
    let cases: [(Vec<u8>, SocketAddr); 3] = [
        (
            b"PROXY TCP4 198.51.100.7 127.0.0.1 51234 443\r\n".to_vec(),
            "198.51.100.7:51234".parse().unwrap(),
        ),
        (
            proxy_v2_tcp([203, 0, 113, 9], 40_000),
            "203.0.113.9:40000".parse().unwrap(),
        ),
        // IPv4-mapped sources are keyed as IPv4.
        (
            proxy_v2_tcp6("::ffff:198.51.100.8".parse().unwrap(), 7),
            "198.51.100.8:7".parse().unwrap(),
        ),
    ];
    for (header, expected) in cases {
        let (address, server) = serve_one(Arc::clone(&transport)).await;
        let mut tcp = TcpStream::connect(address).await.unwrap();
        // Header and request in one write: the surplus must reach HTTP intact.
        tcp.write_all(&[header.as_slice(), b"GET / HTTP/1.1\r\n"].concat())
            .await
            .unwrap();
        let mut stream = server.await.unwrap().expect("header accepted");
        assert_eq!(client_address(&stream), expected);
        assert_eq!(read_some(&mut stream, 16).await, b"GET / HTTP/1.1\r\n");
    }
    assert_eq!(transport.status().proxy_header_rejections, 0);
}

#[tokio::test]
async fn a_second_header_inside_the_stream_is_never_parsed() {
    let transport = Arc::new(EdgeTransport::with_limits(
        plain_config("127.0.0.1/32"),
        FAST,
        MAX_PENDING_SETUPS,
    ));
    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    let spoof = b"PROXY TCP4 192.0.2.66 127.0.0.1 1 443\r\n";
    tcp.write_all(
        &[
            b"PROXY TCP4 198.51.100.7 127.0.0.1 51234 443\r\n".as_slice(),
            spoof,
        ]
        .concat(),
    )
    .await
    .unwrap();
    let mut stream = server.await.unwrap().unwrap();
    assert_eq!(
        client_address(&stream),
        "198.51.100.7:51234".parse().unwrap()
    );
    // The client's own header stays HTTP input, which the parser refuses.
    assert_eq!(read_some(&mut stream, spoof.len()).await, spoof);
}

#[tokio::test]
async fn local_and_unknown_headers_keep_the_balancer_address() {
    let transport = Arc::new(EdgeTransport::with_limits(
        plain_config("127.0.0.1"),
        FAST,
        MAX_PENDING_SETUPS,
    ));
    for header in [
        b"PROXY UNKNOWN\r\n".to_vec(),
        b"\r\n\r\n\0\r\nQUIT\n\x20\x00\x00\x00".to_vec(),
        b"\r\n\r\n\0\r\nQUIT\n\x21\x00\x00\x00".to_vec(),
    ] {
        let (address, server) = serve_one(Arc::clone(&transport)).await;
        let mut tcp = TcpStream::connect(address).await.unwrap();
        let local = tcp.local_addr().unwrap();
        tcp.write_all(&header).await.unwrap();
        let stream = server.await.unwrap().unwrap();
        assert_eq!(client_address(&stream), local);
    }
}

#[tokio::test]
async fn trusted_peers_without_a_valid_header_are_closed_and_counted() {
    let transport = Arc::new(EdgeTransport::with_limits(
        plain_config("127.0.0.0/8"),
        FAST,
        MAX_PENDING_SETUPS,
    ));
    let mut expected = 0;
    for bytes in [
        &b"GET / HTTP/1.1\r\nHost: site-a.example\r\n\r\n"[..],
        b"\x16\x03\x01\x00\x10",
        b"PROXY TCP4 198.51.100.7 127.0.0.1 51234\r\n",
        b"\r\n\r\n\0\r\nQUIT\n\x21\x12\x00\x0c",
    ] {
        let (address, server) = serve_one(Arc::clone(&transport)).await;
        let mut tcp = TcpStream::connect(address).await.unwrap();
        tcp.write_all(bytes).await.unwrap();
        assert!(server.await.unwrap().is_none(), "{bytes:?}");
        expected += 1;
        assert_eq!(transport.status().proxy_header_rejections, expected);
    }
    // Silence and early close are bounded too.
    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let _silent = TcpStream::connect(address).await.unwrap();
    assert!(server.await.unwrap().is_none());
    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(b"PROXY TCP4 198.51").await.unwrap();
    drop(tcp);
    assert!(server.await.unwrap().is_none());
    assert_eq!(transport.status().proxy_header_rejections, expected + 2);
}

#[tokio::test]
async fn untrusted_peers_keep_their_address_and_their_header_is_just_bytes() {
    let transport = Arc::new(EdgeTransport::with_limits(
        plain_config("10.0.0.0/8"),
        FAST,
        MAX_PENDING_SETUPS,
    ));
    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    let local = tcp.local_addr().unwrap();
    let header = b"PROXY TCP4 198.51.100.7 127.0.0.1 51234 443\r\n";
    tcp.write_all(header).await.unwrap();
    let mut stream = server.await.unwrap().unwrap();
    assert_eq!(client_address(&stream), local);
    assert_eq!(read_some(&mut stream, header.len()).await, header);
    assert_eq!(transport.status().proxy_header_rejections, 0);
}

#[tokio::test]
async fn the_proxy_header_precedes_the_tls_handshake() {
    let scratch = Scratch::new("proxy-tls");
    let transport = Arc::new(EdgeTransport::with_limits(
        tls_config(&scratch, Some("127.0.0.1/32")),
        FAST,
        MAX_PENDING_SETUPS,
    ));
    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(&proxy_v2_tcp([198, 51, 100, 20], 9))
        .await
        .unwrap();
    let client = tls_client(tcp, SslVersion::TLS1_3).await;
    let stream = server.await.unwrap().unwrap();
    assert_eq!(client_address(&stream), "198.51.100.20:9".parse().unwrap());
    assert_eq!(stream.selected_alpn_proto(), Some(ALPN::H2));
    drop(client);
    // A TLS ClientHello without the header is refused before the handshake.
    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(&tls11_client_hello()).await.unwrap();
    assert!(server.await.unwrap().is_none());
    let status = transport.status();
    assert_eq!(
        (
            status.proxy_header_rejections,
            status.tls_handshake_failures
        ),
        (1, 0)
    );
}

#[test]
fn setup_slots_bound_pending_connections_per_listener_and_process() {
    let scratch = Scratch::new("slots");
    let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let transport = EdgeTransport::with_limits(tls_config(&scratch, None), FAST, 2);
    let listener = ListenerSetupSlots(Arc::new(Semaphore::new(1)));
    let first = transport.admit(peer, &listener).expect("slot available");
    assert!(transport.admit(peer, &listener).is_none(), "listener full");
    let other_listener = ListenerSetupSlots::new();
    let second = transport
        .admit(peer, &other_listener)
        .expect("other listener");
    assert!(
        transport.admit(peer, &ListenerSetupSlots::new()).is_none(),
        "process full"
    );
    assert_eq!(transport.status().setup_shed, 2);
    drop(first);
    assert!(transport.admit(peer, &listener).is_some(), "slot released");
    drop(second);

    // Plain connections without PROXY protocol need no slot at all.
    let plain = EdgeTransport::with_limits(TransportConfig::plaintext(), FAST, 0);
    assert!(
        plain
            .admit(peer, &ListenerSetupSlots(Arc::new(Semaphore::new(0))))
            .is_some()
    );
    assert_eq!(plain.status().setup_shed, 0);
}

#[tokio::test]
async fn the_first_read_deadline_fires_only_before_the_first_byte() {
    let (client, server) = tokio::io::duplex(64);
    let mut silent = FirstReadDeadline::new(server, Duration::from_millis(50));
    let error = silent.read(&mut [0; 8]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    drop(client);

    let (mut client, server) = tokio::io::duplex(64);
    let mut talking = FirstReadDeadline::new(server, Duration::from_millis(50));
    client.write_all(b"PRI").await.unwrap();
    assert_eq!(talking.read(&mut [0; 8]).await.unwrap(), 3);
    tokio::time::sleep(Duration::from_millis(80)).await;
    client.write_all(b"*").await.unwrap();
    assert_eq!(talking.read(&mut [0; 8]).await.unwrap(), 1, "disarmed");
}

#[tokio::test]
async fn silent_tls_connections_are_closed_after_the_first_request_deadline() {
    let scratch = Scratch::new("first-read");
    let transport = Arc::new(EdgeTransport::with_limits(
        tls_config(&scratch, None),
        FAST,
        MAX_PENDING_SETUPS,
    ));
    let (address, server) = serve_one(Arc::clone(&transport)).await;
    let client = tls_client(
        TcpStream::connect(address).await.unwrap(),
        SslVersion::TLS1_3,
    )
    .await;
    let mut stream = server.await.unwrap().unwrap();
    let error = stream.read(&mut [0; 8]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    drop(client);
}
