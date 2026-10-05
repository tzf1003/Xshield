//! The process-wide edge certificate and its TLS acceptor profile.
//!
//! Profile: Mozilla "intermediate" v5 (TLS 1.2 with AEAD ECDHE/DHE suites,
//! TLS 1.3), an explicit TLS 1.2 floor, ALPN `h2` then `http/1.1`, no
//! renegotiation and no session tickets. OpenSSL generates the ticket key once
//! per process and never rotates it, so tickets would let anyone who obtains
//! that key decrypt every resumed session for the process lifetime; stateful
//! resumption from OpenSSL's bounded in-memory session cache is kept instead.
//! One certificate serves every listener and SNI is not consulted: per-site
//! certificates are out of scope, and routing stays on Host/`:authority`.

use super::{TLS_CERT_PATH_ENV, TLS_KEY_PATH_ENV, TransportConfigError, read_pem_file};
// The same openssl crate Pingora's TLS layer is built on (one version in the
// lock file), so these are the types `pingora::protocols::tls` accepts.
use openssl::{
    asn1::Asn1Time,
    pkey::PKey,
    ssl::{AlpnError, SslAcceptor, SslMethod, SslOptions, SslRef, SslVersion, select_next_proto},
    x509::X509,
};
use std::{cmp::Ordering, path::Path};

/// Server ALPN preference in wire format: HTTP/2, then HTTP/1.1.
const ALPN_PREFERENCE: &[u8] = b"\x02h2\x08http/1.1";

/// Loads and cross-checks the certificate chain and key, then builds the
/// acceptor. Nothing is logged; errors name the variable and path only.
pub(super) fn load_acceptor(
    certificate_path: &Path,
    key_path: &Path,
) -> Result<SslAcceptor, TransportConfigError> {
    let invalid_certificate = || TransportConfigError::InvalidCertificate {
        path: certificate_path.to_path_buf(),
    };
    let invalid_key = || TransportConfigError::InvalidPrivateKey {
        path: key_path.to_path_buf(),
    };
    let chain = read_pem_file(TLS_CERT_PATH_ENV, certificate_path, false)?;
    let mut chain = X509::stack_from_pem(&chain)
        .map_err(|_| invalid_certificate())?
        .into_iter();
    let leaf = chain.next().ok_or_else(invalid_certificate)?;
    let now = Asn1Time::days_from_now(0).map_err(|_| TransportConfigError::TlsBackend)?;
    let current = leaf.not_before().compare(&now).ok() != Some(Ordering::Greater)
        && leaf.not_after().compare(&now).ok() == Some(Ordering::Greater);
    if !current {
        return Err(TransportConfigError::CertificateNotCurrentlyValid {
            path: certificate_path.to_path_buf(),
        });
    }
    let key_pem = read_pem_file(TLS_KEY_PATH_ENV, key_path, true)?;
    let key = PKey::private_key_from_pem(&key_pem).map_err(|_| invalid_key())?;
    drop(key_pem);
    // Checked explicitly so a key from another pair is reported as such
    // rather than as an unusable key.
    if !leaf
        .public_key()
        .is_ok_and(|certified| certified.public_eq(&key))
    {
        return Err(TransportConfigError::KeyMismatch);
    }

    let backend = |_| TransportConfigError::TlsBackend;
    let mut builder =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).map_err(backend)?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(backend)?;
    builder.set_options(SslOptions::NO_TICKET | SslOptions::NO_RENEGOTIATION);
    builder.set_alpn_select_callback(select_alpn);
    builder
        .set_certificate(&leaf)
        .map_err(|_| invalid_certificate())?;
    for intermediate in chain {
        builder
            .add_extra_chain_cert(intermediate)
            .map_err(|_| invalid_certificate())?;
    }
    builder.set_private_key(&key).map_err(|_| invalid_key())?;
    builder
        .check_private_key()
        .map_err(|_| TransportConfigError::KeyMismatch)?;
    Ok(builder.build())
}

/// Picks `h2` when offered, else `http/1.1`; with neither (or an empty list)
/// the handshake continues without ALPN and the connection speaks HTTP/1.1.
fn select_alpn<'a>(_: &mut SslRef, offered: &'a [u8]) -> Result<&'a [u8], AlpnError> {
    if offered.is_empty() {
        return Err(AlpnError::NOACK);
    }
    select_next_proto(ALPN_PREFERENCE, offered).ok_or(AlpnError::NOACK)
}
