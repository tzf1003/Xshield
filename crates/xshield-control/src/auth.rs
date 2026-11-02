//! Administrator sign-in (docs/07-console-architecture.md section 7.9.2).
//!
//! The password is checked against a PBKDF2-SHA256 hash from the environment.
//! The session cookie is stateless: an expiry time signed with a key derived
//! from that hash, so a restart keeps every session that has not expired and
//! changing the password ends them all. Failed sign-ins are counted per client
//! address; ten failures in ten minutes lock that address out for the window.

use std::{
    collections::HashMap,
    fmt::Write as _,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use openssl::{
    base64,
    hash::{MessageDigest, hash},
    pkcs5::pbkdf2_hmac,
    pkey::PKey,
    rand::rand_bytes,
    sign::Signer,
};
use serde::{Deserialize, Serialize};
use xshield_core::constant_time;

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    params::json_body,
};

/// The session cookie name over HTTPS. The `__Host-` prefix binds it to this
/// origin, with `Secure` and `Path=/`.
pub const SESSION_COOKIE: &str = "__Host-xshield-session";
/// The session cookie name when the console is served over plain HTTP
/// (`XSHIELD_CONTROL_PLAIN_HTTP`). Browsers do not keep `Secure` cookies set by an
/// `http://` origin, and the `__Host-` prefix requires `Secure`, so this name has
/// neither.
pub const PLAIN_HTTP_SESSION_COOKIE: &str = "xshield-session";
/// How long a sign-in lasts: twelve hours.
pub const SESSION_LIFETIME_SECS: u64 = 12 * 3600;
const DEFAULT_PBKDF2_ITERATIONS: usize = 210_000;
const PBKDF2_SALT_BYTES: usize = 16;
const PBKDF2_HASH_BYTES: usize = 32;
/// Failed sign-ins one client address may make before it is locked out.
const LOGIN_FAILURES_ALLOWED: usize = 10;
/// The window the failures are counted in.
const LOGIN_WINDOW: Duration = Duration::from_secs(600);
/// The most client addresses the limiter remembers before it drops idle ones.
const LOGIN_TRACKED_MAX: usize = 10_000;

// --- Password hashing: pbkdf2-sha256$<iterations>$<salt-hex>$<hash-hex> ---

struct ParsedPasswordHash {
    iterations: usize,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn parse_password_hash(value: &str) -> Option<ParsedPasswordHash> {
    let mut parts = value.split('$');
    if parts.next()? != "pbkdf2-sha256" {
        return None;
    }
    let iterations: usize = parts.next()?.parse().ok()?;
    let salt = decode_hex(parts.next()?)?;
    let hash = decode_hex(parts.next()?)?;
    if parts.next().is_some() || iterations == 0 || salt.is_empty() || hash.is_empty() {
        return None;
    }
    Some(ParsedPasswordHash {
        iterations,
        salt,
        hash,
    })
}

/// Whether `candidate` is the password `stored_hash` was made from. A malformed
/// stored hash never verifies.
pub fn verify_password(stored_hash: &str, candidate: &str) -> bool {
    let Some(parsed) = parse_password_hash(stored_hash) else {
        return false;
    };
    let mut computed = vec![0_u8; parsed.hash.len()];
    if pbkdf2_hmac(
        candidate.as_bytes(),
        &parsed.salt,
        parsed.iterations,
        MessageDigest::sha256(),
        &mut computed,
    )
    .is_err()
    {
        return false;
    }
    constant_time::eq(&computed, &parsed.hash)
}

/// Computes a `pbkdf2-sha256$<iterations>$<salt-hex>$<hash-hex>` administrator
/// password hash, the value of `XSHIELD_ADMIN_PASSWORD_HASH`.
///
/// # Errors
/// Returns an error when the operating system cannot provide randomness or the
/// PBKDF2 computation fails.
pub fn hash_password(password: &str) -> Result<String, openssl::error::ErrorStack> {
    let mut salt = vec![0_u8; PBKDF2_SALT_BYTES];
    rand_bytes(&mut salt)?;
    let mut digest = vec![0_u8; PBKDF2_HASH_BYTES];
    pbkdf2_hmac(
        password.as_bytes(),
        &salt,
        DEFAULT_PBKDF2_ITERATIONS,
        MessageDigest::sha256(),
        &mut digest,
    )?;
    Ok(format!(
        "pbkdf2-sha256${DEFAULT_PBKDF2_ITERATIONS}${}${}",
        encode_hex(&salt),
        encode_hex(&digest)
    ))
}

/// Whether `value` has the shape [`hash_password`] produces, so a bad setting
/// fails at startup rather than at the first sign-in.
#[must_use]
pub fn is_password_hash(value: &str) -> bool {
    parse_password_hash(value).is_some()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Decodes lowercase or uppercase hex. Works on bytes, so a non-ASCII input is
/// rejected rather than sliced at a character boundary.
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

// --- Session tokens: expiry (8 bytes, big endian) || HMAC-SHA256(key, expiry) ---

/// The key that signs session tokens, derived from the password hash.
pub fn derive_session_key(admin_password_hash: &str) -> Option<[u8; 32]> {
    let digest = hash(MessageDigest::sha256(), admin_password_hash.as_bytes()).ok()?;
    <[u8; 32]>::try_from(digest.as_ref()).ok()
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Option<[u8; 32]> {
    let pkey = PKey::hmac(key).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).ok()?;
    signer.update(data).ok()?;
    let signature = signer.sign_to_vec().ok()?;
    <[u8; 32]>::try_from(signature.as_slice()).ok()
}

fn now_unix() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}

/// A token that expires [`SESSION_LIFETIME_SECS`] from now.
pub fn issue_session_token(key: &[u8; 32]) -> Option<String> {
    let expiry = now_unix().saturating_add(SESSION_LIFETIME_SECS);
    let expiry_bytes = expiry.to_be_bytes();
    let tag = hmac_sha256(key, &expiry_bytes)?;
    let mut payload = Vec::with_capacity(expiry_bytes.len() + tag.len());
    payload.extend_from_slice(&expiry_bytes);
    payload.extend_from_slice(&tag);
    Some(b64url_encode(&payload))
}

/// Whether `token` was signed with `key` and has not expired.
pub fn verify_session_token(key: &[u8; 32], token: &str) -> bool {
    let Some(payload) = b64url_decode(token) else {
        return false;
    };
    if payload.len() != 40 {
        return false;
    }
    let (expiry_bytes, tag) = payload.split_at(8);
    let Some(expected) = hmac_sha256(key, expiry_bytes) else {
        return false;
    };
    if !constant_time::eq(&expected, tag) {
        return false;
    }
    let Ok(expiry_bytes): Result<[u8; 8], _> = expiry_bytes.try_into() else {
        return false;
    };
    u64::from_be_bytes(expiry_bytes) > now_unix()
}

fn b64url_encode(data: &[u8]) -> String {
    base64::encode_block(data)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    let mut standard = value.replace('-', "+").replace('_', "/");
    while !standard.len().is_multiple_of(4) {
        standard.push('=');
    }
    base64::decode_block(&standard).ok()
}

// --- Cookies ---

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

/// The administrator cookie's name for the transport the console is served over.
#[must_use]
pub fn session_cookie_name(plain_http: bool) -> &'static str {
    if plain_http {
        PLAIN_HTTP_SESSION_COOKIE
    } else {
        SESSION_COOKIE
    }
}

fn set_session_cookie(response: &mut Response, plain_http: bool, token: &str, max_age_secs: u64) {
    // `Secure` keeps browsers from sending the cookie over plain HTTP. Only
    // `XSHIELD_CONTROL_PLAIN_HTTP` leaves it out, as an explicit trade-off.
    let secure = if plain_http { "" } else { "Secure; " };
    let name = session_cookie_name(plain_http);
    let value =
        format!("{name}={token}; Path=/; Max-Age={max_age_secs}; {secure}HttpOnly; SameSite=Lax");
    if let Ok(header_value) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .append(header::SET_COOKIE, header_value);
    }
}

/// Whether the request carries a valid, unexpired session cookie.
pub fn session_authenticated(state: &ControlState, headers: &HeaderMap) -> bool {
    cookie_value(headers, session_cookie_name(state.plain_http))
        .is_some_and(|token| verify_session_token(&state.session_key, &token))
}

// --- Failed sign-in limit, per client address ---

/// Counts failed sign-ins per client address.
#[derive(Debug, Default)]
pub struct LoginLimiter {
    failures: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl LoginLimiter {
    fn table(&self) -> MutexGuard<'_, HashMap<IpAddr, Vec<Instant>>> {
        self.failures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `address` may try to sign in at `now`.
    #[must_use]
    pub fn allows(&self, address: IpAddr, now: Instant) -> bool {
        let mut table = self.table();
        let Some(attempts) = table.get_mut(&address) else {
            return true;
        };
        attempts.retain(|at| now.duration_since(*at) < LOGIN_WINDOW);
        attempts.len() < LOGIN_FAILURES_ALLOWED
    }

    /// Records a failed sign-in from `address` at `now`.
    pub fn record_failure(&self, address: IpAddr, now: Instant) {
        let mut table = self.table();
        if table.len() >= LOGIN_TRACKED_MAX {
            table.retain(|_, attempts| {
                attempts
                    .iter()
                    .any(|at| now.duration_since(*at) < LOGIN_WINDOW)
            });
        }
        let attempts = table.entry(address).or_default();
        attempts.retain(|at| now.duration_since(*at) < LOGIN_WINDOW);
        attempts.push(now);
    }

    /// Forgets the failures of `address` after a successful sign-in.
    pub fn clear(&self, address: IpAddr) {
        self.table().remove(&address);
    }
}

fn client_address(connect: Option<&ConnectInfo<SocketAddr>>) -> IpAddr {
    connect.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ConnectInfo(address)| {
        address.ip()
    })
}

// --- Handlers ---

/// Rejects a request without a valid session cookie with `UNAUTHENTICATED`.
pub async fn require_session(
    State(state): State<Arc<ControlState>>,
    request: Request,
    next: Next,
) -> Response {
    if session_authenticated(&state, request.headers()) {
        next.run(request).await
    } else {
        ApiError::new(StatusCode::UNAUTHORIZED, "UNAUTHENTICATED").into_response()
    }
}

#[derive(Deserialize)]
struct LoginBody {
    password: String,
}

/// `POST /api/login`: exchanges the administrator password for a session cookie.
///
/// # Errors
/// `LOGIN_RATE_LIMITED` (429) after ten failures in ten minutes from the same
/// address, `INVALID_PASSWORD` (401) for a wrong password, `INVALID_BODY` for a
/// body that is not `{"password": "..."}`.
pub async fn login(
    State(state): State<Arc<ControlState>>,
    parts: Parts,
    body: Bytes,
) -> ApiResult<Response> {
    let address = client_address(parts.extensions.get::<ConnectInfo<SocketAddr>>());
    if !state.login_limiter.allows(address, Instant::now()) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "LOGIN_RATE_LIMITED",
        ));
    }
    let LoginBody { password } = json_body(&parts.headers, &body)?;
    let stored = state.admin_password_hash.clone();
    let accepted = tokio::task::spawn_blocking(move || verify_password(&stored, &password))
        .await
        .unwrap_or(false);
    if !accepted {
        state.login_limiter.record_failure(address, Instant::now());
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "INVALID_PASSWORD"));
    }
    state.login_limiter.clear(address);
    let token = issue_session_token(&state.session_key)
        .ok_or_else(|| ApiError::internal("session", "could not sign a token"))?;
    let mut response = axum::Json(SessionStateBody {
        authenticated: true,
    })
    .into_response();
    set_session_cookie(
        &mut response,
        state.plain_http,
        &token,
        SESSION_LIFETIME_SECS,
    );
    Ok(response)
}

/// `POST /api/logout`: clears the session cookie. Needs no session.
#[allow(clippy::unused_async)] // axum handlers are async functions.
pub async fn logout(State(state): State<Arc<ControlState>>) -> Response {
    let mut response = axum::Json(SessionStateBody {
        authenticated: false,
    })
    .into_response();
    set_session_cookie(&mut response, state.plain_http, "", 0);
    response
}

/// Whether the request carries a valid session, as `GET /api/session` and the sign-in
/// and sign-out responses report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStateBody {
    pub authenticated: bool,
}

/// `GET /api/session`: whether the request carries a valid session.
#[allow(clippy::unused_async)] // axum handlers are async functions.
pub async fn session(State(state): State<Arc<ControlState>>, headers: HeaderMap) -> Response {
    if session_authenticated(&state, &headers) {
        axum::Json(SessionStateBody {
            authenticated: true,
        })
        .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(SessionStateBody {
                authenticated: false,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn password_hash_round_trips() {
        let stored = hash_password("correct horse").expect("hash");
        assert!(verify_password(&stored, "correct horse"));
        assert!(!verify_password(&stored, "wrong"));
    }

    #[test]
    fn malformed_or_foreign_password_hashes_never_verify() {
        assert!(!verify_password("", "x"));
        assert!(!verify_password("pbkdf2-sha256$0$00$00", "x"));
        assert!(!verify_password("md5$1$00$00", "x"));
        assert!(!verify_password("pbkdf2-sha256$1$zz$00", "x"));
        assert!(!is_password_hash("pbkdf2-sha256$1$ééé$00"));
    }

    #[test]
    fn session_tokens_round_trip_and_reject_tampering() {
        let token = issue_session_token(&KEY).expect("token");
        assert!(verify_session_token(&KEY, &token));
        assert!(!verify_session_token(&[8; 32], &token));
        let mut tampered = token.clone();
        tampered.push('A');
        assert!(!verify_session_token(&KEY, &tampered));
    }

    #[test]
    fn session_tokens_expire() {
        let expiry = now_unix() - 1;
        let expiry_bytes = expiry.to_be_bytes();
        let tag = hmac_sha256(&KEY, &expiry_bytes).expect("tag");
        let mut payload = expiry_bytes.to_vec();
        payload.extend_from_slice(&tag);
        assert!(!verify_session_token(&KEY, &b64url_encode(&payload)));
    }

    #[test]
    fn the_limiter_locks_an_address_after_ten_failures() {
        let limiter = LoginLimiter::default();
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let start = Instant::now();
        for _ in 0..LOGIN_FAILURES_ALLOWED {
            assert!(limiter.allows(address, start));
            limiter.record_failure(address, start);
        }
        assert!(!limiter.allows(address, start));
        assert!(limiter.allows(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), start));
        limiter.clear(address);
        assert!(limiter.allows(address, start));
    }

    #[test]
    fn the_limiter_forgets_failures_after_the_window() {
        let limiter = LoginLimiter::default();
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        let start = Instant::now();
        for _ in 0..LOGIN_FAILURES_ALLOWED {
            limiter.record_failure(address, start);
        }
        assert!(limiter.allows(address, start + LOGIN_WINDOW));
    }

    #[test]
    fn the_cookie_is_secure_over_https_and_unprefixed_over_plain_http() {
        let mut https = Response::new(axum::body::Body::empty());
        set_session_cookie(&mut https, false, "token", 60);
        let https_cookie = https.headers()[header::SET_COOKIE]
            .to_str()
            .expect("ascii cookie")
            .to_owned();
        assert_eq!(
            https_cookie,
            "__Host-xshield-session=token; Path=/; Max-Age=60; Secure; HttpOnly; SameSite=Lax"
        );

        let mut plain = Response::new(axum::body::Body::empty());
        set_session_cookie(&mut plain, true, "token", 60);
        let plain_cookie = plain.headers()[header::SET_COOKIE]
            .to_str()
            .expect("ascii cookie")
            .to_owned();
        assert_eq!(
            plain_cookie,
            "xshield-session=token; Path=/; Max-Age=60; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn non_ascii_hex_is_rejected_without_slicing() {
        assert_eq!(decode_hex("é0"), None);
        assert_eq!(decode_hex("0a0B"), Some(vec![0x0a, 0x0b]));
    }
}
