//! Xshield control-plane HTTP backend (docs/03-admin-config-audit.md).
//!
//! A v4 deployment has a single administrator who signs in with a password,
//! manages site configuration (with history and rollback), and reads the
//! decision log the gateway writes. There is no case management, evidence
//! access approval, OIDC, multi-role authorization, or API keys: those are
//! all v3 mechanisms removed per docs/05-v3-removal.md.
//!
//! This crate performs no security decisions of its own: the gateway judges
//! requests and writes the decision log; this crate only stores and serves
//! site configuration and lets the administrator query that log.

#![warn(missing_docs)]

use std::{fmt::Write as _, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{SecondsFormat, Utc};
use openssl::{
    base64,
    hash::{MessageDigest, hash},
    pkcs5::pbkdf2_hmac,
    pkey::PKey,
    rand::rand_bytes,
    sign::Signer,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use xshield_core::{constant_time, context::SiteSpec, context::log::DecisionRecord};
use xshield_postgres::{
    decision_log_store::{self, DecisionLogFilter, DecisionLogRow, DecisionLogStoreError},
    site_spec_store::{self, HistoryEntry, RollbackOutcome, SiteRecord, SiteSpecStoreError},
};

#[cfg(test)]
mod tests;

const SESSION_COOKIE: &str = "__Host-xshield-session";
const SESSION_LIFETIME_SECS: u64 = 12 * 3600;
const DEFAULT_PBKDF2_ITERATIONS: usize = 210_000;
const PBKDF2_SALT_BYTES: usize = 16;
const PBKDF2_HASH_BYTES: usize = 32;
const DEFAULT_HISTORY_LIMIT: i64 = 50;
const MAX_HISTORY_LIMIT: i64 = 200;
/// How long a decision log row is kept before the retention loop deletes it.
pub const DECISION_LOG_RETENTION_SECS: i64 = 7 * 24 * 3600;

/// Shared control-plane state: the database pool, the session-signing key
/// derived from the admin password hash, and the optional console CORS origin.
pub struct ControlState {
    pool: PgPool,
    admin_password_hash: String,
    session_key: [u8; 32],
    console_origin: Option<String>,
}

impl ControlState {
    /// Builds control-plane state from a database pool and the
    /// operator-configured `XSHIELD_ADMIN_PASSWORD_HASH` value.
    ///
    /// # Errors
    /// Returns [`StartupError`] when the password hash is missing or not in
    /// the `pbkdf2-sha256$<iterations>$<salt-hex>$<hash-hex>` format, or when
    /// the session signing key cannot be derived.
    pub fn new(
        pool: PgPool,
        admin_password_hash: String,
        console_origin: Option<String>,
    ) -> Result<Arc<Self>, StartupError> {
        if parse_password_hash(&admin_password_hash).is_none() {
            return Err(StartupError::InvalidAdminPasswordHash);
        }
        let session_key = derive_session_key(&admin_password_hash)
            .ok_or(StartupError::KeyDerivationUnavailable)?;
        Ok(Arc::new(Self {
            pool,
            admin_password_hash,
            session_key,
            console_origin,
        }))
    }

    /// The database pool, for the executable's background retention loop.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// A control-plane startup configuration failure.
#[derive(Debug)]
pub enum StartupError {
    /// `XSHIELD_ADMIN_PASSWORD_HASH` is missing or not in the expected format.
    InvalidAdminPasswordHash,
    /// The runtime could not derive the session signing key (hash failure).
    KeyDerivationUnavailable,
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAdminPasswordHash => "XSHIELD_ADMIN_PASSWORD_HASH is missing or malformed",
            Self::KeyDerivationUnavailable => "could not derive the session signing key",
        })
    }
}

impl std::error::Error for StartupError {}

// --- Password hashing (pbkdf2-sha256$<iterations>$<salt-hex>$<hash-hex>) ---

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

fn verify_password(stored_hash: &str, candidate: &str) -> bool {
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

/// Computes a `pbkdf2-sha256$<iterations>$<salt-hex>$<hash-hex>` admin
/// password hash, for the `hash-password` CLI helper that produces the value
/// of `XSHIELD_ADMIN_PASSWORD_HASH`.
///
/// # Errors
/// Returns an error if the operating system cannot provide randomness or the
/// underlying PBKDF2 computation fails.
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

fn encode_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

// --- Session tokens: HMAC(sha256(admin_password_hash), expiry) ---

fn derive_session_key(admin_password_hash: &str) -> Option<[u8; 32]> {
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

fn issue_session_token(key: &[u8; 32]) -> Option<String> {
    let expiry = now_unix().saturating_add(SESSION_LIFETIME_SECS);
    let expiry_bytes = expiry.to_be_bytes();
    let tag = hmac_sha256(key, &expiry_bytes)?;
    let mut payload = Vec::with_capacity(expiry_bytes.len() + tag.len());
    payload.extend_from_slice(&expiry_bytes);
    payload.extend_from_slice(&tag);
    Some(b64url_encode(&payload))
}

fn verify_session_token(key: &[u8; 32], token: &str) -> bool {
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

fn set_session_cookie(response: &mut Response, token: &str, max_age_secs: u64) {
    let value = format!(
        "{SESSION_COOKIE}={token}; Path=/; Max-Age={max_age_secs}; Secure; HttpOnly; SameSite=Lax"
    );
    if let Ok(header_value) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .append(header::SET_COOKIE, header_value);
    }
}

fn session_authenticated(state: &ControlState, headers: &HeaderMap) -> bool {
    cookie_value(headers, SESSION_COOKIE)
        .is_some_and(|token| verify_session_token(&state.session_key, &token))
}

// --- Auth gate and CORS, as axum middleware ---

async fn auth_middleware(
    State(state): State<Arc<ControlState>>,
    request: Request,
    next: Next,
) -> Response {
    if session_authenticated(&state, request.headers()) {
        next.run(request).await
    } else {
        json_error(StatusCode::UNAUTHORIZED, "UNAUTHENTICATED")
    }
}

async fn cors_middleware(
    State(state): State<Arc<ControlState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(origin) = state.console_origin.clone() else {
        return next.run(request).await;
    };
    if request.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        apply_cors_headers(&mut response, &origin);
        return response;
    }
    let mut response = next.run(request).await;
    apply_cors_headers(&mut response, &origin);
    response
}

fn apply_cors_headers(response: &mut Response, origin: &str) {
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
}

// --- Router ---

/// Builds the complete control-plane HTTP router: public auth endpoints,
/// `/health`, and the session-gated `/api/*` surface for sites and the
/// decision log.
pub fn router(state: Arc<ControlState>) -> Router {
    let protected = Router::new()
        .route("/api/sites", get(sites_list).post(sites_create))
        .route(
            "/api/sites/{name}",
            get(sites_get).put(sites_update).delete(sites_delete),
        )
        .route("/api/sites/{name}/history", get(sites_history))
        .route(
            "/api/sites/{name}/history/{id}/rollback",
            post(sites_rollback),
        )
        .route("/api/decisions", get(decisions_list))
        .route("/api/decisions/{id}", get(decisions_get))
        .route("/api/jev/status", get(jev_status_handler))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth_middleware,
        ));

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .route("/api/session", get(session_handler))
        .merge(protected)
        .with_state(Arc::clone(&state));

    if state.console_origin.is_some() {
        app.layer(middleware::from_fn_with_state(state, cors_middleware))
    } else {
        app
    }
}

fn json_error(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({ "error": code }))).into_response()
}

async fn health_handler() -> &'static str {
    "ok"
}

// --- Auth endpoints ---

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

async fn login_handler(
    State(state): State<Arc<ControlState>>,
    Json(body): Json<LoginRequest>,
) -> Response {
    if !verify_password(&state.admin_password_hash, &body.password) {
        return json_error(StatusCode::UNAUTHORIZED, "INVALID_PASSWORD");
    }
    let Some(token) = issue_session_token(&state.session_key) else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "SESSION_UNAVAILABLE");
    };
    let mut response = Json(serde_json::json!({})).into_response();
    set_session_cookie(&mut response, &token, SESSION_LIFETIME_SECS);
    response
}

async fn logout_handler() -> Response {
    let mut response = Json(serde_json::json!({})).into_response();
    set_session_cookie(&mut response, "", 0);
    response
}

async fn session_handler(State(state): State<Arc<ControlState>>, headers: HeaderMap) -> Response {
    if session_authenticated(&state, &headers) {
        Json(serde_json::json!({ "authenticated": true })).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "authenticated": false })),
        )
            .into_response()
    }
}

// --- Site configuration wire shapes ---

#[derive(Serialize)]
struct SiteRecordWire<'a> {
    #[serde(flatten)]
    spec: &'a SiteSpec,
    version: i64,
    created_at: String,
    updated_at: String,
}

fn site_record_wire(record: &SiteRecord) -> SiteRecordWire<'_> {
    SiteRecordWire {
        spec: &record.spec,
        version: record.version,
        created_at: record
            .created_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        updated_at: record
            .updated_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    }
}

#[derive(Serialize)]
struct HistoryEntryWire<'a> {
    id: i64,
    before: Option<&'a SiteSpec>,
    after: Option<&'a SiteSpec>,
    changed_at: String,
}

fn history_entry_wire(entry: &HistoryEntry) -> HistoryEntryWire<'_> {
    HistoryEntryWire {
        id: entry.id,
        before: entry.before.as_ref(),
        after: entry.after.as_ref(),
        changed_at: entry
            .changed_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    }
}

fn site_store_error_response(error: &SiteSpecStoreError) -> Response {
    eprintln!("xshield-control: site store error: {error}");
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
}

#[allow(clippy::result_large_err)] // the error is the ready HTTP response, which the caller returns as is
fn parse_site_body(body: &Bytes) -> Result<SiteSpec, Response> {
    let text = std::str::from_utf8(body)
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "SITE_CONFIG_MALFORMED"))?;
    SiteSpec::from_json(text)
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, &error.to_string()))
}

// --- Site endpoints ---

async fn sites_list(State(state): State<Arc<ControlState>>) -> Response {
    match site_spec_store::list(&state.pool).await {
        Ok(records) => {
            Json(records.iter().map(site_record_wire).collect::<Vec<_>>()).into_response()
        }
        Err(error) => site_store_error_response(&error),
    }
}

async fn sites_create(State(state): State<Arc<ControlState>>, body: Bytes) -> Response {
    let spec = match parse_site_body(&body) {
        Ok(spec) => spec,
        Err(response) => return response,
    };
    match site_spec_store::create(&state.pool, &spec).await {
        Ok(record) => (StatusCode::CREATED, Json(site_record_wire(&record))).into_response(),
        Err(SiteSpecStoreError::AlreadyExists) => json_error(StatusCode::CONFLICT, "SITE_EXISTS"),
        Err(error) => site_store_error_response(&error),
    }
}

async fn sites_get(State(state): State<Arc<ControlState>>, Path(name): Path<String>) -> Response {
    match site_spec_store::get(&state.pool, &name).await {
        Ok(Some(record)) => Json(site_record_wire(&record)).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "SITE_NOT_FOUND"),
        Err(error) => site_store_error_response(&error),
    }
}

async fn sites_update(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    let spec = match parse_site_body(&body) {
        Ok(spec) => spec,
        Err(response) => return response,
    };
    if spec.name() != name {
        return json_error(StatusCode::BAD_REQUEST, "SITE_NAME_MISMATCH");
    }
    match site_spec_store::update(&state.pool, &name, &spec).await {
        Ok(Some(record)) => Json(site_record_wire(&record)).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "SITE_NOT_FOUND"),
        Err(error) => site_store_error_response(&error),
    }
}

async fn sites_delete(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
) -> Response {
    match site_spec_store::delete(&state.pool, &name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => json_error(StatusCode::NOT_FOUND, "SITE_NOT_FOUND"),
        Err(error) => site_store_error_response(&error),
    }
}

#[derive(Deserialize, Default)]
struct HistoryQuery {
    limit: Option<i64>,
}

async fn sites_history(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> Response {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .clamp(1, MAX_HISTORY_LIMIT);
    let entries = match site_spec_store::history(&state.pool, &name, limit).await {
        Ok(entries) => entries,
        Err(error) => return site_store_error_response(&error),
    };
    if entries.is_empty() {
        match site_spec_store::get(&state.pool, &name).await {
            Ok(Some(_)) => {}
            Ok(None) => return json_error(StatusCode::NOT_FOUND, "SITE_NOT_FOUND"),
            Err(error) => return site_store_error_response(&error),
        }
    }
    Json(entries.iter().map(history_entry_wire).collect::<Vec<_>>()).into_response()
}

async fn sites_rollback(
    State(state): State<Arc<ControlState>>,
    Path((name, id)): Path<(String, i64)>,
) -> Response {
    match site_spec_store::rollback(&state.pool, &name, id).await {
        Ok(RollbackOutcome::Applied(record)) => Json(site_record_wire(&record)).into_response(),
        Ok(RollbackOutcome::TargetDeleted) => {
            json_error(StatusCode::BAD_REQUEST, "ROLLBACK_TARGET_DELETED")
        }
        Ok(RollbackOutcome::NotFound) => json_error(StatusCode::NOT_FOUND, "SITE_NOT_FOUND"),
        Err(error) => site_store_error_response(&error),
    }
}

// --- Decision log endpoints ---

#[derive(Serialize)]
struct DecisionWire<'a> {
    id: i64,
    #[serde(flatten)]
    record: &'a DecisionRecord,
}

fn decision_wire(row: &DecisionLogRow) -> DecisionWire<'_> {
    DecisionWire {
        id: row.id,
        record: &row.record,
    }
}

fn decision_store_error_response(error: &DecisionLogStoreError) -> Response {
    eprintln!("xshield-control: decision log store error: {error}");
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
}

#[derive(Deserialize, Default)]
struct DecisionsQuery {
    site: Option<String>,
    session: Option<String>,
    path: Option<String>,
    outcome: Option<String>,
    since_millis: Option<i64>,
    until_millis: Option<i64>,
    limit: Option<i64>,
    before_id: Option<i64>,
}

async fn decisions_list(
    State(state): State<Arc<ControlState>>,
    Query(query): Query<DecisionsQuery>,
) -> Response {
    let outcome = match query.outcome.as_deref() {
        Some(raw) => match decision_log_store::parse_outcome(raw) {
            Some(outcome) => Some(outcome),
            None => return json_error(StatusCode::BAD_REQUEST, "INVALID_OUTCOME"),
        },
        None => None,
    };
    let filter = DecisionLogFilter {
        site: query.site,
        session_prefix: query.session,
        path_prefix: query.path,
        outcome,
        since_millis: query.since_millis,
        until_millis: query.until_millis,
        before_id: query.before_id,
        limit: query.limit.unwrap_or(0),
    };
    match decision_log_store::query(&state.pool, &filter).await {
        Ok(rows) => Json(rows.iter().map(decision_wire).collect::<Vec<_>>()).into_response(),
        Err(error) => decision_store_error_response(&error),
    }
}

async fn decisions_get(State(state): State<Arc<ControlState>>, Path(id): Path<i64>) -> Response {
    match decision_log_store::get(&state.pool, id).await {
        Ok(Some(row)) => Json(decision_wire(&row)).into_response(),
        Ok(None) => json_error(StatusCode::NOT_FOUND, "DECISION_NOT_FOUND"),
        Err(error) => decision_store_error_response(&error),
    }
}

// TODO: once the gateway exposes a real health metric for Jev connectivity,
// read it here instead of returning a fixed stub.
async fn jev_status_handler() -> Response {
    Json(serde_json::json!({ "status": "unknown" })).into_response()
}

// --- Background retention job ---

/// Runs forever, purging decision log rows older than
/// [`DECISION_LOG_RETENTION_SECS`] once an hour. Logs a failed purge and
/// keeps going rather than exiting the process.
pub async fn run_decision_log_retention_loop(pool: PgPool) {
    const INTERVAL: Duration = Duration::from_secs(3600);
    loop {
        tokio::time::sleep(INTERVAL).await;
        let cutoff_millis = Utc::now()
            .timestamp_millis()
            .saturating_sub(DECISION_LOG_RETENTION_SECS.saturating_mul(1000));
        match decision_log_store::purge_older_than(&pool, cutoff_millis).await {
            Ok(count) => {
                eprintln!("xshield-control: purged {count} decision log rows older than 7 days")
            }
            Err(error) => eprintln!("xshield-control: decision log purge failed: {error}"),
        }
    }
}
