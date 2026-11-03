//! Xshield control-plane HTTP backend (docs/07-console-architecture.md
//! sections 7.2 and 7.9).
//!
//! A v4 deployment has one administrator. The administrator signs in with a
//! password, manages site configuration with versioned history and rollback,
//! reads the decision log the gateway writes, and watches the gateways and
//! Jev. The same origin serves the console, which is embedded in this binary
//! at build time.
//!
//! This crate makes no security decisions of its own: the gateway judges
//! requests and writes the decision log. This crate stores configuration,
//! serves the log, and never returns the values of secret fields.

#![warn(missing_docs)]

mod agent_model;
mod auth;
mod error;
mod insights;
mod jev;
mod maintenance;
mod migrations;
mod object_agent;
mod object_agent_api;
mod object_impact;
mod object_learning;
mod object_map;
mod params;
mod preview;
mod requests;
mod sessions;
mod sites;
mod static_files;
mod stats;
mod status;
mod system;

#[cfg(test)]
mod contract;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use sqlx::PgPool;

use crate::error::ApiError;

pub use auth::{hash_password, is_password_hash};
pub use maintenance::run as run_maintenance;
pub use migrations::{MIGRATOR, run as run_migrations};

/// The largest body an ordinary API request may send: 64 KiB (section 7.9.12).
pub const BODY_LIMIT_BYTES: usize = 64 * 1024;
/// The largest body the import endpoint accepts: 100 MiB of JSON lines (section 7.9.9).
pub const IMPORT_BODY_LIMIT_BYTES: usize = 100 * 1024 * 1024;

/// Shared control-plane state: the database pool, the session key derived from
/// the administrator password hash, the optional console origin allowed by
/// CORS during development, the built console, and the failed sign-in counter.
pub struct ControlState {
    pub(crate) pool: PgPool,
    pub(crate) admin_password_hash: String,
    pub(crate) session_key: [u8; 32],
    pub(crate) console_origin: Option<String>,
    /// Whether the console is served over plain HTTP, which changes the
    /// administrator cookie (see [`auth::session_cookie_name`]).
    pub(crate) plain_http: bool,
    pub(crate) console: &'static [static_files::ConsoleFile],
    pub(crate) login_limiter: auth::LoginLimiter,
    /// The last pending-suggestion count per site, with the time it was counted.
    pub(crate) suggestion_counts: Mutex<BTreeMap<String, (i64, i64)>>,
}

impl ControlState {
    /// Builds control-plane state from a database pool, the operator-configured
    /// `XSHIELD_ADMIN_PASSWORD_HASH` value, the optional CORS origin, and whether
    /// the console is served over plain HTTP (`XSHIELD_CONTROL_PLAIN_HTTP`). The
    /// console served is the one embedded at build time.
    ///
    /// # Errors
    /// Returns [`StartupError`] when the password hash is missing or not in the
    /// `pbkdf2-sha256$<iterations>$<salt-hex>$<hash-hex>` format, or when the
    /// session signing key cannot be derived.
    pub fn new(
        pool: PgPool,
        admin_password_hash: String,
        console_origin: Option<String>,
        plain_http: bool,
    ) -> Result<Arc<Self>, StartupError> {
        Self::with_console(
            pool,
            admin_password_hash,
            console_origin,
            plain_http,
            static_files::EMBEDDED_CONSOLE,
        )
    }

    /// As [`ControlState::new`], serving the given console files instead of the
    /// embedded build. Tests use this to serve a fixed set of files.
    pub(crate) fn with_console(
        pool: PgPool,
        admin_password_hash: String,
        console_origin: Option<String>,
        plain_http: bool,
        console: &'static [static_files::ConsoleFile],
    ) -> Result<Arc<Self>, StartupError> {
        if !auth::is_password_hash(&admin_password_hash) {
            return Err(StartupError::InvalidAdminPasswordHash);
        }
        let session_key = auth::derive_session_key(&admin_password_hash)
            .ok_or(StartupError::KeyDerivationUnavailable)?;
        Ok(Arc::new(Self {
            pool,
            admin_password_hash,
            session_key,
            console_origin,
            plain_http,
            console,
            login_limiter: auth::LoginLimiter::default(),
            suggestion_counts: Mutex::new(BTreeMap::new()),
        }))
    }
}

/// A control-plane startup configuration failure.
#[derive(Debug)]
pub enum StartupError {
    /// `XSHIELD_ADMIN_PASSWORD_HASH` is missing or not in the expected format.
    InvalidAdminPasswordHash,
    /// The runtime could not derive the session signing key.
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

/// Builds the complete HTTP router: the public sign-in and health endpoints,
/// the session-gated `/api` surface, the import endpoint with its larger body
/// limit, and the console for every other path.
pub fn router(state: Arc<ControlState>) -> Router {
    let public = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .route("/api/session", get(auth::session))
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES));

    let gated = Router::new()
        .route("/api/requests", get(requests::list))
        .route("/api/requests/counts", get(requests::counts))
        .route("/api/requests/export", get(requests::export))
        .route("/api/requests/lookup", post(requests::lookup))
        .route("/api/requests/{request_id}", get(requests::detail))
        .route("/api/stats/summary", get(stats::summary))
        .route("/api/stats/timeseries", get(stats::timeseries))
        .route("/api/sessions", get(sessions::list))
        .route("/api/sessions/{label}", get(sessions::detail))
        .route("/api/jev/status", get(jev::status))
        .route("/api/jev/stats", get(jev::stats))
        .route("/api/jev/prompts/{id}", get(jev::prompt))
        .route("/api/sites", get(sites::list).post(sites::create))
        .route("/api/sites/validate", post(sites::validate))
        .route(
            "/api/sites/{name}",
            get(sites::get).put(sites::update).delete(sites::delete),
        )
        .route("/api/sites/{name}/versions", get(sites::versions))
        .route("/api/sites/{name}/versions/{version}", get(sites::version))
        .route("/api/sites/{name}/rollback", post(sites::rollback))
        .route("/api/sites/{name}/preview", post(preview::preview))
        .route("/api/sites/{name}/insights", get(insights::insights))
        .route("/api/sites/{name}/evidence", get(insights::evidence))
        .route("/api/sites/{name}/objects", get(object_map::list))
        .route(
            "/api/sites/{name}/objects/bootstrap",
            get(object_map::bootstrap),
        )
        .route(
            "/api/sites/{name}/objects/slots/{id}",
            get(object_map::slot),
        )
        .route(
            "/api/sites/{name}/objects/slots/{id}/dismiss",
            post(object_map::dismiss),
        )
        .route(
            "/api/sites/{name}/objects/slots/{id}/ambiguous",
            post(object_map::ambiguous),
        )
        .route(
            "/api/sites/{name}/objects/slots/{id}/ask",
            post(object_agent_api::ask),
        )
        .route(
            "/api/sites/{name}/objects/runs",
            get(object_agent_api::runs),
        )
        .route(
            "/api/sites/{name}/objects/runs/{id}",
            get(object_agent_api::run_detail),
        )
        .route(
            "/api/sites/{name}/objects/run",
            post(object_agent_api::run_now),
        )
        .route(
            "/api/sites/{name}/objects/agent-sample",
            get(object_agent_api::sample),
        )
        .route("/api/status", get(status::status))
        .route("/api/system", get(system::system))
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_session,
        ));

    let import = Router::new()
        .route("/api/import", post(requests::import))
        .layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT_BYTES))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_session,
        ));

    let mut app = Router::new()
        .merge(public)
        .merge(gated)
        .merge(import)
        .fallback(static_files::serve);
    if state.console_origin.is_some() {
        app = app.layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            cors_middleware,
        ));
    }
    app.layer(middleware::from_fn(static_files::security_headers))
        .layer(middleware::from_fn(json_body_limit))
        .with_state(state)
}

/// Replaces the framework's plain-text 413 with the API's JSON error code.
async fn json_body_limit(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "BODY_TOO_LARGE").into_response();
    }
    response
}

/// Allows the configured development origin to call the API from another port.
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
