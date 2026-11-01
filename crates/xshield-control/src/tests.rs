//! HTTP behaviour of the control plane (docs/07-console-architecture.md section
//! 7.9). Most tests never touch a database: the session gate, the sign-in
//! limit, body limits, request validation and the console files all answer
//! before the first storage call. A `connect_lazy` pool defers connecting until
//! it is used. The tests that need PostgreSQL are `#[ignore]`d and run with
//! `XSHIELD_DATABASE_URL=... cargo test -p xshield-control -- --ignored`.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;

use crate::{
    BODY_LIMIT_BYTES, ControlState, auth::SESSION_COOKIE, hash_password, router,
    static_files::ConsoleFile,
};

const TEST_PASSWORD: &str = "correct-horse-battery-staple";
const UNREACHABLE_DATABASE: &str =
    "postgres://xshield:xshield@127.0.0.1:1/xshield_test_unreachable";

/// A console build with an index page and one hashed asset.
const TEST_CONSOLE: &[ConsoleFile] = &[
    ConsoleFile {
        path: "index.html",
        bytes: b"<!doctype html><title>console</title>",
    },
    ConsoleFile {
        path: "assets/app-abc123.js",
        bytes: b"console.log(1);",
    },
];

// --- Helpers ---

fn lazy_pool() -> PgPool {
    PgPoolOptions::new()
        .connect_lazy(UNREACHABLE_DATABASE)
        .expect("connect_lazy never touches the network")
}

fn state_with_console(console: &'static [ConsoleFile]) -> Arc<ControlState> {
    let hash = hash_password(TEST_PASSWORD).expect("hash_password");
    ControlState::with_console(lazy_pool(), hash, None, console).expect("valid admin password hash")
}

fn test_state() -> Arc<ControlState> {
    state_with_console(TEST_CONSOLE)
}

fn session_cookie(state: &ControlState) -> String {
    let token = crate::auth::issue_session_token(&state.session_key).expect("session token");
    format!("{SESSION_COOKIE}={token}")
}

fn request(
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    content_type: Option<&str>,
    body: Body,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    builder.body(body).expect("request")
}

fn get(uri: &str, cookie: Option<&str>) -> Request<Body> {
    request("GET", uri, cookie, None, Body::empty())
}

fn json_request(method: &str, uri: &str, cookie: Option<&str>, value: &Value) -> Request<Body> {
    let body = serde_json::to_vec(value).expect("json body");
    request(
        method,
        uri,
        cookie,
        Some("application/json"),
        Body::from(body),
    )
}

async fn send(app: &Router, request: Request<Body>) -> Response {
    app.clone()
        .oneshot(request)
        .await
        .expect("router is infallible")
}

async fn body_text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn body_json(response: Response) -> Value {
    serde_json::from_str(&body_text(response).await).unwrap_or(Value::Null)
}

fn header_text(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

// --- Sign-in and session ---

#[tokio::test]
async fn health_is_public_and_answers_ok() {
    let app = router(test_state());
    let response = send(&app, get("/health", None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_text(response).await, "ok");
}

#[tokio::test]
async fn login_sets_a_host_prefixed_session_cookie() {
    let app = router(test_state());
    let response = send(
        &app,
        json_request(
            "POST",
            "/api/login",
            None,
            &json!({ "password": TEST_PASSWORD }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = header_text(response.headers(), header::SET_COOKIE).unwrap_or_default();
    assert!(cookie.starts_with("__Host-xshield-session="), "{cookie}");
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Max-Age=43200"));
}

#[tokio::test]
async fn a_wrong_password_is_refused_and_repeated_failures_are_rate_limited() {
    let app = router(test_state());
    for _ in 0..10 {
        let response = send(
            &app,
            json_request("POST", "/api/login", None, &json!({ "password": "wrong" })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let limited = send(
        &app,
        json_request("POST", "/api/login", None, &json!({ "password": "wrong" })),
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(limited).await["error"], "LOGIN_RATE_LIMITED");
}

#[tokio::test]
async fn logout_clears_the_session_cookie() {
    let app = router(test_state());
    let response = send(
        &app,
        request("POST", "/api/logout", None, None, Body::empty()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = header_text(response.headers(), header::SET_COOKIE).unwrap_or_default();
    assert!(cookie.contains("Max-Age=0"), "{cookie}");
}

#[tokio::test]
async fn protected_routes_need_a_valid_session_cookie() {
    let state = test_state();
    let app = router(Arc::clone(&state));

    let anonymous = send(&app, get("/api/requests", None)).await;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        header_text(anonymous.headers(), header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
    assert_eq!(body_json(anonymous).await["error"], "UNAUTHENTICATED");

    let forged = send(
        &app,
        get(
            "/api/requests",
            Some("__Host-xshield-session=not-a-real-token"),
        ),
    )
    .await;
    assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);

    // With a valid session the request passes the gate and then fails
    // validation, which happens before any storage call.
    let cookie = session_cookie(&state);
    let signed_in = send(
        &app,
        get("/api/requests?outcome=not_an_outcome", Some(&cookie)),
    )
    .await;
    assert_eq!(signed_in.status(), StatusCode::BAD_REQUEST);
    let body = body_json(signed_in).await;
    assert_eq!(body["error"], "INVALID_FILTER");
    assert_eq!(body["field"], "outcome");
}

#[tokio::test]
async fn the_session_endpoint_reflects_the_cookie() {
    let state = test_state();
    let app = router(Arc::clone(&state));

    let anonymous = send(&app, get("/api/session", None)).await;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let cookie = session_cookie(&state);
    let signed_in = send(&app, get("/api/session", Some(&cookie))).await;
    assert_eq!(signed_in.status(), StatusCode::OK);
}

// --- Requests, bodies and site validation (answered before storage) ---

#[tokio::test]
async fn an_unknown_api_path_is_a_json_not_found_and_never_cached() {
    let app = router(test_state());
    let response = send(&app, get("/api/nothing-here", None)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        header_text(response.headers(), header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
    assert_eq!(body_json(response).await["error"], "NOT_FOUND");
}

#[tokio::test]
async fn a_write_must_declare_json_and_stay_within_the_body_limit() {
    let state = test_state();
    let app = router(Arc::clone(&state));
    let cookie = session_cookie(&state);

    let plain = send(
        &app,
        request(
            "POST",
            "/api/sites",
            Some(&cookie),
            Some("text/plain"),
            Body::from("{}"),
        ),
    )
    .await;
    assert_eq!(plain.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(body_json(plain).await["error"], "UNSUPPORTED_MEDIA_TYPE");

    let oversized = vec![b' '; BODY_LIMIT_BYTES + 1];
    let large = send(
        &app,
        request(
            "POST",
            "/api/sites",
            Some(&cookie),
            Some("application/json"),
            Body::from(oversized),
        ),
    )
    .await;
    assert_eq!(large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_json(large).await["error"], "BODY_TOO_LARGE");
}

#[tokio::test]
async fn an_invalid_site_is_refused_with_its_config_code_before_the_database() {
    let state = test_state();
    let app = router(Arc::clone(&state));
    let cookie = session_cookie(&state);
    let response = send(
        &app,
        json_request(
            "POST",
            "/api/sites",
            Some(&cookie),
            &json!({ "spec": { "name": "shop" } }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    let error = body["error"].as_str().unwrap_or_default();
    assert!(error.starts_with("SITE_CONFIG_"), "got {error}");
}

#[tokio::test]
async fn renaming_a_site_through_its_path_is_refused_before_the_database() {
    let state = test_state();
    let app = router(Arc::clone(&state));
    let cookie = session_cookie(&state);
    let body = json!({
        "spec": {
            "name": "other",
            "hosts": ["other.example.com"],
            "origin": "http://10.0.0.1:80",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"]
        },
        "expected_version": 1
    });
    let response = send(
        &app,
        json_request("PUT", "/api/sites/emr", Some(&cookie), &body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "SITE_NAME_MISMATCH");
}

// --- The console files on the same origin ---

#[tokio::test]
async fn the_console_is_served_with_a_spa_fallback_and_security_headers() {
    let app = router(test_state());

    let index = send(&app, get("/", None)).await;
    assert_eq!(index.status(), StatusCode::OK);
    assert_eq!(
        header_text(index.headers(), header::CONTENT_TYPE).as_deref(),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        header_text(index.headers(), header::CACHE_CONTROL).as_deref(),
        Some("no-cache")
    );
    assert_eq!(
        header_text(index.headers(), header::X_FRAME_OPTIONS).as_deref(),
        Some("DENY")
    );
    assert!(index.headers().contains_key("content-security-policy"));
    assert!(body_text(index).await.contains("console"));

    let asset = send(&app, get("/assets/app-abc123.js", None)).await;
    assert_eq!(asset.status(), StatusCode::OK);
    assert_eq!(
        header_text(asset.headers(), header::CONTENT_TYPE).as_deref(),
        Some("text/javascript; charset=utf-8")
    );
    assert_eq!(
        header_text(asset.headers(), header::CACHE_CONTROL).as_deref(),
        Some("public, max-age=31536000, immutable")
    );

    let deep_link = send(&app, get("/sites/emr", None)).await;
    assert_eq!(deep_link.status(), StatusCode::OK);
    assert!(body_text(deep_link).await.contains("console"));

    let missing = send(&app, get("/assets/missing.js", None)).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let traversal = send(&app, get("/../../etc/passwd", None)).await;
    let served = body_text(traversal).await;
    assert!(
        !served.contains("root:"),
        "path traversal must not read files"
    );

    let post = send(&app, request("POST", "/", None, None, Body::empty())).await;
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn an_unbuilt_console_answers_503_until_it_is_built() {
    let app = router(state_with_console(&[]));
    let response = send(&app, get("/", None)).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_text(response).await, "console assets are not built");
}

// --- Against a live database (run with --ignored) ---

async fn connect_live_state() -> Arc<ControlState> {
    let url = std::env::var("XSHIELD_DATABASE_URL").expect("XSHIELD_DATABASE_URL");
    let pool = PgPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to XSHIELD_DATABASE_URL");
    let hash = hash_password(TEST_PASSWORD).expect("hash_password");
    ControlState::new(pool, hash, None).expect("valid admin password hash")
}

#[tokio::test]
#[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
#[allow(clippy::similar_names)] // `stale` is the request sent with a stale version; `state` is the app state.
async fn a_site_is_created_reported_with_its_rollout_and_guarded_by_versions() {
    let state = connect_live_state().await;
    let app = router(Arc::clone(&state));
    let cookie = session_cookie(&state);
    let name = format!("control-test-{}", std::process::id());
    let host = format!("{name}.example.com");
    let spec = json!({
        "name": name,
        "hosts": [host],
        "origin": "http://10.0.0.9:8080",
        "session": {"cookie": "SESSIONID"},
        "entries": ["/login"]
    });

    let create = send(
        &app,
        json_request(
            "POST",
            "/api/sites",
            Some(&cookie),
            &json!({ "spec": spec, "note": "first version" }),
        ),
    )
    .await;
    assert_eq!(create.status(), StatusCode::CREATED);

    let get_site = send(&app, get(&format!("/api/sites/{name}"), Some(&cookie))).await;
    assert_eq!(get_site.status(), StatusCode::OK);
    let site = body_json(get_site).await;
    assert_eq!(site["version"], 1);
    assert_eq!(site["rollout"]["version"], 1);

    let stale = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/sites/{name}"),
            Some(&cookie),
            &json!({ "spec": spec, "expected_version": 0 }),
        ),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let conflict = body_json(stale).await;
    assert_eq!(conflict["error"], "VERSION_CONFLICT");
    assert_eq!(conflict["current_version"], 1);

    let updated = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/sites/{name}"),
            Some(&cookie),
            &json!({ "spec": spec, "expected_version": 1 }),
        ),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);

    let versions = send(
        &app,
        get(&format!("/api/sites/{name}/versions"), Some(&cookie)),
    )
    .await;
    assert_eq!(versions.status(), StatusCode::OK);

    let deleted = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/sites/{name}"),
            Some(&cookie),
            &json!({ "expected_version": 2 }),
        ),
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
}
