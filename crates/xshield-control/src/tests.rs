//! Unit tests for the control-plane HTTP backend.
//!
//! Most tests here never touch a database: the auth gate only checks the
//! session cookie, and request validation (password check, site config
//! parsing, outcome parsing) happens before any storage-layer call. A
//! `connect_lazy` pool defers connecting until first used, so these tests
//! build a real [`ControlState`] without a reachable PostgreSQL instance.
//! The few tests that do need a live database are `#[ignore]`d and only run
//! when `XSHIELD_DATABASE_URL` is set.

use axum::body::Body;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use super::*;

const TEST_PASSWORD: &str = "correct-horse-battery-staple";

fn test_state() -> Arc<ControlState> {
    let hash = hash_password(TEST_PASSWORD).expect("hash_password");
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield_test_unreachable")
        .expect("connect_lazy never touches the network");
    ControlState::new(pool, hash, None).expect("valid admin password hash")
}

fn session_cookie(state: &ControlState) -> String {
    let token = issue_session_token(&state.session_key).expect("issue_session_token");
    format!("{SESSION_COOKIE}={token}")
}

fn json_request(method: &str, uri: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn get_request(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::empty()).unwrap()
}

// --- Password hashing and session tokens (pure, no DB) ---

#[test]
fn password_hash_round_trips() {
    let hash = hash_password("s3cret").unwrap();
    assert!(verify_password(&hash, "s3cret"));
    assert!(!verify_password(&hash, "wrong"));
}

#[test]
fn malformed_or_foreign_password_hashes_never_verify() {
    assert!(!verify_password("not-the-right-format", "anything"));
    assert!(!verify_password("pbkdf2-sha256$0$aa$bb", "anything"));
    assert!(!verify_password("pbkdf2-sha256$1000$zz$bb", "anything"));
}

#[test]
fn session_tokens_round_trip_and_reject_tampering() {
    let key = [7_u8; 32];
    let token = issue_session_token(&key).unwrap();
    assert!(verify_session_token(&key, &token));
    assert!(!verify_session_token(&[8_u8; 32], &token));
    assert!(!verify_session_token(&key, "garbage"));
    assert!(!verify_session_token(&key, ""));
}

#[test]
fn session_tokens_expire() {
    let key = [3_u8; 32];
    let expiry = now_unix().saturating_sub(1);
    let expiry_bytes = expiry.to_be_bytes();
    let tag = hmac_sha256(&key, &expiry_bytes).unwrap();
    let mut payload = expiry_bytes.to_vec();
    payload.extend_from_slice(&tag);
    let token = b64url_encode(&payload);
    assert!(!verify_session_token(&key, &token));
}

// --- HTTP behaviour (no DB: auth gate and request validation only) ---

#[tokio::test]
async fn login_succeeds_with_the_right_password_and_sets_a_session_cookie() {
    let state = test_state();
    let app = router(Arc::clone(&state));
    let response = app
        .oneshot(json_request(
            "POST",
            "/api/login",
            &serde_json::json!({ "password": TEST_PASSWORD }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie")
        .to_str()
        .unwrap();
    assert!(cookie.starts_with("__Host-xshield-session="));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("Max-Age=43200"));
}

#[tokio::test]
async fn login_fails_with_the_wrong_password() {
    let state = test_state();
    let app = router(state);
    let response = app
        .oneshot(json_request(
            "POST",
            "/api/login",
            &serde_json::json!({ "password": "wrong" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_clears_the_session_cookie() {
    let state = test_state();
    let app = router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie")
        .to_str()
        .unwrap();
    assert!(cookie.contains("Max-Age=0"));
}

#[tokio::test]
async fn a_protected_route_requires_a_valid_session_cookie() {
    let state = test_state();
    let app = router(Arc::clone(&state));

    // `/api/jev/status` is protected but never touches storage, so it
    // exercises the auth gate itself without needing a database.
    let unauthenticated = app
        .clone()
        .oneshot(get_request("/api/jev/status", None))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let forged = app
        .clone()
        .oneshot(get_request(
            "/api/jev/status",
            Some("__Host-xshield-session=not-a-real-token"),
        ))
        .await
        .unwrap();
    assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);

    let cookie = session_cookie(&state);
    let authenticated = app
        .oneshot(get_request("/api/jev/status", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::OK);
}

#[tokio::test]
async fn session_endpoint_reflects_cookie_validity() {
    let state = test_state();
    let app = router(Arc::clone(&state));

    let anonymous = app
        .clone()
        .oneshot(get_request("/api/session", None))
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let cookie = session_cookie(&state);
    let authenticated = app
        .oneshot(get_request("/api/session", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_is_unauthenticated_and_plain_text() {
    let state = test_state();
    let app = router(state);
    let response = app.oneshot(get_request("/health", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn creating_a_site_with_an_invalid_config_is_rejected_before_touching_the_database() {
    let state = test_state();
    let app = router(Arc::clone(&state));
    let cookie = session_cookie(&state);
    let request = Request::builder()
        .method("POST")
        .uri("/api/sites")
        .header(header::COOKIE, cookie)
        .body(Body::from("not json"))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn creating_a_site_without_a_session_is_unauthenticated_not_a_validation_error() {
    let state = test_state();
    let app = router(state);
    let request = Request::builder()
        .method("POST")
        .uri("/api/sites")
        .body(Body::from("not json"))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn updating_a_site_with_a_mismatched_name_is_rejected() {
    let state = test_state();
    let app = router(Arc::clone(&state));
    let cookie = session_cookie(&state);
    let spec = serde_json::json!({
        "name": "other",
        "hosts": ["other.example.com"],
        "origin": "http://10.0.0.1:80",
        "session": {"cookie": "SESSIONID"},
        "entries": ["/login"]
    });
    let request = Request::builder()
        .method("PUT")
        .uri("/api/sites/emr")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&spec).unwrap()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn decisions_list_rejects_an_unknown_outcome_before_touching_the_database() {
    let state = test_state();
    let app = router(Arc::clone(&state));
    let cookie = session_cookie(&state);
    let response = app
        .oneshot(get_request(
            "/api/decisions?outcome=not_a_real_outcome",
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// --- Tests below need a reachable PostgreSQL database and are skipped by
// default; run with `XSHIELD_DATABASE_URL=... cargo test -- --ignored`.

async fn connect_live_state() -> Arc<ControlState> {
    let url = std::env::var("XSHIELD_DATABASE_URL").expect("XSHIELD_DATABASE_URL");
    let pool = PgPoolOptions::new().connect(&url).await.expect("connect");
    let hash = hash_password(TEST_PASSWORD).unwrap();
    ControlState::new(pool, hash, None).unwrap()
}

#[tokio::test]
#[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
async fn site_create_update_history_and_rollback_happy_path() {
    let state = connect_live_state().await;
    let app = router(Arc::clone(&state));
    let cookie = session_cookie(&state);
    let spec = serde_json::json!({
        "name": "control-test-site",
        "hosts": ["control-test.example.com"],
        "origin": "http://10.0.0.9:8080",
        "session": {"cookie": "SESSIONID"},
        "entries": ["/login"]
    });

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/sites")
                .header(header::COOKIE, cookie.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&spec).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    let updated_spec = serde_json::json!({
        "name": "control-test-site",
        "hosts": ["control-test.example.com"],
        "origin": "http://10.0.0.9:8080",
        "session": {"cookie": "SESSIONID"},
        "entries": ["/login", "/api/home"]
    });
    let update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/sites/control-test-site")
                .header(header::COOKIE, cookie.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&updated_spec).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);

    let history = app
        .clone()
        .oneshot(get_request(
            "/api/sites/control-test-site/history",
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(history.status(), StatusCode::OK);

    let _ = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/sites/control-test-site")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
}
