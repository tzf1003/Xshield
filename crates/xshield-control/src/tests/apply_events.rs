//! `apply_events_handler` (SSE push for site apply-state changes): it must
//! publish exactly when `apply_site_snapshot` actually commits a new state,
//! never leak a signal about a site outside the subscriber's own scope, and
//! refuse an API-key principal instead of opening a pointless connection.
//!
//! Against a real `PostgreSQL`-backed control plane and a mock edge, mirroring
//! the harness in `site_approval.rs` but trimmed to only what this needs.

use super::super::site_config;
use super::*;
use axum::{Json, extract::State, routing::post};
use std::sync::{Arc, Mutex};
use tokio_stream::StreamExt as _;

#[derive(Default)]
struct EdgeState {
    snapshot_revision: u64,
    refusal: Option<(u16, Value)>,
}

#[derive(Clone, Default)]
struct MockEdge(Arc<Mutex<EdgeState>>);

impl MockEdge {
    /// Makes the next apply fail the way the real edge refuses one: this
    /// status and unsigned body, nothing applied or served.
    fn refuse_next(&self, status: u16, body: Value) {
        self.0.lock().unwrap().refusal = Some((status, body));
    }
}

/// Signs an acknowledgement the way the edge does: HMAC-SHA256 over the label,
/// the signature of the request it answers and the exact response body.
fn sign_ack(request_signature: &str, ack_body: &[u8]) -> String {
    let key = openssl::pkey::PKey::hmac(&[0x11_u8; 32]).unwrap();
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
    signer
        .update(&xshield_core::edge_channel::apply_ack_message(
            request_signature,
            ack_body,
        ))
        .unwrap();
    signer
        .sign_to_vec()
        .unwrap()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            write!(hex, "{byte:02x}").unwrap();
            hex
        })
}

async fn edge_apply(
    State(edge): State<MockEdge>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let request: Value = serde_json::from_slice(&body).unwrap();
    let revision = request["snapshot_revision"].as_u64().unwrap();
    let mut state = edge.0.lock().unwrap();
    if let Some((status, body)) = state.refusal.take() {
        return (StatusCode::from_u16(status).unwrap(), Json(body)).into_response();
    }
    state.snapshot_revision = revision;
    let ack_body = serde_json::to_vec(&json!({
        "apply_id": request["apply_id"],
        "active_revision": revision,
        "apply_state": "active",
        "reason_code": "EDGE_APPLY_CONFIRMED"
    }))
    .unwrap();
    let request_signature = headers
        .get(xshield_core::edge_channel::APPLY_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let signature = sign_ack(request_signature, &ack_body);
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/json".to_owned(),
            ),
            (
                axum::http::HeaderName::from_static(
                    xshield_core::edge_channel::APPLY_ACK_SIGNATURE_HEADER,
                ),
                signature,
            ),
        ],
        ack_body,
    )
        .into_response()
}

async fn start_edge() -> (MockEdge, String) {
    let edge = MockEdge::default();
    let app = axum::Router::new()
        .route("/internal/v1/apply", post(edge_apply))
        .route(
            "/internal/v1/health",
            axum::routing::get(|| async {
                Json(json!({"edge_state": "healthy", "audit_state": "healthy"}))
            }),
        )
        .with_state(edge.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (edge, format!("http://127.0.0.1:{port}/internal/v1/apply"))
}

const AUTHOR: &str = "author-1";
const APPROVER: &str = "independent-reviewer";

/// A public site (so creating it needs approval in every version of the
/// rules) pointing at `upstream`.
fn site_body(site: &str, upstream: &str) -> Value {
    json!({
        "site_id": site,
        "display_name": site,
        "public_origin": format!("https://{}.example.test", site.replace('_', "-")),
        "upstream_address": upstream,
        "upstream_server_name": "origin.example.test",
        "upstream_tls": false,
        "listen_port": 0,
        "entry_path": "/",
        "security_entry": "public",
        "sensor_enabled": false,
        "policy_revision": "policy-v1",
        "status": "active"
    })
}

struct Ctx {
    tenant: TenantId,
    assertion_key: [u8; 32],
    edge: MockEdge,
    pool: sqlx::PgPool,
    author: axum::Router,
    approver: axum::Router,
    access_directories: Mutex<Vec<std::path::PathBuf>>,
    sequence: std::sync::atomic::AtomicU32,
}

impl Ctx {
    async fn new() -> Self {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
        let tenant = TenantId::parse(format!("tenant_apply_events_{}", Uuid::now_v7())).unwrap();
        let (edge, edge_url) = start_edge().await;
        let default_site = SiteId::parse("site_default").unwrap();

        let store = PostgresIdentityStore::connect(&url, 8, Duration::from_secs(5))
            .await
            .unwrap();
        let mut author = Fixture::with_catalog(100_000, ManagementRole::SystemAdmin, store, 1);
        author.control.config.tenant_id = tenant.clone();
        author.control.config.site_id = default_site.clone();
        author.control.config.principal = ManagementPrincipal::new_tenant_scoped(
            AUTHOR,
            [
                ManagementRole::SystemAdmin,
                ManagementRole::Observer,
                ManagementRole::PolicyAuthor,
                ManagementRole::ReleaseOperator,
            ],
            [tenant.clone()],
        )
        .unwrap();
        let author_access = author.access_directory.clone();
        let assertion_key: [u8; 32] = **author.control.auth_context_key.as_ref().unwrap();
        let client =
            super::super::EdgeApplyClient::new(edge_url.clone(), &"11".repeat(32)).unwrap();
        let author_app = router(author.control.with_edge_apply_client(client));

        let store = PostgresIdentityStore::connect(&url, 8, Duration::from_secs(5))
            .await
            .unwrap();
        let mut approver =
            Fixture::with_decision_catalog(store, APPROVER, ManagementRole::PolicyApprover);
        approver.control.config.tenant_id = tenant.clone();
        approver.control.config.site_id = default_site;
        approver.control.config.principal = ManagementPrincipal::new_tenant_scoped(
            APPROVER,
            [ManagementRole::PolicyApprover, ManagementRole::Observer],
            [tenant.clone()],
        )
        .unwrap();
        let approver_access = approver.access_directory.clone();
        let client = super::super::EdgeApplyClient::new(edge_url, &"11".repeat(32)).unwrap();
        let approver_app = router(approver.control.with_edge_apply_client(client));

        Self {
            tenant,
            assertion_key,
            edge,
            pool: sqlx::PgPool::connect(&url).await.unwrap(),
            author: author_app,
            approver: approver_app,
            access_directories: Mutex::new(vec![author_access, approver_access]),
            sequence: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn key(&self, label: &str) -> String {
        let number = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("apply-events-test-{label}-{number:04}-padding-0000")
    }

    async fn call(
        app: &axum::Router,
        method: &str,
        path: &str,
        body: Option<&Value>,
        key: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"));
        if let Some(key) = key {
            builder = builder.header("idempotency-key", key);
        }
        let request = match body {
            Some(value) => builder
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(value).unwrap()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn create(&self, body: &Value, key: &str) -> (StatusCode, Value) {
        Self::call(
            &self.author,
            "POST",
            "/control/v1/sites",
            Some(body),
            Some(key),
        )
        .await
    }

    async fn approve(&self, site: &str, key: &str) -> (StatusCode, Value) {
        Self::call(
            &self.approver,
            "POST",
            &format!("/control/v1/sites/{site}/approve"),
            None,
            Some(key),
        )
        .await
    }

    async fn apply(&self, site: &str, key: &str) -> (StatusCode, Value) {
        Self::call(
            &self.author,
            "POST",
            &format!("/control/v1/sites/{site}/apply"),
            None,
            Some(key),
        )
        .await
    }

    /// Creates a site and, if the control plane asks for approval, has the
    /// independent reviewer approve it, but never applies it: callers that
    /// want to watch the apply-events stream do that themselves.
    async fn create_pending(&self, site: &str, upstream: &str) {
        let (status, created) = self
            .create(&site_body(site, upstream), &self.key("create"))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        if created["requires_approval"] == true {
            let (status, approved) = self.approve(site, &self.key("approve")).await;
            assert_eq!(status, StatusCode::OK, "{approved}");
        }
    }

    /// Opens the SSE subscription authenticated with the given session
    /// header value (either `Bearer {TOKEN}` for the fixed author identity
    /// or an `Xshield-Session ...` assertion built by [`session_header`]),
    /// returning the still-open response body as a byte stream. The
    /// subscription is registered against the broadcast channel before this
    /// returns, so every caller applies *after* awaiting this.
    async fn subscribe(&self, authorization: &str) -> axum::body::BodyDataStream {
        let request = Request::builder()
            .method("GET")
            .uri(site_config::SITE_APPLY_EVENTS_PATH)
            .header(AUTHORIZATION, authorization)
            .body(Body::empty())
            .unwrap();
        let response = self.author.clone().oneshot(request).await.unwrap();
        if response.status() != StatusCode::OK {
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 65_536).await.unwrap();
            panic!(
                "subscribe failed: {status} {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        response.into_body().into_data_stream()
    }

    /// Drops every app (closing the audit journals), returns the audit events
    /// of all principals and removes the test tenant's rows.
    async fn finish(self) -> Vec<Value> {
        let Self {
            tenant,
            pool,
            author,
            approver,
            access_directories,
            ..
        } = self;
        drop(author);
        drop(approver);
        let mut events = Vec::new();
        for directory in access_directories.lock().unwrap().iter() {
            if directory.exists() {
                events.extend(read_access_events(directory));
                let _ = fs::remove_dir_all(directory.parent().unwrap());
            }
        }
        for statement in [
            "DELETE FROM xshield.protected_site_configs WHERE tenant_id = $1",
            "DELETE FROM xshield.site_descriptor_bindings WHERE tenant_id = $1",
            "DELETE FROM xshield.policy_revisions WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(tenant.as_str())
                .execute(&pool)
                .await
                .unwrap();
        }
        events
    }
}

/// A signed `Xshield-Session` assertion for an Observer scoped to exactly
/// one site (never tenant-wide), the same shape `authorize_site` checks for
/// the ordinary status/health routes.
fn observer_session(assertion_key: &[u8; 32], tenant: &TenantId, site: &str) -> String {
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 30;
    let payload = serde_json::to_vec(&json!({
        "version": 1,
        "subject": "observer-1",
        "tenant_id": tenant.as_str(),
        "site_id": site,
        "tenant_scope": false,
        "machine": false,
        "scopes": [],
        "roles": ["observer"],
        "csrf_valid": true,
        "expires_at": expires_at,
    }))
    .unwrap();
    let signature = super::super::component_signature(
        assertion_key,
        &[b"xshield-control-browser-request-v1", &payload],
    )
    .unwrap();
    let payload_hex: String = payload
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(b"0123456789abcdef"[usize::from(nibble)]))
        .collect();
    format!(
        "Xshield-Session {payload_hex}.{}",
        super::super::lower_hex(&signature)
    )
}

/// Reads SSE frames off `stream` until `needle` appears in the accumulated
/// text or `budget` elapses, returning the accumulated text either way so a
/// failing assertion shows what (if anything) arrived.
async fn read_until(
    stream: &mut axum::body::BodyDataStream,
    needle: &str,
    budget: Duration,
) -> String {
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + budget;
    while !text.contains(needle) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(Ok(chunk))) => text.push_str(&String::from_utf8_lossy(&chunk)),
            _ => break,
        }
    }
    text
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_confirmed_apply_is_signalled_to_a_session_scoped_to_that_site() {
    let ctx = Ctx::new().await;
    ctx.create_pending("site_a", "8.8.8.8:9201").await;
    let mut stream = ctx
        .subscribe(&observer_session(&ctx.assertion_key, &ctx.tenant, "site_a"))
        .await;

    let (status, body) = ctx.apply("site_a", &ctx.key("apply")).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let text = read_until(&mut stream, "site_apply_changed", Duration::from_secs(5)).await;
    assert!(text.contains("site_apply_changed"), "no event: {text}");
    assert!(text.contains("\"site_id\":\"site_a\""), "{text}");
    assert!(text.contains("\"status\":\"confirmed\""), "{text}");

    let events = ctx.finish().await;
    assert!(
        events
            .iter()
            .any(|event| event["payload"]["reason_code"] == "CONTROL_SITE_APPLY_EVENTS_SUBSCRIBED"),
        "no subscribe audit event: {events:?}"
    );
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_failed_apply_is_signalled_with_its_reason() {
    let ctx = Ctx::new().await;
    ctx.create_pending("site_b", "8.8.4.4:9202").await;
    let mut stream = ctx
        .subscribe(&observer_session(&ctx.assertion_key, &ctx.tenant, "site_b"))
        .await;
    ctx.edge.refuse_next(
        422,
        json!({"error": "edge_apply_failed", "reason_code": "EDGE_APPLY_DESCRIPTOR_CONFLICT"}),
    );

    let (status, body) = ctx.apply("site_b", &ctx.key("apply")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["apply_state"], "failed", "{body}");

    let text = read_until(&mut stream, "site_apply_changed", Duration::from_secs(5)).await;
    assert!(text.contains("\"status\":\"failed\""), "{text}");
    assert!(text.contains("EDGE_APPLY_DESCRIPTOR_CONFLICT"), "{text}");

    ctx.finish().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_session_scoped_to_one_site_never_sees_another_sites_failure() {
    let ctx = Ctx::new().await;
    ctx.create_pending("site_c", "1.1.1.1:9203").await;
    ctx.create_pending("site_d", "1.0.0.1:9204").await;
    let mut stream = ctx
        .subscribe(&observer_session(&ctx.assertion_key, &ctx.tenant, "site_c"))
        .await;

    // site_d's apply is refused by the edge before the function ever reaches
    // the batch-confirm step, so nothing about site_c (itself never yet
    // applied) is touched; a session scoped only to site_c must see nothing.
    ctx.edge.refuse_next(
        422,
        json!({"error": "edge_apply_failed", "reason_code": "EDGE_APPLY_DESCRIPTOR_CONFLICT"}),
    );
    let (status, body) = ctx.apply("site_d", &ctx.key("apply")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["apply_state"], "failed", "{body}");

    let text = read_until(&mut stream, "site_apply_changed", Duration::from_secs(2)).await;
    assert!(!text.contains("site_apply_changed"), "leaked: {text}");

    // The channel itself still works for a site in scope.
    let (status, body) = ctx.apply("site_c", &ctx.key("apply")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["apply_state"], "active", "{body}");
    let text = read_until(&mut stream, "site_apply_changed", Duration::from_secs(5)).await;
    assert!(text.contains("\"site_id\":\"site_c\""), "{text}");
    assert!(!text.contains("site_d"), "{text}");

    ctx.finish().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn an_api_key_principal_is_refused_the_subscription() {
    let ctx = Ctx::new().await;
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 30;
    let payload = serde_json::to_vec(&json!({
        "version": 1,
        "subject": "key-1",
        "tenant_id": ctx.tenant.as_str(),
        "site_id": "site_default",
        "tenant_scope": false,
        "machine": true,
        "scopes": [],
        "roles": [],
        "api_key_grants": [{"site_id": "site_default", "capability": "site.read"}],
        "csrf_valid": true,
        "expires_at": expires_at,
    }))
    .unwrap();
    let signature = super::super::component_signature(
        &ctx.assertion_key,
        &[b"xshield-control-browser-request-v1", &payload],
    )
    .unwrap();
    let payload_hex: String = payload
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(b"0123456789abcdef"[usize::from(nibble)]))
        .collect();
    let header = format!(
        "Xshield-Session {payload_hex}.{}",
        super::super::lower_hex(&signature)
    );
    let request = Request::builder()
        .method("GET")
        .uri(site_config::SITE_APPLY_EVENTS_PATH)
        .header(AUTHORIZATION, header)
        .body(Body::empty())
        .unwrap();
    let response = ctx.author.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65_536).await.unwrap()).unwrap();
    assert_eq!(body["error_code"], "CONTROL_SCOPE_DENIED", "{body}");

    ctx.finish().await;
}
