//! End-to-end behaviour of the site approval and apply state machine over
//! HTTP with a mock edge and `PostgreSQL`: an author principal, an independent
//! approver and (for direct apply) a scoped Agent API key.
//!
//! The mock edge mirrors the contract the real edge enforces: complete tenant
//! snapshots, monotonic snapshot revisions and an acknowledgement echoing the
//! apply identity. It records what it is *serving* so tests assert on what
//! reached the data plane, not on control-plane bookkeeping.

use super::*;
use axum::{
    Json,
    extract::State,
    routing::{get, post},
};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct EdgeState {
    snapshot_revision: u64,
    applies: Vec<Value>,
    /// Every apply request as received: the raw body and its signature header.
    signed: Vec<(Vec<u8>, String)>,
    serving: BTreeMap<String, Value>,
    /// A refusal (status and unsigned body) the next apply answers with,
    /// applying nothing; armed by [`MockEdge::refuse_next`].
    refusal: Option<(u16, Value)>,
}

#[derive(Clone, Default)]
struct MockEdge(Arc<Mutex<EdgeState>>);

impl MockEdge {
    fn apply_count(&self) -> usize {
        self.0.lock().unwrap().applies.len()
    }

    /// The upstream address the edge currently serves for `site`, if any.
    fn served_upstream(&self, site: &str) -> Option<String> {
        self.0.lock().unwrap().serving.get(site).map(|config| {
            config["gateway_config"]["origin"]["address"]
                .as_str()
                .unwrap()
                .to_owned()
        })
    }

    /// The gateway configuration the edge currently serves for `site`.
    fn served_gateway_config(&self, site: &str) -> Option<Value> {
        self.0
            .lock()
            .unwrap()
            .serving
            .get(site)
            .map(|config| config["gateway_config"].clone())
    }

    fn served_sites(&self) -> Vec<String> {
        self.0.lock().unwrap().serving.keys().cloned().collect()
    }

    /// The raw body and signature header of the latest apply request.
    fn last_signed_apply(&self) -> Option<(Vec<u8>, String)> {
        self.0.lock().unwrap().signed.last().cloned()
    }

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
    state.signed.push((
        body.to_vec(),
        headers
            .get(xshield_core::edge_channel::APPLY_SIGNATURE_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned(),
    ));
    if let Some((status, body)) = state.refusal.take() {
        return (StatusCode::from_u16(status).unwrap(), Json(body)).into_response();
    }
    if revision < state.snapshot_revision {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "edge_apply_failed", "reason_code": "EDGE_APPLY_STALE_REVISION"})),
        )
            .into_response();
    }
    state.snapshot_revision = revision;
    state.serving = request["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|site| (site["site_id"].as_str().unwrap().to_owned(), site.clone()))
        .collect();
    state.applies.push(request.clone());
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
            get(|| async { Json(json!({"edge_state": "healthy", "audit_state": "healthy"})) }),
        )
        .with_state(edge.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (edge, format!("http://127.0.0.1:{port}/internal/v1/apply"))
}

const AUTHOR: &str = "author-1";
const APPROVER: &str = "independent-reviewer";

struct Ctx {
    tenant: TenantId,
    assertion_key: [u8; 32],
    edge: MockEdge,
    edge_url: String,
    database_url: String,
    pool: sqlx::PgPool,
    author: axum::Router,
    approver: axum::Router,
    access_directories: Mutex<Vec<std::path::PathBuf>>,
    sequence: std::sync::atomic::AtomicU32,
}

impl Ctx {
    async fn new() -> Self {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
        let tenant = TenantId::parse(format!("tenant_site_flow_{}", Uuid::now_v7())).unwrap();
        let (edge, edge_url) = start_edge().await;
        let default_site = SiteId::parse("site_default").unwrap();

        let store = PostgresIdentityStore::connect(&url, 8, Duration::from_secs(5))
            .await
            .unwrap();
        let mut author = Fixture::with_catalog(100_000, ManagementRole::SystemAdmin, store, 1);
        author.control.config.tenant_id = tenant.clone();
        author.control.config.site_id = default_site.clone();
        author.control.config.api_key_hash_key = Some(zeroize::Zeroizing::new([7_u8; 32]));
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
        .unwrap()
        // API-key administration authorizes against the control instance's own
        // site, so the principal needs that exact scope as well.
        .with_exact_site_scope(tenant.clone(), default_site.clone());
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
        let client =
            super::super::EdgeApplyClient::new(edge_url.clone(), &"11".repeat(32)).unwrap();
        let approver_app = router(approver.control.with_edge_apply_client(client));

        Self {
            tenant,
            assertion_key,
            edge,
            edge_url,
            pool: sqlx::PgPool::connect(&url).await.unwrap(),
            database_url: url,
            author: author_app,
            approver: approver_app,
            access_directories: Mutex::new(vec![author_access, approver_access]),
            sequence: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// A further principal with the given roles over the same tenant, store
    /// and edge. Its audit journal is read by [`Ctx::finish`].
    async fn principal(&self, subject: &str, roles: &[ManagementRole]) -> axum::Router {
        self.principal_with_step_up(subject, roles, false).await
    }

    /// Like [`Ctx::principal`], optionally with the fresh MFA step-up that a
    /// browser session carries for two minutes after reauthentication.
    async fn principal_with_step_up(
        &self,
        subject: &str,
        roles: &[ManagementRole],
        step_up: bool,
    ) -> axum::Router {
        let store = PostgresIdentityStore::connect(&self.database_url, 8, Duration::from_secs(5))
            .await
            .unwrap();
        let mut fixture = Fixture::with_decision_catalog(store, subject, roles[0]);
        fixture.control.test_step_up_valid = step_up;
        fixture.control.config.tenant_id = self.tenant.clone();
        fixture.control.config.site_id = SiteId::parse("site_default").unwrap();
        fixture.control.config.principal = ManagementPrincipal::new_tenant_scoped(
            subject,
            roles.iter().copied(),
            [self.tenant.clone()],
        )
        .unwrap();
        self.access_directories
            .lock()
            .unwrap()
            .push(fixture.access_directory.clone());
        let client =
            super::super::EdgeApplyClient::new(self.edge_url.clone(), &"11".repeat(32)).unwrap();
        router(fixture.control.with_edge_apply_client(client))
    }

    /// A fresh, valid idempotency key.
    fn key(&self, label: &str) -> String {
        let number = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("flow-test-{label}-{number:04}-padding-0000")
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

    /// Issues an API key the way production does: through a browser session
    /// holding the key-administration role (the machine credential may not).
    async fn issue_api_key(&self, body: &Value) -> (StatusCode, Value) {
        let header = super::api_key_harness::browser_assertion(
            &self.assertion_key,
            &self.tenant,
            "human-key-admin",
            &super::api_key_harness::ISSUER_ROLES,
        );
        let request = Request::builder()
            .method("POST")
            .uri("/control/v1/agent-api-keys")
            .header(AUTHORIZATION, header)
            .header("idempotency-key", self.key("issue-api-key"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        let response = self.author.clone().oneshot(request).await.unwrap();
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

    async fn put(&self, site: &str, body: &Value, key: &str) -> (StatusCode, Value) {
        Self::call(
            &self.author,
            "PUT",
            &format!("/control/v1/sites/{site}/config"),
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

    async fn status(&self, site: &str) -> Value {
        let (status, body) = Self::call(
            &self.author,
            "GET",
            &format!("/control/v1/sites/{site}/status"),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Creates a site and, if the control plane asks for approval, has the
    /// independent reviewer approve it; afterwards the site must be live.
    async fn create_live(&self, site: &str, upstream: &str) {
        let (status, created) = self
            .create(&site_body(site, upstream), &self.key("create"))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        if created["requires_approval"] == true {
            let (status, approved) = self.approve(site, &self.key("approve")).await;
            assert_eq!(status, StatusCode::OK, "{approved}");
        }
        let state = self.status(site).await;
        assert_eq!(state["apply_state"], "active", "{state}");
        assert_eq!(self.edge.served_upstream(site).as_deref(), Some(upstream));
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
        // Label bindings and edge rows outlive a site by design, so they are
        // removed explicitly.
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

fn with(mut body: Value, field: &str, value: Value) -> Value {
    body[field] = value;
    body
}

/// The reviewer's reproduction: a risky change first returns
/// `requires_approval=true` and is held, but the identical PUT with a new
/// idempotency key returned `requires_approval=false` and went live, putting
/// the unapproved upstream on the edge.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn resubmitting_a_risky_change_never_clears_its_approval() {
    let ctx = Ctx::new().await;
    ctx.create_live("site_resubmit", "8.8.8.8:9000").await;
    let applies_before = ctx.edge.apply_count();

    let risky = site_body("site_resubmit", "8.8.4.4:9000");
    let (_, first) = ctx.put("site_resubmit", &risky, &ctx.key("risky")).await;
    assert_eq!(first["requires_approval"], true, "{first}");
    assert_ne!(first["apply_state"], "active");

    let (_, second) = ctx.put("site_resubmit", &risky, &ctx.key("risky")).await;
    assert_eq!(second["requires_approval"], true, "{second}");
    assert_ne!(second["apply_state"], "active", "{second}");
    assert_eq!(
        ctx.edge.served_upstream("site_resubmit").as_deref(),
        Some("8.8.8.8:9000"),
        "the unapproved upstream must never reach the edge"
    );
    assert_eq!(ctx.edge.apply_count(), applies_before);

    // Only an approval bound to this revision releases it.
    let (status, approved) = ctx.approve("site_resubmit", &ctx.key("approve")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["apply_state"], "active", "{approved}");
    assert_eq!(approved["requires_approval"], false);
    assert_eq!(
        ctx.edge.served_upstream("site_resubmit").as_deref(),
        Some("8.8.4.4:9000")
    );
    let _ = ctx.finish().await;
}

/// The old predicate missed weakening changes: a route downgrade from a UI
/// action to authenticated, WAF fragments and headers cleared, object-access
/// enforcement turned off and limits raised all went live unapproved.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn weakening_changes_are_held_for_approval_until_approved() {
    let ctx = Ctx::new().await;
    let site = "site_weaken";
    let hardened = json!({
        "site_id": site, "display_name": site,
        "public_origin": "https://site-weaken.example.test",
        "upstream_address": "8.8.8.8:9000",
        "upstream_server_name": "origin.example.test",
        "upstream_tls": false, "listen_port": 0, "entry_path": "/",
        "security_entry": "ui_action_required", "sensor_enabled": false,
        "policy_revision": "policy-v1", "status": "active",
        "policy": {
            "routes": [{
                "operation_id": "orders.open", "method": "GET", "path": "/orders",
                "security_entry": "ui_action_required", "source_action": "orders.open"
            }],
            "waf": {
                "enabled": true, "blocked_headers": ["X-Evil"],
                "blocked_query_fragments": ["<script"], "max_cookie_bytes": 4096
            },
            "limits": {"requests_per_second": 100, "burst": 200},
            "origin_object_access_enforced": true
        }
    });
    let (_, created) = ctx.create(&hardened, &ctx.key("create")).await;
    if created["requires_approval"] == true {
        let (status, approved) = ctx.approve(site, &ctx.key("approve")).await;
        assert_eq!(status, StatusCode::OK, "{approved}");
    }
    assert_eq!(ctx.status(site).await["apply_state"], "active");
    let applies = ctx.edge.apply_count();

    let mut downgraded = hardened.clone();
    downgraded["policy"]["routes"][0]["security_entry"] = json!("authenticated_root");
    downgraded["policy"]["routes"][0]["source_action"] = Value::Null;
    let mut cleared = hardened.clone();
    cleared["policy"]["waf"]["blocked_headers"] = json!([]);
    cleared["policy"]["waf"]["blocked_query_fragments"] = json!([]);
    let mut unenforced = hardened.clone();
    unenforced["policy"]["origin_object_access_enforced"] = json!(false);
    let mut raised = hardened.clone();
    raised["policy"]["limits"] = json!({"requests_per_second": 50_000, "burst": 100_000});
    for (label, weakened) in [
        ("route downgraded to authenticated", downgraded),
        ("waf fragments and headers cleared", cleared),
        ("object access enforcement off", unenforced),
        ("limits raised", raised),
    ] {
        let (status, response) = ctx.put(site, &weakened, &ctx.key("weaken")).await;
        assert!(status.is_success(), "{label}: {response}");
        assert_eq!(response["requires_approval"], true, "{label}: {response}");
        assert_ne!(response["apply_state"], "active", "{label}");
        assert_eq!(ctx.edge.apply_count(), applies, "{label} must not be sent");
    }
    let _ = ctx.finish().await;
}

/// Approve revision 2 with key K, stage revision 3, replay K: the replay used
/// to return 200 for `desired_revision` 3, approving a revision nobody reviewed.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn an_approval_is_bound_to_the_revision_it_reviewed() {
    let ctx = Ctx::new().await;
    let site = "site_bound";
    ctx.create_live(site, "8.8.8.8:9000").await;

    let (_, revision_two) = ctx
        .put(site, &site_body(site, "8.8.4.4:9000"), &ctx.key("rev2"))
        .await;
    assert_eq!(revision_two["requires_approval"], true);
    let approval_key = ctx.key("approve-two");
    let (status, approved) = ctx.approve(site, &approval_key).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["apply_state"], "active");

    // The author stages a different risky revision after the review.
    let paused = with(site_body(site, "8.8.4.4:9000"), "status", json!("paused"));
    let (_, revision_three) = ctx.put(site, &paused, &ctx.key("rev3")).await;
    assert_eq!(
        revision_three["requires_approval"], true,
        "{revision_three}"
    );
    let applies = ctx.edge.apply_count();

    let (status, replay) = ctx.approve(site, &approval_key).await;
    assert_eq!(status, StatusCode::CONFLICT, "{replay}");
    assert_eq!(
        replay["error_code"],
        "CONTROL_SITE_APPROVAL_REVISION_MISMATCH"
    );
    let state = ctx.status(site).await;
    assert_eq!(
        state["requires_approval"], true,
        "revision 3 stays unapproved"
    );
    assert_eq!(ctx.edge.apply_count(), applies, "nothing reached the edge");
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("8.8.4.4:9000"),
        "the site is still served, not paused"
    );

    // The same key may still be replayed against the revision it approved:
    // a fresh key for revision 3 is the only way to approve it.
    let (status, approved) = ctx.approve(site, &ctx.key("approve-three")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let _ = ctx.finish().await;
}

/// The approver must not be the author of *that* revision, even when the same
/// person approved an earlier one; the comparison is made inside the approval
/// transaction against the revision actually being approved.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn the_approver_may_not_approve_the_revision_they_authored() {
    let ctx = Ctx::new().await;
    let site = "site_author_check";
    ctx.create_live(site, "8.8.8.8:9000").await;
    let roles = [
        ManagementRole::SystemAdmin,
        ManagementRole::PolicyApprover,
        ManagementRole::ReleaseOperator,
        ManagementRole::Observer,
    ];
    let alice = ctx.principal("alice", &roles).await;
    let bob = ctx.principal("bob", &roles).await;
    let write = |app: &axum::Router, upstream: &'static str, key: String| {
        let app = app.clone();
        async move {
            Ctx::call(
                &app,
                "PUT",
                &format!("/control/v1/sites/{site}/config"),
                Some(&site_body(site, upstream)),
                Some(&key),
            )
            .await
        }
    };
    let approve = |app: &axum::Router, key: String| {
        let app = app.clone();
        async move {
            Ctx::call(
                &app,
                "POST",
                &format!("/control/v1/sites/{site}/approve"),
                None,
                Some(&key),
            )
            .await
        }
    };

    // Alice authors revision 2 and cannot approve it herself.
    let (status, written) = write(&alice, "8.8.4.4:9000", ctx.key("alice-write")).await;
    assert!(status.is_success(), "{written}");
    assert_eq!(written["requires_approval"], true);
    let (status, refused) = approve(&alice, ctx.key("alice-self")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(refused["error_code"], "CONTROL_SITE_APPROVAL_SELF_REJECTED");
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("8.8.8.8:9000")
    );
    // Bob can approve it.
    let (status, approved) = approve(&bob, ctx.key("bob-approve")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("8.8.4.4:9000")
    );

    // Bob then authors revision 3: approving an earlier revision gives him no
    // right to approve one he wrote, but Alice can.
    let (status, written) = write(&bob, "9.9.9.9:9000", ctx.key("bob-write")).await;
    assert!(status.is_success(), "{written}");
    assert_eq!(written["requires_approval"], true);
    let (status, refused) = approve(&bob, ctx.key("bob-self")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(refused["error_code"], "CONTROL_SITE_APPROVAL_SELF_REJECTED");
    let (status, approved) = approve(&alice, ctx.key("alice-approve")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("9.9.9.9:9000")
    );
    drop((alice, bob));
    let events = ctx.finish().await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event["payload"]["reason_code"] == "CONTROL_SITE_APPROVAL_SELF_REJECTED")
            .count(),
        2,
        "both refusals are audited"
    );
}

/// A draft is a preparation state: it must never be routable. Applying one is
/// a stable, audited rejection, and the snapshot of its siblings omits it.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn draft_sites_are_never_applied_or_routable() {
    let ctx = Ctx::new().await;
    ctx.create_live("site_live", "8.8.8.8:9000").await;
    let applies = ctx.edge.apply_count();

    let draft = with(
        with(
            site_body("site_draft", "1.1.1.1:9000"),
            "security_entry",
            json!("ui_action_required"),
        ),
        "status",
        json!("draft"),
    );
    let (status, created) = ctx.create(&draft, &ctx.key("draft")).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert!(
        !ctx.edge.served_sites().contains(&"site_draft".to_owned()),
        "saving a draft must not publish it"
    );
    let (status, rejected) = ctx.apply("site_draft", &ctx.key("apply-draft")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{rejected}");
    assert_eq!(rejected["error_code"], "CONTROL_SITE_DRAFT_NOT_APPLICABLE");
    assert!(!ctx.edge.served_sites().contains(&"site_draft".to_owned()));

    // A sibling's change is applied without dragging the draft along.
    let (status, changed) = ctx
        .put(
            "site_live",
            &with(
                site_body("site_live", "8.8.8.8:9000"),
                "display_name",
                json!("renamed"),
            ),
            &ctx.key("rename"),
        )
        .await;
    assert!(status.is_success(), "{changed}");
    assert_eq!(changed["apply_state"], "active", "{changed}");
    assert!(ctx.edge.apply_count() > applies);
    assert_eq!(ctx.edge.served_sites(), vec!["site_live".to_owned()]);

    // Promoting the draft is an approval-requiring transition.
    let promoted = with(draft.clone(), "status", json!("active"));
    let (_, promotion) = ctx.put("site_draft", &promoted, &ctx.key("promote")).await;
    assert_eq!(promotion["requires_approval"], true, "{promotion}");
    assert!(!ctx.edge.served_sites().contains(&"site_draft".to_owned()));
    let (status, approved) = ctx.approve("site_draft", &ctx.key("approve-draft")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert!(ctx.edge.served_sites().contains(&"site_draft".to_owned()));

    let events = ctx.finish().await;
    assert!(events.iter().any(|event| {
        event["payload"]["reason_code"] == "CONTROL_SITE_DRAFT_NOT_APPLICABLE"
            && event["payload"]["outcome"] == "DENY"
    }));
}

/// Replaying write #1 after write #2 created revision 3 with the old content:
/// a lost update. A superseded key is refused instead.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn replaying_a_superseded_write_never_creates_a_revision() {
    let ctx = Ctx::new().await;
    let site = "site_idem";
    let first = with(
        site_body(site, "8.8.8.8:9000"),
        "display_name",
        json!("first"),
    );
    let second = with(
        site_body(site, "8.8.8.8:9000"),
        "display_name",
        json!("second-newer"),
    );
    let first_key = ctx.key("one");
    let second_key = ctx.key("two");
    let (status, a) = ctx.put(site, &first, &first_key).await;
    assert_eq!(status, StatusCode::CREATED, "{a}");
    let (status, b) = ctx.put(site, &second, &second_key).await;
    assert_eq!(status, StatusCode::OK, "{b}");
    assert_eq!(b["config"]["revision"], 2);

    let (status, stale) = ctx.put(site, &first, &first_key).await;
    assert_eq!(status, StatusCode::CONFLICT, "{stale}");
    assert_eq!(
        stale["error_code"],
        "CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED"
    );
    let (_, current) = Ctx::call(
        &ctx.author,
        "GET",
        &format!("/control/v1/sites/{site}/config"),
        None,
        None,
    )
    .await;
    assert_eq!(current["config"]["display_name"], "second-newer");
    assert_eq!(current["config"]["revision"], 2, "no revision was created");

    // The latest write still replays exactly.
    let (status, replay) = ctx.put(site, &second, &second_key).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["config"]["revision"], 2);
    // A superseded key reused with different content is a conflict, not a replay.
    let (status, conflict) = ctx
        .put(
            site,
            &with(first.clone(), "display_name", json!("something else")),
            &first_key,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    let _ = ctx.finish().await;
}

/// One pending approval used to freeze every apply in the tenant, and applying
/// the snapshot would have published the unapproved sibling.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_pending_approval_never_blocks_or_leaks_into_other_sites() {
    let ctx = Ctx::new().await;
    ctx.create_live("site_pending", "8.8.8.8:9000").await;

    // site_pending gets a risky change that nobody has approved yet.
    let (_, pending) = ctx
        .put(
            "site_pending",
            &site_body("site_pending", "8.8.4.4:9000"),
            &ctx.key("pending"),
        )
        .await;
    assert_eq!(pending["requires_approval"], true);

    // An unrelated site goes live while that approval is outstanding.
    ctx.create_live("site_other", "1.1.1.1:9000").await;
    assert_eq!(
        ctx.edge.served_upstream("site_other").as_deref(),
        Some("1.1.1.1:9000")
    );
    assert_eq!(
        ctx.edge.served_upstream("site_pending").as_deref(),
        Some("8.8.8.8:9000"),
        "the pending site stays on its last approved configuration"
    );
    let state = ctx.status("site_pending").await;
    assert_eq!(state["requires_approval"], true, "{state}");
    assert_ne!(state["apply_state"], "active");

    // A site that was never applied and awaits approval is simply absent.
    let (_, never) = ctx
        .create(&site_body("site_never", "9.9.9.9:9000"), &ctx.key("never"))
        .await;
    assert_eq!(never["requires_approval"], true);
    ctx.put(
        "site_other",
        &with(
            site_body("site_other", "1.1.1.1:9000"),
            "display_name",
            json!("renamed"),
        ),
        &ctx.key("rename"),
    )
    .await;
    assert!(
        !ctx.edge.served_sites().contains(&"site_never".to_owned()),
        "an unapproved new site is never published"
    );
    assert_eq!(
        ctx.edge.served_upstream("site_pending").as_deref(),
        Some("8.8.8.8:9000")
    );

    // Approving the pending change publishes it.
    let (status, approved) = ctx.approve("site_pending", &ctx.key("approve")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(
        ctx.edge.served_upstream("site_pending").as_deref(),
        Some("8.8.4.4:9000")
    );
    let _ = ctx.finish().await;
}

/// The Agent `site.config.apply_direct` capability stays an explicit, scoped
/// direct-apply right, but it now leaves a durable audited record and does not
/// leave a stale `requires_approval` flag that blocks other sites.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn direct_apply_is_recorded_and_does_not_leave_a_stale_flag() {
    let ctx = Ctx::new().await;
    let site = "site_direct";
    let (status, created) = ctx
        .create(&site_body(site, "8.8.8.8:9000"), &ctx.key("create"))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["requires_approval"], true);
    let digest = created["config_digest"].as_str().unwrap().to_owned();

    let expires = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    let (status, issued) = ctx
        .issue_api_key(&json!({
            "subject": "agent-direct", "display_name": "direct", "expires_at": expires,
            "scopes": [{
                "tenant_id": ctx.tenant.as_str(), "site_id": site,
                "capabilities": ["site.config.apply_direct", "site.read"]
            }]
        }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let api_key = issued["api_key"].as_str().unwrap().to_owned();

    // Without the capability (a plain operator) the apply is refused.
    let (status, denied) = ctx.apply(site, &ctx.key("operator")).await;
    assert_eq!(status, StatusCode::OK, "{denied}");
    assert_eq!(denied["requires_approval"], true);
    assert_ne!(denied["apply_state"], "active");
    assert_eq!(ctx.edge.served_upstream(site), None);

    let response = ctx
        .author
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/sites/{site}/apply"))
                .header("x-xshield-api-key", api_key.as_str())
                .header("x-xshield-agent-run-id", "run-1")
                .header("idempotency-key", ctx.key("direct"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let applied: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["apply_state"], "active", "{applied}");
    assert_eq!(
        applied["requires_approval"], false,
        "a direct apply must not leave the flag set"
    );
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("8.8.8.8:9000")
    );

    // Durable record: who applied directly and which digest.
    let record = sqlx::query(
        "SELECT approval_kind, approved_by, authored_by, encode(config_digest, 'hex') AS digest,
                desired_revision
         FROM xshield.site_apply_approvals WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(ctx.tenant.as_str())
    .bind(site)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(record.get::<String, _>("approval_kind"), "direct_apply");
    // The key's principal subject names the key id as well as the agent.
    assert_eq!(
        record.get::<String, _>("approved_by"),
        format!(
            "apikey:{}:agent-direct",
            issued["api_key_id"].as_str().unwrap()
        )
    );
    assert_eq!(record.get::<String, _>("authored_by"), AUTHOR);
    assert_eq!(record.get::<String, _>("digest"), digest);
    assert_eq!(record.get::<i64, _>("desired_revision"), 1);

    // The flag is gone, so an unrelated site is not blocked by it.
    ctx.create_live("site_after_direct", "1.1.1.1:9000").await;
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("8.8.8.8:9000")
    );
    assert_eq!(ctx.status(site).await["requires_approval"], false);

    let events = ctx.finish().await;
    assert!(events.iter().any(|event| {
        event["payload"]["reason_code"] == "EDGE_DIRECT_APPLY_CONFIRMED"
            && event["payload"]["outcome"] == "PASS"
    }));
}

/// A site whose desired configuration the edge cannot compile (a row written
/// before validation matched the edge) used to make every apply in the tenant
/// fail as a whole. It is now held at its last good configuration, reported on
/// its own status, and never blocks other sites; applying the broken site
/// itself fails with a stable reason that names it.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn an_uncompilable_site_is_reported_and_never_blocks_the_tenant() {
    let ctx = Ctx::new().await;
    ctx.create_live("site_broken", "8.8.8.8:9000").await;
    ctx.create_live("site_healthy", "1.1.1.1:9000").await;
    let before = ctx.edge.apply_count();

    // An older version stored a route the edge compiler refuses (a space) and
    // marked the revision applicable.
    sqlx::query(
        "UPDATE xshield.protected_site_configs
         SET policy_json = jsonb_set(policy_json, '{routes}',
             '[{\"operation_id\":\"bad\",\"method\":\"GET\",\"path\":\"/a b\",\"security_entry\":\"public\"}]'::jsonb)
         WHERE tenant_id = $1 AND site_id = 'site_broken'",
    )
    .bind(ctx.tenant.as_str())
    .execute(&ctx.pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE xshield.site_apply_intents SET apply_state = 'pending', reason_code = 'EDGE_APPLY_NOT_CONFIRMED'
         WHERE tenant_id = $1 AND site_id = 'site_broken'",
    )
    .bind(ctx.tenant.as_str())
    .execute(&ctx.pool)
    .await
    .unwrap();

    // Another site's change still applies, and the broken site keeps serving
    // its last good configuration.
    let (status, changed) = ctx
        .put(
            "site_healthy",
            &with(
                site_body("site_healthy", "1.1.1.1:9000"),
                "display_name",
                json!("renamed"),
            ),
            &ctx.key("rename"),
        )
        .await;
    assert!(status.is_success(), "{changed}");
    assert_eq!(changed["apply_state"], "active", "{changed}");
    assert!(ctx.edge.apply_count() > before);
    assert_eq!(
        ctx.edge.served_upstream("site_broken").as_deref(),
        Some("8.8.8.8:9000")
    );
    // The broken site's own status says why it is not progressing.
    let broken = ctx.status("site_broken").await;
    assert_eq!(broken["apply_state"], "failed", "{broken}");
    assert_eq!(broken["reason_code"], "CONTROL_SITE_POLICY_INVALID");

    // Applying it directly reports the same stable reason in the audit trail.
    let sent = ctx.edge.apply_count();
    let (status, applied) = ctx.apply("site_broken", &ctx.key("apply-broken")).await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    assert_eq!(applied["apply_state"], "failed");
    assert_eq!(applied["reason_code"], "CONTROL_SITE_POLICY_INVALID");
    assert_eq!(ctx.edge.apply_count(), sent, "nothing was sent for it");
    let events = ctx.finish().await;
    assert!(events.iter().any(|event| {
        event["payload"]["reason_code"] == "CONTROL_SITE_POLICY_INVALID"
            && event["payload"]["outcome"] == "ERROR"
    }));
}

async fn rollback(ctx: &Ctx, site: &str, key: &str) -> (StatusCode, Value) {
    Ctx::call(
        &ctx.author,
        "POST",
        &format!("/control/v1/sites/{site}/rollback"),
        None,
        Some(key),
    )
    .await
}

/// Rollback used to be unusable (the stored revision lacked `policy_revision`,
/// so every call returned 400) and picked `active - 1`, which can be a revision
/// that never served traffic. It now restores the previously *active*
/// configuration as a NEW revision, risk-evaluated like any other change,
/// audited and idempotent.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn rollback_restores_the_previously_active_configuration_as_a_new_revision() {
    let ctx = Ctx::new().await;
    let site = "site_rollback";
    // r1: live on A.
    ctx.create_live(site, "8.8.8.8:9000").await;
    // r2: B, approved and applied.
    let (_, second) = ctx
        .put(site, &site_body(site, "8.8.4.4:9000"), &ctx.key("to-b"))
        .await;
    assert_eq!(second["requires_approval"], true);
    let (status, approved) = ctx.approve(site, &ctx.key("approve-b")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let config_at_two = ctx.edge.served_gateway_config(site).unwrap();
    assert_eq!(config_at_two["origin"]["address"], "8.8.4.4:9000");
    // r3: C is saved but never approved, so it never serves traffic.
    let (_, third) = ctx
        .put(site, &site_body(site, "9.9.9.9:9000"), &ctx.key("to-c"))
        .await;
    assert_eq!(third["desired_revision"], 3);
    assert_eq!(third["requires_approval"], true);
    // r4: D replaces the unapproved r3 and is approved and applied.
    let (_, fourth) = ctx
        .put(site, &site_body(site, "7.7.7.7:9000"), &ctx.key("to-d"))
        .await;
    assert_eq!(fourth["desired_revision"], 4);
    let (status, approved) = ctx.approve(site, &ctx.key("approve-d")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let state = ctx.status(site).await;
    assert_eq!(state["active_revision"], 4);
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("7.7.7.7:9000")
    );

    // Rolling back from r4 means r2 (B), the revision that served before it,
    // not r3 (C), which merely has the previous number.
    let rollback_key = ctx.key("rollback");
    let (status, rolled) = rollback(&ctx, site, &rollback_key).await;
    assert!(status.is_success(), "{status} {rolled}");
    assert_eq!(
        rolled["desired_revision"], 5,
        "a new revision, never a reused number"
    );
    assert_eq!(rolled["config"]["upstream_address"], "8.8.4.4:9000");
    // Going from D back to B is a change to what the edge serves: the
    // rollback itself needs approval and is not applied yet.
    assert_eq!(rolled["requires_approval"], true, "{rolled}");
    assert_ne!(rolled["apply_state"], "active");
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("7.7.7.7:9000")
    );
    let (status, approved) = ctx.approve(site, &ctx.key("approve-rollback")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["apply_state"], "active", "{approved}");
    let state = ctx.status(site).await;
    assert_eq!(
        (
            state["desired_revision"].as_u64(),
            state["active_revision"].as_u64()
        ),
        (Some(5), Some(5))
    );
    assert_eq!(
        ctx.edge.served_gateway_config(site).unwrap(),
        config_at_two,
        "the edge receives exactly what it served at revision 2"
    );
    // Revision history is complete configurations and keeps every number.
    let (_, history) = Ctx::call(
        &ctx.author,
        "GET",
        &format!("/control/v1/sites/{site}/revisions"),
        None,
        None,
    )
    .await;
    let revisions = history["revisions"].as_array().unwrap();
    assert_eq!(revisions.len(), 5);
    assert_eq!(revisions[0]["revision"], 5);
    assert_eq!(revisions[0]["config"]["policy_revision"], "policy-v1");
    assert_eq!(revisions[0]["config"]["upstream_address"], "8.8.4.4:9000");

    // Idempotent: the same key replays the same outcome and creates nothing.
    let applies = ctx.edge.apply_count();
    let (status, replay) = rollback(&ctx, site, &rollback_key).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["desired_revision"], 5);
    assert_eq!(ctx.status(site).await["desired_revision"], 5);
    assert_eq!(
        ctx.edge.apply_count(),
        applies,
        "a replay publishes nothing"
    );

    // Rolling back again toggles to the revision active before r5 (r4, D) ...
    let (status, again) = rollback(&ctx, site, &ctx.key("rollback-again")).await;
    assert!(status.is_success(), "{again}");
    assert_eq!(again["desired_revision"], 6);
    assert_eq!(again["config"]["upstream_address"], "7.7.7.7:9000");
    assert_eq!(again["requires_approval"], true);
    // ... and a rollback issued while a change is pending cancels that change:
    // it restores what is *active* (r5, B), which equals the baseline, so it
    // needs no approval and the pending r6 is superseded.
    let (status, cancelled) = rollback(&ctx, site, &ctx.key("rollback-cancel")).await;
    assert!(status.is_success(), "{cancelled}");
    assert_eq!(cancelled["desired_revision"], 7);
    assert_eq!(cancelled["config"]["upstream_address"], "8.8.4.4:9000");
    assert_eq!(cancelled["requires_approval"], false, "{cancelled}");
    assert_eq!(cancelled["apply_state"], "active", "{cancelled}");
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("8.8.4.4:9000")
    );

    // The first rollback's key is superseded by now; replaying it neither
    // creates a revision nor resurrects the old outcome.
    let (status, superseded) = rollback(&ctx, site, &rollback_key).await;
    assert_eq!(status, StatusCode::CONFLICT, "{superseded}");
    assert_eq!(
        superseded["error_code"],
        "CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED"
    );
    assert_eq!(ctx.status(site).await["desired_revision"], 7);

    // Nothing to roll back to on a site with a single revision.
    ctx.create_live("site_single", "1.1.1.1:9000").await;
    let (status, unavailable) = rollback(&ctx, "site_single", &ctx.key("single")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{unavailable}");
    assert_eq!(
        unavailable["error_code"],
        "CONTROL_SITE_ROLLBACK_UNAVAILABLE"
    );

    let events = ctx.finish().await;
    let rollbacks = events
        .iter()
        .filter(|event| event["event_type"] == "console.site.config.rollback")
        .collect::<Vec<_>>();
    assert!(rollbacks.len() >= 5, "every attempt is audited");
    assert!(rollbacks.iter().any(|event| {
        event["payload"]["reason_code"] == "CONTROL_SITE_CONFIG_REPLAYED"
            && event["payload"]["outcome"] == "PASS"
    }));
    assert!(rollbacks.iter().any(|event| {
        event["payload"]["reason_code"] == "CONTROL_SITE_ROLLBACK_UNAVAILABLE"
            && event["payload"]["outcome"] == "DENY"
    }));
}

async fn delete(app: &axum::Router, site: &str, key: &str) -> (StatusCode, Value) {
    Ctx::call(
        app,
        "DELETE",
        &format!("/control/v1/sites/{site}"),
        None,
        Some(key),
    )
    .await
}

/// Deleting a site removes it from the edge. It used to need nothing beyond the
/// `SystemAdmin` role (and an API key with `site.config.write` carries that
/// role); it now needs the same fresh browser MFA step-up as the other
/// high-risk actions.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn deleting_a_site_requires_a_recent_step_up() {
    let ctx = Ctx::new().await;
    let site = "site_delete";
    ctx.create_live(site, "8.8.8.8:9000").await;
    let roles = [
        ManagementRole::SystemAdmin,
        ManagementRole::Observer,
        ManagementRole::ReleaseOperator,
    ];
    let stepped_up = ctx.principal_with_step_up("admin-mfa", &roles, true).await;

    // The author's session has no step-up: refused, audited, nothing changed.
    let (status, refused) = delete(&ctx.author, site, &ctx.key("no-step-up")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert_eq!(
        refused["error_code"],
        "CONTROL_SITE_DELETE_STEP_UP_REQUIRED"
    );
    assert_eq!(refused["next_action"], "reauthenticate");
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("8.8.8.8:9000")
    );
    assert_eq!(ctx.status(site).await["apply_state"], "active");

    // A machine credential has no step-up path either, whatever capabilities
    // it holds: `site.config.write` maps to SystemAdmin, which is not enough.
    let expires = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    let (status, issued) = ctx
        .issue_api_key(&json!({
            "subject": "agent-writer", "display_name": "writer", "expires_at": expires,
            "scopes": [{
                "tenant_id": ctx.tenant.as_str(), "site_id": site,
                "capabilities": ["site.config.write", "site.config.apply_direct", "site.rollback"]
            }]
        }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let api_key = issued["api_key"].as_str().unwrap().to_owned();
    let response = ctx
        .author
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/control/v1/sites/{site}"))
                .header("x-xshield-api-key", api_key.as_str())
                .header("x-xshield-agent-run-id", "run-1")
                .header("idempotency-key", ctx.key("api-key-delete"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let denied: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    // API keys never delete: the capability matrix has no delete capability, so
    // the request is refused on scope before the step-up requirement is reached.
    assert_eq!(denied["error_code"], "CONTROL_SCOPE_DENIED");
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("8.8.8.8:9000")
    );

    // After a fresh step-up the delete goes through: the route leaves the edge
    // first, then the site is removed.
    let (status, deleted) = delete(&stepped_up, site, &ctx.key("with-step-up")).await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(deleted["reason_code"], "CONTROL_SITE_DELETED");
    assert_eq!(ctx.edge.served_upstream(site), None);
    let (status, gone) = Ctx::call(
        &ctx.author,
        "GET",
        &format!("/control/v1/sites/{site}/status"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{gone}");

    drop(stepped_up);
    let events = ctx.finish().await;
    let deletions = events
        .iter()
        .filter(|event| event["event_type"] == "console.site.delete")
        .collect::<Vec<_>>();
    assert_eq!(
        deletions
            .iter()
            .filter(|event| event["payload"]["reason_code"]
                == "CONTROL_SITE_DELETE_STEP_UP_REQUIRED"
                && event["payload"]["outcome"] == "DENY")
            .count(),
        1,
        "the session attempt without a step-up is audited"
    );
    assert_eq!(
        deletions
            .iter()
            .filter(
                |event| event["payload"]["reason_code"] == "CONTROL_SCOPE_DENIED"
                    && event["payload"]["outcome"] == "DENY"
            )
            .count(),
        1,
        "the API-key attempt is refused on scope and audited"
    );
    assert!(deletions.iter().any(|event| {
        event["payload"]["reason_code"] == "CONTROL_SITE_DELETED"
            && event["payload"]["subject_ref"] == "admin-mfa"
            && event["payload"]["outcome"] == "PASS"
    }));
}

/// The takedown pause that precedes a delete is the caller's own, freshly
/// re-authenticated decision: it supersedes a revision still awaiting approval
/// instead of being blocked by it, and the unapproved content never serves.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_stepped_up_delete_supersedes_a_pending_approval_and_leaves_the_edge() {
    let ctx = Ctx::new().await;
    let site = "site_delete_pending";
    ctx.create_live(site, "8.8.8.8:9000").await;
    ctx.create_live("site_bystander", "1.1.1.1:9000").await;
    let (_, pending) = ctx
        .put(site, &site_body(site, "8.8.4.4:9000"), &ctx.key("risky"))
        .await;
    assert_eq!(pending["requires_approval"], true);
    let roles = [ManagementRole::SystemAdmin, ManagementRole::Observer];
    let stepped_up = ctx.principal_with_step_up("admin-mfa", &roles, true).await;

    let (status, deleted) = delete(&stepped_up, site, &ctx.key("delete")).await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(ctx.edge.served_upstream(site), None);
    assert_eq!(
        ctx.edge.served_upstream("site_bystander").as_deref(),
        Some("1.1.1.1:9000"),
        "other sites are untouched"
    );
    // The pause is removed together with the site; nothing remains to approve.
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.protected_site_configs WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(ctx.tenant.as_str())
    .bind(site)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(remaining, 0);
    drop(stepped_up);
    let _ = ctx.finish().await;
}

/// The simplest rollback: r1 applied, r2 changed, approved and applied, then a
/// rollback puts r1's configuration back as the new revision 3.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn rolling_back_one_change_restores_the_first_revision_as_revision_three() {
    let ctx = Ctx::new().await;
    let site = "site_rollback_simple";
    ctx.create_live(site, "8.8.8.8:9000").await;
    let at_one = ctx.edge.served_gateway_config(site).unwrap();
    let (_, changed) = ctx
        .put(
            site,
            &with(
                site_body(site, "8.8.4.4:9000"),
                "display_name",
                json!("second"),
            ),
            &ctx.key("change"),
        )
        .await;
    assert_eq!(changed["requires_approval"], true);
    let (status, approved) = ctx.approve(site, &ctx.key("approve")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(
        ctx.edge.served_upstream(site).as_deref(),
        Some("8.8.4.4:9000")
    );

    let (status, rolled) = rollback(&ctx, site, &ctx.key("rollback")).await;
    assert!(status.is_success(), "{status} {rolled}");
    assert_eq!(rolled["desired_revision"], 3);
    assert_eq!(
        rolled["config"]["display_name"], site,
        "revision 1's label too"
    );
    // Restoring the old upstream is a change to what the edge serves.
    assert_eq!(rolled["requires_approval"], true, "{rolled}");
    let (status, approved) = ctx.approve(site, &ctx.key("approve-rollback")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let state = ctx.status(site).await;
    assert_eq!(state["apply_state"], "active");
    assert_eq!(
        state["active_revision"], 3,
        "a new revision, not a reused one"
    );
    assert_eq!(
        ctx.edge.served_gateway_config(site).unwrap(),
        at_one,
        "the edge receives revision 1's configuration"
    );
    let _ = ctx.finish().await;
}

/// A reviewer can pin an approval to the configuration they read; a digest
/// that no longer matches is a stable 409 and approves nothing.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn an_approval_can_be_pinned_to_the_reviewed_configuration_digest() {
    let ctx = Ctx::new().await;
    let site = "site_pinned";
    let (_, created) = ctx
        .create(&site_body(site, "8.8.8.8:9000"), &ctx.key("create"))
        .await;
    assert_eq!(created["requires_approval"], true);
    let reviewed = created["config_digest"].as_str().unwrap().to_owned();
    // The author swaps in a different revision after the review.
    let (_, swapped) = ctx
        .put(site, &site_body(site, "8.8.4.4:9000"), &ctx.key("swap"))
        .await;
    let current = swapped["config_digest"].as_str().unwrap().to_owned();
    assert_ne!(reviewed, current);

    let approve_with = |digest: String, key: String| {
        let app = ctx.approver.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/control/v1/sites/{site}/approve"))
                        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                        .header("idempotency-key", key)
                        .header("x-xshield-expected-config-digest", digest)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap())
                    .unwrap();
            (status, body)
        }
    };
    let (status, stale) = approve_with(reviewed, ctx.key("stale-pin")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{stale}");
    assert_eq!(
        stale["error_code"],
        "CONTROL_SITE_APPROVAL_REVISION_MISMATCH"
    );
    assert_eq!(ctx.status(site).await["requires_approval"], true);
    let (status, malformed) = approve_with("not-a-digest".to_owned(), ctx.key("bad-pin")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{malformed}");
    assert_eq!(ctx.status(site).await["requires_approval"], true);
    let (status, approved) = approve_with(current, ctx.key("good-pin")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["requires_approval"], false);
    let _ = ctx.finish().await;
}

// ---- Browser provenance flow -------------------------------------------------

/// The control-plane spelling of the real-browser loop topology.
const BROWSER_LOOP: &str = include_str!("../../../../tests/site-config/browser-loop.json");
/// Its edge projection for `tenant_loop`/`site_loop`, without `site_policy`;
/// the gateway parity test proves it equals the loop script's operations.
const BROWSER_LOOP_GATEWAY: &str =
    include_str!("../../../../tests/site-config/browser-loop.gateway.json");

/// The loop topology as a create/replace body for `site`.
fn loop_body(site: &str) -> Value {
    let mut body: Value = serde_json::from_str(BROWSER_LOOP).unwrap();
    body["site_id"] = json!(site);
    body
}

/// `POST /sites/{site}/apply` under an Agent API key.
async fn apply_with_key(ctx: &Ctx, site: &str, api_key: &str) -> (StatusCode, Value) {
    let response = ctx
        .author
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/control/v1/sites/{site}/apply"))
                .header("x-xshield-api-key", api_key)
                .header("x-xshield-agent-run-id", "run-flow")
                .header("idempotency-key", ctx.key("direct-flow"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap())
        .unwrap_or(Value::Null);
    (status, body)
}

/// What the mock edge last received for `site`, checked against the
/// signature header it came with, with the per-test tenant normalized to the
/// golden's and `site_policy` returned separately.
fn signed_projection(ctx: &Ctx, site: &str) -> (Value, Value) {
    let (body, signature) = ctx.edge.last_signed_apply().unwrap();
    let key = openssl::pkey::PKey::hmac(&[0x11_u8; 32]).unwrap();
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
    signer.update(&body).unwrap();
    let expected = signer
        .sign_to_vec()
        .unwrap()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            write!(hex, "{byte:02x}").unwrap();
            hex
        });
    assert_eq!(signature, expected, "the projection is the signed body");
    let request: Value = serde_json::from_slice(&body).unwrap();
    let mut projection = request["sites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["site_id"] == site)
        .unwrap()["gateway_config"]
        .clone();
    assert_eq!(projection["tenant_id"], ctx.tenant.as_str());
    projection["tenant_id"] = json!("tenant_loop");
    let policy = projection
        .as_object_mut()
        .unwrap()
        .remove("site_policy")
        .unwrap();
    (projection, policy)
}

/// The real-browser loop topology goes from a write through validation and an
/// independent approval to the edge, and the signed snapshot carries exactly
/// its golden projection. The `site.config.apply_direct` capability can stand
/// in for the approver neither when the flow goes live, nor when it changes,
/// nor when a rollback restores it.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn the_browser_loop_reaches_the_edge_as_its_golden_projection_only_through_an_approver() {
    let ctx = Ctx::new().await;
    let site = "site_loop";
    let golden: Value = serde_json::from_str(BROWSER_LOOP_GATEWAY).unwrap();
    let stored: Value = serde_json::from_str(BROWSER_LOOP).unwrap();

    let (status, created) = ctx.create(&loop_body(site), &ctx.key("create-loop")).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["requires_approval"], true);
    assert_eq!(
        created["config"]["policy"], stored["policy"],
        "read back as written"
    );
    let (status, validated) = Ctx::call(
        &ctx.author,
        "POST",
        &format!("/control/v1/sites/{site}/validate"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{validated}");
    assert_eq!(validated["valid"], true);
    assert_eq!(validated["reason_code"], "CONTROL_SITE_VALIDATED");

    let expires = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    let (status, issued) = ctx
        .issue_api_key(&json!({
            "subject": "agent-flow", "display_name": "flow", "expires_at": expires,
            "scopes": [{
                "tenant_id": ctx.tenant.as_str(), "site_id": site,
                "capabilities": ["site.config.apply_direct", "site.read"]
            }]
        }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let api_key = issued["api_key"].as_str().unwrap().to_owned();
    let refused = |phase: &'static str| {
        let (ctx, api_key) = (&ctx, api_key.clone());
        async move {
            let sent = ctx.edge.apply_count();
            let (status, body) = apply_with_key(ctx, site, &api_key).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{phase}: {body}");
            assert_eq!(
                body["error_code"], "CONTROL_SITE_INDEPENDENT_APPROVAL_REQUIRED",
                "{phase}"
            );
            assert_eq!(ctx.edge.apply_count(), sent, "{phase}: nothing was sent");
            assert_eq!(ctx.status(site).await["requires_approval"], true, "{phase}");
        }
    };

    // Going live with the flow.
    refused("activation").await;
    assert_eq!(ctx.edge.served_upstream(site), None);
    let (status, approved) = ctx.approve(site, &ctx.key("approve-loop")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["apply_state"], "active", "{approved}");
    let (projection, policy) = signed_projection(&ctx, site);
    assert_eq!(projection, golden);
    assert_eq!(policy, stored["policy"]);

    // Changing what a list qualifies.
    let mut changed = loop_body(site);
    changed["policy"]["routes"][3]["resource_grant"]["max_items"] = json!(20);
    let (status, saved) = ctx.put(site, &changed, &ctx.key("grant-change")).await;
    assert!(status.is_success(), "{saved}");
    assert_eq!(saved["requires_approval"], true);
    refused("resource grant change").await;
    let (status, approved) = ctx.approve(site, &ctx.key("approve-change")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let (projection, _) = signed_projection(&ctx, site);
    assert_eq!(
        projection["operations"][3]["response"]["resource_grant"]["max_items"],
        20
    );

    // Rolling back restores the loop as a new revision, held for approval.
    let (status, rolled) = rollback(&ctx, site, &ctx.key("rollback-loop")).await;
    assert!(status.is_success(), "{status} {rolled}");
    assert_eq!(rolled["desired_revision"], 3);
    assert_eq!(rolled["requires_approval"], true);
    refused("rollback").await;
    let (status, approved) = ctx.approve(site, &ctx.key("approve-rollback")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    let (projection, policy) = signed_projection(&ctx, site);
    assert_eq!(projection, golden);
    assert_eq!(policy, stored["policy"]);

    let approvals: Vec<String> = sqlx::query_scalar(
        "SELECT approval_kind FROM xshield.site_apply_approvals
         WHERE tenant_id = $1 AND site_id = $2 ORDER BY desired_revision",
    )
    .bind(ctx.tenant.as_str())
    .bind(site)
    .fetch_all(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(approvals, ["independent", "independent", "independent"]);
    let events = ctx.finish().await;
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event["payload"]["reason_code"] == "CONTROL_SITE_INDEPENDENT_APPROVAL_REQUIRED"
                    && event["payload"]["outcome"] == "DENY"
            })
            .count(),
        3
    );
}

/// Gateway features the control plane does not manage and violations of each
/// flow rule are refused with their own stable reasons, and bodies far above
/// the former 16 KiB limit are accepted.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn flow_refusals_have_their_own_reasons_and_large_sites_fit() {
    type Edit = fn(&mut Value, usize, usize);
    let ctx = Ctx::new().await;
    let site = "site_flow_rules";
    let (status, created) = ctx.create(&loop_body(site), &ctx.key("create")).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");

    let route = |body: &Value, id: &str| -> usize {
        body["policy"]["routes"]
            .as_array()
            .unwrap()
            .iter()
            .position(|route| route["operation_id"] == id)
            .unwrap()
    };
    let cases: [(&str, &str, Edit); 10] = [
        (
            "share issuance",
            "CONTROL_SITE_FEATURE_UNSUPPORTED",
            |b, list, _| {
                b["policy"]["routes"][list]["share_issue"] = json!({"success_status": 200});
            },
        ),
        (
            "service identity",
            "CONTROL_SITE_FEATURE_UNSUPPORTED",
            |b, list, _| {
                b["policy"]["routes"][list]["security_entry"] = json!("service_identity");
            },
        ),
        (
            "compatibility crypto",
            "CONTROL_SITE_FEATURE_UNSUPPORTED",
            |b, list, _| {
                b["policy"]["routes"][list]["request_crypto"] =
                    json!({"mode": "COMPATIBILITY", "adapter_revision": "a"});
            },
        ),
        (
            "credential refresh",
            "CONTROL_SITE_FEATURE_UNSUPPORTED",
            |b, _, logout| {
                b["policy"]["routes"][logout]["auth_refresh"] = json!({"success_status": 200});
            },
        ),
        (
            "binding on a root",
            "CONTROL_SITE_AUTH_FLOW_INVALID",
            |b, _, _| {
                b["policy"]["routes"][1]["security_entry"] = json!("authenticated_root");
            },
        ),
        (
            "sensor disabled",
            "CONTROL_SITE_SENSOR_HTML_INVALID",
            |b, _, _| {
                b["sensor_enabled"] = json!(false);
            },
        ),
        (
            "unknown page",
            "CONTROL_SITE_PAGE_ACTIONS_INVALID",
            |b, list, _| {
                b["policy"]["routes"][list]["issued_by"]["page_operation_id"] = json!("missing");
            },
        ),
        (
            "missing grant target",
            "CONTROL_SITE_RESOURCE_GRANT_INVALID",
            |b, list, _| {
                b["policy"]["routes"][list]["resource_grant"]["target_operation_id"] =
                    json!("orders.gone");
            },
        ),
        (
            "one action, two meanings",
            "CONTROL_SITE_ACTION_DESCRIPTOR_CONFLICT",
            |b, list, _| {
                let mut shadow = b["policy"]["routes"][list].clone();
                shadow["operation_id"] = json!("orders.list.shadow");
                shadow["path"] = json!("/orders-shadow");
                shadow.as_object_mut().unwrap().remove("resource_grant");
                b["policy"]["routes"].as_array_mut().unwrap().push(shadow);
            },
        ),
        (
            "plain policy violation",
            "CONTROL_SITE_POLICY_INVALID",
            |b, list, _| {
                b["policy"]["routes"][list]["path"] = json!("/a b");
            },
        ),
    ];
    for (label, reason, edit) in cases {
        let mut body = loop_body(site);
        let (list, logout) = (route(&body, "orders.list"), route(&body, "auth.logout"));
        edit(&mut body, list, logout);
        let (status, refused) = ctx.put(site, &body, &ctx.key("refused")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {refused}");
        assert_eq!(refused["error_code"], reason, "{label}");
    }
    // A PATCH that asks for an unmanaged feature is named the same way.
    let mut policy = loop_body(site)["policy"].clone();
    policy["routes"][0]["evidence_capture"] = json!({"max_bytes": 1});
    let (status, refused) = Ctx::call(
        &ctx.author,
        "PATCH",
        &format!("/control/v1/sites/{site}"),
        Some(&json!({"policy": policy})),
        Some(&ctx.key("patch-refused")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error_code"], "CONTROL_SITE_FEATURE_UNSUPPORTED");
    // Nothing above created a revision.
    assert_eq!(ctx.status(site).await["desired_revision"], 1);

    // A site with 200 routes is several times the former 16 KiB body limit.
    let mut large = loop_body(site);
    let routes = large["policy"]["routes"].as_array_mut().unwrap();
    for index in 0..194 {
        routes.push(json!({
            "operation_id": format!("docs.page.{index:03}"),
            "method": "GET",
            "path": format!("/documentation/{}/section-{index:03}", "a".repeat(200)),
            "security_entry": "public",
            "response_mode": "BUFFERED_JSON",
            "max_response_bytes": 65_536
        }));
    }
    let body_bytes = serde_json::to_vec(&large).unwrap().len();
    assert!(body_bytes > 4 * 16 * 1024, "{body_bytes} bytes");
    let (status, saved) = ctx.put(site, &large, &ctx.key("large")).await;
    assert!(status.is_success(), "{saved}");
    assert_eq!(saved["desired_revision"], 2);
    // Above the limit the body is refused before it is parsed.
    let mut too_large = loop_body(site);
    too_large["display_name"] = json!("x".repeat(300 * 1024));
    let (status, _) = ctx.put(site, &too_large, &ctx.key("too-large")).await;
    assert!(status.is_client_error(), "{status}");
    assert_eq!(ctx.status(site).await["desired_revision"], 2);

    let events = ctx.finish().await;
    assert!(events.iter().any(|event| {
        event["payload"]["reason_code"] == "CONTROL_SITE_FEATURE_UNSUPPORTED"
            && event["payload"]["outcome"] == "DENY"
    }));
}

/// The loop body for `site` with its page-issued list action moved: the same
/// routes, another action-descriptor set.
fn moved_loop_body(site: &str) -> Value {
    let mut body = loop_body(site);
    for route in body["policy"]["routes"].as_array_mut().unwrap() {
        if route["operation_id"] == "orders.list" {
            route["path"] = json!("/orders-all");
        }
    }
    body
}

/// The descriptor digest the edge derives for a site body, as it stores it.
fn descriptor_digest(body: &Value) -> String {
    let mut config = body.clone();
    config.as_object_mut().unwrap().remove("site_id");
    serde_json::from_value::<xshield_core::SiteConfig>(config)
        .unwrap()
        .edge_descriptor_digest()
        .unwrap()
        .unwrap()
        .to_hex()
}

/// The edge's own policy-revision row for one label, as the edge's descriptor
/// supply leaves it (the mock edge does not write `PostgreSQL`).
async fn edge_binds(ctx: &Ctx, site: &str, label: &str, digest: &str) {
    sqlx::query(
        "INSERT INTO xshield.policy_revisions
             (tenant_id, site_id, revision, status, content_digest, artifact_ref)
         VALUES ($1, $2, $3, 'active', $4, 'test.seed')
         ON CONFLICT (tenant_id, site_id, revision)
         DO UPDATE SET content_digest = EXCLUDED.content_digest",
    )
    .bind(ctx.tenant.as_str())
    .bind(site)
    .bind(label)
    .bind(digest)
    .execute(&ctx.pool)
    .await
    .unwrap();
}

/// Forgets the control plane's label bindings of `site`: the state a control
/// service older than migration 0053 leaves, which neither checked nor bound.
async fn forget_label_bindings(ctx: &Ctx, site: &str) {
    sqlx::query(
        "DELETE FROM xshield.site_descriptor_bindings WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(ctx.tenant.as_str())
    .bind(site)
    .execute(&ctx.pool)
    .await
    .unwrap();
}

/// Moving a page action while keeping the `policy_revision` label is refused
/// on PUT with its own reason, before anything is stored or sent; validate
/// and approve refuse a revision an older control service stored that way.
/// The same change under a new label goes live, and a site without page
/// issuance edits freely under its label.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn reusing_a_policy_revision_label_for_other_page_actions_never_reaches_the_edge() {
    let ctx = Ctx::new().await;
    let site = "site_label";
    let (status, created) = ctx.create(&loop_body(site), &ctx.key("create")).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (status, approved) = ctx.approve(site, &ctx.key("approve")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["apply_state"], "active");
    let applies = ctx.edge.apply_count();

    let (status, refused) = ctx
        .put(site, &moved_loop_body(site), &ctx.key("reuse"))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["error_code"], "CONTROL_SITE_POLICY_REVISION_REUSED");
    assert_eq!(refused["next_action"], "change_policy_revision");
    assert_eq!(refused["retryable"], false);
    assert!(
        refused["message_safe"]
            .as_str()
            .unwrap()
            .contains("new policy_revision"),
        "{refused}"
    );
    assert_eq!(
        ctx.status(site).await["desired_revision"],
        1,
        "nothing stored"
    );
    assert_eq!(ctx.edge.apply_count(), applies, "nothing sent");

    // Under a new label the change is stored, approved and served.
    let moved = with(moved_loop_body(site), "policy_revision", json!("loop-r2"));
    let (status, saved) = ctx.put(site, &moved, &ctx.key("relabel")).await;
    assert!(status.is_success(), "{saved}");
    assert_eq!(saved["requires_approval"], true);
    let (status, approved) = ctx.approve(site, &ctx.key("approve-relabel")).await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["apply_state"], "active");
    assert_eq!(
        ctx.edge.served_gateway_config(site).unwrap()["policy_revision"],
        "loop-r2"
    );

    // An older control service stores the original set under loop-r2, which
    // the edge binds to the moved set.
    forget_label_bindings(&ctx, site).await;
    let stale = with(loop_body(site), "policy_revision", json!("loop-r2"));
    let (status, saved) = ctx.put(site, &stale, &ctx.key("older-service")).await;
    assert!(status.is_success(), "{saved}");
    assert_eq!(saved["requires_approval"], true);
    edge_binds(&ctx, site, "loop-r2", &descriptor_digest(&moved)).await;
    let (status, validated) = Ctx::call(
        &ctx.author,
        "POST",
        &format!("/control/v1/sites/{site}/validate"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{validated}");
    assert_eq!(validated["valid"], false);
    assert_eq!(
        validated["reason_code"],
        "CONTROL_SITE_POLICY_REVISION_REUSED"
    );
    let applies = ctx.edge.apply_count();
    let (status, refused) = ctx.approve(site, &ctx.key("approve-stale")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["error_code"], "CONTROL_SITE_POLICY_REVISION_REUSED");
    assert_eq!(ctx.status(site).await["requires_approval"], true);
    assert_eq!(ctx.edge.apply_count(), applies, "nothing sent");
    assert_eq!(
        ctx.edge.served_gateway_config(site).unwrap()["policy_revision"],
        "loop-r2",
        "the edge keeps serving the approved set"
    );

    // A plain site renames itself and validates under its unchanged label.
    ctx.create_live("site_plain", "8.8.8.8:9000").await;
    let renamed = with(
        site_body("site_plain", "8.8.8.8:9000"),
        "display_name",
        json!("Plain renamed"),
    );
    let (status, saved) = ctx
        .put("site_plain", &renamed, &ctx.key("plain-rename"))
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["apply_state"], "active", "{saved}");
    let (status, validated) = Ctx::call(
        &ctx.author,
        "POST",
        "/control/v1/sites/site_plain/validate",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{validated}");
    assert_eq!(validated["reason_code"], "CONTROL_SITE_VALIDATED");

    let events = ctx.finish().await;
    let refusals = events
        .iter()
        .filter(|event| {
            event["payload"]["reason_code"] == "CONTROL_SITE_POLICY_REVISION_REUSED"
                && event["payload"]["outcome"] == "DENY"
        })
        .count();
    assert_eq!(refusals, 3, "the PUT, the validation and the approval");
}

/// A desired revision that would carry a reused label is held at its last
/// approved configuration while a sibling's change applies, its own status
/// says why, and applying it directly is refused before anything is sent.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_reused_label_holds_back_only_its_own_site() {
    let ctx = Ctx::new().await;
    let (site, sibling) = ("site_reused", "site_sibling");
    let (status, created) = ctx.create(&loop_body(site), &ctx.key("create")).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (status, _) = ctx.approve(site, &ctx.key("approve")).await;
    assert_eq!(status, StatusCode::OK);
    ctx.create_live(sibling, "8.8.8.8:9000").await;

    // An older control service stored the moved set under loop-r1 and
    // approved it without binding anything, while the edge binds loop-r1 to
    // the original set.
    forget_label_bindings(&ctx, site).await;
    let (status, saved) = ctx
        .put(site, &moved_loop_body(site), &ctx.key("older-service"))
        .await;
    assert!(status.is_success(), "{saved}");
    sqlx::query(
        "UPDATE xshield.site_apply_intents
         SET requires_approval = false, reason_code = 'CONTROL_SITE_APPROVED'
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(ctx.tenant.as_str())
    .bind(site)
    .execute(&ctx.pool)
    .await
    .unwrap();
    edge_binds(&ctx, site, "loop-r1", &descriptor_digest(&loop_body(site))).await;

    // The sibling's change applies; the reused site stays on what was
    // approved and reports why on its own status.
    let renamed = with(
        site_body(sibling, "8.8.8.8:9000"),
        "display_name",
        json!("Sibling renamed"),
    );
    let (status, saved) = ctx.put(sibling, &renamed, &ctx.key("sibling")).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["apply_state"], "active", "{saved}");
    let served = ctx.edge.served_gateway_config(site).unwrap();
    let list = served["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["operation_id"] == "orders.list")
        .unwrap()
        .clone();
    assert_eq!(list["path"], "/orders", "held at the approved set");
    let state = ctx.status(site).await;
    assert_eq!(state["apply_state"], "failed", "{state}");
    assert_eq!(state["reason_code"], "CONTROL_SITE_POLICY_REVISION_REUSED");
    assert_eq!(ctx.status(sibling).await["apply_state"], "active");

    // Applying the site itself is refused before anything is sent.
    let sent = ctx.edge.apply_count();
    let (status, outcome) = ctx.apply(site, &ctx.key("apply")).await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(outcome["apply_state"], "failed");
    assert_eq!(
        outcome["reason_code"],
        "CONTROL_SITE_POLICY_REVISION_REUSED"
    );
    assert_eq!(ctx.edge.apply_count(), sent, "nothing sent");

    let events = ctx.finish().await;
    assert!(events.iter().any(|event| {
        event["payload"]["reason_code"] == "CONTROL_SITE_POLICY_REVISION_REUSED"
            && event["payload"]["outcome"] == "ERROR"
    }));
}

/// An edge descriptor conflict names the site that caused it. That site's
/// status carries the code, the site whose save triggered the apply stays
/// pending and the other sites keep their state. A name this plane did not
/// send as a desired revision (unknown, or the target itself) leaves the
/// failure on the target, as before.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_descriptor_conflict_is_recorded_on_the_site_the_edge_names() {
    let ctx = Ctx::new().await;
    for site in ["site_a", "site_b", "site_c"] {
        ctx.create_live(site, "8.8.8.8:9000").await;
    }
    let conflict = |site: &str| {
        json!({
            "error": "edge_apply_failed",
            "reason_code": "EDGE_APPLY_DESCRIPTOR_CONFLICT",
            "site_id": site
        })
    };

    ctx.edge.refuse_next(409, conflict("site_b"));
    let renamed = with(
        site_body("site_a", "8.8.8.8:9000"),
        "display_name",
        json!("A renamed"),
    );
    let (status, saved) = ctx.put("site_a", &renamed, &ctx.key("rename")).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["apply_state"], "pending", "the target caused nothing");
    assert_eq!(saved["reason_code"], "EDGE_APPLY_NOT_CONFIRMED");
    let named = ctx.status("site_b").await;
    assert_eq!(named["apply_state"], "failed", "{named}");
    assert_eq!(named["reason_code"], "EDGE_APPLY_DESCRIPTOR_CONFLICT");
    let other = ctx.status("site_c").await;
    assert_eq!(other["apply_state"], "active", "{other}");
    assert_eq!(other["reason_code"], "EDGE_APPLY_CONFIRMED");

    for name in ["site_unknown", "site_a"] {
        ctx.edge.refuse_next(409, conflict(name));
        let (status, outcome) = ctx.apply("site_a", &ctx.key("apply")).await;
        assert_eq!(status, StatusCode::OK, "{outcome}");
        assert_eq!(outcome["apply_state"], "failed", "{name}: {outcome}");
        assert_eq!(outcome["reason_code"], "EDGE_APPLY_DESCRIPTOR_CONFLICT");
        assert_eq!(ctx.status("site_c").await["apply_state"], "active");
    }
    // Nothing of the refused snapshots was served.
    assert_eq!(
        ctx.edge.served_gateway_config("site_a").unwrap()["origin"]["address"],
        "8.8.8.8:9000"
    );
    let _ = ctx.finish().await;
}
