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
    serving: BTreeMap<String, Value>,
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

    fn served_sites(&self) -> Vec<String> {
        self.0.lock().unwrap().serving.keys().cloned().collect()
    }
}

async fn edge_apply(
    State(edge): State<MockEdge>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<Value>) {
    let request: Value = serde_json::from_slice(&body).unwrap();
    let revision = request["snapshot_revision"].as_u64().unwrap();
    let mut state = edge.0.lock().unwrap();
    if revision < state.snapshot_revision {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "edge_apply_failed", "reason_code": "EDGE_APPLY_STALE_REVISION"})),
        );
    }
    state.snapshot_revision = revision;
    state.serving = request["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|site| (site["site_id"].as_str().unwrap().to_owned(), site.clone()))
        .collect();
    state.applies.push(request.clone());
    (
        StatusCode::OK,
        Json(json!({
            "apply_id": request["apply_id"],
            "active_revision": revision,
            "apply_state": "active",
            "reason_code": "EDGE_APPLY_CONFIRMED"
        })),
    )
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
        let store = PostgresIdentityStore::connect(&self.database_url, 8, Duration::from_secs(5))
            .await
            .unwrap();
        let mut fixture = Fixture::with_decision_catalog(store, subject, roles[0]);
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
        sqlx::query("DELETE FROM xshield.protected_site_configs WHERE tenant_id = $1")
            .bind(tenant.as_str())
            .execute(&pool)
            .await
            .unwrap();
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
    let (status, issued) = Ctx::call(
        &ctx.author,
        "POST",
        "/control/v1/agent-api-keys",
        Some(&json!({
            "subject": "agent-direct", "display_name": "direct", "expires_at": expires,
            "scopes": [{
                "tenant_id": ctx.tenant.as_str(), "site_id": site,
                "capabilities": ["site.config.apply_direct", "site.read"]
            }]
        })),
        None,
    )
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
    assert_eq!(record.get::<String, _>("approved_by"), "agent-direct");
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
