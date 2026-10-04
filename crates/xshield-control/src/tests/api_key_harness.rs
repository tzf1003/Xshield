//! Shared harness for the management API-key HTTP tests: a control plane over a
//! scratch `PostgreSQL` database, a fresh tenant per test, signed browser-session
//! assertions for key administrators, and direct SQL probes of key rows.

use super::*;

pub(super) const RUN_ID: &str = "agt_018f2a3b-4c5d-7000-8000-00000000a001";
pub(super) const DEFAULT_SITE: &str = "site_default";
/// Documented tenant-wide marker; only `site.create` may use it.
pub(super) const TENANT_WIDE: &str = "__tenant__";
pub(super) const ISSUER_ROLES: [&str; 6] = [
    "key_administrator",
    "system_admin",
    "observer",
    "policy_author",
    "policy_approver",
    "release_operator",
];

pub(super) struct Harness {
    pub(super) app: axum::Router,
    pub(super) tenant: TenantId,
    pub(super) access_directory: std::path::PathBuf,
    assertion_key: [u8; 32],
    pool: sqlx::PgPool,
}

pub(super) fn site_body(site: &str) -> Value {
    json!({
        "site_id": site,
        "display_name": site,
        "public_origin": format!("https://{}.example.test", site.replace('_', "-")),
        "upstream_address": "8.8.8.8:9000",
        "upstream_server_name": "origin.example.test",
        "upstream_tls": false,
        "listen_port": 0,
        "entry_path": "/",
        "security_entry": "ui_action_required",
        "sensor_enabled": false,
        "policy_revision": "policy-v1",
        "status": "active"
    })
}

pub(super) fn http_request(
    method: &str,
    path: &str,
    body: Option<&Value>,
    headers: &[(&str, String)],
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

fn idempotency() -> (&'static str, String) {
    (
        "idempotency-key",
        format!("api-key-authz-{}", Uuid::now_v7()),
    )
}

pub(super) fn is_scope_denied(status: StatusCode, body: &Value) -> bool {
    status == StatusCode::FORBIDDEN && body["error_code"] == "CONTROL_SCOPE_DENIED"
}

pub(super) async fn junk_key_request(app: &axum::Router, index: u32) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/control/v1/sites")
                .header("x-xshield-api-key", format!("xsk_{index:048x}"))
                .header("x-xshield-agent-run-id", RUN_ID)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The audit journal of the shared fixture is deliberately tiny; most tests
/// issue many requests, so give them a roomy one with the same layout.
/// `max_bytes` lets a test shrink it to provoke an audit failure.
fn replace_access_journal(fixture: &mut Fixture, max_bytes: u64) {
    let directory = fixture
        .access_directory
        .parent()
        .unwrap()
        .join("access-roomy");
    private_directory(&directory);
    let limits = JournalLimits::new(max_bytes, max_bytes / 2, 1).unwrap();
    let (journal, _) = LocalJournal::open(
        &directory,
        "control-key-r1",
        JournalKey::from_hex(JOURNAL_KEY).unwrap(),
        limits,
    )
    .unwrap();
    *fixture.control.access_journal.lock().unwrap() = journal;
    fixture.access_directory = directory;
}

impl Harness {
    pub(super) async fn new() -> Self {
        Self::build(None, 256 * 1024 * 1024).await
    }

    /// `budget` replaces the process-wide unauthenticated rate window while the
    /// authenticated window keeps its generous test limit.
    pub(super) async fn with_unauthenticated_budget(budget: u64) -> Self {
        Self::build(Some(budget), 256 * 1024 * 1024).await
    }

    /// A journal that holds only a few dozen events, to provoke audit failure.
    pub(super) async fn with_journal_capacity(max_bytes: u64) -> Self {
        Self::build(None, max_bytes).await
    }

    async fn build(budget: Option<u64>, journal_max_bytes: u64) -> Self {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
        let store = PostgresIdentityStore::connect(&url, 8, Duration::from_secs(5))
            .await
            .unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let tenant = TenantId::parse(format!("tenant_ak_{}", Uuid::now_v7().simple())).unwrap();
        let default_site = SiteId::parse(DEFAULT_SITE).unwrap();
        let mut fixture = Fixture::with_catalog(1_000_000, ManagementRole::SystemAdmin, store, 1);
        fixture.control.config.tenant_id = tenant.clone();
        fixture.control.config.site_id = default_site.clone();
        // The static machine credential is a site operator, not a key administrator.
        fixture.control.config.principal = ManagementPrincipal::new_tenant_scoped(
            "static-operator",
            [
                ManagementRole::SystemAdmin,
                ManagementRole::Observer,
                ManagementRole::PolicyAuthor,
                ManagementRole::ReleaseOperator,
            ],
            [tenant.clone()],
        )
        .unwrap()
        .with_exact_site_scope(tenant.clone(), default_site);
        fixture.control.config.api_key_hash_key = Some(zeroize::Zeroizing::new([7_u8; 32]));
        if let Some(limit) = budget {
            *fixture.control.unauthenticated_rate.lock().unwrap() =
                super::super::RateWindow::new(limit);
        }
        replace_access_journal(&mut fixture, journal_max_bytes);
        let assertion_key: [u8; 32] = **fixture.control.auth_context_key.as_ref().unwrap();
        Self {
            app: router(fixture.control),
            tenant,
            assertion_key,
            access_directory: fixture.access_directory,
            pool,
        }
    }

    /// Fresh signed browser-session assertion (30 second lifetime), tenant-wide
    /// like a real OIDC session, with CSRF already validated.
    pub(super) fn browser_header(&self, subject: &str, roles: &[&str]) -> String {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 30;
        let payload = serde_json::to_vec(&json!({
            "version": 1,
            "subject": subject,
            "tenant_id": self.tenant.as_str(),
            "site_id": DEFAULT_SITE,
            "tenant_scope": true,
            "machine": false,
            "scopes": [[self.tenant.as_str(), DEFAULT_SITE]],
            "roles": roles,
            "csrf_valid": true,
            "expires_at": expires_at,
        }))
        .unwrap();
        let signature = super::super::component_signature(
            &self.assertion_key,
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

    pub(super) async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    pub(super) async fn operator(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let (name, key) = idempotency();
        self.send(http_request(
            method,
            path,
            body,
            &[("authorization", format!("Bearer {TOKEN}")), (name, key)],
        ))
        .await
    }

    pub(super) async fn browser(
        &self,
        roles: &[&str],
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let (name, key) = idempotency();
        self.send(http_request(
            method,
            path,
            body,
            &[
                (
                    "authorization",
                    self.browser_header("human-key-admin", roles),
                ),
                (name, key),
            ],
        ))
        .await
    }

    pub(super) async fn with_key(
        &self,
        secret: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let (name, key) = idempotency();
        self.send(http_request(
            method,
            path,
            body,
            &[
                ("x-xshield-api-key", secret.to_owned()),
                ("x-xshield-agent-run-id", RUN_ID.to_owned()),
                (name, key),
            ],
        ))
        .await
    }

    pub(super) async fn create_site(&self, site: &str) {
        let (status, body) = self
            .operator(
                "PUT",
                &format!("/control/v1/sites/{site}/config"),
                Some(&site_body(site)),
            )
            .await;
        assert!(status.is_success(), "site setup failed: {status} {body}");
    }

    /// A well-formed issuance body; tests tamper with individual fields.
    pub(super) fn key_body(scopes: &Value) -> Value {
        json!({
            "subject": "agent-under-test",
            "display_name": "key under test",
            "expires_at": (Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
            "scopes": scopes,
        })
    }

    pub(super) async fn issue_as(&self, roles: &[&str], scopes: &Value) -> (StatusCode, Value) {
        self.browser(
            roles,
            "POST",
            "/control/v1/agent-api-keys",
            Some(&Self::key_body(scopes)),
        )
        .await
    }

    /// Issues a key as a fully privileged key administrator and returns its secret.
    pub(super) async fn issue(&self, scopes: &Value) -> String {
        self.issue_with_id(scopes).await.1
    }

    /// Like [`Self::issue`], returning `(api_key_id, secret)`.
    pub(super) async fn issue_with_id(&self, scopes: &Value) -> (String, String) {
        let (status, body) = self.issue_as(&ISSUER_ROLES, scopes).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        (
            body["api_key_id"].as_str().unwrap().to_owned(),
            body["api_key"].as_str().unwrap().to_owned(),
        )
    }

    pub(super) async fn rotate(&self, api_key_id: &str, body: &Value) -> (StatusCode, Value) {
        self.browser(
            &ISSUER_ROLES,
            "POST",
            &format!("/control/v1/agent-api-keys/{api_key_id}/rotate"),
            Some(body),
        )
        .await
    }

    pub(super) async fn revoke(&self, api_key_id: &str) -> (StatusCode, Value) {
        self.browser(
            &ISSUER_ROLES,
            "POST",
            &format!("/control/v1/agent-api-keys/{api_key_id}/revoke"),
            None,
        )
        .await
    }

    pub(super) async fn list_keys(&self) -> (StatusCode, Value) {
        self.browser(&ISSUER_ROLES, "GET", "/control/v1/agent-api-keys", None)
            .await
    }

    pub(super) fn scope(&self, site: &str, capabilities: &[&str]) -> Value {
        json!({"tenant_id": self.tenant.as_str(), "site_id": site, "capabilities": capabilities})
    }

    /// Audit events written so far (closed segments only, one record each).
    pub(super) fn events(&self) -> Vec<Value> {
        read_access_events(&self.access_directory)
    }

    /// `(status, last_used_at)` straight from the table, bypassing the API.
    pub(super) async fn key_row(
        &self,
        api_key_id: &str,
    ) -> Option<(String, Option<DateTime<Utc>>)> {
        sqlx::query_as::<_, (String, Option<DateTime<Utc>>)>(
            "SELECT status, last_used_at FROM xshield.management_api_keys
             WHERE tenant_id = $1 AND api_key_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(api_key_id)
        .fetch_optional(&self.pool)
        .await
        .unwrap()
    }

    pub(super) async fn key_count(&self) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM xshield.management_api_keys WHERE tenant_id = $1",
        )
        .bind(self.tenant.as_str())
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    /// Moves a key's last use into the past so the one-minute throttle can be
    /// crossed without waiting.
    pub(super) async fn age_last_use(&self, api_key_id: &str, minutes: i32) {
        sqlx::query(
            "UPDATE xshield.management_api_keys
             SET last_used_at = last_used_at - make_interval(mins => $3)
             WHERE tenant_id = $1 AND api_key_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(api_key_id)
        .bind(minutes)
        .execute(&self.pool)
        .await
        .unwrap();
    }
}
