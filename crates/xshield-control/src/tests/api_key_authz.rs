//! HTTP-level contract for management API-key authorization: every decision is
//! made per (site, capability) pair from the scope row that names the site, and
//! a key never inherits a role, an investigation route or key administration.
//! It also covers the unauthenticated budget that keeps junk keys away from the
//! key table and the audit journal.
//!
//! Tests that look keys up need `PostgreSQL` (they are ignored without
//! `XSHIELD_TEST_DATABASE_URL`); the flood test runs against an unreachable
//! database on purpose, because it must not depend on lookups succeeding.

use super::api_key_harness::{
    DEFAULT_SITE, Harness, ISSUER_ROLES, TENANT_WIDE, is_scope_denied, junk_key_request, site_body,
};
use super::*;

struct Route {
    method: &'static str,
    path: &'static str,
    body: bool,
}

const fn route(method: &'static str, path: &'static str, body: bool) -> Route {
    Route { method, path, body }
}

/// Every site-management route a key could reach, with `{site}` substituted.
const SITE_ROUTES: &[Route] = &[
    route("GET", "/control/v1/sites", false),
    route("GET", "/control/v1/sites/{site}", false),
    route("GET", "/control/v1/sites/{site}/config", false),
    route("GET", "/control/v1/sites/{site}/status", false),
    route("GET", "/control/v1/sites/{site}/revisions", false),
    route("GET", "/control/v1/sites/{site}/health", false),
    route("PUT", "/control/v1/sites/{site}/config", true),
    route("PATCH", "/control/v1/sites/{site}", true),
    route("POST", "/control/v1/sites/{site}/validate", false),
    route("POST", "/control/v1/sites/{site}/apply", false),
    route("POST", "/control/v1/sites/{site}/approve", false),
    route("POST", "/control/v1/sites/{site}/rollback", false),
    route("DELETE", "/control/v1/sites/{site}", false),
];

fn grants_route(capability: &str, route: &Route) -> bool {
    matches!(
        (capability, route.method, route.path),
        (
            "site.read",
            "GET",
            "/control/v1/sites"
                | "/control/v1/sites/{site}"
                | "/control/v1/sites/{site}/config"
                | "/control/v1/sites/{site}/status"
                | "/control/v1/sites/{site}/revisions"
        ) | ("site.health.read", "GET", "/control/v1/sites/{site}/health")
            | (
                "site.config.write",
                "PUT",
                "/control/v1/sites/{site}/config"
            )
            | ("site.config.write", "PATCH", "/control/v1/sites/{site}")
            | (
                "site.config.validate",
                "POST",
                "/control/v1/sites/{site}/validate"
            )
            | (
                "site.config.apply_direct",
                "POST",
                "/control/v1/sites/{site}/apply"
            )
            | ("site.rollback", "POST", "/control/v1/sites/{site}/rollback")
    )
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn each_capability_reaches_exactly_its_routes_on_exactly_its_site() {
    let harness = Harness::new().await;
    harness.create_site("site_a").await;
    harness.create_site("site_b").await;
    let mut failures = Vec::new();
    for capability in [
        "site.read",
        "site.health.read",
        "site.config.write",
        "site.config.validate",
        "site.config.apply_direct",
        "site.rollback",
    ] {
        let secret = harness
            .issue(&json!([harness.scope("site_a", &[capability])]))
            .await;
        for site in ["site_a", "site_b"] {
            // DELETE is last in SITE_ROUTES and must never be granted, so the
            // sites survive the whole matrix.
            for route in SITE_ROUTES {
                let path = route.path.replace("{site}", site);
                let body = route.body.then(|| site_body(site));
                let (status, response) = harness
                    .with_key(&secret, route.method, &path, body.as_ref())
                    .await;
                let expected_allowed = should_pass(capability, route, site);
                let denied = is_scope_denied(status, &response);
                if expected_allowed == denied {
                    failures.push(format!(
                        "{capability} {} {path}: expected {}, got {status} {}",
                        route.method,
                        if expected_allowed {
                            "allowed"
                        } else {
                            "403 CONTROL_SCOPE_DENIED"
                        },
                        response["error_code"]
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "authorization matrix violations:\n{}",
        failures.join("\n")
    );
}

/// Whether the capability, granted on `site_a` only, lets the call through.
/// The list route has no site in its path; it is filtered by visibility instead.
fn should_pass(capability: &str, route: &Route, site: &str) -> bool {
    let site_independent = route.path == "/control/v1/sites";
    grants_route(capability, route) && (site == "site_a" || site_independent)
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn scopes_are_never_unioned_across_sites_or_crossed_with_roles() {
    let harness = Harness::new().await;
    harness.create_site("site_a").await;
    harness.create_site("site_b").await;
    // Reviewer reproduction: write on site_a, read on site_b.
    let secret = harness
        .issue(&json!([
            harness.scope("site_a", &["site.config.write"]),
            harness.scope("site_b", &["site.read"]),
        ]))
        .await;
    let put = |site: &'static str| {
        let secret = secret.clone();
        let harness = &harness;
        async move {
            harness
                .with_key(
                    &secret,
                    "PUT",
                    &format!("/control/v1/sites/{site}/config"),
                    Some(&site_body(site)),
                )
                .await
        }
    };
    let (status, body) = put("site_b").await;
    assert!(
        is_scope_denied(status, &body),
        "write on site_b must be denied: {status} {body}"
    );
    let (status, body) = put("site_a").await;
    assert!(
        status.is_success(),
        "write on site_a must work: {status} {body}"
    );
    let (status, body) = harness
        .with_key(&secret, "GET", "/control/v1/sites/site_b/status", None)
        .await;
    assert!(
        status.is_success(),
        "read on site_b must work: {status} {body}"
    );
    let (status, body) = harness
        .with_key(&secret, "GET", "/control/v1/sites/site_a/status", None)
        .await;
    assert!(
        is_scope_denied(status, &body),
        "write on site_a does not imply read on site_a: {status} {body}"
    );
    // A write-only key reached DELETE (authorized, then 404) before the fix.
    let (status, body) = harness
        .with_key(&secret, "DELETE", "/control/v1/sites/site_a", None)
        .await;
    assert!(
        is_scope_denied(status, &body),
        "DELETE must never be granted: {status} {body}"
    );
    let (status, _) = harness
        .operator("GET", "/control/v1/sites/site_a/status", None)
        .await;
    assert_eq!(status, StatusCode::OK, "site_a must still exist");
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn site_create_needs_the_tenant_wide_marker_and_cannot_overwrite() {
    let harness = Harness::new().await;
    harness.create_site("site_existing").await;
    // A concrete site id with site.create used to silently become tenant-wide.
    let (status, body) = harness
        .issue_as(
            &ISSUER_ROLES,
            &json!([harness.scope("site_z", &["site.create"])]),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error_code"], "CONTROL_API_KEY_SCOPE_INVALID");
    // The marker is only meaningful for site.create.
    let (status, body) = harness
        .issue_as(
            &ISSUER_ROLES,
            &json!([harness.scope(TENANT_WIDE, &["site.read"])]),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error_code"], "CONTROL_API_KEY_SCOPE_INVALID");

    let secret = harness
        .issue(&json!([harness.scope(TENANT_WIDE, &["site.create"])]))
        .await;
    let (status, body) = harness
        .with_key(
            &secret,
            "POST",
            "/control/v1/sites",
            Some(&site_body("site_fresh")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    // Creating is not writing: existing sites cannot be overwritten through
    // POST, nor read, nor configured.
    let (status, body) = harness
        .with_key(
            &secret,
            "POST",
            "/control/v1/sites",
            Some(&site_body("site_existing")),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error_code"], "CONTROL_API_KEY_SITE_EXISTS");
    for (method, path) in [
        ("PUT", "/control/v1/sites/site_existing/config"),
        ("PUT", "/control/v1/sites/site_fresh/config"),
        ("GET", "/control/v1/sites/site_fresh/status"),
        ("GET", "/control/v1/sites"),
    ] {
        let body = (method == "PUT").then(|| site_body(path.split('/').nth(4).unwrap()));
        let (status, response) = harness.with_key(&secret, method, path, body.as_ref()).await;
        assert!(
            is_scope_denied(status, &response),
            "{method} {path}: {status} {response}"
        );
    }
    // site.config.write does not create sites either.
    let writer = harness
        .issue(&json!([
            harness.scope("site_unborn", &["site.config.write"])
        ]))
        .await;
    let (status, body) = harness
        .with_key(
            &writer,
            "PUT",
            "/control/v1/sites/site_unborn/config",
            Some(&site_body("site_unborn")),
        )
        .await;
    assert!(
        is_scope_denied(status, &body),
        "PUT must not create: {status} {body}"
    );
    let (status, _) = harness
        .with_key(
            &writer,
            "POST",
            "/control/v1/sites",
            Some(&site_body("site_unborn")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn keys_reach_no_investigation_and_no_key_administration_route() {
    let harness = Harness::new().await;
    harness.create_site(DEFAULT_SITE).await;
    harness.create_site("site_a").await;
    // The most capable key a KeyAdministrator can mint: every capability on
    // two sites plus tenant-wide creation.
    let all = [
        "site.read",
        "site.health.read",
        "site.config.write",
        "site.config.validate",
        "site.config.apply_direct",
        "site.rollback",
    ];
    let secret = harness
        .issue(&json!([
            harness.scope(DEFAULT_SITE, &all),
            harness.scope("site_a", &all),
            harness.scope(TENANT_WIDE, &["site.create"]),
        ]))
        .await;
    let request = format!("req_{}", Uuid::now_v7());
    let model = format!("mdl_{}", Uuid::now_v7());
    let agent = format!("agt_{}", Uuid::now_v7());
    let job = format!("job_{}", Uuid::now_v7());
    let export = format!("export_{}", Uuid::now_v7());
    let report = format!("calr_{}", Uuid::now_v7());
    let grant = format!("grant_{}", Uuid::now_v7());
    let binding = format!("auth_{}", Uuid::now_v7());
    let artifact = format!("artifact_{}", Uuid::now_v7());
    let access = format!("access_{}", Uuid::now_v7());
    let case = format!("case_{}", Uuid::now_v7());
    let hold = format!("ev_{}", Uuid::now_v7());
    let key = format!("key_{}", Uuid::now_v7());
    let routes: Vec<(&str, String)> = vec![
        ("GET", "/control/v1/audit/health".into()),
        ("GET", format!("/control/v1/requests/{request}")),
        ("GET", format!("/control/v1/requests/{request}/events")),
        ("GET", format!("/control/v1/requests/{request}/evidence")),
        ("GET", "/control/v1/model-calls".into()),
        ("GET", format!("/control/v1/model-calls/{model}")),
        ("GET", format!("/control/v1/agent-runs/{agent}")),
        ("GET", format!("/control/v1/jobs/{job}")),
        ("GET", format!("/control/v1/exports/{export}")),
        ("GET", format!("/control/v1/exports/{export}/download")),
        ("GET", format!("/control/v1/calibration-reports/{report}")),
        ("GET", format!("/control/v1/grants/{grant}")),
        ("GET", format!("/control/v1/auth-bindings/{binding}")),
        ("GET", format!("/control/v1/artifacts/{artifact}")),
        ("GET", format!("/control/v1/artifacts/{artifact}/content")),
        ("GET", "/control/v1/evidence-access-requests".into()),
        (
            "GET",
            format!("/control/v1/evidence-access-requests/{access}"),
        ),
        ("GET", "/control/v1/cases".into()),
        ("GET", format!("/control/v1/cases/{case}/items")),
        ("GET", format!("/control/v1/cases/{case}/holds")),
        ("GET", "/control/v1/session".into()),
        ("GET", "/control/v1/agent-api-keys".into()),
        ("POST", "/control/v1/search".into()),
        ("POST", "/control/v1/causality".into()),
        ("POST", "/control/v1/cases".into()),
        ("POST", "/control/v1/exports".into()),
        ("POST", format!("/control/v1/exports/{export}/approve")),
        ("POST", format!("/control/v1/exports/{export}/deny")),
        ("POST", format!("/control/v1/artifacts/{artifact}/access")),
        (
            "POST",
            format!("/control/v1/evidence-access-requests/{access}/approve"),
        ),
        (
            "POST",
            format!("/control/v1/evidence-access-requests/{access}/deny"),
        ),
        ("POST", format!("/control/v1/cases/{case}/analyze")),
        ("POST", format!("/control/v1/cases/{case}/items")),
        ("POST", format!("/control/v1/cases/{case}/close")),
        ("POST", format!("/control/v1/cases/{case}/holds")),
        ("POST", format!("/control/v1/evidence-holds/{hold}/release")),
        ("POST", "/control/v1/session/logout".into()),
        ("POST", "/control/v1/auth/oidc/reauth/start".into()),
        ("POST", "/control/v1/agent-api-keys".into()),
        ("POST", format!("/control/v1/agent-api-keys/{key}/revoke")),
        ("POST", format!("/control/v1/agent-api-keys/{key}/rotate")),
    ];
    let mut leaks = Vec::new();
    for (method, path) in &routes {
        let body = (*method == "POST").then(|| json!({}));
        let (status, response) = harness.with_key(&secret, method, path, body.as_ref()).await;
        // GET handlers authorize before parsing anything; POST handlers may
        // reject an empty body first, but never with a success status.
        let acceptable = if *method == "GET" {
            is_scope_denied(status, &response) || status == StatusCode::UNAUTHORIZED
        } else {
            status.is_client_error()
        };
        if !acceptable {
            leaks.push(format!(
                "{method} {path}: {status} {}",
                response["error_code"]
            ));
        }
    }
    assert!(
        leaks.is_empty(),
        "key reached non-site routes:\n{}",
        leaks.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn only_browser_sessions_administer_keys_and_never_beyond_their_own_authority() {
    let harness = Harness::new().await;
    let scopes = json!([harness.scope("site_a", &["site.read"])]);
    let body = json!({
        "subject": "agent-admin-check",
        "display_name": "admin check",
        "expires_at": (Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
        "scopes": scopes,
    });
    // The static machine credential holds SystemAdmin but is not a browser
    // session; docs/15 allows key administration only to browser sessions.
    let (status, response) = harness
        .operator("POST", "/control/v1/agent-api-keys", Some(&body))
        .await;
    assert!(is_scope_denied(status, &response), "{status} {response}");
    let (status, response) = harness
        .operator("GET", "/control/v1/agent-api-keys", None)
        .await;
    assert!(is_scope_denied(status, &response), "{status} {response}");
    // Roles unrelated to key administration cannot administer either.
    let (status, response) = harness
        .browser(
            &["observer", "policy_author"],
            "POST",
            "/control/v1/agent-api-keys",
            Some(&body),
        )
        .await;
    assert!(is_scope_denied(status, &response), "{status} {response}");
    // Both KeyAdministrator and SystemAdmin sessions may (docs/15 end of chapter),
    // provided they could exercise what they grant.
    let (status, response) = harness
        .browser(
            &["system_admin", "observer"],
            "POST",
            "/control/v1/agent-api-keys",
            Some(&body),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    // An issuer holding only KeyAdministrator can exercise nothing, so it can grant nothing.
    let (status, response) = harness.issue_as(&["key_administrator"], &scopes).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{response}");
    assert_eq!(response["error_code"], "CONTROL_API_KEY_SCOPE_FORBIDDEN");
    // Granting apply_direct needs release authority; SystemAdmin alone is not enough.
    for (roles, capability, expected) in [
        (
            vec!["system_admin", "key_administrator"],
            "site.config.apply_direct",
            false,
        ),
        (
            vec!["system_admin", "key_administrator"],
            "site.rollback",
            false,
        ),
        (
            vec!["system_admin", "key_administrator"],
            "site.config.validate",
            false,
        ),
        (
            vec!["system_admin", "key_administrator"],
            "site.config.write",
            true,
        ),
        (
            vec!["observer", "key_administrator"],
            "site.config.write",
            false,
        ),
        (
            vec!["observer", "key_administrator"],
            "site.health.read",
            true,
        ),
        (
            vec!["release_operator", "policy_approver", "key_administrator"],
            "site.config.apply_direct",
            true,
        ),
        (
            vec!["release_operator", "key_administrator"],
            "site.config.apply_direct",
            false,
        ),
        (
            vec!["release_operator", "key_administrator"],
            "site.rollback",
            true,
        ),
        (
            vec!["policy_author", "key_administrator"],
            "site.config.validate",
            true,
        ),
    ] {
        let (status, response) = harness
            .issue_as(&roles, &json!([harness.scope("site_a", &[capability])]))
            .await;
        assert_eq!(
            status.is_success(),
            expected,
            "{roles:?} granting {capability}: {status} {response}"
        );
        if !expected {
            assert_eq!(response["error_code"], "CONTROL_API_KEY_SCOPE_FORBIDDEN");
        }
    }
    // A key can never mint, list, revoke or rotate keys, whatever it holds.
    let secret = harness
        .issue(&json!([
            harness.scope(DEFAULT_SITE, &["site.config.write", "site.read"])
        ]))
        .await;
    for (method, path, payload) in [
        ("POST", "/control/v1/agent-api-keys".to_owned(), Some(&body)),
        ("GET", "/control/v1/agent-api-keys".to_owned(), None),
    ] {
        let (status, response) = harness.with_key(&secret, method, &path, payload).await;
        assert!(
            is_scope_denied(status, &response),
            "{method} {path}: {status} {response}"
        );
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn workbench_and_site_list_project_only_the_sites_a_key_may_read() {
    let harness = Harness::new().await;
    for site in [DEFAULT_SITE, "site_alpha", "site_beta"] {
        harness.create_site(site).await;
    }
    let reader = harness
        .issue(&json!([harness.scope("site_alpha", &["site.read"])]))
        .await;
    let writer_only = harness
        .issue(&json!(
            [harness.scope("site_alpha", &["site.config.write"])]
        ))
        .await;
    let site_ids = |body: &Value| -> Vec<String> {
        body["sites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|site| site["site_id"].as_str().unwrap().to_owned())
            .collect()
    };
    let (status, body) = harness
        .with_key(&reader, "GET", "/control/v1/workbench/overview", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        site_ids(&body),
        ["site_alpha"],
        "workbench must not list other sites"
    );
    let (status, body) = harness
        .with_key(&reader, "GET", "/control/v1/sites", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(site_ids(&body), ["site_alpha"]);
    // Writing a site is not reading it: no site.read, no workbench, no listing.
    for path in ["/control/v1/workbench/overview", "/control/v1/sites"] {
        let (status, body) = harness.with_key(&writer_only, "GET", path, None).await;
        assert!(is_scope_denied(status, &body), "{path}: {status} {body}");
    }
    // A browser SystemAdmin session stays tenant-wide.
    let (status, body) = harness
        .browser(
            &["system_admin"],
            "GET",
            "/control/v1/workbench/overview",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        site_ids(&body).len(),
        3,
        "browser SystemAdmin keeps the whole tenant"
    );
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn direct_apply_is_scoped_to_one_site_and_audited_with_key_id_and_subject() {
    let harness = Harness::new().await;
    harness.create_site("site_a").await;
    harness.create_site("site_b").await;
    let (status, issued) = harness
        .issue_as(
            &ISSUER_ROLES,
            &json!([harness.scope("site_a", &["site.config.apply_direct"])]),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let secret = issued["api_key"].as_str().unwrap().to_owned();
    let key_id = issued["api_key_id"].as_str().unwrap().to_owned();
    let (status, body) = harness
        .with_key(&secret, "POST", "/control/v1/sites/site_b/apply", None)
        .await;
    assert!(
        is_scope_denied(status, &body),
        "apply on another site: {status} {body}"
    );
    let (status, body) = harness
        .with_key(&secret, "POST", "/control/v1/sites/site_a/apply", None)
        .await;
    assert!(
        status.is_success(),
        "apply on the scoped site: {status} {body}"
    );
    let events = read_access_events(&harness.access_directory);
    let applied: Vec<&Value> = events
        .iter()
        .filter(|event| event["event_type"] == "console.site.config.apply")
        .collect();
    assert!(!applied.is_empty(), "the apply attempt must be audited");
    for event in applied {
        let subject = event["payload"]["subject_ref"].as_str().unwrap();
        assert!(
            subject.contains(&key_id),
            "audit subject must name the key id: {subject}"
        );
        assert!(
            subject.contains("agent-under-test"),
            "and the key subject: {subject}"
        );
    }
    let everything = serde_json::to_string(&events).unwrap();
    assert!(
        !everything.contains(&secret),
        "the secret must never reach the audit journal"
    );
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn legacy_single_site_routes_follow_the_default_site_scope_only() {
    let harness = Harness::new().await;
    harness.create_site(DEFAULT_SITE).await;
    harness.create_site("site_a").await;
    let capabilities = ["site.read", "site.config.write"];
    let on_default = harness
        .issue(&json!([harness.scope(DEFAULT_SITE, &capabilities)]))
        .await;
    let on_other = harness
        .issue(&json!([harness.scope("site_a", &capabilities)]))
        .await;
    let path = "/control/v1/site-config";
    let (status, body) = harness.with_key(&on_default, "GET", path, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = harness
        .with_key(&on_default, "PUT", path, Some(&site_body(DEFAULT_SITE)))
        .await;
    assert!(status.is_success(), "{status} {body}");
    // The legacy routes address the control's default site; a key scoped to
    // another site must not reach it through them.
    let (status, body) = harness.with_key(&on_other, "GET", path, None).await;
    assert!(is_scope_denied(status, &body), "{status} {body}");
    let (status, body) = harness
        .with_key(&on_other, "PUT", path, Some(&site_body(DEFAULT_SITE)))
        .await;
    assert!(is_scope_denied(status, &body), "{status} {body}");
}

/// Reviewer reproduction: 3000 junk keys wrote 450 durable audit events into
/// the 1 MiB test journal, after which every request, including a legitimate
/// bearer call, failed with 503 `AUDIT_DURABILITY_FAILED`. The database is
/// unreachable on purpose: metering must not depend on lookups succeeding.
#[tokio::test]
async fn junk_api_keys_cannot_exhaust_the_audit_journal_or_block_valid_credentials() {
    const BUDGET: u64 = 40;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(10))
        .connect_lazy("postgresql://xshield:xshield@127.0.0.1:1/xshield")
        .unwrap();
    let mut fixture = Fixture::with_catalog(
        BUDGET,
        ManagementRole::AuditAdministrator,
        PostgresIdentityStore::from_pool(pool),
        1,
    );
    fixture.control.config.api_key_hash_key = Some(zeroize::Zeroizing::new([7_u8; 32]));
    let access_directory = fixture.access_directory.clone();
    let app = router(fixture.control);
    let mut statuses = std::collections::BTreeMap::<u16, u32>::new();
    for index in 0..3000 {
        let (status, body) = junk_key_request(&app, index).await;
        *statuses.entry(status.as_u16()).or_default() += 1;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(body["error_code"], "CONTROL_RATE_LIMITED");
            assert_eq!(body["retryable"], true);
        }
    }
    assert_eq!(
        statuses.get(&429).copied(),
        Some(3000 - u32::try_from(BUDGET).unwrap()),
        "everything beyond the budget is a 429: {statuses:?}"
    );
    // A legitimate management credential still works: the journal is not full.
    let response = app.clone().oneshot(authenticated_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    drop(app);
    let events = read_access_events(&access_directory);
    let key_events = events
        .iter()
        .filter(|event| event["event_type"] == "console.agent_api_key.use")
        .count();
    assert_eq!(
        key_events,
        usize::try_from(BUDGET).unwrap(),
        "one audited event per allowed attempt, none once the budget is spent"
    );
    assert_eq!(
        events.len(),
        key_events + 1,
        "junk keys write nothing besides their own attempt events"
    );
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn junk_attempts_leave_exactly_one_event_and_valid_keys_get_their_unit_back() {
    const BUDGET: u64 = 5;
    let harness = Harness::with_unauthenticated_budget(BUDGET).await;
    harness.create_site("site_a").await;
    let secret = harness
        .issue(&json!([harness.scope("site_a", &["site.read"])]))
        .await;
    // Far more valid requests than the budget: each takes a unit and, once the
    // key proves valid, returns it, so honest traffic never drains the budget.
    for _ in 0..20 {
        let (status, body) = harness
            .with_key(&secret, "GET", "/control/v1/sites/site_a/status", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let before = read_access_events(&harness.access_directory).len();
    let mut statuses = Vec::new();
    for index in 0..12 {
        let (status, body) = junk_key_request(&harness.app, index).await;
        statuses.push((
            status.as_u16(),
            body["error_code"].as_str().unwrap_or("").to_owned(),
        ));
    }
    let allowed = usize::try_from(BUDGET).unwrap();
    for (index, (status, code)) in statuses.iter().enumerate() {
        if index < allowed {
            assert_eq!(
                (*status, code.as_str()),
                (401, "CONTROL_API_KEY_INVALID"),
                "{index}"
            );
        } else {
            assert_eq!(
                (*status, code.as_str()),
                (429, "CONTROL_RATE_LIMITED"),
                "{index}"
            );
        }
    }
    let after = read_access_events(&harness.access_directory);
    let added = &after[before..];
    assert_eq!(
        added.len(),
        allowed,
        "exactly one audited event per allowed junk attempt, none for throttled ones"
    );
    for event in added {
        assert_eq!(event["event_type"], "console.agent_api_key.use");
        assert_eq!(event["payload"]["reason_code"], "CONTROL_API_KEY_INVALID");
        assert_eq!(event["payload"]["outcome"], "DENY");
    }
    // While the junk budget is spent even a valid key is throttled, with a
    // retryable 429 rather than a failure of the audit journal.
    let (status, body) = harness
        .with_key(&secret, "GET", "/control/v1/sites/site_a/status", None)
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["retryable"], true);
    // Other credentials are unaffected by the key flood.
    let (status, body) = harness
        .operator("GET", "/control/v1/sites/site_a/status", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
