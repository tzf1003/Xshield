//! The control plane's unauthenticated ops endpoints: they count management
//! API responses, report readiness from the database probe and real
//! access-audit failures, and never disclose tenant, site or subject.

use super::*;
use crate::routers;

async fn get(app: &axum::Router, path: &str) -> (StatusCode, String, String) {
    let response = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cache = response.headers()["cache-control"]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, cache, String::from_utf8(bytes.to_vec()).unwrap())
}

fn authenticated(path: &str) -> Request<Body> {
    Request::get(path)
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

fn assert_no_topology(body: &str) {
    for secret in ["tenant_a", "site_a", "operator", TOKEN] {
        assert!(!body.contains(secret), "{secret} leaked: {body}");
    }
}

#[tokio::test]
async fn ops_count_responses_and_report_an_unreachable_database() {
    let fixture = Fixture::new(10, ManagementRole::Observer);
    let access_directory = fixture.access_directory.clone();
    let (api, ops) = routers(fixture.control);
    let (status, cache, body) = get(&ops, "/livez").await;
    assert_eq!((status, cache.as_str()), (StatusCode::OK, "no-store"));
    assert_eq!(body, r#"{"live":true}"#);

    // Two management responses: one refused for lack of credentials, one
    // served (audit health needs no index for its answer shape).
    let refused = api
        .clone()
        .oneshot(
            Request::get("/control/v1/audit/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let served = api
        .clone()
        .oneshot(authenticated("/control/v1/audit/health"))
        .await
        .unwrap();
    let served_class = format!("{}xx", served.status().as_u16() / 100);

    // The fixture's database is unreachable on purpose.
    let (status, _, body) = get(&ops, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        r#"{"ready":false,"reason_code":"DATABASE_UNAVAILABLE"}"#
    );
    let (status, _, metrics) = get(&ops, "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(metrics.contains("xshield_control_ready 0"), "{metrics}");
    assert!(
        metrics.contains("xshield_control_not_ready{reason=\"DATABASE_UNAVAILABLE\"} 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("xshield_control_request_duration_seconds_count 2"),
        "{metrics}"
    );
    if served_class == "4xx" {
        assert!(metrics.contains("xshield_control_responses_total{class=\"4xx\"} 2"));
    } else {
        assert!(metrics.contains("xshield_control_responses_total{class=\"4xx\"} 1"));
        assert!(metrics.contains(&format!(
            "xshield_control_responses_total{{class=\"{served_class}\"}} 1"
        )));
    }
    assert_no_topology(&metrics);
    fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn a_failed_access_audit_append_makes_the_control_plane_unready() {
    let fixture = Fixture::new(1000, ManagementRole::Observer);
    let full = fixture
        .access_directory
        .parent()
        .unwrap()
        .join("access-full");
    private_directory(&full);
    let (journal, _) = LocalJournal::open(
        &full,
        "control-key-r1",
        JournalKey::from_hex(JOURNAL_KEY).unwrap(),
        JournalLimits::new(2048, 1024, 1).unwrap(),
    )
    .unwrap();
    *fixture.control.access_journal.lock().unwrap() = journal;
    let root = fixture.access_directory.parent().unwrap().to_owned();
    let (api, ops) = routers(fixture.control);
    let mut refused = false;
    for _ in 0..32 {
        let response = api
            .clone()
            .oneshot(authenticated("/control/v1/audit/health"))
            .await
            .unwrap();
        if response.status() == StatusCode::SERVICE_UNAVAILABLE {
            let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            if String::from_utf8_lossy(&bytes).contains("AUDIT_DURABILITY_FAILED") {
                refused = true;
                break;
            }
        }
    }
    assert!(refused, "the tiny journal must eventually refuse an append");
    let (status, _, body) = get(&ops, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, r#"{"ready":false,"reason_code":"AUDIT_UNAVAILABLE"}"#);
    let (_, _, metrics) = get(&ops, "/metrics").await;
    assert!(
        metrics.lines().any(|line| line
            .starts_with("xshield_control_audit_append_failures_total ")
            && line != "xshield_control_audit_append_failures_total 0"),
        "{metrics}"
    );
    assert_no_topology(&metrics);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_reachable_database_makes_the_control_plane_ready() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let fixture = Fixture::with_catalog(
        10,
        ManagementRole::Observer,
        PostgresIdentityStore::from_pool(pool),
        10,
    );
    let root = fixture.access_directory.parent().unwrap().to_owned();
    let (_, ops) = routers(fixture.control);
    let (status, _, body) = get(&ops, "/readyz").await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, r#"{"ready":true}"#)
    );
    let (_, _, metrics) = get(&ops, "/metrics").await;
    assert!(metrics.contains("xshield_control_ready 1"), "{metrics}");
    fs::remove_dir_all(root).unwrap();
}
