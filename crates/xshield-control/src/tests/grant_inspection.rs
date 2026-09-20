use super::*;
use axum::Router;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[path = "../../../xshield-postgres/tests/support/grant_inspection.rs"]
mod ledger_fixture;
use ledger_fixture::{BINDING, GRANT, SOURCE_REQUEST};

fn grant_request(suffix: &str) -> Request<Body> {
    Request::get(format!("/control/v1/grants/{suffix}"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn grant_lookup_rejects_invalid_targets_and_query_before_storage() {
    let fixture = Fixture::new(20, ManagementRole::Observer);
    let app = router(fixture.control);
    for (suffix, code) in [
        ("bad".to_owned(), "CONTROL_GRANT_ID_INVALID"),
        ("%FF".to_owned(), "CONTROL_GRANT_ID_INVALID"),
        (GRANT.to_uppercase(), "CONTROL_GRANT_ID_INVALID"),
        (GRANT.replace("7000", "4000"), "CONTROL_GRANT_ID_INVALID"),
        (BINDING.to_owned(), "CONTROL_GRANT_ID_INVALID"),
        (
            format!("{GRANT}?tenant_id=tenant_b"),
            "CONTROL_QUERY_INVALID",
        ),
        (format!("{GRANT}?cursor=foo"), "CONTROL_QUERY_INVALID"),
    ] {
        let result = response_json(
            app.clone().oneshot(grant_request(&suffix)).await.unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(result["error_code"], code);
    }
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 7);
    for event in events {
        assert_eq!(event["event_type"], "console.grant.read");
        assert_eq!(event["payload"]["path"], "/control/v1/grants/{grant_id}");
        assert_eq!(event["evidence_refs"], json!([]));
        if event["payload"]["reason_code"] == "CONTROL_QUERY_INVALID" {
            assert_eq!(event["payload"]["target_grant_id"], GRANT);
        } else {
            assert!(event["payload"].get("target_grant_id").is_none());
        }
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn grant_lookup_enforces_management_identity_and_shared_capacity() {
    for scenario in ["auth", "role", "scope", "expired", "rate", "busy", "store"] {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let mut fixture = Fixture::with_catalog(
            1,
            ManagementRole::Observer,
            PostgresIdentityStore::from_pool(pool),
            1,
        );
        let mut request = grant_request(GRANT);
        let mut permit = None;
        let (status, code) = match scenario {
            "auth" => {
                request.headers_mut().remove(AUTHORIZATION);
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "role" | "scope" => {
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [if scenario == "role" {
                        ManagementRole::PolicyAuthor
                    } else {
                        ManagementRole::Observer
                    }],
                    [(
                        TenantId::parse(if scenario == "scope" {
                            "other"
                        } else {
                            "tenant_a"
                        })
                        .unwrap(),
                        SiteId::parse("site_a").unwrap(),
                    )],
                )
                .unwrap();
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED")
            }
            "expired" => {
                fixture.control.config.credential.expires_at = 1;
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "rate" => {
                fixture.control.rate.lock().unwrap().used = 1;
                (StatusCode::TOO_MANY_REQUESTS, "CONTROL_RATE_LIMITED")
            }
            "busy" => {
                permit = Some(
                    fixture
                        .control
                        .search_capacity
                        .clone()
                        .acquire_owned()
                        .await
                        .unwrap(),
                );
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_QUERY_CAPACITY_EXHAUSTED",
                )
            }
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_GRANT_STORE_UNAVAILABLE",
            ),
        };
        let result = response_json(
            router(fixture.control).oneshot(request).await.unwrap(),
            status,
        )
        .await;
        assert_eq!(result["error_code"], code);
        assert!(result.get("grant").is_none());
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], "console.grant.read");
        assert_eq!(events[0]["payload"]["reason_code"], code);
        assert_eq!(
            events[0]["payload"]["target_grant_id"],
            if matches!(scenario, "busy" | "store") {
                json!(GRANT)
            } else {
                Value::Null
            }
        );
        drop(permit);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn grant_lookup_reads_redacted_history_and_survives_disconnect() {
    let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    ledger_fixture::seed(&pool, "tenant_a", "site_a").await;
    let fixture = Fixture::with_catalog(
        20,
        ManagementRole::Observer,
        PostgresIdentityStore::from_pool(pool.clone()),
        1,
    );
    let capacity = fixture.control.search_capacity.clone();
    let app = router(fixture.control);
    let first = response_json(
        app.clone().oneshot(grant_request(GRANT)).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_grant_details(&first);
    assert_eq!(first["grant"]["stored_status"], "active");
    assert_eq!(first["grant"]["time_expired"], false);
    assert_eq!(first["grant"]["binding"]["epoch_matches_grant"], true);
    let missing = response_json(
        app.clone()
            .oneshot(grant_request("grant_018f2a3b-4c5d-7000-8000-00000000ffff"))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(missing["found"], false);
    assert!(missing["grant"].is_null());
    assert!(missing["as_of"].is_null());
    sqlx::query("UPDATE xshield.auth_bindings SET auth_epoch=auth_epoch+1, status='revoked', absolute_expires_at=now()-interval '1 second' WHERE tenant_id='tenant_a' AND site_id='site_a' AND binding_id=$1")
        .bind(BINDING).execute(&pool).await.unwrap();
    let changed = response_json(
        app.clone().oneshot(grant_request(GRANT)).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(changed["grant"]["binding"]["stored_status"], "revoked");
    assert_eq!(changed["grant"]["binding"]["time_expired"], true);
    assert_eq!(changed["grant"]["binding"]["epoch_matches_grant"], false);
    assert_eq!(changed["grant"]["stored_status"], "active");
    assert_expired_grant_history(&pool, &app).await;
    assert_disconnect_audit(&pool, &app, &capacity, &fixture.access_directory).await;
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 6);
    assert!(
        events
            .iter()
            .all(|event| event["event_type"] == "console.grant.read")
    );
    assert!(
        events
            .iter()
            .all(|event| event["payload"]["target_request_id"].is_null())
    );
    assert!(
        events
            .iter()
            .all(|event| event["evidence_refs"] == json!([]))
    );
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    assert_success_withheld_on_audit_failure(pool.clone()).await;
    ledger_fixture::cleanup(&pool, "tenant_a", "site_a").await;
    pool.close().await;
}

fn assert_grant_details(result: &Value) {
    assert_eq!(result["found"], true);
    assert_eq!(result["source_grant_id"], GRANT);
    assert_eq!(result["grant"]["binding"]["binding_id"], BINDING);
    assert_eq!(result["grant"]["source_request_id"], SOURCE_REQUEST);
    assert!(DateTime::parse_from_rfc3339(result["as_of"].as_str().unwrap()).is_ok());
    let text = result.to_string();
    for excluded in [
        "principal_ref",
        "authorization_context",
        "fingerprint",
        "resource_key_hmac",
        "issuance_key",
        "action_ref",
        "constraints",
        "eligible",
        "payload_json",
    ] {
        assert!(!text.contains(excluded));
    }
}

async fn assert_expired_grant_history(pool: &sqlx::PgPool, app: &Router) {
    sqlx::query("UPDATE xshield.resource_grants SET status='revoked', expires_at=now()-interval '1 second' WHERE tenant_id='tenant_a' AND site_id='site_a' AND grant_id=$1")
        .bind(GRANT).execute(pool).await.unwrap();
    let expired = response_json(
        app.clone().oneshot(grant_request(GRANT)).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_grant_details(&expired);
    assert_eq!(expired["grant"]["stored_status"], "revoked");
    assert_eq!(expired["grant"]["time_expired"], true);
}

async fn assert_disconnect_audit(
    pool: &sqlx::PgPool,
    app: &Router,
    capacity: &Arc<Semaphore>,
    directory: &Path,
) {
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE xshield.resource_grants IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let client = tokio::spawn(app.clone().oneshot(grant_request(GRANT)));
    tokio::time::timeout(Duration::from_secs(2), async {
        while capacity.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
    let busy = response_json(
        app.clone().oneshot(grant_request(GRANT)).await.unwrap(),
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;
    assert_eq!(busy["error_code"], "CONTROL_QUERY_CAPACITY_EXHAUSTED");
    lock.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(6), async {
        while capacity.available_permits() != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(read_access_events(directory).len(), 6);
}

async fn assert_success_withheld_on_audit_failure(pool: sqlx::PgPool) {
    let fixture = Fixture::with_catalog(
        10,
        ManagementRole::Observer,
        PostgresIdentityStore::from_pool(pool),
        1,
    );
    std::thread::scope(|scope| {
        let journal = &fixture.control.access_journal;
        assert!(
            scope
                .spawn(move || {
                    let _guard = journal.lock().unwrap();
                    panic!("simulate audit failure");
                })
                .join()
                .is_err()
        );
    });
    let result = response_json(
        router(fixture.control)
            .oneshot(grant_request(GRANT))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(result["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(result.get("grant").is_none());
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}
