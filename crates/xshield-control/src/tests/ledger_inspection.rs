use super::*;
use axum::Router;
use std::sync::Arc;
use tokio::sync::Semaphore;

mod wire;

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
async fn ledger_lookup_rejects_invalid_targets_and_query_before_storage() {
    for (path, id, other, event_type, id_code, target_field) in [
        (
            "grants",
            GRANT,
            BINDING,
            "console.grant.read",
            "CONTROL_GRANT_ID_INVALID",
            "target_grant_id",
        ),
        (
            "auth-bindings",
            BINDING,
            GRANT,
            "console.binding.read",
            "CONTROL_BINDING_ID_INVALID",
            "target_binding_id",
        ),
    ] {
        let fixture = Fixture::new(20, ManagementRole::Observer);
        let app = router(fixture.control);
        for (suffix, code) in [
            ("bad".to_owned(), id_code),
            ("%FF".to_owned(), id_code),
            (id.to_uppercase(), id_code),
            (id.replace("7000", "4000"), id_code),
            (other.to_owned(), id_code),
            (format!("{id}?tenant_id=tenant_b"), "CONTROL_QUERY_INVALID"),
            (format!("{id}?cursor=foo"), "CONTROL_QUERY_INVALID"),
        ] {
            let mut request = grant_request(&suffix);
            *request.uri_mut() = format!("/control/v1/{path}/{suffix}").parse().unwrap();
            let result = response_json(
                app.clone().oneshot(request).await.unwrap(),
                StatusCode::BAD_REQUEST,
            )
            .await;
            assert_eq!(result["error_code"], code);
        }
        drop(app);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 7);
        for event in events {
            assert_eq!(event["event_type"], event_type);
            assert_eq!(
                event["payload"]["path"],
                if path == "grants" {
                    "/control/v1/grants/{grant_id}"
                } else {
                    "/control/v1/auth-bindings/{binding_id}"
                }
            );
            assert_eq!(event["evidence_refs"], json!([]));
            if event["payload"]["reason_code"] == "CONTROL_QUERY_INVALID" {
                assert_eq!(event["payload"][target_field], id);
            } else {
                assert!(event["payload"].get(target_field).is_none());
            }
        }
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn ledger_lookup_enforces_management_identity_and_shared_capacity() {
    for binding in [false, true] {
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
            let mut request = if binding {
                binding_request(BINDING)
            } else {
                grant_request(GRANT)
            };
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
                    if binding {
                        "CONTROL_BINDING_STORE_UNAVAILABLE"
                    } else {
                        "CONTROL_GRANT_STORE_UNAVAILABLE"
                    },
                ),
            };
            let result = response_json(
                router(fixture.control).oneshot(request).await.unwrap(),
                status,
            )
            .await;
            assert_eq!(result["error_code"], code);
            assert!(result.get("grant").is_none());
            assert!(result.get("binding").is_none());
            let events = read_access_events(&fixture.access_directory);
            assert_eq!(events.len(), 1);
            assert_eq!(
                events[0]["event_type"],
                if binding {
                    "console.binding.read"
                } else {
                    "console.grant.read"
                }
            );
            assert_eq!(events[0]["payload"]["reason_code"], code);
            assert_eq!(
                events[0]["payload"][if binding {
                    "target_binding_id"
                } else {
                    "target_grant_id"
                }],
                if matches!(scenario, "busy" | "store") {
                    json!(if binding { BINDING } else { GRANT })
                } else {
                    Value::Null
                }
            );
            drop(permit);
            fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
        }
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
    assert_disconnect_audit(
        &pool,
        &app,
        &capacity,
        &fixture.access_directory,
        grant_request(GRANT),
        6,
    )
    .await;
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
    assert_success_withheld_on_audit_failure(pool.clone(), grant_request(GRANT), "tenant_a").await;
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
    request: Request<Body>,
    event_count: usize,
) {
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE xshield.auth_bindings IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let client = tokio::spawn(app.clone().oneshot(request));
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
    assert_eq!(read_access_events(directory).len(), event_count);
}

async fn assert_success_withheld_on_audit_failure(
    pool: sqlx::PgPool,
    request: Request<Body>,
    tenant: &str,
) {
    let fixture = scoped_ledger_fixture(pool, tenant);
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
        router(fixture.control).oneshot(request).await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(result["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(result.get("grant").is_none());
    assert!(result.get("binding").is_none());
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

fn binding_request(suffix: &str) -> Request<Body> {
    Request::get(format!("/control/v1/auth-bindings/{suffix}"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn binding_lookup_reads_redacted_history_and_survives_disconnect() {
    const TENANT: &str = "tenant_binding_control";
    let pool = sqlx::PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    ledger_fixture::seed(&pool, TENANT, "site_a").await;
    let fixture = scoped_ledger_fixture(pool.clone(), TENANT);
    let capacity = fixture.control.search_capacity.clone();
    let app = router(fixture.control);
    let first = response_json(
        app.clone().oneshot(binding_request(BINDING)).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(first["schema_version"], 3);
    assert_eq!(first["tenant_id"], TENANT);
    assert_eq!(first["site_id"], "site_a");
    assert_eq!(first["source_binding_id"], BINDING);
    assert_eq!(first["found"], true);
    assert_eq!(first["binding"]["binding_id"], BINDING);
    assert_eq!(first["binding"]["current_auth_epoch"], 4);
    assert_eq!(first["binding"]["credential_generation"], 2);
    assert_eq!(first["binding"]["stored_status"], "active");
    assert_eq!(first["binding"]["time_expired"], false);
    for timestamp in [
        &first["as_of"],
        &first["binding"]["expires_at"],
        &first["binding"]["updated_at"],
    ] {
        assert!(DateTime::parse_from_rfc3339(timestamp.as_str().unwrap()).is_ok());
    }
    assert_eq!(first["binding"].as_object().unwrap().len(), 7);
    for excluded in [
        "principal",
        "authorization_context",
        "fingerprint",
        "waf_sid",
        "eligible",
        "payload_json",
    ] {
        assert!(!first.to_string().contains(excluded));
    }
    let missing = response_json(
        app.clone()
            .oneshot(binding_request("auth_018f2a3b-4c5d-7000-8000-00000000ffff"))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(missing["found"], false);
    assert!(missing["binding"].is_null());
    assert!(missing["as_of"].is_null());
    sqlx::query("UPDATE xshield.auth_bindings SET auth_epoch=auth_epoch+1, credential_generation=credential_generation+1, status='revoked', absolute_expires_at=now()-interval '1 second' WHERE tenant_id=$2 AND site_id='site_a' AND binding_id=$1")
        .bind(BINDING).bind(TENANT).execute(&pool).await.unwrap();
    let changed = response_json(
        app.clone().oneshot(binding_request(BINDING)).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(changed["binding"]["stored_status"], "revoked");
    assert_eq!(changed["binding"]["current_auth_epoch"], 5);
    assert_eq!(changed["binding"]["credential_generation"], 3);
    assert_eq!(changed["binding"]["time_expired"], true);
    assert_disconnect_audit(
        &pool,
        &app,
        &capacity,
        &fixture.access_directory,
        binding_request(BINDING),
        5,
    )
    .await;
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    let reads: Vec<_> = events
        .iter()
        .filter(|event| event["event_type"] == "console.binding.read")
        .collect();
    assert_eq!(reads.len(), 4);
    for event in reads {
        assert_eq!(event["payload"]["reason_code"], "CONTROL_BINDING_READ");
        assert!(event["payload"]["target_request_id"].is_null());
        assert!(event["payload"].get("target_grant_id").is_none());
        assert!(
            event["payload"]["target_binding_id"]
                .as_str()
                .unwrap()
                .starts_with("auth_")
        );
        assert_eq!(event["evidence_refs"], json!([]));
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    assert_success_withheld_on_audit_failure(pool.clone(), binding_request(BINDING), TENANT).await;
    ledger_fixture::cleanup(&pool, TENANT, "site_a").await;
    pool.close().await;
}

fn scoped_ledger_fixture(pool: sqlx::PgPool, tenant: &str) -> Fixture {
    let mut fixture = Fixture::with_catalog(
        20,
        ManagementRole::Observer,
        PostgresIdentityStore::from_pool(pool),
        1,
    );
    fixture.control.config.tenant_id = TenantId::parse(tenant).unwrap();
    fixture.control.config.principal = ManagementPrincipal::new(
        "operator-1",
        [ManagementRole::Observer],
        [(
            TenantId::parse(tenant).unwrap(),
            SiteId::parse("site_a").unwrap(),
        )],
    )
    .unwrap();
    fixture
}
