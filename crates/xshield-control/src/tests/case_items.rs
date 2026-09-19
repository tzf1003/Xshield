use super::*;

const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000951";
const KEY: &str = "case-evidence-key-0001";

fn item_request(case: &str, key: &str, body: String) -> Request<Body> {
    Request::post(format!("/control/v1/cases/{case}/items"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(body))
        .unwrap()
}

fn item_body(artifact: &str) -> String {
    json!({"artifact_id": artifact}).to_string()
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn case_evidence_validates_before_storage_and_audits_denials() {
    let fixture = Fixture::new(100, ManagementRole::Investigator);
    let app = router(fixture.control);
    for (case, key, body, expected) in [
        (
            "bad",
            KEY,
            item_body(MISSING_ARTIFACT_ID),
            "CONTROL_CASE_ID_INVALID",
        ),
        (
            "%FF",
            KEY,
            item_body(MISSING_ARTIFACT_ID),
            "CONTROL_CASE_ID_INVALID",
        ),
        (CASE, KEY, item_body("bad"), "CONTROL_ARTIFACT_ID_INVALID"),
        (
            CASE,
            KEY,
            "{}".into(),
            "CONTROL_CASE_EVIDENCE_REQUEST_INVALID",
        ),
        (
            CASE,
            KEY,
            format!(r#"{{"artifact_id":"{MISSING_ARTIFACT_ID}","tenant_id":"other"}}"#),
            "CONTROL_CASE_EVIDENCE_REQUEST_INVALID",
        ),
        (
            CASE,
            KEY,
            format!(
                r#"{{"artifact_id":"{MISSING_ARTIFACT_ID}","artifact_id":"{MISSING_ARTIFACT_ID}"}}"#
            ),
            "CONTROL_CASE_EVIDENCE_REQUEST_INVALID",
        ),
        (
            CASE,
            KEY,
            item_body(&"a".repeat(4096)),
            "CONTROL_CASE_EVIDENCE_REQUEST_INVALID",
        ),
        (
            CASE,
            "short",
            item_body(MISSING_ARTIFACT_ID),
            "CONTROL_IDEMPOTENCY_KEY_INVALID",
        ),
    ] {
        let result = response_json(
            app.clone()
                .oneshot(item_request(case, key, body))
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(result["error_code"], expected);
    }
    let mut duplicate = item_request(CASE, KEY, item_body(MISSING_ARTIFACT_ID));
    duplicate
        .headers_mut()
        .append("idempotency-key", "different-key-0001".parse().unwrap());
    let result = response_json(
        app.clone().oneshot(duplicate).await.unwrap(),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(result["error_code"], "CONTROL_IDEMPOTENCY_KEY_INVALID");
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 9);
    for event in events {
        assert_eq!(event["event_type"], "case.evidence.added");
        assert_eq!(event["payload"]["path"], crate::case_items::PATH);
        assert_eq!(event["payload"]["outcome"], "DENY");
        assert_eq!(event["evidence_refs"], json!([]));
        assert!(!event.to_string().contains(KEY));
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn case_evidence_enforces_authentication_scope_role_and_rate() {
    for scenario in ["missing_auth", "role", "scope", "expired", "rate"] {
        let mut fixture = Fixture::new(1, ManagementRole::Investigator);
        let mut request = item_request(CASE, "short", item_body(MISSING_ARTIFACT_ID));
        let (expected, code) = match scenario {
            "missing_auth" => {
                request.headers_mut().remove(AUTHORIZATION);
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "role" => {
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [ManagementRole::Observer],
                    [(
                        TenantId::parse("tenant_a").unwrap(),
                        SiteId::parse("site_a").unwrap(),
                    )],
                )
                .unwrap();
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED")
            }
            "scope" => {
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [ManagementRole::Investigator],
                    [(
                        TenantId::parse("other").unwrap(),
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
            _ => {
                fixture.control.rate.lock().unwrap().used = 1;
                (StatusCode::TOO_MANY_REQUESTS, "CONTROL_RATE_LIMITED")
            }
        };
        let result = response_json(
            router(fixture.control).oneshot(request).await.unwrap(),
            expected,
        )
        .await;
        assert_eq!(result["error_code"], code);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["payload"]["target_case_id"], Value::Null);
        assert_eq!(events[0]["payload"]["reason_code"], code);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn case_evidence_bounds_inflight_work_and_reports_store_failure() {
    for busy in [true, false] {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let fixture = Fixture::with_case_catalog(PostgresIdentityStore::from_pool(pool), 1);
        let permit = if busy {
            Some(
                fixture
                    .control
                    .case_evidence_capacity
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let result = response_json(
            router(fixture.control)
                .oneshot(item_request(CASE, KEY, item_body(MISSING_ARTIFACT_ID)))
                .await
                .unwrap(),
            if busy {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
        )
        .await;
        let code = if busy {
            "CONTROL_CASE_EVIDENCE_BUSY"
        } else {
            "CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE"
        };
        assert_eq!(result["error_code"], code);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["payload"]["reason_code"], code);
        assert_eq!(events[0]["payload"]["target_case_id"], CASE);
        assert_eq!(
            events[0]["payload"]["target_artifact_id"],
            MISSING_ARTIFACT_ID
        );
        assert_eq!(events[0]["evidence_refs"], json!([]));
        drop(permit);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn case_evidence_is_durable_idempotent_and_disconnect_safe() {
    let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let catalog = PostgresIdentityStore::from_pool(pool.clone());
    let tenant = TenantId::parse("tenant_a").unwrap();
    let site = SiteId::parse("site_a").unwrap();
    let fixture = Fixture::with_catalog(100, ManagementRole::Investigator, catalog.clone(), 1);
    let capacity = fixture.control.case_evidence_capacity.clone();
    let vault_root = fixture.access_directory.parent().unwrap().join("evidence");
    private_directory(&vault_root);
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&vault_root, "evidence-key-case-items", 1024, 30).unwrap(),
        EvidenceKey::from_hex("5555555555555555555555555555555555555555555555555555555555555555")
            .unwrap(),
    )
    .unwrap();
    let source = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
    let first = publish_test_artifact(&catalog, &vault, &tenant, &site, &source, 1).await;
    let second = publish_test_artifact(&catalog, &vault, &tenant, &site, &source, 2).await;
    let third = publish_test_artifact(&catalog, &vault, &tenant, &site, &source, 3).await;
    let app = router(fixture.control);
    let case = response_json(
        app.clone()
            .oneshot(case_request(
                "case-items-create-0001",
                r#"{"purpose":"Investigate evidence association"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::CREATED,
    )
    .await;
    let case_id = case["case_id"].as_str().unwrap();
    let original_expiry: DateTime<Utc> = sqlx::query_scalar("SELECT expires_at FROM xshield.artifact_catalog WHERE tenant_id='tenant_a' AND site_id='site_a' AND artifact_id=$1").bind(&first).fetch_one(&pool).await.unwrap();
    let added = response_json(
        app.clone()
            .oneshot(item_request(case_id, KEY, item_body(&first)))
            .await
            .unwrap(),
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(added["replayed"], false);
    assert_eq!(added["artifact_id"], first);
    assert_eq!(added["added_by"], "operator-1");
    assert_eq!(added["schema_version"], 3);
    let retry = response_json(
        app.clone()
            .oneshot(item_request(case_id, KEY, item_body(&first)))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(retry["replayed"], true);
    assert_eq!(retry["added_at"], added["added_at"]);
    let conflict = response_json(
        app.clone()
            .oneshot(item_request(
                case_id,
                "case-evidence-key-0002",
                item_body(&first),
            ))
            .await
            .unwrap(),
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(conflict["error_code"], "CONTROL_CASE_EVIDENCE_CONFLICT");
    let missing = response_json(
        app.clone()
            .oneshot(item_request(
                case_id,
                "case-evidence-key-0003",
                item_body(MISSING_ARTIFACT_ID),
            ))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_eq!(
        missing["error_code"],
        "CONTROL_CASE_EVIDENCE_TARGET_UNAVAILABLE"
    );

    // The HTTP future can disappear while PostgreSQL is waiting on a case lock.
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM xshield.investigation_cases WHERE tenant_id='tenant_a' AND site_id='site_a' AND case_id=$1 FOR UPDATE").bind(case_id).execute(&mut *lock).await.unwrap();
    let pending = tokio::spawn(app.clone().oneshot(item_request(
        case_id,
        "case-evidence-key-cancel",
        item_body(&second),
    )));
    tokio::time::timeout(Duration::from_secs(2), async {
        while capacity.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while capacity.available_permits() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let memberships: i64 = sqlx::query_scalar("SELECT count(*) FROM xshield.case_items WHERE tenant_id='tenant_a' AND site_id='site_a' AND case_id=$1").bind(case_id).fetch_one(&pool).await.unwrap();
    assert_eq!(memberships, 2);
    let events = read_access_events(&fixture.access_directory);
    let item_events: Vec<_> = events
        .iter()
        .filter(|event| event["event_type"] == "case.evidence.added")
        .collect();
    assert_eq!(item_events.len(), 5);
    assert_eq!(item_events.last().unwrap()["payload"]["outcome"], "PASS");
    assert_eq!(
        item_events.last().unwrap()["evidence_refs"],
        json!([second])
    );

    let expiry: DateTime<Utc> = sqlx::query_scalar("SELECT expires_at FROM xshield.artifact_catalog WHERE tenant_id='tenant_a' AND site_id='site_a' AND artifact_id=$1").bind(&first).fetch_one(&pool).await.unwrap();
    assert_eq!(expiry, original_expiry);
    let approvals: i64 = sqlx::query_scalar("SELECT count(*) FROM xshield.evidence_access_requests WHERE tenant_id='tenant_a' AND site_id='site_a' AND case_id=$1").bind(case_id).fetch_one(&pool).await.unwrap();
    assert_eq!(approvals, 0);
    let reader = Fixture::with_catalog(
        10,
        ManagementRole::SensitiveEvidenceReader,
        catalog.clone(),
        1,
    );
    let result = response_json(
        router(reader.control)
            .oneshot(evidence_content_request(
                &first,
                "access_018f2a3b-4c5d-7000-8000-000000000951",
            ))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_eq!(result["error_code"], "CONTROL_EVIDENCE_READ_NOT_AVAILABLE");

    // Business outbox survives management-journal failure; exact retry recovers.
    let failed = Fixture::with_case_catalog(catalog.clone(), 10);
    std::thread::scope(|scope| {
        let journal = &failed.control.access_journal;
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
        router(failed.control)
            .oneshot(item_request(
                case_id,
                "case-evidence-key-fault",
                item_body(&third),
            ))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(result["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(result.get("artifact_id").is_none());
    let recovered = response_json(
        app.clone()
            .oneshot(item_request(
                case_id,
                "case-evidence-key-fault",
                item_body(&third),
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(recovered["replayed"], true);
    let outbox: Vec<Value> = sqlx::query_scalar("SELECT envelope FROM xshield.audit_outbox WHERE tenant_id='tenant_a' AND site_id='site_a' AND aggregate_ref=$1 AND event_type='case.evidence.added'").bind(case_id).fetch_all(&pool).await.unwrap();
    assert_eq!(outbox.len(), 3);
    for envelope in outbox {
        assert_eq!(envelope["payload"]["reason_code"], "CASE_EVIDENCE_ADDED");
        assert!(!envelope.to_string().contains("case-evidence-key"));
    }
    drop(app);
    drop(vault);
    for directory in [
        &fixture.access_directory,
        &reader.access_directory,
        &failed.access_directory,
    ] {
        fs::remove_dir_all(directory.parent().unwrap()).unwrap();
    }
}
