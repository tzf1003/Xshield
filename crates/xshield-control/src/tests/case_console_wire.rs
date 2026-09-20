use super::*;

const TENANT: &str = "tenant_console_case_wire";
const SUBJECT: &str = "console-case-investigator";

#[tokio::test]
async fn case_creation_rejects_duplicate_keys_and_busy_work_before_storage() {
    let fixture = Fixture::new(10, ManagementRole::Investigator);
    let permit = fixture
        .control
        .case_evidence_capacity
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let app = router(fixture.control);
    let mut duplicate = case_request("case-create-test-key", r#"{"purpose":"Review"}"#);
    duplicate
        .headers_mut()
        .append("idempotency-key", "case-create-other-key".parse().unwrap());
    for (request, status, code) in [
        (
            duplicate,
            StatusCode::BAD_REQUEST,
            "CONTROL_IDEMPOTENCY_KEY_INVALID",
        ),
        (
            case_request("case-create-test-key", r#"{"purpose":"Review"}"#),
            StatusCode::TOO_MANY_REQUESTS,
            "CONTROL_CASE_BUSY",
        ),
    ] {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), status);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
        assert_eq!(body["error_code"], code);
    }
    drop(permit);
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 2);
    for (event, reason) in events
        .iter()
        .zip(["CONTROL_IDEMPOTENCY_KEY_INVALID", "CONTROL_CASE_BUSY"])
    {
        assert_eq!(event["event_type"], "case.created");
        assert_eq!(event["payload"]["outcome"], "DENY");
        assert_eq!(event["payload"]["reason_code"], reason);
        assert!(event["payload"]["target_case_id"].is_null());
        assert!(!event.to_string().contains("case-create-test-key"));
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

fn fixture(pool: &sqlx::PgPool, subject: &str, role: ManagementRole) -> Fixture {
    let mut result = Fixture::with_decision_catalog(
        PostgresIdentityStore::from_pool(pool.clone()),
        subject,
        role,
    );
    let tenant = TenantId::parse(TENANT).unwrap();
    result.control.config.tenant_id = tenant.clone();
    result.control.config.principal = ManagementPrincipal::new(
        subject,
        [role],
        [(tenant, SiteId::parse("site_a").unwrap())],
    )
    .unwrap();
    result.control.config.limits.max_query_artifacts = 1;
    result.control.rate.lock().unwrap().limit = 100;
    result
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL and Node.js 22"]
#[allow(clippy::too_many_lines)]
async fn console_case_client_mutates_postgres_http_contract() {
    let database_url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let case_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&database_url)
        .await
        .unwrap();
    let investigator = fixture(&case_pool, SUBJECT, ManagementRole::Investigator);
    let observer = fixture(&pool, "case-observer", ManagementRole::Observer);
    let foreign = fixture(&pool, "another-investigator", ManagementRole::Investigator);
    let vault_root = investigator
        .access_directory
        .parent()
        .unwrap()
        .join("evidence");
    private_directory(&vault_root);
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&vault_root, "case-wire-key", 1024, 30).unwrap(),
        EvidenceKey::from_hex("5555555555555555555555555555555555555555555555555555555555555555")
            .unwrap(),
    )
    .unwrap();
    let catalog = PostgresIdentityStore::from_pool(pool.clone());
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000983").unwrap();
    let mut artifacts = Vec::new();
    for ordinal in 1..=2 {
        artifacts.push(
            publish_test_artifact(
                &catalog,
                &vault,
                &TenantId::parse(TENANT).unwrap(),
                &SiteId::parse("site_a").unwrap(),
                &request,
                ordinal,
            )
            .await,
        );
    }
    // The harness supplies generated artifact IDs and a foreign-owned case to Node.
    let seed_app = router(foreign.control);
    let seeded = seed_app
        .clone()
        .oneshot(case_request(
            "case-wire-foreign-key",
            r#"{"purpose":"Other owner"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(seeded.status(), StatusCode::CREATED);
    let seeded: Value =
        serde_json::from_slice(&to_bytes(seeded.into_body(), 16384).await.unwrap()).unwrap();
    let foreign_case = seeded["case_id"].as_str().unwrap().to_owned();
    drop(seed_app);

    let capacity = investigator.control.case_evidence_capacity.clone();
    let app = router(investigator.control);
    // Exhaust the pool for longer than the endpoint budget. No SQL timeout can
    // fire before acquisition, so this exercises the overall deadline itself.
    let held_connection = case_pool.acquire().await.unwrap();
    let started = std::time::Instant::now();
    let exhausted = tokio::time::timeout(
        Duration::from_secs(20),
        app.clone().oneshot(case_request(
            "case-wire-pool-timeout",
            r#"{"purpose":"Waiting for a connection"}"#,
        )),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(15));
    assert_eq!(exhausted.status(), StatusCode::SERVICE_UNAVAILABLE);
    let exhausted: Value =
        serde_json::from_slice(&to_bytes(exhausted.into_body(), 16384).await.unwrap()).unwrap();
    assert_eq!(exhausted["error_code"], "CONTROL_CASE_STORE_UNAVAILABLE");
    assert_eq!(capacity.available_permits(), 1);
    drop(held_connection);
    let mut stalled = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('xshield-case-v1:' || $1 || ':site_a:' || $2, 0))")
        .bind(TENANT).bind(SUBJECT).execute(&mut *stalled).await.unwrap();
    let unavailable = tokio::time::timeout(
        Duration::from_secs(8),
        app.clone().oneshot(case_request(
            "case-wire-lock-timeout",
            r#"{"purpose":"Stalled creation"}"#,
        )),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    let unavailable: Value =
        serde_json::from_slice(&to_bytes(unavailable.into_body(), 16384).await.unwrap()).unwrap();
    assert_eq!(unavailable["error_code"], "CONTROL_CASE_STORE_UNAVAILABLE");
    assert_eq!(capacity.available_permits(), 1);
    stalled.rollback().await.unwrap();
    // Abort the admitted HTTP future while its actor lock is held. Work must
    // reach a durable case/outbox/audit terminal once the lock becomes available.
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('xshield-case-v1:' || $1 || ':site_a:' || $2, 0))")
        .bind(TENANT).bind(SUBJECT).execute(&mut *lock).await.unwrap();
    let pending = tokio::spawn(app.clone().oneshot(case_request(
        "case-wire-disconnect-key",
        r#"{"purpose":"Recover disconnected creation"}"#,
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let denied_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let denied_address = denied_listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let denied_server =
        tokio::spawn(async move { axum::serve(denied_listener, router(observer.control)).await });
    let result = run_console_wire_with_env(
        "case-wire.ts",
        address,
        Some(denied_address),
        vec![
            ("XSHIELD_CONSOLE_TEST_ARTIFACTS", artifacts.join(",")),
            ("XSHIELD_CONSOLE_TEST_FOREIGN_CASE", foreign_case),
        ],
    )
    .await
    .unwrap();
    server.abort();
    denied_server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert!(denied_server.await.unwrap_err().is_cancelled());
    let events = read_access_events(&investigator.access_directory);
    let denied_events = read_access_events(&observer.access_directory);
    let counts: Vec<(String, i64)> = sqlx::query_as("SELECT event_type, count(*) FROM xshield.audit_outbox WHERE tenant_id=$1 AND event_type LIKE 'case.%' GROUP BY event_type ORDER BY event_type")
        .bind(TENANT).fetch_all(&pool).await.unwrap();
    let cases: Vec<(String, String)> = sqlx::query_as("SELECT purpose, status FROM xshield.investigation_cases WHERE tenant_id=$1 AND owner_ref=$2 ORDER BY purpose")
        .bind(TENANT).bind(SUBJECT).fetch_all(&pool).await.unwrap();
    for statement in [
        "DELETE FROM xshield.case_closures WHERE tenant_id=$1",
        "DELETE FROM xshield.case_items WHERE tenant_id=$1",
        "DELETE FROM xshield.investigation_cases WHERE tenant_id=$1",
        "DELETE FROM xshield.artifact_catalog WHERE tenant_id=$1",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id=$1",
    ] {
        sqlx::query(statement)
            .bind(TENANT)
            .execute(&pool)
            .await
            .unwrap();
    }
    drop(vault);
    for directory in [
        &investigator.access_directory,
        &observer.access_directory,
        &foreign.access_directory,
    ] {
        fs::remove_dir_all(directory.parent().unwrap()).unwrap();
    }
    case_pool.close().await;
    pool.close().await;
    assert!(
        result.success(),
        "case wire contract failed; phase={:?}",
        result.code()
    );
    assert_eq!(
        counts,
        vec![
            ("case.closed".to_owned(), 1),
            ("case.created".to_owned(), 3),
            ("case.evidence.added".to_owned(), 2)
        ]
    );
    assert_eq!(
        cases,
        vec![
            (
                "Recover disconnected creation".to_owned(),
                "open".to_owned()
            ),
            ("Wire investigation".to_owned(), "closed".to_owned())
        ]
    );
    assert_eq!(events.len(), 23);
    for event in &events[..2] {
        assert_eq!(
            event["payload"]["reason_code"],
            "CONTROL_CASE_STORE_UNAVAILABLE"
        );
        assert_eq!(event["payload"]["outcome"], "ERROR");
    }
    assert_eq!(denied_events.len(), 4);
    assert_eq!(
        events
            .iter()
            .filter(|e| e["payload"]["reason_code"] == "CONTROL_CASE_CREATED")
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e["payload"]["reason_code"] == "CONTROL_CASE_ALREADY_CREATED")
            .count(),
        3
    );
    for event in events.iter().chain(&denied_events) {
        assert!(event["payload"]["outcome"].is_string());
        assert!(event["payload"]["reason_code"].is_string());
        assert!(!event.to_string().contains("case-wire-"));
        assert!(!event.to_string().contains("Wire investigation"));
        assert!(!event.to_string().contains(TOKEN));
    }
    for event in denied_events {
        assert_eq!(event["payload"]["reason_code"], "CONTROL_SCOPE_DENIED");
    }
}
