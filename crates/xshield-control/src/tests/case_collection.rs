use super::*;
use xshield_core::domain::{ArtifactId, CaseId};

const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000951";

fn collection_request(path: &str) -> Request<Body> {
    Request::get(path)
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
async fn case_collection_validates_path_and_cursor_before_storage() {
    let fixture = Fixture::new(10, ManagementRole::Investigator);
    let app = router(fixture.control);
    for (path, expected) in [
        ("/control/v1/cases/bad/items", "CONTROL_CASE_ID_INVALID"),
        ("/control/v1/cases/%FF/items", "CONTROL_CASE_ID_INVALID"),
        (
            "/control/v1/cases/case_018f2a3b-4c5d-7000-8000-000000000951/items?cursor=bad",
            "CONTROL_CURSOR_INVALID",
        ),
    ] {
        let result = response_json(
            app.clone().oneshot(collection_request(path)).await.unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(result["error_code"], expected);
    }
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 3);
    assert!(
        events
            .iter()
            .all(|event| event["event_type"] == "console.case.read")
    );
    assert!(
        events
            .iter()
            .all(|event| event["payload"]["method"] == "GET")
    );
    assert!(
        events
            .iter()
            .all(|event| event["evidence_refs"] == json!([]))
    );
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn case_collection_rejects_cursor_reuse_across_case_and_subject() {
    let other_case = "case_018f2a3b-4c5d-7000-8000-000000000952";
    let artifact = ArtifactId::parse(MISSING_ARTIFACT_ID).unwrap();
    let case_id = CaseId::parse(CASE).unwrap();

    let fixture = Fixture::new(10, ManagementRole::Investigator);
    let cursor = fixture
        .control
        .encode_case_cursor("operator-1", &case_id, &artifact)
        .unwrap();
    let result = response_json(
        router(fixture.control)
            .oneshot(collection_request(&format!(
                "/control/v1/cases/{other_case}/items?cursor={cursor}"
            )))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(result["error_code"], "CONTROL_CURSOR_INVALID");

    let mut fixture = Fixture::new(10, ManagementRole::Investigator);
    let cursor = fixture
        .control
        .encode_case_cursor("operator-1", &case_id, &artifact)
        .unwrap();
    fixture.control.config.principal = ManagementPrincipal::new(
        "operator-2",
        [ManagementRole::Investigator],
        [(
            TenantId::parse("tenant_a").unwrap(),
            SiteId::parse("site_a").unwrap(),
        )],
    )
    .unwrap();
    let result = response_json(
        router(fixture.control)
            .oneshot(collection_request(&format!(
                "/control/v1/cases/{CASE}/items?cursor={cursor}"
            )))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(result["error_code"], "CONTROL_CURSOR_INVALID");
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn case_collection_enforces_authentication_scope_role_and_rate() {
    for scenario in ["missing_auth", "role", "scope", "expired", "rate"] {
        let mut fixture = Fixture::new(1, ManagementRole::Investigator);
        let mut request = collection_request(&format!("/control/v1/cases/{CASE}/items"));
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
        assert_eq!(events[0]["event_type"], "console.case.read");
        assert_eq!(events[0]["payload"]["target_case_id"], Value::Null);
        assert_eq!(events[0]["payload"]["reason_code"], code);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn case_collection_bounds_inflight_work_and_reports_store_failure() {
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
                .oneshot(collection_request(&format!(
                    "/control/v1/cases/{CASE}/items"
                )))
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
        assert_eq!(events[0]["event_type"], "console.case.read");
        assert_eq!(events[0]["payload"]["target_case_id"], CASE);
        assert_eq!(events[0]["payload"]["reason_code"], code);
        assert_eq!(events[0]["evidence_refs"], json!([]));
        drop(permit);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn case_collection_withholds_dependency_result_when_audit_fails() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
        .unwrap();
    pool.close().await;
    let fixture = Fixture::with_case_catalog(PostgresIdentityStore::from_pool(pool), 1);
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
            .oneshot(collection_request(&format!(
                "/control/v1/cases/{CASE}/items"
            )))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(result["error_code"], "AUDIT_DURABILITY_FAILED");
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn case_collection_success_is_scoped_and_audited() {
    let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let catalog = PostgresIdentityStore::connect(&url, 4, Duration::from_secs(5))
        .await
        .unwrap();
    let fixture = Fixture::with_catalog(10, ManagementRole::Investigator, catalog, 1);
    let artifact = "artifact_018f2a3b-4c5d-7000-8000-000000000951";
    let second_artifact = "artifact_018f2a3b-4c5d-7000-8000-000000000952";
    let case_event = format!("ev_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
             tenant_id, site_id, case_id, owner_ref, purpose, status,
             idempotency_digest, request_digest, created_event_id
         ) VALUES ('tenant_a', 'site_a', $1, 'operator-1', 'Read case', 'open', $2, $2, $3)",
    )
    .bind(CASE)
    .bind([11_u8; 32])
    .bind(&case_event)
    .execute(&pool)
    .await
    .unwrap();
    insert_collection_item(&pool, CASE, artifact, 12).await;
    insert_collection_item(&pool, CASE, second_artifact, 13).await;

    let app = router(fixture.control);
    let result = response_json(
        app.clone()
            .oneshot(collection_request(&format!(
                "/control/v1/cases/{CASE}/items"
            )))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(result["case"]["case_id"], CASE);
    assert_eq!(result["case"]["status"], "open");
    assert_eq!(result["items"][0]["artifact_id"], artifact);
    assert_eq!(result["items"][0]["catalog_status"], "active");
    assert_eq!(result["truncated"], true);
    let cursor = result["next_cursor"].as_str().unwrap();
    let next = response_json(
        app.clone()
            .oneshot(collection_request(&format!(
                "/control/v1/cases/{CASE}/items?cursor={cursor}"
            )))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(next["items"][0]["artifact_id"], second_artifact);
    assert_eq!(next["truncated"], false);
    assert!(next["next_cursor"].is_null());
    drop(app);
    let access_directory = fixture.access_directory;
    let events = read_access_events(&access_directory);
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event["event_type"] == "console.case.read")
    );
    assert!(
        events
            .iter()
            .all(|event| event["payload"]["outcome"] == "PASS")
    );
    assert_eq!(events[0]["evidence_refs"], json!([artifact]));
    assert_eq!(events[1]["evidence_refs"], json!([second_artifact]));

    sqlx::query("DELETE FROM xshield.case_items WHERE case_id = $1")
        .bind(CASE)
        .execute(&pool)
        .await
        .unwrap();
    for artifact in [artifact, second_artifact] {
        sqlx::query("DELETE FROM xshield.artifact_catalog WHERE artifact_id = $1")
            .bind(artifact)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM xshield.investigation_cases WHERE case_id = $1")
        .bind(CASE)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE aggregate_ref = $1")
        .bind(CASE)
        .execute(&pool)
        .await
        .unwrap();
    fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
}

async fn insert_collection_item(pool: &sqlx::PgPool, case: &str, artifact: &str, nonce: u8) {
    let request = format!("req_{}", Uuid::now_v7());
    let catalog_event = format!("ev_{}", Uuid::now_v7());
    let item_event = format!("ev_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO xshield.artifact_catalog (
             tenant_id, site_id, artifact_id, request_id, schema_version, kind,
             content_type, capture_status, fidelity, bytes_observed, bytes_saved,
             classification, example_only, storage_profile, storage_locator,
             key_ref, integrity_algorithm, integrity_digest, parent_refs,
             recorded_at, expires_at, catalog_event_id, status, deleted_at
         ) VALUES ('tenant_a', 'site_a', $1, $2, 3, 'response_from_origin',
             'application/json', 'complete', 'entity_exact', 2, 2, 'RESTRICTED',
             false, 'aead_envelope_v1', $1 || '.xev', 'evidence-key-r1',
             'sha256_ciphertext', repeat('a', 64), '{}',
             clock_timestamp() - interval '1 minute', clock_timestamp() + interval '1 hour',
             $3, 'active', NULL)",
    )
    .bind(artifact)
    .bind(request)
    .bind(catalog_event)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.case_items (
             tenant_id, site_id, case_id, artifact_id, added_by,
             idempotency_digest, request_digest, added_event_id
         ) VALUES ('tenant_a', 'site_a', $1, $2, 'operator-1', $3, $3, $4)",
    )
    .bind(case)
    .bind(artifact)
    .bind([nonce; 32])
    .bind(&item_event)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1, 'tenant_a', 'site_a', $2, 'case.evidence.added', '{}')",
    )
    .bind(item_event)
    .bind(case)
    .execute(pool)
    .await
    .unwrap();
}
