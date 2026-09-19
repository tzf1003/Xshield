use super::*;

const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000951";
const KEY: &str = "case-close-key-0001";

fn close_request(case: &str, key: &str, body: &str) -> Request<Body> {
    Request::post(format!("/control/v1/cases/{case}/close"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn case_close_validates_before_storage_and_audits_denials() {
    let fixture = Fixture::new(100, ManagementRole::Investigator);
    let app = router(fixture.control);
    for (case, key, body, expected) in [
        (
            "bad",
            KEY,
            r#"{"reason":"review complete"}"#,
            "CONTROL_CASE_ID_INVALID",
        ),
        (
            "%FF",
            KEY,
            r#"{"reason":"review complete"}"#,
            "CONTROL_CASE_ID_INVALID",
        ),
        (CASE, KEY, "{}", "CONTROL_CASE_CLOSE_REQUEST_INVALID"),
        (
            CASE,
            KEY,
            r#"{"reason":" padded "}"#,
            "CONTROL_CASE_CLOSE_REQUEST_INVALID",
        ),
        (
            CASE,
            KEY,
            r#"{"reason":"review complete","tenant_id":"other"}"#,
            "CONTROL_CASE_CLOSE_REQUEST_INVALID",
        ),
        (
            CASE,
            KEY,
            r#"{"reason":"one","reason":"two"}"#,
            "CONTROL_CASE_CLOSE_REQUEST_INVALID",
        ),
        (
            CASE,
            "short",
            r#"{"reason":"review complete"}"#,
            "CONTROL_IDEMPOTENCY_KEY_INVALID",
        ),
    ] {
        let result = response_json(
            app.clone()
                .oneshot(close_request(case, key, body))
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(result["error_code"], expected);
    }
    let mut duplicate = close_request(CASE, KEY, r#"{"reason":"review complete"}"#);
    duplicate
        .headers_mut()
        .append("idempotency-key", "case-close-second-key".parse().unwrap());
    for request in [
        duplicate,
        close_request(CASE, KEY, &json!({"reason": "x".repeat(4096)}).to_string()),
    ] {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 9);
    for event in events {
        assert_eq!(event["event_type"], "case.closed");
        assert_eq!(event["payload"]["path"], crate::case_close::PATH);
        assert_eq!(event["payload"]["outcome"], "DENY");
        assert_eq!(event["evidence_refs"], json!([]));
        assert!(!event.to_string().contains(KEY));
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn case_close_bounds_concurrency_and_withholds_unaudited_results() {
    let fixture = Fixture::new(10, ManagementRole::Investigator);
    let permit = fixture
        .control
        .case_evidence_capacity
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let result = response_json(
        router(fixture.control)
            .oneshot(close_request(CASE, KEY, r#"{"reason":"review complete"}"#))
            .await
            .unwrap(),
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;
    assert_eq!(result["error_code"], "CONTROL_CASE_CLOSE_BUSY");
    assert_eq!(
        read_access_events(&fixture.access_directory)[0]["payload"]["reason_code"],
        "CONTROL_CASE_CLOSE_BUSY"
    );
    drop(permit);
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();

    let fixture = Fixture::new(10, ManagementRole::Investigator);
    poison_audit(&fixture.control);
    let result = response_json(
        router(fixture.control)
            .oneshot(close_request("bad", KEY, "{}"))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(result["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(result.get("case_id").is_none());
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

fn poison_audit(control: &ControlPlane) {
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(|| {
                    let _guard = control.access_journal.lock().unwrap();
                    panic!("simulate audit failure");
                })
                .join()
                .is_err()
        );
    });
}

#[tokio::test]
async fn case_close_enforces_authentication_scope_role_rate_and_store_failure() {
    for scenario in ["missing_auth", "role", "scope", "expired", "rate", "store"] {
        let mut fixture = Fixture::new(1, ManagementRole::Investigator);
        let mut request = close_request(CASE, KEY, r#"{"reason":"review complete"}"#);
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
            "rate" => {
                fixture.control.rate.lock().unwrap().used = 1;
                (StatusCode::TOO_MANY_REQUESTS, "CONTROL_RATE_LIMITED")
            }
            _ => {
                let pool = sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
                    .unwrap();
                pool.close().await;
                fixture.control.catalog = PostgresIdentityStore::from_pool(pool);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_CASE_STORE_UNAVAILABLE",
                )
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
        assert_eq!(events[0]["payload"]["reason_code"], code);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn case_close_is_durable_revokes_new_access_and_survives_disconnect() {
    let pool = sqlx::PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let catalog = PostgresIdentityStore::from_pool(pool.clone());
    let subject = format!("case-close-{}", Uuid::now_v7());
    let tenant = TenantId::parse(format!("tenant_close_http_{}", Uuid::now_v7().simple())).unwrap();
    let mut fixture = scoped_fixture(
        catalog.clone(),
        &subject,
        ManagementRole::Investigator,
        &tenant,
    );
    fixture.control.config.limits.max_open_cases = 1;
    fixture.control.rate.lock().unwrap().limit = 100;
    let capacity = fixture.control.case_evidence_capacity.clone();
    let vault_root = fixture.access_directory.parent().unwrap().join("evidence");
    private_directory(&vault_root);
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&vault_root, "case-close-key", 1024, 30).unwrap(),
        EvidenceKey::from_hex("5555555555555555555555555555555555555555555555555555555555555555")
            .unwrap(),
    )
    .unwrap();
    let artifact = publish_test_artifact(
        &catalog,
        &vault,
        &tenant,
        &SiteId::parse("site_a").unwrap(),
        &RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap(),
        1,
    )
    .await;
    let expiry: DateTime<Utc> = sqlx::query_scalar("SELECT expires_at FROM xshield.artifact_catalog WHERE tenant_id=$1 AND site_id='site_a' AND artifact_id=$2")
        .bind(tenant.as_str()).bind(&artifact).fetch_one(&pool).await.unwrap();
    let app = router(fixture.control);
    let created = response_json(
        app.clone()
            .oneshot(case_request(
                "case-close-create-0001",
                r#"{"purpose":"Complete investigation"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::CREATED,
    )
    .await;
    let case_id = created["case_id"].as_str().unwrap();
    let full = response_json(
        app.clone()
            .oneshot(case_request(
                "case-close-create-0002",
                r#"{"purpose":"Next investigation"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;
    assert_eq!(full["error_code"], "CONTROL_CASE_CAPACITY_EXCEEDED");
    let item = || {
        Request::post(format!("/control/v1/cases/{case_id}/items"))
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(CONTENT_TYPE, "application/json")
            .header("idempotency-key", "case-close-item-0001")
            .body(Body::from(json!({"artifact_id":artifact}).to_string()))
            .unwrap()
    };
    response_json(
        app.clone().oneshot(item()).await.unwrap(),
        StatusCode::CREATED,
    )
    .await;
    let access_body =
        json!({"case_id":case_id,"access_kind":"sensitive_raw","justification":"Review source"})
            .to_string();
    let requested = response_json(
        app.clone()
            .oneshot(evidence_access_request(
                &artifact,
                "case-close-access-0001",
                &access_body,
            ))
            .await
            .unwrap(),
        StatusCode::CREATED,
    )
    .await;
    let access_id = requested["access_request_id"].as_str().unwrap();
    let approver = scoped_fixture(
        catalog.clone(),
        "independent-approver",
        ManagementRole::SensitiveEvidenceApprover,
        &tenant,
    );
    response_json(
        router(approver.control)
            .oneshot(evidence_access_decision_request(
                access_id,
                "approve",
                "case-close-approve-0001",
                r#"{"reason":"Review approved","ttl_seconds":600}"#,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    let reader = scoped_fixture(
        catalog.clone(),
        &subject,
        ManagementRole::SensitiveEvidenceReader,
        &tenant,
    )
    .with_evidence_read_port(EvidenceReadPort::new(vault));
    let reader_app = router(reader.control);
    let content = reader_app
        .clone()
        .oneshot(evidence_content_request(&artifact, access_id))
        .await
        .unwrap();
    assert_eq!(content.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(content.into_body(), 1024).await.unwrap(),
        br#"{"approved":true}"#[..]
    );

    let closed = response_json(
        app.clone()
            .oneshot(close_request(
                case_id,
                KEY,
                r#"{"reason":"review complete"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(closed["status"], "closed");
    assert_eq!(closed["replayed"], false);
    let replay = response_json(
        app.clone()
            .oneshot(close_request(
                case_id,
                KEY,
                r#"{"reason":"review complete"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["closed_at"], closed["closed_at"]);
    let conflict = response_json(
        app.clone()
            .oneshot(close_request(
                case_id,
                KEY,
                r#"{"reason":"different reason"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(conflict["error_code"], "CONTROL_CASE_CLOSE_CONFLICT");
    let unavailable = response_json(
        app.clone()
            .oneshot(close_request(
                case_id,
                "another-close-key",
                r#"{"reason":"review complete"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_eq!(unavailable["error_code"], "CONTROL_CASE_NOT_AVAILABLE");
    let collection = response_json(
        app.clone()
            .oneshot(authenticated_path(&format!(
                "/control/v1/cases/{case_id}/items"
            )))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(collection["case"]["status"], "closed");
    assert_eq!(collection["items"][0]["artifact_id"], artifact);
    assert_eq!(collection["items"][0]["catalog_status"], "active");
    response_json(
        app.clone().oneshot(item()).await.unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
    response_json(
        app.clone()
            .oneshot(evidence_access_request(
                &artifact,
                "case-close-access-0002",
                &access_body,
            ))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
    let read_denied = response_json(
        reader_app
            .clone()
            .oneshot(evidence_content_request(&artifact, access_id))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_eq!(
        read_denied["error_code"],
        "CONTROL_EVIDENCE_READ_NOT_AVAILABLE"
    );
    let remaining_expiry: DateTime<Utc> = sqlx::query_scalar("SELECT expires_at FROM xshield.artifact_catalog WHERE tenant_id=$1 AND site_id='site_a' AND artifact_id=$2")
        .bind(tenant.as_str()).bind(&artifact).fetch_one(&pool).await.unwrap();
    assert_eq!(remaining_expiry, expiry);
    let approval: String = sqlx::query_scalar("SELECT status FROM xshield.evidence_access_requests WHERE tenant_id=$1 AND site_id='site_a' AND access_request_id=$2")
        .bind(tenant.as_str()).bind(access_id).fetch_one(&pool).await.unwrap();
    assert_eq!(approval, "approved");

    // The closed case frees capacity; the next admitted closure survives cancellation.
    let second = response_json(
        app.clone()
            .oneshot(case_request(
                "case-close-create-0002",
                r#"{"purpose":"Next investigation"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::CREATED,
    )
    .await;
    let second_id = second["case_id"].as_str().unwrap();
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM xshield.investigation_cases WHERE tenant_id=$1 AND site_id='site_a' AND case_id=$2 FOR UPDATE")
        .bind(tenant.as_str()).bind(second_id).execute(&mut *lock).await.unwrap();
    let pending = tokio::spawn(app.clone().oneshot(close_request(
        second_id,
        "case-close-disconnect",
        r#"{"reason":"review complete"}"#,
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
    let retry = response_json(
        app.clone()
            .oneshot(close_request(
                second_id,
                "case-close-disconnect",
                r#"{"reason":"review complete"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(retry["replayed"], true);

    // A committed business event remains recoverable after the local audit fails.
    let third = response_json(
        app.clone()
            .oneshot(case_request(
                "case-close-create-0003",
                r#"{"purpose":"Verify terminal audit recovery"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::CREATED,
    )
    .await;
    let third_id = third["case_id"].as_str().unwrap();
    let failed = scoped_fixture(catalog, &subject, ManagementRole::Investigator, &tenant);
    poison_audit(&failed.control);
    let failure = response_json(
        router(failed.control)
            .oneshot(close_request(
                third_id,
                "case-close-audit-fault",
                r#"{"reason":"review complete"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(failure["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(failure.get("closed_at").is_none());
    let recovered = response_json(
        app.clone()
            .oneshot(close_request(
                third_id,
                "case-close-audit-fault",
                r#"{"reason":"review complete"}"#,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(recovered["replayed"], true);
    let envelopes: Vec<Value> = sqlx::query_scalar("SELECT envelope FROM xshield.audit_outbox WHERE tenant_id=$1 AND site_id='site_a' AND event_type='case.closed' AND aggregate_ref=ANY($2)")
        .bind(tenant.as_str()).bind([case_id,second_id,third_id].as_slice()).fetch_all(&pool).await.unwrap();
    assert_eq!(envelopes.len(), 3);
    for event in envelopes {
        assert_eq!(event["payload"]["reason_code"], "CASE_CLOSED");
        assert_eq!(event["payload"]["confidence"], Value::Null);
        assert!(event["payload"].get("reason").is_none());
        assert!(!event.to_string().contains(KEY));
    }
    drop(app);
    drop(reader_app);
    let events = read_access_events(&fixture.access_directory);
    let close_events: Vec<_> = events
        .iter()
        .filter(|event| event["event_type"] == "case.closed")
        .collect();
    assert_eq!(close_events.len(), 7);
    assert!(
        close_events
            .iter()
            .any(|event| event["payload"]["target_case_id"] == second_id
                && event["payload"]["reason_code"] == "CONTROL_CASE_CLOSED")
    );
    for event in close_events {
        assert_eq!(event["payload"]["method"], "POST");
        assert_eq!(event["evidence_refs"], json!([]));
        assert!(event["payload"]["target_case_id"].is_string());
    }
    for directory in [
        &fixture.access_directory,
        &approver.access_directory,
        &reader.access_directory,
        &failed.access_directory,
    ] {
        fs::remove_dir_all(directory.parent().unwrap()).unwrap();
    }
    for statement in [
        "DELETE FROM xshield.case_closures WHERE tenant_id=$1",
        "DELETE FROM xshield.case_items WHERE tenant_id=$1",
        "DELETE FROM xshield.evidence_access_requests WHERE tenant_id=$1",
        "DELETE FROM xshield.artifact_catalog WHERE tenant_id=$1",
        "DELETE FROM xshield.investigation_cases WHERE tenant_id=$1",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id=$1",
    ] {
        sqlx::query(statement)
            .bind(tenant.as_str())
            .execute(&pool)
            .await
            .unwrap();
    }
}

fn scoped_fixture(
    catalog: PostgresIdentityStore,
    subject: &str,
    role: ManagementRole,
    tenant: &TenantId,
) -> Fixture {
    let mut fixture = Fixture::with_decision_catalog(catalog, subject, role);
    fixture.control.config.tenant_id = tenant.clone();
    fixture.control.config.principal = ManagementPrincipal::new(
        subject,
        [role],
        [(tenant.clone(), fixture.control.config.site_id.clone())],
    )
    .unwrap();
    fixture
}
