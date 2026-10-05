//! Real HTTP, `PostgreSQL` and journal coverage for administrator retention holds.

use super::*;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

const ADMIN: &str = "hold-audit-admin";
const OWNER: &str = "hold-case-owner";
const CREATE_KEY: &str = "http-hold-create-0001";
const RELEASE_KEY: &str = "http-hold-release-0001";

struct HoldContext {
    pool: sqlx::PgPool,
    tenant: TenantId,
    roots: Arc<Mutex<Vec<PathBuf>>>,
}

impl HoldContext {
    fn fixture(&self, subject: &str, role: ManagementRole, page_size: u16) -> Fixture {
        let mut fixture = Fixture::with_decision_catalog(
            PostgresIdentityStore::from_pool(self.pool.clone()),
            subject,
            role,
        );
        fixture.control.config.tenant_id = self.tenant.clone();
        fixture.control.config.principal = ManagementPrincipal::new(
            subject,
            [role],
            [(self.tenant.clone(), SiteId::parse("site_a").unwrap())],
        )
        .unwrap();
        fixture.control.config.limits.max_query_artifacts = page_size;
        fixture.control.rate.lock().unwrap().limit = 1_000;
        self.roots
            .lock()
            .unwrap()
            .push(fixture.access_directory.parent().unwrap().to_owned());
        fixture
    }
}

fn mutation(path: &str, key: &str, body: &Value) -> Request<Body> {
    Request::post(path)
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn hold_body(artifact: &str, until: DateTime<Utc>) -> Value {
    json!({"artifact_id":artifact,"reason":"Preserve case evidence",
        "hold_until":until.to_rfc3339_opts(SecondsFormat::Millis,true)})
}

async fn request_json(app: &axum::Router, request: Request<Body>, status: StatusCode) -> Value {
    let path = request.uri().clone();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), status, "{path}");
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}

async fn create_case(app: &axum::Router, key: &str) -> String {
    request_json(
        app,
        case_request(key, r#"{"purpose":"Review retention holds"}"#),
        StatusCode::CREATED,
    )
    .await["case_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn associate(app: &axum::Router, case: &str, artifact: &str, key: &str) {
    request_json(
        app,
        mutation(
            &format!("/control/v1/cases/{case}/items"),
            key,
            &json!({"artifact_id":artifact}),
        ),
        StatusCode::CREATED,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires script-owned XSHIELD_TEST_DATABASE_URL"]
async fn case_holds_are_scoped_idempotent_paginated_and_audited() {
    let pool = sqlx::PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        database.starts_with("xshield_test_"),
        "requires script-owned test database"
    );
    let tenant = TenantId::parse(format!("tenant_hold_http_{}", Uuid::now_v7().simple())).unwrap();
    let roots = Arc::new(Mutex::new(Vec::new()));
    let context = HoldContext {
        pool: pool.clone(),
        tenant: tenant.clone(),
        roots: roots.clone(),
    };
    // Keep cleanup outside the assertion task so a failed HTTP assertion still
    // removes this tenant's synthetic rows and its registered fixture directories.
    let result = tokio::spawn(run_hold_http(context)).await;
    for statement in [
        "DELETE FROM xshield.case_evidence_holds WHERE tenant_id=$1",
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
    for root in roots.lock().unwrap().iter() {
        fs::remove_dir_all(root).unwrap();
    }
    pool.close().await;
    if let Err(error) = result {
        std::panic::resume_unwind(error.into_panic());
    }
}

#[allow(clippy::too_many_lines)]
async fn run_hold_http(context: HoldContext) {
    let owner = context.fixture(OWNER, ManagementRole::Investigator, 128);
    let vault_root = owner.access_directory.parent().unwrap().join("evidence");
    private_directory(&vault_root);
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&vault_root, "hold-http-key", 1024, 30).unwrap(),
        EvidenceKey::from_hex("5555555555555555555555555555555555555555555555555555555555555555")
            .unwrap(),
    )
    .unwrap();
    let catalog = PostgresIdentityStore::from_pool(context.pool.clone());
    let source = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
    let site = SiteId::parse("site_a").unwrap();
    let mut artifacts = Vec::new();
    for sequence in 1..=3 {
        artifacts.push(
            publish_test_artifact(&catalog, &vault, &context.tenant, &site, &source, sequence)
                .await,
        );
    }
    let owner_app = router(owner.control);
    let case = create_case(&owner_app, "hold-http-case-0001").await;
    let other_case = create_case(&owner_app, "hold-http-case-0002").await;
    for (index, artifact) in artifacts.iter().enumerate() {
        associate(
            &owner_app,
            &case,
            artifact,
            &format!("hold-http-item-{index:04}"),
        )
        .await;
    }
    let original_expiry: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM xshield.artifact_catalog WHERE artifact_id=$1")
            .bind(&artifacts[0])
            .fetch_one(&context.pool)
            .await
            .unwrap();
    let now: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds',clock_timestamp())")
            .fetch_one(&context.pool)
            .await
            .unwrap();
    let body = hold_body(&artifacts[0], now + chrono::TimeDelta::days(1));
    let path = format!("/control/v1/cases/{case}/holds");
    let admin = context.fixture(ADMIN, ManagementRole::AuditAdministrator, 1);
    let capacity = admin.control.case_evidence_capacity.clone();
    let admin_directory = admin.access_directory.clone();
    let admin_app = router(admin.control);

    let created = request_json(
        &admin_app,
        mutation(&path, CREATE_KEY, &body),
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(created["schema_version"], 3);
    assert_eq!(created["tenant_id"], context.tenant.as_str());
    assert_eq!(created["site_id"], "site_a");
    assert_eq!(created["case_id"], case);
    assert_eq!(created["artifact_id"], artifacts[0]);
    assert_eq!(created["created_by"], ADMIN);
    assert_eq!(created["hold_until"], body["hold_until"]);
    assert_eq!(created["replayed"], false);
    assert!(created["released_event_id"].is_null());
    let replay = request_json(
        &admin_app,
        mutation(&path, CREATE_KEY, &body),
        StatusCode::OK,
    )
    .await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["hold_id"], created["hold_id"]);
    assert_eq!(replay["created_at"], created["created_at"]);
    let mut changed_reason = body.clone();
    changed_reason["reason"] = json!("Changed reason");
    let mut changed_deadline = body.clone();
    changed_deadline["hold_until"] =
        json!((now + chrono::TimeDelta::days(2)).to_rfc3339_opts(SecondsFormat::Millis, true));
    let mut changed_artifact = body.clone();
    changed_artifact["artifact_id"] = json!(artifacts[1]);
    for (key, changed) in [
        (CREATE_KEY, changed_reason),
        (CREATE_KEY, changed_deadline),
        (CREATE_KEY, changed_artifact),
        ("http-hold-natural-conflict", body.clone()),
    ] {
        let denied = request_json(
            &admin_app,
            mutation(&path, key, &changed),
            StatusCode::CONFLICT,
        )
        .await;
        assert_eq!(denied["error_code"], "CONTROL_EVIDENCE_HOLD_CONFLICT");
    }
    for (key, deadline) in [
        (
            "http-hold-expired-0001",
            now - chrono::TimeDelta::seconds(1),
        ),
        (
            "http-hold-toolong-0001",
            now + chrono::TimeDelta::hours(721),
        ),
    ] {
        let denied = request_json(
            &admin_app,
            mutation(&path, key, &hold_body(&artifacts[1], deadline)),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(
            denied["error_code"],
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID"
        );
    }
    request_json(
        &admin_app,
        mutation(
            &format!("/control/v1/cases/{other_case}/holds"),
            "http-hold-nonmember-0001",
            &body,
        ),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_foreign_scope(&context, &path, &body).await;

    let release_path = format!(
        "/control/v1/evidence-holds/{}/release",
        created["hold_id"].as_str().unwrap()
    );
    let release_body = json!({"reason":"Review complete"});
    let released = request_json(
        &admin_app,
        mutation(&release_path, RELEASE_KEY, &release_body),
        StatusCode::OK,
    )
    .await;
    assert_eq!(released["released_by"], ADMIN);
    assert!(released["released_event_id"].is_string());
    assert_eq!(released["replayed"], false);
    let replay = request_json(
        &admin_app,
        mutation(&release_path, RELEASE_KEY, &release_body),
        StatusCode::OK,
    )
    .await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["released_at"], released["released_at"]);
    request_json(
        &admin_app,
        mutation(
            &release_path,
            RELEASE_KEY,
            &json!({"reason":"Changed release reason"}),
        ),
        StatusCode::CONFLICT,
    )
    .await;
    let renewed = request_json(
        &admin_app,
        mutation(&path, "http-hold-create-0002", &body),
        StatusCode::CREATED,
    )
    .await;
    assert_ne!(renewed["hold_id"], created["hold_id"]);
    let first_page = request_json(&admin_app, authenticated_path(&path), StatusCode::OK).await;
    assert_eq!(first_page["case_status"], "open");
    assert_eq!(first_page["items"][0]["hold_id"], created["hold_id"]);
    assert_eq!(first_page["truncated"], true);
    assert_eq!(first_page["as_of"].as_str().unwrap().len(), 27);
    let cursor = first_page["next_cursor"].as_str().unwrap();
    let next = request_json(
        &admin_app,
        authenticated_path(&format!("{path}?cursor={cursor}")),
        StatusCode::OK,
    )
    .await;
    assert_eq!(next["items"][0]["hold_id"], renewed["hold_id"]);
    assert_eq!(next["truncated"], false);
    assert!(next["next_cursor"].is_null());
    request_json(
        &admin_app,
        authenticated_path(&format!(
            "/control/v1/cases/{other_case}/holds?cursor={cursor}"
        )),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_cursor_bindings(&context, &path, cursor).await;
    assert_full_history_refs(&context, &path, &artifacts[0]).await;

    let after_expiry: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM xshield.artifact_catalog WHERE artifact_id=$1")
            .bind(&artifacts[0])
            .fetch_one(&context.pool)
            .await
            .unwrap();
    assert_eq!(original_expiry, after_expiry);
    let approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.evidence_access_requests WHERE tenant_id=$1",
    )
    .bind(context.tenant.as_str())
    .fetch_one(&context.pool)
    .await
    .unwrap();
    assert_eq!(approvals, 0);
    let reader = context
        .fixture(OWNER, ManagementRole::SensitiveEvidenceReader, 1)
        .with_evidence_read_port(EvidenceReadPort::new(vault));
    let denied = request_json(
        &router(reader.control),
        evidence_content_request(&artifacts[0], "access_018f2a3b-4c5d-7000-8000-000000000951"),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_eq!(denied["error_code"], "CONTROL_EVIDENCE_READ_NOT_AVAILABLE");

    assert_audit_recovery(
        &context,
        &admin_app,
        &path,
        &hold_body(&artifacts[2], now + chrono::TimeDelta::days(1)),
    )
    .await;
    assert_disconnect(
        &context,
        &admin_app,
        &case,
        &hold_body(&artifacts[1], now + chrono::TimeDelta::days(1)),
        &capacity,
        &admin_directory,
    )
    .await;
    request_json(
        &owner_app,
        mutation(
            &format!("/control/v1/cases/{case}/close"),
            "http-hold-close-0001",
            &json!({"reason":"Case complete"}),
        ),
        StatusCode::OK,
    )
    .await;
    request_json(
        &admin_app,
        mutation(&path, "http-hold-closed-0001", &body),
        StatusCode::NOT_FOUND,
    )
    .await;
    let closed = request_json(&admin_app, authenticated_path(&path), StatusCode::OK).await;
    assert_eq!(closed["case_status"], "closed");
    let release_path = format!(
        "/control/v1/evidence-holds/{}/release",
        renewed["hold_id"].as_str().unwrap()
    );
    request_json(
        &admin_app,
        mutation(&release_path, "http-hold-release-0002", &release_body),
        StatusCode::OK,
    )
    .await;
    drop(admin_app);
    assert_hold_audit(
        &admin_directory,
        &artifacts[0],
        &case,
        created["hold_id"].as_str().unwrap(),
    );
}

async fn assert_foreign_scope(context: &HoldContext, path: &str, body: &Value) {
    for tenant_scope in [true, false] {
        let mut fixture = context.fixture(ADMIN, ManagementRole::AuditAdministrator, 1);
        if tenant_scope {
            fixture.control.config.tenant_id = TenantId::parse("tenant_foreign_hold").unwrap();
        } else {
            fixture.control.config.site_id = SiteId::parse("site_foreign_hold").unwrap();
        }
        fixture.control.config.principal = ManagementPrincipal::new(
            ADMIN,
            [ManagementRole::AuditAdministrator],
            [(
                fixture.control.config.tenant_id.clone(),
                fixture.control.config.site_id.clone(),
            )],
        )
        .unwrap();
        let denied = request_json(
            &router(fixture.control),
            mutation(path, "http-hold-other-scope", body),
            StatusCode::NOT_FOUND,
        )
        .await;
        assert_eq!(
            denied["error_code"],
            "CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE"
        );
    }
}

async fn assert_cursor_bindings(context: &HoldContext, path: &str, cursor: &str) {
    for change in ["subject", "credential", "tenant", "site", "budget"] {
        let mut fixture = context.fixture(ADMIN, ManagementRole::AuditAdministrator, 1);
        let mut subject = ADMIN;
        let mut token = TOKEN;
        match change {
            "subject" => subject = "other-hold-administrator",
            "credential" => {
                token = "rotated-synthetic-management-bearer-0001";
                let previous = &fixture.control.config.credential;
                fixture.control.config.credential =
                    ManagementCredential::new(token, previous.issued_at, previous.expires_at)
                        .unwrap();
            }
            "tenant" => {
                fixture.control.config.tenant_id = TenantId::parse("tenant_foreign_hold").unwrap();
            }
            "site" => fixture.control.config.site_id = SiteId::parse("site_foreign_hold").unwrap(),
            "budget" => fixture.control.config.limits.max_query_artifacts = 2,
            _ => unreachable!(),
        }
        fixture.control.config.principal = ManagementPrincipal::new(
            subject,
            [ManagementRole::AuditAdministrator],
            [(
                fixture.control.config.tenant_id.clone(),
                fixture.control.config.site_id.clone(),
            )],
        )
        .unwrap();
        let request = Request::get(format!("{path}?cursor={cursor}"))
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let denied = request_json(&router(fixture.control), request, StatusCode::BAD_REQUEST).await;
        assert_eq!(denied["error_code"], "CONTROL_CURSOR_INVALID", "{change}");
    }
}

async fn assert_full_history_refs(context: &HoldContext, path: &str, artifact: &str) {
    let fixture = context.fixture(ADMIN, ManagementRole::AuditAdministrator, 128);
    let directory = fixture.access_directory.clone();
    let history = request_json(
        &router(fixture.control),
        authenticated_path(path),
        StatusCode::OK,
    )
    .await;
    assert_eq!(history["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        history["items"][0]["artifact_id"],
        history["items"][1]["artifact_id"]
    );
    for item in history["items"].as_array().unwrap() {
        for secret in [
            "request_digest",
            "idempotency_digest",
            "manifest",
            "key_ref",
            "storage_locator",
        ] {
            assert!(item.get(secret).is_none());
        }
    }
    let events = read_access_events(&directory);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "console.evidence.hold.read");
    assert_eq!(events[0]["evidence_refs"], json!([artifact]));
}

async fn assert_audit_recovery(
    context: &HoldContext,
    app: &axum::Router,
    path: &str,
    body: &Value,
) {
    let fixture = context.fixture(ADMIN, ManagementRole::AuditAdministrator, 1);
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(|| {
                    let _guard = fixture.control.access_journal.lock().unwrap();
                    panic!("simulate hold management audit failure");
                })
                .join()
                .is_err()
        );
    });
    let failed = request_json(
        &router(fixture.control),
        mutation(path, "http-hold-audit-recovery", body),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(failed["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(failed.get("hold_id").is_none());
    let durable: (String, i64) = sqlx::query_as(
        "SELECT h.created_event_id,(SELECT count(*) FROM xshield.audit_outbox o
         WHERE o.event_id=h.created_event_id AND o.event_type='evidence.hold.created')
         FROM xshield.case_evidence_holds h WHERE h.tenant_id=$1 AND h.artifact_id=$2",
    )
    .bind(context.tenant.as_str())
    .bind(body["artifact_id"].as_str().unwrap())
    .fetch_one(&context.pool)
    .await
    .unwrap();
    assert_eq!(durable.1, 1);
    let recovered = request_json(
        app,
        mutation(path, "http-hold-audit-recovery", body),
        StatusCode::OK,
    )
    .await;
    assert_eq!(recovered["replayed"], true);
    assert_eq!(recovered["hold_id"], durable.0);
}

async fn assert_disconnect(
    context: &HoldContext,
    app: &axum::Router,
    case: &str,
    body: &Value,
    capacity: &Arc<tokio::sync::Semaphore>,
    directory: &Path,
) {
    let mut blocker = context.pool.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query(
        "SELECT 1 FROM xshield.investigation_cases WHERE tenant_id=$1 AND case_id=$2 FOR UPDATE",
    )
    .bind(context.tenant.as_str())
    .bind(case)
    .execute(&mut *blocker)
    .await
    .unwrap();
    let path = format!("/control/v1/cases/{case}/holds");
    let pending = tokio::spawn(app.clone().oneshot(mutation(
        &path,
        "http-hold-disconnect-0001",
        body,
    )));
    // Eventually-true observation of the lock queue: generous so a loaded machine
    // does not fail the test; a real regression still fails at the bound.
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let queued: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))",
            ).bind(pid).fetch_one(&context.pool).await.unwrap();
            if queued { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    assert_eq!(capacity.available_permits(), 0);
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert_eq!(capacity.available_permits(), 0);
    let busy = request_json(
        app,
        authenticated_path(&path),
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;
    assert_eq!(busy["error_code"], "CONTROL_EVIDENCE_HOLD_BUSY");
    blocker.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while capacity.available_permits() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let events = read_access_events(directory);
    assert_eq!(
        events
            .iter()
            .filter(
                |event| event["event_type"] == "console.evidence.hold.created"
                    && event["payload"]["reason_code"] == "CONTROL_EVIDENCE_HOLD_CREATED"
                    && event["payload"]["target_artifact_id"] == body["artifact_id"]
            )
            .count(),
        1
    );
    let replay = request_json(
        app,
        mutation(&path, "http-hold-disconnect-0001", body),
        StatusCode::OK,
    )
    .await;
    assert_eq!(replay["replayed"], true);
}

fn assert_hold_audit(directory: &Path, artifact: &str, case: &str, hold: &str) {
    let events = read_access_events(directory);
    for event in events.iter().filter(|event| {
        event["event_type"]
            .as_str()
            .unwrap()
            .starts_with("console.evidence.hold.")
    }) {
        assert_eq!(event["schema_version"], 3);
        assert_eq!(event["payload"]["subject_ref"], ADMIN);
        assert!(event["request_id"].is_string());
        assert!(!event.to_string().contains(CREATE_KEY));
        assert!(!event.to_string().contains("Preserve case evidence"));
        if event["payload"]["outcome"] != "PASS" {
            assert_eq!(event["evidence_refs"], json!([]));
        }
    }
    let created = events
        .iter()
        .find(|event| {
            event["payload"]["target_hold_id"] == hold
                && event["payload"]["reason_code"] == "CONTROL_EVIDENCE_HOLD_CREATED"
        })
        .unwrap();
    assert_eq!(created["payload"]["target_case_id"], case);
    assert_eq!(created["payload"]["target_artifact_id"], artifact);
    assert_eq!(created["evidence_refs"], json!([artifact]));
}
