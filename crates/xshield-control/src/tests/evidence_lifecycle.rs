//! Evidence admission, cancellation, dependency deadlines, and audit barriers.

use super::*;
use std::sync::Arc;
use tokio::sync::Semaphore;

const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000991";
const ACCESS: &str = "access_018f2a3b-4c5d-7000-8000-000000000981";
const KEY: &str = "evidence-lifecycle-key-0001";
const OPERATIONS: [&str; 4] = ["request", "approve", "deny", "read"];

fn role(operation: &str) -> ManagementRole {
    match operation {
        "request" => ManagementRole::Investigator,
        "read" => ManagementRole::SensitiveEvidenceReader,
        _ => ManagementRole::SensitiveEvidenceApprover,
    }
}

fn request(operation: &str, artifact: &str, case: &str, access: &str) -> Request<Body> {
    match operation {
        "request" => evidence_access_request_owned(
            artifact,
            KEY,
            json!({"case_id":case,"access_kind":"sensitive_raw","justification":"Review lifecycle"})
                .to_string(),
        ),
        "read" => evidence_content_request(artifact, access),
        decision => evidence_access_decision_request(
            access,
            decision,
            KEY,
            if decision == "approve" {
                r#"{"reason":"Review approved","ttl_seconds":300}"#
            } else {
                r#"{"reason":"Review denied"}"#
            },
        ),
    }
}

fn event_type(operation: &str) -> &'static str {
    match operation {
        "request" => "evidence.access.requested",
        "approve" => "evidence.access.approved",
        "deny" => "evidence.access.denied",
        _ => "evidence.read",
    }
}

fn store_error(operation: &str) -> &'static str {
    match operation {
        "request" => "CONTROL_EVIDENCE_ACCESS_STORE_UNAVAILABLE",
        "read" => "CONTROL_EVIDENCE_READ_STORE_UNAVAILABLE",
        _ => "CONTROL_EVIDENCE_ACCESS_DECISION_STORE_UNAVAILABLE",
    }
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

fn remove_fixture(directory: &Path) {
    fs::remove_dir_all(directory.parent().unwrap()).unwrap();
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
async fn evidence_lifecycle_rejects_ambiguous_headers_queries_and_bodies_before_admission() {
    for operation in OPERATIONS {
        let fixture = Fixture::new(100, role(operation));
        let permit = fixture
            .control
            .case_evidence_capacity
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        let app = router(fixture.control);
        let mut attempts = Vec::new();
        let mut duplicate_auth = request(operation, MISSING_ARTIFACT_ID, CASE, ACCESS);
        duplicate_auth
            .headers_mut()
            .append(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
        attempts.push((
            duplicate_auth,
            StatusCode::UNAUTHORIZED,
            "CONTROL_AUTH_REQUIRED",
        ));
        let mut duplicate_identity = request(operation, MISSING_ARTIFACT_ID, CASE, ACCESS);
        let (header, value, code) = if operation == "read" {
            (
                EVIDENCE_ACCESS_REQUEST_HEADER,
                ACCESS,
                "CONTROL_EVIDENCE_ACCESS_REQUEST_REQUIRED",
            )
        } else {
            ("idempotency-key", KEY, "CONTROL_IDEMPOTENCY_KEY_INVALID")
        };
        duplicate_identity
            .headers_mut()
            .append(header, value.parse().unwrap());
        attempts.push((duplicate_identity, StatusCode::BAD_REQUEST, code));
        let invalid_code = match operation {
            "request" => "CONTROL_EVIDENCE_ACCESS_REQUEST_INVALID",
            "read" => "CONTROL_EVIDENCE_READ_REQUEST_INVALID",
            _ => "CONTROL_EVIDENCE_ACCESS_DECISION_INVALID",
        };
        for query in ["?scope=other", "?"] {
            let mut queried = request(operation, MISSING_ARTIFACT_ID, CASE, ACCESS);
            *queried.uri_mut() = format!("{}{query}", queried.uri()).parse().unwrap();
            attempts.push((queried, StatusCode::BAD_REQUEST, invalid_code));
        }
        if operation != "read" {
            for body in [
                "{}".to_owned(),
                r#"{"reason":"one","reason":"two"}"#.to_owned(),
                json!({"reason":"x".repeat(4096)}).to_string(),
            ] {
                let mut invalid = request(operation, MISSING_ARTIFACT_ID, CASE, ACCESS);
                *invalid.body_mut() = Body::from(body);
                attempts.push((invalid, StatusCode::BAD_REQUEST, invalid_code));
            }
            let mut invalid = request(operation, MISSING_ARTIFACT_ID, CASE, ACCESS);
            let invalid_body = if operation == "request" {
                json!({"case_id":CASE,"access_kind":"sensitive_raw","justification":" padded "})
            } else if operation == "approve" {
                json!({"reason":"Review approved","ttl_seconds":0})
            } else {
                json!({"reason":" padded "})
            };
            *invalid.body_mut() = Body::from(invalid_body.to_string());
            attempts.push((invalid, StatusCode::BAD_REQUEST, invalid_code));
        }
        let count = attempts.len();
        for (input, status, code) in attempts {
            let body = response_json(app.clone().oneshot(input).await.unwrap(), status).await;
            assert_eq!(body["error_code"], code, "{operation}");
        }
        drop(app);
        drop(permit);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), count);
        for event in events {
            assert_eq!(event["event_type"], event_type(operation));
            assert_eq!(event["payload"]["outcome"], "DENY");
            assert!(!event.to_string().contains(KEY));
            assert!(!event.to_string().contains(TOKEN));
        }
        remove_fixture(&fixture.access_directory);
    }
}

#[tokio::test]
async fn evidence_lifecycle_busy_store_failure_and_audit_failure_are_closed_and_classified() {
    for operation in OPERATIONS {
        for scenario in ["busy", "store", "audit"] {
            let mut fixture = Fixture::new(100, role(operation));
            let permit = if scenario == "busy" {
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
            let pool = sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
                .unwrap();
            pool.close().await;
            fixture.control.catalog = PostgresIdentityStore::from_pool(pool);
            if scenario == "audit" {
                poison_audit(&fixture.control);
            }
            let (status, code) = match scenario {
                "busy" => (
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_EVIDENCE_ACCESS_BUSY",
                ),
                "audit" => (StatusCode::SERVICE_UNAVAILABLE, "AUDIT_DURABILITY_FAILED"),
                _ => (StatusCode::SERVICE_UNAVAILABLE, store_error(operation)),
            };
            let body = response_json(
                router(fixture.control)
                    .oneshot(request(operation, MISSING_ARTIFACT_ID, CASE, ACCESS))
                    .await
                    .unwrap(),
                status,
            )
            .await;
            assert_eq!(body["error_code"], code, "{operation}/{scenario}");
            assert!(body.get("access_request_id").is_none());
            assert!(body.get("bytes_read").is_none());
            if scenario != "audit" {
                let events = read_access_events(&fixture.access_directory);
                assert_eq!(events.len(), 1);
                assert_eq!(events[0]["payload"]["reason_code"], code);
                assert_eq!(
                    events[0]["payload"]["outcome"],
                    if scenario == "busy" { "DENY" } else { "ERROR" }
                );
            }
            drop(permit);
            remove_fixture(&fixture.access_directory);
        }
    }
}

struct Context {
    pool: sqlx::PgPool,
    tenant: TenantId,
    case: String,
    artifact: String,
    access: String,
    port: Arc<EvidenceReadPort>,
    directory: std::path::PathBuf,
}

impl Context {
    async fn new() -> Self {
        let pool = sqlx::PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let tenant =
            TenantId::parse(format!("tenant_evidence_{}", Uuid::now_v7().simple())).unwrap();
        let mut fixture =
            Fixture::with_case_catalog(PostgresIdentityStore::from_pool(pool.clone()), 10);
        scope_fixture(
            &mut fixture,
            &tenant,
            "operator-1",
            ManagementRole::Investigator,
        );
        let vault_root = fixture.access_directory.parent().unwrap().join("vault");
        private_directory(&vault_root);
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&vault_root, "lifecycle-key", 1024, 30).unwrap(),
            EvidenceKey::from_hex(
                "5555555555555555555555555555555555555555555555555555555555555555",
            )
            .unwrap(),
        )
        .unwrap();
        let artifact = publish_test_artifact(
            &fixture.control.catalog,
            &vault,
            &tenant,
            &SiteId::parse("site_a").unwrap(),
            &RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap(),
            1,
        )
        .await;
        let app = router(fixture.control);
        let created = response_json(
            app.clone()
                .oneshot(case_request(
                    "lifecycle-seed-case",
                    r#"{"purpose":"Lifecycle regression"}"#,
                ))
                .await
                .unwrap(),
            StatusCode::CREATED,
        )
        .await;
        let case = created["case_id"].as_str().unwrap().to_owned();
        let mut seed = request("request", &artifact, &case, ACCESS);
        seed.headers_mut()
            .insert("idempotency-key", "lifecycle-seed-access".parse().unwrap());
        let requested = response_json(app.oneshot(seed).await.unwrap(), StatusCode::CREATED).await;
        Self {
            pool,
            tenant,
            case,
            artifact,
            access: requested["access_request_id"].as_str().unwrap().to_owned(),
            port: Arc::new(EvidenceReadPort::new(vault)),
            directory: fixture.access_directory,
        }
    }

    fn fixture(&self, operation: &str, pool: &sqlx::PgPool) -> Fixture {
        let subject = if matches!(operation, "approve" | "deny") {
            "independent-approver"
        } else {
            "operator-1"
        };
        let mut fixture = Fixture::with_decision_catalog(
            PostgresIdentityStore::from_pool(pool.clone()),
            subject,
            role(operation),
        );
        scope_fixture(&mut fixture, &self.tenant, subject, role(operation));
        // Retain the seeded request and allow the request-under-test to commit.
        fixture
            .control
            .config
            .limits
            .max_pending_evidence_access_requests = 2;
        fixture.control.evidence_read = Some(self.port.clone());
        fixture
    }

    fn request(&self, operation: &str) -> Request<Body> {
        request(operation, &self.artifact, &self.case, &self.access)
    }

    async fn outbox_count(&self, operation: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM xshield.audit_outbox WHERE tenant_id=$1 AND event_type=$2",
        )
        .bind(self.tenant.as_str())
        .bind(event_type(operation))
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn approve(&self) {
        let fixture = self.fixture("approve", &self.pool);
        response_json(
            router(fixture.control)
                .oneshot(self.request("approve"))
                .await
                .unwrap(),
            StatusCode::OK,
        )
        .await;
        remove_fixture(&fixture.access_directory);
    }

    async fn cleanup(self) {
        for statement in [
            "DELETE FROM xshield.evidence_access_requests WHERE tenant_id=$1",
            "DELETE FROM xshield.artifact_catalog WHERE tenant_id=$1",
            "DELETE FROM xshield.investigation_cases WHERE tenant_id=$1",
            "DELETE FROM xshield.audit_outbox WHERE tenant_id=$1",
        ] {
            sqlx::query(statement)
                .bind(self.tenant.as_str())
                .execute(&self.pool)
                .await
                .unwrap();
        }
        drop(self.port);
        remove_fixture(&self.directory);
    }
}

fn scope_fixture(fixture: &mut Fixture, tenant: &TenantId, subject: &str, role: ManagementRole) {
    fixture.control.config.tenant_id = tenant.clone();
    fixture.control.config.principal = ManagementPrincipal::new(
        subject,
        [role],
        [(tenant.clone(), fixture.control.config.site_id.clone())],
    )
    .unwrap();
}

async fn wait_capacity(capacity: &Semaphore, permits: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while capacity.available_permits() != permits {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn block_audit(
    control: &Arc<ControlPlane>,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let control = Arc::clone(control);
    let (started, start) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let task = tokio::task::spawn_blocking(move || {
        let _guard = control.access_journal.lock().unwrap();
        started.send(()).unwrap();
        released.blocking_recv().unwrap();
    });
    start.await.unwrap();
    (release, task)
}

// Retain the state only to control the journal barrier; requests still use the
// production Axum handlers, extractors, and body limit.
fn barrier_router(control: Arc<ControlPlane>) -> axum::Router {
    use axum::{
        extract::DefaultBodyLimit,
        middleware::from_fn_with_state,
        routing::{get, post},
    };
    axum::Router::new()
        .route(
            crate::EVIDENCE_ACCESS_PATH,
            post(crate::evidence_access_handler),
        )
        .route(
            crate::EVIDENCE_ACCESS_APPROVE_PATH,
            post(crate::evidence_access_approve_handler),
        )
        .route(
            crate::EVIDENCE_ACCESS_DENY_PATH,
            post(crate::evidence_access_deny_handler),
        )
        .route(
            crate::EVIDENCE_CONTENT_PATH,
            get(crate::evidence_content_handler),
        )
        .layer(DefaultBodyLimit::max(crate::CASE_BODY_BYTES_MAX))
        .with_state(Arc::clone(&control))
        .layer(from_fn_with_state(
            control,
            crate::identity::auth_middleware,
        ))
}

async fn single_connection_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_mins(1))
        .connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_lifecycle_post_cancellation_commits_and_holds_shared_admission_through_audit() {
    for operation in ["request", "approve", "deny"] {
        let context = Context::new().await;
        let before = context.outbox_count(operation).await;
        let pool = single_connection_pool().await;
        let connection = pool.acquire().await.unwrap();
        let fixture = context.fixture(operation, &pool);
        let capacity = fixture.control.case_evidence_capacity.clone();
        let control = Arc::new(fixture.control);
        let (release_audit, audit_blocker) = block_audit(&control).await;
        let app = barrier_router(control);
        let client = tokio::spawn(app.clone().oneshot(context.request(operation)));
        wait_capacity(&capacity, 0).await;
        client.abort();
        assert!(client.await.unwrap_err().is_cancelled());
        assert_eq!(capacity.available_permits(), 0);
        drop(connection);
        tokio::time::timeout(Duration::from_secs(5), async {
            while context.outbox_count(operation).await != before + 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            capacity.available_permits(),
            0,
            "commit must retain admission until audit"
        );
        release_audit.send(()).unwrap();
        audit_blocker.await.unwrap();
        wait_capacity(&capacity, 1).await;
        let replay = response_json(
            app.oneshot(context.request(operation)).await.unwrap(),
            StatusCode::OK,
        )
        .await;
        assert_eq!(replay["replayed"], true);
        assert_eq!(context.outbox_count(operation).await, before + 1);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 2);
        for event in events {
            assert_eq!(event["event_type"], event_type(operation));
            assert_eq!(event["payload"]["outcome"], "PASS");
            assert_eq!(event["payload"]["target_artifact_id"], context.artifact);
            assert_eq!(event["payload"]["target_case_id"], context.case);
            assert_eq!(event["evidence_refs"], json!([context.artifact]));
        }
        remove_fixture(&fixture.access_directory);
        pool.close().await;
        context.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_lifecycle_committed_posts_recover_original_keys_after_audit_failure() {
    for operation in ["request", "approve", "deny"] {
        let context = Context::new().await;
        let before = context.outbox_count(operation).await;
        let failed = context.fixture(operation, &context.pool);
        poison_audit(&failed.control);
        let error = response_json(
            router(failed.control)
                .oneshot(context.request(operation))
                .await
                .unwrap(),
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
        assert_eq!(error["error_code"], "AUDIT_DURABILITY_FAILED");
        assert!(error.get("access_request_id").is_none());
        assert_eq!(context.outbox_count(operation).await, before + 1);
        let recovered = context.fixture(operation, &context.pool);
        let replay = response_json(
            router(recovered.control)
                .oneshot(context.request(operation))
                .await
                .unwrap(),
            StatusCode::OK,
        )
        .await;
        assert_eq!(replay["replayed"], true);
        assert_eq!(context.outbox_count(operation).await, before + 1);
        let events = read_access_events(&recovered.access_directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["payload"]["outcome"], "PASS");
        remove_fixture(&failed.access_directory);
        remove_fixture(&recovered.access_directory);
        context.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_lifecycle_database_deadline_includes_pool_wait_and_audits_error() {
    let context = Context::new().await;
    let pool = single_connection_pool().await;
    let connection = pool.acquire().await.unwrap();
    let mut clients = Vec::new();
    for operation in OPERATIONS {
        let fixture = context.fixture(operation, &pool);
        let capacity = fixture.control.case_evidence_capacity.clone();
        let started = std::time::Instant::now();
        let client = tokio::spawn(router(fixture.control).oneshot(context.request(operation)));
        clients.push((
            operation,
            client,
            capacity,
            fixture.access_directory,
            started,
        ));
    }
    for (operation, client, capacity, directory, started) in clients {
        let response = tokio::time::timeout(Duration::from_secs(19), client)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(14));
        assert!(started.elapsed() < Duration::from_secs(19));
        let result = response_json(response, StatusCode::SERVICE_UNAVAILABLE).await;
        let code = store_error(operation);
        assert_eq!(result["error_code"], code);
        assert_eq!(capacity.available_permits(), 1);
        let events = read_access_events(&directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["payload"]["outcome"], "ERROR");
        assert_eq!(events[0]["payload"]["reason_code"], code);
        assert!(events[0]["payload"].get("bytes_read").is_none());
        remove_fixture(&directory);
    }
    drop(connection);
    pool.close().await;
    context.cleanup().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_lifecycle_sql_lock_timeout_audits_error_without_mutation() {
    for operation in ["request", "approve", "deny"] {
        let context = Context::new().await;
        let before = context.outbox_count(operation).await;
        let mut blocker = context.pool.begin().await.unwrap();
        let (sql, id) = if operation == "request" {
            (
                "SELECT 1 FROM xshield.investigation_cases WHERE tenant_id=$1 AND case_id=$2 FOR UPDATE",
                &context.case,
            )
        } else {
            (
                "SELECT 1 FROM xshield.evidence_access_requests WHERE tenant_id=$1 AND access_request_id=$2 FOR UPDATE",
                &context.access,
            )
        };
        sqlx::query(sql)
            .bind(context.tenant.as_str())
            .bind(id)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let fixture = context.fixture(operation, &context.pool);
        let started = std::time::Instant::now();
        let response = tokio::time::timeout(
            Duration::from_secs(8),
            router(fixture.control).oneshot(context.request(operation)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(4));
        let error = response_json(response, StatusCode::SERVICE_UNAVAILABLE).await;
        assert_eq!(error["error_code"], store_error(operation));
        assert_eq!(context.outbox_count(operation).await, before);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["payload"]["outcome"], "ERROR");
        blocker.rollback().await.unwrap();
        remove_fixture(&fixture.access_directory);
        context.cleanup().await;
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_lifecycle_read_cancellation_finishes_audit_and_withholds_unaudited_plaintext() {
    let context = Context::new().await;
    context.approve().await;
    let pool = single_connection_pool().await;
    let connection = pool.acquire().await.unwrap();
    let fixture = context.fixture("read", &pool);
    let capacity = fixture.control.case_evidence_capacity.clone();
    let control = Arc::new(fixture.control);
    let (release_audit, audit_blocker) = block_audit(&control).await;
    let app = barrier_router(control);
    let client = tokio::spawn(app.clone().oneshot(context.request("read")));
    wait_capacity(&capacity, 0).await;
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
    drop(connection);
    wait_capacity(&context.port.capacity, 0).await;
    assert_eq!(capacity.available_permits(), 0);
    release_audit.send(()).unwrap();
    audit_blocker.await.unwrap();
    wait_capacity(&capacity, 1).await;
    wait_capacity(&context.port.capacity, 1).await;
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "evidence.read");
    assert_eq!(events[0]["payload"]["outcome"], "PASS");
    assert_eq!(
        events[0]["payload"]["bytes_read"],
        br#"{"approved":true}"#.len()
    );
    remove_fixture(&fixture.access_directory);

    let failed = context.fixture("read", &context.pool);
    poison_audit(&failed.control);
    let response = router(failed.control)
        .oneshot(context.request("read"))
        .await
        .unwrap();
    assert!(response.headers().get(CONTENT_DISPOSITION).is_none());
    let error = response_json(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(error["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(!error.to_string().contains("approved"));
    assert_eq!(context.port.capacity.available_permits(), 1);
    remove_fixture(&failed.access_directory);

    let reader = context.fixture("read", &context.pool);
    let capacity = reader.control.case_evidence_capacity.clone();
    let response = router(reader.control)
        .oneshot(context.request("read"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(capacity.available_permits(), 1);
    assert_eq!(context.port.capacity.available_permits(), 0);
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(&bytes[..], br#"{"approved":true}"#);
    assert_eq!(context.port.capacity.available_permits(), 0);
    drop(bytes);
    assert_eq!(context.port.capacity.available_permits(), 1);
    remove_fixture(&reader.access_directory);
    pool.close().await;
    context.cleanup().await;
}
