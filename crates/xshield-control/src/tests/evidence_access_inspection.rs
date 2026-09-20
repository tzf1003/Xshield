//! Access-request history, authorization, bounded reads, and durable audit barriers.

use super::*;
use std::sync::Arc;
use tokio::sync::Semaphore;

const ACCESS: &str = "access_018f2a3b-4c5d-7000-8000-000000000981";
const PATH: &str = "/control/v1/evidence-access-requests/{access_request_id}";
const JUSTIFICATION: &str = "Private investigation justification";
const REASON: &str = "Private independent decision reason";
const STORE_ERROR: &str = "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE";
// The table-lock fault must not overlap another history test in this module.
static DATABASE_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn request(id: &str) -> Request<Body> {
    Request::get(format!("/control/v1/evidence-access-requests/{id}"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

fn remove_fixture(directory: &Path) {
    fs::remove_dir_all(directory.parent().unwrap()).unwrap();
}

fn assert_audit(event: &Value, code: &str, outcome: &str, access: Option<&str>) {
    assert_eq!(event["event_type"], "console.evidence.access.read");
    assert_eq!(event["payload"]["method"], "GET");
    assert_eq!(event["payload"]["path"], PATH);
    assert_eq!(event["payload"]["reason_code"], code);
    assert_eq!(event["payload"]["outcome"], outcome);
    assert_eq!(event["payload"]["target_access_request_id"], json!(access));
    for forbidden in [
        TOKEN,
        JUSTIFICATION,
        REASON,
        "decision_reason",
        "requested_by",
    ] {
        assert!(
            !event.to_string().contains(forbidden),
            "audit leaked {forbidden}"
        );
    }
    if outcome != "PASS" {
        assert!(event["payload"]["target_case_id"].is_null());
        assert!(event["payload"]["target_artifact_id"].is_null());
        assert_eq!(event["evidence_refs"], json!([]));
    }
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
async fn evidence_access_inspection_validates_inputs_before_shared_admission() {
    let fixture = Fixture::new(100, ManagementRole::Investigator);
    let permit = fixture
        .control
        .case_evidence_capacity
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let app = router(fixture.control);
    let mut attempts = Vec::new();
    for id in [
        "bad".to_owned(),
        "%FF".to_owned(),
        ACCESS.to_uppercase(),
        ACCESS.replace("7000", "4000"),
        MISSING_ARTIFACT_ID.to_owned(),
    ] {
        attempts.push((request(&id), "CONTROL_EVIDENCE_ACCESS_ID_INVALID", None));
    }
    for suffix in ["?", "?tenant_id=other", "?cursor=ignored"] {
        attempts.push((
            request(&format!("{ACCESS}{suffix}")),
            "CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID",
            Some(ACCESS),
        ));
    }
    for body in ["x".to_owned(), "{}".to_owned(), "x".repeat(8192)] {
        let mut input = request(ACCESS);
        *input.body_mut() = Body::from(body);
        attempts.push((
            input,
            "CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID",
            Some(ACCESS),
        ));
    }
    let mut expected = Vec::new();
    for (input, code, target) in attempts {
        let response = response_json(
            app.clone().oneshot(input).await.unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(response["error_code"], code);
        expected.push((code, target));
    }
    drop(app);
    drop(permit);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), expected.len());
    for (event, (code, target)) in events.iter().zip(expected) {
        assert_audit(event, code, "DENY", target);
    }
    remove_fixture(&fixture.access_directory);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn evidence_access_inspection_auth_role_scope_rate_and_shared_capacity() {
    for scenario in [
        "missing",
        "invalid",
        "duplicate",
        "expired",
        "future",
        "observer",
        "admin",
        "tenant",
        "site",
        "rate",
        "busy",
        "store",
        "reader",
        "approver",
        "audit",
    ] {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let mut fixture = Fixture::with_catalog(
            1,
            ManagementRole::Investigator,
            PostgresIdentityStore::from_pool(pool),
            1,
        );
        let mut input = request(ACCESS);
        let mut permit = None;
        let (status, code, target) = match scenario {
            "missing" | "invalid" | "duplicate" | "expired" | "future" => {
                match scenario {
                    "missing" => {
                        input.headers_mut().remove(AUTHORIZATION);
                    }
                    "invalid" => {
                        input
                            .headers_mut()
                            .insert(AUTHORIZATION, "Bearer wrong".parse().unwrap());
                    }
                    "duplicate" => {
                        input
                            .headers_mut()
                            .append(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
                    }
                    "expired" => fixture.control.config.credential.expires_at = 1,
                    _ => fixture.control.config.credential.issued_at = u64::MAX,
                }
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED", None)
            }
            "observer" | "admin" | "tenant" | "site" => {
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [match scenario {
                        "observer" => ManagementRole::Observer,
                        "admin" => ManagementRole::SystemAdmin,
                        _ => ManagementRole::SensitiveEvidenceApprover,
                    }],
                    [(
                        TenantId::parse(if scenario == "tenant" {
                            "foreign"
                        } else {
                            "tenant_a"
                        })
                        .unwrap(),
                        SiteId::parse(if scenario == "site" {
                            "foreign"
                        } else {
                            "site_a"
                        })
                        .unwrap(),
                    )],
                )
                .unwrap();
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED", None)
            }
            "rate" => {
                fixture.control.rate.lock().unwrap().used = 1;
                (StatusCode::TOO_MANY_REQUESTS, "CONTROL_RATE_LIMITED", None)
            }
            "busy" => {
                permit = Some(
                    fixture
                        .control
                        .case_evidence_capacity
                        .clone()
                        .acquire_owned()
                        .await
                        .unwrap(),
                );
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_EVIDENCE_ACCESS_BUSY",
                    Some(ACCESS),
                )
            }
            "audit" => {
                poison_audit(&fixture.control);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "AUDIT_DURABILITY_FAILED",
                    None,
                )
            }
            _ => {
                if scenario != "store" {
                    fixture.control.config.principal = ManagementPrincipal::new(
                        "operator-1",
                        [if scenario == "reader" {
                            ManagementRole::SensitiveEvidenceReader
                        } else {
                            ManagementRole::SensitiveEvidenceApprover
                        }],
                        [(
                            TenantId::parse("tenant_a").unwrap(),
                            SiteId::parse("site_a").unwrap(),
                        )],
                    )
                    .unwrap();
                }
                (StatusCode::SERVICE_UNAVAILABLE, STORE_ERROR, Some(ACCESS))
            }
        };
        let result = response_json(
            router(fixture.control).oneshot(input).await.unwrap(),
            status,
        )
        .await;
        assert_eq!(result["error_code"], code, "{scenario}");
        assert!(result.get("access_request").is_none());
        if scenario != "audit" {
            let events = read_access_events(&fixture.access_directory);
            assert_eq!(events.len(), 1);
            assert_audit(
                &events[0],
                code,
                if status.is_server_error() {
                    "ERROR"
                } else {
                    "DENY"
                },
                target,
            );
        }
        drop(permit);
        remove_fixture(&fixture.access_directory);
    }
}

struct Context {
    pool: sqlx::PgPool,
    tenant: TenantId,
    case: String,
    artifact: String,
    access: String,
    directory: std::path::PathBuf,
}

fn scope_fixture(
    fixture: &mut Fixture,
    tenant: &TenantId,
    subject: &str,
    roles: &[ManagementRole],
) {
    fixture.control.config.tenant_id = tenant.clone();
    fixture.control.config.principal = ManagementPrincipal::new(
        subject,
        roles.iter().copied(),
        [(tenant.clone(), fixture.control.config.site_id.clone())],
    )
    .unwrap();
    fixture
        .control
        .config
        .limits
        .max_pending_evidence_access_requests = 4;
}

impl Context {
    async fn new() -> Self {
        let pool = sqlx::PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let tenant =
            TenantId::parse(format!("tenant_inspect_{}", Uuid::now_v7().simple())).unwrap();
        let mut fixture =
            Fixture::with_case_catalog(PostgresIdentityStore::from_pool(pool.clone()), 10);
        scope_fixture(
            &mut fixture,
            &tenant,
            "operator-1",
            &[ManagementRole::Investigator],
        );
        let vault_root = fixture.access_directory.parent().unwrap().join("vault");
        private_directory(&vault_root);
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&vault_root, "inspection-key", 1024, 30).unwrap(),
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
                    "inspection-case-key",
                    r#"{"purpose":"Inspection regression"}"#,
                ))
                .await
                .unwrap(),
            StatusCode::CREATED,
        )
        .await;
        let case = created["case_id"].as_str().unwrap().to_owned();
        let requested = response_json(
            app.oneshot(evidence_access_request_owned(
                &artifact,
                "inspection-request-key",
                json!({"case_id":case,"access_kind":"sensitive_raw","justification":JUSTIFICATION})
                    .to_string(),
            ))
            .await
            .unwrap(),
            StatusCode::CREATED,
        )
        .await;
        Self {
            pool,
            tenant,
            case,
            artifact,
            access: requested["access_request_id"].as_str().unwrap().to_owned(),
            directory: fixture.access_directory,
        }
    }

    fn fixture(&self, pool: &sqlx::PgPool, subject: &str, roles: &[ManagementRole]) -> Fixture {
        let mut fixture = Fixture::with_decision_catalog(
            PostgresIdentityStore::from_pool(pool.clone()),
            subject,
            roles[0],
        );
        scope_fixture(&mut fixture, &self.tenant, subject, roles);
        fixture
    }

    async fn inspect(
        &self,
        subject: &str,
        roles: &[ManagementRole],
        access: &str,
        status: StatusCode,
    ) -> Value {
        let fixture = self.fixture(&self.pool, subject, roles);
        let result = response_json(
            router(fixture.control)
                .oneshot(request(access))
                .await
                .unwrap(),
            status,
        )
        .await;
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        let code = if status == StatusCode::OK {
            "CONTROL_EVIDENCE_ACCESS_READ"
        } else {
            "CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE"
        };
        assert_audit(
            &events[0],
            code,
            if status == StatusCode::OK {
                "PASS"
            } else {
                "DENY"
            },
            Some(access),
        );
        assert_eq!(events[0]["request_id"], result["request_id"]);
        if status == StatusCode::OK {
            assert_eq!(events[0]["payload"]["target_case_id"], self.case);
            assert_eq!(events[0]["payload"]["target_artifact_id"], self.artifact);
            assert_eq!(events[0]["evidence_refs"], json!([self.artifact]));
            if subject != "operator-1" {
                assert!(!events[0].to_string().contains("operator-1"));
            }
            if subject != "independent-approver" {
                assert!(!events[0].to_string().contains("independent-approver"));
            }
        } else {
            assert_eq!(result["error_code"], code);
            assert!(result.get("access_request").is_none());
        }
        remove_fixture(&fixture.access_directory);
        result
    }

    async fn decide(&self, access: &str, decision: &str) {
        let fixture = self.fixture(
            &self.pool,
            "independent-approver",
            &[ManagementRole::SensitiveEvidenceApprover],
        );
        let body = if decision == "approve" {
            json!({"reason":REASON,"ttl_seconds":300})
        } else {
            json!({"reason":REASON})
        };
        response_json(
            router(fixture.control)
                .oneshot(evidence_access_decision_request(
                    access,
                    decision,
                    &format!("inspection-{decision}-key"),
                    &body.to_string(),
                ))
                .await
                .unwrap(),
            StatusCode::OK,
        )
        .await;
        remove_fixture(&fixture.access_directory);
    }

    async fn versions(&self) -> Vec<(String, String, String)> {
        sqlx::query_as("SELECT 'access', access_request_id, xmin::text FROM xshield.evidence_access_requests WHERE tenant_id=$1
            UNION ALL SELECT 'case', case_id, xmin::text FROM xshield.investigation_cases WHERE tenant_id=$1
            UNION ALL SELECT 'closure', case_id, xmin::text FROM xshield.case_closures WHERE tenant_id=$1
            UNION ALL SELECT 'artifact', artifact_id, xmin::text FROM xshield.artifact_catalog WHERE tenant_id=$1
            UNION ALL SELECT 'outbox', event_id, xmin::text FROM xshield.audit_outbox WHERE tenant_id=$1 ORDER BY 1,2")
            .bind(self.tenant.as_str()).fetch_all(&self.pool).await.unwrap()
    }

    async fn cleanup(self) {
        for sql in [
            "DELETE FROM xshield.evidence_access_requests WHERE tenant_id=$1",
            "DELETE FROM xshield.artifact_catalog WHERE tenant_id=$1",
            "DELETE FROM xshield.case_closures WHERE tenant_id=$1",
            "DELETE FROM xshield.investigation_cases WHERE tenant_id=$1",
            "DELETE FROM xshield.audit_outbox WHERE tenant_id=$1",
        ] {
            sqlx::query(sql)
                .bind(self.tenant.as_str())
                .execute(&self.pool)
                .await
                .unwrap();
        }
        self.pool.close().await;
        remove_fixture(&self.directory);
    }
}

fn assert_snapshot(context: &Context, result: &Value, access: &str, status: &str) {
    assert_eq!(result["schema_version"], 3);
    assert_eq!(result["tenant_id"], context.tenant.as_str());
    assert_eq!(result["site_id"], "site_a");
    assert_eq!(result["max_approval_ttl_seconds"], 900);
    let as_of = result["as_of"].as_str().unwrap();
    assert_eq!(as_of.len(), 27);
    chrono::DateTime::parse_from_rfc3339(as_of).unwrap();
    let row = &result["access_request"];
    assert_eq!(row["access_request_id"], access);
    assert_eq!(row["case_id"], context.case);
    assert_eq!(row["artifact_id"], context.artifact);
    assert_eq!(row["requested_by"], "operator-1");
    assert_eq!(row["access_kind"], "sensitive_raw");
    assert_eq!(row["justification"], JUSTIFICATION);
    assert_eq!(row["stored_status"], status);
    assert!(
        row["requested_event_id"]
            .as_str()
            .unwrap()
            .starts_with("ev_")
    );
    chrono::DateTime::parse_from_rfc3339(row["requested_at"].as_str().unwrap()).unwrap();
    let mut keys: Vec<_> = row
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let mut expected = vec![
        "access_request_id",
        "case_id",
        "artifact_id",
        "requested_by",
        "access_kind",
        "justification",
        "stored_status",
        "requested_at",
        "requested_event_id",
        "decided_by",
        "decision_reason",
        "decision_ttl_seconds",
        "decision_event_id",
        "decided_at",
        "access_expires_at",
        "case_status",
        "artifact_status",
        "artifact_expires_at",
        "artifact_time_expired",
        "capability_time_expired",
    ];
    expected.sort_unstable();
    assert_eq!(keys, expected);
    for forbidden in [
        "locator",
        "hash",
        "key_ref",
        "manifest",
        "plaintext",
        "idempotency_digest",
        "request_digest",
    ] {
        assert!(!result.to_string().contains(forbidden));
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn evidence_access_inspection_reads_owned_and_approved_history_without_mutation() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
    let before = context.versions().await;
    for (subject, roles) in [
        ("operator-1", vec![ManagementRole::Investigator]),
        ("operator-1", vec![ManagementRole::SensitiveEvidenceReader]),
        (
            "independent-approver",
            vec![ManagementRole::SensitiveEvidenceApprover],
        ),
        (
            "independent-approver",
            vec![
                ManagementRole::Investigator,
                ManagementRole::SensitiveEvidenceApprover,
            ],
        ),
    ] {
        let pending = context
            .inspect(subject, &roles, &context.access, StatusCode::OK)
            .await;
        assert_snapshot(&context, &pending, &context.access, "pending");
        for field in [
            "decided_by",
            "decision_reason",
            "decision_ttl_seconds",
            "decision_event_id",
            "decided_at",
            "access_expires_at",
            "capability_time_expired",
        ] {
            assert_eq!(pending["access_request"].get(field), Some(&Value::Null));
        }
        assert_eq!(pending["access_request"]["case_status"], "open");
        assert_eq!(pending["access_request"]["artifact_status"], "active");
        assert_eq!(pending["access_request"]["artifact_time_expired"], false);
    }
    for role in [
        ManagementRole::Investigator,
        ManagementRole::SensitiveEvidenceReader,
    ] {
        context
            .inspect("stranger", &[role], &context.access, StatusCode::NOT_FOUND)
            .await;
    }
    context
        .inspect(
            "operator-1",
            &[ManagementRole::Investigator],
            ACCESS,
            StatusCode::NOT_FOUND,
        )
        .await;
    let mut foreign = context.fixture(
        &context.pool,
        "independent-approver",
        &[ManagementRole::SensitiveEvidenceApprover],
    );
    scope_fixture(
        &mut foreign,
        &TenantId::parse("foreign_inspection_scope").unwrap(),
        "independent-approver",
        &[ManagementRole::SensitiveEvidenceApprover],
    );
    let unavailable = response_json(
        router(foreign.control)
            .oneshot(request(&context.access))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_eq!(
        unavailable["error_code"],
        "CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE"
    );
    let events = read_access_events(&foreign.access_directory);
    assert_audit(
        &events[0],
        "CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE",
        "DENY",
        Some(&context.access),
    );
    remove_fixture(&foreign.access_directory);
    assert_eq!(before, context.versions().await);

    context.decide(&context.access, "approve").await;
    let approved_before = context.versions().await;
    let approved = context
        .inspect(
            "operator-1",
            &[ManagementRole::Investigator],
            &context.access,
            StatusCode::OK,
        )
        .await;
    assert_snapshot(&context, &approved, &context.access, "approved");
    assert_eq!(
        approved["access_request"]["decided_by"],
        "independent-approver"
    );
    assert_eq!(approved["access_request"]["decision_reason"], REASON);
    assert_eq!(approved["access_request"]["decision_ttl_seconds"], 300);
    assert_eq!(approved["access_request"]["capability_time_expired"], false);
    assert_eq!(approved_before, context.versions().await);

    let fixture = context.fixture(&context.pool, "operator-1", &[ManagementRole::Investigator]);
    let second = response_json(router(fixture.control).oneshot(evidence_access_request_owned(&context.artifact,
        "inspection-second-request", json!({"case_id":context.case,"access_kind":"sensitive_raw","justification":JUSTIFICATION}).to_string()))
        .await.unwrap(), StatusCode::CREATED).await;
    remove_fixture(&fixture.access_directory);
    let denied_id = second["access_request_id"].as_str().unwrap();
    context.decide(denied_id, "deny").await;
    let denied_before = context.versions().await;
    let denied = context
        .inspect(
            "operator-1",
            &[ManagementRole::SensitiveEvidenceReader],
            denied_id,
            StatusCode::OK,
        )
        .await;
    assert_snapshot(&context, &denied, denied_id, "denied");
    assert_eq!(denied["access_request"]["decision_reason"], REASON);
    for field in [
        "decision_ttl_seconds",
        "access_expires_at",
        "capability_time_expired",
    ] {
        assert_eq!(denied["access_request"].get(field), Some(&Value::Null));
    }
    assert_eq!(denied_before, context.versions().await);

    let fixture = context.fixture(&context.pool, "operator-1", &[ManagementRole::Investigator]);
    let close = Request::post(format!("/control/v1/cases/{}/close", context.case))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(CONTENT_TYPE, "application/json")
        .header("idempotency-key", "inspection-close-key")
        .body(Body::from(r#"{"reason":"Investigation completed"}"#))
        .unwrap();
    response_json(
        router(fixture.control).oneshot(close).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    remove_fixture(&fixture.access_directory);
    sqlx::query("UPDATE xshield.artifact_catalog SET status='deleted', deleted_at=clock_timestamp(), recorded_at=clock_timestamp()-interval '1 hour', expires_at=clock_timestamp()-interval '1 minute' WHERE tenant_id=$1")
        .bind(context.tenant.as_str()).execute(&context.pool).await.unwrap();
    sqlx::query("UPDATE xshield.evidence_access_requests SET decided_at=clock_timestamp()-interval '10 minutes', access_expires_at=clock_timestamp()-interval '9 minutes' WHERE tenant_id=$1 AND access_request_id=$2")
        .bind(context.tenant.as_str()).bind(&context.access).execute(&context.pool).await.unwrap();
    let historical_before = context.versions().await;
    let history = context
        .inspect(
            "operator-1",
            &[ManagementRole::SensitiveEvidenceReader],
            &context.access,
            StatusCode::OK,
        )
        .await;
    assert_snapshot(&context, &history, &context.access, "approved");
    assert_eq!(history["access_request"]["case_status"], "closed");
    assert_eq!(history["access_request"]["artifact_status"], "deleted");
    assert_eq!(history["access_request"]["artifact_time_expired"], true);
    assert_eq!(history["access_request"]["capability_time_expired"], true);
    assert_eq!(historical_before, context.versions().await);
    for status in ["expired", "revoked"] {
        sqlx::query("UPDATE xshield.evidence_access_requests SET status=$3 WHERE tenant_id=$1 AND access_request_id=$2")
            .bind(context.tenant.as_str()).bind(&context.access).bind(status).execute(&context.pool).await.unwrap();
        let before = context.versions().await;
        let history = context
            .inspect(
                "independent-approver",
                &[ManagementRole::SensitiveEvidenceApprover],
                &context.access,
                StatusCode::OK,
            )
            .await;
        assert_snapshot(&context, &history, &context.access, status);
        assert_eq!(before, context.versions().await);
    }
    context.cleanup().await;
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

async fn single_connection_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_mins(1))
        .connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap()
}

// The exact production handler and body limit keep extraction behavior intact;
// retaining the state lets the test hold only the durable journal barrier.
fn barrier_router(control: Arc<ControlPlane>) -> axum::Router {
    axum::Router::new()
        .route(
            PATH,
            axum::routing::get(crate::evidence_access_inspection::handler),
        )
        .layer(axum::extract::DefaultBodyLimit::max(0))
        .with_state(control)
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_access_inspection_cancellation_retains_admission_through_audit() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
    let before = context.versions().await;
    let pool = single_connection_pool().await;
    let connection = pool.acquire().await.unwrap();
    let fixture = context.fixture(&pool, "operator-1", &[ManagementRole::Investigator]);
    let capacity = fixture.control.case_evidence_capacity.clone();
    let control = Arc::new(fixture.control);
    let journal_control = Arc::clone(&control);
    let (started, start) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let blocker = tokio::task::spawn_blocking(move || {
        let _guard = journal_control.access_journal.lock().unwrap();
        started.send(()).unwrap();
        released.blocking_recv().unwrap();
    });
    start.await.unwrap();
    let app = barrier_router(control);
    let client = tokio::spawn(app.clone().oneshot(request(&context.access)));
    wait_capacity(&capacity, 0).await;
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
    drop(connection);
    // Observe the pool returning to idle while the durable journal barrier
    // remains blocked; the shared operation permit must still be retained.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if pool.num_idle() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(capacity.available_permits(), 0);
    release.send(()).unwrap();
    blocker.await.unwrap();
    wait_capacity(&capacity, 1).await;
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 1);
    assert_audit(
        &events[0],
        "CONTROL_EVIDENCE_ACCESS_READ",
        "PASS",
        Some(&context.access),
    );
    assert_eq!(events[0]["evidence_refs"], json!([context.artifact]));
    assert_eq!(before, context.versions().await);
    remove_fixture(&fixture.access_directory);
    pool.close().await;
    context.cleanup().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_access_inspection_pool_deadline_and_table_lock_are_audited_errors() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
    let before = context.versions().await;
    for scenario in ["pool", "lock"] {
        let pool = single_connection_pool().await;
        let connection = if scenario == "pool" {
            Some(pool.acquire().await.unwrap())
        } else {
            None
        };
        let mut transaction = context.pool.begin().await.unwrap();
        if scenario == "lock" {
            sqlx::query("LOCK TABLE xshield.evidence_access_requests IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        let fixture = context.fixture(&pool, "operator-1", &[ManagementRole::Investigator]);
        let capacity = fixture.control.case_evidence_capacity.clone();
        let started = std::time::Instant::now();
        let maximum = if scenario == "pool" { 19 } else { 8 };
        let response = tokio::time::timeout(
            Duration::from_secs(maximum),
            router(fixture.control).oneshot(request(&context.access)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(if scenario == "pool" { 14 } else { 4 }));
        let result = response_json(response, StatusCode::SERVICE_UNAVAILABLE).await;
        assert_eq!(result["error_code"], STORE_ERROR);
        assert!(result.get("access_request").is_none());
        assert_eq!(capacity.available_permits(), 1);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_audit(&events[0], STORE_ERROR, "ERROR", Some(&context.access));
        transaction.rollback().await.unwrap();
        drop(connection);
        pool.close().await;
        remove_fixture(&fixture.access_directory);
    }
    assert_eq!(before, context.versions().await);
    context.cleanup().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_access_inspection_withholds_success_when_audit_fails() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
    let before = context.versions().await;
    let fixture = context.fixture(&context.pool, "operator-1", &[ManagementRole::Investigator]);
    poison_audit(&fixture.control);
    let result = response_json(
        router(fixture.control)
            .oneshot(request(&context.access))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(result["error_code"], "AUDIT_DURABILITY_FAILED");
    for forbidden in [
        "access_request",
        "justification",
        "requested_by",
        "decided_by",
        "artifact_id",
        "case_id",
    ] {
        assert!(result.get(forbidden).is_none());
    }
    assert!(!result.to_string().contains(JUSTIFICATION));
    assert_eq!(before, context.versions().await);
    remove_fixture(&fixture.access_directory);
    context.cleanup().await;
}
