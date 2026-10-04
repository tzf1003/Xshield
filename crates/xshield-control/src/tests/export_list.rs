//! Export discovery authorization, cursor isolation, live history and durable read barriers.

use super::evidence_access_inspection::{DATABASE_TEST, scope_fixture};
use super::*;
use crate::CursorError;
use axum::{extract::DefaultBodyLimit, routing::get};
use std::sync::Arc;
use xshield_core::domain::{EvidenceAccessRequestId, ExportId};
use xshield_postgres::{
    EvidenceAccessListView as AccessView,
    InvestigationExportListView::{self, Mine, Review},
};

const PATH: &str = "/control/v1/exports";
const EXPORT: &str = "export_018f2a3b-4c5d-7000-8000-000000000981";
const STORE: &str = "CONTROL_EXPORT_STORE_UNAVAILABLE";
const INVALID: &str = "CONTROL_EXPORT_LIST_REQUEST_INVALID";
const PURPOSE: &str = "Private export purpose";
const REASON: &str = "Private independent decision reason";

fn request(query: &str) -> Request<Body> {
    Request::get(format!("{PATH}{query}"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

async fn json_response(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}

fn cleanup(directory: &Path) {
    fs::remove_dir_all(directory.parent().unwrap()).unwrap();
}

// The journal keeps the caller and the outcome, never the view, a cursor, a
// listed export or another principal.
fn audit(event: &Value, outcome: &str, code: &str) {
    assert_eq!(event["event_type"], "console.export.list");
    assert_eq!(event["payload"]["method"], "GET");
    assert_eq!(event["payload"]["path"], PATH);
    assert_eq!(event["payload"]["outcome"], outcome);
    assert_eq!(event["payload"]["reason_code"], code);
    assert_eq!(event["evidence_refs"], json!([]));
    for (key, value) in event["payload"].as_object().unwrap() {
        if key.starts_with("target_") || matches!(key.as_str(), "query_digest" | "bytes_read") {
            assert!(value.is_null(), "{key}");
        }
    }
    for private in [
        "cursor=",
        "view=",
        "\"view\"",
        "\"cursor\"",
        "requested_by",
        "decided_by",
        "purpose",
        "decision_reason",
        "export_",
        PURPOSE,
        REASON,
        TOKEN,
    ] {
        assert!(
            !event.to_string().contains(private),
            "audit leaked {private}"
        );
    }
}

fn principal(subject: &str, roles: &[ManagementRole]) -> ManagementPrincipal {
    ManagementPrincipal::new(
        subject,
        roles.iter().copied(),
        [(
            TenantId::parse("tenant_a").unwrap(),
            SiteId::parse("site_a").unwrap(),
        )],
    )
    .unwrap()
}

// A closed pool makes every request that reaches the store fail the same,
// observable way, so the status alone separates "authorized" from "refused".
async fn closed_store() -> PostgresIdentityStore {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
        .unwrap();
    pool.close().await;
    PostgresIdentityStore::from_pool(pool)
}

#[tokio::test]
async fn export_list_rejects_noncanonical_input_before_admission() {
    let fixture = Fixture::new(100, ManagementRole::SensitiveEvidenceApprover);
    let id = ExportId::parse(EXPORT).unwrap();
    // Perfectly signed cursors minted for another view or another subject.
    let other_view = fixture
        .control
        .encode_export_list_cursor("operator-1", Review, &id)
        .unwrap();
    let other_subject = fixture
        .control
        .encode_export_list_cursor("operator-2", Mine, &id)
        .unwrap();
    let permit = fixture
        .control
        .case_evidence_capacity
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let app = router(fixture.control);
    let oversized_cursor = format!("?view=mine&cursor={}", "a".repeat(257));
    let mut attempts = Vec::new();
    for query in [
        "",
        "?",
        "?view=",
        "?view=all",
        "?view=Mine",
        "?view=%6dine",
        "?cursor=a&view=mine",
        "?view=mine&view=review",
        "?view=mine&cursor=",
        "?view=mine&limit=2",
        "?view=mine&cursor=a&cursor=b",
        "?view=review&tenant_id=other",
        "?view=review&site_id=other",
        oversized_cursor.as_str(),
    ] {
        attempts.push((request(query), INVALID));
    }
    for body in ["x".to_owned(), "{}".to_owned(), "x".repeat(8192)] {
        let mut input = request("?view=mine");
        *input.body_mut() = Body::from(body);
        attempts.push((input, INVALID));
    }
    attempts.push((
        request("?view=mine&cursor=invalid"),
        "CONTROL_CURSOR_INVALID",
    ));
    attempts.push((
        request(&format!("?view=mine&cursor={other_view}")),
        "CONTROL_CURSOR_INVALID",
    ));
    attempts.push((
        request(&format!("?view=mine&cursor={other_subject}")),
        "CONTROL_CURSOR_INVALID",
    ));
    let mut expected = Vec::new();
    for (input, code) in attempts {
        let response = json_response(
            app.clone().oneshot(input).await.unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(response["error_code"], code);
        assert_eq!(response["retryable"], false);
        assert_eq!(response["next_action"], "restart_query");
        expected.push(code);
    }
    drop(app);
    drop(permit);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), expected.len());
    for (event, code) in events.iter().zip(expected) {
        audit(event, "DENY", code);
    }
    cleanup(&fixture.access_directory);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn export_list_auth_roles_scope_rate_and_capacity() {
    for scenario in [
        "missing",
        "duplicate",
        "invalid",
        "expired",
        "future",
        "session",
        "observer",
        "admin",
        "tenant",
        "site",
        "rate",
        "busy",
        "store",
        "reader",
        "approver",
        "review_reader",
        "review_investigator",
        "review_approver",
    ] {
        let mut fixture =
            Fixture::with_catalog(1, ManagementRole::Investigator, closed_store().await, 1);
        let mut input = request(if scenario.starts_with("review_") {
            "?view=review"
        } else {
            "?view=mine"
        });
        let mut permit = None;
        let (status, code) = match scenario {
            "missing" | "duplicate" | "invalid" | "expired" | "future" => {
                match scenario {
                    "missing" => {
                        input.headers_mut().remove(AUTHORIZATION);
                    }
                    "duplicate" => {
                        input
                            .headers_mut()
                            .append(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
                    }
                    "invalid" => {
                        input
                            .headers_mut()
                            .insert(AUTHORIZATION, "Bearer invalid".parse().unwrap());
                    }
                    "expired" => fixture.control.config.credential.expires_at = 1,
                    _ => fixture.control.config.credential.issued_at = u64::MAX,
                }
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            // A browser-session assertion cannot be verified without the
            // per-process key; this refusal is audited like every other one.
            "session" => {
                fixture.control.auth_context_key = None;
                input
                    .headers_mut()
                    .insert(AUTHORIZATION, "Xshield-Session x.y".parse().unwrap());
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SESSION_UNAVAILABLE",
                )
            }
            "observer" | "admin" | "tenant" | "site" | "review_reader" | "review_investigator" => {
                let role = match scenario {
                    "observer" => ManagementRole::Observer,
                    "admin" => ManagementRole::SystemAdmin,
                    "review_reader" => ManagementRole::SensitiveEvidenceReader,
                    _ => ManagementRole::Investigator,
                };
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [role],
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
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED")
            }
            "rate" => {
                fixture.control.rate.lock().unwrap().used = 1;
                (StatusCode::TOO_MANY_REQUESTS, "CONTROL_RATE_LIMITED")
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
                (StatusCode::TOO_MANY_REQUESTS, "CONTROL_EXPORT_BUSY")
            }
            _ => {
                if scenario != "store" {
                    let role = if scenario == "reader" {
                        ManagementRole::SensitiveEvidenceReader
                    } else {
                        ManagementRole::SensitiveEvidenceApprover
                    };
                    fixture.control.config.principal = principal("operator-1", &[role]);
                }
                (StatusCode::SERVICE_UNAVAILABLE, STORE)
            }
        };
        let result = json_response(
            router(fixture.control).oneshot(input).await.unwrap(),
            status,
        )
        .await;
        assert_eq!(result["error_code"], code, "{scenario}");
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1, "{scenario}");
        audit(
            &events[0],
            if status.is_server_error() {
                "ERROR"
            } else {
                "DENY"
            },
            code,
        );
        drop(permit);
        cleanup(&fixture.access_directory);
    }
}

#[tokio::test]
async fn export_list_role_matrix_admits_exactly_the_documented_roles() {
    for role in [
        ManagementRole::Observer,
        ManagementRole::Investigator,
        ManagementRole::SensitiveEvidenceReader,
        ManagementRole::SensitiveEvidenceApprover,
        ManagementRole::PolicyAuthor,
        ManagementRole::PolicyApprover,
        ManagementRole::ReleaseOperator,
        ManagementRole::AuditAdministrator,
        ManagementRole::KeyAdministrator,
        ManagementRole::SystemAdmin,
    ] {
        for view in [Mine, Review] {
            let allowed = match view {
                Mine => matches!(
                    role,
                    ManagementRole::Investigator
                        | ManagementRole::SensitiveEvidenceReader
                        | ManagementRole::SensitiveEvidenceApprover
                ),
                Review => role == ManagementRole::SensitiveEvidenceApprover,
            };
            let mut fixture =
                Fixture::with_catalog(10, ManagementRole::Observer, closed_store().await, 1);
            fixture.control.config.principal = principal("operator-1", &[role]);
            let response = router(fixture.control)
                .oneshot(request(&format!("?view={}", view.as_str())))
                .await
                .unwrap();
            // An authorized caller reaches the (closed) store, a refused one
            // never does; neither path may answer with data.
            let (status, code, outcome) = if allowed {
                (StatusCode::SERVICE_UNAVAILABLE, STORE, "ERROR")
            } else {
                (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED", "DENY")
            };
            let result = json_response(response, status).await;
            assert_eq!(result["error_code"], code, "{role:?} {view:?}");
            assert!(result.get("items").is_none());
            let events = read_access_events(&fixture.access_directory);
            assert_eq!(events.len(), 1);
            audit(&events[0], outcome, code);
            cleanup(&fixture.access_directory);
        }
    }
    // The roles combine: an investigator who is also an approver may review.
    let mut fixture = Fixture::with_catalog(10, ManagementRole::Observer, closed_store().await, 1);
    fixture.control.config.principal = principal(
        "operator-1",
        &[
            ManagementRole::Investigator,
            ManagementRole::SensitiveEvidenceApprover,
        ],
    );
    let result = json_response(
        router(fixture.control)
            .oneshot(request("?view=review"))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(result["error_code"], STORE);
    cleanup(&fixture.access_directory);
}

#[tokio::test]
async fn export_list_uses_browser_roles_not_the_machine_principal() {
    for (view, roles, allowed) in [
        ("mine", &["sensitive_evidence_reader"][..], true),
        ("mine", &["investigator"][..], true),
        ("mine", &["audit_administrator"][..], false),
        ("review", &["sensitive_evidence_approver"][..], true),
        (
            "review",
            &["sensitive_evidence_reader", "investigator"][..],
            false,
        ),
    ] {
        let mut fixture =
            Fixture::with_catalog(10, ManagementRole::Investigator, closed_store().await, 1);
        // The machine credential would admit `mine`; only the verified browser
        // session roles may decide here.
        fixture.control.config.principal =
            principal("machine-investigator", &[ManagementRole::Investigator]);
        let mut input = request(&format!("?view={view}"));
        input.headers_mut().insert(
            AUTHORIZATION,
            browser_authorization(&fixture.control, "browser-user", roles)
                .parse()
                .unwrap(),
        );
        let (status, code, outcome) = if allowed {
            (StatusCode::SERVICE_UNAVAILABLE, STORE, "ERROR")
        } else {
            (StatusCode::FORBIDDEN, "CONTROL_SCOPE_DENIED", "DENY")
        };
        let response = json_response(
            router(fixture.control).oneshot(input).await.unwrap(),
            status,
        )
        .await;
        assert_eq!(response["error_code"], code, "{view} {roles:?}");
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        audit(&events[0], outcome, code);
        assert_eq!(events[0]["payload"]["subject_ref"], "browser-user");
        cleanup(&fixture.access_directory);
    }
}

// The collection shares its path with export creation. A cookie session without
// a CSRF proof may read the list, but must not be able to create an export, and
// each method must land on its own handler and its own audit event.
#[tokio::test]
async fn export_list_needs_no_csrf_proof_while_creation_on_the_same_path_does() {
    let mut fixture = Fixture::with_catalog(10, ManagementRole::Observer, closed_store().await, 1);
    fixture.control.config.principal = principal("machine", &[ManagementRole::Observer]);
    let session =
        browser_authorization_with_csrf(&fixture.control, "browser-user", &["investigator"], false);
    let app = router(fixture.control);
    let mut list = request("?view=mine");
    list.headers_mut()
        .insert(AUTHORIZATION, session.parse().unwrap());
    let listed = json_response(
        app.clone().oneshot(list).await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(listed["error_code"], STORE, "the list handler was reached");
    let mut create = export_post(
        "export-list-csrf-proof-key",
        "case_018f2a3b-4c5d-7000-8000-000000000001",
    );
    create
        .headers_mut()
        .insert(AUTHORIZATION, session.parse().unwrap());
    let created = json_response(app.oneshot(create).await.unwrap(), StatusCode::FORBIDDEN).await;
    assert_eq!(created["error_code"], "CONTROL_CSRF_REQUIRED");
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 2);
    audit(&events[0], "ERROR", STORE);
    assert_eq!(events[1]["event_type"], "export.requested");
    assert_eq!(events[1]["payload"]["method"], "POST");
    assert_eq!(events[1]["payload"]["reason_code"], "CONTROL_CSRF_REQUIRED");
    cleanup(&fixture.access_directory);
}

#[tokio::test]
async fn export_list_cursor_replay_across_view_and_subject_is_refused_over_http() {
    let mut fixture = Fixture::with_catalog(10, ManagementRole::Observer, closed_store().await, 1);
    fixture.control.config.principal = principal(
        "operator-1",
        &[
            ManagementRole::Investigator,
            ManagementRole::SensitiveEvidenceApprover,
        ],
    );
    let id = ExportId::parse(EXPORT).unwrap();
    // The router consumes the plane, so mint every cursor first. A correctly
    // bound cursor proceeds to the store; a cursor replayed under the other
    // view, or minted for another subject, is refused before any lookup.
    let mint = |subject: &str, view| {
        fixture
            .control
            .encode_export_list_cursor(subject, view, &id)
            .unwrap()
    };
    let cases = [
        (
            Mine,
            mint("operator-1", Mine),
            STORE,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            Review,
            mint("operator-1", Review),
            STORE,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            Review,
            mint("operator-1", Mine),
            "CONTROL_CURSOR_INVALID",
            StatusCode::BAD_REQUEST,
        ),
        (
            Mine,
            mint("operator-1", Review),
            "CONTROL_CURSOR_INVALID",
            StatusCode::BAD_REQUEST,
        ),
        (
            Mine,
            mint("operator-2", Mine),
            "CONTROL_CURSOR_INVALID",
            StatusCode::BAD_REQUEST,
        ),
    ];
    let app = router(fixture.control);
    let mut expected = Vec::new();
    for (view, cursor, code, status) in cases {
        let response = json_response(
            app.clone()
                .oneshot(request(&format!("?view={}&cursor={cursor}", view.as_str())))
                .await
                .unwrap(),
            status,
        )
        .await;
        assert_eq!(response["error_code"], code, "{view:?}");
        expected.push(code);
    }
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), expected.len());
    for (event, code) in events.iter().zip(expected) {
        audit(event, if code == STORE { "ERROR" } else { "DENY" }, code);
    }
    cleanup(&fixture.access_directory);
}

#[tokio::test]
async fn export_list_cursor_binds_scope_subject_credential_limit_view_and_position() {
    for binding in [
        "subject",
        "credential",
        "tenant",
        "site",
        "limit",
        "key",
        "view",
        "position",
        "family",
        "case_family",
        "encoding",
    ] {
        let mut fixture = Fixture::new(10, ManagementRole::Investigator);
        let id = ExportId::parse(EXPORT).unwrap();
        let mut cursor = fixture
            .control
            .encode_export_list_cursor("operator-1", Mine, &id)
            .unwrap();
        assert_eq!(cursor.len(), 111);
        assert_eq!(
            fixture
                .control
                .decode_export_list_cursor("operator-1", Mine, &cursor),
            Ok(id)
        );
        let mut subject = "operator-1";
        let mut view = Mine;
        match binding {
            "subject" => subject = "operator-2",
            "credential" => fixture.control.config.credential.token_digest[0] ^= 1,
            "tenant" => fixture.control.config.tenant_id = TenantId::parse("other").unwrap(),
            "site" => fixture.control.config.site_id = SiteId::parse("other").unwrap(),
            "limit" => fixture.control.config.limits.max_query_artifacts += 1,
            "key" => fixture.control.config.cursor_key.0[0] ^= 1,
            "view" => view = Review,
            "position" => cursor = cursor.replace("000000000981", "000000000982"),
            // A cursor of a sibling listing carries the same shape and the same
            // key, but a different purpose domain, and must not be replayable.
            "family" => {
                cursor = fixture
                    .control
                    .encode_access_list_cursor(
                        "operator-1",
                        AccessView::Mine,
                        &EvidenceAccessRequestId::parse(EXPORT.replace("export_", "access_"))
                            .unwrap(),
                    )
                    .unwrap()
                    .replace("access_", "export_");
            }
            "case_family" => {
                cursor = fixture
                    .control
                    .encode_cases_cursor(
                        "operator-1",
                        &xshield_core::domain::CaseId::parse(EXPORT.replace("export_", "case_"))
                            .unwrap(),
                    )
                    .unwrap()
                    .replace("case_", "export_");
            }
            _ => cursor = cursor.to_uppercase(),
        }
        assert_eq!(
            fixture
                .control
                .decode_export_list_cursor(subject, view, &cursor),
            Err(CursorError::Invalid),
            "{binding}"
        );
        cleanup(&fixture.access_directory);
    }
}

#[tokio::test]
async fn export_list_cursor_shape_is_strict() {
    let fixture = Fixture::new(10, ManagementRole::Investigator);
    let id = ExportId::parse(EXPORT).unwrap();
    let cursor = fixture
        .control
        .encode_export_list_cursor("operator-1", Mine, &id)
        .unwrap();
    let signature = cursor.rsplit('.').next().unwrap();
    for malformed in [
        String::new(),
        "v1".to_owned(),
        format!("v1.{EXPORT}"),
        format!("v2.{EXPORT}.{signature}"),
        format!("v1.{EXPORT}.{signature}.extra"),
        format!("v1.{EXPORT}.{}", &signature[1..]),
        format!("v1.{EXPORT}.{}", signature.to_uppercase()),
        format!("v1.{}.{signature}", EXPORT.replace("export_", "case_")),
        format!("v1.{}.{signature}", EXPORT.to_uppercase()),
        format!("v1..{signature}"),
    ] {
        assert_eq!(
            fixture
                .control
                .decode_export_list_cursor("operator-1", Mine, &malformed),
            Err(CursorError::Invalid),
            "{malformed}"
        );
    }
    cleanup(&fixture.access_directory);
}

// ---------------------------------------------------------------------------
// Real PostgreSQL. These tests own one tenant per run and delete only its rows.

struct Context {
    pool: sqlx::PgPool,
    tenant: TenantId,
}

impl Context {
    async fn new() -> Self {
        let pool = sqlx::PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        Self {
            pool,
            // The name must not contain `export_`, the marker `audit` forbids.
            tenant: TenantId::parse(format!("tenant_exlist_{}", Uuid::now_v7().simple())).unwrap(),
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

    // One real exchange with the production router; each call is its own
    // plane, journal and rate window, like separate requests to separate replicas.
    async fn call(
        &self,
        subject: &str,
        roles: &[ManagementRole],
        step_up: bool,
        input: Request<Body>,
        status: StatusCode,
    ) -> Value {
        let mut fixture = self.fixture(&self.pool, subject, roles);
        fixture.control.test_step_up_valid = step_up;
        let result = json_response(
            router(fixture.control).oneshot(input).await.unwrap(),
            status,
        )
        .await;
        cleanup(&fixture.access_directory);
        result
    }

    async fn http_case(&self, owner: &str, key: &'static str) -> String {
        let created = self
            .call(
                owner,
                &[ManagementRole::Investigator],
                false,
                case_request(key, r#"{"purpose":"Export list regression"}"#),
                StatusCode::CREATED,
            )
            .await;
        created["case_id"].as_str().unwrap().to_owned()
    }

    async fn http_export(&self, owner: &str, case: &str, key: &str) -> String {
        let created = self
            .call(
                owner,
                &[ManagementRole::Investigator],
                false,
                export_post(key, case),
                StatusCode::ACCEPTED,
            )
            .await;
        created["export_id"].as_str().unwrap().to_owned()
    }

    async fn http_deny(&self, export: &str) {
        self.call(
            "independent-approver",
            &[ManagementRole::SensitiveEvidenceApprover],
            true,
            Request::post(format!("{PATH}/{export}/deny"))
                .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .header("idempotency-key", format!("export-list-deny-{export}"))
                .body(Body::from(json!({ "reason": REASON }).to_string()))
                .unwrap(),
            StatusCode::OK,
        )
        .await;
    }

    async fn detail(&self, owner: &str, export: &str) -> Value {
        self.call(
            owner,
            &[ManagementRole::Investigator],
            false,
            Request::get(format!("{PATH}/{export}"))
                .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
            StatusCode::OK,
        )
        .await
    }

    // A case without an HTTP round trip, for tests that only need an owner row.
    async fn seed_case(&self, number: u32, owner: &str) -> String {
        let case = format!("case_018f2a3b-4c5d-7000-8000-{number:012x}");
        sqlx::query(
            "INSERT INTO xshield.investigation_cases (
                 tenant_id, site_id, case_id, owner_ref, purpose, status,
                 idempotency_digest, request_digest, created_event_id
             ) VALUES ($1, 'site_a', $2, $3, 'Export list regression', 'open', $4, $5, $6)",
        )
        .bind(self.tenant.as_str())
        .bind(&case)
        .bind(owner)
        .bind([1_u8; 32].as_slice())
        .bind([2_u8; 32].as_slice())
        .bind(format!("ev_{}", Uuid::now_v7()))
        .execute(&self.pool)
        .await
        .unwrap();
        case
    }

    // Persisted states whose transitions need a vault or a clock (approved,
    // ready, expired, failed) are written directly, shaped exactly as the table
    // constraints and the production writers shape them.
    async fn seed_export(&self, number: u32, owner: &str, case: &str, status: &str) -> String {
        let export = format!("export_018f2a3b-4c5d-7000-8000-{number:012x}");
        let now = Utc::now();
        let decided = status != "pending_approval";
        let digest = vec![u8::try_from(number % 251).unwrap(); 32];
        let ready = status == "ready";
        sqlx::query(
            "INSERT INTO xshield.investigation_exports (
                 tenant_id, site_id, export_id, case_id, requested_by, purpose, kind, status,
                 decided_by, decided_at, decision_reason, expires_at,
                 package_artifact_id, package_request_id, package_digest, package_bytes,
                 idempotency_digest, request_digest, approval_digest, decision_request_digest,
                 created_at, updated_at)
             VALUES ($1, 'site_a', $2, $3, $4, 'Seeded export purpose', 'metadata_only', $5,
                 $6, $7, $8, $9, $10, $11, $12, $13, $14, $14, $15, $15, $16, $16)",
        )
        .bind(self.tenant.as_str())
        .bind(&export)
        .bind(case)
        .bind(owner)
        .bind(status)
        .bind(decided.then_some("seed-approver"))
        .bind(decided.then(|| now - chrono::Duration::hours(1)))
        .bind(decided.then_some("Seeded decision reason"))
        .bind(match status {
            "approved" | "ready" => Some(now + chrono::Duration::minutes(10)),
            "expired" => Some(now - chrono::Duration::minutes(10)),
            _ => None,
        })
        .bind(ready.then(|| format!("artifact_018f2a3b-4c5d-7000-8000-{number:012x}")))
        .bind(ready.then(|| format!("req_018f2a3b-4c5d-7000-8000-{number:012x}")))
        .bind(ready.then(|| "a".repeat(64)))
        .bind(ready.then_some(12_i64))
        .bind(digest.as_slice())
        .bind(decided.then_some(digest.as_slice()))
        .bind(now - chrono::Duration::hours(2))
        .execute(&self.pool)
        .await
        .unwrap();
        export
    }

    async fn versions(&self) -> Vec<(String, String, String)> {
        sqlx::query_as(
            "SELECT 'export', export_id, xmin::text FROM xshield.investigation_exports WHERE tenant_id=$1
             UNION ALL SELECT 'claim', export_id, xmin::text FROM xshield.investigation_export_package_claims WHERE tenant_id=$1
             UNION ALL SELECT 'case', case_id, xmin::text FROM xshield.investigation_cases WHERE tenant_id=$1
             UNION ALL SELECT 'outbox', event_id, xmin::text FROM xshield.audit_outbox WHERE tenant_id=$1 ORDER BY 1,2",
        )
        .bind(self.tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn cleanup(self) {
        for sql in [
            "DELETE FROM xshield.investigation_export_package_claims WHERE tenant_id=$1",
            "DELETE FROM xshield.investigation_exports WHERE tenant_id=$1",
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
    }
}

fn export_post(key: &str, case: &str) -> Request<Body> {
    Request::post(PATH)
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(Body::from(
            json!({ "case_id": case, "purpose": PURPOSE }).to_string(),
        ))
        .unwrap()
}

fn ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["export_id"].as_str().unwrap().to_owned())
        .collect()
}

// Bytewise descending is the contract; plain `String` ordering is bytewise.
fn newest_first(mut ids: Vec<String>) -> Vec<String> {
    ids.sort_unstable_by(|a, b| b.cmp(a));
    ids
}

// One authorized, audited page. Every call asserts the response contract, the
// field whitelist and the single `PASS` journal event with its caller.
async fn page(
    context: &Context,
    subject: &str,
    role: ManagementRole,
    view: InvestigationExportListView,
    limit: u16,
    cursor: Option<&str>,
) -> Value {
    let mut fixture = context.fixture(&context.pool, subject, &[role]);
    fixture.control.config.limits.max_query_artifacts = limit;
    let query = format!(
        "?view={}{}",
        view.as_str(),
        cursor.map_or(String::new(), |cursor| format!("&cursor={cursor}"))
    );
    let response = json_response(
        router(fixture.control)
            .oneshot(request(&query))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 1);
    audit(&events[0], "PASS", "CONTROL_EXPORTS_READ");
    assert_eq!(events[0]["request_id"], response["request_id"]);
    assert_eq!(events[0]["payload"]["subject_ref"], subject);
    assert_eq!(response["schema_version"], 3);
    assert_eq!(response["tenant_id"], context.tenant.as_str());
    assert_eq!(response["site_id"], "site_a");
    assert_eq!(response["view"], view.as_str());
    assert_eq!(response["as_of"].as_str().unwrap().len(), 27);
    chrono::DateTime::parse_from_rfc3339(response["as_of"].as_str().unwrap()).unwrap();
    assert_eq!(response.as_object().unwrap().len(), 9);
    for item in response["items"].as_array().unwrap() {
        let mut keys: Vec<_> = item
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "case_id",
                "decided_at",
                "decided_by",
                "expires_at",
                "export_id",
                "requested_at",
                "requested_by",
                "status"
            ]
        );
        for time in ["requested_at", "decided_at", "expires_at"] {
            if let Some(value) = item[time].as_str() {
                assert_eq!(value.len(), 24, "{time} keeps the detail precision");
                chrono::DateTime::parse_from_rfc3339(value).unwrap();
            }
        }
    }
    for secret in [
        PURPOSE,
        REASON,
        "Seeded",
        "purpose",
        "decision_reason",
        "package",
        "artifact",
        "digest",
        "locator",
        "download_count",
        "updated_at",
        "idempotency",
        "key_ref",
    ] {
        assert!(!response.to_string().contains(secret), "leaked {secret}");
    }
    cleanup(&fixture.access_directory);
    response
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn export_list_history_queue_pagination_and_scope_are_read_only() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
    let case_1 = context
        .http_case("operator-1", "export-list-case-op1")
        .await;
    let case_2 = context
        .http_case("operator-2", "export-list-case-op2")
        .await;
    // Real requests produce the pending rows; one is decided through the real
    // route. Reaching approved or ready needs a vault, so those are seeded.
    let denied = context
        .http_export("operator-1", &case_1, "export-list-op1-denied")
        .await;
    let pending_1 = context
        .http_export("operator-1", &case_1, "export-list-op1-pending")
        .await;
    let pending_2 = context
        .http_export("operator-2", &case_2, "export-list-op2-pending")
        .await;
    context.http_deny(&denied).await;
    let approved = context
        .seed_export(0x9a1, "operator-1", &case_1, "approved")
        .await;
    let ready = context
        .seed_export(0x9a2, "operator-1", &case_1, "ready")
        .await;
    let expired = context
        .seed_export(0x9a3, "operator-1", &case_1, "expired")
        .await;
    let failed = context
        .seed_export(0x9a4, "operator-1", &case_1, "failed")
        .await;
    let status_of = [
        (&denied, "rejected"),
        (&pending_1, "pending_approval"),
        (&approved, "approved"),
        (&ready, "ready"),
        (&expired, "expired"),
        (&failed, "failed"),
    ];
    let mine_1 = newest_first(status_of.iter().map(|(id, _)| (*id).clone()).collect());
    assert_eq!(mine_1.len(), 6);
    let versions = context.versions().await;

    // Own history: every persisted state, strictly descending, no overlap.
    let first = page(
        &context,
        "operator-1",
        ManagementRole::Investigator,
        Mine,
        4,
        None,
    )
    .await;
    assert_eq!(ids(&first), mine_1[..4]);
    assert_eq!(first["truncated"], true);
    let cursor = first["next_cursor"].as_str().unwrap();
    assert!(cursor.starts_with(&format!("v1.{}.", mine_1[3])));
    // The cursor binds subject, scope and view, not the role that fetched it.
    let second = page(
        &context,
        "operator-1",
        ManagementRole::SensitiveEvidenceReader,
        Mine,
        4,
        Some(cursor),
    )
    .await;
    assert_eq!(ids(&second), mine_1[4..]);
    assert_eq!(second["truncated"], false);
    assert!(second["next_cursor"].is_null());
    for item in first["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["items"].as_array().unwrap())
    {
        let id = item["export_id"].as_str().unwrap();
        let expected = status_of
            .iter()
            .find(|(known, _)| known.as_str() == id)
            .unwrap()
            .1;
        assert_eq!(item["status"], expected);
        assert_eq!(item["requested_by"], "operator-1");
        assert_eq!(item["case_id"], case_1);
        assert_eq!(item["decided_by"].is_null(), expected == "pending_approval");
        assert_eq!(item["decided_at"].is_null(), expected == "pending_approval");
        assert_eq!(
            item["expires_at"].is_null(),
            !matches!(expected, "approved" | "ready" | "expired"),
            "{expected}"
        );
        // The list agrees with the detail endpoint field by field; only the
        // name of the creation time differs.
        let detail = context.detail("operator-1", id).await;
        assert_eq!(detail["status"], item["status"]);
        assert_eq!(detail["created_at"], item["requested_at"]);
        assert_eq!(detail["decided_by"], item["decided_by"]);
        assert_eq!(detail["decided_at"], item["decided_at"]);
        assert_eq!(detail["expires_at"], item["expires_at"]);
    }
    // Replaying a mine cursor as review is refused, not reinterpreted.
    let replay = json_response(
        {
            let fixture = context.fixture(
                &context.pool,
                "operator-1",
                &[ManagementRole::SensitiveEvidenceApprover],
            );
            let response = router(fixture.control)
                .oneshot(request(&format!("?view=review&cursor={cursor}")))
                .await
                .unwrap();
            let events = read_access_events(&fixture.access_directory);
            assert_eq!(events.len(), 1);
            audit(&events[0], "DENY", "CONTROL_CURSOR_INVALID");
            cleanup(&fixture.access_directory);
            response
        },
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(replay["error_code"], "CONTROL_CURSOR_INVALID");

    // Another requester sees only their own rows; an unknown subject sees none
    // but still receives a database observation time.
    let theirs = page(
        &context,
        "operator-2",
        ManagementRole::Investigator,
        Mine,
        128,
        None,
    )
    .await;
    assert_eq!(ids(&theirs), std::slice::from_ref(&pending_2));
    let stranger = page(
        &context,
        "stranger",
        ManagementRole::Investigator,
        Mine,
        128,
        None,
    )
    .await;
    assert_eq!(stranger["items"], json!([]));
    assert_eq!(stranger["truncated"], false);

    // The queue holds other principals' undecided exports and nothing else: not
    // the decided, approved, ready, expired or failed ones, and not the
    // reviewer's own.
    let queue = page(
        &context,
        "reviewer",
        ManagementRole::SensitiveEvidenceApprover,
        Review,
        128,
        None,
    )
    .await;
    assert_eq!(
        ids(&queue),
        newest_first(vec![pending_1.clone(), pending_2.clone()])
    );
    for item in queue["items"].as_array().unwrap() {
        assert_eq!(item["status"], "pending_approval");
        assert!(item["decided_by"].is_null() && item["expires_at"].is_null());
    }
    let own_excluded = page(
        &context,
        "operator-1",
        ManagementRole::SensitiveEvidenceApprover,
        Review,
        128,
        None,
    )
    .await;
    assert_eq!(ids(&own_excluded), std::slice::from_ref(&pending_2));
    let paged_queue = page(
        &context,
        "reviewer",
        ManagementRole::SensitiveEvidenceApprover,
        Review,
        1,
        None,
    )
    .await;
    let queue_ids = newest_first(vec![pending_1.clone(), pending_2.clone()]);
    assert_eq!(ids(&paged_queue), queue_ids[..1]);
    let queue_tail = page(
        &context,
        "reviewer",
        ManagementRole::SensitiveEvidenceApprover,
        Review,
        1,
        paged_queue["next_cursor"].as_str(),
    )
    .await;
    assert_eq!(ids(&queue_tail), queue_ids[1..]);
    assert_eq!(queue_tail["truncated"], false);

    // A foreign tenant scope exposes nothing: scope comes from the principal.
    let mut foreign = context.fixture(
        &context.pool,
        "reviewer",
        &[ManagementRole::SensitiveEvidenceApprover],
    );
    scope_fixture(
        &mut foreign,
        &TenantId::parse("foreign_exlist_scope").unwrap(),
        "reviewer",
        &[ManagementRole::SensitiveEvidenceApprover],
    );
    let result = json_response(
        router(foreign.control)
            .oneshot(request("?view=review"))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(result["items"], json!([]));
    cleanup(&foreign.access_directory);
    assert_eq!(versions, context.versions().await, "listing is read-only");

    // A decision removes the item from the queue on the next refresh and shows
    // up in the requester's history.
    context.http_deny(&pending_2).await;
    let after = page(
        &context,
        "reviewer",
        ManagementRole::SensitiveEvidenceApprover,
        Review,
        128,
        None,
    )
    .await;
    assert_eq!(ids(&after), std::slice::from_ref(&pending_1));
    let history = page(
        &context,
        "operator-2",
        ManagementRole::Investigator,
        Mine,
        128,
        None,
    )
    .await;
    assert_eq!(history["items"][0]["status"], "rejected");
    assert_eq!(history["items"][0]["decided_by"], "independent-approver");
    context.cleanup().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn export_list_disconnected_reader_holds_capacity_through_audit() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
    let case = context.seed_case(0x9b0, "operator-1").await;
    context
        .seed_export(0x9b1, "operator-1", &case, "pending_approval")
        .await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let connection = pool.acquire().await.unwrap();
    let fixture = context.fixture(&pool, "operator-1", &[ManagementRole::Investigator]);
    let capacity = fixture.control.case_evidence_capacity.clone();
    let control = Arc::new(fixture.control);
    let journal = control.clone();
    let (started, start) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let blocker = tokio::task::spawn_blocking(move || {
        let _guard = journal.access_journal.lock().unwrap();
        started.send(()).unwrap();
        released.blocking_recv().unwrap();
    });
    start.await.unwrap();
    let app = axum::Router::new()
        .route(
            PATH,
            get(crate::export_list::handler).layer(DefaultBodyLimit::max(0)),
        )
        .with_state(control);
    let client = tokio::spawn(app.clone().oneshot(request("?view=mine")));
    tokio::time::timeout(Duration::from_secs(5), async {
        while capacity.available_permits() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // The client vanishes after admission while the database read is still
    // queued behind the only pooled connection.
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
    drop(connection);
    tokio::time::timeout(Duration::from_secs(5), async {
        while pool.num_idle() != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // The read finished, but the terminal audit is still blocked, so the
    // permit must still be held.
    assert_eq!(capacity.available_permits(), 0);
    release.send(()).unwrap();
    blocker.await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while capacity.available_permits() != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), 1);
    audit(&events[0], "PASS", "CONTROL_EXPORTS_READ");
    drop(app);
    pool.close().await;
    cleanup(&fixture.access_directory);
    context.cleanup().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn export_list_audit_failure_withholds_page() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
    let case = context.seed_case(0x9c0, "operator-1").await;
    let export = context
        .seed_export(0x9c1, "operator-1", &case, "pending_approval")
        .await;
    let fixture = context.fixture(&context.pool, "operator-1", &[ManagementRole::Investigator]);
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(|| {
                    let _guard = fixture.control.access_journal.lock().unwrap();
                    panic!("simulate audit failure");
                })
                .join()
                .is_err()
        );
    });
    let capacity = fixture.control.case_evidence_capacity.clone();
    let result = json_response(
        router(fixture.control)
            .oneshot(request("?view=mine"))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(result["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(result.get("items").is_none());
    assert!(!result.to_string().contains(&export));
    assert_eq!(capacity.available_permits(), 1);
    cleanup(&fixture.access_directory);
    context.cleanup().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn export_list_storage_faults_are_bounded_audited_and_withhold_data() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
    let case = context.seed_case(0x9d0, "operator-1").await;
    let export = context
        .seed_export(0x9d1, "operator-1", &case, "pending_approval")
        .await;
    for scenario in ["pool", "lock", "corrupt"] {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_mins(1))
            .connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let held = if scenario == "pool" {
            Some(pool.acquire().await.unwrap())
        } else {
            None
        };
        let mut transaction = context.pool.begin().await.unwrap();
        if scenario == "lock" {
            sqlx::query("LOCK TABLE xshield.investigation_exports IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        if scenario == "corrupt" {
            // The table allows a deadline on a pending row; the decoder does not.
            sqlx::query("UPDATE xshield.investigation_exports SET expires_at = now() + interval '1 hour' WHERE tenant_id = $1 AND export_id = $2")
                .bind(context.tenant.as_str())
                .bind(&export)
                .execute(&pool)
                .await
                .unwrap();
        }
        let versions = if scenario == "lock" {
            None
        } else {
            Some(context.versions().await)
        };
        let fixture = context.fixture(&pool, "operator-1", &[ManagementRole::Investigator]);
        let capacity = fixture.control.case_evidence_capacity.clone();
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(if scenario == "pool" { 19 } else { 8 }),
            router(fixture.control).oneshot(request("?view=mine")),
        )
        .await
        .unwrap()
        .unwrap();
        let result = json_response(result, StatusCode::SERVICE_UNAVAILABLE).await;
        assert_eq!(result["error_code"], STORE, "{scenario}");
        assert_eq!(result["retryable"], true);
        assert!(result.get("items").is_none());
        assert!(!result.to_string().contains(&export));
        assert_eq!(capacity.available_permits(), 1);
        if scenario != "corrupt" {
            assert!(
                started.elapsed() >= Duration::from_secs(if scenario == "pool" { 14 } else { 4 }),
                "{scenario} must wait for its own deadline"
            );
        }
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        audit(&events[0], "ERROR", STORE);
        transaction.rollback().await.unwrap();
        if let Some(versions) = versions {
            assert_eq!(versions, context.versions().await);
        }
        if scenario == "corrupt" {
            sqlx::query("UPDATE xshield.investigation_exports SET expires_at = NULL WHERE tenant_id = $1 AND export_id = $2")
                .bind(context.tenant.as_str())
                .bind(&export)
                .execute(&context.pool)
                .await
                .unwrap();
        }
        drop(held);
        pool.close().await;
        cleanup(&fixture.access_directory);
    }
    context.cleanup().await;
}
