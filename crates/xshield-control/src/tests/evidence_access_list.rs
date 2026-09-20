//! Discovery authorization, cursor isolation, live history and durable read barriers.

use super::evidence_access_inspection::{Context, DATABASE_TEST, scope_fixture};
use super::*;
use crate::CursorError;
use axum::{extract::DefaultBodyLimit, routing::get};
use std::sync::Arc;
use xshield_core::domain::EvidenceAccessRequestId;
use xshield_postgres::EvidenceAccessListView::{self, Mine, Review};

const PATH: &str = "/control/v1/evidence-access-requests";
const ACCESS: &str = "access_018f2a3b-4c5d-7000-8000-000000000981";
const STORE: &str = "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE";

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

fn audit(event: &Value, outcome: &str, code: &str) {
    assert_eq!(event["event_type"], "console.evidence.access.list");
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
        "requested_by",
        "justification",
        "decision_reason",
        TOKEN,
    ] {
        assert!(!event.to_string().contains(private));
    }
}

#[tokio::test]
async fn evidence_access_list_rejects_noncanonical_input_before_admission() {
    let fixture = Fixture::new(100, ManagementRole::SensitiveEvidenceApprover);
    let permit = fixture
        .control
        .case_evidence_capacity
        .clone()
        .acquire_owned()
        .await
        .unwrap();
    let app = router(fixture.control);
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
    ] {
        attempts.push((
            request(query),
            "CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID",
        ));
    }
    for body in ["x".to_owned(), "{}".to_owned(), "x".repeat(8192)] {
        let mut input = request("?view=mine");
        *input.body_mut() = Body::from(body);
        attempts.push((input, "CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID"));
    }
    attempts.push((
        request("?view=mine&cursor=invalid"),
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
async fn evidence_access_list_auth_roles_scope_rate_and_capacity() {
    for scenario in [
        "missing",
        "duplicate",
        "invalid",
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
        "review_reader",
        "review_investigator",
        "review_approver",
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
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_EVIDENCE_ACCESS_BUSY",
                )
            }
            _ => {
                if scenario != "store" {
                    let role = if scenario == "reader" {
                        ManagementRole::SensitiveEvidenceReader
                    } else {
                        ManagementRole::SensitiveEvidenceApprover
                    };
                    fixture.control.config.principal = ManagementPrincipal::new(
                        "operator-1",
                        [role],
                        [(
                            TenantId::parse("tenant_a").unwrap(),
                            SiteId::parse("site_a").unwrap(),
                        )],
                    )
                    .unwrap();
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
        assert_eq!(events.len(), 1);
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
async fn evidence_access_list_cursor_binds_scope_subject_credential_limit_view_and_position() {
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
        "encoding",
    ] {
        let mut fixture = Fixture::new(10, ManagementRole::Investigator);
        let id = EvidenceAccessRequestId::parse(ACCESS).unwrap();
        let mut cursor = fixture
            .control
            .encode_access_list_cursor("operator-1", Mine, &id)
            .unwrap();
        assert_eq!(
            fixture
                .control
                .decode_access_list_cursor("operator-1", Mine, &cursor),
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
            "family" => {
                cursor = fixture
                    .control
                    .encode_cases_cursor(
                        "operator-1",
                        &xshield_core::domain::CaseId::parse(ACCESS.replace("access_", "case_"))
                            .unwrap(),
                    )
                    .unwrap()
                    .replace("case_", "access_");
            }
            _ => cursor = cursor.to_uppercase(),
        }
        assert_eq!(
            fixture
                .control
                .decode_access_list_cursor(subject, view, &cursor),
            Err(CursorError::Invalid),
            "{binding}"
        );
        cleanup(&fixture.access_directory);
    }
}

async fn page(
    context: &Context,
    subject: &str,
    role: ManagementRole,
    view: EvidenceAccessListView,
    cursor: Option<&str>,
) -> Value {
    let mut fixture = context.fixture(&context.pool, subject, &[role]);
    fixture.control.config.limits.max_query_artifacts = 1;
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
    audit(&events[0], "PASS", "CONTROL_EVIDENCE_ACCESS_LIST_READ");
    assert_eq!(events[0]["request_id"], response["request_id"]);
    assert_eq!(response["schema_version"], 3);
    assert_eq!(response["tenant_id"], context.tenant.as_str());
    assert_eq!(response["site_id"], "site_a");
    assert_eq!(response["view"], view.as_str());
    assert_eq!(response["as_of"].as_str().unwrap().len(), 27);
    chrono::DateTime::parse_from_rfc3339(response["as_of"].as_str().unwrap()).unwrap();
    for item in response["items"].as_array().unwrap() {
        assert_eq!(item.as_object().unwrap().len(), 8);
        assert_eq!(item["case_id"], context.case);
        assert_eq!(item["artifact_id"], context.artifact);
        assert_eq!(item["access_kind"], "sensitive_raw");
    }
    for secret in [
        "justification",
        "decision_reason",
        "access_expires_at",
        "locator",
        "hash",
        "key_ref",
        "digest",
    ] {
        assert!(!response.to_string().contains(secret));
    }
    cleanup(&fixture.access_directory);
    response
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn evidence_access_list_history_queue_pagination_and_scope_are_read_only() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
    let fixture = context.fixture(&context.pool, "operator-1", &[ManagementRole::Investigator]);
    let second = json_response(router(fixture.control).oneshot(evidence_access_request_owned(&context.artifact,
        "listing-second-request", json!({"case_id": context.case,"access_kind":"sensitive_raw","justification":"List regression"}).to_string()))
        .await.unwrap(), StatusCode::CREATED).await;
    cleanup(&fixture.access_directory);
    let second = second["access_request_id"].as_str().unwrap();
    let versions = context.versions().await;
    let first = page(
        &context,
        "operator-1",
        ManagementRole::Investigator,
        Mine,
        None,
    )
    .await;
    assert_eq!(first["items"][0]["access_request_id"], second);
    assert_eq!(first["truncated"], true);
    let cursor = first["next_cursor"].as_str().unwrap();
    let next = page(
        &context,
        "operator-1",
        ManagementRole::SensitiveEvidenceReader,
        Mine,
        Some(cursor),
    )
    .await;
    assert_eq!(next["items"][0]["access_request_id"], context.access);
    assert_eq!(next["truncated"], false);
    assert!(next["next_cursor"].is_null());
    assert_eq!(
        page(
            &context,
            "operator-1",
            ManagementRole::SensitiveEvidenceApprover,
            Review,
            None
        )
        .await["items"],
        json!([])
    );
    assert_eq!(
        page(
            &context,
            "stranger",
            ManagementRole::Investigator,
            Mine,
            None
        )
        .await["items"],
        json!([])
    );
    assert_eq!(
        page(
            &context,
            "reviewer",
            ManagementRole::SensitiveEvidenceApprover,
            Review,
            None
        )
        .await["items"][0]["access_request_id"],
        second
    );
    let mut foreign = context.fixture(
        &context.pool,
        "reviewer",
        &[ManagementRole::SensitiveEvidenceApprover],
    );
    scope_fixture(
        &mut foreign,
        &TenantId::parse("foreign_listing_scope").unwrap(),
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
    assert_eq!(versions, context.versions().await);
    context.decide(second, "deny").await;
    let versions = context.versions().await;
    assert_eq!(
        page(
            &context,
            "operator-1",
            ManagementRole::Investigator,
            Mine,
            None
        )
        .await["items"][0]["stored_status"],
        "denied"
    );
    assert_eq!(
        page(
            &context,
            "reviewer",
            ManagementRole::SensitiveEvidenceApprover,
            Review,
            None
        )
        .await["items"][0]["access_request_id"],
        context.access
    );
    assert_eq!(versions, context.versions().await);
    context.cleanup().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_access_list_disconnected_reader_holds_capacity_through_audit() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
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
            get(crate::evidence_access_list::handler).layer(DefaultBodyLimit::max(0)),
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
    audit(&events[0], "PASS", "CONTROL_EVIDENCE_ACCESS_LIST_READ");
    drop(app);
    pool.close().await;
    cleanup(&fixture.access_directory);
    context.cleanup().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_access_list_audit_failure_withholds_page() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
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
    assert!(!result.to_string().contains(&context.access));
    cleanup(&fixture.access_directory);
    context.cleanup().await;
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_access_list_storage_faults_are_bounded_audited_and_withhold_data() {
    let _serial = DATABASE_TEST.lock().await;
    let context = Context::new().await;
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
            sqlx::query("LOCK TABLE xshield.evidence_access_requests IN ACCESS EXCLUSIVE MODE")
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        if scenario == "corrupt" {
            sqlx::query("UPDATE xshield.audit_outbox SET aggregate_ref='wrong' WHERE tenant_id=$1 AND aggregate_ref=$2 AND event_type='evidence.access.requested'")
                .bind(context.tenant.as_str()).bind(&context.access).execute(&pool).await.unwrap();
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
        assert_eq!(result["error_code"], STORE);
        assert!(result.get("items").is_none());
        assert_eq!(capacity.available_permits(), 1);
        if scenario != "corrupt" {
            assert!(
                started.elapsed() >= Duration::from_secs(if scenario == "pool" { 14 } else { 4 })
            );
        }
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        audit(&events[0], "ERROR", STORE);
        transaction.rollback().await.unwrap();
        if let Some(versions) = versions {
            assert_eq!(versions, context.versions().await);
        }
        drop(held);
        pool.close().await;
        cleanup(&fixture.access_directory);
    }
    context.cleanup().await;
}
