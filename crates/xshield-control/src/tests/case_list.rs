use super::*;
use xshield_core::domain::{ArtifactId, CaseId};

const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000989";
const PATH: &str = "/control/v1/cases";

fn list_request(query: &str) -> Request<Body> {
    Request::get(format!("{PATH}{query}"))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

fn assert_list_audit(event: &Value, outcome: &str, reason: &str) {
    assert_eq!(event["event_type"], "console.case.list");
    assert_eq!(event["payload"]["method"], "GET");
    assert_eq!(event["payload"]["path"], PATH);
    assert_eq!(event["payload"]["outcome"], outcome);
    assert_eq!(event["payload"]["reason_code"], reason);
    assert_eq!(event["evidence_refs"], json!([]));
    for (key, value) in event["payload"].as_object().unwrap() {
        if key.starts_with("target_") || matches!(key.as_str(), "query_digest" | "bytes_read") {
            assert!(value.is_null(), "{key}");
        }
    }
    let serialized = event.to_string();
    for excluded in ["cursor=", "owner_ref", "purpose", TOKEN] {
        assert!(!serialized.contains(excluded));
    }
}

#[tokio::test]
async fn case_list_enforces_authentication_scope_role_and_rate() {
    for scenario in [
        "missing",
        "duplicate",
        "invalid",
        "expired",
        "role",
        "scope",
        "rate",
    ] {
        let mut fixture = Fixture::new(1, ManagementRole::Investigator);
        let mut request = list_request("");
        let (status, code) = match scenario {
            "missing" => {
                request.headers_mut().remove(AUTHORIZATION);
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "duplicate" => {
                request
                    .headers_mut()
                    .append(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "invalid" => {
                request
                    .headers_mut()
                    .insert(AUTHORIZATION, "Bearer invalid".parse().unwrap());
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "expired" => {
                fixture.control.config.credential.expires_at = 1;
                (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
            }
            "role" | "scope" => {
                fixture.control.config.principal = ManagementPrincipal::new(
                    "operator-1",
                    [if scenario == "role" {
                        ManagementRole::Observer
                    } else {
                        ManagementRole::Investigator
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
            _ => {
                fixture.control.rate.lock().unwrap().used = 1;
                (StatusCode::TOO_MANY_REQUESTS, "CONTROL_RATE_LIMITED")
            }
        };
        let result = response_json(
            router(fixture.control).oneshot(request).await.unwrap(),
            status,
        )
        .await;
        assert_eq!(result["error_code"], code);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_list_audit(&events[0], "DENY", code);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn case_list_strictly_validates_query_and_cursor_before_storage() {
    let fixture = Fixture::new(100, ManagementRole::Investigator);
    let cursor = fixture
        .control
        .encode_cases_cursor("operator-1", &CaseId::parse(CASE).unwrap())
        .unwrap();
    let queries = [
        "?".to_owned(),
        "?cursor=".to_owned(),
        "?cursor=bad".to_owned(),
        "?owner=operator-1".to_owned(),
        "?tenant_id=tenant_a".to_owned(),
        "?status=open".to_owned(),
        "?limit=1".to_owned(),
        "?offset=0".to_owned(),
        format!("?cursor={cursor}&cursor={cursor}"),
        format!("?cursor={cursor}&owner=operator-1"),
        format!("?cursor={cursor}.extra"),
        format!("?cursor={}", cursor.replace("v1.", "v2.")),
        format!("?cursor={}", cursor.replace('.', "%2E")),
        format!("?cursor={}", cursor.to_uppercase()),
        format!("?cursor={}", "a".repeat(161)),
    ];
    let count = queries.len();
    let app = router(fixture.control);
    for query in queries {
        let result = response_json(
            app.clone().oneshot(list_request(&query)).await.unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(result["error_code"], "CONTROL_CURSOR_INVALID", "{query}");
    }
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), count);
    for event in events {
        assert_list_audit(&event, "DENY", "CONTROL_CURSOR_INVALID");
        assert!(!event.to_string().contains(&cursor));
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn case_list_cursor_binds_identity_scope_limit_and_purpose() {
    for binding in [
        "credential",
        "subject",
        "tenant",
        "site",
        "limit",
        "key",
        "position",
        "purpose",
    ] {
        let mut fixture = Fixture::new(10, ManagementRole::Investigator);
        let case = CaseId::parse(CASE).unwrap();
        let mut cursor = fixture
            .control
            .encode_cases_cursor("operator-1", &case)
            .unwrap();
        assert_eq!(
            fixture.control.decode_cases_cursor("operator-1", &cursor),
            Ok(case.clone())
        );
        let subject = match binding {
            "credential" => {
                fixture.control.config.credential.token_digest[0] ^= 1;
                "operator-1"
            }
            "subject" => "operator-2",
            "tenant" => {
                fixture.control.config.tenant_id = TenantId::parse("other").unwrap();
                "operator-1"
            }
            "site" => {
                fixture.control.config.site_id = SiteId::parse("other").unwrap();
                "operator-1"
            }
            "limit" => {
                fixture.control.config.limits.max_query_artifacts += 1;
                "operator-1"
            }
            "key" => {
                fixture.control.config.cursor_key.0[0] ^= 1;
                "operator-1"
            }
            "position" => {
                cursor = cursor.replace("000000000989", "000000000990");
                "operator-1"
            }
            _ => {
                let artifact = ArtifactId::parse(MISSING_ARTIFACT_ID).unwrap();
                cursor = fixture
                    .control
                    .encode_case_cursor("operator-1", &case, &artifact)
                    .unwrap();
                // Even a syntactically valid case cursor cannot reuse an item signature.
                cursor = cursor.replace(artifact.as_str(), case.as_str());
                "operator-1"
            }
        };
        assert_eq!(
            fixture.control.decode_cases_cursor(subject, &cursor),
            Err(crate::CursorError::Invalid),
            "{binding}"
        );
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

fn poison_audit(control: &ControlPlane) {
    std::thread::scope(|scope| {
        let journal = &control.access_journal;
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
}

#[tokio::test]
async fn case_list_bounds_inflight_work_and_withholds_unaudited_results() {
    for scenario in ["busy", "store", "audit"] {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let fixture = Fixture::with_case_catalog(PostgresIdentityStore::from_pool(pool), 1);
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
        if scenario == "audit" {
            poison_audit(&fixture.control);
        }
        let code = match scenario {
            "busy" => "CONTROL_CASE_BUSY",
            "audit" => "AUDIT_DURABILITY_FAILED",
            _ => "CONTROL_CASE_STORE_UNAVAILABLE",
        };
        let status = if scenario == "busy" {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        let result = response_json(
            router(fixture.control)
                .oneshot(list_request(""))
                .await
                .unwrap(),
            status,
        )
        .await;
        assert_eq!(result["error_code"], code);
        assert!(result.get("items").is_none());
        if scenario != "audit" {
            let events = read_access_events(&fixture.access_directory);
            assert_eq!(events.len(), 1);
            assert_list_audit(
                &events[0],
                if scenario == "busy" { "DENY" } else { "ERROR" },
                code,
            );
        }
        drop(permit);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

fn pg_fixture(pool: &sqlx::PgPool, tenant: &str, site: &str, subject: &str) -> Fixture {
    let mut fixture = Fixture::with_decision_catalog(
        PostgresIdentityStore::from_pool(pool.clone()),
        subject,
        ManagementRole::Investigator,
    );
    let tenant = TenantId::parse(tenant).unwrap();
    let site = SiteId::parse(site).unwrap();
    fixture.control.config.tenant_id = tenant.clone();
    fixture.control.config.site_id = site.clone();
    fixture.control.config.principal =
        ManagementPrincipal::new(subject, [ManagementRole::Investigator], [(tenant, site)])
            .unwrap();
    fixture.control.rate.lock().unwrap().limit = 100;
    fixture
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn case_list_is_scoped_paginated_audited_and_disconnect_safe() {
    const TENANT: &str = "tenant_case_list_http";
    const OTHER_TENANT: &str = "tenant_case_list_http_other";
    let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let case_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&url)
        .await
        .unwrap();
    let fixture = pg_fixture(&case_pool, TENANT, "site_a", "operator-1");
    let capacity = fixture.control.case_evidence_capacity.clone();
    let app = router(fixture.control);
    let empty = response_json(
        app.clone().oneshot(list_request("")).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(empty["items"], json!([]));
    assert_eq!(empty["truncated"], false);
    assert!(empty["next_cursor"].is_null());
    let mut ids = Vec::new();
    for (key, purpose) in [
        ("case-list-first-key", r#"{"purpose":"First owned case"}"#),
        ("case-list-second-key", r#"{"purpose":"Second owned case"}"#),
    ] {
        let created = response_json(
            app.clone()
                .oneshot(case_request(key, purpose))
                .await
                .unwrap(),
            StatusCode::CREATED,
        )
        .await;
        ids.push(created["case_id"].as_str().unwrap().to_owned());
    }
    ids.sort();
    let closed = Request::post(format!("{PATH}/{}/close", ids[1]))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(CONTENT_TYPE, "application/json")
        .header("idempotency-key", "case-list-close-key")
        .body(Body::from(r#"{"reason":"Completed review"}"#))
        .unwrap();
    response_json(app.clone().oneshot(closed).await.unwrap(), StatusCode::OK).await;
    // Newer out-of-scope rows must not displace owned cases or mark a page truncated.
    for (tenant, site, owner) in [
        (TENANT, "site_a", "another-owner"),
        (TENANT, "site_b", "operator-1"),
        (OTHER_TENANT, "site_a", "operator-1"),
    ] {
        let foreign = pg_fixture(&pool, tenant, site, owner);
        response_json(
            router(foreign.control)
                .oneshot(case_request(
                    "case-list-foreign-key",
                    r#"{"purpose":"Foreign case"}"#,
                ))
                .await
                .unwrap(),
            StatusCode::CREATED,
        )
        .await;
        fs::remove_dir_all(foreign.access_directory.parent().unwrap()).unwrap();
    }
    let page = response_json(
        app.clone().oneshot(list_request("")).await.unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(page["schema_version"], 3);
    assert_eq!(page["tenant_id"], TENANT);
    assert_eq!(page["site_id"], "site_a");
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["items"][0]["case_id"], ids[1]);
    assert_eq!(page["items"][0]["status"], "closed");
    assert_eq!(page["items"][0]["purpose"], "Second owned case");
    assert_eq!(page["items"][0].as_object().unwrap().len(), 4);
    assert_eq!(page["as_of"].as_str().unwrap().len(), 27);
    assert_eq!(page["items"][0]["created_at"].as_str().unwrap().len(), 24);
    assert_eq!(page["truncated"], true);
    let cursor = page["next_cursor"].as_str().unwrap();
    let next = response_json(
        app.clone()
            .oneshot(list_request(&format!("?cursor={cursor}")))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(next["items"][0]["case_id"], ids[0]);
    assert_eq!(next["items"][0]["status"], "open");
    assert_eq!(next["truncated"], false);
    assert!(next["next_cursor"].is_null());
    let items = Request::get(format!("{PATH}/{}/items", ids[1]))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let items = response_json(app.clone().oneshot(items).await.unwrap(), StatusCode::OK).await;
    assert_eq!(items["case"]["status"], "closed");

    // The deadline includes waiting for a pooled connection, before SQL can run.
    let held = case_pool.acquire().await.unwrap();
    let started = std::time::Instant::now();
    let unavailable = tokio::time::timeout(
        Duration::from_secs(20),
        app.clone().oneshot(list_request("")),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(15));
    let unavailable = response_json(unavailable, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(unavailable["error_code"], "CONTROL_CASE_STORE_UNAVAILABLE");
    assert_eq!(capacity.available_permits(), 1);
    // Once admitted, disconnecting the HTTP future cannot cancel the required audit.
    let pending = tokio::spawn(app.clone().oneshot(list_request("")));
    tokio::time::timeout(Duration::from_secs(2), async {
        while capacity.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), async {
        while capacity.available_permits() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let failing = pg_fixture(&pool, TENANT, "site_a", "operator-1");
    poison_audit(&failing.control);
    let withheld = response_json(
        router(failing.control)
            .oneshot(list_request(""))
            .await
            .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(withheld["error_code"], "AUDIT_DURABILITY_FAILED");
    assert!(withheld.get("items").is_none());
    fs::remove_dir_all(failing.access_directory.parent().unwrap()).unwrap();

    // The extra pagination row must be decoded before releasing the visible page.
    sqlx::query(
        "UPDATE xshield.investigation_cases SET purpose=$1 WHERE tenant_id=$2 AND case_id=$3",
    )
    .bind("\u{a0}corrupt purpose\u{a0}")
    .bind(TENANT)
    .bind(&ids[0])
    .execute(&pool)
    .await
    .unwrap();
    let corrupt = response_json(
        app.clone().oneshot(list_request("")).await.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(corrupt["error_code"], "CONTROL_CASE_STORE_UNAVAILABLE");
    assert!(corrupt.get("items").is_none());
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    let list_events: Vec<_> = events
        .iter()
        .filter(|event| event["event_type"] == "console.case.list")
        .collect();
    assert_eq!(list_events.len(), 6);
    assert_eq!(
        list_events
            .iter()
            .filter(|event| event["payload"]["outcome"] == "PASS")
            .count(),
        4
    );
    for event in list_events {
        if event["payload"]["outcome"] == "PASS" {
            assert_list_audit(event, "PASS", "CONTROL_CASES_READ");
        } else {
            assert_list_audit(event, "ERROR", "CONTROL_CASE_STORE_UNAVAILABLE");
        }
    }
    for statement in [
        "DELETE FROM xshield.case_closures WHERE tenant_id IN ($1, $2)",
        "DELETE FROM xshield.investigation_cases WHERE tenant_id IN ($1, $2)",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id IN ($1, $2)",
    ] {
        sqlx::query(statement)
            .bind(TENANT)
            .bind(OTHER_TENANT)
            .execute(&pool)
            .await
            .unwrap();
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    case_pool.close().await;
    pool.close().await;
}
