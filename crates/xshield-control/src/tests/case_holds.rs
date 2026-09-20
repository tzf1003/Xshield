use super::*;

const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000961";
const HOLD: &str = "ev_018f2a3b-4c5d-7000-8000-000000000962";
const KEY: &str = "hold-management-key-0001";

fn request(kind: &str, target: &str, query: &str, body: &str) -> Request<Body> {
    let builder = match kind {
        "create" => Request::post(format!("/control/v1/cases/{target}/holds{query}")),
        "release" => Request::post(format!(
            "/control/v1/evidence-holds/{target}/release{query}"
        )),
        _ => Request::get(format!("/control/v1/cases/{target}/holds{query}")),
    };
    builder
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(CONTENT_TYPE, "application/json")
        .header("idempotency-key", KEY)
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn body(kind: &str) -> String {
    if kind == "create" {
        json!({"artifact_id": MISSING_ARTIFACT_ID, "reason": "private hold reason",
            "hold_until": "2030-01-01T00:00:00.000Z"})
        .to_string()
    } else {
        json!({"reason": "private release reason"}).to_string()
    }
}

async fn response_json(response: axum::response::Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "private, no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn hold_mutations_validate_strict_inputs_before_storage_and_audit_safe_targets() {
    let fixture = Fixture::new(100, ManagementRole::AuditAdministrator);
    let app = router(fixture.control);
    let create = body("create");
    let release = body("release");
    let mut count = 0;
    for (kind, target, query, body, code) in [
        (
            "create",
            "bad",
            "",
            create.as_str(),
            "CONTROL_CASE_ID_INVALID",
        ),
        ("create", "%FF", "", &create, "CONTROL_CASE_ID_INVALID"),
        (
            "release",
            "bad",
            "",
            &release,
            "CONTROL_EVIDENCE_HOLD_ID_INVALID",
        ),
        (
            "release",
            "%FF",
            "",
            &release,
            "CONTROL_EVIDENCE_HOLD_ID_INVALID",
        ),
        (
            "create",
            CASE,
            "?tenant_id=foreign",
            &create,
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID",
        ),
        (
            "release",
            HOLD,
            "?cursor=x",
            &release,
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID",
        ),
        (
            "create",
            CASE,
            "",
            "{}",
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID",
        ),
        (
            "release",
            HOLD,
            "",
            "{}",
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID",
        ),
        (
            "release",
            HOLD,
            "",
            r#"{"reason":"one","reason":"two"}"#,
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID",
        ),
        (
            "release",
            HOLD,
            "",
            r#"{"reason":"one","tenant_id":"other"}"#,
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID",
        ),
        (
            "release",
            HOLD,
            "",
            r#"{"reason":" padded "}"#,
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID",
        ),
        (
            "release",
            HOLD,
            "",
            r#"{"reason":"line\nbreak"}"#,
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID",
        ),
        ("list", "bad", "", "", "CONTROL_CASE_ID_INVALID"),
        ("list", "%FF", "", "", "CONTROL_CASE_ID_INVALID"),
        ("list", CASE, "?cursor=bad", "", "CONTROL_CURSOR_INVALID"),
        ("list", CASE, "?limit=1000", "", "CONTROL_CURSOR_INVALID"),
        (
            "list",
            CASE,
            "?cursor=bad&cursor=bad",
            "",
            "CONTROL_CURSOR_INVALID",
        ),
    ] {
        let result = response_json(
            app.clone()
                .oneshot(request(kind, target, query, body))
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(result["error_code"], code);
        count += 1;
    }
    for (field, invalid) in [
        ("artifact_id", json!("bad")),
        ("reason", json!("")),
        ("reason", json!("界".repeat(171))),
        ("reason", json!("x".repeat(4096))),
        ("hold_until", json!("2030-01-01T00:00:00Z")),
        ("hold_until", json!("2030-01-01T00:00:00.000+00:00")),
        ("hold_until", json!("2030-01-01T00:00:00.000001Z")),
        ("hold_until", json!("1969-01-01T00:00:00.000Z")),
        ("hold_until", json!("9999-01-01T00:00:00.000Z")),
        ("hold_until", json!("2030-01-01T23:59:60.000Z")),
        ("tenant_id", json!("foreign")),
    ] {
        let mut payload: Value = serde_json::from_str(&create).unwrap();
        payload[field] = invalid;
        let result = response_json(
            app.clone()
                .oneshot(request("create", CASE, "", &payload.to_string()))
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(
            result["error_code"],
            "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID"
        );
        count += 1;
    }
    for kind in ["create", "release"] {
        for key in [
            None,
            Some("short"),
            Some("invalid key characters"),
            Some(KEY),
        ] {
            let mut req = request(
                kind,
                if kind == "create" { CASE } else { HOLD },
                "",
                &body(kind),
            );
            req.headers_mut().remove("idempotency-key");
            if let Some(key) = key {
                req.headers_mut()
                    .insert("idempotency-key", key.parse().unwrap());
            }
            if key == Some(KEY) {
                req.headers_mut()
                    .append("idempotency-key", KEY.parse().unwrap());
            }
            let result = response_json(
                app.clone().oneshot(req).await.unwrap(),
                StatusCode::BAD_REQUEST,
            )
            .await;
            assert_eq!(result["error_code"], "CONTROL_IDEMPOTENCY_KEY_INVALID");
            count += 1;
        }
    }
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert_eq!(events.len(), count);
    for event in events {
        assert_eq!(event["payload"]["outcome"], "DENY");
        assert_eq!(event["evidence_refs"], json!([]));
        assert!(!event.to_string().contains(KEY));
        assert!(!event.to_string().contains("private hold reason"));
        assert!(!event.to_string().contains("private release reason"));
        assert!(
            event["event_type"]
                .as_str()
                .unwrap()
                .starts_with("console.evidence.hold.")
        );
    }
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn hold_routes_enforce_auth_scope_role_rate_and_bounded_storage() {
    for kind in ["create", "release", "list"] {
        for scenario in [
            "missing",
            "duplicate",
            "expired",
            "role",
            "scope",
            "rate",
            "busy",
            "store",
            "audit",
        ] {
            let mut fixture = Fixture::new(1, ManagementRole::AuditAdministrator);
            let mut req = request(
                kind,
                if kind == "release" { HOLD } else { CASE },
                "",
                &body(kind),
            );
            let pool = sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
                .unwrap();
            pool.close().await;
            fixture.control.catalog = PostgresIdentityStore::from_pool(pool);
            let mut permit = None;
            let (status, code) = match scenario {
                "missing" => {
                    req.headers_mut().remove(AUTHORIZATION);
                    (StatusCode::UNAUTHORIZED, "CONTROL_AUTH_REQUIRED")
                }
                "duplicate" => {
                    req.headers_mut()
                        .append(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
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
                            ManagementRole::Investigator
                        } else {
                            ManagementRole::AuditAdministrator
                        }],
                        [(
                            TenantId::parse(if scenario == "scope" {
                                "foreign"
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
                            .try_acquire_owned()
                            .unwrap(),
                    );
                    (StatusCode::TOO_MANY_REQUESTS, "CONTROL_EVIDENCE_HOLD_BUSY")
                }
                "audit" => {
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
                    (StatusCode::SERVICE_UNAVAILABLE, "AUDIT_DURABILITY_FAILED")
                }
                _ => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EVIDENCE_HOLD_STORE_UNAVAILABLE",
                ),
            };
            let result =
                response_json(router(fixture.control).oneshot(req).await.unwrap(), status).await;
            assert_eq!(result["error_code"], code, "{kind}/{scenario}");
            assert!(result.get("hold_id").is_none());
            if scenario != "audit" {
                let events = read_access_events(&fixture.access_directory);
                assert_eq!(events.len(), 1);
                assert_eq!(events[0]["payload"]["reason_code"], code);
                assert_eq!(events[0]["evidence_refs"], json!([]));
                if scenario == "busy" || scenario == "store" {
                    let field = if kind == "release" {
                        "target_hold_id"
                    } else {
                        "target_case_id"
                    };
                    assert_eq!(
                        events[0]["payload"][field],
                        if kind == "release" { HOLD } else { CASE }
                    );
                }
            }
            drop(permit);
            fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
        }
    }
}
