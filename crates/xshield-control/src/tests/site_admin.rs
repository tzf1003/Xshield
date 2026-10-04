use super::*;

fn request(method: &str, path: &str, value: &Value, key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"));
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key);
    }
    let body = if value.is_null() {
        Body::empty()
    } else {
        builder = builder.header("content-type", "application/json");
        Body::from(serde_json::to_vec(value).unwrap())
    };
    builder.body(body).unwrap()
}
async fn json_response(response: axum::response::Response, status: StatusCode) -> Value {
    let actual = response.status();
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await.unwrap()).unwrap();
    assert_eq!(actual, status, "{value}");
    value
}

#[tokio::test]
async fn site_admin_separates_role_denials_from_dependency_failure() {
    for (role, expected, code) in [
        (
            ManagementRole::Observer,
            StatusCode::FORBIDDEN,
            "CONTROL_SCOPE_DENIED",
        ),
        (
            ManagementRole::SystemAdmin,
            StatusCode::SERVICE_UNAVAILABLE,
            "CONTROL_SITE_CONFIG_UNAVAILABLE",
        ),
    ] {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy("postgresql://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        let mut fixture =
            Fixture::with_catalog(10, role, PostgresIdentityStore::from_pool(pool), 1);
        fixture.control.config.principal = ManagementPrincipal::new_tenant_scoped(
            "operator-1",
            [role],
            [TenantId::parse("tenant_a").unwrap()],
        )
        .unwrap();
        let app = router(fixture.control);
        let body = json_response(
            app.clone()
                .oneshot(request(
                    "GET",
                    "/control/v1/sites?limit=100",
                    &Value::Null,
                    None,
                ))
                .await
                .unwrap(),
            expected,
        )
        .await;
        assert_eq!(body["error_code"], code);
        assert!(body["request_id"].as_str().unwrap().starts_with("req_"));
        if code == "CONTROL_SITE_CONFIG_UNAVAILABLE" {
            assert_eq!(body["stage"], "site_config_store");
            assert_eq!(body["retryable"], true);
        } else {
            assert!(body.get("stage").is_none());
        }
        drop(app);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["payload"]["reason_code"], code);
        fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn site_admin_http_persists_replays_and_requires_independent_approval() {
    let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let store = PostgresIdentityStore::connect(&url, 4, Duration::from_secs(5))
        .await
        .unwrap();
    let tenant = TenantId::parse(format!("tenant_site_http_{}", Uuid::now_v7())).unwrap();
    let site = SiteId::parse("site_http_contract").unwrap();
    let mut fixture = Fixture::with_catalog(100, ManagementRole::SystemAdmin, store, 1);
    fixture.control.config.tenant_id = tenant.clone();
    fixture.control.config.site_id = site.clone();
    fixture.control.config.principal = ManagementPrincipal::new_tenant_scoped(
        "operator-1",
        [
            ManagementRole::SystemAdmin,
            ManagementRole::Observer,
            ManagementRole::PolicyAuthor,
            ManagementRole::PolicyApprover,
            ManagementRole::ReleaseOperator,
        ],
        [tenant.clone()],
    )
    .unwrap();
    let app = router(fixture.control);
    let list = json_response(
        app.clone()
            .oneshot(request(
                "GET",
                "/control/v1/sites?limit=100",
                &Value::Null,
                None,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(list["sites"], json!([]));
    let missing = json_response(
        app.clone()
            .oneshot(request(
                "GET",
                "/control/v1/sites/site_http_contract/config",
                &Value::Null,
                None,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(missing["found"], false);
    assert_eq!(missing["requires_approval"], Value::Null);
    let payload = json!({"site_id": site.as_str(), "display_name": "HTTP contract site", "public_origin": "https://example.test", "upstream_address": "8.8.8.8:9000", "upstream_server_name": "example.test", "upstream_tls": false, "listen_port": 0, "entry_path": "/", "security_entry": "public", "sensor_enabled": false, "policy_revision": "policy-v1", "status": "draft"});
    let created = json_response(
        app.clone()
            .oneshot(request(
                "POST",
                "/control/v1/sites",
                &payload,
                Some("site-create-contract-key"),
            ))
            .await
            .unwrap(),
        StatusCode::CREATED,
    )
    .await;
    assert_eq!(created["requires_approval"], true);
    assert!(created["config"]["listen_port"].as_u64().unwrap() >= 6100);
    let replay = json_response(
        app.clone()
            .oneshot(request(
                "POST",
                "/control/v1/sites",
                &payload,
                Some("site-create-contract-key"),
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(replay["config"]["revision"], created["config"]["revision"]);
    let validated = json_response(
        app.clone()
            .oneshot(request(
                "POST",
                "/control/v1/sites/site_http_contract/validate",
                &Value::Null,
                None,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(validated["valid"], true);
    let approval = json_response(
        app.clone()
            .oneshot(request(
                "POST",
                "/control/v1/sites/site_http_contract/approve",
                &Value::Null,
                Some("self-approval-contract-key"),
            ))
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(
        approval["error_code"],
        "CONTROL_SITE_APPROVAL_SELF_REJECTED"
    );
    let apply = json_response(
        app.clone()
            .oneshot(request(
                "POST",
                "/control/v1/sites/site_http_contract/apply",
                &Value::Null,
                Some("apply-contract-key"),
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(apply["requires_approval"], true);
    assert_ne!(apply["apply_state"], "active");
    let approver_store = PostgresIdentityStore::connect(&url, 4, Duration::from_secs(5))
        .await
        .unwrap();
    let mut approver_fixture = Fixture::with_decision_catalog(
        approver_store,
        "independent-reviewer",
        ManagementRole::PolicyApprover,
    );
    approver_fixture.control.config.tenant_id = tenant.clone();
    approver_fixture.control.config.site_id = site.clone();
    approver_fixture.control.config.principal = ManagementPrincipal::new(
        "independent-reviewer",
        [ManagementRole::PolicyApprover],
        [(tenant.clone(), site.clone())],
    )
    .unwrap();
    let approver = router(approver_fixture.control);
    let decision = json_response(
        approver
            .clone()
            .oneshot(request(
                "POST",
                "/control/v1/sites/site_http_contract/approve",
                &Value::Null,
                Some("independent-approval-key"),
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(decision["requires_approval"], false);
    assert_ne!(decision["apply_state"], "active");
    drop(approver);
    let approval_events = read_access_events(&approver_fixture.access_directory);
    assert!(
        approval_events
            .iter()
            .any(|event| event["payload"]["reason_code"] == "CONTROL_SITE_APPROVED_PENDING")
    );
    fs::remove_dir_all(approver_fixture.access_directory.parent().unwrap()).unwrap();
    let outsider = json_response(
        app.clone()
            .oneshot(request(
                "GET",
                "/control/v1/sites/another_site/status",
                &Value::Null,
                None,
            ))
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_eq!(outsider["error_code"], "CONTROL_SITE_NOT_FOUND");
    drop(app);
    let events = read_access_events(&fixture.access_directory);
    assert!(
        events
            .iter()
            .any(|event| event["payload"]["reason_code"] == "CONTROL_SITE_APPROVAL_SELF_REJECTED")
    );
    assert!(
        events
            .iter()
            .all(|event| event["evidence_refs"] == json!([]))
    );
    fs::remove_dir_all(fixture.access_directory.parent().unwrap()).unwrap();
}
