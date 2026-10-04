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
    // The site is created `active`: a draft is never applied and exposes
    // nothing, so it has no approval requirement to exercise here (drafts are
    // covered by the `site_approval` tests).
    let payload = json!({"site_id": site.as_str(), "display_name": "HTTP contract site", "public_origin": "https://example.test", "upstream_address": "8.8.8.8:9000", "upstream_server_name": "example.test", "upstream_tls": false, "listen_port": 0, "entry_path": "/", "security_entry": "public", "sensor_enabled": false, "policy_revision": "policy-v1", "status": "active"});
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

fn site_body(site: &str, upstream: &str) -> Value {
    json!({
        "site_id": site,
        "display_name": "SSRF contract site",
        "public_origin": "https://example.test",
        "upstream_address": upstream,
        "upstream_server_name": "example.test",
        "upstream_tls": false,
        "listen_port": 0,
        "entry_path": "/",
        "security_entry": "public",
        "sensor_enabled": false,
        "policy_revision": "policy-v1",
        "status": "active"
    })
}

/// The reviewer's reproduction: every one of these used to be accepted with
/// 201. They are refused before any storage access, with one stable code and
/// an audited DENY for each attempt.
#[tokio::test]
async fn site_admin_refuses_internal_upstreams_before_touching_storage() {
    let fixture = Fixture::new(500, ManagementRole::SystemAdmin);
    let access_directory = fixture.access_directory.clone();
    let app = router(fixture.control);
    let blocked = [
        "[::1]:9000",
        "[fd00::1]:9000",
        "[fe80::1]:9000",
        "[::ffff:127.0.0.1]:8080",
        "[::ffff:169.254.169.254]:8080",
        "127.0.0.1:9000",
        "169.254.169.254:80",
    ];
    for (index, address) in blocked.iter().enumerate() {
        let response = json_response(
            app.clone()
                .oneshot(request(
                    "PUT",
                    "/control/v1/sites/site_a/config",
                    &site_body("site_a", address),
                    Some(&format!("ssrf-contract-key-{index:02}")),
                ))
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        assert_eq!(
            response["error_code"], "CONTROL_SITE_SSRF_BLOCKED",
            "{address}"
        );
    }
    // A bare IP literal as server name is not a DNS name: it made the health
    // probe dial that address instead of the configured upstream.
    let mut literal_name = site_body("site_a", "8.8.8.8:9000");
    literal_name["upstream_server_name"] = json!("127.0.0.1");
    let response = json_response(
        app.clone()
            .oneshot(request(
                "PUT",
                "/control/v1/sites/site_a/config",
                &literal_name,
                Some("ssrf-contract-key-name"),
            ))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(response["error_code"], "CONTROL_SITE_UPSTREAM_INVALID");
    drop(app);
    let events = read_access_events(&access_directory);
    assert_eq!(events.len(), blocked.len() + 1);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event["payload"]["outcome"], "DENY");
        assert_eq!(
            event["payload"]["reason_code"],
            if index < blocked.len() {
                "CONTROL_SITE_SSRF_BLOCKED"
            } else {
                "CONTROL_SITE_UPSTREAM_INVALID"
            }
        );
    }
    fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
}

/// A row written before the rules were tightened (or edited in the database)
/// must not make the health endpoint forward a request to a loopback listener:
/// an Observer's `GET /health` used to send `GET /secret-internal-path` to a
/// service reachable only from the control host.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn site_health_probe_never_dials_a_legacy_mapped_loopback_row() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let url = std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let store = PostgresIdentityStore::connect(&url, 4, Duration::from_secs(5))
        .await
        .unwrap();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let tenant = TenantId::parse(format!("tenant_site_ssrf_{}", Uuid::now_v7())).unwrap();
    let site = SiteId::parse("site_ssrf_legacy").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&connections);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buffer = vec![0_u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
        }
    });
    let mut fixture = Fixture::with_catalog(100, ManagementRole::SystemAdmin, store, 1);
    fixture.control.config.tenant_id = tenant.clone();
    fixture.control.config.site_id = site.clone();
    fixture.control.config.principal = ManagementPrincipal::new_tenant_scoped(
        "operator-1",
        [ManagementRole::SystemAdmin, ManagementRole::Observer],
        [tenant.clone()],
    )
    .unwrap();
    let access_directory = fixture.access_directory.clone();
    let app = router(fixture.control);
    let created = json_response(
        app.clone()
            .oneshot(request(
                "PUT",
                &format!("/control/v1/sites/{}/config", site.as_str()),
                &site_body(site.as_str(), "8.8.8.8:9000"),
                Some("legacy-row-create-key"),
            ))
            .await
            .unwrap(),
        StatusCode::CREATED,
    )
    .await;
    assert!(created["config"]["listen_port"].as_u64().unwrap() >= 6100);
    sqlx::query(
        "UPDATE xshield.protected_site_configs SET upstream_address = $3
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(format!("[::ffff:127.0.0.1]:{port}"))
    .execute(&pool)
    .await
    .unwrap();
    let health = json_response(
        app.clone()
            .oneshot(request(
                "GET",
                &format!("/control/v1/sites/{}/health", site.as_str()),
                &Value::Null,
                None,
            ))
            .await
            .unwrap(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(health["edge_health"]["upstream_state"], "unavailable");
    assert_eq!(
        health["edge_health"]["upstream_health"]["reason_code"],
        "CONTROL_SITE_SSRF_BLOCKED"
    );
    drop(app);
    assert_eq!(
        connections.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the loopback listener must never be contacted"
    );
    fs::remove_dir_all(access_directory.parent().unwrap()).unwrap();
}
