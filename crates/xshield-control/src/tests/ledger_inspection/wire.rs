use super::*;

const TENANT: &str = "tenant_console_ledger_wire";
const FOREIGN: &str = "tenant_console_ledger_foreign";
const SITE: &str = "site_a";
const SUFFIXES: [&str; 5] = ["e201", "e202", "e203", "e204", "e205"];

fn id(kind: &str, suffix: &str) -> String {
    format!("{kind}_018f2a3b-4c5d-7000-8000-00000000{suffix}")
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL and Node.js 22"]
#[allow(clippy::too_many_lines)]
async fn console_ledger_client_reads_postgres_http_contract() {
    let pool = sqlx::PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    seed_wire_history(&pool).await;
    let before = row_versions(&pool).await;
    let observer = scoped_ledger_fixture(pool.clone(), TENANT);
    let mut investigator = scoped_ledger_fixture(pool.clone(), TENANT);
    investigator.control.config.principal = ManagementPrincipal::new(
        "operator-1",
        [ManagementRole::Investigator],
        [(
            TenantId::parse(TENANT).unwrap(),
            SiteId::parse(SITE).unwrap(),
        )],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let denied_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let denied_address = denied_listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router(observer.control)).await });
    let denied_server =
        tokio::spawn(
            async move { axum::serve(denied_listener, router(investigator.control)).await },
        );
    let result = run_console_wire("ledger-wire.ts", address, Some(denied_address)).await;
    server.abort();
    denied_server.abort();
    let stopped = server.await;
    let denied_stopped = denied_server.await;
    let mut events = read_access_events(&observer.access_directory);
    events.extend(read_access_events(&investigator.access_directory));
    let after = row_versions(&pool).await;
    cleanup_wire_history(&pool).await;
    pool.close().await;
    for access in [&observer.access_directory, &investigator.access_directory] {
        // Each root is owned by one fixture created in this test.
        fs::remove_dir_all(access.parent().unwrap()).unwrap();
    }
    assert!(stopped.is_err_and(|error| error.is_cancelled()));
    assert!(denied_stopped.is_err_and(|error| error.is_cancelled()));
    let status = result.unwrap();
    assert!(
        status.success(),
        "ledger wire contract failed; phase={:?}",
        status.code()
    );
    assert_eq!(
        before, after,
        "ledger reads preserve business rows and outbox"
    );
    let expected = [
        ("grant", "e101", "CONTROL_GRANT_READ"),
        ("binding", "e102", "CONTROL_BINDING_READ"),
        ("grant", "ffff", "CONTROL_GRANT_READ"),
        ("binding", "ffff", "CONTROL_BINDING_READ"),
        ("grant", "e201", "CONTROL_GRANT_READ"),
        ("grant", "e202", "CONTROL_GRANT_READ"),
        ("grant", "e203", "CONTROL_GRANT_READ"),
        ("grant", "e204", "CONTROL_GRANT_READ"),
        ("binding", "e201", "CONTROL_BINDING_READ"),
        ("binding", "e202", "CONTROL_BINDING_READ"),
        ("binding", "e203", "CONTROL_BINDING_READ"),
        ("binding", "e204", "CONTROL_BINDING_READ"),
        ("grant", "e205", "CONTROL_GRANT_STORE_UNAVAILABLE"),
        ("binding", "e205", "CONTROL_BINDING_STORE_UNAVAILABLE"),
        ("grant", "e301", "CONTROL_GRANT_READ"),
        ("binding", "e301", "CONTROL_BINDING_READ"),
        ("grant", "e101", "CONTROL_AUTH_REQUIRED"),
        ("binding", "e102", "CONTROL_AUTH_REQUIRED"),
        ("grant", "e101", "CONTROL_SCOPE_DENIED"),
        ("binding", "e102", "CONTROL_SCOPE_DENIED"),
    ];
    assert_eq!(events.len(), expected.len());
    let mut requests = std::collections::BTreeSet::new();
    for (event, (kind, suffix, reason)) in events.iter().zip(expected) {
        let grant = kind == "grant";
        assert_eq!(event["event_type"], format!("console.{kind}.read"));
        assert_eq!(event["tenant_id"], TENANT);
        assert_eq!(event["site_id"], SITE);
        assert!(requests.insert(event["request_id"].as_str().unwrap()));
        assert_eq!(event["payload"]["method"], "GET");
        assert_eq!(
            event["payload"]["path"],
            if grant {
                "/control/v1/grants/{grant_id}"
            } else {
                "/control/v1/auth-bindings/{binding_id}"
            }
        );
        assert_eq!(event["payload"]["reason_code"], reason);
        let denied = matches!(reason, "CONTROL_AUTH_REQUIRED" | "CONTROL_SCOPE_DENIED");
        assert_eq!(
            event["payload"]["outcome"],
            if denied {
                "DENY"
            } else if reason.ends_with("UNAVAILABLE") {
                "ERROR"
            } else {
                "PASS"
            }
        );
        assert_eq!(
            event["payload"][if grant {
                "target_grant_id"
            } else {
                "target_binding_id"
            }],
            if denied {
                Value::Null
            } else {
                json!(id(if grant { "grant" } else { "auth" }, suffix))
            }
        );
        assert!(event["payload"]["target_request_id"].is_null());
        assert!(event["payload"].get("grant").is_none());
        assert!(event["payload"].get("binding").is_none());
        assert_eq!(event["evidence_refs"], json!([]));
    }
}

#[allow(clippy::too_many_lines)]
async fn seed_wire_history(pool: &sqlx::PgPool) {
    ledger_fixture::seed(pool, TENANT, SITE).await;
    ledger_fixture::seed(pool, FOREIGN, SITE).await;
    for (tenant, suffix, status, epoch, generation, expired, corrupt) in [
        (TENANT, "e201", "anonymous", 0_i64, 0_i64, false, false),
        (TENANT, "e202", "active", 4, 2, true, false),
        (TENANT, "e203", "revoked", 5, 3, true, false),
        (TENANT, "e204", "expired", 4, 2, true, false),
        (TENANT, "e205", "active", 4, 2, false, true),
        (FOREIGN, "e301", "active", 4, 2, false, false),
    ] {
        sqlx::query(
            "INSERT INTO xshield.auth_bindings
             (tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
              authorization_context_ref, auth_epoch, credential_generation, status,
              absolute_expires_at)
             VALUES ($1, $2, $3, decode(repeat($4, 16), 'hex'),
              CASE WHEN $5 = 'anonymous' THEN NULL ELSE 'wire-principal' END,
              CASE WHEN $5 = 'anonymous' THEN NULL ELSE 'wire-context' END, $6, $7, $5,
              CASE WHEN $9 THEN 'infinity'::timestamptz
                   WHEN $8 THEN now() - interval '1 second'
                   ELSE now() + interval '900 seconds' END)",
        )
        .bind(tenant)
        .bind(SITE)
        .bind(id("auth", suffix))
        .bind(suffix)
        .bind(status)
        .bind(epoch)
        .bind(generation)
        .bind(expired)
        .bind(corrupt)
        .execute(pool)
        .await
        .unwrap();
    }
    // Preserve the original source graph while observing a later binding epoch.
    sqlx::query(
        "INSERT INTO xshield.page_evidence
         (tenant_id, site_id, page_evidence_id, binding_id, auth_epoch, source_request_id,
          response_artifact_ref, page_template, build_fingerprint, policy_revision,
          mapping_revision, status, verified_at, expires_at)
         SELECT tenant_id, site_id, $3, $4, auth_epoch, source_request_id,
          response_artifact_ref, page_template, build_fingerprint, policy_revision,
          mapping_revision, status, verified_at, expires_at
         FROM xshield.page_evidence WHERE tenant_id=$1 AND site_id=$2
          AND page_evidence_id='page_018f2a3b-4c5d-7000-8000-00000000e105'",
    )
    .bind(TENANT)
    .bind(SITE)
    .bind(id("page", "e203"))
    .bind(id("auth", "e203"))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.ui_actions
         (tenant_id, site_id, action_ref, binding_id, auth_epoch, source_request_id,
          page_evidence_id, operation_id, target_constraints, field_profile, source_rule,
          policy_revision, status, issued_at, expires_at, source_action_ref,
          mapping_revision, method, route_template, allowed_fields)
         SELECT tenant_id, site_id, 'wire-revoked-action', $3, auth_epoch, source_request_id,
          $4, operation_id, target_constraints, field_profile, source_rule,
          policy_revision, status, issued_at, expires_at, source_action_ref,
          mapping_revision, method, route_template, allowed_fields
         FROM xshield.ui_actions WHERE tenant_id=$1 AND site_id=$2
          AND action_ref='inspection-action'",
    )
    .bind(TENANT)
    .bind(SITE)
    .bind(id("auth", "e203"))
    .bind(id("page", "e203"))
    .execute(pool)
    .await
    .unwrap();
    for (tenant, suffix, status, expired) in [
        (TENANT, "e201", "expired", true),
        (TENANT, "e202", "revoked", false),
        (TENANT, "e203", "active", true),
        (TENANT, "e204", "active", false),
        (TENANT, "e205", "active", false),
        (FOREIGN, "e301", "active", false),
    ] {
        sqlx::query(
            "INSERT INTO xshield.resource_grants
             (tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref, resource_type,
              resource_key_hmac, operation_id, view_id, constraints, source_event_id,
              issuance_key, policy_revision, status, issued_at, expires_at)
             SELECT tenant_id, site_id, $3,
              CASE WHEN $4 = 'e204' THEN $7 ELSE binding_id END, auth_epoch,
              CASE WHEN $4 = 'e204' THEN 'wire-revoked-action' ELSE action_ref END,
              resource_type, resource_key_hmac, operation_id, view_id, constraints,
              CASE WHEN $4 = 'e205' THEN 'invalid-event' ELSE source_event_id END,
              $3, policy_revision, $5, issued_at,
              CASE WHEN $6 THEN now() - interval '1 second' ELSE expires_at END
             FROM xshield.resource_grants WHERE tenant_id=$1 AND site_id=$2 AND grant_id=$8",
        )
        .bind(tenant)
        .bind(SITE)
        .bind(id("grant", suffix))
        .bind(suffix)
        .bind(status)
        .bind(expired)
        .bind(id("auth", "e203"))
        .bind(GRANT)
        .execute(pool)
        .await
        .unwrap();
    }
}

async fn row_versions(pool: &sqlx::PgPool) -> Vec<(String, String, String)> {
    sqlx::query_as(
        "SELECT 'binding' AS kind, binding_id AS id, xmin::text AS version
         FROM xshield.auth_bindings WHERE tenant_id=$1 AND site_id=$2
         UNION ALL SELECT 'grant', grant_id, xmin::text FROM xshield.resource_grants
          WHERE tenant_id=$1 AND site_id=$2
         UNION ALL SELECT 'outbox', '', count(*)::text FROM xshield.audit_outbox
          WHERE tenant_id=$1 AND site_id=$2 ORDER BY 1,2",
    )
    .bind(TENANT)
    .bind(SITE)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn cleanup_wire_history(pool: &sqlx::PgPool) {
    for (tenant, suffixes) in [
        (TENANT, SUFFIXES.as_slice()),
        (FOREIGN, ["e301"].as_slice()),
    ] {
        let grants: Vec<_> = suffixes.iter().map(|suffix| id("grant", suffix)).collect();
        sqlx::query("DELETE FROM xshield.resource_grants WHERE tenant_id=$1 AND site_id=$2 AND grant_id=ANY($3)")
            .bind(tenant).bind(SITE).bind(grants).execute(pool).await.unwrap();
        if tenant == TENANT {
            sqlx::query("DELETE FROM xshield.ui_actions WHERE tenant_id=$1 AND site_id=$2 AND action_ref='wire-revoked-action'")
                .bind(tenant).bind(SITE).execute(pool).await.unwrap();
            sqlx::query("DELETE FROM xshield.page_evidence WHERE tenant_id=$1 AND site_id=$2 AND page_evidence_id=$3")
                .bind(tenant).bind(SITE).bind(id("page", "e203")).execute(pool).await.unwrap();
        }
        let bindings: Vec<_> = suffixes.iter().map(|suffix| id("auth", suffix)).collect();
        sqlx::query("DELETE FROM xshield.auth_bindings WHERE tenant_id=$1 AND site_id=$2 AND binding_id=ANY($3)")
            .bind(tenant).bind(SITE).bind(bindings).execute(pool).await.unwrap();
        ledger_fixture::cleanup(pool, tenant, SITE).await;
    }
}
