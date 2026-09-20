//! Console client retention lifecycle over real Axum, `PostgreSQL` and management journals.

use super::*;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

struct Context {
    pool: sqlx::PgPool,
    tenant: TenantId,
    roots: Arc<Mutex<Vec<PathBuf>>>,
}

impl Context {
    fn fixture(
        &self,
        subject: &str,
        role: ManagementRole,
        tenant: TenantId,
        site: SiteId,
    ) -> Fixture {
        let mut fixture = Fixture::with_decision_catalog(
            PostgresIdentityStore::from_pool(self.pool.clone()),
            subject,
            role,
        );
        fixture.control.config.tenant_id = tenant.clone();
        fixture.control.config.site_id = site.clone();
        fixture.control.config.principal =
            ManagementPrincipal::new(subject, [role], [(tenant, site)]).unwrap();
        fixture.control.config.limits.max_query_artifacts = 1;
        fixture.control.rate.lock().unwrap().limit = 1_000;
        self.roots
            .lock()
            .unwrap()
            .push(fixture.access_directory.parent().unwrap().to_owned());
        fixture
    }
}

#[tokio::test]
#[ignore = "requires script-owned XSHIELD_TEST_DATABASE_URL and Node.js 22"]
async fn console_hold_client_mutates_postgres_http_contract() {
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
    let tenant = TenantId::parse(format!("tenant_hold_wire_{}", Uuid::now_v7().simple())).unwrap();
    let roots = Arc::new(Mutex::new(Vec::new()));
    let result = tokio::spawn(run(Context {
        pool: pool.clone(),
        tenant: tenant.clone(),
        roots: roots.clone(),
    }))
    .await;
    // Cleanup is outside the assertion task so even failed wire assertions release fixtures.
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
async fn run(context: Context) {
    let site = SiteId::parse("site_a").unwrap();
    let owner = context.fixture(
        "console-hold-owner",
        ManagementRole::Investigator,
        context.tenant.clone(),
        site.clone(),
    );
    let admin = context.fixture(
        "console-hold-admin",
        ManagementRole::AuditAdministrator,
        context.tenant.clone(),
        site.clone(),
    );
    let observer = context.fixture(
        "console-hold-observer",
        ManagementRole::Observer,
        context.tenant.clone(),
        site.clone(),
    );
    let foreign_tenant = context.fixture(
        "console-hold-admin",
        ManagementRole::AuditAdministrator,
        TenantId::parse("tenant_hold_wire_foreign").unwrap(),
        site.clone(),
    );
    let foreign_site = context.fixture(
        "console-hold-admin",
        ManagementRole::AuditAdministrator,
        context.tenant.clone(),
        SiteId::parse("site_foreign").unwrap(),
    );
    let vault_root = owner.access_directory.parent().unwrap().join("vault");
    private_directory(&vault_root);
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&vault_root, "hold-wire-key", 1024, 30).unwrap(),
        EvidenceKey::from_hex("5555555555555555555555555555555555555555555555555555555555555555")
            .unwrap(),
    )
    .unwrap();
    let artifact = publish_test_artifact(
        &owner.control.catalog,
        &vault,
        &context.tenant,
        &site,
        &RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap(),
        1,
    )
    .await;
    let expiry: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM xshield.artifact_catalog WHERE artifact_id=$1")
            .bind(&artifact)
            .fetch_one(&context.pool)
            .await
            .unwrap();
    let until: DateTime<Utc> = sqlx::query_scalar(
        "SELECT date_trunc('milliseconds',clock_timestamp()) + interval '1 day'",
    )
    .fetch_one(&context.pool)
    .await
    .unwrap();
    // JoinSet aborts all owned loopback servers if an assertion unwinds.
    let mut servers = tokio::task::JoinSet::new();
    let mut addresses = Vec::new();
    let mut directories = Vec::new();
    for fixture in [owner, admin, observer, foreign_tenant, foreign_site] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        addresses.push(listener.local_addr().unwrap());
        directories.push(fixture.access_directory);
        servers.spawn(async move { axum::serve(listener, router(fixture.control)).await });
    }
    let result = run_console_wire_with_env(
        "hold-wire.ts",
        addresses[0],
        Some(addresses[2]),
        vec![
            (
                "XSHIELD_CONSOLE_TEST_ADMIN_ORIGIN",
                format!("http://{}", addresses[1]),
            ),
            (
                "XSHIELD_CONSOLE_TEST_FOREIGN_TENANT_ORIGIN",
                format!("http://{}", addresses[3]),
            ),
            (
                "XSHIELD_CONSOLE_TEST_FOREIGN_SITE_ORIGIN",
                format!("http://{}", addresses[4]),
            ),
            (
                "XSHIELD_CONSOLE_TEST_TENANT",
                context.tenant.as_str().to_owned(),
            ),
            ("XSHIELD_CONSOLE_TEST_ARTIFACT", artifact.clone()),
            (
                "XSHIELD_CONSOLE_TEST_HOLD_UNTIL",
                until.to_rfc3339_opts(SecondsFormat::Millis, true),
            ),
        ],
    )
    .await;
    servers.shutdown().await;
    let result = result.unwrap();
    assert!(
        result.success(),
        "hold wire contract failed; phase={:?}",
        result.code()
    );
    assert_state(&context, &artifact, expiry).await;
    let events: Vec<_> = directories
        .iter()
        .map(|path| read_access_events(path))
        .collect();
    assert_journals(&events);
}

async fn assert_state(context: &Context, artifact: &str, expiry: DateTime<Utc>) {
    let counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT event_type,count(*) FROM xshield.audit_outbox WHERE tenant_id=$1 GROUP BY event_type ORDER BY event_type",
    ).bind(context.tenant.as_str()).fetch_all(&context.pool).await.unwrap();
    assert_eq!(
        counts,
        vec![
            ("case.closed".to_owned(), 1),
            ("case.created".to_owned(), 2),
            ("case.evidence.added".to_owned(), 1),
            ("evidence.cataloged".to_owned(), 1),
            ("evidence.hold.created".to_owned(), 2),
            ("evidence.hold.released".to_owned(), 2),
        ]
    );
    let holds: Vec<(String, String, String, String, bool, bool)> = sqlx::query_as(
        "SELECT h.created_by,h.reason,h.released_by,h.released_reason,
          EXISTS(SELECT 1 FROM xshield.audit_outbox o WHERE o.tenant_id=h.tenant_id AND o.site_id=h.site_id AND o.event_id=h.created_event_id AND o.event_type='evidence.hold.created'),
          EXISTS(SELECT 1 FROM xshield.audit_outbox o WHERE o.tenant_id=h.tenant_id AND o.site_id=h.site_id AND o.event_id=h.released_event_id AND o.event_type='evidence.hold.released')
         FROM xshield.case_evidence_holds h WHERE h.tenant_id=$1",
    ).bind(context.tenant.as_str()).fetch_all(&context.pool).await.unwrap();
    assert_eq!(holds.len(), 2);
    for hold in holds {
        assert_eq!(
            hold,
            (
                "console-hold-admin".to_owned(),
                "Wire sensitive retention reason".to_owned(),
                "console-hold-admin".to_owned(),
                "Wire sensitive release reason".to_owned(),
                true,
                true
            )
        );
    }
    let cases: Vec<(String, String)> = sqlx::query_as("SELECT owner_ref,status FROM xshield.investigation_cases WHERE tenant_id=$1 ORDER BY status")
        .bind(context.tenant.as_str()).fetch_all(&context.pool).await.unwrap();
    assert_eq!(
        cases,
        vec![
            ("console-hold-owner".to_owned(), "closed".to_owned()),
            ("console-hold-owner".to_owned(), "open".to_owned())
        ]
    );
    let after_expiry: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM xshield.artifact_catalog WHERE artifact_id=$1")
            .bind(artifact)
            .fetch_one(&context.pool)
            .await
            .unwrap();
    assert_eq!(expiry, after_expiry);
    let approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.evidence_access_requests WHERE tenant_id=$1",
    )
    .bind(context.tenant.as_str())
    .fetch_one(&context.pool)
    .await
    .unwrap();
    assert_eq!(approvals, 0);
}

fn assert_journals(events: &[Vec<Value>]) {
    for event in events.iter().flatten() {
        for secret in [
            "Wire sensitive retention reason",
            "Wire sensitive release reason",
            "hold-wire-create-key",
            "hold-wire-release-key",
        ] {
            assert!(!event.to_string().contains(secret));
        }
    }
    for reason in [
        "CONTROL_EVIDENCE_HOLD_CREATED",
        "CONTROL_EVIDENCE_HOLD_CREATE_REPLAYED",
        "CONTROL_EVIDENCE_HOLD_RELEASED",
        "CONTROL_EVIDENCE_HOLD_RELEASE_REPLAYED",
        "CONTROL_EVIDENCE_HOLD_CONFLICT",
        "CONTROL_EVIDENCE_HOLD_READ",
        "CONTROL_CURSOR_INVALID",
        "CONTROL_AUTH_REQUIRED",
    ] {
        assert!(
            events[1]
                .iter()
                .any(|event| event["payload"]["reason_code"] == reason),
            "missing administrator audit: {reason}"
        );
    }
    for (index, code) in [
        (0, "CONTROL_SCOPE_DENIED"),
        (2, "CONTROL_SCOPE_DENIED"),
        (3, "CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE"),
        (4, "CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE"),
    ] {
        let holds: Vec<_> = events[index]
            .iter()
            .filter(|event| {
                event["event_type"]
                    .as_str()
                    .unwrap()
                    .starts_with("console.evidence.hold.")
            })
            .collect();
        assert_eq!(holds.len(), 3);
        for event in holds {
            assert_eq!(event["payload"]["reason_code"], code);
            assert_eq!(event["payload"]["outcome"], "DENY");
            assert_eq!(event["evidence_refs"], json!([]));
        }
    }
    for (reason, count) in [
        ("CONTROL_EVIDENCE_HOLD_CREATED", 2),
        ("CONTROL_EVIDENCE_HOLD_RELEASED", 2),
        ("CONTROL_EVIDENCE_HOLD_CREATE_REPLAYED", 1),
        ("CONTROL_EVIDENCE_HOLD_RELEASE_REPLAYED", 2),
    ] {
        assert_eq!(
            events[1]
                .iter()
                .filter(|event| event["payload"]["reason_code"] == reason)
                .count(),
            count
        );
    }
}
