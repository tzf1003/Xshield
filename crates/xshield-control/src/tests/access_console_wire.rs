use super::*;
use std::sync::Arc;

const TENANT: &str = "tenant_console_access_wire";
const SUBJECT: &str = "console-access-requester";

fn fixture(pool: &sqlx::PgPool, subject: &str, roles: &[ManagementRole], tenant: &str) -> Fixture {
    let mut fixture = Fixture::with_decision_catalog(
        PostgresIdentityStore::from_pool(pool.clone()),
        subject,
        roles[0],
    );
    let tenant = TenantId::parse(tenant).unwrap();
    fixture.control.config.tenant_id = tenant.clone();
    fixture.control.config.principal = ManagementPrincipal::new(
        subject,
        roles.iter().copied(),
        [(tenant, SiteId::parse("site_a").unwrap())],
    )
    .unwrap();
    fixture
        .control
        .config
        .limits
        .max_pending_evidence_access_requests = 4;
    fixture.control.rate.lock().unwrap().limit = 100;
    fixture.control.config.limits.max_query_artifacts = 1;
    fixture
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL and Node.js 22"]
#[allow(clippy::too_many_lines)]
async fn console_access_client_mutates_postgres_and_reads_vault_http_contract() {
    let pool = sqlx::PgPool::connect(&std::env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let mut requester = fixture(
        &pool,
        SUBJECT,
        &[
            ManagementRole::Investigator,
            ManagementRole::SensitiveEvidenceReader,
        ],
        TENANT,
    );
    let approver = fixture(
        &pool,
        "console-independent-approver",
        &[ManagementRole::SensitiveEvidenceApprover],
        TENANT,
    );
    let own_approver = fixture(
        &pool,
        SUBJECT,
        &[ManagementRole::SensitiveEvidenceApprover],
        TENANT,
    );
    let observer = fixture(
        &pool,
        "console-access-observer",
        &[ManagementRole::Observer],
        TENANT,
    );
    let mut foreign = fixture(
        &pool,
        "console-foreign-reviewer",
        &[
            ManagementRole::SensitiveEvidenceApprover,
            ManagementRole::SensitiveEvidenceReader,
        ],
        "tenant_console_access_foreign",
    );
    let vault_root = requester.access_directory.parent().unwrap().join("vault");
    private_directory(&vault_root);
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&vault_root, "access-wire-key", 1024, 30).unwrap(),
        EvidenceKey::from_hex("5555555555555555555555555555555555555555555555555555555555555555")
            .unwrap(),
    )
    .unwrap();
    let artifact = publish_test_artifact(
        &requester.control.catalog,
        &vault,
        &TenantId::parse(TENANT).unwrap(),
        &SiteId::parse("site_a").unwrap(),
        &RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap(),
        1,
    )
    .await;
    requester.control.evidence_read = Some(Arc::new(EvidenceReadPort::new(vault)));
    requester.control.test_step_up_valid = true;
    foreign.control.test_step_up_valid = true;
    let mut servers = Vec::new();
    let mut addresses = Vec::new();
    let mut directories = Vec::new();
    for fixture in [requester, approver, own_approver, observer, foreign] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        addresses.push(listener.local_addr().unwrap());
        directories.push(fixture.access_directory);
        servers.push(tokio::spawn(async move {
            axum::serve(listener, router(fixture.control)).await
        }));
    }
    let result = run_console_wire_with_env(
        "access-wire.ts",
        addresses[0],
        Some(addresses[3]),
        vec![
            ("XSHIELD_CONSOLE_TEST_ARTIFACT", artifact.clone()),
            (
                "XSHIELD_CONSOLE_TEST_APPROVER_ORIGIN",
                format!("http://{}", addresses[1]),
            ),
            (
                "XSHIELD_CONSOLE_TEST_SELF_APPROVER_ORIGIN",
                format!("http://{}", addresses[2]),
            ),
            (
                "XSHIELD_CONSOLE_TEST_FOREIGN_ORIGIN",
                format!("http://{}", addresses[4]),
            ),
        ],
    )
    .await;
    for server in &servers {
        server.abort();
    }
    for server in servers {
        assert!(server.await.unwrap_err().is_cancelled());
    }
    let events: Vec<_> = directories
        .iter()
        .map(|path| read_access_events(path))
        .collect();
    let counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT event_type, count(*) FROM xshield.audit_outbox WHERE tenant_id=$1 AND event_type LIKE 'evidence.access.%' GROUP BY event_type ORDER BY event_type",
    )
    .bind(TENANT)
    .fetch_all(&pool)
    .await
    .unwrap();
    let states: Vec<(String, String)> = sqlx::query_as(
        "SELECT status, requested_by FROM xshield.evidence_access_requests WHERE tenant_id=$1 ORDER BY status",
    )
    .bind(TENANT)
    .fetch_all(&pool)
    .await
    .unwrap();
    for statement in [
        "DELETE FROM xshield.evidence_access_requests WHERE tenant_id=$1",
        "DELETE FROM xshield.case_closures WHERE tenant_id=$1",
        "DELETE FROM xshield.case_items WHERE tenant_id=$1",
        "DELETE FROM xshield.investigation_cases WHERE tenant_id=$1",
        "DELETE FROM xshield.artifact_catalog WHERE tenant_id=$1",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id=$1",
    ] {
        sqlx::query(statement)
            .bind(TENANT)
            .execute(&pool)
            .await
            .unwrap();
    }
    for directory in directories {
        fs::remove_dir_all(directory.parent().unwrap()).unwrap();
    }
    pool.close().await;
    let result = result.unwrap();
    assert!(
        result.success(),
        "access wire contract failed; phase={:?}",
        result.code()
    );
    assert_eq!(
        counts,
        vec![
            ("evidence.access.approved".to_owned(), 2),
            ("evidence.access.denied".to_owned(), 1),
            ("evidence.access.requested".to_owned(), 3),
        ]
    );
    assert_eq!(states.len(), 3);
    assert!(states.iter().all(|(_, subject)| subject == SUBJECT));
    assert_eq!(
        states.iter().filter(|(state, _)| state == "denied").count(),
        1
    );
    for event in events.iter().flatten() {
        assert!(!event.to_string().contains("Wire sensitive investigation"));
        assert!(!event.to_string().contains("Wire independent approval"));
        assert!(!event.to_string().contains("access-wire-request-key"));
    }
    for reason in [
        "CONTROL_EVIDENCE_ACCESS_REQUESTED",
        "CONTROL_EVIDENCE_ACCESS_ALREADY_REQUESTED",
        "CONTROL_EVIDENCE_ACCESS_READ",
        "CONTROL_EVIDENCE_ACCESS_LIST_READ",
        "CONTROL_EVIDENCE_READ",
        "CONTROL_EVIDENCE_READ_NOT_AVAILABLE",
    ] {
        assert!(
            events[0]
                .iter()
                .any(|event| event["payload"]["reason_code"] == reason),
            "missing requester audit: {reason}"
        );
    }
    for reason in [
        "CONTROL_EVIDENCE_ACCESS_APPROVED",
        "CONTROL_EVIDENCE_ACCESS_DENIED",
        "CONTROL_EVIDENCE_ACCESS_DECISION_REPLAYED",
        "CONTROL_EVIDENCE_ACCESS_DECISION_CONFLICT",
    ] {
        assert!(
            events[1]
                .iter()
                .any(|event| event["payload"]["reason_code"] == reason),
            "missing approver audit: {reason}"
        );
    }
    assert!(
        events[2].iter().any(|event| event["payload"]["reason_code"]
            == "CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED")
    );
    assert!(
        events[3]
            .iter()
            .all(|event| event["payload"]["reason_code"] == "CONTROL_SCOPE_DENIED")
    );
    assert_eq!(events[3].len(), 6);
    assert_eq!(events[4].len(), 4);
    assert!(
        events[4]
            .iter()
            .filter(|event| event["event_type"] != "console.evidence.access.list")
            .all(|event| event["payload"]["outcome"] == "DENY")
    );
    let lists: Vec<_> = events
        .iter()
        .flatten()
        .filter(|event| event["event_type"] == "console.evidence.access.list")
        .collect();
    assert_eq!(lists.len(), 13);
    for event in lists {
        assert_eq!(event["evidence_refs"], json!([]));
        for (key, value) in event["payload"].as_object().unwrap() {
            if key.starts_with("target_") || matches!(key.as_str(), "query_digest" | "bytes_read") {
                assert!(value.is_null());
            }
        }
    }
    let successful_reads: Vec<_> = events
        .iter()
        .flatten()
        .filter(|event| {
            event["event_type"] == "evidence.read" && event["payload"]["outcome"] == "PASS"
        })
        .collect();
    assert_eq!(successful_reads.len(), 1);
    assert_eq!(successful_reads[0]["evidence_refs"], json!([artifact]));
}
