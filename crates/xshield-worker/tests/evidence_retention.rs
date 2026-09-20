use chrono::{TimeDelta, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::{env, fs, fs::File, path::Path, process::Command, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{EventId, RequestId, SiteId, TenantId};
use xshield_evidence::{
    EvidenceClassification, EvidenceFidelity, EvidenceKey, EvidencePurgeOutcome,
    EvidenceVaultConfig, EvidenceWrite, LocalEvidenceVault, VerifiedEvidenceManifest,
};
use xshield_postgres::{
    EvidenceCatalogPublish, EvidenceOrphanPurgeResult, EvidencePurgeResult, PostgresIdentityStore,
};

const KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn expired_ciphertext_cleanup_is_scoped_audited_exclusive_and_recoverable() {
    let database = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = PgPool::connect(&database).await.unwrap();
    let store = PostgresIdentityStore::connect(&database, 2, Duration::from_secs(5))
        .await
        .unwrap();
    let root = env::temp_dir().join(format!("xshield-retention-test-{}", Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&root, "retention-r1", 1024, 1).unwrap(),
        EvidenceKey::from_hex(KEY).unwrap(),
    )
    .unwrap();
    let tenant = TenantId::parse("tenant_retention").unwrap();
    let site = SiteId::parse("site_retention").unwrap();
    let first = publish(&store, &vault, &tenant, &site, 5).await;
    let second = publish(&store, &vault, &tenant, &site, 5).await;
    let live = publish(&store, &vault, &tenant, &site, 600).await;
    let foreign = publish(
        &store,
        &vault,
        &TenantId::parse("tenant_retention_other").unwrap(),
        &site,
        5,
    )
    .await;
    let foreign_site = publish(
        &store,
        &vault,
        &tenant,
        &SiteId::parse("site_retention_other").unwrap(),
        5,
    )
    .await;
    assert!(
        store
            .prepare_evidence_purge(&tenant, &site, "retention-r1", 0)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_evidence_purge(&tenant, &site, "retention-r1", 33)
            .await
            .is_err()
    );
    assert!(
        store
            .prepare_evidence_purge(&tenant, &site, "retention-r1", 32)
            .await
            .unwrap()
            .is_empty()
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        store
            .prepare_evidence_purge(&tenant, &site, "other-key", 32)
            .await
            .unwrap()
            .is_empty()
    );

    // Match the gateway's directory lock, before any intent can be created.
    let lock = File::open(&root).unwrap();
    lock.try_lock().unwrap();
    let busy = run_cli(&database, &root, 32);
    assert!(!busy.status.success());
    assert!(String::from_utf8_lossy(&busy.stderr).contains("EVIDENCE_PURGE_BUSY"));
    assert_eq!(event_count(&pool, "evidence.purge_requested").await, 0);

    // A failed outbox insert rolls back the entire intent batch.
    sqlx::query(
        "ALTER TABLE xshield.audit_outbox ADD CONSTRAINT test_retention_intent_failure
        CHECK (tenant_id <> 'tenant_retention' OR event_type <> 'evidence.purge_requested')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        store
            .prepare_evidence_purge(&tenant, &site, "retention-r1", 32)
            .await
            .is_err()
    );
    let intents: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.artifact_catalog
        WHERE tenant_id = 'tenant_retention' AND purge_requested_event_id IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(intents, 0);
    sqlx::query("ALTER TABLE xshield.audit_outbox DROP CONSTRAINT test_retention_intent_failure")
        .execute(&pool)
        .await
        .unwrap();

    let jobs = store
        .prepare_evidence_purge(&tenant, &site, "retention-r1", 1)
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].artifact().manifest(), first.manifest());
    assert_eq!(
        store
            .prepare_evidence_purge(&tenant, &site, "retention-r1", 1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(event_count(&pool, "evidence.purge_requested").await, 1);
    let removed = vault
        .purge_expired(&tenant, &site, jobs[0].artifact().manifest())
        .unwrap();
    assert_eq!(removed, EvidencePurgeOutcome::Removed);
    sqlx::query(
        "ALTER TABLE xshield.audit_outbox ADD CONSTRAINT test_retention_completion_failure
        CHECK (tenant_id <> 'tenant_retention' OR event_type <> 'evidence.deleted')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        store
            .finish_evidence_purge(&jobs[0], EvidencePurgeResult::Deleted(removed))
            .await
            .is_err()
    );
    assert_eq!(
        status(&pool, first.manifest().artifact_id.as_str()).await,
        "active"
    );
    assert_eq!(event_count(&pool, "evidence.deleted").await, 0);
    sqlx::query(
        "ALTER TABLE xshield.audit_outbox DROP CONSTRAINT test_retention_completion_failure",
    )
    .execute(&pool)
    .await
    .unwrap();
    drop(lock);

    // Restart completes the absent ciphertext and selects only one candidate.
    let recovered = run_cli(&database, &root, 1);
    assert!(recovered.status.success(), "{recovered:?}");
    assert_eq!(
        status(&pool, &first.manifest().artifact_id).await,
        "deleted"
    );
    assert_eq!(
        status(&pool, &second.manifest().artifact_id).await,
        "active"
    );
    let reason: String = sqlx::query_scalar("SELECT envelope->'payload'->>'reason_code'
        FROM xshield.audit_outbox WHERE tenant_id = 'tenant_retention' AND event_type = 'evidence.deleted'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(reason, "EVIDENCE_DELETE_ALREADY_ABSENT");
    store
        .finish_evidence_purge(&jobs[0], EvidencePurgeResult::Deleted(removed))
        .await
        .unwrap();
    assert_eq!(event_count(&pool, "evidence.deleted").await, 1);

    let second_path = root.join(&second.manifest().storage.locator);
    let original = fs::read(&second_path).unwrap();
    fs::write(&second_path, b"corrupt").unwrap();
    assert!(!run_cli(&database, &root, 32).status.success());
    assert_eq!(event_count(&pool, "evidence.purge_failed").await, 1);
    assert!(second_path.exists());
    assert_eq!(
        status(&pool, &second.manifest().artifact_id).await,
        "active"
    );
    fs::write(&second_path, original).unwrap();
    assert!(run_cli(&database, &root, 32).status.success());
    assert!(!second_path.exists());
    assert!(run_cli(&database, &root, 32).status.success());
    assert_eq!(event_count(&pool, "evidence.purge_requested").await, 2);
    assert_eq!(event_count(&pool, "evidence.deleted").await, 2);
    let orphan_id = format!("artifact_{}", Uuid::now_v7());
    let orphan_path = root.join(format!("{orphan_id}.xev"));
    fs::write(&orphan_path, b"crashed-before-manifest").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&orphan_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let orphan_lock = File::open(&root).unwrap();
    orphan_lock.try_lock().unwrap();
    let candidate = vault
        .list_orphan_candidates(&tenant, &site, Duration::from_secs(1), 32)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.artifact_id() == orphan_id)
        .unwrap();
    let orphan_jobs = store
        .prepare_evidence_orphan_purge(&tenant, &site, std::slice::from_ref(&candidate))
        .await
        .unwrap();
    assert_eq!(orphan_jobs.len(), 1);
    let retry_jobs = store
        .prepare_evidence_orphan_purge(&tenant, &site, std::slice::from_ref(&candidate))
        .await
        .unwrap();
    assert_eq!(
        retry_jobs[0].intent_event_id(),
        orphan_jobs[0].intent_event_id()
    );
    assert_eq!(
        event_count(&pool, "evidence.orphan.purge_requested").await,
        1
    );
    // Inject a storage failure result before removal: the intent remains
    // retryable, and its failure must be publishable alongside the later success.
    store
        .finish_evidence_orphan_purge(&orphan_jobs[0], EvidenceOrphanPurgeResult::Unavailable)
        .await
        .unwrap();
    assert_eq!(event_count(&pool, "evidence.orphan.purge_failed").await, 1);
    let orphan_removed = vault.purge_orphan(&tenant, &site, &candidate).unwrap();
    assert_eq!(orphan_removed, EvidencePurgeOutcome::Removed);
    sqlx::query(
        "ALTER TABLE xshield.audit_outbox ADD CONSTRAINT test_orphan_completion_failure
        CHECK (tenant_id <> 'tenant_retention' OR event_type <> 'evidence.orphan.deleted')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        store
            .finish_evidence_orphan_purge(
                &orphan_jobs[0],
                EvidenceOrphanPurgeResult::Deleted(orphan_removed),
            )
            .await
            .is_err()
    );
    let orphan_status: String = sqlx::query_scalar(
        "SELECT status FROM xshield.evidence_orphan_purges
         WHERE tenant_id = 'tenant_retention' AND site_id = 'site_retention' AND artifact_id = $1",
    )
    .bind(&orphan_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(orphan_status, "pending");
    assert_eq!(event_count(&pool, "evidence.orphan.deleted").await, 0);
    sqlx::query("ALTER TABLE xshield.audit_outbox DROP CONSTRAINT test_orphan_completion_failure")
        .execute(&pool)
        .await
        .unwrap();
    drop(orphan_lock);
    let recovered = run_cli(&database, &root, 32);
    assert!(recovered.status.success(), "{recovered:?}");
    assert!(!orphan_path.exists());
    assert_eq!(
        event_count(&pool, "evidence.orphan.purge_requested").await,
        1
    );
    assert_eq!(event_count(&pool, "evidence.orphan.deleted").await, 1);
    let orphan_reason: String = sqlx::query_scalar(
        "SELECT envelope->'payload'->>'reason_code' FROM xshield.audit_outbox
         WHERE tenant_id = 'tenant_retention' AND event_type = 'evidence.orphan.deleted'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(orphan_reason, "EVIDENCE_ORPHAN_DELETE_ALREADY_ABSENT");
    store
        .finish_evidence_orphan_purge(
            &orphan_jobs[0],
            EvidenceOrphanPurgeResult::Deleted(orphan_removed),
        )
        .await
        .unwrap();
    assert_eq!(event_count(&pool, "evidence.orphan.deleted").await, 1);
    // A cataloged object can sort before a real orphan; the cursor must still
    // advance within the same bounded maintenance pass.
    let later_orphan_id = format!("artifact_{}", Uuid::now_v7());
    let later_orphan_path = root.join(format!("{later_orphan_id}.xev"));
    fs::write(&later_orphan_path, b"later-orphan").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&later_orphan_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let paged = run_cli(&database, &root, 1);
    assert!(paged.status.success(), "{paged:?}");
    assert!(!later_orphan_path.exists());
    assert_eq!(
        event_count(&pool, "evidence.orphan.purge_requested").await,
        2
    );
    assert_eq!(event_count(&pool, "evidence.orphan.deleted").await, 2);
    for retained in [&live, &foreign, &foreign_site] {
        assert!(root.join(&retained.manifest().storage.locator).exists());
        assert_eq!(
            status(&pool, &retained.manifest().artifact_id).await,
            "active"
        );
    }
    // Catalog tampering cannot shorten the signed local retention deadline.
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET recorded_at = now() - interval '2 hours',
        expires_at = now() - interval '1 hour' WHERE artifact_id = $1",
    )
    .bind(&live.manifest().artifact_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(!run_cli(&database, &root, 32).status.success());
    assert!(root.join(&live.manifest().storage.locator).exists());
    assert_eq!(event_count(&pool, "evidence.purge_failed").await, 2);
    let invalid: i64 = sqlx::query_scalar("SELECT count(*) FROM xshield.audit_outbox
        WHERE tenant_id = 'tenant_retention' AND event_type LIKE 'evidence.purge%'
          AND (envelope->>'schema_version' <> '3' OR envelope->'payload'->'confidence' <> 'null'::jsonb)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(invalid, 0);
    fs::remove_dir_all(root).unwrap();
}

fn run_cli(database: &str, root: &Path, limit: u16) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_xshield-evidence-retain"))
        .args(["tenant_retention", "site_retention", &limit.to_string()])
        .env("XSHIELD_DATABASE_URL", database)
        .env("XSHIELD_EVIDENCE_ROOT", root)
        .env("XSHIELD_EVIDENCE_KEY_ID", "retention-r1")
        .env("XSHIELD_EVIDENCE_KEY_HEX", KEY)
        .env("XSHIELD_EVIDENCE_ORPHAN_GRACE_SECONDS", "1")
        .output()
        .unwrap()
}

async fn publish(
    store: &PostgresIdentityStore,
    vault: &LocalEvidenceVault,
    tenant: &TenantId,
    site: &SiteId,
    ttl: i64,
) -> VerifiedEvidenceManifest {
    let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
    let verified = vault
        .write(&EvidenceWrite {
            tenant_id: tenant,
            site_id: site,
            request_id: &request,
            kind: "response_decoded",
            content_type: "application/json",
            fidelity: EvidenceFidelity::Redacted,
            classification: EvidenceClassification::Restricted,
            parent_refs: &[],
            expires_at: Utc::now() + TimeDelta::seconds(ttl),
            plaintext: b"{}",
        })
        .unwrap();
    let event = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
    let envelope = json!({"schema_version":3, "event_id":event.as_str(), "event_type":"evidence.cataloged",
        "tenant_id":tenant.as_str(), "site_id":site.as_str(), "request_id":request.as_str(),
        "evidence_refs":[verified.manifest().artifact_id], "example_only":false,
        "payload":{"stage":"evidence_catalog", "outcome":"PASS", "reason_code":"EVIDENCE_CATALOG_PUBLISHED", "artifact_id":verified.manifest().artifact_id}});
    store
        .publish_evidence_manifest(
            EvidenceCatalogPublish::new(&verified, &event, &envelope).unwrap(),
        )
        .await
        .unwrap();
    verified
}

async fn event_count(pool: &PgPool, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM xshield.audit_outbox WHERE tenant_id = 'tenant_retention' AND event_type = $1")
        .bind(event_type).fetch_one(pool).await.unwrap()
}

async fn status(pool: &PgPool, artifact: &str) -> String {
    sqlx::query_scalar("SELECT status FROM xshield.artifact_catalog WHERE artifact_id = $1")
        .bind(artifact)
        .fetch_one(pool)
        .await
        .unwrap()
}
