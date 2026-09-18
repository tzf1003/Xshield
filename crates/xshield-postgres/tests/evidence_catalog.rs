use chrono::{TimeDelta, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::{env, fs, path::PathBuf, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{EventId, RequestId, SiteId, TenantId};
use xshield_evidence::{
    EvidenceClassification, EvidenceFidelity, EvidenceKey, EvidenceVaultConfig, EvidenceWrite,
    LocalEvidenceVault, VerifiedEvidenceManifest,
};
use xshield_postgres::{
    EvidenceCatalogPublish, EvidenceCatalogQuery, EvidenceCatalogWriteOutcome,
    PostgresIdentityStore,
};

const KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn catalog_publish_is_atomic_idempotent_scoped_and_bounded() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 3, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let root = private_temp_directory();
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&root, "evidence-key-r2", 1024, 30).unwrap(),
        EvidenceKey::from_hex(KEY).unwrap(),
    )
    .unwrap();
    let tenant = TenantId::parse("tenant_catalog").unwrap();
    let site = SiteId::parse("site_catalog").unwrap();
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000901").unwrap();
    let verified = vault
        .write(&EvidenceWrite {
            tenant_id: &tenant,
            site_id: &site,
            request_id: &request,
            kind: "request_decoded",
            content_type: "application/json",
            fidelity: EvidenceFidelity::EntityExact,
            classification: EvidenceClassification::Restricted,
            parent_refs: &[],
            expires_at: Utc::now() + TimeDelta::minutes(10),
            plaintext: br#"{"approved":true}"#,
        })
        .unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000902").unwrap();
    let envelope = catalog_envelope(&verified, &event);
    let mut mismatched = envelope.clone();
    mismatched["tenant_id"] = json!("tenant_other");
    assert!(EvidenceCatalogPublish::new(&verified, &event, &mismatched).is_err());

    assert_audit_failure_rolls_back(&pool, &store, &verified, &tenant, &site, &event, &envelope)
        .await;

    assert_eq!(
        store
            .publish_evidence_manifest(
                EvidenceCatalogPublish::new(&verified, &event, &envelope).unwrap()
            )
            .await
            .unwrap(),
        EvidenceCatalogWriteOutcome::Published
    );
    assert_eq!(
        store
            .publish_evidence_manifest(
                EvidenceCatalogPublish::new(&verified, &event, &envelope).unwrap()
            )
            .await
            .unwrap(),
        EvidenceCatalogWriteOutcome::Existing
    );

    assert_scoped_query(&store, &verified, &tenant, &site, &request).await;

    sqlx::query(
        "UPDATE xshield.artifact_catalog
         SET recorded_at = clock_timestamp() - interval '2 hours',
             expires_at = clock_timestamp() - interval '1 hour'
         WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(&verified.manifest().artifact_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        store
            .list_request_artifacts(
                EvidenceCatalogQuery::new(&tenant, &site, &request, 16).unwrap()
            )
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .publish_evidence_manifest(
                EvidenceCatalogPublish::new(&verified, &event, &envelope).unwrap()
            )
            .await
            .unwrap(),
        EvidenceCatalogWriteOutcome::Conflict
    );

    assert_expired_publication_is_rejected(&store, &vault, &tenant, &site, &request).await;
    fs::remove_dir_all(root).unwrap();
}

async fn assert_expired_publication_is_rejected(
    store: &PostgresIdentityStore,
    vault: &LocalEvidenceVault,
    tenant: &TenantId,
    site: &SiteId,
    request: &RequestId,
) {
    let expiring = vault
        .write(&EvidenceWrite {
            tenant_id: tenant,
            site_id: site,
            request_id: request,
            kind: "request_decoded",
            content_type: "application/json",
            fidelity: EvidenceFidelity::EntityExact,
            classification: EvidenceClassification::Restricted,
            parent_refs: &[],
            expires_at: Utc::now() + TimeDelta::seconds(1),
            plaintext: br#"{"expired":true}"#,
        })
        .unwrap();
    let expired_event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000904").unwrap();
    let expired_envelope = catalog_envelope(&expiring, &expired_event);
    std::thread::sleep(Duration::from_millis(1_100));
    assert!(
        store
            .publish_evidence_manifest(
                EvidenceCatalogPublish::new(&expiring, &expired_event, &expired_envelope).unwrap()
            )
            .await
            .is_err()
    );
}

async fn assert_audit_failure_rolls_back(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    verified: &VerifiedEvidenceManifest,
    tenant: &TenantId,
    site: &SiteId,
    event: &EventId,
    envelope: &serde_json::Value,
) {
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, 'collision', 'fixture', '{}')",
    )
    .bind(event.as_str())
    .bind(tenant.as_str())
    .bind(site.as_str())
    .execute(pool)
    .await
    .unwrap();
    assert!(
        store
            .publish_evidence_manifest(
                EvidenceCatalogPublish::new(verified, event, envelope).unwrap()
            )
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM xshield.artifact_catalog")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(event.as_str())
        .execute(pool)
        .await
        .unwrap();
}

async fn assert_scoped_query(
    store: &PostgresIdentityStore,
    verified: &VerifiedEvidenceManifest,
    tenant: &TenantId,
    site: &SiteId,
    request: &RequestId,
) {
    let entries = store
        .list_request_artifacts(EvidenceCatalogQuery::new(tenant, site, request, 16).unwrap())
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].manifest(), verified.manifest());
    let other_tenant = TenantId::parse("tenant_other").unwrap();
    assert!(
        store
            .list_request_artifacts(
                EvidenceCatalogQuery::new(&other_tenant, site, request, 16).unwrap()
            )
            .await
            .unwrap()
            .is_empty()
    );
    let other_site = SiteId::parse("site_other").unwrap();
    assert!(
        store
            .list_request_artifacts(
                EvidenceCatalogQuery::new(tenant, &other_site, request, 16).unwrap()
            )
            .await
            .unwrap()
            .is_empty()
    );
    let other_request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000903").unwrap();
    assert!(
        store
            .list_request_artifacts(
                EvidenceCatalogQuery::new(tenant, site, &other_request, 16).unwrap()
            )
            .await
            .unwrap()
            .is_empty()
    );
}

fn private_temp_directory() -> PathBuf {
    let root = env::temp_dir().join(format!("xshield-catalog-test-{}", Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    root
}

fn catalog_envelope(verified: &VerifiedEvidenceManifest, event: &EventId) -> serde_json::Value {
    let manifest = verified.manifest();
    json!({
        "schema_version": 3,
        "event_id": event.as_str(),
        "event_type": "evidence.cataloged",
        "tenant_id": manifest.tenant_id,
        "site_id": manifest.site_id,
        "request_id": manifest.request_id,
        "trace_id": "018f2a3b4c5d70008000000000000902",
        "span_id": "018f2a3b4c5d7000",
        "producer_id": "evidence-catalog-test",
        "producer_boot_id": "boot-test",
        "producer_seq": 1,
        "request_seq": 1,
        "occurred_at": "2026-09-18T00:00:00.000Z",
        "observed_at": "2026-09-18T00:00:00.000Z",
        "policy_revision": "policy-test-r1",
        "example_only": false,
        "evidence_refs": [manifest.artifact_id],
        "cause_event_ids": [],
        "payload": {
            "stage": "evidence_catalog",
            "outcome": "PASS",
            "reason_code": "EVIDENCE_CATALOG_PUBLISHED",
            "artifact_id": manifest.artifact_id
        },
        "sensitivity": "RESTRICTED",
        "integrity": {
            "state": "pending",
            "previous_hash": null,
            "event_hash": null
        }
    })
}
