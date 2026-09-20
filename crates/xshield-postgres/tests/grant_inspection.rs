use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, time::Duration};
use xshield_core::domain::{GrantId, SiteId, TenantId};
use xshield_postgres::{
    BindingRecordStatus, GrantInspection, GrantRecordStatus, PostgresIdentityStore, StoreError,
};

#[path = "support/grant_inspection.rs"]
mod fixture;

const TENANT: &str = "tenant_grant_inspection";
const SITE: &str = "site_grant_inspection";

async fn read(store: &PostgresIdentityStore) -> Result<Option<GrantInspection>, StoreError> {
    store
        .read_grant_summary(
            &TenantId::parse(TENANT).unwrap(),
            &SiteId::parse(SITE).unwrap(),
            &GrantId::parse(fixture::GRANT).unwrap(),
        )
        .await
}

async fn change(pool: &PgPool, statement: &'static str) {
    sqlx::query(statement)
        .bind(TENANT)
        .bind(SITE)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn grant_inspection_is_scoped_historical_consistent_and_read_only() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("test database connects");
    fixture::seed(&pool, TENANT, SITE).await;
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let summary = read(&store).await.unwrap().unwrap();
    assert_eq!(summary.grant_id.as_str(), fixture::GRANT);
    assert_eq!(summary.binding_id.as_str(), fixture::BINDING);
    assert_eq!(summary.grant_epoch.value(), 4);
    assert_eq!(summary.binding_epoch.value(), 4);
    assert_eq!(summary.binding_status, BindingRecordStatus::Active);
    assert_eq!(summary.grant_status, GrantRecordStatus::Active);
    assert_eq!(summary.resource_type.as_str(), "order");
    assert_eq!(summary.operation_id.as_str(), "orders.read");
    assert_eq!(summary.view_profile.as_str(), "customer_detail");
    assert_eq!(summary.policy_revision.as_str(), "inspection-r1");
    assert_eq!(summary.source_event_id.as_str(), fixture::SOURCE_EVENT);
    assert_eq!(summary.source_request_id.as_str(), fixture::SOURCE_REQUEST);
    assert!(summary.issued_at < summary.as_of);
    assert!(summary.as_of < summary.expires_at);
    assert!(summary.expires_at < summary.binding_expires_at);
    assert_scope(&store, &pool).await;
    assert_read_only_snapshot(&store, &pool).await;
    assert_history(&store, &pool).await;
    assert_corruption(&store, &pool).await;
    fixture::cleanup(&pool, TENANT, SITE).await;
    pool.close().await;
}

async fn assert_scope(store: &PostgresIdentityStore, pool: &PgPool) {
    let grant = GrantId::parse(fixture::GRANT).unwrap();
    for (tenant, site) in [
        ("tenant_inspection_other", SITE),
        (TENANT, "site_inspection_other"),
    ] {
        let tenant_id = TenantId::parse(tenant).unwrap();
        let site_id = SiteId::parse(site).unwrap();
        assert!(
            store
                .read_grant_summary(&tenant_id, &site_id, &grant)
                .await
                .unwrap()
                .is_none()
        );
        // The same ID can independently exist in another tenant or site.
        fixture::seed(pool, tenant, site).await;
        assert!(
            store
                .read_grant_summary(&tenant_id, &site_id, &grant)
                .await
                .unwrap()
                .is_some()
        );
        assert!(read(store).await.unwrap().is_some());
        fixture::cleanup(pool, tenant, site).await;
    }
    let missing = GrantId::parse("grant_018f2a3b-4c5d-7000-8000-00000000e106").unwrap();
    assert!(
        store
            .read_grant_summary(
                &TenantId::parse(TENANT).unwrap(),
                &SiteId::parse(SITE).unwrap(),
                &missing,
            )
            .await
            .unwrap()
            .is_none()
    );
}

async fn row_versions(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT 'grant', xmin::text FROM xshield.resource_grants
          WHERE tenant_id = $1 AND site_id = $2 AND grant_id = $3
         UNION ALL SELECT 'binding', xmin::text FROM xshield.auth_bindings
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $4
         UNION ALL SELECT 'action', xmin::text FROM xshield.ui_actions
          WHERE tenant_id = $1 AND site_id = $2 AND action_ref = 'inspection-action'
         UNION ALL SELECT 'outbox_count', count(*)::text FROM xshield.audit_outbox
          WHERE tenant_id = $1 AND site_id = $2 ORDER BY 1",
    )
    .bind(TENANT)
    .bind(SITE)
    .bind(fixture::GRANT)
    .bind(fixture::BINDING)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn assert_read_only_snapshot(store: &PostgresIdentityStore, pool: &PgPool) {
    let before = row_versions(pool).await;
    let original = read(store).await.unwrap().unwrap();
    let mut pending = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE xshield.auth_bindings SET status = 'revoked', auth_epoch = 5
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
    )
    .bind(TENANT)
    .bind(SITE)
    .bind(fixture::BINDING)
    .execute(&mut *pending)
    .await
    .unwrap();
    // A held business-row lock must not delay this MVCC read or expose an
    // uncommitted epoch/status. No authorization result is inferred from it.
    let observed = tokio::time::timeout(Duration::from_secs(2), read(store))
        .await
        .expect("investigation does not wait for a business row lock")
        .unwrap()
        .unwrap();
    assert_eq!(observed.binding_status, original.binding_status);
    assert_eq!(observed.binding_epoch, original.binding_epoch);
    assert_eq!(observed.grant_epoch, original.grant_epoch);
    pending.rollback().await.unwrap();
    assert_eq!(row_versions(pool).await, before);
}

async fn assert_history(store: &PostgresIdentityStore, pool: &PgPool) {
    change(
        pool,
        "UPDATE xshield.auth_bindings
         SET auth_epoch = 5, absolute_expires_at = now() - interval '1 second'
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .await;
    change(
        pool,
        "UPDATE xshield.ui_actions SET status = 'revoked'
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .await;
    for binding_status in ["active", "revoked", "expired", "anonymous"] {
        sqlx::query(
            "UPDATE xshield.auth_bindings
             SET status = $3, principal_ref = CASE WHEN $3 = 'anonymous' THEN NULL ELSE 'test' END
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(TENANT)
        .bind(SITE)
        .bind(binding_status)
        .execute(pool)
        .await
        .unwrap();
        let summary = read(store).await.unwrap().unwrap();
        assert_eq!(summary.binding_status.as_str(), binding_status);
        assert_eq!(summary.binding_epoch.value(), 5);
        assert_eq!(summary.grant_epoch.value(), 4);
        assert!(summary.binding_expires_at <= summary.as_of);
        assert!(summary.expires_at > summary.binding_expires_at);
    }
    change(
        pool,
        "UPDATE xshield.resource_grants SET expires_at = now() - interval '1 second'
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .await;
    for grant_status in ["active", "revoked", "expired"] {
        sqlx::query(
            "UPDATE xshield.resource_grants SET status = $3
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(TENANT)
        .bind(SITE)
        .bind(grant_status)
        .execute(pool)
        .await
        .unwrap();
        let summary = read(store).await.unwrap().unwrap();
        assert_eq!(summary.grant_status.as_str(), grant_status);
        assert!(summary.expires_at <= summary.as_of);
        assert_eq!(summary.source_request_id.as_str(), fixture::SOURCE_REQUEST);
    }
}

async fn assert_corruption(store: &PostgresIdentityStore, pool: &PgPool) {
    for statement in [
        "UPDATE xshield.auth_bindings SET auth_epoch = 3 WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.auth_bindings SET absolute_expires_at = 'infinity'
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.ui_actions SET auth_epoch = 3 WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.ui_actions SET operation_id = 'orders.update'
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.ui_actions SET field_profile = 'another_view'
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.ui_actions SET source_request_id = 'invalid'
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.ui_actions SET issued_at = now()
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.ui_actions SET expires_at = now() + interval '500 seconds'
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.ui_actions SET expires_at = 'infinity'
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.resource_grants SET source_event_id = 'invalid'
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.resource_grants SET resource_type = 'invalid resource'
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.resource_grants SET issued_at = '1969-12-31T23:59:59Z'
          WHERE tenant_id = $1 AND site_id = $2",
        "UPDATE xshield.resource_grants SET expires_at = 'infinity'
          WHERE tenant_id = $1 AND site_id = $2",
    ] {
        fixture::cleanup(pool, TENANT, SITE).await;
        fixture::seed(pool, TENANT, SITE).await;
        change(pool, statement).await;
        assert!(matches!(read(store).await, Err(StoreError::CorruptData(_))));
    }
}
