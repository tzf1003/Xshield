use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, time::Duration};
use xshield_core::domain::{AuthBindingId, SiteId, TenantId};
use xshield_postgres::{BindingInspection, BindingRecordStatus, PostgresIdentityStore, StoreError};

#[path = "support/grant_inspection.rs"]
mod fixture;

const TENANT: &str = "tenant_binding_inspection";
const SITE: &str = "site_binding_inspection";

async fn read(store: &PostgresIdentityStore) -> Result<Option<BindingInspection>, StoreError> {
    store
        .read_binding_summary(
            &TenantId::parse(TENANT).unwrap(),
            &SiteId::parse(SITE).unwrap(),
            &AuthBindingId::parse(fixture::BINDING).unwrap(),
        )
        .await
}

async fn change(pool: &PgPool, statement: &'static str) {
    sqlx::query(statement)
        .bind(TENANT)
        .bind(SITE)
        .bind(fixture::BINDING)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn binding_inspection_is_scoped_historical_consistent_and_read_only() {
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
    assert_eq!(summary.binding_id.as_str(), fixture::BINDING);
    assert_eq!(summary.auth_epoch.value(), 4);
    assert_eq!(summary.credential_generation.value(), 2);
    assert_eq!(summary.status, BindingRecordStatus::Active);
    assert!(summary.updated_at <= summary.as_of);
    assert!(summary.as_of < summary.expires_at);
    let debug = format!("{summary:?}");
    assert!(!debug.contains("inspection-principal"));
    assert!(!debug.contains("inspection-context"));
    assert_scope(&store, &pool).await;
    assert_read_only_snapshot(&store, &pool).await;
    assert_history(&store, &pool).await;
    assert_corruption(&store, &pool).await;
    fixture::cleanup(&pool, TENANT, SITE).await;
    pool.close().await;
}

async fn assert_scope(store: &PostgresIdentityStore, pool: &PgPool) {
    let binding = AuthBindingId::parse(fixture::BINDING).unwrap();
    for (tenant, site) in [
        ("tenant_binding_inspection_other", SITE),
        (TENANT, "site_binding_inspection_other"),
    ] {
        let tenant_id = TenantId::parse(tenant).unwrap();
        let site_id = SiteId::parse(site).unwrap();
        assert!(
            store
                .read_binding_summary(&tenant_id, &site_id, &binding)
                .await
                .unwrap()
                .is_none()
        );
        fixture::seed(pool, tenant, site).await;
        sqlx::query(
            "UPDATE xshield.auth_bindings SET credential_generation = 9
             WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        )
        .bind(tenant)
        .bind(site)
        .bind(fixture::BINDING)
        .execute(pool)
        .await
        .unwrap();
        let scoped = store
            .read_binding_summary(&tenant_id, &site_id, &binding)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(scoped.credential_generation.value(), 9);
        assert_eq!(
            read(store)
                .await
                .unwrap()
                .unwrap()
                .credential_generation
                .value(),
            2
        );
        fixture::cleanup(pool, tenant, site).await;
    }
    let missing = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-00000000e106").unwrap();
    assert!(
        store
            .read_binding_summary(
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
        "SELECT 'binding', xmin::text FROM xshield.auth_bindings
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
         UNION ALL SELECT 'outbox_count', count(*)::text FROM xshield.audit_outbox
          WHERE tenant_id = $1 AND site_id = $2 ORDER BY 1",
    )
    .bind(TENANT)
    .bind(SITE)
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
        "UPDATE xshield.auth_bindings
         SET status = 'revoked', auth_epoch = 5, credential_generation = 3,
             absolute_expires_at = now() - interval '1 second', updated_at = now()
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
    )
    .bind(TENANT)
    .bind(SITE)
    .bind(fixture::BINDING)
    .execute(&mut *pending)
    .await
    .unwrap();
    // Investigation must see one committed version without waiting on an
    // in-flight lifecycle transition or taking a business-row lock of its own.
    let observed = tokio::time::timeout(Duration::from_secs(2), read(store))
        .await
        .expect("investigation does not wait for a business row lock")
        .unwrap()
        .unwrap();
    assert_eq!(observed.status, original.status);
    assert_eq!(observed.auth_epoch, original.auth_epoch);
    assert_eq!(
        observed.credential_generation,
        original.credential_generation
    );
    assert_eq!(observed.expires_at, original.expires_at);
    assert_eq!(observed.updated_at, original.updated_at);
    pending.rollback().await.unwrap();
    assert_eq!(row_versions(pool).await, before);
}

async fn assert_history(store: &PostgresIdentityStore, pool: &PgPool) {
    for (status, epoch, generation) in [
        ("active", 5_i64, 3_i64),
        ("revoked", 5, 3),
        ("expired", 5, 3),
        ("anonymous", 0, 0),
        ("revoked", 0, 0),
        ("expired", 0, 0),
        ("active", i64::MAX, i64::MAX),
    ] {
        sqlx::query(
            "UPDATE xshield.auth_bindings
             SET status = $4, auth_epoch = $5, credential_generation = $6,
                 principal_ref = CASE WHEN $4 = 'anonymous' THEN NULL ELSE 'test' END,
                 absolute_expires_at = now() - interval '1 second', updated_at = now()
             WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        )
        .bind(TENANT)
        .bind(SITE)
        .bind(fixture::BINDING)
        .bind(status)
        .bind(epoch)
        .bind(generation)
        .execute(pool)
        .await
        .unwrap();
        let summary = read(store).await.unwrap().unwrap();
        assert_eq!(summary.status.as_str(), status);
        assert_eq!(summary.auth_epoch.value(), u64::try_from(epoch).unwrap());
        assert_eq!(
            summary.credential_generation.value(),
            u64::try_from(generation).unwrap()
        );
        assert!(summary.expires_at < summary.as_of);
        assert!(summary.updated_at > summary.expires_at);
    }
}

async fn assert_corruption(store: &PostgresIdentityStore, pool: &PgPool) {
    for statement in [
        "UPDATE xshield.auth_bindings SET absolute_expires_at = 'infinity'
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        "UPDATE xshield.auth_bindings SET absolute_expires_at = '-infinity'
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        "UPDATE xshield.auth_bindings SET updated_at = 'infinity'
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        "UPDATE xshield.auth_bindings SET updated_at = '-infinity'
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        "UPDATE xshield.auth_bindings SET absolute_expires_at = '1969-12-31T23:59:59Z'
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        "UPDATE xshield.auth_bindings SET updated_at = '1969-12-31T23:59:59Z'
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        "UPDATE xshield.auth_bindings SET auth_epoch = 0
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        "UPDATE xshield.auth_bindings SET credential_generation = 0
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        "UPDATE xshield.auth_bindings
          SET status = 'anonymous', principal_ref = NULL, credential_generation = 0
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        "UPDATE xshield.auth_bindings
          SET status = 'anonymous', principal_ref = NULL, auth_epoch = 0
          WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
    ] {
        fixture::cleanup(pool, TENANT, SITE).await;
        fixture::seed(pool, TENANT, SITE).await;
        change(pool, statement).await;
        assert!(matches!(read(store).await, Err(StoreError::CorruptData(_))));
    }
}
