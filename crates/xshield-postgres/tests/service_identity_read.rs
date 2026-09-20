use sqlx::postgres::PgPoolOptions;
use std::{env, time::Duration};
use xshield_core::{
    access::{AccessDenied, ServiceCredentialFingerprint},
    domain::{OperationId, SiteId, TenantId},
    identity::UnixSeconds,
    ports::{ServiceIdentityProofQuery, ServiceIdentityProofState, ServiceIdentityProofStore},
};
use xshield_postgres::PostgresIdentityStore;

const NOW: u64 = 1_800_000_000;

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn service_identity_is_scoped_expiring_and_revocable() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("assertion pool connects");
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let tenant = TenantId::parse("tenant_service").unwrap();
    let site = SiteId::parse("site_service").unwrap();
    let fingerprint = ServiceCredentialFingerprint::from_bytes([41; 32]);
    sqlx::query(
        "INSERT INTO xshield.service_identities (
            tenant_id, site_id, service_id, credential_fingerprint,
            operation_ids, status, issued_at, expires_at
         ) VALUES ($1, $2, $3, $4, $5, 'active', to_timestamp($6), to_timestamp($7))",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind("svc_018f2a3b-4c5d-7000-8000-000000000701")
    .bind(fingerprint.as_bytes().as_slice())
    .bind(vec!["reports.ingest"])
    .bind(i64::try_from(NOW - 1).unwrap())
    .bind(i64::try_from(NOW + 600).unwrap())
    .execute(&pool)
    .await
    .unwrap();

    let query = |now| ServiceIdentityProofQuery {
        tenant_id: &tenant,
        site_id: &site,
        credential_fingerprint: &fingerprint,
        now: UnixSeconds::new(now),
    };
    let state = store.load_service_identity(query(NOW)).await.unwrap();
    let ServiceIdentityProofState::Verified(identity) = state else {
        panic!("active exact service identity must load");
    };
    assert!(
        identity
            .authorize(
                &tenant,
                &site,
                &fingerprint,
                &OperationId::parse("reports.ingest").unwrap(),
                UnixSeconds::new(NOW),
            )
            .is_ok()
    );
    assert_eq!(
        identity.authorize(
            &tenant,
            &site,
            &fingerprint,
            &OperationId::parse("reports.delete").unwrap(),
            UnixSeconds::new(NOW),
        ),
        Err(AccessDenied::ServiceIdentityMismatch)
    );

    assert!(matches!(
        store.load_service_identity(query(NOW + 600)).await.unwrap(),
        ServiceIdentityProofState::Denied(AccessDenied::ServiceIdentityMismatch)
    ));
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    // The single shared connection exposes temporary expiry changes to the store.
    sqlx::query("BEGIN").execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE xshield.service_identities
         SET issued_at = to_timestamp($4 - 120), expires_at = to_timestamp($4 - 1)
         WHERE tenant_id = $1 AND site_id = $2 AND service_id = $3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(identity.identity_id().as_str())
    .bind(database_now)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        store
            .load_service_identity(query(u64::try_from(database_now - 60).unwrap()))
            .await
            .unwrap(),
        ServiceIdentityProofState::Denied(AccessDenied::ServiceIdentityMismatch)
    ));
    sqlx::query("ROLLBACK").execute(&pool).await.unwrap();

    sqlx::query(
        "UPDATE xshield.service_identities SET status = 'revoked'
         WHERE tenant_id = $1 AND site_id = $2 AND service_id = $3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(identity.identity_id().as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        store.load_service_identity(query(NOW)).await.unwrap(),
        ServiceIdentityProofState::Denied(AccessDenied::ServiceIdentityMismatch)
    ));
}
