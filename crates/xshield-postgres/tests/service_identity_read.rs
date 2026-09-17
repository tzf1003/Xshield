use sqlx::PgPool;
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
async fn service_identity_is_scoped_expiring_and_revocable() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 2, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
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

    let state = store
        .load_service_identity(ServiceIdentityProofQuery {
            tenant_id: &tenant,
            site_id: &site,
            credential_fingerprint: &fingerprint,
            now: UnixSeconds::new(NOW),
        })
        .await
        .unwrap();
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
        store
            .load_service_identity(ServiceIdentityProofQuery {
                tenant_id: &tenant,
                site_id: &site,
                credential_fingerprint: &fingerprint,
                now: UnixSeconds::new(NOW),
            })
            .await
            .unwrap(),
        ServiceIdentityProofState::Denied(AccessDenied::ServiceIdentityMismatch)
    ));
}
