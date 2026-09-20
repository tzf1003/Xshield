use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, time::Duration};
use xshield_core::{
    access::{AccessDenied, ShareTokenFingerprint},
    domain::{OperationId, ResourceType, SiteId, TenantId, ViewProfile},
    grant::ResourceKeyHmac,
    identity::UnixSeconds,
    ports::{ShareGrantProofQuery, ShareGrantProofState, ShareGrantProofStore},
    provenance::HttpMethod,
};
use xshield_postgres::PostgresIdentityStore;

const NOW: u64 = 1_800_000_000;

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn share_grant_is_exact_expiring_and_revocable() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("assertion pool connects");
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let tenant = TenantId::parse("tenant_share").unwrap();
    let site = SiteId::parse("site_share").unwrap();
    let token = ShareTokenFingerprint::from_bytes([51; 32]);
    let resource_type = ResourceType::parse("record").unwrap();
    let resource_key = ResourceKeyHmac::from_bytes([52; 32]);
    let operation = OperationId::parse("records.share.read").unwrap();
    let view = ViewProfile::parse("shared_summary").unwrap();
    seed(&pool, &tenant, &site, &token, &resource_key).await;

    let query = || ShareGrantProofQuery {
        tenant_id: &tenant,
        site_id: &site,
        token_fingerprint: &token,
        resource_type: &resource_type,
        resource_key: &resource_key,
        operation_id: &operation,
        view_profile: &view,
        now: UnixSeconds::new(NOW),
    };
    let ShareGrantProofState::Verified(grant) = store.load_share_grant(query()).await.unwrap()
    else {
        panic!("active exact share grant must load");
    };
    assert!(
        grant
            .authorize(
                &tenant,
                &site,
                &token,
                &resource_type,
                &resource_key,
                &operation,
                &view,
                HttpMethod::Get,
                UnixSeconds::new(NOW),
            )
            .is_ok()
    );

    let wrong_resource = ResourceKeyHmac::from_bytes([53; 32]);
    assert!(matches!(
        store
            .load_share_grant(ShareGrantProofQuery {
                resource_key: &wrong_resource,
                ..query()
            })
            .await
            .unwrap(),
        ShareGrantProofState::Denied(AccessDenied::ShareScopeMismatch)
    ));

    assert!(matches!(
        store
            .load_share_grant(ShareGrantProofQuery {
                now: UnixSeconds::new(NOW + 600),
                ..query()
            })
            .await
            .unwrap(),
        ShareGrantProofState::Denied(AccessDenied::ShareScopeMismatch)
    ));
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    // The single shared connection exposes temporary expiry changes to the store.
    sqlx::query("BEGIN").execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE xshield.share_grants
         SET issued_at = to_timestamp($4 - 120), expires_at = to_timestamp($4 - 1)
         WHERE tenant_id = $1 AND site_id = $2 AND share_id = $3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(grant.share_id().as_str())
    .bind(database_now)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        store
            .load_share_grant(ShareGrantProofQuery {
                now: UnixSeconds::new(u64::try_from(database_now - 60).unwrap()),
                ..query()
            })
            .await
            .unwrap(),
        ShareGrantProofState::Denied(AccessDenied::ShareScopeMismatch)
    ));
    sqlx::query("ROLLBACK").execute(&pool).await.unwrap();

    sqlx::query(
        "UPDATE xshield.share_grants SET status = 'revoked'
         WHERE tenant_id = $1 AND site_id = $2 AND share_id = $3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(grant.share_id().as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        store.load_share_grant(query()).await.unwrap(),
        ShareGrantProofState::Denied(AccessDenied::ShareScopeMismatch)
    ));
}

async fn seed(
    pool: &PgPool,
    tenant: &TenantId,
    site: &SiteId,
    token: &ShareTokenFingerprint,
    resource_key: &ResourceKeyHmac,
) {
    sqlx::query(
        "INSERT INTO xshield.policy_revisions (
            tenant_id, site_id, revision, status, content_digest, artifact_ref
         ) VALUES ($1, $2, 'policy-share-r1', 'active', $3, 'artifact_share_policy_r1')",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind("c".repeat(64))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.auth_bindings (
            tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
            authorization_context_ref, auth_epoch, credential_generation, status,
            absolute_expires_at
         ) VALUES ($1, $2, $3, $4, 'principal_share', 'context_share',
                   1, 1, 'active', to_timestamp($5))",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind("auth_018f2a3b-4c5d-7000-8000-000000000801")
    .bind([54_u8; 32].as_slice())
    .bind(i64::try_from(NOW + 1_000).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.share_grants (
            tenant_id, site_id, share_id, issuer_binding_id, token_fingerprint,
            resource_type, resource_key_hmac, operation_id, view_id, use_policy,
            source_event_id, policy_revision, status, issued_at, expires_at
         ) VALUES ($1, $2, $3, $4, $5, 'record', $6, 'records.share.read',
                   'shared_summary', 'reusable_read', $7, 'policy-share-r1',
                   'active', to_timestamp($8), to_timestamp($9))",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind("share_018f2a3b-4c5d-7000-8000-000000000802")
    .bind("auth_018f2a3b-4c5d-7000-8000-000000000801")
    .bind(token.as_bytes().as_slice())
    .bind(resource_key.as_bytes().as_slice())
    .bind("ev_018f2a3b-4c5d-7000-8000-000000000803")
    .bind(i64::try_from(NOW - 1).unwrap())
    .bind(i64::try_from(NOW + 600).unwrap())
    .execute(pool)
    .await
    .unwrap();
}
