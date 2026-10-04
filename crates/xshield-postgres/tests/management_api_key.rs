//! `PostgreSQL` wire regression for management API-key persistence: staged
//! changes, atomic rotation and the throttled last-use stamp.
//!
//! Rows are isolated by a unique tenant per test; no other data is touched.

use chrono::{Duration as ChronoDuration, Utc};
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_postgres::{ManagementApiKeyScopeInput, NewManagementApiKey, PostgresIdentityStore};

struct Fixture {
    store: PostgresIdentityStore,
    pool: PgPool,
    tenant: String,
}

impl Fixture {
    async fn new() -> Self {
        let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
        Self {
            store: PostgresIdentityStore::connect(&url, 4, Duration::from_secs(5))
                .await
                .expect("store connects"),
            pool: PgPool::connect(&url).await.expect("test database connects"),
            tenant: format!("tenant_keys_{}", Uuid::now_v7().simple()),
        }
    }

    fn scopes() -> Vec<ManagementApiKeyScopeInput> {
        vec![ManagementApiKeyScopeInput {
            tenant_id: String::new(),
            site_id: "site_a".to_owned(),
            capability: "site.read".to_owned(),
        }]
    }

    fn fingerprint(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    async fn stage_create(
        &self,
        api_key_id: &str,
        seed: u8,
    ) -> xshield_postgres::PendingManagementApiKeyChange {
        let mut scopes = Self::scopes();
        scopes[0].tenant_id.clone_from(&self.tenant);
        let fingerprint = Self::fingerprint(seed);
        self.store
            .stage_create_management_api_key(&NewManagementApiKey {
                api_key_id,
                tenant_id: &self.tenant,
                subject: "agent-keys",
                display_name: "store test key",
                key_prefix: "xsk_abcdef01",
                fingerprint: &fingerprint,
                expires_at: Utc::now() + ChronoDuration::days(1),
                created_by: "human-key-admin",
                scopes: &scopes,
            })
            .await
            .expect("create stages")
    }

    async fn status(&self, api_key_id: &str) -> Option<String> {
        sqlx::query_scalar(
            "SELECT status FROM xshield.management_api_keys WHERE tenant_id = $1 AND api_key_id = $2",
        )
        .bind(&self.tenant)
        .bind(api_key_id)
        .fetch_optional(&self.pool)
        .await
        .expect("status is readable")
    }

    async fn count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM xshield.management_api_keys WHERE tenant_id = $1")
            .bind(&self.tenant)
            .fetch_one(&self.pool)
            .await
            .expect("count is readable")
    }

    async fn lookup(&self, seed: u8) -> usize {
        self.store
            .lookup_management_api_key_scopes(&Self::fingerprint(seed), &self.tenant)
            .await
            .expect("lookup succeeds")
            .len()
    }
}

fn key_id() -> String {
    format!("key_{}", Uuid::now_v7())
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn staged_create_is_invisible_until_commit_and_rolls_back_when_dropped() {
    let fixture = Fixture::new().await;
    let dropped = key_id();
    let pending = fixture.stage_create(&dropped, 1).await;
    // Another connection sees nothing while the change is staged.
    assert_eq!(fixture.count().await, 0);
    assert_eq!(fixture.lookup(1).await, 0);
    drop(pending);
    assert_eq!(fixture.count().await, 0, "a dropped change leaves nothing");
    assert_eq!(fixture.status(&dropped).await, None);

    let committed = key_id();
    fixture
        .stage_create(&committed, 2)
        .await
        .commit()
        .await
        .expect("commit succeeds");
    assert_eq!(fixture.status(&committed).await.as_deref(), Some("active"));
    assert_eq!(
        fixture.lookup(2).await,
        1,
        "the committed scope row is found"
    );
    let listed = fixture
        .store
        .list_management_api_keys(&fixture.tenant)
        .await
        .expect("keys list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].api_key_id, committed);
    assert!(listed[0].last_used_at.is_none());
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn rotation_swaps_both_keys_or_neither() {
    let fixture = Fixture::new().await;
    let old = key_id();
    fixture
        .stage_create(&old, 3)
        .await
        .commit()
        .await
        .expect("old key commits");

    let mut scopes = Fixture::scopes();
    scopes[0].tenant_id.clone_from(&fixture.tenant);
    let replacement = key_id();
    let fingerprint = Fixture::fingerprint(4);
    let new_key = NewManagementApiKey {
        api_key_id: &replacement,
        tenant_id: &fixture.tenant,
        subject: "agent-keys",
        display_name: "replacement",
        key_prefix: "xsk_abcdef02",
        fingerprint: &fingerprint,
        expires_at: Utc::now() + ChronoDuration::days(1),
        created_by: "human-key-admin",
        scopes: &scopes,
    };
    // An unknown, foreign or already revoked old key stages nothing at all.
    for unknown in [key_id(), old.replace("key_", "key_0")] {
        assert!(
            fixture
                .store
                .stage_rotate_management_api_key(&unknown, &new_key)
                .await
                .expect("rotation stages")
                .is_none()
        );
    }
    assert_eq!(fixture.count().await, 1);

    // Dropping a staged rotation restores everything.
    let staged = fixture
        .store
        .stage_rotate_management_api_key(&old, &new_key)
        .await
        .expect("rotation stages")
        .expect("old key is active");
    assert_eq!(fixture.status(&old).await.as_deref(), Some("active"));
    drop(staged);
    assert_eq!(fixture.status(&old).await.as_deref(), Some("active"));
    assert_eq!(fixture.count().await, 1);
    assert_eq!(fixture.lookup(3).await, 1);

    // Committing swaps them together.
    fixture
        .store
        .stage_rotate_management_api_key(&old, &new_key)
        .await
        .expect("rotation stages")
        .expect("old key is active")
        .commit()
        .await
        .expect("rotation commits");
    assert_eq!(fixture.status(&old).await.as_deref(), Some("revoked"));
    assert_eq!(
        fixture.status(&replacement).await.as_deref(),
        Some("active")
    );
    assert_eq!(
        fixture.lookup(3).await,
        0,
        "the old fingerprint no longer resolves"
    );
    assert_eq!(fixture.lookup(4).await, 1);
    // The revoked key cannot be rotated again, and nothing is created.
    let again = key_id();
    let other_fingerprint = Fixture::fingerprint(5);
    let second = NewManagementApiKey {
        api_key_id: &again,
        fingerprint: &other_fingerprint,
        ..new_key
    };
    assert!(
        fixture
            .store
            .stage_rotate_management_api_key(&old, &second)
            .await
            .expect("rotation stages")
            .is_none()
    );
    assert_eq!(fixture.count().await, 2);
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn staged_revoke_applies_only_to_an_active_key_of_the_tenant() {
    let fixture = Fixture::new().await;
    let id = key_id();
    fixture
        .stage_create(&id, 6)
        .await
        .commit()
        .await
        .expect("key commits");
    assert!(
        fixture
            .store
            .stage_revoke_management_api_key("tenant_someone_else", &id)
            .await
            .expect("revoke stages")
            .is_none(),
        "another tenant cannot revoke the key"
    );
    assert!(
        fixture
            .store
            .stage_revoke_management_api_key(&fixture.tenant, &key_id())
            .await
            .expect("revoke stages")
            .is_none()
    );
    let staged = fixture
        .store
        .stage_revoke_management_api_key(&fixture.tenant, &id)
        .await
        .expect("revoke stages")
        .expect("key is active");
    assert_eq!(fixture.status(&id).await.as_deref(), Some("active"));
    drop(staged);
    assert_eq!(fixture.status(&id).await.as_deref(), Some("active"));
    fixture
        .store
        .stage_revoke_management_api_key(&fixture.tenant, &id)
        .await
        .expect("revoke stages")
        .expect("key is active")
        .commit()
        .await
        .expect("revoke commits");
    assert_eq!(fixture.status(&id).await.as_deref(), Some("revoked"));
    assert!(
        fixture
            .store
            .stage_revoke_management_api_key(&fixture.tenant, &id)
            .await
            .expect("revoke stages")
            .is_none(),
        "a revoked key cannot be revoked again"
    );
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn last_use_is_stamped_at_most_once_per_minute() {
    let fixture = Fixture::new().await;
    let id = key_id();
    fixture
        .stage_create(&id, 7)
        .await
        .commit()
        .await
        .expect("key commits");
    assert!(
        fixture
            .store
            .touch_management_api_key(&fixture.tenant, &id)
            .await
            .expect("touch succeeds"),
        "the first use writes"
    );
    let stamped: chrono::DateTime<Utc> = sqlx::query_scalar(
        "SELECT last_used_at FROM xshield.management_api_keys WHERE api_key_id = $1",
    )
    .bind(&id)
    .fetch_one(&fixture.pool)
    .await
    .expect("stamp is readable");
    for _ in 0..5 {
        assert!(
            !fixture
                .store
                .touch_management_api_key(&fixture.tenant, &id)
                .await
                .expect("touch succeeds"),
            "later uses within the minute do not write"
        );
    }
    let unchanged: chrono::DateTime<Utc> = sqlx::query_scalar(
        "SELECT last_used_at FROM xshield.management_api_keys WHERE api_key_id = $1",
    )
    .bind(&id)
    .fetch_one(&fixture.pool)
    .await
    .expect("stamp is readable");
    assert_eq!(unchanged, stamped);
    sqlx::query(
        "UPDATE xshield.management_api_keys SET last_used_at = last_used_at - interval '2 minutes'
         WHERE api_key_id = $1",
    )
    .bind(&id)
    .execute(&fixture.pool)
    .await
    .expect("stamp ages");
    assert!(
        fixture
            .store
            .touch_management_api_key(&fixture.tenant, &id)
            .await
            .expect("touch succeeds"),
        "after the minute the stamp is refreshed"
    );
    // A revoked key or another tenant is never stamped.
    assert!(
        !fixture
            .store
            .touch_management_api_key("tenant_someone_else", &id)
            .await
            .expect("touch succeeds")
    );
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn scope_lookup_never_returns_rows_naming_another_tenant() {
    let fixture = Fixture::new().await;
    let id = key_id();
    fixture
        .stage_create(&id, 8)
        .await
        .commit()
        .await
        .expect("key commits");
    // The schema does not tie a scope row's tenant to its key; the lookup must.
    sqlx::query(
        "INSERT INTO xshield.management_api_key_scopes (api_key_id, tenant_id, site_id, capability)
         VALUES ($1, 'tenant_foreign', 'site_x', 'site.config.write')",
    )
    .bind(&id)
    .execute(&fixture.pool)
    .await
    .expect("foreign row inserts");
    let scopes = fixture
        .store
        .lookup_management_api_key_scopes(&Fixture::fingerprint(8), &fixture.tenant)
        .await
        .expect("lookup succeeds");
    assert_eq!(scopes.len(), 1, "{scopes:?}");
    assert_eq!(scopes[0].tenant_id, fixture.tenant);
    assert_eq!(scopes[0].site_id, "site_a");
}
