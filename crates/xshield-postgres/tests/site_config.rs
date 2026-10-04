use serde_json::json;
use sqlx::PgPool;
use std::{env, sync::OnceLock, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{SiteId, TenantId};
use xshield_postgres::{
    PostgresIdentityStore, ProtectedSiteApprovalOutcome, ProtectedSiteConfigUpsert,
    ProtectedSiteConfigWriteOutcome,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn site_config_is_scoped_idempotent_port_safe_and_apply_bounded() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let store = PostgresIdentityStore::connect(&database_url, 4, Duration::from_secs(5))
        .await
        .unwrap();
    let pool = PgPool::connect(&database_url).await.unwrap();
    let tenant = TenantId::parse("tenant_site_contract").unwrap();
    let site_a = SiteId::parse("site_site_contract_a").unwrap();
    let site_b = SiteId::parse("site_site_contract_b").unwrap();
    let site_c = SiteId::parse("site_site_contract_c").unwrap();
    cleanup(&pool, &tenant).await;

    let first = store
        .upsert_protected_site_config(command(
            &tenant, &site_a, "first", false, [1; 32], [11; 32], [21; 32],
        ))
        .await
        .unwrap();
    let first = created(first);
    assert_eq!(first.listen_port(), 6100);
    assert_eq!(first.revision(), 1);

    let second = store
        .upsert_protected_site_config(command(
            &tenant, &site_b, "second", false, [2; 32], [12; 32], [22; 32],
        ))
        .await
        .unwrap();
    let second = created(second);
    assert_eq!(second.listen_port(), 6101);

    let replay = store
        .upsert_protected_site_config(command(
            &tenant, &site_a, "first", false, [1; 32], [11; 32], [21; 32],
        ))
        .await
        .unwrap();
    assert!(matches!(
        replay,
        ProtectedSiteConfigWriteOutcome::Existing(_)
    ));
    let conflict = store
        .upsert_protected_site_config(command(
            &tenant, &site_a, "changed", false, [1; 32], [11; 32], [31; 32],
        ))
        .await
        .unwrap();
    assert!(matches!(
        conflict,
        ProtectedSiteConfigWriteOutcome::Conflict
    ));

    let updated = store
        .upsert_protected_site_config(command(
            &tenant, &site_a, "changed", true, [3; 32], [13; 32], [33; 32],
        ))
        .await
        .unwrap();
    let updated = created_or_updated(updated);
    assert_eq!(updated.revision(), 2);
    assert_eq!(updated.listen_port(), first.listen_port());

    let apply = store
        .read_protected_site_apply_state(&tenant, &site_a)
        .await
        .unwrap()
        .unwrap();
    assert!(apply.requires_approval);
    assert_eq!(apply.desired_revision, 2);

    let approval = store
        .approve_protected_site_apply(
            &tenant,
            &site_a,
            &format!("approval_{}", Uuid::now_v7()),
            "independent-approver",
            &[41; 32],
        )
        .await
        .unwrap();
    assert!(matches!(
        approval,
        ProtectedSiteApprovalOutcome::Applied { .. }
    ));
    let apply = store
        .read_protected_site_apply_state(&tenant, &site_a)
        .await
        .unwrap()
        .unwrap();
    assert!(!apply.requires_approval);

    let snapshot_revision = store
        .next_protected_site_snapshot_revision(&tenant)
        .await
        .unwrap();
    let states = vec![
        (
            site_a.clone(),
            apply.desired_revision,
            apply.apply_id.clone(),
        ),
        (
            site_b.clone(),
            store
                .read_protected_site_apply_state(&tenant, &site_b)
                .await
                .unwrap()
                .unwrap()
                .desired_revision,
            store
                .read_protected_site_apply_state(&tenant, &site_b)
                .await
                .unwrap()
                .unwrap()
                .apply_id,
        ),
    ];
    assert!(
        store
            .mark_protected_site_applies_active_batch(&tenant, &states)
            .await
            .unwrap()
    );
    assert!(snapshot_revision >= 1);
    assert_eq!(
        store
            .read_protected_site_apply_state(&tenant, &site_a)
            .await
            .unwrap()
            .unwrap()
            .active_revision,
        Some(2)
    );

    let pending_update = store
        .upsert_protected_site_config(command(
            &tenant,
            &site_a,
            "after-active",
            false,
            [5; 32],
            [15; 32],
            [25; 32],
        ))
        .await
        .unwrap();
    assert!(matches!(
        pending_update,
        ProtectedSiteConfigWriteOutcome::Updated(_)
    ));
    assert_eq!(
        store
            .read_protected_site_apply_state(&tenant, &site_a)
            .await
            .unwrap()
            .unwrap()
            .active_revision,
        Some(2),
        "a failed desired update must retain the last confirmed revision"
    );

    let page = store
        .list_protected_site_configs(&tenant, None, 1)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    let next = store
        .list_protected_site_configs(&tenant, Some(&page[0].site_id), 1)
        .await
        .unwrap();
    assert_eq!(next.len(), 1);
    assert_ne!(page[0].site_id, next[0].site_id);

    store
        .insert_protected_site_health_snapshot(
            &tenant,
            &site_a,
            "healthy",
            "healthy",
            "active",
            "healthy",
            "CONTROL_SITE_UPSTREAM_HEALTHY",
            &json!({ "status": 200 }),
        )
        .await
        .unwrap();
    let health_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.site_health_snapshots WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant.as_str())
    .bind(site_a.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(health_count, 1);

    // The newest observation of each site wins; unobserved sites and other
    // tenants contribute nothing.
    store
        .insert_protected_site_health_snapshot(
            &tenant,
            &site_a,
            "degraded",
            "unavailable",
            "active",
            "healthy",
            "CONTROL_SITE_UPSTREAM_UNAVAILABLE",
            &json!({}),
        )
        .await
        .unwrap();
    store
        .insert_protected_site_health_snapshot(
            &tenant,
            &site_b,
            "healthy",
            "unknown",
            "pending",
            "unknown",
            "CONTROL_SITE_HEALTH_OBSERVED",
            &json!({}),
        )
        .await
        .unwrap();
    let latest = store
        .latest_protected_site_health_snapshots(&tenant, 128)
        .await
        .unwrap();
    assert_eq!(
        latest
            .iter()
            .map(|snapshot| snapshot.site_id.as_str())
            .collect::<Vec<_>>(),
        [site_a.as_str(), site_b.as_str()]
    );
    assert_eq!(latest[0].edge_state, "degraded");
    assert_eq!(latest[0].upstream_state, "unavailable");
    assert_eq!(latest[1].audit_state, "unknown");
    let other_tenant = TenantId::parse("tenant_site_contract_other").unwrap();
    assert!(
        store
            .latest_protected_site_health_snapshots(&other_tenant, 128)
            .await
            .unwrap()
            .is_empty()
    );

    assert!(
        store
            .delete_protected_site_config(&tenant, &site_a)
            .await
            .unwrap()
    );
    let replacement = store
        .upsert_protected_site_config(command(
            &tenant,
            &site_c,
            "replacement",
            false,
            [4; 32],
            [14; 32],
            [24; 32],
        ))
        .await
        .unwrap();
    assert_eq!(created(replacement).listen_port(), 6100);

    cleanup(&pool, &tenant).await;
}

fn command<'a>(
    tenant_id: &'a TenantId,
    site_id: &'a SiteId,
    display_name: &'a str,
    requires_approval: bool,
    config_digest: [u8; 32],
    idempotency_digest: [u8; 32],
    request_digest: [u8; 32],
) -> ProtectedSiteConfigUpsert<'a> {
    // The arrays are intentionally leaked only for this ignored integration
    // test's short process lifetime; production commands own their digests.
    let config_digest = Box::leak(Box::new(config_digest));
    let idempotency_digest = Box::leak(Box::new(idempotency_digest));
    let request_digest = Box::leak(Box::new(request_digest));
    ProtectedSiteConfigUpsert {
        tenant_id,
        site_id,
        display_name,
        public_origin: "https://example.com",
        upstream_address: "8.8.8.8:9000",
        upstream_server_name: "origin.example",
        upstream_tls: false,
        listen_port: 0,
        entry_path: "/",
        security_entry: "ui_action_required",
        sensor_enabled: true,
        policy_revision: "policy-v1",
        status: "active",
        policy: policy(),
        requires_approval,
        config_digest,
        updated_by: "site-test",
        idempotency_digest,
        request_digest,
    }
}

fn policy() -> &'static xshield_core::SitePolicyConfig {
    static POLICY: OnceLock<xshield_core::SitePolicyConfig> = OnceLock::new();
    POLICY.get_or_init(xshield_core::SitePolicyConfig::default)
}

fn created(
    outcome: ProtectedSiteConfigWriteOutcome,
) -> xshield_postgres::ProtectedSiteConfigRecord {
    match outcome {
        ProtectedSiteConfigWriteOutcome::Created(record) => record,
        other => panic!("expected created, got {other:?}"),
    }
}

fn created_or_updated(
    outcome: ProtectedSiteConfigWriteOutcome,
) -> xshield_postgres::ProtectedSiteConfigRecord {
    match outcome {
        ProtectedSiteConfigWriteOutcome::Created(record)
        | ProtectedSiteConfigWriteOutcome::Updated(record) => record,
        other => panic!("expected update, got {other:?}"),
    }
}

async fn cleanup(pool: &PgPool, tenant: &TenantId) {
    for statement in [
        "DELETE FROM xshield.protected_site_configs WHERE tenant_id = $1",
        "DELETE FROM xshield.protected_sites WHERE tenant_id = $1",
        "DELETE FROM xshield.site_port_leases WHERE tenant_id = $1",
        "DELETE FROM xshield.site_snapshot_sequences WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(tenant.as_str())
            .execute(pool)
            .await
            .unwrap();
    }
}
