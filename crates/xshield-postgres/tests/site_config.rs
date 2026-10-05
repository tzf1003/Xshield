use serde_json::json;
use sqlx::PgPool;
use std::{env, sync::OnceLock, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{SiteId, TenantId};
use xshield_postgres::{
    HEALTH_SNAPSHOT_HISTORY, PostgresIdentityStore, ProtectedSiteApprovalOutcome,
    ProtectedSiteConfigUpsert, ProtectedSiteConfigWriteOutcome,
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
            &tenant, &site_a, "first", [1; 32], [11; 32], [21; 32],
        ))
        .await
        .unwrap();
    let first = created(first);
    assert_eq!(first.listen_port(), 6100);
    assert_eq!(first.revision(), 1);

    let second = store
        .upsert_protected_site_config(command(
            &tenant, &site_b, "second", [2; 32], [12; 32], [22; 32],
        ))
        .await
        .unwrap();
    let second = created(second);
    assert_eq!(second.listen_port(), 6101);

    let replay = store
        .upsert_protected_site_config(command(
            &tenant, &site_a, "first", [1; 32], [11; 32], [21; 32],
        ))
        .await
        .unwrap();
    assert!(matches!(
        replay,
        ProtectedSiteConfigWriteOutcome::Existing(_)
    ));
    let conflict = store
        .upsert_protected_site_config(command(
            &tenant, &site_a, "changed", [1; 32], [11; 32], [31; 32],
        ))
        .await
        .unwrap();
    assert!(matches!(
        conflict,
        ProtectedSiteConfigWriteOutcome::Conflict
    ));

    let updated = store
        .upsert_protected_site_config(command(
            &tenant, &site_a, "changed", [3; 32], [13; 32], [33; 32],
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
            None,
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

    // A site that has never been served needs approval to go live, whatever it
    // contains; only an approved revision is marked active below.
    let apply_b = store
        .read_protected_site_apply_state(&tenant, &site_b)
        .await
        .unwrap()
        .unwrap();
    assert!(apply_b.requires_approval);
    assert!(matches!(
        store
            .approve_protected_site_apply(
                &tenant,
                &site_b,
                &format!("approval_{}", Uuid::now_v7()),
                "independent-approver",
                &[42; 32],
                None,
            )
            .await
            .unwrap(),
        ProtectedSiteApprovalOutcome::Applied { .. }
    ));

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
    // History is bounded per site: repeated reads keep only the newest
    // observations, never touch another site's rows, and keep the latest one.
    for round in 0..(HEALTH_SNAPSHOT_HISTORY + 6) {
        let reason = if round % 2 == 0 {
            "CONTROL_SITE_HEALTH_EVEN"
        } else {
            "CONTROL_SITE_HEALTH_ODD"
        };
        store
            .insert_protected_site_health_snapshot(
                &tenant,
                &site_a,
                "healthy",
                "healthy",
                "active",
                "healthy",
                reason,
                &json!({}),
            )
            .await
            .unwrap();
    }
    let kept_for = |site: &SiteId| {
        let pool = pool.clone();
        let tenant = tenant.clone();
        let site = site.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM xshield.site_health_snapshots
                 WHERE tenant_id = $1 AND site_id = $2",
            )
            .bind(tenant.as_str())
            .bind(site.as_str())
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(kept_for(&site_a).await, HEALTH_SNAPSHOT_HISTORY);
    assert_eq!(
        kept_for(&site_b).await,
        1,
        "another site's history is untouched"
    );
    let latest = store
        .latest_protected_site_health_snapshots(&tenant, 128)
        .await
        .unwrap();
    let newest_round = HEALTH_SNAPSHOT_HISTORY + 5;
    assert_eq!(
        latest[0].reason_code,
        if newest_round % 2 == 0 {
            "CONTROL_SITE_HEALTH_EVEN"
        } else {
            "CONTROL_SITE_HEALTH_ODD"
        },
        "the newest observation survives pruning"
    );
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
        pre_authorized_by: None,
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

/// A configuration an operator saves, owned so tests can vary one field at a
/// time. `key` seeds the idempotency and request digests: the same key with
/// the same content is a replay.
#[derive(Clone)]
struct Draft {
    display_name: String,
    upstream: String,
    status: String,
    author: String,
    key: u8,
}

impl Draft {
    fn new(key: u8) -> Self {
        Self {
            display_name: "demo".to_owned(),
            upstream: "8.8.8.8:9000".to_owned(),
            status: "active".to_owned(),
            author: "site-author".to_owned(),
            key,
        }
    }

    fn upstream(mut self, upstream: &str) -> Self {
        upstream.clone_into(&mut self.upstream);
        self
    }

    fn status(mut self, status: &str) -> Self {
        status.clone_into(&mut self.status);
        self
    }

    fn named(mut self, display_name: &str) -> Self {
        display_name.clone_into(&mut self.display_name);
        self
    }

    fn by(mut self, author: &str) -> Self {
        author.clone_into(&mut self.author);
        self
    }
}

async fn save(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    draft: &Draft,
) -> ProtectedSiteConfigWriteOutcome {
    save_as(store, tenant, site, draft, None).await
}

async fn save_as(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    draft: &Draft,
    pre_authorized_by: Option<&str>,
) -> ProtectedSiteConfigWriteOutcome {
    // The content digest depends on the content, the request digest on the key
    // and the content, the idempotency digest on the key alone.
    let content = draft
        .display_name
        .bytes()
        .chain(draft.upstream.bytes())
        .chain(draft.status.bytes())
        .fold(0_u8, |acc, byte| acc.wrapping_mul(31).wrapping_add(byte));
    let mut config_digest = [draft.key; 32];
    config_digest[0] = content;
    let idempotency_digest = [draft.key.wrapping_add(100); 32];
    let mut request_digest = config_digest;
    request_digest[1] = draft.key.wrapping_add(1);
    request_digest[2] = content.wrapping_add(7);
    let policy = xshield_core::SitePolicyConfig::default();
    store
        .upsert_protected_site_config(ProtectedSiteConfigUpsert {
            tenant_id: tenant,
            site_id: site,
            display_name: &draft.display_name,
            public_origin: "https://example.com",
            upstream_address: &draft.upstream,
            upstream_server_name: "origin.example",
            upstream_tls: false,
            listen_port: 0,
            entry_path: "/",
            security_entry: "public",
            sensor_enabled: false,
            policy_revision: "policy-v1",
            status: &draft.status,
            policy: &policy,
            pre_authorized_by,
            config_digest: &config_digest,
            updated_by: &draft.author,
            idempotency_digest: &idempotency_digest,
            request_digest: &request_digest,
        })
        .await
        .unwrap()
}

async fn approve(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    approver: &str,
    key: u8,
    expected_digest: Option<&[u8; 32]>,
) -> ProtectedSiteApprovalOutcome {
    store
        .approve_protected_site_apply(
            tenant,
            site,
            &format!("approval_{}", Uuid::now_v7()),
            approver,
            &[key; 32],
            expected_digest,
        )
        .await
        .unwrap()
}

async fn apply_state(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) -> xshield_postgres::ProtectedSiteApplyState {
    store
        .read_protected_site_apply_state(tenant, site)
        .await
        .unwrap()
        .unwrap()
}

/// Marks the desired revision of `site` active, the way a confirmed edge
/// snapshot does.
async fn confirm(store: &PostgresIdentityStore, tenant: &TenantId, site: &SiteId) {
    let state = apply_state(store, tenant, site).await;
    assert!(
        !state.requires_approval,
        "only approved revisions are applied"
    );
    assert!(
        store
            .mark_protected_site_applies_active_batch(
                tenant,
                &[(site.clone(), state.desired_revision, state.apply_id)],
            )
            .await
            .unwrap()
    );
}

async fn session(prefix: &str) -> (PostgresIdentityStore, PgPool, TenantId, SiteId) {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let store = PostgresIdentityStore::connect(&database_url, 8, Duration::from_secs(5))
        .await
        .unwrap();
    let pool = PgPool::connect(&database_url).await.unwrap();
    let tenant = TenantId::parse(format!("tenant_{prefix}_{}", Uuid::now_v7())).unwrap();
    let site = SiteId::parse(format!("site_{prefix}")).unwrap();
    (store, pool, tenant, site)
}

/// Risk is decided from the active revision, so re-submitting equal content
/// cannot clear it, and an approval covers exactly the revision it read.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn approval_is_decided_from_the_active_revision_and_bound_to_one_revision() {
    let (store, pool, tenant, site) = session("approval_bound").await;

    // First activation always needs approval; its reasons are recorded.
    created(save(&store, &tenant, &site, &Draft::new(1)).await);
    let state = apply_state(&store, &tenant, &site).await;
    assert!(state.requires_approval);
    assert_eq!(state.risk_reasons, ["ACTIVATION"]);
    assert_eq!(state.reason_code, "CONTROL_SITE_APPROVAL_REQUIRED");
    // A second save of identical content (new key) is evaluated against the
    // same baseline (nothing served), so it needs approval again.
    created_or_updated(save(&store, &tenant, &site, &Draft::new(2)).await);
    assert!(apply_state(&store, &tenant, &site).await.requires_approval);

    // The author cannot approve; the database refuses it as well.
    assert_eq!(
        approve(&store, &tenant, &site, "site-author", 41, None).await,
        ProtectedSiteApprovalOutcome::SelfApproval
    );
    let self_approval = sqlx::query(
        "INSERT INTO xshield.site_apply_approvals
             (tenant_id, site_id, approval_id, desired_revision, config_digest, apply_id,
              approval_kind, approved_by, authored_by)
         SELECT tenant_id, site_id, $3, desired_revision, decode(repeat('00', 32), 'hex'),
                apply_id, 'independent', 'site-author', 'site-author'
         FROM xshield.site_apply_intents WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(format!("approval_{}", Uuid::now_v7()))
    .execute(&pool)
    .await;
    assert!(
        self_approval.is_err(),
        "the CHECK constraint refuses self-approval"
    );

    // An approval pinned to a digest the reviewer did not read is refused.
    assert_eq!(
        approve(&store, &tenant, &site, "reviewer", 42, Some(&[9; 32])).await,
        ProtectedSiteApprovalOutcome::RevisionMismatch
    );
    assert!(apply_state(&store, &tenant, &site).await.requires_approval);
    let ProtectedSiteApprovalOutcome::Applied { approval_id } =
        approve(&store, &tenant, &site, "reviewer", 43, None).await
    else {
        panic!("the independent approval must apply");
    };
    assert!(!apply_state(&store, &tenant, &site).await.requires_approval);
    // The same key replays exactly this approval.
    assert_eq!(
        approve(&store, &tenant, &site, "reviewer", 43, None).await,
        ProtectedSiteApprovalOutcome::Existing { approval_id }
    );
    // A different key finds nothing left to approve.
    assert_eq!(
        approve(&store, &tenant, &site, "second-reviewer", 44, None).await,
        ProtectedSiteApprovalOutcome::NotRequired
    );
    confirm(&store, &tenant, &site).await;

    // Now the edge serves revision 2. A risky change is held...
    created_or_updated(
        save(
            &store,
            &tenant,
            &site,
            &Draft::new(3).upstream("8.8.4.4:9000"),
        )
        .await,
    );
    let state = apply_state(&store, &tenant, &site).await;
    assert!(state.requires_approval);
    assert_eq!(state.risk_reasons, ["UPSTREAM_CHANGED"]);
    // ...resubmitting it under new keys never clears the requirement...
    for key in [4, 5] {
        created_or_updated(
            save(
                &store,
                &tenant,
                &site,
                &Draft::new(key).upstream("8.8.4.4:9000"),
            )
            .await,
        );
        assert!(apply_state(&store, &tenant, &site).await.requires_approval);
    }
    // ...while a cosmetic-only change against the active baseline is free.
    created_or_updated(save(&store, &tenant, &site, &Draft::new(6).named("renamed")).await);
    let state = apply_state(&store, &tenant, &site).await;
    assert!(
        !state.requires_approval,
        "same as what is served, new label"
    );
    assert!(state.risk_reasons.is_empty());

    // The approval key bound to revision 2 is stale against any other revision.
    created_or_updated(
        save(
            &store,
            &tenant,
            &site,
            &Draft::new(7).upstream("9.9.9.9:9000"),
        )
        .await,
    );
    assert!(apply_state(&store, &tenant, &site).await.requires_approval);
    assert_eq!(
        approve(&store, &tenant, &site, "reviewer", 43, None).await,
        ProtectedSiteApprovalOutcome::RevisionMismatch
    );
    assert!(
        apply_state(&store, &tenant, &site).await.requires_approval,
        "the stale replay must not approve the new revision"
    );

    // Two reviewers racing on one revision: exactly one approval is recorded.
    let (first, second) = tokio::join!(
        approve(&store, &tenant, &site, "reviewer-a", 50, None),
        approve(&store, &tenant, &site, "reviewer-b", 51, None),
    );
    let applied = [&first, &second]
        .iter()
        .filter(|outcome| matches!(outcome, ProtectedSiteApprovalOutcome::Applied { .. }))
        .count();
    assert_eq!(applied, 1, "{first:?} / {second:?}");
    let approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.site_apply_approvals
         WHERE tenant_id = $1 AND site_id = $2 AND desired_revision = 7",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(approvals, 1);
    cleanup(&pool, &tenant).await;
}

/// Only the latest write was remembered, so replaying write #1 after write #2
/// silently created revision 3 from stale content.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn idempotency_is_remembered_for_every_revision() {
    let (store, pool, tenant, site) = session("idem_history").await;
    let one = Draft::new(1).named("one");
    let two = Draft::new(2).named("two");
    created(save(&store, &tenant, &site, &one).await);
    created_or_updated(save(&store, &tenant, &site, &two).await);

    assert!(matches!(
        save(&store, &tenant, &site, &two).await,
        ProtectedSiteConfigWriteOutcome::Existing(_)
    ));
    assert!(matches!(
        save(&store, &tenant, &site, &one).await,
        ProtectedSiteConfigWriteOutcome::Superseded
    ));
    // Same key, different content: a conflict rather than a replay.
    assert!(matches!(
        save(&store, &tenant, &site, &one.clone().named("something else")).await,
        ProtectedSiteConfigWriteOutcome::Conflict
    ));
    let record = store
        .read_protected_site_config(&tenant, &site)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.revision(),
        2,
        "no revision was created by the replays"
    );
    assert_eq!(record.display_name(), "two");

    let digest = |key: u8| [key.wrapping_add(100); 32];
    let first = store
        .find_protected_site_write(&tenant, &site, &digest(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((first.revision, first.is_latest), (1, false));
    let latest = store
        .find_protected_site_write(&tenant, &site, &digest(2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((latest.revision, latest.is_latest), (2, true));
    assert!(
        store
            .find_protected_site_write(&tenant, &site, &digest(3))
            .await
            .unwrap()
            .is_none()
    );
    cleanup(&pool, &tenant).await;
}

/// "The revision before this one" is the previously *active* revision, found
/// from the recorded activation order, not `active - 1`.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn activation_history_names_the_previously_active_revision() {
    let (store, pool, tenant, site) = session("activation_history").await;
    assert_eq!(
        store
            .read_protected_site_previous_active_revision(&tenant, &site)
            .await
            .unwrap(),
        None
    );
    created(save(&store, &tenant, &site, &Draft::new(1)).await);
    approve(&store, &tenant, &site, "reviewer", 41, None).await;
    confirm(&store, &tenant, &site).await; // revision 1 active
    assert_eq!(
        store
            .read_protected_site_previous_active_revision(&tenant, &site)
            .await
            .unwrap(),
        None,
        "only one revision has ever been active"
    );
    // Revisions 2 and 3 are saved but never approved or applied.
    for key in [2, 3] {
        created_or_updated(
            save(
                &store,
                &tenant,
                &site,
                &Draft::new(key).upstream("8.8.4.4:9000"),
            )
            .await,
        );
    }
    // Revision 4 is approved and applied.
    created_or_updated(
        save(
            &store,
            &tenant,
            &site,
            &Draft::new(4).upstream("9.9.9.9:9000"),
        )
        .await,
    );
    approve(&store, &tenant, &site, "reviewer", 42, None).await;
    confirm(&store, &tenant, &site).await;
    assert_eq!(
        apply_state(&store, &tenant, &site).await.active_revision,
        Some(4)
    );
    assert_eq!(
        store
            .read_protected_site_previous_active_revision(&tenant, &site)
            .await
            .unwrap(),
        Some(1),
        "not revision 3: it never served traffic"
    );
    // Stored revisions are complete configurations that read back typed.
    let stored = store
        .read_protected_site_revision_config(&tenant, &site, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.policy_revision, "policy-v1");
    assert_eq!(stored.upstream_address, "8.8.8.8:9000");
    cleanup(&pool, &tenant).await;
}

/// Revisions saved by earlier versions lack `policy_revision` (it lives in its
/// own column) and rollback could not read them back; the oldest backfilled
/// rows lack `policy` as well.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn legacy_revision_rows_still_read_back_as_typed_configurations() {
    let (store, pool, tenant, site) = session("legacy_revision").await;
    created(save(&store, &tenant, &site, &Draft::new(1)).await);
    sqlx::query(
        "UPDATE xshield.site_policy_revisions
         SET config_json = config_json - 'policy_revision' - 'policy', policy_revision = 'legacy-r7'
         WHERE tenant_id = $1 AND site_id = $2 AND revision = 1",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .execute(&pool)
    .await
    .unwrap();
    let stored = store
        .read_protected_site_revision_config(&tenant, &site, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.policy_revision, "legacy-r7");
    assert_eq!(stored.policy, xshield_core::SitePolicyConfig::default());
    // A payload that is not a configuration is corruption, not a guess.
    sqlx::query(
        "UPDATE xshield.site_policy_revisions SET config_json = '[]'::jsonb
         WHERE tenant_id = $1 AND site_id = $2 AND revision = 1",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        store
            .read_protected_site_revision_config(&tenant, &site, 1)
            .await
            .is_err()
    );
    cleanup(&pool, &tenant).await;
}

/// The snapshot read returns each site's desired row next to the stored
/// configuration of its active revision, with a revision allocated in the same
/// transaction.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn snapshot_read_pairs_desired_rows_with_the_active_configuration() {
    let (store, pool, tenant, site) = session("snapshot_read").await;
    let other = SiteId::parse("site_snapshot_read_other").unwrap();
    created(save(&store, &tenant, &site, &Draft::new(1)).await);
    approve(&store, &tenant, &site, "reviewer", 41, None).await;
    confirm(&store, &tenant, &site).await;
    created_or_updated(
        save(
            &store,
            &tenant,
            &site,
            &Draft::new(2).upstream("8.8.4.4:9000"),
        )
        .await,
    );
    created(save(&store, &tenant, &other, &Draft::new(3)).await);

    let first = store.begin_protected_site_snapshot(&tenant).await.unwrap();
    let second = store.begin_protected_site_snapshot(&tenant).await.unwrap();
    assert!(second.revision > first.revision);
    assert_eq!(
        first
            .sites
            .iter()
            .map(|site| site.site_id.as_str())
            .collect::<Vec<_>>(),
        [site.as_str(), other.as_str()]
    );
    let held = first
        .sites
        .iter()
        .find(|entry| entry.site_id == site)
        .unwrap();
    assert!(held.requires_approval);
    assert_eq!(held.active_revision, Some(1));
    assert_eq!(
        held.record.upstream_address(),
        "8.8.4.4:9000",
        "the desired row"
    );
    assert_eq!(
        held.active_config.as_ref().unwrap().upstream_address,
        "8.8.8.8:9000",
        "what the edge serves"
    );
    let never = first
        .sites
        .iter()
        .find(|entry| entry.site_id == other)
        .unwrap();
    assert!(never.active_config.is_none());
    cleanup(&pool, &tenant).await;
}

/// The explicit direct-apply right and the delete flow's pre-authorization are
/// recorded like any approval, bound to the exact revision.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn direct_apply_and_pre_authorization_leave_bound_records() {
    use sqlx::Row;
    let (store, pool, tenant, site) = session("direct_records").await;
    created(save(&store, &tenant, &site, &Draft::new(1)).await);
    let state = apply_state(&store, &tenant, &site).await;
    let approval_id = || format!("approval_{}", Uuid::now_v7());

    assert_eq!(
        store
            .authorize_protected_site_direct_apply(
                &tenant,
                &site,
                &approval_id(),
                "agent-direct",
                state.desired_revision + 1,
                &state.apply_id,
            )
            .await
            .unwrap(),
        xshield_postgres::ProtectedSiteDirectApplyOutcome::Stale
    );
    assert!(apply_state(&store, &tenant, &site).await.requires_approval);
    assert!(matches!(
        store
            .authorize_protected_site_direct_apply(
                &tenant,
                &site,
                &approval_id(),
                "agent-direct",
                state.desired_revision,
                &state.apply_id,
            )
            .await
            .unwrap(),
        xshield_postgres::ProtectedSiteDirectApplyOutcome::Authorized { .. }
    ));
    let cleared = apply_state(&store, &tenant, &site).await;
    assert!(!cleared.requires_approval, "no stale flag is left behind");
    assert_eq!(cleared.approved_by.as_deref(), Some("agent-direct"));
    assert_eq!(
        store
            .authorize_protected_site_direct_apply(
                &tenant,
                &site,
                &approval_id(),
                "agent-direct",
                state.desired_revision,
                &state.apply_id,
            )
            .await
            .unwrap(),
        xshield_postgres::ProtectedSiteDirectApplyOutcome::NotRequired
    );
    let row = sqlx::query(
        "SELECT approval_kind, approved_by, authored_by, desired_revision, apply_id
         FROM xshield.site_apply_approvals WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("approval_kind"), "direct_apply");
    assert_eq!(row.get::<String, _>("approved_by"), "agent-direct");
    assert_eq!(row.get::<String, _>("authored_by"), "site-author");
    assert_eq!(row.get::<i64, _>("desired_revision"), 1);
    assert_eq!(row.get::<String, _>("apply_id"), state.apply_id);
    confirm(&store, &tenant, &site).await;

    // A takedown pause pre-authorized by the caller who requested it.
    created_or_updated(
        save_as(
            &store,
            &tenant,
            &site,
            &Draft::new(2).status("paused").by("deleting-admin"),
            Some("deleting-admin"),
        )
        .await,
    );
    let paused = apply_state(&store, &tenant, &site).await;
    assert!(!paused.requires_approval);
    assert_eq!(paused.risk_reasons, ["TAKEDOWN"]);
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT approval_kind FROM xshield.site_apply_approvals
         WHERE tenant_id = $1 AND site_id = $2 AND desired_revision = 2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(kinds, ["delete_step_up"]);
    // Without the pre-authorization the same pause needs an approval.
    created_or_updated(save(&store, &tenant, &site, &Draft::new(3).status("active")).await);
    created_or_updated(save(&store, &tenant, &site, &Draft::new(4).status("paused")).await);
    assert!(apply_state(&store, &tenant, &site).await.requires_approval);
    cleanup(&pool, &tenant).await;
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
