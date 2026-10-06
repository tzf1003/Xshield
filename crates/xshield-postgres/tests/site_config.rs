use serde_json::json;
use sqlx::PgPool;
use std::{env, sync::OnceLock, time::Duration};
use uuid::Uuid;
use xshield_core::{
    SiteConfig,
    domain::{SiteId, TenantId},
};
use xshield_postgres::{
    HEALTH_SNAPSHOT_HISTORY, PostgresIdentityStore, ProtectedSiteApprovalOutcome,
    ProtectedSiteConfigUpsert, ProtectedSiteConfigWriteOutcome, ProtectedSiteDirectApplyOutcome,
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
    assert_eq!(
        store
            .latest_protected_site_health_snapshots(&other_tenant, 128)
            .await
            .unwrap(),
        [] as [xshield_postgres::ProtectedSiteHealthSnapshot; 0]
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
    assert_eq!(state.risk_reasons, [] as [std::string::String; 0]);

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

/// The real-browser loop topology as the control plane stores it.
const BROWSER_LOOP: &str = include_str!("../../../tests/site-config/browser-loop.json");
/// The loop plus a share scope, as the control plane stores it.
const SHARE_FLOW: &str = include_str!("../../../tests/site-config/share-flow.json");
/// A stored configuration exactly as written before the flow fields existed.
const PRE_FLOW: &str = include_str!("../../../tests/site-config/pre-flow.json");

/// Saves a complete typed configuration the way the control plane does.
async fn save_config(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    config: &SiteConfig,
    author: &str,
    key: u8,
) -> Result<ProtectedSiteConfigWriteOutcome, xshield_postgres::StoreError> {
    store
        .upsert_protected_site_config(ProtectedSiteConfigUpsert {
            tenant_id: tenant,
            site_id: site,
            display_name: &config.display_name,
            public_origin: &config.public_origin,
            upstream_address: &config.upstream_address,
            upstream_server_name: &config.upstream_server_name,
            upstream_tls: config.upstream_tls,
            listen_port: config.listen_port,
            entry_path: &config.entry_path,
            security_entry: &config.security_entry,
            sensor_enabled: config.sensor_enabled,
            policy_revision: &config.policy_revision,
            status: &config.status,
            policy: &config.policy,
            pre_authorized_by: None,
            config_digest: &[key; 32],
            updated_by: author,
            idempotency_digest: &[key.wrapping_add(100); 32],
            request_digest: &[key.wrapping_add(50); 32],
        })
        .await
}

/// The loop topology survives every place the store keeps it: the current
/// row, the revision history and the normalized route projection, and it can
/// only go live through an independent approver.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn the_browser_loop_topology_round_trips_through_every_store_projection() {
    use sqlx::Row;
    let (store, pool, tenant, site) = session("browser_loop").await;
    let config: SiteConfig = serde_json::from_str(BROWSER_LOOP).unwrap();
    let record = created(
        save_config(&store, &tenant, &site, &config, "loop-author", 1)
            .await
            .unwrap(),
    );
    assert_eq!(record.site_config(), config, "the current row");
    let revision = store
        .read_protected_site_revision_config(&tenant, &site, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revision, config, "the revision history");
    assert_eq!(
        serde_json::to_string_pretty(&revision).unwrap(),
        BROWSER_LOOP.trim_end(),
        "read back in the canonical stored form"
    );

    let routes = sqlx::query(
        "SELECT operation_id, admission, resource_type, source_action, response_config, issued_by
         FROM xshield.site_routes WHERE tenant_id = $1 AND site_id = $2 ORDER BY operation_id",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_all(&pool)
    .await
    .unwrap();
    let row = |id: &str| {
        routes
            .iter()
            .find(|row| row.get::<String, _>("operation_id") == id)
            .unwrap()
    };
    assert_eq!(routes.len(), 6);
    assert_eq!(
        row("auth.login").get::<String, _>("admission"),
        "AUTH_ENTRY"
    );
    assert_eq!(
        row("auth.login").get::<serde_json::Value, _>("response_config")["auth_binding"]["bearer_pointer"],
        "/access_token"
    );
    let page = row("app.page").get::<serde_json::Value, _>("response_config");
    assert_eq!(page["mode"], "SENSOR_HTML");
    assert_eq!(page["injection_offset"], 293);
    assert_eq!(page["page_actions"]["mapping_revision"], "app-map-r1");
    assert_eq!(
        row("orders.list").get::<serde_json::Value, _>("issued_by"),
        json!({"page_operation_id": "app.page", "ttl_seconds": 600})
    );
    assert_eq!(
        row("orders.list").get::<serde_json::Value, _>("response_config")["resource_grant"]["target_operation_id"],
        "orders.read"
    );
    assert_eq!(
        row("orders.read").get::<Option<String>, _>("resource_type"),
        Some("order".to_owned())
    );
    assert_eq!(
        row("auth.logout").get::<serde_json::Value, _>("response_config")["auth_revoke"],
        json!({"success_status": 200})
    );
    assert_eq!(
        row("login.page").get::<Option<serde_json::Value>, _>("response_config"),
        None
    );

    // Going live with the flow names every facet, and those reasons cannot
    // be cleared by the direct-apply capability.
    let state = apply_state(&store, &tenant, &site).await;
    assert!(state.requires_approval);
    assert_eq!(
        state.risk_reasons,
        [
            "ACTIVATION",
            "AUTH_ENTRY_CHANGED",
            "SENSOR_HTML_CHANGED",
            "PAGE_ACTIONS_CHANGED",
            "RESOURCE_GRANT_CHANGED"
        ]
    );
    assert_eq!(
        store
            .authorize_protected_site_direct_apply(
                &tenant,
                &site,
                &format!("approval_{}", Uuid::now_v7()),
                "agent-direct",
                state.desired_revision,
                &state.apply_id,
            )
            .await
            .unwrap(),
        ProtectedSiteDirectApplyOutcome::IndependentApprovalRequired
    );
    assert!(apply_state(&store, &tenant, &site).await.requires_approval);
    let approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.site_apply_approvals WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(approvals, 0, "a refused direct apply records nothing");
    assert!(matches!(
        approve(&store, &tenant, &site, "independent-reviewer", 41, None).await,
        ProtectedSiteApprovalOutcome::Applied { .. }
    ));
    confirm(&store, &tenant, &site).await;
    cleanup(&pool, &tenant).await;
}

/// A write whose route projection fails rolls back as a whole: the current
/// row, the revision history, the apply intent, the port lease and the route
/// projection keep the last committed revision.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_failing_route_projection_rolls_the_whole_write_back() {
    let (store, pool, tenant, site) = session("flow_atomic").await;
    let config: SiteConfig = serde_json::from_str(BROWSER_LOOP).unwrap();
    created(
        save_config(&store, &tenant, &site, &config, "loop-author", 1)
            .await
            .unwrap(),
    );
    let snapshot = |pool: PgPool, tenant: TenantId| async move {
        let mut tables = Vec::new();
        for statement in [
            "SELECT coalesce(json_agg(t ORDER BY t::text), '[]')::jsonb
             FROM xshield.protected_site_configs t WHERE tenant_id = $1",
            "SELECT coalesce(json_agg(t ORDER BY t::text), '[]')::jsonb
             FROM xshield.site_policy_revisions t WHERE tenant_id = $1",
            "SELECT coalesce(json_agg(t ORDER BY t::text), '[]')::jsonb
             FROM xshield.site_apply_intents t WHERE tenant_id = $1",
            "SELECT coalesce(json_agg(t ORDER BY t::text), '[]')::jsonb
             FROM xshield.site_port_leases t WHERE tenant_id = $1",
            "SELECT coalesce(json_agg(t ORDER BY t::text), '[]')::jsonb
             FROM xshield.site_routes t WHERE tenant_id = $1",
        ] {
            tables.push(
                sqlx::query_scalar::<_, serde_json::Value>(statement)
                    .bind(tenant.as_str())
                    .fetch_one(&pool)
                    .await
                    .unwrap(),
            );
        }
        tables
    };
    let before = snapshot(pool.clone(), tenant.clone()).await;
    // The store trusts its caller's validation; a path the normalized table
    // refuses makes the projection insert fail after the configuration row
    // was already written inside the transaction.
    let mut broken = config.clone();
    broken.display_name = "changed".to_owned();
    broken.policy.routes[0].path = "/a?b".to_owned();
    assert!(
        save_config(&store, &tenant, &site, &broken, "loop-author", 2)
            .await
            .is_err()
    );
    assert_eq!(snapshot(pool.clone(), tenant.clone()).await, before);
    cleanup(&pool, &tenant).await;
}

/// Migrations 0052 and 0054 widen the projection to the authentication and
/// share entries and keep every other admission value refused.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn the_route_projection_accepts_auth_and_share_entries_and_nothing_unknown() {
    let (store, pool, tenant, site) = session("flow_admission").await;
    created(save(&store, &tenant, &site, &Draft::new(1)).await);
    let insert = |admission: &'static str, issued_by: Option<serde_json::Value>| {
        sqlx::query(
            "INSERT INTO xshield.site_routes
                 (tenant_id, site_id, operation_id, method, path, admission, issued_by)
             VALUES ($1, $2, $3, 'POST', '/probe', $4, $5)",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(format!("probe.{}", admission.to_ascii_lowercase()))
        .bind(admission)
        .bind(issued_by)
    };
    insert("AUTH_ENTRY", None).execute(&pool).await.unwrap();
    insert("SHARE_ENTRY", None).execute(&pool).await.unwrap();
    assert!(
        insert(
            "SERVICE_IDENTITY",
            Some(json!({"page_operation_id": "p", "ttl_seconds": 1})),
        )
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        insert("UI_ACTION_REQUIRED", Some(json!(["not", "an", "object"])))
            .execute(&pool)
            .await
            .is_err()
    );
    cleanup(&pool, &tenant).await;
}

/// A share scope is stored whole in both authoritative copies, and its
/// projection rows carry the `SHARE_ENTRY` admission and the issuer's
/// `share_issue` as the edge compiles it.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn a_share_scope_round_trips_and_is_projected_to_its_routes() {
    let (store, pool, tenant, site) = session("share_flow").await;
    let config: SiteConfig = serde_json::from_str(SHARE_FLOW).unwrap();
    let record = created(
        save_config(&store, &tenant, &site, &config, "share-author", 1)
            .await
            .unwrap(),
    );
    assert_eq!(
        serde_json::to_string_pretty(&record.site_config()).unwrap(),
        SHARE_FLOW.trim_end()
    );
    let revision = store
        .read_protected_site_revision_config(&tenant, &site, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_string_pretty(&revision).unwrap(),
        SHARE_FLOW.trim_end()
    );
    let admission: String = sqlx::query_scalar(
        "SELECT admission FROM xshield.site_routes
         WHERE tenant_id = $1 AND site_id = $2 AND operation_id = 'records.share.read'",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(admission, "SHARE_ENTRY");
    let response: serde_json::Value = sqlx::query_scalar(
        "SELECT response_config FROM xshield.site_routes
         WHERE tenant_id = $1 AND site_id = $2 AND operation_id = 'records.share.issue'",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        response["share_issue"]["issuance_rule_id"],
        "record-share-r1"
    );
    cleanup(&pool, &tenant).await;
}

/// A configuration written before the flow fields reads back from both stored
/// forms to the same bytes, so its digest and "same content" comparisons hold.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn configurations_written_before_the_flow_fields_read_back_byte_identical() {
    let (store, pool, tenant, site) = session("pre_flow").await;
    let config: SiteConfig = serde_json::from_str(PRE_FLOW).unwrap();
    let record = created(
        save_config(&store, &tenant, &site, &config, "legacy-author", 1)
            .await
            .unwrap(),
    );
    assert_eq!(
        serde_json::to_string(&record.site_config()).unwrap(),
        PRE_FLOW.trim_end()
    );
    let revision = store
        .read_protected_site_revision_config(&tenant, &site, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_string(&revision).unwrap(),
        PRE_FLOW.trim_end()
    );
    // Its route projection keeps the response shape without flow members.
    let response: serde_json::Value = sqlx::query_scalar(
        "SELECT response_config FROM xshield.site_routes
         WHERE tenant_id = $1 AND site_id = $2 AND operation_id = 'pay'",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        response.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["crypto", "max_bytes", "mode"]
    );
    cleanup(&pool, &tenant).await;
}

async fn cleanup(pool: &PgPool, tenant: &TenantId) {
    for statement in [
        "DELETE FROM xshield.protected_site_configs WHERE tenant_id = $1",
        "DELETE FROM xshield.protected_sites WHERE tenant_id = $1",
        "DELETE FROM xshield.site_port_leases WHERE tenant_id = $1",
        "DELETE FROM xshield.site_snapshot_sequences WHERE tenant_id = $1",
        // Label bindings outlive a deleted site by design (migration 0053).
        "DELETE FROM xshield.site_descriptor_bindings WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(tenant.as_str())
            .execute(pool)
            .await
            .unwrap();
    }
}
