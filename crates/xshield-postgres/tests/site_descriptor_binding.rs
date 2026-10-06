//! A site's `policy_revision` label names one action-descriptor set, as
//! recorded in `site_descriptor_bindings` (migration 0053) and checked by the
//! site store against a real `PostgreSQL`.
//!
//! The edge refuses a second set under a label it has bound, for the whole
//! tenant snapshot; these tests pin which revisions bind a label on the control
//! side (exactly those that became eligible to reach the edge), that every
//! save, approval and snapshot read checks it under the tenant lock, and that
//! the edge's own `policy_revisions` rows count too.

use sqlx::{PgPool, Row};
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::{
    SiteConfig,
    domain::{SiteId, TenantId},
    site::{DescriptorDigest, LabelReuse},
};
use xshield_postgres::{
    PostgresIdentityStore, ProtectedSiteApprovalOutcome, ProtectedSiteConfigUpsert,
    ProtectedSiteConfigWriteOutcome, ProtectedSiteDirectApplyOutcome,
};

/// The real-browser loop topology as the control plane stores it.
const BROWSER_LOOP: &str = include_str!("../../../tests/site-config/browser-loop.json");

const AUTHOR: &str = "loop-author";
const REVIEWER: &str = "independent-reviewer";

/// The loop under `label`, on an allocated port so several sites fit one
/// tenant.
fn loop_config(label: &str) -> SiteConfig {
    let mut config: SiteConfig = serde_json::from_str(BROWSER_LOOP).unwrap();
    config.listen_port = 0;
    label.clone_into(&mut config.policy_revision);
    config
}

/// The loop with its page-issued list action moved: another descriptor set.
fn moved_config(label: &str) -> SiteConfig {
    let mut config = loop_config(label);
    for route in &mut config.policy.routes {
        if route.operation_id == "orders.list" {
            "/orders-all".clone_into(&mut route.path);
        }
    }
    config
}

/// The loop without page issuance: no edge-managed descriptors at all.
fn plain_config(label: &str) -> SiteConfig {
    let mut config = loop_config(label);
    for route in &mut config.policy.routes {
        route.page_actions = None;
        route.issued_by = None;
    }
    config
}

fn digest_of(config: &SiteConfig) -> DescriptorDigest {
    config.edge_descriptor_digest().unwrap().unwrap()
}

/// 32 bytes derived from a per-write seed, so every write has its own
/// idempotency identity.
fn seeded(seed: u32, salt: u8) -> [u8; 32] {
    let mut bytes = [salt; 32];
    bytes[..4].copy_from_slice(&seed.to_be_bytes());
    bytes
}

async fn save(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    config: &SiteConfig,
    seed: u32,
) -> ProtectedSiteConfigWriteOutcome {
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
            config_digest: &seeded(seed, 1),
            updated_by: AUTHOR,
            idempotency_digest: &seeded(seed, 2),
            request_digest: &seeded(seed, 3),
        })
        .await
        .unwrap()
}

/// Saves `config` and returns the new revision; panics on any refusal.
async fn saved(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    config: &SiteConfig,
    seed: u32,
) -> u64 {
    match save(store, tenant, site, config, seed).await {
        ProtectedSiteConfigWriteOutcome::Created(record)
        | ProtectedSiteConfigWriteOutcome::Updated(record) => record.revision(),
        other => panic!("expected the write to be stored, got {other:?}"),
    }
}

async fn approve(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    seed: u32,
) -> ProtectedSiteApprovalOutcome {
    store
        .approve_protected_site_apply(
            tenant,
            site,
            &format!("approval_{}", Uuid::now_v7()),
            REVIEWER,
            &seeded(seed, 4),
            None,
        )
        .await
        .unwrap()
}

/// Saves, approves (when needed) and marks the revision active, the way a
/// confirmed edge snapshot does.
async fn go_live(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    config: &SiteConfig,
    seed: u32,
) -> u64 {
    let revision = saved(store, tenant, site, config, seed).await;
    let state = apply_state(store, tenant, site).await;
    if state.requires_approval {
        assert!(
            matches!(
                approve(store, tenant, site, seed).await,
                ProtectedSiteApprovalOutcome::Applied { .. }
            ),
            "the approval must apply"
        );
    }
    confirm(store, tenant, site).await;
    revision
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

async fn confirm(store: &PostgresIdentityStore, tenant: &TenantId, site: &SiteId) {
    let state = apply_state(store, tenant, site).await;
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

/// `(label, digest, bound_revision, bound_by)` of every binding of `site`.
async fn bindings(
    pool: &PgPool,
    tenant: &TenantId,
    site: &SiteId,
) -> Vec<(String, Vec<u8>, i64, String)> {
    sqlx::query(
        "SELECT policy_revision, descriptor_digest, bound_revision, bound_by
         FROM xshield.site_descriptor_bindings
         WHERE tenant_id = $1 AND site_id = $2 ORDER BY policy_revision",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_all(pool)
    .await
    .unwrap()
    .iter()
    .map(|row| {
        (
            row.get("policy_revision"),
            row.get("descriptor_digest"),
            row.get("bound_revision"),
            row.get("bound_by"),
        )
    })
    .collect()
}

/// Writes the edge's own policy-revision row, as the edge's supply (or a
/// seed, or an operator retiring it) leaves it.
async fn edge_row(
    pool: &PgPool,
    tenant: &TenantId,
    site: &SiteId,
    label: &str,
    status: &str,
    digest: &str,
) {
    sqlx::query(
        "INSERT INTO xshield.policy_revisions
             (tenant_id, site_id, revision, status, content_digest, artifact_ref)
         VALUES ($1, $2, $3, $4, $5, 'test.seed')
         ON CONFLICT (tenant_id, site_id, revision)
         DO UPDATE SET status = EXCLUDED.status, content_digest = EXCLUDED.content_digest",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(label)
    .bind(status)
    .bind(digest)
    .execute(pool)
    .await
    .unwrap();
}

/// Forgets every control-plane binding and edge row of `site`, the state an
/// older control service (which neither checked nor recorded bindings) leaves.
async fn forget_bindings(pool: &PgPool, tenant: &TenantId, site: &SiteId) {
    for statement in [
        "DELETE FROM xshield.site_descriptor_bindings WHERE tenant_id = $1 AND site_id = $2",
        "DELETE FROM xshield.policy_revisions WHERE tenant_id = $1 AND site_id = $2",
    ] {
        sqlx::query(statement)
            .bind(tenant.as_str())
            .bind(site.as_str())
            .execute(pool)
            .await
            .unwrap();
    }
}

async fn session(prefix: &str) -> (PostgresIdentityStore, PgPool, TenantId) {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let store = PostgresIdentityStore::connect(&database_url, 8, Duration::from_secs(5))
        .await
        .unwrap();
    let pool = PgPool::connect(&database_url).await.unwrap();
    let tenant = TenantId::parse(format!("tenant_{prefix}_{}", Uuid::now_v7())).unwrap();
    (store, pool, tenant)
}

async fn cleanup(pool: &PgPool, tenant: &TenantId) {
    for statement in [
        "DELETE FROM xshield.protected_site_configs WHERE tenant_id = $1",
        "DELETE FROM xshield.protected_sites WHERE tenant_id = $1",
        "DELETE FROM xshield.site_port_leases WHERE tenant_id = $1",
        "DELETE FROM xshield.site_snapshot_sequences WHERE tenant_id = $1",
        "DELETE FROM xshield.site_descriptor_bindings WHERE tenant_id = $1",
        "DELETE FROM xshield.policy_revisions WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(tenant.as_str())
            .execute(pool)
            .await
            .unwrap();
    }
}

fn site(name: &str) -> SiteId {
    SiteId::parse(name).unwrap()
}

/// Every branch of the rule over one site's history: a revision that never
/// became eligible binds nothing, an approval binds, a reuse is refused, a new
/// label and a rollback to an identical earlier set are accepted, a plain
/// configuration and a takedown are never refused, and the edge's own rows
/// count.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn a_label_names_one_descriptor_set_once_a_revision_under_it_may_reach_the_edge() {
    let (store, pool, tenant) = session("label_binding").await;
    let site = site("site_label_binding");
    let (original, moved) = (digest_of(&loop_config("x")), digest_of(&moved_config("x")));
    assert_ne!(original, moved);

    // Going live needs approval, so revision 1 is never eligible and binds
    // nothing: a later revision may reuse its label for another set.
    assert_eq!(
        saved(&store, &tenant, &site, &loop_config("loop-r1"), 1).await,
        1
    );
    assert!(apply_state(&store, &tenant, &site).await.requires_approval);
    assert!(bindings(&pool, &tenant, &site).await.is_empty());
    assert_eq!(
        saved(&store, &tenant, &site, &moved_config("loop-r1"), 2).await,
        2
    );
    assert!(bindings(&pool, &tenant, &site).await.is_empty());

    // The approval makes revision 2 eligible and binds its label.
    assert!(matches!(
        approve(&store, &tenant, &site, 2).await,
        ProtectedSiteApprovalOutcome::Applied { .. }
    ));
    confirm(&store, &tenant, &site).await;
    assert_eq!(
        bindings(&pool, &tenant, &site).await,
        [(
            "loop-r1".to_owned(),
            moved.as_bytes().to_vec(),
            2,
            "approval".to_owned()
        )]
    );

    // The same label for the original set is refused before anything is
    // written.
    assert_eq!(
        save(&store, &tenant, &site, &loop_config("loop-r1"), 3).await,
        ProtectedSiteConfigWriteOutcome::PolicyRevisionReused(LabelReuse::OtherDescriptors)
    );
    assert_eq!(
        apply_state(&store, &tenant, &site).await.desired_revision,
        2
    );

    // A new label is free; it binds once its revision is approved.
    let revision = go_live(&store, &tenant, &site, &loop_config("loop-r2"), 4).await;
    assert_eq!(revision, 3, "the refused write created no revision");

    // The same label and the same set: a cosmetic edit needs no approval and
    // keeps the binding as it was first recorded.
    let mut renamed = loop_config("loop-r2");
    renamed.display_name = "Renamed loop".to_owned();
    assert_eq!(saved(&store, &tenant, &site, &renamed, 5).await, 4);
    assert!(!apply_state(&store, &tenant, &site).await.requires_approval);

    // Restoring the earlier set under the label it was bound to is a
    // rollback the edge answers with `Existing`.
    go_live(&store, &tenant, &site, &moved_config("loop-r1"), 6).await;
    assert_eq!(
        bindings(&pool, &tenant, &site).await,
        [
            (
                "loop-r1".to_owned(),
                moved.as_bytes().to_vec(),
                2,
                "approval".to_owned()
            ),
            (
                "loop-r2".to_owned(),
                original.as_bytes().to_vec(),
                3,
                "approval".to_owned()
            ),
        ]
    );

    // Without page issuance there is no digest, so no label is ever refused.
    saved(&store, &tenant, &site, &plain_config("loop-r2"), 7).await;
    // A takedown (draft or pause) is never supplied, so it is never refused
    // either, even under a label bound to another set.
    let mut paused = loop_config("loop-r1");
    paused.status = "paused".to_owned();
    saved(&store, &tenant, &site, &paused, 8).await;
    let mut draft = loop_config("loop-r1");
    draft.status = "draft".to_owned();
    saved(&store, &tenant, &site, &draft, 9).await;

    // The edge's own rows: another digest, a retired label, the same digest.
    edge_row(&pool, &tenant, &site, "loop-r3", "active", &"e".repeat(64)).await;
    assert_eq!(
        save(&store, &tenant, &site, &loop_config("loop-r3"), 10).await,
        ProtectedSiteConfigWriteOutcome::PolicyRevisionReused(LabelReuse::OtherDescriptors)
    );
    edge_row(
        &pool,
        &tenant,
        &site,
        "loop-r4",
        "retired",
        &original.to_hex(),
    )
    .await;
    assert_eq!(
        save(&store, &tenant, &site, &loop_config("loop-r4"), 11).await,
        ProtectedSiteConfigWriteOutcome::PolicyRevisionReused(LabelReuse::InactiveAtEdge)
    );
    edge_row(
        &pool,
        &tenant,
        &site,
        "loop-r5",
        "active",
        &original.to_hex(),
    )
    .await;
    saved(&store, &tenant, &site, &loop_config("loop-r5"), 12).await;

    // The read-only check the validate endpoint uses agrees, and binds nothing.
    let check = |config: SiteConfig| {
        let (store, tenant, site) = (&store, &tenant, &site);
        async move {
            store
                .check_protected_site_label(tenant, site, &config)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        check(loop_config("loop-r1")).await,
        Some(LabelReuse::OtherDescriptors)
    );
    assert_eq!(check(moved_config("loop-r1")).await, None);
    assert_eq!(
        check(loop_config("loop-r4")).await,
        Some(LabelReuse::InactiveAtEdge)
    );
    assert_eq!(check(plain_config("loop-r1")).await, None);
    assert_eq!(check(loop_config("loop-r6")).await, None);
    assert_eq!(bindings(&pool, &tenant, &site).await.len(), 2);
    cleanup(&pool, &tenant).await;
}

/// The edge keeps its rows when a site is deleted, so the control plane does
/// too: a site recreated under the same ID cannot reuse a label for another
/// set.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn bindings_outlive_the_site_they_were_made_for() {
    let (store, pool, tenant) = session("label_delete").await;
    let site = site("site_label_delete");
    go_live(&store, &tenant, &site, &loop_config("loop-r1"), 1).await;
    assert!(
        store
            .delete_protected_site_config(&tenant, &site)
            .await
            .unwrap()
    );
    assert_eq!(bindings(&pool, &tenant, &site).await.len(), 1);
    assert_eq!(
        save(&store, &tenant, &site, &moved_config("loop-r1"), 2).await,
        ProtectedSiteConfigWriteOutcome::PolicyRevisionReused(LabelReuse::OtherDescriptors)
    );
    assert!(matches!(
        save(&store, &tenant, &site, &moved_config("loop-r2"), 3).await,
        ProtectedSiteConfigWriteOutcome::Created(_)
    ));
    cleanup(&pool, &tenant).await;
}

/// Two connections race to give one new label two descriptor sets, in the
/// two shapes the API allows: an eligible save against a save held for
/// approval, and an approval against an eligible save. Whatever the order the
/// tenant lock picks, the label ends up bound to exactly one set, the set of
/// the revision that became eligible, and a racer that would have bound a
/// second set is refused.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn two_connections_racing_for_one_new_label_never_bind_two_sets() {
    let (first, pool, tenant) = session("label_race").await;
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let second = PostgresIdentityStore::connect(&database_url, 8, Duration::from_secs(5))
        .await
        .unwrap();
    let site = site("site_label_race");
    go_live(&first, &tenant, &site, &loop_config("loop-r1"), 1).await;
    let original = digest_of(&loop_config("x"));
    let mut orders = (0_usize, 0_usize);

    for round in 0..8_u32 {
        let seed = 100 + round * 10;
        let label = format!("race-a{round}");
        // The same set as the served revision under a new label needs no
        // approval, so it is eligible and binds; the moved set needs approval.
        let mut eligible = loop_config(&label);
        eligible.display_name = format!("Race {round}");
        let held = moved_config(&label);
        let (eligible_outcome, held_outcome) = tokio::join!(
            save(&first, &tenant, &site, &eligible, seed),
            save(&second, &tenant, &site, &held, seed + 1),
        );
        let eligible_revision = match eligible_outcome {
            ProtectedSiteConfigWriteOutcome::Updated(record) => record.revision(),
            other => panic!("the eligible save always lands, got {other:?}"),
        };
        match held_outcome {
            // The held save came first: it never became eligible, was
            // superseded by the eligible one, and bound nothing.
            ProtectedSiteConfigWriteOutcome::Updated(record) => {
                assert!(record.revision() < eligible_revision, "round {round}");
                orders.0 += 1;
            }
            ProtectedSiteConfigWriteOutcome::PolicyRevisionReused(LabelReuse::OtherDescriptors) => {
                orders.1 += 1;
            }
            other => panic!("round {round}: unexpected {other:?}"),
        }
        let state = apply_state(&first, &tenant, &site).await;
        assert_eq!(state.desired_revision, eligible_revision, "round {round}");
        let bound = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT descriptor_digest FROM xshield.site_descriptor_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND policy_revision = $3",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(&label)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(bound, [original.as_bytes().to_vec()], "round {round}");
    }

    for round in 0..8_u32 {
        let seed = 300 + round * 10;
        let label = format!("race-b{round}");
        // A moved set under a new label, held for approval and not bound...
        saved(&first, &tenant, &site, &moved_config(&label), seed).await;
        assert!(apply_state(&first, &tenant, &site).await.requires_approval);
        // ...raced by its approval and an eligible save of the served set
        // under the same label.
        let mut eligible = loop_config(&label);
        eligible.display_name = format!("Race b{round}");
        let (approval, eligible_outcome) = tokio::join!(
            approve(&first, &tenant, &site, seed),
            save(&second, &tenant, &site, &eligible, seed + 1),
        );
        let bound = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT descriptor_digest FROM xshield.site_descriptor_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND policy_revision = $3",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(&label)
        .fetch_all(&pool)
        .await
        .unwrap();
        match (approval, eligible_outcome) {
            // The approval came first and bound the moved set.
            (
                ProtectedSiteApprovalOutcome::Applied { .. },
                ProtectedSiteConfigWriteOutcome::PolicyRevisionReused(LabelReuse::OtherDescriptors),
            ) => {
                assert_eq!(bound, [digest_of(&moved_config("x")).as_bytes().to_vec()]);
                orders.1 += 1;
            }
            // The eligible save came first and bound the served set; the
            // approval then found nothing left to approve.
            (
                ProtectedSiteApprovalOutcome::NotRequired,
                ProtectedSiteConfigWriteOutcome::Updated(_),
            ) => {
                assert_eq!(bound, [original.as_bytes().to_vec()]);
                orders.0 += 1;
            }
            other => panic!("round {round}: unexpected {other:?}"),
        }
        // Back to the served revision for the next round.
        go_live(&first, &tenant, &site, &loop_config("loop-r1"), seed + 5).await;
    }
    // Either order is legal; the assertions above hold for both.
    assert_eq!(orders.0 + orders.1, 16);
    cleanup(&pool, &tenant).await;
}

/// Revisions written without the rule (by an older control service, or
/// before migration 0053) are caught where they would reach the edge: the
/// approval refuses a reused label and records nothing, and the snapshot
/// read marks an eligible one for the plan to hold back, binding labels that
/// are merely unrecorded.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn approvals_and_snapshots_recheck_revisions_written_without_the_rule() {
    let (store, pool, tenant) = session("label_legacy").await;
    let original = digest_of(&loop_config("x"));
    let (pending, eligible, unrecorded) = (
        site("site_legacy_pending"),
        site("site_legacy_eligible"),
        site("site_legacy_unrecorded"),
    );

    // A site the edge serves under loop-r1, then an older service saved the
    // moved set under the same label, held for approval.
    go_live(&store, &tenant, &pending, &loop_config("loop-r1"), 1).await;
    forget_bindings(&pool, &tenant, &pending).await;
    saved(&store, &tenant, &pending, &moved_config("loop-r1"), 2).await;
    edge_row(
        &pool,
        &tenant,
        &pending,
        "loop-r1",
        "active",
        &original.to_hex(),
    )
    .await;
    assert_eq!(
        store
            .check_protected_site_label(&tenant, &pending, &moved_config("loop-r1"))
            .await
            .unwrap(),
        Some(LabelReuse::OtherDescriptors)
    );
    assert_eq!(
        approve(&store, &tenant, &pending, 2).await,
        ProtectedSiteApprovalOutcome::PolicyRevisionReused(LabelReuse::OtherDescriptors)
    );
    let state = apply_state(&store, &tenant, &pending).await;
    assert!(state.requires_approval, "the requirement stands");
    let approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.site_apply_approvals
         WHERE tenant_id = $1 AND site_id = $2 AND desired_revision = 2",
    )
    .bind(tenant.as_str())
    .bind(pending.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(approvals, 0, "a refused approval records nothing");
    // The direct-apply capability cannot clear a flow change at all.
    assert_eq!(
        store
            .authorize_protected_site_direct_apply(
                &tenant,
                &pending,
                &format!("approval_{}", Uuid::now_v7()),
                "agent-direct",
                state.desired_revision,
                &state.apply_id,
            )
            .await
            .unwrap(),
        ProtectedSiteDirectApplyOutcome::IndependentApprovalRequired
    );

    // A site whose moved set an older service approved under the label the
    // edge already binds to the original set: eligible, and reused.
    go_live(&store, &tenant, &eligible, &loop_config("loop-r1"), 11).await;
    forget_bindings(&pool, &tenant, &eligible).await;
    saved(&store, &tenant, &eligible, &moved_config("loop-r1"), 12).await;
    assert!(matches!(
        approve(&store, &tenant, &eligible, 12).await,
        ProtectedSiteApprovalOutcome::Applied { .. }
    ));
    forget_bindings(&pool, &tenant, &eligible).await;
    edge_row(
        &pool,
        &tenant,
        &eligible,
        "loop-r1",
        "active",
        &original.to_hex(),
    )
    .await;

    // A site live before migration 0053: eligible, consistent, unrecorded.
    go_live(&store, &tenant, &unrecorded, &loop_config("loop-u1"), 21).await;
    forget_bindings(&pool, &tenant, &unrecorded).await;

    let snapshot = store.begin_protected_site_snapshot(&tenant).await.unwrap();
    let conflict = |id: &SiteId| {
        snapshot
            .sites
            .iter()
            .find(|entry| entry.site_id == *id)
            .unwrap()
            .label_conflict
    };
    assert_eq!(
        conflict(&pending),
        None,
        "awaiting approval: its approval decides"
    );
    assert_eq!(conflict(&eligible), Some(LabelReuse::OtherDescriptors));
    assert_eq!(conflict(&unrecorded), None);
    assert!(
        bindings(&pool, &tenant, &eligible).await.is_empty(),
        "a reused label is never bound"
    );
    assert_eq!(
        bindings(&pool, &tenant, &unrecorded).await,
        [(
            "loop-u1".to_owned(),
            original.as_bytes().to_vec(),
            1,
            "snapshot".to_owned()
        )]
    );
    // A second read finds the binding in place and decides the same way.
    let again = store.begin_protected_site_snapshot(&tenant).await.unwrap();
    assert!(again.revision > snapshot.revision);
    assert_eq!(bindings(&pool, &tenant, &unrecorded).await.len(), 1);
    cleanup(&pool, &tenant).await;
}
