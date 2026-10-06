//! `share_issuance_rules` rows written by the site configuration store: only
//! when a revision becomes eligible to reach the edge, only from the typed
//! `share_issue` block, never rewritten, and accepted by the very lookup the
//! edge performs when it issues a share.

use serde_json::json;
use sqlx::PgPool;
use std::{collections::BTreeMap, env, time::Duration};
use uuid::Uuid;
use xshield_core::{
    SiteConfig,
    access::{ShareGrantDraft, ShareIssueAuthority, ShareTokenFingerprint},
    domain::{
        AuthBindingId, EventId, GrantId, IssuanceKey, OperationId, PolicyRevision, ResourceType,
        ShareGrantId, ShareIssuanceRuleId, SiteId, TenantId, ViewProfile, WafSessionId,
    },
    grant::ResourceKeyHmac,
    identity::{
        AuthBinding, AuthEpoch, AuthSnapshot, AuthorizationContextRef, CredentialFingerprint,
        CredentialGeneration, CredentialSlot, UnixSeconds,
    },
};
use xshield_postgres::{
    PostgresIdentityStore, ProtectedSiteApprovalOutcome, ProtectedSiteConfigUpsert,
    ProtectedSiteConfigWriteOutcome, ProtectedSiteDirectApplyOutcome, ShareGrantPersistence,
    ShareGrantWriteOutcome,
};

const SHARE_FLOW: &str = include_str!("../../../tests/site-config/share-flow.json");
const BROWSER_LOOP: &str = include_str!("../../../tests/site-config/browser-loop.json");

type Rule = (String, String, String, String, String, String, i64, String);

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

fn share_flow() -> SiteConfig {
    serde_json::from_str(SHARE_FLOW).unwrap()
}

/// Saves `config` as `site`; `key` distinguishes writes.
async fn save(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    config: &SiteConfig,
    key: u8,
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
            config_digest: &[key; 32],
            updated_by: "share-author",
            idempotency_digest: &[key.wrapping_add(100); 32],
            request_digest: &[key.wrapping_add(50); 32],
        })
        .await
        .unwrap()
}

async fn approve(store: &PostgresIdentityStore, tenant: &TenantId, site: &SiteId, key: u8) {
    let outcome = store
        .approve_protected_site_apply(
            tenant,
            site,
            &format!("approval_{}", Uuid::now_v7()),
            "independent-approver",
            &[key; 32],
            None,
        )
        .await
        .unwrap();
    assert!(
        matches!(outcome, ProtectedSiteApprovalOutcome::Applied { .. }),
        "{outcome:?}"
    );
}

async fn rules(pool: &PgPool, tenant: &TenantId, site: &SiteId) -> Vec<Rule> {
    sqlx::query_as(
        "SELECT policy_revision, rule_id, issuer_operation_id, issuer_view_id,
                share_operation_id, share_view_id, max_ttl_seconds, status
         FROM xshield.share_issuance_rules
         WHERE tenant_id = $1 AND site_id = $2
         ORDER BY policy_revision, rule_id",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_all(pool)
    .await
    .unwrap()
}

fn rule(label: &str, id: &str, ttl: i64) -> Rule {
    (
        label.to_owned(),
        id.to_owned(),
        "records.share.issue".to_owned(),
        "share_controls".to_owned(),
        "records.share.read".to_owned(),
        "shared_summary".to_owned(),
        ttl,
        "active".to_owned(),
    )
}

async fn cleanup(pool: &PgPool, tenant: &TenantId) {
    // Rows the edge relies on outlive a site by design, so they are removed
    // explicitly, children first.
    for statement in [
        "DELETE FROM xshield.share_grants WHERE tenant_id = $1",
        "DELETE FROM xshield.resource_grants WHERE tenant_id = $1",
        "DELETE FROM xshield.ui_actions WHERE tenant_id = $1",
        "DELETE FROM xshield.page_evidence WHERE tenant_id = $1",
        "DELETE FROM xshield.action_descriptors WHERE tenant_id = $1",
        "DELETE FROM xshield.auth_bindings WHERE tenant_id = $1",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id = $1",
        "DELETE FROM xshield.share_issuance_rules WHERE tenant_id = $1",
        "DELETE FROM xshield.policy_revisions WHERE tenant_id = $1",
        "DELETE FROM xshield.protected_site_configs WHERE tenant_id = $1",
        "DELETE FROM xshield.protected_sites WHERE tenant_id = $1",
        "DELETE FROM xshield.site_port_leases WHERE tenant_id = $1",
        "DELETE FROM xshield.site_snapshot_sequences WHERE tenant_id = $1",
        "DELETE FROM xshield.site_descriptor_bindings WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(tenant.as_str())
            .execute(pool)
            .await
            .unwrap();
    }
}

/// Rows appear exactly when approval makes the revision eligible, are exactly
/// what the block derives, and repeating the approval or the apply adds none.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // one scenario: approval, replay and apply in order
async fn rows_are_written_by_the_approval_that_covers_the_block_and_only_once() {
    let (store, pool, tenant, site) = session("rules_once").await;
    let config = share_flow();
    assert!(matches!(
        save(&store, &tenant, &site, &config, 1).await,
        ProtectedSiteConfigWriteOutcome::Created(_)
    ));
    // Held for approval: nothing exists that the approver has not approved.
    assert_eq!(
        rules(&pool, &tenant, &site).await,
        [] as [(
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            i64,
            std::string::String
        ); 0]
    );
    let policy_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM xshield.policy_revisions WHERE tenant_id = $1")
            .bind(tenant.as_str())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(policy_rows, 0);

    // The capability that replaces a second pair of eyes elsewhere cannot
    // release a share issuance change, so it creates no rows either.
    let state = store
        .read_protected_site_apply_state(&tenant, &site)
        .await
        .unwrap()
        .unwrap();
    assert!(
        state
            .risk_reasons
            .iter()
            .any(|reason| reason == "SHARE_ISSUE_CHANGED")
    );
    assert_eq!(
        store
            .authorize_protected_site_direct_apply(
                &tenant,
                &site,
                &format!("approval_{}", Uuid::now_v7()),
                "direct-applier",
                state.desired_revision,
                &state.apply_id,
            )
            .await
            .unwrap(),
        ProtectedSiteDirectApplyOutcome::IndependentApprovalRequired
    );
    assert_eq!(
        rules(&pool, &tenant, &site).await,
        [] as [(
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            i64,
            std::string::String
        ); 0]
    );

    approve(&store, &tenant, &site, 41).await;
    let expected = vec![rule("share-r1", "record-share-r1", 300)];
    assert_eq!(rules(&pool, &tenant, &site).await, expected);
    // The row hangs on the label's policy revision, bound to the digest the
    // edge derives for the configuration (so its own supply finds it equal).
    let (status, digest): (String, String) = sqlx::query_as(
        "SELECT status, content_digest FROM xshield.policy_revisions
         WHERE tenant_id = $1 AND site_id = $2 AND revision = 'share-r1'",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "active");
    assert_eq!(
        digest,
        config.edge_descriptor_digest().unwrap().unwrap().to_hex()
    );

    // Replays: the same approval key, an identical save under a new key, and
    // the snapshot read that carries it all leave exactly the same rows.
    let replay = store
        .approve_protected_site_apply(
            &tenant,
            &site,
            &format!("approval_{}", Uuid::now_v7()),
            "independent-approver",
            &[41; 32],
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        replay,
        ProtectedSiteApprovalOutcome::Existing { .. }
    ));
    assert_eq!(rules(&pool, &tenant, &site).await, expected);
    assert!(matches!(
        save(&store, &tenant, &site, &config, 2).await,
        ProtectedSiteConfigWriteOutcome::Updated(_)
    ));
    // Identical to what is active: no approval is needed, the rows already
    // exist and are accepted as they are.
    assert_eq!(rules(&pool, &tenant, &site).await, expected);
    let snapshot = store.begin_protected_site_snapshot(&tenant).await.unwrap();
    assert!(!snapshot.sites[0].share_rule_conflict);
    assert_eq!(rules(&pool, &tenant, &site).await, expected);
    cleanup(&pool, &tenant).await;
}

/// A new revision adds rows and never touches the old ones; a rule that
/// exists differently is refused (rows are immutable); a rollback to an
/// older revision finds its rows still there.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn new_revisions_add_rows_and_never_touch_old_ones_even_across_a_rollback() {
    let (store, pool, tenant, site) = session("rules_history").await;
    let first = share_flow();
    save(&store, &tenant, &site, &first, 1).await;
    approve(&store, &tenant, &site, 41).await;
    let before = rules(&pool, &tenant, &site).await;
    assert_eq!(before, vec![rule("share-r1", "record-share-r1", 300)]);

    // Same label, same rule id, another ceiling: refused at save time and
    // nothing is stored (the desired revision stays 1).
    let mut retuned = share_flow();
    retuned
        .policy
        .routes
        .iter_mut()
        .find_map(|route| route.share_issue.as_mut())
        .unwrap()
        .ttl_seconds = 600;
    assert_eq!(
        save(&store, &tenant, &site, &retuned, 2).await,
        ProtectedSiteConfigWriteOutcome::ShareRuleConflict
    );
    assert_eq!(
        store
            .read_protected_site_apply_state(&tenant, &site)
            .await
            .unwrap()
            .unwrap()
            .desired_revision,
        1
    );
    assert_eq!(rules(&pool, &tenant, &site).await, before);

    // The same retune under a new rule id is a new revision held for
    // approval: still no row for it until the approver clears it.
    retuned
        .policy
        .routes
        .iter_mut()
        .find_map(|route| route.share_issue.as_mut())
        .unwrap()
        .issuance_rule_id = "record-share-r2".to_owned();
    assert!(matches!(
        save(&store, &tenant, &site, &retuned, 3).await,
        ProtectedSiteConfigWriteOutcome::Updated(_)
    ));
    assert_eq!(rules(&pool, &tenant, &site).await, before);
    approve(&store, &tenant, &site, 42).await;
    let after = rules(&pool, &tenant, &site).await;
    assert_eq!(
        after,
        vec![
            rule("share-r1", "record-share-r1", 300),
            rule("share-r1", "record-share-r2", 600),
        ]
    );
    assert_eq!(after[0], before[0], "the old row is untouched");

    // Rolling back means saving the older content again as a new revision:
    // its row is still there, equal, and nothing is added or changed.
    assert!(matches!(
        save(&store, &tenant, &site, &first, 4).await,
        ProtectedSiteConfigWriteOutcome::Updated(_)
    ));
    approve(&store, &tenant, &site, 43).await;
    assert_eq!(rules(&pool, &tenant, &site).await, after);

    // An operator retired the old rule: the control plane never reactivates
    // it, so the older content cannot be saved again under that rule id.
    sqlx::query(
        "UPDATE xshield.share_issuance_rules SET status = 'retired'
         WHERE tenant_id = $1 AND site_id = $2 AND rule_id = 'record-share-r1'",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        save(&store, &tenant, &site, &first, 5).await,
        ProtectedSiteConfigWriteOutcome::ShareRuleConflict
    );
    assert_eq!(rules(&pool, &tenant, &site).await[0].7, "retired");

    // A new label gets its own rows, and the superseded label keeps its own.
    let mut relabelled = share_flow();
    relabelled.policy_revision = "share-r9".to_owned();
    assert!(matches!(
        save(&store, &tenant, &site, &relabelled, 6).await,
        ProtectedSiteConfigWriteOutcome::Updated(_)
    ));
    approve(&store, &tenant, &site, 44).await;
    let relabelled_rules = rules(&pool, &tenant, &site).await;
    assert_eq!(relabelled_rules.len(), 3);
    assert_eq!(
        relabelled_rules[2],
        rule("share-r9", "record-share-r1", 300)
    );
    cleanup(&pool, &tenant).await;
}

/// A revision without `share_issue` writes nothing, and rows never cross a
/// tenant or a site even under identical labels and rule ids.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn rows_are_scoped_and_only_a_share_issue_block_produces_them() {
    let (store, pool, tenant, site) = session("rules_scope").await;
    let other_site = SiteId::parse("site_rules_scope_other").unwrap();
    let plain_site = SiteId::parse("site_rules_scope_plain").unwrap();
    let mut other = share_flow();
    other.listen_port = 0;

    save(&store, &tenant, &site, &share_flow(), 1).await;
    approve(&store, &tenant, &site, 41).await;
    save(&store, &tenant, &other_site, &other, 2).await;
    approve(&store, &tenant, &other_site, 42).await;
    let mut plain: SiteConfig = serde_json::from_str(BROWSER_LOOP).unwrap();
    plain.listen_port = 0;
    save(&store, &tenant, &plain_site, &plain, 3).await;
    approve(&store, &tenant, &plain_site, 43).await;
    assert_eq!(
        rules(&pool, &tenant, &site).await,
        vec![rule("share-r1", "record-share-r1", 300)]
    );
    assert_eq!(
        rules(&pool, &tenant, &other_site).await,
        vec![rule("share-r1", "record-share-r1", 300)]
    );
    assert_eq!(
        rules(&pool, &tenant, &plain_site).await,
        [] as [(
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            i64,
            std::string::String
        ); 0]
    );

    // A second tenant with the same site id, label and rule id.
    let other_tenant = TenantId::parse(format!("tenant_rules_scope_{}", Uuid::now_v7())).unwrap();
    save(&store, &other_tenant, &site, &share_flow(), 1).await;
    assert_eq!(
        rules(&pool, &other_tenant, &site).await,
        [] as [(
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
            i64,
            std::string::String
        ); 0]
    );
    approve(&store, &other_tenant, &site, 41).await;
    assert_eq!(rules(&pool, &other_tenant, &site).await.len(), 1);
    assert_eq!(rules(&pool, &tenant, &site).await.len(), 1);
    cleanup(&pool, &tenant).await;
    cleanup(&pool, &other_tenant).await;
}

/// The snapshot read is the backstop for a revision written without rows (an
/// older control service): it writes them under the tenant lock, and holds the
/// site back when a row it needs exists differently.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn the_snapshot_read_materializes_missing_rows_and_holds_back_conflicts() {
    let (store, pool, tenant, site) = session("rules_snapshot").await;
    save(&store, &tenant, &site, &share_flow(), 1).await;
    approve(&store, &tenant, &site, 41).await;
    // The state an older control service leaves: approved, no rows.
    for statement in [
        "DELETE FROM xshield.share_issuance_rules WHERE tenant_id = $1",
        "DELETE FROM xshield.policy_revisions WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(tenant.as_str())
            .execute(&pool)
            .await
            .unwrap();
    }
    let snapshot = store.begin_protected_site_snapshot(&tenant).await.unwrap();
    assert!(!snapshot.sites[0].share_rule_conflict);
    assert_eq!(
        rules(&pool, &tenant, &site).await,
        vec![rule("share-r1", "record-share-r1", 300)]
    );

    // A row an operator registered differently is never overwritten; the
    // site is held back instead of carried to a failing edge.
    sqlx::query(
        "UPDATE xshield.share_issuance_rules SET max_ttl_seconds = 60
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .execute(&pool)
    .await
    .unwrap();
    let snapshot = store.begin_protected_site_snapshot(&tenant).await.unwrap();
    assert!(snapshot.sites[0].share_rule_conflict);
    assert_eq!(rules(&pool, &tenant, &site).await[0].6, 60);
    cleanup(&pool, &tenant).await;
}

struct Edge {
    now: u64,
    snapshot: AuthSnapshot,
    binding_id: AuthBindingId,
    authority: ShareIssueAuthority,
}

fn edge_for(now: u64, tenant: &TenantId, site: &SiteId) -> Edge {
    let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000b01").unwrap();
    let session_id = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000b02").unwrap();
    let credentials = BTreeMap::from([(
        CredentialSlot::Cookie,
        CredentialFingerprint::from_bytes([81; 32]),
    )]);
    let binding = AuthBinding::new(
        binding_id.clone(),
        session_id.clone(),
        tenant.clone(),
        site.clone(),
        "principal_rules",
        AuthorizationContextRef::parse("context_rules").unwrap(),
        AuthEpoch::new(4),
        CredentialGeneration::new(1),
        credentials.clone(),
        UnixSeconds::new(now + 2_000),
    )
    .unwrap();
    let snapshot = binding
        .verify(
            tenant,
            site,
            &session_id,
            &credentials,
            UnixSeconds::new(now),
        )
        .unwrap();
    Edge {
        now,
        snapshot,
        binding_id,
        authority: ShareIssueAuthority {
            resource_grant_id: GrantId::parse("grant_018f2a3b-4c5d-7000-8000-000000000b05")
                .unwrap(),
            rule_id: ShareIssuanceRuleId::parse("record-share-r1").unwrap(),
            operation_id: OperationId::parse("records.share.issue").unwrap(),
            view_profile: ViewProfile::parse("share_controls").unwrap(),
        },
    }
}

fn draft(now: u64, number: u64, view: &str, ttl: u64) -> ShareGrantDraft {
    ShareGrantDraft {
        share_id: ShareGrantId::parse(format!("share_018f2a3b-4c5d-7000-8000-{number:012x}"))
            .unwrap(),
        issuance_key: IssuanceKey::parse(format!("rules-share-{number}")).unwrap(),
        token_fingerprint: ShareTokenFingerprint::from_bytes(
            [u8::try_from(number & 0xff).unwrap(); 32],
        ),
        resource_type: ResourceType::parse("record").unwrap(),
        resource_key: ResourceKeyHmac::from_bytes([93; 32]),
        operation_id: OperationId::parse("records.share.read").unwrap(),
        view_profile: ViewProfile::parse(view).unwrap(),
        policy_revision: PolicyRevision::parse("share-r1").unwrap(),
        expires_at: UnixSeconds::new(now + ttl),
    }
}

async fn issue(
    store: &PostgresIdentityStore,
    edge: &Edge,
    draft: &ShareGrantDraft,
    event: u64,
) -> ShareGrantWriteOutcome {
    let event_id = EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{event:012x}")).unwrap();
    let envelope = json!({"schema_version": 3, "event_type": "share.issued"});
    store
        .issue_share_grant(
            ShareGrantPersistence::new(
                &edge.snapshot,
                draft,
                &edge.authority,
                &event_id,
                &envelope,
                UnixSeconds::new(edge.now),
                10,
            )
            .unwrap(),
        )
        .await
        .unwrap()
}

/// The edge's own issuance lookup accepts the control-created rule: with a
/// qualified resource grant under the label, `issue_share_grant` commits a
/// share for the derived target, view and ceiling, and refuses anything the
/// derived row does not cover. Nothing in this test inserts a rule by hand.
#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn the_edge_issues_under_a_rule_the_control_plane_created() {
    let (store, pool, tenant, site) = session("rules_edge").await;
    save(&store, &tenant, &site, &share_flow(), 1).await;
    approve(&store, &tenant, &site, 41).await;
    let database_now: i64 =
        sqlx::query_scalar("SELECT extract(epoch FROM clock_timestamp())::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    let now = u64::try_from(database_now).unwrap();
    let edge = edge_for(now, &tenant, &site);

    // What the edge's page and grant issuance leaves behind for the issuer
    // route, under the label whose policy revision the control plane wrote.
    let binding = edge.binding_id.as_str();
    sqlx::query(
        "INSERT INTO xshield.auth_bindings (
            tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
            authorization_context_ref, auth_epoch, credential_generation, status,
            absolute_expires_at
         ) VALUES ($1, $2, $3, $4, 'principal_rules', 'context_rules',
                   4, 1, 'active', to_timestamp($5))",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(binding)
    .bind([89_u8; 32].as_slice())
    .bind(database_now + 2_000)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.page_evidence (
            tenant_id, site_id, page_evidence_id, binding_id, auth_epoch,
            source_request_id, response_artifact_ref, page_template, build_fingerprint,
            policy_revision, mapping_revision, status, verified_at, expires_at
         ) VALUES ($1, $2, 'page_018f2a3b-4c5d-7000-8000-000000000b03', $3, 4,
                   'req_018f2a3b-4c5d-7000-8000-000000000b04', 'artifact_rules_page',
                   'record_page', $4, 'share-r1', 'mapping-r1', 'verified',
                   to_timestamp($5 - 1), to_timestamp($5 + 1000))",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(binding)
    .bind([90_u8; 32].as_slice())
    .bind(database_now)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.action_descriptors (
            tenant_id, site_id, action_id, page_template, operation_id, method,
            route_template, target_rule, allowed_fields, field_profile,
            policy_revision, mapping_revision, status
         ) VALUES ($1, $2, 'records.share', 'record_page', 'records.share.issue', 'GET',
                   '/share-issue', '{\"kind\":\"resource\",\"resource_type\":\"record\"}',
                   '[]', 'share_controls', 'share-r1', 'mapping-r1', 'approved')",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.ui_actions (
            tenant_id, site_id, action_ref, binding_id, auth_epoch,
            source_request_id, page_evidence_id, source_action_ref, operation_id,
            target_constraints, field_profile, source_rule, policy_revision,
            status, issued_at, expires_at, mapping_revision, method, route_template,
            allowed_fields
         ) VALUES ($1, $2, 'action_rules_share', $3, 4,
                   'req_018f2a3b-4c5d-7000-8000-000000000b04',
                   'page_018f2a3b-4c5d-7000-8000-000000000b03', 'records.share',
                   'records.share.issue', '{}', 'share_controls', 'mapping-r1',
                   'share-r1', 'active', to_timestamp($4 - 1), to_timestamp($4 + 1000),
                   'mapping-r1', 'GET', '/share-issue', '[]')",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(binding)
    .bind(database_now)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.resource_grants (
            tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref,
            resource_type, resource_key_hmac, operation_id, view_id, constraints,
            source_event_id, issuance_key, policy_revision, status, issued_at, expires_at
         ) VALUES ($1, $2, 'grant_018f2a3b-4c5d-7000-8000-000000000b05', $3, 4,
                   'action_rules_share', 'record', $5, 'records.share.issue',
                   'share_controls', '{}', 'ev_018f2a3b-4c5d-7000-8000-000000000b06',
                   'rules-share-authority', 'share-r1', 'active',
                   to_timestamp($4 - 1), to_timestamp($4 + 1000))",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(binding)
    .bind(database_now)
    .bind([93_u8; 32].as_slice())
    .execute(&pool)
    .await
    .unwrap();

    // Covered by the derived row: the target, its view, a lease within the
    // ceiling.
    let created = issue(
        &store,
        &edge,
        &draft(now, 0xb10, "shared_summary", 300),
        0xb20,
    )
    .await;
    assert!(
        matches!(created, ShareGrantWriteOutcome::Created(_)),
        "{created:?}"
    );
    // Not covered: another view, a lease above the ceiling.
    assert_eq!(
        issue(&store, &edge, &draft(now, 0xb11, "shared_full", 300), 0xb21).await,
        ShareGrantWriteOutcome::Ineligible
    );
    assert_eq!(
        issue(
            &store,
            &edge,
            &draft(now, 0xb12, "shared_summary", 301),
            0xb22
        )
        .await,
        ShareGrantWriteOutcome::Ineligible
    );
    // A rule the control plane did not create does not exist for the edge.
    let mut other_rule = edge_for(now, &tenant, &site);
    other_rule.authority.rule_id = ShareIssuanceRuleId::parse("not-registered").unwrap();
    assert_eq!(
        issue(
            &store,
            &other_rule,
            &draft(now, 0xb13, "shared_summary", 300),
            0xb23
        )
        .await,
        ShareGrantWriteOutcome::Ineligible
    );
    cleanup(&pool, &tenant).await;
}
