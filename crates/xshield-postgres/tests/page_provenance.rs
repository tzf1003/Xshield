//! Edge descriptor provisioning, atomic page issuance, bootstrap reads and
//! session-only page identification against a real `PostgreSQL`.

use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    time::Duration,
};
use xshield_core::{
    domain::{
        ActionId, ActionRef, AuthBindingId, EventId, MappingRevision, OperationId, PageEvidenceId,
        PageTemplate, PolicyRevision, RequestId, SiteId, TenantId, ViewProfile, WafSessionId,
    },
    identity::{
        AuthBinding, AuthEpoch, AuthSnapshot, AuthorizationContextRef, CredentialFingerprint,
        CredentialGeneration, CredentialSlot, IdentityDenied, UnixSeconds,
    },
    ports::{IdentityProofState, UiActionProofQuery, UiActionProofState, UiActionProofStore},
    provenance::{
        ActionDescriptor, ActionGrant, ActionGrantDraft, ActionTarget, ActionTargetRule,
        BuildFingerprint, HttpMethod, PageEvidence, RouteTemplate,
    },
};
use xshield_postgres::{
    DocumentSessionQuery, EdgeDescriptorSync, EdgeDescriptorSyncOutcome, PageActionQuery,
    PageProvenanceBatch, PageProvenanceOutcome, PostgresIdentityStore, ProvenancePersistence,
    StoreError,
};

const NOW: u64 = 1_800_000_000;
const DIGEST: &str = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
const SITE: &str = "site_page";
const POLICY: &str = "policy-r1";
const MAPPING: &str = "mapping-r1";

struct Identity {
    binding: AuthBinding,
    snapshot: AuthSnapshot,
    session: WafSessionId,
    session_fingerprint: [u8; 32],
}

async fn pool(connections: u32) -> PgPool {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    PgPoolOptions::new()
        .max_connections(connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("test pool connects")
}

fn bearer(seed: u8) -> BTreeMap<CredentialSlot, CredentialFingerprint> {
    BTreeMap::from([(
        CredentialSlot::Bearer,
        CredentialFingerprint::from_bytes([seed; 32]),
    )])
}

fn descriptor(
    tenant_policy: &PolicyRevision,
    action: &str,
    method: HttpMethod,
    route: &str,
) -> ActionDescriptor {
    ActionDescriptor::approved(
        ActionId::parse(action).unwrap(),
        PageTemplate::parse("app.page").unwrap(),
        OperationId::parse(action.trim_start_matches("app.")).unwrap(),
        method,
        RouteTemplate::parse(route).unwrap(),
        ActionTargetRule::None,
        BTreeSet::new(),
        ViewProfile::parse("none").unwrap(),
        tenant_policy.clone(),
        MappingRevision::parse(MAPPING).unwrap(),
    )
}

fn descriptors() -> Vec<ActionDescriptor> {
    let policy = PolicyRevision::parse(POLICY).unwrap();
    vec![
        descriptor(
            &policy,
            "app.orders.export",
            HttpMethod::Post,
            "/orders/export",
        ),
        descriptor(&policy, "app.orders.list", HttpMethod::Get, "/orders"),
    ]
}

async fn sync(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    digest: &str,
    descriptors: &[ActionDescriptor],
) -> Result<EdgeDescriptorSyncOutcome, StoreError> {
    let site = SiteId::parse(SITE).unwrap();
    let policy = PolicyRevision::parse(POLICY).unwrap();
    store
        .sync_edge_descriptors(EdgeDescriptorSync::new(
            tenant,
            &site,
            &policy,
            digest,
            descriptors,
        )?)
        .await
}

async fn seed_binding(
    pool: &PgPool,
    tenant: &TenantId,
    suffix: u64,
    status: &str,
    credential_seed: u8,
) -> Identity {
    let site = SiteId::parse(SITE).unwrap();
    let binding_id =
        AuthBindingId::parse(format!("auth_018f2a3b-4c5d-7000-8000-{suffix:012x}")).unwrap();
    let session =
        WafSessionId::parse(format!("ses_018f2a3b-4c5d-7000-8000-{suffix:012x}")).unwrap();
    let session_fingerprint = [u8::try_from(suffix % 251).unwrap(); 32];
    let principal = format!("principal_{suffix}");
    sqlx::query(
        "INSERT INTO xshield.auth_bindings (
            tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
            authorization_context_ref, auth_epoch, credential_generation, status,
            absolute_expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, to_timestamp($9))",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(binding_id.as_str())
    .bind(session_fingerprint.as_slice())
    .bind((status != "anonymous").then_some(principal.as_str()))
    .bind((status != "anonymous").then_some("context_page"))
    .bind(i64::from(status != "anonymous"))
    .bind(status)
    .bind(i64::try_from(NOW + 2_000).unwrap())
    .execute(pool)
    .await
    .unwrap();
    if status != "anonymous" {
        sqlx::query(
            "INSERT INTO xshield.credential_bindings (
                tenant_id, site_id, binding_id, generation, credential_kind,
                fingerprint, expires_at, status
             ) VALUES ($1, $2, $3, 1, 'bearer', $4, to_timestamp($5), 'active')",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(binding_id.as_str())
        .bind([credential_seed; 32].as_slice())
        .bind(i64::try_from(NOW + 2_000).unwrap())
        .execute(pool)
        .await
        .unwrap();
    }
    let binding = AuthBinding::new(
        binding_id,
        session.clone(),
        tenant.clone(),
        site.clone(),
        principal,
        AuthorizationContextRef::parse("context_page").unwrap(),
        AuthEpoch::new(1),
        CredentialGeneration::new(1),
        bearer(credential_seed),
        UnixSeconds::new(NOW + 2_000),
    )
    .unwrap();
    let snapshot = binding
        .verify(
            tenant,
            &site,
            &session,
            &bearer(credential_seed),
            UnixSeconds::new(NOW),
        )
        .unwrap();
    Identity {
        binding,
        snapshot,
        session,
        session_fingerprint,
    }
}

fn evidence(identity: &Identity, page: u64) -> PageEvidence {
    PageEvidence::verified(
        PageEvidenceId::parse(format!("page_018f2a3b-4c5d-7000-8000-{page:012x}")).unwrap(),
        &identity.binding,
        identity.snapshot.clone(),
        RequestId::parse(format!("req_018f2a3b-4c5d-7000-8000-{page:012x}")).unwrap(),
        PageTemplate::parse("app.page").unwrap(),
        BuildFingerprint::parse(&"b".repeat(64)).unwrap(),
        PolicyRevision::parse(POLICY).unwrap(),
        MappingRevision::parse(MAPPING).unwrap(),
        UnixSeconds::new(NOW + 1_500),
        UnixSeconds::new(NOW),
    )
    .unwrap()
}

fn action(
    identity: &Identity,
    evidence: &PageEvidence,
    descriptor: &ActionDescriptor,
    reference: &str,
) -> ActionGrant {
    ActionGrant::issue(
        &identity.binding,
        &identity.snapshot,
        evidence,
        descriptor,
        ActionGrantDraft {
            action_ref: ActionRef::parse(reference).unwrap(),
            target: ActionTarget::None,
            fields: BTreeSet::new(),
            expires_at: UnixSeconds::new(NOW + 1_000),
        },
        UnixSeconds::new(NOW),
    )
    .unwrap()
}

fn event(value: u64) -> EventId {
    EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{value:012x}")).unwrap()
}

async fn issue(
    store: &PostgresIdentityStore,
    evidence: &PageEvidence,
    actions: &[(&ActionGrant, EventId)],
    max_active_pages: u32,
) -> Result<PageProvenanceOutcome, StoreError> {
    let envelope = json!({"schema_version": 3, "event_type": "ui_action.issued"});
    let items = actions
        .iter()
        .map(|(action, event_id)| {
            ProvenancePersistence::new(
                evidence,
                action,
                "sha256.page",
                event_id,
                &envelope,
                UnixSeconds::new(NOW),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    store
        .persist_page_provenance(PageProvenanceBatch::new(items, max_active_pages)?)
        .await
}

async fn count(pool: &PgPool, table: &str, tenant: &TenantId) -> i64 {
    let statement = match table {
        "action_descriptors" => {
            "SELECT count(*) FROM xshield.action_descriptors WHERE tenant_id = $1 AND site_id = $2"
        }
        "page_evidence" => {
            "SELECT count(*) FROM xshield.page_evidence WHERE tenant_id = $1 AND site_id = $2"
        }
        "ui_actions" => {
            "SELECT count(*) FROM xshield.ui_actions WHERE tenant_id = $1 AND site_id = $2"
        }
        _ => panic!("unexpected table {table}"),
    };
    sqlx::query_scalar(statement)
        .bind(tenant.as_str())
        .bind(SITE)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn page_query<'a>(
    scope: (&'a TenantId, &'a SiteId, &'a PolicyRevision),
    page: &'a PageEvidence,
    binding: &'a AuthBindingId,
    epoch: u64,
) -> PageActionQuery<'a> {
    PageActionQuery {
        tenant_id: scope.0,
        site_id: scope.1,
        binding_id: binding,
        epoch: AuthEpoch::new(epoch),
        page_evidence_id: page.evidence_id(),
        policy_revision: scope.2,
        now: UnixSeconds::new(NOW),
    }
}

fn session_query<'a>(
    tenant: &'a TenantId,
    site: &'a SiteId,
    identity: &'a Identity,
) -> DocumentSessionQuery<'a> {
    DocumentSessionQuery {
        tenant_id: tenant,
        site_id: site,
        session_id: &identity.session,
        session_fingerprint: &identity.session_fingerprint,
        now: UnixSeconds::new(NOW),
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn edge_descriptor_sync_binds_one_digest_per_revision() {
    let pool = pool(4).await;
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let tenant = TenantId::parse("tenant_page_sync").unwrap();
    let descriptors = descriptors();
    assert_eq!(
        sync(&store, &tenant, DIGEST, &descriptors).await.unwrap(),
        EdgeDescriptorSyncOutcome::Created
    );
    assert_eq!(
        sync(&store, &tenant, DIGEST, &descriptors).await.unwrap(),
        EdgeDescriptorSyncOutcome::Existing
    );
    assert_eq!(count(&pool, "action_descriptors", &tenant).await, 2);
    // Another set under the same revision never overwrites what references mean.
    let other_digest = "e".repeat(64);
    let outcome = sync(&store, &tenant, &other_digest, &descriptors[..1])
        .await
        .unwrap();
    assert_eq!(outcome, EdgeDescriptorSyncOutcome::PolicyConflict);
    assert!(!outcome.is_ready());
    let stored: String = sqlx::query_scalar(
        "SELECT content_digest FROM xshield.policy_revisions
         WHERE tenant_id = $1 AND site_id = $2 AND revision = $3",
    )
    .bind(tenant.as_str())
    .bind(SITE)
    .bind(POLICY)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, DIGEST);

    // A matching digest with a semantically different stored row is refused
    // and the transaction leaves no partial descriptor behind.
    let drift = TenantId::parse("tenant_page_drift").unwrap();
    sqlx::query(
        "INSERT INTO xshield.policy_revisions (
            tenant_id, site_id, revision, status, content_digest, artifact_ref
         ) VALUES ($1, $2, $3, 'active', $4, 'artifact_external')",
    )
    .bind(drift.as_str())
    .bind(SITE)
    .bind(POLICY)
    .bind(DIGEST)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.action_descriptors (
            tenant_id, site_id, action_id, page_template, operation_id, method,
            route_template, target_rule, allowed_fields, field_profile,
            policy_revision, mapping_revision, status
         ) VALUES ($1, $2, 'app.orders.list', 'other.page', 'orders.list', 'GET',
                   '/orders', '{\"kind\":\"none\"}', '[]', 'none', $3, $4, 'approved')",
    )
    .bind(drift.as_str())
    .bind(SITE)
    .bind(POLICY)
    .bind(MAPPING)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        sync(&store, &drift, DIGEST, &descriptors).await.unwrap(),
        EdgeDescriptorSyncOutcome::DescriptorConflict
    );
    assert_eq!(count(&pool, "action_descriptors", &drift).await, 1);

    // A retired revision cannot be reactivated by an edge.
    let retired = TenantId::parse("tenant_page_retired").unwrap();
    assert!(
        sync(&store, &retired, DIGEST, &descriptors)
            .await
            .unwrap()
            .is_ready()
    );
    sqlx::query("UPDATE xshield.policy_revisions SET status = 'retired' WHERE tenant_id = $1")
        .bind(retired.as_str())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        sync(&store, &retired, DIGEST, &descriptors).await.unwrap(),
        EdgeDescriptorSyncOutcome::PolicyConflict
    );

    // Concurrent edges with one configuration converge without an error.
    let racing = TenantId::parse("tenant_page_race").unwrap();
    let (first, second) = tokio::join!(
        sync(&store, &racing, DIGEST, &descriptors),
        sync(&store, &racing, DIGEST, &descriptors)
    );
    let mut outcomes = [first.unwrap(), second.unwrap()];
    outcomes.sort_by_key(|outcome| *outcome == EdgeDescriptorSyncOutcome::Existing);
    assert_eq!(
        outcomes,
        [
            EdgeDescriptorSyncOutcome::Created,
            EdgeDescriptorSyncOutcome::Existing
        ]
    );

    let site = SiteId::parse(SITE).unwrap();
    let policy = PolicyRevision::parse(POLICY).unwrap();
    for (digest, set) in [
        ("A".repeat(64), &descriptors[..]),
        (DIGEST.to_owned(), &[][..]),
    ] {
        assert!(matches!(
            EdgeDescriptorSync::new(&tenant, &site, &policy, &digest, set),
            Err(StoreError::InvalidCommand)
        ));
    }
    let duplicate = [descriptors[0].clone(), descriptors[0].clone()];
    assert!(matches!(
        EdgeDescriptorSync::new(&tenant, &site, &policy, DIGEST, &duplicate),
        Err(StoreError::InvalidCommand)
    ));
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn page_batch_is_atomic_bounded_and_idempotent() {
    let pool = pool(2).await;
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let tenant = TenantId::parse("tenant_page_batch").unwrap();
    let descriptors = descriptors();
    assert!(
        sync(&store, &tenant, DIGEST, &descriptors)
            .await
            .unwrap()
            .is_ready()
    );
    let alice = seed_binding(&pool, &tenant, 0x701, "active", 0xa1).await;
    let first_page = evidence(&alice, 0x711);
    let export = action(&alice, &first_page, &descriptors[0], "action.page-export-1");
    let list = action(&alice, &first_page, &descriptors[1], "action.page-list-1");
    let batch = [(&export, event(0x721)), (&list, event(0x722))];
    assert_eq!(
        issue(&store, &first_page, &batch, 2).await.unwrap(),
        PageProvenanceOutcome::Created
    );
    assert_eq!(
        issue(&store, &first_page, &batch, 2).await.unwrap(),
        PageProvenanceOutcome::Existing
    );
    assert_eq!(count(&pool, "page_evidence", &tenant).await, 1);
    assert_eq!(count(&pool, "ui_actions", &tenant).await, 2);
    let outbox: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.audit_outbox
         WHERE tenant_id = $1 AND event_type = 'ui_action.issued'",
    )
    .bind(tenant.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outbox, 2);
    for issued in [&export, &list] {
        let loaded = store
            .load_ui_action(UiActionProofQuery {
                binding: &alice.binding,
                snapshot: &alice.snapshot,
                action_ref: issued.action_ref(),
                policy_revision: issued.policy_revision(),
                now: UnixSeconds::new(NOW),
            })
            .await
            .unwrap();
        assert!(matches!(loaded, UiActionProofState::Verified(found) if *found == *issued));
    }

    // The live-page bound counts other page instances under the binding lock.
    let second_page = evidence(&alice, 0x712);
    let second = action(&alice, &second_page, &descriptors[1], "action.page-list-2");
    assert_eq!(
        issue(&store, &second_page, &[(&second, event(0x723))], 1)
            .await
            .unwrap(),
        PageProvenanceOutcome::CapacityExceeded
    );
    assert_eq!(count(&pool, "page_evidence", &tenant).await, 1);
    assert_eq!(
        issue(&store, &second_page, &[(&second, event(0x723))], 2)
            .await
            .unwrap(),
        PageProvenanceOutcome::Created
    );

    // One ineligible item rolls back the evidence and every sibling action.
    let unknown = ActionDescriptor::approved(
        ActionId::parse("app.unknown").unwrap(),
        PageTemplate::parse("app.page").unwrap(),
        OperationId::parse("unknown").unwrap(),
        HttpMethod::Get,
        RouteTemplate::parse("/unknown").unwrap(),
        ActionTargetRule::None,
        BTreeSet::new(),
        ViewProfile::parse("none").unwrap(),
        PolicyRevision::parse(POLICY).unwrap(),
        MappingRevision::parse(MAPPING).unwrap(),
    );
    let third_page = evidence(&alice, 0x713);
    let known = action(&alice, &third_page, &descriptors[1], "action.page-list-3");
    let missing = action(&alice, &third_page, &unknown, "action.page-unknown-3");
    assert_eq!(
        issue(
            &store,
            &third_page,
            &[(&known, event(0x724)), (&missing, event(0x725))],
            8
        )
        .await
        .unwrap(),
        PageProvenanceOutcome::Ineligible
    );
    assert_eq!(count(&pool, "page_evidence", &tenant).await, 2);
    assert_eq!(count(&pool, "ui_actions", &tenant).await, 3);

    // A reference reused for another page instance is a semantic conflict.
    let fourth_page = evidence(&alice, 0x714);
    let reused = action(&alice, &fourth_page, &descriptors[1], "action.page-list-1");
    assert_eq!(
        issue(&store, &fourth_page, &[(&reused, event(0x726))], 8)
            .await
            .unwrap(),
        PageProvenanceOutcome::Conflict
    );
    assert_eq!(count(&pool, "page_evidence", &tenant).await, 2);

    // Batches must share one evidence object and unique references/events.
    let envelope = json!({});
    let (one, two) = (event(1), event(2));
    for (items, capacity) in [
        (
            vec![(&first_page, &export, &one), (&second_page, &second, &two)],
            8,
        ),
        (
            vec![(&first_page, &export, &one), (&first_page, &export, &two)],
            8,
        ),
        (Vec::new(), 8),
        (vec![(&first_page, &export, &one)], 0),
    ] {
        let items = items
            .into_iter()
            .map(|(page, issued, event_id)| {
                ProvenancePersistence::new(
                    page,
                    issued,
                    "sha256.page",
                    event_id,
                    &envelope,
                    UnixSeconds::new(NOW),
                )
                .unwrap()
            })
            .collect();
        assert!(matches!(
            PageProvenanceBatch::new(items, capacity),
            Err(StoreError::InvalidCommand)
        ));
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn page_actions_are_returned_only_to_their_live_binding() {
    let pool = pool(2).await;
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let tenant = TenantId::parse("tenant_page_read").unwrap();
    let site = SiteId::parse(SITE).unwrap();
    let policy = PolicyRevision::parse(POLICY).unwrap();
    let descriptors = descriptors();
    assert!(
        sync(&store, &tenant, DIGEST, &descriptors)
            .await
            .unwrap()
            .is_ready()
    );
    let alice = seed_binding(&pool, &tenant, 0x801, "active", 0xb1).await;
    let bob = seed_binding(&pool, &tenant, 0x802, "active", 0xb2).await;
    let page = evidence(&alice, 0x811);
    let export = action(&alice, &page, &descriptors[0], "action.read-export");
    let list = action(&alice, &page, &descriptors[1], "action.read-list");
    assert_eq!(
        issue(
            &store,
            &page,
            &[(&export, event(0x821)), (&list, event(0x822))],
            4
        )
        .await
        .unwrap(),
        PageProvenanceOutcome::Created
    );
    let scope = (&tenant, &site, &policy);
    let read = |binding, epoch| page_query(scope, &page, binding, epoch);
    let views = store
        .load_page_actions(read(alice.snapshot.binding_id(), 1))
        .await
        .unwrap();
    assert_eq!(
        views
            .iter()
            .map(|view| (view.action_ref.as_str(), view.method, view.route.as_str()))
            .collect::<Vec<_>>(),
        [
            ("action.read-export", HttpMethod::Post, "/orders/export"),
            ("action.read-list", HttpMethod::Get, "/orders"),
        ]
    );
    assert!(
        views
            .iter()
            .all(|view| view.expires_at == UnixSeconds::new(NOW + 1_000))
    );
    // Binding B presenting A's page handle receives nothing.
    assert_eq!(
        store
            .load_page_actions(read(bob.snapshot.binding_id(), 1))
            .await
            .unwrap(),
        [] as [xshield_postgres::PageActionView; 0]
    );
    assert_eq!(
        store
            .load_page_actions(read(alice.snapshot.binding_id(), 2))
            .await
            .unwrap(),
        [] as [xshield_postgres::PageActionView; 0]
    );
    sqlx::query("UPDATE xshield.auth_bindings SET status = 'revoked' WHERE binding_id = $1")
        .bind(alice.snapshot.binding_id().as_str())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store
            .load_page_actions(read(alice.snapshot.binding_id(), 1))
            .await
            .unwrap(),
        [] as [xshield_postgres::PageActionView; 0]
    );
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn document_session_identifies_only_active_credentialed_bindings() {
    let pool = pool(2).await;
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let tenant = TenantId::parse("tenant_page_session").unwrap();
    let site = SiteId::parse(SITE).unwrap();
    let active = seed_binding(&pool, &tenant, 0x901, "active", 0xc1).await;
    let anonymous = seed_binding(&pool, &tenant, 0x902, "anonymous", 0xc2).await;
    let stale = seed_binding(&pool, &tenant, 0x903, "active", 0xc3).await;
    sqlx::query(
        "UPDATE xshield.credential_bindings SET expires_at = now() - interval '1 second'
         WHERE binding_id = $1",
    )
    .bind(stale.snapshot.binding_id().as_str())
    .execute(&pool)
    .await
    .unwrap();
    let lookup = |identity| session_query(&tenant, &site, identity);
    match store.load_document_session(lookup(&active)).await.unwrap() {
        IdentityProofState::Verified { snapshot, .. } => assert_eq!(snapshot, active.snapshot),
        IdentityProofState::Denied(error) => panic!("active binding denied: {error}"),
    }
    assert!(matches!(
        store
            .load_document_session(lookup(&anonymous))
            .await
            .unwrap(),
        IdentityProofState::Denied(IdentityDenied::AuthRequired)
    ));
    assert!(matches!(
        store.load_document_session(lookup(&stale)).await.unwrap(),
        IdentityProofState::Denied(IdentityDenied::BindingMismatch)
    ));
    let unknown = DocumentSessionQuery {
        session_fingerprint: &[0xee; 32],
        ..lookup(&active)
    };
    assert!(matches!(
        store.load_document_session(unknown).await.unwrap(),
        IdentityProofState::Denied(IdentityDenied::BindingMismatch)
    ));
}
