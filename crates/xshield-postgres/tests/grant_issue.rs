use serde_json::json;
use sqlx::PgPool;
use std::{collections::BTreeMap, env, time::Duration};
use xshield_core::{
    domain::{
        ActionRef, AuthBindingId, EventId, GrantId, IssuanceKey, OperationId, PolicyRevision,
        RequestId, ResourceType, SiteId, TenantId, ViewProfile, WafSessionId,
    },
    grant::{GrantDenied, GrantDraft, GrantQuery, ResourceKeyHmac},
    identity::{
        AuthBinding, AuthEpoch, AuthSnapshot, CredentialFingerprint, CredentialGeneration,
        CredentialSlot, UnixSeconds,
    },
    ports::{ResourceProofQuery, ResourceProofState, ResourceProofStore},
};
use xshield_postgres::{GrantPersistence, GrantWriteOutcome, PostgresIdentityStore, StoreError};

const NOW: u64 = 1_800_000_000;
const EXPIRES: u64 = 1_800_001_000;
const SESSION_EXPIRES: u64 = 1_800_002_000;

struct Fixture {
    tenant: TenantId,
    site: SiteId,
    binding_id: AuthBindingId,
    action_ref: ActionRef,
    binding: AuthBinding,
    snapshot: AuthSnapshot,
}

fn fixture() -> Fixture {
    let tenant = TenantId::parse("tenant_grant").unwrap();
    let site = SiteId::parse("site_grant").unwrap();
    let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000201").unwrap();
    let session_id = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000202").unwrap();
    let credentials = BTreeMap::from([(
        CredentialSlot::Cookie,
        CredentialFingerprint::parse(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
    )]);
    let binding = AuthBinding::new(
        binding_id.clone(),
        session_id.clone(),
        tenant.clone(),
        site.clone(),
        "principal_grant",
        AuthEpoch::new(4),
        CredentialGeneration::new(2),
        credentials.clone(),
        UnixSeconds::new(SESSION_EXPIRES),
    )
    .unwrap();
    let snapshot = binding
        .verify(
            &tenant,
            &site,
            &session_id,
            &credentials,
            UnixSeconds::new(NOW),
        )
        .unwrap();
    Fixture {
        tenant,
        site,
        binding_id,
        action_ref: ActionRef::parse("action_order_read").unwrap(),
        binding,
        snapshot,
    }
}

fn event_id(value: u64) -> EventId {
    EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{value:012x}")).unwrap()
}

fn draft(value: u64, issuance_key: &str, resource_byte: char) -> GrantDraft {
    GrantDraft {
        grant_id: GrantId::parse(format!("grant_018f2a3b-4c5d-7000-8000-{value:012x}")).unwrap(),
        issuance_key: IssuanceKey::parse(issuance_key).unwrap(),
        resource_type: ResourceType::parse("order").unwrap(),
        resource_key: ResourceKeyHmac::parse(&resource_byte.to_string().repeat(64)).unwrap(),
        operation_id: OperationId::parse("orders.read").unwrap(),
        view_profile: ViewProfile::parse("customer_detail").unwrap(),
        source_request_id: RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000210").unwrap(),
        policy_revision: PolicyRevision::parse("policy-r1").unwrap(),
        expires_at: UnixSeconds::new(EXPIRES),
    }
}

async fn seed_eligibility(pool: &PgPool, fixture: &Fixture) {
    sqlx::query(
        "INSERT INTO xshield.policy_revisions (
            tenant_id, site_id, revision, status, content_digest, artifact_ref
         ) VALUES ($1, $2, 'policy-r1', 'active', $3, 'artifact_policy_r1')",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind("a".repeat(64))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.auth_bindings (
            tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
            auth_epoch, credential_generation, status, absolute_expires_at
         ) VALUES ($1, $2, $3, $4, 'principal_grant', 4, 2, 'active', to_timestamp($5))",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .bind([17_u8; 32].as_slice())
    .bind(i64::try_from(SESSION_EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.page_evidence (
            tenant_id, site_id, page_evidence_id, binding_id, auth_epoch,
            source_request_id, response_artifact_ref, page_template, build_fingerprint,
            policy_revision, mapping_revision, status, verified_at, expires_at
         ) VALUES (
            $1, $2, 'page_018f2a3b-4c5d-7000-8000-000000000211', $3, 4,
            $4, 'artifact_page_grant', 'orders_page', $5,
            'policy-r1', 'mapping-r1', 'verified', to_timestamp($6), to_timestamp($7)
         )",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .bind("req_018f2a3b-4c5d-7000-8000-000000000210")
    .bind([34_u8; 32].as_slice())
    .bind(i64::try_from(NOW - 1).unwrap())
    .bind(i64::try_from(SESSION_EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.action_descriptors (
            tenant_id, site_id, action_id, page_template, operation_id, method,
            route_template, target_rule, allowed_fields, field_profile,
            policy_revision, mapping_revision, status
         ) VALUES (
            $1, $2, 'orders.open', 'orders_page', 'orders.read', 'GET',
            '/api/orders/{id}', '{\"kind\":\"resource\",\"resource_type\":\"order\"}',
            '[]', 'customer_detail', 'policy-r1', 'mapping-r1', 'approved'
         )",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.ui_actions (
            tenant_id, site_id, action_ref, binding_id, auth_epoch,
            source_request_id, page_evidence_id, operation_id, target_constraints,
            field_profile, source_rule, policy_revision, status, issued_at, expires_at,
            source_action_ref, mapping_revision, method, route_template, allowed_fields
         ) VALUES (
            $1, $2, $3, $4, 4, $5,
            'page_018f2a3b-4c5d-7000-8000-000000000211', 'orders.read', '{}',
            'customer_detail', 'orders-list-r1', 'policy-r1', 'active',
            to_timestamp($6), to_timestamp($7), 'orders.open', 'mapping-r1',
            'GET', '/api/orders/{id}', '[]'
         )",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.action_ref.as_str())
    .bind(fixture.binding_id.as_str())
    .bind("req_018f2a3b-4c5d-7000-8000-000000000210")
    .bind(i64::try_from(NOW - 1).unwrap())
    .bind(i64::try_from(SESSION_EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
}

async fn issue(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    draft: &GrantDraft,
    event_id: &EventId,
    capacity: u32,
) -> Result<GrantWriteOutcome, StoreError> {
    let constraints = json!({});
    let envelope = json!({"schema_version": 3, "event_type": "grant.issued"});
    store
        .issue_grant(GrantPersistence::new(
            &fixture.snapshot,
            draft,
            &fixture.action_ref,
            &constraints,
            event_id,
            &envelope,
            UnixSeconds::new(NOW),
            capacity,
        )?)
        .await
}

async fn grant_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM xshield.resource_grants")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn assert_outbox_failure_rolls_back(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    let rollback_event = event_id(220);
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, 'fixture', 'fixture', '{}')",
    )
    .bind(rollback_event.as_str())
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        issue(
            store,
            fixture,
            &draft(221, "issue-rollback", '1'),
            &rollback_event,
            1,
        )
        .await,
        Err(StoreError::Database(_))
    ));
    assert_eq!(grant_count(pool).await, 0);
}

async fn assert_capacity_is_serialized(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    sqlx::query("DELETE FROM xshield.resource_grants")
        .execute(pool)
        .await
        .unwrap();
    let left_draft = draft(225, "issue-left", '4');
    let right_draft = draft(226, "issue-right", '5');
    let left_event = event_id(227);
    let right_event = event_id(228);
    let (left, right) = tokio::join!(
        issue(store, fixture, &left_draft, &left_event, 1),
        issue(store, fixture, &right_draft, &right_event, 1),
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, GrantWriteOutcome::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, GrantWriteOutcome::CapacityExceeded))
            .count(),
        1
    );
}

async fn assert_resource_grant_reads(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    draft: &GrantDraft,
) {
    let loaded = store
        .load_resource_grant(ResourceProofQuery {
            binding: &fixture.binding,
            snapshot: &fixture.snapshot,
            action_ref: &fixture.action_ref,
            resource_type: &draft.resource_type,
            resource_key: &draft.resource_key,
            operation_id: &draft.operation_id,
            view_profile: &draft.view_profile,
            policy_revision: &draft.policy_revision,
            now: UnixSeconds::new(NOW),
        })
        .await
        .unwrap();
    let ResourceProofState::Verified(ledger) = loaded else {
        panic!("exact persisted grant must load");
    };
    assert!(
        ledger
            .authorize(
                &fixture.binding,
                GrantQuery {
                    snapshot: &fixture.snapshot,
                    resource_type: &draft.resource_type,
                    resource_key: &draft.resource_key,
                    operation_id: &draft.operation_id,
                    view_profile: &draft.view_profile,
                    now: UnixSeconds::new(NOW),
                },
            )
            .is_ok()
    );

    let wrong_operation = OperationId::parse("orders.update").unwrap();
    assert!(matches!(
        store
            .load_resource_grant(ResourceProofQuery {
                binding: &fixture.binding,
                snapshot: &fixture.snapshot,
                action_ref: &fixture.action_ref,
                resource_type: &draft.resource_type,
                resource_key: &draft.resource_key,
                operation_id: &wrong_operation,
                view_profile: &draft.view_profile,
                policy_revision: &draft.policy_revision,
                now: UnixSeconds::new(NOW),
            })
            .await
            .unwrap(),
        ResourceProofState::Denied(GrantDenied::OperationNotGranted)
    ));
    let unknown_resource = ResourceKeyHmac::parse(&"9".repeat(64)).unwrap();
    assert!(matches!(
        store
            .load_resource_grant(ResourceProofQuery {
                binding: &fixture.binding,
                snapshot: &fixture.snapshot,
                action_ref: &fixture.action_ref,
                resource_type: &draft.resource_type,
                resource_key: &unknown_resource,
                operation_id: &draft.operation_id,
                view_profile: &draft.view_profile,
                policy_revision: &draft.policy_revision,
                now: UnixSeconds::new(NOW),
            })
            .await
            .unwrap(),
        ResourceProofState::Denied(GrantDenied::CapabilityMissing)
    ));
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn grant_issue_is_atomic_idempotent_and_capacity_bounded() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 4, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let fixture = fixture();
    seed_eligibility(&pool, &fixture).await;

    assert_outbox_failure_rolls_back(&pool, &store, &fixture).await;

    let first_draft = draft(222, "issue-first", '2');
    let first_event = event_id(223);
    assert_eq!(
        issue(&store, &fixture, &first_draft, &first_event, 1)
            .await
            .unwrap(),
        GrantWriteOutcome::Created(first_draft.grant_id.clone())
    );
    assert_eq!(
        issue(&store, &fixture, &first_draft, &first_event, 1)
            .await
            .unwrap(),
        GrantWriteOutcome::Existing(first_draft.grant_id.clone())
    );
    assert_resource_grant_reads(&store, &fixture, &first_draft).await;
    assert_eq!(
        issue(
            &store,
            &fixture,
            &draft(224, "issue-first", '3'),
            &first_event,
            1,
        )
        .await
        .unwrap(),
        GrantWriteOutcome::Conflict
    );

    assert_capacity_is_serialized(&pool, &store, &fixture).await;

    sqlx::query(
        "UPDATE xshield.auth_bindings SET auth_epoch = 5
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        issue(
            &store,
            &fixture,
            &draft(229, "issue-stale", '6'),
            &event_id(230),
            2,
        )
        .await
        .unwrap(),
        GrantWriteOutcome::Ineligible
    );
}
