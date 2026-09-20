use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    time::Duration,
};
use xshield_core::{
    domain::{
        ActionId, ActionRef, AuthBindingId, EventId, FieldName, GrantId, IssuanceKey,
        MappingRevision, OperationId, PageTemplate, PolicyRevision, RequestId, ResourceType,
        ResponseEvidenceId, SiteId, TenantId, ViewProfile, WafSessionId,
    },
    grant::{GrantDenied, GrantDraft, ResourceKeyHmac},
    identity::{
        AuthBinding, AuthEpoch, AuthSnapshot, CredentialFingerprint, CredentialGeneration,
        CredentialSlot, UnixSeconds,
    },
    ports::{
        ResourceProofQuery, ResourceProofState, ResourceProofStore, UiActionProofQuery,
        UiActionProofState, UiActionProofStore,
    },
    provenance::{
        ActionDescriptor, ActionGrant, ActionGrantDraft, ActionTarget, ActionTargetRule,
        HttpMethod, ProvenanceError, ResponseEvidence, RouteTemplate,
    },
};
use xshield_postgres::{
    PostgresIdentityStore, ResponseActionDescriptorQuery, ResponseGrantItem,
    ResponseGrantPersistence, ResponseGrantWriteOutcome, StoreError,
};

const NOW: u64 = 1_800_000_000;
const EXPIRES: u64 = 1_800_000_900;
const SESSION_EXPIRES: u64 = 1_800_001_000;

struct Fixture {
    tenant: TenantId,
    site: SiteId,
    binding_id: AuthBindingId,
    binding: AuthBinding,
    snapshot: AuthSnapshot,
    descriptor: ActionDescriptor,
}

fn fixture() -> Fixture {
    let tenant = TenantId::parse("tenant_response").unwrap();
    let site = SiteId::parse("site_response").unwrap();
    let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000601").unwrap();
    let session = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000602").unwrap();
    let credentials = BTreeMap::from([(
        CredentialSlot::Cookie,
        CredentialFingerprint::parse(&"a".repeat(64)).unwrap(),
    )]);
    let binding = AuthBinding::new(
        binding_id.clone(),
        session.clone(),
        tenant.clone(),
        site.clone(),
        "principal_response",
        xshield_core::identity::AuthorizationContextRef::parse("context_response").unwrap(),
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
            &session,
            &credentials,
            UnixSeconds::new(NOW),
        )
        .unwrap();
    let descriptor = ActionDescriptor::approved(
        ActionId::parse("orders.open").unwrap(),
        PageTemplate::parse("orders_page").unwrap(),
        OperationId::parse("orders.read").unwrap(),
        HttpMethod::Get,
        RouteTemplate::parse("/orders/{order_id}").unwrap(),
        ActionTargetRule::Resource(ResourceType::parse("order").unwrap()),
        BTreeSet::from([FieldName::parse("order_id").unwrap()]),
        ViewProfile::parse("customer_detail").unwrap(),
        PolicyRevision::parse("policy-r1").unwrap(),
        MappingRevision::parse("mapping-r1").unwrap(),
    );
    Fixture {
        tenant,
        site,
        binding_id,
        binding,
        snapshot,
        descriptor,
    }
}

struct Batch {
    evidence: ResponseEvidence,
    actions: Vec<ActionGrant>,
    grants: Vec<GrantDraft>,
    event_ids: Vec<EventId>,
    envelopes: Vec<Value>,
    constraints: Vec<Value>,
}

fn batch(fixture: &Fixture, id_offset: u64) -> Batch {
    let evidence = ResponseEvidence::verified(
        ResponseEvidenceId::parse(format!("response_018f2a3b-4c5d-7000-8000-{id_offset:012x}"))
            .unwrap(),
        &fixture.binding,
        fixture.snapshot.clone(),
        RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000610").unwrap(),
        OperationId::parse("orders.list").unwrap(),
        OperationId::parse("orders.read").unwrap(),
        200,
        PolicyRevision::parse("policy-r1").unwrap(),
        UnixSeconds::new(EXPIRES),
        UnixSeconds::new(NOW),
    )
    .unwrap();
    let mut actions = Vec::new();
    let mut grants = Vec::new();
    let mut event_ids = Vec::new();
    for index in 0..2_u64 {
        let key = ResourceKeyHmac::parse(&format!("{}", index + 1).repeat(64)).unwrap();
        let action = ActionGrant::issue_from_response(
            &fixture.binding,
            &fixture.snapshot,
            &evidence,
            &fixture.descriptor,
            ActionGrantDraft {
                action_ref: ActionRef::parse(format!("action_response_{id_offset}_{index}"))
                    .unwrap(),
                target: ActionTarget::Resource {
                    resource_type: ResourceType::parse("order").unwrap(),
                    resource_key: key.clone(),
                },
                fields: BTreeSet::from([FieldName::parse("order_id").unwrap()]),
                expires_at: UnixSeconds::new(EXPIRES),
            },
            UnixSeconds::new(NOW),
        )
        .unwrap();
        actions.push(action);
        grants.push(GrantDraft {
            grant_id: GrantId::parse(format!(
                "grant_018f2a3b-4c5d-7000-8000-{:012x}",
                id_offset + index + 100
            ))
            .unwrap(),
            issuance_key: IssuanceKey::parse(format!("orders-list-item-{index}")).unwrap(),
            resource_type: ResourceType::parse("order").unwrap(),
            resource_key: key,
            operation_id: OperationId::parse("orders.read").unwrap(),
            view_profile: ViewProfile::parse("customer_detail").unwrap(),
            source_request_id: RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000610")
                .unwrap(),
            policy_revision: PolicyRevision::parse("policy-r1").unwrap(),
            expires_at: UnixSeconds::new(EXPIRES),
        });
        event_ids.push(
            EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{:012x}", 700 + index)).unwrap(),
        );
    }
    Batch {
        evidence,
        actions,
        grants,
        event_ids,
        envelopes: vec![
            json!({"schema_version": 3, "event_type": "response_grant.issued", "item": 0}),
            json!({"schema_version": 3, "event_type": "response_grant.issued", "item": 1}),
        ],
        constraints: vec![json!({}), json!({})],
    }
}

async fn issue(
    store: &PostgresIdentityStore,
    batch: &Batch,
    artifact: &str,
    capacity: u32,
) -> Result<ResponseGrantWriteOutcome, StoreError> {
    let items = batch
        .actions
        .iter()
        .zip(&batch.grants)
        .zip(&batch.constraints)
        .zip(&batch.event_ids)
        .zip(&batch.envelopes)
        .map(|((((action, grant), constraints), event_id), envelope)| {
            ResponseGrantItem::new(action, grant, constraints, event_id, envelope)
        })
        .collect::<Result<Vec<_>, _>>()?;
    store
        .issue_response_grants(ResponseGrantPersistence::new(
            &batch.evidence,
            artifact,
            &items,
            UnixSeconds::new(NOW),
            capacity,
        )?)
        .await
}

async fn seed(pool: &PgPool, fixture: &Fixture) {
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
            authorization_context_ref, auth_epoch, credential_generation, status,
            absolute_expires_at
         ) VALUES ($1, $2, $3, $4, 'principal_response', 'context_response',
                   4, 2, 'active', to_timestamp($5))",
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
        "INSERT INTO xshield.action_descriptors (
            tenant_id, site_id, action_id, page_template, operation_id, method,
            route_template, target_rule, allowed_fields, field_profile,
            policy_revision, mapping_revision, status
         ) VALUES (
            $1, $2, 'orders.open', 'orders_page', 'orders.read', 'GET',
            '/orders/{order_id}', '{\"kind\":\"resource\",\"resource_type\":\"order\"}',
            '[\"order_id\"]', 'customer_detail', 'policy-r1', 'mapping-r1', 'approved'
         )",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .execute(pool)
    .await
    .unwrap();
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    match table {
        "response_evidence" => sqlx::query_scalar(
            "SELECT count(*) FROM xshield.response_evidence
                 WHERE tenant_id = 'tenant_response' AND site_id = 'site_response'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        "ui_actions" => sqlx::query_scalar(
            "SELECT count(*) FROM xshield.ui_actions
             WHERE tenant_id = 'tenant_response' AND site_id = 'site_response'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        "resource_grants" => sqlx::query_scalar(
            "SELECT count(*) FROM xshield.resource_grants
                 WHERE tenant_id = 'tenant_response' AND site_id = 'site_response'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        "audit_outbox" => sqlx::query_scalar(
            "SELECT count(*) FROM xshield.audit_outbox
             WHERE tenant_id = 'tenant_response' AND site_id = 'site_response'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        _ => panic!("unknown fixture table"),
    }
}

#[allow(clippy::too_many_lines)]
async fn assert_response_expiry_reads(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    batch: &Batch,
    action_ref: &ActionRef,
) {
    let action_query = |now| UiActionProofQuery {
        binding: &fixture.binding,
        snapshot: &fixture.snapshot,
        action_ref,
        policy_revision: batch.evidence.policy_revision(),
        now,
    };
    let resource_query = |now| ResourceProofQuery {
        binding: &fixture.binding,
        snapshot: &fixture.snapshot,
        action_ref,
        resource_type: &batch.grants[0].resource_type,
        resource_key: &batch.grants[0].resource_key,
        operation_id: &batch.grants[0].operation_id,
        view_profile: &batch.grants[0].view_profile,
        policy_revision: &batch.grants[0].policy_revision,
        now,
    };
    assert!(matches!(
        store
            .load_ui_action(action_query(UnixSeconds::new(EXPIRES)))
            .await
            .unwrap(),
        UiActionProofState::Denied(ProvenanceError::ActionUnavailable)
    ));
    assert!(matches!(
        store
            .load_resource_grant(resource_query(UnixSeconds::new(EXPIRES)))
            .await
            .unwrap(),
        ResourceProofState::Denied(GrantDenied::CapabilityMissing)
    ));
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(pool)
            .await
            .unwrap();
    let stale_now = UnixSeconds::new(u64::try_from(database_now - 60).unwrap());
    for (statement, reference) in [
        (
            "UPDATE xshield.ui_actions
             SET issued_at = to_timestamp($4 - 120), expires_at = to_timestamp($4 - 1)
             WHERE tenant_id = $1 AND site_id = $2 AND action_ref = $3",
            action_ref.as_str(),
        ),
        (
            "UPDATE xshield.response_evidence
             SET verified_at = to_timestamp($4 - 120), expires_at = to_timestamp($4 - 1)
             WHERE tenant_id = $1 AND site_id = $2 AND response_evidence_id = $3",
            batch.evidence.evidence_id().as_str(),
        ),
    ] {
        // The single shared connection exposes each temporary expiry to the store.
        sqlx::query("BEGIN").execute(pool).await.unwrap();
        sqlx::query(statement)
            .bind(fixture.tenant.as_str())
            .bind(fixture.site.as_str())
            .bind(reference)
            .bind(database_now)
            .execute(pool)
            .await
            .unwrap();
        assert!(matches!(
            store.load_ui_action(action_query(stale_now)).await.unwrap(),
            UiActionProofState::Denied(ProvenanceError::ActionUnavailable)
        ));
        sqlx::query("ROLLBACK").execute(pool).await.unwrap();
    }

    sqlx::query("BEGIN").execute(pool).await.unwrap();
    // Keep the issuance-order join valid so expiry is the reason this grant fails.
    sqlx::query(
        "UPDATE xshield.ui_actions SET issued_at = to_timestamp($4 - 120)
         WHERE tenant_id = $1 AND site_id = $2 AND action_ref = $3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(action_ref.as_str())
    .bind(database_now)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE xshield.resource_grants
         SET issued_at = to_timestamp($4 - 119), expires_at = to_timestamp($4 - 1)
         WHERE tenant_id = $1 AND site_id = $2 AND action_ref = $3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(action_ref.as_str())
    .bind(database_now)
    .execute(pool)
    .await
    .unwrap();
    let wrong_operation = OperationId::parse("orders.update").unwrap();
    for operation_id in [&batch.grants[0].operation_id, &wrong_operation] {
        assert!(matches!(
            store
                .load_resource_grant(ResourceProofQuery {
                    operation_id,
                    ..resource_query(stale_now)
                })
                .await
                .unwrap(),
            ResourceProofState::Denied(GrantDenied::CapabilityMissing)
        ));
    }
    sqlx::query("ROLLBACK").execute(pool).await.unwrap();
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn response_grant_batch_is_atomic_replayable_and_usable() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL required");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .unwrap();
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let fixture = fixture();
    seed(&pool, &fixture).await;
    let policy_revision = PolicyRevision::parse("policy-r1").unwrap();

    assert!(
        store
            .load_response_action_descriptor(ResponseActionDescriptorQuery {
                tenant_id: &fixture.tenant,
                site_id: &fixture.site,
                action_id: fixture.descriptor.action_id(),
                operation_id: fixture.descriptor.operation_id(),
                policy_revision: &policy_revision,
                mapping_revision: &MappingRevision::parse("mapping-r1").unwrap(),
            })
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .load_response_action_descriptor(ResponseActionDescriptorQuery {
                tenant_id: &fixture.tenant,
                site_id: &fixture.site,
                action_id: fixture.descriptor.action_id(),
                operation_id: fixture.descriptor.operation_id(),
                policy_revision: &policy_revision,
                mapping_revision: &MappingRevision::parse("mapping-r2").unwrap(),
            })
            .await
            .unwrap()
            .is_none()
    );

    let first = batch(&fixture, 620);
    assert_eq!(
        issue(&store, &first, "artifact_response", 1).await.unwrap(),
        ResponseGrantWriteOutcome::CapacityExceeded
    );
    assert_eq!(count(&pool, "response_evidence").await, 0);

    let duplicate_event = first.event_ids[0].clone();
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, 'fixture', 'fixture', '{}')",
    )
    .bind(duplicate_event.as_str())
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        issue(&store, &first, "artifact_response", 2).await,
        Err(StoreError::Database(_))
    ));
    assert_eq!(count(&pool, "response_evidence").await, 0);
    assert_eq!(count(&pool, "resource_grants").await, 0);
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(duplicate_event.as_str())
        .execute(&pool)
        .await
        .unwrap();

    let ResponseGrantWriteOutcome::Created(created) =
        issue(&store, &first, "artifact_response", 2).await.unwrap()
    else {
        panic!("the exact batch must commit");
    };
    assert_eq!(created.len(), 2);
    assert_eq!(count(&pool, "response_evidence").await, 1);
    assert_eq!(count(&pool, "ui_actions").await, 2);
    assert_eq!(count(&pool, "resource_grants").await, 2);
    assert_eq!(count(&pool, "audit_outbox").await, 2);

    let retry = batch(&fixture, 630);
    let ResponseGrantWriteOutcome::Existing(existing) =
        issue(&store, &retry, "artifact_response", 2).await.unwrap()
    else {
        panic!("an exact retry must return the committed references");
    };
    assert_eq!(existing, created);
    assert_eq!(
        issue(&store, &retry, "different_artifact", 2)
            .await
            .unwrap(),
        ResponseGrantWriteOutcome::Conflict
    );

    let action_state = store
        .load_ui_action(UiActionProofQuery {
            binding: &fixture.binding,
            snapshot: &fixture.snapshot,
            action_ref: &created[0].action_ref,
            policy_revision: first.evidence.policy_revision(),
            now: UnixSeconds::new(NOW),
        })
        .await
        .unwrap();
    assert!(matches!(action_state, UiActionProofState::Verified(_)));
    let resource_state = store
        .load_resource_grant(ResourceProofQuery {
            binding: &fixture.binding,
            snapshot: &fixture.snapshot,
            action_ref: &created[0].action_ref,
            resource_type: &first.grants[0].resource_type,
            resource_key: &first.grants[0].resource_key,
            operation_id: &first.grants[0].operation_id,
            view_profile: &first.grants[0].view_profile,
            policy_revision: &first.grants[0].policy_revision,
            now: UnixSeconds::new(NOW),
        })
        .await
        .unwrap();
    assert!(matches!(resource_state, ResourceProofState::Verified(_)));
    assert_response_expiry_reads(&pool, &store, &fixture, &first, &created[0].action_ref).await;

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
    let stale = batch(&fixture, 640);
    assert_eq!(
        issue(&store, &stale, "artifact_response", 4).await.unwrap(),
        ResponseGrantWriteOutcome::Ineligible
    );
}
