use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
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
    timed_batch(
        fixture,
        id_offset,
        610,
        NOW,
        EXPIRES,
        [(EXPIRES, EXPIRES); 2],
    )
}

fn timed_batch(
    fixture: &Fixture,
    id_offset: u64,
    source_id: u64,
    now: u64,
    evidence_expires: u64,
    item_expiries: [(u64, u64); 2],
) -> Batch {
    let source_request =
        RequestId::parse(format!("req_018f2a3b-4c5d-7000-8000-{source_id:012x}")).unwrap();
    let evidence = ResponseEvidence::verified(
        ResponseEvidenceId::parse(format!("response_018f2a3b-4c5d-7000-8000-{id_offset:012x}"))
            .unwrap(),
        &fixture.binding,
        fixture.snapshot.clone(),
        source_request.clone(),
        OperationId::parse("orders.list").unwrap(),
        OperationId::parse("orders.read").unwrap(),
        200,
        PolicyRevision::parse("policy-r1").unwrap(),
        UnixSeconds::new(evidence_expires),
        UnixSeconds::new(now),
    )
    .unwrap();
    let mut actions = Vec::new();
    let mut grants = Vec::new();
    let mut event_ids = Vec::new();
    for (index, (action_expires, grant_expires)) in item_expiries.into_iter().enumerate() {
        let index = u64::try_from(index).unwrap();
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
                expires_at: UnixSeconds::new(action_expires),
            },
            UnixSeconds::new(now),
        )
        .unwrap();
        actions.push(action);
        grants.push(GrantDraft {
            grant_id: GrantId::parse(format!(
                "grant_018f2a3b-4c5d-7000-8000-{:012x}",
                id_offset + index + 100
            ))
            .unwrap(),
            issuance_key: IssuanceKey::parse(format!("orders-list-{source_id}-item-{index}"))
                .unwrap(),
            resource_type: ResourceType::parse("order").unwrap(),
            resource_key: key,
            operation_id: OperationId::parse("orders.read").unwrap(),
            view_profile: ViewProfile::parse("customer_detail").unwrap(),
            source_request_id: source_request.clone(),
            policy_revision: PolicyRevision::parse("policy-r1").unwrap(),
            expires_at: UnixSeconds::new(grant_expires),
        });
        event_ids.push(
            EventId::parse(format!(
                "ev_018f2a3b-4c5d-7000-8001-{:012x}",
                source_id + 1000 + index
            ))
            .unwrap(),
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
            batch.evidence.verified_at(),
            capacity,
        )?)
        .await
}

#[test]
fn response_batch_rejects_expanded_or_elapsed_item_leases() {
    let fixture = fixture();
    for invalid in 0..3 {
        let mut batch = timed_batch(
            &fixture,
            1700,
            1700,
            NOW,
            NOW + 100,
            [(NOW + 80, NOW + 60); 2],
        );
        match invalid {
            0 => batch.grants[0].expires_at = UnixSeconds::new(NOW + 81),
            1 => {
                // Reusing an evidence ID must still preserve this command's shorter lease.
                batch.evidence = ResponseEvidence::verified(
                    batch.evidence.evidence_id().clone(),
                    &fixture.binding,
                    fixture.snapshot.clone(),
                    batch.evidence.source_request_id().clone(),
                    batch.evidence.source_operation_id().clone(),
                    batch.evidence.target_operation_id().clone(),
                    batch.evidence.response_status(),
                    batch.evidence.policy_revision().clone(),
                    UnixSeconds::new(NOW + 70),
                    UnixSeconds::new(NOW),
                )
                .unwrap();
            }
            _ => batch.grants[0].expires_at = UnixSeconds::new(NOW),
        }
        let items = (0..batch.actions.len())
            .map(|index| {
                ResponseGrantItem::new(
                    &batch.actions[index],
                    &batch.grants[index],
                    &batch.constraints[index],
                    &batch.event_ids[index],
                    &batch.envelopes[index],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            ResponseGrantPersistence::new(
                &batch.evidence,
                "artifact_invalid_lease",
                &items,
                UnixSeconds::new(NOW),
                100,
            ),
            Err(StoreError::InvalidCommand)
        ));
    }
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

async fn database_now(pool: &PgPool) -> u64 {
    u64::try_from(
        sqlx::query_scalar::<_, i64>("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(pool)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn assert_batch_rows(pool: &PgPool, batch: &Batch, expected: (i64, i64, i64, i64)) {
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
         (SELECT count(*) FROM xshield.response_evidence WHERE response_evidence_id = $1
          AND tenant_id = $4 AND site_id = $5),
         (SELECT count(*) FROM xshield.ui_actions WHERE response_evidence_id = $1
          AND tenant_id = $4 AND site_id = $5),
         (SELECT count(*) FROM xshield.resource_grants WHERE grant_id = ANY($2)
          AND tenant_id = $4 AND site_id = $5),
         (SELECT count(*) FROM xshield.audit_outbox WHERE event_id = ANY($3)
          AND tenant_id = $4 AND site_id = $5)",
    )
    .bind(batch.evidence.evidence_id().as_str())
    .bind(
        batch
            .grants
            .iter()
            .map(|grant| grant.grant_id.as_str())
            .collect::<Vec<_>>(),
    )
    .bind(
        batch
            .event_ids
            .iter()
            .map(EventId::as_str)
            .collect::<Vec<_>>(),
    )
    .bind(batch.evidence.snapshot().tenant_id().as_str())
    .bind(batch.evidence.snapshot().site_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(counts, expected);
}

async fn wait_for_blocked_issuer(pool: &PgPool, blocker: &mut Transaction<'_, Postgres>) {
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **blocker)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .fetch_one(pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("issuer must reach the held lock");
}

async fn release_after_expiry(
    pool: &PgPool,
    mut blocker: Transaction<'_, Postgres>,
    deadline: u64,
) {
    wait_for_blocked_issuer(pool, &mut blocker).await;
    sqlx::query(
        "SELECT pg_sleep(GREATEST(0, $1::double precision + 0.05 - extract(epoch FROM clock_timestamp())))",
    )
    .bind(i64::try_from(deadline).unwrap())
    .execute(&mut *blocker)
    .await
    .unwrap();
    blocker.rollback().await.unwrap();
}

async fn assert_create_waits_expire_atomically(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    for outbox_wait in [false, true] {
        let now = database_now(pool).await;
        let deadline = now + 3;
        let id = if outbox_wait { 1100 } else { 1000 };
        let evidence_expires = if outbox_wait { now + 120 } else { deadline };
        let pending = timed_batch(
            fixture,
            id,
            id,
            now,
            evidence_expires,
            [
                (evidence_expires, evidence_expires),
                (evidence_expires, deadline),
            ],
        );
        let mut blocker = pool.begin().await.unwrap();
        if outbox_wait {
            // The second event blocks after earlier batch rows have been inserted.
            sqlx::query(
                "INSERT INTO xshield.audit_outbox
                 (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
                 VALUES ($1, $2, $3, 'fixture', 'fixture', '{}')",
            )
            .bind(pending.event_ids[1].as_str())
            .bind(fixture.tenant.as_str())
            .bind(fixture.site.as_str())
            .execute(&mut *blocker)
            .await
            .unwrap();
        } else {
            sqlx::query("SELECT 1 FROM xshield.auth_bindings WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3 FOR UPDATE")
                .bind(fixture.tenant.as_str()).bind(fixture.site.as_str())
                .bind(fixture.binding_id.as_str()).execute(&mut *blocker).await.unwrap();
        }
        let (outcome, ()) = tokio::time::timeout(Duration::from_secs(8), async {
            tokio::join!(
                issue(store, &pending, "artifact_expiring_response", 100),
                release_after_expiry(pool, blocker, deadline),
            )
        })
        .await
        .expect("expired issuance must finish after lock release");
        assert_eq!(outcome.unwrap(), ResponseGrantWriteOutcome::Ineligible);
        assert_batch_rows(pool, &pending, (0, 0, 0, 0)).await;
    }
}

async fn assert_existing_waits_recheck_expiry(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    for item_wait in [false, true] {
        let now = database_now(pool).await;
        let deadline = now + 3;
        let id = if item_wait { 1400 } else { 1300 };
        let batch = timed_batch(
            fixture,
            id,
            id,
            now,
            now + 120,
            [(now + 120, now + 120), (now + 120, deadline)],
        );
        assert!(matches!(
            issue(store, &batch, "artifact_existing_response", 100)
                .await
                .unwrap(),
            ResponseGrantWriteOutcome::Created(_)
        ));
        let mut blocker = pool.begin().await.unwrap();
        let (statement, reference) = if item_wait {
            (
                "SELECT 1 FROM xshield.resource_grants WHERE grant_id = $1 FOR UPDATE",
                batch.grants[1].grant_id.as_str(),
            )
        } else {
            (
                "SELECT 1 FROM xshield.response_evidence WHERE response_evidence_id = $1 FOR UPDATE",
                batch.evidence.evidence_id().as_str(),
            )
        };
        sqlx::query(statement)
            .bind(reference)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let (outcome, ()) = tokio::time::timeout(Duration::from_secs(8), async {
            tokio::join!(
                issue(store, &batch, "artifact_existing_response", 100),
                release_after_expiry(pool, blocker, deadline),
            )
        })
        .await
        .expect("existing issuance must finish after lock release");
        assert_eq!(outcome.unwrap(), ResponseGrantWriteOutcome::Ineligible);
        assert_batch_rows(pool, &batch, (1, 2, 2, 2)).await;
    }
}

async fn assert_existing_waits_for_revocation(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    for action_revoked in [false, true] {
        let now = database_now(pool).await;
        let id = if action_revoked { 1600 } else { 1500 };
        let batch = timed_batch(fixture, id, id, now, now + 120, [(now + 120, now + 120); 2]);
        assert!(matches!(
            issue(store, &batch, "artifact_revocable_response", 100)
                .await
                .unwrap(),
            ResponseGrantWriteOutcome::Created(_)
        ));
        let mut blocker = pool.begin().await.unwrap();
        let (statement, reference) = if action_revoked {
            (
                "UPDATE xshield.ui_actions SET status = 'revoked' WHERE action_ref = $1",
                batch.actions[1].action_ref().as_str(),
            )
        } else {
            (
                "UPDATE xshield.resource_grants SET status = 'revoked' WHERE grant_id = $1",
                batch.grants[1].grant_id.as_str(),
            )
        };
        sqlx::query(statement)
            .bind(reference)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let (outcome, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                issue(store, &batch, "artifact_revocable_response", 100),
                async {
                    wait_for_blocked_issuer(pool, &mut blocker).await;
                    blocker.commit().await.unwrap();
                }
            )
        })
        .await
        .expect("existing issuance must finish after revocation");
        assert_eq!(outcome.unwrap(), ResponseGrantWriteOutcome::Conflict);
        assert_batch_rows(pool, &batch, (1, 2, 2, 2)).await;
    }
}

async fn assert_individual_leases(pool: &PgPool, store: &PostgresIdentityStore, fixture: &Fixture) {
    let now = database_now(pool).await;
    let batch = timed_batch(
        fixture,
        1200,
        1200,
        now,
        now + 120,
        [(now + 100, now + 90), (now + 80, now + 70)],
    );
    let created = issue(store, &batch, "artifact_short_items", 100)
        .await
        .unwrap();
    let ResponseGrantWriteOutcome::Created(references) = created else {
        panic!("live item-local leases must issue");
    };
    for (action, grant) in batch.actions.iter().zip(&batch.grants) {
        let expires: (i64, i64) = sqlx::query_as(
            "SELECT extract(epoch FROM action.expires_at)::bigint,
                    extract(epoch FROM grant_row.expires_at)::bigint
             FROM xshield.ui_actions action JOIN xshield.resource_grants grant_row
               ON grant_row.action_ref = action.action_ref
             WHERE grant_row.grant_id = $1",
        )
        .bind(grant.grant_id.as_str())
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            expires,
            (
                i64::try_from(action.expires_at().value()).unwrap(),
                i64::try_from(grant.expires_at.value()).unwrap()
            )
        );
    }
    assert_eq!(
        issue(store, &batch, "artifact_short_items", 100)
            .await
            .unwrap(),
        ResponseGrantWriteOutcome::Existing(references.clone())
    );
    assert_create_waits_expire_atomically(pool, store, fixture).await;
    assert_existing_waits_recheck_expiry(pool, store, fixture).await;
    assert_existing_waits_for_revocation(pool, store, fixture).await;
    assert_eq!(
        issue(store, &batch, "artifact_short_items", 100)
            .await
            .unwrap(),
        ResponseGrantWriteOutcome::Existing(references)
    );
    assert_batch_rows(pool, &batch, (1, 2, 2, 2)).await;
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

    let concurrent_pool = PgPool::connect(&database_url).await.unwrap();
    assert_individual_leases(&concurrent_pool, &store, &fixture).await;
    concurrent_pool.close().await;

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
