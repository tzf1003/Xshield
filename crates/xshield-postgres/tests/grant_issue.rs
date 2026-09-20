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

const TRACE: &str = "018f2a3b4c5d70008000000000000210";

struct Fixture {
    now: u64,
    tenant: TenantId,
    site: SiteId,
    binding_id: AuthBindingId,
    action_ref: ActionRef,
    binding: AuthBinding,
    snapshot: AuthSnapshot,
}

fn fixture(now: u64) -> Fixture {
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
        xshield_core::identity::AuthorizationContextRef::parse("context_grant").unwrap(),
        AuthEpoch::new(4),
        CredentialGeneration::new(2),
        credentials.clone(),
        UnixSeconds::new(now + 2000),
    )
    .unwrap();
    let snapshot = binding
        .verify(
            &tenant,
            &site,
            &session_id,
            &credentials,
            UnixSeconds::new(now),
        )
        .unwrap();
    Fixture {
        now,
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

fn draft(fixture: &Fixture, value: u64, issuance_key: &str, resource_byte: char) -> GrantDraft {
    GrantDraft {
        grant_id: GrantId::parse(format!("grant_018f2a3b-4c5d-7000-8000-{value:012x}")).unwrap(),
        issuance_key: IssuanceKey::parse(issuance_key).unwrap(),
        resource_type: ResourceType::parse("order").unwrap(),
        resource_key: ResourceKeyHmac::parse(&resource_byte.to_string().repeat(64)).unwrap(),
        operation_id: OperationId::parse("orders.read").unwrap(),
        view_profile: ViewProfile::parse("customer_detail").unwrap(),
        source_request_id: RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000210").unwrap(),
        policy_revision: PolicyRevision::parse("policy-r1").unwrap(),
        expires_at: UnixSeconds::new(fixture.now + 1000),
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
            authorization_context_ref, auth_epoch, credential_generation, status,
            absolute_expires_at
         ) VALUES ($1, $2, $3, $4, 'principal_grant', 'context_grant',
                   4, 2, 'active', to_timestamp($5))",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .bind([17_u8; 32].as_slice())
    .bind(i64::try_from(fixture.now + 2000).unwrap())
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
    .bind(i64::try_from(fixture.now - 1).unwrap())
    .bind(i64::try_from(fixture.now + 2000).unwrap())
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
    .bind(i64::try_from(fixture.now - 1).unwrap())
    .bind(i64::try_from(fixture.now + 2000).unwrap())
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
    issue_with_trace(
        store,
        fixture,
        draft,
        event_id,
        capacity,
        fixture.now,
        TRACE,
    )
    .await
}

async fn issue_with_trace(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    draft: &GrantDraft,
    event_id: &EventId,
    capacity: u32,
    now: u64,
    trace: &str,
) -> Result<GrantWriteOutcome, StoreError> {
    let constraints = json!({
        "nested": {"large": 1e18, "decimal": 0.25, "negative_zero": -0.0},
        "label": "订单", "fields": ["id"], "max": u64::MAX,
    });
    store
        .issue_grant(GrantPersistence::new(
            &fixture.snapshot,
            draft,
            &fixture.action_ref,
            &constraints,
            event_id,
            trace,
            UnixSeconds::new(now),
            capacity,
        )?)
        .await
}

async fn grant_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM xshield.resource_grants WHERE tenant_id = 'tenant_grant' AND site_id = 'site_grant'")
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
            &draft(fixture, 221, "issue-rollback", '1'),
            &rollback_event,
            1,
        )
        .await,
        Err(StoreError::Database(_))
    ));
    assert_eq!(grant_count(pool).await, 0);
}

async fn assert_expanded_constraints_are_bounded(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    // JSONB expands exponent notation. Bound the retained representation as
    // well as the small input encoding before any grant or event is written.
    let constraints = json!({"values": vec![1e308; 60]});
    let draft = draft(fixture, 236, "issue-expanded", '8');
    let event = event_id(237);
    let command = GrantPersistence::new(
        &fixture.snapshot,
        &draft,
        &fixture.action_ref,
        &constraints,
        &event,
        TRACE,
        UnixSeconds::new(fixture.now),
        1,
    )
    .unwrap();
    assert!(matches!(
        store.issue_grant(command).await,
        Err(StoreError::InvalidCommand)
    ));
    assert_eq!(grant_count(pool).await, 0);
    let events: i64 =
        sqlx::query_scalar("SELECT count(*) FROM xshield.audit_outbox WHERE event_id = $1")
            .bind(event.as_str())
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(events, 0);
}

async fn assert_capacity_is_serialized(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    sqlx::query("UPDATE xshield.resource_grants SET status = 'revoked' WHERE tenant_id = 'tenant_grant' AND site_id = 'site_grant'")
        .execute(pool)
        .await
        .unwrap();
    let left_draft = draft(fixture, 225, "issue-left", '4');
    let right_draft = draft(fixture, 226, "issue-right", '5');
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
            now: UnixSeconds::new(fixture.now),
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
                    now: UnixSeconds::new(fixture.now),
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
                now: UnixSeconds::new(fixture.now),
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
                now: UnixSeconds::new(fixture.now),
            })
            .await
            .unwrap(),
        ResourceProofState::Denied(GrantDenied::CapabilityMissing)
    ));
}

async fn wait_for_blocked_issuer(pool: &PgPool, blocker_pid: i32) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                 WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker_pid)
            .fetch_one(pool)
            .await
            .unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("grant issuer must reach the held lock");
}

async fn assert_replay_guards(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    existing: &GrantDraft,
    event: &EventId,
) {
    let mut different_id = draft(fixture, 233, "issue-first", '2');
    assert_eq!(
        issue(store, fixture, &different_id, event, 1)
            .await
            .unwrap(),
        GrantWriteOutcome::Conflict
    );
    different_id.grant_id = existing.grant_id.clone();
    assert_eq!(
        issue_with_trace(
            store,
            fixture,
            &different_id,
            event,
            1,
            fixture.now + 1,
            TRACE
        )
        .await
        .unwrap(),
        GrantWriteOutcome::Conflict
    );

    // Revocation is serialized ahead of an idempotent replay, which must check
    // the updated row instead of returning a prior snapshot's active state.
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("UPDATE xshield.resource_grants SET status = 'revoked' WHERE tenant_id = $1 AND site_id = $2 AND grant_id = $3")
        .bind(fixture.tenant.as_str()).bind(fixture.site.as_str()).bind(existing.grant_id.as_str())
        .execute(&mut *blocker).await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let (outcome, ()) = tokio::time::timeout(Duration::from_secs(8), async {
        tokio::join!(issue(store, fixture, existing, event, 1), async {
            wait_for_blocked_issuer(pool, pid).await;
            blocker.commit().await.unwrap();
        })
    })
    .await
    .unwrap();
    assert_eq!(outcome.unwrap(), GrantWriteOutcome::Ineligible);
    sqlx::query("UPDATE xshield.resource_grants SET status = 'active' WHERE tenant_id = $1 AND site_id = $2 AND grant_id = $3")
        .bind(fixture.tenant.as_str()).bind(fixture.site.as_str()).bind(existing.grant_id.as_str())
        .execute(pool).await.unwrap();

    for (sql, key, inactive) in [
        (
            "UPDATE xshield.ui_actions SET status = $4 WHERE tenant_id = $1 AND site_id = $2 AND action_ref = $3",
            fixture.action_ref.as_str(),
            "revoked",
        ),
        (
            "UPDATE xshield.policy_revisions SET status = $4 WHERE tenant_id = $1 AND site_id = $2 AND revision = $3",
            "policy-r1",
            "retired",
        ),
    ] {
        sqlx::query(sql)
            .bind(fixture.tenant.as_str())
            .bind(fixture.site.as_str())
            .bind(key)
            .bind(inactive)
            .execute(pool)
            .await
            .unwrap();
        for (candidate, candidate_event) in [
            (existing, event),
            (&draft(fixture, 234, "issue-inactive", '3'), &event_id(235)),
        ] {
            assert_eq!(
                issue(store, fixture, candidate, candidate_event, 10)
                    .await
                    .unwrap(),
                GrantWriteOutcome::Ineligible
            );
        }
        sqlx::query(sql)
            .bind(fixture.tenant.as_str())
            .bind(fixture.site.as_str())
            .bind(key)
            .bind("active")
            .execute(pool)
            .await
            .unwrap();
    }
    assert_outbox_replay_links(pool, store, fixture, existing, event).await;
}

async fn assert_outbox_replay_links(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    existing: &GrantDraft,
    event: &EventId,
) {
    // PostgreSQL epoch-to-bigint rounding must not hide subsecond drift in
    // persisted times when replay requires exact frozen issuance semantics.
    for sql in [
        "UPDATE xshield.resource_grants SET issued_at = issued_at + $2::double precision * interval '1 second' WHERE grant_id = $1",
        "UPDATE xshield.resource_grants SET expires_at = expires_at + $2::double precision * interval '1 second' WHERE grant_id = $1",
    ] {
        sqlx::query(sql)
            .bind(existing.grant_id.as_str())
            .bind(0.25_f64)
            .execute(pool)
            .await
            .unwrap();
        assert_eq!(
            issue(store, fixture, existing, event, 1).await.unwrap(),
            GrantWriteOutcome::Conflict
        );
        sqlx::query(sql)
            .bind(existing.grant_id.as_str())
            .bind(-0.25_f64)
            .execute(pool)
            .await
            .unwrap();
    }
    for (sql, original) in [
        (
            "UPDATE xshield.audit_outbox SET aggregate_ref = $2 WHERE event_id = $1",
            existing.grant_id.as_str(),
        ),
        (
            "UPDATE xshield.audit_outbox SET event_type = $2 WHERE event_id = $1",
            "grant.issued",
        ),
    ] {
        sqlx::query(sql)
            .bind(event.as_str())
            .bind("fixture-corrupt")
            .execute(pool)
            .await
            .unwrap();
        assert!(matches!(
            issue(store, fixture, existing, event, 1).await,
            Err(StoreError::CorruptData("grant_outbox"))
        ));
        sqlx::query(sql)
            .bind(event.as_str())
            .bind(original)
            .execute(pool)
            .await
            .unwrap();
    }
    assert_eq!(grant_count(pool).await, 1);
    assert_eq!(
        issue(store, fixture, existing, event, 1).await.unwrap(),
        GrantWriteOutcome::Existing(existing.grant_id.clone())
    );
}

async fn assert_lock_wait_expiry_rejected(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    for (index, lock) in ["binding", "replay", "outbox"].into_iter().enumerate() {
        let value = 240 + u64::try_from(index).unwrap() * 2;
        let mut pending = draft(fixture, value, &format!("issue-expiry-{lock}"), '7');
        pending.expires_at = UnixSeconds::new(database_now(pool).await + 3);
        let event = event_id(value + 1);
        if lock == "replay" {
            assert!(matches!(
                issue(store, fixture, &pending, &event, 10).await.unwrap(),
                GrantWriteOutcome::Created(_)
            ));
        }
        let before = grant_count(pool).await;
        let mut blocker = pool.begin().await.unwrap();
        let statement = match lock {
            "binding" => {
                "SELECT 1 FROM xshield.auth_bindings WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3 FOR UPDATE"
            }
            "replay" => {
                "SELECT 1 FROM xshield.resource_grants WHERE tenant_id = $1 AND site_id = $2 AND grant_id = $3 FOR UPDATE"
            }
            _ => {
                "INSERT INTO xshield.audit_outbox (tenant_id, site_id, event_id, aggregate_ref, event_type, envelope) VALUES ($1, $2, $3, 'expiry-blocker', 'fixture', '{}')"
            }
        };
        let key = match lock {
            "binding" => fixture.binding_id.as_str(),
            "replay" => pending.grant_id.as_str(),
            _ => event.as_str(),
        };
        sqlx::query(statement)
            .bind(fixture.tenant.as_str())
            .bind(fixture.site.as_str())
            .bind(key)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        // Observe a real SQL wait at each boundary before exhausting its TTL.
        let (outcome, ()) = tokio::time::timeout(Duration::from_secs(8), async {
            tokio::join!(issue(store, fixture, &pending, &event, 10), async {
                wait_for_blocked_issuer(pool, blocker_pid).await;
                while database_now(pool).await < pending.expires_at.value() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                blocker.rollback().await.unwrap();
            })
        })
        .await
        .expect("grant lock expiry check must finish within eight seconds");
        assert_eq!(outcome.unwrap(), GrantWriteOutcome::Ineligible, "{lock}");
        assert_eq!(grant_count(pool).await, before);
        let events: i64 =
            sqlx::query_scalar("SELECT count(*) FROM xshield.audit_outbox WHERE event_id = $1")
                .bind(event.as_str())
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(events, i64::from(lock == "replay"));
    }
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
    let fixture = fixture(database_now(&pool).await);
    seed_eligibility(&pool, &fixture).await;

    assert_outbox_failure_rolls_back(&pool, &store, &fixture).await;
    assert_expanded_constraints_are_bounded(&pool, &store, &fixture).await;

    let first_draft = draft(&fixture, 222, "issue-first", '2');
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
    assert_eq!(
        issue_with_trace(
            &store,
            &fixture,
            &first_draft,
            &first_event,
            1,
            fixture.now,
            "118f2a3b4c5d70008000000000000210",
        )
        .await
        .unwrap(),
        GrantWriteOutcome::Conflict
    );
    assert_resource_grant_reads(&store, &fixture, &first_draft).await;
    assert_replay_guards(&pool, &store, &fixture, &first_draft, &first_event).await;
    assert_eq!(
        issue(
            &store,
            &fixture,
            &draft(&fixture, 224, "issue-first", '3'),
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
            &draft(&fixture, 229, "issue-stale", '6'),
            &event_id(230),
            2,
        )
        .await
        .unwrap(),
        GrantWriteOutcome::Ineligible
    );

    sqlx::query("UPDATE xshield.auth_bindings SET auth_epoch = 4 WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3")
        .bind(fixture.tenant.as_str()).bind(fixture.site.as_str())
        .bind(fixture.binding_id.as_str()).execute(&pool).await.unwrap();
    assert_lock_wait_expiry_rejected(&pool, &store, &fixture).await;
}

async fn database_now(pool: &PgPool) -> u64 {
    let seconds: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(pool)
            .await
            .unwrap();
    u64::try_from(seconds).unwrap()
}

#[test]
fn grant_command_validates_trace_constraints_and_lease_before_io() {
    let fixture = fixture(1_800_000_000);
    let mut draft = draft(&fixture, 250, "issue-validation", '8');
    let event = event_id(251);
    for (constraints, trace, now, capacity) in [
        (json!([]), TRACE, fixture.now, 1),
        (
            json!({"value": "x".repeat(16 * 1024)}),
            TRACE,
            fixture.now,
            1,
        ),
        (
            json!({}),
            "ABCDEF0123456789abcdef0123456789",
            fixture.now,
            1,
        ),
        (json!({}), "short", fixture.now, 1),
        (json!({}), TRACE, fixture.now + 1000, 1),
        (json!({}), TRACE, fixture.now - 86_400, 1),
        (json!({}), TRACE, fixture.now, 0),
    ] {
        assert!(matches!(
            GrantPersistence::new(
                &fixture.snapshot,
                &draft,
                &fixture.action_ref,
                &constraints,
                &event,
                trace,
                UnixSeconds::new(now),
                capacity
            ),
            Err(StoreError::InvalidCommand)
        ));
    }
    for ttl in [1, 86_400] {
        draft.expires_at = UnixSeconds::new(fixture.now + ttl);
        assert!(
            GrantPersistence::new(
                &fixture.snapshot,
                &draft,
                &fixture.action_ref,
                &json!({"filter": {"active": true}}),
                &event,
                TRACE,
                UnixSeconds::new(fixture.now),
                1
            )
            .is_ok()
        );
    }
    draft.expires_at = UnixSeconds::new(u64::MAX);
    assert!(matches!(
        GrantPersistence::new(
            &fixture.snapshot,
            &draft,
            &fixture.action_ref,
            &json!({}),
            &event,
            TRACE,
            UnixSeconds::new(u64::MAX - 1),
            1
        ),
        Err(StoreError::InvalidCommand)
    ));
}
