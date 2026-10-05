use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    time::Duration,
};
use xshield_core::{
    domain::{
        ActionId, ActionRef, AuthBindingId, EventId, FieldName, MappingRevision, OperationId,
        PageEvidenceId, PageTemplate, PolicyRevision, RequestId, SiteId, TenantId, ViewProfile,
        WafSessionId,
    },
    identity::{
        AuthBinding, AuthEpoch, AuthSnapshot, CredentialFingerprint, CredentialGeneration,
        CredentialSlot, UnixSeconds,
    },
    ports::{UiActionProofQuery, UiActionProofState, UiActionProofStore},
    provenance::{
        ActionDescriptor, ActionGrant, ActionGrantDraft, ActionTarget, ActionTargetRule,
        BuildFingerprint, HttpMethod, PageEvidence, ProvenanceError, RouteTemplate,
    },
};
use xshield_postgres::{
    PostgresIdentityStore, ProvenancePersistence, ProvenanceWriteOutcome, StoreError,
};

const NOW: u64 = 1_800_000_000;

struct Fixture {
    now: u64,
    tenant: TenantId,
    site: SiteId,
    binding_id: AuthBindingId,
    binding: AuthBinding,
    snapshot: AuthSnapshot,
    evidence: PageEvidence,
    descriptor: ActionDescriptor,
}

fn credentials() -> BTreeMap<CredentialSlot, CredentialFingerprint> {
    BTreeMap::from([(
        CredentialSlot::Cookie,
        CredentialFingerprint::parse(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
    )])
}

fn fixture() -> Fixture {
    fixture_at("tenant_provenance", NOW)
}

fn fixture_at(tenant: &str, now: u64) -> Fixture {
    let tenant = TenantId::parse(tenant).unwrap();
    let site = SiteId::parse("site_provenance").unwrap();
    let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000401").unwrap();
    let session = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000402").unwrap();
    let binding = AuthBinding::new(
        binding_id.clone(),
        session.clone(),
        tenant.clone(),
        site.clone(),
        "principal_provenance",
        xshield_core::identity::AuthorizationContextRef::parse("context_provenance").unwrap(),
        AuthEpoch::new(4),
        CredentialGeneration::new(2),
        credentials(),
        UnixSeconds::new(now + 2_000),
    )
    .unwrap();
    let snapshot = binding
        .verify(
            &tenant,
            &site,
            &session,
            &credentials(),
            UnixSeconds::new(now),
        )
        .unwrap();
    let evidence = PageEvidence::verified(
        PageEvidenceId::parse("page_018f2a3b-4c5d-7000-8000-000000000403").unwrap(),
        &binding,
        snapshot.clone(),
        RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000404").unwrap(),
        PageTemplate::parse("settings_page").unwrap(),
        BuildFingerprint::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap(),
        PolicyRevision::parse("policy-r1").unwrap(),
        MappingRevision::parse("mapping-r1").unwrap(),
        UnixSeconds::new(now + 1_500),
        UnixSeconds::new(now),
    )
    .unwrap();
    let descriptor = ActionDescriptor::approved(
        ActionId::parse("settings.change_self_password").unwrap(),
        PageTemplate::parse("settings_page").unwrap(),
        OperationId::parse("user.password.change_self").unwrap(),
        HttpMethod::Post,
        RouteTemplate::parse("/api/password/change").unwrap(),
        ActionTargetRule::VerifiedPrincipal,
        BTreeSet::from([
            FieldName::parse("current_password").unwrap(),
            FieldName::parse("new_password").unwrap(),
        ]),
        ViewProfile::parse("self_password_fields").unwrap(),
        PolicyRevision::parse("policy-r1").unwrap(),
        MappingRevision::parse("mapping-r1").unwrap(),
    );
    Fixture {
        now,
        tenant,
        site,
        binding_id,
        binding,
        snapshot,
        evidence,
        descriptor,
    }
}

impl Fixture {
    fn action(&self, action_ref: &str, expires_at: u64) -> ActionGrant {
        ActionGrant::issue(
            &self.binding,
            &self.snapshot,
            &self.evidence,
            &self.descriptor,
            ActionGrantDraft {
                action_ref: ActionRef::parse(action_ref).unwrap(),
                target: ActionTarget::Principal("principal_provenance".to_owned()),
                fields: BTreeSet::from([FieldName::parse("new_password").unwrap()]),
                expires_at: UnixSeconds::new(expires_at),
            },
            UnixSeconds::new(self.now),
        )
        .unwrap()
    }
}

fn event_id(value: u64) -> EventId {
    EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{value:012x}")).unwrap()
}

async fn seed_policy_binding_and_descriptor(pool: &PgPool, fixture: &Fixture) {
    sqlx::query(
        "INSERT INTO xshield.policy_revisions (
            tenant_id, site_id, revision, status, content_digest, artifact_ref
         ) VALUES ($1, $2, 'policy-r1', 'active', $3, 'artifact_policy_r1')",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind("c".repeat(64))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.auth_bindings (
            tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
            authorization_context_ref, auth_epoch, credential_generation, status,
            absolute_expires_at
         ) VALUES ($1, $2, $3, $4, 'principal_provenance', 'context_provenance',
                   4, 2, 'active', to_timestamp($5))",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .bind([51_u8; 32].as_slice())
    .bind(i64::try_from(fixture.binding.absolute_expires_at().value()).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.action_descriptors (
            tenant_id, site_id, action_id, page_template, operation_id, method,
            route_template, target_rule, allowed_fields, field_profile,
            policy_revision, mapping_revision, status
         ) VALUES (
            $1, $2, 'settings.change_self_password', 'settings_page',
            'user.password.change_self', 'POST', '/api/password/change',
            '{\"kind\":\"verified_principal\"}',
            '[\"current_password\",\"new_password\"]', 'self_password_fields',
            'policy-r1', 'mapping-r1', 'approved'
         )",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .execute(pool)
    .await
    .unwrap();
}

async fn persist(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    action: &ActionGrant,
    event_id: &EventId,
    artifact_ref: &str,
) -> Result<ProvenanceWriteOutcome, StoreError> {
    let envelope = json!({"schema_version": 3, "event_type": "ui_action.issued"});
    store
        .persist_provenance(ProvenancePersistence::new(
            &fixture.evidence,
            action,
            artifact_ref,
            event_id,
            &envelope,
            UnixSeconds::new(fixture.now),
        )?)
        .await
}

async fn assert_outbox_failure_rolls_back(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
) {
    let event = event_id(405);
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, 'fixture', 'fixture', '{}')",
    )
    .bind(event.as_str())
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        persist(
            store,
            fixture,
            &fixture.action("action_password_rollback", 1_800_001_000),
            &event,
            "artifact_page_1",
        )
        .await,
        Err(StoreError::Database(_))
    ));
    let counts: (i64, i64) = (
        sqlx::query_scalar(
            "SELECT count(*) FROM xshield.page_evidence
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(fixture.tenant.as_str())
        .bind(fixture.site.as_str())
        .fetch_one(pool)
        .await
        .unwrap(),
        sqlx::query_scalar(
            "SELECT count(*) FROM xshield.ui_actions
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(fixture.tenant.as_str())
        .bind(fixture.site.as_str())
        .fetch_one(pool)
        .await
        .unwrap(),
    );
    assert_eq!(counts, (0, 0));
}

#[test]
fn provenance_command_rejects_missing_artifact_reference() {
    let fixture = fixture();
    let action = fixture.action("action_password_invalid", 1_800_001_000);
    let event = event_id(409);
    let envelope = json!({"schema_version": 3, "event_type": "ui_action.issued"});
    assert!(matches!(
        ProvenancePersistence::new(
            &fixture.evidence,
            &action,
            "",
            &event,
            &envelope,
            UnixSeconds::new(NOW),
        ),
        Err(StoreError::InvalidCommand)
    ));
}

async fn assert_action_expiry_reads(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    action: &ActionGrant,
) {
    let query = |now| UiActionProofQuery {
        binding: &fixture.binding,
        snapshot: &fixture.snapshot,
        action_ref: action.action_ref(),
        policy_revision: action.policy_revision(),
        now,
    };
    assert!(matches!(
        store
            .load_ui_action(query(action.expires_at()))
            .await
            .unwrap(),
        UiActionProofState::Denied(ProvenanceError::ActionUnavailable)
    ));
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(pool)
            .await
            .unwrap();
    for (statement, reference) in [
        (
            "UPDATE xshield.ui_actions
             SET issued_at = to_timestamp($4 - 120), expires_at = to_timestamp($4 - 1)
             WHERE tenant_id = $1 AND site_id = $2 AND action_ref = $3",
            action.action_ref().as_str(),
        ),
        (
            "UPDATE xshield.page_evidence
             SET verified_at = to_timestamp($4 - 120), expires_at = to_timestamp($4 - 1)
             WHERE tenant_id = $1 AND site_id = $2 AND page_evidence_id = $3",
            fixture.evidence.evidence_id().as_str(),
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
            store
                .load_ui_action(query(UnixSeconds::new(
                    u64::try_from(database_now - 60).unwrap()
                )))
                .await
                .unwrap(),
            UiActionProofState::Denied(ProvenanceError::ActionUnavailable)
        ));
        sqlx::query("ROLLBACK").execute(pool).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn provenance_is_atomic_idempotent_and_epoch_bound() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("assertion pool connects");
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let fixture = fixture();
    seed_policy_binding_and_descriptor(&pool, &fixture).await;
    assert_outbox_failure_rolls_back(&pool, &store, &fixture).await;

    let action = fixture.action("action_password_primary", 1_800_001_000);
    let event = event_id(406);
    assert_eq!(
        persist(&store, &fixture, &action, &event, "artifact_page_1")
            .await
            .unwrap(),
        ProvenanceWriteOutcome::Created
    );
    assert_eq!(
        persist(&store, &fixture, &action, &event, "artifact_page_1")
            .await
            .unwrap(),
        ProvenanceWriteOutcome::Existing
    );
    let loaded = store
        .load_ui_action(UiActionProofQuery {
            binding: &fixture.binding,
            snapshot: &fixture.snapshot,
            action_ref: action.action_ref(),
            policy_revision: action.policy_revision(),
            now: UnixSeconds::new(NOW),
        })
        .await
        .unwrap();
    assert!(matches!(loaded, UiActionProofState::Verified(found) if *found == action));
    assert_action_expiry_reads(&pool, &store, &fixture, &action).await;
    let wrong_policy = PolicyRevision::parse("policy-r2").unwrap();
    assert!(matches!(
        store
            .load_ui_action(UiActionProofQuery {
                binding: &fixture.binding,
                snapshot: &fixture.snapshot,
                action_ref: action.action_ref(),
                policy_revision: &wrong_policy,
                now: UnixSeconds::new(NOW),
            })
            .await
            .unwrap(),
        UiActionProofState::Denied(_)
    ));
    assert_eq!(
        persist(
            &store,
            &fixture,
            &action,
            &event_id(407),
            "artifact_changed"
        )
        .await
        .unwrap(),
        ProvenanceWriteOutcome::Conflict
    );

    sqlx::query(
        "DELETE FROM xshield.audit_outbox
         WHERE tenant_id = $1 AND site_id = $2 AND aggregate_ref = $3
           AND event_type = 'ui_action.issued'",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(action.action_ref().as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        persist(&store, &fixture, &action, &event, "artifact_page_1").await,
        Err(StoreError::CorruptData("ui_action_outbox"))
    ));

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
        persist(
            &store,
            &fixture,
            &fixture.action("action_password_stale", 1_800_001_000),
            &event_id(408),
            "artifact_page_1",
        )
        .await
        .unwrap(),
        ProvenanceWriteOutcome::Ineligible
    );
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

async fn provenance_counts(pool: &PgPool, fixture: &Fixture) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT
         (SELECT count(*) FROM xshield.page_evidence WHERE tenant_id = $1 AND site_id = $2),
         (SELECT count(*) FROM xshield.ui_actions WHERE tenant_id = $1 AND site_id = $2),
         (SELECT count(*) FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2)",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn release_provenance_lock(
    pool: &PgPool,
    mut transaction: Transaction<'_, Postgres>,
    fixture: &Fixture,
    table: &str,
    deadline: u64,
    expiry: bool,
) {
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    // Eventually-true observation of the lock queue: generous so a loaded machine
    // does not fail the test; a real regression still fails at the bound.
    tokio::time::timeout(Duration::from_secs(20), async {
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
    }).await.expect("provenance issuer must reach the held row lock");
    if expiry {
        sqlx::query("SELECT pg_sleep(GREATEST(0, $1::double precision + 0.05 - extract(epoch FROM clock_timestamp())))")
            .bind(i64::try_from(deadline).unwrap())
            .execute(&mut *transaction).await.unwrap();
        transaction.rollback().await.unwrap();
    } else {
        let status = if matches!(table, "policy_revisions" | "action_descriptors") {
            "retired"
        } else {
            "revoked"
        };
        let statement = match table {
            "policy_revisions" => {
                "UPDATE xshield.policy_revisions SET status = $3 WHERE tenant_id = $1 AND site_id = $2"
            }
            "action_descriptors" => {
                "UPDATE xshield.action_descriptors SET status = $3 WHERE tenant_id = $1 AND site_id = $2"
            }
            "page_evidence" => {
                "UPDATE xshield.page_evidence SET status = $3 WHERE tenant_id = $1 AND site_id = $2"
            }
            "ui_actions" => {
                "UPDATE xshield.ui_actions SET status = $3 WHERE tenant_id = $1 AND site_id = $2"
            }
            _ => panic!("unsupported revocation fixture"),
        };
        sqlx::query(statement)
            .bind(fixture.tenant.as_str())
            .bind(fixture.site.as_str())
            .bind(status)
            .execute(&mut *transaction)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn provenance_waits_recheck_short_action_expiry_and_revocation() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL required");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .unwrap();
    let store = PostgresIdentityStore::from_pool(pool.clone());
    for (index, (table, expiry)) in [
        ("auth_bindings", true),
        ("policy_revisions", true),
        ("action_descriptors", true),
        ("page_evidence", true),
        ("ui_actions", true),
        ("audit_outbox", true),
        ("policy_revisions", false),
        ("action_descriptors", false),
        ("page_evidence", false),
        ("ui_actions", false),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = fixture_at(
            &format!("tenant_provenance_wait_{index}"),
            database_now(&pool).await,
        );
        seed_policy_binding_and_descriptor(&pool, &fixture).await;
        let deadline = database_now(&pool).await + if expiry { 3 } else { 900 };
        let action = fixture.action("action_wait", deadline);
        let event = event_id(50_000 + u64::try_from(index).unwrap() * 10);
        if table == "page_evidence" {
            let prior = fixture.action("action_prior", fixture.now + 1_000);
            assert_eq!(
                persist(
                    &store,
                    &fixture,
                    &prior,
                    &event_id(60_000 + u64::try_from(index).unwrap()),
                    "artifact_wait"
                )
                .await
                .unwrap(),
                ProvenanceWriteOutcome::Created
            );
        } else if table == "ui_actions" {
            assert_eq!(
                persist(&store, &fixture, &action, &event, "artifact_wait")
                    .await
                    .unwrap(),
                ProvenanceWriteOutcome::Created
            );
        }
        let before = provenance_counts(&pool, &fixture).await;
        let mut transaction = pool.begin().await.unwrap();
        if table == "audit_outbox" {
            sqlx::query("INSERT INTO xshield.audit_outbox (tenant_id, site_id, event_id, aggregate_ref, event_type, envelope) VALUES ($1, $2, $3, 'blocker', 'fixture', '{}')")
                .bind(fixture.tenant.as_str()).bind(fixture.site.as_str()).bind(event.as_str())
                .execute(&mut *transaction).await.unwrap();
        } else {
            let statement = match table {
                "auth_bindings" => {
                    "SELECT 1 FROM xshield.auth_bindings WHERE tenant_id = $1 AND site_id = $2 FOR UPDATE"
                }
                "policy_revisions" => {
                    "SELECT 1 FROM xshield.policy_revisions WHERE tenant_id = $1 AND site_id = $2 FOR UPDATE"
                }
                "action_descriptors" => {
                    "SELECT 1 FROM xshield.action_descriptors WHERE tenant_id = $1 AND site_id = $2 FOR UPDATE"
                }
                "page_evidence" => {
                    "SELECT 1 FROM xshield.page_evidence WHERE tenant_id = $1 AND site_id = $2 FOR UPDATE"
                }
                "ui_actions" => {
                    "SELECT 1 FROM xshield.ui_actions WHERE tenant_id = $1 AND site_id = $2 FOR UPDATE"
                }
                _ => panic!("unsupported lock fixture"),
            };
            sqlx::query(statement)
                .bind(fixture.tenant.as_str())
                .bind(fixture.site.as_str())
                .fetch_all(&mut *transaction)
                .await
                .unwrap();
        }
        let (result, ()) = tokio::time::timeout(Duration::from_secs(8), async {
            tokio::join!(
                persist(&store, &fixture, &action, &event, "artifact_wait"),
                release_provenance_lock(&pool, transaction, &fixture, table, deadline, expiry),
            )
        })
        .await
        .expect("provenance issuer must finish after the held lock is released");
        let expected = if expiry || matches!(table, "policy_revisions" | "action_descriptors") {
            ProvenanceWriteOutcome::Ineligible
        } else {
            ProvenanceWriteOutcome::Conflict
        };
        assert_eq!(result.unwrap(), expected, "{table}, expiry={expiry}");
        assert_eq!(provenance_counts(&pool, &fixture).await, before);
        if expiry {
            let valid = fixture.action("action_after_wait", fixture.now + 1_000);
            assert_eq!(
                persist(
                    &store,
                    &fixture,
                    &valid,
                    &event_id(70_000 + u64::try_from(index).unwrap()),
                    "artifact_wait"
                )
                .await
                .unwrap(),
                ProvenanceWriteOutcome::Created
            );
        }
    }
}
