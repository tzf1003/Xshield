use serde_json::json;
use sqlx::PgPool;
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
    provenance::{
        ActionDescriptor, ActionGrant, ActionGrantDraft, ActionTarget, ActionTargetRule,
        BuildFingerprint, HttpMethod, PageEvidence, RouteTemplate,
    },
};
use xshield_postgres::{
    PostgresIdentityStore, ProvenancePersistence, ProvenanceWriteOutcome, StoreError,
};

const NOW: u64 = 1_800_000_000;
const EVIDENCE_EXPIRES: u64 = 1_800_001_500;
const SESSION_EXPIRES: u64 = 1_800_002_000;

struct Fixture {
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
    let tenant = TenantId::parse("tenant_provenance").unwrap();
    let site = SiteId::parse("site_provenance").unwrap();
    let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000401").unwrap();
    let session = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000402").unwrap();
    let binding = AuthBinding::new(
        binding_id.clone(),
        session.clone(),
        tenant.clone(),
        site.clone(),
        "principal_provenance",
        AuthEpoch::new(4),
        CredentialGeneration::new(2),
        credentials(),
        UnixSeconds::new(SESSION_EXPIRES),
    )
    .unwrap();
    let snapshot = binding
        .verify(
            &tenant,
            &site,
            &session,
            &credentials(),
            UnixSeconds::new(NOW),
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
        UnixSeconds::new(EVIDENCE_EXPIRES),
        UnixSeconds::new(NOW),
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
            UnixSeconds::new(NOW),
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
            auth_epoch, credential_generation, status, absolute_expires_at
         ) VALUES ($1, $2, $3, $4, 'principal_provenance', 4, 2, 'active', to_timestamp($5))",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .bind([51_u8; 32].as_slice())
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
            UnixSeconds::new(NOW),
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

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn provenance_is_atomic_idempotent_and_epoch_bound() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 3, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
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
