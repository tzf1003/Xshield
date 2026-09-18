use serde_json::json;
use sqlx::{PgPool, Row};
use std::{collections::BTreeMap, env, time::Duration};
use xshield_core::{
    domain::{AuthBindingId, EventId, SiteId, TenantId, WafSessionId},
    identity::{
        AuthBinding, AuthEpoch, AuthorizationContextRef, CredentialFingerprint,
        CredentialGeneration, CredentialSlot, UnixSeconds,
    },
    ports::{IdentityProofQuery, IdentityProofState, IdentityProofStore},
};
use xshield_postgres::{
    ContextSwitchOutcome, CredentialTransition, IdentityContextSwitch, PostgresIdentityStore,
    StoreError,
};

const NOW: u64 = 1_800_000_000;
const EXPIRES: u64 = 4_102_444_700;
const SESSION_EXPIRES: u64 = 4_102_444_800;
const SESSION_FINGERPRINT: [u8; 32] = [31; 32];

struct Fixture {
    binding: AuthBinding,
    snapshot: xshield_core::identity::AuthSnapshot,
    session_id: WafSessionId,
    old_credentials: BTreeMap<CredentialSlot, CredentialFingerprint>,
    new_credentials: BTreeMap<CredentialSlot, CredentialFingerprint>,
    new_context: AuthorizationContextRef,
}

fn credentials(byte: u8) -> BTreeMap<CredentialSlot, CredentialFingerprint> {
    BTreeMap::from([(
        CredentialSlot::Bearer,
        CredentialFingerprint::from_bytes([byte; 32]),
    )])
}

fn fixture() -> Fixture {
    let session_id = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000c02").unwrap();
    let old_credentials = credentials(41);
    let binding = AuthBinding::new(
        AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000c01").unwrap(),
        session_id.clone(),
        TenantId::parse("tenant_switch").unwrap(),
        SiteId::parse("site_switch").unwrap(),
        "principal_a",
        AuthorizationContextRef::parse("tenant_a:role_user").unwrap(),
        AuthEpoch::new(4),
        CredentialGeneration::new(2),
        old_credentials.clone(),
        UnixSeconds::new(SESSION_EXPIRES),
    )
    .unwrap();
    let snapshot = binding
        .verify(
            binding.tenant_id(),
            binding.site_id(),
            &session_id,
            &old_credentials,
            UnixSeconds::new(NOW),
        )
        .unwrap();
    Fixture {
        binding,
        snapshot,
        session_id,
        old_credentials,
        new_credentials: credentials(42),
        new_context: AuthorizationContextRef::parse("tenant_b:role_user").unwrap(),
    }
}

fn event_id(suffix: u64) -> EventId {
    EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{suffix:012x}")).unwrap()
}

fn command<'a>(
    fixture: &'a Fixture,
    previous: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
    event_id: &'a EventId,
    envelope: &'a serde_json::Value,
) -> Result<IdentityContextSwitch<'a>, StoreError> {
    let transition = CredentialTransition::new(
        &fixture.snapshot,
        previous,
        &fixture.new_credentials,
        UnixSeconds::new(EXPIRES),
        UnixSeconds::new(NOW),
        event_id,
        envelope,
    )?;
    IdentityContextSwitch::new(transition, "principal_a", &fixture.new_context)
}

async fn seed(pool: &PgPool, fixture: &Fixture) {
    sqlx::query(
        "INSERT INTO xshield.auth_bindings (
            tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
            authorization_context_ref, auth_epoch, credential_generation, status,
            absolute_expires_at
         ) VALUES ($1, $2, $3, $4, 'principal_a', 'tenant_a:role_user',
                   4, 2, 'active', to_timestamp($5))",
    )
    .bind(fixture.binding.tenant_id().as_str())
    .bind(fixture.binding.site_id().as_str())
    .bind(fixture.binding.binding_id().as_str())
    .bind(SESSION_FINGERPRINT.as_slice())
    .bind(i64::try_from(SESSION_EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.credential_bindings (
            tenant_id, site_id, binding_id, generation, credential_kind,
            fingerprint, expires_at, status
         ) VALUES ($1, $2, $3, 2, 'bearer', $4, to_timestamp($5), 'active')",
    )
    .bind(fixture.binding.tenant_id().as_str())
    .bind(fixture.binding.site_id().as_str())
    .bind(fixture.binding.binding_id().as_str())
    .bind(
        fixture.old_credentials[&CredentialSlot::Bearer]
            .as_bytes()
            .as_slice(),
    )
    .bind(i64::try_from(EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
}

async fn binding_state(pool: &PgPool, fixture: &Fixture) -> (String, String, i64, i64) {
    let row = sqlx::query(
        "SELECT principal_ref, authorization_context_ref, auth_epoch, credential_generation
         FROM xshield.auth_bindings
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
    )
    .bind(fixture.binding.tenant_id().as_str())
    .bind(fixture.binding.site_id().as_str())
    .bind(fixture.binding.binding_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    (
        row.get("principal_ref"),
        row.get("authorization_context_ref"),
        row.get("auth_epoch"),
        row.get("credential_generation"),
    )
}

async fn assert_duplicate_event_rolls_back(
    store: &PostgresIdentityStore,
    pool: &PgPool,
    fixture: &Fixture,
    envelope: &serde_json::Value,
) {
    let duplicate_event = event_id(201);
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, 'fixture', '{}')",
    )
    .bind(duplicate_event.as_str())
    .bind(fixture.binding.tenant_id().as_str())
    .bind(fixture.binding.site_id().as_str())
    .bind(fixture.binding.binding_id().as_str())
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        store
            .switch_identity_context(
                command(
                    fixture,
                    &fixture.old_credentials,
                    &duplicate_event,
                    envelope,
                )
                .unwrap(),
            )
            .await,
        Err(StoreError::Database(_))
    ));
    assert_eq!(
        binding_state(pool, fixture).await,
        (
            "principal_a".to_owned(),
            "tenant_a:role_user".to_owned(),
            4,
            2
        )
    );
}

async fn assert_identity_access(store: &PostgresIdentityStore, fixture: &Fixture) {
    let query = |credentials| IdentityProofQuery {
        tenant_id: fixture.binding.tenant_id(),
        site_id: fixture.binding.site_id(),
        session_id: &fixture.session_id,
        session_fingerprint: &SESSION_FINGERPRINT,
        credentials,
        now: UnixSeconds::new(NOW),
    };
    assert!(matches!(
        store
            .load_identity(query(&fixture.old_credentials))
            .await
            .unwrap(),
        IdentityProofState::Denied(_)
    ));
    assert!(matches!(
        store
            .load_identity(query(&fixture.new_credentials))
            .await
            .unwrap(),
        IdentityProofState::Verified { snapshot, .. }
            if snapshot.principal_ref() == "principal_a"
                && snapshot.authorization_context_ref() == &fixture.new_context
                && snapshot.epoch() == AuthEpoch::new(5)
                && snapshot.generation() == CredentialGeneration::new(3)
    ));
}

#[test]
fn context_switch_requires_a_new_context_and_credential() {
    let fixture = fixture();
    let event_id = event_id(201);
    let envelope = json!({"schema_version": 3, "event_type": "epoch.changed"});
    assert!(matches!(
        IdentityContextSwitch::new(
            CredentialTransition::new(
                &fixture.snapshot,
                &fixture.old_credentials,
                &fixture.new_credentials,
                UnixSeconds::new(EXPIRES),
                UnixSeconds::new(NOW),
                &event_id,
                &envelope,
            )
            .unwrap(),
            "principal_a",
            fixture.snapshot.authorization_context_ref(),
        ),
        Err(StoreError::InvalidCommand)
    ));
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn context_switch_is_atomic_and_invalidates_the_old_identity() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 2, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let fixture = fixture();
    seed(&pool, &fixture).await;
    let envelope = json!({"schema_version": 3, "event_type": "epoch.changed"});

    assert_duplicate_event_rolls_back(&store, &pool, &fixture, &envelope).await;

    let mismatch_event = event_id(202);
    assert_eq!(
        store
            .switch_identity_context(
                command(&fixture, &credentials(99), &mismatch_event, &envelope).unwrap(),
            )
            .await
            .unwrap(),
        ContextSwitchOutcome::Conflict
    );
    assert_eq!(
        binding_state(&pool, &fixture).await,
        (
            "principal_a".to_owned(),
            "tenant_a:role_user".to_owned(),
            4,
            2
        )
    );

    let committed_event = event_id(203);
    assert_eq!(
        store
            .switch_identity_context(
                command(
                    &fixture,
                    &fixture.old_credentials,
                    &committed_event,
                    &envelope,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        ContextSwitchOutcome::Updated {
            previous_epoch: AuthEpoch::new(4),
            current_epoch: AuthEpoch::new(5),
            previous_generation: CredentialGeneration::new(2),
            current_generation: CredentialGeneration::new(3),
        }
    );
    assert_eq!(
        binding_state(&pool, &fixture).await,
        (
            "principal_a".to_owned(),
            "tenant_b:role_user".to_owned(),
            5,
            3
        )
    );

    let stale_event = event_id(204);
    assert_eq!(
        store
            .switch_identity_context(
                command(&fixture, &fixture.old_credentials, &stale_event, &envelope,).unwrap(),
            )
            .await
            .unwrap(),
        ContextSwitchOutcome::Conflict
    );
    assert_identity_access(&store, &fixture).await;
    let event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.audit_outbox
         WHERE event_id = $1 AND event_type = 'epoch.changed'",
    )
    .bind(committed_event.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(event_count, 1);
}
