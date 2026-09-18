use serde_json::json;
use sqlx::{PgPool, Row};
use std::{collections::BTreeMap, env, time::Duration};
use xshield_core::{
    domain::{AuthBindingId, EventId, SiteId, TenantId, WafSessionId},
    identity::{
        AuthBinding, AuthEpoch, AuthSnapshot, CredentialFingerprint, CredentialGeneration,
        CredentialSlot, IdentityDenied, UnixSeconds,
    },
    ports::{IdentityProofQuery, IdentityProofState, IdentityProofStore},
};
use xshield_postgres::{CredentialTransition, PostgresIdentityStore, RefreshOutcome, StoreError};

const OLD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const WRONG: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const NOW: u64 = 1_800_000_000;
const EXPIRES: u64 = 4_102_444_700;
const SESSION_FINGERPRINT: [u8; 32] = [17; 32];

struct Fixture {
    tenant: TenantId,
    site: SiteId,
    binding_id: AuthBindingId,
    session_id: WafSessionId,
    snapshot: AuthSnapshot,
    old_credentials: BTreeMap<CredentialSlot, CredentialFingerprint>,
    new_credentials: BTreeMap<CredentialSlot, CredentialFingerprint>,
}

fn fixture() -> Fixture {
    let tenant = TenantId::parse("tenant_rust").unwrap();
    let site = SiteId::parse("site_rust").unwrap();
    let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000101").unwrap();
    let session_id = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000102").unwrap();
    let old_credentials = credentials(OLD);
    let binding = AuthBinding::new(
        binding_id.clone(),
        session_id.clone(),
        tenant.clone(),
        site.clone(),
        "principal_rust",
        xshield_core::identity::AuthorizationContextRef::parse("context_rust").unwrap(),
        AuthEpoch::new(4),
        CredentialGeneration::new(2),
        old_credentials.clone(),
        UnixSeconds::new(4_102_444_800),
    )
    .unwrap();
    let snapshot = binding
        .verify(
            &tenant,
            &site,
            &session_id,
            &old_credentials,
            UnixSeconds::new(NOW),
        )
        .unwrap();
    Fixture {
        tenant,
        site,
        binding_id,
        session_id,
        snapshot,
        old_credentials,
        new_credentials: credentials(NEW),
    }
}

fn credentials(value: &str) -> BTreeMap<CredentialSlot, CredentialFingerprint> {
    BTreeMap::from([(
        CredentialSlot::Cookie,
        CredentialFingerprint::parse(value).unwrap(),
    )])
}

fn event_id(suffix: u64) -> EventId {
    EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{suffix:012x}")).unwrap()
}

async fn seed_binding(pool: &PgPool, fixture: &Fixture) {
    sqlx::query(
        "INSERT INTO xshield.auth_bindings (
            tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
            authorization_context_ref, auth_epoch, credential_generation, status,
            absolute_expires_at
         ) VALUES ($1, $2, $3, $4, $5, 'context_rust', 4, 2, 'active', to_timestamp($6))",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .bind(SESSION_FINGERPRINT.as_slice())
    .bind("principal_rust")
    .bind(4_102_444_800_i64)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.credential_bindings (
            tenant_id, site_id, binding_id, generation, credential_kind,
            fingerprint, expires_at, status
         ) VALUES ($1, $2, $3, 2, 'cookie', $4, to_timestamp($5), 'active')",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .bind(
        CredentialFingerprint::parse(OLD)
            .unwrap()
            .as_bytes()
            .as_slice(),
    )
    .bind(i64::try_from(EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_duplicate_event(pool: &PgPool, fixture: &Fixture, event_id: &EventId) {
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, 'fixture', '{}')",
    )
    .bind(event_id.as_str())
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .execute(pool)
    .await
    .unwrap();
}

async fn refresh(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    event_id: &EventId,
) -> Result<RefreshOutcome, StoreError> {
    let envelope = json!({"schema_version": 3, "event_type": "identity.refreshed"});
    store
        .refresh_same_context(CredentialTransition::new(
            &fixture.snapshot,
            &fixture.old_credentials,
            &fixture.new_credentials,
            UnixSeconds::new(EXPIRES),
            UnixSeconds::new(NOW),
            event_id,
            &envelope,
        )?)
        .await
}

async fn load_identity(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    credentials: &BTreeMap<CredentialSlot, CredentialFingerprint>,
) -> IdentityProofState {
    store
        .load_identity(IdentityProofQuery {
            tenant_id: &fixture.tenant,
            site_id: &fixture.site,
            session_id: &fixture.session_id,
            session_fingerprint: &SESSION_FINGERPRINT,
            credentials,
            now: UnixSeconds::new(NOW),
        })
        .await
        .unwrap()
}

async fn generation(pool: &PgPool, fixture: &Fixture) -> i64 {
    sqlx::query(
        "SELECT credential_generation FROM xshield.auth_bindings
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .fetch_one(pool)
    .await
    .unwrap()
    .get("credential_generation")
}

async fn assert_committed_state(pool: &PgPool, fixture: &Fixture, event_id: &EventId) {
    let counts = sqlx::query(
        "SELECT
            count(*) FILTER (WHERE generation = 2 AND status = 'revoked') AS old_revoked,
            count(*) FILTER (WHERE generation = 3 AND status = 'active') AS new_active
         FROM xshield.credential_bindings
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(counts.get::<i64, _>("old_revoked"), 1);
    assert_eq!(counts.get::<i64, _>("new_active"), 1);
    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.audit_outbox
         WHERE event_id = $1 AND event_type = 'identity.refreshed'",
    )
    .bind(event_id.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(outbox_count, 1);
}

#[test]
fn refresh_requires_a_complete_credential_set() {
    let fixture = fixture();
    let event_id = event_id(106);
    let envelope = json!({"schema_version": 3, "event_type": "identity.refreshed"});
    assert!(matches!(
        CredentialTransition::new(
            &fixture.snapshot,
            &fixture.old_credentials,
            &BTreeMap::new(),
            UnixSeconds::new(EXPIRES),
            UnixSeconds::new(NOW),
            &event_id,
            &envelope,
        ),
        Err(StoreError::InvalidCommand)
    ));
}

#[tokio::test]
async fn pool_requires_connection_and_time_bounds() {
    assert!(matches!(
        PostgresIdentityStore::connect("postgresql://unused", 0, Duration::from_secs(1)).await,
        Err(StoreError::InvalidPoolConfig)
    ));
    assert!(matches!(
        PostgresIdentityStore::connect("postgresql://unused", 1, Duration::ZERO).await,
        Err(StoreError::InvalidPoolConfig)
    ));
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn refresh_is_atomic_and_compare_and_swap() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 2, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let fixture = fixture();
    seed_binding(&pool, &fixture).await;
    let old_credentials = credentials(OLD);
    assert!(matches!(
        load_identity(&store, &fixture, &old_credentials).await,
        IdentityProofState::Verified { snapshot, .. }
            if snapshot.generation() == CredentialGeneration::new(2)
    ));
    assert!(matches!(
        load_identity(&store, &fixture, &fixture.new_credentials).await,
        IdentityProofState::Denied(IdentityDenied::BindingMismatch)
    ));

    sqlx::query(
        "UPDATE xshield.auth_bindings SET authorization_context_ref = 'context_changed'
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        refresh(&store, &fixture, &event_id(101)).await.unwrap(),
        RefreshOutcome::Conflict
    );
    sqlx::query(
        "UPDATE xshield.auth_bindings SET authorization_context_ref = 'context_rust'
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .execute(&pool)
    .await
    .unwrap();

    let mismatched_event = event_id(102);
    let mismatched_envelope = json!({"schema_version": 3, "event_type": "identity.refreshed"});
    assert_eq!(
        store
            .refresh_same_context(
                CredentialTransition::new(
                    &fixture.snapshot,
                    &credentials(WRONG),
                    &fixture.new_credentials,
                    UnixSeconds::new(EXPIRES),
                    UnixSeconds::new(NOW),
                    &mismatched_event,
                    &mismatched_envelope,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        RefreshOutcome::Conflict
    );
    assert_eq!(generation(&pool, &fixture).await, 2);

    let duplicate_event = event_id(103);
    seed_duplicate_event(&pool, &fixture, &duplicate_event).await;
    assert!(matches!(
        refresh(&store, &fixture, &duplicate_event).await,
        Err(StoreError::Database(_))
    ));
    assert_eq!(generation(&pool, &fixture).await, 2);

    let committed_event = event_id(104);
    assert_eq!(
        refresh(&store, &fixture, &committed_event).await.unwrap(),
        RefreshOutcome::Updated {
            previous_generation: CredentialGeneration::new(2),
            current_generation: CredentialGeneration::new(3),
        }
    );
    assert_eq!(
        refresh(&store, &fixture, &event_id(105)).await.unwrap(),
        RefreshOutcome::Conflict
    );
    assert_committed_state(&pool, &fixture, &committed_event).await;
    assert!(matches!(
        load_identity(&store, &fixture, &fixture.new_credentials).await,
        IdentityProofState::Verified { snapshot, .. }
            if snapshot.generation() == CredentialGeneration::new(3)
    ));
    assert!(matches!(
        load_identity(&store, &fixture, &old_credentials).await,
        IdentityProofState::Denied(IdentityDenied::BindingMismatch)
    ));
}
