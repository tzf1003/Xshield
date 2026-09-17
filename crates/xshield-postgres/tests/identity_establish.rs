use serde_json::json;
use sqlx::PgPool;
use std::{collections::BTreeMap, env, time::Duration};
use xshield_core::{
    domain::{AuthBindingId, EventId, SiteId, TenantId, WafSessionId},
    identity::{
        AuthBinding, AuthEpoch, CredentialFingerprint, CredentialGeneration, CredentialSlot,
        UnixSeconds,
    },
    ports::{IdentityProofQuery, IdentityProofState, IdentityProofStore},
};
use xshield_postgres::{BindingEstablishment, PostgresIdentityStore, StoreError};

const NOW: u64 = 1_800_000_000;
const CREDENTIAL_EXPIRES: u64 = 1_800_003_600;
const SESSION_EXPIRES: u64 = 1_800_086_400;
const SESSION_FINGERPRINT: [u8; 32] = [41; 32];

fn fixture() -> (AuthBinding, WafSessionId) {
    let session_id = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000b02").unwrap();
    let credentials = BTreeMap::from([(
        CredentialSlot::Bearer,
        CredentialFingerprint::from_bytes([42; 32]),
    )]);
    let binding = AuthBinding::new(
        AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000b01").unwrap(),
        session_id.clone(),
        TenantId::parse("tenant_establish").unwrap(),
        SiteId::parse("site_establish").unwrap(),
        "principal_establish",
        AuthEpoch::new(1),
        CredentialGeneration::new(1),
        credentials,
        UnixSeconds::new(SESSION_EXPIRES),
    )
    .unwrap();
    (binding, session_id)
}

#[test]
fn establishment_requires_fresh_bounded_state() {
    let (binding, _) = fixture();
    let event_id = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000b03").unwrap();
    let envelope = json!({"schema_version": 3, "event_type": "binding.created"});
    assert!(
        BindingEstablishment::new(
            &binding,
            &SESSION_FINGERPRINT,
            UnixSeconds::new(CREDENTIAL_EXPIRES),
            UnixSeconds::new(NOW),
            &event_id,
            &envelope,
        )
        .is_ok()
    );
    assert!(matches!(
        BindingEstablishment::new(
            &binding,
            &SESSION_FINGERPRINT,
            UnixSeconds::new(SESSION_EXPIRES + 1),
            UnixSeconds::new(NOW),
            &event_id,
            &envelope,
        ),
        Err(StoreError::InvalidCommand)
    ));
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn establishment_commits_binding_credentials_and_outbox_atomically() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 2, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let (binding, session_id) = fixture();
    let event_id = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000b03").unwrap();
    let envelope = json!({"schema_version": 3, "event_type": "binding.created"});
    store
        .establish_binding(
            BindingEstablishment::new(
                &binding,
                &SESSION_FINGERPRINT,
                UnixSeconds::new(CREDENTIAL_EXPIRES),
                UnixSeconds::new(NOW),
                &event_id,
                &envelope,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let state = store
        .load_identity(IdentityProofQuery {
            tenant_id: binding.tenant_id(),
            site_id: binding.site_id(),
            session_id: &session_id,
            session_fingerprint: &SESSION_FINGERPRINT,
            credentials: binding.credentials(),
            now: UnixSeconds::new(NOW),
        })
        .await
        .unwrap();
    assert!(matches!(
        state,
        IdentityProofState::Verified { snapshot, .. }
            if snapshot.binding_id() == binding.binding_id()
                && snapshot.generation() == CredentialGeneration::new(1)
    ));
    let outbox: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.audit_outbox
         WHERE event_id = $1 AND event_type = 'binding.created'",
    )
    .bind(event_id.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outbox, 1);
}
