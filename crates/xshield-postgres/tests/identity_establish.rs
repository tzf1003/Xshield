use serde_json::json;
use sqlx::PgPool;
use std::{collections::BTreeMap, env, time::Duration};
use xshield_core::{
    domain::{AuthBindingId, EventId, SiteId, TenantId, WafSessionId},
    identity::{
        AnonymousSession, AuthBinding, AuthEpoch, CredentialFingerprint, CredentialGeneration,
        CredentialSlot, UnixSeconds,
    },
    ports::{IdentityProofQuery, IdentityProofState, IdentityProofStore},
};
use xshield_postgres::{
    AnonymousSessionEstablishment, AnonymousSessionWriteOutcome, BindingEstablishment,
    PostgresIdentityStore, SensorSessionQuery, SensorSessionState, StoreError,
};

const NOW: u64 = 1_800_000_000;
const CREDENTIAL_EXPIRES: u64 = 1_800_003_600;
const SESSION_EXPIRES: u64 = 1_800_086_400;
const SESSION_FINGERPRINT: [u8; 32] = [41; 32];
const SECOND_SESSION_FINGERPRINT: [u8; 32] = [43; 32];
const SOURCE_FINGERPRINT: [u8; 32] = [44; 32];
const SECOND_SOURCE_FINGERPRINT: [u8; 32] = [45; 32];

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
        xshield_core::identity::AuthorizationContextRef::parse("context_establish").unwrap(),
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

#[test]
fn anonymous_establishment_requires_live_bounded_state() {
    let tenant = TenantId::parse("tenant_anonymous").unwrap();
    let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000a01").unwrap();
    let session = AnonymousSession::new(
        WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000a02").unwrap(),
        SiteId::parse("site_anonymous").unwrap(),
        UnixSeconds::new(SESSION_EXPIRES),
    );
    let event_id = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000a03").unwrap();
    let envelope = json!({"schema_version": 3, "event_type": "session.created"});
    assert!(
        AnonymousSessionEstablishment::new(
            &tenant,
            &binding_id,
            &session,
            &SESSION_FINGERPRINT,
            &SOURCE_FINGERPRINT,
            1,
            60,
            1,
            2,
            UnixSeconds::new(NOW),
            &event_id,
            &envelope,
        )
        .is_ok()
    );
    assert!(matches!(
        AnonymousSessionEstablishment::new(
            &tenant,
            &binding_id,
            &session,
            &SESSION_FINGERPRINT,
            &SOURCE_FINGERPRINT,
            0,
            60,
            1,
            2,
            UnixSeconds::new(NOW),
            &event_id,
            &envelope,
        ),
        Err(StoreError::InvalidCommand)
    ));
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn anonymous_establishment_is_empty_audited_rate_and_capacity_bounded() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 2, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let tenant = TenantId::parse("tenant_anonymous").unwrap();
    let site = SiteId::parse("site_anonymous").unwrap();
    let first_binding = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000a11").unwrap();
    let first_session = AnonymousSession::new(
        WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000a12").unwrap(),
        site.clone(),
        UnixSeconds::new(SESSION_EXPIRES),
    );
    let first_event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000a13").unwrap();
    let first_envelope = json!({"schema_version": 3, "event_type": "session.created"});
    let first = AnonymousSessionEstablishment::new(
        &tenant,
        &first_binding,
        &first_session,
        &SESSION_FINGERPRINT,
        &SOURCE_FINGERPRINT,
        1,
        60,
        1,
        2,
        UnixSeconds::new(NOW),
        &first_event,
        &first_envelope,
    )
    .unwrap();
    let second_binding = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000a21").unwrap();
    let second_session = AnonymousSession::new(
        WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000a22").unwrap(),
        site.clone(),
        UnixSeconds::new(SESSION_EXPIRES),
    );
    let second_event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000a23").unwrap();
    let second_envelope = json!({"schema_version": 3, "event_type": "session.created"});
    let second = AnonymousSessionEstablishment::new(
        &tenant,
        &second_binding,
        &second_session,
        &SECOND_SESSION_FINGERPRINT,
        &SOURCE_FINGERPRINT,
        1,
        60,
        1,
        2,
        UnixSeconds::new(NOW),
        &second_event,
        &second_envelope,
    )
    .unwrap();
    let (first_outcome, second_outcome) = tokio::join!(
        store.establish_anonymous_session(first),
        store.establish_anonymous_session(second)
    );
    let outcomes = [first_outcome.unwrap(), second_outcome.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == AnonymousSessionWriteOutcome::Created)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == AnonymousSessionWriteOutcome::RateExceeded)
            .count(),
        1
    );

    let third_binding = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000a31").unwrap();
    let third_session = AnonymousSession::new(
        WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000a32").unwrap(),
        site,
        UnixSeconds::new(SESSION_EXPIRES),
    );
    let third_event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000a33").unwrap();
    let third_envelope = json!({"schema_version": 3, "event_type": "session.created"});
    let third = AnonymousSessionEstablishment::new(
        &tenant,
        &third_binding,
        &third_session,
        &SECOND_SESSION_FINGERPRINT,
        &SECOND_SOURCE_FINGERPRINT,
        1,
        60,
        1,
        2,
        UnixSeconds::new(NOW),
        &third_event,
        &third_envelope,
    )
    .unwrap();
    assert_eq!(
        store.establish_anonymous_session(third).await.unwrap(),
        AnonymousSessionWriteOutcome::CapacityExceeded
    );

    let state: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*),
                count(*) FILTER (WHERE status = 'anonymous'),
                (SELECT count(*) FROM xshield.credential_bindings credential
                 WHERE credential.tenant_id = $1 AND credential.site_id = $2),
                (SELECT count(*) FROM xshield.audit_outbox outbox
                 WHERE outbox.tenant_id = $1 AND outbox.site_id = $2
                   AND outbox.event_type = 'session.created'),
                coalesce(max(auth_epoch), -1)
         FROM xshield.auth_bindings
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant.as_str())
    .bind(second_session.site_id().as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state, (1, 1, 0, 1, 0));

    let rate_state: (i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(max(used) FILTER (WHERE scope_kind = 'site'), 0)
         FROM xshield.anonymous_session_rate_limits
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant.as_str())
    .bind(third_session.site_id().as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rate_state, (3, 2));
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
                && snapshot.authorization_context_ref() == binding.authorization_context_ref()
                && snapshot.generation() == CredentialGeneration::new(1)
    ));
    let sensor_session = store
        .load_sensor_session(SensorSessionQuery {
            tenant_id: binding.tenant_id(),
            site_id: binding.site_id(),
            session_fingerprint: &SESSION_FINGERPRINT,
            now: UnixSeconds::new(NOW),
        })
        .await
        .unwrap();
    assert!(matches!(
        sensor_session,
        SensorSessionState::Verified(session)
            if session.binding_id() == binding.binding_id()
                && session.epoch() == AuthEpoch::new(1)
                && session.authenticated()
    ));
    for (fingerprint, now) in [
        ([0; 32], UnixSeconds::new(NOW)),
        (SESSION_FINGERPRINT, UnixSeconds::new(SESSION_EXPIRES)),
    ] {
        assert_eq!(
            store
                .load_sensor_session(SensorSessionQuery {
                    tenant_id: binding.tenant_id(),
                    site_id: binding.site_id(),
                    session_fingerprint: &fingerprint,
                    now,
                })
                .await
                .unwrap(),
            SensorSessionState::Denied
        );
    }
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
