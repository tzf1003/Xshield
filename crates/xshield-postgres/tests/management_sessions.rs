use openssl::sha::sha256;
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_postgres::PostgresIdentityStore;

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL and migrations 0035–0036"]
async fn oidc_transactions_are_one_use_and_browser_sessions_are_revocable() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let store = PostgresIdentityStore::connect(&database_url, 2, Duration::from_secs(5))
        .await
        .unwrap();
    let pool = PgPool::connect(&database_url).await.unwrap();
    let state_digest = sha256(Uuid::now_v7().to_string().as_bytes());
    let expired_state_digest = sha256(Uuid::now_v7().to_string().as_bytes());
    let session_digest = sha256(Uuid::now_v7().to_string().as_bytes());
    let verifier = "a".repeat(43);
    let nonce = Uuid::now_v7().to_string();
    let subject = format!("management-session-{}", Uuid::now_v7());
    let csrf = "ab".repeat(32);

    store
        .begin_management_oidc_transaction(&state_digest, &verifier, &nonce, None)
        .await
        .unwrap();
    let transaction = store
        .consume_management_oidc_transaction(&state_digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(transaction.pkce_verifier(), verifier);
    assert_eq!(transaction.nonce(), nonce);
    assert!(transaction.session_digest().is_none());
    assert!(
        store
            .consume_management_oidc_transaction(&state_digest)
            .await
            .unwrap()
            .is_none()
    );

    store
        .begin_management_oidc_transaction(&expired_state_digest, &"b".repeat(43), "expired", None)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE xshield.management_oidc_transactions
         SET expires_at = '2000-01-01 UTC' WHERE state_digest = $1",
    )
    .bind(expired_state_digest.as_slice())
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        store
            .consume_management_oidc_transaction(&expired_state_digest)
            .await
            .unwrap()
            .is_none()
    );

    store
        .create_management_browser_session(
            &session_digest,
            "https://issuer.example",
            &subject,
            &csrf,
        )
        .await
        .unwrap();
    let session = store
        .active_management_browser_session(&session_digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.issuer(), "https://issuer.example");
    assert_eq!(session.subject(), subject);
    assert_eq!(session.csrf_token(), csrf);
    assert!(!session.step_up_valid());

    verify_bound_step_up(&store, &pool, &session_digest, &subject).await;
    assert!(
        store
            .revoke_management_browser_session(&session_digest)
            .await
            .unwrap()
    );
    assert!(
        store
            .active_management_browser_session(&session_digest)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .revoke_management_browser_session(&session_digest)
            .await
            .unwrap()
    );

    sqlx::query("DELETE FROM xshield.management_oidc_transactions WHERE state_digest = $1")
        .bind(expired_state_digest.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.management_browser_sessions WHERE session_digest = $1")
        .bind(session_digest.as_slice())
        .execute(&pool)
        .await
        .unwrap();
}

async fn verify_bound_step_up(
    store: &PostgresIdentityStore,
    pool: &PgPool,
    session_digest: &[u8; 32],
    subject: &str,
) {
    let state_digest = sha256(Uuid::now_v7().to_string().as_bytes());
    store
        .begin_management_oidc_transaction(
            &state_digest,
            &"c".repeat(43),
            "step-up-nonce",
            Some(session_digest),
        )
        .await
        .unwrap();
    let transaction = store
        .consume_management_oidc_transaction(&state_digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        transaction.session_digest(),
        Some(session_digest.as_slice())
    );
    assert!(
        store
            .reauthenticate_management_browser_session(
                session_digest,
                "https://issuer.example",
                subject,
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .active_management_browser_session(session_digest)
            .await
            .unwrap()
            .unwrap()
            .step_up_valid()
    );
    sqlx::query(
        "UPDATE xshield.management_browser_sessions
         SET created_at = clock_timestamp() - interval '4 minutes',
             last_seen_at = clock_timestamp(),
             last_reauthenticated_at = clock_timestamp() - interval '3 minutes'
         WHERE session_digest = $1",
    )
    .bind(session_digest.as_slice())
    .execute(pool)
    .await
    .unwrap();
    assert!(
        !store
            .active_management_browser_session(session_digest)
            .await
            .unwrap()
            .unwrap()
            .step_up_valid()
    );
    assert!(
        !store
            .reauthenticate_management_browser_session(
                session_digest,
                "https://issuer.example",
                "another-subject",
            )
            .await
            .unwrap()
    );
}
