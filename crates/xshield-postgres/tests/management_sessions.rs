use openssl::sha::sha256;
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_postgres::PostgresIdentityStore;

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL and migration 0035"]
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
        .begin_management_oidc_transaction(&state_digest, &verifier, &nonce)
        .await
        .unwrap();
    assert_eq!(
        store
            .consume_management_oidc_transaction(&state_digest)
            .await
            .unwrap(),
        Some((verifier, nonce))
    );
    assert!(
        store
            .consume_management_oidc_transaction(&state_digest)
            .await
            .unwrap()
            .is_none()
    );

    store
        .begin_management_oidc_transaction(&expired_state_digest, &"b".repeat(43), "expired")
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
