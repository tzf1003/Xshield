use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use sqlx::Row;

/// Active browser-management session data read after server-side validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementBrowserSession {
    issuer: String,
    subject: String,
    csrf_token: String,
    created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    last_reauthenticated_at: Option<DateTime<Utc>>,
    step_up_valid: bool,
}

impl ManagementBrowserSession {
    /// Returns the OIDC issuer that authenticated this session.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the exact OIDC subject; it is not normalized or inferred.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the session-bound CSRF value for an authenticated bootstrap.
    #[must_use]
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }

    /// Reports whether the session has an MFA-backed step-up within two minutes.
    #[must_use]
    pub const fn step_up_valid(&self) -> bool {
        self.step_up_valid
    }

    /// Returns the database-clock absolute expiry of this session.
    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Returns the database-clock time at which the current idle window ends.
    #[must_use]
    pub fn idle_expires_at(&self) -> DateTime<Utc> {
        self.last_seen_at + chrono::Duration::minutes(15)
    }

    /// Returns the creation time used to derive the session policy window.
    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Returns the last successful session-bound step-up time, if any.
    #[must_use]
    pub const fn last_reauthenticated_at(&self) -> Option<DateTime<Utc>> {
        self.last_reauthenticated_at
    }
}

/// One consumed OIDC transaction, optionally bound to an existing browser session.
pub struct ManagementOidcTransaction {
    pkce_verifier: String,
    nonce: String,
    session_digest: Option<Vec<u8>>,
}

impl ManagementOidcTransaction {
    /// Returns the verifier paired with this single-use authorization state.
    #[must_use]
    pub fn pkce_verifier(&self) -> &str {
        &self.pkce_verifier
    }

    /// Returns the nonce paired with this single-use authorization state.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Returns the existing session digest for step-up, or `None` for login.
    #[must_use]
    pub fn session_digest(&self) -> Option<&[u8]> {
        self.session_digest.as_deref()
    }
}

impl PostgresIdentityStore {
    /// Stores a short-lived OIDC authorization transaction for one callback.
    ///
    /// The state digest is the lookup key; the verifier and nonce are retained
    /// only until the five-minute callback window expires.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for malformed transaction data,
    /// or [`StoreError::Database`] when the durable write fails.
    pub async fn begin_management_oidc_transaction(
        &self,
        state_digest: &[u8; 32],
        pkce_verifier: &str,
        nonce: &str,
        session_digest: Option<&[u8; 32]>,
    ) -> Result<(), StoreError> {
        if !(43..=128).contains(&pkce_verifier.len())
            || !pkce_verifier.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
            || nonce.is_empty()
            || nonce.len() > 512
            || nonce.chars().any(char::is_control)
        {
            return Err(StoreError::InvalidCommand);
        }

        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM xshield.management_oidc_transactions
             WHERE expires_at <= clock_timestamp()",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO xshield.management_oidc_transactions
                (state_digest, pkce_verifier, nonce, session_digest, expires_at)
             VALUES ($1, $2, $3, $4, clock_timestamp() + interval '5 minutes')",
        )
        .bind(state_digest.as_slice())
        .bind(pkce_verifier)
        .bind(nonce)
        .bind(session_digest.map(<[u8; 32]>::as_slice))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Consumes one unexpired OIDC transaction exactly once.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the transaction cannot be read or
    /// durably removed.
    pub async fn consume_management_oidc_transaction(
        &self,
        state_digest: &[u8; 32],
    ) -> Result<Option<ManagementOidcTransaction>, StoreError> {
        let row = sqlx::query(
            "DELETE FROM xshield.management_oidc_transactions
             WHERE state_digest = $1 AND expires_at > clock_timestamp()
             RETURNING pkce_verifier, nonce, session_digest",
        )
        .bind(state_digest.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(ManagementOidcTransaction {
                pkce_verifier: row.try_get("pkce_verifier")?,
                nonce: row.try_get("nonce")?,
                session_digest: row.try_get("session_digest")?,
            })
        })
        .transpose()
    }

    /// Creates an opaque, revocable browser session with an eight-hour absolute
    /// lifetime and a fifteen-minute idle timeout.
    ///
    /// Only the session-token digest is used as its key. The independent CSRF
    /// token is retained so the browser can retrieve it from its authenticated
    /// bootstrap endpoint.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for malformed identity/session
    /// data, or [`StoreError::Database`] when persistence fails.
    pub async fn create_management_browser_session(
        &self,
        session_digest: &[u8; 32],
        issuer: &str,
        subject: &str,
        csrf_token: &str,
    ) -> Result<(), StoreError> {
        if issuer.is_empty()
            || issuer.len() > 2_048
            || issuer.chars().any(char::is_control)
            || subject.is_empty()
            || subject.len() > 256
            || subject.trim() != subject
            || subject.chars().any(char::is_control)
            || csrf_token.len() != 64
            || !csrf_token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StoreError::InvalidCommand);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM xshield.management_browser_sessions
             WHERE revoked_at IS NOT NULL OR expires_at <= clock_timestamp()",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO xshield.management_browser_sessions
                (session_digest, issuer, subject, csrf_token, created_at, last_seen_at,
                 expires_at, revoked_at)
             VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp(),
                     clock_timestamp() + interval '8 hours', NULL)",
        )
        .bind(session_digest.as_slice())
        .bind(issuer)
        .bind(subject)
        .bind(csrf_token)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Touches and returns an active session, enforcing idle and absolute
    /// expiry with the database clock.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the session lookup/update fails.
    pub async fn active_management_browser_session(
        &self,
        session_digest: &[u8; 32],
    ) -> Result<Option<ManagementBrowserSession>, StoreError> {
        let row = sqlx::query(
            "UPDATE xshield.management_browser_sessions
             SET last_seen_at = clock_timestamp()
             WHERE session_digest = $1 AND revoked_at IS NULL
               AND expires_at > clock_timestamp()
               AND last_seen_at > clock_timestamp() - interval '15 minutes'
             RETURNING issuer, subject, csrf_token, created_at, last_seen_at,
                       expires_at, last_reauthenticated_at,
                       COALESCE(
                           last_reauthenticated_at > clock_timestamp() - interval '2 minutes',
                           false
                       ) AS step_up_valid",
        )
        .bind(session_digest.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(ManagementBrowserSession {
                issuer: row.try_get("issuer")?,
                subject: row.try_get("subject")?,
                csrf_token: row.try_get("csrf_token")?,
                created_at: row.try_get("created_at")?,
                last_seen_at: row.try_get("last_seen_at")?,
                expires_at: row.try_get("expires_at")?,
                last_reauthenticated_at: row.try_get("last_reauthenticated_at")?,
                step_up_valid: row.try_get("step_up_valid")?,
            })
        })
        .transpose()
    }

    /// Marks an active matching browser session as freshly reauthenticated.
    ///
    /// The database clock defines the two-minute validity window. This update
    /// only succeeds for the exact issuer/subject and a still-live idle session.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the state transition cannot be
    /// durably recorded.
    pub async fn reauthenticate_management_browser_session(
        &self,
        session_digest: &[u8; 32],
        issuer: &str,
        subject: &str,
    ) -> Result<bool, StoreError> {
        Ok(sqlx::query(
            "UPDATE xshield.management_browser_sessions
             SET last_seen_at = GREATEST(last_seen_at, statement_timestamp()),
                 last_reauthenticated_at = GREATEST(last_seen_at, statement_timestamp())
             WHERE session_digest = $1 AND issuer = $2 AND subject = $3
               AND revoked_at IS NULL AND expires_at > clock_timestamp()
               AND last_seen_at > clock_timestamp() - interval '15 minutes'",
        )
        .bind(session_digest.as_slice())
        .bind(issuer)
        .bind(subject)
        .execute(&self.pool)
        .await?
        .rows_affected()
            == 1)
    }

    /// Revokes a session by its opaque-token digest.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the revocation cannot be stored.
    pub async fn revoke_management_browser_session(
        &self,
        session_digest: &[u8; 32],
    ) -> Result<bool, StoreError> {
        Ok(sqlx::query(
            "UPDATE xshield.management_browser_sessions
             SET revoked_at = clock_timestamp()
             WHERE session_digest = $1 AND revoked_at IS NULL",
        )
        .bind(session_digest.as_slice())
        .execute(&self.pool)
        .await?
        .rows_affected()
            == 1)
    }
}
