-- Short MFA-backed reauthentication state for sensitive browser operations.
--
-- The OIDC transaction is tied to the existing session digest; a callback may
-- not create a new session or elevate a different subject. Rollback must first
-- disable raw evidence reads or keep the step-up-aware control release active.
BEGIN;

ALTER TABLE xshield.management_oidc_transactions
    ADD COLUMN session_digest bytea
        CHECK (session_digest IS NULL OR octet_length(session_digest) = 32);

ALTER TABLE xshield.management_browser_sessions
    ADD COLUMN last_reauthenticated_at timestamptz,
    ADD CONSTRAINT management_browser_sessions_reauthenticated_at_valid CHECK (
        last_reauthenticated_at IS NULL
        OR (
            isfinite(last_reauthenticated_at)
            AND last_reauthenticated_at >= created_at
            AND last_reauthenticated_at <= last_seen_at
        )
    );

COMMENT ON COLUMN xshield.management_oidc_transactions.session_digest IS
    'Non-null only for a one-use step-up transaction bound to its existing browser session.';
COMMENT ON COLUMN xshield.management_browser_sessions.last_reauthenticated_at IS
    'Database-clock time of the latest verified, session-bound MFA step-up.';

COMMIT;
