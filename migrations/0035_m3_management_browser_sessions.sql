-- Server-side browser sessions for the human management console.
--
-- The browser receives only a random opaque session token; PostgreSQL stores
-- its SHA-256 digest. OIDC login state is one-use and short-lived. Roles are
-- resolved from the serving process's configured allowlist on every request;
-- a rollout removing a subject takes effect as each updated process serves.
--
-- Rollback: disable OIDC browser login and revoke active browser sessions
-- before dropping these tables. Do not preserve usable session digests in a
-- backup restored to a live control plane.
BEGIN;

CREATE TABLE xshield.management_oidc_transactions (
    state_digest bytea PRIMARY KEY CHECK (octet_length(state_digest) = 32),
    pkce_verifier text NOT NULL CHECK (
        octet_length(pkce_verifier) BETWEEN 43 AND 128
        AND pkce_verifier ~ '^[A-Za-z0-9._~-]+$'
    ),
    nonce text NOT NULL CHECK (
        octet_length(nonce) BETWEEN 1 AND 512
        AND nonce !~ '[[:cntrl:]]'
    ),
    expires_at timestamptz NOT NULL CHECK (
        isfinite(expires_at) AND expires_at > '1970-01-01 UTC'
    )
);

CREATE INDEX management_oidc_transactions_expiry
    ON xshield.management_oidc_transactions (expires_at);

CREATE TABLE xshield.management_browser_sessions (
    session_digest bytea PRIMARY KEY CHECK (octet_length(session_digest) = 32),
    issuer text NOT NULL CHECK (
        octet_length(issuer) BETWEEN 1 AND 2048
        AND issuer !~ '[[:cntrl:]]'
    ),
    subject text NOT NULL CHECK (
        octet_length(subject) BETWEEN 1 AND 256
        AND subject = btrim(subject)
        AND subject !~ '[[:cntrl:]]'
    ),
    csrf_token text NOT NULL CHECK (csrf_token ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (
        isfinite(created_at)
        AND isfinite(last_seen_at)
        AND isfinite(expires_at)
        AND expires_at > created_at
        AND last_seen_at >= created_at
        AND (revoked_at IS NULL OR (isfinite(revoked_at) AND revoked_at >= created_at))
    )
);

CREATE INDEX management_browser_sessions_expiry
    ON xshield.management_browser_sessions (expires_at)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE xshield.management_oidc_transactions IS
    'Single-use five-minute OIDC state, nonce, and PKCE verifier for control-plane login.';
COMMENT ON TABLE xshield.management_browser_sessions IS
    'Revocable opaque human-console sessions with eight-hour absolute and fifteen-minute idle expiry.';

COMMIT;
