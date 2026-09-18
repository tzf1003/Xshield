BEGIN;

CREATE TABLE xshield.anonymous_session_rate_limits (
    tenant_id text NOT NULL CHECK (tenant_id <> ''),
    site_id text NOT NULL CHECK (site_id <> ''),
    scope_kind text NOT NULL CHECK (scope_kind IN ('site', 'source')),
    scope_fingerprint bytea NOT NULL CHECK (octet_length(scope_fingerprint) = 32),
    window_started_at timestamptz NOT NULL,
    used bigint NOT NULL CHECK (used > 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, site_id, scope_kind, scope_fingerprint)
);

CREATE INDEX anonymous_session_rate_limit_expiry
    ON xshield.anonymous_session_rate_limits (
        tenant_id, site_id, window_started_at
    );

COMMIT;
