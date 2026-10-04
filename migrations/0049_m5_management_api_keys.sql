-- Dedicated management API keys for scoped automation agents.
-- Only a keyed fingerprint is retained; the presented secret is never durable.
CREATE TABLE xshield.management_api_keys (
    api_key_id text PRIMARY KEY CHECK (api_key_id ~ '^key_[0-9a-f-]{36}$'),
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 256),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    key_prefix text NOT NULL CHECK (key_prefix ~ '^xsk_[A-Za-z0-9]{4,32}$'),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    expires_at timestamptz NOT NULL,
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    last_used_at timestamptz,
    UNIQUE (tenant_id, fingerprint),
    CHECK ((status = 'active' AND revoked_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL))
);

CREATE TABLE xshield.management_api_key_scopes (
    api_key_id text NOT NULL REFERENCES xshield.management_api_keys(api_key_id)
        ON DELETE CASCADE,
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    capability text NOT NULL CHECK (capability IN (
        'site.read', 'site.create', 'site.config.write',
        'site.config.validate', 'site.config.apply_direct',
        'site.health.read', 'site.rollback'
    )),
    PRIMARY KEY (api_key_id, tenant_id, site_id, capability)
);

CREATE INDEX management_api_keys_active_lookup
    ON xshield.management_api_keys (tenant_id, fingerprint)
    WHERE status = 'active';

CREATE INDEX management_api_key_scopes_lookup
    ON xshield.management_api_key_scopes (api_key_id, tenant_id, site_id, capability);
