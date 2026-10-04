-- Administrative source of truth for one scoped protected-site gateway.
-- Secrets and credentials stay in deployment secret management; this table
-- only contains validated routing and policy metadata.
CREATE TABLE xshield.protected_site_configs (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    public_origin text NOT NULL CHECK (char_length(public_origin) BETWEEN 1 AND 512),
    upstream_address text NOT NULL CHECK (char_length(upstream_address) BETWEEN 1 AND 128),
    upstream_server_name text NOT NULL CHECK (char_length(upstream_server_name) BETWEEN 1 AND 253),
    upstream_tls boolean NOT NULL,
    listen_port integer NOT NULL CHECK (listen_port BETWEEN 6100 AND 65535),
    entry_path text NOT NULL CHECK (entry_path ~ '^/[^?#]*$' AND char_length(entry_path) <= 256),
    security_entry text NOT NULL CHECK (
        security_entry IN ('public', 'authenticated_root', 'ui_action_required')
    ),
    sensor_enabled boolean NOT NULL,
    policy_revision text NOT NULL CHECK (policy_revision ~ '^[A-Za-z0-9_.-]{1,128}$'),
    status text NOT NULL CHECK (status IN ('draft', 'active', 'paused')),
    revision bigint NOT NULL CHECK (revision >= 1),
    config_digest bytea NOT NULL CHECK (octet_length(config_digest) = 32),
    updated_by text NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 256),
    idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest) = 32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, site_id),
    UNIQUE (tenant_id, listen_port)
);

CREATE INDEX protected_site_configs_status
    ON xshield.protected_site_configs (tenant_id, status, updated_at DESC);
