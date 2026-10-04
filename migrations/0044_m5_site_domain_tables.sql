-- Expand the compatibility projection into the normalized multi-site model.
-- The compatibility table remains the write boundary during migration; the
-- control adapter dual-writes these tables and later releases can switch reads.
CREATE TABLE xshield.protected_sites (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    status text NOT NULL CHECK (status IN ('draft', 'active', 'paused')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, site_id)
);

CREATE TABLE xshield.site_origins (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    public_origin text NOT NULL CHECK (char_length(public_origin) BETWEEN 1 AND 512),
    upstream_address text NOT NULL CHECK (char_length(upstream_address) BETWEEN 1 AND 128),
    upstream_server_name text NOT NULL CHECK (char_length(upstream_server_name) BETWEEN 1 AND 253),
    upstream_tls boolean NOT NULL,
    network_policy text NOT NULL DEFAULT 'approved-only',
    health_path text NOT NULL DEFAULT '/',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, site_id),
    FOREIGN KEY (tenant_id, site_id) REFERENCES xshield.protected_sites (tenant_id, site_id)
        ON DELETE CASCADE
);

CREATE TABLE xshield.site_routes (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    operation_id text NOT NULL CHECK (operation_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    method text NOT NULL CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
    path text NOT NULL CHECK (path ~ '^/[^?#]*$' AND char_length(path) <= 256),
    admission text NOT NULL CHECK (admission IN ('PUBLIC', 'AUTHENTICATED_ROOT', 'UI_ACTION_REQUIRED')),
    resource_type text,
    field_constraints jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, site_id, operation_id),
    FOREIGN KEY (tenant_id, site_id) REFERENCES xshield.protected_sites (tenant_id, site_id)
        ON DELETE CASCADE
);

CREATE TABLE xshield.site_policy_revisions (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    policy_revision text NOT NULL CHECK (char_length(policy_revision) BETWEEN 1 AND 128),
    config_digest bytea NOT NULL CHECK (octet_length(config_digest) = 32),
    config_json jsonb NOT NULL,
    signature bytea NOT NULL CHECK (octet_length(signature) BETWEEN 32 AND 128),
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, site_id, revision),
    FOREIGN KEY (tenant_id, site_id) REFERENCES xshield.protected_sites (tenant_id, site_id)
        ON DELETE CASCADE
);

CREATE TABLE xshield.site_health_snapshots (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    captured_at timestamptz NOT NULL DEFAULT now(),
    edge_state text NOT NULL CHECK (edge_state IN ('unknown', 'healthy', 'degraded', 'unavailable')),
    upstream_state text NOT NULL CHECK (upstream_state IN ('unknown', 'healthy', 'degraded', 'unavailable')),
    config_state text NOT NULL CHECK (config_state IN ('unknown', 'active', 'pending', 'failed', 'paused')),
    audit_state text NOT NULL CHECK (audit_state IN ('unknown', 'healthy', 'degraded', 'unavailable')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z0-9_]{1,96}$'),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, site_id, captured_at),
    FOREIGN KEY (tenant_id, site_id) REFERENCES xshield.protected_sites (tenant_id, site_id)
        ON DELETE CASCADE
);

CREATE TABLE xshield.site_secret_refs (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    secret_kind text NOT NULL CHECK (secret_kind IN ('tls', 'session_hmac', 'request_crypto', 'response_crypto', 'model')),
    secret_ref text NOT NULL CHECK (char_length(secret_ref) BETWEEN 1 AND 512),
    key_id text,
    state text NOT NULL CHECK (state IN ('active', 'pending_rotation', 'retired', 'unavailable')),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, site_id, secret_kind),
    FOREIGN KEY (tenant_id, site_id) REFERENCES xshield.protected_sites (tenant_id, site_id)
        ON DELETE CASCADE
);

INSERT INTO xshield.protected_sites (tenant_id, site_id, display_name, status)
SELECT tenant_id, site_id, display_name, status
FROM xshield.protected_site_configs
ON CONFLICT (tenant_id, site_id) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    status = EXCLUDED.status,
    updated_at = now();

INSERT INTO xshield.site_origins (
    tenant_id, site_id, public_origin, upstream_address, upstream_server_name, upstream_tls
)
SELECT tenant_id, site_id, public_origin, upstream_address, upstream_server_name, upstream_tls
FROM xshield.protected_site_configs
ON CONFLICT (tenant_id, site_id) DO UPDATE SET
    public_origin = EXCLUDED.public_origin,
    upstream_address = EXCLUDED.upstream_address,
    upstream_server_name = EXCLUDED.upstream_server_name,
    upstream_tls = EXCLUDED.upstream_tls,
    updated_at = now();

INSERT INTO xshield.site_routes (
    tenant_id, site_id, operation_id, method, path, admission
)
SELECT tenant_id,
       site_id,
       'protected.entry',
       'GET',
       entry_path,
       CASE security_entry
           WHEN 'public' THEN 'PUBLIC'
           WHEN 'authenticated_root' THEN 'AUTHENTICATED_ROOT'
           ELSE 'UI_ACTION_REQUIRED'
       END
FROM xshield.protected_site_configs
ON CONFLICT (tenant_id, site_id, operation_id) DO UPDATE SET
    method = EXCLUDED.method,
    path = EXCLUDED.path,
    admission = EXCLUDED.admission,
    updated_at = now();

INSERT INTO xshield.site_policy_revisions (
    tenant_id, site_id, revision, policy_revision, config_digest, config_json, signature, created_by
)
SELECT tenant_id,
       site_id,
       revision,
       policy_revision,
       config_digest,
       jsonb_build_object(
           'display_name', display_name,
           'public_origin', public_origin,
           'upstream_address', upstream_address,
           'upstream_server_name', upstream_server_name,
           'upstream_tls', upstream_tls,
           'listen_port', listen_port,
           'entry_path', entry_path,
           'security_entry', security_entry,
           'sensor_enabled', sensor_enabled,
           'status', status
       ),
       decode(repeat('00', 32), 'hex'),
       updated_by
FROM xshield.protected_site_configs
ON CONFLICT (tenant_id, site_id, revision) DO NOTHING;

CREATE INDEX site_policy_revisions_latest
    ON xshield.site_policy_revisions (tenant_id, site_id, revision DESC);
CREATE INDEX site_health_snapshots_latest
    ON xshield.site_health_snapshots (tenant_id, site_id, captured_at DESC);
