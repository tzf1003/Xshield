CREATE TABLE xshield.share_grants (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    share_id text NOT NULL CHECK (
        share_id ~ '^share_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    issuer_binding_id text NOT NULL,
    token_fingerprint bytea NOT NULL CHECK (octet_length(token_fingerprint) = 32),
    resource_type text NOT NULL CHECK (resource_type <> ''),
    resource_key_hmac bytea NOT NULL CHECK (octet_length(resource_key_hmac) = 32),
    operation_id text NOT NULL CHECK (operation_id <> ''),
    view_id text NOT NULL CHECK (view_id <> ''),
    use_policy text NOT NULL CHECK (use_policy = 'reusable_read'),
    source_event_id text NOT NULL CHECK (source_event_id <> ''),
    policy_revision text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    PRIMARY KEY (tenant_id, site_id, share_id),
    FOREIGN KEY (tenant_id, site_id, issuer_binding_id)
        REFERENCES xshield.auth_bindings (tenant_id, site_id, binding_id),
    FOREIGN KEY (tenant_id, site_id, policy_revision)
        REFERENCES xshield.policy_revisions (tenant_id, site_id, revision)
);

CREATE UNIQUE INDEX share_grant_active_token
    ON xshield.share_grants (tenant_id, site_id, token_fingerprint)
    WHERE status = 'active';

CREATE INDEX share_grant_exact_lookup
    ON xshield.share_grants (
        tenant_id, site_id, token_fingerprint, resource_type,
        resource_key_hmac, operation_id, view_id, expires_at
    ) WHERE status = 'active';
