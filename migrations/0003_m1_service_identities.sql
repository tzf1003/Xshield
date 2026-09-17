CREATE TABLE xshield.service_identities (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    service_id text NOT NULL CHECK (
        service_id ~ '^svc_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    credential_fingerprint bytea NOT NULL CHECK (octet_length(credential_fingerprint) = 32),
    operation_ids text[] NOT NULL CHECK (cardinality(operation_ids) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    PRIMARY KEY (tenant_id, site_id, service_id)
);

CREATE UNIQUE INDEX service_identity_active_credential
    ON xshield.service_identities (tenant_id, site_id, credential_fingerprint)
    WHERE status = 'active';
