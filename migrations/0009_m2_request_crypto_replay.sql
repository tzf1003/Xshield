BEGIN;

CREATE TABLE xshield.request_crypto_messages (
    tenant_id text NOT NULL CHECK (tenant_id <> ''),
    site_id text NOT NULL CHECK (site_id <> ''),
    key_id text NOT NULL CHECK (key_id <> ''),
    message_id text NOT NULL CHECK (
        message_id ~ '^msg_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    source_request_id text NOT NULL CHECK (source_request_id <> ''),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, site_id, key_id, nonce),
    UNIQUE (tenant_id, site_id, key_id, message_id)
);

CREATE INDEX request_crypto_message_expiry
    ON xshield.request_crypto_messages (tenant_id, site_id, expires_at);

COMMIT;
