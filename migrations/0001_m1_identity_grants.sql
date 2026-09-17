CREATE SCHEMA xshield;

CREATE TABLE xshield.policy_revisions (
    tenant_id text NOT NULL CHECK (tenant_id <> ''),
    site_id text NOT NULL CHECK (site_id <> ''),
    revision text NOT NULL CHECK (revision <> ''),
    status text NOT NULL CHECK (status IN ('draft', 'tested', 'approved', 'active', 'retired')),
    content_digest text NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    artifact_ref text NOT NULL CHECK (artifact_ref <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    approved_by text,
    PRIMARY KEY (tenant_id, site_id, revision)
);

CREATE TABLE xshield.auth_bindings (
    tenant_id text NOT NULL CHECK (tenant_id <> ''),
    site_id text NOT NULL CHECK (site_id <> ''),
    binding_id text NOT NULL CHECK (
        binding_id ~ '^auth_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    waf_sid_fingerprint bytea NOT NULL CHECK (octet_length(waf_sid_fingerprint) = 32),
    principal_ref text,
    auth_epoch bigint NOT NULL CHECK (auth_epoch >= 0),
    credential_generation bigint NOT NULL CHECK (credential_generation >= 0),
    status text NOT NULL CHECK (status IN ('anonymous', 'active', 'revoked', 'expired')),
    absolute_expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, site_id, binding_id),
    CHECK (
        (status = 'anonymous' AND principal_ref IS NULL)
        OR (status = 'active' AND principal_ref IS NOT NULL)
        OR status IN ('revoked', 'expired')
    )
);

CREATE UNIQUE INDEX auth_binding_active_session
    ON xshield.auth_bindings (tenant_id, site_id, waf_sid_fingerprint)
    WHERE status IN ('active', 'anonymous');

CREATE TABLE xshield.credential_bindings (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    binding_id text NOT NULL,
    generation bigint NOT NULL CHECK (generation >= 0),
    credential_kind text NOT NULL CHECK (credential_kind IN ('cookie', 'bearer', 'body_token')),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    predecessor_generation bigint CHECK (predecessor_generation >= 0),
    expires_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'transition', 'revoked')),
    PRIMARY KEY (tenant_id, site_id, binding_id, generation, credential_kind),
    FOREIGN KEY (tenant_id, site_id, binding_id)
        REFERENCES xshield.auth_bindings (tenant_id, site_id, binding_id)
);

CREATE INDEX credential_exact_lookup
    ON xshield.credential_bindings (tenant_id, site_id, credential_kind, fingerprint);

CREATE TABLE xshield.ui_actions (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    action_ref text NOT NULL CHECK (action_ref <> ''),
    binding_id text NOT NULL,
    auth_epoch bigint NOT NULL CHECK (auth_epoch >= 0),
    source_request_id text NOT NULL,
    page_evidence_id text NOT NULL,
    source_action_ref text,
    operation_id text NOT NULL,
    target_constraints jsonb NOT NULL CHECK (jsonb_typeof(target_constraints) = 'object'),
    field_profile text NOT NULL,
    source_rule text NOT NULL,
    policy_revision text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    PRIMARY KEY (tenant_id, site_id, action_ref),
    FOREIGN KEY (tenant_id, site_id, binding_id)
        REFERENCES xshield.auth_bindings (tenant_id, site_id, binding_id),
    FOREIGN KEY (tenant_id, site_id, policy_revision)
        REFERENCES xshield.policy_revisions (tenant_id, site_id, revision)
);

CREATE INDEX action_eligibility
    ON xshield.ui_actions (
        tenant_id, site_id, binding_id, auth_epoch, operation_id, expires_at
    )
    WHERE status = 'active';

CREATE TABLE xshield.resource_grants (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    grant_id text NOT NULL CHECK (
        grant_id ~ '^grant_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    binding_id text NOT NULL,
    auth_epoch bigint NOT NULL CHECK (auth_epoch >= 0),
    action_ref text NOT NULL,
    resource_type text NOT NULL CHECK (resource_type <> ''),
    resource_key_hmac bytea NOT NULL CHECK (octet_length(resource_key_hmac) = 32),
    operation_id text NOT NULL CHECK (operation_id <> ''),
    view_id text NOT NULL CHECK (view_id <> ''),
    constraints jsonb NOT NULL CHECK (jsonb_typeof(constraints) = 'object'),
    source_event_id text NOT NULL,
    issuance_key text NOT NULL CHECK (issuance_key <> ''),
    policy_revision text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    PRIMARY KEY (tenant_id, site_id, grant_id),
    UNIQUE (tenant_id, site_id, issuance_key),
    FOREIGN KEY (tenant_id, site_id, binding_id)
        REFERENCES xshield.auth_bindings (tenant_id, site_id, binding_id),
    FOREIGN KEY (tenant_id, site_id, action_ref)
        REFERENCES xshield.ui_actions (tenant_id, site_id, action_ref),
    FOREIGN KEY (tenant_id, site_id, policy_revision)
        REFERENCES xshield.policy_revisions (tenant_id, site_id, revision)
);

CREATE INDEX grant_exact_lookup
    ON xshield.resource_grants (
        tenant_id, site_id, binding_id, auth_epoch, resource_type,
        resource_key_hmac, operation_id, view_id, expires_at
    )
    WHERE status = 'active';

CREATE TABLE xshield.audit_outbox (
    event_id text PRIMARY KEY CHECK (event_id <> ''),
    tenant_id text NOT NULL CHECK (tenant_id <> ''),
    site_id text NOT NULL CHECK (site_id <> ''),
    aggregate_ref text NOT NULL CHECK (aggregate_ref <> ''),
    event_type text NOT NULL CHECK (event_type <> ''),
    envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    lease_until timestamptz,
    delivery_attempts integer NOT NULL DEFAULT 0 CHECK (delivery_attempts >= 0)
);

CREATE INDEX outbox_pending
    ON xshield.audit_outbox (created_at, event_id)
    WHERE published_at IS NULL;
