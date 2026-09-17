CREATE TABLE xshield.page_evidence (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    page_evidence_id text NOT NULL CHECK (
        page_evidence_id ~ '^page_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    binding_id text NOT NULL,
    auth_epoch bigint NOT NULL CHECK (auth_epoch >= 0),
    source_request_id text NOT NULL CHECK (
        source_request_id ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    response_artifact_ref text NOT NULL CHECK (response_artifact_ref <> ''),
    page_template text NOT NULL CHECK (page_template <> ''),
    build_fingerprint bytea NOT NULL CHECK (octet_length(build_fingerprint) = 32),
    policy_revision text NOT NULL,
    mapping_revision text NOT NULL CHECK (mapping_revision <> ''),
    status text NOT NULL CHECK (status IN ('verified', 'revoked', 'expired')),
    verified_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > verified_at),
    PRIMARY KEY (tenant_id, site_id, page_evidence_id),
    FOREIGN KEY (tenant_id, site_id, binding_id)
        REFERENCES xshield.auth_bindings (tenant_id, site_id, binding_id),
    FOREIGN KEY (tenant_id, site_id, policy_revision)
        REFERENCES xshield.policy_revisions (tenant_id, site_id, revision)
);

CREATE INDEX page_evidence_eligibility
    ON xshield.page_evidence (
        tenant_id, site_id, binding_id, auth_epoch,
        page_template, policy_revision, mapping_revision, expires_at
    )
    WHERE status = 'verified';

CREATE TABLE xshield.action_descriptors (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    action_id text NOT NULL CHECK (action_id <> ''),
    page_template text NOT NULL CHECK (page_template <> ''),
    operation_id text NOT NULL CHECK (operation_id <> ''),
    method text NOT NULL CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
    route_template text NOT NULL CHECK (
        route_template LIKE '/%'
        AND position('?' IN route_template) = 0
        AND position('#' IN route_template) = 0
    ),
    target_rule jsonb NOT NULL CHECK (jsonb_typeof(target_rule) = 'object'),
    allowed_fields jsonb NOT NULL CHECK (jsonb_typeof(allowed_fields) = 'array'),
    field_profile text NOT NULL CHECK (field_profile <> ''),
    policy_revision text NOT NULL,
    mapping_revision text NOT NULL CHECK (mapping_revision <> ''),
    status text NOT NULL CHECK (status IN ('approved', 'retired')),
    PRIMARY KEY (
        tenant_id, site_id, action_id, policy_revision, mapping_revision
    ),
    FOREIGN KEY (tenant_id, site_id, policy_revision)
        REFERENCES xshield.policy_revisions (tenant_id, site_id, revision)
);

CREATE INDEX action_descriptor_lookup
    ON xshield.action_descriptors (
        tenant_id, site_id, action_id, policy_revision, mapping_revision
    )
    WHERE status = 'approved';

ALTER TABLE xshield.ui_actions
    ALTER COLUMN source_action_ref SET NOT NULL,
    ADD COLUMN mapping_revision text NOT NULL CHECK (mapping_revision <> ''),
    ADD COLUMN method text NOT NULL CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
    ADD COLUMN route_template text NOT NULL CHECK (
        route_template LIKE '/%'
        AND position('?' IN route_template) = 0
        AND position('#' IN route_template) = 0
    ),
    ADD COLUMN allowed_fields jsonb NOT NULL CHECK (jsonb_typeof(allowed_fields) = 'array'),
    ADD FOREIGN KEY (tenant_id, site_id, page_evidence_id)
        REFERENCES xshield.page_evidence (tenant_id, site_id, page_evidence_id),
    ADD FOREIGN KEY (
        tenant_id, site_id, source_action_ref, policy_revision, mapping_revision
    ) REFERENCES xshield.action_descriptors (
        tenant_id, site_id, action_id, policy_revision, mapping_revision
    );
