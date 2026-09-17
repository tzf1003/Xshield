CREATE TABLE xshield.response_evidence (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    response_evidence_id text NOT NULL CHECK (
        response_evidence_id ~ '^response_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    binding_id text NOT NULL,
    auth_epoch bigint NOT NULL CHECK (auth_epoch >= 0),
    source_request_id text NOT NULL CHECK (
        source_request_id ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    source_operation_id text NOT NULL CHECK (source_operation_id <> ''),
    target_operation_id text NOT NULL CHECK (target_operation_id <> ''),
    response_status integer NOT NULL CHECK (
        response_status BETWEEN 200 AND 299 AND response_status <> 204
    ),
    response_artifact_ref text NOT NULL CHECK (response_artifact_ref <> ''),
    candidate_count integer NOT NULL CHECK (candidate_count BETWEEN 1 AND 1000),
    policy_revision text NOT NULL,
    status text NOT NULL CHECK (status IN ('verified', 'revoked', 'expired')),
    verified_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > verified_at),
    PRIMARY KEY (tenant_id, site_id, response_evidence_id),
    UNIQUE (
        tenant_id, site_id, source_request_id,
        source_operation_id, target_operation_id, policy_revision
    ),
    FOREIGN KEY (tenant_id, site_id, binding_id)
        REFERENCES xshield.auth_bindings (tenant_id, site_id, binding_id),
    FOREIGN KEY (tenant_id, site_id, policy_revision)
        REFERENCES xshield.policy_revisions (tenant_id, site_id, revision)
);

CREATE INDEX response_evidence_eligibility
    ON xshield.response_evidence (
        tenant_id, site_id, binding_id, auth_epoch,
        source_operation_id, target_operation_id, policy_revision, expires_at
    ) WHERE status = 'verified';

ALTER TABLE xshield.ui_actions
    ALTER COLUMN page_evidence_id DROP NOT NULL,
    ADD COLUMN response_evidence_id text,
    ADD CHECK (num_nonnulls(page_evidence_id, response_evidence_id) = 1),
    ADD FOREIGN KEY (tenant_id, site_id, response_evidence_id)
        REFERENCES xshield.response_evidence (
            tenant_id, site_id, response_evidence_id
        );

CREATE INDEX action_response_evidence
    ON xshield.ui_actions (tenant_id, site_id, response_evidence_id)
    WHERE response_evidence_id IS NOT NULL;
