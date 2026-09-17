CREATE TABLE xshield.share_issuance_rules (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    policy_revision text NOT NULL,
    rule_id text NOT NULL CHECK (rule_id <> ''),
    issuer_operation_id text NOT NULL CHECK (issuer_operation_id <> ''),
    issuer_view_id text NOT NULL CHECK (issuer_view_id <> ''),
    share_operation_id text NOT NULL CHECK (share_operation_id <> ''),
    share_view_id text NOT NULL CHECK (share_view_id <> ''),
    max_ttl_seconds bigint NOT NULL CHECK (max_ttl_seconds BETWEEN 1 AND 86400),
    status text NOT NULL CHECK (status IN ('active', 'retired')),
    CHECK (issuer_operation_id <> share_operation_id),
    PRIMARY KEY (tenant_id, site_id, policy_revision, rule_id),
    FOREIGN KEY (tenant_id, site_id, policy_revision)
        REFERENCES xshield.policy_revisions (tenant_id, site_id, revision)
);

ALTER TABLE xshield.share_grants
    ADD COLUMN issuer_auth_epoch bigint CHECK (issuer_auth_epoch >= 0),
    ADD COLUMN issuer_grant_id text,
    ADD COLUMN issuance_rule_id text,
    ADD COLUMN issuance_key text CHECK (issuance_key <> ''),
    ADD CHECK (
        (issuer_auth_epoch IS NULL AND issuer_grant_id IS NULL
            AND issuance_rule_id IS NULL AND issuance_key IS NULL)
        OR
        (issuer_auth_epoch IS NOT NULL AND issuer_grant_id IS NOT NULL
            AND issuance_rule_id IS NOT NULL AND issuance_key IS NOT NULL)
    ),
    ADD FOREIGN KEY (tenant_id, site_id, issuer_grant_id)
        REFERENCES xshield.resource_grants (tenant_id, site_id, grant_id),
    ADD FOREIGN KEY (tenant_id, site_id, policy_revision, issuance_rule_id)
        REFERENCES xshield.share_issuance_rules (
            tenant_id, site_id, policy_revision, rule_id
        );

CREATE UNIQUE INDEX share_grant_qualified_issuance
    ON xshield.share_grants (tenant_id, site_id, issuance_key)
    WHERE issuance_key IS NOT NULL;

CREATE INDEX share_grant_issuer_capacity
    ON xshield.share_grants (
        tenant_id, site_id, issuer_binding_id, issuer_auth_epoch, expires_at
    ) WHERE status = 'active' AND issuer_auth_epoch IS NOT NULL;
