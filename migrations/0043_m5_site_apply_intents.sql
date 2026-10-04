-- Durable desired/active boundary for save-then-apply site changes.
CREATE TABLE xshield.site_apply_intents (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    desired_revision bigint NOT NULL CHECK (desired_revision >= 1),
    active_revision bigint CHECK (active_revision IS NULL OR active_revision >= 1),
    apply_id text NOT NULL CHECK (apply_id ~ '^apply_[0-9a-f-]{36}$'),
    apply_state text NOT NULL CHECK (apply_state IN ('active', 'pending', 'failed', 'paused')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z0-9_]{1,96}$'),
    retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, site_id),
    UNIQUE (tenant_id, apply_id),
    FOREIGN KEY (tenant_id, site_id)
        REFERENCES xshield.protected_site_configs (tenant_id, site_id)
        ON DELETE CASCADE
);

CREATE INDEX site_apply_intents_pending
    ON xshield.site_apply_intents (tenant_id, apply_state, updated_at DESC);

INSERT INTO xshield.site_apply_intents (
    tenant_id, site_id, desired_revision, active_revision, apply_id,
    apply_state, reason_code
)
SELECT tenant_id, site_id, revision, NULL,
       'apply_' || gen_random_uuid()::text,
       CASE WHEN status = 'paused' THEN 'paused' ELSE 'pending' END,
       'EDGE_APPLY_NOT_CONFIRMED'
FROM xshield.protected_site_configs
ON CONFLICT (tenant_id, site_id) DO NOTHING;
