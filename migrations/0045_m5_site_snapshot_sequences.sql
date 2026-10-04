-- Tenant-scoped monotonic revisions for complete edge snapshots.
-- Per-site policy revisions are not a total order when several sites share an
-- edge; this sequence prevents an older complete snapshot from being accepted
-- after a newer one during concurrent control-plane applies.
CREATE TABLE xshield.site_snapshot_sequences (
    tenant_id text PRIMARY KEY CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    current_revision bigint NOT NULL CHECK (current_revision >= 1),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO xshield.site_snapshot_sequences (tenant_id, current_revision)
SELECT config.tenant_id, GREATEST(
    COALESCE(MAX(config.revision), 0),
    COALESCE(MAX(apply.active_revision), 0),
    1
)
FROM xshield.protected_site_configs AS config
LEFT JOIN xshield.site_apply_intents AS apply
  ON apply.tenant_id = config.tenant_id
 AND apply.site_id = config.site_id
GROUP BY config.tenant_id
ON CONFLICT (tenant_id) DO UPDATE
SET current_revision = GREATEST(
        xshield.site_snapshot_sequences.current_revision,
        EXCLUDED.current_revision
    ),
    updated_at = now();
