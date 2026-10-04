-- Bind approvals, idempotency keys and activation history to exact revisions.
--
-- Before this migration the "requires approval" flag was recomputed against the
-- previous *desired* revision on every write and cleared by re-submitting equal
-- content, an approval row had no revision or apply identity, and only the
-- latest write's idempotency key was remembered. Everything here is additive
-- and idempotent: it can be applied to a database that already holds sites.

-- Per-revision idempotency identity and activation time. A write replayed with
-- an older key is recognised (and refused) instead of silently creating a new
-- revision from stale content; "previously active revision" for rollback is the
-- revision with the latest activated_at before the current one.
ALTER TABLE xshield.site_policy_revisions
    ADD COLUMN IF NOT EXISTS idempotency_digest bytea,
    ADD COLUMN IF NOT EXISTS activated_at timestamptz;

ALTER TABLE xshield.site_policy_revisions
    DROP CONSTRAINT IF EXISTS site_policy_revisions_idempotency_digest_shape;
ALTER TABLE xshield.site_policy_revisions
    ADD CONSTRAINT site_policy_revisions_idempotency_digest_shape
        CHECK (idempotency_digest IS NULL OR octet_length(idempotency_digest) = 32);

CREATE UNIQUE INDEX IF NOT EXISTS site_policy_revisions_idempotency
    ON xshield.site_policy_revisions (tenant_id, site_id, idempotency_digest)
    WHERE idempotency_digest IS NOT NULL;

-- The edge currently serves the active revision of every site; record when it
-- became active so rollback can find the one before it.
UPDATE xshield.site_policy_revisions AS revision
SET activated_at = intent.updated_at
FROM xshield.site_apply_intents AS intent
WHERE revision.tenant_id = intent.tenant_id
  AND revision.site_id = intent.site_id
  AND revision.revision = intent.active_revision
  AND revision.activated_at IS NULL;

-- Why the desired revision needs independent approval (stable tokens computed
-- by the domain layer inside the write transaction); empty when it does not.
ALTER TABLE xshield.site_apply_intents
    ADD COLUMN IF NOT EXISTS risk_reasons text[] NOT NULL DEFAULT '{}';

-- Append-only record of every approval, bound to the exact
-- (desired revision, configuration digest, apply identity) it covers. Only a
-- row in this table can clear a revision's approval requirement.
CREATE TABLE IF NOT EXISTS xshield.site_apply_approvals (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    approval_id text NOT NULL CHECK (approval_id ~ '^approval_[0-9a-f-]{36}$'),
    desired_revision bigint NOT NULL CHECK (desired_revision >= 1),
    config_digest bytea NOT NULL CHECK (octet_length(config_digest) = 32),
    apply_id text NOT NULL CHECK (apply_id ~ '^apply_[0-9a-f-]{36}$'),
    approval_kind text NOT NULL CHECK (
        approval_kind IN ('independent', 'direct_apply', 'delete_step_up')
    ),
    approved_by text NOT NULL CHECK (char_length(approved_by) BETWEEN 1 AND 256),
    authored_by text NOT NULL CHECK (char_length(authored_by) BETWEEN 1 AND 256),
    idempotency_digest bytea CHECK (
        idempotency_digest IS NULL OR octet_length(idempotency_digest) = 32
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, site_id, approval_id),
    -- An apply intent is approved at most once.
    UNIQUE (tenant_id, site_id, apply_id),
    -- Independent approvals are never self-approvals.
    CHECK (approval_kind <> 'independent' OR approved_by <> authored_by),
    FOREIGN KEY (tenant_id, site_id)
        REFERENCES xshield.protected_site_configs (tenant_id, site_id)
        ON DELETE CASCADE
);

-- An approval idempotency key is bound to exactly one approval.
CREATE UNIQUE INDEX IF NOT EXISTS site_apply_approvals_idempotency
    ON xshield.site_apply_approvals (tenant_id, site_id, idempotency_digest)
    WHERE idempotency_digest IS NOT NULL;
