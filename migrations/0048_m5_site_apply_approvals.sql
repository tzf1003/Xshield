ALTER TABLE xshield.site_apply_intents
    ADD COLUMN IF NOT EXISTS requires_approval boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS approved_by text,
    ADD COLUMN IF NOT EXISTS approval_id text,
    ADD COLUMN IF NOT EXISTS approval_idempotency_digest bytea;

ALTER TABLE xshield.site_apply_intents
    ADD CONSTRAINT site_apply_intents_approval_id_shape
        CHECK (approval_id IS NULL OR approval_id ~ '^approval_[0-9a-f-]{36}$');

ALTER TABLE xshield.site_apply_intents
    ADD CONSTRAINT site_apply_intents_approval_idempotency_digest_shape
        CHECK (approval_idempotency_digest IS NULL OR octet_length(approval_idempotency_digest) = 32);
