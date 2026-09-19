BEGIN;

-- Delivery state is independent from the transactional event payload. A
-- nullable token lets existing rows be claimed without changing producers.
ALTER TABLE xshield.audit_outbox
    ADD COLUMN IF NOT EXISTS lease_token text,
    ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN IF NOT EXISTS last_error_code text;

CREATE INDEX IF NOT EXISTS outbox_delivery_ready
    ON xshield.audit_outbox (tenant_id, site_id, next_attempt_at, created_at, event_id)
    WHERE published_at IS NULL;

COMMIT;
