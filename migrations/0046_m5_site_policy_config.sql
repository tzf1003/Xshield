-- Persist the typed policy surface alongside the compatibility projection.
-- The value contains references and bounded policy metadata only; secret
-- material is never accepted by the control API or stored in this column.
ALTER TABLE xshield.protected_site_configs
    ADD COLUMN IF NOT EXISTS policy_json jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE xshield.protected_site_configs
SET policy_json = '{}'::jsonb
WHERE policy_json IS NULL;

ALTER TABLE xshield.protected_site_configs
    DROP CONSTRAINT IF EXISTS protected_site_configs_policy_object;

ALTER TABLE xshield.protected_site_configs
    ADD CONSTRAINT protected_site_configs_policy_object
    CHECK (jsonb_typeof(policy_json) = 'object');
