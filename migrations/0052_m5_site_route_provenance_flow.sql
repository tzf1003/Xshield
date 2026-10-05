-- Let the normalized route projection hold the browser provenance flow.
--
-- Control-plane routes may now use the AUTH_ENTRY admission (an approved
-- authentication entry whose `auth_binding` establishes identity) and may carry
-- the page-issuance link `issued_by`. The authoritative copies stay in
-- `protected_site_configs.policy_json` and `site_policy_revisions.config_json`
-- (JSONB, read back through the typed configuration), which need no change.
-- This only widens the write-only `site_routes` projection, which the site
-- write transaction fills next to them: without it that transaction fails on
-- the admission CHECK and nothing is stored.
--
-- Additive and idempotent: the wider CHECK accepts every existing row, and the
-- new column is nullable. Narrowing the CHECK again is not a supported
-- rollback once AUTH_ENTRY rows exist; older binaries never write them.

ALTER TABLE xshield.site_routes
    DROP CONSTRAINT IF EXISTS site_routes_admission_check;
ALTER TABLE xshield.site_routes
    ADD CONSTRAINT site_routes_admission_check
        CHECK (admission IN ('PUBLIC', 'AUTH_ENTRY', 'AUTHENTICATED_ROOT', 'UI_ACTION_REQUIRED'));

ALTER TABLE xshield.site_routes
    ADD COLUMN IF NOT EXISTS issued_by jsonb;
ALTER TABLE xshield.site_routes
    DROP CONSTRAINT IF EXISTS site_routes_issued_by_object;
ALTER TABLE xshield.site_routes
    ADD CONSTRAINT site_routes_issued_by_object
        CHECK (issued_by IS NULL OR jsonb_typeof(issued_by) = 'object');
