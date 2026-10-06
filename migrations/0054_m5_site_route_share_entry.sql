-- Let the normalized route projection hold a share entry.
--
-- Control-plane routes may now use the SHARE_ENTRY admission: the fixed,
-- resource-bound read an issued share credential redeems without any identity
-- binding. The authoritative copy of every route stays in
-- `protected_site_configs.policy_json` and `site_policy_revisions.config_json`
-- (JSONB, read back through the typed configuration), which need no change.
-- This only widens the write-only `site_routes` projection, which the site
-- write transaction fills next to them: without it that transaction fails on
-- the admission CHECK and nothing is stored. The `share_issue` block needs no
-- column: it travels in `site_routes.response_config`, built from the same
-- typed projection the edge compiles.
--
-- Additive and idempotent: the wider CHECK accepts every existing row.
-- Narrowing the CHECK again is not a supported rollback once SHARE_ENTRY rows
-- exist; older binaries never write them.

ALTER TABLE xshield.site_routes
    DROP CONSTRAINT IF EXISTS site_routes_admission_check;
ALTER TABLE xshield.site_routes
    ADD CONSTRAINT site_routes_admission_check
        CHECK (admission IN (
            'PUBLIC', 'AUTH_ENTRY', 'AUTHENTICATED_ROOT', 'UI_ACTION_REQUIRED', 'SHARE_ENTRY'
        ));
