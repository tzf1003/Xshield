-- Upgrade: build before enabling case discovery. This non-concurrent build
-- blocks case writes while indexing; schedule an appropriate maintenance window
-- for large tables. Existing open-case capacity lookups retain their index.
-- Rollback: the application can be rolled back with this additive index intact.
-- DROP INDEX xshield.investigation_case_owner_page removes only this index;
-- case data and outbox history remain, but list queries may require a sort/scan.
BEGIN;

CREATE INDEX investigation_case_owner_page
    ON xshield.investigation_cases (
        tenant_id, site_id, owner_ref, case_id COLLATE "C" DESC
    );

COMMIT;
