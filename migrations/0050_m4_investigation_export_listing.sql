-- Upgrade before enabling investigation-export discovery. Index construction
-- blocks writes to this table; schedule a maintenance window for a large
-- deployment. Rollback may leave these additive indexes intact, or drop only
-- these indexes; export rows, package claims and immutable audit history are
-- preserved, and list queries merely fall back to a scan plus sort.
--
-- Migration 0039 indexes a requester by created_at and its primary key uses the
-- database default collation, so neither can serve the bytewise export_id
-- keyset pages and cursor comparison that discovery requires.
BEGIN;

CREATE INDEX IF NOT EXISTS investigation_export_owner_page
    ON xshield.investigation_exports (
        tenant_id, site_id, requested_by, export_id COLLATE "C" DESC
    );

CREATE INDEX IF NOT EXISTS investigation_export_pending_page
    ON xshield.investigation_exports (
        tenant_id, site_id, export_id COLLATE "C" DESC
    ) WHERE status = 'pending_approval';

COMMIT;
