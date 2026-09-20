-- Upgrade before enabling access-request discovery. Index construction blocks
-- writes to this table; schedule a maintenance window for a large deployment.
-- Rollback may leave these additive indexes intact, or drop only these indexes;
-- request records and immutable outbox events are preserved.
BEGIN;

CREATE INDEX evidence_access_owner_page
    ON xshield.evidence_access_requests (
        tenant_id, site_id, requested_by, access_request_id COLLATE "C" DESC
    );

CREATE INDEX evidence_access_pending_page
    ON xshield.evidence_access_requests (
        tenant_id, site_id, access_request_id COLLATE "C" DESC
    ) WHERE status = 'pending';

COMMIT;
