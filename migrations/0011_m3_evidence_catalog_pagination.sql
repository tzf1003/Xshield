BEGIN;

CREATE INDEX artifact_request_page
    ON xshield.artifact_catalog (
        tenant_id, site_id, request_id, artifact_id
    )
    WHERE status = 'active' AND deleted_at IS NULL;

COMMIT;
