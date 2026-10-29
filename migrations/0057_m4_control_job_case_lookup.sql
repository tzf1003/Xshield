-- Supports the case-scoped job listing added alongside this migration
-- (crates/xshield-postgres/src/control_job_case_list.rs): one owner's jobs for
-- one case, newest job_id first. control_jobs_owner_lookup already covers the
-- owner-only listing; this adds case_id so that equality filter is indexed too
-- instead of falling back to a sequential scan of the owner's other cases.
BEGIN;

CREATE INDEX control_jobs_case_owner_lookup
    ON xshield.control_jobs (tenant_id, site_id, owner_ref, case_id, job_id DESC);

COMMIT;
