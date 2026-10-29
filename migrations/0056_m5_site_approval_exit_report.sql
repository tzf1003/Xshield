-- docs/32 32.7 decision 4: an approval that tightens an observe rollout
-- records which exit report it relied on. The digest is the control plane's
-- SHA-256 of the report facts (GET /control/v1/rollout-report); it is optional
-- and never authorizes anything by itself.
ALTER TABLE xshield.site_apply_approvals
    ADD COLUMN IF NOT EXISTS exit_report_digest bytea CHECK (
        exit_report_digest IS NULL OR octet_length(exit_report_digest) = 32
    );
