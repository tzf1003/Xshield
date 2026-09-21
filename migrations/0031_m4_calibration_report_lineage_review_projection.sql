-- M4 report recovery must retain the review identity used to issue its
-- capability. This makes an unknown-result retry compare the complete
-- authorization provenance without relying on mutable capability state.
--
-- Existing pre-gate reports remain retained audit facts. The NOT VALID check
-- rejects a new report projection without a review while avoiding a false
-- assertion that historic reports were reviewed.
BEGIN;

ALTER TABLE xshield.calibration_reports
    ADD COLUMN lineage_review_id text CHECK (
        lineage_review_id IS NULL
        OR lineage_review_id ~ '^calrev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    );

ALTER TABLE xshield.calibration_reports
    ADD CONSTRAINT calibration_report_lineage_review_fk
        FOREIGN KEY (tenant_id, site_id, lineage_review_id)
        REFERENCES xshield.calibration_lineage_reviews (tenant_id, site_id, review_id)
        ON DELETE RESTRICT;

ALTER TABLE xshield.calibration_reports
    ADD CONSTRAINT calibration_report_lineage_review_required
        CHECK (lineage_review_id IS NOT NULL) NOT VALID;

CREATE INDEX calibration_reports_lineage_review_lookup
    ON xshield.calibration_reports (tenant_id, site_id, lineage_review_id)
    WHERE lineage_review_id IS NOT NULL;

COMMENT ON COLUMN xshield.calibration_reports.lineage_review_id IS
    'Immutable lineage review that authorized the consumed capability; retained with each new report to make unknown-result recovery exact.';

COMMIT;
