-- M4 lineage review bindings are authorization provenance. Once a capability
-- or report has been committed, ordinary database writers must not rebind it
-- to another otherwise-valid review. Retention may update its own state, but
-- never this authorization identity.
--
-- Rollback: stop new calibration issuance/report publication first. Retain
-- these guards with the durable facts; removing them would make historical
-- lineage provenance mutable without a migration or a dedicated repair path.
BEGIN;

CREATE FUNCTION xshield.reject_calibration_lineage_review_binding_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.lineage_review_id IS DISTINCT FROM OLD.lineage_review_id THEN
        RAISE EXCEPTION 'calibration lineage review binding is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER calibration_read_capability_reject_lineage_review_update
BEFORE UPDATE OF lineage_review_id ON xshield.calibration_read_capabilities
FOR EACH ROW EXECUTE FUNCTION xshield.reject_calibration_lineage_review_binding_mutation();

CREATE TRIGGER calibration_report_reject_lineage_review_update
BEFORE UPDATE OF lineage_review_id ON xshield.calibration_reports
FOR EACH ROW EXECUTE FUNCTION xshield.reject_calibration_lineage_review_binding_mutation();

COMMIT;
