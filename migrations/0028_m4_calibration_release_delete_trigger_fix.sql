-- Correct the release-reservation catalog guard for DELETE operations.
--
-- PostgreSQL requires a BEFORE DELETE row trigger to return OLD to continue
-- the deletion.  Returning NEW silently skips the row, which would make an
-- unreserved catalog object undeletable.  The reservation exclusion remains
-- unchanged: a live matching reservation still raises 55000 before either
-- mutation kind can proceed.
--
-- Rollback: do not restore the old trigger body.  Retaining this correction
-- preserves ordinary catalog retention while the reservation guard remains
-- active.
BEGIN;

CREATE OR REPLACE FUNCTION xshield.reject_catalog_mutation_during_calibration_release()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM xshield.calibration_evidence_release_reservations reservation
        WHERE reservation.tenant_id = OLD.tenant_id
          AND reservation.site_id = OLD.site_id
          AND reservation.artifact_id = OLD.artifact_id
          AND reservation.reserved_until > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'calibration plaintext release is reserved'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

COMMIT;
