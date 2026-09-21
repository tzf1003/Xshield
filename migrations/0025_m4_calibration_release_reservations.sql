-- M4 plaintext-release linearization. A vault reader may need bounded local
-- I/O after it has verified catalog authority. This table gives that short
-- interval an exact, token-digest-bound durable reservation without holding a
-- PostgreSQL row lock across vault decryption or local journal fsync.
--
-- Catalog mutation for a reserved artifact is rejected by the trigger below.
-- The reader commits the release boundary only after its local encrypted
-- journal receipt; it then deletes the reservation in the same transaction.
-- Expired reservations are ignored, so a crashed reader cannot retain an
-- artifact beyond the bounded window.
--
-- Rollback: stop readers first. Ordinary rollback leaves this additive guard
-- in place because dropping it would reopen the release race.
BEGIN;

CREATE TABLE xshield.calibration_evidence_release_reservations (
    reservation_id text PRIMARY KEY CHECK (
        reservation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    capability_id text NOT NULL,
    lease_id text NOT NULL,
    artifact_id text NOT NULL,
    lease_token_digest bytea NOT NULL CHECK (octet_length(lease_token_digest) = 32),
    reserved_at timestamptz NOT NULL CHECK (
        isfinite(reserved_at)
        AND date_trunc('milliseconds', reserved_at) = reserved_at
    ),
    reserved_until timestamptz NOT NULL CHECK (
        isfinite(reserved_until)
        AND reserved_until > reserved_at
        AND date_trunc('milliseconds', reserved_until) = reserved_until
    ),
    FOREIGN KEY (tenant_id, site_id, capability_id)
        REFERENCES xshield.calibration_read_capabilities (tenant_id, site_id, capability_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (lease_id)
        REFERENCES xshield.calibration_read_capability_leases (lease_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, site_id, artifact_id)
        REFERENCES xshield.artifact_catalog (tenant_id, site_id, artifact_id)
        ON DELETE RESTRICT,
    UNIQUE (tenant_id, site_id, capability_id, lease_id, artifact_id)
);

CREATE INDEX calibration_release_reservation_artifact_live
    ON xshield.calibration_evidence_release_reservations (
        tenant_id, site_id, artifact_id, reserved_until
    );

CREATE FUNCTION xshield.reject_catalog_mutation_during_calibration_release()
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
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifact_catalog_reject_calibration_release_mutation
BEFORE UPDATE OR DELETE ON xshield.artifact_catalog
FOR EACH ROW EXECUTE FUNCTION xshield.reject_catalog_mutation_during_calibration_release();

COMMIT;
