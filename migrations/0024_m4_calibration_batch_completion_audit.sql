-- M4 completion terminal: the only path that consumes a calibration batch
-- must atomically retain a minimal, searchable audit fact. The capability and
-- lease tables remain the authorization truth; this reference prevents a
-- completed header from silently losing the terminal it committed with.
--
-- Upgrade after 0023. Rollback disables completion first; do not drop this
-- additive column or immutable outbox events as an ordinary rollback.
BEGIN;

ALTER TABLE xshield.calibration_read_capabilities
    ADD COLUMN completion_event_id text UNIQUE;

ALTER TABLE xshield.calibration_read_capabilities
    ADD CONSTRAINT calibration_read_capability_completion_event_fk
    FOREIGN KEY (completion_event_id)
    REFERENCES xshield.audit_outbox (event_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE xshield.calibration_read_capabilities
    ADD CONSTRAINT calibration_read_capability_completion_audit_shape CHECK (
        (status = 'consumed') = (completion_event_id IS NOT NULL)
    ) NOT VALID;

COMMIT;
