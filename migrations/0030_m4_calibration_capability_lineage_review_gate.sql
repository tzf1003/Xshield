-- Bind every newly issued calibration read capability to one already committed
-- declaration-only lineage review. The review projection was inserted only
-- after dedicated vault attestation; the capability issuer locks and compares
-- that projection with its exact provenance and four manifest references.
--
-- Historical capabilities cannot be backfilled safely because a historical
-- event or outbox row is not proof of the required review. The nullable column
-- preserves audit history, while the NOT VALID check is enforced on every new
-- insert or update. The adapter rejects historical NULL rows before leasing,
-- authorizing, reserving, releasing, or completing a batch.
--
-- Rollback: disable new capability issuance and all calibration batch use
-- first. Ordinary rollback leaves the review bindings and immutable review
-- records in place; deleting them would weaken retained audit history.
BEGIN;

ALTER TABLE xshield.calibration_read_capabilities
    ADD COLUMN lineage_review_id text CHECK (
        lineage_review_id IS NULL
        OR lineage_review_id ~ '^calrev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    );

ALTER TABLE xshield.calibration_read_capabilities
    ADD CONSTRAINT calibration_read_capability_lineage_review_fk
        FOREIGN KEY (tenant_id, site_id, lineage_review_id)
        REFERENCES xshield.calibration_lineage_reviews (tenant_id, site_id, review_id)
        ON DELETE RESTRICT;

-- `NOT VALID` avoids pretending pre-gate rows were reviewed, while PostgreSQL
-- still enforces the invariant on every future INSERT or UPDATE.
ALTER TABLE xshield.calibration_read_capabilities
    ADD CONSTRAINT calibration_read_capability_lineage_review_required
        CHECK (lineage_review_id IS NOT NULL) NOT VALID;

CREATE INDEX calibration_read_capability_lineage_review_lookup
    ON xshield.calibration_read_capabilities (tenant_id, site_id, lineage_review_id)
    WHERE lineage_review_id IS NOT NULL;

COMMIT;
