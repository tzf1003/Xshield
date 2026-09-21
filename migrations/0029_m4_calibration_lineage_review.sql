-- M4 declaration-only calibration partition-lineage review publication.
--
-- A lineage review is an authenticated restricted evidence object with no
-- request identity.  Its body contains the submitted source graph and stays
-- exclusively in the evidence vault.  PostgreSQL retains fixed metadata,
-- frozen provenance, the four manifest identities, and one restricted outbox
-- fact; none of those rows authorizes evidence access or policy publication.
--
-- This migration also creates the immutable cross-family artifact registry.
-- `artifact_catalog` and calibration reports previously each had a local
-- uniqueness constraint, which could not prevent a UUID reuse across object
-- families.  The registry is intentionally append-only: retention removes a
-- body, never the identity that protected an audit reference.
--
-- Rollback: disable lineage-review publication before any schema rollback.
-- Ordinary rollback leaves immutable audit, registry, and review facts in
-- place; retention and archival must follow their separate policy.
BEGIN;

CREATE TABLE xshield.artifact_identity_registry (
    artifact_id text PRIMARY KEY CHECK (
        artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    family text NOT NULL CHECK (
        family IN ('evidence_catalog', 'calibration_report', 'calibration_lineage_review')
    ),
    registered_at timestamptz NOT NULL CHECK (
        isfinite(registered_at)
        AND registered_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', registered_at) = registered_at
    )
);

COMMENT ON TABLE xshield.artifact_identity_registry IS
    'Append-only global artifact identity fence shared by request catalog, calibration report, and lineage-review evidence families.';

CREATE FUNCTION xshield.reject_artifact_identity_registry_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'artifact identity registry is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER artifact_identity_registry_reject_mutation
BEFORE UPDATE OR DELETE ON xshield.artifact_identity_registry
FOR EACH ROW EXECUTE FUNCTION xshield.reject_artifact_identity_registry_mutation();

-- Detect historical cross-family or cross-scope reuse explicitly.  An
-- `ON CONFLICT DO NOTHING` backfill would silently preserve exactly the
-- collision this registry is intended to close.
LOCK TABLE xshield.artifact_catalog, xshield.calibration_report_artifacts
    IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT artifact_id
        FROM (
            SELECT artifact_id FROM xshield.artifact_catalog
            UNION ALL
            SELECT artifact_id FROM xshield.calibration_report_artifacts
        ) AS existing_artifacts
        GROUP BY artifact_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot establish global artifact identity registry: existing artifact_id collision';
    END IF;
END;
$$;

INSERT INTO xshield.artifact_identity_registry (
    artifact_id, tenant_id, site_id, family, registered_at
)
SELECT artifact_id, tenant_id, site_id, 'evidence_catalog',
       date_trunc('milliseconds', clock_timestamp())
FROM xshield.artifact_catalog
UNION ALL
SELECT artifact_id, tenant_id, site_id, 'calibration_report',
       date_trunc('milliseconds', recorded_at)
FROM xshield.calibration_report_artifacts;

CREATE FUNCTION xshield.register_artifact_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    existing_tenant_id text;
    existing_site_id text;
    existing_family text;
BEGIN
    INSERT INTO xshield.artifact_identity_registry (
        artifact_id, tenant_id, site_id, family, registered_at
    ) VALUES (
        NEW.artifact_id, NEW.tenant_id, NEW.site_id, TG_ARGV[0],
        date_trunc('milliseconds', clock_timestamp())
    ) ON CONFLICT (artifact_id) DO NOTHING;

    -- A trusted writer may claim the append-only identity immediately before
    -- inserting its owner row so a concurrent collision becomes a closed
    -- application outcome.  The owner trigger must accept that exact claim,
    -- but never silently accept an identity owned by another scope or family.
    SELECT tenant_id, site_id, family
    INTO existing_tenant_id, existing_site_id, existing_family
    FROM xshield.artifact_identity_registry
    WHERE artifact_id = NEW.artifact_id
    FOR KEY SHARE;

    IF NOT FOUND
       OR existing_tenant_id IS DISTINCT FROM NEW.tenant_id
       OR existing_site_id IS DISTINCT FROM NEW.site_id
       OR existing_family IS DISTINCT FROM TG_ARGV[0]
    THEN
        RAISE EXCEPTION 'artifact identity belongs to another scope or family'
            USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION xshield.reject_artifact_identity_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.artifact_id IS DISTINCT FROM OLD.artifact_id THEN
        RAISE EXCEPTION 'artifact identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- `AFTER INSERT` is intentional. Existing writers use `ON CONFLICT DO
-- NOTHING` for unknown-result recovery; a `BEFORE INSERT` registry write
-- would conflict before that local idempotency check could resolve. On a
-- genuine new owner row, the registry insertion remains in the same
-- transaction and rolls back the owner row if a different family owns the ID.
CREATE TRIGGER artifact_catalog_register_global_identity
AFTER INSERT ON xshield.artifact_catalog
FOR EACH ROW EXECUTE FUNCTION xshield.register_artifact_identity('evidence_catalog');

CREATE TRIGGER artifact_catalog_reject_identity_update
BEFORE UPDATE OF artifact_id ON xshield.artifact_catalog
FOR EACH ROW EXECUTE FUNCTION xshield.reject_artifact_identity_update();

CREATE TRIGGER calibration_report_artifact_register_global_identity
AFTER INSERT ON xshield.calibration_report_artifacts
FOR EACH ROW EXECUTE FUNCTION xshield.register_artifact_identity('calibration_report');

CREATE TRIGGER calibration_report_artifact_reject_identity_update
BEFORE UPDATE OF artifact_id ON xshield.calibration_report_artifacts
FOR EACH ROW EXECUTE FUNCTION xshield.reject_artifact_identity_update();

CREATE TABLE xshield.calibration_lineage_review_artifacts (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    review_id text NOT NULL CHECK (
        review_id ~ '^calrev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    artifact_id text NOT NULL CHECK (
        artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    schema_version smallint NOT NULL CHECK (schema_version = 1),
    kind text NOT NULL CHECK (kind = 'calibration_partition_lineage_review'),
    content_type text NOT NULL CHECK (
        content_type = 'application/vnd.xshield.calibration-lineage-review+json'
    ),
    canonical_body_encoding text NOT NULL CHECK (
        canonical_body_encoding = 'xshield_calibration_lineage_review_canonical_json_v1'
    ),
    capture_status text NOT NULL CHECK (capture_status = 'complete'),
    fidelity text NOT NULL CHECK (fidelity = 'entity_exact'),
    bytes_observed bigint NOT NULL CHECK (bytes_observed BETWEEN 0 AND 4194304),
    bytes_saved bigint NOT NULL CHECK (bytes_saved = bytes_observed),
    classification text NOT NULL CHECK (classification = 'RESTRICTED'),
    storage_profile text NOT NULL CHECK (storage_profile = 'aead_envelope_v1'),
    storage_locator text NOT NULL,
    key_ref text NOT NULL CHECK (key_ref ~ '^[A-Za-z0-9_.-]{1,128}$'),
    integrity_algorithm text NOT NULL CHECK (integrity_algorithm = 'sha256_ciphertext'),
    integrity_digest text NOT NULL CHECK (integrity_digest ~ '^[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL CHECK (
        isfinite(recorded_at)
        AND recorded_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', recorded_at) = recorded_at
    ),
    reviewed_at timestamptz NOT NULL CHECK (
        isfinite(reviewed_at)
        AND reviewed_at = recorded_at
        AND date_trunc('milliseconds', reviewed_at) = reviewed_at
    ),
    expires_at timestamptz NOT NULL CHECK (
        isfinite(expires_at) AND expires_at > recorded_at
    ),

    PRIMARY KEY (tenant_id, site_id, artifact_id),
    UNIQUE (artifact_id),
    UNIQUE (tenant_id, site_id, review_id),
    UNIQUE (review_id),
    UNIQUE (tenant_id, site_id, review_id, artifact_id),
    CHECK (storage_locator = artifact_id || '.xev')
);

COMMENT ON TABLE xshield.calibration_lineage_review_artifacts IS
    'Authenticated restricted lineage-review metadata. The source graph exists only in the encrypted review artifact and is not projected here.';

CREATE TRIGGER calibration_lineage_review_artifact_register_global_identity
AFTER INSERT ON xshield.calibration_lineage_review_artifacts
FOR EACH ROW EXECUTE FUNCTION xshield.register_artifact_identity('calibration_lineage_review');

CREATE TRIGGER calibration_lineage_review_artifact_reject_identity_update
BEFORE UPDATE OF artifact_id ON xshield.calibration_lineage_review_artifacts
FOR EACH ROW EXECUTE FUNCTION xshield.reject_artifact_identity_update();

CREATE TABLE xshield.calibration_lineage_reviews (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    review_id text NOT NULL CHECK (
        review_id ~ '^calrev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    review_artifact_id text NOT NULL CHECK (
        review_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    schema_version smallint NOT NULL CHECK (schema_version = 1),
    policy_revision text NOT NULL CHECK (policy_revision = 'calibration-lineage-v1'),
    approval_ref text NOT NULL CHECK (approval_ref ~ '^[A-Za-z0-9_.-]{1,128}$'),
    dataset_revision text NOT NULL CHECK (dataset_revision ~ '^[A-Za-z0-9_.-]{1,128}$'),
    label_revision text NOT NULL CHECK (label_revision ~ '^[A-Za-z0-9_.-]{1,128}$'),
    task_revision text NOT NULL CHECK (task_revision ~ '^[A-Za-z0-9_.-]{1,128}$'),
    threshold_policy_revision text NOT NULL CHECK (
        threshold_policy_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    mapping_revision text NOT NULL CHECK (mapping_revision ~ '^[A-Za-z0-9_.-]{1,128}$'),
    evaluation_manifest_artifact_id text NOT NULL CHECK (
        evaluation_manifest_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    training_manifest_artifact_id text NOT NULL CHECK (
        training_manifest_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    calibration_manifest_artifact_id text NOT NULL CHECK (
        calibration_manifest_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    label_manifest_artifact_id text NOT NULL CHECK (
        label_manifest_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    provider text NOT NULL CHECK (provider ~ '^[A-Za-z0-9_.-]{1,128}$'),
    provider_model_id text NOT NULL CHECK (
        octet_length(provider_model_id) BETWEEN 1 AND 128
        AND provider_model_id !~ '[[:cntrl:]]'
        AND provider_model_id = btrim(provider_model_id)
    ),
    model_revision text NOT NULL CHECK (model_revision ~ '^[A-Za-z0-9_.-]{1,128}$'),
    prompt_revision text NOT NULL CHECK (prompt_revision ~ '^[A-Za-z0-9_.-]{1,128}$'),
    resolved_model_revision text CHECK (
        resolved_model_revision IS NULL
        OR resolved_model_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    source_graph_digest bytea NOT NULL CHECK (octet_length(source_graph_digest) = 32),
    reviewed_event_id text NOT NULL UNIQUE CHECK (
        reviewed_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    reviewed_at timestamptz NOT NULL CHECK (
        isfinite(reviewed_at)
        AND reviewed_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', reviewed_at) = reviewed_at
    ),

    PRIMARY KEY (tenant_id, site_id, review_id),
    UNIQUE (review_id),
    UNIQUE (tenant_id, site_id, review_artifact_id),
    FOREIGN KEY (tenant_id, site_id, review_id, review_artifact_id)
        REFERENCES xshield.calibration_lineage_review_artifacts (
            tenant_id, site_id, review_id, artifact_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, site_id, evaluation_manifest_artifact_id)
        REFERENCES xshield.artifact_catalog (tenant_id, site_id, artifact_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, site_id, training_manifest_artifact_id)
        REFERENCES xshield.artifact_catalog (tenant_id, site_id, artifact_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, site_id, calibration_manifest_artifact_id)
        REFERENCES xshield.artifact_catalog (tenant_id, site_id, artifact_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, site_id, label_manifest_artifact_id)
        REFERENCES xshield.artifact_catalog (tenant_id, site_id, artifact_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (reviewed_event_id)
        REFERENCES xshield.audit_outbox (event_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        review_artifact_id <> evaluation_manifest_artifact_id
        AND review_artifact_id <> training_manifest_artifact_id
        AND review_artifact_id <> calibration_manifest_artifact_id
        AND review_artifact_id <> label_manifest_artifact_id
    ),
    CHECK (
        evaluation_manifest_artifact_id <> training_manifest_artifact_id
        AND evaluation_manifest_artifact_id <> calibration_manifest_artifact_id
        AND evaluation_manifest_artifact_id <> label_manifest_artifact_id
        AND training_manifest_artifact_id <> calibration_manifest_artifact_id
        AND training_manifest_artifact_id <> label_manifest_artifact_id
        AND calibration_manifest_artifact_id <> label_manifest_artifact_id
    )
);

COMMENT ON TABLE xshield.calibration_lineage_reviews IS
    'Frozen declaration-review provenance, four catalog manifest identities, and reviewed event binding. It is not an evidence-read capability or policy authorization.';

CREATE INDEX calibration_lineage_reviews_manifest_lookup
    ON xshield.calibration_lineage_reviews (
        tenant_id, site_id, evaluation_manifest_artifact_id,
        training_manifest_artifact_id, calibration_manifest_artifact_id,
        label_manifest_artifact_id
    );

COMMIT;
