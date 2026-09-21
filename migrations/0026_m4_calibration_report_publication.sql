-- M4 offline calibration report publication. A report body remains a separate,
-- authenticated restricted evidence object; these tables retain only its
-- durable identity and the frozen public provenance needed for the restricted
-- `calibration.reported` outbox fact.
--
-- A report is not a request artifact, so this migration intentionally does not
-- place it in `artifact_catalog` or fabricate a request identity. The matching
-- adapter commits the report artifact metadata, report projection, batch lease
-- completion, capability consumption, and both audit events in one transaction.
-- The pre-existing completion pathway remains independently valid for batches
-- that have no report publication.
--
-- Rollback: disable report publication first. Ordinary rollback leaves these
-- additive durable audit and provenance facts in place; retention or archival
-- must follow the evidence and audit policy.
BEGIN;

CREATE TABLE xshield.calibration_report_artifacts (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    report_id text NOT NULL CHECK (
        report_id ~ '^calr_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    artifact_id text NOT NULL CHECK (
        artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    schema_version smallint NOT NULL CHECK (schema_version = 1),
    kind text NOT NULL CHECK (kind = 'calibration_evaluation_report'),
    content_type text NOT NULL CHECK (
        content_type = 'application/vnd.xshield.calibration-report+json'
    ),
    canonical_body_encoding text NOT NULL CHECK (
        canonical_body_encoding = 'xshield_calibration_report_canonical_json_v1'
    ),
    capture_status text NOT NULL CHECK (capture_status = 'complete'),
    fidelity text NOT NULL CHECK (fidelity = 'entity_exact'),
    bytes_observed bigint NOT NULL CHECK (
        bytes_observed BETWEEN 0 AND 4194304
    ),
    bytes_saved bigint NOT NULL CHECK (bytes_saved = bytes_observed),
    classification text NOT NULL CHECK (classification = 'RESTRICTED'),
    storage_profile text NOT NULL CHECK (storage_profile = 'aead_envelope_v1'),
    storage_locator text NOT NULL,
    key_ref text NOT NULL CHECK (key_ref ~ '^[A-Za-z0-9_.-]{1,128}$'),
    integrity_algorithm text NOT NULL CHECK (
        integrity_algorithm = 'sha256_ciphertext'
    ),
    integrity_digest text NOT NULL CHECK (
        integrity_digest ~ '^[0-9a-f]{64}$'
    ),
    recorded_at timestamptz NOT NULL CHECK (
        isfinite(recorded_at)
        AND recorded_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', recorded_at) = recorded_at
    ),
    published_at timestamptz NOT NULL CHECK (
        isfinite(published_at)
        AND published_at = recorded_at
        AND date_trunc('milliseconds', published_at) = published_at
    ),
    expires_at timestamptz NOT NULL CHECK (
        isfinite(expires_at)
        AND expires_at > recorded_at
    ),

    PRIMARY KEY (tenant_id, site_id, artifact_id),
    UNIQUE (artifact_id),
    UNIQUE (tenant_id, site_id, report_id),
    UNIQUE (tenant_id, site_id, report_id, artifact_id),
    CHECK (storage_locator = artifact_id || '.xev')
);

COMMENT ON TABLE xshield.calibration_report_artifacts IS
    'Authenticated metadata for restricted calibration reports; encrypted report content remains in evidence storage and is not in artifact_catalog.';

CREATE TABLE xshield.calibration_reports (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    report_id text NOT NULL CHECK (
        report_id ~ '^calr_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    report_artifact_id text NOT NULL CHECK (
        report_artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    capability_id text NOT NULL CHECK (
        capability_id ~ '^calcap_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    approval_ref text NOT NULL CHECK (
        approval_ref ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    dataset_revision text NOT NULL CHECK (
        dataset_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    label_revision text NOT NULL CHECK (
        label_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    task_revision text NOT NULL CHECK (
        task_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    threshold_policy_revision text NOT NULL CHECK (
        threshold_policy_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    mapping_revision text NOT NULL CHECK (
        mapping_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
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
    model_revision text NOT NULL CHECK (
        model_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    prompt_revision text NOT NULL CHECK (
        prompt_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    resolved_model_revision text CHECK (
        resolved_model_revision IS NULL
        OR resolved_model_revision ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    completion_event_id text NOT NULL UNIQUE CHECK (
        completion_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    reported_event_id text NOT NULL UNIQUE CHECK (
        reported_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    completed_at timestamptz NOT NULL CHECK (
        isfinite(completed_at)
        AND completed_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', completed_at) = completed_at
    ),
    reported_at timestamptz NOT NULL CHECK (
        isfinite(reported_at)
        AND reported_at = completed_at
        AND date_trunc('milliseconds', reported_at) = reported_at
    ),

    PRIMARY KEY (tenant_id, site_id, report_id),
    UNIQUE (report_id),
    UNIQUE (tenant_id, site_id, report_artifact_id),
    UNIQUE (tenant_id, site_id, capability_id),
    FOREIGN KEY (tenant_id, site_id, capability_id)
        REFERENCES xshield.calibration_read_capabilities (tenant_id, site_id, capability_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, site_id, report_id, report_artifact_id)
        REFERENCES xshield.calibration_report_artifacts (
            tenant_id, site_id, report_id, artifact_id
        )
        ON DELETE RESTRICT,
    FOREIGN KEY (completion_event_id)
        REFERENCES xshield.audit_outbox (event_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (reported_event_id)
        REFERENCES xshield.audit_outbox (event_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (completion_event_id <> reported_event_id),
    CHECK (
        report_artifact_id <> evaluation_manifest_artifact_id
        AND report_artifact_id <> training_manifest_artifact_id
        AND report_artifact_id <> calibration_manifest_artifact_id
        AND report_artifact_id <> label_manifest_artifact_id
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

COMMENT ON TABLE xshield.calibration_reports IS
    'Frozen report provenance and atomic event bindings. The report commit path is additive; legacy batch completion remains an independent terminal.';

CREATE INDEX calibration_reports_capability_lookup
    ON xshield.calibration_reports (tenant_id, site_id, capability_id);

COMMIT;
