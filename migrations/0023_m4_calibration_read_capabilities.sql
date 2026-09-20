-- Upgrade before enabling any calibration batch issuer or reader. This schema
-- persists an exact, purpose-limited batch capability; it is not an evidence
-- reader, an approval, a report, or a policy publication mechanism.
--
-- The matching adapter must insert the frozen header, every member snapshot,
-- and the small `calibration.read_capability.issued` audit-outbox fact in one
-- transaction. The event identifies the capability and its canonical scope
-- digest/counts only: the complete member set remains in the protected
-- relational rows below and must never be expanded into an outbox envelope.
--
-- Rollback: disable calibration batch issuance and reading first. Dropping
-- these tables removes durable authorization/recovery facts and must therefore
-- follow the retention and audit policy; an ordinary rollback leaves this
-- additive schema and immutable outbox events in place.
BEGIN;

CREATE TABLE xshield.calibration_read_capabilities (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    capability_id text NOT NULL CHECK (
        capability_id ~ '^calcap_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),

    -- Frozen EvaluationProvenance. These are audit/provenance values only;
    -- none is a console evidence-access approval or a business authorization.
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
    provider text NOT NULL CHECK (
        provider ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
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

    -- `scope_digest` is SHA-256 over the adapter's canonical ordered member
    -- representation. The database preserves it for exact retry/revalidation;
    -- it does not attempt to construct a non-canonical JSON aggregate.
    scope_digest bytea NOT NULL CHECK (octet_length(scope_digest) = 32),
    sample_count integer NOT NULL CHECK (sample_count BETWEEN 1 AND 10000),
    member_count integer NOT NULL CHECK (
        member_count = 4 + 2 * sample_count
    ),
    max_total_bytes bigint NOT NULL CHECK (
        max_total_bytes BETWEEN 1 AND 536870912
    ),
    frozen_total_bytes bigint NOT NULL CHECK (
        frozen_total_bytes BETWEEN 0 AND max_total_bytes
    ),
    not_before timestamptz NOT NULL CHECK (
        isfinite(not_before)
        AND not_before >= '1970-01-01 UTC'
        AND date_trunc('second', not_before) = not_before
    ),
    expires_at timestamptz NOT NULL CHECK (
        isfinite(expires_at)
        AND expires_at > not_before
        AND date_trunc('second', expires_at) = expires_at
    ),

    -- The issuer plus digest permits exact recovery after an unknown commit.
    -- The event is deliberately small and must bind this capability ID and
    -- scope digest; the future adapter verifies that semantic binding itself.
    issued_by text NOT NULL CHECK (
        octet_length(issued_by) BETWEEN 1 AND 256
        AND issued_by !~ '[[:cntrl:]]'
        AND issued_by = btrim(issued_by)
    ),
    issuance_idempotency_digest bytea NOT NULL CHECK (
        octet_length(issuance_idempotency_digest) = 32
    ),
    issuance_request_digest bytea NOT NULL CHECK (
        octet_length(issuance_request_digest) = 32
    ),
    issued_event_id text NOT NULL UNIQUE CHECK (
        issued_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    issued_at timestamptz NOT NULL CHECK (
        isfinite(issued_at)
        AND issued_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', issued_at) = issued_at
    ),

    -- A batch is leased as a whole. The plaintext token is never persisted:
    -- adapters retain it only in the worker session and compare its digest.
    -- A recovery always creates the next lease generation; it never revives
    -- a prior lease token or changes the frozen member set.
    status text NOT NULL CHECK (
        status IN ('issued', 'leased', 'recovery_required', 'consumed', 'expired', 'revoked')
    ),
    lease_generation integer NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    recovery_attempts integer NOT NULL DEFAULT 0 CHECK (
        recovery_attempts BETWEEN 0 AND 16
    ),
    recovery_required_at timestamptz,
    consumed_at timestamptz,
    expired_at timestamptz,
    revoked_at timestamptz,

    PRIMARY KEY (tenant_id, site_id, capability_id),
    UNIQUE (capability_id),
    UNIQUE (tenant_id, site_id, issued_by, issuance_idempotency_digest),
    FOREIGN KEY (issued_event_id)
        REFERENCES xshield.audit_outbox (event_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT calibration_read_capability_lifecycle_shape CHECK (
        (status = 'issued'
         AND lease_generation = 0
         AND recovery_attempts = 0
         AND recovery_required_at IS NULL
         AND consumed_at IS NULL
         AND expired_at IS NULL
         AND revoked_at IS NULL)
        OR
        (status = 'leased'
         AND lease_generation = recovery_attempts + 1
         AND recovery_required_at IS NULL
         AND consumed_at IS NULL
         AND expired_at IS NULL
         AND revoked_at IS NULL)
        OR
        (status = 'recovery_required'
         AND lease_generation = recovery_attempts + 1
         AND recovery_required_at IS NOT NULL
         AND consumed_at IS NULL
         AND expired_at IS NULL
         AND revoked_at IS NULL)
        OR
        (status = 'consumed'
         AND lease_generation = recovery_attempts + 1
         AND recovery_required_at IS NULL
         AND consumed_at IS NOT NULL
         AND expired_at IS NULL
         AND revoked_at IS NULL)
        OR
        (status = 'expired'
         AND recovery_required_at IS NULL
         AND consumed_at IS NULL
         AND expired_at IS NOT NULL
         AND revoked_at IS NULL)
        OR
        (status = 'revoked'
         AND recovery_required_at IS NULL
         AND consumed_at IS NULL
         AND expired_at IS NULL
         AND revoked_at IS NOT NULL)
    ),
    CHECK (
        (recovery_required_at IS NULL OR (
            isfinite(recovery_required_at)
            AND recovery_required_at >= issued_at
            AND recovery_required_at <= expires_at
            AND date_trunc('milliseconds', recovery_required_at) = recovery_required_at
        ))
        AND (consumed_at IS NULL OR (
            isfinite(consumed_at)
            AND consumed_at >= issued_at
            AND consumed_at <= expires_at
            AND date_trunc('milliseconds', consumed_at) = consumed_at
        ))
        AND (expired_at IS NULL OR (
            isfinite(expired_at)
            AND expired_at >= issued_at
            AND date_trunc('milliseconds', expired_at) = expired_at
        ))
        AND (revoked_at IS NULL OR (
            isfinite(revoked_at)
            AND revoked_at >= issued_at
            AND date_trunc('milliseconds', revoked_at) = revoked_at
        ))
    )
);

CREATE TABLE xshield.calibration_read_capability_members (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    capability_id text NOT NULL,
    artifact_id text NOT NULL CHECK (
        artifact_id ~ '^artifact_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    role text NOT NULL CHECK (
        role IN (
            'training_manifest',
            'calibration_manifest',
            'evaluation_manifest',
            'label_manifest',
            'model_call_record',
            'reviewed_label'
        )
    ),
    sample_index integer CHECK (sample_index BETWEEN 0 AND 9999),

    -- These are the catalog facts observed while issuance held every catalog
    -- row lock. A reader compares the live row before vault access so object
    -- replacement, expiry, deletion, or byte-budget drift is never ignored.
    catalog_bytes_saved bigint NOT NULL CHECK (
        catalog_bytes_saved BETWEEN 0 AND 67108864
    ),
    catalog_integrity_digest text NOT NULL CHECK (
        catalog_integrity_digest ~ '^[0-9a-f]{64}$'
    ),
    catalog_kind text NOT NULL CHECK (
        catalog_kind ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    catalog_content_type text NOT NULL CHECK (
        octet_length(catalog_content_type) BETWEEN 1 AND 256
        AND catalog_content_type !~ '[[:cntrl:]]'
    ),
    catalog_fidelity text NOT NULL CHECK (
        catalog_fidelity IN ('entity_exact', 'semantic', 'redacted')
    ),
    catalog_classification text NOT NULL CHECK (
        catalog_classification IN ('INTERNAL', 'SENSITIVE', 'RESTRICTED')
    ),
    catalog_expires_at timestamptz NOT NULL CHECK (
        isfinite(catalog_expires_at)
        AND catalog_expires_at >= '1970-01-01 UTC'
    ),
    catalog_event_id text NOT NULL CHECK (
        catalog_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),

    PRIMARY KEY (tenant_id, site_id, capability_id, artifact_id),
    FOREIGN KEY (tenant_id, site_id, capability_id)
        REFERENCES xshield.calibration_read_capabilities (
            tenant_id, site_id, capability_id
        )
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, site_id, artifact_id)
        REFERENCES xshield.artifact_catalog (tenant_id, site_id, artifact_id)
        ON DELETE RESTRICT,
    CONSTRAINT calibration_read_capability_member_role_shape CHECK (
        (role IN (
            'training_manifest', 'calibration_manifest',
            'evaluation_manifest', 'label_manifest'
        ) AND sample_index IS NULL)
        OR
        (role IN ('model_call_record', 'reviewed_label') AND sample_index IS NOT NULL)
    )
);

-- Each partition manifest has exactly one declared role. Each source role can
-- occur once per sample slot; the deferred scope trigger below also requires a
-- complete contiguous pair for every frozen sample.
CREATE UNIQUE INDEX calibration_read_capability_manifest_role
    ON xshield.calibration_read_capability_members (
        tenant_id, site_id, capability_id, role
    )
    WHERE sample_index IS NULL;

CREATE UNIQUE INDEX calibration_read_capability_sample_role
    ON xshield.calibration_read_capability_members (
        tenant_id, site_id, capability_id, role, sample_index
    )
    WHERE sample_index IS NOT NULL;

CREATE TABLE xshield.calibration_read_capability_leases (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    capability_id text NOT NULL,
    lease_id text NOT NULL CHECK (
        lease_id ~ '^callease_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    lease_generation integer NOT NULL CHECK (lease_generation >= 1),
    runner_id text NOT NULL CHECK (
        octet_length(runner_id) BETWEEN 1 AND 128
        AND runner_id !~ '[[:cntrl:]]'
        AND runner_id = btrim(runner_id)
    ),
    lease_token_digest bytea NOT NULL CHECK (
        octet_length(lease_token_digest) = 32
    ),
    status text NOT NULL CHECK (
        status IN ('active', 'recovery_required', 'completed', 'abandoned')
    ),
    acquired_at timestamptz NOT NULL CHECK (
        isfinite(acquired_at)
        AND acquired_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', acquired_at) = acquired_at
    ),
    lease_until timestamptz NOT NULL CHECK (
        isfinite(lease_until)
        AND lease_until > acquired_at
        AND date_trunc('milliseconds', lease_until) = lease_until
    ),
    recovery_required_at timestamptz,
    completed_at timestamptz,
    abandoned_at timestamptz,

    PRIMARY KEY (tenant_id, site_id, capability_id, lease_generation),
    UNIQUE (lease_id),
    FOREIGN KEY (tenant_id, site_id, capability_id)
        REFERENCES xshield.calibration_read_capabilities (
            tenant_id, site_id, capability_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT calibration_read_capability_lease_state_shape CHECK (
        (status = 'active'
         AND recovery_required_at IS NULL
         AND completed_at IS NULL
         AND abandoned_at IS NULL)
        OR
        (status = 'recovery_required'
         AND recovery_required_at IS NOT NULL
         AND completed_at IS NULL
         AND abandoned_at IS NULL)
        OR
        (status = 'completed'
         AND recovery_required_at IS NULL
         AND completed_at IS NOT NULL
         AND abandoned_at IS NULL)
        OR
        (status = 'abandoned'
         AND recovery_required_at IS NULL
         AND completed_at IS NULL
         AND abandoned_at IS NOT NULL)
    ),
    CHECK (
        (recovery_required_at IS NULL OR (
            isfinite(recovery_required_at)
            AND recovery_required_at >= acquired_at
            AND date_trunc('milliseconds', recovery_required_at) = recovery_required_at
        ))
        AND (completed_at IS NULL OR (
            isfinite(completed_at)
            AND completed_at >= acquired_at
            AND date_trunc('milliseconds', completed_at) = completed_at
        ))
        AND (abandoned_at IS NULL OR (
            isfinite(abandoned_at)
            AND abandoned_at >= acquired_at
            AND date_trunc('milliseconds', abandoned_at) = abandoned_at
        ))
    )
);

CREATE UNIQUE INDEX calibration_read_capability_one_active_lease
    ON xshield.calibration_read_capability_leases (
        tenant_id, site_id, capability_id
    )
    WHERE status = 'active';

CREATE INDEX calibration_read_capability_ready_lookup
    ON xshield.calibration_read_capabilities (
        tenant_id, site_id, status, expires_at, capability_id
    )
    WHERE status IN ('issued', 'leased', 'recovery_required');

CREATE INDEX calibration_read_capability_member_lookup
    ON xshield.calibration_read_capability_members (
        tenant_id, site_id, capability_id, role, sample_index, artifact_id
    );

-- This deferred check lets a single transaction insert the header and its
-- bounded member rows in either order, while making an incomplete or expanded
-- frozen scope uncommittable. The adapter still validates the canonical scope
-- digest and the live catalog/vault facts at each batch acquisition/read.
CREATE FUNCTION xshield.validate_calibration_read_capability_members()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scoped_tenant text := COALESCE(NEW.tenant_id, OLD.tenant_id);
    scoped_site text := COALESCE(NEW.site_id, OLD.site_id);
    scoped_capability text := COALESCE(NEW.capability_id, OLD.capability_id);
    header xshield.calibration_read_capabilities%ROWTYPE;
    actual_members integer;
    actual_bytes bigint;
    training_manifests integer;
    calibration_manifests integer;
    evaluation_manifests integer;
    label_manifests integer;
    model_records integer;
    reviewed_labels integer;
    model_slots integer;
    label_slots integer;
BEGIN
    SELECT * INTO header
    FROM xshield.calibration_read_capabilities
    WHERE tenant_id = scoped_tenant
      AND site_id = scoped_site
      AND capability_id = scoped_capability;

    -- Parent and members can be removed together during a controlled archival
    -- procedure. There is no remaining frozen capability to validate then.
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT
        count(*)::integer,
        COALESCE(sum(catalog_bytes_saved), 0),
        count(*) FILTER (WHERE role = 'training_manifest')::integer,
        count(*) FILTER (WHERE role = 'calibration_manifest')::integer,
        count(*) FILTER (WHERE role = 'evaluation_manifest')::integer,
        count(*) FILTER (WHERE role = 'label_manifest')::integer,
        count(*) FILTER (WHERE role = 'model_call_record')::integer,
        count(*) FILTER (WHERE role = 'reviewed_label')::integer,
        count(DISTINCT sample_index) FILTER (WHERE role = 'model_call_record')::integer,
        count(DISTINCT sample_index) FILTER (WHERE role = 'reviewed_label')::integer
    INTO actual_members, actual_bytes, training_manifests, calibration_manifests,
         evaluation_manifests, label_manifests, model_records, reviewed_labels,
         model_slots, label_slots
    FROM xshield.calibration_read_capability_members
    WHERE tenant_id = scoped_tenant
      AND site_id = scoped_site
      AND capability_id = scoped_capability;

    IF actual_members <> header.member_count
       OR actual_bytes <> header.frozen_total_bytes
       OR training_manifests <> 1
       OR calibration_manifests <> 1
       OR evaluation_manifests <> 1
       OR label_manifests <> 1
       OR model_records <> header.sample_count
       OR reviewed_labels <> header.sample_count
       OR model_slots <> header.sample_count
       OR label_slots <> header.sample_count
       OR EXISTS (
            SELECT 1
            FROM generate_series(0, header.sample_count - 1) AS slot(sample_index)
            LEFT JOIN xshield.calibration_read_capability_members model_record
              ON model_record.tenant_id = scoped_tenant
             AND model_record.site_id = scoped_site
             AND model_record.capability_id = scoped_capability
             AND model_record.role = 'model_call_record'
             AND model_record.sample_index = slot.sample_index
            LEFT JOIN xshield.calibration_read_capability_members reviewed_label
              ON reviewed_label.tenant_id = scoped_tenant
             AND reviewed_label.site_id = scoped_site
             AND reviewed_label.capability_id = scoped_capability
             AND reviewed_label.role = 'reviewed_label'
             AND reviewed_label.sample_index = slot.sample_index
            WHERE model_record.artifact_id IS NULL
               OR reviewed_label.artifact_id IS NULL
       )
    THEN
        RAISE EXCEPTION
            USING ERRCODE = '23514',
                  MESSAGE = 'calibration read capability member set does not match frozen header';
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER calibration_read_capability_header_members_complete
AFTER INSERT OR UPDATE OR DELETE ON xshield.calibration_read_capabilities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION xshield.validate_calibration_read_capability_members();

CREATE CONSTRAINT TRIGGER calibration_read_capability_members_complete
AFTER INSERT OR UPDATE OR DELETE ON xshield.calibration_read_capability_members
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION xshield.validate_calibration_read_capability_members();

-- This second deferred check binds lease history to the frozen outer lease.
-- It deliberately has no content access side effect: adapter code must lock
-- the header, members, and live catalog rows with the database clock before
-- changing these states or opening the vault.
CREATE FUNCTION xshield.validate_calibration_read_capability_leases()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scoped_tenant text := COALESCE(NEW.tenant_id, OLD.tenant_id);
    scoped_site text := COALESCE(NEW.site_id, OLD.site_id);
    scoped_capability text := COALESCE(NEW.capability_id, OLD.capability_id);
    header xshield.calibration_read_capabilities%ROWTYPE;
    lease_count integer;
    active_count integer;
    latest_state text;
BEGIN
    SELECT * INTO header
    FROM xshield.calibration_read_capabilities
    WHERE tenant_id = scoped_tenant
      AND site_id = scoped_site
      AND capability_id = scoped_capability;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM xshield.calibration_read_capability_leases lease
        WHERE lease.tenant_id = scoped_tenant
          AND lease.site_id = scoped_site
          AND lease.capability_id = scoped_capability
          AND (
              lease.acquired_at < header.not_before
              OR lease.lease_until > header.expires_at
          )
    ) THEN
        RAISE EXCEPTION
            USING ERRCODE = '23514',
                  MESSAGE = 'calibration read capability lease is outside frozen bounds';
    END IF;

    SELECT count(*)::integer,
           count(*) FILTER (WHERE status = 'active')::integer
    INTO lease_count, active_count
    FROM xshield.calibration_read_capability_leases
    WHERE tenant_id = scoped_tenant
      AND site_id = scoped_site
      AND capability_id = scoped_capability;

    SELECT status INTO latest_state
    FROM xshield.calibration_read_capability_leases
    WHERE tenant_id = scoped_tenant
      AND site_id = scoped_site
      AND capability_id = scoped_capability
    ORDER BY lease_generation DESC
    LIMIT 1;

    IF (header.status = 'issued'
        AND lease_count = 0)
       OR (header.status = 'leased'
           AND lease_count = header.lease_generation
           AND active_count = 1
           AND latest_state = 'active')
       OR (header.status = 'recovery_required'
           AND lease_count = header.lease_generation
           AND active_count = 0
           AND latest_state = 'recovery_required')
       OR (header.status = 'consumed'
           AND lease_count = header.lease_generation
           AND active_count = 0
           AND latest_state = 'completed')
       OR (header.status IN ('expired', 'revoked')
           AND active_count = 0
           AND lease_count = header.lease_generation
           AND (lease_count = 0 OR latest_state = 'abandoned'))
    THEN
        RETURN NULL;
    END IF;

    RAISE EXCEPTION
        USING ERRCODE = '23514',
              MESSAGE = 'calibration read capability lifecycle does not match lease history';
END;
$$;

CREATE CONSTRAINT TRIGGER calibration_read_capability_header_leases_complete
AFTER INSERT OR UPDATE OR DELETE ON xshield.calibration_read_capabilities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION xshield.validate_calibration_read_capability_leases();

CREATE CONSTRAINT TRIGGER calibration_read_capability_leases_complete
AFTER INSERT OR UPDATE OR DELETE ON xshield.calibration_read_capability_leases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION xshield.validate_calibration_read_capability_leases();

COMMIT;
