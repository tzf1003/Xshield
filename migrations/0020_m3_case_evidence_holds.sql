BEGIN;

CREATE TABLE xshield.case_evidence_holds (
    tenant_id text NOT NULL,
    site_id text NOT NULL,
    case_id text NOT NULL,
    artifact_id text NOT NULL,
    created_event_id text PRIMARY KEY CHECK (
        created_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    created_by text NOT NULL CHECK (octet_length(created_by) BETWEEN 1 AND 256 AND created_by !~ '[[:cntrl:]]' AND created_by = btrim(created_by)),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 512 AND reason !~ '[[:cntrl:]]' AND reason = btrim(reason)),
    created_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds', clock_timestamp()),
    hold_until timestamptz NOT NULL CHECK (
        isfinite(hold_until) AND hold_until > created_at
        AND hold_until <= created_at + interval '720 hours'
        AND date_trunc('milliseconds', hold_until) = hold_until
    ),
    idempotency_digest bytea NOT NULL CHECK (octet_length(idempotency_digest) = 32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    released_event_id text UNIQUE CHECK (
        released_event_id IS NULL OR released_event_id ~ '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    released_by text CHECK (released_by IS NULL OR (octet_length(released_by) BETWEEN 1 AND 256 AND released_by !~ '[[:cntrl:]]' AND released_by = btrim(released_by))),
    released_reason text CHECK (released_reason IS NULL OR (octet_length(released_reason) BETWEEN 1 AND 512 AND released_reason !~ '[[:cntrl:]]' AND released_reason = btrim(released_reason))),
    released_at timestamptz,
    release_idempotency_digest bytea CHECK (release_idempotency_digest IS NULL OR octet_length(release_idempotency_digest) = 32),
    release_request_digest bytea CHECK (release_request_digest IS NULL OR octet_length(release_request_digest) = 32),
    FOREIGN KEY (tenant_id, site_id, case_id, artifact_id)
        REFERENCES xshield.case_items (tenant_id, site_id, case_id, artifact_id),
    FOREIGN KEY (tenant_id, site_id, artifact_id)
        REFERENCES xshield.artifact_catalog (tenant_id, site_id, artifact_id),
    CONSTRAINT case_evidence_hold_release_shape CHECK (
        (released_event_id IS NULL AND released_by IS NULL AND released_reason IS NULL AND released_at IS NULL
            AND release_idempotency_digest IS NULL AND release_request_digest IS NULL)
        OR (released_event_id IS NOT NULL AND released_by IS NOT NULL AND released_reason IS NOT NULL AND released_at IS NOT NULL
            AND release_idempotency_digest IS NOT NULL AND release_request_digest IS NOT NULL)
    ),
    CHECK (isfinite(created_at) AND created_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', created_at) = created_at),
    CHECK (released_event_id IS NULL OR released_event_id <> created_event_id),
    CHECK (released_at IS NULL OR (isfinite(released_at) AND released_at >= '1970-01-01 UTC'
        AND date_trunc('milliseconds', released_at) = released_at))
);

CREATE UNIQUE INDEX case_evidence_holds_active_target
    ON xshield.case_evidence_holds (tenant_id, site_id, case_id, artifact_id)
    WHERE released_at IS NULL;
CREATE UNIQUE INDEX case_evidence_holds_idempotency
    ON xshield.case_evidence_holds (tenant_id, site_id, created_by, idempotency_digest);
CREATE UNIQUE INDEX case_evidence_holds_release_idempotency
    ON xshield.case_evidence_holds (tenant_id, site_id, released_by, release_idempotency_digest)
    WHERE released_at IS NOT NULL;
CREATE INDEX case_evidence_holds_case_history
    ON xshield.case_evidence_holds (tenant_id, site_id, case_id, created_event_id);
CREATE INDEX case_evidence_holds_active_by_artifact
    ON xshield.case_evidence_holds (tenant_id, site_id, artifact_id, hold_until)
    WHERE released_at IS NULL;

COMMIT;
