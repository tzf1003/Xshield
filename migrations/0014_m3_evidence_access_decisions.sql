BEGIN;

ALTER TABLE xshield.evidence_access_requests
    ADD COLUMN decided_by text,
    ADD COLUMN decision_reason text,
    ADD COLUMN decision_ttl_seconds integer,
    ADD COLUMN decision_idempotency_digest bytea,
    ADD COLUMN decision_request_digest bytea,
    ADD COLUMN decision_event_id text,
    ADD COLUMN decided_at timestamptz,
    ADD COLUMN access_expires_at timestamptz;

ALTER TABLE xshield.evidence_access_requests
    ADD CONSTRAINT evidence_access_decider_valid CHECK (
        decided_by IS NULL OR (
            octet_length(decided_by) BETWEEN 1 AND 256
            AND decided_by !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT evidence_access_decision_reason_valid CHECK (
        decision_reason IS NULL OR (
            octet_length(decision_reason) BETWEEN 1 AND 512
            AND decision_reason !~ '[[:cntrl:]]'
            AND decision_reason = btrim(decision_reason)
        )
    ),
    ADD CONSTRAINT evidence_access_decision_ttl_valid CHECK (
        decision_ttl_seconds IS NULL OR decision_ttl_seconds > 0
    ),
    ADD CONSTRAINT evidence_access_decision_idempotency_valid CHECK (
        decision_idempotency_digest IS NULL
        OR octet_length(decision_idempotency_digest) = 32
    ),
    ADD CONSTRAINT evidence_access_decision_request_valid CHECK (
        decision_request_digest IS NULL
        OR octet_length(decision_request_digest) = 32
    ),
    ADD CONSTRAINT evidence_access_decision_event_valid CHECK (
        decision_event_id IS NULL OR decision_event_id ~
        '^ev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    ADD CONSTRAINT evidence_access_decision_state_valid CHECK (
        (status = 'pending'
         AND decided_by IS NULL
         AND decision_reason IS NULL
         AND decision_ttl_seconds IS NULL
         AND decision_idempotency_digest IS NULL
         AND decision_request_digest IS NULL
         AND decision_event_id IS NULL
         AND decided_at IS NULL
         AND access_expires_at IS NULL)
        OR
        (status = 'denied'
         AND decided_by IS NOT NULL
         AND decided_by <> requested_by
         AND decision_reason IS NOT NULL
         AND decision_ttl_seconds IS NULL
         AND decision_idempotency_digest IS NOT NULL
         AND decision_request_digest IS NOT NULL
         AND decision_event_id IS NOT NULL
         AND decided_at IS NOT NULL
         AND access_expires_at IS NULL)
        OR
        (status IN ('approved', 'expired', 'revoked')
         AND decided_by IS NOT NULL
         AND decided_by <> requested_by
         AND decision_reason IS NOT NULL
         AND decision_ttl_seconds IS NOT NULL
         AND decision_idempotency_digest IS NOT NULL
         AND decision_request_digest IS NOT NULL
         AND decision_event_id IS NOT NULL
         AND decided_at IS NOT NULL
         AND access_expires_at > decided_at)
    );

CREATE UNIQUE INDEX evidence_access_decision_idempotency
    ON xshield.evidence_access_requests (
        tenant_id, site_id, decided_by, decision_idempotency_digest
    )
    WHERE decision_idempotency_digest IS NOT NULL;

CREATE UNIQUE INDEX evidence_access_decision_event
    ON xshield.evidence_access_requests (decision_event_id)
    WHERE decision_event_id IS NOT NULL;

CREATE INDEX evidence_access_capability_lookup
    ON xshield.evidence_access_requests (
        tenant_id, site_id, requested_by, access_request_id, access_expires_at
    )
    WHERE status = 'approved';

COMMIT;
