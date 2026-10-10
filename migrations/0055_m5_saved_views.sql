-- Per-owner saved investigation searches. A row stores the validated search body
-- (filters, sort, window and limit, never a cursor). Reopening a view runs an
-- ordinary search, so every read still passes the existing audited search path.
--
-- Rows hold no result data, evidence content or credentials. Deleting a row
-- deletes only the saved parameters.
BEGIN;

CREATE TABLE xshield.saved_search_views (
    tenant_id text NOT NULL CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    site_id text NOT NULL CHECK (
        site_id ~ '^[A-Za-z0-9_.-]{1,128}$'
    ),
    view_id text NOT NULL CHECK (
        view_id ~ '^view_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    owner_ref text NOT NULL CHECK (
        octet_length(owner_ref) BETWEEN 1 AND 256
        AND owner_ref !~ '[[:cntrl:]]'
    ),
    name text NOT NULL CHECK (
        octet_length(name) BETWEEN 1 AND 160
        AND name !~ '[[:cntrl:]]'
    ),
    request jsonb NOT NULL CHECK (
        jsonb_typeof(request) = 'object'
        AND octet_length(request::text) <= 8192
        AND NOT (request ? 'cursor')
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, site_id, view_id),
    UNIQUE (tenant_id, site_id, owner_ref, name),
    CHECK (isfinite(created_at))
);

CREATE INDEX saved_search_views_owner_lookup
    ON xshield.saved_search_views (tenant_id, site_id, owner_ref, created_at DESC, view_id DESC);

COMMIT;
