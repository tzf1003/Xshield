-- v4 baseline schema.
--
-- The product has not shipped yet (docs/05-v3-removal.md section 5.2), so this
-- one migration replaces the ~57 v3 migrations that used to live in this
-- directory wholesale instead of migrating their tables forward. There are
-- only three tables in v4: a site's current configuration, that site's
-- configuration history, and the decision log (docs/03-admin-config-audit.md
-- sections 3.2 and 3.4). Everything else from v3 (cases, evidence access,
-- exports, calibration, grants, OIDC sessions, API keys, outbox, ...) is gone.

CREATE TABLE site_configs (
    name text PRIMARY KEY,
    spec jsonb NOT NULL,
    -- Incremented on every update (left at 1 on create); the gateway polls
    -- this column directly, on its own connection, every few seconds as a
    -- cheap way to detect a configuration change without comparing `spec`.
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE site_config_history (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    site_name text NOT NULL,
    before jsonb,
    after jsonb,
    changed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX site_config_history_site_name_idx ON site_config_history (site_name, changed_at DESC);

CREATE TABLE decision_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at_millis bigint NOT NULL,
    site text NOT NULL,
    request_id text NOT NULL,
    session text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    status integer,
    decision_path text NOT NULL,
    outcome text NOT NULL,
    jev jsonb
);

CREATE INDEX decision_log_at_millis_idx ON decision_log (at_millis DESC);
CREATE INDEX decision_log_site_idx ON decision_log (site, at_millis DESC);
CREATE INDEX decision_log_session_idx ON decision_log (session, at_millis DESC);
CREATE INDEX decision_log_path_idx ON decision_log (path, at_millis DESC);
CREATE INDEX decision_log_outcome_idx ON decision_log (outcome, at_millis DESC);
