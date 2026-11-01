-- v4 baseline schema (docs/07-console-architecture.md section 7.8.1).
--
-- The product has not shipped yet (docs/05-v3-removal.md section 5.2), so this
-- one migration replaces the ~57 v3 migrations wholesale instead of migrating
-- their tables forward. Five tables:
--
--   site_configs         a site's current configuration (the gateway reads it)
--   site_config_history  every version of every site, full text, never pruned
--   decision_log         one row per request the gateway handled, by UTC day
--   edge_status          one heartbeat row per gateway instance
--   jev_prompts          the Jev instruction text, one row per prompt version
--
-- The control plane is the only writer of the two site tables and of the
-- partitions of decision_log; the gateway writes decision_log, edge_status and
-- jev_prompts. The columns below are the contract between the two processes.

CREATE TABLE site_configs (
    name       text PRIMARY KEY,
    spec       jsonb NOT NULL,                 -- may carry an optional "advanced" section
    -- Equals the highest site_config_history.version of this site. The gateway
    -- polls this column to notice a change without comparing `spec`.
    version    bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE site_config_history (
    site        text NOT NULL,
    version     bigint NOT NULL,               -- counts up from 1 per site; continues after a delete and re-create
    spec        jsonb,                         -- the whole configuration after the change; NULL for a delete
    change      text NOT NULL,                 -- create | update | rollback | delete | import
    rollback_of bigint,                        -- the version restored when change = rollback
    note        text,                          -- optional remark, at most 500 characters
    changed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (site, version),
    CONSTRAINT site_config_history_change_check
        CHECK (change IN ('create', 'update', 'rollback', 'delete', 'import')),
    CONSTRAINT site_config_history_spec_check
        CHECK ((change = 'delete') = (spec IS NULL)),
    CONSTRAINT site_config_history_rollback_check
        CHECK ((change = 'rollback') = (rollback_of IS NOT NULL)),
    CONSTRAINT site_config_history_note_check
        CHECK (note IS NULL OR char_length(note) <= 500)
);

-- One row per request. Partitioned by at_millis, one partition per UTC day
-- (decision_log_pYYYYMMDD), created ahead of time and dropped by the control
-- plane. A row that fits no partition (a wrong clock) is refused, see below.
CREATE TABLE decision_log (
    id             bigint GENERATED ALWAYS AS IDENTITY,
    at_millis      bigint NOT NULL,
    request_id     text NOT NULL,
    site           text,                       -- NULL for unknown_site
    site_version   bigint,
    edge           text NOT NULL,
    host           text NOT NULL,
    client         text NOT NULL,
    session        text NOT NULL DEFAULT '',
    context        text,                       -- session | address
    method         text NOT NULL,
    path           text NOT NULL,
    query          text,
    status         smallint,
    decision_path  text NOT NULL,
    outcome        text NOT NULL,
    -- Columns derived from trace / jev so lists and statistics need not parse JSON.
    total_ms       integer,
    jev_ms         integer,
    jev_access     text,
    jev_attack     text,
    jev_confidence real,
    jev_failure    text,
    trace          jsonb NOT NULL,
    jev            jsonb,
    PRIMARY KEY (at_millis, id)
) PARTITION BY RANGE (at_millis);

-- No default partition, on purpose: a default partition that holds rows of some
-- day blocks creating that day's partition, so partition maintenance would stall.
-- An insert with no matching partition fails; the gateway counts it in
-- write_errors and the console shows the gap (docs/07 section 7.8.1).

CREATE INDEX decision_log_request_idx ON decision_log (request_id);
CREATE INDEX decision_log_site_idx ON decision_log (site, at_millis DESC);
CREATE INDEX decision_log_session_idx ON decision_log (session, at_millis) WHERE session <> '';
CREATE INDEX decision_log_path_idx ON decision_log (site, path text_pattern_ops, at_millis DESC);
CREATE INDEX decision_log_attention_idx ON decision_log (at_millis DESC)
    WHERE outcome IN ('blocked', 'would_block', 'unjudged');
CREATE INDEX decision_log_jev_idx ON decision_log (at_millis DESC) WHERE jev IS NOT NULL;
-- Finds the request that issued a session (trace.response.issued_session) without
-- scanning the window; only the few issuing rows are indexed. It serves the
-- issuing-request lookups of sections 7.9.4 and 7.9.6, which the index list of
-- section 7.8.1 does not mention.
CREATE INDEX decision_log_issued_idx ON decision_log ((trace #>> '{response,issued_session}'))
    WHERE trace #>> '{response,issued_session}' IS NOT NULL;

-- One heartbeat row per gateway instance, upserted every 10 seconds.
CREATE TABLE edge_status (
    edge         text PRIMARY KEY,
    started_at   timestamptz NOT NULL,
    seen_at      timestamptz NOT NULL,
    build        text NOT NULL,
    listen       text NOT NULL,
    tls          boolean NOT NULL,
    sites        jsonb NOT NULL,               -- {"emr":{"version":12},"bad":{"error":"SITE_CONFIG_ORIGIN_INVALID"}}
    sessions     integer NOT NULL,
    queue        integer NOT NULL,
    written      bigint NOT NULL,
    dropped      bigint NOT NULL,
    dropped_bypass bigint NOT NULL,            -- bypass rows shed under queue pressure (docs/07 section 7.7.4)
    write_errors bigint NOT NULL,
    -- Recent loss intervals, last 24 hours, e.g. [{"from_ms":...,"to_ms":...,"dropped":37,"dropped_bypass":0,"write_errors":0}]
    gaps         jsonb NOT NULL,
    jev          jsonb NOT NULL,               -- route, endpoint host, model, default timeout, prompt id; never a key
    params       jsonb NOT NULL                -- the gateway's effective run parameters
);

-- The instruction text of a Jev prompt version; decision_log.jev->>'prompt'
-- refers to id. Written once per version by the gateway at start-up.
CREATE TABLE jev_prompts (
    id         text PRIMARY KEY,
    questions  jsonb NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT now()
);
