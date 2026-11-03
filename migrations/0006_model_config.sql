-- Model settings the console owns: the Jev judgement model and the learning
-- agent's model (docs/03 section 3.3, the model tab of the system page).
--
-- One row, id 1. Each group versions itself: a save bumps that group's version
-- and writes one row to model_config_history. A key is stored sealed (AES-256-GCM,
-- xshield-postgres key_seal.rs); only its last four characters are kept in clear,
-- for display. A NULL key means the console holds no key for that group. For
-- Jev, the gateway then reads its environment variables, as before.

CREATE TABLE model_config (
    id                smallint PRIMARY KEY CHECK (id = 1),

    jev_version       bigint NOT NULL DEFAULT 0 CHECK (jev_version >= 0),
    jev_route         text NOT NULL DEFAULT 'gateway'
                      CHECK (jev_route IN ('gateway', 'direct', 'custom')),
    jev_endpoint      text CHECK (jev_endpoint IS NULL OR length(jev_endpoint) <= 2048),
    jev_model         text CHECK (jev_model IS NULL OR length(jev_model) <= 200),
    jev_timeout_ms    integer NOT NULL DEFAULT 2000
                      CHECK (jev_timeout_ms BETWEEN 100 AND 30000),
    jev_key           bytea,
    jev_key_last4     text CHECK (jev_key_last4 IS NULL OR length(jev_key_last4) <= 4),
    jev_key_at        timestamptz,
    jev_saved_at      timestamptz,
    CHECK (jev_route <> 'custom' OR (jev_endpoint IS NOT NULL AND jev_model IS NOT NULL)),
    CHECK ((jev_key IS NULL) = (jev_key_last4 IS NULL)),

    agent_version     bigint NOT NULL DEFAULT 0 CHECK (agent_version >= 0),
    agent_provider    text NOT NULL DEFAULT 'gateway'
                      CHECK (agent_provider IN ('gateway', 'custom')),
    agent_endpoint    text CHECK (agent_endpoint IS NULL OR length(agent_endpoint) <= 2048),
    agent_model       text CHECK (agent_model IS NULL OR length(agent_model) <= 200),
    agent_timeout_ms  integer NOT NULL DEFAULT 30000
                      CHECK (agent_timeout_ms BETWEEN 5000 AND 120000),
    agent_share_key   boolean NOT NULL DEFAULT false,
    agent_key         bytea,
    agent_key_last4   text CHECK (agent_key_last4 IS NULL OR length(agent_key_last4) <= 4),
    agent_key_at      timestamptz,
    agent_saved_at    timestamptz,
    CHECK (agent_provider <> 'custom' OR agent_endpoint IS NOT NULL),
    CHECK ((agent_key IS NULL) = (agent_key_last4 IS NULL)),
    CHECK (NOT agent_share_key OR agent_key IS NULL)
);

INSERT INTO model_config (id) VALUES (1);

CREATE TABLE model_config_history (
    model_group   text NOT NULL CHECK (model_group IN ('jev', 'agent')),
    version       bigint NOT NULL CHECK (version >= 1),
    -- save: a new configuration; revert_to_env: the console gave Jev back to the environment.
    change        text NOT NULL CHECK (change IN ('save', 'revert_to_env')),
    -- The non-secret configuration of this version, for restoring it. No key.
    config        jsonb NOT NULL,
    -- [{"field": "...", "from": "...", "to": "..."}] for the fields that differ; the key
    -- appears as its last four characters.
    changes       jsonb NOT NULL,
    -- replaced: a new key; cleared: the console dropped its key; NULL: kept.
    key_change    text CHECK (key_change IN ('replaced', 'cleared')),
    -- The key in use after this version, as its last four characters.
    key_last4     text CHECK (key_last4 IS NULL OR length(key_last4) <= 4),
    note          text CHECK (note IS NULL OR length(note) <= 200),
    -- Whether the operator's test of these exact values had succeeded before saving.
    tested        boolean NOT NULL DEFAULT false,
    changed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (model_group, version)
);
