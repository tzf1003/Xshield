-- Object-map learning agent (object-map design note, section 4; console design 3.2 to 3.5
-- and 5.2). The agent answers the positions the rules cannot decide.
--
--   object_positions.source  who gave a position's kind: the rules or the agent. The
--                            console filters by it, and automatic tightening leaves an
--                            agent proposal in the queue.
--   object_agent_calls       one row per question the agent was asked, answered or not.
--                            The calls of a site on a day are its daily budget, the latest
--                            answer of a position is its verdict, and the rows give the
--                            usage and the last call of the model.
--   object_learning_runs     one row per learning run of a site: the hourly run or a
--                            manual one, with what it proposed and what the agent did.
--
-- A site's rows go with the site (forget_site). The learning pass prunes the calls and
-- the runs it no longer shows.

ALTER TABLE object_positions
    ADD COLUMN source text NOT NULL DEFAULT 'rule',
    ADD COLUMN ask_requested boolean NOT NULL DEFAULT false, -- the administrator asked again
    ADD CONSTRAINT object_positions_source_check CHECK (source IN ('rule', 'agent'));

CREATE TABLE object_learning_runs (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    site            text NOT NULL,
    trigger         text NOT NULL,              -- 'scheduled' (the hourly pass) or 'manual'
    started_millis  bigint NOT NULL,
    finished_millis bigint,                     -- NULL while the run is going
    proposals       integer NOT NULL DEFAULT 0, -- positions proposed by the rules or the agent
    tightened       integer NOT NULL DEFAULT 0,
    paused          integer NOT NULL DEFAULT 0,
    agent_asked     integer NOT NULL DEFAULT 0,
    agent_answered  integer NOT NULL DEFAULT 0,
    agent_failed    integer NOT NULL DEFAULT 0,
    agent_skipped   integer NOT NULL DEFAULT 0, -- questions held back by the budget or the pass
    error           text,
    CONSTRAINT object_learning_runs_trigger_check CHECK (trigger IN ('scheduled', 'manual')),
    CONSTRAINT object_learning_runs_counts_check CHECK (proposals >= 0 AND tightened >= 0
        AND paused >= 0 AND agent_asked >= 0 AND agent_answered >= 0 AND agent_failed >= 0
        AND agent_skipped >= 0)
);
CREATE INDEX object_learning_runs_site_idx ON object_learning_runs (site, id DESC);

CREATE TABLE object_agent_calls (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    site                 text NOT NULL,
    slot                 text NOT NULL,           -- the request position asked about
    run_id               bigint,                  -- the learning run that asked
    day                  bigint NOT NULL,         -- UTC day, counted from the epoch
    asked_millis         bigint NOT NULL,
    votes                integer NOT NULL,        -- votes in the window when asked
    flows                text[] NOT NULL DEFAULT '{}', -- response positions shown, sorted
    model                text NOT NULL DEFAULT '', -- the model's name, never its key
    latency_ms           integer NOT NULL DEFAULT 0,
    choice               text,                    -- NULL when no answer was accepted
    class                text,                    -- the kind: a candidate id, or a new id
    new_name             text,
    new_description      text,
    confidence           integer,                 -- percent, 0 to 100
    reason               text NOT NULL DEFAULT '',
    cites                text[] NOT NULL DEFAULT '{}',
    question             text NOT NULL DEFAULT '', -- the question's JSON: positions and votes, no values
    rule_choice          text,                    -- the rules' kind, when they disagreed with the answer
    failure              text,                    -- NULL when answered, else why not
    CONSTRAINT object_agent_calls_choice_check CHECK (choice IS NULL
        OR choice IN ('existing', 'new', 'ambiguous')),
    CONSTRAINT object_agent_calls_answer_check CHECK ((choice IS NULL) = (failure IS NOT NULL)),
    CONSTRAINT object_agent_calls_failure_check CHECK (failure IS NULL OR failure IN
        ('timeout', 'unavailable', 'not_json', 'choice', 'confidence', 'class', 'new_kind')),
    CONSTRAINT object_agent_calls_class_check CHECK (choice IS NULL OR choice = 'ambiguous'
        OR class IS NOT NULL),
    CONSTRAINT object_agent_calls_confidence_check CHECK (confidence IS NULL
        OR confidence BETWEEN 0 AND 100),
    CONSTRAINT object_agent_calls_counts_check CHECK (votes >= 0 AND latency_ms >= 0)
);
CREATE INDEX object_agent_calls_day_idx ON object_agent_calls (site, day);
CREATE INDEX object_agent_calls_slot_idx ON object_agent_calls (site, slot, id);
CREATE INDEX object_agent_calls_asked_idx ON object_agent_calls (asked_millis);
