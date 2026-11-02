-- Object-map learning (docs/object-map-design.md section 3). The control plane's
-- learning pass reads each site's decision log through a cursor, keeps the evidence
-- the rules count, and records the state of each position they have judged. Only
-- the control plane writes these tables. Nothing here changes a site configuration:
-- an administrator confirms a proposal, and only then does its kind enter the
-- site's `objects` section.
--
--   object_evidence        one row per position, session and UTC day that voted or
--                          was refused; only the seven-day window is kept
--   object_positions       the state of each position the rules have judged
--   object_learning_cursor how far the pass has read each site's decision log
--
-- A site's rows carry only the site's name. Deleting the site removes its evidence and
-- positions in the same transaction (site_spec_store::delete) and moves its cursor to
-- the deletion time, so a site created later under the same name never learns from the
-- decision rows the old site logged. Every learning write checks that the site still
-- has a configuration.

CREATE TABLE object_evidence (
    site       text NOT NULL,
    slot       text NOT NULL,                   -- request position: METHOD route location
    session    text NOT NULL,                   -- session label, never a credential
    day        bigint NOT NULL,                 -- UTC day, counted from the epoch
    kind       text NOT NULL,                   -- 'vote' or 'denial'
    from_slots text[] NOT NULL DEFAULT '{}',    -- response positions a vote was shown at
    CONSTRAINT object_evidence_pkey PRIMARY KEY (site, slot, session, day, kind),
    CONSTRAINT object_evidence_kind_check CHECK (kind IN ('vote', 'denial')),
    CONSTRAINT object_evidence_from_check CHECK (kind = 'vote' OR cardinality(from_slots) = 0)
);
CREATE INDEX object_evidence_day_idx ON object_evidence (site, day);

CREATE TABLE object_positions (
    site            text NOT NULL,
    slot            text NOT NULL,
    state           text NOT NULL,
    class           text,                       -- the kind the state is about
    votes           integer NOT NULL DEFAULT 0,
    sessions        integer NOT NULL DEFAULT 0,
    share_per_mille integer NOT NULL DEFAULT 0, -- votes whose response position has the kind
    last_day        bigint NOT NULL,            -- last UTC day with a vote
    updated_millis  bigint NOT NULL,
    CONSTRAINT object_positions_pkey PRIMARY KEY (site, slot),
    CONSTRAINT object_positions_state_check CHECK (state IN
        ('proposed', 'confirmed', 'suspended', 'retired', 'dismissed', 'ambiguous')),
    CONSTRAINT object_positions_class_check CHECK (class IS NOT NULL
        OR state IN ('retired', 'dismissed', 'ambiguous')),
    CONSTRAINT object_positions_share_check CHECK (share_per_mille BETWEEN 0 AND 1000),
    CONSTRAINT object_positions_counts_check CHECK (votes >= 0 AND sessions >= 0)
);
CREATE INDEX object_positions_state_idx ON object_positions (site, state);

CREATE TABLE object_learning_cursor (
    site            text PRIMARY KEY,
    -- The last decision row read is (after_millis, after_id), in the decision log's
    -- (at_millis, id) order, so a batch that ends inside one millisecond resumes exactly.
    after_millis    bigint NOT NULL,
    after_id        bigint NOT NULL,
    updated_millis  bigint NOT NULL,
    CONSTRAINT object_learning_cursor_after_check CHECK (after_millis >= 0 AND after_id >= 0)
);
