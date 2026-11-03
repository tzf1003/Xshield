-- Acceptance judgements of the object-map learning (docs/07 section 7.9.16). The learning pass
-- proposes, for a declared request position, whether normal traffic sends it values from public
-- positions, and how sure the rules are. An administrator confirms a proposal, and only then does
-- the judgement enter the site's `objects` section as the entry's `accepts_public` and
-- `reliability`. Only the control plane writes this table. Deleting the site removes its rows in
-- the same transaction (`object_learning_store::forget_site`).
--
-- A dismissed proposal stays as a row with `dismissed` set, so the rules do not propose the same
-- value again. The row is replaced once the rules reach the other value.

CREATE TABLE object_judgements (
    site             text NOT NULL,
    slot             text NOT NULL,              -- declared request position: METHOD route location
    accepts_public   boolean NOT NULL,           -- the value the rules propose
    reliability      text NOT NULL,              -- 'high' or 'medium', as the rules grade it
    votes            integer NOT NULL,           -- votes the judgement counts
    sessions         integer NOT NULL,           -- distinct sessions among them
    public_per_mille integer NOT NULL,           -- share of those votes sent from public positions
    last_day         bigint NOT NULL,            -- last UTC day with a vote the judgement counts
    updated_millis   bigint NOT NULL,
    dismissed        boolean NOT NULL DEFAULT false,
    CONSTRAINT object_judgements_pkey PRIMARY KEY (site, slot),
    CONSTRAINT object_judgements_reliability_check CHECK (reliability IN ('high', 'medium')),
    CONSTRAINT object_judgements_counts_check CHECK (votes >= 0 AND sessions >= 0),
    CONSTRAINT object_judgements_share_check CHECK (public_per_mille BETWEEN 0 AND 1000),
    CONSTRAINT object_judgements_day_check CHECK (last_day >= 0)
);
