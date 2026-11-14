-- The public-source share of a request position whose acceptance the rules leave open (docs/07 section
-- 7.9.16, LQ-9). Between `RARE_PUBLIC_PER_MILLE` and `COMMON_PUBLIC_PER_MILLE` the rules give no acceptance,
-- so the position keeps its configuration and an administrator decides it. These rows are what the console
-- shows them to decide with. A row is replaced when the rules judge the position again, and removed when they
-- give an answer, when the position has no votes, or when the configuration already carries its acceptance.
-- Only the control plane writes this table. Deleting the site removes its rows in the same transaction
-- (`object_learning_store::forget_site`).
CREATE TABLE object_public_shares (
    site              text NOT NULL,
    slot              text NOT NULL,             -- declared request position: METHOD route location
    public_per_mille  integer NOT NULL,          -- judged votes whose values came from public positions only, in thousandths
    pending_per_mille integer NOT NULL,          -- judged votes with a value at a position awaiting its kind, in thousandths
    votes             integer NOT NULL,          -- votes the judgement counts
    sessions          integer NOT NULL,          -- distinct units among them
    last_day          bigint NOT NULL,           -- last UTC day with a vote the judgement counts
    updated_millis    bigint NOT NULL,
    CONSTRAINT object_public_shares_pkey PRIMARY KEY (site, slot),
    CONSTRAINT object_public_shares_share_check CHECK (public_per_mille BETWEEN 0 AND 1000
        AND pending_per_mille BETWEEN 0 AND 1000 AND public_per_mille + pending_per_mille <= 1000),
    CONSTRAINT object_public_shares_counts_check CHECK (votes >= 0 AND sessions >= 0),
    CONSTRAINT object_public_shares_day_check CHECK (last_day >= 0)
);
