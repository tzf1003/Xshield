-- Response tiers of the object-map learning (docs/07 section 7.9.16). The learning pass keeps, per
-- response position, what each unit saw there by UTC day: the fingerprints it saw, and whether
-- every record of the unit kept all the values the position showed. Admin units and the refusals of
-- a route are kept beside them, and so is a unit whose record was cut before it reached every
-- position. The rules propose a position's tier from these rows, and an administrator confirms the
-- proposal before the tier enters the site's configuration. Only the control plane writes these
-- tables. Deleting the site removes its rows in the same transaction (`object_learning_store::forget_site`).

CREATE TABLE object_response_evidence (
    site         text NOT NULL,
    kind         text NOT NULL,                  -- 'seen', 'admin', 'refused' or 'capped'
    slot         text NOT NULL,                  -- 'seen' and 'admin': the response position; 'refused': the route, METHOD route; 'capped': empty
    unit         text NOT NULL,                  -- the user label, or the session label where the site declares no users
    day          bigint NOT NULL,                -- UTC day, counted from the epoch
    fingerprints text[] NOT NULL DEFAULT '{}',   -- 'seen' only: the smallest values the unit saw that day, at most 64
    complete     boolean NOT NULL DEFAULT true,  -- 'seen' only: false once a record kept only the smallest values
    CONSTRAINT object_response_evidence_pkey PRIMARY KEY (site, kind, slot, unit, day),
    CONSTRAINT object_response_evidence_kind_check CHECK (kind IN ('seen', 'admin', 'refused', 'capped')),
    CONSTRAINT object_response_evidence_shape_check CHECK (kind = 'seen' OR cardinality(fingerprints) = 0),
    CONSTRAINT object_response_evidence_day_check CHECK (day >= 0)
);
CREATE INDEX object_response_evidence_day_idx ON object_response_evidence (site, day);

-- The tier proposals of the rules, one row per declared response position. A proposal waits for an
-- administrator. A dismissed proposal stays as a row marked dismissed, so the rules do not propose the
-- same tier again, until they reach another one.
CREATE TABLE object_tier_judgements (
    site                text NOT NULL,
    slot                text NOT NULL,           -- declared response position: METHOD route location
    tier                text NOT NULL,           -- 'self', 'org', 'admin' or 'public', as the rules give it
    reliability         text NOT NULL,           -- 'high' or 'medium', as the rules grade it
    units               integer NOT NULL,        -- units the judgement counts
    seen_values         integer NOT NULL,        -- distinct values among them
    agreement_per_mille integer NOT NULL,        -- the share of values that agree with the tier
    last_day            bigint NOT NULL,         -- last UTC day with a value the judgement counts
    updated_millis      bigint NOT NULL,
    dismissed           boolean NOT NULL DEFAULT false,
    CONSTRAINT object_tier_judgements_pkey PRIMARY KEY (site, slot),
    CONSTRAINT object_tier_judgements_tier_check CHECK (tier IN ('self', 'org', 'admin', 'public')),
    CONSTRAINT object_tier_judgements_reliability_check CHECK (reliability IN ('high', 'medium')),
    CONSTRAINT object_tier_judgements_counts_check CHECK (units >= 0 AND seen_values >= 0),
    CONSTRAINT object_tier_judgements_share_check CHECK (agreement_per_mille BETWEEN 0 AND 1000),
    CONSTRAINT object_tier_judgements_day_check CHECK (last_day >= 0)
);
