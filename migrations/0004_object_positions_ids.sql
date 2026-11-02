-- Object-map learning, console contract (PR-3c). Every position the learning pass sees
-- gets a row, so the console can list it and address it by an opaque id, and a
-- dismissal is a flag on the row rather than a state.
--
--   id               an identity. The console addresses a learned row as `s<id>` and
--                    never reads the number's meaning
--   side             'request' for a position a request value sits at; 'response' for a
--                    response position a vote was shown at
--   state 'pending'  seen in the window, no proposal yet
--   dismissed        the administrator dismissed the proposal, or the position while it
--                    was pending. The rules do not propose it again until the evidence
--                    changes significantly: the kind differs from dismissed_class (when
--                    one was recorded), or the votes reach twice dismissed_votes.

ALTER TABLE object_positions DROP CONSTRAINT object_positions_state_check;
ALTER TABLE object_positions DROP CONSTRAINT object_positions_class_check;

ALTER TABLE object_positions
    ADD COLUMN id bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    ADD COLUMN side text NOT NULL DEFAULT 'request',
    ADD COLUMN dismissed boolean NOT NULL DEFAULT false,
    ADD COLUMN dismissed_class text,
    ADD COLUMN dismissed_votes integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT object_positions_side_check CHECK (side IN ('request', 'response')),
    ADD CONSTRAINT object_positions_dismissed_check CHECK (
        dismissed_votes >= 0 AND (NOT dismissed OR state IN ('pending', 'retired')));

-- No code wrote 'dismissed' as a state before this migration. A row that carries it
-- becomes a dismissed pending row, with the baseline the rules would use (the default
-- minimum of 20 votes), so the migration fails on no data it can meet.
UPDATE object_positions
    SET state = 'pending', class = NULL, dismissed = true,
        dismissed_class = class, dismissed_votes = GREATEST(votes, 20)
    WHERE state = 'dismissed';

ALTER TABLE object_positions
    ADD CONSTRAINT object_positions_state_check CHECK (state IN
        ('pending', 'proposed', 'confirmed', 'suspended', 'retired', 'ambiguous')),
    ADD CONSTRAINT object_positions_class_check CHECK (class IS NOT NULL
        OR state IN ('pending', 'retired', 'ambiguous'));
