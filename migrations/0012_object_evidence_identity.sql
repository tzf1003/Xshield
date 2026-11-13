-- Who used each vote of the object-map learning (docs/07 sections 7.4.7 and 7.9.16). The acceptance
-- judgement of a request position counts users where the site declares identities, and leaves the votes
-- of administrators out, so a vote keeps the user label its session showed and whether the session showed
-- the administrator role. The label is the keyed hash the tier evidence keeps (`object_response_evidence.unit`),
-- never the user id.
--
-- Votes written before this migration keep no user and no administrator role (NULL and false). Nothing is
-- backfilled: the seven-day window drops those rows. Denials carry neither. The table keeps its key and its
-- generation guard; deleting the site still removes its rows (`object_learning_store::forget_site`).

ALTER TABLE object_evidence ADD COLUMN user_label text;
ALTER TABLE object_evidence ADD COLUMN admin boolean NOT NULL DEFAULT false;
-- Added NOT VALID and validated on its own: the check then scans the table under a lock that lets reads and
-- writes go on, instead of holding ACCESS EXCLUSIVE for the whole scan.
ALTER TABLE object_evidence ADD CONSTRAINT object_evidence_identity_check
    CHECK (kind = 'vote' OR (user_label IS NULL AND NOT admin)) NOT VALID;
ALTER TABLE object_evidence VALIDATE CONSTRAINT object_evidence_identity_check;

COMMENT ON COLUMN object_evidence.user_label IS 'Votes only: the user label the session showed, a keyed hash as in object_response_evidence.unit; NULL when the session showed none. Denials: NULL.';
COMMENT ON COLUMN object_evidence.admin IS 'Votes only: whether the session showed the administrator role. Denials: false.';
