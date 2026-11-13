-- Function evidence of the object-map learning (docs/07 section 7.9.19). The learning pass keeps, per
-- function (a method and a route template, `METHOD template`) and UTC day, which units used it, which
-- administrator units used it, and which ordinary units were refused it. The rules propose a function that
-- only administrators use as an administrator function, in `object_tier_judgements`, and an administrator
-- confirms it before it enters the site's `objects.functions`. Only the control plane writes these rows, and
-- deleting the site removes them (`object_learning_store::forget_site`).
--
-- The rows share the table of the response tiers (0010), its pruning and its generation guard, so this
-- migration only widens the kind check. It backfills nothing and changes no other constraint.
--
--   function          an ordinary unit used the function; the unit is the user, or the session where the
--                     site declares no users
--   function_anon     a unit without an identity used it: `s:` and the session label, or `a:` and the
--                     client address
--   function_admin    an administrator's unit used it
--   function_refused  an ordinary unit was refused it

ALTER TABLE object_response_evidence DROP CONSTRAINT object_response_evidence_kind_check;
ALTER TABLE object_response_evidence ADD CONSTRAINT object_response_evidence_kind_check
    CHECK (kind IN ('seen', 'admin', 'refused', 'capped', 'function', 'function_anon', 'function_admin', 'function_refused'));

COMMENT ON TABLE object_response_evidence IS 'Object-map learning evidence per unit, position or function, and UTC day: the response tiers (seen, admin, refused, capped) and the function evidence (function, function_anon, function_admin, function_refused). Deleting the site removes its rows.';
COMMENT ON COLUMN object_response_evidence.kind IS 'seen, admin, refused, capped (response tiers), or function, function_anon, function_admin, function_refused (function evidence, section 7.9.19).';
COMMENT ON COLUMN object_response_evidence.slot IS 'seen and admin: the response position; refused: the route, METHOD route; capped: empty; the function kinds: the function key, METHOD template.';
COMMENT ON COLUMN object_response_evidence.unit IS 'The user label, or the session label where the site declares no users. function_anon: s: and the session label, or a: and the client address.';
