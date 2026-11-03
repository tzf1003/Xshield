//! The fast allows a draft moves over the last day of decisions: the `new_fast_allow` and
//! `back_to_jev` changes of the impact preview (docs/07 section 7.9.10), for `objects.slots`
//! and `advanced.field_kinds`.
//!
//! The judge fast-allows a request when each of its values is verified: a place that showed
//! the value to the session shows it as the kind of object the request needs. The kind of a
//! request position comes from the object map, or from the name when the map is silent. The
//! kind of a query, form or body value comes from a declaration of its key, or else from the
//! key's name. A draft that changes the kind of a position, or a declaration a name is read
//! under, changes which values are verified, so each decision of the window that touched such
//! a position or name is judged again under the proposed configuration, with the judge's own
//! rule (`xshield_core::kind::shown_as`). A Jev call that would now be verified becomes a new
//! fast allow; a fast allow that would no longer be verified goes back to Jev. The history
//! keeps at most three places per value, so the counts are estimates.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;
use xshield_core::{
    context::{ADMIN_ROLE, Reliability, SiteSpec, Tier, TraceValue, tier_proves},
    kind::{
        LONG_VALUE_CHARS, Rules, Shown, Used, declaration_reads, declared_kind_of, name_kind_of,
        path_segment, shown_as,
    },
    path_template::{is_templatable, position_template},
};
use xshield_judge::slots::request_place;
use xshield_postgres::decision_stats::{self, Reach, Scope, SlotRow};

use crate::{
    error::ApiResult,
    preview::{ChangeBody, ChangeDetailBody, PathCount, TOP_PATHS},
};

/// The change kind of Jev calls that would become fast allows.
const NEW_FAST_ALLOW: &str = "new_fast_allow";
/// The change kind of fast allows that would call Jev again.
const BACK_TO_JEV: &str = "back_to_jev";
/// The deciding step of a request whose every value was verified.
const FAST_ALLOW: &str = "fast_allow";
/// The deciding steps that called Jev.
const JEV_CALLS: [&str; 3] = ["jev_allow", "jev_deny", "jev_unavailable"];

/// The fast-allow changes that a draft makes over `scope`, and whether the window was read in
/// full. The draft is the difference between `current` and `proposed`.
///
/// # Errors
/// Returns the database error when the decisions cannot be read.
pub(crate) async fn changes(
    pool: &PgPool,
    scope: &Scope,
    current: &SiteSpec,
    proposed: &SiteSpec,
) -> ApiResult<(Vec<ChangeBody>, bool)> {
    let moved = Moved::of(current, proposed);
    if moved.is_empty() {
        return Ok((Vec::new(), true));
    }
    let (rows, complete) =
        decision_stats::window_rows(pool, scope, &moved.reach(), &moved.fields).await?;
    let shifted = moves_of(&rows, &moved, &Reading::of(current), &Reading::of(proposed));
    let changes = [
        shifted.new_fast_allow.change(NEW_FAST_ALLOW),
        shifted.back_to_jev.change(BACK_TO_JEV),
    ]
    .into_iter()
    .flatten()
    .collect();
    Ok((changes, complete))
}

/// What a draft moves: the positions whose kind or pause changes, the field names whose
/// `advanced.field_kinds` declarations differ, and whether the draft changes whether the site
/// judges public access.
#[derive(Debug, Default, PartialEq, Eq)]
struct Moved {
    /// The request and response positions the judge reads a different kind for.
    slots: BTreeSet<String>,
    /// The field names of the declarations the draft adds, removes or changes.
    fields: Vec<String>,
    /// Whether the site starts or stops judging public access. Then the judge places the values
    /// of every path the map cannot template differently, so every decision of the window is read.
    judging: bool,
}

impl Moved {
    fn of(current: &SiteSpec, proposed: &SiteSpec) -> Self {
        let (old, new) = (
            current.advanced().field_kinds(),
            proposed.advanced().field_kinds(),
        );
        let fields: BTreeSet<String> = old
            .iter()
            .filter(|declared| !new.contains(*declared))
            .chain(new.iter().filter(|declared| !old.contains(*declared)))
            .map(|declared| declared.field().to_owned())
            .collect();
        Self {
            slots: moved_positions(current, proposed),
            fields: fields.into_iter().collect(),
            judging: current.objects().judges_public_access()
                != proposed.objects().judges_public_access(),
        }
    }

    fn is_empty(&self) -> bool {
        self.slots.is_empty() && self.fields.is_empty() && !self.judging
    }

    /// The part of the window the draft can move (see [`Reach`]): the positions it names, the
    /// declared positions whose `{id}` segments may govern a value recorded at another spelling,
    /// and every decision when it changes whether the site judges public access.
    fn reach(&self) -> Reach {
        let covered: BTreeSet<(String, String)> = self
            .slots
            .iter()
            .filter_map(|key| covering_of(key))
            .collect();
        Reach {
            slots: self.slots.iter().cloned().collect(),
            covered: covered.into_iter().collect(),
            every: self.judging,
        }
    }

    /// Whether the judge reads a value of a decision differently under the draft: its position,
    /// or a place that showed it, moved; or a declaration its key or its origin's field is read
    /// under changed.
    fn touches(&self, value: &TraceValue, slot: &str) -> bool {
        self.slots.contains(slot)
            || value.sources.iter().any(|source| {
                source
                    .slot
                    .as_deref()
                    .is_some_and(|at| self.slots.contains(at))
            })
            || value.key.as_deref().is_some_and(|key| self.reads(key))
            || value.sources.iter().any(|source| self.reads(&source.field))
    }

    /// Whether a declaration the draft changes is one `name` is read under.
    fn reads(&self, name: &str) -> bool {
        self.fields
            .iter()
            .any(|declared| declaration_reads(name, declared))
    }
}

/// The positions the judge reads a different way under the two configurations: the positions a
/// draft adds, removes, or gives another kind, tier, reliability or public-source setting. A paused
/// entry reads as nothing, so pausing one counts as a change too.
fn moved_positions(current: &SiteSpec, proposed: &SiteSpec) -> BTreeSet<String> {
    let keys: BTreeSet<&str> = current
        .objects()
        .slots()
        .iter()
        .chain(proposed.objects().slots())
        .map(|slot| slot.key.as_str())
        .collect();
    keys.into_iter()
        .filter(|key| read_of(current, key) != read_of(proposed, key))
        .map(str::to_owned)
        .collect()
}

/// The method and location of a declared position whose route template has an `{id}` segment.
/// Such a position may govern a value that the trace records at another spelling of its segment,
/// such as a slug id, a `;` parameter or an escaped slash. `None` for a literal template.
fn covering_of(key: &str) -> Option<(String, String)> {
    let (method, rest) = key.split_once(' ')?;
    let (template, location) = rest.rsplit_once(' ')?;
    template
        .split('/')
        .any(|segment| segment == "{id}")
        .then(|| (method.to_owned(), location.to_owned()))
}

/// The route template of a position key: `/api/patients/{id}` for `DELETE /api/patients/{id} path[2]`.
fn template_of(key: &str) -> Option<&str> {
    let (_, rest) = key.split_once(' ')?;
    rest.rsplit_once(' ').map(|(template, _)| template)
}

/// How the judge reads one position of a configuration: its kind, its tier judgement (with how sure
/// the map is of it), and its public-source setting (docs/07 section 7.4.7).
#[derive(Debug, PartialEq, Eq)]
struct PositionRead {
    class: Option<String>,
    tier: Option<(Tier, Reliability)>,
    accepts_public: Option<bool>,
    reliability: Option<Reliability>,
}

fn read_of(spec: &SiteSpec, key: &str) -> PositionRead {
    let objects = spec.objects();
    PositionRead {
        class: objects.class_of(key).map(str::to_owned),
        tier: objects.tier_judgement_of(key),
        accepts_public: objects.accepts_public_of(key),
        reliability: objects.reliability_of(key),
    }
}

/// A configuration as the judge reads it: its object map, and the kind rules of its
/// advanced section.
struct Reading<'a> {
    spec: &'a SiteSpec,
    rules: Rules,
}

impl<'a> Reading<'a> {
    fn of(spec: &'a SiteSpec) -> Self {
        Self {
            spec,
            rules: Rules::of(spec.advanced()),
        }
    }

    /// Whether the judge gives no request of this path a fast allow under this configuration: the
    /// site judges public access, and no template can place the path (docs/07 section 7.4.7).
    fn unplaceable(&self, row: &SlotRow) -> bool {
        self.spec.objects().judges_public_access() && !is_templatable(&row.path)
    }

    /// The position the judge gives a request value under this configuration, and whether the
    /// value is unplaced: no declared position governs it on a path that cannot be placed.
    fn placed(&self, row: &SlotRow, value: &TraceValue) -> (String, bool) {
        let place = request_place(self.spec.objects(), &row.method, &row.path, &value.at);
        let unplaced = !value.inert && self.unplaceable(row) && place.key.is_none();
        (place.slot(&row.method, &row.path, &value.at), unplaced)
    }

    /// The route template a decision is grouped under: the template of the declared position that
    /// governs one of its values, else the template its path names.
    fn route(&self, row: &SlotRow, values: &[TraceValue]) -> String {
        values
            .iter()
            .filter(|value| !value.inert)
            .find_map(|value| {
                request_place(self.spec.objects(), &row.method, &row.path, &value.at)
                    .key
                    .and_then(template_of)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| position_template(&row.path))
    }

    /// Whether a request value is verified at position `slot`: one place that showed the
    /// value to the session shows it as the kind the request needs, judged as the gateway
    /// judges it, and the configuration's tiers let that place prove a right (docs/07 section
    /// 7.4.7). The rule reads the value's key, its location and its length, not its text.
    fn verifies(&self, row: &SlotRow, value: &TraceValue, slot: &str) -> bool {
        let objects = self.spec.objects();
        let wanted = objects.class_of(slot);
        let used = used_of(row, value);
        let long = value.len.unwrap_or_else(|| value.value.chars().count()) >= LONG_VALUE_CHARS;
        let closed = objects.closed_to_public(slot);
        let admin = row.role.as_deref() == Some(ADMIN_ROLE);
        value.sources.iter().any(|source| {
            let shown = Shown {
                field: &source.field,
                request: &source.request,
            };
            let known = source.slot.as_deref().and_then(|at| objects.class_of(at));
            let tier = source
                .slot
                .as_deref()
                .and_then(|at| objects.tier_judgement_of(at));
            shown_as(used, shown, wanted, known, &self.rules, long)
                && tier_proves(tier, closed, admin)
        })
    }
}

/// How a request uses a value: its key, its path and its place in the path. The text of the
/// value is not part of it, because the judge's rule does not read it.
fn used_of<'a>(row: &'a SlotRow, value: &'a TraceValue) -> Used<'a> {
    Used {
        value: "",
        path: &row.path,
        key: value.key.as_deref(),
        segment: path_segment(&value.at),
    }
}

/// How one decision moves under the proposed configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shift {
    /// A Jev call whose every value is verified under the proposed configuration.
    NewFastAllow,
    /// A fast allow with a value that the proposed configuration no longer verifies.
    BackToJev,
}

/// The shift of one decision, and for a fast allow that calls Jev again, the kinds that explain
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    shift: Shift,
    /// The kind the name gives the value the draft stops verifying, and the kind the draft gives
    /// it.
    kinds: Option<(String, String)>,
}

/// The shift of one decision, if it has one. A value is judged again when the draft touches it
/// (see [`Moved::touches`]) or places it differently; every other value keeps the verdict the
/// trace recorded. A value that no position governs is unverified where the site judges public
/// access, and so is every value of a path no template can place (docs/07 section 7.4.7).
fn shift(
    row: &SlotRow,
    values: &[TraceValue],
    moved: &Moved,
    current: &Reading<'_>,
    next: &Reading<'_>,
) -> Option<Verdict> {
    let mut verified_now = !current.unplaceable(row);
    let mut verified_next = !next.unplaceable(row);
    // The first value that verifies now and stops verifying under the draft, with its position
    // under the draft, and whether the draft places it differently.
    let mut lost: Option<(&TraceValue, String, bool)> = None;
    for value in values.iter().filter(|value| !value.inert) {
        // Where the judge places the value now, and under the draft. The draft changes the value's
        // placement when either differs; the trace's own position is not compared, because a trace
        // written before a declaration was judged may name another spelling of the same position.
        let (before, unplaced_before) = current.placed(row, value);
        let (slot, unplaced) = next.placed(row, value);
        let placed_differently = before != slot || unplaced_before != unplaced;
        verified_now &= value.verified;
        let verified = if unplaced {
            false
        } else if (placed_differently
            || moved.touches(value, &before)
            || moved.touches(value, &slot))
            && !value.sources.is_empty()
        {
            next.verifies(row, value, &slot)
        } else {
            value.verified
        };
        if value.verified && !verified && lost.is_none() {
            lost = Some((value, slot, placed_differently));
        }
        verified_next &= verified;
    }
    match row.decision_path.as_str() {
        FAST_ALLOW if verified_now && !verified_next => Some(Verdict {
            shift: Shift::BackToJev,
            // A value the draft places differently, or a path it no longer places at all, is
            // explained by the placement, not by a name's kind.
            kinds: lost
                .filter(|(_, _, placed_differently)| !placed_differently && !next.unplaceable(row))
                .and_then(|(value, slot, _)| kinds_of(row, value, &slot, current, next)),
        }),
        decision if JEV_CALLS.contains(&decision) && !verified_now && verified_next => {
            Some(Verdict {
                shift: Shift::NewFastAllow,
                kinds: None,
            })
        }
        _ => None,
    }
}

/// The kinds that explain a value the draft stops verifying: the kind its name gives under the
/// current configuration, and the kind the proposed configuration gives it, from the object map
/// at its position or else from a declaration of its key. `None` when either is missing, and
/// when the current map gives the position a class: that class judged the value, not its name,
/// so no name explains the change.
fn kinds_of(
    row: &SlotRow,
    value: &TraceValue,
    slot: &str,
    current: &Reading<'_>,
    next: &Reading<'_>,
) -> Option<(String, String)> {
    if current.spec.objects().class_of(slot).is_some() {
        return None;
    }
    let used = used_of(row, value);
    let name = name_kind_of(used, &current.rules)?;
    let object = next
        .spec
        .objects()
        .class_of(slot)
        .or_else(|| declared_kind_of(used, &next.rules))?;
    Some((name, object.to_owned()))
}

/// The requests that each change kind moves.
#[derive(Default)]
struct Moves {
    new_fast_allow: Groups,
    back_to_jev: Groups,
}

/// Judges every row again and sorts the ones that move into their change kind.
fn moves_of(rows: &[SlotRow], moved: &Moved, current: &Reading<'_>, next: &Reading<'_>) -> Moves {
    let mut found = Moves::default();
    for row in rows {
        // A trace the history wrote in an older form carries no values to judge.
        let Ok(values) = serde_json::from_str::<Vec<TraceValue>>(&row.values) else {
            continue;
        };
        let Some(verdict) = shift(row, &values, moved, current, next) else {
            continue;
        };
        let route = next.route(row, &values);
        match verdict.shift {
            Shift::NewFastAllow => found.new_fast_allow.add(row, None, route),
            Shift::BackToJev => found.back_to_jev.add(row, verdict.kinds, route),
        }
    }
    found
}

/// The requests of one change kind, by method and route template, and the kinds that explain
/// them.
#[derive(Default)]
struct Groups {
    count: i64,
    /// `(method, route)` to its requests, and the first request id among them.
    routes: BTreeMap<(String, String), (i64, String)>,
    /// How many requests each (name kind, object kind) pair explains.
    kinds: BTreeMap<(String, String), i64>,
}

impl Groups {
    fn add(&mut self, row: &SlotRow, kinds: Option<(String, String)>, route: String) {
        self.count += 1;
        let (requests, _) = self
            .routes
            .entry((row.method.clone(), route))
            .or_insert_with(|| (0, row.request_id.clone()));
        *requests += 1;
        if let Some(pair) = kinds {
            *self.kinds.entry(pair).or_insert(0) += 1;
        }
    }

    /// The change for these requests, or `None` when there are none. The example request
    /// comes from the largest group, and the detail names the kinds most requests share.
    fn change(&self, kind: &str) -> Option<ChangeBody> {
        if self.count == 0 {
            return None;
        }
        let mut routes: Vec<(&(String, String), i64, &str)> = self
            .routes
            .iter()
            .map(|(route, (requests, sample))| (route, *requests, sample.as_str()))
            .collect();
        routes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        let sample = routes.first().map(|(_, _, sample)| (*sample).to_owned());
        let top: Vec<PathCount> = routes
            .iter()
            .take(TOP_PATHS)
            .map(|(route, requests, _)| (route.0.clone(), route.1.clone(), *requests))
            .collect();
        let detail = match self.explanation() {
            Some((name_kind, object_kind)) => ChangeDetailBody::Kinds {
                approximate: true,
                name_kind,
                object_kind,
            },
            None => ChangeDetailBody::Approximate { approximate: true },
        };
        Some(ChangeBody {
            kind: kind.to_owned(),
            count: self.count,
            top: Some(top),
            would_block: None,
            sample,
            detail: Some(detail),
        })
    }

    /// The (name kind, object kind) pair that the most requests share; on a tie, the smaller
    /// pair.
    fn explanation(&self) -> Option<(String, String)> {
        self.kinds
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(pair, _)| pair.clone())
    }
}

#[cfg(test)]
mod tests {
    use xshield_core::context::TraceSource;

    use super::*;

    /// A map with a document and a doctor: two response positions, and one request position
    /// of a doctor. Written on one line, so that the tests can rewrite single entries.
    const DOCS: &str = r#"{"classes":[{"id":"document","name":"文档"},{"id":"doctor","name":"医生"}],"slots":[{"key":"GET /api/docs [].id","class":"document","source":"admin"},{"key":"GET /api/doctors [].id","class":"doctor","source":"admin"},{"key":"GET /doctor/{id} path[1]","class":"doctor","source":"admin"}]}"#;

    const DOCTOR_SLOT: &str =
        r#"{"key":"GET /doctor/{id} path[1]","class":"doctor","source":"admin"}"#;

    fn spec(objects: &str) -> SiteSpec {
        let text = format!(
            r#"{{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{{"cookie":"SID"}},"entries":["/login"],"objects":{objects}}}"#
        );
        SiteSpec::from_json(&text).expect("valid test site")
    }

    /// `spec` with the declarations of `advanced.field_kinds` written as `field_kinds`.
    fn spec_declaring(objects: &str, field_kinds: &str) -> SiteSpec {
        let text = format!(
            r#"{{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{{"cookie":"SID"}},"entries":["/login"],"objects":{objects},"advanced":{{"field_kinds":{field_kinds}}}}}"#
        );
        SiteSpec::from_json(&text).expect("valid test site")
    }

    /// The map of `DOCS` with one piece rewritten. The piece must be in `DOCS`, or the test
    /// would compare a configuration with itself.
    fn edited(from: &str, to: &str) -> SiteSpec {
        assert!(DOCS.contains(from), "not in the test map: {from}");
        spec(&DOCS.replace(from, to))
    }

    fn origin(field: &str, request: &str, slot: &str) -> TraceSource {
        TraceSource {
            field: field.to_owned(),
            request: request.to_owned(),
            request_id: None,
            at_millis: None,
            slot: Some(slot.to_owned()),
            object: None,
            object_from: None,
            tier: None,
            reliability: None,
        }
    }

    fn value(at: &str, verified: bool, sources: Vec<TraceSource>) -> TraceValue {
        TraceValue {
            at: at.to_owned(),
            at_len: None,
            key: None,
            value: "7".to_owned(),
            len: None,
            clipped: false,
            kind: "reference".to_owned(),
            inert: false,
            seen: !sources.is_empty(),
            verified,
            sources,
            slot: None,
            object: None,
            object_from: None,
            public_access: None,
            attempt: None,
            unplaced: false,
        }
    }

    /// A query value of `key`, as the trace keeps it.
    fn keyed(key: &str, verified: bool, sources: Vec<TraceSource>) -> TraceValue {
        TraceValue {
            at: "query".to_owned(),
            key: Some(key.to_owned()),
            ..value("query", verified, sources)
        }
    }

    fn row(decision: &str, path: &str) -> SlotRow {
        method_row("GET", decision, path)
    }

    /// A decision of `method` to `path` by a session that declared no role.
    fn method_row(method: &str, decision: &str, path: &str) -> SlotRow {
        SlotRow {
            request_id: "req_1".to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            decision_path: decision.to_owned(),
            values: String::new(),
            role: None,
        }
    }

    /// The verdict of a decision when a draft moves the configuration from `current` to
    /// `proposed`.
    fn verdict_under(
        current: &SiteSpec,
        proposed: &SiteSpec,
        row: &SlotRow,
        values: &[TraceValue],
    ) -> Option<Verdict> {
        let moved = Moved::of(current, proposed);
        shift(
            row,
            values,
            &moved,
            &Reading::of(current),
            &Reading::of(proposed),
        )
    }

    /// The shift of a decision when a draft moves the configuration (see [`verdict_under`]).
    fn shift_under(
        current: &SiteSpec,
        proposed: &SiteSpec,
        row: &SlotRow,
        values: &[TraceValue],
    ) -> Option<Shift> {
        verdict_under(current, proposed, row, values).map(|verdict| verdict.shift)
    }

    #[test]
    fn a_position_given_a_kind_turns_its_jev_calls_into_fast_allows() {
        // `/doctors/7` names a doctor by its route word, so by name the value is not a
        // document. The draft gives the position a document, which `GET /api/docs` showed:
        // the value is verified under the draft and was not before.
        let current = spec(DOCS);
        let proposed = edited(
            DOCTOR_SLOT,
            &format!(
                r#"{DOCTOR_SLOT},{{"key":"GET /doctors/{{id}} path[1]","class":"document","source":"admin"}}"#
            ),
        );
        let call = row("jev_allow", "/doctors/7");
        let docs = [value(
            "path[1]",
            false,
            vec![origin("id", "GET /api/docs", "GET /api/docs [].id")],
        )];
        assert_eq!(
            shift_under(&current, &proposed, &call, &docs),
            Some(Shift::NewFastAllow)
        );
        // A value the response showed as a doctor is still not a document: it stays a call.
        let doctors = [value(
            "path[1]",
            false,
            vec![origin("id", "GET /api/doctors", "GET /api/doctors [].id")],
        )];
        assert_eq!(shift_under(&current, &proposed, &call, &doctors), None);
    }

    /// A map of patients: a search that shows them as tier `search` to every session, a DELETE of
    /// a patient that takes public sources when `accepts`, and an administrator's listing of tier
    /// `listing` at reliability `listing_reliability`.
    fn tiered(search: &str, accepts: bool, listing: &str, listing_reliability: &str) -> SiteSpec {
        spec(&format!(
            r#"{{"classes":[{{"id":"patient","name":"患者"}}],"slots":[
                {{"key":"GET /api/search results[].id","class":"patient","source":"admin","tier":"{search}","reliability":"high"}},
                {{"key":"DELETE /api/patients/{{id}} path[2]","class":"patient","source":"admin","accepts_public":{accepts},"reliability":"high"}},
                {{"key":"GET /api/admin/patients patients[].id","class":"patient","source":"admin","tier":"{listing}","reliability":"{listing_reliability}"}}
            ]}}"#
        ))
    }

    const DELETE_SLOT: &str = "DELETE /api/patients/{id} path[2]";

    #[test]
    fn a_draft_that_opens_a_closed_position_turns_its_attempts_into_fast_allows() {
        // The search shows the patient to every session and the DELETE takes no such source, so the
        // value is an attempt that Jev judges. The draft lets the DELETE take public sources: the same
        // value is then verified, and the Jev call would be a fast allow.
        let current = tiered("public", false, "admin", "high");
        let proposed = tiered("public", true, "admin", "high");
        assert_eq!(
            moved_positions(&current, &proposed),
            BTreeSet::from([DELETE_SLOT.to_owned()])
        );
        let attempt = method_row("DELETE", "jev_deny", "/api/patients/7005");
        let values = [value(
            "path[2]",
            false,
            vec![origin(
                "id",
                "GET /api/search",
                "GET /api/search results[].id",
            )],
        )];
        assert_eq!(
            shift_under(&current, &proposed, &attempt, &values),
            Some(Shift::NewFastAllow)
        );
    }

    #[test]
    fn a_draft_that_closes_a_position_sends_fast_allows_on_public_sources_back_to_jev() {
        let current = tiered("public", true, "admin", "high");
        let proposed = tiered("public", false, "admin", "high");
        let allowed = method_row("DELETE", "fast_allow", "/api/patients/7005");
        let values = [value(
            "path[2]",
            true,
            vec![origin(
                "id",
                "GET /api/search",
                "GET /api/search results[].id",
            )],
        )];
        assert_eq!(
            shift_under(&current, &proposed, &allowed, &values),
            Some(Shift::BackToJev)
        );
    }

    #[test]
    fn a_public_sighting_the_draft_marks_as_own_no_longer_proves_the_value() {
        // The search is tier public in the current map and tier self in the draft: its sighting
        // proves nothing as the session's own record, so the fast allow goes back to Jev.
        let current = tiered("public", true, "admin", "high");
        let proposed = tiered("self", true, "admin", "high");
        let allowed = method_row("DELETE", "fast_allow", "/api/patients/7005");
        let values = [value(
            "path[2]",
            true,
            vec![origin(
                "id",
                "GET /api/search",
                "GET /api/search results[].id",
            )],
        )];
        assert_eq!(
            shift_under(&current, &proposed, &allowed, &values),
            Some(Shift::BackToJev)
        );
    }

    #[test]
    fn an_administrator_fast_allow_on_an_admin_listing_stands_while_the_listing_stays_admin() {
        // For a session that declared the admin role, an admin-tier listing proves the value: a
        // reliability change that keeps the tier keeps the fast allow.
        let current = tiered("public", true, "admin", "high");
        let proposed = tiered("public", true, "admin", "medium");
        let mut allowed = method_row("DELETE", "fast_allow", "/api/patients/7005");
        allowed.role = Some("admin".to_owned());
        let values = [value(
            "path[2]",
            true,
            vec![origin(
                "id",
                "GET /api/admin/patients",
                "GET /api/admin/patients patients[].id",
            )],
        )];
        assert_eq!(moved_positions(&current, &proposed).len(), 1);
        assert_eq!(shift_under(&current, &proposed, &allowed, &values), None);
    }

    #[test]
    fn an_administrator_fast_allow_goes_back_to_jev_when_the_listing_is_no_longer_admin_tier() {
        let current = tiered("public", true, "admin", "high");
        let proposed = tiered("public", true, "self", "high");
        let mut allowed = method_row("DELETE", "fast_allow", "/api/patients/7005");
        allowed.role = Some("admin".to_owned());
        let values = [value(
            "path[2]",
            true,
            vec![origin(
                "id",
                "GET /api/admin/patients",
                "GET /api/admin/patients patients[].id",
            )],
        )];
        assert_eq!(
            shift_under(&current, &proposed, &allowed, &values),
            Some(Shift::BackToJev)
        );
    }

    #[test]
    fn a_request_spelled_another_way_is_read_at_the_position_it_names() {
        let current = tiered("public", false, "admin", "high");
        let spelled = method_row("DELETE", "jev_deny", "/api/patients/%37005/");
        let attempt = value("path[2]", false, Vec::new());
        assert_eq!(
            Reading::of(&current).placed(&spelled, &attempt).0,
            DELETE_SLOT
        );
    }

    #[test]
    fn a_fast_allow_whose_position_changes_kind_goes_back_to_jev() {
        let current = spec(DOCS);
        let proposed = edited(
            DOCTOR_SLOT,
            r#"{"key":"GET /doctor/{id} path[1]","class":"document","source":"admin"}"#,
        );
        let values = [value(
            "path[1]",
            true,
            vec![origin("id", "GET /api/doctors", "GET /api/doctors [].id")],
        )];
        let allowed = row("fast_allow", "/doctor/7");
        let verdict = verdict_under(&current, &proposed, &allowed, &values).expect("it moves");
        assert_eq!(verdict.shift, Shift::BackToJev);
        // The map gave the position a doctor and now gives a document: that class judged the
        // value, not the name, so no name explains the change.
        assert_eq!(verdict.kinds, None);
        // Decisions that are neither fast allows nor Jev calls do not move.
        let cached = row("cached_allow", "/doctor/7");
        assert_eq!(shift_under(&current, &proposed, &cached, &values), None);
    }

    #[test]
    fn a_position_without_a_class_is_explained_by_its_name() {
        // Without the entry, `/doctor/7` is judged by its route word, a doctor, and the response
        // showed a doctor: the name verified it. The draft gives the position a document, so the
        // name is what the old verdict relied on.
        let current = edited(&format!(",{DOCTOR_SLOT}"), "");
        let proposed = edited(
            DOCTOR_SLOT,
            r#"{"key":"GET /doctor/{id} path[1]","class":"document","source":"admin"}"#,
        );
        let values = [value(
            "path[1]",
            true,
            vec![origin("id", "GET /api/doctors", "GET /api/doctors [].id")],
        )];
        let allowed = row("fast_allow", "/doctor/7");
        let verdict = verdict_under(&current, &proposed, &allowed, &values).expect("it moves");
        assert_eq!(verdict.shift, Shift::BackToJev);
        assert_eq!(
            verdict.kinds,
            Some(("doctor".to_owned(), "document".to_owned()))
        );
    }

    #[test]
    fn a_removed_position_is_judged_by_its_name() {
        // Without the entry, `/doctor/7` is judged by its route word, which names a doctor,
        // and the response showed a doctor: still verified, so nothing moves.
        let current = spec(DOCS);
        let proposed = edited(&format!(",{DOCTOR_SLOT}"), "");
        let values = [value(
            "path[1]",
            true,
            vec![origin("id", "GET /api/doctors", "GET /api/doctors [].id")],
        )];
        let allowed = row("fast_allow", "/doctor/7");
        assert_eq!(shift_under(&current, &proposed, &allowed, &values), None);
    }

    #[test]
    fn decisions_that_touch_no_moved_position_keep_their_verdict() {
        let current = spec(DOCS);
        let proposed = edited(
            DOCTOR_SLOT,
            r#"{"key":"GET /doctor/{id} path[1]","class":"document","source":"admin"}"#,
        );
        // An unverified value at an unrelated route stays unverified under the draft.
        let docs = [value(
            "path[1]",
            false,
            vec![origin("id", "GET /api/docs", "GET /api/docs [].id")],
        )];
        let call = row("jev_deny", "/api/records/7");
        assert_eq!(shift_under(&current, &proposed, &call, &docs), None);
        let verified = [value(
            "path[1]",
            true,
            vec![origin("id", "GET /api/docs", "GET /api/docs [].id")],
        )];
        let allowed = row("fast_allow", "/api/records/7");
        assert_eq!(shift_under(&current, &proposed, &allowed, &verified), None);
    }

    #[test]
    fn inert_route_words_never_hold_a_decision_back() {
        let current = spec(DOCS);
        let proposed = edited(
            DOCTOR_SLOT,
            r#"{"key":"GET /doctor/{id} path[1]","class":"document","source":"admin"}"#,
        );
        let mut route = value("path[0]", false, Vec::new());
        route.inert = true;
        let values = [
            route,
            value(
                "path[1]",
                true,
                vec![origin("id", "GET /api/doctors", "GET /api/doctors [].id")],
            ),
        ];
        let allowed = row("fast_allow", "/doctor/7");
        assert_eq!(
            shift_under(&current, &proposed, &allowed, &values),
            Some(Shift::BackToJev)
        );
    }

    #[test]
    fn pausing_a_position_moves_it() {
        let current = spec(DOCS);
        let paused = edited(
            DOCTOR_SLOT,
            r#"{"key":"GET /doctor/{id} path[1]","class":"doctor","source":"admin","paused":true}"#,
        );
        assert_eq!(
            moved_positions(&current, &paused)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["GET /doctor/{id} path[1]".to_owned()]
        );
        assert!(moved_positions(&current, &current).is_empty());
    }

    #[test]
    fn a_declaration_that_moves_a_name_moves_the_decisions_that_read_it() {
        // `doc_id` was a doctor's id and is now a document's: a query value that a document
        // response showed is verified now, and one a doctor response showed no longer is.
        let current = spec_declaring(DOCS, r#"[{"field":"doc_id","kind":"doctor"}]"#);
        let proposed = spec_declaring(DOCS, r#"[{"field":"doc_id","kind":"document"}]"#);
        let docs = [keyed(
            "doc_id",
            false,
            vec![origin("id", "GET /api/docs", "GET /api/docs [].id")],
        )];
        let call = row("jev_allow", "/api/appointments");
        assert_eq!(
            shift_under(&current, &proposed, &call, &docs),
            Some(Shift::NewFastAllow)
        );
        let doctors = [keyed(
            "doc_id",
            true,
            vec![origin("id", "GET /api/doctors", "GET /api/doctors [].id")],
        )];
        let allowed = row("fast_allow", "/api/appointments");
        let verdict = verdict_under(&current, &proposed, &allowed, &doctors).expect("it moves");
        assert_eq!(verdict.shift, Shift::BackToJev);
        // The declaration named a doctor, and the draft now declares a document.
        assert_eq!(
            verdict.kinds,
            Some(("doctor".to_owned(), "document".to_owned()))
        );
    }

    #[test]
    fn a_declaration_outside_the_decision_path_moves_nothing() {
        // The declaration is limited to `/api/schedule`, so `/api/appointments` reads the name
        // as it always did.
        let current = spec_declaring(
            DOCS,
            r#"[{"field":"doc_id","kind":"doctor","in":["/api/schedule"]}]"#,
        );
        let proposed = spec_declaring(
            DOCS,
            r#"[{"field":"doc_id","kind":"document","in":["/api/schedule"]}]"#,
        );
        let docs = [keyed(
            "doc_id",
            false,
            vec![origin("id", "GET /api/docs", "GET /api/docs [].id")],
        )];
        let call = row("jev_allow", "/api/appointments");
        assert_eq!(shift_under(&current, &proposed, &call, &docs), None);
    }

    #[test]
    fn a_declaration_of_another_name_moves_nothing() {
        let current = spec(DOCS);
        let proposed = spec_declaring(DOCS, r#"[{"field":"visit","kind":"document"}]"#);
        let docs = [keyed(
            "page",
            false,
            vec![origin("id", "GET /api/docs", "GET /api/docs [].id")],
        )];
        let call = row("jev_deny", "/api/records");
        assert_eq!(shift_under(&current, &proposed, &call, &docs), None);
    }

    #[test]
    fn the_largest_route_gives_the_example_and_the_ranking() {
        let mut groups = Groups::default();
        let mut first = row("fast_allow", "/doctor/7");
        first.request_id = "req_small".to_owned();
        groups.add(&first, None, "/doctor/{id}".to_owned());
        let mut big = row("fast_allow", "/api/records/3");
        big.request_id = "req_big".to_owned();
        for _ in 0..3 {
            groups.add(&big, None, "/api/records/{id}".to_owned());
        }
        let change = groups.change(BACK_TO_JEV).expect("requests are counted");
        assert_eq!(change.kind, BACK_TO_JEV);
        assert_eq!(change.count, 4);
        assert_eq!(change.sample.as_deref(), Some("req_big"));
        assert_eq!(
            change.top,
            Some(vec![
                ("GET".to_owned(), "/api/records/{id}".to_owned(), 3),
                ("GET".to_owned(), "/doctor/{id}".to_owned(), 1),
            ])
        );
        assert_eq!(
            change.detail,
            Some(ChangeDetailBody::Approximate { approximate: true })
        );
        assert!(Groups::default().change(NEW_FAST_ALLOW).is_none());
    }

    #[test]
    fn the_kinds_most_requests_share_name_the_change() {
        let mut groups = Groups::default();
        let a = row("fast_allow", "/doctor/7");
        let b = row("fast_allow", "/doctor/8");
        let c = row("fast_allow", "/doctor/9");
        let pair = |name: &str, object: &str| Some((name.to_owned(), object.to_owned()));
        groups.add(&a, pair("doctor", "document"), "/doctor/{id}".to_owned());
        groups.add(&b, pair("doctor", "document"), "/doctor/{id}".to_owned());
        groups.add(&c, pair("doc", "doctor"), "/doctor/{id}".to_owned());
        let change = groups.change(BACK_TO_JEV).expect("requests are counted");
        assert_eq!(
            change.detail,
            Some(ChangeDetailBody::Kinds {
                approximate: true,
                name_kind: "doctor".to_owned(),
                object_kind: "document".to_owned(),
            })
        );
    }

    /// The search that shows every session a patient at a public tier, beside the entries `extra`
    /// of the map. Its position is classed, so a value it shows is a patient.
    const SEARCH_SLOT: &str = "GET /api/search results[].id";

    /// A map of patients: the public search, and the entries `extra`, each written with a comma.
    fn patients(extra: &str) -> SiteSpec {
        spec(&format!(
            r#"{{"classes":[{{"id":"patient","name":"患者"}}],"slots":[{{"key":"{SEARCH_SLOT}","class":"patient","source":"admin","tier":"public","reliability":"high"}}{extra}]}}"#
        ))
    }

    /// A DELETE of a patient at a declared id, closed to public sources. It makes the site judge
    /// public access.
    const CLOSED_DELETE: &str = r#"{"key":"DELETE /api/patients/{id} path[2]","class":"patient","source":"admin","accepts_public":false,"reliability":"high"}"#;

    /// A note written to a patient at a declared id, open to public sources.
    const OPEN_NOTE: &str = r#"{"key":"POST /api/notes/{id} path[2]","class":"patient","source":"admin","accepts_public":true,"reliability":"high"}"#;

    /// A position that no other test's request reaches, which a draft may add.
    const OTHER: &str = r#"{"key":"GET /api/other path[1]","class":"patient","source":"admin"}"#;

    /// A path that no template can place: its canonical spelling is longer than the templates take.
    fn long_path() -> String {
        format!("/api/patients/{}", "a".repeat(300))
    }

    /// The origin of a value that the search showed.
    fn seen_in_search() -> Vec<TraceSource> {
        vec![origin("id", "GET /api/search", SEARCH_SLOT)]
    }

    #[test]
    fn a_fast_allow_of_a_slug_id_goes_back_to_jev_once_a_closed_declared_id_governs_it() {
        // Nothing declares the DELETE today, so the slug id is an undeclared route and the search
        // sighting proves it. The draft declares the DELETE closed to public sources: its `{id}`
        // governs the slug id (docs/07 section 7.4.7), and the sighting no longer proves it.
        let current = patients("");
        let proposed = patients(&format!(",{CLOSED_DELETE}"));
        let delete = method_row("DELETE", "fast_allow", "/api/patients/PT-7004");
        let seen = [value("path[2]", true, seen_in_search())];
        assert_eq!(
            verdict_under(&current, &proposed, &delete, &seen),
            Some(Verdict {
                shift: Shift::BackToJev,
                kinds: None,
            })
        );
        // A Jev call on the same slug id, which the sighting never proved, stays a call.
        let called = method_row("DELETE", "jev_allow", "/api/patients/PT-7004");
        let unproved = [value("path[2]", false, seen_in_search())];
        assert_eq!(shift_under(&current, &proposed, &called, &unproved), None);
    }

    #[test]
    fn removing_a_closed_declared_id_lets_the_sighting_prove_a_slug_id_delete_again() {
        // The judge recorded the value at the declared position, which the draft removes.
        let current = patients(&format!(",{CLOSED_DELETE}"));
        let proposed = patients("");
        let attempt = method_row("DELETE", "jev_deny", "/api/patients/PT-7004");
        let placed = [TraceValue {
            slot: Some(DELETE_SLOT.to_owned()),
            ..value("path[2]", false, seen_in_search())
        }];
        assert_eq!(
            shift_under(&current, &proposed, &attempt, &placed),
            Some(Shift::NewFastAllow)
        );
    }

    #[test]
    fn a_fast_allow_of_a_path_no_template_places_goes_back_to_jev_once_the_site_judges_public_access()
     {
        // Another position gets a public-access judgement, so the site judges public access. The
        // judge no longer fast-allows a path that no template can place (docs/07 section 7.4.7).
        let long = long_path();
        let current = patients("");
        let proposed = patients(&format!(",{OPEN_NOTE}"));
        let allowed = method_row("GET", "fast_allow", &long);
        let seen = [value("path[2]", true, seen_in_search())];
        assert_eq!(
            verdict_under(&current, &proposed, &allowed, &seen),
            Some(Verdict {
                shift: Shift::BackToJev,
                kinds: None,
            })
        );
        // A Jev call on it is unplaced where the site judges public access, so it stays a call.
        let called = method_row("GET", "jev_allow", &long);
        let unplaced = [TraceValue {
            unplaced: true,
            ..value("path[2]", false, seen_in_search())
        }];
        assert_eq!(shift_under(&current, &proposed, &called, &unplaced), None);
    }

    #[test]
    fn a_call_on_an_unplaced_path_becomes_a_fast_allow_once_the_site_stops_judging_public_access() {
        let long = long_path();
        let current = patients(&format!(",{OPEN_NOTE}"));
        let proposed = patients("");
        let called = method_row("GET", "jev_allow", &long);
        let unplaced = [TraceValue {
            unplaced: true,
            ..value("path[2]", false, seen_in_search())
        }];
        assert_eq!(
            shift_under(&current, &proposed, &called, &unplaced),
            Some(Shift::NewFastAllow)
        );
    }

    #[test]
    fn a_slug_id_is_grouped_under_the_declared_route_it_moves_under() {
        let current = patients("");
        let proposed = patients(&format!(",{CLOSED_DELETE}"));
        let moved = Moved::of(&current, &proposed);
        let values = [value("path[2]", true, seen_in_search())];
        let rows = [SlotRow {
            values: serde_json::to_string(&values).expect("the values serialize"),
            ..method_row("DELETE", "fast_allow", "/api/patients/PT-7004")
        }];
        let found = moves_of(
            &rows,
            &moved,
            &Reading::of(&current),
            &Reading::of(&proposed),
        );
        assert_eq!(found.back_to_jev.count, 1);
        assert_eq!(
            found.back_to_jev.routes.keys().collect::<Vec<_>>(),
            vec![&("DELETE".to_owned(), "/api/patients/{id}".to_owned())]
        );
    }

    #[test]
    fn a_trace_written_before_a_declaration_is_judged_by_the_placement_it_has_now() {
        // The declared id already governs the slug id, and the draft only adds an unrelated position.
        // A trace that names the slug id at its own spelling, as one written before the declaration
        // was judged does, keeps its verdict: the placement is the same under both configurations.
        let current = patients(&format!(",{OPEN_NOTE},{CLOSED_DELETE}"));
        let proposed = patients(&format!(",{OPEN_NOTE},{CLOSED_DELETE},{OTHER}"));
        let delete = method_row("DELETE", "fast_allow", "/api/patients/PT-7004");
        let seen = [value("path[2]", true, seen_in_search())];
        assert_eq!(shift_under(&current, &proposed, &delete, &seen), None);
    }

    #[test]
    fn a_declared_id_covers_a_position_and_its_template_is_the_route() {
        assert_eq!(
            covering_of(DELETE_SLOT),
            Some(("DELETE".to_owned(), "path[2]".to_owned()))
        );
        assert_eq!(covering_of(SEARCH_SLOT), None);
        assert_eq!(template_of(DELETE_SLOT), Some("/api/patients/{id}"));
    }

    /// The trace of one request value that the search showed, recorded at `slot`, as the decision
    /// log keeps it.
    fn logged_trace(value: &str, verified: bool, slot: &str) -> String {
        format!(
            r#"[{{"at":"path[2]","value":"{value}","kind":"reference","inert":false,"seen":true,"verified":{verified},"sources":[{{"field":"id","request":"GET /api/search","request_id":"req_search","at_millis":1,"slot":"{SEARCH_SLOT}"}}],"slot":"{slot}"}}]"#
        )
    }

    /// Writes `rows` (request id, decision, method, path and trace) into the database as the
    /// decisions of `site` on `day_start`, after clearing the site. Needs the migrations applied.
    async fn write_window(
        pool: &PgPool,
        site: &str,
        day_start: i64,
        rows: &[(&str, &str, &str, String, String)],
    ) {
        use crate::test_support::ensure_days;

        ensure_days(pool, &[day_start]).await;
        sqlx::query("DELETE FROM decision_log WHERE site = $1")
            .bind(site)
            .execute(pool)
            .await
            .expect("clear the test site");
        for (index, (request_id, decision, method, path, trace)) in rows.iter().enumerate() {
            let offset = i64::try_from(index).expect("a few rows");
            sqlx::query(
                "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client,
                    method, path, decision_path, outcome, trace)
                 VALUES ($1, $2, $3, 'edge-test', 'host', 'client', $4, $5, $6, 'allowed', $7::jsonb)",
            )
            .bind(day_start + 1_000 + offset)
            .bind(*request_id)
            .bind(site)
            .bind(*method)
            .bind(path.as_str())
            .bind(*decision)
            .bind(format!(r#"{{"values":{trace}}}"#))
            .execute(pool)
            .await
            .expect("insert a decision");
        }
    }

    /// The window of a declared closed id, run through the database, where the site already judges
    /// public access through another position: the slug id the declared id now governs is judged
    /// again, and the decisions the declaration does not govern are left alone. Needs the migrations
    /// applied to `XSHIELD_DATABASE_URL`.
    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_closed_declared_id_moves_the_window_slug_ids_it_governs() {
        const SITE: &str = "impact-declared-id";
        let url = std::env::var("XSHIELD_DATABASE_URL").expect("XSHIELD_DATABASE_URL");
        let pool = PgPool::connect(&url).await.expect("connect");
        let day_start = 4_102_531_200_000_i64;
        write_window(
            &pool,
            SITE,
            day_start,
            &[
                // The sighting proved this delete, recorded at the spelling of its path.
                (
                    "req_slug_back",
                    "fast_allow",
                    "DELETE",
                    "/api/patients/PT-7004".to_owned(),
                    logged_trace("PT-7004", true, "DELETE /api/patients/PT-7004 path[2]"),
                ),
                // The closed declared id refuses this slug id already, so the Jev call stays.
                (
                    "req_slug_jev",
                    "jev_deny",
                    "DELETE",
                    "/api/patients/PT-7005".to_owned(),
                    logged_trace("PT-7005", false, DELETE_SLOT),
                ),
                // A route the draft does not touch.
                (
                    "req_plain",
                    "fast_allow",
                    "GET",
                    "/api/records/3".to_owned(),
                    logged_trace("3", true, "GET /api/records/{id} path[2]"),
                ),
            ],
        )
        .await;
        // The site judges public access through the note already, so the draft does not change
        // that, and the window is read by the positions it names.
        let current = patients(&format!(",{OPEN_NOTE}"));
        let proposed = patients(&format!(",{OPEN_NOTE},{CLOSED_DELETE}"));
        let scope = Scope {
            site: Some(SITE.to_owned()),
            since_millis: day_start,
            until_millis: day_start + 86_400_000 - 1,
        };
        let (found, complete) = changes(&pool, &scope, &current, &proposed)
            .await
            .expect("the window reads");
        assert!(complete);
        let summary: Vec<(&str, i64, Option<&str>)> = found
            .iter()
            .map(|change| (change.kind.as_str(), change.count, change.sample.as_deref()))
            .collect();
        assert_eq!(summary, vec![(BACK_TO_JEV, 1, Some("req_slug_back"))]);
        assert_eq!(
            found[0].top,
            Some(vec![(
                "DELETE".to_owned(),
                "/api/patients/{id}".to_owned(),
                1
            )])
        );
    }

    /// The window of a draft that starts judging public access, run through the database. A slug
    /// id that the declared id now governs, and a path no template can place, are judged again; a
    /// Jev call that the closed declared id already refuses, and a route the draft does not touch,
    /// are left alone. Needs the migrations applied to `XSHIELD_DATABASE_URL`.
    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_draft_that_judges_public_access_moves_the_window_decisions_it_places_differently() {
        use crate::test_support::ensure_days;

        const SITE: &str = "impact-placement";
        let url = std::env::var("XSHIELD_DATABASE_URL").expect("XSHIELD_DATABASE_URL");
        let pool = PgPool::connect(&url).await.expect("connect");
        // A day of its own, the day after the others in 2100, that no other test writes to.
        let day_start = 4_102_531_200_000_i64;
        ensure_days(&pool, &[day_start]).await;
        sqlx::query("DELETE FROM decision_log WHERE site = $1")
            .bind(SITE)
            .execute(&pool)
            .await
            .expect("clear the test site");
        let long = long_path();
        let rows = [
            // The sighting proved this delete, which the trace recorded at the spelling of its path.
            (
                "req_slug_back",
                "fast_allow",
                "DELETE",
                "/api/patients/PT-7004".to_owned(),
                logged_trace("PT-7004", true, "DELETE /api/patients/PT-7004 path[2]"),
            ),
            // The same sighting proved a request on a path no template can place.
            (
                "req_long_back",
                "fast_allow",
                "GET",
                long.clone(),
                logged_trace("aaaaaaaa", true, &format!("GET {long} path[2]")),
            ),
            // The closed declared id refuses this slug id already, so the Jev call stays.
            (
                "req_slug_jev",
                "jev_deny",
                "DELETE",
                "/api/patients/PT-7005".to_owned(),
                logged_trace("PT-7005", false, DELETE_SLOT),
            ),
            // A route the draft does not touch.
            (
                "req_plain",
                "fast_allow",
                "GET",
                "/api/records/3".to_owned(),
                logged_trace("3", true, "GET /api/records/{id} path[2]"),
            ),
        ];
        for (index, (request_id, decision, method, path, trace)) in rows.into_iter().enumerate() {
            let offset = i64::try_from(index).expect("four rows");
            sqlx::query(
                "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client,
                    method, path, decision_path, outcome, trace)
                 VALUES ($1, $2, $3, 'edge-test', 'host', 'client', $4, $5, $6, 'allowed', $7::jsonb)",
            )
            .bind(day_start + 1_000 + offset)
            .bind(request_id)
            .bind(SITE)
            .bind(method)
            .bind(path)
            .bind(decision)
            .bind(format!(r#"{{"values":{trace}}}"#))
            .execute(&pool)
            .await
            .expect("insert a decision");
        }

        let current = patients("");
        let proposed = patients(&format!(",{CLOSED_DELETE}"));
        let scope = Scope {
            site: Some(SITE.to_owned()),
            since_millis: day_start,
            until_millis: day_start + 86_400_000 - 1,
        };
        let (found, complete) = changes(&pool, &scope, &current, &proposed)
            .await
            .expect("the window reads");
        assert!(complete);
        let summary: Vec<(&str, i64, Option<&str>)> = found
            .iter()
            .map(|change| (change.kind.as_str(), change.count, change.sample.as_deref()))
            .collect();
        assert_eq!(summary, vec![(BACK_TO_JEV, 2, Some("req_slug_back"))]);
        assert_eq!(
            found[0].top,
            Some(vec![
                ("DELETE".to_owned(), "/api/patients/{id}".to_owned(), 1),
                ("GET".to_owned(), long, 1),
            ])
        );
        assert_eq!(
            found[0].detail,
            Some(ChangeDetailBody::Approximate { approximate: true })
        );
    }

    /// The window of a draft run through the database: the decisions that name a moved
    /// position are judged again, and the rest are left alone. Needs the migrations applied
    /// to `XSHIELD_DATABASE_URL`.
    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_draft_moves_the_window_decisions_that_name_its_positions() {
        use crate::test_support::ensure_days;

        const SITE: &str = "impact-live";
        let url = std::env::var("XSHIELD_DATABASE_URL").expect("XSHIELD_DATABASE_URL");
        let pool = PgPool::connect(&url).await.expect("connect");
        // A day of its own, in 2100, that no other test writes to.
        let day_start = 4_102_444_800_000_i64;
        ensure_days(&pool, &[day_start]).await;
        sqlx::query("DELETE FROM decision_log WHERE site = $1")
            .bind(SITE)
            .execute(&pool)
            .await
            .expect("clear the test site");
        let rows = [
            // The position is a doctor's by the current map; the response showed a doctor.
            (
                "req_back",
                "fast_allow",
                "/doctor/7",
                r#"[{"at":"path[1]","value":"7","kind":"reference","inert":false,"seen":true,"verified":true,"sources":[{"field":"id","request":"GET /api/doctors","request_id":"req_o1","at_millis":1,"slot":"GET /api/doctors [].id"}],"slot":"GET /doctor/{id} path[1]"}]"#,
            ),
            // The draft gives the position a document, which the response showed.
            (
                "req_new",
                "jev_allow",
                "/doctors/7",
                r#"[{"at":"path[1]","value":"7","kind":"reference","inert":false,"seen":true,"verified":false,"sources":[{"field":"id","request":"GET /api/docs","request_id":"req_o2","at_millis":2,"slot":"GET /api/docs [].id"}],"slot":"GET /doctors/{id} path[1]"}]"#,
            ),
            // A route the draft does not touch.
            (
                "req_plain",
                "fast_allow",
                "/api/records/3",
                r#"[{"at":"path[1]","value":"3","kind":"reference","inert":false,"seen":true,"verified":true,"sources":[{"field":"id","request":"GET /api/docs","request_id":"req_o3","at_millis":3,"slot":"GET /api/docs [].id"}],"slot":"GET /api/records/{id} path[1]"}]"#,
            ),
            // Served from the allow cache: a draft cannot move that decision.
            (
                "req_cached",
                "cached_allow",
                "/doctor/8",
                r#"[{"at":"path[1]","value":"8","kind":"reference","inert":false,"seen":true,"verified":true,"sources":[{"field":"id","request":"GET /api/doctors","request_id":"req_o4","at_millis":4,"slot":"GET /api/doctors [].id"}],"slot":"GET /doctor/{id} path[1]"}]"#,
            ),
        ];
        for (index, (request_id, decision, path, trace)) in rows.into_iter().enumerate() {
            let offset = i64::try_from(index).expect("four rows");
            sqlx::query(
                "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client,
                    method, path, decision_path, outcome, trace)
                 VALUES ($1, $2, $3, 'edge-test', 'host', 'client', 'GET', $4, $5, 'allowed', $6::jsonb)",
            )
            .bind(day_start + 1_000 + offset)
            .bind(request_id)
            .bind(SITE)
            .bind(path)
            .bind(decision)
            .bind(format!(r#"{{"values":{trace}}}"#))
            .execute(&pool)
            .await
            .expect("insert a decision");
        }

        let current = spec(DOCS);
        let proposed = spec(
            r#"{"classes":[{"id":"document","name":"文档"},{"id":"doctor","name":"医生"}],"slots":[{"key":"GET /api/docs [].id","class":"document","source":"admin"},{"key":"GET /api/doctors [].id","class":"doctor","source":"admin"},{"key":"GET /doctor/{id} path[1]","class":"document","source":"admin"},{"key":"GET /doctors/{id} path[1]","class":"document","source":"admin"}]}"#,
        );
        let scope = Scope {
            site: Some(SITE.to_owned()),
            since_millis: day_start,
            until_millis: day_start + 86_400_000 - 1,
        };
        let (found, complete) = changes(&pool, &scope, &current, &proposed)
            .await
            .expect("the window reads");
        assert!(complete);
        let summary: Vec<(&str, i64, Option<&str>)> = found
            .iter()
            .map(|change| (change.kind.as_str(), change.count, change.sample.as_deref()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (NEW_FAST_ALLOW, 1, Some("req_new")),
                (BACK_TO_JEV, 1, Some("req_back")),
            ]
        );
        assert_eq!(
            found[0].top,
            Some(vec![("GET".to_owned(), "/doctors/{id}".to_owned(), 1)])
        );
        assert_eq!(
            found[1].top,
            Some(vec![("GET".to_owned(), "/doctor/{id}".to_owned(), 1)])
        );
        // The map gave the position a doctor and now gives a document: no name explains it.
        assert_eq!(
            found[1].detail,
            Some(ChangeDetailBody::Approximate { approximate: true })
        );
    }

    /// The window of a draft that changes a field declaration, run through the database: the
    /// query values that name the field are judged again. Needs the migrations applied to
    /// `XSHIELD_DATABASE_URL`.
    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_draft_moves_the_window_decisions_that_read_its_declared_field() {
        use crate::test_support::ensure_days;

        const SITE: &str = "impact-fields";
        let url = std::env::var("XSHIELD_DATABASE_URL").expect("XSHIELD_DATABASE_URL");
        let pool = PgPool::connect(&url).await.expect("connect");
        // A day of its own, the day after the position test's, that no other test writes to.
        let day_start = 4_102_531_200_000_i64;
        ensure_days(&pool, &[day_start]).await;
        sqlx::query("DELETE FROM decision_log WHERE site = $1")
            .bind(SITE)
            .execute(&pool)
            .await
            .expect("clear the test site");
        let rows = [
            // The current declaration makes `doc_id` a doctor's id, which the response showed
            // as a doctor: verified. The draft makes it a document's, so it is not any more.
            (
                "req_back",
                "fast_allow",
                "/api/appointments",
                r#"[{"at":"query","key":"doc_id","value":"5","kind":"reference","inert":false,"seen":true,"verified":true,"sources":[{"field":"id","request":"GET /api/doctors","request_id":"req_o1","at_millis":1,"slot":"GET /api/doctors [].id"}]}]"#,
            ),
            // The draft makes `doc_id` a document's id, which the response showed as a document.
            (
                "req_new",
                "jev_allow",
                "/api/appointments",
                r#"[{"at":"query","key":"doc_id","value":"5","kind":"reference","inert":false,"seen":true,"verified":false,"sources":[{"field":"id","request":"GET /api/docs","request_id":"req_o2","at_millis":2,"slot":"GET /api/docs [].id"}]}]"#,
            ),
            // A key the draft does not declare, which a jev_deny decided: left alone.
            (
                "req_plain",
                "jev_deny",
                "/api/records",
                r#"[{"at":"query","key":"page","value":"2","kind":"reference","inert":false,"seen":true,"verified":false,"sources":[{"field":"id","request":"GET /api/docs","request_id":"req_o3","at_millis":3,"slot":"GET /api/docs [].id"}]}]"#,
            ),
        ];
        for (index, (request_id, decision, path, trace)) in rows.into_iter().enumerate() {
            let offset = i64::try_from(index).expect("three rows");
            sqlx::query(
                "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client,
                    method, path, decision_path, outcome, trace)
                 VALUES ($1, $2, $3, 'edge-test', 'host', 'client', 'GET', $4, $5, 'allowed', $6::jsonb)",
            )
            .bind(day_start + 1_000 + offset)
            .bind(request_id)
            .bind(SITE)
            .bind(path)
            .bind(decision)
            .bind(format!(r#"{{"values":{trace}}}"#))
            .execute(&pool)
            .await
            .expect("insert a decision");
        }

        let current = spec_declaring(
            DOCS,
            r#"[{"field":"doc_id","kind":"doctor","in":["/api/appointments*"]}]"#,
        );
        let proposed = spec_declaring(
            DOCS,
            r#"[{"field":"doc_id","kind":"document","in":["/api/appointments*"]}]"#,
        );
        let scope = Scope {
            site: Some(SITE.to_owned()),
            since_millis: day_start,
            until_millis: day_start + 86_400_000 - 1,
        };
        let (found, complete) = changes(&pool, &scope, &current, &proposed)
            .await
            .expect("the window reads");
        assert!(complete);
        let summary: Vec<(&str, i64, Option<&str>)> = found
            .iter()
            .map(|change| (change.kind.as_str(), change.count, change.sample.as_deref()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (NEW_FAST_ALLOW, 1, Some("req_new")),
                (BACK_TO_JEV, 1, Some("req_back")),
            ]
        );
        assert_eq!(
            found[1].detail,
            Some(ChangeDetailBody::Kinds {
                approximate: true,
                name_kind: "doctor".to_owned(),
                object_kind: "document".to_owned(),
            })
        );
    }

    /// A draft that changes a field declaration, judged as the gateway judges it: the declaration
    /// is scoped to the logical path of an interface-named request (its physical path is
    /// `/api/rpc`), and one key spells the name with a doubled separator, which the judge reads
    /// as the same name. Needs the migrations applied to `XSHIELD_DATABASE_URL`.
    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_draft_reads_a_declaration_at_the_logical_path_and_every_spelling_of_its_name() {
        use crate::test_support::ensure_days;

        const SITE: &str = "impact-logical";
        let url = std::env::var("XSHIELD_DATABASE_URL").expect("XSHIELD_DATABASE_URL");
        let pool = PgPool::connect(&url).await.expect("connect");
        // A day of its own, the day after the field test's, that no other test writes to.
        let day_start = 4_102_617_600_000_i64;
        ensure_days(&pool, &[day_start]).await;
        sqlx::query("DELETE FROM decision_log WHERE site = $1")
            .bind(SITE)
            .execute(&pool)
            .await
            .expect("clear the test site");
        let traces = [
            (
                "req_key",
                r#"[{"at":"query","key":"doc_id","value":"5","kind":"reference","inert":false,"seen":true,"verified":true,"sources":[{"field":"id","request":"GET /api/doctors","request_id":"req_o1","at_millis":1,"slot":"GET /api/doctors [].id"}]}]"#,
            ),
            (
                "req_spelled",
                r#"[{"at":"query","key":"doc__id","value":"5","kind":"reference","inert":false,"seen":true,"verified":true,"sources":[{"field":"id","request":"GET /api/doctors","request_id":"req_o2","at_millis":2,"slot":"GET /api/doctors [].id"}]}]"#,
            ),
        ];
        for (index, (request_id, trace)) in traces.into_iter().enumerate() {
            let offset = i64::try_from(index).expect("two rows");
            sqlx::query(
                "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client,
                    method, path, logical_path, decision_path, outcome, trace)
                 VALUES ($1, $2, $3, 'edge-test', 'host', 'client', 'GET', '/api/rpc',
                    '/api/rpc/getDoctor', 'fast_allow', 'allowed', $4::jsonb)",
            )
            .bind(day_start + 1_000 + offset)
            .bind(request_id)
            .bind(SITE)
            .bind(format!(r#"{{"values":{trace}}}"#))
            .execute(&pool)
            .await
            .expect("insert a decision");
        }

        let current = spec_declaring(
            DOCS,
            r#"[{"field":"doc_id","kind":"doctor","in":["/api/rpc/getDoctor*"]}]"#,
        );
        let proposed = spec_declaring(
            DOCS,
            r#"[{"field":"doc_id","kind":"document","in":["/api/rpc/getDoctor*"]}]"#,
        );
        let scope = Scope {
            site: Some(SITE.to_owned()),
            since_millis: day_start,
            until_millis: day_start + 86_400_000 - 1,
        };
        let (found, complete) = changes(&pool, &scope, &current, &proposed)
            .await
            .expect("the window reads");
        assert!(complete);
        // Both values stop verifying under the document declaration. The declaration applies at
        // the logical path only, so reading the physical path would miss its kinds.
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind.as_str(), BACK_TO_JEV);
        assert_eq!(found[0].count, 2);
        assert_eq!(
            found[0].top,
            Some(vec![("GET".to_owned(), "/api/rpc/getDoctor".to_owned(), 2)])
        );
        assert_eq!(
            found[0].detail,
            Some(ChangeDetailBody::Kinds {
                approximate: true,
                name_kind: "doctor".to_owned(),
                object_kind: "document".to_owned(),
            })
        );
    }
}
