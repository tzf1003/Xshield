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
    context::{SiteSpec, TraceValue},
    kind::{
        LONG_VALUE_CHARS, Rules, Shown, Used, declaration_reads, declared_kind_of, name_kind_of,
        path_segment, shown_as,
    },
    path_template::normalize,
};
use xshield_postgres::decision_stats::{self, Scope, SlotRow};

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
    let slots: Vec<String> = moved.slots.iter().cloned().collect();
    let (rows, complete) = decision_stats::window_rows(pool, scope, &slots, &moved.fields).await?;
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

/// What a draft moves: the positions whose kind or pause changes, and the field names whose
/// `advanced.field_kinds` declarations differ.
#[derive(Debug, Default, PartialEq, Eq)]
struct Moved {
    /// The request and response positions the judge reads a different kind for.
    slots: BTreeSet<String>,
    /// The field names of the declarations the draft adds, removes or changes.
    fields: Vec<String>,
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
        }
    }

    fn is_empty(&self) -> bool {
        self.slots.is_empty() && self.fields.is_empty()
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

/// The request positions the judge reads a different kind for under the two configurations:
/// the positions a draft adds, removes or gives another kind. A paused entry gives no kind,
/// so pausing one counts as a change too.
fn moved_positions(current: &SiteSpec, proposed: &SiteSpec) -> BTreeSet<String> {
    let keys: BTreeSet<&str> = current
        .objects()
        .slots()
        .iter()
        .chain(proposed.objects().slots())
        .map(|slot| slot.key.as_str())
        .collect();
    keys.into_iter()
        .filter(|key| current.objects().class_of(key) != proposed.objects().class_of(key))
        .map(str::to_owned)
        .collect()
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

    /// Whether a request value is verified at position `slot`: one place that showed the
    /// value to the session shows it as the kind the request needs, judged as the gateway
    /// judges it. The rule reads the value's key, its location and its length, not its text.
    fn verifies(&self, row: &SlotRow, value: &TraceValue, slot: &str) -> bool {
        let objects = self.spec.objects();
        let wanted = objects.class_of(slot);
        let used = used_of(row, value);
        let long = value.len.unwrap_or_else(|| value.value.chars().count()) >= LONG_VALUE_CHARS;
        value.sources.iter().any(|source| {
            let shown = Shown {
                field: &source.field,
                request: &source.request,
            };
            let known = source.slot.as_deref().and_then(|at| objects.class_of(at));
            shown_as(used, shown, wanted, known, &self.rules, long)
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
/// (see [`Moved::touches`]); every other value keeps the verdict the trace recorded. A value
/// whose trace kept no place for it keeps its recorded verdict too.
fn shift(
    row: &SlotRow,
    values: &[TraceValue],
    moved: &Moved,
    current: &Reading<'_>,
    next: &Reading<'_>,
) -> Option<Verdict> {
    let mut verified_now = true;
    let mut verified_next = true;
    // The first value that verifies now and stops verifying under the draft, with its position.
    let mut lost: Option<(&TraceValue, String)> = None;
    for value in values.iter().filter(|value| !value.inert) {
        let slot = request_slot(row, value);
        verified_now &= value.verified;
        let verified = if moved.touches(value, &slot) && !value.sources.is_empty() {
            next.verifies(row, value, &slot)
        } else {
            value.verified
        };
        if value.verified && !verified && lost.is_none() {
            lost = Some((value, slot));
        }
        verified_next &= verified;
    }
    match row.decision_path.as_str() {
        FAST_ALLOW if verified_now && !verified_next => Some(Verdict {
            shift: Shift::BackToJev,
            kinds: lost.and_then(|(value, slot)| kinds_of(row, value, &slot, current, next)),
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

/// The position of a request value: the trace's own, or the one the gateway gives it.
fn request_slot(row: &SlotRow, value: &TraceValue) -> String {
    value
        .slot
        .clone()
        .unwrap_or_else(|| format!("{} {} {}", row.method, route_of(&row.path), value.at))
}

/// The route template of a path, as positions name it.
fn route_of(path: &str) -> String {
    normalize(path).unwrap_or_else(|| path.to_owned())
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
        match shift(row, &values, moved, current, next) {
            Some(Verdict {
                shift: Shift::NewFastAllow,
                ..
            }) => found.new_fast_allow.add(row, None),
            Some(Verdict {
                shift: Shift::BackToJev,
                kinds,
            }) => found.back_to_jev.add(row, kinds),
            None => {}
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
    fn add(&mut self, row: &SlotRow, kinds: Option<(String, String)>) {
        self.count += 1;
        let (requests, _) = self
            .routes
            .entry((row.method.clone(), route_of(&row.path)))
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
        SlotRow {
            request_id: "req_1".to_owned(),
            method: "GET".to_owned(),
            path: path.to_owned(),
            decision_path: decision.to_owned(),
            values: String::new(),
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
        groups.add(&first, None);
        let mut big = row("fast_allow", "/api/records/3");
        big.request_id = "req_big".to_owned();
        for _ in 0..3 {
            groups.add(&big, None);
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
        groups.add(&a, pair("doctor", "document"));
        groups.add(&b, pair("doctor", "document"));
        groups.add(&c, pair("doc", "doctor"));
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
