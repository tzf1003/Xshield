//! Impact preview of a proposed site configuration (docs/07 section 7.9.10).
//!
//! The last 24 hours of the site's decisions are grouped by method, path,
//! session presence, decision path and outcome. Each group is routed again under
//! the current and the proposed configuration, and what moves is counted. Nothing
//! is written. The warnings name what history cannot estimate.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use xshield_core::context::{Mode, SiteSpec};
use xshield_postgres::{
    decision_stats::{self, Breakdown, PathGroup, Scope},
    site_spec_store,
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    insights::{
        ADDRESS_CONTEXT, BLOCKED, CACHED_ALLOW, Effective, JEV_CALL_LIMIT, SESSION_CONTEXT,
        WOULD_BLOCK, redacts, refused_count, scan_states, site_not_found, sum_rows,
    },
    params::{DAY_MILLIS, json_body, now_millis},
};

const WINDOW_HOURS: i64 = 24;
/// Most paths listed under one change.
const TOP_PATHS: usize = 5;
/// Most field locations listed under the secret field change.
const TOP_FIELDS: usize = 10;

const NO_SESSION_TO_ENTRY: &str = "no_session_to_entry";
const ENTRY_TO_NO_SESSION: &str = "entry_to_no_session";
const JUDGED_TO_BYPASS: &str = "judged_to_bypass";
const BYPASS_TO_JUDGED: &str = "bypass_to_judged";
const WOULD_BLOCK_TO_BLOCKED: &str = "would_block_to_blocked";
const BLOCKED_TO_WOULD_BLOCK: &str = "blocked_to_would_block";
const SESSION_CHANGED: &str = "SESSION_CHANGED";
const HOSTS_CHANGED: &str = "HOSTS_CHANGED";
const SYNONYMS_CHANGED: &str = "SYNONYMS_CHANGED";
const CACHE_RAISED: &str = "CACHE_RAISED";

/// The route a request takes under one configuration, in the gateway's order:
/// bypass first, then the entry rule for requests without a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// Forwarded without judgement.
    Bypass,
    /// Refused: no session and not an entry.
    NoSession,
    /// Judged with the address context: no session, but an entry.
    Entry,
    /// Judged with the session context.
    Judged,
}

fn route(spec: &SiteSpec, path: &str, has_session: bool) -> Route {
    if spec.is_bypass(path) {
        Route::Bypass
    } else if has_session {
        Route::Judged
    } else if spec.is_entry(path) {
        Route::Entry
    } else {
        Route::NoSession
    }
}

/// The change kind of a route that moves; `None` when it stays where it was.
/// A bypass counts as the boundary of judging: a request that starts or stops
/// being bypassed is `judged_to_bypass` or `bypass_to_judged`.
fn route_change(before: Route, after: Route) -> Option<&'static str> {
    if before == after {
        return None;
    }
    match (before, after) {
        (Route::NoSession, Route::Entry) => Some(NO_SESSION_TO_ENTRY),
        (Route::Entry, Route::NoSession) => Some(ENTRY_TO_NO_SESSION),
        (Route::Bypass, _) => Some(BYPASS_TO_JUDGED),
        (_, Route::Bypass) => Some(JUDGED_TO_BYPASS),
        _ => None,
    }
}

/// The kind a mode switch moves, and the outcome of the rows it moves.
fn mode_change(before: Mode, after: Mode) -> Option<(&'static str, &'static str)> {
    match (before, after) {
        (Mode::Observe, Mode::Enforce) => Some((WOULD_BLOCK_TO_BLOCKED, WOULD_BLOCK)),
        (Mode::Enforce, Mode::Observe) => Some((BLOCKED_TO_WOULD_BLOCK, BLOCKED)),
        _ => None,
    }
}

/// The requests of one change kind: how many, how many observe mode would have
/// refused, the method and path pairs they touch, and an example from the
/// largest group.
#[derive(Default)]
struct Tally {
    count: i64,
    would_block: i64,
    paths: BTreeMap<(String, String), i64>,
    sample: Option<(i64, String)>,
}

impl Tally {
    fn add(&mut self, group: &PathGroup) {
        self.count += group.count;
        if group.outcome == WOULD_BLOCK {
            self.would_block += group.count;
        }
        *self
            .paths
            .entry((group.method.clone(), group.path.clone()))
            .or_insert(0) += group.count;
        if self
            .sample
            .as_ref()
            .is_none_or(|(best, _)| group.count > *best)
        {
            self.sample = Some((group.count, group.sample.clone()));
        }
    }

    fn to_json(&self, kind: &str, count: i64) -> Value {
        let mut paths: Vec<(&(String, String), i64)> =
            self.paths.iter().map(|(key, n)| (key, *n)).collect();
        paths.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        let top: Vec<Value> = paths
            .into_iter()
            .take(TOP_PATHS)
            .map(|((method, path), n)| json!([method, path, n]))
            .collect();
        let mut change = json!({ "kind": kind, "count": count, "top": top });
        if self.would_block > 0 {
            change["would_block"] = json!(self.would_block);
        }
        if let Some((_, sample)) = &self.sample {
            change["sample"] = json!(sample);
        }
        change
    }
}

/// The route and mode changes of every path group, and the paths they move.
#[derive(Default)]
struct PathChanges {
    changed: BTreeMap<&'static str, Tally>,
    /// Paths that would become entries, with their requests.
    entries: BTreeMap<String, i64>,
    /// Bypass patterns the proposed configuration adds, with their requests.
    bypass: BTreeMap<String, i64>,
}

/// Routes every group under both configurations and counts what moves. A group
/// whose route moves is counted once, under its route change; a mode switch
/// counts the groups whose route stays and that are not bypassed afterwards.
fn path_changes(current: &SiteSpec, proposed: &SiteSpec, groups: &[PathGroup]) -> PathChanges {
    let mut changes = PathChanges::default();
    let mode = mode_change(current.mode(), proposed.mode());
    for group in groups {
        let before = route(current, &group.path, group.has_session);
        let after = route(proposed, &group.path, group.has_session);
        if let Some(kind) = route_change(before, after) {
            changes.changed.entry(kind).or_default().add(group);
            if kind == NO_SESSION_TO_ENTRY {
                *changes.entries.entry(group.path.clone()).or_insert(0) += group.count;
            }
            if kind == JUDGED_TO_BYPASS
                && let Some(pattern) = proposed.matching_bypass(&group.path)
            {
                *changes.bypass.entry(pattern.to_owned()).or_insert(0) += group.count;
            }
        } else if let Some((kind, outcome)) = mode
            && after != Route::Bypass
            && group.outcome == outcome
        {
            changes.changed.entry(kind).or_default().add(group);
        }
    }
    changes
}

/// A change that counts requests, or `None` when nothing is affected.
fn plain_change(kind: &str, count: i64, detail: Value) -> Option<Value> {
    if count <= 0 {
        return None;
    }
    let mut change = json!({ "kind": kind, "count": count });
    change["detail"] = detail;
    Some(change)
}

/// The Jev timeout change: calls a shorter timeout would cut off, or timeouts a
/// longer one may let through.
async fn timeout_change(
    pool: &PgPool,
    scope: &Scope,
    old: u32,
    new: u32,
) -> ApiResult<Option<Value>> {
    if old == new {
        return Ok(None);
    }
    let count =
        decision_stats::jev_timeout_impact(pool, scope, i64::from(old), i64::from(new)).await?;
    Ok(plain_change(
        "jev_timeout",
        count,
        json!({ "old_ms": old, "new_ms": new }),
    ))
}

/// The per-minute limit changes, per scope. A lower limit counts the calls it
/// would refuse and the sessions or addresses they belong to. A higher limit
/// counts the refused calls it may let through, an upper bound.
async fn call_limit_changes(
    pool: &PgPool,
    scope: &Scope,
    rows: &[Breakdown],
    current: Effective,
    proposed: Effective,
) -> ApiResult<Vec<Value>> {
    let limits = [
        (
            "session",
            false,
            SESSION_CONTEXT,
            current.session_calls,
            proposed.session_calls,
        ),
        (
            "address",
            true,
            ADDRESS_CONTEXT,
            current.address_calls,
            proposed.address_calls,
        ),
    ];
    let mut changes = Vec::new();
    for (name, by_address, context, old, new) in limits {
        if old == new {
            continue;
        }
        let (count, detail) = if new < old {
            let peaks =
                decision_stats::minute_peaks(pool, scope, by_address, i64::from(new)).await?;
            (
                peaks.excess,
                json!({ "scope": name, "old": old, "new": new, "keys": peaks.keys_over }),
            )
        } else {
            let refused = refused_count(rows, context, JEV_CALL_LIMIT);
            (
                refused,
                json!({ "scope": name, "old": old, "new": new, "upper_bound": true }),
            )
        };
        changes.extend(plain_change("call_limit", count, detail));
    }
    Ok(changes)
}

/// The cache change: turning the allow cache off makes every cached allow a Jev
/// call. Raising the cache cannot be estimated from history; it is a warning.
fn cache_change(
    rows: &[Breakdown],
    groups: &[PathGroup],
    current: Effective,
    proposed: Effective,
) -> Option<Value> {
    if proposed.cache_minutes != 0 || current.cache_minutes == 0 {
        return None;
    }
    let count = sum_rows(rows, |row| row.decision_path == CACHED_ALLOW);
    let mut tally = Tally::default();
    for group in groups
        .iter()
        .filter(|group| group.decision_path == CACHED_ALLOW)
    {
        tally.add(group);
    }
    (count > 0).then(|| tally.to_json("cache", count))
}

/// The secret field change: Jev calls whose state holds a value that a newly
/// added word would now redact.
async fn secret_change(
    pool: &PgPool,
    scope: &Scope,
    current: &SiteSpec,
    proposed: &SiteSpec,
) -> ApiResult<Option<Value>> {
    let added: Vec<String> = proposed
        .advanced()
        .secret_fields()
        .iter()
        .map(|word| word.to_ascii_lowercase())
        .filter(|word| !redacts(current, word))
        .collect();
    if added.is_empty() {
        return Ok(None);
    }
    let words: Vec<&str> = added.iter().map(String::as_str).collect();
    let states = decision_stats::jev_state_rows(pool, scope).await?;
    let scan = scan_states(&states, &words);
    let detail = json!({ "values": scan.values, "fields": top_fields(&scan.fields) });
    Ok(plain_change("secret_fields", scan.calls, detail))
}

/// The field locations affected most, with their counts, most first.
fn top_fields(fields: &BTreeMap<String, i64>) -> Value {
    let mut ranked: Vec<(&String, i64)> = fields.iter().map(|(name, n)| (name, *n)).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    Value::Array(
        ranked
            .into_iter()
            .take(TOP_FIELDS)
            .map(|(name, n)| json!([name, n]))
            .collect(),
    )
}

fn hosts_of(spec: &SiteSpec) -> BTreeSet<&str> {
    spec.hosts().iter().map(String::as_str).collect()
}

fn synonyms_of(spec: &SiteSpec) -> BTreeSet<&(String, String)> {
    spec.advanced().synonyms().iter().collect()
}

/// The warnings for what history cannot estimate: a new session credential, new
/// hosts, changed synonyms, or a longer allow cache.
fn warning_codes(current: &SiteSpec, proposed: &SiteSpec) -> Vec<&'static str> {
    let mut codes = Vec::new();
    if current.session() != proposed.session() {
        codes.push(SESSION_CHANGED);
    }
    if hosts_of(current) != hosts_of(proposed) {
        codes.push(HOSTS_CHANGED);
    }
    if synonyms_of(current) != synonyms_of(proposed) {
        codes.push(SYNONYMS_CHANGED);
    }
    if Effective::of(proposed).cache_minutes > Effective::of(current).cache_minutes {
        codes.push(CACHE_RAISED);
    }
    codes
}

/// The `spec` of a preview body, validated.
///
/// # Errors
/// `INVALID_BODY` when there is no `spec`; the `SITE_CONFIG_*` code when it is invalid.
fn spec_from_body(body: &Value) -> ApiResult<SiteSpec> {
    let spec = body
        .get("spec")
        .ok_or_else(|| ApiError::invalid_body("spec"))?;
    SiteSpec::from_value(spec).map_err(ApiError::from)
}

/// Previews a proposed configuration against the site's last 24 hours of
/// decisions (docs/07 section 7.9.10). Nothing is written.
///
/// # Errors
/// `INVALID_BODY` or `SITE_CONFIG_*` for a body that is not a valid spec,
/// `SITE_NAME_MISMATCH` when the spec's name differs from the path, `SITE_NOT_FOUND`
/// for an unknown site, and a 500 when a query fails.
pub async fn preview(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let body: Value = json_body(&headers, &body)?;
    let proposed = spec_from_body(&body)?;
    if proposed.name() != name {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "SITE_NAME_MISMATCH"));
    }
    let record = site_spec_store::get(&state.pool, &name)
        .await?
        .ok_or_else(site_not_found)?;
    let now = now_millis();
    let scope = Scope {
        site: Some(name),
        since_millis: now - DAY_MILLIS,
        until_millis: now,
    };
    let (groups, complete) = decision_stats::path_groups(&state.pool, &scope).await?;
    let rows = decision_stats::breakdown(&state.pool, &scope).await?;
    let paths = path_changes(&record.spec, &proposed, &groups);
    let current = Effective::of(&record.spec);
    let next = Effective::of(&proposed);

    let mut changes: Vec<Value> = Vec::new();
    for kind in [
        NO_SESSION_TO_ENTRY,
        ENTRY_TO_NO_SESSION,
        JUDGED_TO_BYPASS,
        BYPASS_TO_JUDGED,
        WOULD_BLOCK_TO_BLOCKED,
        BLOCKED_TO_WOULD_BLOCK,
    ] {
        if let Some(tally) = paths.changed.get(kind) {
            changes.push(tally.to_json(kind, tally.count));
        }
    }
    changes.extend(
        timeout_change(
            &state.pool,
            &scope,
            current.jev_timeout_ms,
            next.jev_timeout_ms,
        )
        .await?,
    );
    changes.extend(call_limit_changes(&state.pool, &scope, &rows, current, next).await?);
    changes.extend(cache_change(&rows, &groups, current, next));
    changes.extend(secret_change(&state.pool, &scope, &record.spec, &proposed).await?);

    let total: i64 = groups.iter().map(|group| group.count).sum();
    Ok(Json(json!({
        "window_hours": WINDOW_HOURS,
        "rows": total,
        "groups": groups.len(),
        "complete": complete,
        "changes": changes,
        "patterns": { "entries": paths.entries, "bypass": paths.bypass },
        "warnings": warning_codes(&record.spec, &proposed),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(entries: &str) -> SiteSpec {
        let text = format!(
            r#"{{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{{"cookie":"SID"}},"entries":{entries},"bypass":["/assets/*"]}}"#
        );
        SiteSpec::from_json(&text).expect("valid test site")
    }

    fn group(
        path: &str,
        has_session: bool,
        decision: &str,
        outcome: &str,
        count: i64,
    ) -> PathGroup {
        PathGroup {
            method: "GET".to_owned(),
            path: path.to_owned(),
            has_session,
            decision_path: decision.to_owned(),
            outcome: outcome.to_owned(),
            count,
            sample: format!("req_{count}"),
        }
    }

    #[test]
    fn routes_follow_the_gateway_order() {
        let spec = site(r#"["/login"]"#);
        assert_eq!(route(&spec, "/assets/app.js", false), Route::Bypass);
        assert_eq!(route(&spec, "/assets/app.js", true), Route::Bypass);
        assert_eq!(route(&spec, "/login", false), Route::Entry);
        assert_eq!(route(&spec, "/api/records", false), Route::NoSession);
        assert_eq!(route(&spec, "/api/records", true), Route::Judged);
    }

    #[test]
    fn route_moves_are_named_by_kind() {
        assert_eq!(
            route_change(Route::NoSession, Route::Entry),
            Some(NO_SESSION_TO_ENTRY)
        );
        assert_eq!(
            route_change(Route::Entry, Route::NoSession),
            Some(ENTRY_TO_NO_SESSION)
        );
        assert_eq!(
            route_change(Route::Judged, Route::Bypass),
            Some(JUDGED_TO_BYPASS)
        );
        assert_eq!(
            route_change(Route::Bypass, Route::Judged),
            Some(BYPASS_TO_JUDGED)
        );
        assert_eq!(route_change(Route::Judged, Route::Judged), None);
    }

    #[test]
    fn an_added_entry_moves_refused_requests_and_names_the_path() {
        let current = site(r#"["/login"]"#);
        let proposed = site(r#"["/login","/api/records"]"#);
        let groups = [group("/api/records", false, "no_session", "blocked", 3)];
        let changes = path_changes(&current, &proposed, &groups);
        assert_eq!(
            changes
                .changed
                .get(NO_SESSION_TO_ENTRY)
                .map(|tally| tally.count),
            Some(3)
        );
        assert_eq!(changes.entries.get("/api/records"), Some(&3));
        assert!(changes.bypass.is_empty());
    }

    #[test]
    fn tallies_rank_paths_and_sample_the_largest_group() {
        let mut tally = Tally::default();
        tally.add(&group("/a", true, "jev_allow", "allowed", 2));
        tally.add(&group("/b", true, "jev_deny", "would_block", 5));
        tally.add(&group("/a", true, "jev_allow", "allowed", 4));
        let change = tally.to_json("judged_to_bypass", tally.count);
        assert_eq!(change["top"][0], json!(["GET", "/a", 6]));
        assert_eq!(change["top"][1], json!(["GET", "/b", 5]));
        assert_eq!(change["would_block"], 5);
        assert_eq!(change["sample"], "req_5");
    }

    #[test]
    fn mode_switches_move_the_matching_outcome() {
        assert_eq!(
            mode_change(Mode::Observe, Mode::Enforce),
            Some((WOULD_BLOCK_TO_BLOCKED, WOULD_BLOCK))
        );
        assert_eq!(mode_change(Mode::Enforce, Mode::Enforce), None);
    }
}
