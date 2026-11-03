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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use xshield_core::context::{Mode, Route as RouteRule, SiteSpec};
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
    object_impact,
    params::{DAY_MILLIS, json_body, now_millis},
};

const WINDOW_HOURS: i64 = 24;
/// Most paths listed under one change.
pub(crate) const TOP_PATHS: usize = 5;
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
const INTERFACE_UNVERIFIED: &str = "INTERFACE_UNVERIFIED";
const API_SPLIT: &str = "api_split";
const ENTRY_UNREACHABLE: &str = "entry_unreachable";
const CACHE_BY_API: &str = "cache_by_api";
/// Stands in for the interface name of a request. The history does not hold the
/// name, and a route name is never `~`, so no pattern matches it by accident.
const NAME_PLACEHOLDER: &str = "~";

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

/// The route that names the interface of `path`: the one whose pattern covers the path,
/// or whose exact path the path lies under. Routes do not overlap, so there is at most
/// one.
fn covering_route<'a>(spec: &'a SiteSpec, path: &str) -> Option<&'a RouteRule> {
    spec.routes()
        .iter()
        .find(|route| route.path().matches(path) || covers_subpath(route, path))
}

/// Whether `path` lies under the exact path of `route`. The gateway cannot name the
/// interface of such a request, so it is unknown.
fn covers_subpath(route: &RouteRule, path: &str) -> bool {
    let pattern = route.path();
    let stem = pattern.stem();
    !pattern.is_prefix()
        && path.len() > stem.len()
        && path.starts_with(stem)
        && path.as_bytes().get(stem.len()) == Some(&b'/')
}

/// The path a group's requests are judged by under `spec`, as the gateway matches it.
/// A path a route names gets an interface name the history does not hold, so the
/// placeholder stands in for it: an exact entry or bypass pattern stops matching it,
/// a prefix pattern still does. `None` when the interface is unknown, which is never an
/// entry and never bypassed.
fn judged_path(spec: &SiteSpec, path: &str) -> Option<String> {
    match covering_route(spec, path) {
        None => Some(path.to_owned()),
        Some(route) if route.path().matches(path) => Some(format!("{path}/{NAME_PLACEHOLDER}")),
        Some(_) => None,
    }
}

/// The route a group takes under `spec`, judged by its logical path.
fn logical_route(spec: &SiteSpec, path: &str, has_session: bool) -> Route {
    match judged_path(spec, path) {
        Some(logical) => route(spec, &logical, has_session),
        None if has_session => Route::Judged,
        None => Route::NoSession,
    }
}

/// Whether the proposed routes name the interface of `path` differently from the
/// current ones: a route is new, or its name sources differ.
fn naming_changed(current: &SiteSpec, proposed: &SiteSpec, path: &str) -> bool {
    let next = covering_route(proposed, path);
    next.is_some() && next != covering_route(current, path)
}

/// Whether a change kind is an estimate: its requests are counted under the placeholder
/// name, since the history holds no interface names.
#[must_use]
fn is_estimate(kind: &str) -> bool {
    matches!(kind, API_SPLIT | ENTRY_UNREACHABLE | CACHE_BY_API)
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

/// `POST /api/sites/{name}/preview` (docs/07 section 7.9.10): what a proposed
/// configuration would change over the last 24 hours. Nothing is written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreviewBody {
    pub window_hours: i64,
    /// Requests in the window.
    pub rows: i64,
    /// Path groups the requests fell into.
    pub groups: usize,
    /// False when the window was not read in full.
    pub complete: bool,
    pub changes: Vec<ChangeBody>,
    pub patterns: PatternsBody,
    /// Codes for what the history cannot estimate.
    pub warnings: Vec<String>,
}

/// One change the proposed configuration would make. Route and cache changes name the
/// requests they touch in `top`; setting changes say what moves in `detail`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeBody {
    pub kind: String,
    /// Requests the change affects.
    pub count: i64,
    /// The busiest method and path pairs, most requests first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top: Option<Vec<PathCount>>,
    /// Requests observe mode would have refused, when some were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub would_block: Option<i64>,
    /// A request id from the largest group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<ChangeDetailBody>,
}

/// A method, a path and the requests they account for: `[method, path, requests]`.
pub type PathCount = (String, String, i64);

/// What a setting change moves. Each shape has its own fields, so the variants are
/// told apart by them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChangeDetailBody {
    /// A Jev timeout, in milliseconds, before and after.
    Timeout { old_ms: u32, new_ms: u32 },
    /// A per-minute limit that tightens, and how many keys would go over it.
    CallLimit {
        scope: String,
        old: u32,
        new: u32,
        keys: i64,
    },
    /// A per-minute limit that loosens, and the refused calls it may let through.
    CallLimitBound {
        scope: String,
        old: u32,
        new: u32,
        upper_bound: bool,
    },
    /// Unredacted values that a new secret field would hide, and the field locations
    /// holding them most, as `[field, values]` pairs.
    Secret {
        values: i64,
        fields: Vec<(String, i64)>,
    },
    /// A fast allow that calls Jev again, and the kinds that explain it: the kind the name of
    /// its request value gives (`name_kind`), and the kind the object map or a field
    /// declaration gives it (`object_kind`). Estimated, like `Approximate`.
    Kinds {
        approximate: bool,
        name_kind: String,
        object_kind: String,
    },
    /// A count the history cannot settle, because it names requests by an interface the
    /// history does not hold: `api_split`, `entry_unreachable` and `cache_by_api`, and the
    /// estimated fast allows of `new_fast_allow` and `back_to_jev`.
    Approximate { approximate: bool },
}

/// The entries and bypass patterns the proposed configuration adds, with the requests
/// each one matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternsBody {
    pub entries: BTreeMap<String, i64>,
    pub bypass: BTreeMap<String, i64>,
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

    fn change(&self, kind: &str, count: i64) -> ChangeBody {
        let mut paths: Vec<(&(String, String), i64)> =
            self.paths.iter().map(|(key, n)| (key, *n)).collect();
        paths.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        let top = paths
            .into_iter()
            .take(TOP_PATHS)
            .map(|((method, path), n)| (method.clone(), path.clone(), n))
            .collect();
        ChangeBody {
            kind: kind.to_owned(),
            count,
            top: Some(top),
            would_block: (self.would_block > 0).then_some(self.would_block),
            sample: self.sample.as_ref().map(|(_, sample)| sample.clone()),
            detail: is_estimate(kind)
                .then_some(ChangeDetailBody::Approximate { approximate: true }),
        }
    }
}

/// The route and mode changes of every path group, the paths they move, and the
/// requests that a proposed route starts to name by interface.
#[derive(Default)]
struct PathChanges {
    changed: BTreeMap<&'static str, Tally>,
    /// Paths that would become entries, with their requests.
    entries: BTreeMap<String, i64>,
    /// Bypass patterns the proposed configuration adds, with their requests.
    bypass: BTreeMap<String, i64>,
    /// Requests on paths that a proposed route newly names by interface.
    split: Tally,
    /// Cached allows on such paths: their cache key gains the interface name.
    cached_split: Tally,
}

/// Routes every group under both configurations, judged by its logical path, and counts
/// what moves. A group whose route moves is counted once, under its route change; a
/// mode switch counts the groups whose route stays and that are not bypassed
/// afterwards. A group on a path that a proposed route newly names is also counted
/// under `api_split`, and a cached one under `cache_by_api`.
fn path_changes(current: &SiteSpec, proposed: &SiteSpec, groups: &[PathGroup]) -> PathChanges {
    let mut changes = PathChanges::default();
    let mode = mode_change(current.mode(), proposed.mode());
    let cache_on = Effective::of(proposed).cache_minutes > 0;
    for group in groups {
        let split = naming_changed(current, proposed, &group.path);
        if split {
            changes.split.add(group);
            if cache_on && group.decision_path == CACHED_ALLOW {
                changes.cached_split.add(group);
            }
        }
        let before = logical_route(current, &group.path, group.has_session);
        let after = logical_route(proposed, &group.path, group.has_session);
        if let Some(kind) = route_change(before, after) {
            // The entry is still registered at this path, so the interface name is
            // what made its requests miss it.
            let kind = if split && kind == ENTRY_TO_NO_SESSION && proposed.is_entry(&group.path) {
                ENTRY_UNREACHABLE
            } else {
                kind
            };
            changes.changed.entry(kind).or_default().add(group);
            if kind == NO_SESSION_TO_ENTRY && !split {
                *changes.entries.entry(group.path.clone()).or_insert(0) += group.count;
            }
            if kind == JUDGED_TO_BYPASS
                && let Some(logical) = judged_path(proposed, &group.path)
                && let Some(pattern) = proposed.matching_bypass(&logical)
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
fn plain_change(kind: &str, count: i64, detail: ChangeDetailBody) -> Option<ChangeBody> {
    if count <= 0 {
        return None;
    }
    Some(ChangeBody {
        kind: kind.to_owned(),
        count,
        top: None,
        would_block: None,
        sample: None,
        detail: Some(detail),
    })
}

/// The Jev timeout change: calls a shorter timeout would cut off, or timeouts a
/// longer one may let through.
async fn timeout_change(
    pool: &PgPool,
    scope: &Scope,
    old: u32,
    new: u32,
) -> ApiResult<Option<ChangeBody>> {
    if old == new {
        return Ok(None);
    }
    let count =
        decision_stats::jev_timeout_impact(pool, scope, i64::from(old), i64::from(new)).await?;
    Ok(plain_change(
        "jev_timeout",
        count,
        ChangeDetailBody::Timeout {
            old_ms: old,
            new_ms: new,
        },
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
) -> ApiResult<Vec<ChangeBody>> {
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
                ChangeDetailBody::CallLimit {
                    scope: name.to_owned(),
                    old,
                    new,
                    keys: peaks.keys_over,
                },
            )
        } else {
            let refused = refused_count(rows, context, JEV_CALL_LIMIT);
            (
                refused,
                ChangeDetailBody::CallLimitBound {
                    scope: name.to_owned(),
                    old,
                    new,
                    upper_bound: true,
                },
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
) -> Option<ChangeBody> {
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
    (count > 0).then(|| tally.change("cache", count))
}

/// The secret field change: Jev calls whose state holds a value that a newly
/// added word would now redact.
async fn secret_change(
    pool: &PgPool,
    scope: &Scope,
    current: &SiteSpec,
    proposed: &SiteSpec,
) -> ApiResult<Option<ChangeBody>> {
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
    let detail = ChangeDetailBody::Secret {
        values: scan.values,
        fields: top_fields(&scan.fields),
    };
    Ok(plain_change("secret_fields", scan.calls, detail))
}

/// The field locations affected most, with their counts, most first.
fn top_fields(fields: &BTreeMap<String, i64>) -> Vec<(String, i64)> {
    let mut ranked: Vec<(&String, i64)> = fields.iter().map(|(name, n)| (name, *n)).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    ranked
        .into_iter()
        .take(TOP_FIELDS)
        .map(|(name, n)| (name.clone(), n))
        .collect()
}

fn hosts_of(spec: &SiteSpec) -> BTreeSet<&str> {
    spec.hosts().iter().map(String::as_str).collect()
}

fn synonyms_of(spec: &SiteSpec) -> BTreeSet<&(String, String)> {
    spec.advanced().synonyms().iter().collect()
}

/// The warnings for what history cannot estimate: a new session credential, new
/// hosts, changed synonyms, a longer allow cache, or a route that names requests of the
/// window by interface (`interface_unverified`), whose names the history does not hold.
fn warning_codes(
    current: &SiteSpec,
    proposed: &SiteSpec,
    interface_unverified: bool,
) -> Vec<&'static str> {
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
    if interface_unverified {
        codes.push(INTERFACE_UNVERIFIED);
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
) -> ApiResult<Json<PreviewBody>> {
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

    let mut changes: Vec<ChangeBody> = Vec::new();
    if paths.split.count > 0 {
        changes.push(paths.split.change(API_SPLIT, paths.split.count));
    }
    for kind in [
        ENTRY_UNREACHABLE,
        NO_SESSION_TO_ENTRY,
        ENTRY_TO_NO_SESSION,
        JUDGED_TO_BYPASS,
        BYPASS_TO_JUDGED,
        WOULD_BLOCK_TO_BLOCKED,
        BLOCKED_TO_WOULD_BLOCK,
    ] {
        if let Some(tally) = paths.changed.get(kind) {
            changes.push(tally.change(kind, tally.count));
        }
    }
    // The fast allows the object map difference moves, judged again over the window.
    let (object_changes, objects_complete) =
        object_impact::changes(&state.pool, &scope, &record.spec, &proposed).await?;
    changes.extend(object_changes);
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
    if paths.cached_split.count > 0 {
        changes.push(
            paths
                .cached_split
                .change(CACHE_BY_API, paths.cached_split.count),
        );
    }
    changes.extend(secret_change(&state.pool, &scope, &record.spec, &proposed).await?);

    let total: i64 = groups.iter().map(|group| group.count).sum();
    Ok(Json(PreviewBody {
        window_hours: WINDOW_HOURS,
        rows: total,
        groups: groups.len(),
        complete: complete && objects_complete,
        changes,
        patterns: PatternsBody {
            entries: paths.entries,
            bypass: paths.bypass,
        },
        warnings: warning_codes(&record.spec, &proposed, paths.split.count > 0)
            .into_iter()
            .map(str::to_owned)
            .collect(),
    }))
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
        let change = tally.change("judged_to_bypass", tally.count);
        let top = change.top.expect("a tally lists its paths");
        assert_eq!(top[0], ("GET".to_owned(), "/a".to_owned(), 6));
        assert_eq!(top[1], ("GET".to_owned(), "/b".to_owned(), 5));
        assert_eq!(change.would_block, Some(5));
        assert_eq!(change.sample.as_deref(), Some("req_5"));
    }

    #[test]
    fn mode_switches_move_the_matching_outcome() {
        assert_eq!(
            mode_change(Mode::Observe, Mode::Enforce),
            Some((WOULD_BLOCK_TO_BLOCKED, WOULD_BLOCK))
        );
        assert_eq!(mode_change(Mode::Enforce, Mode::Enforce), None);
    }

    fn routed(entries: &str, routes: &str) -> SiteSpec {
        let text = format!(
            r#"{{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{{"cookie":"SID"}},"entries":{entries},"bypass":["/assets/*"],"routes":{routes}}}"#
        );
        SiteSpec::from_json(&text).expect("valid routed test site")
    }

    const RPC: &str = r#"[{"path":"/api/rpc","name_from":[["body.method"]]}]"#;

    #[test]
    fn a_route_that_names_a_path_splits_its_requests_by_api() {
        let current = routed(r#"["/login"]"#, "[]");
        let proposed = routed(r#"["/login"]"#, RPC);
        let groups = [
            group("/api/rpc", true, "jev_allow", "allowed", 4),
            group("/api/records", true, "jev_allow", "allowed", 9),
        ];
        let changes = path_changes(&current, &proposed, &groups);
        assert_eq!(changes.split.count, 4);
        assert!(changes.changed.is_empty());
        assert_eq!(
            judged_path(&proposed, "/api/rpc"),
            Some("/api/rpc/~".to_owned())
        );
        assert_eq!(
            judged_path(&proposed, "/api/records"),
            Some("/api/records".to_owned())
        );
    }

    #[test]
    fn an_unchanged_route_splits_nothing() {
        let spec = routed(r#"["/login"]"#, RPC);
        let groups = [group("/api/rpc", true, "jev_allow", "allowed", 4)];
        let changes = path_changes(&spec, &spec, &groups);
        assert_eq!(changes.split.count, 0);
        assert!(changes.changed.is_empty());
    }

    #[test]
    fn an_entry_on_a_split_path_stops_matching_and_is_unreachable() {
        let current = routed(r#"["/api/rpc"]"#, "[]");
        let proposed = routed(r#"["/api/rpc"]"#, RPC);
        let groups = [group("/api/rpc", false, "no_session", "blocked", 3)];
        let changes = path_changes(&current, &proposed, &groups);
        assert_eq!(
            changes
                .changed
                .get(ENTRY_UNREACHABLE)
                .map(|tally| tally.count),
            Some(3)
        );
        assert!(!changes.changed.contains_key(ENTRY_TO_NO_SESSION));
        assert_eq!(changes.split.count, 3);
    }

    #[test]
    fn a_prefix_entry_still_covers_the_named_requests() {
        let current = routed(r#"["/api/*"]"#, "[]");
        let proposed = routed(r#"["/api/*"]"#, RPC);
        let groups = [group("/api/rpc", false, "no_session", "blocked", 3)];
        let changes = path_changes(&current, &proposed, &groups);
        assert!(changes.changed.is_empty());
        assert_eq!(changes.split.count, 3);
    }

    #[test]
    fn a_sub_path_of_an_exact_route_is_unknown_and_never_an_entry() {
        let current = routed(r#"["/api/rpc/list"]"#, "[]");
        let proposed = routed(r#"["/api/rpc/list"]"#, RPC);
        let groups = [group("/api/rpc/list", false, "no_session", "blocked", 2)];
        let changes = path_changes(&current, &proposed, &groups);
        assert_eq!(judged_path(&proposed, "/api/rpc/list"), None);
        assert_eq!(
            changes
                .changed
                .get(ENTRY_UNREACHABLE)
                .map(|tally| tally.count),
            Some(2)
        );
    }

    #[test]
    fn a_cached_allow_on_a_newly_named_path_is_counted_by_api() {
        let current = routed(r#"["/login"]"#, "[]");
        let proposed = routed(r#"["/login"]"#, RPC);
        let groups = [
            group("/api/rpc", true, CACHED_ALLOW, "allowed", 5),
            group("/api/rpc", true, "jev_allow", "allowed", 7),
        ];
        let changes = path_changes(&current, &proposed, &groups);
        assert_eq!(changes.cached_split.count, 5);
        assert_eq!(changes.split.count, 12);
    }

    #[test]
    fn the_route_estimates_are_marked_approximate() {
        let current = routed(r#"["/login"]"#, "[]");
        let proposed = routed(r#"["/login"]"#, RPC);
        let groups = [group("/api/rpc", true, CACHED_ALLOW, "allowed", 5)];
        let changes = path_changes(&current, &proposed, &groups);
        let split = changes.split.change(API_SPLIT, changes.split.count);
        let cached = changes
            .cached_split
            .change(CACHE_BY_API, changes.cached_split.count);
        let marked = Some(ChangeDetailBody::Approximate { approximate: true });
        assert_eq!(split.detail, marked);
        assert_eq!(cached.detail, marked);
        let json = serde_json::to_value(&split).expect("json");
        assert_eq!(json["detail"], serde_json::json!({"approximate": true}));
        // The other kinds are counted from the history as it is, and carry no mark.
        assert_eq!(Tally::default().change("cache", 1).detail, None);
    }

    #[test]
    fn a_route_that_names_requests_raises_the_interface_warning() {
        let current = routed(r#"["/login"]"#, "[]");
        let proposed = routed(r#"["/login"]"#, RPC);
        let named = [group("/api/rpc", true, "jev_allow", "allowed", 4)];
        let split = path_changes(&current, &proposed, &named).split.count > 0;
        assert!(warning_codes(&current, &proposed, split).contains(&INTERFACE_UNVERIFIED));
        // A prefix entry still covers the named requests, so no entry change shows them.
        let current = routed(r#"["/api/*"]"#, "[]");
        let proposed = routed(r#"["/api/*"]"#, RPC);
        let split = path_changes(&current, &proposed, &named).split.count > 0;
        assert!(warning_codes(&current, &proposed, split).contains(&INTERFACE_UNVERIFIED));
        // A route that names no request of the window raises nothing.
        let other = [group("/api/records", true, "jev_allow", "allowed", 9)];
        let split = path_changes(&current, &proposed, &other).split.count > 0;
        assert!(!warning_codes(&current, &proposed, split).contains(&INTERFACE_UNVERIFIED));
    }
}
