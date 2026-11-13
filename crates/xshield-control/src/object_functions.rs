//! The function table's candidates, confirmations and dismissals (docs/07 section 7.9.20).
//!
//! `GET …/objects/functions` lists the site's function table with the evidence of the learning window, the
//! functions the learning saw that the table does not name (the candidates), the administrator proposals that
//! wait, and the traffic of the last day that neither names. `POST …/objects/functions/changes` applies one batch
//! of the administrator's changes to the table as one new configuration version, and
//! `POST …/objects/functions/proposals/dismiss` dismisses one proposal. These handlers make no judgement themselves:
//! they read the store and write the configuration, and every write waits for an administrator. How the table takes
//! part in judging is docs/07 section 7.9.18.

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
use sqlx::PgPool;
use xshield_core::context::{
    Reliability, SiteSpec, SlotSource, Tier,
    learning::{FUNCTION_KEYS_MAX, WINDOW_DAYS, function_key},
    objects::{FUNCTIONS_MAX, KEY_MAX, ObjectFunction, ObjectMap, ObjectMapDto},
};
use xshield_postgres::{
    decision_stats::{self, FunctionTraffic, Scope},
    object_function_store as function_store,
    object_tier_judgement_store::{self as tier_judgements, TierProposal},
    site_spec_store::{self, Change, SiteRecord, WriteOutcome},
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    object_learning::{FunctionWindow, function_window, identified_by},
    object_map::{last_seen, oldest_day, site_of},
    params::{DAY_MILLIS, json_body, now_millis},
};

/// The most traffic groups the unlearned list names: the functions with the most requests.
const UNLEARNED_TOP: usize = 50;

/// Words that mark a template as an operations or administration path. A candidate whose template holds one is
/// `sensitive`, which reminds the administrator not to add it to the baseline by accident (docs/07 section 7.9.20).
/// Matched in lower case. The list is the one the judge's instructions give for privileged and operations functions
/// (docs/02 section 2.2); change the two together.
const SENSITIVE_WORDS: [&str; 15] = [
    "admin",
    "manage",
    "audit",
    "metrics",
    "actuator",
    "server-status",
    "debug",
    "swagger",
    "console",
    "phpinfo",
    "internal",
    "config",
    "backup",
    "ftp",
    "export",
];

/// The state of the function list: whether its candidates and evidence are read, or why they are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionsStatus {
    /// The learning window is read, and the candidates and the evidence come from it.
    Ok,
    /// The window holds more function keys than one pass reads. There are no candidates, and the table's
    /// evidence reads as none.
    OverLimit,
    /// The site has learning off. The evidence the store holds is shown, and no pass runs.
    LearningOff,
}

/// `GET /api/sites/{name}/objects/functions` (docs/07 section 7.9.20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionsBody {
    /// Whether the candidates and the evidence are read (see [`FunctionsStatus`]).
    pub status: FunctionsStatus,
    /// The days the learning window covers.
    pub window_days: u64,
    /// The units a candidate needs to be suggested: the site's `thresholds.sessions`.
    pub threshold_units: u32,
    /// Whether the site declares a user identity, so that its units are users and not sessions.
    pub identified: bool,
    /// The site's ordinary units over the window.
    pub ordinary_units: u32,
    /// The administrator units over the window.
    pub admin_units: u32,
    /// The functions of the table, in the order the configuration writes them.
    pub functions: Vec<FunctionRow>,
    /// The functions the learning saw that the table does not name, the least used first.
    pub candidates: Vec<CandidateRow>,
    /// The administrator proposals that the table does not already carry, by key.
    pub proposals: Vec<ProposalRow>,
    /// The traffic of the last day that neither the table nor the candidates name.
    pub unlearned: UnlearnedBody,
}

/// One function of the table, with its evidence over the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRow {
    /// `METHOD template`.
    pub key: String,
    /// Where the entry came from.
    pub source: SlotSource,
    /// `admin` for an administrator function. Absent when the function is open to all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// How sure the rules are of the tier. Absent with the tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<Reliability>,
    /// The distinct ordinary units that used the function.
    pub ordinary_units: u32,
    /// The distinct administrator units that used the function.
    pub admin_units: u32,
    /// The distinct ordinary units refused the function.
    pub refused_units: u32,
    /// The day the function was last seen, as the object map shows its positions.
    pub last_seen: Option<String>,
    /// Whether the template falls on one of the site's entries.
    pub on_entry: bool,
}

/// A function the learning saw that the table does not name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRow {
    /// `METHOD template`, as merged.
    pub key: String,
    /// The distinct ordinary units that used the function.
    pub ordinary_units: u32,
    /// The distinct administrator units that used the function.
    pub admin_units: u32,
    /// The distinct ordinary units refused the function.
    pub refused_units: u32,
    /// The day the function was last seen.
    pub last_seen: Option<String>,
    /// The requests of the last day the gateway allowed to this function without Jev.
    pub requests_24h: u64,
    /// Whether the candidate has as many units as the threshold. The console selects by default the candidates that
    /// are suggested and not sensitive (docs/07 section 7.9.20).
    pub suggested: bool,
    /// Whether the template holds a word that marks an operations path (`SENSITIVE_WORDS`).
    pub sensitive: bool,
    /// Whether the template falls on one of the site's entries.
    pub on_entry: bool,
}

/// An administrator proposal the rules make for a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalRow {
    /// `METHOD template`.
    pub key: String,
    /// The tier the rules give, always `admin` for a function.
    pub tier: Tier,
    /// How sure the rules are.
    pub reliability: Reliability,
    /// The administrator units the proposal counts.
    pub admin_units: u32,
    /// The distinct ordinary units refused the function over the window. `None` when the window holds no
    /// evidence of it, or is not read.
    pub refused_units: Option<u32>,
    /// The day the proposal's evidence last saw the function.
    pub last_seen: Option<String>,
    /// Whether the table names the function under the same key.
    pub in_table: bool,
}

/// The traffic of the last day that neither the table nor the candidates name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlearnedBody {
    /// The requests of all the unlearned functions, not only those in `top`.
    pub requests: u64,
    /// The requests whose function key cannot be written (`function_key` gives none).
    pub unkeyed_requests: u64,
    /// Whether the traffic was read to its end. `false` means the counts are lower bounds.
    pub complete: bool,
    /// The unlearned functions with the most requests, at most 50.
    pub top: Vec<UnlearnedRow>,
}

/// One unlearned function and how many requests it had.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlearnedRow {
    /// `METHOD template`, as merged when the window merges it.
    pub key: String,
    /// The requests of the last day.
    pub requests: u64,
    /// One request id of the function, as an example.
    pub sample: String,
}

/// The body of `POST …/objects/functions/changes`: one batch of the administrator's changes to the table. Each
/// list may be left out. The batch is applied in the order `remove`, `open`, `admin`, `add`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionChanges {
    /// Functions to add to the table as known functions, without a tier.
    #[serde(default)]
    pub add: Vec<String>,
    /// Administrator proposals the batch confirms.
    #[serde(default)]
    pub admin: Vec<AdminConfirmation>,
    /// Functions whose administrator tier the batch removes. They stay in the table as known functions.
    #[serde(default)]
    pub open: Vec<String>,
    /// Functions the batch deletes from the table.
    #[serde(default)]
    pub remove: Vec<String>,
}

/// One proposal the batch confirms: its key, and the reliability the administrator saw.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfirmation {
    /// `METHOD template`.
    pub key: String,
    /// The reliability of the proposal the administrator saw. It must be the proposal's own.
    pub reliability: Reliability,
}

/// The body of `POST …/objects/functions/proposals/dismiss`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DismissBody {
    /// The function's key, `METHOD template`.
    pub key: String,
}

/// `GET /api/sites/{name}/objects/functions`: the table, its candidates, the proposals and the unlearned
/// traffic, read at the time of the request.
///
/// # Errors
/// `SITE_NOT_FOUND` (404) for an unknown site, and a 500 when a query fails.
pub async fn list(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<FunctionsBody>> {
    let record = site_of(&state, &name).await?;
    let body = read_functions(&state.pool, &record, now_millis(), FUNCTION_KEYS_MAX).await?;
    Ok(Json(body))
}

/// `POST /api/sites/{name}/objects/functions/changes`: applies a batch of the administrator's changes to the
/// function table as one new configuration version, and clears the proposals it confirms (docs/07 section 7.9.20).
///
/// # Errors
/// `UNSUPPORTED_MEDIA_TYPE` (415) and `INVALID_BODY` (400) for a body that is not JSON of the batch, an empty
/// batch, one that names a key twice, or one with more entries than the table holds; `SITE_NOT_FOUND`
/// (404); `FUNCTION_CHANGED` (409, with `field`) for a removal or an opening of an entry the table does not hold
/// in that state; `JUDGEMENT_NOT_FOUND` (404, with `field`) for a confirmation with no proposal;
/// `JUDGEMENT_CHANGED` (409, with `field`) for a reliability other than the proposal's; `FUNCTION_ON_ENTRY` (409,
/// with `field`) for an administrator function on an entry; `SITE_CONFIG_OBJECTS_INVALID` (400, with `field`) when
/// the table as changed is refused; `VERSION_CONFLICT` (409, with `current_version`) when a save moved the site on
/// meanwhile; a 500 when a query or the write fails.
pub async fn changes(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let changes: FunctionChanges = json_body(&headers, &body)?;
    confirm_changes(&state.pool, &name, &changes, now_millis()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/sites/{name}/objects/functions/proposals/dismiss`: dismisses the administrator proposal of a
/// function. The rules propose it again only when their evidence reaches another judgement (docs/07 section 7.9.20).
///
/// # Errors
/// `INVALID_BODY` (400, with `field` `key`) for a key that is not a function key, which has one space; `SITE_NOT_FOUND`
/// (404); `JUDGEMENT_NOT_FOUND` (404) when the function has no proposal to dismiss; a 500 when a write fails.
pub async fn dismiss(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let body: DismissBody = json_body(&headers, &body)?;
    dismiss_proposal(&state.pool, &name, &body.key, now_millis()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reads the function list of the site `record` at `now`, reading at most `keys_max` function keys of the window.
/// Reads only.
///
/// # Errors
/// A 500 when a query fails.
pub(crate) async fn read_functions(
    pool: &PgPool,
    record: &SiteRecord,
    now: i64,
    keys_max: usize,
) -> ApiResult<FunctionsBody> {
    let site = record.spec.name();
    let oldest = oldest_day(now);
    let window = function_window(pool, record, oldest, keys_max).await?;
    let ordinary_units = match &window {
        Some(window) => window.ordinary_units,
        None => function_store::site_ordinary_units(pool, site, oldest).await?,
    };
    // The decision log outlives a site, so a site created again under the same name reads its own rows only.
    let scope = Scope {
        site: Some(site.to_owned()),
        since_millis: (now - DAY_MILLIS).max(record.created_at.timestamp_millis()),
        until_millis: now,
    };
    let (traffic, traffic_complete) = decision_stats::function_traffic(pool, &scope).await?;
    let reads = Reads {
        window,
        ordinary_units,
        admin_units: function_store::site_admin_units(pool, site, oldest).await?,
        traffic,
        traffic_complete,
        proposals: tier_judgements::proposals(pool, site).await?,
    };
    Ok(build_body(&record.spec, reads))
}

/// What the function list reads from the store (see [`read_functions`]).
struct Reads {
    /// The window's merged evidence, or `None` when it holds more function keys than one pass reads.
    window: Option<FunctionWindow>,
    ordinary_units: u32,
    admin_units: u32,
    /// The allowed requests of the last day, grouped by method and logical path.
    traffic: Vec<FunctionTraffic>,
    traffic_complete: bool,
    /// The open tier proposals of the site, of every kind of key.
    proposals: Vec<TierProposal>,
}

/// Builds the function list from what was read. Pure: the same inputs always give the same body.
fn build_body(spec: &SiteSpec, reads: Reads) -> FunctionsBody {
    let map = spec.objects();
    let learning = map.learning();
    let threshold = learning.thresholds.sessions;
    let window = reads.window.as_ref();
    let status = match (learning.auto_learn, window) {
        (false, _) => FunctionsStatus::LearningOff,
        (true, None) => FunctionsStatus::OverLimit,
        (true, Some(_)) => FunctionsStatus::Ok,
    };
    let candidates = candidate_keys(map, window);
    let traffic = read_traffic(map, window, &candidates, &reads.traffic);
    FunctionsBody {
        status,
        window_days: WINDOW_DAYS,
        threshold_units: threshold,
        identified: identified_by(map),
        ordinary_units: reads.ordinary_units,
        admin_units: reads.admin_units,
        functions: function_rows(spec, window),
        candidates: candidate_rows(spec, window, &candidates, &traffic.by_candidate, threshold),
        proposals: proposal_rows(spec, window, reads.proposals),
        unlearned: unlearned_body(traffic, reads.traffic_complete),
    }
}

/// The function rows of the table, in the order the configuration writes them. A function without evidence in the
/// window (or with no window) has no units, no refusals and no last day.
fn function_rows(spec: &SiteSpec, window: Option<&FunctionWindow>) -> Vec<FunctionRow> {
    spec.objects()
        .functions()
        .iter()
        .map(|function| {
            let evidence = window.and_then(|window| window.evidence.get(&function.key));
            FunctionRow {
                key: function.key.clone(),
                source: function.source,
                tier: function.tier,
                reliability: function.reliability,
                ordinary_units: evidence.map_or(0, |evidence| evidence.ordinary_units),
                admin_units: evidence.map_or(0, |evidence| evidence.admin_units),
                refused_units: evidence.map_or(0, |evidence| evidence.refused_units),
                last_seen: evidence.and_then(|evidence| seen(evidence.last_day)),
                on_entry: on_entry(spec, &function.key),
            }
        })
        .collect()
}

/// The candidates: the window's merged function keys that the table does not know, within the key limit. None
/// without a window.
fn candidate_keys(map: &ObjectMap, window: Option<&FunctionWindow>) -> BTreeSet<String> {
    window.map_or_else(BTreeSet::new, |window| {
        window
            .evidence
            .keys()
            .filter(|key| key.len() <= KEY_MAX && !knows(map, key))
            .cloned()
            .collect()
    })
}

/// The candidate rows: the least used first, and by key within the same count (docs/07 section 7.9.20).
fn candidate_rows(
    spec: &SiteSpec,
    window: Option<&FunctionWindow>,
    candidates: &BTreeSet<String>,
    by_key: &BTreeMap<String, u64>,
    threshold: u32,
) -> Vec<CandidateRow> {
    let Some(window) = window else {
        return Vec::new();
    };
    let mut rows: Vec<CandidateRow> = candidates
        .iter()
        .filter_map(|key| {
            let evidence = window.evidence.get(key)?;
            let (_, template) = key.split_once(' ')?;
            let units = evidence.ordinary_units.saturating_add(evidence.admin_units);
            Some(CandidateRow {
                key: key.clone(),
                ordinary_units: evidence.ordinary_units,
                admin_units: evidence.admin_units,
                refused_units: evidence.refused_units,
                last_seen: seen(evidence.last_day),
                requests_24h: by_key.get(key).copied().unwrap_or(0),
                suggested: units >= threshold,
                sensitive: is_sensitive(template),
                on_entry: spec.matching_entry(template).is_some(),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        units_of(a)
            .cmp(&units_of(b))
            .then_with(|| a.key.cmp(&b.key))
    });
    rows
}

/// The units a candidate has, ordinary and administrator together.
fn units_of(row: &CandidateRow) -> u32 {
    row.ordinary_units.saturating_add(row.admin_units)
}

/// The proposals the table does not already carry: a function key with one space, whose key the table does not
/// name under the same tier and reliability. By key.
fn proposal_rows(
    spec: &SiteSpec,
    window: Option<&FunctionWindow>,
    proposals: Vec<TierProposal>,
) -> Vec<ProposalRow> {
    let table = spec.objects().functions();
    let mut rows: Vec<ProposalRow> = proposals
        .into_iter()
        .filter(|proposal| is_function_key(&proposal.slot))
        .filter(|proposal| {
            !table.iter().any(|function| {
                function.key == proposal.slot
                    && function.tier == Some(Tier::Admin)
                    && function.reliability == Some(proposal.reliability)
            })
        })
        .map(|proposal| ProposalRow {
            tier: proposal.tier,
            reliability: proposal.reliability,
            admin_units: proposal.units,
            refused_units: window
                .and_then(|window| window.evidence.get(&proposal.slot))
                .map(|evidence| evidence.refused_units),
            last_seen: seen(proposal.last_day),
            in_table: table.iter().any(|function| function.key == proposal.slot),
            key: proposal.slot,
        })
        .collect();
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    rows
}

/// What the traffic of the last day adds up to, by candidate and among the functions neither the table nor the
/// candidates name.
#[derive(Debug, Default, PartialEq, Eq)]
struct Traffic {
    /// The requests of each candidate, by its key.
    by_candidate: BTreeMap<String, u64>,
    /// The requests of each unlearned function, with one request id of it.
    unlearned: BTreeMap<String, (u64, String)>,
    /// The requests of all the unlearned functions.
    unlearned_requests: u64,
    /// The requests whose function key cannot be written.
    unkeyed_requests: u64,
}

/// Sorts the allowed requests of the last day into those of each candidate, those of the unlearned functions and
/// those without a key. A request's key is the merged key the window counts its function under; a key the window
/// does not merge counts as it is.
fn read_traffic(
    map: &ObjectMap,
    window: Option<&FunctionWindow>,
    candidates: &BTreeSet<String>,
    groups: &[FunctionTraffic],
) -> Traffic {
    let mut traffic = Traffic::default();
    for group in groups {
        let count = u64::try_from(group.count).unwrap_or(0);
        let Some(raw) = function_key(&group.method, &group.path) else {
            traffic.unkeyed_requests = traffic.unkeyed_requests.saturating_add(count);
            continue;
        };
        let key = window
            .and_then(|window| window.mapping.get(&raw))
            .cloned()
            .unwrap_or(raw);
        if candidates.contains(&key) {
            let total = traffic.by_candidate.entry(key).or_insert(0);
            *total = total.saturating_add(count);
        } else if !knows(map, &key) {
            traffic.unlearned_requests = traffic.unlearned_requests.saturating_add(count);
            let (total, _) = traffic
                .unlearned
                .entry(key)
                .or_insert_with(|| (0, group.sample.clone()));
            *total = total.saturating_add(count);
        }
    }
    traffic
}

/// The unlearned functions, the most requested first and by key within the same count, at most [`UNLEARNED_TOP`].
fn unlearned_body(traffic: Traffic, complete: bool) -> UnlearnedBody {
    let mut top: Vec<UnlearnedRow> = traffic
        .unlearned
        .into_iter()
        .map(|(key, (requests, sample))| UnlearnedRow {
            key,
            requests,
            sample,
        })
        .collect();
    top.sort_by(|a, b| b.requests.cmp(&a.requests).then_with(|| a.key.cmp(&b.key)));
    top.truncate(UNLEARNED_TOP);
    UnlearnedBody {
        requests: traffic.unlearned_requests,
        unkeyed_requests: traffic.unkeyed_requests,
        complete,
        top,
    }
}

/// Whether the table knows the function a key names: the map's own answer for its method and template.
fn knows(map: &ObjectMap, key: &str) -> bool {
    key.split_once(' ')
        .is_some_and(|(method, template)| map.knows_function(method, template))
}

/// Whether a function key's template falls on one of the site's entries.
fn on_entry(spec: &SiteSpec, key: &str) -> bool {
    key.split_once(' ')
        .is_some_and(|(_, template)| spec.matching_entry(template).is_some())
}

/// Whether a template holds one of [`SENSITIVE_WORDS`], in lower case.
fn is_sensitive(template: &str) -> bool {
    let lower = template.to_lowercase();
    SENSITIVE_WORDS.iter().any(|word| lower.contains(word))
}

/// Whether a key is a function key: `METHOD template`, with exactly one space. A position key has two.
fn is_function_key(key: &str) -> bool {
    key.bytes().filter(|&byte| byte == b' ').count() == 1
}

/// The day a function was last seen, in the form the object map shows its positions.
fn seen(day: u64) -> Option<String> {
    last_seen(i64::try_from(day).unwrap_or(i64::MAX))
}

/// Applies a batch of changes to the table of the site `name`, as one new version (see [`changes`]). The batch is
/// checked against the table, the window's candidates and the proposals the site holds now. The table it makes is
/// written when it differs; then the proposals the batch confirms are cleared, whether or not a version was written.
///
/// # Errors
/// As [`changes`], except for the body's media type, which the handler has already checked.
pub(crate) async fn confirm_changes(
    pool: &PgPool,
    name: &str,
    changes: &FunctionChanges,
    now: i64,
) -> ApiResult<()> {
    check_shape(changes)?;
    let record = record_of(pool, name).await?;
    let window = function_window(pool, &record, oldest_day(now), FUNCTION_KEYS_MAX).await?;
    let candidates = candidate_keys(record.spec.objects(), window.as_ref());
    let proposals = function_proposals(pool, name).await?;
    let map = changed_table(&record.spec, changes, &candidates, &proposals)?;
    if map.functions() != record.spec.objects().functions() {
        write_table(pool, name, &record, map, &change_note(changes)).await?;
    }
    for confirmation in &changes.admin {
        tier_judgements::clear_confirmed(
            pool,
            name,
            &confirmation.key,
            Tier::Admin,
            confirmation.reliability,
        )
        .await?;
    }
    Ok(())
}

/// Refuses an empty batch, a batch that names a key twice (within a list or across them), or one with more entries
/// than the table holds. The field of a repeated key is the second place it is named. A batch whose changes are
/// already in the table passes: the caller writes nothing for it.
fn check_shape(changes: &FunctionChanges) -> ApiResult<()> {
    let total = changes.add.len() + changes.admin.len() + changes.open.len() + changes.remove.len();
    if total == 0 || total > FUNCTIONS_MAX {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "INVALID_BODY"));
    }
    let named = changes
        .add
        .iter()
        .enumerate()
        .map(|(at, key)| (format!("add[{at}]"), key.as_str()))
        .chain(
            changes
                .admin
                .iter()
                .enumerate()
                .map(|(at, confirmation)| (format!("admin[{at}]"), confirmation.key.as_str())),
        )
        .chain(
            changes
                .open
                .iter()
                .enumerate()
                .map(|(at, key)| (format!("open[{at}]"), key.as_str())),
        )
        .chain(
            changes
                .remove
                .iter()
                .enumerate()
                .map(|(at, key)| (format!("remove[{at}]"), key.as_str())),
        );
    let mut seen_keys = BTreeSet::new();
    for (field, key) in named {
        if !seen_keys.insert(key) {
            return Err(ApiError::invalid_body(&field));
        }
    }
    Ok(())
}

/// The table the batch makes of `spec`'s table, or the refusal. `candidates` are the keys the window holds that the
/// table does not know; `proposals` maps each function key with an open administrator proposal to its reliability.
/// Pure: the caller reads the store and writes the result. The map is validated as a whole, so a key the map cannot
/// hold is refused at its place in the table (`objects.functions[n]`).
fn changed_table(
    spec: &SiteSpec,
    changes: &FunctionChanges,
    candidates: &BTreeSet<String>,
    proposals: &BTreeMap<String, Reliability>,
) -> ApiResult<ObjectMap> {
    let mut functions: Vec<ObjectFunction> = spec.objects().functions().to_vec();
    for (at, key) in changes.remove.iter().enumerate() {
        let place = functions
            .iter()
            .position(|function| function.key == *key)
            .ok_or_else(|| function_changed(format!("remove[{at}]")))?;
        functions.remove(place);
    }
    for (at, key) in changes.open.iter().enumerate() {
        let function = functions
            .iter_mut()
            .find(|function| function.key == *key && function.tier.is_some())
            .ok_or_else(|| function_changed(format!("open[{at}]")))?;
        function.tier = None;
        function.reliability = None;
        function.source = SlotSource::Admin;
    }
    for (at, confirmation) in changes.admin.iter().enumerate() {
        let field = format!("admin[{at}]");
        let key = confirmation.key.as_str();
        let reliability = *proposals
            .get(key)
            .ok_or_else(|| judgement_not_found(&field))?;
        if reliability != confirmation.reliability {
            return Err(judgement_changed(&field));
        }
        if on_entry(spec, key) {
            return Err(function_on_entry(&field));
        }
        match functions.iter_mut().find(|function| function.key == key) {
            Some(function) => {
                function.source = SlotSource::Rule;
                function.tier = Some(Tier::Admin);
                function.reliability = Some(reliability);
            }
            None => functions.push(ObjectFunction {
                key: key.to_owned(),
                source: SlotSource::Rule,
                tier: Some(Tier::Admin),
                reliability: Some(reliability),
            }),
        }
    }
    for key in &changes.add {
        if functions.iter().any(|function| function.key == *key) {
            continue;
        }
        let source = if candidates.contains(key) {
            SlotSource::Rule
        } else {
            SlotSource::Admin
        };
        functions.push(ObjectFunction {
            key: key.clone(),
            source,
            tier: None,
            reliability: None,
        });
    }
    let dto = ObjectMapDto {
        functions,
        ..ObjectMapDto::from(spec.objects().clone())
    };
    ObjectMap::try_from(dto).map_err(ApiError::from)
}

/// The note the configuration history keeps for a batch: the number of each kind of change.
fn change_note(changes: &FunctionChanges) -> String {
    format!(
        "管理员确认了功能表的变更：新增 {}，管理档 {}，取消管理档 {}，删除 {}",
        changes.add.len(),
        changes.admin.len(),
        changes.open.len(),
        changes.remove.len()
    )
}

/// The function proposals of the site: the open administrator proposals of function keys, with their reliability.
async fn function_proposals(pool: &PgPool, name: &str) -> ApiResult<BTreeMap<String, Reliability>> {
    let proposals = tier_judgements::proposals(pool, name).await?;
    Ok(proposals
        .into_iter()
        .filter(|proposal| is_function_key(&proposal.slot) && proposal.tier == Tier::Admin)
        .map(|proposal| (proposal.slot, proposal.reliability))
        .collect())
}

/// Writes the table `map` as a new version of the site `name` whose record was read as `record`. The write names the
/// version the record had, so a save made since is a conflict and nothing is written.
///
/// # Errors
/// `SITE_NOT_FOUND` (404) when the site is gone, `VERSION_CONFLICT` (409, with `current_version`) when a save moved the
/// site on, and a 500 when the write fails.
pub(crate) async fn write_table(
    pool: &PgPool,
    name: &str,
    record: &SiteRecord,
    map: ObjectMap,
    note: &str,
) -> ApiResult<()> {
    let spec = record.spec.clone().with_objects(map);
    match site_spec_store::write(
        pool,
        name,
        &spec,
        record.version,
        Change::Update,
        Some(note),
    )
    .await?
    {
        WriteOutcome::Applied(_) => Ok(()),
        WriteOutcome::NotFound => Err(ApiError::new(StatusCode::NOT_FOUND, "SITE_NOT_FOUND")),
        WriteOutcome::VersionConflict { current } => {
            Err(ApiError::new(StatusCode::CONFLICT, "VERSION_CONFLICT").at_version(current))
        }
    }
}

/// Dismisses the proposal of the function `key` of the site `name` (see [`dismiss`]).
pub(crate) async fn dismiss_proposal(
    pool: &PgPool,
    name: &str,
    key: &str,
    now: i64,
) -> ApiResult<()> {
    if !is_function_key(key) {
        return Err(ApiError::invalid_body("key"));
    }
    let record = record_of(pool, name).await?;
    if tier_judgements::dismiss(pool, name, record.created_at, key, now).await? {
        Ok(())
    } else {
        Err(judgement_not_found("key"))
    }
}

/// The site's record, read for a write that names its version.
///
/// # Errors
/// `SITE_NOT_FOUND` (404) when no such site exists, and a 500 when the read fails.
async fn record_of(pool: &PgPool, name: &str) -> ApiResult<SiteRecord> {
    site_spec_store::get(pool, name)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "SITE_NOT_FOUND"))
}

/// `FUNCTION_CHANGED` (409): a removal or an opening names an entry the table does not hold in that state.
fn function_changed(field: String) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "FUNCTION_CHANGED").in_field(field)
}

/// `FUNCTION_ON_ENTRY` (409): an administrator function would sit on an entry, which is always reachable.
fn function_on_entry(field: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "FUNCTION_ON_ENTRY").in_field(field)
}

/// `JUDGEMENT_NOT_FOUND` (404): the function has no open proposal.
fn judgement_not_found(field: &str) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "JUDGEMENT_NOT_FOUND").in_field(field)
}

/// `JUDGEMENT_CHANGED` (409): the reliability named is not the proposal's.
fn judgement_changed(field: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "JUDGEMENT_CHANGED").in_field(field)
}

/// The status and the body an error is sent with, for the tests that read a refusal.
#[cfg(test)]
async fn refused(error: ApiError) -> (StatusCode, serde_json::Value) {
    let response = axum::response::IntoResponse::into_response(error);
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body");
    (status, serde_json::from_slice(&bytes).expect("JSON"))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use xshield_core::context::learning::FunctionEvidence;

    use super::*;

    /// A day in the window of every test window.
    const DAY: u64 = 20_000;

    /// A site on the given entries, with the given `objects` section.
    fn site(entries: &[&str], objects: &Value) -> SiteSpec {
        let spec = json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": entries,
            "objects": objects,
        });
        SiteSpec::from_json(&spec.to_string()).expect("test spec")
    }

    /// A window with the evidence `(key, ordinary, admin, refused)` and no merges.
    fn evidence_window(evidence: &[(&str, u32, u32, u32)]) -> FunctionWindow {
        FunctionWindow {
            evidence: evidence
                .iter()
                .map(|&(key, ordinary, admin, refused)| {
                    (
                        key.to_owned(),
                        FunctionEvidence {
                            ordinary_units: ordinary,
                            admin_units: admin,
                            admin_days: 2,
                            refused_units: refused,
                            last_day: DAY,
                        },
                    )
                })
                .collect(),
            ordinary_units: 0,
            mapping: BTreeMap::new(),
        }
    }

    fn confirmation(key: &str, reliability: Reliability) -> AdminConfirmation {
        AdminConfirmation {
            key: key.to_owned(),
            reliability,
        }
    }

    fn rule(key: &str) -> ObjectFunction {
        ObjectFunction {
            key: key.to_owned(),
            source: SlotSource::Rule,
            tier: None,
            reliability: None,
        }
    }

    fn known(key: &str) -> ObjectFunction {
        ObjectFunction {
            key: key.to_owned(),
            source: SlotSource::Admin,
            tier: None,
            reliability: None,
        }
    }

    fn admin_of(key: &str, reliability: Reliability) -> ObjectFunction {
        ObjectFunction {
            key: key.to_owned(),
            source: SlotSource::Rule,
            tier: Some(Tier::Admin),
            reliability: Some(reliability),
        }
    }

    #[test]
    fn adding_a_candidate_writes_a_rule_entry_and_any_other_key_an_admin_one() {
        let before = site(
            &["/login"],
            &json!({"functions": [{"key": "GET /api/known", "source": "admin"}]}),
        );
        let candidates = BTreeSet::from(["GET /api/reports/{id}".to_owned()]);
        let changes = FunctionChanges {
            add: vec![
                "GET /api/reports/{id}".to_owned(),
                "POST /api/reports".to_owned(),
                // Already in the table: left as it is.
                "GET /api/known".to_owned(),
            ],
            ..FunctionChanges::default()
        };
        let map = changed_table(&before, &changes, &candidates, &BTreeMap::new())
            .expect("the table changes");
        assert_eq!(
            map.functions(),
            [
                known("GET /api/known"),
                rule("GET /api/reports/{id}"),
                ObjectFunction {
                    key: "POST /api/reports".to_owned(),
                    source: SlotSource::Admin,
                    tier: None,
                    reliability: None,
                },
            ]
        );
    }

    #[test]
    fn confirming_a_proposal_sets_the_admin_tier_on_the_entry_or_adds_it() {
        let before = site(
            &["/login"],
            &json!({"functions": [{"key": "DELETE /api/users/{id}", "source": "admin"}]}),
        );
        let proposals = BTreeMap::from([
            ("DELETE /api/users/{id}".to_owned(), Reliability::Medium),
            ("POST /api/admin/export".to_owned(), Reliability::High),
        ]);
        let changes = FunctionChanges {
            admin: vec![
                confirmation("DELETE /api/users/{id}", Reliability::Medium),
                confirmation("POST /api/admin/export", Reliability::High),
            ],
            ..FunctionChanges::default()
        };
        let map = changed_table(&before, &changes, &BTreeSet::new(), &proposals)
            .expect("the table changes");
        assert_eq!(
            map.functions(),
            [
                admin_of("DELETE /api/users/{id}", Reliability::Medium),
                admin_of("POST /api/admin/export", Reliability::High),
            ]
        );
    }

    #[tokio::test]
    async fn a_proposal_that_changed_or_is_gone_is_not_confirmed() {
        let before = site(&["/login"], &json!({}));
        let gone = FunctionChanges {
            admin: vec![confirmation("GET /api/gone", Reliability::High)],
            ..FunctionChanges::default()
        };
        let error = changed_table(&before, &gone, &BTreeSet::new(), &BTreeMap::new())
            .expect_err("no proposal, no confirmation");
        let (status, body) = refused(error).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "JUDGEMENT_NOT_FOUND");
        assert_eq!(body["field"], "admin[0]");

        let proposals =
            BTreeMap::from([("DELETE /api/users/{id}".to_owned(), Reliability::Medium)]);
        let changed = FunctionChanges {
            admin: vec![confirmation("DELETE /api/users/{id}", Reliability::High)],
            ..FunctionChanges::default()
        };
        let error = changed_table(&before, &changed, &BTreeSet::new(), &proposals)
            .expect_err("another reliability is another proposal");
        let (status, body) = refused(error).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "JUDGEMENT_CHANGED");
        assert_eq!(body["field"], "admin[0]");
    }

    #[tokio::test]
    async fn an_admin_tier_is_not_confirmed_on_an_entry() {
        let before = site(&["/login", "/api/admin/export"], &json!({}));
        let proposals = BTreeMap::from([("POST /api/admin/export".to_owned(), Reliability::High)]);
        let changes = FunctionChanges {
            admin: vec![confirmation("POST /api/admin/export", Reliability::High)],
            ..FunctionChanges::default()
        };
        let error = changed_table(&before, &changes, &BTreeSet::new(), &proposals)
            .expect_err("an entry is always reachable");
        let (status, body) = refused(error).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "FUNCTION_ON_ENTRY");
        assert_eq!(body["field"], "admin[0]");
    }

    #[tokio::test]
    async fn opening_a_function_keeps_it_known_without_a_tier() {
        let before = site(
            &["/login"],
            &json!({"functions": [
                {"key": "POST /api/admin/export", "source": "rule", "tier": "admin", "reliability": "high"},
                {"key": "GET /api/open", "source": "admin"}
            ]}),
        );
        let changes = FunctionChanges {
            open: vec!["POST /api/admin/export".to_owned()],
            ..FunctionChanges::default()
        };
        let map = changed_table(&before, &changes, &BTreeSet::new(), &BTreeMap::new())
            .expect("the table changes");
        assert_eq!(
            map.functions(),
            [
                ObjectFunction {
                    key: "POST /api/admin/export".to_owned(),
                    source: SlotSource::Admin,
                    tier: None,
                    reliability: None,
                },
                known("GET /api/open"),
            ]
        );

        // An entry that is not there, or has no tier to take away, is refused.
        for key in ["GET /api/missing", "GET /api/open"] {
            let changes = FunctionChanges {
                open: vec![key.to_owned()],
                ..FunctionChanges::default()
            };
            let error = changed_table(&before, &changes, &BTreeSet::new(), &BTreeMap::new())
                .expect_err("nothing to open");
            let (status, body) = refused(error).await;
            assert_eq!(status, StatusCode::CONFLICT, "{key}");
            assert_eq!(body["error"], "FUNCTION_CHANGED", "{key}");
            assert_eq!(body["field"], "open[0]", "{key}");
        }
    }

    #[tokio::test]
    async fn removing_a_function_deletes_the_entry() {
        let before = site(
            &["/login"],
            &json!({"functions": [
                {"key": "GET /api/a", "source": "admin"},
                {"key": "GET /api/b", "source": "admin"},
                {"key": "GET /api/c", "source": "rule"}
            ]}),
        );
        let changes = FunctionChanges {
            remove: vec!["GET /api/b".to_owned()],
            ..FunctionChanges::default()
        };
        let map = changed_table(&before, &changes, &BTreeSet::new(), &BTreeMap::new())
            .expect("the table changes");
        assert_eq!(
            map.functions(),
            [
                known("GET /api/a"),
                ObjectFunction {
                    key: "GET /api/c".to_owned(),
                    source: SlotSource::Rule,
                    tier: None,
                    reliability: None,
                },
            ]
        );

        // The table as it stands after the removal: the function is no longer in it.
        let after = site(
            &["/login"],
            &json!({"functions": [
                {"key": "GET /api/a", "source": "admin"},
                {"key": "GET /api/c", "source": "rule"}
            ]}),
        );
        let changes = FunctionChanges {
            remove: vec!["GET /api/b".to_owned()],
            ..FunctionChanges::default()
        };
        let error = changed_table(&after, &changes, &BTreeSet::new(), &BTreeMap::new())
            .expect_err("already gone");
        let (status, body) = refused(error).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "FUNCTION_CHANGED");
        assert_eq!(body["field"], "remove[0]");
    }

    #[tokio::test]
    async fn an_empty_or_repeating_change_is_refused() {
        let empty = FunctionChanges::default();
        let (status, body) = refused(check_shape(&empty).expect_err("nothing to change")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "INVALID_BODY");

        let repeated = FunctionChanges {
            add: vec!["GET /api/a".to_owned(), "GET /api/a".to_owned()],
            ..FunctionChanges::default()
        };
        let (_, body) = refused(check_shape(&repeated).expect_err("named twice")).await;
        assert_eq!(body["error"], "INVALID_BODY");
        assert_eq!(body["field"], "add[1]");

        let across = FunctionChanges {
            add: vec!["GET /api/a".to_owned()],
            remove: vec!["GET /api/a".to_owned()],
            ..FunctionChanges::default()
        };
        let (_, body) = refused(check_shape(&across).expect_err("named in two lists")).await;
        assert_eq!(body["error"], "INVALID_BODY");
        assert_eq!(body["field"], "remove[0]");

        let too_many = FunctionChanges {
            add: (0..=FUNCTIONS_MAX)
                .map(|at| format!("GET /n{at}"))
                .collect(),
            ..FunctionChanges::default()
        };
        let (_, body) =
            refused(check_shape(&too_many).expect_err("more than the table holds")).await;
        assert_eq!(body["error"], "INVALID_BODY");
    }

    #[tokio::test]
    async fn an_invalid_key_is_refused_by_the_map() {
        let before = site(&["/login"], &json!({}));
        for key in ["get /x", "GET /a/{userId}"] {
            let changes = FunctionChanges {
                add: vec![key.to_owned()],
                ..FunctionChanges::default()
            };
            let error = changed_table(&before, &changes, &BTreeSet::new(), &BTreeMap::new())
                .expect_err("the map refuses the key");
            let (status, body) = refused(error).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{key}");
            assert_eq!(body["error"], "SITE_CONFIG_OBJECTS_INVALID", "{key}");
            assert_eq!(body["field"], "objects.functions[0]", "{key}");
            assert_eq!(body["reason"], "key_invalid", "{key}");
        }
    }

    #[test]
    fn the_other_parts_of_the_map_are_untouched() {
        let before = site(
            &["/login"],
            &json!({
                "classes": [{"id": "patient", "name": "患者"}],
                "slots": [{"key": "GET /api/patients/{id} [].id", "class": "patient", "source": "admin"}],
                "functions": [{"key": "GET /api/a", "source": "admin"}],
                "learning": {"auto_tighten": false}
            }),
        );
        let changes = FunctionChanges {
            add: vec!["GET /api/b".to_owned()],
            remove: vec!["GET /api/a".to_owned()],
            ..FunctionChanges::default()
        };
        let map = changed_table(&before, &changes, &BTreeSet::new(), &BTreeMap::new())
            .expect("the table changes");
        let mut after = ObjectMapDto::from(map);
        let mut prior = ObjectMapDto::from(before.objects().clone());
        after.functions.clear();
        prior.functions.clear();
        assert_eq!(after, prior);
    }

    #[test]
    fn candidates_leave_out_what_the_map_knows() {
        let map_spec = site(
            &["/login"],
            &json!({
                "classes": [{"id": "doctor", "name": "医生"}],
                "slots": [{"key": "GET /api/doctors/{id} [].id", "class": "doctor", "source": "admin"}],
                "functions": [{"key": "GET /api/known/{id}", "source": "admin"}]
            }),
        );
        let too_long = format!("GET /{}", "a".repeat(KEY_MAX));
        let window = evidence_window(&[
            // Named by the table.
            ("GET /api/known/{id}", 5, 0, 0),
            // Covered by a declared position on the same route.
            ("GET /api/doctors/{id}", 5, 0, 0),
            ("GET /api/new/{id}", 1, 0, 0),
            (too_long.as_str(), 1, 0, 0),
        ]);
        let candidates = candidate_keys(map_spec.objects(), Some(&window));
        assert_eq!(candidates, BTreeSet::from(["GET /api/new/{id}".to_owned()]));
        assert!(candidate_keys(map_spec.objects(), None).is_empty());
    }

    #[test]
    fn a_route_word_under_an_id_entry_is_a_sensitive_candidate() {
        let spec = site(
            &["/login"],
            &json!({"functions": [{"key": "GET /api/patients/{id}", "source": "admin"}]}),
        );
        let window = evidence_window(&[
            ("GET /api/patients/7005", 5, 0, 0),
            ("GET /api/patients/export-all", 5, 0, 0),
        ]);
        let candidates = candidate_keys(spec.objects(), Some(&window));
        assert_eq!(
            candidates,
            BTreeSet::from(["GET /api/patients/export-all".to_owned()])
        );
        let rows = candidate_rows(&spec, Some(&window), &candidates, &BTreeMap::new(), 5);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].sensitive);
    }

    #[test]
    fn a_candidate_is_suggested_at_the_threshold_and_flagged_when_sensitive() {
        let spec = site(&["/login"], &json!({}));
        let window = evidence_window(&[
            ("GET /api/patients", 9, 0, 0),
            ("GET /api/a", 4, 1, 0),
            ("GET /api/b", 4, 0, 0),
            ("GET /api/admin/users", 1, 1, 0),
            ("GET /metrics", 0, 1, 0),
        ]);
        let candidates = candidate_keys(spec.objects(), Some(&window));
        let by_key = BTreeMap::from([("GET /api/a".to_owned(), 340_u64)]);
        let rows = candidate_rows(&spec, Some(&window), &candidates, &by_key, 5);
        let shape: Vec<(&str, bool, bool)> = rows
            .iter()
            .map(|row| (row.key.as_str(), row.suggested, row.sensitive))
            .collect();
        // The least used first: the administrator sees the odd ones before the common ones.
        assert_eq!(
            shape,
            vec![
                ("GET /metrics", false, true),
                ("GET /api/admin/users", false, true),
                ("GET /api/b", false, false),
                ("GET /api/a", true, false),
                ("GET /api/patients", true, false),
            ]
        );
        assert_eq!(rows[3].requests_24h, 340);
        assert_eq!(rows[2].requests_24h, 0);
    }

    #[test]
    fn proposals_already_in_the_table_are_left_out() {
        let spec = site(
            &["/login"],
            &json!({"functions": [
                {"key": "DELETE /api/users/{id}", "source": "admin", "tier": "admin", "reliability": "medium"},
                {"key": "POST /api/x", "source": "rule", "tier": "admin", "reliability": "high"}
            ]}),
        );
        let window = evidence_window(&[("POST /api/x", 0, 2, 1), ("GET /api/y", 0, 3, 0)]);
        let proposal = |slot: &str, reliability: Reliability| TierProposal {
            slot: slot.to_owned(),
            tier: Tier::Admin,
            reliability,
            units: 2,
            seen_values: 0,
            agreement_per_mille: 0,
            last_day: DAY,
        };
        let rows = proposal_rows(
            &spec,
            Some(&window),
            vec![
                // The same key, tier and reliability: already in the table.
                proposal("DELETE /api/users/{id}", Reliability::Medium),
                // The table has the key with another reliability: listed, in the table.
                proposal("POST /api/x", Reliability::Medium),
                // Not in the table, and with no evidence in the window: no refusals to show.
                proposal("GET /api/z", Reliability::High),
                // A position's proposal is not a function's.
                proposal("GET /api/search [].id", Reliability::High),
            ],
        );
        let shape: Vec<(&str, bool, Option<u32>)> = rows
            .iter()
            .map(|row| (row.key.as_str(), row.in_table, row.refused_units))
            .collect();
        assert_eq!(
            shape,
            vec![("GET /api/z", false, None), ("POST /api/x", true, Some(1))]
        );
        // Without a window, nothing is refused as far as the list knows.
        let blind = proposal_rows(&spec, None, vec![proposal("GET /api/y", Reliability::High)]);
        assert_eq!(blind[0].refused_units, None);
    }

    #[test]
    fn traffic_outside_the_table_and_the_candidates_is_unlearned() {
        let spec = site(
            &["/login"],
            &json!({"functions": [{"key": "GET /api/known/{id}", "source": "admin"}]}),
        );
        // The window merges the product's key into the route's `{id}`, and that merged key is the candidate.
        let merged = "GET /api/products/{id}".to_owned();
        let mut window = evidence_window(&[(merged.as_str(), 2, 0, 0)]);
        window
            .mapping
            .insert("GET /api/products/PT-7004".to_owned(), merged.clone());
        let candidates = candidate_keys(spec.objects(), Some(&window));
        assert_eq!(candidates, BTreeSet::from([merged.clone()]));

        let group = |method: &str, path: &str, count: i64, sample: &str| FunctionTraffic {
            method: method.to_owned(),
            path: path.to_owned(),
            count,
            sample: sample.to_owned(),
        };
        let mut groups = vec![
            // Known by the table: not counted.
            group("GET", "/api/known/7", 5, "req_known"),
            // The candidate, through the merge.
            group("GET", "/api/products/PT-7004", 3, "req_product"),
            group("GET", "/api/metrics", 40, "req_metrics"),
            group("POST", "/api/zzz", 2, "req_zzz"),
            // Without a function key: OPTIONS is no function, and a path that cannot be canonical has none.
            group("OPTIONS", "/api/x", 4, "req_options"),
            group("GET", "/a/%zz", 1, "req_bad"),
        ];
        // Fifty-five more unlearned functions, the first with one request and the last with 55, to check the cut.
        for index in 0..55_i64 {
            groups.push(group(
                "GET",
                &format!("/n{index}"),
                index + 1,
                &format!("req_n{index}"),
            ));
        }
        let traffic = read_traffic(spec.objects(), Some(&window), &candidates, &groups);
        assert_eq!(traffic.by_candidate, BTreeMap::from([(merged, 3)]));
        assert_eq!(traffic.unkeyed_requests, 5);
        assert_eq!(
            traffic.unlearned_requests,
            40 + 2 + (1_u64..=55).sum::<u64>()
        );

        let body = unlearned_body(traffic, true);
        assert_eq!(body.top.len(), UNLEARNED_TOP);
        assert_eq!(body.top[0].key, "GET /n54");
        assert_eq!(body.top[0].requests, 55);
        // The fifty listed are the keys with at least seven requests, the 40-request function among them, so the
        // last one listed has seven.
        assert_eq!(body.top.last().map(|row| row.requests), Some(7));
        assert!(!body.top.iter().any(|row| row.key == "GET /n0"));
        let metrics = body
            .top
            .iter()
            .find(|row| row.key == "GET /api/metrics")
            .expect("the 40-request function is listed");
        assert_eq!(metrics.sample, "req_metrics");
        assert!(
            body.top
                .windows(2)
                .all(|pair| pair[0].requests >= pair[1].requests)
        );
        assert!(body.complete);
    }
}

#[cfg(test)]
mod live_tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::{Value, json};
    use xshield_core::context::objects::LearningThresholds;

    use super::*;
    use crate::object_learning::learn_once;
    use crate::object_learning::pass_tests::{drop_scratch, scratch};
    use crate::params::DAY_MILLIS;
    use crate::test_support::ensure_days;

    /// The administrator's function the learning sees, used by the administrator alone.
    const SEARCH: &str = "GET /api/admin/search";
    /// The ordinary users' function.
    const FEED: &str = "GET /api/feed";

    /// Creates the site `clinic`: an identified clinic with the function table `functions` and the learning
    /// settings `learning`.
    async fn create_clinic(pool: &PgPool, functions: Value, learning: Value) -> SiteRecord {
        let spec = json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"],
            "objects": {
                "classes": [{"id": "patient", "name": "患者"}],
                "slots": [
                    {"key": "GET /api/me user.id", "class": "patient", "source": "admin", "identity": "user"},
                    {"key": "GET /api/me role", "class": "patient", "source": "admin", "identity": "role"}
                ],
                "functions": functions,
                "learning": learning
            }
        });
        let spec = SiteSpec::from_json(&spec.to_string()).expect("test spec");
        site_spec_store::create(pool, &spec, None)
            .await
            .expect("create the site")
    }

    /// Writes one allowed decision row of `clinic` at `at_millis`, made by `session` as `user` in `role`.
    async fn log_row(
        pool: &PgPool,
        at_millis: i64,
        session: &str,
        user: &str,
        role: &str,
        method: &str,
        path: &str,
    ) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let trace = json!({
            "v": 1,
            "values_truncated": false,
            "values": [],
            "timing": {"judge_ms": 1},
            "session": {
                "age_seconds": 1,
                "known_values": 0,
                "identity": {"user": user, "role": role}
            }
        });
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace)
             VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                $4, $5, 200, 'fast_allow', 'allowed', $6)",
        )
        .bind(at_millis)
        .bind(format!("fnlist-{}-{id}", std::process::id()))
        .bind(session)
        .bind(method)
        .bind(path)
        .bind(trace)
        .execute(pool)
        .await
        .expect("insert a decision row");
    }

    /// The evidence the live tests learn from: `SEARCH` used by the administrator on two days, and `FEED` used by
    /// ten ordinary users two days ago.
    async fn learn_scenario(pool: &PgPool, now: i64) {
        ensure_days(
            pool,
            &[
                now,
                now - DAY_MILLIS,
                now - 2 * DAY_MILLIS,
                now - 3 * DAY_MILLIS,
            ],
        )
        .await;
        for days in [2_i64, 3] {
            log_row(
                pool,
                now - days * DAY_MILLIS,
                "adm",
                "root",
                "admin",
                "GET",
                "/api/admin/search",
            )
            .await;
        }
        for user in 0..10_i64 {
            log_row(
                pool,
                now - 2 * DAY_MILLIS,
                &format!("s{user}"),
                &format!("u{user}"),
                "user",
                "GET",
                "/api/feed",
            )
            .await;
        }
    }

    /// The site as the store holds it now.
    async fn record(pool: &PgPool) -> SiteRecord {
        site_spec_store::get(pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists")
    }

    /// A confirmation of the proposal of `key` with `reliability`.
    fn confirm(key: &str, reliability: Reliability) -> AdminConfirmation {
        AdminConfirmation {
            key: key.to_owned(),
            reliability,
        }
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_BASE_URL)"]
    async fn the_functions_list_shows_the_table_the_candidates_and_the_proposals() {
        let Some((admin, pool, name)) = scratch("fn_list").await else {
            return;
        };
        create_clinic(
            &pool,
            json!([{"key": FEED, "source": "admin"}]),
            json!({"auto_tighten": false, "auto_pause": false}),
        )
        .await;
        // The clock is read after the site exists: the last day's traffic starts no earlier than its creation.
        let now = crate::params::now_millis();
        learn_scenario(&pool, now).await;
        // One request of the administrator's search just now, so it has a count in the last day.
        log_row(
            &pool,
            now,
            "adm",
            "root",
            "admin",
            "GET",
            "/api/admin/search",
        )
        .await;
        learn_once(&pool, None, now).await;

        let body = read_functions(&pool, &record(&pool).await, now, FUNCTION_KEYS_MAX)
            .await
            .expect("read the list");
        assert_eq!(body.status, FunctionsStatus::Ok);
        assert!(body.identified);
        assert_eq!(body.window_days, WINDOW_DAYS);
        assert_eq!(body.threshold_units, LearningThresholds::default().sessions);
        assert_eq!(body.ordinary_units, 10);
        assert_eq!(body.admin_units, 1);

        // The table's function has the window's evidence, and is not a candidate.
        assert_eq!(body.functions.len(), 1);
        assert_eq!(body.functions[0].key, FEED);
        assert_eq!(
            (
                body.functions[0].ordinary_units,
                body.functions[0].admin_units
            ),
            (10, 0)
        );
        assert!(body.functions[0].last_seen.is_some());

        // The administrator's search is the candidate: unknown to the table, used by the administrator alone.
        assert_eq!(body.candidates.len(), 1);
        let search = &body.candidates[0];
        assert_eq!(search.key, SEARCH);
        assert_eq!((search.ordinary_units, search.admin_units), (0, 1));
        assert_eq!(search.requests_24h, 1, "the request of the last hour");
        assert!(!search.suggested, "one unit is below the threshold");
        assert!(search.sensitive, "the template says admin");
        assert!(!search.on_entry);

        // The rules propose the search, and the table does not name it.
        assert_eq!(body.proposals.len(), 1);
        assert_eq!(body.proposals[0].key, SEARCH);
        assert_eq!(body.proposals[0].tier, Tier::Admin);
        assert_eq!(body.proposals[0].reliability, Reliability::High);
        assert_eq!(body.proposals[0].refused_units, Some(0));
        assert!(!body.proposals[0].in_table);

        // The table's function was requested two days ago, so nothing is unlearned in the last day.
        assert_eq!(body.unlearned.requests, 0);
        assert!(body.unlearned.complete);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_BASE_URL)"]
    async fn a_site_over_the_key_limit_lists_no_candidates() {
        let Some((admin, pool, name)) = scratch("fn_limit").await else {
            return;
        };
        let now = crate::params::now_millis();
        create_clinic(
            &pool,
            json!([]),
            json!({"auto_tighten": false, "auto_pause": false}),
        )
        .await;
        learn_scenario(&pool, now).await;
        learn_once(&pool, None, now).await;
        // A third key with evidence: two keys in all, and the list reads one.
        log_row(
            &pool,
            now - 2 * DAY_MILLIS,
            "s0",
            "u0",
            "user",
            "GET",
            "/api/other",
        )
        .await;
        learn_once(&pool, None, now).await;

        let body = read_functions(&pool, &record(&pool).await, now, 1)
            .await
            .expect("read the list");
        assert_eq!(body.status, FunctionsStatus::OverLimit);
        assert!(body.candidates.is_empty());
        assert!(body.functions.is_empty());
        // The proposal an earlier pass made is still listed, with no refusals to show.
        assert_eq!(body.proposals.len(), 1);
        assert_eq!(body.proposals[0].key, SEARCH);
        assert_eq!(body.proposals[0].refused_units, None);
        // The units are counted all the same.
        assert_eq!(body.ordinary_units, 10);
        assert_eq!(body.admin_units, 1);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_BASE_URL)"]
    async fn a_site_with_learning_off_says_so() {
        let Some((admin, pool, name)) = scratch("fn_off").await else {
            return;
        };
        let now = crate::params::now_millis();
        create_clinic(&pool, json!([]), json!({"auto_learn": false})).await;
        learn_scenario(&pool, now).await;
        learn_once(&pool, None, now).await;

        let body = read_functions(&pool, &record(&pool).await, now, FUNCTION_KEYS_MAX)
            .await
            .expect("read the list");
        assert_eq!(body.status, FunctionsStatus::LearningOff);
        assert!(body.candidates.is_empty());
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_BASE_URL)"]
    async fn confirming_changes_writes_one_version_and_clears_the_proposal() {
        let Some((admin, pool, name)) = scratch("fn_confirm").await else {
            return;
        };
        let now = crate::params::now_millis();
        create_clinic(
            &pool,
            json!([]),
            json!({"auto_tighten": false, "auto_pause": false}),
        )
        .await;
        learn_scenario(&pool, now).await;
        learn_once(&pool, None, now).await;
        assert_eq!(record(&pool).await.version, 1);

        // Two additions and one confirmation in one batch.
        let changes = FunctionChanges {
            add: vec![FEED.to_owned(), "POST /api/feed".to_owned()],
            admin: vec![confirm(SEARCH, Reliability::High)],
            ..FunctionChanges::default()
        };
        confirm_changes(&pool, "clinic", &changes, now)
            .await
            .expect("confirm the batch");

        let after = record(&pool).await;
        assert_eq!(after.version, 2, "one version for the whole batch");
        let functions = after.spec.objects().functions();
        let find = |key: &str| {
            functions
                .iter()
                .find(|function| function.key == key)
                .expect("the function is in the table")
        };
        // The candidate is added as a rule's, the other key as the administrator's.
        assert_eq!(find(FEED).source, SlotSource::Rule);
        assert_eq!(find(FEED).tier, None);
        assert_eq!(find("POST /api/feed").source, SlotSource::Admin);
        assert_eq!(find(SEARCH).tier, Some(Tier::Admin));
        assert_eq!(find(SEARCH).reliability, Some(Reliability::High));
        assert_eq!(functions.len(), 3);

        let note: Option<String> = sqlx::query_scalar(
            "SELECT note FROM site_config_history WHERE site = 'clinic' AND version = 2",
        )
        .fetch_one(&pool)
        .await
        .expect("read the note of the version");
        let note = note.expect("the version has a note");
        assert!(
            note.contains("新增 2，管理档 1，取消管理档 0，删除 0"),
            "{note}"
        );

        assert!(
            tier_judgements::proposal(&pool, "clinic", SEARCH)
                .await
                .expect("read the proposal")
                .is_none(),
            "the confirmed proposal is cleared"
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_BASE_URL)"]
    async fn a_change_that_changes_nothing_writes_no_version() {
        let Some((admin, pool, name)) = scratch("fn_nochange").await else {
            return;
        };
        let now = crate::params::now_millis();
        create_clinic(
            &pool,
            json!([{"key": FEED, "source": "admin"}]),
            json!({"auto_tighten": false, "auto_pause": false}),
        )
        .await;
        learn_scenario(&pool, now).await;
        learn_once(&pool, None, now).await;

        // An addition the table already holds changes nothing.
        let known = FunctionChanges {
            add: vec![FEED.to_owned()],
            ..FunctionChanges::default()
        };
        confirm_changes(&pool, "clinic", &known, now)
            .await
            .expect("nothing to write");
        assert_eq!(record(&pool).await.version, 1);

        // Confirming the search writes it once.
        let confirming = FunctionChanges {
            admin: vec![confirm(SEARCH, Reliability::High)],
            ..FunctionChanges::default()
        };
        confirm_changes(&pool, "clinic", &confirming, now)
            .await
            .expect("confirm");
        assert_eq!(record(&pool).await.version, 2);

        // The rules propose the search again (their evidence is unchanged): the table already carries it, so
        // confirming it again writes no version, and clears the proposal.
        let last_day = u64::try_from(now / DAY_MILLIS).unwrap_or(0);
        tier_judgements::put(
            &pool,
            "clinic",
            record(&pool).await.created_at,
            &TierProposal {
                slot: SEARCH.to_owned(),
                tier: Tier::Admin,
                reliability: Reliability::High,
                units: 1,
                seen_values: 0,
                agreement_per_mille: 0,
                last_day,
            },
            now,
        )
        .await
        .expect("the rules propose it again");
        confirm_changes(&pool, "clinic", &confirming, now)
            .await
            .expect("confirm it again");
        assert_eq!(record(&pool).await.version, 2, "no new version");
        assert!(
            tier_judgements::proposal(&pool, "clinic", SEARCH)
                .await
                .expect("read the proposal")
                .is_none(),
            "the proposal is cleared all the same"
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_BASE_URL)"]
    async fn a_stale_version_is_a_conflict() {
        let Some((admin, pool, name)) = scratch("fn_stale").await else {
            return;
        };
        create_clinic(
            &pool,
            json!([]),
            json!({"auto_tighten": false, "auto_pause": false}),
        )
        .await;
        // The record a change reads, at version 1, and a save that moves the site on before the write.
        let stale = record(&pool).await;
        let moved = site_spec_store::update(&pool, "clinic", &stale.spec, stale.version, None)
            .await
            .expect("save the site");
        assert!(matches!(moved, WriteOutcome::Applied(_)));

        let changes = FunctionChanges {
            add: vec!["GET /api/x".to_owned()],
            ..FunctionChanges::default()
        };
        let map = changed_table(&stale.spec, &changes, &BTreeSet::new(), &BTreeMap::new())
            .expect("the table changes");
        let error = write_table(&pool, "clinic", &stale, map, "a note")
            .await
            .expect_err("the version has moved");
        let (status, body) = refused(error).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "VERSION_CONFLICT");
        assert_eq!(body["current_version"], 2);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_BASE_URL)"]
    async fn dismissing_a_function_proposal_keeps_it_dismissed() {
        let Some((admin, pool, name)) = scratch("fn_dismiss").await else {
            return;
        };
        let now = crate::params::now_millis();
        create_clinic(
            &pool,
            json!([]),
            json!({"auto_tighten": false, "auto_pause": false}),
        )
        .await;
        learn_scenario(&pool, now).await;
        learn_once(&pool, None, now).await;

        dismiss_proposal(&pool, "clinic", SEARCH, now)
            .await
            .expect("dismiss the proposal");
        let body = read_functions(&pool, &record(&pool).await, now, FUNCTION_KEYS_MAX)
            .await
            .expect("read the list");
        assert!(
            body.proposals.is_empty(),
            "a dismissed proposal is not listed"
        );

        // The evidence is unchanged, so the next pass does not propose it again.
        learn_once(&pool, None, now).await;
        assert!(
            tier_judgements::proposal(&pool, "clinic", SEARCH)
                .await
                .expect("read the proposal")
                .is_none(),
            "a dismissed function is not proposed again"
        );

        let (status, body) = refused(
            dismiss_proposal(&pool, "clinic", SEARCH, now)
                .await
                .expect_err("nothing left to dismiss"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "JUDGEMENT_NOT_FOUND");

        // A position's key is not a function's: the position's own proposal is dismissed on its own action.
        let (status, body) = refused(
            dismiss_proposal(&pool, "clinic", "GET /api/search [].id", now)
                .await
                .expect_err("a position key is refused"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "INVALID_BODY");
        drop_scratch(admin, pool, name).await;
    }
}
