//! Tuning suggestions, the readiness check for observe mode and the parameter
//! evidence of one site (docs/07 sections 7.9.11 and 7.9.2).
//!
//! `insights` and `pending_suggestions` share one analysis, so the number the site
//! list shows is the number of suggestions the insights page lists.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    sync::Arc,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use xshield_core::context::{Mode, OnJevUnavailable, SiteSpec, config::is_plain_path};
use xshield_postgres::{
    decision_log_store::{self, RequestFilter},
    decision_stats::{self, Breakdown, JevStats, PathGroup, RefusedGroup, Scope},
    site_spec_store::{self, HistoryEntry, SiteRecord},
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    jev::health_of,
    params::{Params, now_millis},
};

pub(crate) const NO_SESSION: &str = "no_session";
pub(crate) const BYPASS: &str = "bypass";
pub(crate) const UNKNOWN_SITE: &str = "unknown_site";
pub(crate) const CACHED_ALLOW: &str = "cached_allow";
pub(crate) const WOULD_BLOCK: &str = "would_block";
pub(crate) const BLOCKED: &str = "blocked";
pub(crate) const JEV_TIMEOUT: &str = "JEV_TIMEOUT";
pub(crate) const JEV_CALL_LIMIT: &str = "JEV_CALL_LIMIT";
pub(crate) const SESSION_CONTEXT: &str = "session";
pub(crate) const ADDRESS_CONTEXT: &str = "address";
const BODY_NOT_INSPECTABLE: &str = "body_not_inspectable";
const REDACTED: &str = "<redacted>";

const DEFAULT_JEV_TIMEOUT_MS: u32 = 2_000;
const DEFAULT_SESSION_CALLS: u32 = 60;
const DEFAULT_ADDRESS_CALLS: u32 = 30;
const DEFAULT_CACHE_MINUTES: u32 = 10;
const DEFAULT_WINDOW_HOURS: i64 = 24;
const MAX_WINDOW_HOURS: i64 = 168;
const EVIDENCE_WINDOW_HOURS: i64 = 24;
const HOUR_MILLIS: i64 = 3_600_000;
/// Versions read per page while looking for when observing began. `history` returns
/// at most 200 versions a page.
const OBSERVE_PAGE: i64 = 200;
const HOT_TEMPLATES: usize = 5;
const SUGGESTIONS_PER_RULE: usize = 50;
const PREFIX_MIN_PATHS: usize = 3;
const ROOT_BUNDLE_MIN_FILES: usize = 2;
/// Requests a path needs in the window before a route rule is suggested for it.
const ROUTE_RULE_MIN_REQUESTS: i64 = 20;
/// Most fields one route rule suggestion offers to name a path's interface by.
const ROUTE_FIELDS_PER_PATH: usize = 3;
/// The newest requests of the candidate paths that the route rule scan reads, the same
/// bound as the Jev state scan so the insights stay quick on a busy site. When the
/// candidates have more requests in the window, the scan covers the newest ones only,
/// and the insights say so (`complete` is false).
const ROUTE_SCAN_LIMIT: i64 = 20_000;
const TIMEOUT_STEP_MS: u32 = 500;
const TIMEOUT_MAX_MS: u32 = 30_000;
const CALL_LIMIT_MAX: i64 = 600;
const HISTOGRAM_BUCKETS: usize = 300;
const HISTOGRAM_BUCKET_MS: i64 = 100;

/// The words the judge always redacts. A copy: the judge's list is private.
const BUILT_IN_SECRET_WORDS: [&str; 9] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "otp",
    "credential",
    "authorization",
    "cvv",
];
/// Sensitive personal data a site may add to `secret_fields` (section 7.9.11).
const SENSITIVE_WORDS: [&str; 9] = [
    "ssn",
    "idcard",
    "id_card",
    "passport",
    "cardnum",
    "card_number",
    "cvc",
    "iban",
    "bankaccount",
];
const STATIC_EXTENSIONS: [&str; 14] = [
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".webp", ".avif",
];
const STATIC_DIRS: [&str; 5] = ["/static/", "/assets/", "/public/", "/fonts/", "/images/"];
/// The words that name a method. A request header or body field whose last word (after
/// `-` or `.`, in lower case) is one of them may carry the interface name.
const METHOD_WORDS: [&str; 11] = [
    "method",
    "action",
    "operation",
    "op",
    "cmd",
    "command",
    "rpc",
    "func",
    "function",
    "service",
    "api",
];

const RAISE_JEV_TIMEOUT: &str = "raise_jev_timeout";
const RAISE_CALL_LIMIT: &str = "raise_call_limit";
const ENTRY_CANDIDATE: &str = "entry_candidate";
const BYPASS_CANDIDATE: &str = "bypass_candidate";
const UPLOAD_CANDIDATE: &str = "upload_candidate";
const SECRET_FIELD_CANDIDATE: &str = "secret_field_candidate";
const HOT_WOULD_BLOCK: &str = "hot_would_block";
const ROUTE_RULE_CANDIDATE: &str = "route_rule_candidate";
/// The order suggestions are listed in.
const RULE_ORDER: [&str; 8] = [
    RAISE_JEV_TIMEOUT,
    RAISE_CALL_LIMIT,
    ENTRY_CANDIDATE,
    BYPASS_CANDIDATE,
    UPLOAD_CANDIDATE,
    SECRET_FIELD_CANDIDATE,
    HOT_WOULD_BLOCK,
    ROUTE_RULE_CANDIDATE,
];

/// The judging limits a configuration applies, defaults included.
#[derive(Clone, Copy)]
pub(crate) struct Effective {
    pub(crate) jev_timeout_ms: u32,
    pub(crate) session_calls: u32,
    pub(crate) address_calls: u32,
    pub(crate) cache_minutes: u32,
}

impl Effective {
    /// The limits `spec` applies.
    #[must_use]
    pub(crate) fn of(spec: &SiteSpec) -> Self {
        let advanced = spec.advanced();
        Self {
            jev_timeout_ms: advanced.jev_timeout_ms_or(DEFAULT_JEV_TIMEOUT_MS),
            session_calls: advanced.session_calls_per_minute_or(DEFAULT_SESSION_CALLS),
            address_calls: advanced.address_calls_per_minute_or(DEFAULT_ADDRESS_CALLS),
            cache_minutes: advanced.allow_cache_minutes_or(DEFAULT_CACHE_MINUTES),
        }
    }
}

/// The 404 for a site that does not exist.
#[must_use]
pub(crate) fn site_not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "SITE_NOT_FOUND")
}

/// Whether a field called `field` is redacted under `spec`: its name holds a
/// built-in word or a word the site adds.
#[must_use]
pub(crate) fn redacts(spec: &SiteSpec, field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    BUILT_IN_SECRET_WORDS
        .iter()
        .any(|word| lower.contains(*word))
        || spec
            .advanced()
            .secret_fields()
            .iter()
            .any(|word| lower.contains(word.to_ascii_lowercase().as_str()))
}

/// The sum of the counts of the breakdown rows `keep` accepts.
#[must_use]
pub(crate) fn sum_rows(rows: &[Breakdown], keep: impl Fn(&Breakdown) -> bool) -> i64 {
    rows.iter()
        .filter(|row| keep(row))
        .map(|row| row.count)
        .sum()
}

/// Requests refused for `code` in `context` (`session` or `address`).
#[must_use]
pub(crate) fn refused_count(rows: &[Breakdown], context: &str, code: &str) -> i64 {
    sum_rows(rows, |row| {
        row.context.as_deref() == Some(context) && row.jev_failure.as_deref() == Some(code)
    })
}

/// Unredacted values in Jev states whose field location holds one of the words.
#[derive(Default)]
pub(crate) struct SecretScan {
    /// Calls with at least one such value.
    pub(crate) calls: i64,
    /// Such values.
    pub(crate) values: i64,
    /// Such values per field location.
    pub(crate) fields: BTreeMap<String, i64>,
    /// Per word: the calls and values that name it.
    pub(crate) words: BTreeMap<String, WordHit>,
}

/// The calls and values that name one word, and the newest request that did.
#[derive(Default)]
pub(crate) struct WordHit {
    pub(crate) calls: i64,
    pub(crate) values: i64,
    /// The id of the newest request whose Jev state named the word.
    pub(crate) sample: Option<String>,
}

/// Scans Jev states, given newest first with their request ids, for values that are
/// not redacted and whose field location contains one of `wanted` (lowercase words).
#[must_use]
pub(crate) fn scan_states(states: &[(String, String)], wanted: &[&str]) -> SecretScan {
    let mut scan = SecretScan::default();
    for (request_id, state) in states {
        let lower = state.to_ascii_lowercase();
        if !wanted.iter().any(|word| lower.contains(*word)) {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<Value>(state) else {
            continue;
        };
        let Some(values) = parsed.pointer("/request/values").and_then(Value::as_array) else {
            continue;
        };
        let mut hit_words: BTreeSet<&str> = BTreeSet::new();
        for item in values {
            let (Some(at), Some(value)) = (
                item.get("at").and_then(Value::as_str),
                item.get("value").and_then(Value::as_str),
            ) else {
                continue;
            };
            if value == REDACTED {
                continue;
            }
            let at_lower = at.to_ascii_lowercase();
            let mut named = false;
            for &word in wanted {
                if at_lower.contains(word) {
                    named = true;
                    hit_words.insert(word);
                    scan.words.entry(word.to_owned()).or_default().values += 1;
                }
            }
            if named {
                scan.values += 1;
                *scan.fields.entry(at.to_owned()).or_insert(0) += 1;
            }
        }
        if hit_words.is_empty() {
            continue;
        }
        scan.calls += 1;
        for word in hit_words {
            let hit = scan.words.entry(word.to_owned()).or_default();
            hit.calls += 1;
            if hit.sample.is_none() {
                hit.sample = Some(request_id.clone());
            }
        }
    }
    scan
}

/// `GET /api/sites/{name}/insights` (docs/07 section 7.9.11): the tuning suggestions
/// of the window and, in observe mode, the readiness check. `readiness` is null in
/// enforce mode, where nothing is left to observe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InsightsBody {
    pub window_hours: i64,
    pub suggestions: Vec<SuggestionBody>,
    pub readiness: Option<ReadinessBody>,
    pub complete: bool,
}

/// One suggestion: what it concerns, the requests behind it, and the ways to apply it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuggestionBody {
    /// The same suggestion keeps its id from one window to the next.
    pub id: String,
    pub kind: String,
    /// Null for a suggestion about a setting rather than about requests.
    pub method: Option<String>,
    pub path: Option<String>,
    pub count: i64,
    /// A request id to look at, when one is known.
    pub sample: Option<String>,
    pub actions: Vec<ActionBody>,
    pub reason: String,
}

/// One way to apply a suggestion. `matches` counts the requests the pattern covers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionBody {
    AddEntry {
        label: MatchLabel,
        add_entry: String,
        matches: i64,
    },
    AddBypass {
        label: MatchLabel,
        add_bypass: String,
        matches: i64,
    },
    /// A route rule that names the interface by one request field (`route_rule_candidate`).
    AddRoute {
        label: MatchLabel,
        add_route: RouteRuleBody,
        matches: i64,
    },
    AddSecretField {
        add_secret_field: String,
    },
    SetAdvanced {
        set_advanced: BTreeMap<String, i64>,
    },
}

/// Whether a pattern matches one path exactly, or every path under a prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchLabel {
    Exact,
    Prefix,
}

/// A route rule as the console reads and writes it (`RouteRule`, header-routes-design
/// section 2): the URL path it covers and, for each part of the interface name, the
/// sources the part is read from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRuleBody {
    /// An exact path, or a prefix ending in `*`; never ends with `/`.
    pub path: String,
    /// One group per part of the name, joined with `/`.
    pub name_from: Vec<Vec<String>>,
}

/// The readiness check of an observe-mode site (docs/07 section 7.9.11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadinessBody {
    /// When the site started observing, Unix milliseconds.
    pub observing_since_millis: i64,
    /// Requests observe mode would have refused, by the decision path that refused them.
    pub would_block: BTreeMap<String, i64>,
    pub open_suggestions: i64,
    /// `idle`, `ok`, `degraded` or `down`.
    pub jev_health: String,
    /// The 95th percentile of the window's Jev round trips, in whole milliseconds.
    pub jev_p95_ms: Option<i64>,
    /// Timeouts over calls, from 0 to 1; null when the window has no Jev call.
    pub jev_timeout_ratio: Option<f64>,
    /// How often a value learned from a would-be refused request was cited later.
    pub after_would_block_refs: i64,
    pub on_jev_unavailable: OnJevUnavailable,
}

/// `GET /api/sites/{name}/evidence` (docs/07 section 7.9.2): the Jev latency, timeouts,
/// call-limit peaks and hits, and cached allows of the last 24 hours.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBody {
    pub window_hours: i64,
    pub jev: JevEvidenceBody,
    pub call_limit: CallLimitEvidenceBody,
    pub cache: CacheEvidenceBody,
    /// Jev calls per latency bucket, each `histogram_bucket_ms` wide.
    pub histogram: Vec<i64>,
    pub histogram_bucket_ms: i64,
}

/// The Jev round trips of the window, and the timeout the site applies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevEvidenceBody {
    pub calls: i64,
    /// Latency percentiles in whole milliseconds; null when there is no call.
    pub p50_ms: Option<i64>,
    pub p95_ms: Option<i64>,
    pub p99_ms: Option<i64>,
    pub timeouts: i64,
    pub timeout_ms_used: u32,
}

/// The per-minute call limits: the busiest minute of each scope, and the calls refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallLimitEvidenceBody {
    pub session_peak: i64,
    pub address_peak: i64,
    pub session_hits: i64,
    pub address_hits: i64,
}

/// The allow cache: the requests it answered in the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEvidenceBody {
    pub cached_allows: i64,
}

/// A suggestion before it is sent. `key` names what it concerns (a pattern, a
/// word, a template or a setting). The id is made of the kind, the method and the
/// key, so the same suggestion keeps its id from one window to the next.
struct Draft {
    kind: &'static str,
    method: Option<String>,
    path: Option<String>,
    key: String,
    count: i64,
    sample: Option<String>,
    actions: Vec<ActionBody>,
    reason: String,
}

impl From<&Draft> for SuggestionBody {
    fn from(draft: &Draft) -> Self {
        Self {
            id: suggestion_id(
                draft.kind,
                draft.method.as_deref().unwrap_or(""),
                &draft.key,
            ),
            kind: draft.kind.to_owned(),
            method: draft.method.clone(),
            path: draft.path.clone(),
            count: draft.count,
            sample: draft.sample.clone(),
            actions: draft.actions.clone(),
            reason: draft.reason.clone(),
        }
    }
}

/// Requests summed under one suggestion: the count, the paths and methods they
/// touch, and an example from the largest group.
#[derive(Default)]
struct Total {
    count: i64,
    paths: BTreeSet<String>,
    methods: BTreeSet<String>,
    sample: Option<(i64, String)>,
}

impl Total {
    fn add(&mut self, method: &str, path: &str, count: i64, sample: &str) {
        self.count += count;
        self.paths.insert(path.to_owned());
        self.methods.insert(method.to_owned());
        if self.sample.as_ref().is_none_or(|(best, _)| count > *best) {
            self.sample = Some((count, sample.to_owned()));
        }
    }

    /// The method, when every request used the same one.
    fn method(&self) -> Option<String> {
        if self.methods.len() == 1 {
            self.methods.first().cloned()
        } else {
            None
        }
    }

    fn example(&self) -> Option<String> {
        self.sample.as_ref().map(|(_, id)| id.clone())
    }
}

/// One window of a site's decisions: the groups the readiness check reads, the
/// Jev totals, and the ranked suggestions.
struct Analysis {
    complete: bool,
    groups: Vec<PathGroup>,
    stats: JevStats,
    drafts: Vec<Draft>,
}

/// Reads one window of decisions and builds the ranked suggestions.
///
/// # Errors
/// A database failure is a 500.
async fn analyse(
    pool: &PgPool,
    site: &str,
    spec: &SiteSpec,
    hours: i64,
    now: i64,
) -> ApiResult<Analysis> {
    let scope = Scope {
        site: Some(site.to_owned()),
        since_millis: now - hours * HOUR_MILLIS,
        until_millis: now,
    };
    let (groups, mut complete) = decision_stats::path_groups(pool, &scope).await?;
    let rows = decision_stats::breakdown(pool, &scope).await?;
    let stats = decision_stats::jev_stats(pool, &scope).await?;
    let mut drafts: Vec<Draft> = Vec::new();
    drafts.extend(timeout_draft(pool, &scope, spec, &stats).await?);
    drafts.extend(call_limit_drafts(pool, &scope, &rows, spec).await?);
    drafts.extend(entry_drafts(&groups, spec));
    drafts.extend(bypass_drafts(&groups, spec));
    drafts.extend(upload_drafts(pool, &scope).await?);
    if stats.calls > 0 {
        drafts.extend(secret_drafts(pool, &scope, spec).await?);
    }
    drafts.extend(hot_drafts(&groups));
    let (routes, routes_complete) = route_rule_drafts(pool, site, &scope, &groups, spec).await?;
    drafts.extend(routes);
    complete &= routes_complete;
    Ok(Analysis {
        complete,
        groups,
        stats,
        drafts: ranked(drafts),
    })
}

/// The Jev timeout suggestion: timeouts at one call in a hundred or more, or p95
/// close to the timeout in use, with a recommended value above the current one.
async fn timeout_draft(
    pool: &PgPool,
    scope: &Scope,
    spec: &SiteSpec,
    stats: &JevStats,
) -> ApiResult<Option<Draft>> {
    let timeout = Effective::of(spec).jev_timeout_ms;
    let timeouts = stats.timeouts;
    let share_high = stats.calls > 0 && timeouts * 100 >= stats.calls;
    let p95_high = stats
        .p95_ms
        .is_some_and(|p95| p95 > 0.8 * f64::from(timeout));
    let Some(p99) = stats.p99_ms else {
        return Ok(None);
    };
    if !share_high && !p95_high {
        return Ok(None);
    }
    let recommended = round_up(p99 * 1.5, TIMEOUT_STEP_MS, TIMEOUT_MAX_MS);
    if recommended <= timeout {
        return Ok(None);
    }
    let share = timeouts
        .saturating_mul(100)
        .checked_div(stats.calls)
        .unwrap_or(0);
    Ok(Some(Draft {
        kind: RAISE_JEV_TIMEOUT,
        method: None,
        path: None,
        count: timeouts,
        sample: sample_request(pool, scope, JEV_TIMEOUT, None).await?,
        actions: vec![set_advanced("jev_timeout_ms", i64::from(recommended))],
        reason: format!(
            "Jev 超时 {timeouts} 次，占调用的 {share}%，或 p95 接近当前超时 {timeout} ms。推荐 {recommended} ms：p99 的 1.5 倍，向上取整到 500 ms。"
        ),
        key: "jev_timeout_ms".to_owned(),
    }))
}

/// The call-limit suggestions: a limit that refused calls rises to the highest
/// observed minute plus a fifth, at most 600. Session first, then address.
async fn call_limit_drafts(
    pool: &PgPool,
    scope: &Scope,
    rows: &[Breakdown],
    spec: &SiteSpec,
) -> ApiResult<Vec<Draft>> {
    let limits = Effective::of(spec);
    let scopes = [
        (
            "会话",
            "session_calls_per_minute",
            false,
            SESSION_CONTEXT,
            limits.session_calls,
        ),
        (
            "地址",
            "address_calls_per_minute",
            true,
            ADDRESS_CONTEXT,
            limits.address_calls,
        ),
    ];
    let mut drafts = Vec::new();
    for (label, setting, by_address, context, current) in scopes {
        let refused = refused_count(rows, context, JEV_CALL_LIMIT);
        if refused == 0 {
            continue;
        }
        let peaks =
            decision_stats::minute_peaks(pool, scope, by_address, i64::from(current)).await?;
        let recommended = recommended_calls(peaks.peak.max(i64::from(current)));
        if recommended <= i64::from(current) {
            continue;
        }
        drafts.push(Draft {
            kind: RAISE_CALL_LIMIT,
            method: None,
            path: None,
            count: refused,
            sample: sample_request(pool, scope, JEV_CALL_LIMIT, Some(context)).await?,
            actions: vec![set_advanced(setting, recommended)],
            reason: format!(
                "{label}级每分钟调用上限为 {current}，已有 {refused} 次调用被拒。推荐 {recommended}：观察到的最高每分钟调用数加 20%，不超过 600。若触发的是未登录页面的轮询，把接口登记为入口或绕过通常更合适。"
            ),
            key: setting.to_owned(),
        });
    }
    Ok(drafts)
}

/// Entry suggestions: refused requests without a session, per method and path.
/// When three or more sibling paths share a parent, a prefix is offered as well.
fn entry_drafts(groups: &[PathGroup], spec: &SiteSpec) -> Vec<Draft> {
    let mut paths: BTreeMap<(String, String), Total> = BTreeMap::new();
    let mut parents: BTreeMap<String, Total> = BTreeMap::new();
    for group in groups.iter().filter(|group| {
        group.decision_path == NO_SESSION
            && !is_static_path(&group.path)
            && !spec.is_entry(&group.path)
    }) {
        paths
            .entry((group.method.clone(), group.path.clone()))
            .or_default()
            .add(&group.method, &group.path, group.count, &group.sample);
        parents
            .entry(parent_dir(&group.path).to_owned())
            .or_default()
            .add(&group.method, &group.path, group.count, &group.sample);
    }
    paths
        .into_iter()
        .map(|((method, path), total)| {
            let parent = parent_dir(&path);
            let mut actions = vec![ActionBody::AddEntry {
                label: MatchLabel::Exact,
                add_entry: path.clone(),
                matches: total.count,
            }];
            let mut reason =
                "无会话的请求被拒绝。登记为入口后，这类请求改为按地址判定。".to_owned();
            if let Some(family) = parents
                .get(parent)
                .filter(|family| !parent.is_empty() && family.paths.len() >= PREFIX_MIN_PATHS)
            {
                actions.push(ActionBody::AddEntry {
                    label: MatchLabel::Prefix,
                    add_entry: format!("{parent}/*"),
                    matches: family.count,
                });
                let _ = write!(
                    reason,
                    "同一父路径下有 {} 个路径；前缀入口会放大无会话可达的范围。",
                    family.paths.len()
                );
            }
            Draft {
                kind: ENTRY_CANDIDATE,
                method: Some(method),
                path: Some(path.clone()),
                count: total.count,
                sample: total.example(),
                actions,
                reason,
                key: path,
            }
        })
        .collect()
}

/// Bypass suggestions for static resources. A directory becomes a prefix, a
/// root-level bundle with two or more files becomes `/name-*`, and any other
/// root-level file is listed alone.
fn bypass_drafts(groups: &[PathGroup], spec: &SiteSpec) -> Vec<Draft> {
    let candidates: Vec<&PathGroup> = groups
        .iter()
        .filter(|group| group.decision_path != BYPASS && group.decision_path != UNKNOWN_SITE)
        .filter(|group| is_static_path(&group.path) && !spec.is_bypass(&group.path))
        .collect();
    let mut bundles: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for group in &candidates {
        if let Some(bundle) = root_bundle_prefix(&group.path) {
            bundles.entry(bundle).or_default().insert(&group.path);
        }
    }
    let mut totals: BTreeMap<String, (bool, Total)> = BTreeMap::new();
    for group in candidates {
        let bundle = root_bundle_prefix(&group.path).filter(|bundle| {
            bundles
                .get(bundle)
                .is_some_and(|files| files.len() >= ROOT_BUNDLE_MIN_FILES)
        });
        let (pattern, prefix) = match (bundle, parent_dir(&group.path)) {
            (Some(bundle), _) => (format!("{bundle}-*"), true),
            (None, "") => (group.path.clone(), false),
            (None, dir) => (format!("{dir}/*"), true),
        };
        totals
            .entry(pattern)
            .or_insert_with(|| (prefix, Total::default()))
            .1
            .add(&group.method, &group.path, group.count, &group.sample);
    }
    totals
        .into_iter()
        .map(|(pattern, (prefix, total))| {
            let label = if prefix {
                MatchLabel::Prefix
            } else {
                MatchLabel::Exact
            };
            Draft {
                kind: BYPASS_CANDIDATE,
                method: total.method(),
                path: Some(pattern.clone()),
                count: total.count,
                sample: total.example(),
                actions: vec![ActionBody::AddBypass {
                    label,
                    add_bypass: pattern.clone(),
                    matches: total.count,
                }],
                reason: format!(
                    "静态资源，涉及 {} 个路径，合并为 {pattern}。绕过后这些请求不再判定。",
                    total.paths.len()
                ),
                key: pattern,
            }
        })
        .collect()
}

/// Upload suggestions: requests whose body the edge could not inspect. Bypassing
/// them ends the authorization check on that endpoint, and the reason says so.
async fn upload_drafts(pool: &PgPool, scope: &Scope) -> ApiResult<Vec<Draft>> {
    let groups = decision_stats::refused_groups(pool, scope, BODY_NOT_INSPECTABLE).await?;
    Ok(groups
        .into_iter()
        .map(
            |RefusedGroup {
                 method,
                 path,
                 count,
                 sample,
             }| Draft {
                kind: UPLOAD_CANDIDATE,
                method: Some(method),
                path: Some(path.clone()),
                count,
                sample: Some(sample),
                actions: vec![ActionBody::AddBypass {
                    label: MatchLabel::Exact,
                    add_bypass: path.clone(),
                    matches: count,
                }],
                reason: "请求体无法检查（过大或长度未知）。加入绕过后，该接口不做越权判定。"
                    .to_owned(),
                key: path,
            },
        )
        .collect())
}

/// Sensitive personal fields that reached Jev unredacted: the words to add to
/// `secret_fields`. Jev states are read only when such a word is not yet covered.
/// The example is the newest request whose Jev state held such a value.
async fn secret_drafts(pool: &PgPool, scope: &Scope, spec: &SiteSpec) -> ApiResult<Vec<Draft>> {
    let candidates: Vec<&str> = SENSITIVE_WORDS
        .into_iter()
        .filter(|word| !redacts(spec, word))
        .collect();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let states = decision_stats::jev_state_rows(pool, scope).await?;
    let scan = scan_states(&states, &candidates);
    Ok(scan
        .words
        .into_iter()
        .filter(|(_, hit)| hit.calls > 0)
        .map(|(word, hit)| Draft {
            kind: SECRET_FIELD_CANDIDATE,
            method: None,
            path: None,
            count: hit.calls,
            sample: hit.sample,
            actions: vec![ActionBody::AddSecretField {
                add_secret_field: word.clone(),
            }],
            reason: format!(
                "字段 {word} 的值未脱敏（{} 次 Jev 调用，{} 个值）。加入 secret_fields 后这些值不再发给 Jev；Jev 无法据此判断越权。",
                hit.calls, hit.values
            ),
            key: word,
        })
        .collect())
}

/// The most-would-blocked path templates, per method. They carry no configuration
/// action; the console links them to the filtered request list.
fn hot_drafts(groups: &[PathGroup]) -> Vec<Draft> {
    let mut templates: BTreeMap<(String, String), Total> = BTreeMap::new();
    for group in groups.iter().filter(|group| group.outcome == WOULD_BLOCK) {
        let template = path_template(&group.path);
        templates
            .entry((group.method.clone(), template.clone()))
            .or_default()
            .add(&group.method, &template, group.count, &group.sample);
    }
    let mut ranked_templates: Vec<((String, String), Total)> = templates.into_iter().collect();
    ranked_templates.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
    ranked_templates
        .into_iter()
        .take(HOT_TEMPLATES)
        .map(|((method, path), total)| Draft {
            kind: HOT_WOULD_BLOCK,
            method: Some(method),
            path: Some(path.clone()),
            count: total.count,
            sample: total.example(),
            actions: Vec::new(),
            reason: "本应拦截次数最多的路径模板。不提供配置动作，可打开筛选后的请求列表查看。"
                .to_owned(),
            key: path,
        })
        .collect()
}

/// Route rule suggestions (docs/header-routes-design section 5). A path with enough
/// requests in the window, and no route of the site covering it, may name its
/// interface by one field of its requests: a request header, or a JSON or form body
/// field, whose name reads like a method. Returns the drafts, and whether the scan
/// read every request of the candidate paths.
///
/// # Errors
/// A database failure is a 500.
async fn route_rule_drafts(
    pool: &PgPool,
    site: &str,
    scope: &Scope,
    groups: &[PathGroup],
    spec: &SiteSpec,
) -> ApiResult<(Vec<Draft>, bool)> {
    let mut totals: BTreeMap<String, Total> = BTreeMap::new();
    for group in groups {
        totals.entry(group.path.clone()).or_default().add(
            &group.method,
            &group.path,
            group.count,
            &group.sample,
        );
    }
    let eligible: Vec<(&String, &Total)> = totals
        .iter()
        .filter(|(path, total)| route_path_eligible(spec, path, total.count))
        .collect();
    let requests: i64 = eligible.iter().map(|(_, total)| total.count).sum();
    let complete = requests <= ROUTE_SCAN_LIMIT;
    if eligible.is_empty() {
        return Ok((Vec::new(), complete));
    }
    let paths: Vec<String> = eligible.iter().map(|(path, _)| (*path).clone()).collect();
    let Ok(document) = serde_json::to_value(spec) else {
        return Ok((Vec::new(), complete));
    };
    let headers = header_field_rows(pool, site, scope, &paths).await?;
    let bodies = body_field_rows(pool, site, scope, &paths).await?;
    let mut fields = field_sources(&headers, &bodies);
    let drafts: Vec<Draft> = totals
        .iter()
        .filter_map(|(path, total)| {
            route_rule_draft(
                spec,
                &document,
                path,
                total,
                fields.remove(path).unwrap_or_default(),
            )
        })
        .collect();
    Ok((drafts, complete))
}

/// A field a route rule could name a path's interface by, and the requests that carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteField {
    /// The route source: `header.<name>` or `body.<keys>`.
    source: String,
    /// Requests of the window on the path that carry the field.
    matches: i64,
}

/// The route rule suggestion for one path, or `None` when no field of the path can name
/// its interface. A field is kept only when the gateway would save the site with its
/// rule, so no suggestion offers a rule the gateway refuses. The most frequent fields
/// come first, ties by source, and at most `ROUTE_FIELDS_PER_PATH` are offered.
fn route_rule_draft(
    spec: &SiteSpec,
    document: &Value,
    path: &str,
    total: &Total,
    mut fields: Vec<RouteField>,
) -> Option<Draft> {
    if !route_path_eligible(spec, path, total.count) {
        return None;
    }
    fields.retain(|field| {
        route_would_save(
            document,
            &RouteRuleBody {
                path: path.to_owned(),
                name_from: vec![vec![field.source.clone()]],
            },
        )
    });
    fields.sort_by(|a, b| {
        b.matches
            .cmp(&a.matches)
            .then_with(|| a.source.cmp(&b.source))
    });
    fields.truncate(ROUTE_FIELDS_PER_PATH);
    if fields.is_empty() {
        return None;
    }
    let actions = fields
        .into_iter()
        .map(|field| ActionBody::AddRoute {
            label: MatchLabel::Exact,
            add_route: RouteRuleBody {
                path: path.to_owned(),
                name_from: vec![vec![field.source]],
            },
            matches: field.matches,
        })
        .collect();
    Some(Draft {
        kind: ROUTE_RULE_CANDIDATE,
        method: None,
        path: Some(path.to_owned()),
        count: total.count,
        sample: total.example(),
        actions,
        reason: "同一路径的请求带有类似方法名的请求头或正文字段，可能是统一网关；选定一个字段写成路由规则后，各接口可分别判定。"
            .to_owned(),
        key: path.to_owned(),
    })
}

/// Whether a path may take a route rule of its own: enough requests, a path the gateway
/// matches at all and that is exact (no `*`), not bypassed, and no route of the site
/// covering it. A route names the interface of the path's requests, which would move an
/// exact bypass off them.
#[must_use]
fn route_path_eligible(spec: &SiteSpec, path: &str, requests: i64) -> bool {
    requests >= ROUTE_RULE_MIN_REQUESTS
        && !path.contains('*')
        && is_plain_path(path)
        && !spec.is_bypass(path)
        && !spec.routes().iter().any(|route| route.path().matches(path))
}

/// Whether the gateway would save the site, as `document` (the site as JSON), with one
/// more route. The check is the one a write of the site runs, so the route's syntax, the
/// route count and any overlap with the site's other routes are all checked.
#[must_use]
fn route_would_save(document: &Value, rule: &RouteRuleBody) -> bool {
    let Ok(rule) = serde_json::to_value(rule) else {
        return false;
    };
    let mut document = document.clone();
    let Some(routes) = document
        .as_object_mut()
        .map(|object| {
            object
                .entry("routes")
                .or_insert_with(|| Value::Array(Vec::new()))
        })
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    routes.push(rule);
    SiteSpec::from_value(&document).is_ok()
}

/// Whether a word is a method word, in any case.
#[must_use]
fn method_word(word: &str) -> bool {
    METHOD_WORDS.contains(&word.to_ascii_lowercase().as_str())
}

/// Whether a request header name names a method: its last `-` word is a method word.
#[must_use]
fn method_header(name: &str) -> bool {
    name.rsplit('-').next().is_some_and(method_word)
}

/// The route source of a body field, `body.<keys>`, when its last key is a method word.
/// `location` is where the trace records the value (`body.params.method`) and `key` the
/// name it travels under. The two agree when the name is not dotted and not under an
/// array, the only fields a route source can name.
#[must_use]
fn body_source(location: &str, key: Option<&str>) -> Option<String> {
    let keys = location.strip_prefix("body.")?;
    let last = keys.rsplit('.').next()?;
    (key == Some(last) && method_word(last)).then(|| format!("body.{keys}"))
}

/// The fields each path could be named by, from the header and body rows the scan read.
/// A body field whose values are all numbers is left out: the trace keeps a number and a
/// string alike, and the route parser refuses a number as a name.
fn field_sources(
    headers: &[(String, String, i64)],
    bodies: &[(String, String, Option<String>, i64, i64)],
) -> BTreeMap<String, Vec<RouteField>> {
    let mut fields: BTreeMap<String, Vec<RouteField>> = BTreeMap::new();
    for (path, name, requests) in headers.iter().filter(|(_, name, _)| method_header(name)) {
        fields.entry(path.clone()).or_default().push(RouteField {
            source: format!("header.{name}"),
            matches: *requests,
        });
    }
    for (path, location, key, requests, _) in bodies.iter().filter(|row| row.4 > 0) {
        if let Some(source) = body_source(location, key.as_deref()) {
            fields.entry(path.clone()).or_default().push(RouteField {
                source,
                matches: *requests,
            });
        }
    }
    fields
}

/// The regular expression of the header names whose last `-` word is a method word.
fn method_header_pattern() -> String {
    format!("(^|-)({})$", METHOD_WORDS.join("|"))
}

/// The regular expression of the body locations whose last key is a method word.
fn method_body_pattern() -> String {
    format!(r"^body\.(.*\.)?({})$", METHOD_WORDS.join("|"))
}

/// The header names of the newest `ROUTE_SCAN_LIMIT` requests of `paths` in the window
/// that end in a method word, with the requests that carry each: `(path, name, requests)`.
async fn header_field_rows(
    pool: &PgPool,
    site: &str,
    scope: &Scope,
    paths: &[String],
) -> Result<Vec<(String, String, i64)>, sqlx::Error> {
    sqlx::query_as::<_, (String, String, i64)>(
        "WITH recent AS (
             SELECT id, path, request_headers FROM decision_log
             WHERE site = $1 AND at_millis >= $2 AND at_millis <= $3 AND path = ANY($4)
             ORDER BY at_millis DESC LIMIT $5
         )
         SELECT recent.path, h.name, count(DISTINCT recent.id)
         FROM recent CROSS JOIN LATERAL unnest(recent.request_headers) AS h(name)
         WHERE h.name ~* $6
         GROUP BY recent.path, h.name",
    )
    .bind(site)
    .bind(scope.since_millis)
    .bind(scope.until_millis)
    .bind(paths.to_vec())
    .bind(ROUTE_SCAN_LIMIT)
    .bind(method_header_pattern())
    .fetch_all(pool)
    .await
}

/// The body fields of the newest `ROUTE_SCAN_LIMIT` requests of `paths` in the window
/// whose location ends in a method word: `(path, location, key, requests, named)`, where
/// `named` counts the requests whose value is not a number. The location and the key
/// are as the trace records them (`body.params.method`, `method`).
async fn body_field_rows(
    pool: &PgPool,
    site: &str,
    scope: &Scope,
    paths: &[String],
) -> Result<Vec<(String, String, Option<String>, i64, i64)>, sqlx::Error> {
    // The key list is the cheap filter on the expanded values; the location pattern then
    // makes the match exact, as `body_source` checks it.
    sqlx::query_as::<_, (String, String, Option<String>, i64, i64)>(
        "WITH recent AS (
             SELECT id, path, trace FROM decision_log
             WHERE site = $1 AND at_millis >= $2 AND at_millis <= $3 AND path = ANY($4)
             ORDER BY at_millis DESC LIMIT $5
         ),
         fields AS (
             SELECT recent.id, recent.path, item ->> 'at' AS at_location,
                    item ->> 'key' AS field_key, item ->> 'value' AS field_value
             FROM recent
             CROSS JOIN LATERAL jsonb_array_elements(
                 CASE WHEN jsonb_typeof(recent.trace -> 'values') = 'array'
                      THEN recent.trace -> 'values' ELSE '[]'::jsonb END
             ) AS v(item)
             WHERE lower(item ->> 'key') = ANY($6)
         )
         SELECT path, at_location, field_key,
                count(DISTINCT id),
                count(DISTINCT id) FILTER (WHERE field_value !~ '^-?[0-9.]+$')
         FROM fields
         WHERE at_location ~* $7
         GROUP BY path, at_location, field_key",
    )
    .bind(site)
    .bind(scope.since_millis)
    .bind(scope.until_millis)
    .bind(paths.to_vec())
    .bind(ROUTE_SCAN_LIMIT)
    .bind(METHOD_WORDS.to_vec())
    .bind(method_body_pattern())
    .fetch_all(pool)
    .await
}

/// One request id of `code` in the window, in `context` when one is given.
async fn sample_request(
    pool: &PgPool,
    scope: &Scope,
    code: &str,
    context: Option<&str>,
) -> ApiResult<Option<String>> {
    let filter = RequestFilter {
        site: scope.site.clone(),
        since_millis: scope.since_millis,
        until_millis: scope.until_millis,
        jev_failure: Some(code.to_owned()),
        include_unjudged: true,
        ..Default::default()
    };
    let rows = decision_log_store::list(pool, &filter, None, 50).await?;
    Ok(rows
        .into_iter()
        .find(|row| context.is_none_or(|wanted| row.context.as_deref() == Some(wanted)))
        .map(|row| row.request_id))
}

/// An action that sets one advanced parameter of the site.
#[must_use]
fn set_advanced(key: &str, value: i64) -> ActionBody {
    ActionBody::SetAdvanced {
        set_advanced: BTreeMap::from([(key.to_owned(), value)]),
    }
}

/// Orders suggestions by rule, then by count, and keeps `SUGGESTIONS_PER_RULE`
/// of each rule.
fn ranked(mut drafts: Vec<Draft>) -> Vec<Draft> {
    drafts.sort_by(|a, b| {
        rule_rank(a.kind)
            .cmp(&rule_rank(b.kind))
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.key.cmp(&b.key))
    });
    let mut kept: BTreeMap<&str, usize> = BTreeMap::new();
    drafts.retain(|draft| {
        let seen = kept.entry(draft.kind).or_insert(0);
        *seen += 1;
        *seen <= SUGGESTIONS_PER_RULE
    });
    drafts
}

fn rule_rank(kind: &str) -> usize {
    RULE_ORDER
        .iter()
        .position(|rule| *rule == kind)
        .unwrap_or(usize::MAX)
}

/// A stable id: `FNV-1a` over the kind, the method and the key, separated by unit
/// separators so that different splits cannot collide.
#[must_use]
fn suggestion_id(kind: &str, method: &str, key: &str) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let hash = [kind, method, key]
        .iter()
        .flat_map(|part| part.bytes().chain([0x1f]))
        .fold(OFFSET, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(PRIME)
        });
    format!("{hash:016x}")
}

/// Whether a path names a static resource: a static extension, or a path under a
/// static directory at the top of the site.
#[must_use]
fn is_static_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    STATIC_DIRS.iter().any(|dir| lower.starts_with(*dir))
        || STATIC_EXTENSIONS.iter().any(|ext| lower.ends_with(*ext))
}

/// The path with its identifier segments replaced by `{id}`.
#[must_use]
fn path_template(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if is_identifier(segment) {
                "{id}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// A number, a run of eight or more hex digits, or a UUID.
fn is_identifier(segment: &str) -> bool {
    let numeric = !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit());
    let hex = segment.len() >= 8 && segment.bytes().all(|byte| byte.is_ascii_hexdigit());
    let uuid = segment.len() == 36
        && segment
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            });
    numeric || hex || uuid
}

/// The directory part of a path: `/a/b/c.js` gives `/a/b`, `/c.js` gives `""`.
#[must_use]
fn parent_dir(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// The bundle of a root-level packaged file: `/chunk-ABC.js` is in `/chunk`.
#[must_use]
fn root_bundle_prefix(path: &str) -> Option<&str> {
    let name = path.strip_prefix('/')?;
    if name.contains('/') {
        return None;
    }
    let (prefix, _) = name.split_once('-')?;
    path.get(..=prefix.len()).filter(|bundle| bundle.len() > 1)
}

/// `value` rounded up to a multiple of `step`, at most `max`.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn round_up(value: f64, step: u32, max: u32) -> u32 {
    let steps = (value / f64::from(step)).ceil();
    ((steps * f64::from(step)) as u32).min(max)
}

/// The recommended per-minute limit: the highest observed minute plus a fifth, at
/// least one and at most `CALL_LIMIT_MAX`.
#[must_use]
fn recommended_calls(peak: i64) -> i64 {
    let peak = u64::try_from(peak).unwrap_or(0);
    i64::try_from(peak + peak.div_ceil(5))
        .unwrap_or(i64::MAX)
        .clamp(1, CALL_LIMIT_MAX)
}

/// Jev latency counts per 100 ms from 0 to 30 s, from the `width_bucket` rows of
/// `decision_stats::jev_latency_histogram` (bucket 1 is 0 to 100 ms; bucket 301
/// holds 30 s and over, and the last slot takes it).
#[must_use]
fn histogram_counts(buckets: &[(i32, i64)]) -> Vec<i64> {
    let mut counts = vec![0_i64; HISTOGRAM_BUCKETS];
    for &(bucket, count) in buckets {
        let Some(index) = bucket
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
        else {
            continue;
        };
        if let Some(slot) = counts.get_mut(index.min(HISTOGRAM_BUCKETS - 1)) {
            *slot += count;
        }
    }
    counts
}

/// Walks a site's versions newest first and remembers where the newest run of
/// observe-mode versions began.
#[derive(Debug, Default)]
struct ObserveRun {
    /// Whether the walk has reached an observe-mode version yet.
    inside: bool,
    /// When the oldest observe-mode version seen so far was recorded.
    since: Option<DateTime<Utc>>,
}

impl ObserveRun {
    /// Takes the next version, which is older than the ones before it. Returns `false`
    /// once the walk has left the run.
    fn take(&mut self, entry: &HistoryEntry) -> bool {
        if entry
            .spec
            .as_ref()
            .is_some_and(|spec| spec.mode() == Mode::Observe)
        {
            self.inside = true;
            self.since = Some(entry.changed_at);
            true
        } else {
            !self.inside
        }
    }
}

/// When observing began: the start of the newest run of observe-mode versions, or
/// `None` when the site never observed. Versions are read newest first, a page at a
/// time, and the walk stops at the first version outside the run, so the answer does
/// not depend on how much history the site has.
async fn observing_since(pool: &PgPool, name: &str) -> ApiResult<Option<DateTime<Utc>>> {
    let mut run = ObserveRun::default();
    let mut before = None;
    loop {
        let page = site_spec_store::history(pool, name, before, OBSERVE_PAGE).await?;
        let Some(oldest) = page.last() else {
            return Ok(run.since);
        };
        if !page.iter().all(|entry| run.take(entry)) {
            return Ok(run.since);
        }
        before = Some(oldest.version);
    }
}

/// The readiness check before observe mode is switched to enforce: when observing
/// began, what observe mode would have refused by decision path, the Jev health,
/// and how often values learned from would-be refused requests were cited later.
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
async fn readiness_of(
    pool: &PgPool,
    record: &SiteRecord,
    analysis: &Analysis,
    hours: i64,
    now: i64,
) -> ApiResult<ReadinessBody> {
    let name = record.spec.name();
    let since = observing_since(pool, name)
        .await?
        .unwrap_or(record.created_at);
    let mut would_block: BTreeMap<String, i64> = BTreeMap::new();
    for group in analysis
        .groups
        .iter()
        .filter(|group| group.outcome == WOULD_BLOCK)
    {
        *would_block.entry(group.decision_path.clone()).or_insert(0) += group.count;
    }
    let stats = &analysis.stats;
    let last = decision_stats::last_calls(pool, 5).await?;
    let health = health_of(
        stats.calls,
        stats.calls - stats.ok,
        whole_ms(stats.p95_ms),
        i64::from(Effective::of(&record.spec).jev_timeout_ms),
        last.len() == 5 && last.iter().all(Option::is_some),
    );
    let refs =
        decision_stats::after_would_block_references(pool, name, now - hours * HOUR_MILLIS).await?;
    let ratio = (stats.calls > 0).then(|| stats.timeouts as f64 / stats.calls as f64);
    Ok(ReadinessBody {
        observing_since_millis: since.timestamp_millis(),
        would_block,
        open_suggestions: i64::try_from(analysis.drafts.len()).unwrap_or(i64::MAX),
        jev_health: health.as_str().to_owned(),
        jev_p95_ms: whole_ms(stats.p95_ms),
        jev_timeout_ratio: ratio,
        after_would_block_refs: refs,
        on_jev_unavailable: record.spec.on_jev_unavailable(),
    })
}

/// A latency in whole milliseconds, rounded the way the API reports them (docs/07
/// section 7.9.2).
#[allow(clippy::cast_possible_truncation)]
fn whole_ms(ms: Option<f64>) -> Option<i64> {
    ms.map(|ms| ms.round() as i64)
}

/// The `window_hours` parameter: a whole number of hours from 1 to 168, 24 by
/// default.
///
/// # Errors
/// `INVALID_FILTER` naming `window_hours` when it is not such a number.
fn window_hours(params: &Params) -> ApiResult<i64> {
    let hours = params.int("window_hours")?.unwrap_or(DEFAULT_WINDOW_HOURS);
    if (1..=MAX_WINDOW_HOURS).contains(&hours) {
        Ok(hours)
    } else {
        Err(ApiError::invalid_filter("window_hours"))
    }
}

/// Tuning suggestions and the readiness check for one site (docs/07 section 7.9.11).
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, `INVALID_FILTER` for a bad `window_hours`,
/// and a 500 when a query fails.
pub async fn insights(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<InsightsBody>> {
    let hours = window_hours(&Params::from(query))?;
    let now = now_millis();
    let record = site_spec_store::get(&state.pool, &name)
        .await?
        .ok_or_else(site_not_found)?;
    let analysis = analyse(&state.pool, &name, &record.spec, hours, now).await?;
    let readiness = match record.spec.mode() {
        Mode::Observe => Some(readiness_of(&state.pool, &record, &analysis, hours, now).await?),
        Mode::Enforce => None,
    };
    Ok(Json(InsightsBody {
        window_hours: hours,
        suggestions: analysis.drafts.iter().map(SuggestionBody::from).collect(),
        readiness,
        complete: analysis.complete,
    }))
}

/// The evidence shown beside the judging parameters: the last 24 hours of Jev
/// latency, timeouts, call-limit hits and peaks, and cached allows (docs/07
/// section 7.9.2).
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, and a 500 when a query fails.
#[allow(clippy::similar_names)] // `stats` holds the Jev totals; `state` is the app state.
pub async fn evidence(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<EvidenceBody>> {
    let record = site_spec_store::get(&state.pool, &name)
        .await?
        .ok_or_else(site_not_found)?;
    let pool = &state.pool;
    let now = now_millis();
    let limits = Effective::of(&record.spec);
    let scope = Scope {
        site: Some(name),
        since_millis: now - EVIDENCE_WINDOW_HOURS * HOUR_MILLIS,
        until_millis: now,
    };
    let stats = decision_stats::jev_stats(pool, &scope).await?;
    let histogram = decision_stats::jev_latency_histogram(pool, &scope).await?;
    let rows = decision_stats::breakdown(pool, &scope).await?;
    let session_peak =
        decision_stats::minute_peaks(pool, &scope, false, i64::from(limits.session_calls))
            .await?
            .peak;
    let address_peak =
        decision_stats::minute_peaks(pool, &scope, true, i64::from(limits.address_calls))
            .await?
            .peak;
    let session_hits = refused_count(&rows, SESSION_CONTEXT, JEV_CALL_LIMIT);
    let address_hits = refused_count(&rows, ADDRESS_CONTEXT, JEV_CALL_LIMIT);
    let cached_allows = sum_rows(&rows, |row| row.decision_path == CACHED_ALLOW);
    Ok(Json(EvidenceBody {
        window_hours: EVIDENCE_WINDOW_HOURS,
        jev: JevEvidenceBody {
            calls: stats.calls,
            p50_ms: whole_ms(stats.p50_ms),
            p95_ms: whole_ms(stats.p95_ms),
            p99_ms: whole_ms(stats.p99_ms),
            timeouts: stats.timeouts,
            timeout_ms_used: limits.jev_timeout_ms,
        },
        call_limit: CallLimitEvidenceBody {
            session_peak,
            address_peak,
            session_hits,
            address_hits,
        },
        cache: CacheEvidenceBody { cached_allows },
        histogram: histogram_counts(&histogram),
        histogram_bucket_ms: HISTOGRAM_BUCKET_MS,
    }))
}

/// The number of suggestions `insights` lists for the default window, from the same
/// analysis. The site list and the site detail show it.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, and a 500 when a query fails.
pub(crate) async fn pending_suggestions(
    pool: &PgPool,
    site: &str,
    now_millis: i64,
) -> Result<i64, ApiError> {
    let record = site_spec_store::get(pool, site)
        .await?
        .ok_or_else(site_not_found)?;
    let analysis = analyse(pool, site, &record.spec, DEFAULT_WINDOW_HOURS, now_millis).await?;
    Ok(i64::try_from(analysis.drafts.len()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;
    use serde_json::json;
    use sqlx::{AssertSqlSafe, postgres::PgPoolOptions};
    use xshield_postgres::{decision_log_store::NewDecision, partitions::ensure_partition};

    use super::*;

    #[test]
    fn paths_become_templates_and_static_bundles() {
        assert_eq!(path_template("/api/patients/8"), "/api/patients/{id}");
        assert_eq!(
            path_template("/files/3f2504e0-4f89-11d3-9a0c-0305e82c3301/x"),
            "/files/{id}/x"
        );
        assert!(is_static_path("/assets/i18n/en.json"));
        assert!(is_static_path("/main.abc123.js"));
        assert!(!is_static_path("/api/assets/7"));
        assert_eq!(root_bundle_prefix("/chunk-ABC.js"), Some("/chunk"));
        assert_eq!(root_bundle_prefix("/a/chunk-1.js"), None);
        assert_eq!(root_bundle_prefix("/main.js"), None);
    }

    #[test]
    fn limits_and_timeouts_round_as_documented() {
        assert_eq!(recommended_calls(60), 72);
        assert_eq!(recommended_calls(600), 600);
        assert_eq!(round_up(1400.0, 500, 30_000), 1500);
        assert_eq!(round_up(43_500.0, 500, 30_000), 30_000);
    }

    #[test]
    fn suggestion_ids_are_stable_and_distinct_by_key() {
        let first = suggestion_id("bypass_candidate", "", "/assets/*");
        assert_eq!(first, suggestion_id("bypass_candidate", "", "/assets/*"));
        assert_ne!(first, suggestion_id("bypass_candidate", "", "/static/*"));
        assert_eq!(first.len(), 16);
    }

    #[test]
    fn scans_find_unredacted_values_by_field_location() {
        let state = r#"{"request":{"values":[{"at":"body.idcard","value":"1101"},{"at":"body.note","value":"ok"},{"at":"body.ssn","value":"<redacted>"}]}}"#;
        let states = [("req_0123".to_owned(), state.to_owned())];
        let scan = scan_states(&states, &["idcard", "ssn"]);
        assert_eq!(scan.calls, 1);
        assert_eq!(scan.values, 1);
        assert_eq!(scan.words["idcard"].calls, 1);
        assert_eq!(scan.words["idcard"].sample.as_deref(), Some("req_0123"));
        assert!(!scan.words.contains_key("ssn"));
    }

    /// `observing_since`'s walk over versions given newest first and read `page` at
    /// a time.
    fn since_read_in_pages(newest_first: &[HistoryEntry], page: usize) -> Option<DateTime<Utc>> {
        let mut run = ObserveRun::default();
        for chunk in newest_first.chunks(page) {
            if !chunk.iter().all(|entry| run.take(entry)) {
                break;
            }
        }
        run.since
    }

    #[test]
    fn observing_began_with_the_newest_run_of_observe_versions() {
        use xshield_postgres::site_spec_store::Change;

        // A version that holds a configuration in `mode`, or a delete for `None`.
        fn version(number: i64, mode: Option<&str>) -> HistoryEntry {
            HistoryEntry {
                version: number,
                change: Change::Update,
                rollback_of: None,
                note: None,
                changed_at: DateTime::from_timestamp_millis(number * 1_000).expect("time"),
                spec: mode.map(|mode| {
                    SiteSpec::from_json(&format!(
                        r#"{{"name": "emr", "hosts": ["emr.example.com"],
                            "origin": "http://10.0.0.5:8080",
                            "session": {{"cookie": "SESSIONID"}},
                            "entries": ["/login"], "mode": "{mode}"}}"#
                    ))
                    .expect("test spec")
                }),
            }
        }
        let at = |number: i64| DateTime::from_timestamp_millis(number * 1_000);
        // Newest first, as the database returns them.
        let cases = [
            (
                vec![
                    version(3, Some("observe")),
                    version(2, Some("observe")),
                    version(1, Some("enforce")),
                ],
                at(2),
            ),
            (
                vec![
                    version(3, Some("enforce")),
                    version(2, Some("observe")),
                    version(1, Some("observe")),
                ],
                at(1),
            ),
            (
                vec![version(2, Some("enforce")), version(1, Some("enforce"))],
                None,
            ),
            (vec![version(1, Some("observe"))], at(1)),
            (
                vec![
                    version(3, Some("observe")),
                    version(2, None),
                    version(1, Some("observe")),
                ],
                at(3),
            ),
            (Vec::new(), None),
        ];
        for (history, expected) in &cases {
            // The answer must not depend on how the history is paged.
            for page in 1..=4 {
                assert_eq!(since_read_in_pages(history, page), *expected, "page {page}");
            }
        }
    }

    /// A site with the given routes (rules as JSON, comma separated), for the route tests.
    fn site_with_routes(routes: &str) -> SiteSpec {
        SiteSpec::from_json(&format!(
            r#"{{"name": "gw", "hosts": ["gw.example.com"], "origin": "http://10.0.0.5:8080",
                "session": {{"cookie": "SESSIONID"}}, "entries": ["/login"],
                "routes": [{routes}]}}"#
        ))
        .expect("test spec")
    }

    /// `requests` requests on `/api/rpc`, with `req_0` as the example.
    fn requests_on_rpc(requests: i64) -> Total {
        let mut total = Total::default();
        total.add("POST", "/api/rpc", requests, "req_0");
        total
    }

    fn field(source: &str, matches: i64) -> RouteField {
        RouteField {
            source: source.to_owned(),
            matches,
        }
    }

    /// The route source and the matched requests of each action of `draft`.
    fn offered(draft: &Draft) -> Vec<(String, i64)> {
        draft
            .actions
            .iter()
            .map(|action| match action {
                ActionBody::AddRoute {
                    label: MatchLabel::Exact,
                    add_route,
                    matches,
                } => (add_route.name_from[0][0].clone(), *matches),
                other => panic!("not an exact route action: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn a_path_needs_twenty_requests_and_no_route_of_its_own() {
        let spec = site_with_routes("");
        let document = serde_json::to_value(&spec).expect("document");
        let fields = || vec![field("header.x-service-method", 25)];
        assert!(
            route_rule_draft(&spec, &document, "/api/rpc", &requests_on_rpc(19), fields())
                .is_none()
        );
        assert!(
            route_rule_draft(&spec, &document, "/api/rpc", &requests_on_rpc(20), fields())
                .is_some()
        );
        // A prefix route covering the path, and an exact route on it, both leave it alone.
        for routes in [
            r#"{"path": "/api*", "name_from": [["header.x-other"]]}"#,
            r#"{"path": "/api/rpc", "name_from": [["header.x-other"]]}"#,
        ] {
            let spec = site_with_routes(routes);
            let document = serde_json::to_value(&spec).expect("document");
            assert!(
                route_rule_draft(&spec, &document, "/api/rpc", &requests_on_rpc(40), fields())
                    .is_none(),
                "{routes}"
            );
        }
    }

    #[test]
    fn the_most_frequent_fields_come_first_and_three_at_most() {
        let spec = site_with_routes("");
        let document = serde_json::to_value(&spec).expect("document");
        let fields = vec![
            field("body.params.op", 25),
            field("header.x-action", 12),
            field("body.method", 25),
            field("header.x-service-method", 30),
        ];
        let draft = route_rule_draft(&spec, &document, "/api/rpc", &requests_on_rpc(30), fields)
            .expect("a draft");
        assert_eq!(draft.count, 30);
        assert_eq!(
            offered(&draft),
            [
                ("header.x-service-method".to_owned(), 30),
                ("body.method".to_owned(), 25),
                ("body.params.op".to_owned(), 25),
            ]
        );
    }

    #[test]
    fn a_field_the_gateway_would_refuse_is_never_offered() {
        let spec = site_with_routes("");
        let document = serde_json::to_value(&spec).expect("document");
        // An array item (the parser reads no array), and a name over 64 bytes.
        let long = format!("body.{}.method", "k".repeat(60));
        let fields = vec![
            field("body.items[].method", 40),
            field(&long, 39),
            field("header.x-service-method", 10),
        ];
        let draft = route_rule_draft(&spec, &document, "/api/rpc", &requests_on_rpc(30), fields)
            .expect("a draft");
        assert_eq!(
            offered(&draft),
            [("header.x-service-method".to_owned(), 10)]
        );
    }

    #[test]
    fn a_route_that_overlaps_another_of_the_site_is_not_offered() {
        // An exact `/api` route covers the paths under it as unknown, so a rule on `/api/rpc` overlaps it.
        let spec = site_with_routes(r#"{"path": "/api", "name_from": [["header.x-id"]]}"#);
        let document = serde_json::to_value(&spec).expect("document");
        let fields = vec![field("header.x-service-method", 30)];
        assert!(
            route_rule_draft(&spec, &document, "/api/rpc", &requests_on_rpc(30), fields).is_none()
        );
    }

    #[test]
    fn a_bypassed_path_is_never_offered() {
        // A route names the requests' interface, which would move an exact bypass off them.
        let spec = SiteSpec::from_json(
            r#"{"name": "gw", "hosts": ["gw.example.com"], "origin": "http://10.0.0.5:8080",
                "session": {"cookie": "SESSIONID"}, "entries": ["/login"],
                "bypass": ["/api/rpc"]}"#,
        )
        .expect("test spec");
        let document = serde_json::to_value(&spec).expect("document");
        let fields = vec![field("header.x-service-method", 30)];
        assert!(
            route_rule_draft(&spec, &document, "/api/rpc", &requests_on_rpc(30), fields).is_none()
        );
    }

    #[test]
    fn a_name_is_a_method_by_its_last_word_only() {
        for name in [
            "x-service-method",
            "method",
            "x-api",
            "x-rpc",
            "x-func-function",
        ] {
            assert!(method_header(name), "{name}");
        }
        for name in ["x-method-name", "api-key", "methods", "x-request-id"] {
            assert!(!method_header(name), "{name}");
        }
        assert_eq!(
            body_source("body.method", Some("method")).as_deref(),
            Some("body.method")
        );
        assert_eq!(
            body_source("body.params.Op", Some("Op")).as_deref(),
            Some("body.params.Op")
        );
        // A dotted JSON key is not a path, and a word that only ends in a method word is no name.
        assert_eq!(body_source("body.a.method", Some("a.method")), None);
        assert_eq!(body_source("body.methodName", Some("methodName")), None);
    }

    #[test]
    fn fields_come_from_the_rows_that_name_a_method_and_hold_names() {
        let headers = [
            ("/api/rpc".to_owned(), "x-service-method".to_owned(), 30),
            ("/api/rpc".to_owned(), "x-trace-id".to_owned(), 30),
        ];
        let bodies = [
            (
                "/api/rpc".to_owned(),
                "body.method".to_owned(),
                Some("method".to_owned()),
                20,
                20,
            ),
            // Only numbers: the trace keeps them as text, but the parser refuses them.
            (
                "/api/rpc".to_owned(),
                "body.op".to_owned(),
                Some("op".to_owned()),
                25,
                0,
            ),
            (
                "/api/rpc".to_owned(),
                "body.params.cmd".to_owned(),
                Some("cmd".to_owned()),
                9,
                9,
            ),
        ];
        let fields = field_sources(&headers, &bodies);
        assert_eq!(
            fields["/api/rpc"],
            [
                field("header.x-service-method", 30),
                field("body.method", 20),
                field("body.params.cmd", 9),
            ]
        );
    }

    #[test]
    fn a_route_rule_suggestion_has_the_shape_the_console_reads() {
        let spec = site_with_routes("");
        let document = serde_json::to_value(&spec).expect("document");
        let fields = vec![field("header.x-service-method", 30)];
        let draft = route_rule_draft(&spec, &document, "/api/rpc", &requests_on_rpc(30), fields)
            .expect("a draft");
        let suggestion = SuggestionBody::from(&draft);
        let json = serde_json::to_value(&suggestion).expect("json");
        assert_eq!(json["kind"], "route_rule_candidate");
        assert_eq!(json["method"], Value::Null);
        assert_eq!(json["path"], "/api/rpc");
        assert_eq!(json["count"], 30);
        assert_eq!(json["sample"], "req_0");
        assert_eq!(
            json["id"],
            suggestion_id(ROUTE_RULE_CANDIDATE, "", "/api/rpc")
        );
        assert_eq!(
            json["actions"],
            json!([{
                "label": "exact",
                "add_route": {"path": "/api/rpc", "name_from": [["header.x-service-method"]]},
                "matches": 30
            }])
        );
        let back: SuggestionBody = serde_json::from_value(json).expect("reads back");
        assert_eq!(back, suggestion);
    }

    /// 2026-11-02 12:00 UTC, in Unix milliseconds.
    fn noon_utc() -> i64 {
        NaiveDate::from_ymd_opt(2026, 11, 2)
            .and_then(|day| day.and_hms_opt(12, 0, 0))
            .expect("a valid time")
            .and_utc()
            .timestamp_millis()
    }

    /// A decision row on `path`, `index` seconds before noon, with the header names and
    /// the request values (`body.<key>` location, value) its trace holds.
    fn logged(index: i64, path: &str, headers: &[&str], values: &[(&str, &str)]) -> NewDecision {
        let trace_values: Vec<Value> = values
            .iter()
            .map(|(at, value)| json!({"at": at, "key": at.rsplit('.').next(), "value": value}))
            .collect();
        NewDecision {
            at_millis: noon_utc() - index * 1_000,
            request_id: format!("req_{index:032x}"),
            site: Some("gw".to_owned()),
            site_version: Some(1),
            edge: "edge-1".to_owned(),
            host: "gw.example.com".to_owned(),
            client: "10.0.0.1".to_owned(),
            session: "7c1e9a40d2b35f61".to_owned(),
            context: Some("session".to_owned()),
            method: "POST".to_owned(),
            path: path.to_owned(),
            logical_path: path.to_owned(),
            api: None,
            request_headers: headers.iter().map(|name| (*name).to_owned()).collect(),
            query: None,
            status: Some(200),
            decision_path: "fast_allow".to_owned(),
            outcome: "allowed".to_owned(),
            trace: json!({"v": 1, "values": trace_values}),
            jev: None,
        }
    }

    /// The route suggestions read from the decision log of a migrated database. Skipped
    /// unless `XSHIELD_TEST_DATABASE_BASE_URL` (a server URL without a database name) is set.
    #[tokio::test]
    async fn the_route_scan_reads_the_decision_log() {
        let Ok(base) = std::env::var("XSHIELD_TEST_DATABASE_BASE_URL") else {
            eprintln!("skipped: XSHIELD_TEST_DATABASE_BASE_URL is not set");
            return;
        };
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&format!("{base}/postgres"))
            .await
            .expect("admin connection");
        let name = format!("control_insights_{}", std::process::id());
        sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name}")))
            .execute(&admin)
            .await
            .expect("drop a database left by an earlier run");
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create the scratch database");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!("{base}/{name}"))
            .await
            .expect("connect to the scratch database");
        crate::run_migrations(&pool).await.expect("migrations");

        let now = noon_utc();
        let day = NaiveDate::from_ymd_opt(2026, 11, 2).expect("day");
        ensure_partition(&pool, day).await.expect("partition");
        let mut rows = Vec::new();
        // 30 requests on /api/rpc: 25 carry the method header, 20 a body `method` name,
        // and 25 a numeric `op`, which is no name.
        for index in 0..30 {
            let mut headers = vec!["host"];
            let mut values = Vec::new();
            if index < 25 {
                headers.push("x-service-method");
                values.push(("body.op", "5"));
            }
            if index < 20 {
                values.push(("body.method", "saveList"));
            }
            rows.push(logged(index, "/api/rpc", &headers, &values));
        }
        // Too few requests for a rule, and a path a route of the site already names.
        for index in 0..19 {
            rows.push(logged(100 + index, "/short", &["x-service-method"], &[]));
        }
        for index in 0..25 {
            rows.push(logged(200 + index, "/api/other", &["x-action"], &[]));
        }
        decision_log_store::insert_many(&pool, &rows)
            .await
            .expect("rows");

        let scope = Scope {
            site: Some("gw".to_owned()),
            since_millis: now - DEFAULT_WINDOW_HOURS * HOUR_MILLIS,
            until_millis: now,
        };
        let (groups, _) = decision_stats::path_groups(&pool, &scope)
            .await
            .expect("groups");
        let spec =
            site_with_routes(r#"{"path": "/api/other", "name_from": [["header.x-action"]]}"#);
        let (drafts, complete) = route_rule_drafts(&pool, "gw", &scope, &groups, &spec)
            .await
            .expect("drafts");
        assert!(complete);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].path.as_deref(), Some("/api/rpc"));
        assert_eq!(drafts[0].count, 30);
        assert_eq!(
            offered(&drafts[0]),
            [
                ("header.x-service-method".to_owned(), 25),
                ("body.method".to_owned(), 20),
            ]
        );

        pool.close().await;
        sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name}")))
            .execute(&admin)
            .await
            .expect("drop the scratch database");
    }
}
