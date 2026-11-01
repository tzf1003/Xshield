//! Jev health, statistics and instruction text (docs/07 section 7.9.7). The wire
//! types are those of `web/console/src/api/types.ts`.
//!
//! Health reads the last five minutes of Jev calls. The configuration shown is the
//! newest online gateway's heartbeat report: `null` when no gateway is online or a
//! value is not reported.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use xshield_postgres::{
    decision_stats::{self, Scope},
    edge_status_store::{self, EdgeStatus},
    jev_prompt_store, site_spec_store,
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    params::{MAX_WINDOW_MILLIS, Params, Window, now_millis, rfc3339},
};

/// The window the health rule reads, in minutes.
const WINDOW_MINUTES: i64 = 5;
/// The same window in milliseconds.
const WINDOW_MILLIS: i64 = WINDOW_MINUTES * 60_000;
/// How many newest calls, all failed, make Jev down.
const DOWN_STREAK: i64 = 5;
/// The timeout when no online gateway reports one (docs/02-jev.md section 2.5).
const DEFAULT_TIMEOUT_MS: i64 = 2_000;
/// Width of one latency bucket, in milliseconds.
const LATENCY_BUCKET_MS: i64 = 100;
/// Width of one hour in milliseconds: the bucket of the hourly series.
const HOUR_MILLIS: i64 = 3_600_000;
/// Buckets of the confidence histogram, each 0.1 wide.
const CONFIDENCE_STEPS: i32 = 10;

/// One `decision_stats::jev_outcomes` row: hour, failure, access, attack, count.
type OutcomeRow = (i64, Option<String>, Option<String>, Option<String>, i64);

/// The health of Jev over the last five minutes, by [`health_of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Health {
    Idle,
    Ok,
    Degraded,
    Down,
}

impl Health {
    /// The name the API uses for this health.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Down => "down",
        }
    }
}

/// The calls of one hour: answered `allow`, answered `deny`, or unavailable.
#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    allow: i64,
    deny: i64,
    unavailable: i64,
}

/// Jev health over the last five minutes, with the figures the status views show.
#[derive(Debug)]
pub(crate) struct Report {
    health: Health,
    calls: i64,
    ok: i64,
    failures: Vec<(String, i64)>,
    /// Median and 95th percentile of the usable answers, in milliseconds.
    p50_ms: Option<i64>,
    p95_ms: Option<i64>,
    /// When Jev last gave a usable answer, in Unix milliseconds, within the retention.
    last_ok_at: Option<i64>,
    /// The newest failure within the retention: when, which code, which site.
    last_failure: Option<(i64, String, Option<String>)>,
    /// The configuration of the newest online gateway; `None` when none is online.
    config: Option<Value>,
}

impl Report {
    /// The fields shared by `GET /api/jev/status` and the `jev` block of
    /// `GET /api/status`.
    #[must_use]
    pub(crate) fn fields(&self) -> Value {
        json!({
            "health": self.health.as_str(),
            "window_minutes": WINDOW_MINUTES,
            "calls": self.calls,
            "ok": self.ok,
            "failures": failure_counts(&self.failures),
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "last_ok_at": self.last_ok_at.and_then(rfc3339),
            "last_failure": self.last_failure.as_ref().map(|(at, failure, site)| {
                json!({ "at": rfc3339(*at), "failure": failure, "site": site })
            }),
        })
    }

    /// The body of `GET /api/jev/status`: the shared fields and `config`.
    #[must_use]
    pub(crate) fn with_config(&self) -> Value {
        let mut body = self.fields();
        if let Value::Object(map) = &mut body {
            map.insert(
                "config".to_owned(),
                self.config.clone().unwrap_or(Value::Null),
            );
        }
        body
    }
}

/// `GET /api/jev/status`: Jev health, counts, latencies, the last success and
/// failure, and the newest online gateway's configuration.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
pub async fn status(State(state): State<Arc<ControlState>>) -> ApiResult<Json<Value>> {
    let report = health_summary(&state.pool, now_millis()).await?;
    Ok(Json(report.with_config()))
}

/// `GET /api/jev/stats?site=&since_millis=&until_millis=`: calls, conclusions,
/// failure codes, latency and confidence histograms, and the hourly series.
///
/// # Errors
/// `INVALID_FILTER` or `WINDOW_TOO_LARGE` for a bad window, `INTERNAL` on database errors.
pub async fn stats(
    State(state): State<Arc<ControlState>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let params = Params::from(query);
    let window = params.window(now_millis())?;
    let site = params.text("site").map(str::to_owned);
    let timeout_ms = timeout_for(&state.pool, site.as_deref()).await?;
    let scope = Scope {
        site,
        since_millis: window.since_millis,
        until_millis: window.until_millis,
    };
    let totals = decision_stats::jev_stats(&state.pool, &scope).await?;
    let outcomes = decision_stats::jev_outcomes(&state.pool, &scope, HOUR_MILLIS).await?;
    let latency = decision_stats::jev_latency_histogram(&state.pool, &scope).await?;
    let confidence = decision_stats::jev_confidence_histogram(&state.pool, &scope).await?;
    let summary = decision_stats::summary(&state.pool, &scope).await?;
    Ok(Json(json!({
        "since_millis": window.since_millis,
        "until_millis": window.until_millis,
        "calls": totals.calls,
        "by_conclusion": by_conclusion(&outcomes),
        "by_failure": failure_counts(&totals.failures),
        "p50_ms": whole_ms(totals.p50_ms),
        "p95_ms": whole_ms(totals.p95_ms),
        "latency_histogram": latency_histogram(&latency, timeout_ms),
        "confidence_histogram": { "counts": confidence_counts(&confidence) },
        "hourly": hourly(&outcomes, window),
        "complete": summary.complete,
    })))
}

/// `GET /api/jev/prompts/{id}`: the two questions of one instruction version and
/// when the gateway first registered it.
///
/// # Errors
/// `PROMPT_NOT_FOUND` (404) when no such version exists, `INTERNAL` on database errors.
pub async fn prompt(
    State(state): State<Arc<ControlState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let found = jev_prompt_store::get(&state.pool, &id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "PROMPT_NOT_FOUND"))?;
    Ok(Json(json!({
        "id": found.id,
        "first_seen": rfc3339(found.first_seen.timestamp_millis()),
        "questions": {
            "access": found.questions.get("access").cloned().unwrap_or(Value::Null),
            "attack": found.questions.get("attack").cloned().unwrap_or(Value::Null),
        },
    })))
}

/// Reads the Jev health of the last five minutes and the newest gateway's configuration.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
pub(crate) async fn health_summary(pool: &PgPool, now: i64) -> ApiResult<Report> {
    let scope = Scope {
        site: None,
        since_millis: now.saturating_sub(WINDOW_MILLIS),
        until_millis: now,
    };
    let stats = decision_stats::jev_stats(pool, &scope).await?;
    // The newest calls are the window's own calls once the window holds a full streak.
    let last_five_failed = stats.calls >= DOWN_STREAK
        && newest_all_failed(&decision_stats::last_calls(pool, DOWN_STREAK).await?);
    let (last_ok, last_failure) =
        decision_stats::last_ok_and_failure(pool, now.saturating_sub(MAX_WINDOW_MILLIS)).await?;
    let edges = edge_status_store::list(pool).await?;
    let instant: DateTime<Utc> = DateTime::from_timestamp_millis(now).unwrap_or_else(Utc::now);
    let config = newest_online(&edges, instant).map(reported_config);
    let timeout_ms = timeout_of(config.as_ref());
    let failed = stats.calls.saturating_sub(stats.ok);
    let p95_ms = whole_ms(stats.p95_ms);
    Ok(Report {
        health: health_of(stats.calls, failed, p95_ms, timeout_ms, last_five_failed),
        calls: stats.calls,
        ok: stats.ok,
        failures: stats.failures,
        p50_ms: whole_ms(stats.p50_ms),
        p95_ms,
        last_ok_at: last_ok,
        last_failure,
        config,
    })
}

/// The gateway instance that sent the most recent heartbeat among those online.
#[must_use]
fn newest_online(edges: &[EdgeStatus], now: DateTime<Utc>) -> Option<&EdgeStatus> {
    edges
        .iter()
        .filter(|edge| edge.is_online(now))
        .max_by_key(|edge| edge.seen_at)
}

/// The Jev configuration one instance reports: route, endpoint host, model, default
/// timeout and prompt id. A value it does not report is `null`.
#[must_use]
pub(crate) fn reported_config(edge: &EdgeStatus) -> Value {
    let field = |name: &str| edge.jev.get(name).cloned().unwrap_or(Value::Null);
    json!({
        "route": field("route"),
        "endpoint_host": field("endpoint_host"),
        "model": field("model"),
        "default_timeout_ms": field("default_timeout_ms"),
        "prompt": field("prompt"),
    })
}

/// The health rule of docs/07 section 7.9.7 over one window. `failed` counts the
/// calls without a usable answer, `p95_ms` is the 95th percentile of the usable
/// ones, and `last_five_failed` says the newest five calls all failed. Shares are
/// integers: `failed * 5 >= calls` is a failure share of 20 % or more.
#[must_use]
pub(crate) fn health_of(
    calls: i64,
    failed: i64,
    p95_ms: Option<i64>,
    timeout_ms: i64,
    last_five_failed: bool,
) -> Health {
    if calls <= 0 {
        return Health::Idle;
    }
    let failing = failed.saturating_mul(5);
    let slow = p95_ms.is_some_and(|p95| p95.saturating_mul(10) >= timeout_ms.saturating_mul(9));
    if failing >= calls.saturating_mul(4) || last_five_failed {
        Health::Down
    } else if failing >= calls || slow {
        Health::Degraded
    } else {
        Health::Ok
    }
}

/// The Jev timeout a histogram is cut at: the site's own when a site is named and
/// sets one, the online gateway's default otherwise.
async fn timeout_for(pool: &PgPool, site: Option<&str>) -> ApiResult<i64> {
    let own = match site {
        Some(name) => site_spec_store::get(pool, name)
            .await?
            .and_then(|record| record.spec.advanced().jev_timeout_ms()),
        None => None,
    };
    if let Some(timeout) = own {
        return Ok(i64::from(timeout));
    }
    let edges = edge_status_store::list(pool).await?;
    let config = newest_online(&edges, Utc::now()).map(reported_config);
    Ok(timeout_of(config.as_ref()))
}

/// The timeout a reported configuration names, or the deployment default.
#[must_use]
fn timeout_of(config: Option<&Value>) -> i64 {
    config
        .and_then(|config| config.get("default_timeout_ms"))
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_TIMEOUT_MS)
}

/// Whether `recent`, newest first as `last_calls` returns it, holds a full streak
/// and every call in it failed.
#[must_use]
fn newest_all_failed(recent: &[Option<String>]) -> bool {
    i64::try_from(recent.len()).is_ok_and(|len| len >= DOWN_STREAK)
        && recent.iter().all(Option::is_some)
}

/// A latency in whole milliseconds, rounded to the nearest.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // a latency is far below the range of i64
fn whole_ms(value: Option<f64>) -> Option<i64> {
    value.map(|ms| ms.round() as i64)
}

/// Failure counts as an object from failure code to count.
#[must_use]
fn failure_counts(failures: &[(String, i64)]) -> Value {
    json!(failures.iter().cloned().collect::<BTreeMap<String, i64>>())
}

/// The conclusion of one Jev call from its stored answers (docs/02-jev.md section
/// 2.3): `UNKNOWN` or the `JEV_UNKNOWN` failure is `unknown`, `DENY` access or
/// `ATTACK` attack is `deny`, any other answer is `allow`. A failed call without an
/// answer has no conclusion.
#[must_use]
fn conclusion_of(
    failure: Option<&str>,
    access: Option<&str>,
    attack: Option<&str>,
) -> Option<&'static str> {
    if failure == Some("JEV_UNKNOWN") || access == Some("UNKNOWN") || attack == Some("UNKNOWN") {
        return Some("unknown");
    }
    let (Some(access), Some(attack), None) = (access, attack, failure) else {
        return None;
    };
    Some(if access == "DENY" || attack == "ATTACK" {
        "deny"
    } else {
        "allow"
    })
}

/// Calls by conclusion, summed over the outcome rows. Every key is present.
#[must_use]
fn by_conclusion(outcomes: &[OutcomeRow]) -> Value {
    let mut counts = BTreeMap::from([("allow", 0_i64), ("deny", 0), ("unknown", 0)]);
    for (_, failure, access, attack, count) in outcomes {
        let Some(conclusion) =
            conclusion_of(failure.as_deref(), access.as_deref(), attack.as_deref())
        else {
            continue;
        };
        let total = counts.entry(conclusion).or_insert(0);
        *total = total.saturating_add(*count);
    }
    json!(counts)
}

/// The start of the UTC hour that holds `millis`.
#[must_use]
fn floor_hour(millis: i64) -> i64 {
    millis.saturating_sub(millis.rem_euclid(HOUR_MILLIS))
}

/// One entry per hour the window touches, in time order. A call is `allow` or `deny`
/// when it was answered so, and `unavailable` otherwise.
#[must_use]
fn hourly(outcomes: &[OutcomeRow], window: Window) -> Vec<Value> {
    let mut tallies: BTreeMap<i64, Tally> = BTreeMap::new();
    for (hour, failure, access, attack, count) in outcomes {
        let tally = tallies.entry(*hour).or_default();
        match conclusion_of(failure.as_deref(), access.as_deref(), attack.as_deref()) {
            Some("allow") => tally.allow = tally.allow.saturating_add(*count),
            Some("deny") => tally.deny = tally.deny.saturating_add(*count),
            _ => tally.unavailable = tally.unavailable.saturating_add(*count),
        }
    }
    let first = floor_hour(window.since_millis);
    let last_step = floor_hour(window.until_millis).saturating_sub(first).max(0) / HOUR_MILLIS;
    (0..=last_step)
        .map(|step| {
            let at = first.saturating_add(step.saturating_mul(HOUR_MILLIS));
            let tally = tallies.get(&at).copied().unwrap_or_default();
            json!({
                "at_millis": at,
                "allow": tally.allow,
                "deny": tally.deny,
                "unavailable": tally.unavailable,
            })
        })
        .collect()
}

/// Calls per 100 ms bucket, up to and including the timeout bucket. Calls at or
/// beyond the timeout bucket are counted in it, so the counts add up to every call.
#[must_use]
fn latency_histogram(histogram: &[(i32, i64)], timeout_ms: i64) -> Value {
    let last = (timeout_ms / LATENCY_BUCKET_MS).max(0);
    let length = usize::try_from(last.saturating_add(1)).unwrap_or(1);
    let mut counts = vec![0_i64; length];
    for &(bucket, count) in histogram {
        // The storage numbers the first bucket 1, for 0 to 100 ms.
        let index = i64::from(bucket.max(1) - 1).min(last);
        if let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|position| counts.get_mut(position))
        {
            *slot = slot.saturating_add(count);
        }
    }
    json!({
        "bucket_ms": LATENCY_BUCKET_MS,
        "counts": counts,
        "timeout_ms": timeout_ms,
    })
}

/// Calls per 0.1 confidence bucket, all ten in order. A confidence of exactly 1.0 is
/// numbered past the last bucket by the storage, and counts in the top bucket.
#[must_use]
fn confidence_counts(histogram: &[(i32, i64)]) -> Vec<i64> {
    (1..=CONFIDENCE_STEPS)
        .map(|step| {
            histogram
                .iter()
                .filter(|&&(bucket, _)| bucket.clamp(1, CONFIDENCE_STEPS) == step)
                .map(|&(_, count)| count)
                .sum::<i64>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_follows_the_failure_share_latency_and_streak() {
        assert_eq!(
            health_of(0, 0, None, DEFAULT_TIMEOUT_MS, false),
            Health::Idle
        );
        assert_eq!(health_of(10, 0, Some(1_799), 2_000, false), Health::Ok);
        assert_eq!(
            health_of(10, 0, Some(1_800), 2_000, false),
            Health::Degraded
        );
        assert_eq!(health_of(10, 2, Some(540), 2_000, false), Health::Degraded);
        assert_eq!(health_of(10, 8, Some(540), 2_000, false), Health::Down);
        assert_eq!(health_of(10, 1, Some(540), 2_000, true), Health::Down);
    }

    #[test]
    fn conclusions_follow_section_2_3_and_skip_calls_without_an_answer() {
        assert_eq!(
            conclusion_of(None, Some("DENY"), Some("BENIGN")),
            Some("deny")
        );
        assert_eq!(
            conclusion_of(None, Some("ALLOW"), Some("ATTACK")),
            Some("deny")
        );
        assert_eq!(
            conclusion_of(None, Some("UNKNOWN"), Some("BENIGN")),
            Some("unknown")
        );
        assert_eq!(conclusion_of(Some("JEV_TIMEOUT"), None, None), None);
        let rows: Vec<OutcomeRow> = vec![
            (
                0,
                None,
                Some("DENY".to_owned()),
                Some("BENIGN".to_owned()),
                3,
            ),
            (0, Some("JEV_TIMEOUT".to_owned()), None, None, 9),
        ];
        assert_eq!(
            by_conclusion(&rows),
            json!({ "allow": 0, "deny": 3, "unknown": 0 })
        );
    }

    #[test]
    fn histograms_end_at_the_timeout_and_the_top_confidence_bucket_takes_one_point_zero() {
        // Bucket 1 is 0 to 100 ms, bucket 301 is the overflow past 30 s.
        let mut expected = vec![3, 1];
        expected.extend(std::iter::repeat_n(0, 18));
        expected.push(2);
        assert_eq!(
            latency_histogram(&[(1, 3), (2, 1), (301, 2)], 2_000),
            json!({ "bucket_ms": 100, "counts": expected, "timeout_ms": 2_000 })
        );
        assert_eq!(
            confidence_counts(&[(1, 2), (10, 1), (11, 4)]),
            vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 5]
        );
    }

    #[test]
    fn the_hourly_series_has_one_entry_per_hour_of_the_window() {
        let hour = 1_793_491_200_000_i64;
        let outcomes: Vec<OutcomeRow> = vec![
            (
                hour,
                None,
                Some("ALLOW".to_owned()),
                Some("BENIGN".to_owned()),
                4,
            ),
            (hour, Some("JEV_TIMEOUT".to_owned()), None, None, 1),
            (
                hour + HOUR_MILLIS,
                None,
                Some("DENY".to_owned()),
                Some("ATTACK".to_owned()),
                2,
            ),
        ];
        let window = Window {
            since_millis: hour + 30 * 60_000,
            until_millis: hour + 2 * HOUR_MILLIS + 10 * 60_000,
        };
        assert_eq!(
            hourly(&outcomes, window),
            vec![
                json!({ "at_millis": hour, "allow": 4, "deny": 0, "unavailable": 1 }),
                json!({ "at_millis": hour + HOUR_MILLIS, "allow": 0, "deny": 2, "unavailable": 0 }),
                json!({ "at_millis": hour + 2 * HOUR_MILLIS, "allow": 0, "deny": 0, "unavailable": 0 }),
            ]
        );
    }
}
