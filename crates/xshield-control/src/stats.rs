//! Overview totals and the decision-path timeline (docs/07-console-architecture.md
//! sections 7.9.1 and 7.9.2).
//!
//! Both read one window of the decision log. The storage reads at most its scan
//! limit of rows. The answer says `complete: false` when the window holds that
//! many rows or more, and then carries `scanned`, the rows read.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use xshield_postgres::decision_stats::{self, Bucket, Scope, Summary};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    params::{DAY_MILLIS, Params, Window, now_millis},
};

/// The longest site name a statistic may filter on, as the request list bounds it.
const SITE_MAX_CHARS: usize = 64;
/// One minute in milliseconds: the smallest bucket, and the unit the default
/// bucket is rounded to.
const MINUTE_MILLIS: i64 = 60_000;
/// How many buckets a default timeline aims for.
const DEFAULT_BUCKETS: i64 = 120;
/// How long the decision log keeps its rows (docs/07 section 7.8.2).
const RETENTION_MILLIS: i64 = 7 * DAY_MILLIS;

/// The site and window a statistic covers (docs/07 section 7.9.1). The window
/// defaults to the last 24 hours and `site` is optional.
///
/// # Errors
/// `INVALID_FILTER` for a bad window bound or a site name over 64 characters,
/// `WINDOW_TOO_LARGE` for a window over seven days.
pub(crate) fn scope_from(params: &Params, now: i64) -> ApiResult<(Scope, Window)> {
    let window = params.window(now)?;
    let site = match params.text("site") {
        None => None,
        Some(site) if site.chars().count() <= SITE_MAX_CHARS => Some(site.to_owned()),
        Some(_) => return Err(ApiError::invalid_filter("site")),
    };
    let scope = Scope {
        site,
        since_millis: window.since_millis,
        until_millis: window.until_millis,
    };
    Ok((scope, window))
}

/// `GET /api/stats/summary`: the overview totals of a window, and the same totals
/// for the window of equal length just before it when that is still retained
/// (docs/07 section 7.9.2).
///
/// # Errors
/// As `scope_from`, and `INTERNAL` when the database cannot be read.
pub async fn summary(
    State(state): State<Arc<ControlState>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<Value>> {
    let params = Params::from(query);
    let now = now_millis();
    let (scope, window) = scope_from(&params, now)?;
    let totals = decision_stats::summary(&state.pool, &scope).await?;
    let earlier = previous_window(window, now).map(|earlier| Scope {
        site: scope.site.clone(),
        since_millis: earlier.since_millis,
        until_millis: earlier.until_millis,
    });
    let previous = match earlier {
        Some(earlier) => Some(decision_stats::summary(&state.pool, &earlier).await?),
        None => None,
    };
    Ok(Json(summary_json(window, &totals, previous.as_ref())))
}

/// `GET /api/stats/timeseries`: the judged requests of a window counted per bucket,
/// each bucket by decision path (docs/07 section 7.9.2). Buckets with no requests
/// are not sent.
///
/// # Errors
/// As `scope_from`, `INVALID_FILTER` naming `bucket_millis` for a bucket under one
/// minute, and `INTERNAL` when the database cannot be read.
/// The `GET /api/stats/timeseries` response. `scanned` accompanies `complete: false` only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeseriesBody {
    pub bucket_ms: i64,
    pub since_millis: i64,
    pub until_millis: i64,
    pub buckets: Vec<BucketBody>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned: Option<i64>,
}

/// One bucket of the timeline: its start, and the requests per decision path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BucketBody {
    pub at_millis: i64,
    pub counts: BTreeMap<String, i64>,
}

pub async fn timeseries(
    State(state): State<Arc<ControlState>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<TimeseriesBody>> {
    let params = Params::from(query);
    let (scope, window) = scope_from(&params, now_millis())?;
    let bucket_ms = bucket_param(&params, window)?;
    let timeline = decision_stats::timeseries(&state.pool, &scope, bucket_ms).await?;
    Ok(Json(TimeseriesBody {
        bucket_ms,
        since_millis: window.since_millis,
        until_millis: window.until_millis,
        buckets: timeline.buckets.iter().map(bucket_body).collect(),
        complete: timeline.complete,
        scanned: (!timeline.complete).then_some(timeline.scanned),
    }))
}

/// The totals as the console reads them: the window, the figures, the figures of
/// the window before it (null when that is not retained), and whether the window
/// was read in full.
fn summary_json(window: Window, totals: &Summary, previous: Option<&Summary>) -> Value {
    let mut body = json!({
        "since_millis": window.since_millis,
        "until_millis": window.until_millis,
        "judged": totals.judged,
        "blocked": totals.blocked,
        "would_block": totals.would_block,
        "unjudged": totals.unjudged,
        "jev_calls": totals.jev_calls,
        "jev_timeouts": totals.jev_timeouts,
        "jev_p95_ms": totals.jev_p95_ms,
        "previous": previous.map(previous_json),
        "complete": totals.complete,
    });
    // docs/07 section 7.9.1: `scanned` accompanies `complete: false` only.
    if !totals.complete {
        body["scanned"] = json!(totals.scanned);
    }
    body
}

/// The figures of the window before, the ones the console compares with.
fn previous_json(totals: &Summary) -> Value {
    json!({
        "judged": totals.judged,
        "blocked": totals.blocked,
        "would_block": totals.would_block,
        "unjudged": totals.unjudged,
        "jev_calls": totals.jev_calls,
        "jev_p95_ms": totals.jev_p95_ms,
    })
}

fn bucket_body(bucket: &Bucket) -> BucketBody {
    BucketBody {
        at_millis: bucket.start_millis,
        counts: bucket.counts.clone(),
    }
}

/// The window of the same length that ends just before `window` starts. `None`
/// when that window reaches back past the retention, where its counts would be
/// partial.
fn previous_window(window: Window, now: i64) -> Option<Window> {
    let span = window.until_millis.saturating_sub(window.since_millis);
    let until_millis = window.since_millis.checked_sub(1)?;
    let since_millis = until_millis.checked_sub(span)?;
    (since_millis >= now.saturating_sub(RETENTION_MILLIS)).then_some(Window {
        since_millis,
        until_millis,
    })
}

/// The bucket a timeline counts in: `bucket_millis` when given, otherwise the
/// default for the window.
///
/// # Errors
/// `INVALID_FILTER` naming `bucket_millis` for a bucket under one minute.
fn bucket_param(params: &Params, window: Window) -> ApiResult<i64> {
    match params.int("bucket_millis")? {
        None => Ok(default_bucket_millis(
            window.until_millis.saturating_sub(window.since_millis),
        )),
        Some(bucket) if bucket >= MINUTE_MILLIS => Ok(bucket),
        Some(_) => Err(ApiError::invalid_filter("bucket_millis")),
    }
}

/// A 120th of a window `span_millis` long, rounded up to a whole minute and never
/// less than one minute.
fn default_bucket_millis(span_millis: i64) -> i64 {
    let target = span_millis / DEFAULT_BUCKETS;
    let minutes = target / MINUTE_MILLIS + i64::from(target % MINUTE_MILLIS > 0);
    minutes.max(1).saturating_mul(MINUTE_MILLIS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> Params {
        Params::from(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    #[test]
    fn the_default_bucket_is_a_120th_of_the_window_rounded_up_to_a_minute() {
        assert_eq!(default_bucket_millis(DAY_MILLIS), 12 * MINUTE_MILLIS);
        assert_eq!(
            default_bucket_millis(5 * 60 * MINUTE_MILLIS),
            3 * MINUTE_MILLIS
        );
        assert_eq!(default_bucket_millis(7 * DAY_MILLIS), 84 * MINUTE_MILLIS);
    }

    #[test]
    fn the_default_bucket_is_never_below_a_minute() {
        assert_eq!(default_bucket_millis(0), MINUTE_MILLIS);
        assert_eq!(default_bucket_millis(60 * MINUTE_MILLIS), MINUTE_MILLIS);
    }

    #[test]
    fn a_bucket_under_a_minute_is_refused_by_name() {
        let window = Window {
            since_millis: 0,
            until_millis: DAY_MILLIS,
        };
        let error =
            bucket_param(&params(&[("bucket_millis", "1000")]), window).expect_err("too small");
        assert_eq!(error.code(), "INVALID_FILTER");
    }

    #[test]
    fn the_scope_defaults_to_the_last_day_and_bounds_the_site_name() {
        let (scope, window) = scope_from(&params(&[]), 10 * DAY_MILLIS).expect("default scope");
        assert_eq!(scope.site, None);
        assert_eq!(window.since_millis, 9 * DAY_MILLIS);
        assert_eq!(scope.until_millis, 10 * DAY_MILLIS);
        let long = "s".repeat(65);
        assert!(scope_from(&params(&[("site", long.as_str())]), 10 * DAY_MILLIS).is_err());
    }

    #[test]
    fn the_previous_window_has_the_same_length_and_ends_where_this_one_starts() {
        let window = Window {
            since_millis: 9 * DAY_MILLIS,
            until_millis: 10 * DAY_MILLIS,
        };
        let earlier = previous_window(window, 10 * DAY_MILLIS).expect("retained");
        assert_eq!(earlier.until_millis, 9 * DAY_MILLIS - 1);
        assert_eq!(earlier.until_millis - earlier.since_millis, DAY_MILLIS);
    }

    #[test]
    fn a_previous_window_past_the_retention_is_not_offered() {
        let window = Window {
            since_millis: 0,
            until_millis: 7 * DAY_MILLIS,
        };
        assert!(previous_window(window, 7 * DAY_MILLIS).is_none());
    }

    #[test]
    fn scanned_is_sent_only_when_the_window_was_not_read_in_full() {
        let window = Window {
            since_millis: 0,
            until_millis: DAY_MILLIS,
        };
        let complete = Summary {
            complete: true,
            scanned: 5,
            ..Summary::default()
        };
        assert!(
            summary_json(window, &complete, None)
                .get("scanned")
                .is_none()
        );
        let partial = Summary {
            complete: false,
            scanned: 42,
            ..Summary::default()
        };
        assert_eq!(summary_json(window, &partial, None)["scanned"], json!(42));
    }
}
