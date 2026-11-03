//! Aggregations over the decision log for the console (docs/07-console-architecture.md
//! sections 7.9.6, 7.9.7, 7.9.10 and 7.9.11).
//!
//! Every query here is bounded: a window in time and, for whole-window
//! aggregates, a scan limit of [`SCAN_LIMIT`] rows. A result that stopped at the
//! limit says so with `complete == false`, so the console can show that it was
//! computed over the most recent rows only.

use std::collections::BTreeMap;

use sqlx::{AssertSqlSafe, PgPool, Postgres, QueryBuilder, Row};

use crate::decision_log_store::{
    DETAIL_COLUMNS, JEV_CALLED_SQL, JEV_DEMAND_SQL, RequestDetail, RequestSummary, SUMMARY_COLUMNS,
    summary_from_row,
};

/// Most rows one whole-window aggregate reads (docs/07 section 7.9.1).
pub const SCAN_LIMIT: i64 = 2_000_000;

/// Most rows one Jev `state` scan reads (docs/07 section 7.9.10).
pub const STATE_SCAN_LIMIT: i64 = 20_000;

/// Which site and time window an aggregate covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// Exact site name, or `None` for every site.
    pub site: Option<String>,
    /// Lower bound of `at_millis`, inclusive.
    pub since_millis: i64,
    /// Upper bound of `at_millis`, inclusive.
    pub until_millis: i64,
}

fn push_scope(query: &mut QueryBuilder<Postgres>, scope: &Scope) {
    query
        .push(" WHERE at_millis >= ")
        .push_bind(scope.since_millis);
    query
        .push(" AND at_millis <= ")
        .push_bind(scope.until_millis);
    if let Some(site) = &scope.site {
        query.push(" AND site = ").push_bind(site.clone());
    }
}

/// Whole-window totals for the overview.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    /// Rows the aggregate read.
    pub scanned: i64,
    /// False when the window holds [`SCAN_LIMIT`] rows or more, so the totals cover
    /// only the newest rows.
    pub complete: bool,
    /// Requests that were judged: everything except bypassed and unknown-site requests.
    pub judged: i64,
    /// Requests refused.
    pub blocked: i64,
    /// Requests that observe mode would have refused but forwarded.
    pub would_block: i64,
    /// Requests forwarded without a judgement.
    pub unjudged: i64,
    /// Jev round trips.
    pub jev_calls: i64,
    /// Jev round trips that timed out.
    pub jev_timeouts: i64,
    /// 95th percentile of Jev round trips in milliseconds.
    pub jev_p95_ms: Option<f64>,
}

/// Totals over the scope, read from at most [`SCAN_LIMIT`] of the newest rows.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn summary(pool: &PgPool, scope: &Scope) -> Result<Summary, sqlx::Error> {
    // The Jev predicate is computed in the inner select. The outer select reads only
    // the columns that select lists, so it cannot test `jev` itself.
    let mut query = QueryBuilder::<Postgres>::new(format!(
        "SELECT count(*)::bigint AS scanned,
            count(*) FILTER (WHERE decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS judged,
            count(*) FILTER (WHERE outcome = 'blocked' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS blocked,
            count(*) FILTER (WHERE outcome = 'would_block' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS would_block,
            count(*) FILTER (WHERE outcome = 'unjudged' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS unjudged,
            count(*) FILTER (WHERE jev_called)::bigint AS jev_calls,
            count(*) FILTER (WHERE jev_failure = 'JEV_TIMEOUT')::bigint AS jev_timeouts,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY jev_ms)
                FILTER (WHERE jev_called) AS jev_p95_ms
         FROM (SELECT decision_path, outcome, jev_ms, jev_failure,
                      ({JEV_CALLED_SQL}) AS jev_called
               FROM decision_log"
    ));
    push_scope(&mut query, scope);
    query.push(format!(
        " ORDER BY at_millis DESC LIMIT {SCAN_LIMIT}) AS window_rows"
    ));
    let row = query.build().fetch_one(pool).await?;
    let scanned: i64 = row.try_get("scanned")?;
    Ok(Summary {
        scanned,
        complete: scanned < SCAN_LIMIT,
        judged: row.try_get("judged")?,
        blocked: row.try_get("blocked")?,
        would_block: row.try_get("would_block")?,
        unjudged: row.try_get("unjudged")?,
        jev_calls: row.try_get("jev_calls")?,
        jev_timeouts: row.try_get("jev_timeouts")?,
        jev_p95_ms: row.try_get("jev_p95_ms")?,
    })
}

/// How many slices the overview's mini trend cuts its window into (docs/07 section 7.9.2).
pub const SPARK_POINTS: usize = 12;

/// The overview's mini trend: the window cut into [`SPARK_POINTS`] equal slices, oldest
/// first. A count covers one slice, so the slices of a figure add up to its total in
/// [`Summary`]. A slice with no Jev call has no latency.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Spark {
    /// Judged requests per slice.
    pub judged: Vec<i64>,
    /// Refused requests per slice.
    pub blocked: Vec<i64>,
    /// Requests observe mode would have refused, per slice.
    pub would_block: Vec<i64>,
    /// Requests forwarded without a judgement, per slice.
    pub unjudged: Vec<i64>,
    /// Jev round trips per slice.
    pub jev_calls: Vec<i64>,
    /// 95th percentile of the Jev round trips in each slice, `None` when it has none.
    pub jev_p95_ms: Vec<Option<f64>>,
}

/// The mini trend of the window of `scope`, read from the same rows as [`summary`].
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn spark(pool: &PgPool, scope: &Scope) -> Result<Spark, sqlx::Error> {
    // The window includes both of its bounds, so its span is one more than the
    // difference. Slice `i` starts at `since + i * span / SPARK_POINTS`.
    let span = scope
        .until_millis
        .saturating_sub(scope.since_millis)
        .saturating_add(1)
        .max(1);
    let last = SPARK_POINTS - 1;
    let mut query = QueryBuilder::<Postgres>::new(format!(
        "SELECT slice,
            count(*) FILTER (WHERE decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS judged,
            count(*) FILTER (WHERE outcome = 'blocked' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS blocked,
            count(*) FILTER (WHERE outcome = 'would_block' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS would_block,
            count(*) FILTER (WHERE outcome = 'unjudged' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS unjudged,
            count(*) FILTER (WHERE jev_called)::bigint AS jev_calls,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY jev_ms)
                FILTER (WHERE jev_called) AS jev_p95_ms
         FROM (SELECT decision_path, outcome, jev_ms,
                      ({JEV_CALLED_SQL}) AS jev_called,
                      LEAST({last}, ((at_millis - "
    ));
    query
        .push_bind(scope.since_millis)
        .push(format!(") * {SPARK_POINTS}) / "))
        .push_bind(span)
        .push(")::bigint AS slice FROM decision_log");
    push_scope(&mut query, scope);
    query.push(format!(
        " ORDER BY at_millis DESC LIMIT {SCAN_LIMIT}) AS window_rows GROUP BY slice ORDER BY slice"
    ));
    let rows = query.build().fetch_all(pool).await?;
    let mut trend = Spark {
        judged: vec![0; SPARK_POINTS],
        blocked: vec![0; SPARK_POINTS],
        would_block: vec![0; SPARK_POINTS],
        unjudged: vec![0; SPARK_POINTS],
        jev_calls: vec![0; SPARK_POINTS],
        jev_p95_ms: vec![None; SPARK_POINTS],
    };
    for row in &rows {
        let slice = usize::try_from(row.try_get::<i64, _>("slice")?).unwrap_or(usize::MAX);
        if slice >= SPARK_POINTS {
            continue;
        }
        trend.judged[slice] = row.try_get("judged")?;
        trend.blocked[slice] = row.try_get("blocked")?;
        trend.would_block[slice] = row.try_get("would_block")?;
        trend.unjudged[slice] = row.try_get("unjudged")?;
        trend.jev_calls[slice] = row.try_get("jev_calls")?;
        trend.jev_p95_ms[slice] = row.try_get("jev_p95_ms")?;
    }
    Ok(trend)
}

/// One bucket of the request timeline: the judged requests of one time slice,
/// counted by decision path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// Start of the bucket, Unix milliseconds.
    pub start_millis: i64,
    /// Requests per decision path in the bucket. A path with no request in the
    /// bucket is absent.
    pub counts: BTreeMap<String, i64>,
}

/// The judged requests of one window counted per bucket of `bucket_millis` and by
/// decision path, with the rows the scan read (docs/07 section 7.9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeline {
    /// Buckets, oldest first. Bypassed and unknown-site requests are not counted.
    pub buckets: Vec<Bucket>,
    /// Rows the scan read, bypassed and unknown-site rows included.
    pub scanned: i64,
    /// False when the window holds [`SCAN_LIMIT`] rows or more.
    pub complete: bool,
}

/// Counts the judged requests of the window per bucket and decision path.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn timeseries(
    pool: &PgPool,
    scope: &Scope,
    bucket_millis: i64,
) -> Result<Timeline, sqlx::Error> {
    // The scan reads every row of the window, as the other whole-window aggregates
    // do, so `scanned` means the same on every endpoint. Bypassed and unknown-site
    // rows are dropped from the buckets afterwards.
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT bucket, decision_path, count(*)::bigint AS requests, max(scanned) AS scanned
         FROM (
            SELECT bucket, decision_path, count(*) OVER () AS scanned
            FROM (
                SELECT (at_millis / ",
    );
    query
        .push_bind(bucket_millis)
        .push(") * ")
        .push_bind(bucket_millis);
    query.push(" AS bucket, decision_path FROM decision_log");
    push_scope(&mut query, scope);
    query.push(format!(" ORDER BY at_millis DESC LIMIT {SCAN_LIMIT}"));
    query.push(") AS limited) AS window_rows GROUP BY bucket, decision_path ORDER BY bucket ASC");
    let rows = query.build().fetch_all(pool).await?;
    let mut scanned = 0_i64;
    let mut buckets: Vec<Bucket> = Vec::new();
    for row in &rows {
        scanned = scanned.max(row.try_get("scanned")?);
        let path: String = row.try_get("decision_path")?;
        if matches!(path.as_str(), "bypass" | "unknown_site") {
            continue;
        }
        let start_millis: i64 = row.try_get("bucket")?;
        let requests: i64 = row.try_get("requests")?;
        match buckets.last_mut() {
            Some(bucket) if bucket.start_millis == start_millis => {
                bucket.counts.insert(path, requests);
            }
            _ => buckets.push(Bucket {
                start_millis,
                counts: BTreeMap::from([(path, requests)]),
            }),
        }
    }
    Ok(Timeline {
        buckets,
        scanned,
        complete: scanned < SCAN_LIMIT,
    })
}

/// Request counts of one site over a window, for the site list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteCounts {
    /// Site name.
    pub site: String,
    /// Judged requests (bypassed and unknown-site excluded).
    pub requests: i64,
    /// Refused requests.
    pub blocked: i64,
    /// Requests observe mode would have refused.
    pub would_block: i64,
    /// Jev round trips.
    pub jev_calls: i64,
    /// Requests forwarded without a judgement (outcome `unjudged`).
    pub unjudged: i64,
    /// Jev calls that timed out.
    pub jev_timeouts: i64,
    /// Jev calls refused by the per-session call limit.
    pub call_limits: i64,
}

/// Counts per site since `since_millis`.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn site_counts(pool: &PgPool, since_millis: i64) -> Result<Vec<SiteCounts>, sqlx::Error> {
    let rows = sqlx::query(AssertSqlSafe(format!("SELECT site,
            count(*) FILTER (WHERE decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS requests,
            count(*) FILTER (WHERE outcome = 'blocked' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS blocked,
            count(*) FILTER (WHERE outcome = 'would_block' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS would_block,
            count(*) FILTER (WHERE {JEV_CALLED_SQL})::bigint AS jev_calls,
            count(*) FILTER (WHERE outcome = 'unjudged' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS unjudged,
            count(*) FILTER (WHERE jev_failure = 'JEV_TIMEOUT')::bigint AS jev_timeouts,
            count(*) FILTER (WHERE jev_failure = 'JEV_CALL_LIMIT')::bigint AS call_limits
         FROM decision_log
         WHERE at_millis >= $1 AND site IS NOT NULL
           AND decision_path NOT IN ('bypass', 'unknown_site')
         GROUP BY site ORDER BY site")))
    .bind(since_millis)
    .fetch_all(pool)
    .await?;
    let mut counts = Vec::with_capacity(rows.len());
    for row in &rows {
        counts.push(SiteCounts {
            site: row.try_get("site")?,
            requests: row.try_get("requests")?,
            blocked: row.try_get("blocked")?,
            would_block: row.try_get("would_block")?,
            jev_calls: row.try_get("jev_calls")?,
            unjudged: row.try_get("unjudged")?,
            jev_timeouts: row.try_get("jev_timeouts")?,
            call_limits: row.try_get("call_limits")?,
        });
    }
    Ok(counts)
}

/// Which sessions to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionFlag {
    /// Every session.
    Any,
    /// Sessions with a refused or would-be-refused request.
    Blocked,
    /// Sessions with a Jev round trip.
    Jev,
}

/// One session, summarized over a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// Session label (16 hex digits).
    pub label: String,
    /// `session` or `address`.
    pub context: Option<String>,
    /// Site the session belongs to, when one site was seen.
    pub site: Option<String>,
    /// Oldest request, Unix milliseconds.
    pub first_at: i64,
    /// Newest request, Unix milliseconds.
    pub last_at: i64,
    /// Requests in the window.
    pub requests: i64,
    /// Jev round trips.
    pub jev_calls: i64,
    /// Refused requests.
    pub blocked: i64,
    /// Requests observe mode would have refused.
    pub would_block: i64,
}

/// Lists sessions active in `scope`, newest activity first, or one session when
/// `label` is given.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn sessions(
    pool: &PgPool,
    scope: &Scope,
    label: Option<&str>,
    flag: SessionFlag,
    limit: i64,
) -> Result<Vec<SessionRow>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(format!(
        "SELECT session AS label, max(context) AS context, max(site) AS site,
            min(at_millis) AS first_at, max(at_millis) AS last_at,
            count(*)::bigint AS requests,
            count(*) FILTER (WHERE {JEV_CALLED_SQL})::bigint AS jev_calls,
            count(*) FILTER (WHERE outcome = 'blocked' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS blocked,
            count(*) FILTER (WHERE outcome = 'would_block' AND decision_path NOT IN ('bypass', 'unknown_site'))::bigint AS would_block
         FROM decision_log"
    ));
    push_scope(&mut query, scope);
    query.push(" AND session <> ''");
    if let Some(label) = label {
        query.push(" AND session = ").push_bind(label.to_owned());
    }
    query.push(" GROUP BY session");
    match flag {
        SessionFlag::Any => {}
        SessionFlag::Blocked => {
            query.push(" HAVING count(*) FILTER (WHERE outcome IN ('blocked', 'would_block')) > 0");
        }
        SessionFlag::Jev => {
            query.push(format!(
                " HAVING count(*) FILTER (WHERE {JEV_CALLED_SQL}) > 0"
            ));
        }
    }
    query
        .push(" ORDER BY last_at DESC LIMIT ")
        .push_bind(limit.clamp(1, 200));
    let rows = query.build().fetch_all(pool).await?;
    let mut sessions = Vec::with_capacity(rows.len());
    for row in &rows {
        sessions.push(SessionRow {
            label: row.try_get("label")?,
            context: row.try_get("context")?,
            site: row.try_get("site")?,
            first_at: row.try_get("first_at")?,
            last_at: row.try_get("last_at")?,
            requests: row.try_get("requests")?,
            jev_calls: row.try_get("jev_calls")?,
            blocked: row.try_get("blocked")?,
            would_block: row.try_get("would_block")?,
        });
    }
    Ok(sessions)
}

/// A session timeline row: the list columns plus the trace, which says what
/// the request taught the session.
#[derive(Debug, Clone, PartialEq)]
pub struct TimelineRow {
    /// The list columns.
    pub summary: RequestSummary,
    /// The trace of the request.
    pub trace: serde_json::Value,
}

/// Which rows of a session timeline to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineOnly {
    /// Every request the gateway judged: bypassed and unknown-site requests are excluded.
    Judged,
    /// Requests that called Jev.
    Jev,
    /// Refused and would-be-refused requests.
    Blocks,
    /// Every request.
    All,
}

/// Rows of one session in time order after `(at_millis, id)`.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn session_timeline(
    pool: &PgPool,
    scope: &Scope,
    label: &str,
    only: TimelineOnly,
    after: Option<(i64, i64)>,
    limit: i64,
) -> Result<Vec<TimelineRow>, sqlx::Error> {
    let mut query =
        QueryBuilder::<Postgres>::new(format!("SELECT {SUMMARY_COLUMNS}, trace FROM decision_log"));
    push_scope(&mut query, scope);
    // The literal condition lets the partial index decision_log_session_idx serve
    // the timeline (docs/07 section 7.8.3).
    query
        .push(" AND session <> '' AND session = ")
        .push_bind(label.to_owned());
    match only {
        TimelineOnly::Judged => {
            query.push(" AND decision_path NOT IN ('bypass', 'unknown_site')");
        }
        TimelineOnly::Jev => {
            query.push(format!(" AND {JEV_CALLED_SQL}"));
        }
        TimelineOnly::Blocks => {
            query.push(" AND outcome IN ('blocked', 'would_block')");
        }
        TimelineOnly::All => {}
    }
    if let Some((at_millis, id)) = after {
        query
            .push(" AND (at_millis, id) > (")
            .push_bind(at_millis)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    query
        .push(" ORDER BY at_millis ASC, id ASC LIMIT ")
        .push_bind(limit.clamp(1, 500));
    let rows = query.build().fetch_all(pool).await?;
    let mut timeline = Vec::with_capacity(rows.len());
    for row in &rows {
        timeline.push(TimelineRow {
            summary: summary_from_row(row)?,
            trace: row.try_get("trace")?,
        });
    }
    Ok(timeline)
}

/// The login request that opened the session `label`, as a timeline row. A login is
/// recorded under its client address rather than under the session it opens, so it
/// is found by `trace.response.issued_session`. `None` when that request is past
/// retention.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn issuing_row(pool: &PgPool, label: &str) -> Result<Option<TimelineRow>, sqlx::Error> {
    let mut query =
        QueryBuilder::<Postgres>::new(format!("SELECT {SUMMARY_COLUMNS}, trace FROM decision_log"));
    query
        .push(" WHERE trace #>> '{response,issued_session}' = ")
        .push_bind(label.to_owned())
        .push(" ORDER BY at_millis ASC, id ASC LIMIT 1");
    let row = query.build().fetch_optional(pool).await?;
    row.as_ref()
        .map(|row| -> Result<TimelineRow, sqlx::Error> {
            Ok(TimelineRow {
                summary: summary_from_row(row)?,
                trace: row.try_get("trace")?,
            })
        })
        .transpose()
}

/// Jev round trips over a window.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JevStats {
    /// Jev round trips, including timeouts.
    pub calls: i64,
    /// Round trips that produced a usable answer.
    pub ok: i64,
    /// Round trips that timed out.
    pub timeouts: i64,
    /// Failure codes with their counts.
    pub failures: Vec<(String, i64)>,
    /// Median round trip of successful calls.
    pub p50_ms: Option<f64>,
    /// 95th percentile of successful calls.
    pub p95_ms: Option<f64>,
    /// 99th percentile of successful calls.
    pub p99_ms: Option<f64>,
}

/// Jev round trips in `scope`, with latency percentiles and failure codes.
///
/// # Errors
/// Returns [`sqlx::Error`] when a query fails.
pub async fn jev_stats(pool: &PgPool, scope: &Scope) -> Result<JevStats, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(format!(
        "SELECT count(*) FILTER (WHERE {JEV_CALLED_SQL})::bigint AS calls,
            count(*) FILTER (WHERE {JEV_CALLED_SQL} AND jev_failure IS NULL)::bigint AS ok,
            count(*) FILTER (WHERE jev_failure = 'JEV_TIMEOUT')::bigint AS timeouts,
            percentile_cont(0.5) WITHIN GROUP (ORDER BY jev_ms)
                FILTER (WHERE {JEV_CALLED_SQL} AND jev_failure IS NULL) AS p50,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY jev_ms)
                FILTER (WHERE {JEV_CALLED_SQL} AND jev_failure IS NULL) AS p95,
            percentile_cont(0.99) WITHIN GROUP (ORDER BY jev_ms)
                FILTER (WHERE {JEV_CALLED_SQL} AND jev_failure IS NULL) AS p99
         FROM decision_log"
    ));
    push_scope(&mut query, scope);
    let row = query.build().fetch_one(pool).await?;
    let mut stats = JevStats {
        calls: row.try_get("calls")?,
        ok: row.try_get("ok")?,
        timeouts: row.try_get("timeouts")?,
        failures: Vec::new(),
        p50_ms: row.try_get("p50")?,
        p95_ms: row.try_get("p95")?,
        p99_ms: row.try_get("p99")?,
    };
    let mut failures = QueryBuilder::<Postgres>::new(
        "SELECT jev_failure, count(*)::bigint AS n FROM decision_log",
    );
    push_scope(&mut failures, scope);
    failures.push(format!(
        " AND {JEV_CALLED_SQL} AND jev_failure IS NOT NULL GROUP BY jev_failure ORDER BY jev_failure"
    ));
    for row in &failures.build().fetch_all(pool).await? {
        stats
            .failures
            .push((row.try_get("jev_failure")?, row.try_get("n")?));
    }
    Ok(stats)
}

/// Jev latency histogram: `(bucket, count)` pairs for `width_bucket` buckets
/// of 100 ms up to 30 s. Bucket 1 is 0 to 100 ms.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn jev_latency_histogram(
    pool: &PgPool,
    scope: &Scope,
) -> Result<Vec<(i32, i64)>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT width_bucket(jev_ms, 0, 30000, 300) AS bucket, count(*)::bigint AS n FROM decision_log",
    );
    push_scope(&mut query, scope);
    query.push(format!(
        " AND {JEV_CALLED_SQL} GROUP BY bucket ORDER BY bucket"
    ));
    let rows = query.build().fetch_all(pool).await?;
    let mut histogram = Vec::with_capacity(rows.len());
    for row in &rows {
        histogram.push((row.try_get("bucket")?, row.try_get("n")?));
    }
    Ok(histogram)
}

/// Jev confidence histogram: `(bucket, count)` pairs for ten buckets of 0.1.
/// Bucket 1 is 0.0 to 0.1; a confidence of exactly 1.0 falls into bucket 11.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn jev_confidence_histogram(
    pool: &PgPool,
    scope: &Scope,
) -> Result<Vec<(i32, i64)>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT width_bucket(jev_confidence, 0, 1, 10) AS bucket, count(*)::bigint AS n FROM decision_log",
    );
    push_scope(&mut query, scope);
    query.push(" AND jev_confidence IS NOT NULL GROUP BY bucket ORDER BY bucket");
    let rows = query.build().fetch_all(pool).await?;
    let mut histogram = Vec::with_capacity(rows.len());
    for row in &rows {
        histogram.push((row.try_get("bucket")?, row.try_get("n")?));
    }
    Ok(histogram)
}

/// Jev round trips, newest first, as the failure code of each (`None` for a
/// usable answer), for the health rule that looks at the last five calls.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn last_calls(pool: &PgPool, limit: i64) -> Result<Vec<Option<String>>, sqlx::Error> {
    let rows = sqlx::query(AssertSqlSafe(format!(
        "SELECT jev_failure FROM decision_log WHERE {JEV_CALLED_SQL}
         ORDER BY at_millis DESC, id DESC LIMIT $1"
    )))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.iter().map(|row| row.try_get("jev_failure")).collect()
}

/// The newest successful Jev call and the newest failed one since `since_millis`.
///
/// # Errors
/// Returns [`sqlx::Error`] when a query fails.
pub async fn last_ok_and_failure(
    pool: &PgPool,
    since_millis: i64,
) -> Result<(Option<i64>, Option<(i64, String, Option<String>)>), sqlx::Error> {
    let ok: Option<i64> = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT at_millis FROM decision_log
         WHERE at_millis >= $1 AND {JEV_CALLED_SQL} AND jev_failure IS NULL
         ORDER BY at_millis DESC LIMIT 1"
    )))
    .bind(since_millis)
    .fetch_optional(pool)
    .await?;
    let failure = sqlx::query(AssertSqlSafe(format!(
        "SELECT at_millis, jev_failure, site FROM decision_log
         WHERE at_millis >= $1 AND {JEV_CALLED_SQL} AND jev_failure IS NOT NULL
         ORDER BY at_millis DESC LIMIT 1"
    )))
    .bind(since_millis)
    .fetch_optional(pool)
    .await?;
    let failure = match failure {
        Some(row) => Some((
            row.try_get("at_millis")?,
            row.try_get("jev_failure")?,
            row.try_get("site")?,
        )),
        None => None,
    };
    Ok((ok, failure))
}

/// One group of requests with the same method, path, session presence,
/// decision and outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathGroup {
    /// HTTP method.
    pub method: String,
    /// Path without the query.
    pub path: String,
    /// Whether the requests carried a session credential.
    pub has_session: bool,
    /// The deciding step.
    pub decision_path: String,
    /// What the gateway did.
    pub outcome: String,
    /// Requests in the group.
    pub count: i64,
    /// One request id from the group, as an example.
    pub sample: String,
}

/// The largest number of path groups one preview or insight reads.
pub const GROUP_LIMIT: i64 = 5_000;

/// Groups the requests of a site by method, path, session presence, decision
/// and outcome, largest group first. Returns the groups and whether they are
/// all of the window.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn path_groups(
    pool: &PgPool,
    scope: &Scope,
) -> Result<(Vec<PathGroup>, bool), sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT method, path, (session <> '') AS has_session, decision_path, outcome,
            count(*)::bigint AS n, max(request_id) AS sample
         FROM decision_log",
    );
    push_scope(&mut query, scope);
    query.push(" GROUP BY method, path, (session <> ''), decision_path, outcome");
    query
        .push(" ORDER BY n DESC LIMIT ")
        .push_bind(GROUP_LIMIT + 1);
    let rows = query.build().fetch_all(pool).await?;
    let limit = usize::try_from(GROUP_LIMIT).unwrap_or(usize::MAX);
    let complete = rows.len() <= limit;
    let mut groups = Vec::with_capacity(rows.len().min(limit));
    for row in rows.iter().take(limit) {
        groups.push(PathGroup {
            method: row.try_get("method")?,
            path: row.try_get("path")?,
            has_session: row.try_get("has_session")?,
            decision_path: row.try_get("decision_path")?,
            outcome: row.try_get("outcome")?,
            count: row.try_get("n")?,
            sample: row.try_get("sample")?,
        });
    }
    Ok((groups, complete))
}

/// Per-minute Jev call counts against a per-session or per-address limit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MinutePeaks {
    /// The most Jev calls one key made in one minute.
    pub peak: i64,
    /// Calls above `threshold`, summed over every key and minute.
    pub excess: i64,
    /// Distinct keys that went above `threshold` in some minute.
    pub keys_over: i64,
}

/// Measures per-minute Jev calls per session (`by_address == false`, requests
/// with a session) or per client address (`by_address == true`, requests
/// without one), against `threshold`. A call the per-minute limit refused counts
/// as demand: without it the peak could never exceed the limit.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn minute_peaks(
    pool: &PgPool,
    scope: &Scope,
    by_address: bool,
    threshold: i64,
) -> Result<MinutePeaks, sqlx::Error> {
    let (key, condition) = if by_address {
        ("client", "session = ''")
    } else {
        ("session", "session <> ''")
    };
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT coalesce(max(n), 0)::bigint AS peak,
            coalesce(sum(n - ",
    );
    query
        .push_bind(threshold)
        .push(") FILTER (WHERE n > ")
        .push_bind(threshold);
    query.push(
        "), 0)::bigint AS excess,
            count(DISTINCT key) FILTER (WHERE n > ",
    );
    query
        .push_bind(threshold)
        .push(")::bigint AS keys_over FROM (SELECT ");
    query
        .push(key)
        .push(" AS key, (at_millis / 60000) AS minute, count(*) AS n FROM decision_log");
    push_scope(&mut query, scope);
    query.push(format!(
        " AND {JEV_DEMAND_SQL} AND {condition} GROUP BY 1, 2) AS per_minute"
    ));
    let row = query.build().fetch_one(pool).await?;
    Ok(MinutePeaks {
        peak: row.try_get("peak")?,
        excess: row.try_get("excess")?,
        keys_over: row.try_get("keys_over")?,
    })
}

/// The request id and Jev `state` document of the newest Jev calls in `scope`, newest
/// first, at most [`STATE_SCAN_LIMIT`] of them.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn jev_state_rows(
    pool: &PgPool,
    scope: &Scope,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT request_id, jev->>'state' AS state FROM decision_log",
    );
    push_scope(&mut query, scope);
    query.push(" AND jev IS NOT NULL AND jev->>'state' IS NOT NULL ORDER BY at_millis DESC LIMIT ");
    query.push_bind(STATE_SCAN_LIMIT);
    let rows = query.build().fetch_all(pool).await?;
    rows.iter()
        .map(|row| -> Result<(String, String), sqlx::Error> {
            Ok((row.try_get("request_id")?, row.try_get("state")?))
        })
        .collect()
}

/// Most decisions one object impact scan reads (docs/07 section 7.9.10).
pub const SLOT_SCAN_LIMIT: i64 = 20_000;

/// A decision of the window whose trace names a position an object map change moves:
/// a request value at it, or a place the session saw a value at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotRow {
    /// The gateway request id.
    pub request_id: String,
    /// HTTP method.
    pub method: String,
    /// The logical path the judge matched the request by, or the physical path for a row that
    /// kept none. A declaration's scope is read against this path.
    pub path: String,
    /// The deciding step.
    pub decision_path: String,
    /// The request values of the trace, as JSON text.
    pub values: String,
}

/// The decisions of `scope` that were fast-allowed or called Jev, and whose trace names one of
/// `slots` as a request position or as the position a value was seen at, or mentions one of
/// `fields` as a name. A name matches in any case and with any number of `_` or `-` between its
/// letters, so `doc_id` also finds `docId` and `doc__id`: the match is a superset, and the caller
/// checks each value exactly. Newest first, at most [`SLOT_SCAN_LIMIT`]. Returns the rows and
/// whether they are all of the window. A trace written before positions were recorded has no
/// `slot` and is not found.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn window_rows(
    pool: &PgPool,
    scope: &Scope,
    slots: &[String],
    fields: &[String],
) -> Result<(Vec<SlotRow>, bool), sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT request_id, method, COALESCE(logical_path, path) AS path, decision_path,
            (trace -> 'values')::text AS values
         FROM decision_log",
    );
    push_scope(&mut query, scope);
    query.push(
        " AND decision_path IN ('fast_allow', 'jev_allow', 'jev_deny', 'jev_unavailable')
          AND jsonb_typeof(trace -> 'values') = 'array'
          AND (EXISTS (
              SELECT 1 FROM jsonb_array_elements(trace -> 'values') AS v
              WHERE v ->> 'slot' = ANY(",
    );
    query.push_bind(slots.to_vec());
    query.push(
        ") OR EXISTS (
                  SELECT 1 FROM jsonb_array_elements(COALESCE(v -> 'sources', '[]'::jsonb)) AS s
                  WHERE s ->> 'slot' = ANY(",
    );
    query.push_bind(slots.to_vec());
    // Closes the `ANY`, the inner `EXISTS` and the outer one; the name test goes in the group.
    query.push(")))");
    if let Some(pattern) = name_pattern(fields) {
        query.push(" OR (trace -> 'values')::text ~* ");
        query.push_bind(pattern);
    }
    query.push(") ORDER BY at_millis DESC LIMIT ");
    query.push_bind(SLOT_SCAN_LIMIT + 1);
    let rows = query.build().fetch_all(pool).await?;
    let limit = usize::try_from(SLOT_SCAN_LIMIT).unwrap_or(usize::MAX);
    let complete = rows.len() <= limit;
    let mut out = Vec::with_capacity(rows.len().min(limit));
    for row in rows.iter().take(limit) {
        out.push(SlotRow {
            request_id: row.try_get("request_id")?,
            method: row.try_get("method")?,
            path: row.try_get("path")?,
            decision_path: row.try_get("decision_path")?,
            values: row.try_get("values")?,
        });
    }
    Ok((out, complete))
}

/// The case-insensitive pattern of the spellings of `names`: each name's letters in order, with
/// any number of `_` or `-` allowed between them, as the judge reads a field name (`doc_id`,
/// `docId`, `doc-id` and `doc__id` are one name). `None` when there is no name to look for.
fn name_pattern(names: &[String]) -> Option<String> {
    let alternatives: Vec<String> = names
        .iter()
        .map(|name| {
            name.chars()
                .filter(|c| !matches!(c, '_' | '-'))
                .map(|c| {
                    if c.is_alphanumeric() {
                        format!("{c}[_-]*")
                    } else {
                        format!("\\{c}[_-]*")
                    }
                })
                .collect::<String>()
        })
        .filter(|pattern| !pattern.is_empty())
        .collect();
    (!alternatives.is_empty()).then(|| format!("({})", alternatives.join("|")))
}

/// Requests in `since_millis..` whose trace says they cite a value learned
/// from a request that observe mode let through as would-be refused
/// (docs/07 section 7.4.6).
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn after_would_block_references(
    pool: &PgPool,
    site: &str,
    since_millis: i64,
) -> Result<i64, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        "WITH learners AS (
             SELECT request_id FROM decision_log
             WHERE site = $1 AND at_millis >= $2
               AND trace #>> '{response,after_would_block}' = 'true'
             LIMIT 5000
         )
         SELECT count(*)::bigint FROM decision_log d
         WHERE d.site = $1 AND d.at_millis >= $2
           AND EXISTS (
               SELECT 1
               FROM jsonb_array_elements(COALESCE(d.trace -> 'values', '[]'::jsonb)) AS v,
                    jsonb_array_elements(COALESCE(v -> 'sources', '[]'::jsonb)) AS s
               WHERE s ->> 'request_id' IN (SELECT request_id FROM learners)
           )",
    )
    .bind(site)
    .bind(since_millis)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Counts of rows by decision path, failure code and context, under a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breakdown {
    /// The deciding step.
    pub decision_path: String,
    /// The Jev failure code, if any.
    pub jev_failure: Option<String>,
    /// `session`, `address`, or `None`.
    pub context: Option<String>,
    /// Rows in this combination.
    pub count: i64,
}

/// Counts rows grouped by decision path, failure code and context.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn breakdown(pool: &PgPool, scope: &Scope) -> Result<Vec<Breakdown>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT decision_path, jev_failure, context, count(*)::bigint AS n FROM decision_log",
    );
    push_scope(&mut query, scope);
    query.push(" GROUP BY decision_path, jev_failure, context");
    let rows = query.build().fetch_all(pool).await?;
    let mut breakdown = Vec::with_capacity(rows.len());
    for row in &rows {
        breakdown.push(Breakdown {
            decision_path: row.try_get("decision_path")?,
            jev_failure: row.try_get("jev_failure")?,
            context: row.try_get("context")?,
            count: row.try_get("n")?,
        });
    }
    Ok(breakdown)
}

/// The full rows of the requests whose trace names `request_ids`, found
/// through their time window. Used to show the request a value came from.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn full_rows_in_window(
    pool: &PgPool,
    request_ids: &[String],
    from_millis: i64,
    to_millis: i64,
) -> Result<Vec<RequestDetail>, sqlx::Error> {
    let rows = sqlx::query(AssertSqlSafe(format!(
        "SELECT {DETAIL_COLUMNS} FROM decision_log
         WHERE request_id = ANY($1) AND at_millis BETWEEN $2 AND $3"
    )))
    .bind(request_ids.to_vec())
    .bind(from_millis)
    .bind(to_millis)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(RequestDetail {
                summary: summary_from_row(row)?,
                trace: row.try_get("trace")?,
                jev: row.try_get("jev")?,
                request_headers: row.try_get("request_headers")?,
            })
        })
        .collect()
}

/// The server version of the database, for the system page.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn server_version(pool: &PgPool) -> Result<String, sqlx::Error> {
    sqlx::query_scalar("SELECT current_setting('server_version')")
        .fetch_one(pool)
        .await
}

/// How many Jev calls a change of the Jev timeout from `old_ms` to `new_ms`
/// affects in `scope` (docs/07 section 7.9.10). A shorter timeout affects the
/// calls answered after the new limit; a longer one may let through the
/// timeouts recorded under the old limit.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn jev_timeout_impact(
    pool: &PgPool,
    scope: &Scope,
    old_ms: i64,
    new_ms: i64,
) -> Result<i64, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new("SELECT count(*)::bigint FROM decision_log");
    push_scope(&mut query, scope);
    if new_ms < old_ms {
        query
            .push(format!(
                " AND {JEV_CALLED_SQL} AND jev_failure IS NULL AND jev_ms > "
            ))
            .push_bind(new_ms);
    } else {
        query.push(" AND jev_failure = 'JEV_TIMEOUT'");
    }
    let count: i64 = query.build_query_scalar().fetch_one(pool).await?;
    Ok(count)
}

/// Requests the gateway refused for the reason `refused` in their trace (for
/// example `body_not_inspectable`), grouped by method and path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedGroup {
    /// HTTP method.
    pub method: String,
    /// Path without the query.
    pub path: String,
    /// Requests in the group.
    pub count: i64,
    /// One request id from the group.
    pub sample: String,
}

/// Groups the requests refused for `refused` under `scope`, largest first.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn refused_groups(
    pool: &PgPool,
    scope: &Scope,
    refused: &str,
) -> Result<Vec<RefusedGroup>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT method, path, count(*)::bigint AS n, max(request_id) AS sample FROM decision_log",
    );
    push_scope(&mut query, scope);
    query
        .push(" AND trace ->> 'refused' = ")
        .push_bind(refused.to_owned());
    query
        .push(" GROUP BY method, path ORDER BY n DESC LIMIT ")
        .push_bind(GROUP_LIMIT);
    let rows = query.build().fetch_all(pool).await?;
    let mut groups = Vec::with_capacity(rows.len());
    for row in &rows {
        groups.push(RefusedGroup {
            method: row.try_get("method")?,
            path: row.try_get("path")?,
            count: row.try_get("n")?,
            sample: row.try_get("sample")?,
        });
    }
    Ok(groups)
}

/// One group of Jev-called requests: the start of the hour they fell in, their
/// `jev_failure`, `jev_access` and `jev_attack` columns, and how many share them.
pub type JevOutcomeRow = (i64, Option<String>, Option<String>, Option<String>, i64);

/// Jev-called requests of the scope grouped by hour and by their conclusion columns,
/// oldest hour first (docs/07 section 7.9.7). Reads at most [`SCAN_LIMIT`] of the
/// newest rows; the console derives allow, deny and unavailable from the groups.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn jev_outcomes(
    pool: &PgPool,
    scope: &Scope,
    bucket_millis: i64,
) -> Result<Vec<JevOutcomeRow>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT bucket, jev_failure, jev_access, jev_attack, count(*)::bigint AS calls
         FROM (
            SELECT (at_millis / ",
    );
    query
        .push_bind(bucket_millis)
        .push(") * ")
        .push_bind(bucket_millis);
    query.push(" AS bucket, jev_failure, jev_access, jev_attack FROM decision_log");
    push_scope(&mut query, scope);
    query.push(format!(
        " AND {JEV_CALLED_SQL} ORDER BY at_millis DESC LIMIT {SCAN_LIMIT}"
    ));
    query.push(
        ") AS limited GROUP BY bucket, jev_failure, jev_access, jev_attack ORDER BY bucket ASC",
    );
    let rows = query.build().fetch_all(pool).await?;
    rows.iter()
        .map(|row| {
            Ok((
                row.try_get("bucket")?,
                row.try_get("jev_failure")?,
                row.try_get("jev_access")?,
                row.try_get("jev_attack")?,
                row.try_get("calls")?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;

    use super::*;
    use crate::partitions::{day_bounds_millis, ensure_partition};

    #[test]
    fn a_name_matches_its_spellings_in_any_case_and_with_separators() {
        assert_eq!(
            name_pattern(&["doc_id".to_owned()]).as_deref(),
            Some("(d[_-]*o[_-]*c[_-]*i[_-]*d[_-]*)")
        );
        // A name's own separators do not count: `doc__id` is the same name as `doc_id`.
        assert_eq!(
            name_pattern(&["doc__id".to_owned()]).as_deref(),
            Some("(d[_-]*o[_-]*c[_-]*i[_-]*d[_-]*)")
        );
        assert_eq!(name_pattern(&["_".to_owned()]), None);
        assert_eq!(name_pattern(&[]), None);
    }

    /// The site of the rows these tests write, so a scope on it sees only them.
    const TEST_SITE: &str = "stats-test";

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }

    /// Writes one decision row of [`TEST_SITE`].
    async fn insert(
        pool: &PgPool,
        at_millis: i64,
        decision_path: &str,
        outcome: &str,
        jev: Option<&str>,
        jev_ms: Option<i32>,
        jev_failure: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, method, path,
                decision_path, outcome, jev_ms, jev_failure, trace, jev)
             VALUES ($1, $2, $3, 'edge-test', 'host', 'client', 'GET', '/', $4, $5, $6, $7,
                '{}'::jsonb, $8::jsonb)",
        )
        .bind(at_millis)
        .bind(format!("{TEST_SITE}-{at_millis}"))
        .bind(TEST_SITE)
        .bind(decision_path)
        .bind(outcome)
        .bind(jev_ms)
        .bind(jev_failure)
        .bind(jev)
        .execute(pool)
        .await
        .expect("insert");
    }

    /// Writes the sample window of these tests: twelve one-minute slices of
    /// [`TEST_SITE`], starting one second into 2098-03-04 UTC, a day no other test
    /// uses. Returns the scope of that window.
    async fn seed(pool: &PgPool) -> Scope {
        let day = NaiveDate::from_ymd_opt(2098, 3, 4).expect("date");
        ensure_partition(pool, day).await.expect("partition");
        sqlx::query("DELETE FROM decision_log WHERE site = $1")
            .bind(TEST_SITE)
            .execute(pool)
            .await
            .expect("clear the test site");
        let (day_start, _) = day_bounds_millis(day).expect("bounds");
        let since = day_start + 1_000;
        // Slice `k` starts `k` minutes after `since`; `offset` keeps the rows apart.
        let at = |k: i32, offset: i64| since + i64::from(k) * 60_000 + offset;
        // One allowed request with a Jev call in each slice, the call taking 100 + 10 k ms.
        for k in 0..12 {
            insert(
                pool,
                at(k, 5),
                "allow",
                "allowed",
                Some(r#"{"state":"x"}"#),
                Some(100 + 10 * k),
                None,
            )
            .await;
        }
        // A refusal in every second slice.
        for k in (0..=10).step_by(2) {
            insert(pool, at(k, 6), "deny", "blocked", None, None, None).await;
        }
        // Observe mode would have refused in slices 0, 3, 6 and 9.
        for k in [0, 3, 6, 9] {
            insert(pool, at(k, 7), "allow", "would_block", None, None, None).await;
        }
        insert(pool, at(3, 8), "allow", "unjudged", None, None, None).await;
        // Bypassed and unknown-site requests are not judged.
        insert(pool, at(5, 9), "bypass", "allowed", None, None, None).await;
        insert(pool, at(7, 9), "unknown_site", "unjudged", None, None, None).await;
        // A call the limit refused is not a Jev call; a timed-out call is, at 2000 ms.
        insert(
            pool,
            at(2, 10),
            "allow",
            "allowed",
            Some(r#"{"state":"y"}"#),
            Some(5),
            Some("JEV_CALL_LIMIT"),
        )
        .await;
        insert(
            pool,
            at(9, 10),
            "allow",
            "allowed",
            Some(r#"{"state":"z"}"#),
            Some(2000),
            Some("JEV_TIMEOUT"),
        )
        .await;
        Scope {
            site: Some(TEST_SITE.to_owned()),
            since_millis: since,
            until_millis: since + 12 * 60_000 - 1,
        }
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn summary_and_spark_agree_with_the_sample_window() {
        let pool = connect_test_pool().await;
        let scope = seed(&pool).await;
        let totals = summary(&pool, &scope).await.expect("summary");
        // Twelve allowed requests with a Jev call, six refusals, four would-blocks, one
        // unjudged request, one bypass, one unknown-site request, one limited call and
        // one timeout.
        assert_eq!(totals.scanned, 27);
        assert!(totals.complete);
        // Bypassed and unknown-site requests are not judged.
        assert_eq!(totals.judged, 25);
        assert_eq!(totals.blocked, 6);
        assert_eq!(totals.would_block, 4);
        assert_eq!(totals.unjudged, 1);
        // The limited call is not a Jev call; the timed-out one is.
        assert_eq!(totals.jev_calls, 13);
        assert_eq!(totals.jev_timeouts, 1);
        // Linear interpolation over 100, 110, ..., 210 and 2000 ms.
        let p95 = totals.jev_p95_ms.expect("a 95th percentile over the calls");
        assert!((p95 - 926.0).abs() < 1e-6, "{p95}");

        // The slices of each figure add up to its total.
        let trend = spark(&pool, &scope).await.expect("spark");
        assert_eq!(trend.judged.len(), SPARK_POINTS);
        assert_eq!(trend.judged.iter().sum::<i64>(), totals.judged);
        assert_eq!(trend.blocked.iter().sum::<i64>(), totals.blocked);
        assert_eq!(trend.would_block.iter().sum::<i64>(), totals.would_block);
        assert_eq!(trend.unjudged.iter().sum::<i64>(), totals.unjudged);
        assert_eq!(trend.jev_calls.iter().sum::<i64>(), totals.jev_calls);
        // Slice 0 holds the allowed, the refused and the would-block request.
        assert_eq!(trend.judged[0], 3);
        // Slice 0 holds one call of 100 ms.
        let first = trend.jev_p95_ms[0].expect("a call in slice 0");
        assert!((first - 100.0).abs() < 1e-6, "{first}");
        // Slice 9 holds two calls, of 190 ms and 2000 ms: 190 + 0.95 * (2000 - 190).
        let ninth = trend.jev_p95_ms[9].expect("calls in slice 9");
        assert!((ninth - 1909.5).abs() < 1e-6, "{ninth}");
    }
}
