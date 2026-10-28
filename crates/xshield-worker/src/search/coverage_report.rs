//! Refusal and coverage statistics for one site over a window (feasibility
//! P1 item 5): how many requests each route completed and refused, which
//! reasons the refusals had, and which endpoints no route covers yet. An
//! uncovered endpoint is listed by method and the path shape the edge
//! recorded (`xshield_core::path_shape`), never by the path itself.
//!
//! Like the rollout report, it states what the index holds. A request that
//! started before the window may lack its route and counts as unrouted.

use super::{deserialize_event_time, query_error, serialize_event_time};
use crate::{PublishError, PublisherConfig, valid_method, valid_name};
use chrono::{DateTime, Utc};
use clickhouse::{Client, Row, sql::Identifier};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use xshield_core::{
    domain::{SiteId, TenantId},
    path_shape::valid_path_shape,
    query::QueryWindow,
};

/// Most routes and most (route, reason) rows one report lists.
pub const COVERAGE_REPORT_ROWS_MAX: u16 = 200;
/// Most uncovered (method, path shape) rows one report lists.
pub const COVERAGE_REPORT_UNCOVERED_MAX: u16 = 100;

/// Requests one route completed in the window, and how they ended.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Row)]
pub struct RouteTraffic {
    /// The route's operation.
    pub operation_id: String,
    /// Requests that reached a terminal event.
    pub completed: u64,
    /// Of those, refused (`DENY`).
    pub refused: u64,
    /// Of those, refusals an observe rollout forwarded.
    pub observed: u64,
}

/// Refusals of one route for one reason. An empty route is a request that
/// matched none.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Row)]
pub struct RouteRefusal {
    /// The route's operation, or empty.
    pub operation_id: String,
    /// The stable reason code.
    pub reason_code: String,
    /// How many requests it was.
    pub count: u64,
    /// When the last of them completed.
    #[serde(
        deserialize_with = "deserialize_event_time",
        serialize_with = "serialize_event_time"
    )]
    pub last_seen: DateTime<Utc>,
}

/// Refused requests for an endpoint no route covers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Row)]
pub struct UncoveredEndpoint {
    /// The request method.
    pub method: String,
    /// The path's shape: route words kept, every other segment `{}`.
    pub path_shape: String,
    /// How many requests it was.
    pub count: u64,
    /// When the last of them completed.
    #[serde(
        deserialize_with = "deserialize_event_time",
        serialize_with = "serialize_event_time"
    )]
    pub last_seen: DateTime<Utc>,
}

/// What the index holds about a site's refusals and coverage in a window.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CoverageReport {
    /// Requests that reached a terminal event in the window.
    pub completed_requests: u64,
    /// Of those, refused.
    pub refused_requests: u64,
    /// Of those, refusals an observe rollout forwarded.
    pub observed_requests: u64,
    /// Refusals of requests that matched no route.
    pub unrouted_refusals: u64,
    /// Of those, recorded without a path shape (before the edge recorded
    /// one, or whose route lay outside the window).
    pub unshaped_unrouted_refusals: u64,
    /// Traffic per route, busiest first.
    pub routes: Vec<RouteTraffic>,
    /// More routes exist than [`COVERAGE_REPORT_ROWS_MAX`].
    pub routes_truncated: bool,
    /// Refusals per route and reason, most frequent first.
    pub refusals: Vec<RouteRefusal>,
    /// More (route, reason) pairs exist than [`COVERAGE_REPORT_ROWS_MAX`].
    pub refusals_truncated: bool,
    /// Endpoints no route covers, most refused first.
    pub uncovered: Vec<UncoveredEndpoint>,
    /// More uncovered endpoints exist than [`COVERAGE_REPORT_UNCOVERED_MAX`].
    pub uncovered_truncated: bool,
}

#[derive(Debug, Deserialize, Row)]
struct TotalsRow {
    completed: u64,
    refused: u64,
    observed: u64,
    unnamed: u64,
    unrouted: u64,
    unshaped: u64,
}

/// Reads the report for one site and window from the retention-aware view.
///
/// # Errors
/// Returns [`PublishError::QueryBudgetExceeded`] or
/// [`PublishError::QueryTimeout`] when a query budget runs out,
/// [`PublishError::InvalidEvent`] for rows that contradict the query, and
/// [`PublishError::ClickHouse`] when the index is unavailable. Callers own
/// authorization and the access audit.
pub async fn query_coverage_report(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    window: QueryWindow,
) -> Result<CoverageReport, PublishError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        execute(config, client, tenant_id, site_id, window),
    )
    .await
    .map_err(|_| PublishError::QueryTimeout)?
}

/// One row per request that reached a terminal event in the window, with
/// its route, method and, for a refusal that matched no route, path shape.
const REQUESTS: &str = "(SELECT request_id, \
       argMinIf(operation_id,tuple(request_seq,event_id),operation_id != '' AND \
         event_type IN ('request.accepted','stage.completed','stage.skipped')) AS operation_id, \
       argMinIf(method,tuple(request_seq,event_id),method != '') AS method, \
       argMaxIf(JSONExtractString(payload_json,'unmatched_path'),tuple(request_seq,event_id), \
         event_type = 'decision.composed') AS unmatched_path, \
       argMaxIf(outcome,tuple(request_seq,event_id),is_terminal = 1) AS outcome, \
       argMaxIf(reason_code,tuple(request_seq,event_id),is_terminal = 1) AS reason_code, \
       maxIf(occurred_at,is_terminal = 1) AS completed_at, \
       countIf(is_terminal = 1) AS terminals \
     FROM ? WHERE tenant_id = ? AND site_id = ? AND request_id != '' \
       AND occurred_at >= fromUnixTimestamp64Micro(?) AND occurred_at < fromUnixTimestamp64Micro(?) \
     GROUP BY request_id HAVING terminals > 0)";

const UNROUTED: &str = "outcome = 'DENY' AND operation_id = ''";

#[allow(clippy::too_many_lines)]
async fn execute(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    window: QueryWindow,
) -> Result<CoverageReport, PublishError> {
    let micros = |seconds: u64| {
        i64::try_from(seconds)
            .ok()
            .and_then(|value| value.checked_mul(1_000_000))
            .ok_or(PublishError::InvalidConfig)
    };
    let start = micros(window.start().value())?;
    let end = micros(window.end().value())?;
    let scoped = |sql: &str| {
        client
            .query(sql)
            .bind(Identifier(&config.active_view))
            .bind(tenant_id.as_str())
            .bind(site_id.as_str())
            .bind(start)
            .bind(end)
            .with_setting("max_execution_time", "2")
            .with_setting("timeout_before_checking_execution_speed", "0")
            .with_setting("max_rows_to_read", "1000000")
            .with_setting("max_bytes_to_read", "67108864")
            .with_setting("read_overflow_mode", "throw")
            .with_setting("timeout_overflow_mode", "throw")
            .with_setting("max_result_bytes", "1048576")
            .with_setting("result_overflow_mode", "throw")
            .with_setting("max_memory_usage", "268435456")
            .with_setting("max_threads", "2")
            .with_setting("wait_end_of_query", "1")
    };
    let rows_max = u64::from(COVERAGE_REPORT_ROWS_MAX) + 1;

    let totals = scoped(&format!(
        "SELECT count() AS completed, countIf(outcome = 'DENY') AS refused, \
         countIf(outcome = 'OBSERVED_WOULD_DENY') AS observed, \
         countIf(operation_id = '') AS unnamed, countIf({UNROUTED}) AS unrouted, \
         countIf({UNROUTED} AND unmatched_path = '') AS unshaped FROM {REQUESTS}"
    ))
    .fetch_one::<TotalsRow>()
    .await
    .map_err(query_error)?;

    let mut routes = Vec::new();
    let mut cursor = scoped(&format!(
        "SELECT operation_id, count() AS completed, countIf(outcome = 'DENY') AS refused, \
         countIf(outcome = 'OBSERVED_WOULD_DENY') AS observed FROM {REQUESTS} \
         WHERE operation_id != '' GROUP BY operation_id \
         ORDER BY completed DESC, operation_id LIMIT ?"
    ))
    .bind(rows_max)
    .fetch::<RouteTraffic>()
    .map_err(query_error)?;
    while let Some(row) = cursor.next().await.map_err(query_error)? {
        routes.push(row);
    }

    let mut refusals = Vec::new();
    let mut cursor = scoped(&format!(
        "SELECT operation_id, reason_code, count() AS count, max(completed_at) AS last_seen \
         FROM {REQUESTS} WHERE outcome = 'DENY' GROUP BY operation_id, reason_code \
         ORDER BY count DESC, operation_id, reason_code LIMIT ?"
    ))
    .bind(rows_max)
    .fetch::<RouteRefusal>()
    .map_err(query_error)?;
    while let Some(row) = cursor.next().await.map_err(query_error)? {
        refusals.push(row);
    }

    let mut uncovered = Vec::new();
    let mut cursor = scoped(&format!(
        "SELECT method, unmatched_path AS path_shape, count() AS count, \
         max(completed_at) AS last_seen FROM {REQUESTS} \
         WHERE {UNROUTED} AND unmatched_path != '' GROUP BY method, path_shape \
         ORDER BY count DESC, method, path_shape LIMIT ?"
    ))
    .bind(u64::from(COVERAGE_REPORT_UNCOVERED_MAX) + 1)
    .fetch::<UncoveredEndpoint>()
    .map_err(query_error)?;
    while let Some(row) = cursor.next().await.map_err(query_error)? {
        uncovered.push(row);
    }

    let routes_truncated = routes.len() > usize::from(COVERAGE_REPORT_ROWS_MAX);
    routes.truncate(usize::from(COVERAGE_REPORT_ROWS_MAX));
    let refusals_truncated = refusals.len() > usize::from(COVERAGE_REPORT_ROWS_MAX);
    refusals.truncate(usize::from(COVERAGE_REPORT_ROWS_MAX));
    let uncovered_truncated = uncovered.len() > usize::from(COVERAGE_REPORT_UNCOVERED_MAX);
    uncovered.truncate(usize::from(COVERAGE_REPORT_UNCOVERED_MAX));
    let report = CoverageReport {
        completed_requests: totals.completed,
        refused_requests: totals.refused,
        observed_requests: totals.observed,
        unrouted_refusals: totals.unrouted,
        unshaped_unrouted_refusals: totals.unshaped,
        routes,
        routes_truncated,
        refusals,
        refusals_truncated,
        uncovered,
        uncovered_truncated,
    };
    check(&report, totals.unnamed, start..end)?;
    Ok(report)
}

fn sum(mut counts: impl Iterator<Item = u64>) -> Result<u64, PublishError> {
    counts
        .try_fold(0_u64, u64::checked_add)
        .ok_or(PublishError::InvalidEvent)
}

/// `listed` equals `total` for a complete list and is below it for a cut one.
const fn adds_up(listed: u64, total: u64, truncated: bool) -> bool {
    if truncated {
        listed < total
    } else {
        listed == total
    }
}

/// Rejects a report that cannot come from its own queries: totals nest,
/// every list is distinct, named, ordered, inside the window and adds up.
fn check(
    report: &CoverageReport,
    unnamed: u64,
    window: std::ops::Range<i64>,
) -> Result<(), PublishError> {
    let invalid = || PublishError::InvalidEvent;
    let nested = report.unshaped_unrouted_refusals <= report.unrouted_refusals
        && report.unrouted_refusals <= report.refused_requests
        && report.unrouted_refusals <= unnamed
        && unnamed <= report.completed_requests
        && report
            .refused_requests
            .checked_add(report.observed_requests)
            .is_some_and(|ended| ended <= report.completed_requests);
    if !nested {
        return Err(invalid());
    }

    let mut previous = u64::MAX;
    let mut names = BTreeSet::new();
    for route in &report.routes {
        if !valid_name(&route.operation_id)
            || route.completed == 0
            || route.completed > previous
            || route.refused + route.observed > route.completed
            || !names.insert(route.operation_id.as_str())
        {
            return Err(invalid());
        }
        previous = route.completed;
    }
    let routed = sum(report.routes.iter().map(|route| route.completed))?;
    if !adds_up(
        routed,
        report.completed_requests - unnamed,
        report.routes_truncated,
    ) {
        return Err(invalid());
    }

    let mut previous = u64::MAX;
    let mut pairs = BTreeSet::new();
    for row in &report.refusals {
        if !(row.operation_id.is_empty() || valid_name(&row.operation_id))
            || !valid_name(&row.reason_code)
            || row.count == 0
            || row.count > previous
            || !window.contains(&row.last_seen.timestamp_micros())
            || !pairs.insert((row.operation_id.as_str(), row.reason_code.as_str()))
        {
            return Err(invalid());
        }
        previous = row.count;
    }
    let refused = sum(report.refusals.iter().map(|row| row.count))?;
    if !adds_up(refused, report.refused_requests, report.refusals_truncated) {
        return Err(invalid());
    }

    let mut previous = u64::MAX;
    let mut endpoints = BTreeSet::new();
    for row in &report.uncovered {
        if !valid_method(&row.method)
            || !valid_path_shape(&row.path_shape)
            || row.count == 0
            || row.count > previous
            || !window.contains(&row.last_seen.timestamp_micros())
            || !endpoints.insert((row.method.as_str(), row.path_shape.as_str()))
        {
            return Err(invalid());
        }
        previous = row.count;
    }
    let shaped = sum(report.uncovered.iter().map(|row| row.count))?;
    if adds_up(
        shaped,
        report.unrouted_refusals - report.unshaped_unrouted_refusals,
        report.uncovered_truncated,
    ) {
        Ok(())
    } else {
        Err(invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::{CoverageReport, RouteRefusal, RouteTraffic, UncoveredEndpoint, check};
    use chrono::{DateTime, Utc};

    const WINDOW: std::ops::Range<i64> = 1_000_000..2_000_000;

    fn seen() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_micros(1_500_000).unwrap()
    }

    fn route(operation: &str, completed: u64, refused: u64) -> RouteTraffic {
        RouteTraffic {
            operation_id: operation.to_owned(),
            completed,
            refused,
            observed: 0,
        }
    }

    fn refusal(operation: &str, reason: &str, count: u64) -> RouteRefusal {
        RouteRefusal {
            operation_id: operation.to_owned(),
            reason_code: reason.to_owned(),
            count,
            last_seen: seen(),
        }
    }

    fn uncovered(method: &str, shape: &str, count: u64) -> UncoveredEndpoint {
        UncoveredEndpoint {
            method: method.to_owned(),
            path_shape: shape.to_owned(),
            count,
            last_seen: seen(),
        }
    }

    /// Ten requests: orders.list 6 (2 refused), account.read 1, three that
    /// matched no route (two shaped as one endpoint, one unshaped).
    fn report() -> CoverageReport {
        CoverageReport {
            completed_requests: 10,
            refused_requests: 5,
            observed_requests: 0,
            unrouted_refusals: 3,
            unshaped_unrouted_refusals: 1,
            routes: vec![route("orders.list", 6, 2), route("account.read", 1, 0)],
            routes_truncated: false,
            refusals: vec![
                refusal("", "OPERATION_NOT_MATCHED", 3),
                refusal("orders.list", "AUTH_REQUIRED", 2),
            ],
            refusals_truncated: false,
            uncovered: vec![uncovered("GET", "/api/users/{}", 2)],
            uncovered_truncated: false,
        }
    }

    #[test]
    fn a_report_must_add_up_to_its_totals() {
        assert!(check(&report(), 3, WINDOW).is_ok());
        let empty = CoverageReport {
            completed_requests: 0,
            refused_requests: 0,
            unrouted_refusals: 0,
            unshaped_unrouted_refusals: 0,
            routes: vec![],
            refusals: vec![],
            uncovered: vec![],
            ..report()
        };
        assert!(check(&empty, 0, WINDOW).is_ok());
        let cut = CoverageReport {
            routes_truncated: true,
            completed_requests: 11,
            ..report()
        };
        assert!(check(&cut, 3, WINDOW).is_ok());
        for broken in [
            CoverageReport {
                completed_requests: 11,
                ..report()
            },
            CoverageReport {
                refused_requests: 6,
                ..report()
            },
            CoverageReport {
                unshaped_unrouted_refusals: 0,
                ..report()
            },
            CoverageReport {
                unshaped_unrouted_refusals: 4,
                ..report()
            },
            CoverageReport {
                observed_requests: 6,
                ..report()
            },
            CoverageReport {
                uncovered_truncated: true,
                ..report()
            },
        ] {
            assert!(check(&broken, 3, WINDOW).is_err(), "{broken:?}");
        }
        assert!(check(&report(), 2, WINDOW).is_err());
    }

    #[test]
    fn rows_are_distinct_valid_ordered_and_inside_the_window() {
        let late = DateTime::<Utc>::from_timestamp_micros(2_000_000).unwrap();
        let mutations: [fn(&mut CoverageReport); 9] = [
            |report| report.routes[1] = route("orders.list", 1, 0),
            |report| report.routes[1] = route("x/y", 1, 0),
            |report| report.routes[0].refused = 7,
            |report| report.routes.swap(0, 1),
            |report| report.refusals[1].reason_code = "has space".to_owned(),
            |report| {
                report.refusals[0].last_seen =
                    DateTime::<Utc>::from_timestamp_micros(2_000_000).unwrap();
            },
            |report| report.uncovered[0].path_shape = "/api/users/4711".to_owned(),
            |report| report.uncovered[0].method = "get".to_owned(),
            |report| report.uncovered[0].count = 0,
        ];
        for mutate in mutations {
            let mut broken = report();
            mutate(&mut broken);
            assert!(check(&broken, 3, WINDOW).is_err(), "{broken:?}");
        }
        let mut stale = report();
        stale.uncovered[0].last_seen = late;
        assert!(check(&stale, 3, WINDOW).is_err());
    }
}
