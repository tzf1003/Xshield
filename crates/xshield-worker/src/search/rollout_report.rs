//! The facts behind an observe → enforce decision (docs/32 32.4): how many
//! requests completed in a window, how many an observe rollout forwarded past
//! a refusal, and which routes and reasons those were. The report states what
//! the index holds; whether that is enough to enforce is the approver's call.

use super::{deserialize_event_time, query_error, serialize_event_time};
use crate::{PublishError, PublisherConfig, valid_name};
use chrono::{DateTime, Utc};
use clickhouse::{Client, Row, sql::Identifier};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use xshield_core::{
    domain::{SiteId, TenantId},
    query::QueryWindow,
};

/// Most (route, reason) rows one report lists; the rest are only counted.
pub const ROLLOUT_REPORT_ROWS_MAX: u16 = 200;

/// A validated report request: one observe window label over a UTC window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolloutReportPlan {
    window: QueryWindow,
    rollout_revision: String,
}

impl RolloutReportPlan {
    /// Binds a window to the observe rollout it reports on.
    ///
    /// # Errors
    /// Returns [`PublishError::InvalidConfig`] when the label is not a name.
    pub fn new(window: QueryWindow, rollout_revision: &str) -> Result<Self, PublishError> {
        if !valid_name(rollout_revision) {
            return Err(PublishError::InvalidConfig);
        }
        Ok(Self {
            window,
            rollout_revision: rollout_revision.to_owned(),
        })
    }

    /// The half-open UTC window the counts cover.
    #[must_use]
    pub const fn window(&self) -> QueryWindow {
        self.window
    }

    /// The `rollout_revision` observed refusals are matched on.
    #[must_use]
    pub fn rollout_revision(&self) -> &str {
        &self.rollout_revision
    }
}

/// Observed refusals of one route for one reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Row)]
pub struct RolloutObservation {
    /// Empty when the request's route was recorded before the window began.
    pub operation_id: String,
    /// The refusal enforcement would have applied.
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

/// What the index holds about one observe window.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RolloutReport {
    /// Requests that reached a terminal event in the window, whatever the outcome.
    pub completed_requests: u64,
    /// Of those, refusals this rollout forwarded (`OBSERVED_WOULD_DENY`).
    pub observed_requests: u64,
    /// Enforced refusals of requests that matched no route: endpoints the
    /// configuration does not cover yet. Observe never forwards these.
    pub unrouted_refusals: u64,
    /// Observed refusals by route and reason, most frequent first.
    pub observations: Vec<RolloutObservation>,
    /// More (route, reason) pairs exist than [`ROLLOUT_REPORT_ROWS_MAX`].
    pub truncated: bool,
}

#[derive(Debug, Deserialize, Row)]
struct TotalsRow {
    completed: u64,
    observed: u64,
    unrouted: u64,
}

/// Reads the report for one site and window from the retention-aware view.
///
/// # Errors
/// Returns [`PublishError::QueryBudgetExceeded`] or
/// [`PublishError::QueryTimeout`] when a query budget runs out,
/// [`PublishError::InvalidEvent`] for rows that contradict the plan, and
/// [`PublishError::ClickHouse`] when the index is unavailable. Callers own
/// authorization and the access audit.
pub async fn query_rollout_report(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    plan: &RolloutReportPlan,
) -> Result<RolloutReport, PublishError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        execute(config, client, tenant_id, site_id, plan),
    )
    .await
    .map_err(|_| PublishError::QueryTimeout)?
}

/// One row per request that reached a terminal event in the window. The
/// terminal event carries the decision; the route comes from the request's
/// earlier events, so a request that started before the window may lack it.
const REQUESTS: &str = "(SELECT request_id, \
       argMinIf(operation_id,tuple(request_seq,event_id),operation_id != '' AND \
         event_type IN ('request.accepted','stage.completed','stage.skipped')) AS operation_id, \
       argMaxIf(outcome,tuple(request_seq,event_id),is_terminal = 1) AS outcome, \
       argMaxIf(reason_code,tuple(request_seq,event_id),is_terminal = 1) AS reason_code, \
       argMaxIf(JSONExtractString(payload_json,'rollout_revision'),tuple(request_seq,event_id), \
         is_terminal = 1) AS rollout_revision, \
       maxIf(occurred_at,is_terminal = 1) AS completed_at, \
       countIf(is_terminal = 1) AS terminals \
     FROM ? WHERE tenant_id = ? AND site_id = ? AND request_id != '' \
       AND occurred_at >= fromUnixTimestamp64Micro(?) AND occurred_at < fromUnixTimestamp64Micro(?) \
     GROUP BY request_id HAVING terminals > 0)";

const OBSERVED: &str = "outcome = 'OBSERVED_WOULD_DENY' AND rollout_revision = ?";

async fn execute(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    plan: &RolloutReportPlan,
) -> Result<RolloutReport, PublishError> {
    let micros = |seconds: u64| {
        i64::try_from(seconds)
            .ok()
            .and_then(|value| value.checked_mul(1_000_000))
            .ok_or(PublishError::InvalidConfig)
    };
    let start = micros(plan.window().start().value())?;
    let end = micros(plan.window().end().value())?;
    let bounded = |query: clickhouse::query::Query| {
        query
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

    let totals = bounded(
        client
            .query(&format!(
                "SELECT count() AS completed, countIf({OBSERVED}) AS observed, \
                 countIf(outcome = 'DENY' AND operation_id = '') AS unrouted FROM {REQUESTS}"
            ))
            .bind(plan.rollout_revision())
            .bind(Identifier(&config.active_view))
            .bind(tenant_id.as_str())
            .bind(site_id.as_str())
            .bind(start)
            .bind(end),
    )
    .fetch_one::<TotalsRow>()
    .await
    .map_err(query_error)?;

    let mut cursor = bounded(
        client
            .query(&format!(
                "SELECT operation_id, reason_code, count() AS count, max(completed_at) AS last_seen \
                 FROM {REQUESTS} WHERE {OBSERVED} GROUP BY operation_id, reason_code \
                 ORDER BY count DESC, operation_id, reason_code LIMIT ?"
            ))
            .bind(Identifier(&config.active_view))
            .bind(tenant_id.as_str())
            .bind(site_id.as_str())
            .bind(start)
            .bind(end)
            .bind(plan.rollout_revision())
            .bind(u64::from(ROLLOUT_REPORT_ROWS_MAX) + 1),
    )
    .fetch::<RolloutObservation>()
    .map_err(query_error)?;
    let mut observations = Vec::new();
    while let Some(row) = cursor.next().await.map_err(query_error)? {
        observations.push(row);
    }
    let truncated = observations.len() > usize::from(ROLLOUT_REPORT_ROWS_MAX);
    observations.truncate(usize::from(ROLLOUT_REPORT_ROWS_MAX));
    check(&totals, &observations, truncated, start..end)?;
    Ok(RolloutReport {
        completed_requests: totals.completed,
        observed_requests: totals.observed,
        unrouted_refusals: totals.unrouted,
        observations,
        truncated,
    })
}

/// Rejects rows that cannot come from the plan's own query: the counts must
/// add up, every pair is distinct and named, and nothing lies outside the
/// window.
fn check(
    totals: &TotalsRow,
    observations: &[RolloutObservation],
    truncated: bool,
    window: std::ops::Range<i64>,
) -> Result<(), PublishError> {
    let mut pairs = BTreeSet::new();
    let mut listed = 0_u64;
    let mut previous = u64::MAX;
    for row in observations {
        if !(row.operation_id.is_empty() || valid_name(&row.operation_id))
            || !valid_name(&row.reason_code)
            || row.count == 0
            || row.count > previous
            || !window.contains(&row.last_seen.timestamp_micros())
            || !pairs.insert((row.operation_id.as_str(), row.reason_code.as_str()))
        {
            return Err(PublishError::InvalidEvent);
        }
        previous = row.count;
        listed = listed
            .checked_add(row.count)
            .ok_or(PublishError::InvalidEvent)?;
    }
    let consistent = totals.observed <= totals.completed
        && totals.unrouted <= totals.completed - totals.observed
        && if truncated {
            listed < totals.observed
        } else {
            listed == totals.observed
        };
    if consistent {
        Ok(())
    } else {
        Err(PublishError::InvalidEvent)
    }
}

#[cfg(test)]
mod tests {
    use super::{RolloutObservation, RolloutReportPlan, TotalsRow, check};
    use chrono::{DateTime, Utc};
    use xshield_core::{identity::UnixSeconds, query::QueryWindow};

    const WINDOW: std::ops::Range<i64> = 1_000_000..2_000_000;

    fn row(operation: &str, reason: &str, count: u64) -> RolloutObservation {
        RolloutObservation {
            operation_id: operation.to_owned(),
            reason_code: reason.to_owned(),
            count,
            last_seen: DateTime::<Utc>::from_timestamp_micros(1_500_000).unwrap(),
        }
    }

    const fn totals(completed: u64, observed: u64, unrouted: u64) -> TotalsRow {
        TotalsRow {
            completed,
            observed,
            unrouted,
        }
    }

    #[test]
    fn a_report_must_add_up_to_its_totals() {
        let rows = [
            row("orders.list", "UI_ACTION_NOT_AVAILABLE", 5),
            row("account.read", "AUTH_REQUIRED", 2),
        ];
        assert!(check(&totals(20, 7, 3), &rows, false, WINDOW).is_ok());
        assert!(check(&totals(20, 8, 3), &rows, true, WINDOW).is_ok());
        assert!(check(&totals(0, 0, 0), &[], false, WINDOW).is_ok());
        for bad in [
            totals(20, 8, 3),  // listed rows miss one observed request
            totals(6, 7, 0),   // more observed than completed
            totals(20, 7, 14), // unrouted refusals overlap observed ones
        ] {
            assert!(check(&bad, &rows, false, WINDOW).is_err());
        }
        assert!(check(&totals(20, 7, 0), &rows, true, WINDOW).is_err());
    }

    #[test]
    fn rows_are_distinct_named_ordered_and_inside_the_window() {
        let ok = row("orders.list", "UI_ACTION_NOT_AVAILABLE", 1);
        let late = RolloutObservation {
            last_seen: DateTime::<Utc>::from_timestamp_micros(2_000_000).unwrap(),
            ..ok.clone()
        };
        for rows in [
            vec![ok.clone(), ok.clone()],
            vec![row("x/y", "AUTH_REQUIRED", 1)],
            vec![row("orders.list", "has space", 1)],
            vec![row("orders.list", "AUTH_REQUIRED", 0)],
            vec![ok.clone(), row("account.read", "AUTH_REQUIRED", 2)],
            vec![late],
        ] {
            let observed = rows.iter().map(|row| row.count).sum();
            assert!(check(&totals(10, observed, 0), &rows, false, WINDOW).is_err());
        }
    }

    #[test]
    fn the_plan_names_one_rollout() {
        let window = QueryWindow::new(UnixSeconds::new(10), UnixSeconds::new(20)).unwrap();
        assert_eq!(
            RolloutReportPlan::new(window, "rollout-1")
                .unwrap()
                .rollout_revision(),
            "rollout-1"
        );
        for invalid in ["", "has space", "x/y"] {
            assert!(RolloutReportPlan::new(window, invalid).is_err());
        }
    }
}
