//! The gateway status light, its problems and the Jev health (docs/07 section 7.9.13).
//!
//! An instance is online when its heartbeat is at most 30 seconds old. The light
//! is `down` with no online instance, `warn` with any problem, and `ok`
//! otherwise. Each problem carries exactly the fields the console types.

use std::sync::Arc;

use axum::{Json, extract::State};
use chrono::{DateTime, Days, NaiveDate, Utc};
use serde_json::{Map, Value, json};
use xshield_postgres::{
    edge_status_store::{self, EdgeStatus},
    partitions::{self, PartitionInfo},
    site_spec_store::{self, SiteRecord},
};

use crate::{ControlState, error::ApiResult, jev, params::DAY_MILLIS};

/// How long a new site version may take to reach the gateways before it counts as behind.
const SAVE_GRACE_MILLIS: i64 = 30_000;
/// A log gap that ended within this long before now is reported.
const GAP_WINDOW_MILLIS: i64 = 15 * 60_000;
/// A heartbeat older than this is late.
const HEARTBEAT_LATE_MILLIS: i64 = 15_000;
/// The queue share of its capacity, in percent, above which pressure is reported.
const QUEUE_PRESSURE_PERCENT: i64 = 80;
/// The queue capacity an instance is assumed to have when it reports none.
const DEFAULT_QUEUE_CAPACITY: i64 = 10_000;
/// The future days with a partition that the console expects.
const FUTURE_DAYS_NEEDED: i64 = 2;

/// `GET /api/status`: the gateway light, the problems behind it, and the Jev
/// health. Polled every 15 seconds, so it reads only what the light needs.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
pub async fn status(State(state): State<Arc<ControlState>>) -> ApiResult<Json<Value>> {
    let now = Utc::now();
    let now_ms = now.timestamp_millis();
    let edges = edge_status_store::list(&state.pool).await?;
    let sites = site_spec_store::list(&state.pool).await?;
    let daily = partitions::list_partitions(&state.pool).await?;
    let jev_health = jev::health_summary(&state.pool, now_ms).await?;
    let problems = collect_problems(&edges, &sites, &daily, now);
    let online = edges.iter().filter(|edge| edge.is_online(now)).count();
    let total = edges
        .iter()
        .filter(|edge| heard_within_a_day(edge, now_ms))
        .count();
    Ok(Json(json!({
        "gateway": {
            "light": light(online, problems.len()),
            "edges": { "online": online, "total": total },
            "problems": problems,
        },
        "jev": jev_health.fields(),
    })))
}

/// The light: `down` with no online instance, `warn` with any problem, `ok`
/// otherwise.
#[must_use]
fn light(online: usize, problems: usize) -> &'static str {
    if online == 0 {
        "down"
    } else if problems > 0 {
        "warn"
    } else {
        "ok"
    }
}

/// The problems of section 7.9.13, in the order the spec lists them.
#[must_use]
fn collect_problems(
    edges: &[EdgeStatus],
    sites: &[SiteRecord],
    daily: &[PartitionInfo],
    now: DateTime<Utc>,
) -> Vec<Value> {
    let now_ms = now.timestamp_millis();
    let online: Vec<&EdgeStatus> = edges.iter().filter(|edge| edge.is_online(now)).collect();
    let mut found = site_load_failures(&online);
    found.extend(versions_behind(&online, sites, now_ms));
    found.extend(offline_edges(edges, now));
    found.extend(log_gaps(edges, now_ms));
    found.extend(queue_pressure(&online));
    found.extend(partition_missing(daily, now));
    found.extend(late_heartbeats(&online, now_ms));
    found
}

/// Sites that an online instance failed to load, with the error code it reports.
#[must_use]
fn site_load_failures(online: &[&EdgeStatus]) -> Vec<Value> {
    let mut found = Vec::new();
    for edge in online {
        let Some(sites) = edge.sites.as_object() else {
            continue;
        };
        for (site, entry) in sites {
            let Some(error) = entry.get("error").filter(|error| !error.is_null()) else {
                continue;
            };
            found.push(json!({
                "kind": "site_load_failed",
                "edge": edge.edge,
                "site": site,
                "error": error,
            }));
        }
    }
    found
}

/// Sites whose newest version was saved more than 30 seconds ago, and that an
/// online instance still reports at an older version.
#[must_use]
fn versions_behind(online: &[&EdgeStatus], sites: &[SiteRecord], now_ms: i64) -> Vec<Value> {
    let mut found = Vec::new();
    for record in sites {
        let saved_at = record.updated_at.timestamp_millis();
        if now_ms.saturating_sub(saved_at) <= SAVE_GRACE_MILLIS {
            continue;
        }
        let site = record.spec.name();
        for edge in online {
            let entry = edge.sites.get(site);
            // A site the instance failed to load is reported as `site_load_failed`.
            if entry
                .and_then(|entry| entry.get("error"))
                .is_some_and(|error| !error.is_null())
            {
                continue;
            }
            let Some(loaded) = entry
                .and_then(|entry| entry.get("version"))
                .and_then(Value::as_i64)
            else {
                continue;
            };
            if loaded < record.version {
                found.push(json!({
                    "kind": "version_behind",
                    "edge": edge.edge,
                    "site": site,
                    "expected": record.version,
                    "loaded": loaded,
                    "saved_at_millis": saved_at,
                }));
            }
        }
    }
    found
}

/// Whether an instance sent a heartbeat within the last day.
#[must_use]
fn heard_within_a_day(edge: &EdgeStatus, now_ms: i64) -> bool {
    edge.seen_at.timestamp_millis() >= now_ms.saturating_sub(DAY_MILLIS)
}

/// Instances that sent a heartbeat within the last day but not within the last 30
/// seconds, with the version of each site they stopped at. They are left out of
/// `version_behind`, so one fault is reported once.
#[must_use]
fn offline_edges(edges: &[EdgeStatus], now: DateTime<Utc>) -> Vec<Value> {
    let now_ms = now.timestamp_millis();
    edges
        .iter()
        .filter(|edge| !edge.is_online(now) && heard_within_a_day(edge, now_ms))
        .map(|edge| {
            json!({
                "kind": "edge_offline",
                "edge": edge.edge,
                "last_seen_ms": edge.seen_at.timestamp_millis(),
                "loaded": loaded_versions(edge),
            })
        })
        .collect()
}

/// The version each site an instance reports has loaded, by site name. A site with
/// no version, such as one that never loaded, is left out.
#[must_use]
fn loaded_versions(edge: &EdgeStatus) -> Value {
    let loaded: Map<String, Value> = edge
        .sites
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(site, entry)| {
            let version = entry.get("version").and_then(Value::as_i64)?;
            Some((site.clone(), json!(version)))
        })
        .collect();
    Value::Object(loaded)
}

/// Log gaps that ended within the last 15 minutes, from each instance's history.
#[must_use]
fn log_gaps(edges: &[EdgeStatus], now_ms: i64) -> Vec<Value> {
    let since = now_ms.saturating_sub(GAP_WINDOW_MILLIS);
    let mut found = Vec::new();
    for edge in edges {
        let Some(gaps) = edge.gaps.as_array() else {
            continue;
        };
        for gap in gaps {
            let Some(to_ms) = gap.get("to_ms").and_then(Value::as_i64) else {
                continue;
            };
            if to_ms < since {
                continue;
            }
            found.push(json!({
                "kind": "log_gap",
                "edge": edge.edge,
                "from_ms": gap.get("from_ms"),
                "to_ms": to_ms,
                "dropped": gap.get("dropped"),
                "dropped_bypass": gap.get("dropped_bypass"),
                "write_errors": gap.get("write_errors"),
            }));
        }
    }
    found
}

/// Online instances whose send queue is above 80 % of its capacity.
#[must_use]
fn queue_pressure(online: &[&EdgeStatus]) -> Vec<Value> {
    let mut found = Vec::new();
    for edge in online {
        let capacity = queue_capacity(edge);
        let queue = i64::from(edge.queue);
        if queue.saturating_mul(100) > capacity.saturating_mul(QUEUE_PRESSURE_PERCENT) {
            found.push(json!({
                "kind": "queue_pressure",
                "edge": edge.edge,
                "queue": queue,
                "capacity": capacity,
            }));
        }
    }
    found
}

/// The queue capacity an instance reports among its run parameters, or the default.
#[must_use]
fn queue_capacity(edge: &EdgeStatus) -> i64 {
    edge.params
        .get("fixed")
        .and_then(|fixed| fixed.get("queue_capacity"))
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_QUEUE_CAPACITY)
}

/// The partition problem: today has no partition, or fewer than two future days
/// in a row have one. `days_ahead` counts the future days in a row that have one.
#[must_use]
fn partition_missing(daily: &[PartitionInfo], now: DateTime<Utc>) -> Vec<Value> {
    let today = now.date_naive();
    let ahead = days_ahead(daily, today);
    if has_partition(daily, today) && ahead >= FUTURE_DAYS_NEEDED {
        return Vec::new();
    }
    vec![json!({ "kind": "partition_missing", "days_ahead": ahead })]
}

/// Whether a daily partition holds `day`.
#[must_use]
fn has_partition(daily: &[PartitionInfo], day: NaiveDate) -> bool {
    daily.iter().any(|partition| partition.day == Some(day))
}

/// How many days in a row, starting tomorrow, have a partition.
#[must_use]
fn days_ahead(daily: &[PartitionInfo], today: NaiveDate) -> i64 {
    let mut ahead = 0;
    let mut day = today;
    while let Some(next) = day.checked_add_days(Days::new(1)) {
        if !has_partition(daily, next) {
            break;
        }
        ahead += 1;
        day = next;
    }
    ahead
}

/// Online instances whose last heartbeat is more than 15 seconds old.
#[must_use]
fn late_heartbeats(online: &[&EdgeStatus], now_ms: i64) -> Vec<Value> {
    let mut found = Vec::new();
    for edge in online {
        if now_ms.saturating_sub(edge.seen_at.timestamp_millis()) > HEARTBEAT_LATE_MILLIS {
            found.push(json!({ "kind": "heartbeat_late", "edge": edge.edge }));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    fn partition(day: NaiveDate) -> PartitionInfo {
        PartitionInfo {
            name: String::new(),
            day: Some(day),
            rows_estimate: 0,
            bytes: 0,
        }
    }

    #[test]
    fn no_online_instance_is_down_and_a_problem_is_a_warning() {
        assert_eq!(light(0, 0), "down");
        assert_eq!(light(0, 3), "down");
        assert_eq!(light(2, 1), "warn");
        assert_eq!(light(2, 0), "ok");
    }

    #[test]
    fn future_days_are_counted_in_a_row_from_tomorrow() {
        let today = NaiveDate::from_ymd_opt(2026, 11, 1).expect("date");
        let plus = |days: u64| today.checked_add_days(Days::new(days)).expect("day");
        assert_eq!(
            days_ahead(&[partition(plus(1)), partition(plus(2))], today),
            2
        );
        assert_eq!(
            days_ahead(&[partition(plus(1)), partition(plus(3))], today),
            1
        );
        assert_eq!(days_ahead(&[partition(plus(2))], today), 0);
    }

    fn edge(name: &str, seen_at: DateTime<Utc>, sites: Value) -> EdgeStatus {
        EdgeStatus {
            edge: name.to_owned(),
            started_at: seen_at,
            seen_at,
            build: String::new(),
            listen: String::new(),
            tls: false,
            sites,
            sessions: 0,
            queue: 0,
            written: 0,
            dropped: 0,
            dropped_bypass: 0,
            write_errors: 0,
            gaps: json!([]),
            jev: json!({}),
            params: json!({}),
        }
    }

    #[test]
    fn an_instance_silent_for_over_thirty_seconds_is_offline_at_the_versions_it_stopped_at() {
        let now = DateTime::from_timestamp_millis(1_793_538_000_000).expect("time");
        let fresh = edge("edge-1", now, json!({}));
        let silent = edge(
            "edge-2",
            now - TimeDelta::seconds(60),
            json!({
                "emr": {"version": 11, "error": null},
                "juice": {"version": 7, "error": null},
                "shop": {"error": "SITE_CONFIG_ORIGIN_INVALID"},
            }),
        );
        let gone = edge(
            "edge-3",
            now - TimeDelta::hours(25),
            json!({"emr": {"version": 1, "error": null}}),
        );
        let found = offline_edges(&[fresh, silent, gone], now);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["kind"], json!("edge_offline"));
        assert_eq!(found[0]["edge"], json!("edge-2"));
        assert_eq!(found[0]["last_seen_ms"], json!(1_793_537_940_000_i64));
        assert_eq!(found[0]["loaded"], json!({"emr": 11, "juice": 7}));
    }
}
