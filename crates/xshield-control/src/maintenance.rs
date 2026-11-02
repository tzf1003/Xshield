//! Partition, retention and edge status maintenance of the control plane
//! (docs/07-console-architecture.md section 7.8.2).

use std::time::Duration;

use chrono::{DateTime, NaiveDate};
use sqlx::PgPool;
use xshield_postgres::partitions;

use crate::params::DAY_MILLIS;

/// The time between maintenance passes, after the first one at startup.
const PASS_INTERVAL: Duration = Duration::from_hours(1);
/// An edge whose last heartbeat is older than this has its status row deleted.
const EDGE_STALE_MILLIS: i64 = DAY_MILLIS;

/// Runs [`maintain_once`] at startup and then once an hour, for as long as the
/// process runs. The binary spawns it once; it never returns.
pub async fn run(pool: PgPool) {
    let mut ticker = tokio::time::interval(PASS_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // The first tick completes at once, so the first pass runs at startup.
        ticker.tick().await;
        maintain_once(&pool, crate::params::now_millis()).await;
    }
}

/// Runs one maintenance pass at `now_millis`, in four independent steps: it creates
/// the decision log partitions from the start of the retention period to seven days
/// ahead, drops the partitions that ended before the retention period, deletes the
/// edge status rows that have not been refreshed for a day, and runs the object map
/// learning over the decision log (`object_learning`). A step that fails is logged,
/// and the next step still runs.
pub async fn maintain_once(pool: &PgPool, now_millis: i64) {
    match utc_day(now_millis) {
        Some(today) => ensure_partitions(pool, today).await,
        None => eprintln!(
            "xshield-control: partition maintenance skipped, {now_millis} is outside the calendar"
        ),
    }
    drop_expired_partitions(pool, now_millis).await;
    purge_stale_edges(pool, now_millis).await;
    crate::object_learning::learn_once(pool, now_millis).await;
}

/// The UTC day of `now_millis`, or `None` when the time is outside the calendar.
fn utc_day(now_millis: i64) -> Option<NaiveDate> {
    Some(DateTime::from_timestamp_millis(now_millis)?.date_naive())
}

/// Creates the partition of each day in [`partitions::partition_days`]. A day that
/// fails is logged, and the other days are still created.
async fn ensure_partitions(pool: &PgPool, today: NaiveDate) {
    for day in partitions::partition_days(today) {
        if let Err(error) = partitions::ensure_partition(pool, day).await {
            eprintln!("xshield-control: creating the partition for {day} failed: {error}");
        }
    }
}

/// The cutoff below which decision log partitions are dropped: `now_millis` less the
/// retention period. A retention that does not fit an `i64` keeps every partition.
fn retention_cutoff(now_millis: i64) -> i64 {
    let retention_millis = i64::try_from(partitions::RETENTION_DAYS)
        .map_or(i64::MAX, |days| days.saturating_mul(DAY_MILLIS));
    now_millis.saturating_sub(retention_millis)
}

/// Drops the decision log partitions that ended before the retention period.
async fn drop_expired_partitions(pool: &PgPool, now_millis: i64) {
    match partitions::drop_partitions_ended_before(pool, retention_cutoff(now_millis)).await {
        Ok(dropped) if !dropped.is_empty() => {
            eprintln!(
                "xshield-control: dropped {} decision log partitions past retention",
                dropped.len()
            );
        }
        Ok(_) => {}
        Err(error) => eprintln!("xshield-control: dropping expired partitions failed: {error}"),
    }
}

/// Deletes the edge status rows whose last heartbeat is older than
/// `EDGE_STALE_MILLIS`.
async fn purge_stale_edges(pool: &PgPool, now_millis: i64) {
    let stale_before = now_millis.saturating_sub(EDGE_STALE_MILLIS);
    let Some(before) = DateTime::from_timestamp_millis(stale_before) else {
        eprintln!(
            "xshield-control: edge status purge skipped, {stale_before} is outside the calendar"
        );
        return;
    };
    match partitions::purge_edges_seen_before(pool, before).await {
        Ok(0) => {}
        Ok(removed) => {
            eprintln!(
                "xshield-control: removed {removed} edge status rows not refreshed for a day"
            );
        }
        Err(error) => eprintln!("xshield-control: purging edge status failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_day_of_a_time_is_its_utc_date() {
        assert_eq!(
            utc_day(1_793_491_200_000),
            NaiveDate::from_ymd_opt(2026, 11, 1)
        );
        assert_eq!(
            utc_day(1_793_491_199_999),
            NaiveDate::from_ymd_opt(2026, 10, 31)
        );
    }

    #[test]
    fn the_cutoff_is_the_retention_before_now() {
        let retention = i64::try_from(partitions::RETENTION_DAYS).expect("retention");
        assert_eq!(
            retention_cutoff(10 * DAY_MILLIS),
            (10 - retention) * DAY_MILLIS
        );
    }
}
