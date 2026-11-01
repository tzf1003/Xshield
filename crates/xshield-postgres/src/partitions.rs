//! Daily partitions of `decision_log` (docs/07-console-architecture.md section
//! 7.8.2).
//!
//! Each UTC day has a partition named `decision_log_pYYYYMMDD`, created ahead
//! of time. There is no default partition: a row that fits no daily partition
//! is refused, and the gateway counts it as a write error.

use chrono::{DateTime, Days, NaiveDate, NaiveTime, Utc};
use sqlx::{AssertSqlSafe, PgPool, Row};

/// How many days of decision log are kept. A code default, not configuration
/// (docs/07 section 7.8.2).
pub const RETENTION_DAYS: u64 = 7;

/// One partition of the decision log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionInfo {
    /// Partition table name.
    pub name: String,
    /// The UTC day the partition holds; `None` when the name is not a daily
    /// partition name.
    pub day: Option<NaiveDate>,
    /// Estimated number of rows, from the planner statistics.
    pub rows_estimate: i64,
    /// Total size on disk, table and indexes, in bytes.
    pub bytes: i64,
}

/// Name of the partition holding `day`.
#[must_use]
pub fn partition_name(day: NaiveDate) -> String {
    format!("decision_log_p{}", day.format("%Y%m%d"))
}

/// The day a partition name stands for, if the name is a daily partition.
#[must_use]
pub fn day_of_partition(name: &str) -> Option<NaiveDate> {
    let digits = name.strip_prefix("decision_log_p")?;
    if digits.len() != 8 {
        return None;
    }
    NaiveDate::parse_from_str(digits, "%Y%m%d").ok()
}

/// Half-open `[start, end)` bounds of `day` in Unix milliseconds.
#[must_use]
pub fn day_bounds_millis(day: NaiveDate) -> Option<(i64, i64)> {
    let start = day.and_time(NaiveTime::MIN).and_utc().timestamp_millis();
    let next = day.checked_add_days(Days::new(1))?;
    let end = next.and_time(NaiveTime::MIN).and_utc().timestamp_millis();
    Some((start, end))
}

/// Failure of a partition maintenance step.
#[derive(Debug)]
pub enum PartitionError {
    /// The database refused a statement.
    Database(sqlx::Error),
    /// The requested day is outside the representable calendar.
    OutOfRange,
}

impl std::fmt::Display for PartitionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::OutOfRange => formatter.write_str("partition day is out of range"),
        }
    }
}

impl std::error::Error for PartitionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::OutOfRange => None,
        }
    }
}

impl From<sqlx::Error> for PartitionError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

/// Creates the partition for `day` if it does not exist yet. Idempotent.
///
/// # Errors
/// Returns [`PartitionError`] when the day is out of range or the statement fails.
pub async fn ensure_partition(pool: &PgPool, day: NaiveDate) -> Result<(), PartitionError> {
    let (start, end) = day_bounds_millis(day).ok_or(PartitionError::OutOfRange)?;
    let name = partition_name(day);
    let create = format!(
        "CREATE TABLE IF NOT EXISTS \"{name}\" PARTITION OF decision_log \
         FOR VALUES FROM ({start}) TO ({end})"
    );
    sqlx::query(AssertSqlSafe(create)).execute(pool).await?;
    Ok(())
}

/// Drops every daily partition whose end is at or before `cutoff_millis`: first
/// `DETACH PARTITION ... CONCURRENTLY`, so the parent table is not locked for
/// long, then `DROP TABLE`. Returns the names dropped.
///
/// # Errors
/// Returns [`PartitionError`] when a statement fails.
pub async fn drop_partitions_ended_before(
    pool: &PgPool,
    cutoff_millis: i64,
) -> Result<Vec<String>, PartitionError> {
    let mut dropped = Vec::new();
    for partition in list_partitions(pool).await? {
        // Only names that are exactly a daily partition name reach the SQL below.
        let Some(day) = day_of_partition(&partition.name) else {
            continue;
        };
        if partition_name(day) != partition.name {
            continue;
        }
        let Some((_, end)) = day_bounds_millis(day) else {
            continue;
        };
        if end > cutoff_millis {
            continue;
        }
        // DETACH ... CONCURRENTLY cannot run inside a transaction block, so each
        // statement runs on the pool, one at a time.
        let name = &partition.name;
        let detach = format!("ALTER TABLE decision_log DETACH PARTITION \"{name}\" CONCURRENTLY");
        sqlx::query(AssertSqlSafe(detach)).execute(pool).await?;
        let drop = format!("DROP TABLE \"{name}\"");
        sqlx::query(AssertSqlSafe(drop)).execute(pool).await?;
        dropped.push(partition.name);
    }
    Ok(dropped)
}

/// Lists the partitions of the decision log.
///
/// # Errors
/// Returns [`PartitionError`] when the catalog query fails.
pub async fn list_partitions(pool: &PgPool) -> Result<Vec<PartitionInfo>, PartitionError> {
    let rows = sqlx::query(
        "SELECT c.relname AS name,
                GREATEST(c.reltuples, 0)::bigint AS rows_estimate,
                pg_total_relation_size(c.oid)::bigint AS bytes
         FROM pg_inherits i
         JOIN pg_class c ON c.oid = i.inhrelid
         JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname = 'decision_log'
         ORDER BY c.relname",
    )
    .fetch_all(pool)
    .await?;
    let mut partitions = Vec::with_capacity(rows.len());
    for row in &rows {
        let name: String = row.try_get("name")?;
        partitions.push(PartitionInfo {
            day: day_of_partition(&name),
            name,
            rows_estimate: row.try_get("rows_estimate")?,
            bytes: row.try_get("bytes")?,
        });
    }
    Ok(partitions)
}

/// The timestamp of the oldest row, in Unix milliseconds.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn earliest_at_millis(pool: &PgPool) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar("SELECT at_millis FROM decision_log ORDER BY at_millis ASC LIMIT 1")
        .fetch_optional(pool)
        .await
}

/// Deletes heartbeat rows that have not been refreshed since `before`.
///
/// # Errors
/// Returns [`sqlx::Error`] when the statement fails.
pub async fn purge_edges_seen_before(
    pool: &PgPool,
    before: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM edge_status WHERE seen_at < $1")
        .bind(before)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_daily_partition_is_named_by_its_utc_day() {
        let day = NaiveDate::from_ymd_opt(2026, 11, 1).expect("date");
        assert_eq!(partition_name(day), "decision_log_p20261101");
        assert_eq!(day_of_partition("decision_log_p20261101"), Some(day));
        assert_eq!(day_of_partition("decision_log_default"), None);
        assert_eq!(day_of_partition("decision_log_p2026110x"), None);
    }

    #[test]
    fn a_day_spans_exactly_twenty_four_hours() {
        let day = NaiveDate::from_ymd_opt(2026, 11, 1).expect("date");
        let (start, end) = day_bounds_millis(day).expect("bounds");
        assert_eq!(start, 1_793_491_200_000);
        assert_eq!(end - start, 86_400_000);
    }

    // The database tests need a reachable PostgreSQL instance and run when
    // `XSHIELD_TEST_DATABASE_URL` is set (scripts/test_postgres.sh does that).

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn ensure_partition_creates_the_day_and_is_idempotent() {
        let pool = connect_test_pool().await;
        let day = NaiveDate::from_ymd_opt(2099, 6, 1).expect("date");
        ensure_partition(&pool, day).await.expect("first call");
        ensure_partition(&pool, day).await.expect("second call");

        let partitions = list_partitions(&pool).await.expect("list");
        let matching: Vec<&PartitionInfo> = partitions
            .iter()
            .filter(|partition| partition.name == partition_name(day))
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].day, Some(day));

        let bound: String = sqlx::query_scalar(
            "SELECT pg_get_expr(relpartbound, oid) FROM pg_class WHERE relname = $1",
        )
        .bind(partition_name(day))
        .fetch_one(&pool)
        .await
        .expect("partition bound");
        let (start, end) = day_bounds_millis(day).expect("bounds");
        assert_eq!(bound, format!("FOR VALUES FROM ('{start}') TO ('{end}')"));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn drop_removes_only_the_partitions_that_ended_by_the_cutoff() {
        let pool = connect_test_pool().await;
        // Two days that end at or before the cutoff, and one that ends after it.
        // The days lie in 1969 and 1970, which no other test uses, so dropping
        // partitions ended before the cutoff touches nothing else.
        let ended_first = NaiveDate::from_ymd_opt(1969, 12, 30).expect("date");
        let ended_second = NaiveDate::from_ymd_opt(1969, 12, 31).expect("date");
        let kept = NaiveDate::from_ymd_opt(1970, 1, 1).expect("date");
        for day in [ended_first, ended_second, kept] {
            ensure_partition(&pool, day).await.expect("create");
        }
        // The cutoff is the start of 1970-01-01 UTC, where 1969-12-31 ends exactly.
        let (cutoff, _) = day_bounds_millis(kept).expect("bounds");

        let dropped = drop_partitions_ended_before(&pool, cutoff)
            .await
            .expect("drop");
        assert!(dropped.contains(&partition_name(ended_first)));
        assert!(dropped.contains(&partition_name(ended_second)));
        assert!(!dropped.contains(&partition_name(kept)));

        let names: Vec<String> = list_partitions(&pool)
            .await
            .expect("list")
            .into_iter()
            .map(|partition| partition.name)
            .collect();
        assert!(!names.contains(&partition_name(ended_first)));
        assert!(!names.contains(&partition_name(ended_second)));
        assert!(names.contains(&partition_name(kept)));

        // Drop the remaining day too, so the table is left as the test found it.
        let (_, kept_end) = day_bounds_millis(kept).expect("bounds");
        drop_partitions_ended_before(&pool, kept_end)
            .await
            .expect("cleanup");
    }
}
