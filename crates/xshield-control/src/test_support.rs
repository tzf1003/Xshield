//! Helpers the live tests of this crate share.

use sqlx::PgPool;
use xshield_postgres::partitions::ensure_partition;

/// The live tests run in parallel against one database. `ensure_partition` is `CREATE TABLE IF
/// NOT EXISTS`, which two connections creating the same day at once can still fail on, so the
/// tests take turns creating their partitions.
static PARTITION_TURNS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Creates the decision-log partitions of the days the `millis` fall on.
pub(crate) async fn ensure_days(pool: &PgPool, millis: &[i64]) {
    let _turn = PARTITION_TURNS.lock().await;
    for &at in millis {
        let day = chrono::DateTime::from_timestamp_millis(at)
            .expect("a day")
            .date_naive();
        ensure_partition(pool, day)
            .await
            .expect("create the partition");
    }
}
