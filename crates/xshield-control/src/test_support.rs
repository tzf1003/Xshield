//! Helpers the live tests of this crate share.

use sqlx::PgPool;
use xshield_postgres::partitions::ensure_partition;

/// Creates the decision-log partitions of the days the `millis` fall on. The live tests run in
/// parallel against one database; two of them creating the same day at once is safe.
pub(crate) async fn ensure_days(pool: &PgPool, millis: &[i64]) {
    for &at in millis {
        let day = chrono::DateTime::from_timestamp_millis(at)
            .expect("a day")
            .date_naive();
        ensure_partition(pool, day)
            .await
            .expect("create the partition");
    }
}
