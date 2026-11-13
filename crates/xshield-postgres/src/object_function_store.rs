//! Function evidence of the object-map learning (docs/07 section 7.9.19): which units used each function
//! (a method and a route template) by UTC day, which administrator units used it, and which ordinary units
//! were refused it. The rows sit in `object_response_evidence`, beside the response tiers: `migrations/0010`
//! defines the table and `migrations/0011_function_evidence.sql` admits the four function kinds. Only the
//! control plane writes them.
//!
//! A write names the site's generation, as the other learning writes do, and lands only while the site still
//! has that configuration. A repeated fact changes nothing, so recording a batch again is harmless.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
use xshield_core::context::learning::{FunctionEvidence, FunctionFact, FunctionUse};

use crate::object_learning_store::LearningStoreError;

/// Rows per INSERT statement, as the other evidence writes count them.
const FUNCTION_CHUNK: usize = 1_000;

/// The kind a unit that the site identifies used a function under.
const USED: &str = "function";
/// The kind a unit without an identity used a function under.
const ANONYMOUS: &str = "function_anon";
/// The kind an administrator's unit used a function under.
const ADMIN: &str = "function_admin";
/// The kind an ordinary unit was refused a function under.
const REFUSED: &str = "function_refused";

/// One row a batch writes: its kind, function, unit and day.
type FunctionRow<'a> = (&'static str, &'a str, &'a str, u64);

/// Records the function facts of a batch of the site's `generation`. A fact of one kind, function, unit and
/// UTC day is one row. Rows of a generation the site no longer has are dropped.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn record_function_facts(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    facts: &[FunctionFact],
) -> Result<(), LearningStoreError> {
    let mut distinct: BTreeSet<FunctionRow<'_>> = BTreeSet::new();
    for fact in facts {
        let row = match fact {
            FunctionFact::Used {
                function,
                unit,
                day,
            } => (USED, function.as_str(), unit.as_str(), *day),
            FunctionFact::Anonymous {
                function,
                unit,
                day,
            } => (ANONYMOUS, function.as_str(), unit.as_str(), *day),
            FunctionFact::Admin {
                function,
                unit,
                day,
            } => (ADMIN, function.as_str(), unit.as_str(), *day),
            FunctionFact::Refused {
                function,
                unit,
                day,
            } => (REFUSED, function.as_str(), unit.as_str(), *day),
        };
        distinct.insert(row);
    }
    let rows: Vec<FunctionRow<'_>> = distinct.into_iter().collect();
    for chunk in rows.chunks(FUNCTION_CHUNK) {
        // One row per tuple, as the other evidence writes do: a text column is one value per row.
        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO object_response_evidence (site, kind, slot, unit, day)
             SELECT site, kind, slot, unit, day FROM (",
        );
        builder.push_values(chunk, |mut values, (kind, function, unit, day)| {
            values.push_bind(site);
            values.push_unseparated("::text");
            values.push_bind(*kind);
            values.push_unseparated("::text");
            values.push_bind(*function);
            values.push_unseparated("::text");
            values.push_bind(*unit);
            values.push_unseparated("::text");
            values.push_bind(day_i64(*day));
            values.push_unseparated("::bigint");
        });
        // The rows land only while the site still has the configuration of this generation.
        builder.push(
            ") AS v(site, kind, slot, unit, day)
             WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = ",
        );
        builder.push_bind(site);
        builder.push(" AND created_at = ");
        builder.push_bind(generation);
        builder.push(
            " FOR SHARE)
             ON CONFLICT (site, kind, slot, unit, day) DO NOTHING",
        );
        builder.build().execute(pool).await?;
    }
    Ok(())
}

/// The function keys with evidence from `oldest_day` on, each with the distinct units that used it: the
/// function, anonymous and administrator uses counted together, a unit once. Refusals alone make no key.
/// The keys come most-used first, then by key, at most `limit` of them. The second value says whether more
/// keys have evidence than `limit`.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn function_keys(
    pool: &PgPool,
    site: &str,
    oldest_day: u64,
    limit: usize,
) -> Result<(Vec<FunctionUse>, bool), LearningStoreError> {
    let fetch = i64::try_from(limit).unwrap_or(i64::MAX).saturating_add(1);
    let rows = sqlx::query(
        "SELECT slot, count(DISTINCT unit) AS units FROM object_response_evidence
         WHERE site = $1 AND kind IN ('function', 'function_anon', 'function_admin') AND day >= $2
         GROUP BY slot ORDER BY units DESC, slot LIMIT $3",
    )
    .bind(site)
    .bind(day_i64(oldest_day))
    .bind(fetch)
    .fetch_all(pool)
    .await?;
    let more = rows.len() > limit;
    let mut keys = Vec::with_capacity(rows.len().min(limit));
    for row in rows.iter().take(limit) {
        keys.push(FunctionUse {
            key: row.try_get("slot")?,
            units: count_u32(row.try_get::<i64, _>("units")?),
        });
    }
    Ok((keys, more))
}

/// The evidence of each merged function over the window from `oldest_day` on. `mapping` names, for each
/// function key, the key its evidence counts under (`merge_functions` in xshield-core). The units and days
/// of keys that map to one key count once. The result has an entry for each merged key with evidence.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure, or when a stored kind is not one this build reads.
pub async fn function_evidence(
    pool: &PgPool,
    site: &str,
    oldest_day: u64,
    mapping: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, FunctionEvidence>, LearningStoreError> {
    let originals: Vec<String> = mapping.keys().cloned().collect();
    let merged: Vec<String> = mapping.values().cloned().collect();
    let rows = sqlx::query(
        "SELECT m.merged, e.kind, count(DISTINCT e.unit) AS units,
                count(DISTINCT e.day) AS days, max(e.day) AS last_day
         FROM unnest($2::text[], $3::text[]) AS m(original, merged)
         JOIN object_response_evidence e ON e.slot = m.original
         WHERE e.site = $1 AND e.day >= $4
           AND e.kind IN ('function', 'function_anon', 'function_admin', 'function_refused')
         GROUP BY m.merged, e.kind",
    )
    .bind(site)
    .bind(originals)
    .bind(merged)
    .bind(day_i64(oldest_day))
    .fetch_all(pool)
    .await?;
    let mut evidence: BTreeMap<String, FunctionEvidence> = BTreeMap::new();
    for row in &rows {
        let key: String = row.try_get("merged")?;
        let kind: String = row.try_get("kind")?;
        let units = count_u32(row.try_get::<i64, _>("units")?);
        let days = count_u32(row.try_get::<i64, _>("days")?);
        let last_day = u64::try_from(row.try_get::<i64, _>("last_day")?).unwrap_or(0);
        let entry = evidence.entry(key).or_default();
        entry.last_day = entry.last_day.max(last_day);
        match kind.as_str() {
            USED | ANONYMOUS => {
                entry.ordinary_units = entry.ordinary_units.saturating_add(units);
            }
            ADMIN => {
                entry.admin_units = units;
                entry.admin_days = days;
            }
            REFUSED => entry.refused_units = units,
            other => {
                return Err(LearningStoreError::Database(sqlx::Error::Decode(
                    format!("unknown function kind {other} in object_response_evidence").into(),
                )));
            }
        }
    }
    Ok(evidence)
}

/// The distinct units that used any function over the window from `oldest_day` on: the ordinary units the
/// rules weigh against "no ordinary unit used it". Anonymous units are not counted.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn site_ordinary_units(
    pool: &PgPool,
    site: &str,
    oldest_day: u64,
) -> Result<u32, LearningStoreError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT unit) FROM object_response_evidence
         WHERE site = $1 AND kind = 'function' AND day >= $2",
    )
    .bind(site)
    .bind(day_i64(oldest_day))
    .fetch_one(pool)
    .await?;
    Ok(count_u32(count))
}

/// A day counted from the epoch as the column stores it. A value out of range saturates, which no real day
/// reaches.
fn day_i64(day: u64) -> i64 {
    i64::try_from(day).unwrap_or(i64::MAX)
}

/// A count the table returns as a 64-bit integer, held as the evidence keeps it. A count too large for it
/// saturates.
fn count_u32(count: i64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    // These storage-layer tests need a reachable PostgreSQL instance. They run when
    // `XSHIELD_TEST_DATABASE_URL` is set (scripts/test_postgres.sh does that after applying
    // `migrations/`).

    use std::sync::atomic::{AtomicU64, Ordering};

    use xshield_core::context::learning::{SeenUnit, TierFact};

    use super::*;
    use crate::object_learning_store::forget_site;
    use crate::object_tier_store::{load_tier_evidence, prune_tier_evidence, record_tier_facts};

    /// The function the tests read.
    const FUNCTION: &str = "GET /api/patients/{id}";
    const DAY: u64 = 20_000;

    fn unique_site(prefix: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!("{prefix}_{}", COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }

    /// Creates the configuration row a write looks for, and returns its generation.
    async fn with_site(pool: &PgPool, site: &str) -> DateTime<Utc> {
        sqlx::query_scalar(
            "INSERT INTO site_configs (name, spec, version) VALUES ($1, '{}'::jsonb, 1)
             RETURNING created_at",
        )
        .bind(site)
        .fetch_one(pool)
        .await
        .expect("create the site row")
    }

    fn used(function: &str, unit: &str, day: u64) -> FunctionFact {
        FunctionFact::Used {
            function: function.to_owned(),
            unit: unit.to_owned(),
            day,
        }
    }

    fn anonymous(function: &str, unit: &str, day: u64) -> FunctionFact {
        FunctionFact::Anonymous {
            function: function.to_owned(),
            unit: unit.to_owned(),
            day,
        }
    }

    fn admin(function: &str, unit: &str, day: u64) -> FunctionFact {
        FunctionFact::Admin {
            function: function.to_owned(),
            unit: unit.to_owned(),
            day,
        }
    }

    fn refused(function: &str, unit: &str, day: u64) -> FunctionFact {
        FunctionFact::Refused {
            function: function.to_owned(),
            unit: unit.to_owned(),
            day,
        }
    }

    async fn count_rows(pool: &PgPool, site: &str, kind: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM object_response_evidence WHERE site = $1 AND kind = $2",
        )
        .bind(site)
        .bind(kind)
        .fetch_one(pool)
        .await
        .expect("count the rows")
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_repeated_fact_is_one_row_and_a_dropped_generation_records_nothing() {
        let pool = connect_test_pool().await;
        let site = unique_site("function_once");
        let generation = with_site(&pool, &site).await;
        let facts = vec![used(FUNCTION, "s1", DAY), used(FUNCTION, "s1", DAY)];
        record_function_facts(&pool, &site, generation, &facts)
            .await
            .expect("record the facts");
        record_function_facts(&pool, &site, generation, &facts)
            .await
            .expect("record them again");
        assert_eq!(count_rows(&pool, &site, USED).await, 1);

        // A write names the generation it read: a site created in its place gets none of it.
        record_function_facts(&pool, &site, Utc::now(), &[used(FUNCTION, "s2", DAY)])
            .await
            .expect("a stale write is dropped, not refused");
        assert_eq!(count_rows(&pool, &site, USED).await, 1);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn function_keys_count_the_use_kinds_and_skip_refusals() {
        let pool = connect_test_pool().await;
        let site = unique_site("function_keys");
        let generation = with_site(&pool, &site).await;
        record_function_facts(
            &pool,
            &site,
            generation,
            &[
                used(FUNCTION, "alice", DAY),
                // The same unit under another kind counts once.
                used(FUNCTION, "alice", DAY + 1),
                anonymous(FUNCTION, "s:x", DAY),
                admin(FUNCTION, "root", DAY),
                refused("GET /api/refused-only", "bob", DAY),
                used("GET /api/other", "carol", DAY),
                // A window older than `oldest_day` is left out.
                used("GET /api/old", "dave", DAY - 10),
            ],
        )
        .await
        .expect("record the facts");

        let (keys, more) = function_keys(&pool, &site, DAY - 1, 10)
            .await
            .expect("list the keys");
        assert!(!more);
        assert_eq!(
            keys,
            vec![
                FunctionUse {
                    key: FUNCTION.to_owned(),
                    units: 3,
                },
                FunctionUse {
                    key: "GET /api/other".to_owned(),
                    units: 1,
                },
            ]
        );

        let (limited, more) = function_keys(&pool, &site, DAY - 1, 1)
            .await
            .expect("list the keys within a limit");
        assert!(more, "another key has evidence");
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].key, FUNCTION);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn function_evidence_sums_the_ordinary_kinds_and_joins_merged_keys() {
        let pool = connect_test_pool().await;
        let site = unique_site("function_evidence");
        let generation = with_site(&pool, &site).await;
        let first = "GET /u/{id}/posts";
        let second = "GET /u/alice/posts";
        record_function_facts(
            &pool,
            &site,
            generation,
            &[
                used(first, "alice", DAY),
                // An anonymous unit adds to the ordinary units, a unit counted once per key.
                anonymous(second, "a:10.0.0.9", DAY),
                used(second, "alice", DAY),
                // Two administrator days, one of them repeated, plus a refusal.
                admin(first, "root", DAY),
                admin(second, "root", DAY),
                admin(second, "root", DAY + 2),
                refused(second, "bob", DAY + 1),
                // Outside the window.
                admin(first, "root", DAY - 10),
            ],
        )
        .await
        .expect("record the facts");

        let mapping: BTreeMap<String, String> = [
            (first.to_owned(), "GET /u/{id}/posts".to_owned()),
            (second.to_owned(), "GET /u/{id}/posts".to_owned()),
        ]
        .into_iter()
        .collect();
        let evidence = function_evidence(&pool, &site, DAY - 1, &mapping)
            .await
            .expect("read the evidence");
        assert_eq!(evidence.len(), 1);
        let merged = &evidence["GET /u/{id}/posts"];
        assert_eq!(
            merged,
            &FunctionEvidence {
                ordinary_units: 2,
                admin_units: 1,
                admin_days: 2,
                refused_units: 1,
                last_day: DAY + 2,
            }
        );
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn site_ordinary_units_counts_only_the_function_kind() {
        let pool = connect_test_pool().await;
        let site = unique_site("function_ordinary");
        let generation = with_site(&pool, &site).await;
        record_function_facts(
            &pool,
            &site,
            generation,
            &[
                used(FUNCTION, "alice", DAY),
                used("GET /api/other", "alice", DAY),
                used(FUNCTION, "bob", DAY),
                anonymous(FUNCTION, "a:10.0.0.9", DAY),
                admin(FUNCTION, "root", DAY),
                refused(FUNCTION, "carol", DAY),
            ],
        )
        .await
        .expect("record the facts");
        assert_eq!(
            site_ordinary_units(&pool, &site, DAY - 1)
                .await
                .expect("count the units"),
            2
        );
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn pruning_and_forgetting_a_site_remove_function_rows() {
        let pool = connect_test_pool().await;
        let site = unique_site("function_prune");
        let generation = with_site(&pool, &site).await;
        record_function_facts(
            &pool,
            &site,
            generation,
            &[
                used(FUNCTION, "alice", DAY),
                admin(FUNCTION, "root", DAY - 9),
            ],
        )
        .await
        .expect("record the facts");

        // The rows older than the window go with the response tiers' pruning.
        let pruned = prune_tier_evidence(&pool, &site, DAY - 1)
            .await
            .expect("prune the evidence");
        assert_eq!(pruned, 1);
        assert_eq!(count_rows(&pool, &site, ADMIN).await, 0);
        assert_eq!(count_rows(&pool, &site, USED).await, 1);

        let mut transaction = pool.begin().await.expect("begin");
        forget_site(&mut transaction, &site, 1)
            .await
            .expect("forget the site");
        transaction.commit().await.expect("commit");
        assert_eq!(count_rows(&pool, &site, USED).await, 0);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn function_rows_leave_the_response_readings_unchanged() {
        let pool = connect_test_pool().await;
        let site = unique_site("function_readings");
        let generation = with_site(&pool, &site).await;
        let slot = "GET /api/search [].id";
        let seen = TierFact::Seen {
            slot: slot.to_owned(),
            unit: "s1".to_owned(),
            day: DAY,
            fingerprints: vec!["a".to_owned(), "b".to_owned()],
            complete: true,
        };
        record_tier_facts(&pool, &site, generation, &[seen])
            .await
            .expect("record the tier facts");
        let before = load_tier_evidence(&pool, &site, &[slot.to_owned()], DAY)
            .await
            .expect("read the tier evidence");

        record_function_facts(
            &pool,
            &site,
            generation,
            &[
                used(FUNCTION, "s1", DAY),
                admin(FUNCTION, "root", DAY),
                refused(FUNCTION, "s2", DAY),
                // A function kind on the same position key: the position's reading still names only its own kinds.
                used(slot, "s9", DAY),
            ],
        )
        .await
        .expect("record the function facts");
        let after = load_tier_evidence(&pool, &site, &[slot.to_owned()], DAY)
            .await
            .expect("read the tier evidence again");
        assert_eq!(before[slot], after[slot]);
        assert_eq!(
            after[slot].evidence.seen,
            vec![SeenUnit {
                fingerprints: vec!["a".to_owned(), "b".to_owned()],
                complete: true,
            }]
        );
        assert_eq!(after[slot].evidence.admin_units, 0);
        assert_eq!(after[slot].evidence.refused_units, 0);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_migration_admits_the_function_kinds_and_refuses_others() {
        let pool = connect_test_pool().await;
        let site = unique_site("function_kinds");
        with_site(&pool, &site).await;
        for kind in [USED, ANONYMOUS, ADMIN, REFUSED] {
            sqlx::query(
                "INSERT INTO object_response_evidence (site, kind, slot, unit, day)
                 VALUES ($1, $2, $3, 'u', 1)",
            )
            .bind(&site)
            .bind(kind)
            .bind(FUNCTION)
            .execute(&pool)
            .await
            .expect("a function kind the migration names is accepted");
        }
        let refused_kind = sqlx::query(
            "INSERT INTO object_response_evidence (site, kind, slot, unit, day)
             VALUES ($1, 'function_other', $2, 'u', 1)",
        )
        .bind(&site)
        .bind(FUNCTION)
        .execute(&pool)
        .await;
        assert!(refused_kind.is_err(), "an unknown kind is refused");
    }
}
