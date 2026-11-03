//! Response evidence of the object-map learning (docs/07 section 7.9.16): what each unit saw at
//! each response position, by UTC day, which the tier rules read. `migrations/0010_object_tiers.sql`
//! defines the table, and only the control plane writes it.
//!
//! A row is written per unit, position and day, and each write names the site's generation, as the
//! other learning writes do. Values are never kept as text: a fingerprint is a keyed hash that the
//! gateway computed, and the rows keep only the smallest of them per unit and day.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
use xshield_core::context::learning::{
    SeenUnit, TierEvidence, TierFact, UNIT_FINGERPRINTS_MAX, route_prefix,
};

use crate::object_learning_store::LearningStoreError;

/// Rows per INSERT statement, as the evidence writes count them.
const TIER_CHUNK: usize = 1_000;

/// What the rules read of one response position over the window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TierRead {
    /// The evidence of the position.
    pub evidence: TierEvidence,
    /// The last UTC day with a value a unit saw at the position, zero when none.
    pub last_day: u64,
}

/// One row a batch writes: its kind, position or route, unit and day, with the smallest values it saw.
#[derive(Debug)]
struct TierRow {
    kind: &'static str,
    slot: String,
    unit: String,
    day: i64,
    fingerprints: Vec<String>,
    complete: bool,
}

/// The merged facts of a batch, keyed by kind, position or route, unit and day: the values seen and
/// whether every fact kept them all.
type TierGroups<'a> = BTreeMap<(&'static str, &'a str, &'a str, u64), (BTreeSet<&'a str>, bool)>;

/// Records the tier facts of a batch of the site's `generation`. Facts of one kind, position, unit and
/// day are merged before they are written: their values union, and a unit that any of them cut stays
/// incomplete. Recording the same facts again is harmless. Rows of a generation the site no longer has
/// are dropped.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn record_tier_facts(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    facts: &[TierFact],
) -> Result<(), LearningStoreError> {
    let mut grouped: TierGroups<'_> = BTreeMap::new();
    for fact in facts {
        let (kind, slot, unit, day, digests, complete): (
            &'static str,
            &str,
            &str,
            u64,
            &[String],
            bool,
        ) = match fact {
            TierFact::Seen {
                slot,
                unit,
                day,
                fingerprints,
                complete,
            } => ("seen", slot, unit, *day, fingerprints, *complete),
            TierFact::Admin { slot, unit, day } => ("admin", slot, unit, *day, &[], true),
            TierFact::Refused { route, unit, day } => ("refused", route, unit, *day, &[], true),
            TierFact::Capped { unit, day } => ("capped", "", unit, *day, &[], false),
        };
        let (values, whole) = grouped
            .entry((kind, slot, unit, day))
            .or_insert_with(|| (BTreeSet::new(), true));
        values.extend(digests.iter().map(String::as_str));
        *whole &= complete;
    }
    let rows: Vec<TierRow> = grouped
        .into_iter()
        .map(|((kind, slot, unit, day), (values, whole))| TierRow {
            kind,
            slot: slot.to_owned(),
            unit: unit.to_owned(),
            day: day_i64(day),
            complete: whole && values.len() <= UNIT_FINGERPRINTS_MAX,
            fingerprints: if kind == "seen" {
                values
                    .iter()
                    .take(UNIT_FINGERPRINTS_MAX)
                    .map(|value| (*value).to_owned())
                    .collect()
            } else {
                Vec::new()
            },
        })
        .collect();
    let cap = i64::try_from(UNIT_FINGERPRINTS_MAX).unwrap_or(i64::MAX);
    for chunk in rows.chunks(TIER_CHUNK) {
        // One row per tuple, as the evidence writes do: a text[] column is one value per row.
        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO object_response_evidence (site, kind, slot, unit, day, fingerprints, complete)
             SELECT site, kind, slot, unit, day, fingerprints, complete FROM (",
        );
        builder.push_values(chunk, |mut values, row| {
            values.push_bind(site);
            values.push_unseparated("::text");
            values.push_bind(row.kind);
            values.push_unseparated("::text");
            values.push_bind(row.slot.as_str());
            values.push_unseparated("::text");
            values.push_bind(row.unit.as_str());
            values.push_unseparated("::text");
            values.push_bind(row.day);
            values.push_unseparated("::bigint");
            values.push_bind(row.fingerprints.clone());
            values.push_unseparated("::text[]");
            values.push_bind(row.complete);
            values.push_unseparated("::boolean");
        });
        // The rows land only while the site still has the configuration of this generation.
        builder.push(
            ") AS v(site, kind, slot, unit, day, fingerprints, complete)
             WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = ",
        );
        builder.push_bind(site);
        builder.push(" AND created_at = ");
        builder.push_bind(generation);
        builder.push(
            " FOR SHARE)
             ON CONFLICT (site, kind, slot, unit, day) DO UPDATE SET
                 fingerprints = ARRAY(SELECT DISTINCT f FROM unnest(
                     object_response_evidence.fingerprints || EXCLUDED.fingerprints) AS f
                     ORDER BY f LIMIT ",
        );
        builder.push_bind(cap);
        builder.push(
            "),
                 complete = object_response_evidence.complete AND EXCLUDED.complete AND cardinality(
                     ARRAY(SELECT DISTINCT f FROM unnest(
                         object_response_evidence.fingerprints || EXCLUDED.fingerprints) AS f)) <= ",
        );
        builder.push_bind(cap);
        builder.build().execute(pool).await?;
    }
    Ok(())
}

/// Reads the tier evidence of the given response positions from `oldest_day` on, and the refusals of
/// their routes. A unit counts as incomplete at a position when any of its records kept only the
/// smallest values, when it kept more values than [`UNIT_FINGERPRINTS_MAX`] over the window, or when
/// one of its records kept fewer positions than the response showed.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure, or when a stored row does not decode.
pub async fn load_tier_evidence(
    pool: &PgPool,
    site: &str,
    slots: &[String],
    oldest_day: u64,
) -> Result<BTreeMap<String, TierRead>, LearningStoreError> {
    let mut reads: BTreeMap<String, TierRead> = slots
        .iter()
        .map(|slot| (slot.clone(), TierRead::default()))
        .collect();
    if slots.is_empty() {
        return Ok(reads);
    }
    let oldest = day_i64(oldest_day);
    let routes: Vec<String> = slots
        .iter()
        .filter_map(|slot| route_prefix(slot))
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    let capped: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT unit FROM object_response_evidence
         WHERE site = $1 AND kind = 'capped' AND day >= $2",
    )
    .bind(site)
    .bind(oldest)
    .fetch_all(pool)
    .await?;
    let capped: BTreeSet<String> = capped.into_iter().collect();
    let seen = sqlx::query(
        "SELECT slot, unit, day, fingerprints, complete FROM object_response_evidence
         WHERE site = $1 AND kind = 'seen' AND day >= $2 AND slot = ANY($3::text[])",
    )
    .bind(site)
    .bind(oldest)
    .bind(slots.to_vec())
    .fetch_all(pool)
    .await?;
    let admin = sqlx::query(
        "SELECT slot, unit FROM object_response_evidence
         WHERE site = $1 AND kind = 'admin' AND day >= $2 AND slot = ANY($3::text[])",
    )
    .bind(site)
    .bind(oldest)
    .bind(slots.to_vec())
    .fetch_all(pool)
    .await?;
    let refused = sqlx::query(
        "SELECT slot, unit FROM object_response_evidence
         WHERE site = $1 AND kind = 'refused' AND day >= $2 AND slot = ANY($3::text[])",
    )
    .bind(site)
    .bind(oldest)
    .bind(routes)
    .fetch_all(pool)
    .await?;

    // Per position and unit: the values seen over the window, and whether every record kept them all.
    let mut per_unit: BTreeMap<(String, String), (BTreeSet<String>, bool)> = BTreeMap::new();
    for row in &seen {
        let slot: String = row.try_get("slot")?;
        let unit: String = row.try_get("unit")?;
        let day: i64 = row.try_get("day")?;
        let fingerprints: Vec<String> = row.try_get("fingerprints")?;
        let complete: bool = row.try_get("complete")?;
        let (values, whole) = per_unit
            .entry((slot.clone(), unit))
            .or_insert_with(|| (BTreeSet::new(), true));
        values.extend(fingerprints);
        *whole &= complete;
        let read = reads.entry(slot).or_default();
        read.last_day = read.last_day.max(u64::try_from(day).unwrap_or(0));
    }
    for ((slot, unit), (values, whole)) in per_unit {
        let mut complete = whole && !capped.contains(&unit);
        let mut fingerprints: Vec<String> = values.into_iter().collect();
        if fingerprints.len() > UNIT_FINGERPRINTS_MAX {
            fingerprints.truncate(UNIT_FINGERPRINTS_MAX);
            complete = false;
        }
        reads.entry(slot).or_default().evidence.seen.push(SeenUnit {
            fingerprints,
            complete,
        });
    }

    let mut admins: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in &admin {
        let slot: String = row.try_get("slot")?;
        let unit: String = row.try_get("unit")?;
        admins.entry(slot).or_default().insert(unit);
    }
    let mut refusals: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in &refused {
        let route: String = row.try_get("slot")?;
        let unit: String = row.try_get("unit")?;
        refusals.entry(route).or_default().insert(unit);
    }
    for (slot, read) in &mut reads {
        if let Some(units) = admins.get(slot) {
            read.evidence.admin_units = saturating_u32(units.len());
        }
        if let Some(units) = route_prefix(slot).and_then(|route| refusals.get(&route)) {
            read.evidence.refused_units = saturating_u32(units.len());
        }
    }
    Ok(reads)
}

/// Deletes the tier evidence of the site older than `oldest_day`. Returns the rows deleted.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn prune_tier_evidence(
    pool: &PgPool,
    site: &str,
    oldest_day: u64,
) -> Result<u64, LearningStoreError> {
    let result = sqlx::query("DELETE FROM object_response_evidence WHERE site = $1 AND day < $2")
        .bind(site)
        .bind(day_i64(oldest_day))
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// A day counted from the epoch as the column stores it. A value out of range saturates, which
/// no real day reaches.
fn day_i64(day: u64) -> i64 {
    i64::try_from(day).unwrap_or(i64::MAX)
}

/// A count as the evidence keeps it. A count too large for it saturates.
fn saturating_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    // These storage-layer tests need a reachable PostgreSQL instance. They run when
    // `XSHIELD_TEST_DATABASE_URL` is set (scripts/test_postgres.sh does that after applying
    // `migrations/`).

    use std::sync::atomic::{AtomicU64, Ordering};

    use chrono::Utc;

    use super::*;

    /// The response position the tests read.
    const SLOT: &str = "GET /api/search [].id";
    /// The route the position belongs to.
    const ROUTE: &str = "GET /api/search";
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

    /// A unit's record that showed `fingerprints` at the position on `DAY`.
    fn seen(unit: &str, fingerprints: &[&str], complete: bool) -> TierFact {
        TierFact::Seen {
            slot: SLOT.to_owned(),
            unit: unit.to_owned(),
            day: DAY,
            fingerprints: fingerprints
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            complete,
        }
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_records_of_a_unit_union_and_a_cut_record_leaves_it_incomplete() {
        let pool = connect_test_pool().await;
        let site = unique_site("tier_evidence");
        let generation = with_site(&pool, &site).await;
        let facts = vec![
            seen("s1", &["a", "b"], true),
            seen("s1", &["b", "c"], true),
            // A record that kept only the smallest values of the position.
            seen("s2", &["a"], false),
            TierFact::Admin {
                slot: SLOT.to_owned(),
                unit: "root".to_owned(),
                day: DAY,
            },
            TierFact::Refused {
                route: ROUTE.to_owned(),
                unit: "s3".to_owned(),
                day: DAY,
            },
        ];
        record_tier_facts(&pool, &site, generation, &facts)
            .await
            .expect("record the facts");
        // Recording the same facts again changes nothing.
        record_tier_facts(&pool, &site, generation, &facts)
            .await
            .expect("record them again");

        let reads = load_tier_evidence(&pool, &site, &[SLOT.to_owned()], DAY)
            .await
            .expect("load the evidence");
        let read = &reads[SLOT];
        assert_eq!(read.last_day, DAY);
        assert_eq!(read.evidence.admin_units, 1);
        assert_eq!(read.evidence.refused_units, 1);
        assert_eq!(
            read.evidence.seen,
            vec![
                SeenUnit {
                    fingerprints: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
                    complete: true,
                },
                SeenUnit {
                    fingerprints: vec!["a".to_owned()],
                    complete: false,
                },
            ]
        );

        let pruned = prune_tier_evidence(&pool, &site, DAY + 1)
            .await
            .expect("prune the evidence");
        assert_eq!(
            pruned, 4,
            "the two seen units, the admin unit and the refusal"
        );
        let reads = load_tier_evidence(&pool, &site, &[SLOT.to_owned()], DAY)
            .await
            .expect("load the evidence");
        assert!(reads[SLOT].evidence.seen.is_empty());
        assert_eq!(reads[SLOT].last_day, 0);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_capped_unit_is_incomplete_and_a_dropped_generation_records_nothing() {
        let pool = connect_test_pool().await;
        let site = unique_site("tier_capped");
        let generation = with_site(&pool, &site).await;
        record_tier_facts(
            &pool,
            &site,
            generation,
            &[
                seen("s4", &["x"], true),
                // The record showed more positions than it kept: the unit may have seen this one.
                TierFact::Capped {
                    unit: "s4".to_owned(),
                    day: DAY,
                },
            ],
        )
        .await
        .expect("record the facts");
        // A write names the generation it read: a site created in its place gets none.
        record_tier_facts(&pool, &site, Utc::now(), &[seen("s5", &["z"], true)])
            .await
            .expect("a stale write is dropped, not refused");

        let reads = load_tier_evidence(&pool, &site, &[SLOT.to_owned()], DAY)
            .await
            .expect("load the evidence");
        let units = &reads[SLOT].evidence.seen;
        assert_eq!(units.len(), 1, "the dropped generation's unit is not kept");
        assert!(
            !units[0].complete,
            "a capped unit is incomplete at every position"
        );
    }
}
