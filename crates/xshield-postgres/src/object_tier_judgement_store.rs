//! Tier proposals of the object-map learning (docs/07 section 7.9.16): the tier the rules give a
//! declared response position, and how sure they are. `migrations/0010_object_tiers.sql` defines
//! the table, and only the control plane writes it.
//!
//! A proposal waits for an administrator. Confirming it writes the tier into the site's
//! configuration, and then the proposal is cleared. A dismissed proposal stays as a row marked
//! dismissed, so the rules do not propose the same tier again. Each write that adds state names the
//! site's generation and lands only while the site still has that configuration, as the other
//! learning writes do (`object_learning_store`).

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row, postgres::PgRow};
use xshield_core::context::{Reliability, Tier};

use crate::object_learning_store::LearningStoreError;

/// A tier the rules give a declared response position, and the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierProposal {
    /// The response position's key.
    pub slot: String,
    /// Whose objects the position shows, by the rules.
    pub tier: Tier,
    /// How sure the rules are.
    pub reliability: Reliability,
    /// The units the judgement counts.
    pub units: u32,
    /// The distinct values among them.
    pub seen_values: u32,
    /// The share of values, in thousandths, that agree with the tier.
    pub agreement_per_mille: u32,
    /// The last UTC day with a value the judgement counts.
    pub last_day: u64,
}

/// Writes the proposal of a response position of the site's `generation`. A dismissed proposal of the
/// same tier is left as it is. A proposal of another tier, or one not dismissed, replaces the row.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn put(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    proposal: &TierProposal,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "INSERT INTO object_tier_judgements
             (site, slot, tier, reliability, units, seen_values, agreement_per_mille, last_day,
              updated_millis, dismissed)
         SELECT $1::text, $2::text, $3::text, $4::text, $5::integer, $6::integer, $7::integer,
             $8::bigint, $9::bigint, false
         WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $10 FOR SHARE)
         ON CONFLICT (site, slot) DO UPDATE SET
             tier = EXCLUDED.tier,
             reliability = EXCLUDED.reliability,
             units = EXCLUDED.units,
             seen_values = EXCLUDED.seen_values,
             agreement_per_mille = EXCLUDED.agreement_per_mille,
             last_day = EXCLUDED.last_day,
             updated_millis = EXCLUDED.updated_millis,
             dismissed = false
         WHERE NOT (object_tier_judgements.dismissed AND object_tier_judgements.tier = EXCLUDED.tier)",
    )
    .bind(site)
    .bind(&proposal.slot)
    .bind(tier_text(proposal.tier))
    .bind(reliability_text(proposal.reliability))
    .bind(i32::try_from(proposal.units).unwrap_or(i32::MAX))
    .bind(i32::try_from(proposal.seen_values).unwrap_or(i32::MAX))
    .bind(i32::try_from(proposal.agreement_per_mille).unwrap_or(1_000))
    .bind(day_i64(proposal.last_day))
    .bind(now_millis)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// Withdraws the proposal of a response position of the site's `generation`. A dismissed row stays,
/// so the rules do not propose its tier again, unless the rules reached another tier: `reached` is that
/// tier when the rules judge the position and the configuration already carries it. Then the dismissal
/// lapses. `None` when the rules cannot judge the position, which keeps every dismissal.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn withdraw(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    slot: &str,
    reached: Option<Tier>,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "DELETE FROM object_tier_judgements WHERE site = $1 AND slot = $2
           AND (NOT dismissed OR ($4::text IS NOT NULL AND tier <> $4::text))
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $3 FOR SHARE)",
    )
    .bind(site)
    .bind(slot)
    .bind(generation)
    .bind(reached.map(tier_text))
    .execute(pool)
    .await?;
    Ok(())
}

/// Forgets the proposals of the site's `generation` whose position is not in `slots`: the response
/// positions the configuration no longer declares for tier learning. Returns the rows forgotten. A function
/// proposal (docs/07 section 7.9.19) is no position, so it is kept: see [`retain_functions`].
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn retain(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    slots: &[String],
) -> Result<u64, LearningStoreError> {
    let result = sqlx::query(
        "DELETE FROM object_tier_judgements WHERE site = $1 AND slot LIKE '% % %'
           AND NOT (slot = ANY($2::text[]))
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $3 FOR SHARE)",
    )
    .bind(site)
    .bind(slots.to_vec())
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Withdraws the function proposals of the site's `generation` whose function is not in `judged`: the
/// functions this pass did not propose. A dismissed proposal stays, as [`withdraw`] keeps it. Returns the rows
/// withdrawn. A function key has one space and a position key two, so the rows of the two kinds tell apart by
/// the spaces in their key (docs/07 section 7.9.19).
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn retain_functions(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    judged: &[String],
) -> Result<u64, LearningStoreError> {
    let result = sqlx::query(
        "DELETE FROM object_tier_judgements WHERE site = $1 AND slot NOT LIKE '% % %'
           AND NOT (slot = ANY($2::text[])) AND NOT dismissed
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $3 FOR SHARE)",
    )
    .bind(site)
    .bind(judged.to_vec())
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Dismisses the proposal of a response position of the site's `generation`. Returns whether a
/// proposal was dismissed.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn dismiss(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    slot: &str,
    now_millis: i64,
) -> Result<bool, LearningStoreError> {
    let result = sqlx::query(
        "UPDATE object_tier_judgements SET dismissed = true, updated_millis = $3
         WHERE site = $1 AND slot = $2 AND NOT dismissed
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $4 FOR SHARE)",
    )
    .bind(site)
    .bind(slot)
    .bind(now_millis)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Clears the proposal of a response position once an administrator has confirmed the tier and
/// reliability it carries into the configuration. A proposal of another tier, which the rules made
/// after the administrator read the one confirmed, stays: the next pass judges it again. Returns whether
/// a row was cleared.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn clear_confirmed(
    pool: &PgPool,
    site: &str,
    slot: &str,
    tier: Tier,
    reliability: Reliability,
) -> Result<bool, LearningStoreError> {
    let result = sqlx::query(
        "DELETE FROM object_tier_judgements
         WHERE site = $1 AND slot = $2 AND NOT dismissed AND tier = $3 AND reliability = $4",
    )
    .bind(site)
    .bind(slot)
    .bind(tier_text(tier))
    .bind(reliability_text(reliability))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// The tier proposals of a site that no administrator has dismissed, in key order.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure, or when a stored row is not one this build reads.
pub async fn proposals(pool: &PgPool, site: &str) -> Result<Vec<TierProposal>, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT slot, tier, reliability, units, seen_values, agreement_per_mille, last_day
         FROM object_tier_judgements WHERE site = $1 AND NOT dismissed ORDER BY slot",
    )
    .bind(site)
    .fetch_all(pool)
    .await?;
    rows.iter().map(proposal_of).collect()
}

/// The tier proposal of one response position, unless an administrator has dismissed it.
///
/// # Errors
/// As [`proposals`].
pub async fn proposal(
    pool: &PgPool,
    site: &str,
    slot: &str,
) -> Result<Option<TierProposal>, LearningStoreError> {
    let row = sqlx::query(
        "SELECT slot, tier, reliability, units, seen_values, agreement_per_mille, last_day
         FROM object_tier_judgements WHERE site = $1 AND slot = $2 AND NOT dismissed",
    )
    .bind(site)
    .bind(slot)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(proposal_of).transpose()
}

fn proposal_of(row: &PgRow) -> Result<TierProposal, LearningStoreError> {
    let tier: String = row.try_get("tier")?;
    let reliability: String = row.try_get("reliability")?;
    Ok(TierProposal {
        slot: row.try_get("slot")?,
        tier: tier_of(&tier)?,
        reliability: reliability_of(&reliability)?,
        units: u32::try_from(row.try_get::<i32, _>("units")?).unwrap_or(0),
        seen_values: u32::try_from(row.try_get::<i32, _>("seen_values")?).unwrap_or(0),
        agreement_per_mille: u32::try_from(row.try_get::<i32, _>("agreement_per_mille")?)
            .unwrap_or(0),
        last_day: u64::try_from(row.try_get::<i64, _>("last_day")?).unwrap_or(0),
    })
}

/// The text the table stores a tier as, as the configuration writes it.
fn tier_text(tier: Tier) -> &'static str {
    match tier {
        Tier::Own => "self",
        Tier::Org => "org",
        Tier::Admin => "admin",
        Tier::Public => "public",
    }
}

fn tier_of(text: &str) -> Result<Tier, LearningStoreError> {
    match text {
        "self" => Ok(Tier::Own),
        "org" => Ok(Tier::Org),
        "admin" => Ok(Tier::Admin),
        "public" => Ok(Tier::Public),
        other => Err(LearningStoreError::Database(sqlx::Error::Decode(
            format!("unknown tier {other} in object_tier_judgements").into(),
        ))),
    }
}

/// The text the table stores a reliability as. The rules never propose `low`, which the table refuses.
fn reliability_text(reliability: Reliability) -> &'static str {
    match reliability {
        Reliability::High => "high",
        Reliability::Medium => "medium",
        Reliability::Low => "low",
    }
}

fn reliability_of(text: &str) -> Result<Reliability, LearningStoreError> {
    match text {
        "high" => Ok(Reliability::High),
        "medium" => Ok(Reliability::Medium),
        other => Err(LearningStoreError::Database(sqlx::Error::Decode(
            format!("unknown reliability {other} in object_tier_judgements").into(),
        ))),
    }
}

/// A day counted from the epoch as the column stores it. A value out of range saturates, which
/// no real day reaches.
fn day_i64(day: u64) -> i64 {
    i64::try_from(day).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    // These storage-layer tests need a reachable PostgreSQL instance. They run when
    // `XSHIELD_TEST_DATABASE_URL` is set (scripts/test_postgres.sh does that after applying
    // `migrations/`).

    use std::sync::atomic::{AtomicU64, Ordering};

    use chrono::Utc;

    use super::*;

    /// The response position the tests judge.
    const SLOT: &str = "GET /api/search [].id";

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

    fn offer(tier: Tier, reliability: Reliability) -> TierProposal {
        TierProposal {
            slot: SLOT.to_owned(),
            tier,
            reliability,
            units: 12,
            seen_values: 30,
            agreement_per_mille: 960,
            last_day: 3,
        }
    }

    /// The open proposal of `SLOT`, when there is one.
    async fn current(pool: &PgPool, site: &str) -> Option<TierProposal> {
        proposal(pool, site, SLOT).await.expect("read the proposal")
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_dismissed_tier_holds_until_the_rules_reach_another_tier() {
        let pool = connect_test_pool().await;
        let site = unique_site("tier_judgement_dismiss");
        let generation = with_site(&pool, &site).await;
        put(
            &pool,
            &site,
            generation,
            &offer(Tier::Public, Reliability::High),
            1,
        )
        .await
        .expect("propose public");
        assert!(
            dismiss(&pool, &site, generation, SLOT, 2)
                .await
                .expect("dismiss")
        );
        assert!(current(&pool, &site).await.is_none());

        // The same tier with another reliability: the dismissal holds.
        put(
            &pool,
            &site,
            generation,
            &offer(Tier::Public, Reliability::Medium),
            3,
        )
        .await
        .expect("propose public again");
        assert!(current(&pool, &site).await.is_none());

        // Another tier is proposed at once, since the dismissal covers the tier it refused.
        put(
            &pool,
            &site,
            generation,
            &offer(Tier::Own, Reliability::High),
            4,
        )
        .await
        .expect("propose self");
        assert_eq!(
            current(&pool, &site).await.map(|row| row.tier),
            Some(Tier::Own)
        );
        assert_eq!(proposals(&pool, &site).await.expect("list").len(), 1);

        // Dismissed, the self tier holds while the rules give nothing.
        assert!(
            dismiss(&pool, &site, generation, SLOT, 5)
                .await
                .expect("dismiss self")
        );
        withdraw(&pool, &site, generation, SLOT, None)
            .await
            .expect("withdraw without a judgement");
        put(
            &pool,
            &site,
            generation,
            &offer(Tier::Own, Reliability::High),
            6,
        )
        .await
        .expect("propose self again");
        assert!(current(&pool, &site).await.is_none());

        // The rules reach the tier the entry carries, which is not `self`: the dismissal lapses.
        withdraw(&pool, &site, generation, SLOT, Some(Tier::Public))
            .await
            .expect("withdraw once the rules reach the configured tier");
        put(
            &pool,
            &site,
            generation,
            &offer(Tier::Own, Reliability::High),
            7,
        )
        .await
        .expect("propose self once more");
        assert_eq!(
            current(&pool, &site).await.map(|row| row.tier),
            Some(Tier::Own)
        );
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_confirmed_or_forgotten_tier_proposal_is_cleared() {
        let pool = connect_test_pool().await;
        let site = unique_site("tier_judgement_clear");
        let generation = with_site(&pool, &site).await;
        put(
            &pool,
            &site,
            generation,
            &offer(Tier::Own, Reliability::High),
            1,
        )
        .await
        .expect("propose self");

        // A confirmation of another tier clears nothing. The confirmed one clears its proposal.
        assert!(
            !clear_confirmed(&pool, &site, SLOT, Tier::Public, Reliability::High)
                .await
                .expect("clear the other tier")
        );
        assert!(current(&pool, &site).await.is_some());
        assert!(
            clear_confirmed(&pool, &site, SLOT, Tier::Own, Reliability::High)
                .await
                .expect("clear the confirmed tier")
        );
        assert!(current(&pool, &site).await.is_none());

        // A position the configuration no longer declares loses its proposal.
        put(
            &pool,
            &site,
            generation,
            &offer(Tier::Admin, Reliability::High),
            8,
        )
        .await
        .expect("propose admin");
        let forgotten = retain(&pool, &site, generation, &["GET /other [].id".to_owned()])
            .await
            .expect("retain");
        assert_eq!(forgotten, 1);
        assert!(current(&pool, &site).await.is_none());

        // A write names the generation it read: a site created in its place gets none.
        put(
            &pool,
            &site,
            Utc::now(),
            &offer(Tier::Admin, Reliability::High),
            9,
        )
        .await
        .expect("a stale write is dropped, not refused");
        assert!(current(&pool, &site).await.is_none());
    }

    /// Every row of the site, dismissed or not.
    async fn rows(pool: &PgPool, site: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM object_tier_judgements WHERE site = $1")
            .bind(site)
            .fetch_one(pool)
            .await
            .expect("count the rows")
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn function_and_position_proposals_survive_each_others_passes() {
        let pool = connect_test_pool().await;
        let site = unique_site("tier_functions");
        let generation = with_site(&pool, &site).await;
        let admin_function = |slot: &str| TierProposal {
            slot: slot.to_owned(),
            tier: Tier::Admin,
            reliability: Reliability::High,
            units: 2,
            seen_values: 0,
            agreement_per_mille: 0,
            last_day: 3,
        };
        put(
            &pool,
            &site,
            generation,
            &offer(Tier::Public, Reliability::High),
            1,
        )
        .await
        .expect("put the position proposal");
        put(
            &pool,
            &site,
            generation,
            &admin_function("GET /api/patients/{id}"),
            1,
        )
        .await
        .expect("put the function proposal");
        put(
            &pool,
            &site,
            generation,
            &admin_function("GET /api/other"),
            1,
        )
        .await
        .expect("put the other function proposal");
        assert!(
            dismiss(&pool, &site, generation, "GET /api/other", 2)
                .await
                .expect("dismiss the other function"),
            "the other function's proposal is dismissed"
        );

        // The position pass forgets the position it no longer declares, and no function row.
        let forgotten = retain(&pool, &site, generation, &[])
            .await
            .expect("retain the positions");
        assert_eq!(forgotten, 1, "only the position row is forgotten");
        assert_eq!(rows(&pool, &site).await, 2, "both function rows remain");

        // The function pass withdraws the function nobody judged; the dismissed one stays, and a position is
        // not touched.
        put(
            &pool,
            &site,
            generation,
            &offer(Tier::Public, Reliability::High),
            1,
        )
        .await
        .expect("put the position proposal again");
        let withdrawn = retain_functions(&pool, &site, generation, &[])
            .await
            .expect("retain the functions");
        assert_eq!(withdrawn, 1, "only the undismissed function is withdrawn");
        assert_eq!(
            rows(&pool, &site).await,
            2,
            "the dismissed function and the position remain"
        );
        assert!(
            current(&pool, &site).await.is_some(),
            "the position is untouched"
        );
        let listed: Vec<String> = proposals(&pool, &site)
            .await
            .expect("list the proposals")
            .into_iter()
            .map(|proposal| proposal.slot)
            .collect();
        assert_eq!(
            listed,
            vec![SLOT.to_owned()],
            "a dismissed function is not listed"
        );
    }
}
