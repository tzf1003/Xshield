//! Storage of the acceptance judgements of the object-map learning (docs/07 section 7.9.16):
//! the proposal the rules make for a declared request position, whether normal traffic sends
//! it values from public positions. `migrations/0009_object_judgements.sql` defines the table,
//! and only the control plane writes it.
//!
//! A proposal waits for an administrator. Confirming it writes the judgement into the site's
//! configuration, and then the proposal is cleared. A dismissed proposal stays as a row marked
//! dismissed, so the rules do not propose the same value again.
//!
//! Each write that adds state names the site's generation and lands only while the site still
//! has that configuration, as the other learning writes do (`object_learning_store`).

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row, postgres::PgRow};
use xshield_core::context::Reliability;

use crate::object_learning_store::LearningStoreError;

/// A judgement of a declared request position: the value the rules give, and the evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The request position's key.
    pub slot: String,
    /// `false`: normal traffic rarely sends public values here. `true`: it commonly does.
    pub accepts_public: bool,
    /// How sure the rules are.
    pub reliability: Reliability,
    /// The votes the judgement counts.
    pub votes: u32,
    /// The distinct sessions among them.
    pub sessions: u32,
    /// The share of those votes, in thousandths, whose values came from public positions.
    pub public_per_mille: u32,
    /// The last UTC day with a vote the judgement counts.
    pub last_day: u64,
}

/// Writes the proposal of a request position of the site's `generation`. A dismissed proposal of
/// the same value is left as it is. A proposal of the other value, or one not dismissed, replaces
/// the row.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn put(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    proposal: &Proposal,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "INSERT INTO object_judgements
             (site, slot, accepts_public, reliability, votes, sessions, public_per_mille,
              last_day, updated_millis, dismissed)
         SELECT $1::text, $2::text, $3::boolean, $4::text, $5::integer, $6::integer,
             $7::integer, $8::bigint, $9::bigint, false
         WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $10 FOR SHARE)
         ON CONFLICT (site, slot) DO UPDATE SET
             accepts_public = EXCLUDED.accepts_public,
             reliability = EXCLUDED.reliability,
             votes = EXCLUDED.votes,
             sessions = EXCLUDED.sessions,
             public_per_mille = EXCLUDED.public_per_mille,
             last_day = EXCLUDED.last_day,
             updated_millis = EXCLUDED.updated_millis,
             dismissed = false
         WHERE NOT (object_judgements.dismissed
                    AND object_judgements.accepts_public = EXCLUDED.accepts_public)",
    )
    .bind(site)
    .bind(&proposal.slot)
    .bind(proposal.accepts_public)
    .bind(reliability_text(proposal.reliability))
    .bind(i32::try_from(proposal.votes).unwrap_or(i32::MAX))
    .bind(i32::try_from(proposal.sessions).unwrap_or(i32::MAX))
    .bind(i32::try_from(proposal.public_per_mille).unwrap_or(1_000))
    .bind(day_i64(proposal.last_day))
    .bind(now_millis)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// Withdraws the proposal of a request position of the site's `generation`. A dismissed row stays,
/// so the rules do not propose its value again, unless the rules reached the other value: `reached`
/// is that value when the rules judge the position and the configuration already carries it. Then the
/// dismissal lapses, and the value may be proposed again once the rules reach it. `None` when the rules
/// cannot judge the position, which keeps every dismissal.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn withdraw(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    slot: &str,
    reached: Option<bool>,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "DELETE FROM object_judgements WHERE site = $1 AND slot = $2
           AND (NOT dismissed OR ($4::boolean IS NOT NULL AND accepts_public <> $4::boolean))
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $3 FOR SHARE)",
    )
    .bind(site)
    .bind(slot)
    .bind(generation)
    .bind(reached)
    .execute(pool)
    .await?;
    Ok(())
}

/// Forgets the rows of the site's `generation` whose position is not in `slots`: the positions the
/// configuration no longer declares as request positions in effect. Returns the rows forgotten.
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
        "DELETE FROM object_judgements WHERE site = $1 AND NOT (slot = ANY($2::text[]))
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $3 FOR SHARE)",
    )
    .bind(site)
    .bind(slots.to_vec())
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Dismisses the proposal of a request position of the site's `generation`, so the rules do not
/// propose its value again. Returns whether a proposal was dismissed.
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
        "UPDATE object_judgements SET dismissed = true, updated_millis = $3
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

/// Clears the proposal of a request position once an administrator has confirmed the value it carries
/// into the configuration. A proposal of the other value, which the rules made after the administrator
/// read the one confirmed, stays: the next pass judges it again. Returns whether a row was cleared.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn clear_confirmed(
    pool: &PgPool,
    site: &str,
    slot: &str,
    accepts_public: bool,
    reliability: Reliability,
) -> Result<bool, LearningStoreError> {
    let result = sqlx::query(
        "DELETE FROM object_judgements
         WHERE site = $1 AND slot = $2 AND NOT dismissed
           AND accepts_public = $3 AND reliability = $4",
    )
    .bind(site)
    .bind(slot)
    .bind(accepts_public)
    .bind(reliability_text(reliability))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// The proposals of a site that no administrator has dismissed, in key order.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure, or when a stored row is not one this
/// build reads.
pub async fn proposals(pool: &PgPool, site: &str) -> Result<Vec<Proposal>, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT slot, accepts_public, reliability, votes, sessions, public_per_mille, last_day
         FROM object_judgements WHERE site = $1 AND NOT dismissed ORDER BY slot",
    )
    .bind(site)
    .fetch_all(pool)
    .await?;
    rows.iter().map(proposal_of).collect()
}

/// The proposal of one request position, unless an administrator has dismissed it.
///
/// # Errors
/// As [`proposals`].
pub async fn proposal(
    pool: &PgPool,
    site: &str,
    slot: &str,
) -> Result<Option<Proposal>, LearningStoreError> {
    let row = sqlx::query(
        "SELECT slot, accepts_public, reliability, votes, sessions, public_per_mille, last_day
         FROM object_judgements WHERE site = $1 AND slot = $2 AND NOT dismissed",
    )
    .bind(site)
    .bind(slot)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(proposal_of).transpose()
}

fn proposal_of(row: &PgRow) -> Result<Proposal, LearningStoreError> {
    let reliability: String = row.try_get("reliability")?;
    let reliability = match reliability.as_str() {
        "high" => Reliability::High,
        "medium" => Reliability::Medium,
        other => {
            return Err(LearningStoreError::Database(sqlx::Error::Decode(
                format!("unknown reliability {other} in object_judgements").into(),
            )));
        }
    };
    Ok(Proposal {
        slot: row.try_get("slot")?,
        accepts_public: row.try_get("accepts_public")?,
        reliability,
        votes: u32::try_from(row.try_get::<i32, _>("votes")?).unwrap_or(0),
        sessions: u32::try_from(row.try_get::<i32, _>("sessions")?).unwrap_or(0),
        public_per_mille: u32::try_from(row.try_get::<i32, _>("public_per_mille")?).unwrap_or(0),
        last_day: u64::try_from(row.try_get::<i64, _>("last_day")?).unwrap_or(0),
    })
}

/// The text the table stores a reliability as. The rules never propose `low`, which the table refuses.
fn reliability_text(reliability: Reliability) -> &'static str {
    match reliability {
        Reliability::High => "high",
        Reliability::Medium => "medium",
        Reliability::Low => "low",
    }
}

/// A day counted from the epoch as the column stores it. A value out of range saturates, which
/// no real day reaches.
fn day_i64(day: u64) -> i64 {
    i64::try_from(day).unwrap_or(i64::MAX)
}
