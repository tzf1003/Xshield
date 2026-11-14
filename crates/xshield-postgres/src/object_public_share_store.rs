//! Storage of the public-source shares of the object-map learning that the acceptance judgement leaves open
//! (docs/07 section 7.9.16, LQ-9). Where the rules give no acceptance for a request position, the share of its
//! use that came from public sources is kept here, so the console can show it to the administrator, who decides
//! the acceptance by hand. `migrations/0013_object_public_shares.sql` defines the table, and only the control
//! plane writes it.
//!
//! Each write names the site's generation and lands only while the site still has that configuration, as the
//! other learning writes do (`object_learning_store`).

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row, postgres::PgRow};

use crate::object_learning_store::LearningStoreError;

/// The share of a request position whose acceptance the rules leave open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicShare {
    /// The request position's key.
    pub slot: String,
    /// The share of judged votes, in thousandths, whose values came from public positions only.
    pub public_per_mille: u32,
    /// The share of judged votes, in thousandths, with a value at a position still awaiting its kind.
    pub pending_per_mille: u32,
    /// The votes the judgement counts.
    pub votes: u32,
    /// The distinct units among them.
    pub sessions: u32,
    /// The last UTC day with a vote the judgement counts.
    pub last_day: u64,
}

/// Writes the share of a request position of the site's `generation`, replacing the share the row held.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn put(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    share: &PublicShare,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "INSERT INTO object_public_shares
             (site, slot, public_per_mille, pending_per_mille, votes, sessions, last_day,
              updated_millis)
         SELECT $1::text, $2::text, $3::integer, $4::integer, $5::integer, $6::integer,
             $7::bigint, $8::bigint
         WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $9 FOR SHARE)
         ON CONFLICT (site, slot) DO UPDATE SET
             public_per_mille = EXCLUDED.public_per_mille,
             pending_per_mille = EXCLUDED.pending_per_mille,
             votes = EXCLUDED.votes,
             sessions = EXCLUDED.sessions,
             last_day = EXCLUDED.last_day,
             updated_millis = EXCLUDED.updated_millis",
    )
    .bind(site)
    .bind(&share.slot)
    .bind(i32::try_from(share.public_per_mille).unwrap_or(1_000))
    .bind(i32::try_from(share.pending_per_mille).unwrap_or(1_000))
    .bind(i32::try_from(share.votes).unwrap_or(i32::MAX))
    .bind(i32::try_from(share.sessions).unwrap_or(i32::MAX))
    .bind(day_i64(share.last_day))
    .bind(now_millis)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// Removes the share of a request position of the site's `generation`, when the rules give it an answer, or
/// give it no votes, or the configuration carries its acceptance.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn withdraw(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    slot: &str,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "DELETE FROM object_public_shares WHERE site = $1 AND slot = $2
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $3 FOR SHARE)",
    )
    .bind(site)
    .bind(slot)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// Forgets the shares of the site's `generation` whose position is not in `slots`: the request positions the
/// configuration no longer declares in effect.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn retain(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    slots: &[String],
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "DELETE FROM object_public_shares WHERE site = $1 AND NOT (slot = ANY($2::text[]))
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $3 FOR SHARE)",
    )
    .bind(site)
    .bind(slots.to_vec())
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// The shares of a site, in key order.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn shares(pool: &PgPool, site: &str) -> Result<Vec<PublicShare>, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT slot, public_per_mille, pending_per_mille, votes, sessions, last_day
         FROM object_public_shares WHERE site = $1 ORDER BY slot",
    )
    .bind(site)
    .fetch_all(pool)
    .await?;
    rows.iter().map(share_of).collect()
}

fn share_of(row: &PgRow) -> Result<PublicShare, LearningStoreError> {
    Ok(PublicShare {
        slot: row.try_get("slot")?,
        public_per_mille: u32::try_from(row.try_get::<i32, _>("public_per_mille")?).unwrap_or(0),
        pending_per_mille: u32::try_from(row.try_get::<i32, _>("pending_per_mille")?).unwrap_or(0),
        votes: u32::try_from(row.try_get::<i32, _>("votes")?).unwrap_or(0),
        sessions: u32::try_from(row.try_get::<i32, _>("sessions")?).unwrap_or(0),
        last_day: u64::try_from(row.try_get::<i64, _>("last_day")?).unwrap_or(0),
    })
}

/// A day counted from the epoch as the column stores it. A value out of range saturates, which no real day
/// reaches.
fn day_i64(day: u64) -> i64 {
    i64::try_from(day).unwrap_or(i64::MAX)
}
