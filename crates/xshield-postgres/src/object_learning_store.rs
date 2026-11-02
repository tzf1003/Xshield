//! Storage of the object-map learning (docs/object-map-design.md section 3): the
//! evidence the rules count, the state of each position they have judged, and each
//! site's cursor over its decision log. Only the control plane writes these tables,
//! which `migrations/0003_object_learning.sql` defines.
//!
//! Every write is idempotent. The evidence of a position, session and UTC day is
//! counted once, and a judgement overwrites only the rows the rules own, so a pass
//! that reads a batch twice, or stops half way, changes nothing it should not.
//!
//! A site's generation is the creation time of its configuration. A write that adds
//! state names the generation its pass read and lands only while the site still has
//! that configuration, so a site deleted while a pass runs keeps no state, and a pass
//! that began before a deletion writes nothing into a site created later under the same
//! name. Each such write checks the row, by name and generation, while it holds a share
//! lock on that row. The deletion removes the evidence and the positions and moves the
//! cursor to the deletion time (`forget_site`), so the new site never learns from the
//! traffic the old one logged. Pruning and retirement only act on rows the window has
//! aged out, so they need no generation.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use xshield_core::context::learning::{DecisionFacts, Denial, Evidence, Vote};
use xshield_core::context::log::{DecisionPath, Outcome};
use xshield_core::context::trace::Trace;

/// Evidence rows per insert statement, which bounds the size of one statement.
const EVIDENCE_CHUNK: usize = 1_000;

/// Failure of an object learning storage operation.
#[derive(Debug)]
pub enum LearningStoreError {
    /// The underlying database operation failed.
    Database(sqlx::Error),
}

impl std::fmt::Display for LearningStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
        }
    }
}

impl std::error::Error for LearningStoreError {}

impl From<sqlx::Error> for LearningStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// The states the learning pass writes. Dismissed, ambiguous and retired positions
/// are written by an administrator or by the expiry step, not by a judgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnedState {
    /// The rules propose a kind, and an administrator has yet to confirm it.
    Proposed,
    /// A confirmed position whose evidence still agrees with its kind.
    Confirmed,
    /// A confirmed position whose evidence now points at other kinds.
    Suspended,
}

impl LearnedState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Confirmed => "confirmed",
            Self::Suspended => "suspended",
        }
    }
}

/// What the pass writes for one position it judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement<'a> {
    /// The request position, `METHOD route location`.
    pub slot: &'a str,
    /// The state the rules give the position.
    pub state: LearnedState,
    /// The kind the state is about.
    pub class: &'a str,
    /// Votes in the window.
    pub votes: u32,
    /// Sessions that voted in the window.
    pub sessions: u32,
    /// Share of the votes whose response position has `class`, in thousandths.
    pub share_per_mille: u32,
    /// The last UTC day with a vote.
    pub last_day: u64,
}

/// A place in a site's decision log: the time of a row and its id. Rows are read in
/// this order, so a cursor names the last row read even when many rows share a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cursor {
    /// The row's time, Unix milliseconds.
    pub at_millis: i64,
    /// The row's id, which orders the rows of one millisecond.
    pub id: i64,
}

/// One batch of decision rows of a site, in (time, id) order.
#[derive(Debug, Default)]
pub struct DecisionBatch {
    /// The rows whose stored values this build reads.
    pub facts: Vec<DecisionFacts>,
    /// Every row read, including those left out of `facts`.
    pub rows: usize,
    /// The last row read, when the batch has one.
    pub newest: Option<Cursor>,
}

/// Reads up to `limit` decision rows of `site` after `after` and at or before
/// `through_millis`, in (time, id) order. A row whose stored values this build does
/// not read is counted in `rows` but left out of `facts`, so the cursor moves past it.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn read_batch(
    pool: &PgPool,
    site: &str,
    after: Cursor,
    through_millis: i64,
    limit: i64,
) -> Result<DecisionBatch, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT id, at_millis, session, status, decision_path, outcome, trace FROM decision_log
         WHERE site = $1 AND (at_millis, id) > ($2, $3) AND at_millis <= $4
         ORDER BY at_millis, id LIMIT $5",
    )
    .bind(site)
    .bind(after.at_millis)
    .bind(after.id)
    .bind(through_millis)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut batch = DecisionBatch {
        rows: rows.len(),
        ..DecisionBatch::default()
    };
    for row in &rows {
        let cursor = Cursor {
            at_millis: row.try_get("at_millis")?,
            id: row.try_get("id")?,
        };
        batch.newest = Some(batch.newest.map_or(cursor, |newest| newest.max(cursor)));
        if let Some(facts) = facts_of(row, cursor.at_millis)? {
            batch.facts.push(facts);
        }
    }
    Ok(batch)
}

/// The facts of one row, or `None` when a stored value is not one this build reads.
fn facts_of(row: &PgRow, at_millis: i64) -> Result<Option<DecisionFacts>, sqlx::Error> {
    let session: String = row.try_get("session")?;
    let status: Option<i16> = row.try_get("status")?;
    let path: String = row.try_get("decision_path")?;
    let outcome: String = row.try_get("outcome")?;
    let trace: Value = row.try_get("trace")?;
    let (Ok(at_millis), Ok(decision_path), Ok(outcome), Ok(trace)) = (
        u64::try_from(at_millis),
        serde_json::from_value::<DecisionPath>(Value::String(path)),
        serde_json::from_value::<Outcome>(Value::String(outcome)),
        serde_json::from_value::<Trace>(trace),
    ) else {
        return Ok(None);
    };
    Ok(Some(DecisionFacts {
        at_millis,
        session,
        status: status.and_then(|status| u16::try_from(status).ok()),
        decision_path,
        outcome,
        trace,
    }))
}

/// Records the votes and refusals of a batch of the site's `generation`. A position,
/// session and UTC day is counted once: a repeat changes nothing, and the first vote
/// keeps the response position it came from. Recording the same rows again is therefore
/// harmless. Rows of a generation the site no longer has are dropped.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn record_evidence(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    votes: &[Vote],
    denials: &[Denial],
) -> Result<(), LearningStoreError> {
    let rows: Vec<EvidenceRow<'_>> = votes
        .iter()
        .map(|vote| EvidenceRow {
            slot: vote.slot.as_str(),
            session: vote.session.as_str(),
            day: day_i64(vote.day),
            kind: "vote",
            from: vote.from.clone(),
        })
        .chain(denials.iter().map(|denial| EvidenceRow {
            slot: denial.slot.as_str(),
            session: denial.session.as_str(),
            day: day_i64(denial.day),
            kind: "denial",
            from: Vec::new(),
        }))
        .collect();
    for chunk in rows.chunks(EVIDENCE_CHUNK) {
        // One row per tuple: a text[] column cannot be unnested row by row, and a
        // vote's response positions are a list, not one value. The casts type each
        // value, since a SELECT over VALUES does not take the column types as INSERT does.
        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO object_evidence (site, slot, session, day, kind, from_slots)
             SELECT site, slot, session, day, kind, from_slots FROM (",
        );
        builder.push_values(chunk, |mut values, row| {
            values.push_bind(site);
            values.push_unseparated("::text");
            values.push_bind(row.slot);
            values.push_unseparated("::text");
            values.push_bind(row.session);
            values.push_unseparated("::text");
            values.push_bind(row.day);
            values.push_unseparated("::bigint");
            values.push_bind(row.kind);
            values.push_unseparated("::text");
            values.push_bind(row.from.clone());
            values.push_unseparated("::text[]");
        });
        // The rows land only while the site still has the configuration of this
        // generation. The share lock holds that row, so a deletion of the site waits
        // for this statement.
        builder.push(
            ") AS v(site, slot, session, day, kind, from_slots)
             WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = ",
        );
        builder.push_bind(site);
        builder.push(" AND created_at = ");
        builder.push_bind(generation);
        builder.push(" FOR SHARE) ON CONFLICT DO NOTHING");
        builder.build().execute(pool).await?;
    }
    Ok(())
}

/// One evidence row as the table stores it.
struct EvidenceRow<'a> {
    slot: &'a str,
    session: &'a str,
    day: i64,
    kind: &'static str,
    /// The response positions of a vote, in the order its record names them; empty for a denial.
    from: Vec<String>,
}

/// The evidence of the given positions on or after `oldest_day`, keyed by position.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn load_evidence(
    pool: &PgPool,
    site: &str,
    slots: &[String],
    oldest_day: u64,
) -> Result<HashMap<String, Evidence>, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT slot, session, day, kind, from_slots FROM object_evidence
         WHERE site = $1 AND slot = ANY($2) AND day >= $3",
    )
    .bind(site)
    .bind(slots.to_vec())
    .bind(day_i64(oldest_day))
    .fetch_all(pool)
    .await?;
    let mut evidence: HashMap<String, Evidence> = HashMap::new();
    for row in &rows {
        let slot: String = row.try_get("slot")?;
        let session: String = row.try_get("session")?;
        let day = u64::try_from(row.try_get::<i64, _>("day")?).unwrap_or(0);
        let kind: String = row.try_get("kind")?;
        let from: Vec<String> = row.try_get("from_slots")?;
        let entry = evidence.entry(slot.clone()).or_default();
        match kind.as_str() {
            "vote" => entry.add_vote(Vote {
                slot,
                session,
                day,
                from,
            }),
            "denial" => entry.add_denial(Denial { slot, session, day }),
            _ => {}
        }
    }
    Ok(evidence)
}

/// Deletes the evidence of `site` older than `oldest_day`, and returns the rows deleted.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn prune_evidence(
    pool: &PgPool,
    site: &str,
    oldest_day: u64,
) -> Result<u64, LearningStoreError> {
    let result = sqlx::query("DELETE FROM object_evidence WHERE site = $1 AND day < $2")
        .bind(site)
        .bind(day_i64(oldest_day))
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Writes the state of one position of the site's `generation`. A row an administrator
/// dismissed or marked ambiguous is left alone, and a confirmed write never undoes a
/// suspension: that one waits for an administrator.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn put_judgement(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    judgement: &Judgement<'_>,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "INSERT INTO object_positions
             (site, slot, state, class, votes, sessions, share_per_mille, last_day, updated_millis)
         SELECT $1::text, $2::text, $3::text, $4::text, $5::integer, $6::integer, $7::integer,
             $8::bigint, $9::bigint
         WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $10 FOR SHARE)
         ON CONFLICT (site, slot) DO UPDATE SET
             state = EXCLUDED.state,
             class = EXCLUDED.class,
             votes = EXCLUDED.votes,
             sessions = EXCLUDED.sessions,
             share_per_mille = EXCLUDED.share_per_mille,
             last_day = EXCLUDED.last_day,
             updated_millis = EXCLUDED.updated_millis
         WHERE object_positions.state NOT IN ('dismissed', 'ambiguous')
           AND NOT (EXCLUDED.state = 'confirmed' AND object_positions.state = 'suspended')",
    )
    .bind(site)
    .bind(judgement.slot)
    .bind(judgement.state.as_str())
    .bind(judgement.class)
    .bind(i32::try_from(judgement.votes).unwrap_or(i32::MAX))
    .bind(i32::try_from(judgement.sessions).unwrap_or(i32::MAX))
    .bind(i32::try_from(judgement.share_per_mille).unwrap_or(1_000))
    .bind(day_i64(judgement.last_day))
    .bind(now_millis)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// Retires the proposed, confirmed and suspended positions whose last vote is on or
/// before `last_day_at_most`, and returns the number retired.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn retire_unseen(
    pool: &PgPool,
    site: &str,
    last_day_at_most: u64,
    now_millis: i64,
) -> Result<u64, LearningStoreError> {
    let result = sqlx::query(
        "UPDATE object_positions SET state = 'retired', updated_millis = $3
         WHERE site = $1 AND state IN ('proposed', 'confirmed', 'suspended')
           AND last_day <= $2",
    )
    .bind(site)
    .bind(day_i64(last_day_at_most))
    .bind(now_millis)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// The last decision row the pass has read for the site, if it has started.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn cursor(pool: &PgPool, site: &str) -> Result<Option<Cursor>, LearningStoreError> {
    let row =
        sqlx::query("SELECT after_millis, after_id FROM object_learning_cursor WHERE site = $1")
            .bind(site)
            .fetch_optional(pool)
            .await?;
    match row {
        Some(row) => Ok(Some(Cursor {
            at_millis: row.try_get("after_millis")?,
            id: row.try_get("after_id")?,
        })),
        None => Ok(None),
    }
}

/// Moves the site's cursor to `after`, for a pass of the site's `generation`. The cursor
/// never moves back, and a site with no configuration of that generation keeps none.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn advance_cursor(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    after: Cursor,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "INSERT INTO object_learning_cursor (site, after_millis, after_id, updated_millis)
         SELECT $1::text, $2::bigint, $3::bigint, $4::bigint
         WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $5 FOR SHARE)
         ON CONFLICT (site) DO UPDATE SET
             after_millis = EXCLUDED.after_millis,
             after_id = EXCLUDED.after_id,
             updated_millis = EXCLUDED.updated_millis
         WHERE (object_learning_cursor.after_millis, object_learning_cursor.after_id)
             <= (EXCLUDED.after_millis, EXCLUDED.after_id)",
    )
    .bind(site)
    .bind(after.at_millis)
    .bind(after.id)
    .bind(now_millis)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// The positions that hold a proposal, in order.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn proposed_slots(pool: &PgPool, site: &str) -> Result<Vec<String>, LearningStoreError> {
    let slots = sqlx::query_scalar(
        "SELECT slot FROM object_positions WHERE site = $1 AND state = 'proposed' ORDER BY slot",
    )
    .bind(site)
    .fetch_all(pool)
    .await?;
    Ok(slots)
}

/// Withdraws the proposal of a position of the site's `generation`, when it is still a
/// proposal. Confirmed, suspended, retired, dismissed and ambiguous positions are left alone.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn withdraw_proposal(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    slot: &str,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "DELETE FROM object_positions WHERE site = $1 AND slot = $2 AND state = 'proposed'
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $3 FOR SHARE)",
    )
    .bind(site)
    .bind(slot)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// Forgets the learning state of a site inside the transaction that deletes the site.
/// The evidence and the positions go. The cursor stays, moved to `deleted_millis`, so
/// the decision rows the old site logged before the deletion are never learned from,
/// not even by a site created again under the same name. The deletion locks the site
/// row until it commits, so a write still running waits, then finds no site of its
/// generation and writes nothing.
///
/// # Errors
/// Returns [`sqlx::Error`] on a database failure.
pub async fn forget_site(
    transaction: &mut Transaction<'_, Postgres>,
    site: &str,
    deleted_millis: i64,
) -> Result<(), sqlx::Error> {
    for statement in [
        "DELETE FROM object_evidence WHERE site = $1",
        "DELETE FROM object_positions WHERE site = $1",
    ] {
        sqlx::query(statement)
            .bind(site)
            .execute(&mut **transaction)
            .await?;
    }
    sqlx::query(
        "INSERT INTO object_learning_cursor (site, after_millis, after_id, updated_millis)
         VALUES ($1, $2, $3, $2)
         ON CONFLICT (site) DO UPDATE SET
             after_millis = EXCLUDED.after_millis,
             after_id = EXCLUDED.after_id,
             updated_millis = EXCLUDED.updated_millis",
    )
    .bind(site)
    .bind(deleted_millis)
    .bind(i64::MAX)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// A day counted from the epoch as the column stores it. A value out of range
/// saturates, which no real day reaches.
fn day_i64(day: u64) -> i64 {
    i64::try_from(day).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    // These storage-layer tests need a reachable PostgreSQL instance. They run
    // when `XSHIELD_TEST_DATABASE_URL` is set (scripts/test_postgres.sh does that
    // after applying `migrations/`).

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use xshield_core::context::ObjectMap;

    fn unique_site(prefix: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!("{prefix}_{}", COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }

    /// Creates the configuration row a learning write looks for, and returns its
    /// generation. A site without one keeps no state.
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

    fn cursor_at(at_millis: i64, id: i64) -> Cursor {
        Cursor { at_millis, id }
    }

    /// A proposal of `SLOT` as a doctor, with enough evidence to be written.
    fn proposal() -> Judgement<'static> {
        Judgement {
            slot: SLOT,
            state: LearnedState::Proposed,
            class: "doctor",
            votes: 20,
            sessions: 5,
            share_per_mille: 950,
            last_day: 3,
        }
    }

    /// The learning rows the site keeps across the three tables.
    async fn learning_rows(pool: &PgPool, site: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM object_evidence WHERE site = $1)
                  + (SELECT count(*) FROM object_positions WHERE site = $1)
                  + (SELECT count(*) FROM object_learning_cursor WHERE site = $1)",
        )
        .bind(site)
        .fetch_one(pool)
        .await
        .expect("count the learning rows")
    }

    const SLOT: &str = "GET /doctor/{id} path[1]";

    fn vote(session: &str, day: u64, from: &[&str]) -> Vote {
        Vote {
            slot: SLOT.to_owned(),
            session: session.to_owned(),
            day,
            from: from.iter().map(|position| (*position).to_owned()).collect(),
        }
    }

    /// Doctor positions are the appointment and record fields; `GET /api/docs [].id` is a document.
    fn doctor_map() -> ObjectMap {
        serde_json::from_str(
            r#"{"classes": [{"id": "doctor", "name": "医生"}, {"id": "document", "name": "文档"}],
                "slots": [
                    {"key": "GET /api/appointments [].doc_id", "class": "doctor", "source": "admin"},
                    {"key": "GET /api/records [].doc_id", "class": "doctor", "source": "admin"},
                    {"key": "GET /api/docs [].id", "class": "document", "source": "admin"}
                ]}"#,
        )
        .expect("the test map")
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_vote_is_counted_once_and_keeps_its_first_position() {
        let pool = connect_test_pool().await;
        let site = unique_site("evidence_once");
        let generation = with_site(&pool, &site).await;
        let first = vec![vote("a", 3, &["GET /api/appointments [].doc_id"])];
        record_evidence(&pool, &site, generation, &first, &[])
            .await
            .unwrap();
        // The same session and day again, from another position: changes nothing.
        let again = vec![vote("a", 3, &["GET /api/other [].id"])];
        record_evidence(&pool, &site, generation, &again, &[])
            .await
            .unwrap();
        let loaded = load_evidence(&pool, &site, &[SLOT.to_owned()], 0)
            .await
            .unwrap();
        let evidence = &loaded[SLOT];
        assert_eq!(evidence.votes(), 1);
        // The first position still names the doctor kind, so the vote counts toward it.
        assert_eq!(evidence.kinds(&doctor_map()).get("doctor"), Some(&1));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn every_response_position_of_a_vote_is_kept() {
        let pool = connect_test_pool().await;
        let site = unique_site("evidence_from");
        let generation = with_site(&pool, &site).await;
        // Both positions are doctors, so the first vote counts toward the doctor kind.
        let agree = vote(
            "a",
            3,
            &[
                "GET /api/appointments [].doc_id",
                "GET /api/records [].doc_id",
            ],
        );
        // The positions disagree, so the second vote counts toward no kind.
        let disagree = vote(
            "b",
            3,
            &["GET /api/appointments [].doc_id", "GET /api/docs [].id"],
        );
        record_evidence(&pool, &site, generation, &[agree, disagree], &[])
            .await
            .unwrap();
        let loaded = load_evidence(&pool, &site, &[SLOT.to_owned()], 0)
            .await
            .unwrap();
        let evidence = &loaded[SLOT];
        assert_eq!(evidence.votes(), 2);
        assert_eq!(evidence.kinds(&doctor_map()).get("doctor"), Some(&1));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn pruning_keeps_only_the_window() {
        let pool = connect_test_pool().await;
        let site = unique_site("evidence_window");
        let generation = with_site(&pool, &site).await;
        let votes = vec![vote("a", 1, &[]), vote("b", 10, &[])];
        record_evidence(&pool, &site, generation, &votes, &[])
            .await
            .unwrap();
        let deleted = prune_evidence(&pool, &site, 5).await.unwrap();
        assert_eq!(deleted, 1);
        let loaded = load_evidence(&pool, &site, &["GET /doctor/{id} path[1]".to_owned()], 0)
            .await
            .unwrap();
        assert_eq!(loaded["GET /doctor/{id} path[1]"].votes(), 1);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_dismissed_position_is_not_proposed_again() {
        let pool = connect_test_pool().await;
        let site = unique_site("dismissed");
        let generation = with_site(&pool, &site).await;
        let slot = "GET /doctor/{id} path[1]";
        let judgement = Judgement {
            slot,
            state: LearnedState::Proposed,
            class: "doctor",
            votes: 20,
            sessions: 5,
            share_per_mille: 950,
            last_day: 3,
        };
        put_judgement(&pool, &site, generation, &judgement, 1)
            .await
            .unwrap();
        sqlx::query("UPDATE object_positions SET state = 'dismissed' WHERE site = $1")
            .bind(&site)
            .execute(&pool)
            .await
            .unwrap();
        put_judgement(&pool, &site, generation, &judgement, 2)
            .await
            .unwrap();
        let state: String =
            sqlx::query_scalar("SELECT state FROM object_positions WHERE site = $1")
                .bind(&site)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(state, "dismissed");
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_cursor_starts_empty_and_moves_forward() {
        let pool = connect_test_pool().await;
        let site = unique_site("cursor");
        let generation = with_site(&pool, &site).await;
        assert_eq!(cursor(&pool, &site).await.unwrap(), None);
        advance_cursor(&pool, &site, generation, cursor_at(100, 0), 1_000)
            .await
            .unwrap();
        advance_cursor(&pool, &site, generation, cursor_at(250, 4), 2_000)
            .await
            .unwrap();
        // The cursor never moves back, not even within one millisecond.
        advance_cursor(&pool, &site, generation, cursor_at(250, 2), 3_000)
            .await
            .unwrap();
        assert_eq!(cursor(&pool, &site).await.unwrap(), Some(cursor_at(250, 4)));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_site_without_a_configuration_keeps_no_learning_state() {
        let pool = connect_test_pool().await;
        // No configuration row: the site was deleted while a pass was running.
        let site = unique_site("deleted");
        let generation = Utc::now();
        record_evidence(&pool, &site, generation, &[vote("a", 3, &[])], &[])
            .await
            .unwrap();
        put_judgement(&pool, &site, generation, &proposal(), 1)
            .await
            .unwrap();
        advance_cursor(&pool, &site, generation, cursor_at(100, 0), 1)
            .await
            .unwrap();
        assert_eq!(learning_rows(&pool, &site).await, 0);
        assert_eq!(cursor(&pool, &site).await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn forgetting_a_site_removes_its_evidence_and_moves_its_cursor() {
        let pool = connect_test_pool().await;
        let site = unique_site("forget");
        let generation = with_site(&pool, &site).await;
        record_evidence(&pool, &site, generation, &[vote("a", 3, &[])], &[])
            .await
            .unwrap();
        put_judgement(&pool, &site, generation, &proposal(), 1)
            .await
            .unwrap();
        advance_cursor(&pool, &site, generation, cursor_at(100, 0), 1)
            .await
            .unwrap();
        assert_eq!(learning_rows(&pool, &site).await, 3);
        let mut transaction = pool.begin().await.unwrap();
        forget_site(&mut transaction, &site, 500).await.unwrap();
        transaction.commit().await.unwrap();
        // Only the cursor remains, moved to the deletion time.
        assert_eq!(learning_rows(&pool, &site).await, 1);
        assert_eq!(
            cursor(&pool, &site).await.unwrap(),
            Some(cursor_at(500, i64::MAX))
        );
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_write_from_an_earlier_generation_of_the_site_is_dropped() {
        let pool = connect_test_pool().await;
        let site = unique_site("generation");
        let earlier = with_site(&pool, &site).await;
        // The site is deleted and created again under the same name while a pass that read
        // it before the deletion is still running.
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query("DELETE FROM site_configs WHERE name = $1")
            .bind(&site)
            .execute(&mut *transaction)
            .await
            .unwrap();
        forget_site(&mut transaction, &site, 500).await.unwrap();
        transaction.commit().await.unwrap();
        let current = with_site(&pool, &site).await;
        assert_ne!(earlier, current);
        // The earlier pass writes its batch, its judgement and its cursor: all dropped.
        record_evidence(&pool, &site, earlier, &[vote("a", 3, &[])], &[])
            .await
            .unwrap();
        put_judgement(&pool, &site, earlier, &proposal(), 1)
            .await
            .unwrap();
        advance_cursor(&pool, &site, earlier, cursor_at(600, 0), 1)
            .await
            .unwrap();
        // Only the cursor the deletion left remains, still at the deletion time.
        assert_eq!(learning_rows(&pool, &site).await, 1);
        assert_eq!(
            cursor(&pool, &site).await.unwrap(),
            Some(cursor_at(500, i64::MAX))
        );
        // The current generation writes as usual.
        record_evidence(&pool, &site, current, &[vote("b", 3, &[])], &[])
            .await
            .unwrap();
        assert_eq!(learning_rows(&pool, &site).await, 2);
    }
}
