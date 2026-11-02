//! Storage of the object-map learning (docs/object-map-design.md section 3): the
//! evidence the rules count, the state of each position they have judged, and each
//! site's cursor over its decision log. Only the control plane writes these tables,
//! which `migrations/0003_object_learning.sql` defines.
//!
//! Every write is idempotent. The evidence of a position, session and UTC day is
//! counted once, and a judgement overwrites only the rows the rules own, so a pass
//! that reads a batch twice, or stops half way, changes nothing it should not.

use std::collections::HashMap;

use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
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

/// One batch of decision rows of a site, oldest first.
#[derive(Debug, Default)]
pub struct DecisionBatch {
    /// The rows whose stored values this build reads.
    pub facts: Vec<DecisionFacts>,
    /// Every row read, including those left out of `facts`.
    pub rows: usize,
    /// The newest time among the rows read, Unix milliseconds.
    pub newest_millis: Option<i64>,
}

/// Reads up to `limit` decision rows of `site` judged after `after_millis` and at or
/// before `through_millis`, oldest first. A row whose stored values this build does
/// not read is counted in `rows` but left out of `facts`, so the cursor moves past it.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn read_batch(
    pool: &PgPool,
    site: &str,
    after_millis: i64,
    through_millis: i64,
    limit: i64,
) -> Result<DecisionBatch, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT at_millis, session, status, decision_path, outcome, trace FROM decision_log
         WHERE site = $1 AND at_millis > $2 AND at_millis <= $3
         ORDER BY at_millis, id LIMIT $4",
    )
    .bind(site)
    .bind(after_millis)
    .bind(through_millis)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut batch = DecisionBatch {
        rows: rows.len(),
        ..DecisionBatch::default()
    };
    for row in &rows {
        let at_millis: i64 = row.try_get("at_millis")?;
        batch.newest_millis = Some(
            batch
                .newest_millis
                .map_or(at_millis, |newest| newest.max(at_millis)),
        );
        if let Some(facts) = facts_of(row, at_millis)? {
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

/// Records the votes and refusals of a batch. A position, session and UTC day is
/// counted once: a repeat changes nothing, and the first vote keeps the response
/// position it came from. Recording the same rows again is therefore harmless.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn record_evidence(
    pool: &PgPool,
    site: &str,
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
        // vote's response positions are a list, not one value.
        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO object_evidence (site, slot, session, day, kind, from_slots) ",
        );
        builder.push_values(chunk, |mut values, row| {
            values
                .push_bind(site)
                .push_bind(row.slot)
                .push_bind(row.session)
                .push_bind(row.day)
                .push_bind(row.kind)
                .push_bind(row.from.clone());
        });
        builder.push(" ON CONFLICT DO NOTHING");
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

/// Writes the state of one position. A row an administrator dismissed or marked
/// ambiguous is left alone, and a confirmed write never undoes a suspension: that
/// one waits for an administrator.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn put_judgement(
    pool: &PgPool,
    site: &str,
    judgement: &Judgement<'_>,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "INSERT INTO object_positions
             (site, slot, state, class, votes, sessions, share_per_mille, last_day, updated_millis)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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

/// The time up to which the pass has read the site's decision log, if it has started.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn cursor(pool: &PgPool, site: &str) -> Result<Option<i64>, LearningStoreError> {
    let row = sqlx::query("SELECT after_millis FROM object_learning_cursor WHERE site = $1")
        .bind(site)
        .fetch_optional(pool)
        .await?;
    match row {
        Some(row) => Ok(Some(row.try_get("after_millis")?)),
        None => Ok(None),
    }
}

/// Moves the site's cursor to `after_millis`.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn advance_cursor(
    pool: &PgPool,
    site: &str,
    after_millis: i64,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "INSERT INTO object_learning_cursor (site, after_millis, updated_millis)
         VALUES ($1, $2, $3)
         ON CONFLICT (site) DO UPDATE SET
             after_millis = EXCLUDED.after_millis,
             updated_millis = EXCLUDED.updated_millis",
    )
    .bind(site)
    .bind(after_millis)
    .bind(now_millis)
    .execute(pool)
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
        let first = vec![vote("a", 3, &["GET /api/appointments [].doc_id"])];
        record_evidence(&pool, &site, &first, &[]).await.unwrap();
        // The same session and day again, from another position: changes nothing.
        let again = vec![vote("a", 3, &["GET /api/other [].id"])];
        record_evidence(&pool, &site, &again, &[]).await.unwrap();
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
        record_evidence(&pool, &site, &[agree, disagree], &[])
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
        let votes = vec![vote("a", 1, &[]), vote("b", 10, &[])];
        record_evidence(&pool, &site, &votes, &[]).await.unwrap();
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
        put_judgement(&pool, &site, &judgement, 1).await.unwrap();
        sqlx::query("UPDATE object_positions SET state = 'dismissed' WHERE site = $1")
            .bind(&site)
            .execute(&pool)
            .await
            .unwrap();
        put_judgement(&pool, &site, &judgement, 2).await.unwrap();
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
        assert_eq!(cursor(&pool, &site).await.unwrap(), None);
        advance_cursor(&pool, &site, 100, 1_000).await.unwrap();
        advance_cursor(&pool, &site, 250, 2_000).await.unwrap();
        assert_eq!(cursor(&pool, &site).await.unwrap(), Some(250));
    }
}
