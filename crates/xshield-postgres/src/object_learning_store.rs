//! Storage of the object-map learning (docs/object-map-design.md section 3): the
//! evidence the rules count, the state of each position they have judged, and each
//! site's cursor over its decision log. Only the control plane writes these tables,
//! which `migrations/0003_object_learning.sql` and `migrations/0004_object_positions_ids.sql`
//! define.
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

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use xshield_core::context::learning::{DecisionFacts, Denial, Evidence, Vote};
use xshield_core::context::log::{DecisionPath, Outcome};
use xshield_core::context::trace::Trace;

/// Evidence rows per insert statement, which bounds the size of one statement.
const EVIDENCE_CHUNK: usize = 1_000;
/// Milliseconds in a UTC day.
const DAY_MILLIS: i64 = 86_400_000;
/// Decision rows read to find the responses a response position's examples come from.
const EXAMPLE_ROWS_READ: i64 = 200;

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

/// Who gave a position's kind: the rules, or the learning agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The rules judged the position from its names and votes.
    Rule,
    /// The learning agent answered the position's question.
    Agent,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Agent => "agent",
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
    /// Who gave the kind.
    pub source: Source,
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

/// How many decision rows a site logged at or after `since_millis`.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn records_since(
    pool: &PgPool,
    site: &str,
    since_millis: i64,
) -> Result<i64, LearningStoreError> {
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM decision_log WHERE site = $1 AND at_millis >= $2")
            .bind(site)
            .bind(since_millis)
            .fetch_one(pool)
            .await?;
    Ok(count)
}

/// The newest decision rows of a site at or after `since_millis`, at most `limit` of them, read as
/// facts. A row whose stored values this build does not read is left out.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn recent_facts(
    pool: &PgPool,
    site: &str,
    since_millis: i64,
    limit: i64,
) -> Result<Vec<DecisionFacts>, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT id, at_millis, session, status, decision_path, outcome, trace FROM decision_log
         WHERE site = $1 AND at_millis >= $2
         ORDER BY at_millis DESC, id DESC LIMIT $3",
    )
    .bind(site)
    .bind(since_millis)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut facts = Vec::with_capacity(rows.len());
    for row in &rows {
        let at_millis: i64 = row.try_get("at_millis")?;
        facts.extend(facts_of(row, at_millis)?);
    }
    Ok(facts)
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
            from: distinct(&vote.from),
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
    let stored = stored_sources(pool, site, votes).await?;
    record_positions(pool, site, generation, votes, denials, &stored).await?;
    Ok(())
}

/// The day and the response positions of each vote the evidence holds, whether this call wrote
/// that evidence or an earlier call did. The evidence and the positions are written by separate
/// statements, so a call can fail between them, and its retry finds the evidence already there:
/// the sources it holds name the positions to write, not what this call happened to insert.
async fn stored_sources(
    pool: &PgPool,
    site: &str,
    votes: &[Vote],
) -> Result<Vec<(i64, Vec<String>)>, LearningStoreError> {
    let mut stored: Vec<(i64, Vec<String>)> = Vec::new();
    for chunk in votes.chunks(EVIDENCE_CHUNK) {
        let slots: Vec<String> = chunk.iter().map(|vote| vote.slot.clone()).collect();
        let sessions: Vec<String> = chunk.iter().map(|vote| vote.session.clone()).collect();
        let days: Vec<i64> = chunk.iter().map(|vote| day_i64(vote.day)).collect();
        let rows = sqlx::query(
            "SELECT e.day, e.from_slots
             FROM object_evidence e
             JOIN unnest($2::text[], $3::text[], $4::bigint[]) AS k(slot, session, day)
                 ON e.slot = k.slot AND e.session = k.session AND e.day = k.day
             WHERE e.site = $1 AND e.kind = 'vote'",
        )
        .bind(site)
        .bind(slots)
        .bind(sessions)
        .bind(days)
        .fetch_all(pool)
        .await?;
        for row in rows {
            stored.push((row.try_get("day")?, row.try_get("from_slots")?));
        }
    }
    Ok(stored)
}

/// Keeps a row for every position the batch names: a request position a value sat at, and a
/// response position a vote's evidence holds. A new row is pending until a judgement arrives,
/// and a row the window retired comes back pending when a vote sees it again. A refusal is not
/// a use: it adds a pending row when the position has none, and it never moves the day the
/// position was last used, so retirement counts from the last vote.
async fn record_positions(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    votes: &[Vote],
    denials: &[Denial],
    stored: &[(i64, Vec<String>)],
) -> Result<(), LearningStoreError> {
    // One entry per position: a statement may not change the same row twice.
    let mut used: BTreeMap<&str, (&'static str, i64)> = BTreeMap::new();
    for vote in votes {
        note_position(&mut used, &vote.slot, "request", day_i64(vote.day));
    }
    // A response position comes from the sources the evidence holds. A repeat of a vote holds
    // none of its own sources, so they name no flow and make no position.
    for (day, from) in stored {
        for position in from {
            note_position(&mut used, position.as_str(), "response", *day);
        }
    }
    let mut refused: BTreeMap<&str, i64> = BTreeMap::new();
    for denial in denials {
        let day = day_i64(denial.day);
        let last = refused.entry(denial.slot.as_str()).or_insert(day);
        *last = (*last).max(day);
    }
    refused.retain(|slot, _| !used.contains_key(slot));
    let used: Vec<(&str, &str, i64)> = used
        .into_iter()
        .map(|(slot, (side, day))| (slot, side, day))
        .collect();
    let refused: Vec<(&str, &str, i64)> = refused
        .into_iter()
        .map(|(slot, day)| (slot, "request", day))
        .collect();
    write_positions(pool, site, generation, &used, USED_CONFLICT).await?;
    write_positions(pool, site, generation, &refused, REFUSED_CONFLICT).await?;
    Ok(())
}

/// Notes that `slot` was seen on `side` on `day`. A position seen as a request keeps the
/// request side, and its last day is the latest day it was seen.
fn note_position<'a>(
    positions: &mut BTreeMap<&'a str, (&'static str, i64)>,
    slot: &'a str,
    side: &'static str,
    day: i64,
) {
    let entry = positions.entry(slot).or_insert((side, day));
    entry.1 = entry.1.max(day);
    if side == "request" {
        entry.0 = "request";
    }
}

/// A vote's response positions, each once. A value can match one position twice, when two
/// history items sit at the same location, but a vote reached each position once.
fn distinct(from: &[String]) -> Vec<String> {
    let mut from = from.to_vec();
    from.sort_unstable();
    from.dedup();
    from
}

/// How a used position's row changes when a vote sees it: its last day moves to the latest day
/// it was used, and a retired row comes back pending.
const USED_CONFLICT: &str = " ON CONFLICT (site, slot) DO UPDATE SET
         last_day = GREATEST(object_positions.last_day, EXCLUDED.last_day),
         updated_millis = GREATEST(object_positions.updated_millis, EXCLUDED.updated_millis),
         state = CASE WHEN object_positions.state = 'retired' THEN 'pending'
                      ELSE object_positions.state END,
         class = CASE WHEN object_positions.state = 'retired' THEN NULL
                      ELSE object_positions.class END";

/// How a refused position's row changes: a row the position already has stays as it is.
const REFUSED_CONFLICT: &str = " ON CONFLICT (site, slot) DO NOTHING";

/// Writes position rows in chunks, while the site still has the configuration of `generation`.
/// Each row is a slot, its side, and the day it was used or refused.
async fn write_positions(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    rows: &[(&str, &str, i64)],
    on_conflict: &'static str,
) -> Result<(), LearningStoreError> {
    for chunk in rows.chunks(EVIDENCE_CHUNK) {
        let mut builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO object_positions (site, slot, side, state, last_day, updated_millis)
             SELECT site, slot, side, 'pending', day, updated FROM (",
        );
        builder.push_values(chunk, |mut values, &(slot, side, day)| {
            values.push_bind(site);
            values.push_unseparated("::text");
            values.push_bind(slot);
            values.push_unseparated("::text");
            values.push_bind(side);
            values.push_unseparated("::text");
            values.push_bind(day);
            values.push_unseparated("::bigint");
            values.push_bind(day.saturating_mul(DAY_MILLIS));
            values.push_unseparated("::bigint");
        });
        builder.push(
            ") AS v(site, slot, side, day, updated)
             WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = ",
        );
        builder.push_bind(site);
        builder.push(" AND created_at = ");
        builder.push_bind(generation);
        builder.push(" FOR SHARE)");
        builder.push(on_conflict);
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
/// marked ambiguous is left alone, and a confirmed write never undoes a suspension: that
/// one waits for an administrator. A dismissed proposal is written again only when the
/// evidence has changed significantly (see migration 0004).
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
             (site, slot, state, class, votes, sessions, share_per_mille, last_day, updated_millis,
              source)
         SELECT $1::text, $2::text, $3::text, $4::text, $5::integer, $6::integer, $7::integer,
             $8::bigint, $9::bigint, $11::text
         WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $10 FOR SHARE)
         ON CONFLICT (site, slot) DO UPDATE SET
             state = EXCLUDED.state,
             class = EXCLUDED.class,
             votes = EXCLUDED.votes,
             sessions = EXCLUDED.sessions,
             share_per_mille = EXCLUDED.share_per_mille,
             last_day = EXCLUDED.last_day,
             updated_millis = EXCLUDED.updated_millis,
             source = EXCLUDED.source,
             dismissed = false,
             dismissed_class = NULL,
             dismissed_votes = 0
         WHERE object_positions.state <> 'ambiguous'
           AND NOT (EXCLUDED.state = 'confirmed' AND object_positions.state = 'suspended')
           AND (EXCLUDED.state <> 'proposed' OR NOT object_positions.dismissed
                OR (object_positions.dismissed_class IS NOT NULL
                    AND EXCLUDED.class IS DISTINCT FROM object_positions.dismissed_class)
                OR EXCLUDED.votes >= 2 * object_positions.dismissed_votes)",
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
    .bind(judgement.source.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Retires the pending, proposed, confirmed and suspended positions whose last vote is on or
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
         WHERE site = $1 AND state IN ('pending', 'proposed', 'confirmed', 'suspended')
           AND last_day <= $2",
    )
    .bind(site)
    .bind(day_i64(last_day_at_most))
    .bind(now_millis)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Forgets the retired positions whose last use is on or before `last_day_at_most`, so a
/// position keeps its row for the retention period after its last use. Like the retirement
/// it needs no generation: it acts only on rows the window has aged out. Returns how many
/// rows were forgotten.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn prune_retired(
    pool: &PgPool,
    site: &str,
    last_day_at_most: u64,
) -> Result<u64, LearningStoreError> {
    let result = sqlx::query(
        "DELETE FROM object_positions WHERE site = $1 AND state = 'retired' AND last_day <= $2",
    )
    .bind(site)
    .bind(day_i64(last_day_at_most))
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
/// proposal: the position returns to pending, so the console still lists it. Confirmed,
/// suspended, retired, dismissed and ambiguous positions are left alone.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn withdraw_proposal(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    slot: &str,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "UPDATE object_positions SET state = 'pending', class = NULL, source = 'rule',
             updated_millis = $4
         WHERE site = $1 AND slot = $2 AND state = 'proposed'
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $3 FOR SHARE)",
    )
    .bind(site)
    .bind(slot)
    .bind(generation)
    .bind(now_millis)
    .execute(pool)
    .await?;
    Ok(())
}

/// One position row as the console lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionRow {
    /// The row's identity. The console addresses a learned row as `s<id>`.
    pub id: i64,
    /// The position key, `METHOD route location`.
    pub slot: String,
    /// `request` for a position a request value sits at, `response` for a response position.
    pub side: String,
    /// The state the rules gave the position, or `pending` while it has no proposal.
    pub state: String,
    /// The kind the state is about, when it has one.
    pub class: Option<String>,
    /// Whether the proposal was dismissed, or the position was while it was pending.
    pub dismissed: bool,
    /// `rule` or `agent`: who gave the kind of a proposal.
    pub source: String,
    /// Votes in the window.
    pub votes: i32,
    /// Sessions that voted in the window.
    pub sessions: i32,
    /// Share of the votes whose response position has `class`, in thousandths.
    pub share_per_mille: i32,
    /// The last UTC day the position was seen.
    pub last_day: i64,
}

/// The positions of a site, in the order they were first kept.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn positions(pool: &PgPool, site: &str) -> Result<Vec<PositionRow>, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT id, slot, side, state, class, dismissed, source, votes, sessions, share_per_mille,
             last_day
         FROM object_positions WHERE site = $1 ORDER BY id",
    )
    .bind(site)
    .fetch_all(pool)
    .await?;
    rows.iter().map(position_row).collect()
}

/// The position of the site with the given id, if there is one.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn position(
    pool: &PgPool,
    site: &str,
    id: i64,
) -> Result<Option<PositionRow>, LearningStoreError> {
    let row = sqlx::query(
        "SELECT id, slot, side, state, class, dismissed, source, votes, sessions, share_per_mille,
             last_day
         FROM object_positions WHERE site = $1 AND id = $2",
    )
    .bind(site)
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(position_row).transpose()
}

fn position_row(row: &PgRow) -> Result<PositionRow, LearningStoreError> {
    Ok(PositionRow {
        id: row.try_get("id")?,
        slot: row.try_get("slot")?,
        side: row.try_get("side")?,
        state: row.try_get("state")?,
        class: row.try_get("class")?,
        dismissed: row.try_get("dismissed")?,
        source: row.try_get("source")?,
        votes: row.try_get("votes")?,
        sessions: row.try_get("sessions")?,
        share_per_mille: row.try_get("share_per_mille")?,
        last_day: row.try_get("last_day")?,
    })
}

/// One other end of a position's votes: how many reached it, and from how many sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// The position at the other end.
    pub other: String,
    /// Votes that reached it, on or after the window's first day.
    pub uses: i64,
    /// Sessions among those votes.
    pub sessions: i64,
}

/// The other ends of a position's votes on or after `oldest_day`, most used first. A
/// request position's other ends are the response positions its votes were shown at; a
/// response position's are the request positions that showed a value at it. Every end the
/// votes reached is listed, so the rows are bounded by the positions the votes reached. The
/// drawer caps what it shows after it merges them with the decisions.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn flows(
    pool: &PgPool,
    site: &str,
    slot: &str,
    slot_side: &str,
    oldest_day: u64,
) -> Result<Vec<Flow>, LearningStoreError> {
    let sql: &'static str = if slot_side == "response" {
        "SELECT e.slot AS other, count(*) AS uses, count(DISTINCT e.session) AS sessions
         FROM object_evidence e
         WHERE e.site = $1 AND e.kind = 'vote' AND e.day >= $3 AND $2 = ANY(e.from_slots)
         GROUP BY e.slot ORDER BY uses DESC, other"
    } else {
        "SELECT f.other, count(*) AS uses, count(DISTINCT e.session) AS sessions
         FROM object_evidence e CROSS JOIN LATERAL unnest(e.from_slots) AS f(other)
         WHERE e.site = $1 AND e.slot = $2 AND e.kind = 'vote' AND e.day >= $3
         GROUP BY f.other ORDER BY uses DESC, other"
    };
    let rows = sqlx::query(sql)
        .bind(site)
        .bind(slot)
        .bind(day_i64(oldest_day))
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|row| -> Result<Flow, LearningStoreError> {
            Ok(Flow {
                other: row.try_get("other")?,
                uses: row.try_get("uses")?,
                sessions: row.try_get("sessions")?,
            })
        })
        .collect()
}

/// The votes that reached a position on or after `oldest_day`: the uses its flows share. A
/// request position's uses are its own votes, and a response position's are the votes that
/// showed a value at it. A flow's share is its uses over these.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn uses(
    pool: &PgPool,
    site: &str,
    slot: &str,
    slot_side: &str,
    oldest_day: u64,
) -> Result<i64, LearningStoreError> {
    let total: i64 = if slot_side == "response" {
        sqlx::query_scalar(
            "SELECT count(*) FROM object_evidence
             WHERE site = $1 AND kind = 'vote' AND day >= $3 AND $2 = ANY(from_slots)",
        )
    } else {
        sqlx::query_scalar(
            "SELECT count(*) FROM object_evidence
             WHERE site = $1 AND kind = 'vote' AND day >= $3 AND slot = $2",
        )
    }
    .bind(site)
    .bind(slot)
    .bind(day_i64(oldest_day))
    .fetch_one(pool)
    .await?;
    Ok(total)
}

/// Jev's decisions on the requests that reached one other end of a position's flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JevFlow {
    /// The position at the other end.
    pub other: String,
    /// Requests that reached it and that Jev allowed.
    pub allow: i64,
    /// Requests that reached it and that Jev refused.
    pub deny: i64,
}

/// Up to `limit` request ids that used a position, newest first. A request position's
/// examples are the requests whose values sat at it. A response position's are the
/// responses that showed a value at it, newest observed first: the requests that used such
/// a value name the response in their `sources`, and only the newest [`EXAMPLE_ROWS_READ`]
/// of those requests are read. A source without its observation time is placed by the
/// request that used it. Only decision rows at or after `since_millis` count.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn examples(
    pool: &PgPool,
    site: &str,
    slot: &str,
    slot_side: &str,
    since_millis: i64,
    limit: i64,
) -> Result<Vec<String>, LearningStoreError> {
    let rows = if slot_side == "response" {
        sqlx::query(
            "WITH recent AS (
                 SELECT d.trace, d.at_millis FROM decision_log d
                 WHERE d.site = $1 AND d.at_millis >= $3
                   AND d.trace @> jsonb_build_object('values', jsonb_build_array(
                       jsonb_build_object('sources', jsonb_build_array(
                           jsonb_build_object('slot', $2::text)))))
                 ORDER BY d.at_millis DESC
                 LIMIT $5
             )
             SELECT s ->> 'request_id' AS request_id
             FROM recent
             CROSS JOIN LATERAL jsonb_array_elements(
                 COALESCE(recent.trace -> 'values', '[]'::jsonb)) AS v
             CROSS JOIN LATERAL jsonb_array_elements(COALESCE(v -> 'sources', '[]'::jsonb)) AS s
             WHERE s ->> 'slot' = $2 AND s ->> 'request_id' IS NOT NULL
             GROUP BY s ->> 'request_id'
             ORDER BY max(COALESCE((s ->> 'at_millis')::bigint, recent.at_millis)) DESC
             LIMIT $4",
        )
        .bind(site)
        .bind(slot)
        .bind(since_millis)
        .bind(limit)
        .bind(EXAMPLE_ROWS_READ)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query(
            "SELECT d.request_id FROM decision_log d
             WHERE d.site = $1 AND d.at_millis >= $3
               AND d.trace @> jsonb_build_object('values', jsonb_build_array(
                   jsonb_build_object('slot', $2::text)))
             ORDER BY d.at_millis DESC
             LIMIT $4",
        )
        .bind(site)
        .bind(slot)
        .bind(since_millis)
        .bind(limit)
        .fetch_all(pool)
        .await?
    };
    rows.iter()
        .map(|row| {
            row.try_get::<String, _>("request_id")
                .map_err(LearningStoreError::from)
        })
        .collect()
}

/// Jev's decisions on the requests of a position's flows since `since_millis`, most decided
/// first. A request position's other ends are the response positions its values were shown
/// at; a response position's are the request positions that used its values. Each request
/// counts once per other end. There is one row per other end Jev decided on, whether or not
/// the votes reached it, so the drawer's flows always carry their decisions. The rows are
/// bounded by the positions the values reached, so no limit is applied. Only calls to Jev
/// are read, which the partial index on them covers.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn jev_flows(
    pool: &PgPool,
    site: &str,
    slot: &str,
    slot_side: &str,
    since_millis: i64,
) -> Result<Vec<JevFlow>, LearningStoreError> {
    let sql: &'static str = if slot_side == "response" {
        "WITH judged AS (
             SELECT DISTINCT d.at_millis, d.id, d.decision_path, v ->> 'slot' AS other
             FROM decision_log d
             CROSS JOIN LATERAL jsonb_array_elements(COALESCE(d.trace -> 'values', '[]'::jsonb)) AS v
             WHERE d.site = $1 AND d.at_millis >= $3 AND d.jev IS NOT NULL
               AND d.decision_path IN ('jev_allow', 'jev_deny')
               AND d.trace @> jsonb_build_object('values', jsonb_build_array(
                   jsonb_build_object('sources', jsonb_build_array(
                       jsonb_build_object('slot', $2::text)))))
               AND v ->> 'slot' IS NOT NULL
               AND EXISTS (
                   SELECT 1 FROM jsonb_array_elements(COALESCE(v -> 'sources', '[]'::jsonb)) AS s
                   WHERE s ->> 'slot' = $2)
         )
         SELECT other,
                count(*) FILTER (WHERE decision_path = 'jev_allow') AS allow,
                count(*) FILTER (WHERE decision_path = 'jev_deny') AS deny
         FROM judged GROUP BY other ORDER BY count(*) DESC, other"
    } else {
        "WITH judged AS (
             SELECT DISTINCT d.at_millis, d.id, d.decision_path, s ->> 'slot' AS other
             FROM decision_log d
             CROSS JOIN LATERAL jsonb_array_elements(COALESCE(d.trace -> 'values', '[]'::jsonb)) AS v
             CROSS JOIN LATERAL jsonb_array_elements(COALESCE(v -> 'sources', '[]'::jsonb)) AS s
             WHERE d.site = $1 AND d.at_millis >= $3 AND d.jev IS NOT NULL
               AND d.decision_path IN ('jev_allow', 'jev_deny')
               AND d.trace @> jsonb_build_object('values', jsonb_build_array(
                   jsonb_build_object('slot', $2::text)))
               AND v ->> 'slot' = $2 AND s ->> 'slot' IS NOT NULL
         )
         SELECT other,
                count(*) FILTER (WHERE decision_path = 'jev_allow') AS allow,
                count(*) FILTER (WHERE decision_path = 'jev_deny') AS deny
         FROM judged GROUP BY other ORDER BY count(*) DESC, other"
    };
    let rows = sqlx::query(sql)
        .bind(site)
        .bind(slot)
        .bind(since_millis)
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|row| -> Result<JevFlow, LearningStoreError> {
            Ok(JevFlow {
                other: row.try_get("other")?,
                allow: row.try_get("allow")?,
                deny: row.try_get("deny")?,
            })
        })
        .collect()
}

/// Dismisses the proposal of a request position, or the position while it is pending: the
/// rules stop proposing it. The baseline the evidence must double from is the votes the
/// position has now, or `min_votes` when it has fewer. Returns whether a position was
/// dismissed; a confirmed, suspended, retired or ambiguous position is not.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn dismiss(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    id: i64,
    min_votes: i32,
    now_millis: i64,
) -> Result<bool, LearningStoreError> {
    let result = sqlx::query(
        "UPDATE object_positions SET
             state = 'pending',
             class = NULL,
             dismissed = true,
             dismissed_class = class,
             dismissed_votes = GREATEST(votes, $3::integer),
             updated_millis = $4
         WHERE site = $1 AND id = $2 AND side = 'request' AND state IN ('proposed', 'pending')
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $5 FOR SHARE)",
    )
    .bind(site)
    .bind(id)
    .bind(min_votes)
    .bind(now_millis)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Marks a request position ambiguous: it stays with Jev, and the rules never propose it.
/// Only a pending or proposed position is marked: a confirmed, suspended, retired or ambiguous
/// one is not. Returns whether a position was marked.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn mark_ambiguous(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    id: i64,
    now_millis: i64,
) -> Result<bool, LearningStoreError> {
    let result = sqlx::query(
        "UPDATE object_positions SET
             state = 'ambiguous',
             class = NULL,
             dismissed = false,
             dismissed_class = NULL,
             dismissed_votes = 0,
             updated_millis = $3
         WHERE site = $1 AND id = $2 AND side = 'request' AND state IN ('pending', 'proposed')
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $4 FOR SHARE)",
    )
    .bind(site)
    .bind(id)
    .bind(now_millis)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
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
        "DELETE FROM object_agent_calls WHERE site = $1",
        "DELETE FROM object_learning_runs WHERE site = $1",
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
            source: Source::Rule,
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

    /// The row the store keeps for `slot` on `side`, as the console lists it.
    async fn row_of(pool: &PgPool, site: &str, slot: &str, slot_side: &str) -> PositionRow {
        positions(pool, site)
            .await
            .expect("list the positions")
            .into_iter()
            .find(|row| row.slot == slot && row.side == slot_side)
            .expect("the position has a row")
    }

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
    async fn a_retired_position_is_forgotten_once_its_retention_period_ends() {
        let pool = connect_test_pool().await;
        let site = unique_site("retention");
        let generation = with_site(&pool, &site).await;
        // One position last used on day 10, and one used on day 50.
        let old = Judgement {
            last_day: 10,
            ..proposal()
        };
        let recent = Judgement {
            slot: "GET /other/{id} path[1]",
            last_day: 50,
            ..proposal()
        };
        put_judgement(&pool, &site, generation, &old, 1)
            .await
            .unwrap();
        put_judgement(&pool, &site, generation, &recent, 1)
            .await
            .unwrap();
        // Unused for the retirement period, only the old position is retired.
        assert_eq!(retire_unseen(&pool, &site, 10, 2).await.unwrap(), 1);
        // It is kept until its retention period has passed, and then forgotten.
        assert_eq!(prune_retired(&pool, &site, 9).await.unwrap(), 0);
        assert_eq!(prune_retired(&pool, &site, 10).await.unwrap(), 1);
        let kept: Vec<String> = positions(&pool, &site)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.slot)
            .collect();
        assert_eq!(kept, vec!["GET /other/{id} path[1]".to_owned()]);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_dismissed_proposal_is_not_proposed_again_until_the_evidence_doubles() {
        let pool = connect_test_pool().await;
        let site = unique_site("dismissed");
        let generation = with_site(&pool, &site).await;
        put_judgement(&pool, &site, generation, &proposal(), 1)
            .await
            .unwrap();
        let proposed = row_of(&pool, &site, SLOT, "request").await;
        assert_eq!(proposed.state, "proposed");
        assert!(
            dismiss(&pool, &site, generation, proposed.id, 20, 2)
                .await
                .unwrap()
        );
        let dismissed = row_of(&pool, &site, SLOT, "request").await;
        assert_eq!(dismissed.state, "pending");
        assert_eq!(dismissed.class, None);
        assert!(dismissed.dismissed);
        // The same evidence again changes nothing.
        put_judgement(&pool, &site, generation, &proposal(), 3)
            .await
            .unwrap();
        assert_eq!(row_of(&pool, &site, SLOT, "request").await.state, "pending");
        // Twice the votes the position had when it was dismissed is a significant change.
        let doubled = Judgement {
            votes: 40,
            ..proposal()
        };
        put_judgement(&pool, &site, generation, &doubled, 4)
            .await
            .unwrap();
        let returned = row_of(&pool, &site, SLOT, "request").await;
        assert_eq!(returned.state, "proposed");
        assert!(!returned.dismissed);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_dismissed_proposal_returns_when_its_kind_changes() {
        let pool = connect_test_pool().await;
        let site = unique_site("dismissed_kind");
        let generation = with_site(&pool, &site).await;
        put_judgement(&pool, &site, generation, &proposal(), 1)
            .await
            .unwrap();
        let proposed = row_of(&pool, &site, SLOT, "request").await;
        dismiss(&pool, &site, generation, proposed.id, 20, 2)
            .await
            .unwrap();
        // The same votes for another kind are a significant change.
        let other = Judgement {
            class: "document",
            ..proposal()
        };
        put_judgement(&pool, &site, generation, &other, 3)
            .await
            .unwrap();
        let returned = row_of(&pool, &site, SLOT, "request").await;
        assert_eq!(returned.state, "proposed");
        assert_eq!(returned.class.as_deref(), Some("document"));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_pending_position_can_be_dismissed_and_stays_pending() {
        let pool = connect_test_pool().await;
        let site = unique_site("dismissed_pending");
        let generation = with_site(&pool, &site).await;
        record_evidence(&pool, &site, generation, &[vote("a", 3, &[])], &[])
            .await
            .unwrap();
        let pending = row_of(&pool, &site, SLOT, "request").await;
        assert!(
            dismiss(&pool, &site, generation, pending.id, 20, 2)
                .await
                .unwrap()
        );
        // Fewer votes than twice the minimum: the rules do not propose it yet.
        put_judgement(&pool, &site, generation, &proposal(), 3)
            .await
            .unwrap();
        let row = row_of(&pool, &site, SLOT, "request").await;
        assert_eq!(row.state, "pending");
        assert!(row.dismissed);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_confirmed_position_is_neither_dismissed_nor_marked_ambiguous() {
        let pool = connect_test_pool().await;
        let site = unique_site("confirmed");
        let generation = with_site(&pool, &site).await;
        let confirmed = Judgement {
            state: LearnedState::Confirmed,
            ..proposal()
        };
        put_judgement(&pool, &site, generation, &confirmed, 1)
            .await
            .unwrap();
        let row = row_of(&pool, &site, SLOT, "request").await;
        assert!(
            !dismiss(&pool, &site, generation, row.id, 20, 2)
                .await
                .unwrap()
        );
        assert!(
            !mark_ambiguous(&pool, &site, generation, row.id, 2)
                .await
                .unwrap()
        );
        assert_eq!(
            row_of(&pool, &site, SLOT, "request").await.state,
            "confirmed"
        );
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn an_ambiguous_position_is_never_proposed_again() {
        let pool = connect_test_pool().await;
        let site = unique_site("ambiguous");
        let generation = with_site(&pool, &site).await;
        let response_slot = "GET /api/appointments [].doc_id";
        record_evidence(
            &pool,
            &site,
            generation,
            &[vote("a", 3, &[response_slot])],
            &[],
        )
        .await
        .unwrap();
        // Only a request position can be marked: a response position has no proposal.
        let response = row_of(&pool, &site, response_slot, "response").await;
        assert!(
            !mark_ambiguous(&pool, &site, generation, response.id, 2)
                .await
                .unwrap()
        );
        let request = row_of(&pool, &site, SLOT, "request").await;
        assert!(
            mark_ambiguous(&pool, &site, generation, request.id, 2)
                .await
                .unwrap()
        );
        put_judgement(&pool, &site, generation, &proposal(), 3)
            .await
            .unwrap();
        // The window retiring everything does not retire it either.
        retire_unseen(&pool, &site, 100, 4).await.unwrap();
        let row = row_of(&pool, &site, SLOT, "request").await;
        assert_eq!(row.state, "ambiguous");
        assert_eq!(row.class, None);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_retired_position_is_not_marked_ambiguous() {
        let pool = connect_test_pool().await;
        let site = unique_site("retired_ambiguous");
        let generation = with_site(&pool, &site).await;
        record_evidence(&pool, &site, generation, &[vote("a", 1, &[])], &[])
            .await
            .unwrap();
        assert_eq!(retire_unseen(&pool, &site, 5, 2).await.unwrap(), 1);
        let row = row_of(&pool, &site, SLOT, "request").await;
        assert!(
            !mark_ambiguous(&pool, &site, generation, row.id, 3)
                .await
                .unwrap()
        );
        assert_eq!(row_of(&pool, &site, SLOT, "request").await.state, "retired");
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_refusal_does_not_move_the_day_a_position_was_last_used() {
        let pool = connect_test_pool().await;
        let site = unique_site("refusal_day");
        let generation = with_site(&pool, &site).await;
        record_evidence(&pool, &site, generation, &[vote("a", 1, &[])], &[])
            .await
            .unwrap();
        // Refused on day 20. The last vote is still on day 1, so the pass that
        // retires what was last used on or before day 5 retires the position.
        let refusal = Denial {
            slot: SLOT.to_owned(),
            session: "b".to_owned(),
            day: 20,
        };
        record_evidence(&pool, &site, generation, &[], &[refusal])
            .await
            .unwrap();
        assert_eq!(row_of(&pool, &site, SLOT, "request").await.last_day, 1);
        assert_eq!(retire_unseen(&pool, &site, 5, 2).await.unwrap(), 1);
        assert_eq!(row_of(&pool, &site, SLOT, "request").await.state, "retired");
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_refused_position_without_a_row_is_listed_pending() {
        let pool = connect_test_pool().await;
        let site = unique_site("refused_first");
        let generation = with_site(&pool, &site).await;
        let refusal = Denial {
            slot: SLOT.to_owned(),
            session: "b".to_owned(),
            day: 7,
        };
        record_evidence(&pool, &site, generation, &[], &[refusal])
            .await
            .unwrap();
        let row = row_of(&pool, &site, SLOT, "request").await;
        assert_eq!(row.state, "pending");
        assert_eq!(row.last_day, 7);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_repeat_vote_makes_no_position_from_the_sources_it_lost() {
        let pool = connect_test_pool().await;
        let site = unique_site("repeat_vote");
        let generation = with_site(&pool, &site).await;
        let first = "GET /api/a [].id";
        let repeat = "GET /api/b [].id";
        record_evidence(&pool, &site, generation, &[vote("a", 3, &[first])], &[])
            .await
            .unwrap();
        // The same session's vote on the same day keeps its first evidence, so the sources
        // of the repeat are not sources of any kept vote.
        record_evidence(&pool, &site, generation, &[vote("a", 3, &[repeat])], &[])
            .await
            .unwrap();
        let slots: Vec<String> = positions(&pool, &site)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.slot)
            .collect();
        assert!(slots.iter().any(|slot| slot == first));
        assert!(!slots.iter().any(|slot| slot == repeat));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_source_named_twice_in_one_vote_counts_once() {
        let pool = connect_test_pool().await;
        let site = unique_site("twice");
        let generation = with_site(&pool, &site).await;
        let source = "GET /api/doctors [].id";
        record_evidence(
            &pool,
            &site,
            generation,
            &[vote("a", 3, &[source, source])],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(uses(&pool, &site, SLOT, "request", 0).await.unwrap(), 1);
        let found = flows(&pool, &site, SLOT, "request", 0).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].other, source);
        assert_eq!(found[0].uses, 1);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_retried_vote_names_the_response_positions_its_evidence_holds() {
        let pool = connect_test_pool().await;
        let site = unique_site("retried_vote");
        let generation = with_site(&pool, &site).await;
        let response_slot = "GET /api/appointments [].doc_id";
        // An earlier call wrote this vote's evidence, then failed before it wrote the positions.
        sqlx::query(
            "INSERT INTO object_evidence (site, slot, session, day, kind, from_slots)
             VALUES ($1, $2, 'a', 3, 'vote', $3)",
        )
        .bind(&site)
        .bind(SLOT)
        .bind(vec![response_slot.to_owned()])
        .execute(&pool)
        .await
        .unwrap();
        // The retry carries the same vote, so its evidence is already there and its insert is a no-op.
        record_evidence(
            &pool,
            &site,
            generation,
            &[vote("a", 3, &[response_slot])],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(row_of(&pool, &site, SLOT, "request").await.last_day, 3);
        assert_eq!(
            row_of(&pool, &site, response_slot, "response")
                .await
                .last_day,
            3
        );
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_seen_position_is_listed_pending_on_both_sides() {
        let pool = connect_test_pool().await;
        let site = unique_site("both_sides");
        let generation = with_site(&pool, &site).await;
        let response_slot = "GET /api/appointments [].doc_id";
        record_evidence(
            &pool,
            &site,
            generation,
            &[vote("a", 3, &[response_slot])],
            &[],
        )
        .await
        .unwrap();
        let request = row_of(&pool, &site, SLOT, "request").await;
        assert_eq!(request.state, "pending");
        assert_eq!(request.class, None);
        assert_eq!(request.last_day, 3);
        let response = row_of(&pool, &site, response_slot, "response").await;
        assert_eq!(response.state, "pending");
        assert_eq!(response.last_day, 3);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_retired_position_is_pending_again_when_it_is_seen() {
        let pool = connect_test_pool().await;
        let site = unique_site("returns");
        let generation = with_site(&pool, &site).await;
        put_judgement(&pool, &site, generation, &proposal(), 1)
            .await
            .unwrap();
        // The window has passed the position's last vote, on day 3.
        assert_eq!(retire_unseen(&pool, &site, 5, 2).await.unwrap(), 1);
        assert_eq!(row_of(&pool, &site, SLOT, "request").await.state, "retired");
        record_evidence(&pool, &site, generation, &[vote("b", 9, &[])], &[])
            .await
            .unwrap();
        let row = row_of(&pool, &site, SLOT, "request").await;
        assert_eq!(row.state, "pending");
        assert_eq!(row.class, None);
        assert_eq!(row.last_day, 9);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_flows_of_a_position_name_the_positions_its_votes_reached() {
        let pool = connect_test_pool().await;
        let site = unique_site("flows");
        let generation = with_site(&pool, &site).await;
        let appointments = "GET /api/appointments [].doc_id";
        let records = "GET /api/records [].doc_id";
        let votes = vec![
            vote("a", 3, &[appointments, records]),
            vote("b", 3, &[appointments]),
        ];
        record_evidence(&pool, &site, generation, &votes, &[])
            .await
            .unwrap();
        // A request position's flows are the response positions its votes reached, most used first.
        let reached = flows(&pool, &site, SLOT, "request", 0).await.unwrap();
        assert_eq!(
            reached,
            vec![
                Flow {
                    other: appointments.to_owned(),
                    uses: 2,
                    sessions: 2,
                },
                Flow {
                    other: records.to_owned(),
                    uses: 1,
                    sessions: 1,
                },
            ]
        );
        // A response position's flows are the request positions whose votes reached it.
        let reaching = flows(&pool, &site, appointments, "response", 0)
            .await
            .unwrap();
        assert_eq!(
            reaching,
            vec![Flow {
                other: SLOT.to_owned(),
                uses: 2,
                sessions: 2,
            }]
        );
        // The uses a flow's share is taken over: the votes of each position.
        assert_eq!(uses(&pool, &site, SLOT, "request", 0).await.unwrap(), 2);
        assert_eq!(
            uses(&pool, &site, appointments, "response", 0)
                .await
                .unwrap(),
            2
        );
        assert_eq!(uses(&pool, &site, records, "response", 0).await.unwrap(), 1);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_flows_of_a_position_list_every_end_its_votes_reached() {
        let pool = connect_test_pool().await;
        let site = unique_site("flows_all");
        let generation = with_site(&pool, &site).await;
        // Twenty-one response positions, each reached by one vote from its own session.
        let ends: Vec<String> = (0..21)
            .map(|index| format!("GET /api/source{index} [].id"))
            .collect();
        let votes: Vec<Vote> = ends
            .iter()
            .enumerate()
            .map(|(index, end)| vote(&format!("s{index}"), 3, &[end.as_str()]))
            .collect();
        record_evidence(&pool, &site, generation, &votes, &[])
            .await
            .unwrap();
        // The store lists all of them, so the drawer can take the flows it shows only after
        // it merges them with the decisions. A cap here would show zero uses for a flow past it.
        let reached = flows(&pool, &site, SLOT, "request", 0).await.unwrap();
        assert_eq!(reached.len(), 21);
        assert!(
            reached
                .iter()
                .all(|flow| flow.uses == 1 && flow.sessions == 1)
        );
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
        // The cursor, the evidence of the vote and the position the vote names.
        assert_eq!(learning_rows(&pool, &site).await, 3);
    }
}
