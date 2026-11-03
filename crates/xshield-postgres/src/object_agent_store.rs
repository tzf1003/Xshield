//! The learning agent's records in the control plane: the questions it was asked and
//! what it answered (`object_agent_calls`), the learning runs of a site
//! (`object_learning_runs`), and the state a rule-or-agent conflict leaves a position in.
//! Writes carry the same generation guard as the rest of the learning state
//! (`object_learning_store`): a pass that outlives its site writes nothing.
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row, postgres::PgRow};
use xshield_core::context::agent::{Choice, Refusal, Verdict};

use crate::object_learning_store::LearningStoreError;

/// Days of calls the learning pass keeps. The budget needs one day, the verdicts a little
/// longer, and the usage and the last call of the model the rest.
pub const CALLS_KEEP_DAYS: u64 = 30;
/// Learning runs kept per site, newest first. The console shows the last 48.
pub const RUNS_KEEP: i64 = 48;

/// What started a learning run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The hourly pass.
    Scheduled,
    /// The administrator's “run now”.
    Manual,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Manual => "manual",
        }
    }
}

/// What a learning run did. The agent's counts are questions asked, answered, failed,
/// and held back by the budget or the pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunCounts {
    /// Positions the rules or the agent proposed.
    pub proposals: u32,
    /// Proposals confirmed automatically by tightening.
    pub tightened: u32,
    /// Confirmed positions paused by the automatic check.
    pub paused: u32,
    /// Questions asked of the agent.
    pub asked: u32,
    /// Questions answered with an accepted answer.
    pub answered: u32,
    /// Questions that failed or were refused.
    pub failed: u32,
    /// Questions held back: the daily budget or the pass's own limit was reached.
    pub skipped: u32,
}

/// One learning run as the console lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRow {
    /// The run's id.
    pub id: i64,
    /// `scheduled` or `manual`.
    pub trigger: String,
    /// When the run started, in milliseconds.
    pub started_millis: i64,
    /// When it finished; `None` while it is going.
    pub finished_millis: Option<i64>,
    /// What it did.
    pub counts: RunCounts,
    /// The server's reason when the run failed as a whole.
    pub error: Option<String>,
}

/// How long a run may go without finishing before the site stops counting it as running.
pub const RUN_STALE_MILLIS: i64 = 30 * 60_000;

/// Starts a learning run of the site's `generation`, and returns its id. `None` when
/// the site has another configuration by now, or a run of it is still going.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn start_run(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    trigger: Trigger,
    now_millis: i64,
) -> Result<Option<i64>, LearningStoreError> {
    let id = sqlx::query_scalar(
        "INSERT INTO object_learning_runs (site, trigger, started_millis)
         SELECT $1::text, $2::text, $3::bigint
         WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $4 FOR SHARE)
           AND NOT EXISTS (SELECT 1 FROM object_learning_runs
               WHERE site = $1 AND finished_millis IS NULL AND started_millis > $3 - $5)
         RETURNING id",
    )
    .bind(site)
    .bind(trigger.as_str())
    .bind(now_millis)
    .bind(generation)
    .bind(RUN_STALE_MILLIS)
    .fetch_optional(pool)
    .await?;
    Ok(id)
}

/// Whether a learning run of the site is going at `now_millis`.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn running(
    pool: &PgPool,
    site: &str,
    now_millis: i64,
) -> Result<bool, LearningStoreError> {
    let running = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM object_learning_runs
             WHERE site = $1 AND finished_millis IS NULL AND started_millis > $2 - $3)",
    )
    .bind(site)
    .bind(now_millis)
    .bind(RUN_STALE_MILLIS)
    .fetch_one(pool)
    .await?;
    Ok(running)
}

/// The outcome of each of the latest `limit` calls, newest first: `None` for an answer,
/// otherwise the failure. The console reads the agent's health from them.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn recent_outcomes(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<Option<String>>, LearningStoreError> {
    let outcomes =
        sqlx::query_scalar("SELECT failure FROM object_agent_calls ORDER BY id DESC LIMIT $1")
            .bind(limit)
            .fetch_all(pool)
            .await?;
    Ok(outcomes)
}

/// The model's calls on one day, for every site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayUsage {
    /// Questions asked.
    pub calls: i64,
    /// Questions without an accepted answer.
    pub failed: i64,
    /// The failure most of the failed questions ended with; the smaller code when two tie.
    pub top_failure: Option<String>,
}

/// The model's use on `day`, for every site.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn day_usage(pool: &PgPool, day: u64) -> Result<DayUsage, LearningStoreError> {
    let row = sqlx::query(
        "SELECT count(*) AS calls,
             count(*) FILTER (WHERE failure IS NOT NULL) AS failed,
             (SELECT failure FROM object_agent_calls WHERE day = $1 AND failure IS NOT NULL
                 GROUP BY failure ORDER BY count(*) DESC, failure LIMIT 1) AS top_failure
         FROM object_agent_calls WHERE day = $1",
    )
    .bind(day_i64(day))
    .fetch_one(pool)
    .await?;
    Ok(DayUsage {
        calls: row.try_get("calls")?,
        failed: row.try_get("failed")?,
        top_failure: row.try_get("top_failure")?,
    })
}

/// One site's use of the model on a day, and when it last asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteDay {
    /// The site's name.
    pub site: String,
    /// Questions asked on the day.
    pub used: i64,
    /// Questions on the day without an accepted answer.
    pub failed: i64,
    /// When the site's latest question was asked, on any day, in milliseconds.
    pub last_call_millis: Option<i64>,
}

/// Every site that has asked the model, with its use on `day`.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn day_usage_by_site(
    pool: &PgPool,
    day: u64,
) -> Result<Vec<SiteDay>, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT site,
             count(*) FILTER (WHERE day = $1) AS used,
             count(*) FILTER (WHERE day = $1 AND failure IS NOT NULL) AS failed,
             max(asked_millis) AS last_call
         FROM object_agent_calls GROUP BY site ORDER BY site",
    )
    .bind(day_i64(day))
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| -> Result<SiteDay, LearningStoreError> {
            Ok(SiteDay {
                site: row.try_get("site")?,
                used: row.try_get("used")?,
                failed: row.try_get("failed")?,
                last_call_millis: row.try_get("last_call")?,
            })
        })
        .collect()
}

/// The questions one site asked on one day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteDayCount {
    /// The site's name.
    pub site: String,
    /// The UTC day, counted from the epoch.
    pub day: u64,
    /// Questions asked on the day.
    pub used: i64,
}

/// The questions every site asked on the days from `first` to `last`, both included. A site
/// and day without questions has no row.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn calls_by_site_and_day(
    pool: &PgPool,
    first: u64,
    last: u64,
) -> Result<Vec<SiteDayCount>, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT site, day, count(*) AS used FROM object_agent_calls
         WHERE day BETWEEN $1 AND $2 GROUP BY site, day",
    )
    .bind(day_i64(first))
    .bind(day_i64(last))
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| -> Result<SiteDayCount, LearningStoreError> {
            let day: i64 = row.try_get("day")?;
            Ok(SiteDayCount {
                site: row.try_get("site")?,
                day: u64::try_from(day).unwrap_or(0),
                used: row.try_get("used")?,
            })
        })
        .collect()
}

/// Asks the agent again about a position, at the next pass that reaches it. Returns
/// `false` when the position is not a request position of the site.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn request_ask(pool: &PgPool, site: &str, id: i64) -> Result<bool, LearningStoreError> {
    let result = sqlx::query(
        "UPDATE object_positions SET ask_requested = true
         WHERE site = $1 AND id = $2 AND side = 'request'",
    )
    .bind(site)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// The positions the administrator asked the agent about again and that are still waiting.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn requested_slots(pool: &PgPool, site: &str) -> Result<Vec<String>, LearningStoreError> {
    let slots = sqlx::query_scalar(
        "SELECT slot FROM object_positions WHERE site = $1 AND ask_requested ORDER BY slot",
    )
    .bind(site)
    .fetch_all(pool)
    .await?;
    Ok(slots)
}

/// Clears the request to ask again about a position, once the pass has asked or met the budget.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn clear_request(
    pool: &PgPool,
    site: &str,
    slot: &str,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "UPDATE object_positions SET ask_requested = false
         WHERE site = $1 AND slot = $2 AND side = 'request' AND ask_requested",
    )
    .bind(site)
    .bind(slot)
    .execute(pool)
    .await?;
    Ok(())
}

/// Finishes a learning run: its counts, when it failed as a whole, and the time.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn finish_run(
    pool: &PgPool,
    run_id: i64,
    counts: &RunCounts,
    error: Option<&str>,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    sqlx::query(
        "UPDATE object_learning_runs SET
             finished_millis = $2, proposals = $3, tightened = $4, paused = $5,
             agent_asked = $6, agent_answered = $7, agent_failed = $8, agent_skipped = $9,
             error = $10
         WHERE id = $1",
    )
    .bind(run_id)
    .bind(now_millis)
    .bind(count(counts.proposals))
    .bind(count(counts.tightened))
    .bind(count(counts.paused))
    .bind(count(counts.asked))
    .bind(count(counts.answered))
    .bind(count(counts.failed))
    .bind(count(counts.skipped))
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// The latest learning runs of a site, newest first, at most `limit`.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn recent_runs(
    pool: &PgPool,
    site: &str,
    limit: i64,
) -> Result<Vec<RunRow>, LearningStoreError> {
    let rows =
        sqlx::query("SELECT * FROM object_learning_runs WHERE site = $1 ORDER BY id DESC LIMIT $2")
            .bind(site)
            .bind(limit)
            .fetch_all(pool)
            .await?;
    rows.iter().map(run_row).collect()
}

/// The learning run of a site with the given id, if there is one.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn run(pool: &PgPool, site: &str, id: i64) -> Result<Option<RunRow>, LearningStoreError> {
    let row = sqlx::query("SELECT * FROM object_learning_runs WHERE site = $1 AND id = $2")
        .bind(site)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.as_ref().map(run_row).transpose()
}

/// When the site's last manual run started, if it ever had one.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn last_manual_start(
    pool: &PgPool,
    site: &str,
) -> Result<Option<i64>, LearningStoreError> {
    let started = sqlx::query_scalar(
        "SELECT max(started_millis) FROM object_learning_runs WHERE site = $1 AND trigger = 'manual'",
    )
    .bind(site)
    .fetch_one(pool)
    .await?;
    Ok(started)
}

/// Keeps the newest [`RUNS_KEEP`] learning runs of a site and deletes the rest.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn prune_runs(pool: &PgPool, site: &str) -> Result<u64, LearningStoreError> {
    let result = sqlx::query(
        "DELETE FROM object_learning_runs WHERE site = $1 AND id NOT IN (
             SELECT id FROM object_learning_runs WHERE site = $1 ORDER BY id DESC LIMIT $2)",
    )
    .bind(site)
    .bind(RUNS_KEEP)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

fn run_row(row: &PgRow) -> Result<RunRow, LearningStoreError> {
    Ok(RunRow {
        id: row.try_get("id")?,
        trigger: row.try_get("trigger")?,
        started_millis: row.try_get("started_millis")?,
        finished_millis: row.try_get("finished_millis")?,
        counts: RunCounts {
            proposals: small(row.try_get("proposals")?),
            tightened: small(row.try_get("tightened")?),
            paused: small(row.try_get("paused")?),
            asked: small(row.try_get("agent_asked")?),
            answered: small(row.try_get("agent_answered")?),
            failed: small(row.try_get("agent_failed")?),
            skipped: small(row.try_get("agent_skipped")?),
        },
        error: row.try_get("error")?,
    })
}

/// One question the agent was asked about a position, as the pass records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRecord<'a> {
    /// The learning run that asked, when one did.
    pub run_id: Option<i64>,
    /// The request position asked about.
    pub slot: &'a str,
    /// The UTC day of the call.
    pub day: u64,
    /// When the call was made, in milliseconds.
    pub asked_millis: i64,
    /// The votes in the window when the question was made.
    pub votes: u32,
    /// The response positions the question showed, sorted.
    pub flows: &'a [String],
    /// The model's name, without its address or key.
    pub model: &'a str,
    /// How long the model took, in milliseconds.
    pub latency_ms: u32,
    /// What came back.
    pub outcome: Outcome<'a>,
    /// The question as sent: its JSON, which carries no values from the requests.
    pub question: &'a str,
}

/// What came back from one question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<'a> {
    /// An answer the question allowed.
    Answered(&'a Verdict),
    /// An answer the question refused, and why.
    Refused(Refusal),
    /// No answer in the time allowed.
    TimedOut,
    /// No answer: the call failed, and the text is the reason (`HTTP 401`, for example).
    Failed(&'a str),
}

/// The columns one call writes.
struct Columns<'a> {
    choice: Option<&'static str>,
    class: Option<&'a str>,
    new_name: Option<&'a str>,
    new_description: Option<&'a str>,
    confidence: Option<i32>,
    reason: &'a str,
    cites: Vec<String>,
    failure: Option<&'static str>,
}

fn columns<'a>(outcome: &'a Outcome<'_>) -> Columns<'a> {
    match outcome {
        Outcome::Answered(verdict) => {
            let (choice, class, new_name, new_description) = match &verdict.choice {
                Choice::Existing(class) => ("existing", Some(class.as_str()), None, None),
                Choice::New(kind) => (
                    "new",
                    Some(kind.id.as_str()),
                    Some(kind.name.as_str()),
                    Some(kind.description.as_str()),
                ),
                Choice::Ambiguous => ("ambiguous", None, None, None),
            };
            Columns {
                choice: Some(choice),
                class,
                new_name,
                new_description,
                confidence: Some(count(verdict.confidence)),
                reason: &verdict.reason,
                cites: verdict.cites.clone(),
                failure: None,
            }
        }
        Outcome::Refused(refusal) => Columns {
            choice: None,
            class: None,
            new_name: None,
            new_description: None,
            confidence: None,
            reason: "",
            cites: Vec::new(),
            failure: Some(match refusal {
                Refusal::NotJson => "not_json",
                Refusal::Choice => "choice",
                Refusal::Confidence => "confidence",
                Refusal::Class => "class",
                Refusal::NewKind => "new_kind",
            }),
        },
        Outcome::TimedOut => Columns {
            choice: None,
            class: None,
            new_name: None,
            new_description: None,
            confidence: None,
            reason: "",
            cites: Vec::new(),
            failure: Some("timeout"),
        },
        Outcome::Failed(reason) => Columns {
            choice: None,
            class: None,
            new_name: None,
            new_description: None,
            confidence: None,
            reason,
            cites: Vec::new(),
            failure: Some("unavailable"),
        },
    }
}

/// Records one question and its outcome, when the site is still of `generation`.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn record_call(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    call: &CallRecord<'_>,
) -> Result<(), LearningStoreError> {
    let columns = columns(&call.outcome);
    sqlx::query(
        "INSERT INTO object_agent_calls
             (site, slot, run_id, day, asked_millis, votes, flows, model, latency_ms,
              choice, class, new_name, new_description, confidence, reason, cites, failure,
              question)
         SELECT $1::text, $2::text, $3::bigint, $4::bigint, $5::bigint, $6::integer, $7::text[],
             $8::text, $9::integer, $10::text, $11::text, $12::text, $13::text, $14::integer,
             $15::text, $16::text[], $17::text, $18::text
         WHERE EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $19 FOR SHARE)",
    )
    .bind(site)
    .bind(call.slot)
    .bind(call.run_id)
    .bind(day_i64(call.day))
    .bind(call.asked_millis)
    .bind(count(call.votes))
    .bind(call.flows.to_vec())
    .bind(call.model)
    .bind(count(call.latency_ms))
    .bind(columns.choice)
    .bind(columns.class)
    .bind(columns.new_name)
    .bind(columns.new_description)
    .bind(columns.confidence)
    .bind(columns.reason)
    .bind(columns.cites)
    .bind(columns.failure)
    .bind(call.question)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(())
}

/// The questions the site asked on `day`, answered or not: its budget for the day.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn calls_on_day(pool: &PgPool, site: &str, day: u64) -> Result<i64, LearningStoreError> {
    let calls =
        sqlx::query_scalar("SELECT count(*) FROM object_agent_calls WHERE site = $1 AND day = $2")
            .bind(site)
            .bind(day_i64(day))
            .fetch_one(pool)
            .await?;
    Ok(calls)
}

/// A recorded call, as the console and the learning pass read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRow {
    /// The call's id; a later call has a larger one.
    pub id: i64,
    /// The position the question was about: its key.
    pub slot: String,
    /// The learning run that asked.
    pub run_id: Option<i64>,
    /// When the call was made, in milliseconds.
    pub asked_millis: i64,
    /// The votes in the window when asked.
    pub votes: i32,
    /// The response positions the question showed, sorted.
    pub flows: Vec<String>,
    /// The model's name.
    pub model: String,
    /// How long the model took, in milliseconds.
    pub latency_ms: i32,
    /// The choice, when an answer was accepted.
    pub choice: Option<String>,
    /// The kind: a candidate id, or the id of a new kind.
    pub class: Option<String>,
    /// The name of a new kind.
    pub new_name: Option<String>,
    /// The description of a new kind.
    pub new_description: Option<String>,
    /// The confidence, in percent.
    pub confidence: Option<i32>,
    /// The reason, as plain text.
    pub reason: String,
    /// The flow ids the answer relied on.
    pub cites: Vec<String>,
    /// Why no answer was accepted, or why the call failed.
    pub failure: Option<String>,
    /// The question as sent, as JSON text. Empty for a call made before it was kept.
    pub question: String,
    /// The rules' kind, when they proposed another kind than the accepted answer.
    pub rule_choice: Option<String>,
}

/// The latest call about a position, answered or not.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn latest_call(
    pool: &PgPool,
    site: &str,
    slot: &str,
) -> Result<Option<CallRow>, LearningStoreError> {
    let row = sqlx::query(
        "SELECT * FROM object_agent_calls WHERE site = $1 AND slot = $2 ORDER BY id DESC LIMIT 1",
    )
    .bind(site)
    .bind(slot)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(call_row).transpose()
}

/// The calls a learning run made, in the order it made them.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn calls_of_run(
    pool: &PgPool,
    site: &str,
    run_id: i64,
) -> Result<Vec<CallRow>, LearningStoreError> {
    let rows =
        sqlx::query("SELECT * FROM object_agent_calls WHERE site = $1 AND run_id = $2 ORDER BY id")
            .bind(site)
            .bind(run_id)
            .fetch_all(pool)
            .await?;
    rows.iter().map(call_row).collect()
}

/// The latest accepted answer about a position.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn latest_answer(
    pool: &PgPool,
    site: &str,
    slot: &str,
) -> Result<Option<CallRow>, LearningStoreError> {
    let row = sqlx::query(
        "SELECT * FROM object_agent_calls
         WHERE site = $1 AND slot = $2 AND choice IS NOT NULL ORDER BY id DESC LIMIT 1",
    )
    .bind(site)
    .bind(slot)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(call_row).transpose()
}

fn call_row(row: &PgRow) -> Result<CallRow, LearningStoreError> {
    Ok(CallRow {
        id: row.try_get("id")?,
        slot: row.try_get("slot")?,
        run_id: row.try_get("run_id")?,
        asked_millis: row.try_get("asked_millis")?,
        votes: row.try_get("votes")?,
        flows: row.try_get("flows")?,
        model: row.try_get("model")?,
        latency_ms: row.try_get("latency_ms")?,
        choice: row.try_get("choice")?,
        class: row.try_get("class")?,
        new_name: row.try_get("new_name")?,
        new_description: row.try_get("new_description")?,
        confidence: row.try_get("confidence")?,
        reason: row.try_get("reason")?,
        cites: row.try_get("cites")?,
        failure: row.try_get("failure")?,
        question: row.try_get("question")?,
        rule_choice: row.try_get("rule_choice")?,
    })
}

/// The model's use since `since_millis`, for every site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    /// Questions asked.
    pub calls: i64,
    /// Questions without an accepted answer.
    pub failed: i64,
    /// The 95th percentile of the time the model took, when there was a call.
    pub p95_ms: Option<i64>,
}

/// The model's use since `since_millis`.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn usage_since(pool: &PgPool, since_millis: i64) -> Result<Usage, LearningStoreError> {
    let row = sqlx::query(
        "SELECT count(*) AS calls,
             count(*) FILTER (WHERE failure IS NOT NULL) AS failed,
             percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms)::bigint AS p95_ms
         FROM object_agent_calls WHERE asked_millis >= $1",
    )
    .bind(since_millis)
    .fetch_one(pool)
    .await?;
    Ok(Usage {
        calls: row.try_get("calls")?,
        failed: row.try_get("failed")?,
        p95_ms: row.try_get("p95_ms")?,
    })
}

/// The model's last call, for every site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastCall {
    /// When it was made, in milliseconds.
    pub at_millis: i64,
    /// Whether it gave an accepted answer.
    pub ok: bool,
    /// Why it did not, when it did not.
    pub failure: Option<String>,
}

/// The model's last call, if it has made one.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn last_call(pool: &PgPool) -> Result<Option<LastCall>, LearningStoreError> {
    let row = sqlx::query(
        "SELECT asked_millis, failure FROM object_agent_calls ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    row.map(|row| -> Result<LastCall, LearningStoreError> {
        let failure: Option<String> = row.try_get("failure")?;
        Ok(LastCall {
            at_millis: row.try_get("asked_millis")?,
            ok: failure.is_none(),
            failure,
        })
    })
    .transpose()
}

/// Deletes the site's calls on or before `before_day`. Returns the rows deleted.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn prune_calls(
    pool: &PgPool,
    site: &str,
    before_day: u64,
) -> Result<u64, LearningStoreError> {
    let result = sqlx::query("DELETE FROM object_agent_calls WHERE site = $1 AND day < $2")
        .bind(site)
        .bind(day_i64(before_day))
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// The state a position is in, as the learning pass reads it before it asks the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionState {
    /// The state: `pending`, `proposed`, `confirmed`, and so on.
    pub state: String,
    /// Whether the administrator asked the agent about the position again.
    pub ask_requested: bool,
    /// `rule` or `agent`: who gave the kind of a proposal.
    pub source: String,
    /// Whether an administrator dismissed the proposal.
    pub dismissed: bool,
    /// The votes the dismissal rested on.
    pub dismissed_votes: i32,
}

/// The state of a request position of the site.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn position_state(
    pool: &PgPool,
    site: &str,
    slot: &str,
) -> Result<Option<PositionState>, LearningStoreError> {
    let row = sqlx::query(
        "SELECT state, source, dismissed, dismissed_votes, ask_requested FROM object_positions
         WHERE site = $1 AND slot = $2 AND side = 'request'",
    )
    .bind(site)
    .bind(slot)
    .fetch_optional(pool)
    .await?;
    row.map(|row| -> Result<PositionState, LearningStoreError> {
        Ok(PositionState {
            state: row.try_get("state")?,
            ask_requested: row.try_get("ask_requested")?,
            source: row.try_get("source")?,
            dismissed: row.try_get("dismissed")?,
            dismissed_votes: row.try_get("dismissed_votes")?,
        })
    })
    .transpose()
}

/// Marks a position ambiguous when the rules and the agent disagree about its kind, and
/// keeps the rules' kind with the accepted answer it disagrees with. The position then
/// waits for an administrator, and the judge treats it as unknown, as it does any ambiguous
/// position. Written only while the site is of `generation`.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn mark_disputed(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    slot: &str,
    rule_class: &str,
    now_millis: i64,
) -> Result<(), LearningStoreError> {
    let marked = sqlx::query(
        "UPDATE object_positions SET
             state = 'ambiguous', class = NULL, source = 'rule',
             dismissed = false, dismissed_class = NULL, dismissed_votes = 0,
             updated_millis = $3
         WHERE site = $1 AND slot = $2 AND side = 'request' AND state IN ('pending', 'proposed')
           AND EXISTS (SELECT 1 FROM site_configs WHERE name = $1 AND created_at = $4 FOR SHARE)",
    )
    .bind(site)
    .bind(slot)
    .bind(now_millis)
    .bind(generation)
    .execute(pool)
    .await?
    .rows_affected();
    if marked > 0 {
        sqlx::query(
            "UPDATE object_agent_calls SET rule_choice = $3
             WHERE id = (SELECT max(id) FROM object_agent_calls
                 WHERE site = $1 AND slot = $2 AND choice IS NOT NULL)",
        )
        .bind(site)
        .bind(slot)
        .bind(rule_class)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// The latest call about each position of the site, answered or not.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn latest_calls(pool: &PgPool, site: &str) -> Result<Vec<CallRow>, LearningStoreError> {
    let rows = sqlx::query(
        "SELECT DISTINCT ON (slot) * FROM object_agent_calls WHERE site = $1 ORDER BY slot, id DESC",
    )
    .bind(site)
    .fetch_all(pool)
    .await?;
    rows.iter().map(call_row).collect()
}

/// The calls made about a position since its latest accepted answer, that answer included,
/// or all of them when no answer was accepted: the attempts behind the position's answer.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn attempts_since_answer(
    pool: &PgPool,
    site: &str,
    slot: &str,
) -> Result<i64, LearningStoreError> {
    let attempts = sqlx::query_scalar(
        "SELECT count(*) FROM object_agent_calls
         WHERE site = $1 AND slot = $2 AND id >= COALESCE(
             (SELECT max(id) FROM object_agent_calls
                 WHERE site = $1 AND slot = $2 AND choice IS NOT NULL), 0)",
    )
    .bind(site)
    .bind(slot)
    .fetch_one(pool)
    .await?;
    Ok(attempts)
}

/// When the site's latest scheduled learning run started, in milliseconds, if it has one.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn last_scheduled_start(
    pool: &PgPool,
    site: &str,
) -> Result<Option<i64>, LearningStoreError> {
    let started = sqlx::query_scalar(
        "SELECT max(started_millis) FROM object_learning_runs WHERE site = $1 AND trigger = 'scheduled'",
    )
    .bind(site)
    .fetch_one(pool)
    .await?;
    Ok(started)
}

/// Saturates a count into the column's `integer`.
fn count<T: TryInto<i32>>(value: T) -> i32 {
    value.try_into().unwrap_or(i32::MAX)
}

fn small(value: i32) -> u32 {
    u32::try_from(value).unwrap_or(0)
}

fn day_i64(day: u64) -> i64 {
    i64::try_from(day).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One day in milliseconds, as the calls' `asked_millis` count them.
    const DAY_MILLIS: i64 = 86_400_000;

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }

    /// Removes the calls of the given sites, so a test starts from nothing it did not write.
    async fn clear(pool: &PgPool, sites: &[&str]) {
        let names: Vec<String> = sites.iter().map(|site| (*site).to_owned()).collect();
        sqlx::query("DELETE FROM object_agent_calls WHERE site = ANY($1)")
            .bind(names)
            .execute(pool)
            .await
            .expect("clear the calls");
    }

    /// A call of `site` asked on `day` at `asked_millis`: answered, or failed with `failure`.
    async fn insert_call(
        pool: &PgPool,
        site: &str,
        day: u64,
        asked_millis: i64,
        failure: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO object_agent_calls (site, slot, day, asked_millis, votes, choice, class, failure)
             VALUES ($1, 'slot', $2, $3, 0,
                 CASE WHEN $4::text IS NULL THEN 'existing' END,
                 CASE WHEN $4::text IS NULL THEN 'doctor' END,
                 $4::text)",
        )
        .bind(site)
        .bind(day_i64(day))
        .bind(asked_millis)
        .bind(failure)
        .execute(pool)
        .await
        .expect("insert a call");
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_day_counts_its_answers_and_the_failure_most_of_them_ended_with() {
        let pool = connect_test_pool().await;
        let sites = ["day-usage-a", "day-usage-b"];
        clear(&pool, &sites).await;
        let day: u64 = 60_101;
        let start = day_i64(day) * DAY_MILLIS;
        insert_call(&pool, sites[0], day, start + 1, None).await;
        insert_call(&pool, sites[0], day, start + 2, Some("timeout")).await;
        insert_call(&pool, sites[1], day, start + 3, Some("timeout")).await;
        insert_call(&pool, sites[1], day, start + 4, Some("not_json")).await;
        insert_call(&pool, sites[0], day - 1, start - 1, Some("unavailable")).await;

        let usage = day_usage(&pool, day).await.expect("the day's usage");
        assert_eq!(
            usage,
            DayUsage {
                calls: 4,
                failed: 3,
                top_failure: Some("timeout".to_owned()),
            }
        );
        let idle = day_usage(&pool, day + 1).await.expect("an idle day");
        assert_eq!(
            idle,
            DayUsage {
                calls: 0,
                failed: 0,
                top_failure: None,
            }
        );
        clear(&pool, &sites).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn each_site_counts_its_day_and_keeps_its_latest_question() {
        let pool = connect_test_pool().await;
        let sites = ["site-use-busy", "site-use-quiet"];
        clear(&pool, &sites).await;
        let day: u64 = 60_111;
        let start = day_i64(day) * DAY_MILLIS;
        insert_call(&pool, sites[0], day, start + 10, None).await;
        insert_call(&pool, sites[0], day, start + 20, Some("timeout")).await;
        insert_call(&pool, sites[1], day - 1, start - 5, None).await;

        let rows = day_usage_by_site(&pool, day).await.expect("the sites' use");
        let find = |name: &str| rows.iter().find(|found| found.site == name).cloned();
        assert_eq!(
            find(sites[0]),
            Some(SiteDay {
                site: sites[0].to_owned(),
                used: 2,
                failed: 1,
                last_call_millis: Some(start + 20),
            })
        );
        assert_eq!(
            find(sites[1]),
            Some(SiteDay {
                site: sites[1].to_owned(),
                used: 0,
                failed: 0,
                last_call_millis: Some(start - 5),
            })
        );
        clear(&pool, &sites).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_history_counts_each_site_on_each_day_of_the_range() {
        let pool = connect_test_pool().await;
        let sites = ["history-a", "history-b"];
        clear(&pool, &sites).await;
        let first: u64 = 60_121;
        let start = day_i64(first) * DAY_MILLIS;
        insert_call(&pool, sites[0], first, start + 1, None).await;
        insert_call(&pool, sites[0], first, start + 2, Some("timeout")).await;
        insert_call(&pool, sites[0], first + 1, start + DAY_MILLIS, None).await;
        insert_call(&pool, sites[0], first + 5, start + 5 * DAY_MILLIS, None).await;
        insert_call(&pool, sites[1], first, start + 3, None).await;

        let mut rows: Vec<(String, u64, i64)> = calls_by_site_and_day(&pool, first, first + 2)
            .await
            .expect("the history")
            .into_iter()
            .filter(|row| sites.contains(&row.site.as_str()))
            .map(|row| (row.site, row.day, row.used))
            .collect();
        rows.sort();
        assert_eq!(
            rows,
            vec![
                (sites[0].to_owned(), first, 2),
                (sites[0].to_owned(), first + 1, 1),
                (sites[1].to_owned(), first, 1),
            ]
        );
        clear(&pool, &sites).await;
    }
}
