//! The learning agent's console API (object-map design section 5.2): the learning status
//! a site's object map reports, its runs, a run started now, asking the agent about a
//! position again, an example of what the agent is given, and the agent's share of a
//! position's drawer.
//!
//! The learning pass makes the agent's calls. These handlers only read what the pass
//! recorded, start a run, or mark a position to be asked at the next pass. None of them
//! returns the model's key, and the model is named by its name alone.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use xshield_core::context::{
    agent::{self, Question},
    learning::{Thresholds, day_of},
};
use xshield_postgres::{
    object_agent_store::{self as records, CallRow, RUNS_KEEP, RunRow},
    object_learning_store::{self as store, PositionRow},
    site_spec_store::SiteRecord,
};

use crate::{
    ControlState, agent_model,
    error::{ApiError, ApiResult},
    object_learning::{run_manual, thresholds_of},
    object_map::{learned_id, learned_request, oldest_day, site_of},
    params::{now_millis, rfc3339},
};

/// The least time between two runs one administrator starts by hand, in milliseconds.
const RUN_COOLDOWN_MILLIS: i64 = 5 * 60_000;
/// The time between two scheduled passes, in milliseconds.
const PASS_MILLIS: i64 = 60 * 60_000;

/// Where the agent stands on a learned position, as the console names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentPhase {
    /// Waiting for the agent: it is asked at the next pass.
    Queued,
    /// Waiting for the agent, and the site's budget for the day is used up.
    SkippedBudget,
    /// The latest call gave an answer.
    Answered,
    /// The latest call gave no usable answer.
    Failed,
}

/// What the agent's share of a site's map reads from the store: the switch and the model,
/// the day's budget, the latest call about each position, and the positions asked again.
/// It is read once per request.
pub(crate) struct AgentView {
    /// Whether a model is configured.
    model: bool,
    /// Whether the site's switch lets the agent answer.
    enabled: bool,
    /// The calls the site may make in a day, and the calls it made today.
    limit: i64,
    used: i64,
    thresholds: Thresholds,
    latest: BTreeMap<String, CallRow>,
    requested: BTreeSet<String>,
}

impl AgentView {
    /// Reads the agent's share of the site at `now`.
    ///
    /// # Errors
    /// Returns [`ApiError`] when a query fails.
    pub(crate) async fn load(
        state: &ControlState,
        record: &SiteRecord,
        now: i64,
    ) -> ApiResult<Self> {
        let pool = &state.pool;
        let name = record.spec.name();
        let learning = record.spec.objects().learning();
        let today = day_of(u64::try_from(now).unwrap_or(0));
        Ok(Self {
            model: agent_model::configured(pool, state.key_sealer.as_ref())
                .await
                .is_some(),
            enabled: learning.agent.enabled,
            limit: i64::from(learning.agent.daily_limit),
            used: records::calls_on_day(pool, name, today).await?,
            thresholds: thresholds_of(learning),
            latest: records::latest_calls(pool, name)
                .await?
                .into_iter()
                .map(|call| (call.slot.clone(), call))
                .collect(),
            requested: records::requested_slots(pool, name)
                .await?
                .into_iter()
                .collect(),
        })
    }

    /// A view of a site whose agent has nothing to read: no model, no calls, no budget.
    #[cfg(test)]
    pub(crate) fn idle() -> Self {
        Self {
            model: false,
            enabled: false,
            limit: 0,
            used: 0,
            thresholds: Thresholds {
                votes: 0,
                sessions: 0,
                share_per_mille: 0,
            },
            latest: BTreeMap::new(),
            requested: BTreeSet::new(),
        }
    }

    /// Whether a model is configured for the agent.
    pub(crate) fn model_configured(&self) -> bool {
        self.model
    }

    /// The latest call about a position, answered or not.
    pub(crate) fn latest(&self, slot: &str) -> Option<&CallRow> {
        self.latest.get(slot)
    }

    /// Whether the agent may answer about a pending learned position at all.
    fn may_ask(&self, row: &PositionRow) -> bool {
        self.enabled && self.model && row.state == "pending" && !row.dismissed
    }

    /// Whether the evidence of a learned position meets the thresholds the agent is asked at.
    fn enough(&self, row: &PositionRow) -> bool {
        i64::from(row.votes) >= i64::from(self.thresholds.votes)
            && i64::from(row.sessions) >= i64::from(self.thresholds.sessions)
    }

    /// Whether the agent's status of a learned position is queued: it is asked again, or
    /// it has never been asked and its evidence is enough.
    fn queued(&self, row: &PositionRow) -> bool {
        self.may_ask(row)
            && (self.requested.contains(&row.slot)
                || (!self.latest.contains_key(&row.slot) && self.enough(row)))
    }

    /// The agent's status of a learned position, or `None` when the agent has nothing to do
    /// with it: a response position, or a request position it was never asked about.
    pub(crate) fn phase_of(&self, row: &PositionRow) -> Option<AgentPhase> {
        if row.side != "request" {
            return None;
        }
        if self.queued(row) {
            return Some(if self.used < self.limit {
                AgentPhase::Queued
            } else {
                AgentPhase::SkippedBudget
            });
        }
        let call = self.latest.get(&row.slot)?;
        Some(if call.failure.is_none() {
            AgentPhase::Answered
        } else {
            AgentPhase::Failed
        })
    }
}

/// The site's daily budget of questions, and the questions asked today.
#[derive(Debug, Serialize)]
pub(crate) struct DailyUse {
    used: i64,
    limit: i64,
}

/// The agent's share of a site's learning status: `learning_run` in `GET …/objects`.
#[derive(Debug, Serialize)]
pub(crate) struct LearningRunBody {
    last: Option<RunBody>,
    next_at: Option<String>,
    running: bool,
    agent_today: DailyUse,
    /// Positions waiting for the agent.
    agent_waiting: usize,
    /// Positions whose latest call gave no usable answer.
    agent_failed: usize,
}

/// One learning run: its time, how it was started, what it did, and any error.
#[derive(Debug, Serialize)]
pub(crate) struct RunBody {
    id: i64,
    at: String,
    trigger: &'static str,
    duration_ms: Option<i64>,
    proposals: u32,
    tightened: u32,
    paused: u32,
    agent: AgentCounts,
    error: Option<String>,
}

/// What a run did with the agent.
#[derive(Debug, Serialize)]
pub(crate) struct AgentCounts {
    asked: u32,
    answered: u32,
    failed: u32,
    skipped: u32,
}

/// `GET …/objects/runs`: the newest runs, newest first.
#[derive(Debug, Serialize)]
pub struct RunsBody {
    runs: Vec<RunBody>,
}

/// `GET …/objects/runs/{id}`: one run, and each call the agent made in it.
#[derive(Debug, Serialize)]
pub struct RunDetailBody {
    #[serde(flatten)]
    run: RunBody,
    calls: Vec<CallBody>,
}

/// One call the agent was asked in a run.
#[derive(Debug, Serialize)]
pub(crate) struct CallBody {
    id: i64,
    /// The position's key.
    key: String,
    /// The position's id in the console, when the site keeps a learned row for it.
    position: Option<String>,
    #[serde(flatten)]
    answer: AgentBody,
    votes: i32,
    latency_ms: i32,
}

/// The new kind an answer proposes.
#[derive(Debug, Serialize)]
pub(crate) struct NewClass {
    id: String,
    name: String,
    description: String,
}

/// The agent's share of a learned position's drawer: `agent` in `GET …/objects/slots/{id}`.
#[derive(Debug, Serialize)]
pub(crate) struct AgentBody {
    status: AgentPhase,
    asked_at: Option<String>,
    model: Option<String>,
    attempts: i64,
    /// The kind the agent chose, `new` for a new kind, or `ambiguous`.
    choice: Option<String>,
    new_class: Option<NewClass>,
    /// The agent's confidence, from 0 to 1.
    confidence: Option<f64>,
    cites: Vec<String>,
    reason: Option<String>,
    /// The kind the rules gave, when they disagreed with the answer.
    rule_choice: Option<String>,
    /// Why no answer was usable, when none was.
    failure: Option<String>,
    /// The question as the agent was given it: positions, flows and candidates, no values.
    input: Option<Value>,
}

impl AgentBody {
    /// The body of a position with `status`, from its latest call and the attempts behind
    /// its answer.
    fn of(status: AgentPhase, call: Option<&CallRow>, attempts: i64) -> Self {
        let Some(call) = call else {
            return Self {
                status,
                asked_at: None,
                model: None,
                attempts,
                choice: None,
                new_class: None,
                confidence: None,
                cites: Vec::new(),
                reason: None,
                rule_choice: None,
                failure: None,
                input: None,
            };
        };
        Self {
            status,
            asked_at: rfc3339(call.asked_millis),
            model: Some(call.model.clone()),
            attempts,
            choice: choice_of(call),
            new_class: new_class_of(call),
            confidence: confidence_of(call),
            cites: call.cites.clone(),
            reason: (!call.reason.is_empty()).then(|| call.reason.clone()),
            rule_choice: call.rule_choice.clone(),
            failure: call.failure.clone(),
            input: serde_json::from_str(&call.question).ok(),
        }
    }
}

/// The kind a call's answer names: the class for an existing kind, otherwise `new` or
/// `ambiguous`.
fn choice_of(call: &CallRow) -> Option<String> {
    match call.choice.as_deref()? {
        "existing" => call.class.clone(),
        other => Some(other.to_owned()),
    }
}

fn new_class_of(call: &CallRow) -> Option<NewClass> {
    if call.choice.as_deref() != Some("new") {
        return None;
    }
    Some(NewClass {
        id: call.class.clone()?,
        name: call.new_name.clone().unwrap_or_default(),
        description: call.new_description.clone().unwrap_or_default(),
    })
}

fn confidence_of(call: &CallRow) -> Option<f64> {
    call.confidence.map(|percent| f64::from(percent) / 100.0)
}

fn run_body(run: &RunRow) -> RunBody {
    RunBody {
        id: run.id,
        at: rfc3339(run.started_millis).unwrap_or_default(),
        trigger: if run.trigger == "manual" {
            "manual"
        } else {
            "schedule"
        },
        duration_ms: run
            .finished_millis
            .map(|finished| (finished - run.started_millis).max(0)),
        proposals: run.counts.proposals,
        tightened: run.counts.tightened,
        paused: run.counts.paused,
        agent: AgentCounts {
            asked: run.counts.asked,
            answered: run.counts.answered,
            failed: run.counts.failed,
            skipped: run.counts.skipped,
        },
        error: run.error.clone(),
    }
}

/// The agent's share of the learning status of a site.
///
/// # Errors
/// Returns [`ApiError`] when a query fails.
pub(crate) async fn learning_run(
    pool: &PgPool,
    site: &str,
    now: i64,
    view: &AgentView,
    waiting: usize,
    failed: usize,
) -> ApiResult<LearningRunBody> {
    let last = records::recent_runs(pool, site, 1)
        .await?
        .first()
        .map(run_body);
    let next_at = records::last_scheduled_start(pool, site)
        .await?
        .and_then(|started| rfc3339(started + PASS_MILLIS));
    Ok(LearningRunBody {
        last,
        next_at,
        running: records::running(pool, site, now).await?,
        agent_today: DailyUse {
            used: view.used,
            limit: view.limit,
        },
        agent_waiting: waiting,
        agent_failed: failed,
    })
}

/// Whether the model's last call gave an answer: `ok`, `failing`, or `unknown` before any call.
///
/// # Errors
/// Returns [`ApiError`] when the query fails.
pub(crate) async fn health(pool: &PgPool) -> ApiResult<&'static str> {
    Ok(match records::last_call(pool).await? {
        None => "unknown",
        Some(call) if call.ok => "ok",
        Some(_) => "failing",
    })
}

/// The agent's share of a learned position's drawer, or `None` when the agent has nothing
/// to do with the position.
///
/// # Errors
/// Returns [`ApiError`] when a query fails.
pub(crate) async fn agent_body(
    pool: &PgPool,
    site: &str,
    view: &AgentView,
    row: &PositionRow,
) -> ApiResult<Option<AgentBody>> {
    let Some(status) = view.phase_of(row) else {
        return Ok(None);
    };
    let call = view.latest(&row.slot);
    let attempts = match call {
        Some(_) => records::attempts_since_answer(pool, site, &row.slot).await?,
        None => 0,
    };
    Ok(Some(AgentBody::of(status, call, attempts)))
}

/// `GET /api/sites/{name}/objects/runs?limit=`: the newest learning runs, at most 48.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, `INVALID_FILTER` naming `limit` for a value that
/// is not a number from 1 to 48, and a 500 when a query fails.
pub async fn runs(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<RunsBody>> {
    site_of(&state, &name).await?;
    let limit = match query.get("limit") {
        None => RUNS_KEEP,
        Some(value) => value
            .parse::<i64>()
            .ok()
            .filter(|limit| (1..=RUNS_KEEP).contains(limit))
            .ok_or_else(|| ApiError::invalid_filter("limit"))?,
    };
    let runs = records::recent_runs(&state.pool, &name, limit).await?;
    Ok(Json(RunsBody {
        runs: runs.iter().map(run_body).collect(),
    }))
}

/// `GET /api/sites/{name}/objects/runs/{id}`: one learning run and its calls, oldest first.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, `RUN_NOT_FOUND` (404) for an id that names no run
/// of the site, and a 500 when a query fails.
pub async fn run_detail(
    State(state): State<Arc<ControlState>>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<RunDetailBody>> {
    site_of(&state, &name).await?;
    let run = id
        .parse::<i64>()
        .ok()
        .map(|id| records::run(&state.pool, &name, id));
    let run = match run {
        Some(run) => run.await?,
        None => None,
    }
    .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "RUN_NOT_FOUND"))?;
    let ids: BTreeMap<String, String> = store::positions(&state.pool, &name)
        .await?
        .iter()
        .filter(|row| row.side == "request")
        .map(|row| (row.slot.clone(), learned_id(row.id)))
        .collect();
    let calls = records::calls_of_run(&state.pool, &name, run.id).await?;
    Ok(Json(RunDetailBody {
        run: run_body(&run),
        calls: calls
            .iter()
            .map(|call| CallBody {
                id: call.id,
                key: call.slot.clone(),
                position: ids.get(&call.slot).cloned(),
                answer: AgentBody::of(
                    if call.failure.is_none() {
                        AgentPhase::Answered
                    } else {
                        AgentPhase::Failed
                    },
                    Some(call),
                    0,
                ),
                votes: call.votes,
                latency_ms: call.latency_ms,
            })
            .collect(),
    }))
}

/// `POST /api/sites/{name}/objects/run`: starts a learning run of the site now, as the
/// administrator asks. It returns at once; the run goes on in the background.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, `RUN_IN_PROGRESS` (409) while a run is going, and
/// `RUN_TOO_SOON` (429) within five minutes of the last run started by hand.
pub async fn run_now(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    let record = site_of(&state, &name).await?;
    let now = now_millis();
    if records::running(&state.pool, &name, now).await? {
        return Err(ApiError::new(StatusCode::CONFLICT, "RUN_IN_PROGRESS"));
    }
    if let Some(started) = records::last_manual_start(&state.pool, &name).await?
        && now - started < RUN_COOLDOWN_MILLIS
    {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "RUN_TOO_SOON"));
    }
    let background = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(error) =
            run_manual(&background.pool, background.key_sealer.as_ref(), &record).await
        {
            eprintln!(
                "xshield-control: manual object learning failed for site {}: {error}",
                record.spec.name()
            );
        }
    });
    Ok(StatusCode::ACCEPTED)
}

/// `POST /api/sites/{name}/objects/slots/{id}/ask`: asks the agent about a learned request
/// position again, at the next pass that reaches it.
///
/// # Errors
/// As the other position actions, with `AGENT_OFF`, `AGENT_NOT_CONFIGURED` and
/// `AGENT_BUDGET_USED` (409) when the agent cannot be asked, and `SLOT_STATE_CONFLICT` (409)
/// for a position whose state does not take a question.
pub async fn ask(
    State(state): State<Arc<ControlState>>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let record = site_of(&state, &name).await?;
    let row = learned_request(&state, &name, &record.spec, &id).await?;
    let learning = record.spec.objects().learning();
    if !learning.agent.enabled {
        return Err(ApiError::new(StatusCode::CONFLICT, "AGENT_OFF"));
    }
    if agent_model::configured(&state.pool, state.key_sealer.as_ref())
        .await
        .is_none()
    {
        return Err(ApiError::new(StatusCode::CONFLICT, "AGENT_NOT_CONFIGURED"));
    }
    let open = row.state == "pending" || (row.state == "proposed" && row.source == "agent");
    if !open {
        return Err(ApiError::new(StatusCode::CONFLICT, "SLOT_STATE_CONFLICT"));
    }
    let today = day_of(u64::try_from(now_millis()).unwrap_or(0));
    let used = records::calls_on_day(&state.pool, &name, today).await?;
    if used >= i64::from(learning.agent.daily_limit) {
        return Err(ApiError::new(StatusCode::CONFLICT, "AGENT_BUDGET_USED"));
    }
    if records::request_ask(&state.pool, &name, row.id).await? {
        Ok(StatusCode::ACCEPTED)
    } else {
        Err(ApiError::new(StatusCode::CONFLICT, "SLOT_STATE_CONFLICT"))
    }
}

/// `GET /api/sites/{name}/objects/agent-sample`: the question the agent would be given for
/// one position it is waiting to answer, with no values from the requests.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, `NO_SAMPLE` (404) when no position is waiting, and
/// a 500 when a query fails.
pub async fn sample(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<Question>> {
    let record = site_of(&state, &name).await?;
    let map = record.spec.objects();
    let thresholds = thresholds_of(map.learning());
    let learned = store::positions(&state.pool, &name).await?;
    let waiting = learned.iter().find(|row| {
        row.side == "request"
            && row.state == "pending"
            && !row.dismissed
            && map.declared_class_of(&row.slot).is_none()
            && i64::from(row.votes) >= i64::from(thresholds.votes)
            && i64::from(row.sessions) >= i64::from(thresholds.sessions)
    });
    let no_sample = || ApiError::new(StatusCode::NOT_FOUND, "NO_SAMPLE");
    let slot = waiting.ok_or_else(no_sample)?.slot.clone();
    let now = now_millis();
    let evidence = store::load_evidence(
        &state.pool,
        &name,
        std::slice::from_ref(&slot),
        oldest_day(now),
    )
    .await?;
    let evidence = evidence.get(&slot).ok_or_else(no_sample)?;
    let question = agent::question(&slot, evidence, map).ok_or_else(no_sample)?;
    Ok(Json(question))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(slot: &str, side: &str, state: &str, votes: i32) -> PositionRow {
        PositionRow {
            id: 1,
            slot: slot.to_owned(),
            side: side.to_owned(),
            state: state.to_owned(),
            class: None,
            dismissed: false,
            source: "rule".to_owned(),
            votes,
            sessions: 5,
            share_per_mille: 0,
            last_day: 1,
        }
    }

    fn call(slot: &str, failure: Option<&str>) -> CallRow {
        CallRow {
            id: 7,
            slot: slot.to_owned(),
            run_id: None,
            asked_millis: 1_000,
            votes: 20,
            flows: Vec::new(),
            model: "test-model".to_owned(),
            latency_ms: 12,
            choice: failure.is_none().then(|| "existing".to_owned()),
            class: failure.is_none().then(|| "doctor".to_owned()),
            new_name: None,
            new_description: None,
            confidence: failure.is_none().then_some(90),
            reason: String::new(),
            cites: Vec::new(),
            failure: failure.map(str::to_owned),
            question: String::new(),
            rule_choice: None,
        }
    }

    /// A view of a site whose agent is on and has a model, with the given day's use.
    fn view(used: i64) -> AgentView {
        let mut view = AgentView::idle();
        view.model = true;
        view.enabled = true;
        view.limit = 10;
        view.used = used;
        view.thresholds = Thresholds {
            votes: 20,
            sessions: 5,
            share_per_mille: 0,
        };
        view
    }

    #[test]
    fn a_response_position_has_no_agent_status() {
        let view = view(0);
        assert_eq!(
            view.phase_of(&row("GET /x [].a", "response", "pending", 99)),
            None
        );
    }

    #[test]
    fn an_unasked_position_with_enough_evidence_is_queued_until_the_budget_is_used() {
        let position = row("GET /x [].a", "request", "pending", 20);
        assert_eq!(view(0).phase_of(&position), Some(AgentPhase::Queued));
        assert_eq!(
            view(10).phase_of(&position),
            Some(AgentPhase::SkippedBudget)
        );
    }

    #[test]
    fn a_position_below_the_thresholds_or_without_a_model_is_not_queued() {
        let thin = row("GET /x [].a", "request", "pending", 3);
        assert_eq!(view(0).phase_of(&thin), None);
        let mut no_model = view(0);
        no_model.model = false;
        let enough = row("GET /x [].a", "request", "pending", 20);
        assert_eq!(no_model.phase_of(&enough), None);
    }

    #[test]
    fn a_position_asked_again_is_queued_even_after_an_answer() {
        let mut view = view(0);
        view.latest
            .insert("GET /x [].a".to_owned(), call("GET /x [].a", None));
        view.requested.insert("GET /x [].a".to_owned());
        let position = row("GET /x [].a", "request", "pending", 20);
        assert_eq!(view.phase_of(&position), Some(AgentPhase::Queued));
    }

    #[test]
    fn the_latest_call_gives_answered_or_failed() {
        let mut view = view(0);
        view.latest
            .insert("GET /x [].a".to_owned(), call("GET /x [].a", None));
        view.latest.insert(
            "GET /x [].b".to_owned(),
            call("GET /x [].b", Some("timeout")),
        );
        let answered = row("GET /x [].a", "request", "proposed", 20);
        let failed = row("GET /x [].b", "request", "pending", 20);
        assert_eq!(view.phase_of(&answered), Some(AgentPhase::Answered));
        // A failed call is retried by the pass, so the position is still shown as failed.
        assert_eq!(view.phase_of(&failed), Some(AgentPhase::Failed));
    }

    #[test]
    fn a_dismissed_position_is_not_queued() {
        let mut position = row("GET /x [].a", "request", "pending", 20);
        position.dismissed = true;
        assert_eq!(view(0).phase_of(&position), None);
    }

    #[test]
    fn the_choice_names_the_class_or_the_kind_of_answer() {
        let existing = call("GET /x [].a", None);
        assert_eq!(choice_of(&existing).as_deref(), Some("doctor"));
        let mut ambiguous = call("GET /x [].a", None);
        ambiguous.choice = Some("ambiguous".to_owned());
        ambiguous.class = None;
        assert_eq!(choice_of(&ambiguous).as_deref(), Some("ambiguous"));
        assert!(choice_of(&call("GET /x [].a", Some("timeout"))).is_none());
    }

    #[test]
    fn a_new_kind_carries_its_name_and_description() {
        let mut new = call("GET /x [].a", None);
        new.choice = Some("new".to_owned());
        new.class = Some("ledger".to_owned());
        new.new_name = Some("账本".to_owned());
        new.new_description = Some("记账的对象".to_owned());
        let kind = new_class_of(&new).expect("a new kind");
        assert_eq!(choice_of(&new).as_deref(), Some("new"));
        assert_eq!(kind.id, "ledger");
        assert_eq!(kind.name, "账本");
        assert_eq!(kind.description, "记账的对象");
        assert!(new_class_of(&existing_call()).is_none());
    }

    fn existing_call() -> CallRow {
        call("GET /x [].a", None)
    }

    #[test]
    fn the_confidence_is_a_fraction_of_the_percent() {
        assert_eq!(confidence_of(&call("GET /x [].a", None)), Some(0.9));
        assert_eq!(confidence_of(&call("GET /x [].a", Some("timeout"))), None);
    }
}
