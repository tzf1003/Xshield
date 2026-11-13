//! The learning agent's share of a learning run: which positions the rules leave to it,
//! how many questions a site may ask in a day, and what an answer does to a position.
//!
//! The rules go first. A position they can name is theirs, unless an accepted answer
//! names another kind: then it is ambiguous, for an administrator to settle. The agent is
//! asked only about a position the rules cannot name, once its evidence meets the
//! thresholds and no refusal has come in the window. An answer that is not decisive (an
//! ambiguous one, or one below the confidence bar) withdraws the proposal it replaces.
use std::time::Instant;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use xshield_core::context::SiteSpec;
use xshield_core::context::agent::{self, Choice, NewKind, Question, Refusal, Verdict};
use xshield_core::context::learning::{Evidence, Thresholds, kind_share, propose};
use xshield_core::context::position::PositionState;
use xshield_postgres::object_agent_store::{
    self as records, CallRecord, CallRow, Outcome, RunCounts,
};
use xshield_postgres::object_learning_store::{
    self as store, Judgement, LearnedState, LearningStoreError, Source,
};

use crate::agent_model::{AgentModel, CallError};

/// Questions one learning run may ask, whatever the daily budget allows. A run whose
/// model fails stops asking for the rest of the run.
pub const RUN_QUESTIONS_MAX: u32 = 20;

/// What a learning run has for the agent: the model, the questions left, and the counts
/// the run record keeps.
pub struct Run<'a> {
    model: Option<&'a dyn AgentModel>,
    id: Option<i64>,
    questions_left: u32,
    model_down: bool,
    /// What the run did, for its record.
    pub counts: RunCounts,
}

impl<'a> Run<'a> {
    /// A run that may ask `model` (none when no model is configured), as learning run `run_id`.
    #[must_use]
    pub fn new(model: Option<&'a dyn AgentModel>, run_id: Option<i64>) -> Self {
        Self {
            model,
            id: run_id,
            questions_left: RUN_QUESTIONS_MAX,
            model_down: false,
            counts: RunCounts::default(),
        }
    }
}

/// Why a question got no accepted answer.
enum Missed {
    TimedOut,
    Failed(String),
    Refused(Refusal),
}

/// Where a settlement writes: the site and its generation, the position with its
/// evidence, and the day and time of the pass.
pub struct Place<'a> {
    /// The site's configuration as the pass read it.
    pub spec: &'a SiteSpec,
    /// The generation of that configuration.
    pub generation: DateTime<Utc>,
    /// The request position.
    pub slot: &'a str,
    /// The position's evidence in the window.
    pub evidence: &'a Evidence,
    /// The UTC day of the pass.
    pub today: u64,
    /// The time of the pass, in milliseconds.
    pub now_millis: i64,
}

/// Settles a position the agent may answer. Returns `true` when this settled it: a
/// proposal from an answer, or an ambiguous mark. `false` means the rules judge the
/// position as usual, and any proposal the rules no longer make is withdrawn.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn settle(
    run: &mut Run<'_>,
    pool: &PgPool,
    place: &Place<'_>,
) -> Result<bool, LearningStoreError> {
    let site = place.spec.name();
    let map = place.spec.objects();
    let evidence = place.evidence;
    let slot = place.slot;
    if map.declared_class_of(slot).is_some() {
        return Ok(false);
    }
    let thresholds = crate::object_learning::thresholds_of(map.learning());
    if let Some(proposal) = propose(evidence, map, thresholds) {
        let answer = records::latest_answer(pool, site, slot).await?;
        if let Some(Choice::Existing(class) | Choice::New(NewKind { id: class, .. })) =
            answer.as_ref().and_then(accepted)
            && class != proposal.class
        {
            records::mark_disputed(
                pool,
                site,
                place.generation,
                slot,
                &proposal.class,
                place.now_millis,
            )
            .await?;
            return Ok(true);
        }
        return Ok(false);
    }
    if !enough(evidence, thresholds) || !map.learning().agent.enabled || run.model.is_none() {
        return Ok(false);
    }
    let state = records::position_state(pool, site, slot).await?;
    if let Some(state) = &state {
        let votes = i64::from(evidence.votes());
        let calm = state.dismissed && votes < 2 * i64::from(state.dismissed_votes);
        if state.state == PositionState::Ambiguous || calm {
            return Ok(false);
        }
    }
    let requested = state.as_ref().is_some_and(|state| state.ask_requested);
    let was_proposed = state.is_some_and(|state| state.state == PositionState::Proposed);
    let flows = flow_keys(evidence);
    let votes = evidence.votes();
    let latest = records::latest_call(pool, site, slot).await?;
    let stored = records::latest_answer(pool, site, slot)
        .await?
        .filter(|answer| answer.flows == flows && i64::from(votes) < 2 * i64::from(answer.votes))
        .and_then(|answer| accepted(&answer));
    let due = requested
        || match &latest {
            None => true,
            Some(call) if matches!(call.failure.as_deref(), Some("timeout" | "unavailable")) => {
                true
            }
            Some(call) => flows != call.flows || i64::from(votes) >= 2 * i64::from(call.votes),
        };
    let before = run.counts.asked;
    let asked = if due {
        ask(run, pool, place, &flows).await?
    } else {
        None
    };
    if run.counts.asked > before && requested {
        // The request is answered by the call it made; a request held back by the budget waits.
        records::clear_request(pool, site, slot).await?;
    }
    if let Some(verdict) = asked {
        if !verdict.decisive() {
            // The answer supersedes an earlier proposal: an ambiguous answer withdraws it.
            return Ok(false);
        }
        apply(run, pool, place, &verdict.choice, was_proposed).await?;
        return Ok(true);
    }
    match stored {
        Some(choice) => {
            apply(run, pool, place, &choice, was_proposed).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Asks the model about a position, when the day's budget and the run allow it. The
/// answer is recorded either way, and returned when the agent gave one the question allows.
async fn ask(
    run: &mut Run<'_>,
    pool: &PgPool,
    place: &Place<'_>,
    flows: &[String],
) -> Result<Option<Verdict>, LearningStoreError> {
    let site = place.spec.name();
    let map = place.spec.objects();
    let Some(model) = run.model else {
        return Ok(None);
    };
    let used = records::calls_on_day(pool, site, place.today).await?;
    let daily_limit = i64::from(map.learning().agent.daily_limit);
    if run.model_down || run.questions_left == 0 || used >= daily_limit {
        run.counts.skipped = run.counts.skipped.saturating_add(1);
        return Ok(None);
    }
    let Some(question) = agent::question(place.slot, place.evidence, map) else {
        return Ok(None);
    };
    run.questions_left -= 1;
    run.counts.asked = run.counts.asked.saturating_add(1);
    let message = question_message(&question);
    let started = Instant::now();
    let reply = model.ask(agent::SYSTEM_PROMPT, &message).await;
    let latency_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
    let result = match reply {
        Ok(text) => agent::verdict(&text, &question, map).map_err(Missed::Refused),
        Err(CallError::Timeout) => Err(Missed::TimedOut),
        Err(CallError::Failed(reason)) => Err(Missed::Failed(reason)),
    };
    let outcome = match &result {
        Ok(verdict) => Outcome::Answered(verdict),
        Err(Missed::Refused(refusal)) => Outcome::Refused(*refusal),
        Err(Missed::TimedOut) => Outcome::TimedOut,
        Err(Missed::Failed(reason)) => Outcome::Failed(reason),
    };
    records::record_call(
        pool,
        site,
        place.generation,
        &CallRecord {
            run_id: run.id,
            slot: place.slot,
            day: place.today,
            asked_millis: place.now_millis,
            votes: place.evidence.votes(),
            flows,
            model: model.name(),
            latency_ms,
            outcome,
            question: &message,
        },
    )
    .await?;
    match result {
        Ok(verdict) => {
            run.counts.answered = run.counts.answered.saturating_add(1);
            Ok(Some(verdict))
        }
        Err(missed) => {
            run.counts.failed = run.counts.failed.saturating_add(1);
            if matches!(missed, Missed::TimedOut | Missed::Failed(_)) {
                run.model_down = true;
            }
            Ok(None)
        }
    }
}

/// Writes the agent's kind as a proposal of the position.
async fn apply(
    run: &mut Run<'_>,
    pool: &PgPool,
    place: &Place<'_>,
    choice: &Choice,
    was_proposed: bool,
) -> Result<(), LearningStoreError> {
    let evidence = place.evidence;
    let (class, share_per_mille) = match choice {
        Choice::Existing(class) => (
            class.as_str(),
            kind_share(evidence, place.spec.objects(), class),
        ),
        Choice::New(kind) => (kind.id.as_str(), 0),
        Choice::Ambiguous => return Ok(()),
    };
    if !was_proposed {
        run.counts.proposals = run.counts.proposals.saturating_add(1);
    }
    store::put_judgement(
        pool,
        place.spec.name(),
        place.generation,
        &Judgement {
            slot: place.slot,
            state: LearnedState::Proposed,
            class,
            votes: evidence.votes(),
            sessions: evidence.sessions(),
            share_per_mille,
            last_day: evidence.last_day().unwrap_or(place.today),
            source: Source::Agent,
        },
        place.now_millis,
    )
    .await
}

/// Whether a request position holds a proposal already, so a proposal that is written
/// again is not counted as new in the run record.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub async fn was_proposed(
    pool: &PgPool,
    site: &str,
    slot: &str,
) -> Result<bool, LearningStoreError> {
    Ok(records::position_state(pool, site, slot)
        .await?
        .is_some_and(|state| state.state == PositionState::Proposed))
}

/// The answer a stored call holds, when it is one the pass may act on: an existing or a
/// new kind at the confidence bar.
fn accepted(call: &CallRow) -> Option<Choice> {
    let confidence = u32::try_from(call.confidence?).ok()?;
    if confidence < agent::CONFIDENCE_MIN {
        return None;
    }
    match call.choice.as_deref()? {
        "existing" => Some(Choice::Existing(call.class.clone()?)),
        "new" => Some(Choice::New(NewKind {
            id: call.class.clone()?,
            name: call.new_name.clone()?,
            description: call.new_description.clone().unwrap_or_default(),
        })),
        _ => None,
    }
}

/// The response positions the votes were shown at, sorted by key: the set a question
/// is about, and the set a stored answer must still match.
fn flow_keys(evidence: &Evidence) -> Vec<String> {
    let mut keys: Vec<String> = evidence.flows().into_iter().map(|flow| flow.from).collect();
    keys.sort();
    keys
}

pub(crate) fn enough(evidence: &Evidence, thresholds: Thresholds) -> bool {
    evidence.votes() >= thresholds.votes
        && evidence.sessions() >= thresholds.sessions
        && evidence.denials() == 0
}

fn question_message(question: &Question) -> String {
    serde_json::to_string(question).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use serde_json::json;
    use xshield_core::context::agent::Verdict;
    use xshield_core::context::learning::{Evidence, Vote};
    use xshield_postgres::object_agent_store::{self as records, Trigger};
    use xshield_postgres::site_spec_store;

    use super::*;
    use crate::agent_model::{AgentModel, CallError};
    use crate::object_learning::learn_all;
    use crate::object_learning::pass_tests::{clinic_with, drop_scratch, partitions, scratch};
    use crate::params::{DAY_MILLIS, now_millis};

    const SLOT: &str = "GET /doctor/{id} path[1]";
    const MYSTERY: &str = "GET /api/mystery [].code";
    const ANSWER_DOCTOR: &str =
        r#"{"choice":"existing","class":"doctor","confidence":90,"cites":["f1"],"reason":"ok"}"#;

    /// A model that gives one fixed reply and counts the questions it was asked.
    struct Canned {
        reply: Result<String, CallError>,
        asked: AtomicUsize,
    }

    impl Canned {
        fn new(reply: Result<String, CallError>) -> Self {
            Self {
                reply,
                asked: AtomicUsize::new(0),
            }
        }

        fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl AgentModel for Canned {
        fn name(&self) -> &'static str {
            "test-model"
        }

        async fn ask(&self, _system: &str, _user: &str) -> Result<String, CallError> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            self.reply.clone()
        }
    }

    /// Twenty uses of `GET /doctor/7` from five sessions over four days, whose value was
    /// shown at a response position the map does not confirm: the rules cannot name it.
    async fn mystery_uses(pool: &PgPool, now: i64) {
        for index in 0..20_i64 {
            let at_millis = now - (1 + index / 5) * DAY_MILLIS;
            let trace = json!({
                "v": 1,
                "values_truncated": false,
                "values": [{
                    "at": "path[1]",
                    "value": "7",
                    "kind": "reference",
                    "inert": false,
                    "seen": true,
                    "verified": true,
                    "slot": SLOT,
                    "sources": [{"field": "code", "request": "GET /api/mystery", "slot": MYSTERY}]
                }],
                "timing": {"judge_ms": 1}
            });
            sqlx::query(
                "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                    method, path, status, decision_path, outcome, trace)
                 VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                    'GET', '/doctor/7', 200, 'fast_allow', 'allowed', $4)",
            )
            .bind(at_millis)
            .bind(format!("req_{index:032x}"))
            .bind(format!("s{}", index % 5))
            .bind(trace)
            .execute(pool)
            .await
            .expect("insert a decision row");
        }
    }

    fn agent_site(agent: &serde_json::Value) -> SiteSpec {
        clinic_with(json!({"agent": agent}))
    }

    /// The judged state of the position: a pending position has no judgement yet.
    async fn position_of(pool: &PgPool) -> Option<(String, Option<String>, String)> {
        sqlx::query_as(
            "SELECT state, class, source FROM object_positions
             WHERE site = 'clinic' AND slot = $1 AND state <> 'pending'",
        )
        .bind(SLOT)
        .fetch_optional(pool)
        .await
        .expect("read the position")
    }

    async fn only_run(pool: &PgPool) -> records::RunRow {
        let mut runs = records::recent_runs(pool, "clinic", 10)
            .await
            .expect("read the runs");
        assert_eq!(runs.len(), 1, "one run of the site");
        runs.remove(0)
    }

    #[tokio::test]
    async fn an_answer_proposes_the_kind_the_rules_cannot_name() {
        let Some((admin, pool, name)) = scratch("agent_proposal").await else {
            return;
        };
        let now = now_millis();
        site_spec_store::create(&pool, &agent_site(&json!({"enabled": true})), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        mystery_uses(&pool, now).await;
        let model = Canned::new(Ok(ANSWER_DOCTOR.to_owned()));
        learn_all(&pool, now, Some(&model), Trigger::Scheduled).await;
        assert_eq!(model.asked(), 1);
        let (state, class, source) = position_of(&pool).await.expect("the position is judged");
        assert_eq!(
            (state.as_str(), class.as_deref(), source.as_str()),
            ("proposed", Some("doctor"), "agent")
        );
        let run = only_run(&pool).await;
        assert_eq!(
            (run.counts.asked, run.counts.answered, run.counts.proposals),
            (1, 1, 1)
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_kept_answer_is_not_asked_about_again_while_its_evidence_holds() {
        let Some((admin, pool, name)) = scratch("agent_kept").await else {
            return;
        };
        let now = now_millis();
        site_spec_store::create(&pool, &agent_site(&json!({"enabled": true})), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        mystery_uses(&pool, now).await;
        let model = Canned::new(Ok(ANSWER_DOCTOR.to_owned()));
        learn_all(&pool, now, Some(&model), Trigger::Scheduled).await;
        learn_all(&pool, now + 60 * 60_000, Some(&model), Trigger::Scheduled).await;
        assert_eq!(model.asked(), 1, "the second pass keeps the answer");
        let (state, _, source) = position_of(&pool).await.expect("the position is judged");
        assert_eq!((state.as_str(), source.as_str()), ("proposed", "agent"));
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_site_with_no_daily_budget_asks_nothing() {
        let Some((admin, pool, name)) = scratch("agent_budget").await else {
            return;
        };
        let now = now_millis();
        site_spec_store::create(
            &pool,
            &agent_site(&json!({"enabled": true, "daily_limit": 0})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        mystery_uses(&pool, now).await;
        let model = Canned::new(Ok(ANSWER_DOCTOR.to_owned()));
        learn_all(&pool, now, Some(&model), Trigger::Scheduled).await;
        assert_eq!(model.asked(), 0);
        assert_eq!(position_of(&pool).await, None);
        let run = only_run(&pool).await;
        assert_eq!((run.counts.asked, run.counts.skipped), (0, 1));
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_switched_off_agent_is_never_asked() {
        let Some((admin, pool, name)) = scratch("agent_off").await else {
            return;
        };
        let now = now_millis();
        site_spec_store::create(&pool, &agent_site(&json!({"enabled": false})), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        mystery_uses(&pool, now).await;
        let model = Canned::new(Ok(ANSWER_DOCTOR.to_owned()));
        learn_all(&pool, now, Some(&model), Trigger::Scheduled).await;
        assert_eq!(model.asked(), 0);
        assert_eq!(position_of(&pool).await, None);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_failed_call_is_recorded_and_proposes_nothing() {
        let Some((admin, pool, name)) = scratch("agent_failed").await else {
            return;
        };
        let now = now_millis();
        site_spec_store::create(&pool, &agent_site(&json!({"enabled": true})), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        mystery_uses(&pool, now).await;
        let model = Canned::new(Err(CallError::Failed("HTTP 401".to_owned())));
        learn_all(&pool, now, Some(&model), Trigger::Scheduled).await;
        assert_eq!(model.asked(), 1);
        assert_eq!(position_of(&pool).await, None);
        let call = records::latest_call(&pool, "clinic", SLOT)
            .await
            .expect("read the call")
            .expect("the call is recorded");
        assert_eq!(call.failure.as_deref(), Some("unavailable"));
        assert_eq!(call.reason, "HTTP 401");
        let run = only_run(&pool).await;
        assert_eq!((run.counts.asked, run.counts.failed), (1, 1));
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn an_answer_outside_the_candidates_is_refused_and_proposes_nothing() {
        let Some((admin, pool, name)) = scratch("agent_refused").await else {
            return;
        };
        let now = now_millis();
        site_spec_store::create(&pool, &agent_site(&json!({"enabled": true})), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        mystery_uses(&pool, now).await;
        let reply = r#"{"choice":"existing","class":"ward","confidence":90}"#;
        let model = Canned::new(Ok(reply.to_owned()));
        learn_all(&pool, now, Some(&model), Trigger::Scheduled).await;
        assert_eq!(position_of(&pool).await, None);
        let call = records::latest_call(&pool, "clinic", SLOT)
            .await
            .expect("read the call")
            .expect("the call is recorded");
        assert_eq!(call.failure.as_deref(), Some("class"));
        assert_eq!(call.choice, None);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_low_confidence_answer_leaves_the_position_pending() {
        let Some((admin, pool, name)) = scratch("agent_low").await else {
            return;
        };
        let now = now_millis();
        site_spec_store::create(&pool, &agent_site(&json!({"enabled": true})), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        mystery_uses(&pool, now).await;
        let reply = r#"{"choice":"existing","class":"doctor","confidence":60}"#;
        let model = Canned::new(Ok(reply.to_owned()));
        learn_all(&pool, now, Some(&model), Trigger::Scheduled).await;
        assert_eq!(position_of(&pool).await, None, "no proposal is written");
        let call = records::latest_answer(&pool, "clinic", SLOT)
            .await
            .expect("read the answer")
            .expect("the answer is recorded");
        assert_eq!(call.choice.as_deref(), Some("existing"));
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_rule_that_names_another_kind_makes_the_agent_answer_ambiguous() {
        let Some((admin, pool, name)) = scratch("agent_conflict").await else {
            return;
        };
        let now = now_millis();
        let spec = agent_site(&json!({"enabled": true}));
        let created = site_spec_store::create(&pool, &spec, None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        // An accepted answer names a document for the position.
        let answer = Verdict {
            choice: Choice::Existing("document".to_owned()),
            confidence: 90,
            cites: Vec::new(),
            reason: String::new(),
        };
        let flows = vec!["GET /api/appointments [].doc_id".to_owned()];
        records::record_call(
            &pool,
            "clinic",
            created.created_at,
            &records::CallRecord {
                run_id: None,
                slot: SLOT,
                day: 1,
                asked_millis: now,
                votes: 20,
                flows: &flows,
                model: "test-model",
                latency_ms: 1,
                outcome: Outcome::Answered(&answer),
                question: "{}",
            },
        )
        .await
        .expect("record the answer");
        // The rules name a doctor: every vote was shown at a confirmed doctor position.
        let mut evidence = Evidence::default();
        for index in 0..20_u64 {
            evidence.add_vote(Vote {
                slot: SLOT.to_owned(),
                session: format!("s{}", index % 5),
                day: index / 5,
                from: flows.clone(),
            });
        }
        // The rules' earlier proposal: an agent proposal of a document the rules now contradict.
        sqlx::query(
            "INSERT INTO object_positions (site, slot, state, class, votes, sessions,
                 share_per_mille, last_day, updated_millis, source)
             VALUES ('clinic', $1, 'proposed', 'document', 20, 5, 900, 1, $2, 'agent')",
        )
        .bind(SLOT)
        .bind(now)
        .execute(&pool)
        .await
        .expect("the earlier proposal");
        let mut run = Run::new(None, None);
        let place = Place {
            spec: &spec,
            generation: created.created_at,
            slot: SLOT,
            evidence: &evidence,
            today: 5,
            now_millis: now,
        };
        assert!(settle(&mut run, &pool, &place).await.expect("settle"));
        let (state, class, _) = position_of(&pool).await.expect("the position is written");
        assert_eq!((state.as_str(), class), ("ambiguous", None));
        drop_scratch(admin, pool, name).await;
    }
}
