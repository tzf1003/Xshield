//! The object-map learning pass of the control plane (docs/object-map-design.md
//! section 3). Each maintenance pass reads every site's decision log since the
//! site's cursor, counts the votes and refusals of the request positions, and
//! writes the state of each position the rules judged: a proposal for a position
//! the map does not know, or a confirmed position whose evidence now points at
//! other kinds (suspended). Where the rules cannot name a kind, the learning agent
//! answers (`object_agent`). An administrator confirms a proposal. The pass changes a
//! site configuration in two ways only, each as one new configuration version: with
//! `auto_pause` on, a suspended position that the map declares is paused; with
//! `auto_tighten` on, a class whose window votes show groups of positions that never
//! share a value is split, so each group has a class of its own. The judge reads both
//! from that configuration. A site turns the pass off, or sets how much evidence a
//! proposal needs and how many questions the agent may ask, with its `objects.learning`
//! settings.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use xshield_core::context::learning::{
    DecisionFacts, Evidence, FUNCTION_KEYS_MAX, FunctionEvidence, KEEP_RETIRED_DAYS, RETIRE_DAYS,
    Thresholds, WINDOW_DAYS, contradicting_kind, contradicts, day_of, judge_accepts_public,
    judge_function, judge_tier, kind_share, merge_functions, observe, observe_functions,
    observe_tiers, propose, propose_source, response_stats,
};
use xshield_core::context::objects::KEY_MAX;
use xshield_core::context::position::PositionState;
use xshield_core::context::{LearningSettings, ObjectMap, SiteSpec, Tier};
use xshield_core::kind::Rules;
use xshield_postgres::key_seal::KeySealer;
use xshield_postgres::object_agent_store::{self as runs, CALLS_KEEP_DAYS, Trigger};
use xshield_postgres::object_function_store as function_store;
use xshield_postgres::object_judgement_store::{self as judgements, Proposal};
use xshield_postgres::object_learning_store::{
    self as store, Cursor, Judgement, LearnedState, Source,
};
use xshield_postgres::object_tier_judgement_store::{self as tier_judgements, TierProposal};
use xshield_postgres::object_tier_store::{self as tier_store, TierRead};
use xshield_postgres::site_spec_store::{self, Change, NOTE_MAX_CHARS, SiteRecord, WriteOutcome};

use crate::agent_model::AgentModel;
use crate::object_agent::{self, Place, Run};
use crate::object_map::{is_request_key, name_word};
use crate::params::DAY_MILLIS;
use crate::tightening::{adds_fast_allow, apply, plan_splits};

/// Decision rows this old are read. Newer rows may still be on their way from a gateway.
const LAG_MILLIS: i64 = 10 * 60 * 1_000;
/// Decision rows read per batch. A batch is held in memory, so this bounds the memory.
const BATCH_ROWS: i64 = 5_000;
/// Batches read per site in one pass. A site still behind resumes at its cursor next time.
const BATCHES_PER_PASS: usize = 20;
/// Distinct votes of the window a tightening reads at most. A window with more is left for a later
/// pass, since a split decided on part of the votes could add a fast allow the rest would show.
const TIGHTEN_VOTES_MAX: usize = 20_000;

/// Runs one learning pass over every site at `now_millis`, the hourly one. The agent
/// asks the configured model, when there is one. A site that fails is logged, and the
/// other sites still run.
pub async fn learn_once(pool: &PgPool, sealer: Option<&KeySealer>, now_millis: i64) {
    let model = crate::agent_model::configured(pool, sealer).await;
    learn_all(
        pool,
        now_millis,
        model.as_ref().map(|model| model as &dyn AgentModel),
        Trigger::Scheduled,
    )
    .await;
}

pub(crate) async fn learn_all(
    pool: &PgPool,
    now_millis: i64,
    model: Option<&dyn AgentModel>,
    trigger: Trigger,
) {
    let records = match site_spec_store::list(pool).await {
        Ok(records) => records,
        Err(error) => {
            eprintln!("xshield-control: object learning skipped, {error}");
            return;
        }
    };
    for record in &records {
        if let Err(error) = run_site(
            pool,
            &record.spec,
            record.created_at,
            now_millis,
            model,
            trigger,
        )
        .await
        {
            eprintln!(
                "xshield-control: object learning failed for site {}: {error}",
                record.spec.name()
            );
        }
    }
}

/// Runs one site's learning now, on the administrator's request, as the hourly pass does.
///
/// # Errors
/// Returns [`LearningStoreError`] on a database failure.
pub(crate) async fn run_manual(
    pool: &PgPool,
    sealer: Option<&KeySealer>,
    record: &SiteRecord,
) -> Result<(), store::LearningStoreError> {
    let model = crate::agent_model::configured(pool, sealer).await;
    run_site(
        pool,
        &record.spec,
        record.created_at,
        crate::params::now_millis(),
        model.as_ref().map(|model| model as &dyn AgentModel),
        Trigger::Manual,
    )
    .await
}

/// Runs one site's learning once and keeps its run record: when it started, what it did,
/// and why it failed, if it did. A run of a site replaced by another configuration in the
/// meantime records nothing.
async fn run_site(
    pool: &PgPool,
    spec: &SiteSpec,
    generation: DateTime<Utc>,
    now_millis: i64,
    model: Option<&dyn AgentModel>,
    trigger: Trigger,
) -> Result<(), store::LearningStoreError> {
    let site = spec.name();
    let Some(run_id) = runs::start_run(pool, site, generation, trigger, now_millis).await? else {
        return Ok(());
    };
    let mut run = Run::new(model, Some(run_id));
    let result = learn_site(pool, spec, generation, now_millis, &mut run).await;
    let error = result.as_ref().err().map(ToString::to_string);
    runs::finish_run(
        pool,
        run_id,
        &run.counts,
        error.as_deref(),
        crate::params::now_millis(),
    )
    .await?;
    runs::prune_runs(pool, site).await?;
    result
}

/// Reads one site's decision log from its cursor up to the lag horizon, batch by
/// batch, then prunes the evidence older than the window, judges the proposals again,
/// and retires the positions no vote has reached for the retirement period, then forgets
/// the retired ones unused for the retention period.
///
/// `generation` is the creation time of the configuration the pass read. The store
/// drops each write once the site has another configuration, so a pass that outlives a
/// deletion of the site writes nothing into the site created in its place.
///
/// A batch is recorded before its cursor moves, and recording is idempotent: when a
/// step fails, the next pass reads the same rows again and changes nothing twice.
async fn learn_site(
    pool: &PgPool,
    spec: &SiteSpec,
    generation: DateTime<Utc>,
    now_millis: i64,
    run: &mut Run<'_>,
) -> Result<(), store::LearningStoreError> {
    let site = spec.name();
    if !spec.objects().learning().auto_learn {
        // A site with learning off keeps no evidence and gets no proposals. Its cursor
        // stays where it was, and the window below starts the next pass in range.
        return Ok(());
    }
    let identified = identified_by(spec.objects());
    let horizon = now_millis - LAG_MILLIS;
    // The cursor once a pass has read every row up to the horizon.
    let end = Cursor {
        at_millis: horizon,
        id: i64::MAX,
    };
    let today = day_of(u64::try_from(now_millis).unwrap_or(0));
    let oldest_day = today.saturating_sub(WINDOW_DAYS - 1);
    let window = i64::try_from(WINDOW_DAYS)
        .unwrap_or(0)
        .saturating_mul(DAY_MILLIS);
    let window_start = Cursor {
        at_millis: horizon.saturating_sub(window),
        id: 0,
    };
    let mut after = store::cursor(pool, site)
        .await?
        .map_or(window_start, |cursor| cursor.max(window_start));
    for _ in 0..BATCHES_PER_PASS {
        if after >= end {
            break;
        }
        let batch = store::read_batch(pool, site, after, horizon, BATCH_ROWS).await?;
        let complete = batch.rows < usize::try_from(BATCH_ROWS).unwrap_or(usize::MAX);
        let next = next_cursor(after, end, complete, batch.newest);
        let slots = record_batch(pool, site, generation, &batch.facts, identified).await?;
        if !slots.is_empty() {
            let evidence = store::load_evidence(pool, site, &slots, oldest_day).await?;
            for slot in &slots {
                if let Some(evidence) = evidence.get(slot) {
                    let place = Place {
                        spec,
                        generation,
                        slot,
                        evidence,
                        today,
                        now_millis,
                    };
                    settle_and_judge(run, pool, &place).await?;
                }
            }
        }
        store::advance_cursor(pool, site, generation, next, now_millis).await?;
        after = next;
        if complete {
            break;
        }
    }
    store::prune_evidence(pool, site, oldest_day).await?;
    tier_store::prune_tier_evidence(pool, site, oldest_day).await?;
    runs::prune_calls(pool, site, today.saturating_sub(CALLS_KEEP_DAYS)).await?;
    rejudge_proposals(run, pool, spec, generation, oldest_day, today, now_millis).await?;
    let requested = runs::requested_slots(pool, site).await?;
    if !requested.is_empty() {
        let evidence = store::load_evidence(pool, site, &requested, oldest_day).await?;
        let empty = Evidence::default();
        for slot in &requested {
            let evidence = evidence.get(slot).unwrap_or(&empty);
            let place = Place {
                spec,
                generation,
                slot,
                evidence,
                today,
                now_millis,
            };
            settle_and_judge(run, pool, &place).await?;
        }
    }
    judge_sources(run, pool, site, generation, oldest_day, now_millis).await?;
    pause_drifted(run, pool, site, generation, oldest_day).await?;
    tighten_split(run, pool, site, generation, oldest_day).await?;
    judge_accepts(pool, site, generation, oldest_day, now_millis).await?;
    judge_tiers(pool, site, generation, oldest_day, now_millis).await?;
    judge_functions(
        pool,
        site,
        generation,
        oldest_day,
        FUNCTION_KEYS_MAX,
        now_millis,
    )
    .await?;
    store::retire_unseen(pool, site, today.saturating_sub(RETIRE_DAYS), now_millis).await?;
    store::prune_retired(pool, site, today.saturating_sub(KEEP_RETIRED_DAYS)).await?;
    Ok(())
}

/// Records the evidence of one batch of decision rows: the votes and refusals of the request positions, the
/// tier facts of the response positions (docs/07 section 7.9.16) and the function facts (section 7.9.19).
/// Returns the request positions the votes and refusals name, in key order.
async fn record_batch(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    facts: &[DecisionFacts],
    identified: bool,
) -> Result<Vec<String>, store::LearningStoreError> {
    let mut votes = Vec::new();
    let mut denials = Vec::new();
    let mut tiers = Vec::new();
    let mut functions = Vec::new();
    for record in facts {
        let observed = observe(record);
        votes.extend(observed.votes);
        denials.extend(observed.denials);
        tiers.extend(observe_tiers(record, identified));
        functions.extend(observe_functions(record, identified));
    }
    store::record_evidence(pool, site, generation, &votes, &denials).await?;
    tier_store::record_tier_facts(pool, site, generation, &tiers).await?;
    function_store::record_function_facts(pool, site, generation, &functions).await?;
    Ok(votes
        .iter()
        .map(|vote| vote.slot.clone())
        .chain(denials.iter().map(|denial| denial.slot.clone()))
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect())
}

/// Settles one position: the learning agent first, when the rules cannot decide it, and
/// the rules otherwise. See `object_agent::settle`.
async fn settle_and_judge(
    run: &mut Run<'_>,
    pool: &PgPool,
    place: &Place<'_>,
) -> Result<(), store::LearningStoreError> {
    if object_agent::settle(run, pool, place).await? {
        return Ok(());
    }
    judge(run, pool, place).await
}

/// Writes the state the rules give one position. When the rules give it no proposal,
/// an earlier proposal of the position is withdrawn.
async fn judge(
    run: &mut Run<'_>,
    pool: &PgPool,
    place: &Place<'_>,
) -> Result<(), store::LearningStoreError> {
    let Some(decision) = decide(
        place.slot,
        place.evidence,
        place.spec.objects(),
        place.today,
    ) else {
        return store::withdraw_proposal(
            pool,
            place.spec.name(),
            place.generation,
            place.slot,
            place.now_millis,
        )
        .await;
    };
    if decision.state == LearnedState::Proposed
        && !object_agent::was_proposed(pool, place.spec.name(), place.slot).await?
    {
        run.counts.proposals = run.counts.proposals.saturating_add(1);
    }
    let judgement = Judgement {
        slot: place.slot,
        state: decision.state,
        class: &decision.class,
        votes: decision.votes,
        sessions: decision.sessions,
        share_per_mille: decision.share_per_mille,
        last_day: decision.last_day,
        source: Source::Rule,
    };
    store::put_judgement(
        pool,
        place.spec.name(),
        place.generation,
        &judgement,
        place.now_millis,
    )
    .await
}

/// Judges every proposal of the site again. The window has moved on and refusals may
/// have arrived since a proposal was made, so a proposal the rules no longer make is
/// withdrawn, and one that still stands keeps its place with its current counts.
async fn rejudge_proposals(
    run: &mut Run<'_>,
    pool: &PgPool,
    spec: &SiteSpec,
    generation: DateTime<Utc>,
    oldest_day: u64,
    today: u64,
    now_millis: i64,
) -> Result<(), store::LearningStoreError> {
    let site = spec.name();
    let slots = store::proposed_slots(pool, site).await?;
    if slots.is_empty() {
        return Ok(());
    }
    let evidence = store::load_evidence(pool, site, &slots, oldest_day).await?;
    let empty = Evidence::default();
    for slot in &slots {
        let evidence = evidence.get(slot).unwrap_or(&empty);
        let place = Place {
            spec,
            generation,
            slot,
            evidence,
            today,
            now_millis,
        };
        settle_and_judge(run, pool, &place).await?;
    }
    Ok(())
}

/// Proposes the kind of each response position that the window's values flow to (LQ-4a, docs/07 7.9.21): an
/// undeclared position a value was shown at, when the request positions that used the value hold one confirmed
/// kind (`propose_source`). A proposal waits for an administrator, as the other proposals do, and a proposal the
/// rules no longer make is withdrawn. A key the window also sees as a request is judged by the request rules, so
/// it is left alone here. The writes name the site's generation, as the other judgements do, so a site deleted
/// meanwhile gets none. Nothing here changes the configuration.
async fn judge_sources(
    run: &mut Run<'_>,
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    oldest_day: u64,
    now_millis: i64,
) -> Result<(), store::LearningStoreError> {
    let record = match site_spec_store::get(pool, site).await {
        Ok(Some(record)) if record.created_at == generation => record,
        Ok(_) => return Ok(()),
        Err(error) => {
            eprintln!("xshield-control: source proposal skipped for site {site}, {error}");
            return Ok(());
        }
    };
    let map = record.spec.objects();
    let thresholds = thresholds_of(map.learning());
    let positions: Vec<(String, PositionState)> = store::positions(pool, site)
        .await?
        .into_iter()
        .filter(|row| row.side == "response")
        .filter(|row| matches!(row.state, PositionState::Pending | PositionState::Proposed))
        .map(|row| (row.slot, row.state))
        .collect();
    if positions.is_empty() {
        return Ok(());
    }
    let slots: Vec<String> = positions.iter().map(|(slot, _)| slot.clone()).collect();
    let requested = store::load_evidence(pool, site, &slots, oldest_day).await?;
    let votes = store::load_source_evidence(pool, site, &slots, oldest_day).await?;
    for (slot, state) in &positions {
        // A key the window also sees as a request belongs to the request rules, which own its state.
        if requested.contains_key(slot) {
            continue;
        }
        let window = votes.get(slot).map_or(&[][..], Vec::as_slice);
        // A declared position is decided by its entry, so a proposal left from before the entry is withdrawn.
        let proposal = if map.declared_class_of(slot).is_some() {
            None
        } else {
            propose_source(slot, window, map, thresholds)
        };
        let Some(proposal) = proposal else {
            if *state == PositionState::Proposed {
                store::withdraw_proposal(pool, site, generation, slot, now_millis).await?;
            }
            continue;
        };
        if !object_agent::was_proposed(pool, site, slot).await? {
            run.counts.proposals = run.counts.proposals.saturating_add(1);
        }
        let judgement = Judgement {
            slot,
            state: LearnedState::Proposed,
            class: &proposal.class,
            votes: proposal.votes,
            sessions: proposal.sessions,
            share_per_mille: proposal.share_per_mille,
            last_day: window.iter().map(|vote| vote.day).max().unwrap_or(0),
            source: Source::Rule,
        };
        store::put_judgement(pool, site, generation, &judgement, now_millis).await?;
    }
    Ok(())
}

/// Pauses the suspended positions the site's map declares, when the site has `auto_pause` on.
/// The pauses are one new configuration version, written over the configuration the site holds
/// now and recorded as an automatic change, so the judge stops using the positions with the next
/// configuration load. A position the map does not declare has no entry to pause: it stays
/// suspended for an administrator to decide. A site that has moved on since the pass began gets
/// no write; so does a write that finds a newer version. The positions stay suspended until they
/// are paused, so the next pass tries again.
async fn pause_drifted(
    run: &mut Run<'_>,
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    oldest_day: u64,
) -> Result<(), store::LearningStoreError> {
    let record = match site_spec_store::get(pool, site).await {
        Ok(Some(record)) if record.created_at == generation => record,
        Ok(_) => return Ok(()),
        Err(error) => {
            eprintln!("xshield-control: automatic pause skipped for site {site}, {error}");
            return Ok(());
        }
    };
    let map = record.spec.objects();
    if !map.learning().auto_pause {
        return Ok(());
    }
    let keys: Vec<String> = store::positions(pool, site)
        .await?
        .into_iter()
        .filter(|row| row.state == PositionState::Suspended)
        .map(|row| row.slot)
        .filter(|slot| map.declared_class_of(slot).is_some() && !map.is_paused(slot))
        .collect();
    if keys.is_empty() {
        return Ok(());
    }
    let evidence = store::load_evidence(pool, site, &keys, oldest_day).await?;
    let note = pause_note(map, &keys, &evidence, thresholds_of(map.learning()));
    let paused = record
        .spec
        .clone()
        .with_objects(map.clone().with_paused(&keys));
    // A write refused by a newer version, or to a site that is gone, writes nothing; the
    // positions stay suspended, so the next pass tries again.
    let outcome = site_spec_store::write(
        pool,
        site,
        &paused,
        record.version,
        Change::AutoPause,
        Some(&note),
    )
    .await;
    match outcome {
        Ok(WriteOutcome::Applied(_)) => {
            run.counts.paused = run.counts.paused.saturating_add(count_of(keys.len()));
        }
        Ok(_) => {}
        Err(error) => {
            eprintln!("xshield-control: automatic pause skipped for site {site}, {error}");
        }
    }
    Ok(())
}

/// The note of an automatic pause: how many positions it paused, the first of them, and then one clause for each
/// paused position whose values now show another kind (LQ-7). A clause names the position with its kind, the kind
/// its values show instead, and the response position that gives most of the votes of that kind, so the
/// administrator knows the error may be on that side. Clauses that would take the note past its length limit are
/// left out; the others are kept.
fn pause_note(
    map: &ObjectMap,
    keys: &[String],
    evidence: &HashMap<String, Evidence>,
    thresholds: Thresholds,
) -> String {
    let mut note = format!(
        "学习任务自动暂停了 {} 个位置：{} 等，证据已转向其他类别",
        keys.len(),
        keys.first().map_or("", String::as_str),
    );
    let mut added = false;
    for clause in keys.iter().filter_map(|key| {
        let found = evidence.get(key)?;
        pause_clause(map, key, found, thresholds)
    }) {
        let separator = if added { "；" } else { "。" };
        // The note ends with a full stop, which counts toward its length.
        let length = note.chars().count() + separator.chars().count() + clause.chars().count() + 1;
        if length > NOTE_MAX_CHARS {
            continue;
        }
        note.push_str(separator);
        note.push_str(&clause);
        added = true;
    }
    if added {
        note.push('。');
    }
    note
}

/// The clause a paused position's note carries: its kind, the other kind its values show now, and the response
/// position that gives the most votes of that kind. `None` when the evidence no longer shows another kind.
fn pause_clause(
    map: &ObjectMap,
    key: &str,
    evidence: &Evidence,
    thresholds: Thresholds,
) -> Option<String> {
    let class = map.declared_class_of(key)?;
    let (other, share_per_mille) = contradicting_kind(class, evidence, map, thresholds)?;
    let source = evidence
        .flows()
        .into_iter()
        .find(|flow| map.class_of(&flow.from) == Some(other))?;
    let percent = (share_per_mille + 5) / 10;
    Some(format!(
        "{key}（{}）的值 {percent}% 来自 {}（{}），错的可能是后者",
        class_name(map, class),
        source.from,
        class_name(map, other),
    ))
}

/// The name the console shows for a class id: the class's name, or the id when the map names no class for it.
fn class_name<'a>(map: &'a ObjectMap, id: &'a str) -> &'a str {
    map.classes()
        .iter()
        .find(|class| class.id == id)
        .map_or(id, |class| class.name.as_str())
}

/// Splits the classes whose window votes show groups of positions that never share a value, when the
/// site has `auto_tighten` on. The split is one new configuration version, recorded as an automatic
/// change, and the moved positions take their new class. A split only removes fast allows, and it is
/// written only when no window vote gains one. Like the pause, it writes nothing when the site has
/// moved on since the pass began, or when the write finds a newer version; the next pass tries again.
/// The run counts the positions it moved.
async fn tighten_split(
    run: &mut Run<'_>,
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    oldest_day: u64,
) -> Result<(), store::LearningStoreError> {
    let record = match site_spec_store::get(pool, site).await {
        Ok(Some(record)) if record.created_at == generation => record,
        Ok(_) => return Ok(()),
        Err(error) => {
            eprintln!("xshield-control: automatic tightening skipped for site {site}, {error}");
            return Ok(());
        }
    };
    let map = record.spec.objects();
    if !map.learning().auto_tighten || map.classes().is_empty() {
        return Ok(());
    }
    let Some(votes) = store::window_votes(pool, site, oldest_day, TIGHTEN_VOTES_MAX).await? else {
        eprintln!(
            "xshield-control: automatic tightening skipped for site {site}, more than {TIGHTEN_VOTES_MAX} votes in the window"
        );
        return Ok(());
    };
    let rules = Rules::of(record.spec.advanced());
    let word_of = |key: &str| name_word(key, &rules);
    // A split an administrator undid is not planned again: its positions stay as the administrator
    // left them, so a split that moves any of them is left out.
    let undone = store::undone_slots(pool, site, generation).await?;
    let splits: Vec<_> = plan_splits(map, &votes, &word_of)
        .into_iter()
        .filter(|split| split.moves.iter().all(|(key, _)| !undone.contains(key)))
        .collect();
    let moved: usize = splits.iter().map(|split| split.moves.len()).sum();
    let Some((first, _)) = splits.first().and_then(|split| split.moves.first()) else {
        return Ok(());
    };
    let Some(after) = apply(map, &splits).filter(|after| !adds_fast_allow(map, after, &votes))
    else {
        return Ok(());
    };
    let note = format!("学习任务自动收紧了 {moved} 个位置：{first} 等，按证据拆分了类别");
    let tightened = record.spec.clone().with_objects(after);
    // A write refused by a newer version, or to a site that is gone, writes nothing; the next
    // pass tries again.
    let outcome = site_spec_store::write(
        pool,
        site,
        &tightened,
        record.version,
        Change::AutoTighten,
        Some(&note),
    )
    .await;
    match outcome {
        Ok(WriteOutcome::Applied(_)) => {
            run.counts.tightened = run.counts.tightened.saturating_add(count_of(moved));
        }
        Ok(_) => {}
        Err(error) => {
            eprintln!("xshield-control: automatic tightening skipped for site {site}, {error}");
        }
    }
    Ok(())
}

/// Judges whether normal traffic sends public sources to each declared request position in effect,
/// and proposes the judgement the rules give when the entry does not already carry it. A position
/// the rules cannot judge loses its proposal, and so does a position the configuration no longer
/// declares in effect. The judgements are read from the configuration the site holds now, and the
/// writes name its generation, so a site deleted meanwhile gets none. The proposals wait for an
/// administrator; nothing here changes the configuration.
async fn judge_accepts(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    oldest_day: u64,
    now_millis: i64,
) -> Result<(), store::LearningStoreError> {
    let record = match site_spec_store::get(pool, site).await {
        Ok(Some(record)) if record.created_at == generation => record,
        Ok(_) => return Ok(()),
        Err(error) => {
            eprintln!("xshield-control: acceptance judgement skipped for site {site}, {error}");
            return Ok(());
        }
    };
    let map = record.spec.objects();
    let thresholds = thresholds_of(map.learning());
    let slots: Vec<String> = map
        .slots()
        .iter()
        .filter(|slot| !slot.paused && is_request_key(&slot.key))
        .map(|slot| slot.key.clone())
        .collect();
    judgements::retain(pool, site, generation, &slots).await?;
    if slots.is_empty() {
        return Ok(());
    }
    let evidence = store::load_evidence(pool, site, &slots, oldest_day).await?;
    // Where the site declares identities, its units are the users and the votes of its administrator
    // sessions are left out (docs/07 section 7.9.16). Elsewhere the units are the sessions, and
    // reliability drops one step, as before.
    let identified = identified_by(map);
    for slot in &slots {
        let Some(evidence) = evidence.get(slot) else {
            judgements::withdraw(pool, site, generation, slot, None).await?;
            continue;
        };
        let admins = if identified {
            evidence.admin_sessions()
        } else {
            BTreeSet::new()
        };
        match judge_accepts_public(
            evidence,
            |position| map.tier_of(position),
            &admins,
            identified,
            thresholds,
        ) {
            Some(judged)
                if map.accepts_public_of(slot) != Some(judged.accepts_public)
                    || map.reliability_of(slot) != Some(judged.reliability) =>
            {
                let proposal = Proposal {
                    slot: slot.clone(),
                    accepts_public: judged.accepts_public,
                    reliability: judged.reliability,
                    votes: judged.votes,
                    sessions: judged.sessions,
                    public_per_mille: judged.public_per_mille,
                    last_day: evidence.last_day().unwrap_or(0),
                };
                judgements::put(pool, site, generation, &proposal, now_millis).await?;
            }
            Some(judged) => {
                // The rules reach the value the entry carries, so a dismissal of the other value lapses.
                judgements::withdraw(pool, site, generation, slot, Some(judged.accepts_public))
                    .await?;
            }
            None => judgements::withdraw(pool, site, generation, slot, None).await?,
        }
    }
    Ok(())
}

/// Whether the site declares a user identity the responses show, so its response units are users
/// and not sessions. A paused entry shows none, as the judge reads it.
pub(crate) fn identified_by(map: &ObjectMap) -> bool {
    map.declares_user_identity()
}

/// Judges the tier of each declared response position from the response evidence of the window: the
/// tier the rules give, and how sure they are. A proposal waits for an administrator, as the acceptance
/// judgement does. Request positions, positions that state an identity and paused entries are left out.
/// A position the rules cannot judge loses its proposal, and so does one the configuration no longer
/// declares. The writes are read against the configuration the site holds now and name its generation,
/// so a site deleted meanwhile gets none. Nothing here changes the configuration.
async fn judge_tiers(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    oldest_day: u64,
    now_millis: i64,
) -> Result<(), store::LearningStoreError> {
    let record = match site_spec_store::get(pool, site).await {
        Ok(Some(record)) if record.created_at == generation => record,
        Ok(_) => return Ok(()),
        Err(error) => {
            eprintln!("xshield-control: tier judgement skipped for site {site}, {error}");
            return Ok(());
        }
    };
    let map = record.spec.objects();
    let thresholds = thresholds_of(map.learning());
    let identified = identified_by(map);
    let slots: Vec<String> = map
        .slots()
        .iter()
        .filter(|slot| !slot.paused && slot.identity.is_none() && !is_request_key(&slot.key))
        .map(|slot| slot.key.clone())
        .collect();
    tier_judgements::retain(pool, site, generation, &slots).await?;
    if slots.is_empty() {
        return Ok(());
    }
    let reads = tier_store::load_tier_evidence(pool, site, &slots, oldest_day).await?;
    let empty = TierRead::default();
    for slot in &slots {
        let read = reads.get(slot).unwrap_or(&empty);
        let stats = response_stats(&read.evidence, identified);
        match judge_tier(&stats, thresholds) {
            Some(judged)
                if map.tier_of(slot) != Some(judged.tier)
                    || map.reliability_of(slot) != Some(judged.reliability) =>
            {
                let proposal = TierProposal {
                    slot: slot.clone(),
                    tier: judged.tier,
                    reliability: judged.reliability,
                    units: stats.units,
                    seen_values: stats.values,
                    agreement_per_mille: judged.agreement_per_mille,
                    last_day: read.last_day,
                };
                tier_judgements::put(pool, site, generation, &proposal, now_millis).await?;
            }
            Some(judged) => {
                // The rules reach the tier the entry carries, so a dismissal of another tier lapses.
                tier_judgements::withdraw(pool, site, generation, slot, Some(judged.tier)).await?;
            }
            None => tier_judgements::withdraw(pool, site, generation, slot, None).await?,
        }
    }
    Ok(())
}

/// The function evidence of one window of a site, as the learning pass and the function list (docs/07 section
/// 7.9.20) both read it, so that the two see the same merged keys.
pub(crate) struct FunctionWindow {
    /// The merged function key to its evidence.
    pub(crate) evidence: BTreeMap<String, FunctionEvidence>,
    /// The site's ordinary units over the window (`site_ordinary_units`).
    pub(crate) ordinary_units: u32,
    /// Each function key with evidence in the window to the key its evidence counts under: itself, or the
    /// merged key `merge_functions` gives it. A key with no evidence is not here.
    pub(crate) mapping: BTreeMap<String, String>,
}

/// The function evidence of the window that starts at `oldest_day`, merged as the learning pass merges it.
/// `None` when more function keys have evidence than `keys_max`: such a window is not merged, and the caller
/// decides what that means. Reads only; the configuration is the one `record` holds.
pub(crate) async fn function_window(
    pool: &PgPool,
    record: &SiteRecord,
    oldest_day: u64,
    keys_max: usize,
) -> Result<Option<FunctionWindow>, store::LearningStoreError> {
    let site = record.spec.name();
    let thresholds = thresholds_of(record.spec.objects().learning());
    let (uses, more) = function_store::function_keys(pool, site, oldest_day, keys_max).await?;
    if more {
        return Ok(None);
    }
    let named_under: Vec<String> = record
        .spec
        .routes()
        .iter()
        .map(|route| route.path().stem().trim_end_matches('/').to_owned())
        .collect();
    let mapping = merge_functions(&uses, thresholds, &named_under);
    let evidence = function_store::function_evidence(pool, site, oldest_day, &mapping).await?;
    let ordinary_units = function_store::site_ordinary_units(pool, site, oldest_day).await?;
    Ok(Some(FunctionWindow {
        evidence,
        ordinary_units,
        mapping,
    }))
}

/// Judges which functions only administrators use, from the function evidence of the window, and proposes
/// each as an administrator function (docs/07 section 7.9.19). Functions the pass merges (`merge_functions`)
/// are judged under their merged key. A proposal waits for an administrator, as a tier proposal does. A
/// proposal the rules no longer make is withdrawn, and a dismissed one stays. The writes read the configuration
/// the site holds now and name its generation, as `judge_tiers` does, so a site deleted meanwhile gets none.
/// Nothing here changes the configuration.
///
/// The pass reads the `keys_max` keys used by the most units. When more keys have evidence, the pass judges
/// nothing and writes nothing: a key past the limit would look unused, and its proposal would be withdrawn.
async fn judge_functions(
    pool: &PgPool,
    site: &str,
    generation: DateTime<Utc>,
    oldest_day: u64,
    keys_max: usize,
    now_millis: i64,
) -> Result<(), store::LearningStoreError> {
    let record = match site_spec_store::get(pool, site).await {
        Ok(Some(record)) if record.created_at == generation => record,
        Ok(_) => return Ok(()),
        Err(error) => {
            eprintln!("xshield-control: function judgement skipped for site {site}, {error}");
            return Ok(());
        }
    };
    let map = record.spec.objects();
    let thresholds = thresholds_of(map.learning());
    let identified = identified_by(map);
    let Some(window) = function_window(pool, &record, oldest_day, keys_max).await? else {
        eprintln!(
            "xshield-control: function judgement skipped for site {site}, more than {keys_max} function keys have evidence"
        );
        return Ok(());
    };
    let FunctionWindow {
        evidence,
        ordinary_units,
        ..
    } = window;
    let mut judged = Vec::new();
    for (function, evidence) in &evidence {
        // A key longer than a position key is one the configuration cannot hold, so it is not proposed.
        if function.len() > KEY_MAX {
            continue;
        }
        let Some(reliability) = judge_function(evidence, ordinary_units, identified, thresholds)
        else {
            continue;
        };
        let proposal = TierProposal {
            slot: function.clone(),
            tier: Tier::Admin,
            reliability,
            units: evidence.admin_units,
            seen_values: 0,
            agreement_per_mille: 0,
            last_day: evidence.last_day,
        };
        tier_judgements::put(pool, site, generation, &proposal, now_millis).await?;
        judged.push(function.clone());
    }
    tier_judgements::retain_functions(pool, site, generation, &judged).await?;
    Ok(())
}

/// A count of positions as the run record keeps it. A count too large for it is held at the largest.
fn count_of(positions: usize) -> u32 {
    u32::try_from(positions).unwrap_or(u32::MAX)
}

/// The state the rules give a position: a confirmed position is confirmed or
/// suspended by its evidence, and an unknown position is proposed when the rules
/// can tell its kind. `None` when the evidence says nothing yet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Decision {
    state: LearnedState,
    class: String,
    votes: u32,
    sessions: u32,
    share_per_mille: u32,
    last_day: u64,
}

/// The thresholds a site's learning settings give the rules. The share is the design's own.
pub(crate) fn thresholds_of(learning: &LearningSettings) -> Thresholds {
    Thresholds {
        votes: learning.thresholds.uses,
        sessions: learning.thresholds.sessions,
        ..Thresholds::default()
    }
}

fn decide(slot: &str, evidence: &Evidence, map: &ObjectMap, today: u64) -> Option<Decision> {
    let thresholds = thresholds_of(map.learning());
    if let Some(class) = map.declared_class_of(slot) {
        // A confirmed position is judged by its votes alone. Refusals without a vote in
        // the window leave its state as it is, and its last vote ages toward retirement.
        // A paused position stays suspended until an administrator confirms it again.
        let last_day = evidence.last_day()?;
        let state = if map.is_paused(slot) || contradicts(class, evidence, map, thresholds) {
            LearnedState::Suspended
        } else {
            LearnedState::Confirmed
        };
        return Some(Decision {
            state,
            class: class.to_owned(),
            votes: evidence.votes(),
            sessions: evidence.sessions(),
            share_per_mille: kind_share(evidence, map, class),
            last_day,
        });
    }
    let proposal = propose(evidence, map, thresholds)?;
    Some(Decision {
        state: LearnedState::Proposed,
        class: proposal.class,
        votes: proposal.votes,
        sessions: proposal.sessions,
        share_per_mille: proposal.share_per_mille,
        last_day: evidence.last_day().unwrap_or(today),
    })
}

/// The cursor after a batch. A batch that read every row up to the horizon moves the
/// cursor to `end`. A full batch moves it to its newest row, and the rows after that
/// row, including those that share its time, are read by the next batch.
fn next_cursor(after: Cursor, end: Cursor, complete: bool, newest: Option<Cursor>) -> Cursor {
    match (complete, newest) {
        (true, _) => end,
        (false, Some(newest)) if newest > after => newest,
        (false, _) => after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCTOR_FROM: &str = "GET /api/appointments [].doc_id";
    const DOCUMENT_FROM: &str = "GET /api/docs [].id";
    const SLOT: &str = "GET /doctor/{id} path[1]";

    fn map() -> ObjectMap {
        serde_json::from_str::<ObjectMap>(
            r#"{
                "classes": [{"id": "doctor", "name": "医生"}, {"id": "document", "name": "文档"}],
                "slots": [
                    {"key": "GET /api/appointments [].doc_id", "class": "doctor", "source": "rule"},
                    {"key": "GET /api/docs [].id", "class": "document", "source": "admin"},
                    {"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin"}
                ]
            }"#,
        )
        .unwrap()
    }

    /// Evidence of `SLOT`: `count` votes from `sessions` sessions, all from `from`.
    fn evidence(count: u32, sessions: u32, from: &str) -> Evidence {
        let mut evidence = Evidence::default();
        for index in 0..count {
            evidence.add_vote(xshield_core::context::learning::Vote {
                slot: SLOT.to_owned(),
                session: format!("s{}", index % sessions),
                day: u64::from(index),
                from: vec![from.to_owned()],
                user: None,
                admin: false,
            });
        }
        evidence
    }

    #[test]
    fn an_unknown_position_is_proposed_when_the_rules_can_tell_its_kind() {
        let map = map();
        let slot = "GET /other/{id} path[1]";
        let decision = decide(slot, &evidence(20, 5, DOCTOR_FROM), &map, 10).unwrap();
        assert_eq!(decision.state, LearnedState::Proposed);
        assert_eq!(decision.class, "doctor");
        assert_eq!(decision.share_per_mille, 1_000);
        // Too little evidence, or no kind the rules can name: nothing is written.
        assert_eq!(decide(slot, &evidence(19, 5, DOCTOR_FROM), &map, 10), None);
        assert_eq!(
            decide(slot, &evidence(20, 5, "GET /api/x [].y"), &map, 10),
            None
        );
    }

    #[test]
    fn a_confirmed_position_is_confirmed_while_its_evidence_agrees() {
        let decision = decide(SLOT, &evidence(20, 5, DOCTOR_FROM), &map(), 10).unwrap();
        assert_eq!(decision.state, LearnedState::Confirmed);
        assert_eq!(decision.class, "doctor");
        assert_eq!(decision.votes, 20);
        assert_eq!(decision.last_day, 19);
    }

    #[test]
    fn a_confirmed_position_whose_evidence_points_elsewhere_is_suspended() {
        let decision = decide(SLOT, &evidence(20, 5, DOCUMENT_FROM), &map(), 10).unwrap();
        assert_eq!(decision.state, LearnedState::Suspended);
        assert_eq!(decision.class, "doctor");
        assert_eq!(decision.share_per_mille, 0);
    }

    #[test]
    fn the_pause_note_names_the_kind_the_values_show_and_the_source_with_most_votes() {
        let note = pause_note(
            &map(),
            &[SLOT.to_owned()],
            &HashMap::from([(SLOT.to_owned(), evidence(20, 5, DOCUMENT_FROM))]),
            Thresholds::default(),
        );
        assert_eq!(
            note,
            "学习任务自动暂停了 1 个位置：GET /doctor/{id} path[1] 等，证据已转向其他类别。\
             GET /doctor/{id} path[1]（医生）的值 100% 来自 GET /api/docs [].id（文档），错的可能是后者。"
        );
    }

    #[test]
    fn a_paused_position_whose_evidence_shows_no_other_kind_gets_no_clause() {
        let note = pause_note(
            &map(),
            &[SLOT.to_owned()],
            &HashMap::from([(SLOT.to_owned(), evidence(20, 5, DOCTOR_FROM))]),
            Thresholds::default(),
        );
        assert_eq!(
            note,
            "学习任务自动暂停了 1 个位置：GET /doctor/{id} path[1] 等，证据已转向其他类别"
        );
    }

    #[test]
    fn clauses_that_would_take_the_pause_note_past_its_length_limit_are_left_out() {
        let routes: Vec<String> = (0..12)
            .map(|index| format!("GET /r{index}/{{id}} path[1]"))
            .collect();
        let slots: Vec<String> = routes
            .iter()
            .map(|key| format!(r#"{{"key": "{key}", "class": "doctor", "source": "admin"}}"#))
            .collect();
        let map = serde_json::from_str::<ObjectMap>(&format!(
            r#"{{"classes": [{{"id": "doctor", "name": "医生"}}, {{"id": "document", "name": "文档"}}],
                "slots": [{}, {{"key": "GET /api/docs [].id", "class": "document", "source": "admin"}}]}}"#,
            slots.join(",")
        ))
        .unwrap();
        let evidence: HashMap<String, Evidence> = routes
            .iter()
            .map(|key| {
                let mut found = Evidence::default();
                for index in 0..20_u32 {
                    found.add_vote(xshield_core::context::learning::Vote {
                        slot: key.clone(),
                        session: format!("s{}", index % 5),
                        day: u64::from(index),
                        from: vec![DOCUMENT_FROM.to_owned()],
                        user: None,
                        admin: false,
                    });
                }
                (key.clone(), found)
            })
            .collect();
        let note = pause_note(&map, &routes, &evidence, Thresholds::default());
        assert!(note.chars().count() <= NOTE_MAX_CHARS, "{note}");
        assert!(note.contains("GET /r0/{id} path[1]（医生）的值 100%"));
        // The first clauses fit and the last does not, so the note ends with a clause it names.
        assert!(!note.contains("GET /r11/{id} path[1]"));
        assert!(note.ends_with("错的可能是后者。"));
    }

    #[test]
    fn refusals_alone_leave_a_confirmed_position_alone() {
        let mut refused = Evidence::default();
        refused.add_denial(xshield_core::context::learning::Denial {
            slot: SLOT.to_owned(),
            session: "s0".to_owned(),
            day: 5,
        });
        assert_eq!(decide(SLOT, &refused, &map(), 10), None);
    }

    fn cursor_at(at_millis: i64, id: i64) -> Cursor {
        Cursor { at_millis, id }
    }

    #[test]
    fn a_paused_position_stays_suspended_while_its_evidence_agrees() {
        let paused = map().with_paused(&[SLOT.to_owned()]);
        let decision = decide(SLOT, &evidence(20, 5, DOCTOR_FROM), &paused, 10).unwrap();
        assert_eq!(decision.state, LearnedState::Suspended);
        assert_eq!(decision.class, "doctor");
    }

    #[test]
    fn the_cursor_reaches_the_horizon_only_when_a_batch_was_complete() {
        let start = cursor_at(0, 0);
        let end = cursor_at(100, i64::MAX);
        // A short batch read every row up to the horizon.
        assert_eq!(next_cursor(start, end, true, Some(cursor_at(40, 3))), end);
        // A full batch stops at its newest row, and the rows after it are read next.
        assert_eq!(
            next_cursor(start, end, false, Some(cursor_at(50, 9))),
            cursor_at(50, 9)
        );
        // Rows of one millisecond that did not fit are not skipped: the id resumes them.
        assert_eq!(
            next_cursor(cursor_at(50, 9), end, false, Some(cursor_at(50, 5_009))),
            cursor_at(50, 5_009)
        );
        // A batch whose newest row is not past the cursor leaves the cursor where it was.
        assert_eq!(
            next_cursor(cursor_at(10, 2), end, false, Some(cursor_at(10, 2))),
            cursor_at(10, 2)
        );
        assert_eq!(next_cursor(start, end, false, None), start);
    }

    #[test]
    fn the_site_sets_how_much_evidence_a_proposal_needs() {
        let lenient: ObjectMap = serde_json::from_str(
            r#"{"classes": [{"id": "doctor", "name": "医生"}],
                "slots": [{"key": "GET /api/appointments [].doc_id", "class": "doctor", "source": "rule"}],
                "learning": {"thresholds": {"uses": 10, "sessions": 2}}}"#,
        )
        .unwrap();
        let slot = "GET /other/{id} path[1]";
        assert!(decide(slot, &evidence(10, 2, DOCTOR_FROM), &lenient, 10).is_some());
        assert!(decide(slot, &evidence(9, 2, DOCTOR_FROM), &lenient, 10).is_none());
        assert!(decide(slot, &evidence(10, 1, DOCTOR_FROM), &lenient, 10).is_none());
        // A site that sets no thresholds keeps the design's bar of twenty uses.
        assert!(decide(slot, &evidence(10, 2, DOCTOR_FROM), &map(), 10).is_none());
    }
}

/// Passes over a migrated scratch database. They need a reachable PostgreSQL server
/// (`XSHIELD_TEST_DATABASE_BASE_URL`, a server URL without a database name) and
/// return at once without one, as the migration tests do.
#[cfg(test)]
pub(crate) mod pass_tests {
    use super::*;
    use crate::MIGRATOR;
    use sqlx::{AssertSqlSafe, PgPool};

    pub(crate) async fn scratch(tag: &str) -> Option<(PgPool, PgPool, String)> {
        let base = std::env::var("XSHIELD_TEST_DATABASE_BASE_URL").ok()?;
        let admin = PgPool::connect(&format!("{base}/postgres"))
            .await
            .expect("admin connection");
        let name = format!("object_learning_{}_{tag}", std::process::id());
        sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name}")))
            .execute(&admin)
            .await
            .expect("drop a database left by an earlier run");
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create the scratch database");
        let pool = PgPool::connect(&format!("{base}/{name}"))
            .await
            .expect("scratch connection");
        MIGRATOR.run(&pool).await.expect("migrations");
        Some((admin, pool, name))
    }

    pub(crate) async fn drop_scratch(admin: PgPool, pool: PgPool, name: String) {
        pool.close().await;
        sqlx::query(AssertSqlSafe(format!("DROP DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("drop the scratch database");
    }

    /// A site whose response position `GET /api/appointments [].doc_id` is confirmed
    /// as a doctor, so the rules can tell the kind of a value that came from it.
    fn clinic() -> SiteSpec {
        clinic_with(serde_json::Value::Null)
    }

    /// The clinic site with the learning settings `learning`, or the defaults when null.
    pub(crate) fn clinic_with(learning: serde_json::Value) -> SiteSpec {
        let mut objects = serde_json::json!({
            "classes": [{"id": "doctor", "name": "医生"}],
            "slots": [{"key": "GET /api/appointments [].doc_id", "class": "doctor", "source": "admin"}]
        });
        if !learning.is_null() {
            objects["learning"] = learning;
        }
        let spec = serde_json::json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"],
            "objects": objects
        });
        SiteSpec::from_json(&spec.to_string()).expect("test spec")
    }

    /// Partitions for the days the test rows fall on. The pass reads from its
    /// cursor, so rows must exist before the first pass.
    pub(crate) async fn partitions(pool: &PgPool, now: i64) {
        let days: Vec<i64> = (0..=5).map(|days| now - days * DAY_MILLIS).collect();
        crate::test_support::ensure_days(pool, &days).await;
    }

    /// One decision row of `GET /doctor/7` at `at_millis`. Five sessions make uses in
    /// turn, so `index` names the request and, modulo five, the session that made it.
    async fn record_at(
        pool: &PgPool,
        index: i64,
        at_millis: i64,
        path: &str,
        outcome: &str,
        status: i16,
    ) {
        let trace = serde_json::json!({
            "v": 1,
            "values_truncated": false,
            "values": [{
                "at": "path[1]",
                "value": "7",
                "kind": "reference",
                "inert": false,
                "seen": true,
                "verified": true,
                "slot": "GET /doctor/{id} path[1]",
                "sources": [{
                    "field": "doc_id",
                    "request": "GET /api/appointments",
                    "slot": "GET /api/appointments [].doc_id"
                }]
            }],
            "timing": {"judge_ms": 1}
        });
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace)
             VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                'GET', '/doctor/7', $4, $5, $6, $7)",
        )
        .bind(at_millis)
        .bind(format!("req_{index:032x}"))
        .bind(format!("s{}", index % 5))
        .bind(status)
        .bind(path)
        .bind(outcome)
        .bind(trace)
        .execute(pool)
        .await
        .expect("insert a decision row");
    }

    /// One decision row of `GET /doctor/7` made `1 + index / 5` days before `now`, so
    /// twenty uses from five sessions fall on distinct days inside the window.
    async fn record(pool: &PgPool, index: i64, now: i64, path: &str, outcome: &str, status: i16) {
        record_at(
            pool,
            index,
            now - (1 + index / 5) * DAY_MILLIS,
            path,
            outcome,
            status,
        )
        .await;
    }

    #[tokio::test]
    async fn twenty_uses_from_five_sessions_propose_the_kind_of_their_source() {
        let Some((admin, pool, name)) = scratch("proposal").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..20 {
            record(&pool, index, now, "fast_allow", "allowed", 200).await;
        }
        learn_once(&pool, None, now).await;
        let (state, class): (String, String) = sqlx::query_as(
            "SELECT state, class FROM object_positions
             WHERE site = 'clinic' AND slot = 'GET /doctor/{id} path[1]'",
        )
        .fetch_one(&pool)
        .await
        .expect("the position is judged");
        assert_eq!((state.as_str(), class.as_str()), ("proposed", "doctor"));
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_refusal_in_the_window_keeps_the_position_unproposed() {
        let Some((admin, pool, name)) = scratch("refusal").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..20 {
            record(&pool, index, now, "fast_allow", "allowed", 200).await;
        }
        record(&pool, 20, now, "jev_deny", "blocked", 403).await;
        learn_once(&pool, None, now).await;
        // The position is listed as pending, and no judgement names it.
        let judged: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM object_positions WHERE site = 'clinic' AND state <> 'pending'",
        )
        .fetch_one(&pool)
        .await
        .expect("count the judged positions");
        assert_eq!(judged, 0);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn ten_uses_propose_a_kind_when_the_site_asks_for_ten() {
        let Some((admin, pool, name)) = scratch("site_threshold").await else {
            return;
        };
        let now = crate::params::now_millis();
        let learning = serde_json::json!({"thresholds": {"uses": 10, "sessions": 5}});
        site_spec_store::create(&pool, &clinic_with(learning), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..10 {
            record(&pool, index, now, "fast_allow", "allowed", 200).await;
        }
        learn_once(&pool, None, now).await;
        let (state, class): (String, String) = sqlx::query_as(
            "SELECT state, class FROM object_positions
             WHERE site = 'clinic' AND slot = 'GET /doctor/{id} path[1]'",
        )
        .fetch_one(&pool)
        .await
        .expect("the position is judged");
        assert_eq!((state.as_str(), class.as_str()), ("proposed", "doctor"));
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_site_with_learning_off_reads_nothing() {
        let Some((admin, pool, name)) = scratch("learning_off").await else {
            return;
        };
        let now = crate::params::now_millis();
        let learning = serde_json::json!({"auto_learn": false});
        site_spec_store::create(&pool, &clinic_with(learning), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..20 {
            record(&pool, index, now, "fast_allow", "allowed", 200).await;
        }
        learn_once(&pool, None, now).await;
        let evidence: i64 =
            sqlx::query_scalar("SELECT count(*) FROM object_evidence WHERE site = 'clinic'")
                .fetch_one(&pool)
                .await
                .expect("count the evidence");
        let positions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM object_positions WHERE site = 'clinic'")
                .fetch_one(&pool)
                .await
                .expect("count the judged positions");
        let cursor = store::cursor(&pool, "clinic")
            .await
            .expect("read the cursor");
        assert_eq!((evidence, positions, cursor), (0, 0, None));
        drop_scratch(admin, pool, name).await;
    }

    /// The positions of the clinic site that hold a proposal.
    async fn proposed(pool: &PgPool) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM object_positions WHERE site = 'clinic' AND state = 'proposed'",
        )
        .fetch_one(pool)
        .await
        .expect("count the proposals")
    }

    #[tokio::test]
    async fn a_refusal_after_a_proposal_withdraws_it() {
        let Some((admin, pool, name)) = scratch("withdrawn").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..20 {
            record(&pool, index, now, "fast_allow", "allowed", 200).await;
        }
        learn_once(&pool, None, now).await;
        assert_eq!(proposed(&pool).await, 1);
        // Jev refuses the position after the proposal was made. The pass an hour later
        // reads the refusal, which lies after the cursor the first pass left.
        record_at(&pool, 20, now - 5 * 60_000, "jev_deny", "blocked", 403).await;
        learn_once(&pool, None, now + 60 * 60_000).await;
        assert_eq!(proposed(&pool).await, 0);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_proposal_whose_evidence_ages_out_is_withdrawn() {
        let Some((admin, pool, name)) = scratch("aged_out").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..20 {
            record(&pool, index, now, "fast_allow", "allowed", 200).await;
        }
        learn_once(&pool, None, now).await;
        assert_eq!(proposed(&pool).await, 1);
        // Eight days later no vote is in the window, and no new row has arrived.
        learn_once(&pool, None, now + 8 * DAY_MILLIS).await;
        assert_eq!(proposed(&pool).await, 0);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn deleting_a_site_forgets_what_it_learned() {
        let Some((admin, pool, name)) = scratch("forget").await else {
            return;
        };
        let now = crate::params::now_millis();
        let created = site_spec_store::create(&pool, &clinic(), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..20 {
            record(&pool, index, now, "fast_allow", "allowed", 200).await;
        }
        learn_once(&pool, None, now).await;
        assert_eq!(proposed(&pool).await, 1);
        let deleted = site_spec_store::delete(&pool, "clinic", created.version, None)
            .await
            .expect("delete the site");
        assert!(matches!(
            deleted,
            site_spec_store::DeleteOutcome::Deleted { .. }
        ));
        // The same name again. The traffic the old site logged before the deletion is
        // never learned from, even once the passes have run past it.
        site_spec_store::create(&pool, &clinic(), None)
            .await
            .expect("create the site again");
        learn_once(&pool, None, now).await;
        learn_once(&pool, None, now + 60 * 60_000).await;
        let evidence: i64 =
            sqlx::query_scalar("SELECT count(*) FROM object_evidence WHERE site = 'clinic'")
                .fetch_one(&pool)
                .await
                .expect("count the evidence");
        assert_eq!((evidence, proposed(&pool).await), (0, 0));
        drop_scratch(admin, pool, name).await;
    }

    /// A clinic site that declares `GET /doctor/{id} path[1]` a doctor and `GET /api/docs [].id` a
    /// document, with the learning settings `learning` (null for the defaults).
    fn clinic_declaring_both(learning: serde_json::Value) -> SiteSpec {
        let mut objects = serde_json::json!({
            "classes": [{"id": "doctor", "name": "医生"}, {"id": "document", "name": "文档"}],
            "slots": [
                {"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin"},
                {"key": "GET /api/docs [].id", "class": "document", "source": "admin"}
            ]
        });
        if !learning.is_null() {
            objects["learning"] = learning;
        }
        let spec = serde_json::json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"],
            "objects": objects
        });
        SiteSpec::from_json(&spec.to_string()).expect("test spec")
    }

    /// One decision row of `GET /doctor/7` made `1 + index / 5` days before `now`, whose value the
    /// origin showed as a document: the evidence of the position points at another kind.
    async fn record_document_source(pool: &PgPool, index: i64, now: i64) {
        let trace = serde_json::json!({
            "v": 1,
            "values_truncated": false,
            "values": [{
                "at": "path[1]",
                "value": "7",
                "kind": "reference",
                "inert": false,
                "seen": true,
                "verified": true,
                "slot": "GET /doctor/{id} path[1]",
                "sources": [{
                    "field": "id",
                    "request": "GET /api/docs",
                    "slot": "GET /api/docs [].id"
                }]
            }],
            "timing": {"judge_ms": 1}
        });
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace)
             VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                'GET', '/doctor/7', 200, 'fast_allow', 'allowed', $4)",
        )
        .bind(now - (1 + index / 5) * DAY_MILLIS)
        .bind(format!("req_{index:032x}"))
        .bind(format!("s{}", index % 5))
        .bind(trace)
        .execute(pool)
        .await
        .expect("insert a decision row");
    }

    /// A clinic site whose one class `entity` holds two flows that never cross: a doctor position
    /// with the response that shows its id, and a document position with the response that shows
    /// its id. `learning` is the learning settings (null for the defaults).
    fn clinic_with_two_flows(learning: serde_json::Value) -> SiteSpec {
        let mut objects = serde_json::json!({
            "classes": [{"id": "entity", "name": "对象"}],
            "slots": [
                {"key": "GET /doctor/{id} path[1]", "class": "entity", "source": "rule"},
                {"key": "GET /api/appointments [].doc_id", "class": "entity", "source": "rule"},
                {"key": "GET /document/{id} path[1]", "class": "entity", "source": "rule"},
                {"key": "GET /api/documents [].id", "class": "entity", "source": "rule"}
            ]
        });
        if !learning.is_null() {
            objects["learning"] = learning;
        }
        let spec = serde_json::json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"],
            "objects": objects
        });
        SiteSpec::from_json(&spec.to_string()).expect("test spec")
    }

    /// One allowed decision row of `path`, whose value names `value_slot` and was shown by `source`,
    /// the request and the response position that showed it, made in `session` at `at_millis`.
    async fn record_flow(
        pool: &PgPool,
        id: &str,
        at_millis: i64,
        session: &str,
        path: &str,
        value_slot: &str,
        source: (&str, &str),
    ) {
        let trace = serde_json::json!({
            "v": 1,
            "values_truncated": false,
            "values": [{
                "at": "path[1]",
                "value": "7",
                "kind": "reference",
                "inert": false,
                "seen": true,
                "verified": true,
                "slot": value_slot,
                "sources": [{
                    "field": "id",
                    "request": source.0,
                    "slot": source.1
                }]
            }],
            "timing": {"judge_ms": 1}
        });
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace)
             VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                'GET', $4, 200, 'fast_allow', 'allowed', $5)",
        )
        .bind(at_millis)
        .bind(id)
        .bind(session)
        .bind(path)
        .bind(trace)
        .execute(pool)
        .await
        .expect("insert a decision row");
    }

    /// Twenty uses of each flow from five sessions over the last four days, so the window holds
    /// the votes that join each doctor to its source and each document to its source.
    async fn record_two_flows(pool: &PgPool, now: i64) {
        for index in 0..20 {
            let at_millis = now - (1 + index / 5) * DAY_MILLIS;
            let session = format!("s{}", index % 5);
            record_flow(
                pool,
                &format!("req_doctor_{index:032x}"),
                at_millis,
                &session,
                "/doctor/7",
                "GET /doctor/{id} path[1]",
                ("GET /api/appointments", "GET /api/appointments [].doc_id"),
            )
            .await;
            record_flow(
                pool,
                &format!("req_document_{index:032x}"),
                at_millis,
                &session,
                "/document/9",
                "GET /document/{id} path[1]",
                ("GET /api/documents", "GET /api/documents [].id"),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn a_class_whose_votes_show_two_flows_is_split_by_one_new_version() {
        let Some((admin, pool, name)) = scratch("auto_tighten").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic_with_two_flows(serde_json::json!({"auto_tighten": true})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        record_two_flows(&pool, now).await;
        learn_once(&pool, None, now).await;
        let record = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        assert_eq!(record.version, 2);
        let map = record.spec.objects();
        // The doctor flow keeps the class; the document flow moves to a class of its own.
        assert_eq!(map.class_of("GET /doctor/{id} path[1]"), Some("entity"));
        assert_eq!(
            map.class_of("GET /api/appointments [].doc_id"),
            Some("entity")
        );
        assert_eq!(
            map.class_of("GET /document/{id} path[1]"),
            Some("documents")
        );
        assert_eq!(map.class_of("GET /api/documents [].id"), Some("documents"));
        assert!(
            map.classes()
                .iter()
                .any(|class| class.id == "documents" && class.name == "document")
        );
        let history = site_spec_store::history(&pool, "clinic", None, 10)
            .await
            .expect("read the history");
        assert_eq!(history[0].change, Change::AutoTighten);
        assert!(
            history[0]
                .note
                .as_deref()
                .is_some_and(|note| note.contains("自动收紧"))
        );
        // A later pass finds the split already in place and writes no further version.
        learn_once(&pool, None, now).await;
        let again = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        assert_eq!(again.version, 2);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn with_auto_tighten_off_a_split_is_not_written() {
        let Some((admin, pool, name)) = scratch("auto_tighten_off").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic_with_two_flows(serde_json::json!({"auto_tighten": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        record_two_flows(&pool, now).await;
        learn_once(&pool, None, now).await;
        let record = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        assert_eq!(record.version, 1);
        assert_eq!(
            record.spec.objects().class_of("GET /document/{id} path[1]"),
            Some("entity")
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn without_learning_settings_a_split_is_not_written() {
        let Some((admin, pool, name)) = scratch("auto_tighten_absent").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic_with_two_flows(serde_json::Value::Null), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        record_two_flows(&pool, now).await;
        learn_once(&pool, None, now).await;
        let record = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        // The default is off: the pass writes no version and the document position keeps its class.
        assert_eq!(record.version, 1);
        assert_eq!(
            record.spec.objects().class_of("GET /document/{id} path[1]"),
            Some("entity")
        );
        let history = site_spec_store::history(&pool, "clinic", None, 10)
            .await
            .expect("read the history");
        assert!(
            history
                .iter()
                .all(|entry| entry.change != Change::AutoTighten)
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_split_the_administrator_undid_is_not_planned_again() {
        let Some((admin, pool, name)) = scratch("undone_split").await else {
            return;
        };
        let now = crate::params::now_millis();
        // Tightening is on here, so the split the administrator undid is one the pass would make.
        let created = site_spec_store::create(
            &pool,
            &clinic_with_two_flows(serde_json::json!({"auto_tighten": true})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        record_two_flows(&pool, now).await;
        // The administrator undid the split of the document position, so the event is handled.
        xshield_postgres::object_learning_store::record_event(
            &pool,
            "clinic",
            created.created_at,
            &xshield_postgres::object_learning_store::EventStatus {
                event: "v1-0".to_owned(),
                status: xshield_core::context::position::Handling::Undone,
                kind: "auto_tighten".to_owned(),
                slot: "GET /document/{id} path[1]".to_owned(),
                handled_by: "administrator".to_owned(),
                handled_millis: now,
                handled_version: Some(2),
            },
        )
        .await
        .expect("record the undo");
        learn_once(&pool, None, now).await;
        let record = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        assert_eq!(record.version, 1);
        assert_eq!(
            record.spec.objects().class_of("GET /document/{id} path[1]"),
            Some("entity")
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_suspended_declared_position_is_paused_by_one_new_version() {
        let Some((admin, pool, name)) = scratch("auto_pause").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic_declaring_both(serde_json::Value::Null), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..20 {
            record_document_source(&pool, index, now).await;
        }
        learn_once(&pool, None, now).await;
        let record = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        assert_eq!(record.version, 2);
        assert!(record.spec.objects().is_paused("GET /doctor/{id} path[1]"));
        // The paused entry stays declared, so the position keeps its kind for the learning task.
        assert_eq!(
            record
                .spec
                .objects()
                .declared_class_of("GET /doctor/{id} path[1]"),
            Some("doctor")
        );
        let history = site_spec_store::history(&pool, "clinic", None, 10)
            .await
            .expect("read the history");
        assert_eq!(history[0].change, Change::AutoPause);
        // The note names the kind the values show instead, and the source that gives most of the votes (LQ-7).
        assert_eq!(
            history[0].note.as_deref(),
            Some(
                "学习任务自动暂停了 1 个位置：GET /doctor/{id} path[1] 等，证据已转向其他类别。\
                 GET /doctor/{id} path[1]（医生）的值 100% 来自 GET /api/docs [].id（文档），错的可能是后者。"
            )
        );
        let state: String = sqlx::query_scalar(
            "SELECT state FROM object_positions
             WHERE site = 'clinic' AND slot = 'GET /doctor/{id} path[1]'",
        )
        .fetch_one(&pool)
        .await
        .expect("the position is judged");
        assert_eq!(state, "suspended");
        // A later pass finds the position paused already, and writes no further version.
        learn_once(&pool, None, now + 60 * 60_000).await;
        let again = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        assert_eq!(again.version, 2);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_suspended_position_keeps_the_function_table_in_the_new_version() {
        let Some((admin, pool, name)) = scratch("auto_pause_functions").await else {
            return;
        };
        let now = crate::params::now_millis();
        let spec = SiteSpec::from_json(
            &serde_json::json!({
                "name": "clinic",
                "hosts": ["clinic.example.com"],
                "origin": "http://10.0.0.5:8080",
                "session": {"cookie": "SESSIONID"},
                "entries": ["/login"],
                "objects": {
                    "classes": [{"id": "doctor", "name": "医生"}, {"id": "document", "name": "文档"}],
                    "slots": [
                        {"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin"},
                        {"key": "GET /api/docs [].id", "class": "document", "source": "admin"}
                    ],
                    "functions": [
                        {"key": "POST /api/admin/export", "source": "rule", "tier": "admin", "reliability": "high"},
                        {"key": "GET /api/docs", "source": "admin"}
                    ]
                }
            })
            .to_string(),
        )
        .expect("test spec");
        site_spec_store::create(&pool, &spec, None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..20 {
            record_document_source(&pool, index, now).await;
        }
        learn_once(&pool, None, now).await;
        let record = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        assert_eq!(record.version, 2);
        assert!(record.spec.objects().is_paused("GET /doctor/{id} path[1]"));
        // The pause writes a new version, and the function table is in it, unchanged.
        assert_eq!(
            record.spec.objects().functions(),
            spec.objects().functions()
        );
        assert!(
            record
                .spec
                .objects()
                .admin_only("POST", "/api/admin/export")
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn with_auto_pause_off_a_suspended_position_is_only_marked() {
        let Some((admin, pool, name)) = scratch("auto_pause_off").await else {
            return;
        };
        let now = crate::params::now_millis();
        let learning = serde_json::json!({"auto_pause": false});
        site_spec_store::create(&pool, &clinic_declaring_both(learning), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..20 {
            record_document_source(&pool, index, now).await;
        }
        learn_once(&pool, None, now).await;
        // The position is suspended for an administrator to decide, and the configuration is kept.
        let record = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        assert_eq!(record.version, 1);
        assert!(!record.spec.objects().is_paused("GET /doctor/{id} path[1]"));
        let state: String = sqlx::query_scalar(
            "SELECT state FROM object_positions
             WHERE site = 'clinic' AND slot = 'GET /doctor/{id} path[1]'",
        )
        .fetch_one(&pool)
        .await
        .expect("the position is judged");
        assert_eq!(state, "suspended");
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_millisecond_with_more_rows_than_a_batch_is_read_to_the_end() {
        let Some((admin, pool, name)) = scratch("same_millisecond").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        // One more row than a batch holds, all at one millisecond inside the window.
        let at = now - 2 * DAY_MILLIS - 60 * 60_000;
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace)
             SELECT $1::bigint, 'req_' || lpad(to_hex(n), 32, '0'), 'clinic', 'edge-1',
                'clinic.example.com', '10.0.0.1', 's' || (n % 5), 'GET', '/doctor/7', 200,
                'fast_allow', 'allowed', $2::jsonb
             FROM generate_series(1, $3::bigint) AS n",
        )
        .bind(at)
        .bind(serde_json::json!({"v": 1}))
        .bind(BATCH_ROWS + 1)
        .execute(&pool)
        .await
        .expect("insert the rows of one millisecond");
        learn_once(&pool, None, now).await;
        // The pass read the log up to its horizon, past the first batch and into the next.
        let cursor = store::cursor(&pool, "clinic")
            .await
            .expect("read the cursor");
        assert_eq!(
            cursor,
            Some(Cursor {
                at_millis: now - LAG_MILLIS,
                id: i64::MAX,
            })
        );
        drop_scratch(admin, pool, name).await;
    }
}

/// Acceptance judgements of the learning pass over a migrated scratch database: the proposals of
/// request positions that the rules judge by the public and self tiers of their response positions.
#[cfg(test)]
mod judgement_pass_tests {
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use xshield_core::context::{Reliability, SiteSpec};
    use xshield_postgres::{
        object_judgement_store::{self as judgements, Proposal},
        site_spec_store::{self, Change},
    };

    use super::learn_once;
    use super::pass_tests::{drop_scratch, partitions, scratch};
    use crate::params::DAY_MILLIS;

    /// A public response position: the search results.
    const SEARCH: &str = "GET /api/search [].id";
    /// A self response position: the doctor's own patients.
    const OWN: &str = "GET /api/patients [].id";
    /// A request position the search results feed.
    const SHARE: &str = "GET /api/share/{id} path[1]";
    /// A request position the doctor's own patients feed.
    const DELETE: &str = "DELETE /api/patients/{id} path[1]";

    /// A clinic site with the two response positions, and `requests` as its declared request
    /// positions, each with the fields its judgement gives (none for a plain entry).
    fn clinic(requests: &[(&str, Value)], learning: &Value) -> SiteSpec {
        let mut slots = vec![
            json!({"key": SEARCH, "class": "patient", "source": "admin", "tier": "public"}),
            json!({"key": OWN, "class": "patient", "source": "admin", "tier": "self"}),
        ];
        for (key, judgement) in requests {
            let mut entry = json!({"key": key, "class": "patient", "source": "admin"});
            if let Value::Object(fields) = judgement {
                for (field, value) in fields {
                    entry[field] = value.clone();
                }
            }
            slots.push(entry);
        }
        let spec = json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"],
            "objects": {
                "classes": [{"id": "patient", "name": "患者"}],
                "slots": slots,
                "learning": learning.clone()
            }
        });
        SiteSpec::from_json(&spec.to_string()).expect("test spec")
    }

    /// The learning settings the tests use: no automatic tightening or pausing moves the entries.
    fn quiet() -> Value {
        json!({"auto_tighten": false, "auto_pause": false})
    }

    /// `count` allowed uses of `method path` from `sessions` sessions, each a day apart in turn and
    /// each shown at `source` (the request and the response position of the value).
    #[allow(clippy::too_many_arguments)]
    async fn traffic(
        pool: &PgPool,
        now: i64,
        count: i64,
        sessions: i64,
        method: &str,
        path: &str,
        value_slot: &str,
        source: (&str, &str),
    ) {
        for index in 0..count {
            let at_millis = now - (1 + index / sessions) * DAY_MILLIS;
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
                    "slot": value_slot,
                    "sources": [{"field": "id", "request": source.0, "slot": source.1}]
                }],
                "timing": {"judge_ms": 1}
            });
            sqlx::query(
                "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                    method, path, status, decision_path, outcome, trace)
                 VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                    $4, $5, 200, 'fast_allow', 'allowed', $6)",
            )
            .bind(at_millis)
            .bind(format!("req_{method}{}_{index:08}", path.replace('/', "_")))
            .bind(format!("s{}", index % sessions))
            .bind(method)
            .bind(path)
            .bind(trace)
            .execute(pool)
            .await
            .expect("insert a decision row");
        }
    }

    async fn proposal_of(pool: &PgPool, slot: &str) -> Option<Proposal> {
        judgements::proposal(pool, "clinic", slot)
            .await
            .expect("read the proposal")
    }

    /// `clinic`, with the user identity the lab's base configuration declares: the `id` of `GET /api/me`.
    fn clinic_with_users(requests: &[(&str, Value)], learning: &Value) -> SiteSpec {
        let mut slots = vec![
            json!({"key": SEARCH, "class": "patient", "source": "admin", "tier": "public"}),
            json!({"key": OWN, "class": "patient", "source": "admin", "tier": "self"}),
            json!({"key": "GET /api/me user.id", "class": "patient", "source": "admin", "identity": "user"}),
        ];
        for (key, judgement) in requests {
            let mut entry = json!({"key": key, "class": "patient", "source": "admin"});
            if let Value::Object(fields) = judgement {
                for (field, value) in fields {
                    entry[field] = value.clone();
                }
            }
            slots.push(entry);
        }
        let spec = json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"],
            "objects": {
                "classes": [{"id": "patient", "name": "患者"}],
                "slots": slots,
                "learning": learning.clone()
            }
        });
        SiteSpec::from_json(&spec.to_string()).expect("test spec")
    }

    /// The sessions that make the uses of one position in `traffic_of_users`: `count` uses from
    /// `sessions` sessions, `users` users among them, and the first `admins` sessions showing the
    /// administrator role.
    #[derive(Clone, Copy)]
    struct Crowd {
        count: i64,
        sessions: i64,
        users: i64,
        admins: i64,
    }

    /// `traffic`, where session `s<k>` shows the user `u<k % users>`, and the first `admins` sessions
    /// the administrator role, as the decision records of an identified site carry them.
    async fn traffic_of_users(
        pool: &PgPool,
        now: i64,
        crowd: Crowd,
        method: &str,
        path: &str,
        value_slot: &str,
        source: (&str, &str),
    ) {
        for index in 0..crowd.count {
            let at_millis = now - (1 + index / crowd.sessions) * DAY_MILLIS;
            let session = index % crowd.sessions;
            let mut identity = json!({"user": format!("u{}", session % crowd.users)});
            if session < crowd.admins {
                identity["role"] = json!("admin");
            }
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
                    "slot": value_slot,
                    "sources": [{"field": "id", "request": source.0, "slot": source.1}]
                }],
                "timing": {"judge_ms": 1},
                "session": {"age_seconds": 1, "known_values": 0, "identity": identity}
            });
            sqlx::query(
                "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                    method, path, status, decision_path, outcome, trace)
                 VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                    $4, $5, 200, 'fast_allow', 'allowed', $6)",
            )
            .bind(at_millis)
            .bind(format!("req_{method}{}_{index:08}", path.replace('/', "_")))
            .bind(format!("s{session}"))
            .bind(method)
            .bind(path)
            .bind(trace)
            .execute(pool)
            .await
            .expect("insert a decision row");
        }
    }

    #[tokio::test]
    async fn an_identified_site_proposes_high_for_a_position_fed_only_by_its_own_values() {
        let Some((admin, pool, name)) = scratch("accepts_identified").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic_with_users(&[(SHARE, json!({})), (DELETE, json!({}))], &quiet()),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        // Forty uses of each position from twenty sessions of ten users: the doubled thresholds of
        // users and votes, so the rules reach high.
        let crowd = Crowd {
            count: 40,
            sessions: 20,
            users: 10,
            admins: 0,
        };
        traffic_of_users(
            &pool,
            now,
            crowd,
            "GET",
            "/api/share/7",
            SHARE,
            ("GET /api/search", SEARCH),
        )
        .await;
        traffic_of_users(
            &pool,
            now,
            crowd,
            "DELETE",
            "/api/patients/7",
            DELETE,
            ("GET /api/patients", OWN),
        )
        .await;
        learn_once(&pool, None, now).await;

        let delete = proposal_of(&pool, DELETE)
            .await
            .expect("the delete is proposed");
        assert!(!delete.accepts_public);
        assert_eq!(delete.reliability, Reliability::High);
        assert_eq!((delete.votes, delete.sessions), (40, 10));
        let share = proposal_of(&pool, SHARE)
            .await
            .expect("the share is proposed");
        assert!(share.accepts_public);
        assert_eq!(share.reliability, Reliability::High);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn the_sessions_of_one_user_are_one_unit_on_an_identified_site() {
        let Some((admin, pool, name)) = scratch("accepts_one_user").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic_with_users(&[(DELETE, json!({}))], &quiet()),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        // Forty uses from twenty sessions, all of one user: one unit, below the sessions threshold.
        let crowd = Crowd {
            count: 40,
            sessions: 20,
            users: 1,
            admins: 0,
        };
        traffic_of_users(
            &pool,
            now,
            crowd,
            "DELETE",
            "/api/patients/7",
            DELETE,
            ("GET /api/patients", OWN),
        )
        .await;
        learn_once(&pool, None, now).await;
        assert!(proposal_of(&pool, DELETE).await.is_none());
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn the_votes_of_administrator_sessions_are_left_out_on_an_identified_site() {
        let Some((admin, pool, name)) = scratch("accepts_admins").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic_with_users(&[(DELETE, json!({}))], &quiet()),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        // The first ten of the twenty sessions show the administrator role: their twenty votes are
        // left out, so the other twenty are all that count.
        let crowd = Crowd {
            count: 40,
            sessions: 20,
            users: 10,
            admins: 10,
        };
        traffic_of_users(
            &pool,
            now,
            crowd,
            "DELETE",
            "/api/patients/7",
            DELETE,
            ("GET /api/patients", OWN),
        )
        .await;
        learn_once(&pool, None, now).await;
        let delete = proposal_of(&pool, DELETE)
            .await
            .expect("the delete is proposed");
        assert_eq!((delete.votes, delete.sessions), (20, 10));
        assert_eq!(delete.reliability, Reliability::Medium);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_position_fed_by_public_positions_is_proposed_as_accepting_them() {
        let Some((admin, pool, name)) = scratch("accepts_judged").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&[(SHARE, json!({})), (DELETE, json!({}))], &quiet()),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        // Forty uses from ten sessions of each position: the thresholds the rules double.
        traffic(
            &pool,
            now,
            40,
            10,
            "GET",
            "/api/share/7",
            SHARE,
            ("GET /api/search", SEARCH),
        )
        .await;
        traffic(
            &pool,
            now,
            40,
            10,
            "DELETE",
            "/api/patients/7",
            DELETE,
            ("GET /api/patients", OWN),
        )
        .await;
        learn_once(&pool, None, now).await;

        let share = proposal_of(&pool, SHARE)
            .await
            .expect("the share is proposed");
        assert!(share.accepts_public);
        // Without declared identities the rules grade one step lower than the evidence.
        assert_eq!(share.reliability, Reliability::Medium);
        assert_eq!((share.votes, share.sessions), (40, 10));
        assert_eq!(share.public_per_mille, 1000);
        let delete = proposal_of(&pool, DELETE)
            .await
            .expect("the delete is proposed");
        assert!(
            !delete.accepts_public,
            "a self-fed position refuses public sources"
        );
        assert_eq!(delete.public_per_mille, 0);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_judgement_the_entry_carries_is_not_proposed_again() {
        let Some((admin, pool, name)) = scratch("accepts_carried").await else {
            return;
        };
        let now = crate::params::now_millis();
        let carried = json!({"accepts_public": true, "reliability": "medium"});
        site_spec_store::create(
            &pool,
            &clinic(&[(SHARE, carried), (DELETE, json!({}))], &quiet()),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        traffic(
            &pool,
            now,
            40,
            10,
            "GET",
            "/api/share/7",
            SHARE,
            ("GET /api/search", SEARCH),
        )
        .await;
        traffic(
            &pool,
            now,
            40,
            10,
            "DELETE",
            "/api/patients/7",
            DELETE,
            ("GET /api/patients", OWN),
        )
        .await;
        learn_once(&pool, None, now).await;

        assert!(
            proposal_of(&pool, SHARE).await.is_none(),
            "the configuration already says what the rules give"
        );
        assert!(proposal_of(&pool, DELETE).await.is_some());
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_dismissed_proposal_waits_for_the_other_value() {
        let Some((admin, pool, name)) = scratch("accepts_dismissed").await else {
            return;
        };
        let now = crate::params::now_millis();
        let created =
            site_spec_store::create(&pool, &clinic(&[(SHARE, json!({}))], &quiet()), None)
                .await
                .expect("create the site");
        partitions(&pool, now).await;
        traffic(
            &pool,
            now,
            40,
            10,
            "GET",
            "/api/share/7",
            SHARE,
            ("GET /api/search", SEARCH),
        )
        .await;
        learn_once(&pool, None, now).await;
        assert!(proposal_of(&pool, SHARE).await.is_some());

        assert!(
            judgements::dismiss(&pool, "clinic", created.created_at, SHARE, now)
                .await
                .expect("dismiss the proposal")
        );
        // The same value, again: the rules do not propose it while the evidence agrees.
        learn_once(&pool, None, now + 60 * 60_000).await;
        assert!(proposal_of(&pool, SHARE).await.is_none());

        // The other value is a new proposal, and it is listed.
        let other = Proposal {
            slot: SHARE.to_owned(),
            accepts_public: false,
            reliability: Reliability::Medium,
            votes: 40,
            sessions: 10,
            public_per_mille: 0,
            last_day: 0,
        };
        judgements::put(&pool, "clinic", created.created_at, &other, now)
            .await
            .expect("propose the other value");
        assert_eq!(
            proposal_of(&pool, SHARE)
                .await
                .map(|proposal| proposal.accepts_public),
            Some(false)
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_position_the_configuration_no_longer_declares_loses_its_proposal() {
        let Some((admin, pool, name)) = scratch("accepts_retained").await else {
            return;
        };
        let now = crate::params::now_millis();
        let created = site_spec_store::create(
            &pool,
            &clinic(&[(SHARE, json!({})), (DELETE, json!({}))], &quiet()),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        traffic(
            &pool,
            now,
            40,
            10,
            "GET",
            "/api/share/7",
            SHARE,
            ("GET /api/search", SEARCH),
        )
        .await;
        traffic(
            &pool,
            now,
            40,
            10,
            "DELETE",
            "/api/patients/7",
            DELETE,
            ("GET /api/patients", OWN),
        )
        .await;
        learn_once(&pool, None, now).await;
        assert!(proposal_of(&pool, DELETE).await.is_some());

        // The administrator takes the delete position out of the configuration.
        site_spec_store::write(
            &pool,
            "clinic",
            &clinic(&[(SHARE, json!({}))], &quiet()),
            created.version,
            Change::Update,
            None,
        )
        .await
        .expect("save the configuration without the delete position");
        learn_once(&pool, None, now + 60 * 60_000).await;
        assert!(proposal_of(&pool, DELETE).await.is_none());
        assert!(proposal_of(&pool, SHARE).await.is_some());
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn deleting_a_site_forgets_its_judgements() {
        let Some((admin, pool, name)) = scratch("accepts_forgotten").await else {
            return;
        };
        let now = crate::params::now_millis();
        let created =
            site_spec_store::create(&pool, &clinic(&[(SHARE, json!({}))], &quiet()), None)
                .await
                .expect("create the site");
        judgements::put(
            &pool,
            "clinic",
            created.created_at,
            &Proposal {
                slot: SHARE.to_owned(),
                accepts_public: true,
                reliability: Reliability::Medium,
                votes: 40,
                sessions: 10,
                public_per_mille: 1000,
                last_day: 0,
            },
            now,
        )
        .await
        .expect("propose a judgement");
        let deleted = site_spec_store::delete(&pool, "clinic", created.version, None)
            .await
            .expect("delete the site");
        assert!(matches!(
            deleted,
            site_spec_store::DeleteOutcome::Deleted { .. }
        ));
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM object_judgements WHERE site = 'clinic'")
                .fetch_one(&pool)
                .await
                .expect("count the judgements");
        assert_eq!(rows, 0);
        drop_scratch(admin, pool, name).await;
    }
}

/// The tier pass: response positions judged from what their units saw, and proposed as tiers. Each test
/// runs against a scratch database and returns at once without `XSHIELD_TEST_DATABASE_BASE_URL`.
#[cfg(test)]
mod tier_pass_tests {
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use xshield_core::context::{Reliability, SiteSpec, Tier};
    use xshield_postgres::{object_tier_judgement_store as tier_judgements, site_spec_store};

    use super::learn_once;
    use super::pass_tests::{drop_scratch, partitions, scratch};
    use crate::params::DAY_MILLIS;

    /// A response position whose units see the same values: a public one.
    const SHARED: &str = "GET /api/search [].id";
    /// A response position whose units each see values of their own: a self one.
    const OWN: &str = "GET /api/patients [].id";
    /// A response position shown the same values as `SHARED`, whose entry already says so.
    const CARRIED: &str = "GET /api/feed [].id";

    /// A clinic whose response positions are declared as given, each with the fields its entry states.
    fn clinic(positions: &[(&str, Value)]) -> SiteSpec {
        let slots: Vec<Value> = positions
            .iter()
            .map(|(key, judgement)| {
                let mut entry = json!({"key": key, "class": "patient", "source": "admin"});
                if let Value::Object(fields) = judgement {
                    for (field, value) in fields {
                        entry[field] = value.clone();
                    }
                }
                entry
            })
            .collect();
        let spec = json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"],
            "objects": {
                "classes": [{"id": "patient", "name": "患者"}],
                "slots": slots,
                "learning": {"auto_tighten": false, "auto_pause": false}
            }
        });
        SiteSpec::from_json(&spec.to_string()).expect("test spec")
    }

    /// One allowed request of `session` at `at_millis` whose response showed `values` at `slot`. Each
    /// request has an id of its own, `index` numbers them.
    async fn shown(
        pool: &PgPool,
        index: i64,
        session: i64,
        at_millis: i64,
        slot: &str,
        values: &[String],
    ) {
        let trace = json!({
            "v": 1,
            "values_truncated": false,
            "values": [],
            "timing": {"judge_ms": 1},
            "response": {
                "bytes": 64,
                "observed": "json",
                "values": values.len(),
                "new_values": 0,
                "fields": [],
                "entry_passed": false,
                "after_would_block": false,
                "fingerprints": {slot: values}
            }
        });
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace)
             VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                'GET', '/api/feed', 200, 'fast_allow', 'allowed', $4)",
        )
        .bind(at_millis)
        .bind(format!("tier_{index:08}"))
        .bind(format!("s{session}"))
        .bind(trace)
        .execute(pool)
        .await
        .expect("insert a decision row");
    }

    /// Ten sessions, five requests each. `SHARED` and `CARRIED` show every session the same 25 values, five
    /// per request. `OWN` shows each session 25 values of its own.
    async fn traffic(pool: &PgPool, at_millis: i64, positions: &[&str]) {
        let shared: Vec<String> = (0..25).map(|index| format!("shared-{index}")).collect();
        for session in 0..10_i64 {
            for request in 0..5_usize {
                let row = session * 5 + i64::try_from(request).unwrap_or(0);
                let chunk = &shared[request * 5..request * 5 + 5];
                let own: Vec<String> = (0..5)
                    .map(|value| format!("own-{session}-{request}-{value}"))
                    .collect();
                for position in positions {
                    let values = if *position == OWN { &own[..] } else { chunk };
                    let offset = match *position {
                        SHARED => 0,
                        CARRIED => 100,
                        _ => 200,
                    };
                    shown(pool, row + offset, session, at_millis, position, values).await;
                }
            }
        }
    }

    #[tokio::test]
    async fn a_position_its_units_share_is_proposed_public_and_one_they_keep_apart_self() {
        let Some((admin, pool, name)) = scratch("tiers_judged").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&[
                // The entry says `self`, but every unit sees the same values here.
                (SHARED, json!({"tier": "self"})),
                // The entry says nothing, and every unit sees values of its own.
                (OWN, json!({})),
                // The entry carries what the rules give for it: nothing is proposed.
                (CARRIED, json!({"tier": "public", "reliability": "medium"})),
            ]),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        traffic(&pool, now - 2 * DAY_MILLIS, &[SHARED, OWN, CARRIED]).await;
        learn_once(&pool, None, now).await;

        let shared = tier_judgements::proposal(&pool, "clinic", SHARED)
            .await
            .expect("read the proposal")
            .expect("the shared position is proposed");
        assert_eq!(shared.tier, Tier::Public);
        // Without declared identities the rules grade one step lower than the evidence.
        assert_eq!(shared.reliability, Reliability::Medium);
        assert_eq!((shared.units, shared.seen_values), (10, 25));
        assert_eq!(shared.agreement_per_mille, 1000);

        let own = tier_judgements::proposal(&pool, "clinic", OWN)
            .await
            .expect("read the proposal")
            .expect("the unit-own position is proposed");
        assert_eq!(own.tier, Tier::Own);
        assert_eq!(own.reliability, Reliability::Medium);
        assert_eq!((own.units, own.seen_values), (10, 250));
        assert_eq!(own.agreement_per_mille, 1000);

        assert!(
            tier_judgements::proposal(&pool, "clinic", CARRIED)
                .await
                .expect("read the proposal")
                .is_none(),
            "a tier the entry carries is not proposed again"
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_tier_proposal_whose_evidence_ages_out_is_withdrawn() {
        let Some((admin, pool, name)) = scratch("tiers_aged").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(&[(SHARED, json!({"tier": "self"}))]), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        traffic(&pool, now - 2 * DAY_MILLIS, &[SHARED]).await;
        learn_once(&pool, None, now).await;
        assert!(
            tier_judgements::proposal(&pool, "clinic", SHARED)
                .await
                .expect("read the proposal")
                .is_some(),
            "the shared position is proposed first"
        );

        // Eight days on, the evidence is outside the window: the rules judge nothing, and the proposal goes.
        learn_once(&pool, None, now + 8 * DAY_MILLIS).await;
        assert!(
            tier_judgements::proposal(&pool, "clinic", SHARED)
                .await
                .expect("read the proposal")
                .is_none(),
            "a proposal whose evidence aged out is withdrawn"
        );
        drop_scratch(admin, pool, name).await;
    }
}

#[cfg(test)]
mod source_pass_tests {
    use super::pass_tests::{drop_scratch, partitions, scratch};
    use super::*;

    /// The response position a patient's search results are shown at.
    const SEARCH: &str = "GET /api/search results[].id";
    /// The request position of a patient, declared.
    const PATIENT: &str = "GET /patients/{id} path[1]";

    /// The clinic site. It declares `PATIENT` as a patient, and `SEARCH` as one too when `declare_search`.
    fn clinic(declare_search: bool) -> SiteSpec {
        let mut slots =
            vec![serde_json::json!({"key": PATIENT, "class": "patient", "source": "admin"})];
        if declare_search {
            slots.push(serde_json::json!({"key": SEARCH, "class": "patient", "source": "admin"}));
        }
        let spec = serde_json::json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"],
            "objects": {
                "classes": [{"id": "patient", "name": "患者"}],
                "slots": slots
            }
        });
        SiteSpec::from_json(&spec.to_string()).expect("test spec")
    }

    /// One use of `GET /patients/7` by session `index % 5`, on the day `1 + index / 5` days before `now`, whose
    /// value `7` was shown at the response position `from`. Twenty uses from five sessions fall on distinct
    /// days inside the window.
    async fn use_of(pool: &PgPool, index: i64, now: i64, from: &str) {
        let at_millis = now - (1 + index / 5) * DAY_MILLIS;
        let trace = serde_json::json!({
            "v": 1,
            "values_truncated": false,
            "values": [{
                "at": "path[1]",
                "value": "7",
                "kind": "reference",
                "inert": false,
                "seen": true,
                "verified": true,
                "slot": PATIENT,
                "sources": [{"field": "id", "request": "GET /api/search", "slot": from}]
            }],
            "timing": {"judge_ms": 1}
        });
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace)
             VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                'GET', '/patients/7', 200, 'fast_allow', 'allowed', $4)",
        )
        .bind(at_millis)
        .bind(format!("req_{index:032x}"))
        .bind(format!("s{}", index % 5))
        .bind(trace)
        .execute(pool)
        .await
        .expect("insert a decision row");
    }

    /// The state, class and side of the site's row for `slot`, when it has one.
    async fn row_of(pool: &PgPool, slot: &str) -> Option<(String, Option<String>, String)> {
        sqlx::query_as::<_, (String, Option<String>, String)>(
            "SELECT state, class, side FROM object_positions WHERE site = 'clinic' AND slot = $1",
        )
        .bind(slot)
        .fetch_optional(pool)
        .await
        .expect("read the position")
    }

    async fn proposed(pool: &PgPool) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM object_positions WHERE site = 'clinic' AND state = 'proposed'",
        )
        .fetch_one(pool)
        .await
        .expect("count the proposals")
    }

    /// Twenty uses from five sessions whose values were shown at `from`, read by one pass at `now`.
    async fn learn_uses(pool: &PgPool, now: i64, from: &str) {
        for index in 0..20 {
            use_of(pool, index, now, from).await;
        }
        learn_once(pool, None, now).await;
    }

    fn proposed_as_patient() -> (String, Option<String>, String) {
        (
            "proposed".to_owned(),
            Some("patient".to_owned()),
            "response".to_owned(),
        )
    }

    #[tokio::test]
    async fn the_values_patient_uses_show_at_a_response_position_are_proposed_as_patients() {
        let Some((admin, pool, name)) = scratch("source_proposal").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(false), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        learn_uses(&pool, now, SEARCH).await;
        assert_eq!(row_of(&pool, SEARCH).await, Some(proposed_as_patient()));
        // The next pass reads nothing new and the evidence still stands, so the proposal stays.
        learn_once(&pool, None, now + 60 * 60_000).await;
        assert_eq!(row_of(&pool, SEARCH).await, Some(proposed_as_patient()));
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_response_proposal_is_withdrawn_when_its_evidence_ages_out() {
        let Some((admin, pool, name)) = scratch("source_aged_out").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(false), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        learn_uses(&pool, now, SEARCH).await;
        assert_eq!(row_of(&pool, SEARCH).await, Some(proposed_as_patient()));
        // Eight days later no use is in the window, and no new row has arrived.
        learn_once(&pool, None, now + 8 * DAY_MILLIS).await;
        assert_eq!(
            row_of(&pool, SEARCH)
                .await
                .map(|(state, class, _)| (state, class)),
            Some(("pending".to_owned(), None))
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_response_proposal_stays_while_its_evidence_holds() {
        let Some((admin, pool, name)) = scratch("source_holds").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(false), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        learn_uses(&pool, now, SEARCH).await;
        assert_eq!(row_of(&pool, SEARCH).await, Some(proposed_as_patient()));
        // The next round still sees the same uses in the window, so the proposal is kept.
        learn_once(&pool, None, now + DAY_MILLIS).await;
        assert_eq!(row_of(&pool, SEARCH).await, Some(proposed_as_patient()));
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_declared_response_position_is_not_proposed() {
        let Some((admin, pool, name)) = scratch("source_declared").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(true), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        learn_uses(&pool, now, SEARCH).await;
        assert_eq!(proposed(&pool).await, 0);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_response_proposal_the_administrator_declares_is_withdrawn() {
        let Some((admin, pool, name)) = scratch("source_declared_later").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(false), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        learn_uses(&pool, now, SEARCH).await;
        assert_eq!(row_of(&pool, SEARCH).await, Some(proposed_as_patient()));
        // The administrator confirms the proposal: the entry declares the position as a patient.
        let record = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        site_spec_store::write(
            &pool,
            "clinic",
            &clinic(true),
            record.version,
            Change::Update,
            None,
        )
        .await
        .expect("write the confirmed entry");
        learn_once(&pool, None, now + 60 * 60_000).await;
        assert_eq!(
            row_of(&pool, SEARCH)
                .await
                .map(|(state, class, _)| (state, class)),
            Some(("pending".to_owned(), None))
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_response_field_that_is_not_an_identifier_is_not_proposed() {
        let Some((admin, pool, name)) = scratch("source_field").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(&pool, &clinic(false), None)
            .await
            .expect("create the site");
        partitions(&pool, now).await;
        learn_uses(&pool, now, "GET /api/search page").await;
        assert_eq!(proposed(&pool).await, 0);
        drop_scratch(admin, pool, name).await;
    }
}

#[cfg(test)]
mod function_pass_tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use serde_json::{Value, json};
    use sqlx::PgPool;
    use xshield_core::context::learning::{FUNCTION_KEYS_MAX, FunctionFact, WINDOW_DAYS, day_of};
    use xshield_core::context::{Reliability, SiteSpec, Tier};
    use xshield_postgres::{
        object_function_store as function_store, object_tier_judgement_store as tier_judgements,
        site_spec_store,
    };

    use super::pass_tests::{drop_scratch, partitions, scratch};
    use super::{judge_functions, learn_once};
    use crate::params::DAY_MILLIS;

    /// The function the administrator alone uses in most tests.
    const SEARCH: &str = "GET /api/admin/search";
    /// Another function only administrators use, in the test that reads one key at a time.
    const EXPORT: &str = "GET /api/admin/export";
    /// The function ordinary users use.
    const FEED: &str = "GET /api/feed";
    /// A response position that the ordinary users all see the same values at.
    const SHARED: &str = "GET /api/search [].id";

    /// A clinic that declares a user and a role identity and the response position `SHARED`, with the
    /// learning settings `learning`.
    fn clinic(learning: &Value) -> SiteSpec {
        let spec = json!({
            "name": "clinic",
            "hosts": ["clinic.example.com"],
            "origin": "http://10.0.0.5:8080",
            "session": {"cookie": "SESSIONID"},
            "entries": ["/login"],
            "objects": {
                "classes": [{"id": "patient", "name": "患者"}],
                "slots": [
                    {"key": "GET /api/me user.id", "class": "patient", "source": "admin", "identity": "user"},
                    {"key": "GET /api/me role", "class": "patient", "source": "admin", "identity": "role"},
                    {"key": SHARED, "class": "patient", "source": "admin"}
                ],
                "learning": learning
            }
        });
        SiteSpec::from_json(&spec.to_string()).expect("test spec")
    }

    /// One allowed request as the gateway logs it: the session that made it, the identity the session
    /// showed, and what it asked.
    struct Call<'a> {
        session: &'a str,
        user: Option<&'a str>,
        role: Option<&'a str>,
        method: &'a str,
        path: &'a str,
        entry: bool,
    }

    /// A row id of its own, unique across the tests of the process.
    fn next_request_id() -> String {
        static NEXT: AtomicI64 = AtomicI64::new(0);
        format!("fn_{:08}", NEXT.fetch_add(1, Ordering::Relaxed))
    }

    /// Inserts one allowed decision row of `method path` made by `session` at `at_millis`, with `trace`.
    async fn insert(
        pool: &PgPool,
        at_millis: i64,
        session: &str,
        method: &str,
        path: &str,
        trace: Value,
    ) {
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace)
             VALUES ($1, $2, 'clinic', 'edge-1', 'clinic.example.com', '10.0.0.1', $3,
                $4, $5, 200, 'fast_allow', 'allowed', $6)",
        )
        .bind(at_millis)
        .bind(next_request_id())
        .bind(session)
        .bind(method)
        .bind(path)
        .bind(trace)
        .execute(pool)
        .await
        .expect("insert a decision row");
    }

    /// Logs `call` as made at `at_millis`, by a request the origin answered 200 and the gateway allowed.
    async fn log(pool: &PgPool, at_millis: i64, call: &Call<'_>) {
        let mut trace = json!({
            "v": 1,
            "values_truncated": false,
            "values": [],
            "timing": {"judge_ms": 1},
            "session": {
                "age_seconds": 1,
                "known_values": 0,
                "identity": {"user": call.user, "role": call.role}
            }
        });
        if call.entry {
            trace["entry"] = json!("/login");
        }
        insert(pool, at_millis, call.session, call.method, call.path, trace).await;
    }

    /// The administrator `root` makes `function` (`METHOD path`) on two days, on an entry when `entry` is set.
    async fn admin_uses(pool: &PgPool, now: i64, function: &str, entry: bool) {
        let (method, path) = function
            .split_once(' ')
            .expect("a function is `METHOD path`");
        for days in [2_i64, 3] {
            let call = Call {
                session: "adm",
                user: Some("root"),
                role: Some("admin"),
                method,
                path,
                entry,
            };
            log(pool, now - days * DAY_MILLIS, &call).await;
        }
    }

    /// Ten ordinary users each use `FEED` once, so the window holds ten ordinary units.
    async fn ten_users_use_feed(pool: &PgPool, now: i64) {
        for user in 0..10_i64 {
            let name = format!("u{user}");
            let session = format!("s{user}");
            let call = Call {
                session: &session,
                user: Some(&name),
                role: Some("user"),
                method: "GET",
                path: "/api/feed",
                entry: false,
            };
            log(pool, now - 2 * DAY_MILLIS, &call).await;
        }
    }

    /// One request of ordinary user `user` at `at_millis`, whose response showed `values` at `SHARED`.
    async fn shown_to(pool: &PgPool, at_millis: i64, user: i64, values: &[String]) {
        let name = format!("u{user}");
        let trace = json!({
            "v": 1,
            "values_truncated": false,
            "values": [],
            "timing": {"judge_ms": 1},
            "session": {
                "age_seconds": 1,
                "known_values": 0,
                "identity": {"user": name, "role": "user"}
            },
            "response": {
                "bytes": 64,
                "observed": "json",
                "values": values.len(),
                "new_values": 0,
                "fields": [],
                "entry_passed": false,
                "after_would_block": false,
                "fingerprints": {SHARED: values}
            }
        });
        insert(
            pool,
            at_millis,
            &format!("s{user}"),
            "GET",
            "/api/search",
            trace,
        )
        .await;
    }

    /// Ten ordinary users each see the same 25 values at `SHARED`, five per request, on two days, so the tier
    /// pass proposes the position.
    async fn shared_position(pool: &PgPool, now: i64) {
        let values: Vec<String> = (0..25).map(|index| format!("shared-{index}")).collect();
        for user in 0..10_i64 {
            for request in 0..5_usize {
                let chunk = &values[request * 5..request * 5 + 5];
                shown_to(pool, now - 2 * DAY_MILLIS, user, chunk).await;
            }
        }
    }

    /// Whether the site carries an open proposal for `key`.
    async fn proposed(pool: &PgPool, key: &str) -> bool {
        tier_judgements::proposal(pool, "clinic", key)
            .await
            .expect("read the proposal")
            .is_some()
    }

    #[tokio::test]
    async fn a_function_only_admins_use_is_proposed_as_admin() {
        let Some((admin, pool, name)) = scratch("function_admin").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        admin_uses(&pool, now, SEARCH, false).await;
        ten_users_use_feed(&pool, now).await;
        learn_once(&pool, None, now).await;

        let proposal = tier_judgements::proposal(&pool, "clinic", SEARCH)
            .await
            .expect("read the proposal")
            .expect("the function only the administrator uses is proposed");
        assert_eq!(proposal.tier, Tier::Admin);
        assert_eq!(proposal.reliability, Reliability::High);
        assert_eq!(proposal.units, 1);
        assert!(
            tier_judgements::proposal(&pool, "clinic", FEED)
                .await
                .expect("read the proposal")
                .is_none(),
            "a function ordinary users use is not proposed"
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_function_an_ordinary_user_uses_is_not_proposed() {
        let Some((admin, pool, name)) = scratch("function_ordinary").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        admin_uses(&pool, now, SEARCH, false).await;
        ten_users_use_feed(&pool, now).await;
        // One ordinary user also uses the administrator's function.
        let user = Call {
            session: "s0",
            user: Some("u0"),
            role: Some("user"),
            method: "GET",
            path: "/api/admin/search",
            entry: false,
        };
        log(&pool, now - 2 * DAY_MILLIS, &user).await;
        learn_once(&pool, None, now).await;
        assert!(
            tier_judgements::proposal(&pool, "clinic", SEARCH)
                .await
                .expect("read the proposal")
                .is_none(),
            "a function an ordinary unit uses is not proposed"
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn an_entry_is_never_proposed() {
        let Some((admin, pool, name)) = scratch("function_entry").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        admin_uses(&pool, now, SEARCH, true).await;
        ten_users_use_feed(&pool, now).await;
        learn_once(&pool, None, now).await;
        assert!(
            tier_judgements::proposal(&pool, "clinic", SEARCH)
                .await
                .expect("read the proposal")
                .is_none(),
            "a function used on an entry is never proposed"
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn slug_paths_are_judged_as_one_function() {
        let Some((admin, pool, name)) = scratch("function_slugs").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        for index in 0..12 {
            admin_uses(
                &pool,
                now,
                &format!("POST /admin/users/member{index}/ban"),
                false,
            )
            .await;
        }
        ten_users_use_feed(&pool, now).await;
        learn_once(&pool, None, now).await;

        let proposed: Vec<String> = tier_judgements::proposals(&pool, "clinic")
            .await
            .expect("list the proposals")
            .into_iter()
            .map(|proposal| proposal.slot)
            .filter(|slot| slot.starts_with("POST "))
            .collect();
        assert_eq!(proposed, vec!["POST /admin/users/{id}/ban".to_owned()]);
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_function_proposal_is_withdrawn_when_its_evidence_ages_out() {
        let Some((admin, pool, name)) = scratch("function_aged").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        admin_uses(&pool, now, SEARCH, false).await;
        ten_users_use_feed(&pool, now).await;
        learn_once(&pool, None, now).await;
        assert!(
            proposed(&pool, SEARCH).await,
            "the function is proposed first"
        );

        // Eight days on, the evidence is outside the window: the rules judge nothing, and the proposal goes.
        learn_once(&pool, None, now + 8 * DAY_MILLIS).await;
        assert!(
            !proposed(&pool, SEARCH).await,
            "a proposal whose evidence aged out is withdrawn"
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_dismissed_function_proposal_stays_dismissed() {
        let Some((admin, pool, name)) = scratch("function_dismissed").await else {
            return;
        };
        let now = crate::params::now_millis();
        let record = site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        admin_uses(&pool, now, SEARCH, false).await;
        ten_users_use_feed(&pool, now).await;
        learn_once(&pool, None, now).await;
        assert!(
            tier_judgements::dismiss(&pool, "clinic", record.created_at, SEARCH, now)
                .await
                .expect("dismiss the proposal"),
            "the proposal is dismissed"
        );

        learn_once(&pool, None, now).await;
        assert!(
            !proposed(&pool, SEARCH).await,
            "a dismissed function is not proposed again"
        );
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM object_tier_judgements WHERE site = 'clinic' AND slot = $1",
        )
        .bind(SEARCH)
        .fetch_one(&pool)
        .await
        .expect("count the rows");
        assert_eq!(rows, 1, "the dismissed row stays");
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn tier_proposals_of_positions_survive_the_function_pass_and_the_other_way_round() {
        let Some((admin, pool, name)) = scratch("function_and_tiers").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        admin_uses(&pool, now, SEARCH, false).await;
        ten_users_use_feed(&pool, now).await;
        shared_position(&pool, now).await;
        learn_once(&pool, None, now).await;
        learn_once(&pool, None, now).await;

        assert!(
            proposed(&pool, SEARCH).await,
            "the function proposal survives the tier pass"
        );
        assert!(
            tier_judgements::proposal(&pool, "clinic", SHARED)
                .await
                .expect("read the proposal")
                .is_some(),
            "the position proposal survives the function pass"
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_site_with_learning_off_keeps_no_function_evidence() {
        let Some((admin, pool, name)) = scratch("function_off").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_learn": false, "auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        admin_uses(&pool, now, SEARCH, false).await;
        ten_users_use_feed(&pool, now).await;
        learn_once(&pool, None, now).await;

        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM object_response_evidence
             WHERE site = 'clinic' AND kind LIKE 'function%'",
        )
        .fetch_one(&pool)
        .await
        .expect("count the rows");
        assert_eq!(rows, 0, "no function evidence is kept");
        assert!(!proposed(&pool, SEARCH).await);
        drop_scratch(admin, pool, name).await;
    }

    /// Each of `users`, an administrator, logs in once two days ago. A login is an entry request: the function
    /// evidence counts it as an ordinary use of the entry, and as the administrator's use of it.
    async fn admin_logins(pool: &PgPool, now: i64, users: &[&str]) {
        for &user in users {
            let session = format!("login-{user}");
            let call = Call {
                session: &session,
                user: Some(user),
                role: Some("admin"),
                method: "POST",
                path: "/login",
                entry: true,
            };
            log(pool, now - 2 * DAY_MILLIS, &call).await;
        }
    }

    #[tokio::test]
    async fn administrators_on_entries_are_no_ordinary_bystanders() {
        let Some((admin, pool, name)) = scratch("function_entries").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        // Six administrators: `root` uses the administrator's function on two days, and the other five only log
        // in. There is no ordinary user. A login counts as an administrator's use too, so none of the six is a
        // bystander: neither the function nor the entry is proposed.
        admin_logins(&pool, now, &["root2", "root3", "root4", "root5", "root6"]).await;
        admin_uses(&pool, now, SEARCH, false).await;
        learn_once(&pool, None, now).await;
        assert!(
            !proposed(&pool, SEARCH).await,
            "an administrator who uses the function is no ordinary bystander"
        );
        assert!(
            !proposed(&pool, "POST /login").await,
            "an entry is never proposed, even when only administrators log in"
        );
        drop_scratch(admin, pool, name).await;
    }

    #[tokio::test]
    async fn a_site_with_more_function_keys_than_one_pass_reads_is_not_judged() {
        let Some((admin, pool, name)) = scratch("function_more").await else {
            return;
        };
        let now = crate::params::now_millis();
        site_spec_store::create(
            &pool,
            &clinic(&json!({"auto_tighten": false, "auto_pause": false})),
            None,
        )
        .await
        .expect("create the site");
        partitions(&pool, now).await;
        admin_uses(&pool, now, SEARCH, false).await;
        ten_users_use_feed(&pool, now).await;
        learn_once(&pool, None, now).await;
        assert!(
            proposed(&pool, SEARCH).await,
            "the first pass proposes the function only the administrator uses"
        );

        // A second administrator function that two administrators use, so it has more units and sorts first.
        // A limit of one reads it alone. A pass that judged that key would withdraw SEARCH, which it does not read.
        let site = site_spec_store::get(&pool, "clinic")
            .await
            .expect("read the site")
            .expect("the site exists");
        let today = day_of(u64::try_from(now).unwrap_or(0));
        let mut facts = Vec::new();
        for unit in ["root", "root2"] {
            for back in [2_u64, 3] {
                facts.push(FunctionFact::Admin {
                    function: EXPORT.to_owned(),
                    unit: unit.to_owned(),
                    day: today - back,
                });
            }
        }
        function_store::record_function_facts(&pool, "clinic", site.created_at, &facts)
            .await
            .expect("record the facts");
        let oldest_day = today.saturating_sub(WINDOW_DAYS - 1);
        let (_, more) = function_store::function_keys(&pool, "clinic", oldest_day, 1)
            .await
            .expect("list the keys");
        assert!(
            more,
            "two function keys have evidence and one pass reads one"
        );

        judge_functions(&pool, "clinic", site.created_at, oldest_day, 1, now)
            .await
            .expect("judge the functions");
        assert!(
            proposed(&pool, SEARCH).await,
            "a pass that does not read every key keeps the proposal it does not read"
        );
        assert!(
            !proposed(&pool, EXPORT).await,
            "a pass that does not read every key proposes nothing"
        );

        // Read every key, and the same evidence proposes both functions.
        judge_functions(
            &pool,
            "clinic",
            site.created_at,
            oldest_day,
            FUNCTION_KEYS_MAX,
            now,
        )
        .await
        .expect("judge the functions");
        assert!(proposed(&pool, SEARCH).await);
        assert!(
            proposed(&pool, EXPORT).await,
            "with every key read, the second function is proposed"
        );
        drop_scratch(admin, pool, name).await;
    }
}
