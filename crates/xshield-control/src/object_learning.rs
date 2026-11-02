//! The object-map learning pass of the control plane (docs/object-map-design.md
//! section 3). Each maintenance pass reads every site's decision log since the
//! site's cursor, counts the votes and refusals of the request positions, and
//! writes the state of each position the rules judged: a proposal for a position
//! the map does not know, or a confirmed position whose evidence now points at
//! other kinds (suspended). An administrator confirms a proposal. This pass never
//! changes a site configuration, and the judge does not read its states yet. A site
//! turns the pass off, or sets how much evidence a proposal needs, with its
//! `objects.learning` settings.

use std::collections::BTreeSet;

use sqlx::PgPool;
use xshield_core::context::learning::{
    Evidence, RETIRE_DAYS, Thresholds, WINDOW_DAYS, contradicts, day_of, kind_share, observe,
    propose,
};
use xshield_core::context::{LearningSettings, ObjectMap, SiteSpec};
use xshield_postgres::object_learning_store::{self as store, Judgement, LearnedState};
use xshield_postgres::site_spec_store;

use crate::params::DAY_MILLIS;

/// Decision rows this old are read. Newer rows may still be on their way from a gateway.
const LAG_MILLIS: i64 = 10 * 60 * 1_000;
/// Decision rows read per batch. A batch is held in memory, so this bounds the memory.
const BATCH_ROWS: i64 = 5_000;
/// Batches read per site in one pass. A site still behind resumes at its cursor next time.
const BATCHES_PER_PASS: usize = 20;

/// Runs one learning pass over every site at `now_millis`. A site that fails is
/// logged, and the other sites still run.
pub async fn learn_once(pool: &PgPool, now_millis: i64) {
    let records = match site_spec_store::list(pool).await {
        Ok(records) => records,
        Err(error) => {
            eprintln!("xshield-control: object learning skipped, {error}");
            return;
        }
    };
    for record in &records {
        if let Err(error) = learn_site(pool, &record.spec, now_millis).await {
            eprintln!(
                "xshield-control: object learning failed for site {}: {error}",
                record.spec.name()
            );
        }
    }
}

/// Reads one site's decision log from its cursor up to the lag horizon, batch by
/// batch, then prunes the evidence older than the window and retires the positions
/// no vote has reached for the retirement period.
///
/// A batch is recorded before its cursor moves, and recording is idempotent: when a
/// step fails, the next pass reads the same rows again and changes nothing twice.
async fn learn_site(
    pool: &PgPool,
    spec: &SiteSpec,
    now_millis: i64,
) -> Result<(), store::LearningStoreError> {
    let site = spec.name();
    if !spec.objects().learning().auto_learn {
        // A site with learning off keeps no evidence and gets no proposals. Its cursor
        // stays where it was, and the window below starts the next pass in range.
        return Ok(());
    }
    let horizon = now_millis - LAG_MILLIS;
    let today = day_of(u64::try_from(now_millis).unwrap_or(0));
    let oldest_day = today.saturating_sub(WINDOW_DAYS - 1);
    let window = i64::try_from(WINDOW_DAYS)
        .unwrap_or(0)
        .saturating_mul(DAY_MILLIS);
    let window_start = horizon.saturating_sub(window);
    let mut after = store::cursor(pool, site)
        .await?
        .map_or(window_start, |cursor| cursor.max(window_start));
    for _ in 0..BATCHES_PER_PASS {
        if after >= horizon {
            break;
        }
        let batch = store::read_batch(pool, site, after, horizon, BATCH_ROWS).await?;
        let complete = batch.rows < usize::try_from(BATCH_ROWS).unwrap_or(usize::MAX);
        let next = next_cursor(after, horizon, complete, batch.newest_millis);
        let mut votes = Vec::new();
        let mut denials = Vec::new();
        for facts in &batch.facts {
            let observed = observe(facts);
            votes.extend(observed.votes);
            denials.extend(observed.denials);
        }
        store::record_evidence(pool, site, &votes, &denials).await?;
        let slots: Vec<String> = votes
            .iter()
            .map(|vote| vote.slot.clone())
            .chain(denials.iter().map(|denial| denial.slot.clone()))
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        if !slots.is_empty() {
            let evidence = store::load_evidence(pool, site, &slots, oldest_day).await?;
            for slot in &slots {
                if let Some(evidence) = evidence.get(slot) {
                    judge(pool, spec, slot, evidence, today, now_millis).await?;
                }
            }
        }
        store::advance_cursor(pool, site, next, now_millis).await?;
        after = next;
        if complete {
            break;
        }
    }
    store::prune_evidence(pool, site, oldest_day).await?;
    store::retire_unseen(pool, site, today.saturating_sub(RETIRE_DAYS), now_millis).await?;
    Ok(())
}

/// Writes the state the rules give one position, when they give one.
async fn judge(
    pool: &PgPool,
    spec: &SiteSpec,
    slot: &str,
    evidence: &Evidence,
    today: u64,
    now_millis: i64,
) -> Result<(), store::LearningStoreError> {
    let Some(decision) = decide(slot, evidence, spec.objects(), today) else {
        return Ok(());
    };
    let judgement = Judgement {
        slot,
        state: decision.state,
        class: &decision.class,
        votes: decision.votes,
        sessions: decision.sessions,
        share_per_mille: decision.share_per_mille,
        last_day: decision.last_day,
    };
    store::put_judgement(pool, spec.name(), &judgement, now_millis).await
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
fn thresholds_of(learning: &LearningSettings) -> Thresholds {
    Thresholds {
        votes: learning.thresholds.uses,
        sessions: learning.thresholds.sessions,
        ..Thresholds::default()
    }
}

fn decide(slot: &str, evidence: &Evidence, map: &ObjectMap, today: u64) -> Option<Decision> {
    let thresholds = thresholds_of(map.learning());
    let last_day = evidence.last_day().unwrap_or(today);
    if let Some(class) = map.class_of(slot) {
        let state = if contradicts(class, evidence, map, thresholds) {
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
        last_day,
    })
}

/// The cursor after a batch. A batch that reached the horizon moves the cursor to
/// the horizon. A full batch moves it to one millisecond before its newest row, so
/// rows that share that time and did not fit are read again. Reading a row twice
/// changes nothing, and a full batch always moves the cursor forward.
fn next_cursor(after: i64, horizon: i64, complete: bool, newest: Option<i64>) -> i64 {
    match (complete, newest) {
        (true, _) | (false, None) => horizon,
        (false, Some(newest)) if newest - 1 > after => newest - 1,
        (false, Some(newest)) => newest,
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
    fn the_cursor_reaches_the_horizon_only_when_a_batch_was_complete() {
        // A short batch reached the horizon.
        assert_eq!(next_cursor(0, 100, true, Some(40)), 100);
        // A full batch stops one millisecond before its newest row.
        assert_eq!(next_cursor(0, 100, false, Some(50)), 49);
        // It always moves forward, even when the whole batch shares one time.
        assert_eq!(next_cursor(10, 100, false, Some(11)), 11);
        // An empty batch is complete.
        assert_eq!(next_cursor(0, 100, false, None), 100);
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
mod pass_tests {
    use super::*;
    use crate::MIGRATOR;
    use sqlx::{AssertSqlSafe, PgPool};

    async fn scratch(tag: &str) -> Option<(PgPool, PgPool, String)> {
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

    async fn drop_scratch(admin: PgPool, pool: PgPool, name: String) {
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
    fn clinic_with(learning: serde_json::Value) -> SiteSpec {
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
    async fn partitions(pool: &PgPool, now: i64) {
        for days in 0..=5 {
            let day = chrono::DateTime::from_timestamp_millis(now - days * DAY_MILLIS)
                .expect("a day")
                .date_naive();
            xshield_postgres::partitions::ensure_partition(pool, day)
                .await
                .expect("create the partition");
        }
    }

    /// One decision row of `GET /doctor/7`. Five sessions each make uses on their own
    /// days, so `index` gives a distinct (session, day) pair for each of twenty uses.
    async fn record(pool: &PgPool, index: i64, now: i64, path: &str, outcome: &str, status: i16) {
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
        .bind(now - (1 + index / 5) * DAY_MILLIS)
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
        learn_once(&pool, now).await;
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
        learn_once(&pool, now).await;
        let judged: i64 =
            sqlx::query_scalar("SELECT count(*) FROM object_positions WHERE site = 'clinic'")
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
        learn_once(&pool, now).await;
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
        learn_once(&pool, now).await;
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
}
