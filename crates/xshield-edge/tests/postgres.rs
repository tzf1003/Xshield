//! The `PostgreSQL` adapters against a real database (docs/07 sections 7.7.6
//! and 7.8.1). Skipped unless `XSHIELD_TEST_DATABASE_BASE_URL` (a server URL
//! without a database name) is set.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{AssertSqlSafe, PgPool, Row};
use xshield_core::context::{
    Api, Conclusion, ContextKind, DecisionPath, DecisionRecord, JevRecord, Outcome, Timing, Trace,
};
use xshield_edge::sink::{Counters, DecisionSink, Gap, now_millis, write_postgres};
use xshield_edge::sites::{ORIGIN_INVALID, SiteStatus, SiteTable};
use xshield_edge::source::{SiteLoader, SiteSource};
use xshield_edge::status::{self, Beat, Instance};
use xshield_judge::context::ContextKey;
use xshield_judge::engine::Judge;
use xshield_judge::jev::{JevFailure, JevPort};
use xshield_judge::state::Prompt;

// The tables the control plane owns (docs/07 section 7.8.1); the columns the
// edge reads and writes are the contract between the two processes. There is
// deliberately no default partition for `decision_log`.
const SCHEMA: &[&str] = &[
    "CREATE TABLE site_configs (name text PRIMARY KEY, spec jsonb NOT NULL, \
     version bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), \
     updated_at timestamptz NOT NULL DEFAULT now())",
    "CREATE TABLE decision_log (id bigint GENERATED ALWAYS AS IDENTITY, \
     at_millis bigint NOT NULL, request_id text NOT NULL, site text, site_version bigint, \
     edge text NOT NULL, host text NOT NULL, client text NOT NULL, \
     session text NOT NULL DEFAULT '', context text, method text NOT NULL, path text NOT NULL, \
     logical_path text, api jsonb, request_headers text[] NOT NULL DEFAULT '{}', \
     query text, status smallint, decision_path text NOT NULL, outcome text NOT NULL, \
     total_ms integer, jev_ms integer, jev_access text, jev_attack text, \
     jev_confidence real, jev_failure text, trace jsonb NOT NULL, jev jsonb, \
     PRIMARY KEY (at_millis, id)) PARTITION BY RANGE (at_millis)",
    "CREATE TABLE edge_status (edge text PRIMARY KEY, started_at timestamptz NOT NULL, \
     seen_at timestamptz NOT NULL, build text NOT NULL, listen text NOT NULL, \
     tls boolean NOT NULL, sites jsonb NOT NULL, sessions integer NOT NULL, \
     queue integer NOT NULL, written bigint NOT NULL, dropped bigint NOT NULL, \
     dropped_bypass bigint NOT NULL, write_errors bigint NOT NULL, gaps jsonb NOT NULL, \
     jev jsonb NOT NULL, params jsonb NOT NULL)",
    "CREATE TABLE jev_prompts (id text PRIMARY KEY, questions jsonb NOT NULL, \
     first_seen timestamptz NOT NULL DEFAULT now())",
];

const DAY_MS: i64 = 86_400_000;

/// A fresh database with the schema. `tag` names it, so tests in one process
/// never drop each other's database.
async fn database(tag: &str) -> Option<PgPool> {
    let base = std::env::var("XSHIELD_TEST_DATABASE_BASE_URL").ok()?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{base}/postgres"))
        .await
        .expect("admin connection");
    let name = format!("edge_test_{}_{tag}", std::process::id());
    sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name}")))
        .execute(&admin)
        .await
        .expect("drop");
    sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .expect("create");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&format!("{base}/{name}"))
        .await
        .expect("connect");
    for statement in SCHEMA {
        sqlx::query(*statement)
            .execute(&pool)
            .await
            .expect("schema");
    }
    Some(pool)
}

/// Creates the UTC day partition `decision_log_pYYYYMMDD` that holds
/// `at_millis`, as the control plane does (docs/07 section 7.8.2). The gateway
/// never does this itself.
async fn partition_for(pool: &PgPool, at_millis: i64) {
    let start = at_millis - at_millis.rem_euclid(DAY_MS);
    let day: String = sqlx::query_scalar(
        "SELECT to_char(to_timestamp($1::bigint::double precision / 1000) AT TIME ZONE 'UTC', \
         'YYYYMMDD')",
    )
    .bind(start)
    .fetch_one(pool)
    .await
    .expect("day name");
    sqlx::query(AssertSqlSafe(format!(
        "CREATE TABLE IF NOT EXISTS decision_log_p{day} PARTITION OF decision_log \
         FOR VALUES FROM ({start}) TO ({})",
        start + DAY_MS
    )))
    .execute(pool)
    .await
    .expect("partition");
}

fn now() -> i64 {
    i64::try_from(now_millis()).expect("the clock is in range")
}

fn spec(host: &str, origin: &str) -> serde_json::Value {
    json!({
        "name": "emr", "hosts": [host], "origin": origin,
        "session": {"cookie": "SID"}, "entries": ["/login"]
    })
}

fn judged(request_id: &str, at_millis: u64) -> DecisionRecord {
    DecisionRecord {
        at_millis,
        request_id: request_id.to_owned(),
        site: Some("emr".to_owned()),
        site_version: Some(3),
        edge: "edge-test".to_owned(),
        host: "emr.test".to_owned(),
        client: "192.0.2.7".to_owned(),
        session: "ab12cd34ef567890".to_owned(),
        context: Some(ContextKind::Session),
        method: "GET".to_owned(),
        path: "/api/patients/patient-D".to_owned(),
        logical_path: "/api/patients/patient-D/getPatient".to_owned(),
        api: Some(Api::Named {
            name: "getPatient".to_owned(),
            from: vec!["header.x-method".to_owned()],
        }),
        request_headers: vec![
            "accept".to_owned(),
            "x-method".to_owned(),
            "x-request-id".to_owned(),
        ],
        query: Some("page=2".to_owned()),
        status: Some(403),
        decision_path: DecisionPath::JevDeny,
        outcome: Outcome::Blocked,
        trace: Trace {
            timing: Timing {
                total_ms: Some(12),
                judge_ms: 9,
                origin_ms: None,
            },
            ..Trace::new()
        },
        jev: Some(JevRecord {
            prompt: "jq_0123456789abcdef".to_owned(),
            route: "fake".to_owned(),
            timeout_ms: 2000,
            millis: 12,
            access: BTreeMap::from([
                ("ALLOW".to_owned(), 0.2),
                ("DENY".to_owned(), 0.7),
                ("UNKNOWN".to_owned(), 0.1),
            ]),
            attack: BTreeMap::from([
                ("ATTACK".to_owned(), 0.05),
                ("BENIGN".to_owned(), 0.9),
                ("UNKNOWN".to_owned(), 0.05),
            ]),
            conclusion: Some(Conclusion::Deny),
            ..JevRecord::default()
        }),
    }
}

fn bypass(request_id: &str, at_millis: u64) -> DecisionRecord {
    DecisionRecord {
        request_id: request_id.to_owned(),
        decision_path: DecisionPath::Bypass,
        outcome: Outcome::Allowed,
        status: Some(200),
        path: "/assets/logo.png".to_owned(),
        logical_path: "/assets/logo.png".to_owned(),
        request_headers: Vec::new(),
        query: None,
        context: None,
        session: String::new(),
        trace: Trace {
            timing: Timing {
                total_ms: Some(6),
                judge_ms: 0,
                origin_ms: Some(5),
            },
            ..Trace::new()
        },
        jev: None,
        ..judged(request_id, at_millis)
    }
}

/// The Jev stand-in for the heartbeat test: never called, only described.
struct Unreachable;

#[async_trait]
impl JevPort for Unreachable {
    fn model(&self) -> &'static str {
        "fake-model"
    }
    fn route(&self) -> &'static str {
        "fake"
    }
    fn endpoint_host(&self) -> &'static str {
        "jev.test"
    }
    fn default_timeout(&self) -> Duration {
        Duration::from_millis(2000)
    }
    async fn ask(&self, _body: Vec<u8>, _timeout: Duration) -> Result<Vec<u8>, JevFailure> {
        Err(JevFailure::Timeout)
    }
}

/// Polls `check` for up to five seconds.
async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !check() {
        assert!(Instant::now() < deadline, "not reached within 5 s: {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn edge_sites(pool: &PgPool, edge: &str) -> Option<serde_json::Value> {
    sqlx::query_scalar("SELECT sites FROM edge_status WHERE edge = $1")
        .bind(edge)
        .fetch_optional(pool)
        .await
        .expect("edge_status read")
}

#[tokio::test]
async fn sites_follow_the_table_and_report_their_status() {
    let Some(pool) = database("sites").await else {
        eprintln!("skipped: XSHIELD_TEST_DATABASE_BASE_URL is not set");
        return;
    };

    sqlx::query("INSERT INTO site_configs (name, spec, version) VALUES ($1, $2, 1)")
        .bind("emr")
        .bind(spec("a.test", "http://127.0.0.1:1"))
        .execute(&pool)
        .await
        .expect("insert site");
    let table = Arc::new(SiteTable::new());
    let mut loader = SiteLoader::new(SiteSource::Postgres(pool.clone()), Arc::clone(&table));
    loader.refresh().await.expect("first refresh");
    assert!(table.find("a.test").is_some());
    assert_eq!(table.statuses()["emr"].version, Some(1));

    // A new version moves the host.
    sqlx::query("UPDATE site_configs SET spec = $1, version = version + 1 WHERE name = 'emr'")
        .bind(spec("b.test", "http://127.0.0.1:1"))
        .execute(&pool)
        .await
        .expect("update");
    loader.refresh().await.expect("second refresh");
    assert!(table.find("a.test").is_none() && table.find("b.test").is_some());
    assert_eq!(table.statuses()["emr"].version, Some(2));
    let loaded_v2 = table.statuses()["emr"].loaded_at_millis;

    // An invalid version leaves the old one serving, and the status says both.
    sqlx::query("UPDATE site_configs SET spec = $1, version = version + 1 WHERE name = 'emr'")
        .bind(spec("c.test", "ftp://nope"))
        .execute(&pool)
        .await
        .expect("bad update");
    loader.refresh().await.expect("third refresh");
    assert!(table.find("b.test").is_some() && table.find("c.test").is_none());
    // Version 2 is still served, with the time it was loaded at.
    let stale = &table.statuses()["emr"];
    assert_eq!(stale.version, Some(2));
    assert_eq!(stale.loaded_at_millis, loaded_v2);
    assert_eq!(stale.error.as_deref(), Some(ORIGIN_INVALID));

    sqlx::query("DELETE FROM site_configs")
        .execute(&pool)
        .await
        .expect("delete");
    loader.refresh().await.expect("fourth refresh");
    assert!(table.find("b.test").is_none());
    assert!(table.statuses().is_empty());
}

#[tokio::test]
async fn a_batch_lands_with_its_derived_columns() {
    let Some(pool) = database("batch").await else {
        return;
    };
    let at = now();
    partition_for(&pool, at).await;

    let (sink, rx) = DecisionSink::channel(10);
    let counters = sink.counters();
    let writer = tokio::spawn(write_postgres(pool.clone(), rx, counters.clone()));
    let at = u64::try_from(at).expect("positive");
    sink.send(judged("req_00000000000000000000000000000001", at));
    sink.send(bypass("req_00000000000000000000000000000002", at));
    drop(sink);
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("writer drains")
        .expect("writer task");
    assert_eq!(counters.written(), 2);
    assert_eq!(counters.write_errors(), 0);

    let rows = sqlx::query(
        "SELECT request_id, at_millis, edge, site_version, context, logical_path, api, \
         request_headers, query, status, decision_path, outcome, total_ms, jev_ms, jev_access, \
         jev_attack, jev_confidence, jev_failure, trace, jev FROM decision_log ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("rows");
    assert_eq!(rows.len(), 2);

    let first = &rows[0];
    assert_eq!(
        first.get::<String, _>("request_id"),
        "req_00000000000000000000000000000001"
    );
    assert_eq!(
        first.get::<i64, _>("at_millis"),
        i64::try_from(at).expect("in range")
    );
    assert_eq!(first.get::<String, _>("edge"), "edge-test");
    assert_eq!(first.get::<Option<i64>, _>("site_version"), Some(3));
    assert_eq!(
        first.get::<Option<String>, _>("context").as_deref(),
        Some("session")
    );
    assert_eq!(
        first.get::<Option<String>, _>("query").as_deref(),
        Some("page=2")
    );
    assert_eq!(first.get::<Option<i16>, _>("status"), Some(403));
    assert_eq!(first.get::<String, _>("decision_path"), "jev_deny");
    assert_eq!(first.get::<String, _>("outcome"), "blocked");
    // The route fields: the logical path, the interface name as JSON, and the
    // header names, which are names and never values.
    assert_eq!(
        first.get::<Option<String>, _>("logical_path").as_deref(),
        Some("/api/patients/patient-D/getPatient")
    );
    assert_eq!(
        first.get::<Option<serde_json::Value>, _>("api"),
        Some(json!({"name": "getPatient", "from": ["header.x-method"]}))
    );
    assert_eq!(
        first.get::<Vec<String>, _>("request_headers"),
        ["accept", "x-method", "x-request-id"]
    );
    assert_eq!(first.get::<Option<i32>, _>("total_ms"), Some(12));
    assert_eq!(first.get::<Option<i32>, _>("jev_ms"), Some(12));
    assert_eq!(
        first.get::<Option<String>, _>("jev_access").as_deref(),
        Some("DENY")
    );
    assert_eq!(
        first.get::<Option<String>, _>("jev_attack").as_deref(),
        Some("BENIGN")
    );
    // The smaller of the two highest probabilities: 0.7 and 0.9.
    let confidence = first
        .get::<Option<f32>, _>("jev_confidence")
        .expect("confidence");
    assert!((confidence - 0.7).abs() < 1e-4, "{confidence}");
    assert_eq!(first.get::<Option<String>, _>("jev_failure"), None);
    let trace: serde_json::Value = first.get("trace");
    assert_eq!(trace["v"], 1);
    assert_eq!(trace["timing"]["total_ms"], 12);
    let jev: serde_json::Value = first.get("jev");
    assert_eq!(jev["prompt"], "jq_0123456789abcdef");

    let second = &rows[1];
    assert_eq!(second.get::<String, _>("decision_path"), "bypass");
    assert_eq!(second.get::<String, _>("outcome"), "allowed");
    assert_eq!(second.get::<Option<i32>, _>("total_ms"), Some(6));
    assert_eq!(second.get::<Option<i32>, _>("jev_ms"), None);
    assert_eq!(second.get::<Option<String>, _>("jev_access"), None);
    assert!(second.get::<Option<serde_json::Value>, _>("jev").is_none());
    assert_eq!(second.get::<Option<String>, _>("context"), None);
}

#[tokio::test]
async fn a_failed_batch_is_retried_once() {
    let Some(pool) = database("retry").await else {
        return;
    };
    // The first attempt at any row fails; sequences are not rolled back, so the
    // retry gets past it. The trigger is cloned into the partition below.
    let at = now();
    for statement in [
        "CREATE SEQUENCE injected_failures START 1",
        "CREATE FUNCTION fail_first_insert() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF nextval('injected_failures') = 1 THEN \
         RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$",
    ] {
        sqlx::query(AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .expect("injection setup");
    }
    partition_for(&pool, at).await;
    sqlx::query(
        "CREATE TRIGGER fail_first_insert BEFORE INSERT ON decision_log \
         FOR EACH ROW EXECUTE FUNCTION fail_first_insert()",
    )
    .execute(&pool)
    .await
    .expect("trigger");

    let (sink, rx) = DecisionSink::channel(10);
    let counters = sink.counters();
    let writer = tokio::spawn(write_postgres(pool.clone(), rx, counters.clone()));
    let at = u64::try_from(at).expect("positive");
    sink.send(judged("req_00000000000000000000000000000011", at));
    sink.send(judged("req_00000000000000000000000000000012", at));
    drop(sink);
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("writer drains")
        .expect("writer task");

    assert_eq!(counters.written(), 2);
    assert_eq!(counters.write_errors(), 0);
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM decision_log")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(stored, 2);
    // The failed attempt used up number 1, so the retry used a later number.
    let last: i64 = sqlx::query_scalar("SELECT last_value FROM injected_failures")
        .fetch_one(&pool)
        .await
        .expect("sequence");
    assert!(last >= 2, "last value {last}");
}

#[tokio::test]
async fn a_batch_without_its_partition_is_counted_as_write_errors() {
    let Some(pool) = database("partition").await else {
        return;
    };
    let at = now();
    partition_for(&pool, at).await;

    let (sink, rx) = DecisionSink::channel(10);
    let counters: Counters = sink.counters();
    let writer = tokio::spawn(write_postgres(pool.clone(), rx, counters.clone()));
    // Ten years before any partition exists: no partition takes this row.
    let long_ago = u64::try_from(at - 3_650 * DAY_MS).expect("positive");
    sink.send(judged("req_00000000000000000000000000000021", long_ago));
    eventually("the lost batch is counted", || counters.write_errors() == 1).await;

    let at = u64::try_from(at).expect("positive");
    sink.send(judged("req_00000000000000000000000000000022", at));
    drop(sink);
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("writer drains")
        .expect("writer task");

    assert_eq!(counters.write_errors(), 1);
    assert_eq!(counters.written(), 1);
    let ids: Vec<String> = sqlx::query_scalar("SELECT request_id FROM decision_log")
        .fetch_all(&pool)
        .await
        .expect("ids");
    assert_eq!(ids, ["req_00000000000000000000000000000022"]);
}

#[tokio::test]
async fn the_heartbeat_is_one_row_per_instance_and_is_rewritten() {
    let Some(pool) = database("heartbeat").await else {
        return;
    };
    let instance = Instance {
        edge: "edge-a".to_owned(),
        started_at_millis: now() - 60_000,
        listen: "8080,8443".to_owned(),
        tls: true,
    };
    let mut beat = Beat {
        sites: BTreeMap::from([
            ("bad".to_owned(), SiteStatus::failed(None, ORIGIN_INVALID)),
            ("emr".to_owned(), SiteStatus::serving(2, 1_793_537_900_000)),
        ]),
        sessions: 3,
        queue: 4,
        written: 10,
        dropped: 2,
        dropped_bypass: 5,
        write_errors: 1,
        gaps: vec![Gap {
            from_ms: 60_000,
            to_ms: 120_000,
            dropped: 2,
            dropped_bypass: 5,
            write_errors: 1,
        }],
        jev: json!({
            "route": "fake", "endpoint_host": "jev.test", "model": "fake-model",
            "timeout_ms": 2000, "prompt": "jq_0123456789abcdef"
        }),
        params: json!({"fixed": {"queue_capacity": 10_000}}),
    };
    status::write_heartbeat(&pool, &instance, &beat)
        .await
        .expect("first beat");
    beat.written = 20;
    beat.sessions = 5;
    status::write_heartbeat(&pool, &instance, &beat)
        .await
        .expect("second beat");

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM edge_status")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 1);
    let row = sqlx::query(
        "SELECT sessions, written, dropped_bypass, listen, tls, build, sites, gaps, params, jev, \
         (extract(epoch FROM started_at) * 1000)::bigint AS started, \
         now() - seen_at < interval '30 seconds' AS fresh FROM edge_status WHERE edge = 'edge-a'",
    )
    .fetch_one(&pool)
    .await
    .expect("row");
    assert_eq!(row.get::<i32, _>("sessions"), 5);
    assert_eq!(row.get::<i64, _>("written"), 20);
    assert_eq!(row.get::<i64, _>("dropped_bypass"), 5);
    assert_eq!(row.get::<String, _>("listen"), "8080,8443");
    assert!(row.get::<bool, _>("tls"));
    assert_eq!(row.get::<String, _>("build"), env!("CARGO_PKG_VERSION"));
    assert!(row.get::<bool, _>("fresh"));
    assert!((row.get::<i64, _>("started") - instance.started_at_millis).abs() <= 1);

    let sites: serde_json::Value = row.get("sites");
    assert_eq!(
        sites["emr"],
        json!({"version": 2, "loaded_at_millis": 1_793_537_900_000_i64})
    );
    assert_eq!(sites["bad"], json!({"error": "SITE_CONFIG_ORIGIN_INVALID"}));
    let gaps: serde_json::Value = row.get("gaps");
    assert_eq!(gaps[0]["from_ms"], 60_000);
    assert_eq!(gaps[0]["to_ms"], 120_000);
    assert_eq!(gaps[0]["dropped_bypass"], 5);
    let params: serde_json::Value = row.get("params");
    assert_eq!(params["fixed"]["queue_capacity"], 10_000);
    let jev: serde_json::Value = row.get("jev");
    assert_eq!(jev["prompt"], "jq_0123456789abcdef");
    assert!(!jev.to_string().to_ascii_lowercase().contains("key"));
}

#[tokio::test]
async fn the_instruction_version_is_stored_once() {
    let Some(pool) = database("prompt").await else {
        return;
    };
    let prompt = Prompt::new();
    assert!(prompt.id().starts_with("jq_"));
    assert_eq!(prompt.id().len(), 19);
    status::register_prompt(&pool, &prompt)
        .await
        .expect("first registration");
    status::register_prompt(&pool, &prompt)
        .await
        .expect("second registration");

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM jev_prompts WHERE id = $1")
        .bind(prompt.id())
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 1);
    let same: bool =
        sqlx::query_scalar("SELECT questions = $1::jsonb FROM jev_prompts WHERE id = $2")
            .bind(prompt.questions_json())
            .bind(prompt.id())
            .fetch_one(&pool)
            .await
            .expect("questions");
    assert!(same, "the stored questions are the prompt's");
}

#[tokio::test]
async fn a_site_change_is_reported_without_waiting_for_the_interval() {
    let Some(pool) = database("notify").await else {
        return;
    };
    let table = Arc::new(SiteTable::new());
    let (sink, _rx) = DecisionSink::channel(10);
    let judge = Arc::new(Judge::new(ContextKey::new(vec![7; 32]), Unreachable));
    let instance = Instance {
        edge: "edge-n".to_owned(),
        started_at_millis: now(),
        listen: "8080".to_owned(),
        tls: false,
    };
    let heartbeat = tokio::spawn(status::run(
        pool.clone(),
        judge,
        Arc::clone(&table),
        sink.counters(),
        instance,
    ));
    // The first beat happens at once; it also registers the prompt before it.
    let deadline = Instant::now() + Duration::from_secs(5);
    while edge_sites(&pool, "edge-n").await.is_none() {
        assert!(Instant::now() < deadline, "the first beat was not written");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let before = edge_sites(&pool, "edge-n").await.expect("first beat");
    assert_eq!(before, json!({}));
    let prompts: i64 = sqlx::query_scalar("SELECT count(*) FROM jev_prompts")
        .fetch_one(&pool)
        .await
        .expect("prompts");
    assert_eq!(prompts, 1);

    sqlx::query("INSERT INTO site_configs (name, spec, version) VALUES ('emr', $1, 1)")
        .bind(spec("a.test", "http://127.0.0.1:1"))
        .execute(&pool)
        .await
        .expect("insert site");
    let mut loader = SiteLoader::new(SiteSource::Postgres(pool.clone()), Arc::clone(&table));
    loader.refresh().await.expect("refresh");

    // The interval is ten seconds; this must come much sooner.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if edge_sites(&pool, "edge-n")
            .await
            .is_some_and(|sites| sites.get("emr").is_some())
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the site change was not sent at once"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    heartbeat.abort();
}
