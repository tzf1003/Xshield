//! The two `PostgreSQL` adapters against a real database. Skipped unless
//! `XSHIELD_TEST_DATABASE_BASE_URL` (a server URL without a database name) is set.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::{AssertSqlSafe, PgPool, Row};
use xshield_core::context::{DecisionPath, DecisionRecord, JevRecord, Outcome};
use xshield_edge::sink::{DecisionSink, write_postgres};
use xshield_edge::sites::SiteTable;
use xshield_edge::source::{SiteLoader, SiteSource};

// The tables the control plane owns (see the console migration); the columns
// below are the contract between the two processes.
const SCHEMA: &[&str] = &[
    "CREATE TABLE site_configs (name text PRIMARY KEY, spec jsonb NOT NULL, \
     version bigint NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), \
     updated_at timestamptz NOT NULL DEFAULT now())",
    "CREATE TABLE decision_log (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, \
     at_millis bigint NOT NULL, site text NOT NULL, request_id text NOT NULL, \
     session text NOT NULL, method text NOT NULL, path text NOT NULL, status integer, \
     decision_path text NOT NULL, outcome text NOT NULL, jev jsonb)",
];

async fn database() -> Option<PgPool> {
    let base = std::env::var("XSHIELD_TEST_DATABASE_BASE_URL").ok()?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{base}/postgres"))
        .await
        .expect("admin connection");
    let name = format!("edge_test_{}", std::process::id());
    sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name}")))
        .execute(&admin)
        .await
        .expect("drop");
    sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .expect("create");
    let pool = PgPoolOptions::new()
        .max_connections(2)
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

fn spec(host: &str, origin: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "emr", "hosts": [host], "origin": origin,
        "session": {"cookie": "SID"}, "entries": ["/login"]
    })
}

#[tokio::test]
async fn sites_follow_the_table_and_decisions_land_in_the_log() {
    let Some(pool) = database().await else {
        eprintln!("skipped: XSHIELD_TEST_DATABASE_BASE_URL is not set");
        return;
    };

    sqlx::query("INSERT INTO site_configs (name, spec) VALUES ($1, $2)")
        .bind("emr")
        .bind(spec("a.test", "http://127.0.0.1:1"))
        .execute(&pool)
        .await
        .expect("insert site");
    let table = Arc::new(SiteTable::new());
    let mut loader = SiteLoader::new(SiteSource::Postgres(pool.clone()), Arc::clone(&table));
    loader.refresh().await.expect("first refresh");
    assert!(table.find("a.test").is_some());

    // A new version moves the host; an invalid one leaves the old site serving.
    sqlx::query("UPDATE site_configs SET spec = $1, version = version + 1 WHERE name = 'emr'")
        .bind(spec("b.test", "http://127.0.0.1:1"))
        .execute(&pool)
        .await
        .expect("update");
    loader.refresh().await.expect("second refresh");
    assert!(table.find("a.test").is_none() && table.find("b.test").is_some());
    sqlx::query("UPDATE site_configs SET spec = $1, version = version + 1 WHERE name = 'emr'")
        .bind(spec("c.test", "ftp://nope"))
        .execute(&pool)
        .await
        .expect("bad update");
    loader.refresh().await.expect("third refresh");
    assert!(table.find("b.test").is_some() && table.find("c.test").is_none());
    sqlx::query("DELETE FROM site_configs")
        .execute(&pool)
        .await
        .expect("delete");
    loader.refresh().await.expect("fourth refresh");
    assert!(table.find("b.test").is_none());

    let (sink, rx) = DecisionSink::channel(10);
    let writer = tokio::spawn(write_postgres(pool.clone(), rx));
    sink.send(DecisionRecord {
        at_millis: 1_700_000_000_123,
        site: "emr".into(),
        request_id: "req_1".into(),
        session: "ab12cd34".into(),
        method: "GET".into(),
        path: "/api/patients/patient-D".into(),
        status: Some(403),
        decision_path: DecisionPath::JevDeny,
        outcome: Outcome::Blocked,
        jev: Some(JevRecord {
            state: "{}".into(),
            access: BTreeMap::from([("DENY".to_owned(), 0.9)]),
            attack: BTreeMap::new(),
            millis: 12,
            failure: None,
        }),
    });
    sink.send(DecisionRecord {
        at_millis: 1,
        site: "emr".into(),
        request_id: "req_2".into(),
        session: "-".into(),
        method: "GET".into(),
        path: "/".into(),
        status: None,
        decision_path: DecisionPath::FastAllow,
        outcome: Outcome::Allowed,
        jev: None,
    });
    drop(sink);
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("writer drains")
        .expect("writer task");

    let rows = sqlx::query(
        "SELECT request_id, at_millis, status, decision_path, outcome, jev FROM decision_log ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .expect("rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<String, _>("decision_path"), "jev_deny");
    assert_eq!(rows[0].get::<String, _>("outcome"), "blocked");
    assert_eq!(rows[0].get::<i64, _>("at_millis"), 1_700_000_000_123);
    assert_eq!(rows[0].get::<Option<i32>, _>("status"), Some(403));
    let jev: serde_json::Value = rows[0].get("jev");
    assert_eq!(jev["millis"], 12);
    assert_eq!(rows[1].get::<Option<i32>, _>("status"), None);
    assert!(rows[1].get::<Option<serde_json::Value>, _>("jev").is_none());
}
