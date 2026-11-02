//! Start-up migrations (docs/04 section 4.2). The database tests are skipped
//! unless `XSHIELD_TEST_DATABASE_BASE_URL` (a server URL without a database
//! name) is set; CI's validate job sets it.

use sha2::{Digest as _, Sha384};
use sqlx::migrate::MigrateError;
use sqlx::postgres::PgPoolOptions;
use sqlx::{AssertSqlSafe, PgPool};
use xshield_control::{MIGRATOR, run_migrations};

/// The baseline migration as its file holds it, byte for byte.
const BASELINE_FILE: &str = include_str!("../../../migrations/0001_v4_baseline.sql");

/// A database of its own on the test server.
struct Scratch {
    admin: PgPool,
    name: String,
    pool: PgPool,
}

impl Scratch {
    /// `None` when the test server is not configured.
    async fn new(tag: &str) -> Option<Self> {
        let base = std::env::var("XSHIELD_TEST_DATABASE_BASE_URL").ok()?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&format!("{base}/postgres"))
            .await
            .expect("admin connection");
        // The process id keeps one run's database from another run's.
        let name = format!("control_migrations_{}_{tag}", std::process::id());
        sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name}")))
            .execute(&admin)
            .await
            .expect("drop a database left by an earlier run");
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .expect("create the scratch database");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!("{base}/{name}"))
            .await
            .expect("connect to the scratch database");
        Some(Self { admin, name, pool })
    }

    async fn finish(self) {
        self.pool.close().await;
        sqlx::query(AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS {}",
            self.name
        )))
        .execute(&self.admin)
        .await
        .expect("drop the scratch database");
    }
}

/// How many migrations the ledger records as applied.
async fn applied(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(pool)
        .await
        .expect("count the applied migrations")
}

async fn table_exists(pool: &PgPool, table: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("public.{table}"))
        .fetch_one(pool)
        .await
        .expect("look up the table")
}

fn migration_count() -> i64 {
    i64::try_from(MIGRATOR.iter().count()).expect("a small number of migrations")
}

#[test]
fn every_migration_file_is_compiled_in() {
    let on_disk = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations"))
        .expect("the migrations directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sql"))
        .count();
    assert_eq!(MIGRATOR.iter().count(), on_disk);
}

#[tokio::test]
async fn a_fresh_database_gets_every_migration_once() {
    let Some(db) = Scratch::new("fresh").await else {
        eprintln!("skipped: XSHIELD_TEST_DATABASE_BASE_URL is not set");
        return;
    };
    run_migrations(&db.pool)
        .await
        .expect("the first start applies every migration");
    assert!(table_exists(&db.pool, "site_configs").await);
    assert_eq!(applied(&db.pool).await, migration_count());

    run_migrations(&db.pool)
        .await
        .expect("a restart has nothing left to apply");
    assert_eq!(applied(&db.pool).await, migration_count());
    db.finish().await;
}

#[tokio::test]
async fn a_database_with_the_baseline_but_no_ledger_is_refused_not_adopted() {
    let Some(db) = Scratch::new("unledgered").await else {
        eprintln!("skipped: XSHIELD_TEST_DATABASE_BASE_URL is not set");
        return;
    };
    sqlx::raw_sql(BASELINE_FILE)
        .execute(&db.pool)
        .await
        .expect("the baseline, applied by hand");

    let error = run_migrations(&db.pool)
        .await
        .expect_err("the baseline is not recorded, so it must not run again");
    assert!(
        matches!(error, MigrateError::ExecuteMigration(_, 1)),
        "unexpected error: {error}"
    );
    assert_eq!(applied(&db.pool).await, 0);
    assert!(table_exists(&db.pool, "site_configs").await);
    db.finish().await;
}

#[tokio::test]
async fn a_database_adopted_with_the_recipe_in_docs_is_not_migrated_again() {
    let Some(db) = Scratch::new("adopted").await else {
        eprintln!("skipped: XSHIELD_TEST_DATABASE_BASE_URL is not set");
        return;
    };
    sqlx::raw_sql(BASELINE_FILE)
        .execute(&db.pool)
        .await
        .expect("the baseline, applied by hand");
    // The first start creates the ledger and refuses the baseline; the recipe
    // in docs/04 section 4.2 starts from that state.
    let error = run_migrations(&db.pool)
        .await
        .expect_err("refused until the baseline is recorded");
    assert!(matches!(error, MigrateError::ExecuteMigration(_, 1)));

    // The recipe records the SHA-384 of the file as the checksum.
    let checksum = Sha384::digest(BASELINE_FILE.as_bytes()).to_vec();
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (1, 'v4 baseline', true, $1, 0)",
    )
    .bind(checksum)
    .execute(&db.pool)
    .await
    .expect("record the baseline as applied");

    run_migrations(&db.pool)
        .await
        .expect("the recorded baseline is not run again");
    assert_eq!(applied(&db.pool).await, migration_count());
    db.finish().await;
}
