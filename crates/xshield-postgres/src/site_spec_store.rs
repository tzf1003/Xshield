//! `PostgreSQL` storage for site configuration and its versioned history
//! (docs/07-console-architecture.md sections 7.8.1 and 7.9.2).
//!
//! `site_configs` holds each site's current configuration. `site_config_history`
//! holds every version of every site, with the full text of the configuration
//! after the change, so any version can be opened, compared and restored. A
//! version number counts up from 1 per site and keeps counting after a delete,
//! so `(site, version)` never names two different configurations.
//!
//! Every write takes the site's row lock, checks the caller's `expected_version`
//! and then writes the new version and its history row in one transaction.

use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, PgPool, Postgres, Row, Transaction, postgres::PgRow};
use xshield_core::context::SiteSpec;

/// Longest note accepted with a write, in characters.
pub const NOTE_MAX_CHARS: usize = 500;

/// A site's current stored configuration.
#[derive(Debug, Clone)]
pub struct SiteRecord {
    /// The validated site configuration.
    pub spec: SiteSpec,
    /// The current version. Starts at 1 and counts up across updates, rollbacks
    /// and a delete followed by a re-create.
    pub version: i64,
    /// When the site was first created.
    pub created_at: DateTime<Utc>,
    /// When the site was last changed.
    pub updated_at: DateTime<Utc>,
}

/// What a history row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The site was created.
    Create,
    /// The configuration was changed by the administrator.
    Update,
    /// The configuration was restored from an earlier version.
    Rollback,
    /// The site was deleted; the row has no configuration.
    Delete,
    /// The configuration was imported.
    Import,
    /// The learning task tightened an object position on its own.
    AutoTighten,
    /// The learning task paused a confirmed object position on its own.
    AutoPause,
}

impl Change {
    /// The stored spelling of this change kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Rollback => "rollback",
            Self::Delete => "delete",
            Self::Import => "import",
            Self::AutoTighten => "auto_tighten",
            Self::AutoPause => "auto_pause",
        }
    }

    /// Parses the stored spelling of a change kind.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "create" => Self::Create,
            "update" => Self::Update,
            "rollback" => Self::Rollback,
            "delete" => Self::Delete,
            "import" => Self::Import,
            "auto_tighten" => Self::AutoTighten,
            "auto_pause" => Self::AutoPause,
            _ => return None,
        })
    }
}

/// One version of a site.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// The version number, unique per site.
    pub version: i64,
    /// What this version records.
    pub change: Change,
    /// For a rollback, the version whose configuration was restored.
    pub rollback_of: Option<i64>,
    /// The administrator's remark, if any.
    pub note: Option<String>,
    /// When this version was recorded.
    pub changed_at: DateTime<Utc>,
    /// The whole configuration of this version; `None` for a delete.
    pub spec: Option<SiteSpec>,
}

/// Outcome of a write that names an `expected_version`.
#[derive(Debug)]
pub enum WriteOutcome {
    /// The site does not exist.
    NotFound,
    /// The site has moved on from the expected version.
    VersionConflict {
        /// The version the site is at now.
        current: i64,
    },
    /// The write was applied; this is the resulting current record.
    Applied(Box<SiteRecord>),
}

/// Outcome of deleting a site.
#[derive(Debug)]
pub enum DeleteOutcome {
    /// The site does not exist.
    NotFound,
    /// The site has moved on from the expected version.
    VersionConflict {
        /// The version the site is at now.
        current: i64,
    },
    /// The site was deleted; the delete is recorded as this version.
    Deleted {
        /// The history version recording the delete.
        version: i64,
    },
}

/// Outcome of restoring an earlier version.
#[derive(Debug)]
pub enum RollbackOutcome {
    /// The site does not exist (or is currently deleted).
    NotFound,
    /// The site has moved on from the expected version.
    VersionConflict {
        /// The version the site is at now.
        current: i64,
    },
    /// The requested version does not exist for this site.
    VersionNotFound,
    /// The requested version is a delete, so it has no configuration to restore.
    TargetDeleted,
    /// The rollback was applied as a new version.
    Applied(Box<SiteRecord>),
}

/// Failure of a site configuration storage operation.
#[derive(Debug)]
pub enum SiteSpecStoreError {
    /// The underlying database operation failed.
    Database(sqlx::Error),
    /// Storing or loading the configuration as JSON failed.
    Serialize(serde_json::Error),
    /// A stored configuration failed to re-validate as a [`SiteSpec`].
    InvalidStoredSpec,
    /// A stored history row carries a change kind this build does not know.
    CorruptHistory,
    /// `create` was called with a name that already has a row.
    AlreadyExists,
}

impl std::fmt::Display for SiteSpecStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::Serialize(error) => write!(formatter, "serialization error: {error}"),
            Self::InvalidStoredSpec => {
                formatter.write_str("stored site configuration failed to re-validate")
            }
            Self::CorruptHistory => formatter.write_str("stored site history row is malformed"),
            Self::AlreadyExists => formatter.write_str("site name already exists"),
        }
    }
}

impl std::error::Error for SiteSpecStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Serialize(error) => Some(error),
            Self::InvalidStoredSpec | Self::CorruptHistory | Self::AlreadyExists => None,
        }
    }
}

impl From<sqlx::Error> for SiteSpecStoreError {
    fn from(value: sqlx::Error) -> Self {
        if is_unique_violation(&value) {
            Self::AlreadyExists
        } else {
            Self::Database(value)
        }
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}

fn spec_to_json(spec: &SiteSpec) -> Result<serde_json::Value, SiteSpecStoreError> {
    serde_json::to_value(spec).map_err(SiteSpecStoreError::Serialize)
}

fn json_to_spec(value: &serde_json::Value) -> Result<SiteSpec, SiteSpecStoreError> {
    let text = serde_json::to_string(value).map_err(SiteSpecStoreError::Serialize)?;
    SiteSpec::from_json(&text).map_err(|_| SiteSpecStoreError::InvalidStoredSpec)
}

fn row_to_record(row: &PgRow) -> Result<SiteRecord, SiteSpecStoreError> {
    let spec: serde_json::Value = row.try_get("spec")?;
    Ok(SiteRecord {
        spec: json_to_spec(&spec)?,
        version: row.try_get("version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_history(row: &PgRow) -> Result<HistoryEntry, SiteSpecStoreError> {
    let change: String = row.try_get("change")?;
    let spec: Option<serde_json::Value> = row.try_get("spec")?;
    Ok(HistoryEntry {
        version: row.try_get("version")?,
        change: Change::parse(&change).ok_or(SiteSpecStoreError::CorruptHistory)?,
        rollback_of: row.try_get("rollback_of")?,
        note: row.try_get("note")?,
        changed_at: row.try_get("changed_at")?,
        spec: spec.as_ref().map(json_to_spec).transpose()?,
    })
}

const RECORD_COLUMNS: &str = "spec, version, created_at, updated_at";

/// Lists every current site, ordered by name.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database failure or a stored
/// configuration that no longer validates.
pub async fn list(pool: &PgPool) -> Result<Vec<SiteRecord>, SiteSpecStoreError> {
    let sql = format!("SELECT {RECORD_COLUMNS} FROM site_configs ORDER BY name");
    let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(pool).await?;
    rows.iter().map(row_to_record).collect()
}

/// Fetches one current site by name.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database failure or a stored
/// configuration that no longer validates.
pub async fn get(pool: &PgPool, name: &str) -> Result<Option<SiteRecord>, SiteSpecStoreError> {
    let sql = format!("SELECT {RECORD_COLUMNS} FROM site_configs WHERE name = $1");
    let row = sqlx::query(AssertSqlSafe(sql))
        .bind(name)
        .fetch_optional(pool)
        .await?;
    row.as_ref().map(row_to_record).transpose()
}

async fn insert_history(
    transaction: &mut Transaction<'_, Postgres>,
    site: &str,
    version: i64,
    change: Change,
    rollback_of: Option<i64>,
    spec: Option<&serde_json::Value>,
    note: Option<&str>,
) -> Result<(), SiteSpecStoreError> {
    sqlx::query(
        "INSERT INTO site_config_history (site, version, spec, change, rollback_of, note)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(site)
    .bind(version)
    .bind(spec)
    .bind(change.as_str())
    .bind(rollback_of)
    .bind(note)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The version a site's next history row takes: one more than the highest
/// version ever recorded for it, deleted sites included.
async fn next_version(
    transaction: &mut Transaction<'_, Postgres>,
    site: &str,
) -> Result<i64, SiteSpecStoreError> {
    let current: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM site_config_history WHERE site = $1")
            .bind(site)
            .fetch_one(&mut **transaction)
            .await?;
    Ok(current.unwrap_or(0) + 1)
}

/// Creates a site as version 1, or the next version after an earlier delete.
///
/// # Errors
/// Returns [`SiteSpecStoreError::AlreadyExists`] if the name is taken, or
/// another [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn create(
    pool: &PgPool,
    spec: &SiteSpec,
    note: Option<&str>,
) -> Result<SiteRecord, SiteSpecStoreError> {
    let json = spec_to_json(spec)?;
    let mut transaction = pool.begin().await?;
    let version = next_version(&mut transaction, spec.name()).await?;
    let sql = format!(
        "INSERT INTO site_configs (name, spec, version) VALUES ($1, $2, $3)
         RETURNING {RECORD_COLUMNS}"
    );
    let row = sqlx::query(AssertSqlSafe(sql))
        .bind(spec.name())
        .bind(&json)
        .bind(version)
        .fetch_one(&mut *transaction)
        .await?;
    insert_history(
        &mut transaction,
        spec.name(),
        version,
        Change::Create,
        None,
        Some(&json),
        note,
    )
    .await?;
    transaction.commit().await?;
    row_to_record(&row)
}

/// Replaces a site's configuration when the site is still at `expected_version`.
///
/// `name` is the site's current name; the caller checks that `spec` carries the
/// same name before calling.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn update(
    pool: &PgPool,
    name: &str,
    spec: &SiteSpec,
    expected_version: i64,
    note: Option<&str>,
) -> Result<WriteOutcome, SiteSpecStoreError> {
    write(pool, name, spec, expected_version, Change::Update, note).await
}

/// Replaces a site's configuration as a version recorded as `change`, when the site is
/// still at `expected_version`. The learning task records its automatic changes this way.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn write(
    pool: &PgPool,
    name: &str,
    spec: &SiteSpec,
    expected_version: i64,
    change: Change,
    note: Option<&str>,
) -> Result<WriteOutcome, SiteSpecStoreError> {
    let after = spec_to_json(spec)?;
    let mut transaction = pool.begin().await?;
    let current = lock_current_version(&mut transaction, name).await?;
    let Some(current) = current else {
        transaction.rollback().await?;
        return Ok(WriteOutcome::NotFound);
    };
    if current != expected_version {
        transaction.rollback().await?;
        return Ok(WriteOutcome::VersionConflict { current });
    }
    let version = current + 1;
    let sql = format!(
        "UPDATE site_configs SET spec = $2, version = $3, updated_at = now()
         WHERE name = $1 RETURNING {RECORD_COLUMNS}"
    );
    let row = sqlx::query(AssertSqlSafe(sql))
        .bind(name)
        .bind(&after)
        .bind(version)
        .fetch_one(&mut *transaction)
        .await?;
    insert_history(
        &mut transaction,
        name,
        version,
        change,
        None,
        Some(&after),
        note,
    )
    .await?;
    transaction.commit().await?;
    Ok(WriteOutcome::Applied(Box::new(row_to_record(&row)?)))
}

/// Deletes a site when it is still at `expected_version`. The delete is
/// recorded as a history version with no configuration, and the site's
/// learning state is deleted with it.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database failure.
pub async fn delete(
    pool: &PgPool,
    name: &str,
    expected_version: i64,
    note: Option<&str>,
) -> Result<DeleteOutcome, SiteSpecStoreError> {
    let mut transaction = pool.begin().await?;
    let current = lock_current_version(&mut transaction, name).await?;
    let Some(current) = current else {
        transaction.rollback().await?;
        return Ok(DeleteOutcome::NotFound);
    };
    if current != expected_version {
        transaction.rollback().await?;
        return Ok(DeleteOutcome::VersionConflict { current });
    }
    sqlx::query("DELETE FROM site_configs WHERE name = $1")
        .bind(name)
        .execute(&mut *transaction)
        .await?;
    // In this transaction, so the learning state goes with the site, and a site
    // created later under the same name never learns from the old site's traffic.
    crate::object_learning_store::forget_site(
        &mut transaction,
        name,
        chrono::Utc::now().timestamp_millis(),
    )
    .await?;
    let version = current + 1;
    insert_history(
        &mut transaction,
        name,
        version,
        Change::Delete,
        None,
        None,
        note,
    )
    .await?;
    transaction.commit().await?;
    Ok(DeleteOutcome::Deleted { version })
}

/// Restores the configuration of `to_version` as a new version, when the site
/// is still at `expected_version`.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn rollback(
    pool: &PgPool,
    name: &str,
    to_version: i64,
    expected_version: i64,
    note: Option<&str>,
) -> Result<RollbackOutcome, SiteSpecStoreError> {
    let mut transaction = pool.begin().await?;
    let current = lock_current_version(&mut transaction, name).await?;
    let Some(current) = current else {
        transaction.rollback().await?;
        return Ok(RollbackOutcome::NotFound);
    };
    if current != expected_version {
        transaction.rollback().await?;
        return Ok(RollbackOutcome::VersionConflict { current });
    }
    let target: Option<Option<serde_json::Value>> =
        sqlx::query_scalar("SELECT spec FROM site_config_history WHERE site = $1 AND version = $2")
            .bind(name)
            .bind(to_version)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some(target) = target else {
        transaction.rollback().await?;
        return Ok(RollbackOutcome::VersionNotFound);
    };
    let Some(after) = target else {
        transaction.rollback().await?;
        return Ok(RollbackOutcome::TargetDeleted);
    };
    // A row written by an older build must still parse as today's `SiteSpec`
    // before it becomes the current configuration.
    json_to_spec(&after)?;
    let version = current + 1;
    let sql = format!(
        "UPDATE site_configs SET spec = $2, version = $3, updated_at = now()
         WHERE name = $1 RETURNING {RECORD_COLUMNS}"
    );
    let row = sqlx::query(AssertSqlSafe(sql))
        .bind(name)
        .bind(&after)
        .bind(version)
        .fetch_one(&mut *transaction)
        .await?;
    insert_history(
        &mut transaction,
        name,
        version,
        Change::Rollback,
        Some(to_version),
        Some(&after),
        note,
    )
    .await?;
    transaction.commit().await?;
    Ok(RollbackOutcome::Applied(Box::new(row_to_record(&row)?)))
}

/// Locks the site's row and returns its current version, or `None` when the
/// site does not exist. Writes hold this lock, so version checks never race.
async fn lock_current_version(
    transaction: &mut Transaction<'_, Postgres>,
    name: &str,
) -> Result<Option<i64>, SiteSpecStoreError> {
    let version: Option<i64> =
        sqlx::query_scalar("SELECT version FROM site_configs WHERE name = $1 FOR UPDATE")
            .bind(name)
            .fetch_optional(&mut **transaction)
            .await?;
    Ok(version)
}

/// Lists a site's versions, newest first. `before` pages backwards: only
/// versions strictly below it are returned.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn history(
    pool: &PgPool,
    name: &str,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<HistoryEntry>, SiteSpecStoreError> {
    let limit = limit.clamp(1, 200);
    let rows = sqlx::query(
        "SELECT version, change, rollback_of, note, changed_at, spec
         FROM site_config_history
         WHERE site = $1 AND version < $2
         ORDER BY version DESC LIMIT $3",
    )
    .bind(name)
    .bind(before.unwrap_or(i64::MAX))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_history).collect()
}

/// Lists a site's automatic versions, newest first: the versions the learning task recorded, as
/// [`Change::AutoTighten`] or [`Change::AutoPause`].
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn automatic_history(
    pool: &PgPool,
    name: &str,
    limit: i64,
) -> Result<Vec<HistoryEntry>, SiteSpecStoreError> {
    let limit = limit.clamp(1, 200);
    let rows = sqlx::query(
        "SELECT version, change, rollback_of, note, changed_at, spec
         FROM site_config_history
         WHERE site = $1 AND change IN ('auto_tighten', 'auto_pause')
         ORDER BY version DESC LIMIT $2",
    )
    .bind(name)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_history).collect()
}

/// Fetches one version of a site.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn version(
    pool: &PgPool,
    name: &str,
    version: i64,
) -> Result<Option<HistoryEntry>, SiteSpecStoreError> {
    let row = sqlx::query(
        "SELECT version, change, rollback_of, note, changed_at, spec
         FROM site_config_history WHERE site = $1 AND version = $2",
    )
    .bind(name)
    .bind(version)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(row_to_history).transpose()
}

#[cfg(test)]
mod tests {
    // These storage-layer tests need a reachable PostgreSQL instance. They run
    // when `XSHIELD_TEST_DATABASE_URL` is set (scripts/test_postgres.sh does
    // that after applying `migrations/`).

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Each test gets its own site name: the tests share one database and can
    // run concurrently, and `create` rejects a name that already exists.
    fn minimal_spec(name: &str, entries: &[&str]) -> SiteSpec {
        let host = name.replace('_', "-");
        let entries = entries
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(", ");
        SiteSpec::from_json(&format!(
            r#"{{
                "name": "{name}",
                "hosts": ["{host}.example.com"],
                "origin": "http://10.0.0.5:8080",
                "session": {{"cookie": "SESSIONID"}},
                "entries": [{entries}]
            }}"#
        ))
        .expect("test spec")
    }

    fn unique_name(prefix: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!("{prefix}_{}", COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn history_pages_back_from_a_version() {
        let pool = connect_test_pool().await;
        let name = unique_name("paging");
        create(&pool, &minimal_spec(&name, &["/one"]), None)
            .await
            .unwrap();
        update(
            &pool,
            &name,
            &minimal_spec(&name, &["/one", "/two"]),
            1,
            None,
        )
        .await
        .unwrap();
        update(
            &pool,
            &name,
            &minimal_spec(&name, &["/one", "/two", "/three"]),
            2,
            None,
        )
        .await
        .unwrap();

        let numbers = |entries: Vec<HistoryEntry>| -> Vec<i64> {
            entries.iter().map(|entry| entry.version).collect()
        };
        let newest = history(&pool, &name, None, 2).await.unwrap();
        assert_eq!(numbers(newest), vec![3, 2]);
        let older = history(&pool, &name, Some(3), 2).await.unwrap();
        assert_eq!(numbers(older), vec![2, 1]);
        let oldest = history(&pool, &name, Some(2), 2).await.unwrap();
        assert_eq!(numbers(oldest), vec![1]);
        assert!(history(&pool, &name, Some(1), 2).await.unwrap().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn versions_count_up_and_survive_a_delete_and_recreate() {
        let pool = connect_test_pool().await;
        let name = unique_name("versions");
        let first = minimal_spec(&name, &["/login"]);
        let created = create(&pool, &first, Some("first")).await.unwrap();
        assert_eq!(created.version, 1);

        let second = minimal_spec(&name, &["/login", "/api/home"]);
        let WriteOutcome::Applied(updated) = update(&pool, &name, &second, 1, None).await.unwrap()
        else {
            panic!("update should apply at the expected version");
        };
        assert_eq!(updated.version, 2);
        assert_eq!(updated.spec, second);

        let DeleteOutcome::Deleted { version } = delete(&pool, &name, 2, None).await.unwrap()
        else {
            panic!("delete should apply at the expected version");
        };
        assert_eq!(version, 3);
        assert!(get(&pool, &name).await.unwrap().is_none());

        let recreated = create(&pool, &first, None).await.unwrap();
        assert_eq!(recreated.version, 4);

        let entries = history(&pool, &name, None, 50).await.unwrap();
        let versions: Vec<i64> = entries.iter().map(|entry| entry.version).collect();
        assert_eq!(versions, vec![4, 3, 2, 1]);
        assert_eq!(entries[1].change, Change::Delete);
        assert!(entries[1].spec.is_none());
        assert_eq!(entries[3].note.as_deref(), Some("first"));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_stale_expected_version_is_a_conflict_and_changes_nothing() {
        let pool = connect_test_pool().await;
        let name = unique_name("conflict");
        let spec = minimal_spec(&name, &["/login"]);
        create(&pool, &spec, None).await.unwrap();
        update(&pool, &name, &spec, 1, None).await.unwrap();

        let outcome = update(&pool, &name, &spec, 1, None).await.unwrap();
        assert!(matches!(
            outcome,
            WriteOutcome::VersionConflict { current: 2 }
        ));
        let record = get(&pool, &name).await.unwrap().unwrap();
        assert_eq!(record.version, 2);
        assert_eq!(history(&pool, &name, None, 50).await.unwrap().len(), 2);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn rollback_restores_an_earlier_text_as_a_new_version() {
        let pool = connect_test_pool().await;
        let name = unique_name("rollback");
        let original = minimal_spec(&name, &["/login"]);
        create(&pool, &original, None).await.unwrap();
        let changed = minimal_spec(&name, &["/login", "/api/home"]);
        update(&pool, &name, &changed, 1, None).await.unwrap();

        let RollbackOutcome::Applied(restored) =
            rollback(&pool, &name, 1, 2, Some("back")).await.unwrap()
        else {
            panic!("rollback should apply");
        };
        assert_eq!(restored.version, 3);
        assert_eq!(restored.spec, original);
        let newest = history(&pool, &name, None, 1).await.unwrap().remove(0);
        assert_eq!(newest.change, Change::Rollback);
        assert_eq!(newest.rollback_of, Some(1));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn rolling_back_to_a_deleted_version_is_refused() {
        let pool = connect_test_pool().await;
        let name = unique_name("deleted_target");
        let spec = minimal_spec(&name, &["/login"]);
        create(&pool, &spec, None).await.unwrap();
        let DeleteOutcome::Deleted { version } = delete(&pool, &name, 1, None).await.unwrap()
        else {
            panic!("delete should apply");
        };
        create(&pool, &spec, None).await.unwrap();
        let outcome = rollback(&pool, &name, version, 3, None).await.unwrap();
        assert!(matches!(outcome, RollbackOutcome::TargetDeleted));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_second_create_under_the_same_name_is_already_exists() {
        let pool = connect_test_pool().await;
        let spec = minimal_spec(&unique_name("create_twice"), &["/login"]);
        create(&pool, &spec, None).await.unwrap();
        let error = create(&pool, &spec, None).await.unwrap_err();
        assert!(matches!(error, SiteSpecStoreError::AlreadyExists));
    }
}
