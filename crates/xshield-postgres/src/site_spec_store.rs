//! `PostgreSQL` storage for site configuration and its change history
//! (docs/03-admin-config-audit.md section 3.2).
//!
//! Each site's current [`SiteSpec`] lives in `site_configs`, keyed by name.
//! Every create, update, rollback or delete also appends one row to
//! `site_config_history` recording the configuration before and after the
//! change, so the console can show history and roll back to an earlier
//! version. This module works directly against a [`PgPool`] with runtime
//! (not compile-time-checked) `sqlx` queries, and defines its own error type
//! rather than reusing the v3 `PostgresIdentityStore`/`StoreError`.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use xshield_core::context::SiteSpec;

/// A site's current stored configuration.
#[derive(Debug, Clone)]
pub struct SiteRecord {
    /// The validated site configuration.
    pub spec: SiteSpec,
    /// Starts at 1 and increments by 1 on every `update`; the gateway polls
    /// this on its own connection as a cheap change-detection signal.
    pub version: i64,
    /// When the row was first created.
    pub created_at: DateTime<Utc>,
    /// When the row was last changed.
    pub updated_at: DateTime<Utc>,
}

/// One row of a site's configuration history.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// History row id, used to select a rollback target.
    pub id: i64,
    /// The configuration before this change, or `None` for the first change.
    pub before: Option<SiteSpec>,
    /// The configuration after this change, or `None` when the site was deleted.
    pub after: Option<SiteSpec>,
    /// When this change was recorded.
    pub changed_at: DateTime<Utc>,
}

/// Outcome of rolling a site back to an earlier history entry.
#[derive(Debug)]
pub enum RollbackOutcome {
    /// The site or the history row does not exist.
    NotFound,
    /// The target history row's `after` is `None`: there is nothing to restore.
    TargetDeleted,
    /// The rollback was applied; this is the resulting current record.
    Applied(SiteRecord),
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
            Self::AlreadyExists => formatter.write_str("site name already exists"),
        }
    }
}

impl std::error::Error for SiteSpecStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Serialize(error) => Some(error),
            Self::InvalidStoredSpec | Self::AlreadyExists => None,
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

fn json_to_spec_opt(
    value: Option<&serde_json::Value>,
) -> Result<Option<SiteSpec>, SiteSpecStoreError> {
    value.map(json_to_spec).transpose()
}

fn row_to_record(row: &sqlx::postgres::PgRow) -> Result<SiteRecord, SiteSpecStoreError> {
    let spec: serde_json::Value = row.try_get("spec")?;
    Ok(SiteRecord {
        spec: json_to_spec(&spec)?,
        version: row.try_get("version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_history(row: &sqlx::postgres::PgRow) -> Result<HistoryEntry, SiteSpecStoreError> {
    let before: Option<serde_json::Value> = row.try_get("before")?;
    let after: Option<serde_json::Value> = row.try_get("after")?;
    Ok(HistoryEntry {
        id: row.try_get("id")?,
        before: json_to_spec_opt(before.as_ref())?,
        after: json_to_spec_opt(after.as_ref())?,
        changed_at: row.try_get("changed_at")?,
    })
}

/// Lists every site, ordered by name.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database failure or a stored
/// configuration that no longer validates.
pub async fn list(pool: &PgPool) -> Result<Vec<SiteRecord>, SiteSpecStoreError> {
    let rows = sqlx::query("SELECT spec, version, created_at, updated_at FROM site_configs ORDER BY name")
        .fetch_all(pool)
        .await?;
    rows.iter().map(row_to_record).collect()
}

/// Fetches one site by name.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database failure or a stored
/// configuration that no longer validates.
pub async fn get(pool: &PgPool, name: &str) -> Result<Option<SiteRecord>, SiteSpecStoreError> {
    let row = sqlx::query("SELECT spec, version, created_at, updated_at FROM site_configs WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    row.as_ref().map(row_to_record).transpose()
}

async fn insert_history(
    transaction: &mut Transaction<'_, Postgres>,
    name: &str,
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
) -> Result<(), SiteSpecStoreError> {
    sqlx::query(
        "INSERT INTO site_config_history (site_name, before, after) VALUES ($1, $2, $3)",
    )
    .bind(name)
    .bind(before)
    .bind(after)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Creates a new site, recording a history row with `before: NULL`.
///
/// # Errors
/// Returns [`SiteSpecStoreError::AlreadyExists`] if the name is taken, or
/// another [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn create(pool: &PgPool, spec: &SiteSpec) -> Result<SiteRecord, SiteSpecStoreError> {
    let json = spec_to_json(spec)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "INSERT INTO site_configs (name, spec) VALUES ($1, $2)
         RETURNING spec, version, created_at, updated_at",
    )
    .bind(spec.name())
    .bind(&json)
    .fetch_one(&mut *transaction)
    .await?;
    insert_history(&mut transaction, spec.name(), None, Some(&json)).await?;
    transaction.commit().await?;
    row_to_record(&row)
}

/// Updates an existing site's configuration, keyed by `name` (not
/// `spec.name()`; the caller decides whether a rename is allowed before
/// calling this).
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn update(
    pool: &PgPool,
    name: &str,
    spec: &SiteSpec,
) -> Result<Option<SiteRecord>, SiteSpecStoreError> {
    let mut transaction = pool.begin().await?;
    let existing = sqlx::query("SELECT spec FROM site_configs WHERE name = $1 FOR UPDATE")
        .bind(name)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(existing) = existing else {
        transaction.rollback().await?;
        return Ok(None);
    };
    let before: serde_json::Value = existing.try_get("spec")?;
    let after = spec_to_json(spec)?;
    let row = sqlx::query(
        "UPDATE site_configs SET spec = $2, version = version + 1, updated_at = now()
         WHERE name = $1
         RETURNING spec, version, created_at, updated_at",
    )
    .bind(name)
    .bind(&after)
    .fetch_one(&mut *transaction)
    .await?;
    insert_history(&mut transaction, name, Some(&before), Some(&after)).await?;
    transaction.commit().await?;
    Ok(Some(row_to_record(&row)?))
}

/// Deletes a site, recording a history row with `after: NULL`.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database failure.
pub async fn delete(pool: &PgPool, name: &str) -> Result<bool, SiteSpecStoreError> {
    let mut transaction = pool.begin().await?;
    let existing = sqlx::query("SELECT spec FROM site_configs WHERE name = $1 FOR UPDATE")
        .bind(name)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(existing) = existing else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let before: serde_json::Value = existing.try_get("spec")?;
    sqlx::query("DELETE FROM site_configs WHERE name = $1")
        .bind(name)
        .execute(&mut *transaction)
        .await?;
    insert_history(&mut transaction, name, Some(&before), None).await?;
    transaction.commit().await?;
    Ok(true)
}

/// Lists a site's history, newest first.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn history(
    pool: &PgPool,
    name: &str,
    limit: i64,
) -> Result<Vec<HistoryEntry>, SiteSpecStoreError> {
    let limit = limit.clamp(1, 200);
    let rows = sqlx::query(
        "SELECT id, before, after, changed_at FROM site_config_history
         WHERE site_name = $1 ORDER BY id DESC LIMIT $2",
    )
    .bind(name)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_history).collect()
}

/// Rolls a site back to the configuration recorded in history row
/// `history_id`, applying it as the new current configuration and recording
/// yet another history row for the rollback itself.
///
/// # Errors
/// Returns [`SiteSpecStoreError`] on a database or serialization failure.
pub async fn rollback(
    pool: &PgPool,
    name: &str,
    history_id: i64,
) -> Result<RollbackOutcome, SiteSpecStoreError> {
    let mut transaction = pool.begin().await?;
    let target = sqlx::query(
        "SELECT after FROM site_config_history WHERE id = $1 AND site_name = $2",
    )
    .bind(history_id)
    .bind(name)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(target) = target else {
        transaction.rollback().await?;
        return Ok(RollbackOutcome::NotFound);
    };
    let after: Option<serde_json::Value> = target.try_get("after")?;
    let Some(after) = after else {
        transaction.rollback().await?;
        return Ok(RollbackOutcome::TargetDeleted);
    };
    // Re-validate before writing it back as the current configuration: a row
    // written by an older build must still parse as today's `SiteSpec`.
    json_to_spec(&after)?;
    let current = sqlx::query("SELECT spec FROM site_configs WHERE name = $1 FOR UPDATE")
        .bind(name)
        .fetch_optional(&mut *transaction)
        .await?;
    let before: Option<serde_json::Value> = match &current {
        Some(row) => Some(row.try_get("spec")?),
        None => None,
    };
    let row = if current.is_some() {
        sqlx::query(
            "UPDATE site_configs SET spec = $2, version = version + 1, updated_at = now()
             WHERE name = $1
             RETURNING spec, version, created_at, updated_at",
        )
        .bind(name)
        .bind(&after)
        .fetch_one(&mut *transaction)
        .await?
    } else {
        sqlx::query(
            "INSERT INTO site_configs (name, spec) VALUES ($1, $2)
             RETURNING spec, version, created_at, updated_at",
        )
        .bind(name)
        .bind(&after)
        .fetch_one(&mut *transaction)
        .await?
    };
    insert_history(&mut transaction, name, before.as_ref(), Some(&after)).await?;
    transaction.commit().await?;
    Ok(RollbackOutcome::Applied(row_to_record(&row)?))
}

#[cfg(test)]
mod tests {
    // These storage-layer tests need a reachable PostgreSQL instance, which
    // this sandbox does not have. They document the expected behaviour and
    // are exercised in an environment with `XSHIELD_DATABASE_URL` set.

    use super::*;

    const MINIMAL: &str = r#"{
        "name": "emr",
        "hosts": ["emr.example.com"],
        "origin": "http://10.0.0.5:8080",
        "session": {"cookie": "SESSIONID"},
        "entries": ["/login"]
    }"#;

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn create_then_get_round_trips() {
        let pool = connect_test_pool().await;
        let spec = SiteSpec::from_json(MINIMAL).unwrap();
        let created = create(&pool, &spec).await.unwrap();
        assert_eq!(created.spec, spec);
        let fetched = get(&pool, spec.name()).await.unwrap().unwrap();
        assert_eq!(fetched.spec, spec);
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn create_twice_is_already_exists() {
        let pool = connect_test_pool().await;
        let spec = SiteSpec::from_json(MINIMAL).unwrap();
        create(&pool, &spec).await.unwrap();
        let error = create(&pool, &spec).await.unwrap_err();
        assert!(matches!(error, SiteSpecStoreError::AlreadyExists));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn update_missing_site_is_none() {
        let pool = connect_test_pool().await;
        let spec = SiteSpec::from_json(MINIMAL).unwrap();
        assert!(update(&pool, "missing", &spec).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn rollback_to_deleted_target_is_rejected() {
        let pool = connect_test_pool().await;
        let spec = SiteSpec::from_json(MINIMAL).unwrap();
        create(&pool, &spec).await.unwrap();
        delete(&pool, spec.name()).await.unwrap();
        let entries = history(&pool, spec.name(), 50).await.unwrap();
        let deleted_entry = entries.iter().find(|entry| entry.after.is_none()).unwrap();
        let outcome = rollback(&pool, spec.name(), deleted_entry.id).await.unwrap();
        assert!(matches!(outcome, RollbackOutcome::TargetDeleted));
    }

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_DATABASE_URL").expect("XSHIELD_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }
}
