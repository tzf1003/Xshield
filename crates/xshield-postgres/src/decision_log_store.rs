//! `PostgreSQL` storage for the decision log (docs/03-admin-config-audit.md
//! section 3.4): one row per judged request, written by the gateway and
//! queried by the control plane. This module performs no authorization
//! decisions of its own; it only stores and retrieves [`DecisionRecord`]s.

use std::fmt::Write as _;

use sqlx::{PgPool, Row};
use xshield_core::context::log::{DecisionPath, DecisionRecord, JevRecord, Outcome};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

/// One stored decision log row.
#[derive(Debug, Clone)]
pub struct DecisionLogRow {
    /// The row's id, usable as a `before_id` pagination cursor.
    pub id: i64,
    /// The decision record as the gateway produced it.
    pub record: DecisionRecord,
}

/// Filters for [`query`]. All fields are optional; `None` means unfiltered.
#[derive(Default)]
pub struct DecisionLogFilter {
    /// Exact site name.
    pub site: Option<String>,
    /// Session key prefix match.
    pub session_prefix: Option<String>,
    /// Path prefix match.
    pub path_prefix: Option<String>,
    /// Exact outcome.
    pub outcome: Option<Outcome>,
    /// Lower bound (inclusive) on `at_millis`.
    pub since_millis: Option<i64>,
    /// Upper bound (inclusive) on `at_millis`.
    pub until_millis: Option<i64>,
    /// Only rows with `id` strictly less than this, for backward pagination.
    pub before_id: Option<i64>,
    /// Maximum rows to return; clamped to [`MAX_LIMIT`] (not an error).
    pub limit: i64,
}

/// Failure of a decision log storage operation.
#[derive(Debug)]
pub enum DecisionLogStoreError {
    /// The underlying database operation failed.
    Database(sqlx::Error),
    /// Storing or loading a [`JevRecord`] as JSON failed.
    Serialize(serde_json::Error),
    /// A stored row held a `decision_path`/`outcome` string this build does
    /// not recognize.
    CorruptRow(&'static str),
}

impl std::fmt::Display for DecisionLogStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::Serialize(error) => write!(formatter, "serialization error: {error}"),
            Self::CorruptRow(field) => write!(formatter, "invalid stored {field}"),
        }
    }
}

impl std::error::Error for DecisionLogStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Serialize(error) => Some(error),
            Self::CorruptRow(_) => None,
        }
    }
}

impl From<sqlx::Error> for DecisionLogStoreError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

fn decision_path_str(value: DecisionPath) -> &'static str {
    match value {
        DecisionPath::FastAllow => "fast_allow",
        DecisionPath::CachedAllow => "cached_allow",
        DecisionPath::JevAllow => "jev_allow",
        DecisionPath::JevDeny => "jev_deny",
        DecisionPath::JevUnavailable => "jev_unavailable",
        DecisionPath::NoSession => "no_session",
    }
}

fn parse_decision_path(value: &str) -> Option<DecisionPath> {
    Some(match value {
        "fast_allow" => DecisionPath::FastAllow,
        "cached_allow" => DecisionPath::CachedAllow,
        "jev_allow" => DecisionPath::JevAllow,
        "jev_deny" => DecisionPath::JevDeny,
        "jev_unavailable" => DecisionPath::JevUnavailable,
        "no_session" => DecisionPath::NoSession,
        _ => return None,
    })
}

/// The wire/storage spelling of an [`Outcome`], e.g. `"would_block"`.
///
/// Exposed so the HTTP layer can validate an `outcome` query parameter using
/// the exact same strings this store accepts.
#[must_use]
pub fn outcome_str(value: Outcome) -> &'static str {
    match value {
        Outcome::Allowed => "allowed",
        Outcome::Blocked => "blocked",
        Outcome::WouldBlock => "would_block",
        Outcome::Unjudged => "unjudged",
    }
}

/// Parses the wire/storage spelling of an [`Outcome`].
#[must_use]
pub fn parse_outcome(value: &str) -> Option<Outcome> {
    Some(match value {
        "allowed" => Outcome::Allowed,
        "blocked" => Outcome::Blocked,
        "would_block" => Outcome::WouldBlock,
        "unjudged" => Outcome::Unjudged,
        _ => return None,
    })
}

fn row_to_decision(row: &sqlx::postgres::PgRow) -> Result<DecisionLogRow, DecisionLogStoreError> {
    let id: i64 = row.try_get("id")?;
    let at_millis: i64 = row.try_get("at_millis")?;
    let site: String = row.try_get("site")?;
    let request_id: String = row.try_get("request_id")?;
    let session: String = row.try_get("session")?;
    let method: String = row.try_get("method")?;
    let path: String = row.try_get("path")?;
    let status: Option<i32> = row.try_get("status")?;
    let decision_path: String = row.try_get("decision_path")?;
    let outcome: String = row.try_get("outcome")?;
    let jev: Option<serde_json::Value> = row.try_get("jev")?;
    let decision_path = parse_decision_path(&decision_path)
        .ok_or(DecisionLogStoreError::CorruptRow("decision_path"))?;
    let outcome = parse_outcome(&outcome).ok_or(DecisionLogStoreError::CorruptRow("outcome"))?;
    let jev = jev
        .map(|value| {
            serde_json::from_value::<JevRecord>(value).map_err(DecisionLogStoreError::Serialize)
        })
        .transpose()?;
    Ok(DecisionLogRow {
        id,
        record: DecisionRecord {
            #[allow(clippy::cast_sign_loss)]
            at_millis: at_millis as u64,
            site,
            request_id,
            session,
            method,
            path,
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            status: status.map(|value| value as u16),
            decision_path,
            outcome,
            jev,
        },
    })
}

/// Inserts one decision record, returning the new row id.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database or serialization failure.
pub async fn insert(pool: &PgPool, record: &DecisionRecord) -> Result<i64, DecisionLogStoreError> {
    let jev = record
        .jev
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(DecisionLogStoreError::Serialize)?;
    #[allow(clippy::cast_possible_wrap)]
    let at_millis = record.at_millis as i64;
    let status = record.status.map(i32::from);
    let row = sqlx::query(
        "INSERT INTO decision_log (
            at_millis, site, request_id, session, method, path, status,
            decision_path, outcome, jev
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id",
    )
    .bind(at_millis)
    .bind(&record.site)
    .bind(&record.request_id)
    .bind(&record.session)
    .bind(&record.method)
    .bind(&record.path)
    .bind(status)
    .bind(decision_path_str(record.decision_path))
    .bind(outcome_str(record.outcome))
    .bind(&jev)
    .fetch_one(pool)
    .await?;
    Ok(row.try_get("id")?)
}

/// Queries the decision log, newest first, applying whichever filters are set.
///
/// `filter.limit` is clamped to at least 1 and at most 200; it is never an
/// error to ask for more.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database or deserialization failure.
pub async fn query(
    pool: &PgPool,
    filter: &DecisionLogFilter,
) -> Result<Vec<DecisionLogRow>, DecisionLogStoreError> {
    let limit = if filter.limit <= 0 {
        DEFAULT_LIMIT
    } else {
        filter.limit
    }
    .clamp(1, MAX_LIMIT);

    let mut sql = String::from(
        "SELECT id, at_millis, site, request_id, session, method, path, status,
                decision_path, outcome, jev
         FROM decision_log WHERE 1 = 1",
    );
    let mut index = 1;
    let mut push_clause = |sql: &mut String, clause: &str| {
        let _ = write!(sql, " AND {clause} ${index}");
        index += 1;
    };
    if filter.site.is_some() {
        push_clause(&mut sql, "site =");
    }
    if filter.session_prefix.is_some() {
        push_clause(&mut sql, "session LIKE");
    }
    if filter.path_prefix.is_some() {
        push_clause(&mut sql, "path LIKE");
    }
    if filter.outcome.is_some() {
        push_clause(&mut sql, "outcome =");
    }
    if filter.since_millis.is_some() {
        push_clause(&mut sql, "at_millis >=");
    }
    if filter.until_millis.is_some() {
        push_clause(&mut sql, "at_millis <=");
    }
    if filter.before_id.is_some() {
        push_clause(&mut sql, "id <");
    }
    let _ = write!(sql, " ORDER BY id DESC LIMIT ${index}");

    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
    if let Some(site) = &filter.site {
        query = query.bind(site.clone());
    }
    if let Some(prefix) = &filter.session_prefix {
        query = query.bind(like_prefix(prefix));
    }
    if let Some(prefix) = &filter.path_prefix {
        query = query.bind(like_prefix(prefix));
    }
    if let Some(outcome) = filter.outcome {
        query = query.bind(outcome_str(outcome));
    }
    if let Some(since) = filter.since_millis {
        query = query.bind(since);
    }
    if let Some(until) = filter.until_millis {
        query = query.bind(until);
    }
    if let Some(before_id) = filter.before_id {
        query = query.bind(before_id);
    }
    query = query.bind(limit);

    let rows = query.fetch_all(pool).await?;
    rows.iter().map(row_to_decision).collect()
}

/// Escapes `%`/`_`/`\` and appends `%`, for a `LIKE`-based prefix match.
fn like_prefix(prefix: &str) -> String {
    let mut escaped = String::with_capacity(prefix.len() + 1);
    for byte in prefix.chars() {
        if matches!(byte, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(byte);
    }
    escaped.push('%');
    escaped
}

/// Fetches one decision log row by id.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database or deserialization failure.
pub async fn get(pool: &PgPool, id: i64) -> Result<Option<DecisionLogRow>, DecisionLogStoreError> {
    let row = sqlx::query(
        "SELECT id, at_millis, site, request_id, session, method, path, status,
                decision_path, outcome, jev
         FROM decision_log WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(row_to_decision).transpose()
}

/// Deletes every row older than `cutoff_millis`, returning the row count.
///
/// Used by the hourly 7-day retention job.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database failure.
pub async fn purge_older_than(
    pool: &PgPool,
    cutoff_millis: i64,
) -> Result<u64, DecisionLogStoreError> {
    let result = sqlx::query("DELETE FROM decision_log WHERE at_millis < $1")
        .bind(cutoff_millis)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_path_round_trips_through_its_string_form() {
        for path in [
            DecisionPath::FastAllow,
            DecisionPath::CachedAllow,
            DecisionPath::JevAllow,
            DecisionPath::JevDeny,
            DecisionPath::JevUnavailable,
            DecisionPath::NoSession,
        ] {
            assert_eq!(
                parse_decision_path(decision_path_str(path)),
                Some(path),
                "{path:?}"
            );
        }
    }

    #[test]
    fn outcome_round_trips_through_its_string_form() {
        for outcome in [
            Outcome::Allowed,
            Outcome::Blocked,
            Outcome::WouldBlock,
            Outcome::Unjudged,
        ] {
            assert_eq!(
                parse_outcome(outcome_str(outcome)),
                Some(outcome),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn unknown_outcome_string_does_not_parse() {
        assert!(parse_outcome("nope").is_none());
        assert!(parse_decision_path("nope").is_none());
    }

    #[test]
    fn like_prefix_escapes_wildcards() {
        assert_eq!(like_prefix("abc"), "abc%");
        assert_eq!(like_prefix("a%b_c\\d"), "a\\%b\\_c\\\\d%");
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn insert_then_get_round_trips() {
        let pool = connect_test_pool().await;
        let record = DecisionRecord {
            at_millis: 1,
            site: "emr".to_owned(),
            request_id: "r1".to_owned(),
            session: "abcd1234".to_owned(),
            method: "GET".to_owned(),
            path: "/login".to_owned(),
            status: Some(200),
            decision_path: DecisionPath::FastAllow,
            outcome: Outcome::Allowed,
            jev: None,
        };
        let id = insert(&pool, &record).await.unwrap();
        let fetched = get(&pool, id).await.unwrap().unwrap();
        assert_eq!(fetched.record, record);
    }

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }
}
