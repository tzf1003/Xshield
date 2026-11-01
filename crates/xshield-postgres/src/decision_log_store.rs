//! `PostgreSQL` storage for the decision log (docs/07-console-architecture.md
//! sections 7.4, 7.8 and 7.9): one row per request the gateway handled,
//! partitioned by UTC day.
//!
//! The gateway writes most rows. This module reads them for the console, and
//! writes the rows an administrator imports from a gateway's file-mode output.
//! Nothing here decides anything about a request: the log is never an
//! authorization input (AGENTS.md).

use std::collections::{BTreeMap, HashSet};

use sqlx::{AssertSqlSafe, PgPool, Postgres, QueryBuilder, Row, postgres::PgRow};

use crate::decision_stats::SCAN_LIMIT;

/// Predicate for rows where Jev was actually called: a round trip happened,
/// including calls that timed out. Calls refused by the per-minute limit or
/// by the state size limit never reached Jev. The literal `jev IS NOT NULL`
/// lets the partial index `decision_log_jev_idx` be used.
pub const JEV_CALLED_SQL: &str = "jev IS NOT NULL AND jev_ms IS NOT NULL AND (jev_failure IS NULL \
     OR jev_failure NOT IN ('JEV_CALL_LIMIT', 'JEV_STATE_TOO_LARGE'))";

/// Predicate for rows that asked Jev for a decision: the calls of [`JEV_CALLED_SQL`]
/// plus the calls the per-minute limit refused. A refused call is demand that the
/// limit turned away, so the per-minute demand measurements count it.
pub const JEV_DEMAND_SQL: &str = "((jev IS NOT NULL AND jev_failure = 'JEV_CALL_LIMIT') \
     OR (jev IS NOT NULL AND jev_ms IS NOT NULL AND (jev_failure IS NULL \
     OR jev_failure NOT IN ('JEV_CALL_LIMIT', 'JEV_STATE_TOO_LARGE'))))";

/// How far either side of the time a request id encodes [`get_detail`] searches.
/// The row is written when the response ends, so it can come well after the
/// request arrived.
const DETAIL_WINDOW_MILLIS: i64 = 60_000;

/// Columns of a list row. Trace and Jev document are not selected here.
pub(crate) const SUMMARY_COLUMNS: &str = "id, at_millis, request_id, site, site_version, edge, host, \
     client, session, context, method, path, query, status, decision_path, outcome, total_ms, \
     jev_ms, jev_access, jev_attack, jev_confidence, jev_failure, (jev IS NOT NULL) AS has_jev";

/// Columns of a full row: the list columns plus the trace and the Jev document.
pub(crate) const DETAIL_COLUMNS: &str = "id, at_millis, request_id, site, site_version, edge, host, \
     client, session, context, method, path, query, status, decision_path, outcome, total_ms, \
     jev_ms, jev_access, jev_attack, jev_confidence, jev_failure, (jev IS NOT NULL) AS has_jev, \
     trace, jev";

/// Failure of a decision log storage operation.
#[derive(Debug)]
pub enum DecisionLogStoreError {
    /// The underlying database operation failed.
    Database(sqlx::Error),
    /// A stored row holds a value this build does not recognize.
    Corrupt(&'static str),
}

impl std::fmt::Display for DecisionLogStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::Corrupt(field) => write!(formatter, "invalid stored {field}"),
        }
    }
}

impl std::error::Error for DecisionLogStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Corrupt(_) => None,
        }
    }
}

impl From<sqlx::Error> for DecisionLogStoreError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

/// A decision log row without its trace and Jev document, as lists show it.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestSummary {
    /// Row id, the tie breaker for ordering and the live-mode cursor.
    pub id: i64,
    /// When the gateway received the request, Unix milliseconds.
    pub at_millis: i64,
    /// Gateway-assigned request id (`req_` plus 32 hex digits).
    pub request_id: String,
    /// Site name; `None` for a request whose host matched no site.
    pub site: Option<String>,
    /// Site configuration version in force when the request was judged.
    pub site_version: Option<i64>,
    /// Gateway instance that handled the request.
    pub edge: String,
    /// Host header, lower case.
    pub host: String,
    /// Client address.
    pub client: String,
    /// Session label (16 hex digits), empty when the request had no session.
    pub session: String,
    /// `session`, `address`, or `None` when no context applied.
    pub context: Option<String>,
    /// HTTP method.
    pub method: String,
    /// Request path without the query.
    pub path: String,
    /// Redacted query string, if any.
    pub query: Option<String>,
    /// Status returned to the client.
    pub status: Option<i16>,
    /// The deciding step, as stored (`fast_allow`, `jev_deny`, ...).
    pub decision_path: String,
    /// What the gateway did (`allowed`, `blocked`, `would_block`, `unjudged`).
    pub outcome: String,
    /// Total handling time in milliseconds.
    pub total_ms: Option<i32>,
    /// Jev round trip in milliseconds, when Jev was called.
    pub jev_ms: Option<i32>,
    /// Top answer of the access question.
    pub jev_access: Option<String>,
    /// Top answer of the attack question.
    pub jev_attack: Option<String>,
    /// The smaller of the two top probabilities.
    pub jev_confidence: Option<f32>,
    /// Failure code when Jev gave no usable answer.
    pub jev_failure: Option<String>,
    /// Whether a Jev document is stored for this row.
    pub has_jev: bool,
}

/// A full decision log row: the summary, the trace and the Jev document.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestDetail {
    /// The list columns.
    pub summary: RequestSummary,
    /// The per-request trace (docs/07 section 7.4.3); `{"v":0}` for old rows.
    pub trace: serde_json::Value,
    /// The Jev document (docs/07 section 7.5.1), when Jev was involved.
    pub jev: Option<serde_json::Value>,
}

/// Matches a status code exactly, or a whole class such as `4xx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusMatch {
    /// One status code.
    Exact(i16),
    /// A hundred-block, given by its first digit (4 means 400 to 499).
    Class(i16),
}

/// Matches a path exactly, or as a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMatch {
    /// The whole path.
    Exact(String),
    /// Paths starting with this text.
    Prefix(String),
}

/// Filters for the decision log. The time window is always present; every
/// other field narrows the result when set.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RequestFilter {
    /// Exact site name.
    pub site: Option<String>,
    /// Lower bound of `at_millis`, inclusive.
    pub since_millis: i64,
    /// Upper bound of `at_millis`, inclusive.
    pub until_millis: i64,
    /// Any of these outcomes.
    pub outcomes: Vec<String>,
    /// Any of these decision paths.
    pub decision_paths: Vec<String>,
    /// Exact method.
    pub method: Option<String>,
    /// Status code or class.
    pub status: Option<StatusMatch>,
    /// Path, exact or prefix.
    pub path: Option<PathMatch>,
    /// Exact session label.
    pub session: Option<String>,
    /// Exact client address.
    pub client: Option<String>,
    /// Exact request id.
    pub request_id: Option<String>,
    /// Top access answer, for example `DENY`.
    pub jev_access: Option<String>,
    /// Top attack answer, for example `ATTACK`.
    pub jev_attack: Option<String>,
    /// Failure code, for example `JEV_TIMEOUT`.
    pub jev_failure: Option<String>,
    /// Confidence strictly below this value.
    pub max_confidence: Option<f32>,
    /// Total handling time at least this many milliseconds.
    pub min_ms: Option<i32>,
    /// Jev round trip at least this many milliseconds.
    pub min_jev_ms: Option<i32>,
    /// Whether the Jev `state` was trimmed (`Some(true)`) or not (`Some(false)`).
    pub jev_trimmed: Option<bool>,
    /// Whether a Jev document exists.
    pub has_jev: Option<bool>,
    /// Exact site configuration version.
    pub site_version: Option<i64>,
    /// Whether the request matched an entry (`Some(true)`) or not.
    pub entry: Option<bool>,
    /// Whether rows whose `decision_path` is `bypass` or `unknown_site` are
    /// included. When false, they are hidden.
    pub include_unjudged: bool,
}

/// Escapes `%`, `_` and `\` so that the text matches literally in `LIKE`.
fn like_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// Appends the conditions of a request list or export: whether bypassed and
/// unknown-site rows count, the outcomes and the decision paths, then everything
/// that [`push_common_filter`] covers.
pub(crate) fn push_filter(query: &mut QueryBuilder<Postgres>, filter: &RequestFilter) {
    if !filter.include_unjudged {
        query.push(" AND decision_path NOT IN ('bypass', 'unknown_site')");
    }
    if !filter.outcomes.is_empty() {
        query
            .push(" AND outcome = ANY(")
            .push_bind(filter.outcomes.clone())
            .push(")");
        // The literal condition lets the partial index decision_log_attention_idx
        // serve the query (docs/07 section 7.8.3). It is implied by the bound one.
        if filter
            .outcomes
            .iter()
            .all(|outcome| matches!(outcome.as_str(), "blocked" | "would_block" | "unjudged"))
        {
            query.push(" AND outcome IN ('blocked', 'would_block', 'unjudged')");
        }
    }
    if !filter.decision_paths.is_empty() {
        query
            .push(" AND decision_path = ANY(")
            .push_bind(filter.decision_paths.clone())
            .push(")");
    }
    push_common_filter(query, filter);
}

/// Appends the conditions that counts and lists share: the time window, the
/// site and request attributes, the session, and the Jev conditions.
fn push_common_filter(query: &mut QueryBuilder<Postgres>, filter: &RequestFilter) {
    query
        .push(" AND at_millis >= ")
        .push_bind(filter.since_millis);
    query
        .push(" AND at_millis <= ")
        .push_bind(filter.until_millis);
    if let Some(site) = &filter.site {
        query.push(" AND site = ").push_bind(site.clone());
    }
    if let Some(method) = &filter.method {
        query.push(" AND method = ").push_bind(method.clone());
    }
    match &filter.status {
        Some(StatusMatch::Exact(code)) => {
            query.push(" AND status = ").push_bind(*code);
        }
        Some(StatusMatch::Class(class)) => {
            query
                .push(" AND status >= ")
                .push_bind(class * 100)
                .push(" AND status < ")
                .push_bind((class + 1) * 100);
        }
        None => {}
    }
    match &filter.path {
        Some(PathMatch::Exact(path)) => {
            query.push(" AND path = ").push_bind(path.clone());
        }
        Some(PathMatch::Prefix(prefix)) => {
            query
                .push(" AND path LIKE ")
                .push_bind(format!("{}%", like_escape(prefix)));
        }
        None => {}
    }
    if let Some(session) = &filter.session {
        // The literal condition lets the partial index decision_log_session_idx
        // serve the query (docs/07 section 7.8.3). An empty label matches the
        // requests without a session, which the index does not hold, so it gets
        // no literal.
        if !session.is_empty() {
            query.push(" AND session <> ''");
        }
        query.push(" AND session = ").push_bind(session.clone());
    }
    if let Some(client) = &filter.client {
        query.push(" AND client = ").push_bind(client.clone());
    }
    if let Some(request_id) = &filter.request_id {
        query
            .push(" AND request_id = ")
            .push_bind(request_id.clone());
    }
    if filter.jev_access.is_some()
        || filter.jev_attack.is_some()
        || filter.jev_failure.is_some()
        || filter.max_confidence.is_some()
    {
        // The literal condition lets the partial index decision_log_jev_idx serve
        // the query (docs/07 section 7.8.3). It is implied by the Jev conditions.
        query.push(" AND jev IS NOT NULL");
    }
    if let Some(access) = &filter.jev_access {
        query.push(" AND jev_access = ").push_bind(access.clone());
    }
    if let Some(attack) = &filter.jev_attack {
        query.push(" AND jev_attack = ").push_bind(attack.clone());
    }
    if let Some(failure) = &filter.jev_failure {
        query.push(" AND jev_failure = ").push_bind(failure.clone());
    }
    if let Some(confidence) = filter.max_confidence {
        query.push(" AND jev_confidence < ").push_bind(confidence);
    }
    if let Some(ms) = filter.min_ms {
        query.push(" AND total_ms >= ").push_bind(ms);
    }
    if let Some(ms) = filter.min_jev_ms {
        query.push(" AND jev_ms >= ").push_bind(ms);
    }
    push_jev_filter(query, filter);
}

/// Filters on the Jev document, the entry match and the site configuration version.
fn push_jev_filter(query: &mut QueryBuilder<Postgres>, filter: &RequestFilter) {
    match filter.jev_trimmed {
        Some(true) => {
            query.push(" AND COALESCE((jev->>'trim')::int, 0) > 0");
        }
        Some(false) => {
            query.push(" AND COALESCE((jev->>'trim')::int, 0) = 0");
        }
        None => {}
    }
    match filter.has_jev {
        Some(true) => {
            query.push(" AND jev IS NOT NULL");
        }
        Some(false) => {
            query.push(" AND jev IS NULL");
        }
        None => {}
    }
    if let Some(version) = filter.site_version {
        query.push(" AND site_version = ").push_bind(version);
    }
    match filter.entry {
        Some(true) => {
            query.push(" AND trace->>'entry' IS NOT NULL");
        }
        Some(false) => {
            query.push(" AND trace->>'entry' IS NULL");
        }
        None => {}
    }
}

pub(crate) fn summary_from_row(row: &PgRow) -> Result<RequestSummary, sqlx::Error> {
    Ok(RequestSummary {
        id: row.try_get("id")?,
        at_millis: row.try_get("at_millis")?,
        request_id: row.try_get("request_id")?,
        site: row.try_get("site")?,
        site_version: row.try_get("site_version")?,
        edge: row.try_get("edge")?,
        host: row.try_get("host")?,
        client: row.try_get("client")?,
        session: row.try_get("session")?,
        context: row.try_get("context")?,
        method: row.try_get("method")?,
        path: row.try_get("path")?,
        query: row.try_get("query")?,
        status: row.try_get("status")?,
        decision_path: row.try_get("decision_path")?,
        outcome: row.try_get("outcome")?,
        total_ms: row.try_get("total_ms")?,
        jev_ms: row.try_get("jev_ms")?,
        jev_access: row.try_get("jev_access")?,
        jev_attack: row.try_get("jev_attack")?,
        jev_confidence: row.try_get("jev_confidence")?,
        jev_failure: row.try_get("jev_failure")?,
        has_jev: row.try_get("has_jev")?,
    })
}

fn detail_from_row(row: &PgRow) -> Result<RequestDetail, sqlx::Error> {
    Ok(RequestDetail {
        summary: summary_from_row(row)?,
        trace: row.try_get("trace")?,
        jev: row.try_get("jev")?,
    })
}

/// Lists rows matching `filter`, newest first. `cursor` continues after an
/// `(at_millis, id)` pair; `limit` is clamped to 1 to 500.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database failure.
pub async fn list(
    pool: &PgPool,
    filter: &RequestFilter,
    cursor: Option<(i64, i64)>,
    limit: i64,
) -> Result<Vec<RequestSummary>, DecisionLogStoreError> {
    let mut query = QueryBuilder::<Postgres>::new(format!(
        "SELECT {SUMMARY_COLUMNS} FROM decision_log WHERE TRUE"
    ));
    push_filter(&mut query, filter);
    if let Some((at_millis, id)) = cursor {
        query
            .push(" AND (at_millis, id) < (")
            .push_bind(at_millis)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    query
        .push(" ORDER BY at_millis DESC, id DESC LIMIT ")
        .push_bind(limit.clamp(1, 500));
    let rows = query.build().fetch_all(pool).await?;
    rows.iter()
        .map(|row| summary_from_row(row).map_err(DecisionLogStoreError::from))
        .collect()
}

/// Counts of the quick-filter labels of the request list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestCounts {
    /// Judged requests: everything except `bypass` and `unknown_site`.
    pub judged: i64,
    /// Requests that need attention: outcome `blocked`, `would_block` or `unjudged`.
    pub attention: i64,
    /// Requests refused.
    pub blocked: i64,
    /// Requests that observe mode would have refused but forwarded.
    pub would_block: i64,
    /// Requests forwarded without a judgement.
    pub unjudged: i64,
    /// Requests that have a Jev document, including calls that were not made.
    pub jev: i64,
    /// Requests without a session credential that were not entries.
    pub no_session: i64,
    /// Bypassed requests (static resources).
    pub bypass: i64,
    /// Requests whose host matched no site.
    pub unknown_site: i64,
    /// False when the window holds the scan limit of rows or more, so the
    /// counts may cover only part of it.
    pub complete: bool,
}

/// Counts for every quick-filter label of the request list in one scan of the
/// window (docs/07 section 7.9.3). The counts ignore the outcome, decision path
/// and `include_unjudged` fields of `filter`, so bypassed and unknown-site
/// requests are counted too.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database failure.
pub async fn counts(
    pool: &PgPool,
    filter: &RequestFilter,
) -> Result<RequestCounts, DecisionLogStoreError> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT count(*) FILTER (WHERE decision_path NOT IN ('bypass', 'unknown_site')) AS judged,
            count(*) FILTER (WHERE outcome IN ('blocked', 'would_block', 'unjudged')) AS attention,
            count(*) FILTER (WHERE outcome = 'blocked') AS blocked,
            count(*) FILTER (WHERE outcome = 'would_block') AS would_block,
            count(*) FILTER (WHERE outcome = 'unjudged') AS unjudged,
            count(*) FILTER (WHERE jev IS NOT NULL) AS jev,
            count(*) FILTER (WHERE decision_path = 'no_session') AS no_session,
            count(*) FILTER (WHERE decision_path = 'bypass') AS bypass,
            count(*) FILTER (WHERE decision_path = 'unknown_site') AS unknown_site,
            count(*) AS scanned
         FROM (SELECT decision_path, outcome, jev FROM decision_log WHERE TRUE",
    );
    push_common_filter(&mut query, filter);
    query.push(format!(" LIMIT {SCAN_LIMIT}) AS window_rows"));
    let row = query.build().fetch_one(pool).await?;
    let scanned: i64 = row.try_get("scanned")?;
    Ok(RequestCounts {
        judged: row.try_get("judged")?,
        attention: row.try_get("attention")?,
        blocked: row.try_get("blocked")?,
        would_block: row.try_get("would_block")?,
        unjudged: row.try_get("unjudged")?,
        jev: row.try_get("jev")?,
        no_session: row.try_get("no_session")?,
        bypass: row.try_get("bypass")?,
        unknown_site: row.try_get("unknown_site")?,
        complete: scanned < SCAN_LIMIT,
    })
}

/// Fetches one full row by request id. The time window narrows the search to
/// one or two day partitions; `around_millis` is the time the id encodes.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database or decoding failure.
pub async fn get_detail(
    pool: &PgPool,
    request_id: &str,
    around_millis: i64,
) -> Result<Option<RequestDetail>, DecisionLogStoreError> {
    let sql = format!(
        "SELECT {DETAIL_COLUMNS} FROM decision_log
         WHERE request_id = $1 AND at_millis BETWEEN $2 AND $3 LIMIT 1"
    );
    let row = sqlx::query(AssertSqlSafe(sql))
        .bind(request_id)
        .bind(around_millis - DETAIL_WINDOW_MILLIS)
        .bind(around_millis + DETAIL_WINDOW_MILLIS)
        .fetch_optional(pool)
        .await?;
    row.as_ref()
        .map(detail_from_row)
        .transpose()
        .map_err(DecisionLogStoreError::from)
}

/// Finds list rows for a set of request ids within a time window.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database failure.
pub async fn find_summaries(
    pool: &PgPool,
    request_ids: &[String],
    from_millis: i64,
    to_millis: i64,
) -> Result<Vec<RequestSummary>, DecisionLogStoreError> {
    let sql = format!(
        "SELECT {SUMMARY_COLUMNS} FROM decision_log
         WHERE request_id = ANY($1) AND at_millis BETWEEN $2 AND $3"
    );
    let rows = sqlx::query(AssertSqlSafe(sql))
        .bind(request_ids.to_vec())
        .bind(from_millis)
        .bind(to_millis)
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|row| summary_from_row(row).map_err(DecisionLogStoreError::from))
        .collect()
}

/// The request before and after `(at_millis, id)` in the same session.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database failure.
pub async fn session_neighbors(
    pool: &PgPool,
    session: &str,
    at_millis: i64,
    id: i64,
) -> Result<(Option<String>, Option<String>), DecisionLogStoreError> {
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT request_id FROM decision_log
         WHERE session = $1 AND session <> '' AND (at_millis, id) < ($2, $3)
         ORDER BY at_millis DESC, id DESC LIMIT 1",
    )
    .bind(session)
    .bind(at_millis)
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let next: Option<String> = sqlx::query_scalar(
        "SELECT request_id FROM decision_log
         WHERE session = $1 AND session <> '' AND (at_millis, id) > ($2, $3)
         ORDER BY at_millis ASC, id ASC LIMIT 1",
    )
    .bind(session)
    .bind(at_millis)
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok((previous, next))
}

/// The request that issued each of the given session labels, found through the
/// `trace.response.issued_session` expression index.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database failure.
pub async fn issuing_requests(
    pool: &PgPool,
    labels: &[String],
) -> Result<BTreeMap<String, String>, DecisionLogStoreError> {
    let rows = sqlx::query(
        "SELECT trace #>> '{response,issued_session}' AS label, request_id
         FROM decision_log
         WHERE trace #>> '{response,issued_session}' = ANY($1)",
    )
    .bind(labels.to_vec())
    .fetch_all(pool)
    .await?;
    let mut issued = BTreeMap::new();
    for row in &rows {
        let label: Option<String> = row.try_get("label")?;
        if let Some(label) = label {
            issued.entry(label).or_insert(row.try_get("request_id")?);
        }
    }
    Ok(issued)
}

/// One page of full rows matching `filter`, newest first, for export.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database or decoding failure.
pub async fn export_page(
    pool: &PgPool,
    filter: &RequestFilter,
    cursor: Option<(i64, i64)>,
    limit: i64,
) -> Result<Vec<RequestDetail>, DecisionLogStoreError> {
    let mut query = QueryBuilder::<Postgres>::new(format!(
        "SELECT {DETAIL_COLUMNS} FROM decision_log WHERE TRUE"
    ));
    push_filter(&mut query, filter);
    if let Some((at_millis, id)) = cursor {
        query
            .push(" AND (at_millis, id) < (")
            .push_bind(at_millis)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    query.push(" ORDER BY at_millis DESC, id DESC LIMIT ");
    query.push_bind(limit.clamp(1, 1000));
    let rows = query.build().fetch_all(pool).await?;
    rows.iter()
        .map(|row| detail_from_row(row).map_err(DecisionLogStoreError::from))
        .collect()
}

/// One row to import or to insert, with the columns the gateway derives from
/// its trace and Jev document filled in by [`insert_many`].
#[derive(Debug, Clone, PartialEq)]
pub struct NewDecision {
    /// When the gateway received the request, Unix milliseconds.
    pub at_millis: i64,
    /// Gateway-assigned request id.
    pub request_id: String,
    /// Site name, or `None` for an unknown site.
    pub site: Option<String>,
    /// Site configuration version in force.
    pub site_version: Option<i64>,
    /// Gateway instance name.
    pub edge: String,
    /// Host header.
    pub host: String,
    /// Client address.
    pub client: String,
    /// Session label, empty when none.
    pub session: String,
    /// `session`, `address`, or `None`.
    pub context: Option<String>,
    /// HTTP method.
    pub method: String,
    /// Path without the query.
    pub path: String,
    /// Redacted query string.
    pub query: Option<String>,
    /// Status returned to the client.
    pub status: Option<i16>,
    /// Deciding step.
    pub decision_path: String,
    /// What the gateway did.
    pub outcome: String,
    /// The trace document.
    pub trace: serde_json::Value,
    /// The Jev document, when Jev was involved.
    pub jev: Option<serde_json::Value>,
}

/// Columns the gateway derives from the Jev document, filled the same way for
/// imported rows.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JevColumns {
    /// Jev round trip in milliseconds.
    pub jev_ms: Option<i32>,
    /// Top access answer.
    pub jev_access: Option<String>,
    /// Top attack answer.
    pub jev_attack: Option<String>,
    /// The smaller of the two top probabilities.
    pub jev_confidence: Option<f32>,
    /// Failure code.
    pub jev_failure: Option<String>,
}

/// The top answer of a probability map and its probability, ties going to the
/// first key in order.
fn top_choice(value: Option<&serde_json::Value>) -> Option<(String, f64)> {
    let map = value?.as_object()?;
    let mut best: Option<(String, f64)> = None;
    for (key, probability) in map {
        let Some(probability) = probability.as_f64() else {
            continue;
        };
        let better = match &best {
            Some((_, current)) => probability > *current,
            None => true,
        };
        if better {
            best = Some((key.clone(), probability));
        }
    }
    best
}

/// Derives the Jev columns of a row from its Jev document.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // a probability is stored as the real column type
pub fn jev_columns(jev: Option<&serde_json::Value>) -> JevColumns {
    let Some(jev) = jev else {
        return JevColumns::default();
    };
    let access = top_choice(jev.get("access"));
    let attack = top_choice(jev.get("attack"));
    let jev_confidence = match (&access, &attack) {
        (Some((_, first)), Some((_, second))) => Some(first.min(*second) as f32),
        _ => None,
    };
    JevColumns {
        jev_ms: jev
            .get("millis")
            .and_then(serde_json::Value::as_i64)
            .and_then(|millis| i32::try_from(millis).ok()),
        jev_access: access.map(|(key, _)| key),
        jev_attack: attack.map(|(key, _)| key),
        jev_confidence,
        jev_failure: jev
            .get("failure")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    }
}

/// The handling time recorded in a trace, in milliseconds.
#[must_use]
pub fn total_ms_of(trace: &serde_json::Value) -> Option<i32> {
    let millis = trace.pointer("/timing/total_ms")?.as_i64()?;
    i32::try_from(millis).ok()
}

/// Which of `rows` already exist, identified by `(request_id, at_millis)`.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database failure.
pub async fn existing_keys(
    pool: &PgPool,
    rows: &[NewDecision],
) -> Result<HashSet<(String, i64)>, DecisionLogStoreError> {
    let ids: Vec<String> = rows.iter().map(|row| row.request_id.clone()).collect();
    let times: Vec<i64> = rows.iter().map(|row| row.at_millis).collect();
    let found = sqlx::query(
        "SELECT request_id, at_millis FROM decision_log
         WHERE request_id = ANY($1) AND at_millis = ANY($2)",
    )
    .bind(ids)
    .bind(times)
    .fetch_all(pool)
    .await?;
    let mut keys = HashSet::with_capacity(found.len());
    for row in &found {
        keys.insert((row.try_get("request_id")?, row.try_get("at_millis")?));
    }
    Ok(keys)
}

/// Inserts rows in one statement, deriving their Jev and total time columns.
/// Returns the number of rows written.
///
/// # Errors
/// Returns [`DecisionLogStoreError`] on a database failure.
pub async fn insert_many(
    pool: &PgPool,
    rows: &[NewDecision],
) -> Result<u64, DecisionLogStoreError> {
    if rows.is_empty() {
        return Ok(0);
    }
    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO decision_log (at_millis, request_id, site, site_version, edge, host, client, \
         session, context, method, path, query, status, decision_path, outcome, total_ms, jev_ms, \
         jev_access, jev_attack, jev_confidence, jev_failure, trace, jev) ",
    );
    query.push_values(rows, |mut bind, row| {
        let columns = jev_columns(row.jev.as_ref());
        bind.push_bind(row.at_millis)
            .push_bind(row.request_id.clone())
            .push_bind(row.site.clone())
            .push_bind(row.site_version)
            .push_bind(row.edge.clone())
            .push_bind(row.host.clone())
            .push_bind(row.client.clone())
            .push_bind(row.session.clone())
            .push_bind(row.context.clone())
            .push_bind(row.method.clone())
            .push_bind(row.path.clone())
            .push_bind(row.query.clone())
            .push_bind(row.status)
            .push_bind(row.decision_path.clone())
            .push_bind(row.outcome.clone())
            .push_bind(total_ms_of(&row.trace))
            .push_bind(columns.jev_ms)
            .push_bind(columns.jev_access)
            .push_bind(columns.jev_attack)
            .push_bind(columns.jev_confidence)
            .push_bind(columns.jev_failure)
            .push_bind(row.trace.clone())
            .push_bind(row.jev.clone());
    });
    let result = query.build().execute(pool).await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    // The database tests need a reachable PostgreSQL instance and run when
    // `XSHIELD_TEST_DATABASE_URL` is set (scripts/test_postgres.sh does that after
    // applying `migrations/`).

    use super::*;
    use crate::partitions::{day_bounds_millis, ensure_partition, partition_name};
    use chrono::NaiveDate;
    use serde_json::json;
    use sqlx::{Connection, PgConnection};

    #[test]
    fn like_escape_protects_wildcards() {
        assert_eq!(like_escape("/a_b%c\\d"), "/a\\_b\\%c\\\\d");
    }

    #[test]
    fn jev_columns_take_the_top_answers_and_the_smaller_probability() {
        let jev = json!({
            "access": {"ALLOW": 0.12, "DENY": 0.86, "UNKNOWN": 0.02},
            "attack": {"BENIGN": 0.99, "ATTACK": 0.007, "UNKNOWN": 0.003},
            "millis": 512,
            "failure": null,
        });
        let columns = jev_columns(Some(&jev));
        assert_eq!(columns.jev_access.as_deref(), Some("DENY"));
        assert_eq!(columns.jev_attack.as_deref(), Some("BENIGN"));
        assert_eq!(columns.jev_ms, Some(512));
        assert_eq!(columns.jev_failure, None);
        let confidence = columns.jev_confidence.expect("confidence");
        assert!((confidence - 0.86).abs() < 1e-6);
    }

    #[test]
    fn a_failed_call_has_a_failure_code_and_no_answers() {
        let jev = json!({"access": {}, "attack": {}, "millis": 3002, "failure": "JEV_TIMEOUT"});
        let columns = jev_columns(Some(&jev));
        assert_eq!(columns.jev_failure.as_deref(), Some("JEV_TIMEOUT"));
        assert_eq!(columns.jev_access, None);
        assert_eq!(columns.jev_confidence, None);
    }

    #[test]
    fn total_time_comes_from_the_trace_timing() {
        assert_eq!(
            total_ms_of(&json!({"v": 1, "timing": {"total_ms": 812}})),
            Some(812)
        );
        assert_eq!(total_ms_of(&json!({"v": 0})), None);
    }

    /// The SQL text that [`push_filter`] adds to a request list over one window.
    fn filter_sql(filter: &RequestFilter) -> String {
        let mut query = QueryBuilder::<Postgres>::new("SELECT 1 FROM decision_log WHERE TRUE");
        push_filter(&mut query, filter);
        query.into_string()
    }

    fn window() -> RequestFilter {
        RequestFilter {
            since_millis: 0,
            until_millis: 1,
            ..RequestFilter::default()
        }
    }

    #[test]
    fn bypass_and_unknown_site_rows_are_hidden_unless_asked_for() {
        let hidden = filter_sql(&window());
        assert!(hidden.contains("AND decision_path NOT IN ('bypass', 'unknown_site')"));
        let shown = filter_sql(&RequestFilter {
            include_unjudged: true,
            ..window()
        });
        assert!(!shown.contains("NOT IN ('bypass', 'unknown_site')"));
    }

    #[test]
    fn attention_outcomes_add_the_literal_condition_only_when_all_qualify() {
        let attention = filter_sql(&RequestFilter {
            outcomes: vec!["blocked".to_owned(), "would_block".to_owned()],
            ..window()
        });
        assert!(attention.contains("AND outcome = ANY("));
        assert!(attention.contains("AND outcome IN ('blocked', 'would_block', 'unjudged')"));
        let mixed = filter_sql(&RequestFilter {
            outcomes: vec!["blocked".to_owned(), "allowed".to_owned()],
            ..window()
        });
        assert!(!mixed.contains("AND outcome IN ("));
    }

    #[test]
    fn jev_and_session_conditions_add_their_literal_predicates() {
        let by_access = filter_sql(&RequestFilter {
            jev_access: Some("DENY".to_owned()),
            ..window()
        });
        assert!(by_access.contains("AND jev IS NOT NULL"));
        let by_session = filter_sql(&RequestFilter {
            session: Some("7c1e9a40d2b35f61".to_owned()),
            ..window()
        });
        assert!(by_session.contains("AND session <> ''"));
        let no_session_label = filter_sql(&RequestFilter {
            session: Some(String::new()),
            ..window()
        });
        assert!(!no_session_label.contains("AND session <> ''"));
        let plain = filter_sql(&window());
        assert!(!plain.contains("AND jev IS NOT NULL"));
        assert!(!plain.contains("AND session <> ''"));
    }

    /// Rows written to a probe day for the plan checks: enough that the planner's
    /// statistics make the partial indexes the cheap path.
    const PROBE_ROWS: i64 = 2_000;

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }

    /// Creates the partition of `day`, fills it with rows in which the session
    /// label, the outcome and the Jev call are each rare, and analyzes it.
    /// Returns the bounds of the day in Unix milliseconds.
    async fn fill_probe_day(pool: &PgPool, day: NaiveDate) -> (i64, i64) {
        ensure_partition(pool, day).await.expect("partition");
        let (start, end) = day_bounds_millis(day).expect("bounds");
        sqlx::query(
            r#"INSERT INTO decision_log
                   (at_millis, request_id, edge, host, client, session, method, path,
                    decision_path, outcome, trace, jev, jev_ms)
               SELECT $1 + n, 'req_' || n, 'edge-1', 'probe.example.com', '10.0.0.1',
                      CASE WHEN n % 20 = 0 THEN 'session-probe' ELSE '' END,
                      'GET', '/probe',
                      CASE WHEN n % 10 = 0 THEN 'jev_deny' ELSE 'fast_allow' END,
                      CASE WHEN n % 25 = 0 THEN 'blocked' ELSE 'allowed' END,
                      '{"v":1}'::jsonb,
                      CASE WHEN n % 10 = 0 THEN '{"access":{"DENY":0.9}}'::jsonb END,
                      CASE WHEN n % 10 = 0 THEN 100 END
               FROM generate_series(1, $2) AS n"#,
        )
        .bind(start)
        .bind(PROBE_ROWS)
        .execute(pool)
        .await
        .expect("rows");
        let analyze = format!("ANALYZE \"{}\"", partition_name(day));
        sqlx::query(AssertSqlSafe(analyze))
            .execute(pool)
            .await
            .expect("analyze");
        (start, end)
    }

    /// Held by the two tests that write to the 2099-08-04 partition, so that they
    /// create it one at a time.
    static SHARED_DAY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A connection of its own, on which `statement` is prepared. Sequential scans
    /// are discouraged, so that the plan uses an index whenever one applies. Custom
    /// plans are forced: each plan is made for the call's literal arguments, so
    /// partition pruning leaves only the probe day's partition. A generic plan would
    /// cover every partition the database holds, and partitions that other tests
    /// create at the same time would change the plan. The setting is not shared with
    /// the pool.
    async fn prepared_on_own_connection(statement: &str) -> PgConnection {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        let mut connection = PgConnection::connect(&url).await.expect("connect");
        sqlx::raw_sql("SET plan_cache_mode = force_custom_plan; SET enable_seqscan = off")
            .execute(&mut connection)
            .await
            .expect("settings");
        sqlx::raw_sql(AssertSqlSafe(statement.to_owned()))
            .execute(&mut connection)
            .await
            .expect("prepare");
        connection
    }

    /// The plan lines of `EXPLAIN EXECUTE` for `call`, such as `probe(1, 2)`.
    /// EXPLAIN takes no bound parameters, so the arguments of `call` are literals
    /// that the test writes itself.
    async fn explain_execute(connection: &mut PgConnection, call: &str) -> Vec<String> {
        sqlx::query_scalar(AssertSqlSafe(format!("EXPLAIN (COSTS OFF) EXECUTE {call}")))
            .fetch_all(connection)
            .await
            .expect("explain")
    }

    /// Asserts that the plan scans a partition copy of `parent_index`. PostgreSQL
    /// names each copy after its partition, so the plan shows those names rather
    /// than the parent's.
    async fn assert_plan_scans(connection: &mut PgConnection, parent_index: &str, plan: &[String]) {
        let copies: Vec<String> = sqlx::query_scalar(
            "SELECT child.relname::text
             FROM pg_inherits inherits
             JOIN pg_class child ON child.oid = inherits.inhrelid
             JOIN pg_class parent ON parent.oid = inherits.inhparent
             WHERE parent.relname = $1",
        )
        .bind(parent_index)
        .fetch_all(&mut *connection)
        .await
        .expect("partition copies");
        let plan = plan.join("\n");
        assert!(
            plan.split_whitespace()
                .any(|token| copies.iter().any(|copy| copy == token)),
            "the plan does not scan {parent_index}:\n{plan}"
        );
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_session_timeline_scans_the_session_index() {
        let pool = connect_test_pool().await;
        let day = NaiveDate::from_ymd_opt(2099, 8, 1).expect("date");
        let (start, end) = fill_probe_day(&pool, day).await;
        let mut connection = prepared_on_own_connection(
            "PREPARE probe (text, bigint, bigint, bigint) AS
             SELECT id FROM decision_log
             WHERE session = $1 AND session <> '' AND at_millis >= $2 AND at_millis <= $3
             ORDER BY at_millis ASC, id ASC LIMIT $4",
        )
        .await;
        let plan = explain_execute(
            &mut connection,
            &format!("probe('session-probe', {start}, {end}, 100)"),
        )
        .await;
        assert_plan_scans(&mut connection, "decision_log_session_idx", &plan).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_attention_listing_scans_the_attention_index() {
        let pool = connect_test_pool().await;
        let day = NaiveDate::from_ymd_opt(2099, 8, 2).expect("date");
        let (start, end) = fill_probe_day(&pool, day).await;
        let mut connection = prepared_on_own_connection(
            "PREPARE probe (text[], bigint, bigint, bigint) AS
             SELECT id FROM decision_log
             WHERE outcome = ANY($1) AND outcome IN ('blocked', 'would_block', 'unjudged')
               AND at_millis >= $2 AND at_millis <= $3
             ORDER BY at_millis DESC, id DESC LIMIT $4",
        )
        .await;
        let plan = explain_execute(
            &mut connection,
            &format!("probe(ARRAY['blocked', 'would_block', 'unjudged'], {start}, {end}, 100)"),
        )
        .await;
        assert_plan_scans(&mut connection, "decision_log_attention_idx", &plan).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_jev_listing_scans_the_jev_index() {
        let pool = connect_test_pool().await;
        let day = NaiveDate::from_ymd_opt(2099, 8, 3).expect("date");
        let (start, end) = fill_probe_day(&pool, day).await;
        let mut connection = prepared_on_own_connection(&format!(
            "PREPARE probe (bigint, bigint, bigint) AS
             SELECT id FROM decision_log
             WHERE at_millis >= $1 AND at_millis <= $2 AND {JEV_CALLED_SQL}
             ORDER BY at_millis DESC, id DESC LIMIT $3"
        ))
        .await;
        let plan = explain_execute(&mut connection, &format!("probe({start}, {end}, 100)")).await;
        assert_plan_scans(&mut connection, "decision_log_jev_idx", &plan).await;
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn a_login_is_found_by_the_session_it_issued_and_is_not_on_its_rows() {
        use crate::decision_stats::{self, Scope, TimelineOnly};

        let _shared_day = SHARED_DAY.lock().await;
        let pool = connect_test_pool().await;
        let day = NaiveDate::from_ymd_opt(2099, 8, 4).expect("date");
        ensure_partition(&pool, day).await.expect("partition");
        let (start, end) = day_bounds_millis(day).expect("bounds");
        // The login is recorded under its client address with no session label. The
        // request after it carries the label that the login issued.
        sqlx::query(
            r#"INSERT INTO decision_log
                   (at_millis, request_id, site, edge, host, client, session, context,
                    method, path, decision_path, outcome, trace)
               VALUES
                   ($1, 'req_login_issue', 'emr', 'edge-1', 'emr.test', '192.0.2.9', '',
                    'address', 'POST', '/login', 'entry', 'allowed',
                    '{"response":{"issued_session":"sess-issued-1"}}'::jsonb),
                   ($2, 'req_after_login', 'emr', 'edge-1', 'emr.test', '192.0.2.9',
                    'sess-issued-1', 'session', 'GET', '/patients', 'fast_allow', 'allowed',
                    '{"response":{"entry_passed":false}}'::jsonb)"#,
        )
        .bind(start + 1_000)
        .bind(start + 2_000)
        .execute(&pool)
        .await
        .expect("rows");
        let scope = Scope {
            site: Some("emr".to_owned()),
            since_millis: start,
            until_millis: end,
        };
        let opening = decision_stats::issuing_row(&pool, "sess-issued-1")
            .await
            .expect("query")
            .expect("the login that issued the session");
        assert_eq!(opening.summary.request_id, "req_login_issue");
        let timeline = decision_stats::session_timeline(
            &pool,
            &scope,
            "sess-issued-1",
            TimelineOnly::All,
            None,
            10,
        )
        .await
        .expect("timeline");
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].summary.request_id, "req_after_login");
        let never = decision_stats::issuing_row(&pool, "sess-never-issued")
            .await
            .expect("query");
        assert!(never.is_none());
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn minute_peaks_counts_the_calls_the_limit_refused() {
        use crate::decision_stats::{self, Scope};

        let _shared_day = SHARED_DAY.lock().await;
        let pool = connect_test_pool().await;
        let day = NaiveDate::from_ymd_opt(2099, 8, 4).expect("date");
        ensure_partition(&pool, day).await.expect("partition");
        let (start, _end) = day_bounds_millis(day).expect("bounds");
        // (request id, offset in ms, Jev failure, Jev round trip in ms). Three calls
        // reached Jev, two were refused by the per-minute limit, and one was refused
        // for its state size, which never asks Jev at all.
        let rows = [
            ("req_call_1", 1_000_i64, None, Some(40_i64)),
            ("req_call_2", 2_000, None, Some(45)),
            ("req_call_3", 3_000, None, Some(50)),
            ("req_refused_1", 4_000, Some("JEV_CALL_LIMIT"), None),
            ("req_refused_2", 5_000, Some("JEV_CALL_LIMIT"), None),
            ("req_too_large", 6_000, Some("JEV_STATE_TOO_LARGE"), None),
        ];
        for (request_id, offset, failure, jev_ms) in rows {
            sqlx::query(
                r#"INSERT INTO decision_log
                       (at_millis, request_id, site, edge, host, client, session, context,
                        method, path, decision_path, outcome, trace, jev, jev_ms, jev_failure)
                   VALUES
                       ($1, $2, 'emr', 'edge-1', 'emr.test', '192.0.2.9', 'sess-busy',
                        'session', 'GET', '/a', 'fast_allow', 'allowed', '{}'::jsonb,
                        '{"prompt":"jq_0000000000000001"}'::jsonb, $3, $4)"#,
            )
            .bind(start + offset)
            .bind(request_id)
            .bind(jev_ms)
            .bind(failure)
            .execute(&pool)
            .await
            .expect("row");
        }
        let scope = Scope {
            site: Some("emr".to_owned()),
            since_millis: start,
            until_millis: start + 86_400_000,
        };
        let peaks = decision_stats::minute_peaks(&pool, &scope, false, 3)
            .await
            .expect("peaks");
        // Five calls demanded in one minute against a limit of three: the two refused
        // calls are demand, and the state-size refusal is not.
        assert_eq!(peaks.peak, 5);
        assert_eq!(peaks.excess, 2);
        assert_eq!(peaks.keys_over, 1);
    }
}
