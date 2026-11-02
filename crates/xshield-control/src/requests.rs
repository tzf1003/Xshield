//! Decision log requests: the list, the counts, one request in full, batch
//! lookup, export and import (docs/07-console-architecture.md sections 7.3.1,
//! 7.9.3 to 7.9.5 and 7.9.9).
//!
//! A request id names its own time: its first twelve hex digits are Unix
//! milliseconds, so the lookup reads only the day partitions around that time.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io,
    sync::Arc,
};

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use xshield_postgres::{
    decision_log_store::{
        self, NewDecision, PathMatch, RequestDetail, RequestFilter, RequestSummary, StatusMatch,
    },
    partitions,
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    params::{Params, format_cursor, json_body, now_millis},
};

/// Outcomes a request may filter on, as the gateway writes them.
const OUTCOMES: &[&str] = &["allowed", "blocked", "would_block", "unjudged"];
/// Deciding steps a request may filter on, as the gateway writes them (7.4.1).
const DECISION_PATHS: &[&str] = &[
    "fast_allow",
    "cached_allow",
    "jev_allow",
    "jev_deny",
    "jev_unavailable",
    "no_session",
    "body_not_inspectable",
    "bypass",
    "unknown_site",
];
/// Paths that are not a judgement of a site's request, so judged views leave them out.
const HIDDEN_PATHS: &[&str] = &["bypass", "unknown_site"];
const DEFAULT_PAGE: i64 = 100;
const MAX_PAGE: i64 = 500;
const SITE_MAX_CHARS: usize = 64;
const TEXT_MAX_CHARS: usize = 64;
const PATH_MAX_CHARS: usize = 512;
/// How far a request may trail its own id in time: the gateway writes the row after the response.
const LOOKBACK_MILLIS: i64 = 60_000;
const LOOKUP_MAX_IDS: usize = 1_000;
const SOURCES_MAX: usize = 1_000;
const EXPORT_MAX_ROWS: usize = 100_000;
const EXPORT_PAGE: i64 = 1_000;
const IMPORT_LOOKUP_CHUNK: usize = 1_000;
const IMPORT_WRITE_CHUNK: usize = 500;
const IMPORT_ERROR_LINES: usize = 20;
const CSV_HEADER: &str = "id,request_id,at_millis,site,site_version,edge,host,client,session,\
context,method,path,query,status,decision_path,outcome,total_ms,jev_ms,jev_access,jev_attack,\
jev_confidence,jev_failure\n";

/// The time a request id encodes, in Unix milliseconds: the first twelve hex
/// digits after `req_`. `None` for anything that is not `req_` and 32 lowercase hex.
#[must_use]
pub fn request_time_millis(request_id: &str) -> Option<i64> {
    let hex = request_id.strip_prefix("req_")?;
    if hex.len() != 32
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let millis = u64::from_str_radix(hex.get(..12)?, 16).ok()?;
    i64::try_from(millis).ok()
}

/// The window that covers every time in `times`, with the lookback on both ends.
fn window_around(times: &[i64]) -> Option<(i64, i64)> {
    let earliest = times.iter().min()?;
    let latest = times.iter().max()?;
    Some((
        earliest.saturating_sub(LOOKBACK_MILLIS),
        latest.saturating_add(LOOKBACK_MILLIS),
    ))
}

fn bounded_text(params: &Params, name: &str, max_chars: usize) -> ApiResult<Option<String>> {
    match params.text(name) {
        None => Ok(None),
        Some(value) if value.chars().count() <= max_chars => Ok(Some(value.to_owned())),
        Some(_) => Err(ApiError::invalid_filter(name)),
    }
}

fn method_param(params: &Params) -> ApiResult<Option<String>> {
    match params.text("method") {
        None => Ok(None),
        Some(method)
            if method.len() <= 16 && method.bytes().all(|byte| byte.is_ascii_uppercase()) =>
        {
            Ok(Some(method.to_owned()))
        }
        Some(_) => Err(ApiError::invalid_filter("method")),
    }
}

/// `404` for one code, `4xx` for a class.
fn status_param(params: &Params) -> ApiResult<Option<StatusMatch>> {
    let Some(raw) = params.text("status") else {
        return Ok(None);
    };
    if let Some(class) = raw.strip_suffix("xx") {
        return match class.parse::<i16>() {
            Ok(class) if (1..=5).contains(&class) => Ok(Some(StatusMatch::Class(class))),
            _ => Err(ApiError::invalid_filter("status")),
        };
    }
    match raw.parse::<i16>() {
        Ok(code) if (100..=599).contains(&code) => Ok(Some(StatusMatch::Exact(code))),
        _ => Err(ApiError::invalid_filter("status")),
    }
}

/// An exact path, or a prefix when the parameter ends in `*`.
fn path_param(params: &Params) -> ApiResult<Option<PathMatch>> {
    let Some(raw) = params.text("path") else {
        return Ok(None);
    };
    if !raw.starts_with('/') || raw.chars().count() > PATH_MAX_CHARS {
        return Err(ApiError::invalid_filter("path"));
    }
    Ok(Some(match raw.strip_suffix('*') {
        Some(prefix) => PathMatch::Prefix(prefix.to_owned()),
        None => PathMatch::Exact(raw.to_owned()),
    }))
}

fn confidence_param(params: &Params) -> ApiResult<Option<f32>> {
    match params.text("max_confidence") {
        None => Ok(None),
        Some(raw) => raw
            .parse::<f32>()
            .ok()
            .filter(|value| (0.0..=1.0).contains(value))
            .map(Some)
            .ok_or_else(|| ApiError::invalid_filter("max_confidence")),
    }
}

fn min_ms_param(params: &Params) -> ApiResult<Option<i32>> {
    match params.int("min_ms")? {
        None => Ok(None),
        Some(value) => i32::try_from(value)
            .ok()
            .filter(|millis| *millis >= 0)
            .map(Some)
            .ok_or_else(|| ApiError::invalid_filter("min_ms")),
    }
}

/// The filter the list, the counts and the export share (docs/07 section
/// 7.9.3). `scope=all`, or naming `bypass` or `unknown_site` in
/// `decision_path`, lets those rows in.
fn filter_from(params: &Params, now: i64) -> ApiResult<RequestFilter> {
    let window = params.window(now)?;
    let decision_paths = params.list("decision_path", DECISION_PATHS)?;
    let scope_all = match params.text("scope") {
        None | Some("judged") => false,
        Some("all") => true,
        Some(_) => return Err(ApiError::invalid_filter("scope")),
    };
    let names_hidden = decision_paths
        .iter()
        .any(|path| HIDDEN_PATHS.contains(&path.as_str()));
    Ok(RequestFilter {
        site: bounded_text(params, "site", SITE_MAX_CHARS)?,
        since_millis: window.since_millis,
        until_millis: window.until_millis,
        outcomes: params.list("outcome", OUTCOMES)?,
        decision_paths,
        include_unjudged: scope_all || names_hidden,
        method: method_param(params)?,
        status: status_param(params)?,
        path: path_param(params)?,
        session: bounded_text(params, "session", TEXT_MAX_CHARS)?,
        client: bounded_text(params, "client", TEXT_MAX_CHARS)?,
        request_id: bounded_text(params, "request_id", TEXT_MAX_CHARS)?,
        jev_access: bounded_text(params, "jev_access", TEXT_MAX_CHARS)?,
        jev_attack: bounded_text(params, "jev_attack", TEXT_MAX_CHARS)?,
        jev_failure: bounded_text(params, "jev_failure", TEXT_MAX_CHARS)?,
        max_confidence: confidence_param(params)?,
        min_ms: min_ms_param(params)?,
        min_jev_ms: None,
        jev_trimmed: None,
        has_jev: None,
        site_version: params.int("site_version")?,
        entry: params.flag("entry")?,
    })
}

/// One list row as the console shows it (docs/07 section 7.9.3). The trace and
/// the Jev document are left out: they come with the detail. The contract tests
/// round-trip the console's fixtures through this type (section 7.10.8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestRow {
    /// Row id.
    pub id: i64,
    /// Gateway-assigned request id.
    pub request_id: String,
    /// When the gateway received the request, Unix milliseconds.
    pub at_millis: i64,
    /// Site name; `None` when the host matched no site.
    pub site: Option<String>,
    /// Site configuration version the request was judged with.
    pub site_version: Option<i64>,
    /// HTTP method.
    pub method: String,
    /// Host header, lower case.
    pub host: String,
    /// Request path without the query.
    pub path: String,
    /// Redacted query string, if any.
    pub query: Option<String>,
    /// Status returned to the client.
    pub status: Option<i16>,
    /// The deciding step, as stored.
    pub decision_path: String,
    /// What the gateway did.
    pub outcome: String,
    /// Session label; empty when the request had no session.
    pub session: String,
    /// `session`, `address`, or `None` when no context applied.
    pub context: Option<String>,
    /// Client address.
    pub client: String,
    /// Total handling time in milliseconds.
    pub total_ms: Option<i32>,
    /// The Jev figures, present when a Jev document is stored for the row.
    pub jev: Option<JevRow>,
}

/// The Jev figures a list row shows; the whole document comes with the detail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevRow {
    /// Top answer of the access question.
    pub access: Option<String>,
    /// Top answer of the attack question.
    pub attack: Option<String>,
    /// The smaller of the two top probabilities, as the shortest decimal that reads
    /// back to the stored value (`0.88`, not `0.8799999952316284`).
    pub confidence: Option<f64>,
    /// Jev round trip in milliseconds.
    pub ms: Option<i32>,
    /// Failure code when Jev gave no usable answer.
    pub failure: Option<String>,
}

impl From<&RequestSummary> for RequestRow {
    fn from(row: &RequestSummary) -> Self {
        Self {
            id: row.id,
            request_id: row.request_id.clone(),
            at_millis: row.at_millis,
            site: row.site.clone(),
            site_version: row.site_version,
            method: row.method.clone(),
            host: row.host.clone(),
            path: row.path.clone(),
            query: row.query.clone(),
            status: row.status,
            decision_path: row.decision_path.clone(),
            outcome: row.outcome.clone(),
            session: row.session.clone(),
            context: row.context.clone(),
            client: row.client.clone(),
            total_ms: row.total_ms,
            jev: row.has_jev.then(|| JevRow {
                access: row.jev_access.clone(),
                attack: row.jev_attack.clone(),
                confidence: row.jev_confidence.map(shortest_decimal),
                ms: row.jev_ms,
                failure: row.jev_failure.clone(),
            }),
        }
    }
}

/// The shortest decimal that reads back to `value`. An `f32` widens to an `f64`
/// with noise (`0.88f32` is `0.8799999952316284`), and the console shows the figure
/// the gateway wrote.
fn shortest_decimal(value: f32) -> f64 {
    value
        .to_string()
        .parse()
        .unwrap_or_else(|_| f64::from(value))
}

/// `GET /api/requests` (docs/07 section 7.9.3): one page of requests, newest first, and
/// the cursor of the next page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestsPageBody {
    pub rows: Vec<RequestRow>,
    /// Null when the page is not full, so there is no next page.
    pub next_cursor: Option<String>,
}

/// `POST /api/requests/lookup`: one row per requested id, in the order given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LookupBody {
    pub rows: Vec<LookupRowBody>,
}

/// One id of a lookup. `summary` is set only when `found` is true.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LookupRowBody {
    pub request_id: String,
    pub found: bool,
    pub summary: Option<RequestRow>,
}

/// `GET /api/requests/{request_id}`: one request in full, with its session neighbours
/// and the summaries of the requests its trace refers to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestDetailBody {
    pub summary: RequestRow,
    pub edge: String,
    /// The stored trace (docs/07 section 7.4.3), kept as the gateway wrote it. The
    /// `Trace` type reads it, and the contract tests check it against the fixtures.
    pub trace: Value,
    /// The stored Jev document (docs/07 section 7.5.1), null when Jev was not involved.
    pub jev: Option<Value>,
    pub neighbors: NeighborsBody,
    /// The summaries of the requests the trace refers to, by request id. Ids past
    /// retention are missing.
    pub sources: BTreeMap<String, SourceBody>,
}

/// The requests before and after this one in its session, by request id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborsBody {
    pub prev: Option<String>,
    pub next: Option<String>,
}

/// A request the trace of another refers to, summarized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceBody {
    pub method: String,
    pub path: String,
    pub status: Option<i16>,
    pub decision_path: String,
    pub at_millis: i64,
}

/// `GET /api/requests`: one page of requests, newest first. Live mode asks
/// the same endpoint with a `since_millis` a minute behind the newest row.
///
/// # Errors
/// `INVALID_FILTER` naming the bad parameter, `WINDOW_TOO_LARGE` for a window
/// over seven days, `INTERNAL` for a database failure.
pub async fn list(
    State(state): State<Arc<ControlState>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<RequestsPageBody>> {
    let params = Params::from(query);
    let filter = filter_from(&params, now_millis())?;
    let limit = params.limit(DEFAULT_PAGE, MAX_PAGE)?;
    let cursor = params.cursor("cursor")?;
    let rows = decision_log_store::list(&state.pool, &filter, cursor, limit).await?;
    let full_page = i64::try_from(rows.len()).unwrap_or(i64::MAX) == limit;
    let next_cursor = rows
        .last()
        .filter(|_| full_page)
        .map(|row| format_cursor(row.at_millis, row.id));
    Ok(Json(RequestsPageBody {
        rows: rows.iter().map(RequestRow::from).collect(),
        next_cursor,
    }))
}

/// `GET /api/requests/counts` (docs/07 section 7.9.1): the quick-filter counts of the
/// window. `scanned` is written only when `complete` is false.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CountsBody {
    pub judged: i64,
    pub attention: i64,
    pub blocked: i64,
    pub would_block: i64,
    pub unjudged: i64,
    pub jev: i64,
    pub no_session: i64,
    pub bypass: i64,
    pub unknown_site: i64,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned: Option<i64>,
}

/// `GET /api/requests/counts`: the quick-filter counts, from one scan of the window.
/// The page and the outcome and path selections are not part of it.
///
/// # Errors
/// The same as [`list`] for the filters it shares, `INTERNAL` when the database
/// cannot be read.
pub async fn counts(
    State(state): State<Arc<ControlState>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<CountsBody>> {
    let params = Params::from(query);
    let filter = filter_from(&params, now_millis())?;
    let counts = decision_log_store::counts(&state.pool, &filter).await?;
    // Every row the count read is judged, bypassed or an unknown-site stub, so their sum is the scan.
    let scanned = counts.judged + counts.bypass + counts.unknown_site;
    Ok(Json(CountsBody {
        judged: counts.judged,
        attention: counts.attention,
        blocked: counts.blocked,
        would_block: counts.would_block,
        unjudged: counts.unjudged,
        jev: counts.jev,
        no_session: counts.no_session,
        bypass: counts.bypass,
        unknown_site: counts.unknown_site,
        complete: counts.complete,
        scanned: (!counts.complete).then_some(scanned),
    }))
}

/// The request ids a trace refers to: value sources, the cached decision, the
/// recent requests of the session and the entries it passed (docs/07 section 7.3.2).
fn collect_trace_ids(trace: &Value, out: &mut BTreeSet<String>) {
    if let Some(values) = trace.get("values").and_then(Value::as_array) {
        for value in values {
            if let Some(sources) = value.get("sources").and_then(Value::as_array) {
                for source in sources {
                    push_id(out, source.get("request_id"));
                }
            }
        }
    }
    push_id(out, trace.get("cache_source"));
    for key in ["recent", "entries_passed"] {
        if let Some(items) = trace
            .pointer(&format!("/session/{key}"))
            .and_then(Value::as_array)
        {
            for item in items {
                push_id(out, item.get("request_id"));
            }
        }
    }
}

fn push_id(out: &mut BTreeSet<String>, value: Option<&Value>) {
    if let Some(id) = value.and_then(Value::as_str) {
        out.insert(id.to_owned());
    }
}

/// The summaries of the requests a detail refers to, keyed by request id. Ids
/// past retention are missing from the result, which the console shows as such.
async fn sources_for(
    pool: &PgPool,
    detail: &RequestDetail,
) -> ApiResult<BTreeMap<String, SourceBody>> {
    let mut ids = BTreeSet::new();
    collect_trace_ids(&detail.trace, &mut ids);
    if !detail.summary.session.is_empty() {
        let issued = decision_log_store::issuing_requests(
            pool,
            std::slice::from_ref(&detail.summary.session),
        )
        .await?;
        if let Some(id) = issued.get(&detail.summary.session) {
            ids.insert(id.to_owned());
        }
    }
    let times: Vec<i64> = ids
        .iter()
        .filter_map(|id| request_time_millis(id))
        .take(SOURCES_MAX)
        .collect();
    let Some((from, to)) = window_around(&times) else {
        return Ok(BTreeMap::new());
    };
    let wanted: Vec<String> = ids.into_iter().take(SOURCES_MAX).collect();
    let found = decision_log_store::find_summaries(pool, &wanted, from, to).await?;
    let mut sources = BTreeMap::new();
    for row in found {
        sources.insert(
            row.request_id.clone(),
            SourceBody {
                method: row.method,
                path: row.path,
                status: row.status,
                decision_path: row.decision_path,
                at_millis: row.at_millis,
            },
        );
    }
    Ok(sources)
}

/// `GET /api/requests/{request_id}`: one request in full, with its session
/// neighbours and the summaries of the requests its trace refers to.
///
/// # Errors
/// `REQUEST_NOT_FOUND` for an unknown id or one whose time cannot be read.
pub async fn detail(
    State(state): State<Arc<ControlState>>,
    Path(request_id): Path<String>,
) -> ApiResult<Json<RequestDetailBody>> {
    let not_found = || ApiError::new(axum::http::StatusCode::NOT_FOUND, "REQUEST_NOT_FOUND");
    let at = request_time_millis(&request_id).ok_or_else(not_found)?;
    let found = decision_log_store::get_detail(&state.pool, &request_id, at)
        .await?
        .ok_or_else(not_found)?;
    let (prev, next) = if found.summary.session.is_empty() {
        (None, None)
    } else {
        decision_log_store::session_neighbors(
            &state.pool,
            &found.summary.session,
            found.summary.at_millis,
            found.summary.id,
        )
        .await?
    };
    let sources = sources_for(&state.pool, &found).await?;
    Ok(Json(RequestDetailBody {
        summary: RequestRow::from(&found.summary),
        edge: found.summary.edge,
        trace: found.trace,
        jev: found.jev,
        neighbors: NeighborsBody { prev, next },
        sources,
    }))
}

/// The request body of a batch lookup: `{"ids": [...]}`, deduplicated in order.
fn lookup_ids(body: &Value) -> ApiResult<Vec<String>> {
    let items = body
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::invalid_body("ids"))?;
    let mut seen = BTreeSet::new();
    let mut ids = Vec::new();
    for item in items {
        let id = item.as_str().ok_or_else(|| ApiError::invalid_body("ids"))?;
        if seen.insert(id.to_owned()) {
            ids.push(id.to_owned());
        }
    }
    if ids.len() > LOOKUP_MAX_IDS {
        return Err(
            ApiError::new(axum::http::StatusCode::BAD_REQUEST, "TOO_MANY_IDS").in_field("ids"),
        );
    }
    Ok(ids)
}

/// `POST /api/requests/lookup`: finds many requests at once, one row per id in
/// the order given. Ids that are not found, or whose time cannot be read, come
/// back with `found: false`.
///
/// # Errors
/// `INVALID_BODY` for a body without an `ids` array, `TOO_MANY_IDS` above 1000.
pub async fn lookup(
    State(state): State<Arc<ControlState>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> ApiResult<Json<LookupBody>> {
    let body: Value = json_body(&headers, &body)?;
    let ids = lookup_ids(&body)?;
    let readable: Vec<String> = ids
        .iter()
        .filter(|id| request_time_millis(id).is_some())
        .cloned()
        .collect();
    let times: Vec<i64> = readable
        .iter()
        .filter_map(|id| request_time_millis(id))
        .collect();
    let found: BTreeMap<String, RequestSummary> = match window_around(&times) {
        Some((from, to)) => decision_log_store::find_summaries(&state.pool, &readable, from, to)
            .await?
            .into_iter()
            .map(|row| (row.request_id.clone(), row))
            .collect(),
        None => BTreeMap::new(),
    };
    let rows = ids
        .iter()
        .map(|id| match found.get(id) {
            Some(row) => LookupRowBody {
                request_id: id.clone(),
                found: true,
                summary: Some(RequestRow::from(row)),
            },
            None => LookupRowBody {
                request_id: id.clone(),
                found: false,
                summary: None,
            },
        })
        .collect();
    Ok(Json(LookupBody { rows }))
}

/// A decision-log row as the gateway's file mode writes it (docs/07 section 7.9.9).
fn jsonl_line(detail: &RequestDetail) -> String {
    let row = &detail.summary;
    let line = json!({
        "at_millis": row.at_millis,
        "request_id": row.request_id,
        "site": row.site,
        "site_version": row.site_version,
        "edge": row.edge,
        "host": row.host,
        "client": row.client,
        "session": row.session,
        "context": row.context,
        "method": row.method,
        "path": row.path,
        "query": row.query,
        "status": row.status,
        "decision_path": row.decision_path,
        "outcome": row.outcome,
        "trace": detail.trace,
        "jev": detail.jev,
    });
    format!("{line}\n")
}

/// One CSV cell. A value that a spreadsheet would read as a formula gets a
/// leading quote (section 7.9.9), and the cell is quoted when it needs to be.
#[must_use]
pub fn csv_cell(value: &str) -> String {
    let mut cell = value.to_owned();
    if cell.starts_with(['=', '+', '-', '@']) {
        cell.insert(0, '\'');
    }
    if cell.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell
    }
}

fn csv_line(detail: &RequestDetail) -> String {
    let row = &detail.summary;
    let cells = [
        json!(row.id),
        json!(row.request_id),
        json!(row.at_millis),
        json!(row.site),
        json!(row.site_version),
        json!(row.edge),
        json!(row.host),
        json!(row.client),
        json!(row.session),
        json!(row.context),
        json!(row.method),
        json!(row.path),
        json!(row.query),
        json!(row.status),
        json!(row.decision_path),
        json!(row.outcome),
        json!(row.total_ms),
        json!(row.jev_ms),
        json!(row.jev_access),
        json!(row.jev_attack),
        json!(row.jev_confidence),
        json!(row.jev_failure),
    ];
    let line: Vec<String> = cells
        .iter()
        .map(|cell| match cell {
            Value::Null => String::new(),
            Value::String(text) => csv_cell(text),
            other => csv_cell(&other.to_string()),
        })
        .collect();
    format!("{}\n", line.join(","))
}

/// Writes the rows of a filter into `sender` a page at a time, so a large
/// export never sits whole in memory. A database failure ends the body early;
/// the client sees the truncation rather than a silently short file.
async fn stream_export(
    pool: PgPool,
    filter: RequestFilter,
    csv: bool,
    sender: mpsc::Sender<Result<Bytes, io::Error>>,
) {
    if csv
        && sender
            .send(Ok(Bytes::from_static(CSV_HEADER.as_bytes())))
            .await
            .is_err()
    {
        return;
    }
    let mut cursor = None;
    let mut written = 0_usize;
    while written < EXPORT_MAX_ROWS {
        let page = match decision_log_store::export_page(&pool, &filter, cursor, EXPORT_PAGE).await
        {
            Ok(page) => page,
            Err(error) => {
                eprintln!("xshield-control: export failed: {error}");
                let _ = sender.send(Err(io::Error::other("export failed"))).await;
                return;
            }
        };
        let Some(last) = page.last() else {
            return;
        };
        cursor = Some((last.summary.at_millis, last.summary.id));
        let last_page = i64::try_from(page.len()).unwrap_or(i64::MAX) < EXPORT_PAGE;
        let mut chunk = String::new();
        for detail in page.iter().take(EXPORT_MAX_ROWS - written) {
            chunk.push_str(&if csv {
                csv_line(detail)
            } else {
                jsonl_line(detail)
            });
            written += 1;
        }
        if sender.send(Ok(Bytes::from(chunk))).await.is_err() || last_page {
            return;
        }
    }
}

/// `GET /api/requests/export?format=jsonl|csv`: the rows of a filter, newest
/// first, streamed. At most 100 000 rows.
///
/// # Errors
/// `INVALID_FILTER` for an unknown format or a bad filter.
pub async fn export(
    State(state): State<Arc<ControlState>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Response> {
    let params = Params::from(query);
    let now = now_millis();
    let csv = match params.text("format") {
        None | Some("jsonl") => false,
        Some("csv") => true,
        Some(_) => return Err(ApiError::invalid_filter("format")),
    };
    let filter = filter_from(&params, now)?;
    let (sender, receiver) = mpsc::channel(8);
    tokio::spawn(stream_export(state.pool.clone(), filter, csv, sender));
    let mut response = Body::from_stream(ReceiverStream::new(receiver)).into_response();
    let (content_type, extension) = if csv {
        ("text/csv; charset=utf-8", "csv")
    } else {
        ("application/x-ndjson; charset=utf-8", "jsonl")
    };
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(disposition) = HeaderValue::from_str(&format!(
        "attachment; filename=\"xshield-requests-{now}.{extension}\""
    )) {
        headers.insert(header::CONTENT_DISPOSITION, disposition);
    }
    Ok(response)
}

/// Reads one imported line, or returns `None` when it is not a decision row
/// this build understands. A line without `trace` is an older v4 row; it gets
/// `{"v": 0}` and the console labels it as an old format.
fn decision_from_json(value: &Value) -> Option<NewDecision> {
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    let decision_path = text("decision_path")?;
    let outcome = text("outcome")?;
    if !DECISION_PATHS.contains(&decision_path.as_str()) || !OUTCOMES.contains(&outcome.as_str()) {
        return None;
    }
    let status = match value.get("status") {
        None | Some(Value::Null) => None,
        Some(status) => Some(i16::try_from(status.as_i64()?).ok()?),
    };
    Some(NewDecision {
        at_millis: value.get("at_millis").and_then(Value::as_i64)?,
        request_id: text("request_id")?,
        site: text("site"),
        site_version: value.get("site_version").and_then(Value::as_i64),
        edge: "import".to_owned(),
        host: text("host").unwrap_or_default(),
        client: text("client").unwrap_or_default(),
        session: text("session").unwrap_or_default(),
        context: text("context"),
        method: text("method")?,
        path: text("path")?,
        query: text("query"),
        status,
        decision_path,
        outcome,
        trace: value
            .get("trace")
            .filter(|trace| !trace.is_null())
            .cloned()
            .unwrap_or_else(|| json!({ "v": 0 })),
        jev: value.get("jev").filter(|jev| !jev.is_null()).cloned(),
    })
}

/// What an import body held, line by line: the rows to write, the rows whose time
/// lies outside the kept window, and the lines that failed.
#[derive(Default)]
struct ImportLines {
    rows: Vec<NewDecision>,
    out_of_range: i64,
    failed: i64,
    error_lines: Vec<usize>,
}

/// Reads the lines of an import body against the day partitions that exist and the
/// kept `window` (both ends included, section 7.9.9). A row outside the window has no
/// partition to go to: it is counted as out of range, which is not an error. A line
/// that is not a row, or whose day has no partition, is an error, and its line number
/// is kept for the first few.
fn read_import_lines(
    body: &[u8],
    days: &HashSet<chrono::NaiveDate>,
    window: (i64, i64),
) -> ImportLines {
    let mut lines = ImportLines::default();
    for (index, line) in body.split(|byte| *byte == b'\n').enumerate() {
        let text = line.trim_ascii();
        if text.is_empty() {
            continue;
        }
        let row = serde_json::from_slice::<Value>(text)
            .ok()
            .as_ref()
            .and_then(decision_from_json);
        match row {
            Some(row) if row.at_millis < window.0 || row.at_millis > window.1 => {
                lines.out_of_range += 1;
            }
            Some(row)
                if DateTime::from_timestamp_millis(row.at_millis)
                    .is_some_and(|time| days.contains(&time.date_naive())) =>
            {
                lines.rows.push(row);
            }
            _ => {
                lines.failed += 1;
                if lines.error_lines.len() < IMPORT_ERROR_LINES {
                    lines.error_lines.push(index + 1);
                }
            }
        }
    }
    lines
}

/// `POST /api/import`: imports gateway file-mode output, one JSON row per line.
/// A row that already exists is skipped. A row outside the kept window is counted as
/// `out_of_range`, and a line that cannot be used is an error; the reply says which
/// lines failed.
///
/// # Errors
/// `INTERNAL` for a database failure while writing.
pub async fn import(State(state): State<Arc<ControlState>>, body: Bytes) -> ApiResult<Json<Value>> {
    let days: HashSet<chrono::NaiveDate> = partitions::list_partitions(&state.pool)
        .await?
        .iter()
        .filter_map(|partition| partition.day)
        .collect();
    let window = partitions::kept_window_millis(crate::params::now_millis());
    let lines = read_import_lines(&body, &days, window);
    let mut skipped = 0_i64;
    let mut seen = HashSet::new();
    let mut fresh = Vec::with_capacity(lines.rows.len());
    for row in lines.rows {
        if seen.insert((row.request_id.clone(), row.at_millis)) {
            fresh.push(row);
        } else {
            skipped += 1;
        }
    }
    let mut to_write = Vec::with_capacity(fresh.len());
    for chunk in fresh.chunks(IMPORT_LOOKUP_CHUNK) {
        let existing = decision_log_store::existing_keys(&state.pool, chunk).await?;
        for row in chunk {
            if existing.contains(&(row.request_id.clone(), row.at_millis)) {
                skipped += 1;
            } else {
                to_write.push(row.clone());
            }
        }
    }
    let mut imported = 0_u64;
    for chunk in to_write.chunks(IMPORT_WRITE_CHUNK) {
        imported += decision_log_store::insert_many(&state.pool, chunk).await?;
    }
    Ok(Json(json!({
        "imported": imported,
        "skipped": skipped,
        "out_of_range": lines.out_of_range,
        "errors": lines.failed,
        "error_lines": lines.error_lines,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_id_names_its_time_and_nothing_else_is_read() {
        assert_eq!(
            request_time_millis("req_01a19741107477ff9224781077354552"),
            Some(1_793_538_986_100)
        );
        assert_eq!(
            request_time_millis("req_01A19741107477FF9224781077354552"),
            None
        );
        assert_eq!(request_time_millis("req_short"), None);
        assert_eq!(
            request_time_millis("01a19741107477ff9224781077354552"),
            None
        );
    }

    #[test]
    fn csv_cells_neutralise_formulas_and_quote_separators() {
        assert_eq!(csv_cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell("-1"), "'-1");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("plain"), "plain");
    }

    #[test]
    fn a_window_covers_every_time_with_the_lookback_on_both_ends() {
        assert_eq!(
            window_around(&[10 * 60_000, 3 * 60_000]),
            Some((2 * 60_000, 11 * 60_000))
        );
        assert_eq!(window_around(&[]), None);
    }

    #[test]
    fn an_imported_row_needs_a_known_path_and_outcome() {
        let row = json!({
            "at_millis": 1_793_538_986_100_i64, "request_id": "req_x", "site": "juice",
            "method": "GET", "path": "/", "decision_path": "fast_allow", "outcome": "allowed",
        });
        let parsed = decision_from_json(&row).expect("a valid row");
        assert_eq!(parsed.edge, "import");
        assert_eq!(parsed.trace, json!({ "v": 0 }));
        let unknown = json!({
            "at_millis": 1, "request_id": "req_x", "method": "GET", "path": "/",
            "decision_path": "teleport", "outcome": "allowed",
        });
        assert!(decision_from_json(&unknown).is_none());
    }

    #[test]
    fn an_import_counts_a_row_outside_the_kept_window_apart_from_an_error() {
        const DAY: i64 = 86_400_000;
        // 2026-11-01 12:00 UTC, with the window and the partitions that hold it.
        let now: i64 = 1_793_491_200_000 + 12 * 3_600_000;
        let window = partitions::kept_window_millis(now);
        let days: HashSet<chrono::NaiveDate> =
            partitions::partition_days(chrono::NaiveDate::from_ymd_opt(2026, 11, 1).expect("date"))
                .into_iter()
                .collect();
        let row = |at_millis: i64, request_id: &str| {
            json!({
                "at_millis": at_millis, "request_id": request_id, "site": "juice",
                "method": "GET", "path": "/", "decision_path": "fast_allow", "outcome": "allowed",
            })
            .to_string()
        };
        let body = format!(
            "{}\n{}\n{{not json\n",
            row(now - 5 * DAY, "req_five"),
            row(now - 9 * DAY, "req_nine"),
        );
        let lines = read_import_lines(body.as_bytes(), &days, window);
        assert_eq!(lines.rows.len(), 1);
        assert_eq!(lines.out_of_range, 1);
        assert_eq!(lines.failed, 1);
        assert_eq!(lines.error_lines, vec![3]);

        // Inside the window but with no partition for its day: an error, not out of range.
        let lines = read_import_lines(body.as_bytes(), &HashSet::new(), window);
        assert!(lines.rows.is_empty());
        assert_eq!(lines.out_of_range, 1);
        assert_eq!(lines.failed, 2);
        assert_eq!(lines.error_lines, vec![1, 3]);
    }

    #[test]
    fn a_status_filter_takes_a_code_or_a_class() {
        let params = Params::from(BTreeMap::from([("status".to_owned(), "4xx".to_owned())]));
        assert_eq!(
            status_param(&params).expect("class"),
            Some(StatusMatch::Class(4))
        );
        let params = Params::from(BTreeMap::from([("status".to_owned(), "9xx".to_owned())]));
        assert!(status_param(&params).is_err());
    }

    #[test]
    fn lookups_are_deduplicated_in_order_and_capped() {
        let body = json!({ "ids": ["req_b", "req_a", "req_b"] });
        assert_eq!(
            lookup_ids(&body).expect("ids"),
            vec!["req_b".to_owned(), "req_a".to_owned()]
        );
        let many: Vec<String> = (0..=LOOKUP_MAX_IDS)
            .map(|index| format!("req_{index}"))
            .collect();
        let error = lookup_ids(&json!({ "ids": many })).expect_err("too many");
        assert_eq!(error.code(), "TOO_MANY_IDS");
    }

    #[test]
    fn a_trace_refers_to_its_sources_entries_and_cached_decision() {
        let trace = json!({
            "values": [{"sources": [{"request_id": "req_a"}, {"request_id": null}]}],
            "cache_source": "req_b",
            "session": {
                "recent": [{"request_id": "req_c"}],
                "entries_passed": [{"request_id": "req_d"}],
            },
        });
        let mut ids = BTreeSet::new();
        collect_trace_ids(&trace, &mut ids);
        assert_eq!(
            ids.into_iter().collect::<Vec<_>>(),
            vec![
                "req_a".to_owned(),
                "req_b".to_owned(),
                "req_c".to_owned(),
                "req_d".to_owned()
            ]
        );
    }
}
