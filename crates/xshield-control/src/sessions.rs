//! Session list and timeline (docs/07-console-architecture.md section 7.9.6).
//!
//! A session is the label of the credential a request carried. The list sums
//! each session's requests over the window; the timeline gives one session's
//! requests in time order, each with what its response taught the session.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use xshield_postgres::{
    decision_log_store,
    decision_stats::{self, SessionFlag, SessionRow, TimelineOnly, TimelineRow},
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    params::{Params, format_cursor, now_millis},
    requests::RequestRow,
    stats::scope_from,
};

/// Sessions the list shows when the caller names no size.
const LIST_DEFAULT: i64 = 100;
/// The largest session list.
const LIST_MAX: i64 = 200;
/// Requests a timeline page shows when the caller names no size.
const TIMELINE_DEFAULT: i64 = 200;
/// The largest timeline page.
const TIMELINE_MAX: i64 = 500;
/// The longest session label.
const LABEL_MAX_CHARS: usize = 64;

/// `GET /api/sessions` (docs/07 section 7.9.6): the sessions active in the window,
/// newest activity first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionsBody {
    pub rows: Vec<SessionRowBody>,
}

/// One session as the list shows it, and as the detail's `summary` does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRowBody {
    /// Session label (16 hex digits).
    pub label: String,
    /// `session` or `address`.
    pub context: Option<String>,
    /// Site the session belongs to, when one site was seen.
    pub site: Option<String>,
    /// Oldest request, Unix milliseconds.
    pub first_at_millis: i64,
    /// Newest request, Unix milliseconds.
    pub last_at_millis: i64,
    /// Requests in the window.
    pub requests: i64,
    /// Jev round trips.
    pub jev_calls: i64,
    /// Refused requests.
    pub blocked: i64,
    /// Requests observe mode would have refused.
    pub would_block: i64,
    /// The request that issued the session, when it is still within retention.
    pub issued_by: Option<String>,
}

/// `GET /api/sessions/{label}` (docs/07 section 7.9.6): the session's summary, its
/// requests in time order, and the cursor for the next page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionDetailBody {
    pub summary: SessionRowBody,
    pub rows: Vec<TimelineRowBody>,
    pub next_cursor: Option<String>,
}

/// One timeline row: the request row, then what its response taught the session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineRowBody {
    #[serde(flatten)]
    pub request: RequestRow,
    pub learned: Option<i64>,
    pub entry_passed: bool,
    pub issued_session: Option<String>,
    pub after_would_block: bool,
}

/// `GET /api/sessions`: `{"rows": [...]}`, the sessions active in the window,
/// newest activity first.
///
/// # Errors
/// `INVALID_FILTER` naming the bad parameter, `WINDOW_TOO_LARGE` for a window over
/// seven days, `INTERNAL` when the database cannot be read.
pub async fn list(
    State(state): State<Arc<ControlState>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<SessionsBody>> {
    let params = Params::from(query);
    let (scope, _) = scope_from(&params, now_millis())?;
    let flag = flag_param(&params)?;
    let limit = params.limit(LIST_DEFAULT, LIST_MAX)?;
    let sessions = decision_stats::sessions(&state.pool, &scope, None, flag, limit).await?;
    let issued = issuing_request_ids(&state.pool, &sessions).await?;
    let rows = sessions
        .iter()
        .map(|session| session_row(session, issued.get(&session.label).map(String::as_str)))
        .collect();
    Ok(Json(SessionsBody { rows }))
}

/// `GET /api/sessions/{label}`: `{"summary": ..., "rows": [...], "next_cursor": ...}`.
/// The summary is one list row. The rows are the session's requests in time order;
/// `only` picks them and defaults to the judged ones, as the request list does. On
/// the first page of `judged` or `all`, the login that opened the session leads the
/// rows. `next_cursor` is set only when the page is full.
///
/// # Errors
/// `INVALID_FILTER` naming `label` or another bad parameter, `SESSION_NOT_FOUND`
/// (404) when the session has no requests in the window, `INTERNAL` when the
/// database cannot be read.
pub async fn detail(
    State(state): State<Arc<ControlState>>,
    Path(label): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<SessionDetailBody>> {
    if !label_is_valid(&label) {
        return Err(ApiError::invalid_filter("label"));
    }
    let params = Params::from(query);
    let (scope, _) = scope_from(&params, now_millis())?;
    let only = only_param(&params)?;
    let limit = params.limit(TIMELINE_DEFAULT, TIMELINE_MAX)?;
    let cursor = params.cursor("cursor")?;
    let summary = decision_stats::sessions(
        &state.pool,
        &scope,
        Some(label.as_str()),
        SessionFlag::Any,
        1,
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "SESSION_NOT_FOUND"))?;
    let page =
        decision_stats::session_timeline(&state.pool, &scope, &label, only, cursor, limit).await?;
    let full_page = i64::try_from(page.len()).unwrap_or(i64::MAX) == limit;
    let next_cursor = page
        .last()
        .filter(|_| full_page)
        .map(|row| format_cursor(row.summary.at_millis, row.summary.id));
    // The login that opened the session precedes its requests (docs/07 section 7.9.6).
    // It is not on the session's own rows, so it is looked up apart.
    let opening = if cursor.is_none() && matches!(only, TimelineOnly::Judged | TimelineOnly::All) {
        decision_stats::issuing_row(&state.pool, &label).await?
    } else {
        None
    };
    let issued = issuing_request_ids(&state.pool, std::slice::from_ref(&summary)).await?;
    let rows = opening
        .iter()
        .chain(page.iter())
        .map(timeline_row)
        .collect();
    Ok(Json(SessionDetailBody {
        summary: session_row(&summary, issued.get(&label).map(String::as_str)),
        rows,
        next_cursor,
    }))
}

/// One session as the list shows it, and as the detail's `summary` does: its label,
/// context and site, the first and last request in Unix milliseconds, the counts, and
/// the request that issued it.
#[must_use]
fn session_row(session: &SessionRow, issued_by: Option<&str>) -> SessionRowBody {
    SessionRowBody {
        label: session.label.clone(),
        context: session.context.clone(),
        site: session.site.clone(),
        first_at_millis: session.first_at,
        last_at_millis: session.last_at,
        requests: session.requests,
        jev_calls: session.jev_calls,
        blocked: session.blocked,
        would_block: session.would_block,
        issued_by: issued_by.map(str::to_owned),
    }
}

/// A timeline row: the request row as the request list shows it (docs/07 section
/// 7.9.3), then what its response taught the session (section 7.4.3). `learned` is
/// the count of new values, or null when the response was not read (see
/// `learned_count`). `entry_passed` and `after_would_block` are false and
/// `issued_session` is null when the trace has no response section.
#[must_use]
fn timeline_row(row: &TimelineRow) -> TimelineRowBody {
    let response = row.trace.get("response");
    TimelineRowBody {
        request: RequestRow::from(&row.summary),
        learned: learned_count(response),
        entry_passed: response
            .and_then(|response| response.get("entry_passed"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        issued_session: response
            .and_then(|response| response.get("issued_session"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        after_would_block: response
            .and_then(|response| response.get("after_would_block"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

/// The count of new values a response taught the session, or null when the response
/// was not read. Observe mode skips a response to a request it would refuse, and such
/// a response taught nothing, so it has no count rather than a zero (section 7.4.6).
fn learned_count(response: Option<&Value>) -> Option<i64> {
    let read = response
        .filter(|response| response.get("observed").and_then(Value::as_str) != Some("skipped"))?;
    read.get("new_values").and_then(Value::as_i64)
}

/// The request that issued each of `sessions`, keyed by session label. Sessions
/// whose issuing request is past retention are missing from the map.
async fn issuing_request_ids(
    pool: &PgPool,
    sessions: &[SessionRow],
) -> ApiResult<BTreeMap<String, String>> {
    if sessions.is_empty() {
        return Ok(BTreeMap::new());
    }
    let labels: Vec<String> = sessions
        .iter()
        .map(|session| session.label.clone())
        .collect();
    Ok(decision_log_store::issuing_requests(pool, &labels).await?)
}

/// The `flag` parameter: `blocked` keeps the sessions with a refused or
/// would-be-refused request, `jev` the sessions with a Jev call, and no flag every
/// session.
///
/// # Errors
/// `INVALID_FILTER` naming `flag` for any other value.
fn flag_param(params: &Params) -> ApiResult<SessionFlag> {
    match params.text("flag") {
        None => Ok(SessionFlag::Any),
        Some("blocked") => Ok(SessionFlag::Blocked),
        Some("jev") => Ok(SessionFlag::Jev),
        Some(_) => Err(ApiError::invalid_filter("flag")),
    }
}

/// The `only` parameter of a timeline: `judged` (the default), `jev` or `blocks`.
///
/// # Errors
/// `INVALID_FILTER` naming `only` for any other value.
fn only_param(params: &Params) -> ApiResult<TimelineOnly> {
    match params.text("only") {
        None | Some("judged") => Ok(TimelineOnly::Judged),
        Some("jev") => Ok(TimelineOnly::Jev),
        Some("blocks") => Ok(TimelineOnly::Blocks),
        Some(_) => Err(ApiError::invalid_filter("only")),
    }
}

/// Whether `label` is a session label: one to 64 letters, digits, `_` or `-`.
fn label_is_valid(label: &str) -> bool {
    (1..=LABEL_MAX_CHARS).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_is_one_to_sixty_four_letters_digits_underscores_or_dashes() {
        assert!(label_is_valid("7c1e9a40d2b35f61"));
        assert!(label_is_valid("a-B_9"));
        assert!(label_is_valid(&"a".repeat(64)));
        assert!(!label_is_valid(""));
        assert!(!label_is_valid(&"a".repeat(65)));
        assert!(!label_is_valid("a/b"));
        assert!(!label_is_valid("a b"));
    }

    #[test]
    fn a_response_that_was_not_read_has_no_learned_count() {
        let refused = serde_json::json!({
            "observed": "skipped",
            "skip": "would_block",
            "new_values": 0,
            "after_would_block": true,
        });
        assert_eq!(learned_count(Some(&refused)), None);
        let read = serde_json::json!({ "observed": "json", "new_values": 0 });
        assert_eq!(learned_count(Some(&read)), Some(0));
        let read_with_new = serde_json::json!({ "observed": "json", "new_values": 9 });
        assert_eq!(learned_count(Some(&read_with_new)), Some(9));
        assert_eq!(learned_count(None), None);
    }

    #[test]
    fn a_timeline_shows_judged_requests_unless_told_otherwise() {
        let default = only_param(&Params::default()).expect("default");
        assert_eq!(default, TimelineOnly::Judged);
        let blocks = Params::from(BTreeMap::from([("only".to_owned(), "blocks".to_owned())]));
        assert_eq!(only_param(&blocks).expect("blocks"), TimelineOnly::Blocks);
        let unknown = Params::from(BTreeMap::from([("only".to_owned(), "all".to_owned())]));
        assert!(only_param(&unknown).is_err());
    }
}
