//! Site configuration: create, read, replace, delete, history, rollback and
//! validation (docs/07-console-architecture.md sections 7.9.2 and 7.9.12).
//!
//! Every write carries the version the caller last read. A stale version gets
//! `VERSION_CONFLICT` with the current one, so two editors cannot silently
//! overwrite each other.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use xshield_core::context::{Mode, SiteSpec};
use xshield_postgres::{
    decision_stats,
    edge_status_store::{self, EdgeStatus},
    site_spec_store::{
        self, DeleteOutcome, HistoryEntry, NOTE_MAX_CHARS, RollbackOutcome, SiteRecord,
        WriteOutcome,
    },
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult, ValidationBody},
    params::{DAY_MILLIS, Params, json_body, now_millis},
};

/// Names a site may not take: they are routes of the API.
const RESERVED_SITE_NAMES: &[&str] = &["validate"];
/// Versions one history page shows when the caller names no size.
const DEFAULT_VERSION_PAGE: i64 = 50;
/// The largest history page.
const MAX_VERSION_PAGE: i64 = 200;
/// Versions read per page while looking for the start of an observing run.
const OBSERVING_PAGE: i64 = 200;

/// `GET /api/sites` (docs/07 section 7.9.2): every site, with what each gateway
/// loaded for it and the requests it saw in the last 24 hours.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SitesBody {
    pub sites: Vec<SiteSummaryBody>,
}

/// A site's summary (`SiteSummary` in the console contract): identity, version,
/// rollout across the gateways and the figures of the last 24 hours.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteSummaryBody {
    pub name: String,
    pub hosts: Vec<String>,
    pub origin: String,
    pub mode: Mode,
    pub version: i64,
    pub updated_at: String,
    /// When the site started observing: the first version of its current run of
    /// observe-mode versions. `None` in enforce mode.
    pub observing_since_millis: Option<i64>,
    /// The lowest version the online gateways loaded; `None` when none has loaded it.
    pub loaded_version: Option<i64>,
    /// Every gateway seen in the last 24 hours, with what it loaded.
    pub edges: Vec<EdgeLoadBody>,
    /// How far the online gateways have loaded `version` (section 7.9.13).
    pub rollout: RolloutBody,
    pub requests_24h: i64,
    pub blocked_24h: i64,
    pub would_block_24h: i64,
    pub jev_calls_24h: i64,
    pub unjudged_24h: i64,
    pub jev_timeouts_24h: i64,
    pub call_limits_24h: i64,
    pub suggestions: i64,
}

/// What one gateway has loaded for a site.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeLoadBody {
    pub edge: String,
    /// The version the instance has loaded; `None` while it has none.
    pub version: Option<i64>,
    /// The error code when the instance rejected the site.
    pub error: Option<String>,
    /// When the instance loaded `version`, Unix milliseconds. `None` while it has no
    /// version, or when the instance does not report the time.
    pub loaded_at_millis: Option<i64>,
}

/// The rollout of a site's current version across the gateways (section 7.9.13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolloutBody {
    pub version: i64,
    pub edges_online: i64,
    pub edges_loaded: i64,
    pub edges: Vec<RolloutEdgeBody>,
}

/// One gateway's place in a rollout.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolloutEdgeBody {
    pub edge: String,
    pub online: bool,
    pub loaded_version: Option<i64>,
    pub error: Option<String>,
}

/// `GET /api/sites/{name}` and the write endpoints' answer: the summary, the
/// configuration and the creation time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteDetailBody {
    #[serde(flatten)]
    pub summary: SiteSummaryBody,
    pub spec: SiteSpec,
    pub created_at: String,
}

/// `DELETE /api/sites/{name}`: the version the deletion recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedBody {
    pub deleted: bool,
    pub version: i64,
}

/// `GET /api/sites/{name}/versions`: one page of the history, newest first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionsBody {
    pub versions: Vec<HistoryRowBody>,
    /// The `before` of the next page; `None` on the last page.
    pub next_before: Option<i64>,
}

/// A history row: a version, what it recorded, and the changes from the version
/// before it. `GET /api/sites/{name}/versions/{version}` answers with one row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryRowBody {
    pub version: i64,
    pub change: String,
    pub rollback_of: Option<i64>,
    pub note: Option<String>,
    pub changed_at: String,
    /// The whole configuration of the version; `None` for a deletion.
    pub spec: Option<SiteSpec>,
    /// What changed from the version before this one.
    pub summary: Vec<DiffBody>,
}

/// One change between two configurations, as the history shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DiffBody {
    /// A list of strings: what was added to it and what was removed from it.
    Items {
        field: String,
        added: Vec<String>,
        removed: Vec<String>,
    },
    /// Any other value: what it was and what it became.
    Scalar {
        field: String,
        from: Value,
        to: Value,
    },
}

fn site_not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "SITE_NOT_FOUND")
}

fn version_conflict(current: i64) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "VERSION_CONFLICT").at_version(current)
}

fn time_text(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The version a gateway reports it loaded for a site.
#[must_use]
fn loaded_version_of(edge: &EdgeStatus, name: &str) -> Option<i64> {
    edge.sites
        .get(name)
        .and_then(|entry| entry.get("version"))
        .and_then(Value::as_i64)
}

/// When a gateway loaded the version it reports for a site, Unix milliseconds.
#[must_use]
fn loaded_at_of(edge: &EdgeStatus, name: &str) -> Option<i64> {
    edge.sites
        .get(name)
        .and_then(|entry| entry.get("loaded_at_millis"))
        .and_then(Value::as_i64)
}

/// The error a gateway reports for a site it refused.
#[must_use]
fn error_of(edge: &EdgeStatus, name: &str) -> Option<String> {
    edge.sites
        .get(name)
        .and_then(|entry| entry.get("error"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The rollout of a site's current version across the gateways (section 7.9.13): every
/// instance seen in the last 24 hours, with the version it loaded and the error that
/// kept it from loading. `edges_loaded` counts the online instances that loaded the
/// current version.
#[must_use]
fn rollout_of(name: &str, version: i64, edges: &[EdgeStatus], now: DateTime<Utc>) -> RolloutBody {
    let mut edges_online = 0_i64;
    let mut edges_loaded = 0_i64;
    let rows = edges
        .iter()
        .map(|edge| {
            let online = edge.is_online(now);
            let loaded_version = loaded_version_of(edge, name);
            if online {
                edges_online += 1;
                if loaded_version == Some(version) {
                    edges_loaded += 1;
                }
            }
            RolloutEdgeBody {
                edge: edge.edge.clone(),
                online,
                loaded_version,
                error: error_of(edge, name),
            }
        })
        .collect();
    RolloutBody {
        version,
        edges_online,
        edges_loaded,
        edges: rows,
    }
}

/// The console's summary of a site: identity, version, when it started observing,
/// what the gateways loaded, and the figures of the last 24 hours.
#[must_use]
fn site_summary(
    record: &SiteRecord,
    edges: &[EdgeStatus],
    counts: Option<&decision_stats::SiteCounts>,
    suggestions: i64,
    observing_since_millis: Option<i64>,
    now: DateTime<Utc>,
) -> SiteSummaryBody {
    let name = record.spec.name();
    SiteSummaryBody {
        name: name.to_owned(),
        hosts: record.spec.hosts().to_vec(),
        origin: record.spec.origin().to_owned(),
        mode: record.spec.mode(),
        version: record.version,
        updated_at: time_text(record.updated_at),
        observing_since_millis,
        loaded_version: edges
            .iter()
            .filter(|edge| edge.is_online(now))
            .filter_map(|edge| loaded_version_of(edge, name))
            .min(),
        edges: edges
            .iter()
            .map(|edge| EdgeLoadBody {
                edge: edge.edge.clone(),
                version: loaded_version_of(edge, name),
                error: error_of(edge, name),
                loaded_at_millis: loaded_at_of(edge, name),
            })
            .collect(),
        rollout: rollout_of(name, record.version, edges, now),
        requests_24h: counts.map_or(0, |count| count.requests),
        blocked_24h: counts.map_or(0, |count| count.blocked),
        would_block_24h: counts.map_or(0, |count| count.would_block),
        jev_calls_24h: counts.map_or(0, |count| count.jev_calls),
        unjudged_24h: counts.map_or(0, |count| count.unjudged),
        jev_timeouts_24h: counts.map_or(0, |count| count.jev_timeouts),
        call_limits_24h: counts.map_or(0, |count| count.call_limits),
        suggestions,
    }
}

/// How long a site's pending-suggestion count is reused. The analysis reads up to
/// 20 000 Jev states, so the site list must not run it again on every load.
const SUGGESTION_CACHE_MILLIS: i64 = 60_000;

/// The pending-suggestion count of a site (docs/06 section 6.2): the analysis of
/// the insights endpoint, reused for [`SUGGESTION_CACHE_MILLIS`].
async fn pending_suggestions_of(state: &ControlState, site: &str, now: i64) -> ApiResult<i64> {
    let cached = state
        .suggestion_counts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(site)
        .copied();
    if let Some((_, count)) = cached.filter(|(at, _)| now - at < SUGGESTION_CACHE_MILLIS) {
        return Ok(count);
    }
    let count = crate::insights::pending_suggestions(&state.pool, site, now).await?;
    state
        .suggestion_counts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(site.to_owned(), (now, count));
    Ok(count)
}

/// When a site started observing: the first version of its current run of observe-mode
/// versions, read from the history newest first. `None` in enforce mode. A version in
/// enforce mode, or a deletion, ends the run.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
async fn observing_since(pool: &PgPool, record: &SiteRecord) -> ApiResult<Option<i64>> {
    if record.spec.mode() != Mode::Observe {
        return Ok(None);
    }
    let mut since = None;
    let mut before = None;
    loop {
        let page =
            site_spec_store::history(pool, record.spec.name(), before, OBSERVING_PAGE).await?;
        for entry in &page {
            if entry.spec.as_ref().map(SiteSpec::mode) != Some(Mode::Observe) {
                return Ok(since);
            }
            since = Some(entry.changed_at.timestamp_millis());
        }
        match page.last() {
            Some(oldest) if i64::try_from(page.len()).unwrap_or(i64::MAX) == OBSERVING_PAGE => {
                before = Some(oldest.version);
            }
            _ => return Ok(since),
        }
    }
}

/// The detail of a site as the console reads it, with the live rollout and the last 24
/// hours' figures.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
async fn detail_view(state: &ControlState, record: &SiteRecord) -> ApiResult<SiteDetailBody> {
    let edges = edge_status_store::list(&state.pool).await?;
    let counts = decision_stats::site_counts(&state.pool, now_millis() - DAY_MILLIS).await?;
    let found = counts.iter().find(|count| count.site == record.spec.name());
    let suggestions = pending_suggestions_of(state, record.spec.name(), now_millis()).await?;
    let observing = observing_since(&state.pool, record).await?;
    Ok(SiteDetailBody {
        summary: site_summary(record, &edges, found, suggestions, observing, Utc::now()),
        spec: record.spec.clone(),
        created_at: time_text(record.created_at),
    })
}

/// The `spec` member of a write body, validated the way the gateway validates it.
fn spec_from_body(body: &Value) -> ApiResult<SiteSpec> {
    let spec = body
        .get("spec")
        .ok_or_else(|| ApiError::invalid_body("spec"))?;
    let parsed = SiteSpec::from_value(spec)?;
    if RESERVED_SITE_NAMES.contains(&parsed.name()) {
        return Err(
            ApiError::new(StatusCode::BAD_REQUEST, "SITE_CONFIG_NAME_INVALID").in_field("name"),
        );
    }
    Ok(parsed)
}

/// The optional `note` of a write, at most [`NOTE_MAX_CHARS`] characters.
pub(crate) fn note_from(body: &Value) -> ApiResult<Option<String>> {
    match body.get("note") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(note)) if note.is_empty() => Ok(None),
        Some(Value::String(note)) if note.chars().count() <= NOTE_MAX_CHARS => {
            Ok(Some(note.to_owned()))
        }
        Some(_) => Err(ApiError::invalid_body("note")),
    }
}

/// The `expected_version` of a write: the version the caller last read.
pub(crate) fn expected_version(body: &Value) -> ApiResult<i64> {
    body.get("expected_version")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::invalid_body("expected_version"))
}

/// The optional `object_event` of a write: the automatic change the write undoes or re-confirms.
fn event_from(body: &Value) -> ApiResult<Option<String>> {
    match body.get("object_event") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(event)) if !event.is_empty() => Ok(Some(event.to_owned())),
        Some(_) => Err(ApiError::invalid_body("object_event")),
    }
}

/// Refuses a configuration whose host names another site already uses. The
/// gateway would keep only the first site to claim a host and log the rest to
/// stderr, so the control plane refuses the write instead (section 7.9.12).
async fn check_hosts_free(pool: &PgPool, spec: &SiteSpec) -> ApiResult<()> {
    let records = site_spec_store::list(pool).await?;
    for (index, host) in spec.hosts().iter().enumerate() {
        let taken = records
            .iter()
            .any(|record| record.spec.name() != spec.name() && record.spec.hosts().contains(host));
        if taken {
            return Err(ApiError::new(StatusCode::CONFLICT, "SITE_HOST_TAKEN")
                .in_field(format!("hosts[{index}]")));
        }
    }
    Ok(())
}

/// `GET /api/sites`: every site, with what each gateway loaded for it and the
/// requests it saw in the last 24 hours.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
pub async fn list(State(state): State<Arc<ControlState>>) -> ApiResult<Json<SitesBody>> {
    let records = site_spec_store::list(&state.pool).await?;
    let edges = edge_status_store::list(&state.pool).await?;
    let counts = decision_stats::site_counts(&state.pool, now_millis() - DAY_MILLIS).await?;
    let now = Utc::now();
    let mut sites = Vec::with_capacity(records.len());
    for record in &records {
        let found = counts.iter().find(|count| count.site == record.spec.name());
        let suggestions = pending_suggestions_of(&state, record.spec.name(), now_millis()).await?;
        let observing = observing_since(&state.pool, record).await?;
        sites.push(site_summary(
            record,
            &edges,
            found,
            suggestions,
            observing,
            now,
        ));
    }
    Ok(Json(SitesBody { sites }))
}

/// `POST /api/sites`: creates a site from `{"spec": {...}, "note": "..."}`.
///
/// # Errors
/// `SITE_CONFIG_*` for an invalid configuration, `SITE_HOST_TAKEN` for a host
/// another site uses, `SITE_EXISTS` when the name is taken.
pub async fn create(
    State(state): State<Arc<ControlState>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<SiteDetailBody>)> {
    let body: Value = json_body(&headers, &body)?;
    let spec = spec_from_body(&body)?;
    let note = note_from(&body)?;
    check_hosts_free(&state.pool, &spec).await?;
    let record = site_spec_store::create(&state.pool, &spec, note.as_deref()).await?;
    Ok((
        StatusCode::CREATED,
        Json(detail_view(&state, &record).await?),
    ))
}

/// `GET /api/sites/{name}`: one site's current configuration.
///
/// # Errors
/// `SITE_NOT_FOUND` when no such site exists.
pub async fn get(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<SiteDetailBody>> {
    let record = site_spec_store::get(&state.pool, &name)
        .await?
        .ok_or_else(site_not_found)?;
    Ok(Json(detail_view(&state, &record).await?))
}

/// `PUT /api/sites/{name}`: replaces a site from `{"spec": {...},
/// "expected_version": n, "note": "..."}`.
///
/// # Errors
/// `SITE_NAME_MISMATCH` when the body names another site, `VERSION_CONFLICT`
/// (409, with `current_version`) when `expected_version` is stale, plus the
/// errors of [`create`].
pub async fn update(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SiteDetailBody>> {
    let body: Value = json_body(&headers, &body)?;
    let spec = spec_from_body(&body)?;
    if spec.name() != name {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "SITE_NAME_MISMATCH"));
    }
    let expected = expected_version(&body)?;
    let note = note_from(&body)?;
    let event = match event_from(&body)? {
        Some(id) => {
            let record = crate::object_map::site_of(&state, &name).await?;
            Some(crate::object_map::check_save_event(&state, &record, &id).await?)
        }
        None => None,
    };
    check_hosts_free(&state.pool, &spec).await?;
    match site_spec_store::update(&state.pool, &name, &spec, expected, note.as_deref()).await? {
        WriteOutcome::Applied(record) => {
            if let Some(event) = &event {
                crate::object_map::mark_saved(&state, event, record.version).await;
            }
            Ok(Json(detail_view(&state, &record).await?))
        }
        WriteOutcome::NotFound => Err(site_not_found()),
        WriteOutcome::VersionConflict { current } => Err(version_conflict(current)),
    }
}

/// `DELETE /api/sites/{name}`: deletes a site from `{"expected_version": n,
/// "note": "..."}`. The history is kept, so the site can be rolled back to.
///
/// # Errors
/// `SITE_NOT_FOUND`, or `VERSION_CONFLICT` for a stale `expected_version`.
pub async fn delete(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<DeletedBody>> {
    let body: Value = json_body(&headers, &body)?;
    let expected = expected_version(&body)?;
    let note = note_from(&body)?;
    match site_spec_store::delete(&state.pool, &name, expected, note.as_deref()).await? {
        DeleteOutcome::Deleted { version } => Ok(Json(DeletedBody {
            deleted: true,
            version,
        })),
        DeleteOutcome::NotFound => Err(site_not_found()),
        DeleteOutcome::VersionConflict { current } => Err(version_conflict(current)),
    }
}

/// `POST /api/sites/validate`: checks `{"spec": {...}}` without saving it.
/// Reports `valid: false` with the error code and the field for a configuration
/// that would be refused, and `valid: true` otherwise.
///
/// # Errors
/// Only a database failure, which is an error rather than a verdict.
pub async fn validate(
    State(state): State<Arc<ControlState>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<ValidationBody>> {
    let body: Value = json_body(&headers, &body)?;
    let outcome = match spec_from_body(&body) {
        Ok(spec) => check_hosts_free(&state.pool, &spec).await,
        Err(error) => Err(error),
    };
    match outcome {
        Ok(()) => Ok(Json(ValidationBody::accepted())),
        Err(error) if error.status() == StatusCode::INTERNAL_SERVER_ERROR => Err(error),
        Err(error) => Ok(Json(error.validation_report())),
    }
}

/// A history row: its version, what changed, when, and the summary of the change from
/// the version before it.
#[must_use]
fn history_row(entry: &HistoryEntry, summary: Vec<DiffBody>) -> HistoryRowBody {
    HistoryRowBody {
        version: entry.version,
        change: entry.change.as_str().to_owned(),
        rollback_of: entry.rollback_of,
        note: entry.note.clone(),
        changed_at: time_text(entry.changed_at),
        spec: entry.spec.clone(),
        summary,
    }
}

/// `GET /api/sites/{name}/versions?before=&limit=`: the history, newest first, each row
/// with its change summary.
///
/// # Errors
/// `SITE_NOT_FOUND` when the site does not exist, `INVALID_FILTER` for a bad
/// `limit` or `before`.
pub async fn versions(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<VersionsBody>> {
    let params = Params::from(query);
    let limit = params.limit(DEFAULT_VERSION_PAGE, MAX_VERSION_PAGE)?;
    let before = params.int("before")?;
    // One extra row: the summary of the last row on the page needs the version before it.
    let fetched = site_spec_store::history(&state.pool, &name, before, limit + 1).await?;
    if fetched.is_empty() && site_spec_store::get(&state.pool, &name).await?.is_none() {
        return Err(site_not_found());
    }
    let page = usize::try_from(limit).unwrap_or(usize::MAX);
    let shown = fetched.len().min(page);
    let rows: Vec<HistoryRowBody> = (0..shown)
        .filter_map(|index| {
            let entry = fetched.get(index)?;
            let older = fetched
                .get(index + 1)
                .and_then(|previous| previous.spec.as_ref());
            let summary = diff_specs(older, entry.spec.as_ref());
            Some(history_row(entry, summary))
        })
        .collect();
    let next_before = if fetched.len() > page {
        rows.last().map(|row| row.version)
    } else {
        None
    };
    Ok(Json(VersionsBody {
        versions: rows,
        next_before,
    }))
}

/// `GET /api/sites/{name}/versions/{version}`: one version in full, with its summary and
/// its configuration.
///
/// # Errors
/// `VERSION_NOT_FOUND` when the site has no such version.
pub async fn version(
    State(state): State<Arc<ControlState>>,
    Path((name, version)): Path<(String, i64)>,
) -> ApiResult<Json<HistoryRowBody>> {
    let entry = site_spec_store::version(&state.pool, &name, version)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "VERSION_NOT_FOUND"))?;
    let previous = match version.checked_sub(1) {
        Some(earlier) if earlier >= 1 => {
            site_spec_store::version(&state.pool, &name, earlier).await?
        }
        _ => None,
    };
    let summary = diff_specs(
        previous.as_ref().and_then(|entry| entry.spec.as_ref()),
        entry.spec.as_ref(),
    );
    Ok(Json(history_row(&entry, summary)))
}

/// `POST /api/sites/{name}/rollback`: makes a new version with the text of
/// `to_version`, from `{"to_version": n, "expected_version": m, "note": "..."}`.
///
/// # Errors
/// `VERSION_NOT_FOUND`, `ROLLBACK_TARGET_DELETED` for a version that is a
/// deletion, `VERSION_CONFLICT` for a stale `expected_version`.
pub async fn rollback(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SiteDetailBody>> {
    let body: Value = json_body(&headers, &body)?;
    let to_version = body
        .get("to_version")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::invalid_body("to_version"))?;
    let expected = expected_version(&body)?;
    let note = note_from(&body)?;
    let outcome =
        site_spec_store::rollback(&state.pool, &name, to_version, expected, note.as_deref())
            .await?;
    match outcome {
        RollbackOutcome::Applied(record) => Ok(Json(detail_view(&state, &record).await?)),
        RollbackOutcome::NotFound => Err(site_not_found()),
        RollbackOutcome::VersionConflict { current } => Err(version_conflict(current)),
        RollbackOutcome::VersionNotFound => {
            Err(ApiError::new(StatusCode::NOT_FOUND, "VERSION_NOT_FOUND"))
        }
        RollbackOutcome::TargetDeleted => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "ROLLBACK_TARGET_DELETED",
        )),
    }
}

/// The changes between two configurations, as the history shows them. Scalars give
/// `from` and `to`; string lists give what was `added` and `removed`; objects such as
/// `advanced` are compared field by field. Nothing is listed when either side is
/// absent, as for a creation or a deletion.
#[must_use]
pub fn diff_specs(before: Option<&SiteSpec>, after: Option<&SiteSpec>) -> Vec<DiffBody> {
    let (Some(before), Some(after)) = (before, after) else {
        return Vec::new();
    };
    let before = serde_json::to_value(before).unwrap_or(Value::Null);
    let after = serde_json::to_value(after).unwrap_or(Value::Null);
    let mut changes = Vec::new();
    diff_values("", &before, &after, &mut changes);
    changes
}

fn diff_values(prefix: &str, before: &Value, after: &Value, out: &mut Vec<DiffBody>) {
    match (before, after) {
        (Value::Object(old), Value::Object(new)) => {
            let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
            for key in keys {
                let field = field_name(prefix, key);
                let old_value = old.get(key).unwrap_or(&Value::Null);
                let new_value = new.get(key).unwrap_or(&Value::Null);
                diff_values(&field, old_value, new_value, out);
            }
        }
        // An object that appeared or disappeared, such as `advanced` on a site that
        // had none, changes field by field rather than as one value.
        (Value::Null, Value::Object(new)) => {
            for (key, value) in new {
                diff_values(&field_name(prefix, key), &Value::Null, value, out);
            }
        }
        (Value::Object(old), Value::Null) => {
            for (key, value) in old {
                diff_values(&field_name(prefix, key), value, &Value::Null, out);
            }
        }
        (Value::Array(old), Value::Array(new)) if old != new => {
            let added: Vec<String> = new
                .iter()
                .filter(|item| !old.contains(item))
                .map(item_text)
                .collect();
            let removed: Vec<String> = old
                .iter()
                .filter(|item| !new.contains(item))
                .map(item_text)
                .collect();
            out.push(DiffBody::Items {
                field: prefix.to_owned(),
                added,
                removed,
            });
        }
        _ if before != after => {
            out.push(DiffBody::Scalar {
                field: prefix.to_owned(),
                from: before.clone(),
                to: after.clone(),
            });
        }
        _ => {}
    }
}

/// The name of a field under `prefix`: `key` at the top, `prefix.key` below it.
fn field_name(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

fn item_text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn spec(json_text: &str) -> SiteSpec {
        SiteSpec::from_json(json_text).expect("valid spec")
    }

    const BASE: &str = r#"{
        "name": "juice", "hosts": ["juice.example.com"], "origin": "http://127.0.0.1:3000",
        "session": {"cookie": "SESSIONID"}, "entries": ["/rest/user/login"],
        "bypass": ["/assets/*"], "mode": "observe"
    }"#;

    #[test]
    fn a_creation_or_deletion_has_no_summary() {
        assert!(diff_specs(None, Some(&spec(BASE))).is_empty());
        assert!(diff_specs(Some(&spec(BASE)), None).is_empty());
    }

    #[test]
    fn list_changes_name_what_was_added_and_removed() {
        let after = BASE.replace(
            r#"["/rest/user/login"]"#,
            r#"["/rest/user/login", "/share/*"]"#,
        );
        let changes = diff_specs(Some(&spec(BASE)), Some(&spec(&after)));
        assert_eq!(
            changes,
            vec![DiffBody::Items {
                field: "entries".to_owned(),
                added: vec!["/share/*".to_owned()],
                removed: Vec::new(),
            }]
        );
    }

    #[test]
    fn scalar_changes_give_both_values() {
        let after = BASE.replace(r#""mode": "observe""#, r#""mode": "enforce""#);
        let changes = diff_specs(Some(&spec(BASE)), Some(&spec(&after)));
        assert_eq!(
            changes,
            vec![DiffBody::Scalar {
                field: "mode".to_owned(),
                from: json!("observe"),
                to: json!("enforce"),
            }]
        );
    }

    #[test]
    fn advanced_changes_are_listed_per_field() {
        let after = BASE.replace(
            r#""mode": "observe""#,
            r#""mode": "observe", "advanced": {"jev_timeout_ms": 1500}"#,
        );
        let changes = diff_specs(Some(&spec(BASE)), Some(&spec(&after)));
        assert_eq!(
            changes,
            vec![DiffBody::Scalar {
                field: "advanced.jev_timeout_ms".to_owned(),
                from: Value::Null,
                to: json!(1500),
            }]
        );
    }

    #[test]
    fn a_reserved_site_name_is_refused() {
        let body = json!({"spec": serde_json::from_str::<Value>(&BASE.replace("juice", "validate")).expect("json")});
        let error = spec_from_body(&body).expect_err("reserved");
        assert_eq!(
            error.validation_report().error.as_deref(),
            Some("SITE_CONFIG_NAME_INVALID")
        );
    }

    #[test]
    fn a_note_longer_than_the_limit_is_refused() {
        let long = "x".repeat(NOTE_MAX_CHARS + 1);
        assert!(note_from(&json!({"note": long})).is_err());
        assert_eq!(note_from(&json!({"note": ""})).expect("empty"), None);
    }

    #[test]
    fn the_site_list_says_when_each_gateway_loaded_its_version() {
        let now = DateTime::from_timestamp_millis(1_793_538_000_000).expect("time");
        let record = SiteRecord {
            spec: spec(BASE),
            version: 3,
            created_at: now,
            updated_at: now,
        };
        let edge = |name: &str, juice: Value| EdgeStatus {
            edge: name.to_owned(),
            started_at: now,
            seen_at: now,
            build: String::new(),
            listen: String::new(),
            tls: false,
            sites: json!({ "juice": juice }),
            sessions: 0,
            queue: 0,
            written: 0,
            dropped: 0,
            dropped_bypass: 0,
            write_errors: 0,
            gaps: json!([]),
            jev: json!({}),
            params: json!({}),
        };
        let edges = [
            edge(
                "edge-1",
                json!({ "version": 3, "loaded_at_millis": 1_793_537_900_000_i64 }),
            ),
            // An instance that predates the load time reports only its version.
            edge("edge-2", json!({ "version": 3 })),
        ];
        let summary = site_summary(&record, &edges, None, 0, None, now);
        assert_eq!(summary.edges[0].loaded_at_millis, Some(1_793_537_900_000));
        assert_eq!(summary.edges[1].version, Some(3));
        assert_eq!(summary.edges[1].loaded_at_millis, None);
    }
}
