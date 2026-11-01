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
use serde_json::{Value, json};
use sqlx::PgPool;
use xshield_core::context::SiteSpec;
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
    error::{ApiError, ApiResult},
    params::{DAY_MILLIS, Params, json_body, now_millis},
};

/// Names a site may not take: they are routes of the API.
const RESERVED_SITE_NAMES: &[&str] = &["validate"];
/// Versions one history page shows when the caller names no size.
const DEFAULT_VERSION_PAGE: i64 = 50;
/// The largest history page.
const MAX_VERSION_PAGE: i64 = 200;

fn site_not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "SITE_NOT_FOUND")
}

fn version_conflict(current: i64) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "VERSION_CONFLICT").at_version(current)
}

fn time_text(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The rollout of a site's current version across the gateways (section 7.9.13):
/// every instance seen in the last 24 hours, with the version it loaded and the
/// error that kept it from loading. `edges_loaded` counts the online instances
/// that loaded the current version.
fn rollout_json(name: &str, version: i64, edges: &[EdgeStatus], now: DateTime<Utc>) -> Value {
    let mut edges_online = 0_i64;
    let mut edges_loaded = 0_i64;
    let rows: Vec<Value> = edges
        .iter()
        .map(|edge| {
            let online = edge.is_online(now);
            let entry = edge.sites.get(name);
            let loaded_version = entry
                .and_then(|entry| entry.get("version"))
                .and_then(Value::as_i64);
            let error = entry
                .and_then(|entry| entry.get("error"))
                .filter(|error| !error.is_null())
                .cloned()
                .unwrap_or(Value::Null);
            if online {
                edges_online += 1;
                if loaded_version == Some(version) {
                    edges_loaded += 1;
                }
            }
            json!({
                "edge": edge.edge,
                "online": online,
                "loaded_version": loaded_version,
                "error": error,
            })
        })
        .collect();
    json!({
        "version": version,
        "edges_online": edges_online,
        "edges_loaded": edges_loaded,
        "edges": rows,
    })
}

/// The console's summary of a site (`SiteSummary` in the console contract): identity,
/// version, rollout across the gateways and the figures of the last 24 hours.
fn site_summary(
    record: &SiteRecord,
    edges: &[EdgeStatus],
    counts: Option<&decision_stats::SiteCounts>,
    suggestions: i64,
    now: DateTime<Utc>,
) -> Value {
    json!({
        "name": record.spec.name(),
        "hosts": record.spec.hosts(),
        "origin": record.spec.origin(),
        "mode": serde_json::to_value(record.spec.mode()).unwrap_or(Value::Null),
        "version": record.version,
        "updated_at": time_text(record.updated_at),
        "rollout": rollout_json(record.spec.name(), record.version, edges, now),
        "requests_24h": counts.map_or(0, |count| count.requests),
        "blocked_24h": counts.map_or(0, |count| count.blocked),
        "would_block_24h": counts.map_or(0, |count| count.would_block),
        "jev_calls_24h": counts.map_or(0, |count| count.jev_calls),
        "unjudged_24h": counts.map_or(0, |count| count.unjudged),
        "jev_timeouts_24h": counts.map_or(0, |count| count.jev_timeouts),
        "call_limits_24h": counts.map_or(0, |count| count.call_limits),
        "suggestions": suggestions,
    })
}

/// A site's detail: its summary plus the configuration and the creation time.
fn site_detail(
    record: &SiteRecord,
    edges: &[EdgeStatus],
    counts: Option<&decision_stats::SiteCounts>,
    suggestions: i64,
    now: DateTime<Utc>,
) -> Value {
    let mut value = site_summary(record, edges, counts, suggestions, now);
    if let Value::Object(map) = &mut value {
        map.insert(
            "spec".to_owned(),
            serde_json::to_value(&record.spec).unwrap_or(Value::Null),
        );
        map.insert("created_at".to_owned(), json!(time_text(record.created_at)));
    }
    value
}

/// The detail of a site as the console reads it, with the live rollout and the
/// last 24 hours' figures.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
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

async fn detail_view(state: &ControlState, record: &SiteRecord) -> ApiResult<Value> {
    let edges = edge_status_store::list(&state.pool).await?;
    let counts = decision_stats::site_counts(&state.pool, now_millis() - DAY_MILLIS).await?;
    let found = counts.iter().find(|count| count.site == record.spec.name());
    let suggestions = pending_suggestions_of(state, record.spec.name(), now_millis()).await?;
    Ok(site_detail(record, &edges, found, suggestions, Utc::now()))
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
fn note_from(body: &Value) -> ApiResult<Option<String>> {
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
fn expected_version(body: &Value) -> ApiResult<i64> {
    body.get("expected_version")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::invalid_body("expected_version"))
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
pub async fn list(State(state): State<Arc<ControlState>>) -> ApiResult<Json<Value>> {
    let records = site_spec_store::list(&state.pool).await?;
    let edges = edge_status_store::list(&state.pool).await?;
    let counts = decision_stats::site_counts(&state.pool, now_millis() - DAY_MILLIS).await?;
    let now = Utc::now();
    let mut sites = Vec::with_capacity(records.len());
    for record in &records {
        let found = counts.iter().find(|count| count.site == record.spec.name());
        let suggestions = pending_suggestions_of(&state, record.spec.name(), now_millis()).await?;
        sites.push(site_summary(record, &edges, found, suggestions, now));
    }
    Ok(Json(json!({ "sites": sites })))
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
) -> ApiResult<(StatusCode, Json<Value>)> {
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
) -> ApiResult<Json<Value>> {
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
) -> ApiResult<Json<Value>> {
    let body: Value = json_body(&headers, &body)?;
    let spec = spec_from_body(&body)?;
    if spec.name() != name {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "SITE_NAME_MISMATCH"));
    }
    let expected = expected_version(&body)?;
    let note = note_from(&body)?;
    check_hosts_free(&state.pool, &spec).await?;
    match site_spec_store::update(&state.pool, &name, &spec, expected, note.as_deref()).await? {
        WriteOutcome::Applied(record) => Ok(Json(detail_view(&state, &record).await?)),
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
) -> ApiResult<Json<Value>> {
    let body: Value = json_body(&headers, &body)?;
    let expected = expected_version(&body)?;
    let note = note_from(&body)?;
    match site_spec_store::delete(&state.pool, &name, expected, note.as_deref()).await? {
        DeleteOutcome::Deleted { version } => {
            Ok(Json(json!({ "deleted": true, "version": version })))
        }
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
) -> ApiResult<Json<Value>> {
    let body: Value = json_body(&headers, &body)?;
    let outcome = match spec_from_body(&body) {
        Ok(spec) => check_hosts_free(&state.pool, &spec).await,
        Err(error) => Err(error),
    };
    match outcome {
        Ok(()) => Ok(Json(json!({ "valid": true }))),
        Err(error) if error.status() == StatusCode::INTERNAL_SERVER_ERROR => Err(error),
        Err(error) => Ok(Json(error.validation_report())),
    }
}

/// A history row: its version, what changed, when, and the summary of the
/// change from the version before it.
fn history_json(entry: &HistoryEntry, summary: &[Value]) -> Value {
    json!({
        "version": entry.version,
        "change": entry.change.as_str(),
        "rollback_of": entry.rollback_of,
        "note": entry.note,
        "changed_at": time_text(entry.changed_at),
        "spec": entry.spec.as_ref().and_then(|spec| serde_json::to_value(spec).ok()),
        "summary": summary,
    })
}

/// `GET /api/sites/{name}/versions?before=&limit=`: the history, newest first,
/// each row with its change summary.
///
/// # Errors
/// `SITE_NOT_FOUND` when the site does not exist, `INVALID_FILTER` for a bad
/// `limit` or `before`.
pub async fn versions(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<Value>> {
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
    let rows: Vec<Value> = (0..shown)
        .filter_map(|index| {
            let entry = fetched.get(index)?;
            let older = fetched
                .get(index + 1)
                .and_then(|previous| previous.spec.as_ref());
            let summary = diff_specs(older, entry.spec.as_ref());
            Some(history_json(entry, &summary))
        })
        .collect();
    let next_before = if fetched.len() > page {
        rows.last().and_then(|row| row.get("version")).cloned()
    } else {
        None
    };
    Ok(Json(
        json!({ "versions": rows, "next_before": next_before }),
    ))
}

/// `GET /api/sites/{name}/versions/{version}`: one version in full, with its
/// summary and its configuration.
///
/// # Errors
/// `VERSION_NOT_FOUND` when the site has no such version.
pub async fn version(
    State(state): State<Arc<ControlState>>,
    Path((name, version)): Path<(String, i64)>,
) -> ApiResult<Json<Value>> {
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
    let mut value = history_json(&entry, &summary);
    if let Value::Object(map) = &mut value {
        map.insert("spec".to_owned(), json!(entry.spec));
    }
    Ok(Json(value))
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
) -> ApiResult<Json<Value>> {
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

/// The changes between two configurations, as the history shows them. Scalars
/// give `from` and `to`; string lists give what was `added` and `removed`;
/// objects such as `advanced` are compared field by field. Nothing is listed
/// when either side is absent, as for a creation or a deletion.
#[must_use]
pub fn diff_specs(before: Option<&SiteSpec>, after: Option<&SiteSpec>) -> Vec<Value> {
    let (Some(before), Some(after)) = (before, after) else {
        return Vec::new();
    };
    let before = serde_json::to_value(before).unwrap_or(Value::Null);
    let after = serde_json::to_value(after).unwrap_or(Value::Null);
    let mut changes = Vec::new();
    diff_values("", &before, &after, &mut changes);
    changes
}

fn diff_values(prefix: &str, before: &Value, after: &Value, out: &mut Vec<Value>) {
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
            out.push(json!({ "field": prefix, "added": added, "removed": removed }));
        }
        _ if before != after => {
            out.push(json!({ "field": prefix, "from": before, "to": after }));
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
            vec![json!({"field": "entries", "added": ["/share/*"], "removed": []})]
        );
    }

    #[test]
    fn scalar_changes_give_both_values() {
        let after = BASE.replace(r#""mode": "observe""#, r#""mode": "enforce""#);
        let changes = diff_specs(Some(&spec(BASE)), Some(&spec(&after)));
        assert_eq!(
            changes,
            vec![json!({"field": "mode", "from": "observe", "to": "enforce"})]
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
            vec![json!({"field": "advanced.jev_timeout_ms", "from": null, "to": 1500})]
        );
    }

    #[test]
    fn a_reserved_site_name_is_refused() {
        let body = json!({"spec": serde_json::from_str::<Value>(&BASE.replace("juice", "validate")).expect("json")});
        let error = spec_from_body(&body).expect_err("reserved");
        assert_eq!(
            error.validation_report()["error"],
            "SITE_CONFIG_NAME_INVALID"
        );
    }

    #[test]
    fn a_note_longer_than_the_limit_is_refused() {
        let long = "x".repeat(NOTE_MAX_CHARS + 1);
        assert!(note_from(&json!({"note": long})).is_err());
        assert_eq!(note_from(&json!({"note": ""})).expect("empty"), None);
    }
}
