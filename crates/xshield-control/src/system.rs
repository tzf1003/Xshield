//! The system page (docs/07 section 7.9.8): control build, gateway instances,
//! decision log storage and run parameters.
//!
//! The page reads this once when it opens; nothing polls it. Run parameters come
//! from the newest heartbeat, and the code defaults fill any parameter that
//! heartbeat does not carry. Site state keeps only the version and the error of
//! each site, and nothing of the heartbeat's Jev configuration but its five fields.

use std::sync::Arc;

use axum::{Json, extract::State};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use xshield_postgres::{
    decision_stats,
    edge_status_store::{self, EdgeStatus},
    partitions::{self, PartitionInfo},
};

use crate::{ControlState, error::ApiResult, jev, params::rfc3339};

/// `GET /api/system`: the control build and the database version, every gateway
/// instance with its last heartbeat, the decision log's partitions and loss
/// intervals, and the run parameters.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
pub async fn system(State(state): State<Arc<ControlState>>) -> ApiResult<Json<Value>> {
    let now = Utc::now();
    let build = env!("CARGO_PKG_VERSION");
    let postgres = decision_stats::server_version(&state.pool).await?;
    let edges = edge_status_store::list(&state.pool).await?;
    let daily = partitions::list_partitions(&state.pool).await?;
    let earliest = partitions::earliest_at_millis(&state.pool).await?;
    // An online instance always sent the newest heartbeat, so this is its report
    // whenever one is online. With none online it is the last report there is.
    let reported = edges
        .iter()
        .max_by_key(|edge| edge.seen_at)
        .map(|edge| &edge.params);
    let instances: Vec<Value> = edges.iter().map(|edge| edge_json(edge, now)).collect();
    Ok(Json(json!({
        "control_build": build,
        "postgres": postgres,
        "edges": instances,
        "storage": {
            "retention_days": partitions::RETENTION_DAYS,
            "earliest_millis": earliest,
            "partitions": partition_json(&daily),
            "gaps": storage_gaps(&edges),
        },
        "params": runtime_params(reported),
    })))
}

/// One gateway instance as the system page shows it: its heartbeat, whether it is
/// online, and the Jev configuration it reports.
#[must_use]
fn edge_json(edge: &EdgeStatus, now: DateTime<Utc>) -> Value {
    json!({
        "edge": edge.edge,
        "online": edge.is_online(now),
        "started_at": rfc3339(edge.started_at.timestamp_millis()),
        "seen_at": rfc3339(edge.seen_at.timestamp_millis()),
        "build": edge.build,
        "listen": edge.listen,
        "tls": edge.tls,
        "sessions": edge.sessions,
        "queue": edge.queue,
        "written": edge.written,
        "dropped": edge.dropped,
        "dropped_bypass": edge.dropped_bypass,
        "write_errors": edge.write_errors,
        "gaps": edge.gaps,
        "sites": site_states(&edge.sites),
        "jev": jev::reported_config(edge),
    })
}

/// The state of each site on one instance: the version it loaded, or the error
/// that made it refuse the site. Nothing else the heartbeat carries is returned.
#[must_use]
fn site_states(sites: &Value) -> Value {
    let states: Map<String, Value> = sites
        .as_object()
        .into_iter()
        .flatten()
        .map(|(site, entry)| {
            let state: Map<String, Value> = ["version", "error"]
                .into_iter()
                .filter_map(|key| {
                    entry
                        .get(key)
                        .filter(|value| !value.is_null())
                        .map(|value| (key.to_owned(), value.clone()))
                })
                .collect();
            (site.clone(), Value::Object(state))
        })
        .collect();
    Value::Object(states)
}

/// The partitions of the decision log with their size and the UTC range each
/// holds. `to_millis` is exclusive: the start of the next day.
#[must_use]
fn partition_json(daily: &[PartitionInfo]) -> Vec<Value> {
    daily
        .iter()
        .map(|partition| {
            let bounds = partition.day.and_then(partitions::day_bounds_millis);
            json!({
                "name": partition.name,
                "rows": partition.rows_estimate,
                "bytes": partition.bytes,
                "from_millis": bounds.map(|(from, _)| from),
                "to_millis": bounds.map(|(_, to)| to),
            })
        })
        .collect()
}

/// The loss intervals of every instance, flattened into one list for the storage
/// section.
#[must_use]
fn storage_gaps(edges: &[EdgeStatus]) -> Vec<Value> {
    edges
        .iter()
        .flat_map(|edge| gap_rows(&edge.edge, &edge.gaps))
        .collect()
}

/// The loss intervals one instance reports, as the storage section lists them.
/// A gap is a `write_error` when writes failed in it and `queue_full` otherwise.
/// Its rows are every row it dropped, on the queue or bypassing it, or failed to
/// write.
#[must_use]
fn gap_rows(edge: &str, gaps: &Value) -> Vec<Value> {
    let Some(gaps) = gaps.as_array() else {
        return Vec::new();
    };
    gaps.iter()
        .filter_map(|gap| {
            let from = gap.get("from_ms").and_then(Value::as_i64)?;
            let to = gap.get("to_ms").and_then(Value::as_i64)?;
            let count = |key: &str| gap.get(key).and_then(Value::as_i64).unwrap_or(0);
            let write_errors = count("write_errors");
            let rows = count("dropped")
                .saturating_add(count("dropped_bypass"))
                .saturating_add(write_errors);
            let reason = if write_errors > 0 {
                "write_error"
            } else {
                "queue_full"
            };
            Some(json!({
                "edge": edge,
                "from_millis": from,
                "to_millis": to,
                "rows": rows,
                "reason": reason,
            }))
        })
        .collect()
}

/// The run parameters in the two groups of section 7.9.8. Each key takes the value
/// the report carries, or its code default when the report does not carry it.
#[must_use]
fn runtime_params(reported: Option<&Value>) -> Value {
    let site_overridable = merged_group(reported, "site_overridable", &site_overridable_defaults());
    let fixed = merged_group(reported, "fixed", &fixed_defaults());
    json!({
        "site_overridable": site_overridable,
        "fixed": fixed,
    })
}

/// One group of the run parameters. Only the keys in `defaults` are returned, so a
/// key the report adds is never shown.
#[must_use]
fn merged_group(reported: Option<&Value>, group: &str, defaults: &[(&str, Value)]) -> Value {
    let report = reported.and_then(|params| params.get(group));
    let merged: Map<String, Value> = defaults
        .iter()
        .map(|(key, default)| {
            let value = report
                .and_then(|values| values.get(*key))
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| default.clone());
            ((*key).to_owned(), value)
        })
        .collect();
    Value::Object(merged)
}

/// The per-site parameters with their code defaults.
#[must_use]
fn site_overridable_defaults() -> Vec<(&'static str, Value)> {
    vec![
        ("jev_timeout_ms", json!(2_000)),
        ("session_calls_per_minute", json!(60)),
        ("address_calls_per_minute", json!(30)),
        ("allow_cache_minutes", json!(10)),
        (
            "secret_fields",
            json!([
                "authorization",
                "credential",
                "cvv",
                "otp",
                "passwd",
                "password",
                "pwd",
                "secret",
                "token"
            ]),
        ),
        ("synonyms", json!([["card", "payment"]])),
    ]
}

/// The fixed parameters, which no site can change, with their code defaults.
#[must_use]
fn fixed_defaults() -> Vec<(&'static str, Value)> {
    vec![
        ("seen_max", json!(5_000)),
        ("sources_max", json!(6)),
        ("recent_max", json!(50)),
        ("idle_hours", json!(24)),
        ("sessions_max", json!(20_000)),
        ("long_value_chars", json!(8)),
        ("state_bytes_max", json!(8_192)),
        ("request_body_max", json!(49_152)),
        ("response_parse_max", json!(1_048_576)),
        ("request_values_max", json!(200)),
        ("queue_capacity", json!(10_000)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reported_value_replaces_its_default_and_unknown_keys_are_dropped() {
        let reported = json!({ "fixed": { "seen_max": 7_000, "not_a_param": 1 } });
        let params = runtime_params(Some(&reported));
        assert_eq!(params["fixed"]["seen_max"], json!(7_000));
        assert_eq!(params["fixed"]["sources_max"], json!(6));
        assert!(params["fixed"].get("not_a_param").is_none());
    }

    #[test]
    fn without_a_report_the_code_defaults_are_returned() {
        let params = runtime_params(None);
        assert_eq!(params["site_overridable"]["jev_timeout_ms"], json!(2_000));
        assert_eq!(params["fixed"]["queue_capacity"], json!(10_000));
    }

    #[test]
    fn a_gap_is_a_write_error_when_writes_failed_and_counts_every_lost_row() {
        let gaps = json!([
            { "from_ms": 1_000, "to_ms": 2_000, "dropped": 3, "dropped_bypass": 1, "write_errors": 0 },
            { "from_ms": 3_000, "to_ms": 4_000, "dropped": 0, "dropped_bypass": 0, "write_errors": 2 }
        ]);
        assert_eq!(
            gap_rows("edge-a", &gaps),
            vec![
                json!({ "edge": "edge-a", "from_millis": 1_000, "to_millis": 2_000, "rows": 4, "reason": "queue_full" }),
                json!({ "edge": "edge-a", "from_millis": 3_000, "to_millis": 4_000, "rows": 2, "reason": "write_error" })
            ]
        );
    }
}
