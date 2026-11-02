//! The system page (docs/07 section 7.9.8): control build, gateway instances,
//! decision log storage and run parameters.
//!
//! The page reads this once when it opens; nothing polls it. Run parameters come
//! from the newest heartbeat, and the code defaults fill any parameter that
//! heartbeat does not carry. Site state keeps only the version and the error of
//! each site, and nothing of the heartbeat's Jev configuration but its five fields.

use std::{collections::BTreeMap, sync::Arc};

use axum::{Json, extract::State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use xshield_postgres::{
    decision_stats,
    edge_status_store::{self, EdgeStatus},
    partitions::{self, PartitionInfo},
};

use crate::{
    ControlState,
    error::ApiResult,
    jev::{self, JevConfigBody},
    params::rfc3339,
};

/// `GET /api/system` (docs/07 section 7.9.8): the control build and the database
/// version, every gateway instance with its last heartbeat, the decision log's
/// partitions and loss intervals, and the run parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemBody {
    /// The control plane's build version.
    pub control_build: String,
    /// The PostgreSQL server version.
    pub postgres: String,
    /// Every gateway instance, online or not, with its last heartbeat.
    pub edges: Vec<EdgeBody>,
    /// The decision log's partitions, loss intervals and retention.
    pub storage: StorageBody,
    /// The run parameters in their two groups.
    pub params: ParamsBody,
}

/// One gateway instance: its last heartbeat, whether it is online, and the Jev
/// configuration it reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeBody {
    pub edge: String,
    pub online: bool,
    pub started_at: Option<String>,
    pub seen_at: Option<String>,
    pub build: String,
    pub listen: String,
    pub tls: bool,
    pub sessions: i32,
    pub queue: i32,
    pub written: i64,
    pub dropped: i64,
    pub dropped_bypass: i64,
    pub write_errors: i64,
    /// The loss intervals the heartbeat reports, last 24 hours.
    pub gaps: Vec<GapBody>,
    /// Per site: the loaded version, or the error that kept it from loading.
    pub sites: BTreeMap<String, SiteStateBody>,
    pub jev: JevConfigBody,
}

/// One loss interval as a gateway reports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GapBody {
    pub from_ms: i64,
    pub to_ms: i64,
    pub dropped: i64,
    pub dropped_bypass: i64,
    pub write_errors: i64,
}

/// One site on one instance: the version it loaded and when, or the error that kept it
/// from loading. A key the heartbeat does not carry is left out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteStateBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    /// When the instance loaded `version`, Unix milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded_at_millis: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The decision log's storage: retention, the earliest record, the daily partitions
/// and the loss intervals of every instance, flattened into one list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageBody {
    pub retention_days: u64,
    pub earliest_millis: Option<i64>,
    pub partitions: Vec<PartitionBody>,
    pub gaps: Vec<StorageGapBody>,
}

/// One daily partition of the decision log. `to_millis` is exclusive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartitionBody {
    pub name: String,
    pub rows: i64,
    pub bytes: i64,
    pub from_millis: Option<i64>,
    pub to_millis: Option<i64>,
}

/// A loss interval of one instance, as the storage section lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageGapBody {
    pub edge: String,
    pub from_millis: i64,
    pub to_millis: i64,
    pub rows: i64,
    pub reason: GapReason,
}

/// Why rows were lost in an interval: the queue was full, or an insert failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    QueueFull,
    WriteError,
}

/// The run parameters in the two groups of docs/07 section 7.9.8.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParamsBody {
    pub site_overridable: SiteOverridableBody,
    pub fixed: FixedParamsBody,
}

/// The parameters a site can override.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteOverridableBody {
    pub jev_timeout_ms: i64,
    pub session_calls_per_minute: i64,
    pub address_calls_per_minute: i64,
    pub allow_cache_minutes: i64,
    pub secret_fields: Vec<String>,
    pub synonyms: Vec<Vec<String>>,
}

/// The parameters no site can change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixedParamsBody {
    pub seen_max: i64,
    pub sources_max: i64,
    pub recent_max: i64,
    pub idle_hours: i64,
    pub sessions_max: i64,
    pub long_value_chars: i64,
    pub state_bytes_max: i64,
    pub request_body_max: i64,
    pub response_parse_max: i64,
    pub request_values_max: i64,
    pub queue_capacity: i64,
}

/// `GET /api/system`: the control build and the database version, every gateway
/// instance with its last heartbeat, the decision log's partitions and loss
/// intervals, and the run parameters.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
pub async fn system(State(state): State<Arc<ControlState>>) -> ApiResult<Json<SystemBody>> {
    let now = Utc::now();
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
    Ok(Json(SystemBody {
        control_build: env!("CARGO_PKG_VERSION").to_owned(),
        postgres,
        edges: edges.iter().map(|edge| edge_body(edge, now)).collect(),
        storage: StorageBody {
            retention_days: partitions::RETENTION_DAYS,
            earliest_millis: earliest,
            partitions: daily.iter().map(partition_body).collect(),
            gaps: storage_gaps(&edges),
        },
        params: runtime_params(reported),
    }))
}

/// One gateway instance as the system page shows it.
#[must_use]
fn edge_body(edge: &EdgeStatus, now: DateTime<Utc>) -> EdgeBody {
    EdgeBody {
        edge: edge.edge.clone(),
        online: edge.is_online(now),
        started_at: rfc3339(edge.started_at.timestamp_millis()),
        seen_at: rfc3339(edge.seen_at.timestamp_millis()),
        build: edge.build.clone(),
        listen: edge.listen.clone(),
        tls: edge.tls,
        sessions: edge.sessions,
        queue: edge.queue,
        written: edge.written,
        dropped: edge.dropped,
        dropped_bypass: edge.dropped_bypass,
        write_errors: edge.write_errors,
        gaps: gap_list(&edge.gaps),
        sites: site_states(&edge.sites),
        jev: jev::reported_config(edge),
    }
}

/// The state of each site on one instance: the version it loaded and when, or the error
/// that made it refuse the site. Nothing else the heartbeat carries is returned.
#[must_use]
fn site_states(sites: &Value) -> BTreeMap<String, SiteStateBody> {
    sites
        .as_object()
        .into_iter()
        .flatten()
        .map(|(site, entry)| {
            let state = SiteStateBody {
                version: field(Some(entry), "version"),
                loaded_at_millis: field(Some(entry), "loaded_at_millis"),
                error: field(Some(entry), "error"),
            };
            (site.clone(), state)
        })
        .collect()
}

/// The loss intervals one instance reports. A gap without its bounds is left out, and
/// a counter it does not carry reads as zero.
#[must_use]
fn gap_list(gaps: &Value) -> Vec<GapBody> {
    gaps.as_array()
        .into_iter()
        .flatten()
        .filter_map(|gap| {
            Some(GapBody {
                from_ms: field(Some(gap), "from_ms")?,
                to_ms: field(Some(gap), "to_ms")?,
                dropped: count(gap, "dropped"),
                dropped_bypass: count(gap, "dropped_bypass"),
                write_errors: count(gap, "write_errors"),
            })
        })
        .collect()
}

/// The loss intervals of every instance, flattened into one list for the storage
/// section.
#[must_use]
fn storage_gaps(edges: &[EdgeStatus]) -> Vec<StorageGapBody> {
    edges
        .iter()
        .flat_map(|edge| storage_gap_rows(&edge.edge, &edge.gaps))
        .collect()
}

/// The loss intervals one instance reports, as the storage section lists them.
/// A gap is a `write_error` when writes failed in it and `queue_full` otherwise.
/// Its rows are every row it dropped, on the queue or bypassing it, or failed to
/// write.
#[must_use]
fn storage_gap_rows(edge: &str, gaps: &Value) -> Vec<StorageGapBody> {
    gap_list(gaps)
        .into_iter()
        .map(|gap| {
            let rows = gap
                .dropped
                .saturating_add(gap.dropped_bypass)
                .saturating_add(gap.write_errors);
            let reason = if gap.write_errors > 0 {
                GapReason::WriteError
            } else {
                GapReason::QueueFull
            };
            StorageGapBody {
                edge: edge.to_owned(),
                from_millis: gap.from_ms,
                to_millis: gap.to_ms,
                rows,
                reason,
            }
        })
        .collect()
}

/// The partitions of the decision log with their size and the UTC range each
/// holds. `to_millis` is exclusive: the start of the next day.
#[must_use]
fn partition_body(partition: &PartitionInfo) -> PartitionBody {
    let bounds = partition.day.and_then(partitions::day_bounds_millis);
    PartitionBody {
        name: partition.name.clone(),
        rows: partition.rows_estimate,
        bytes: partition.bytes,
        from_millis: bounds.map(|(from, _)| from),
        to_millis: bounds.map(|(_, to)| to),
    }
}

/// The run parameters in the two groups of section 7.9.8. Each key takes the value
/// the report carries, or its code default when the report does not carry it, or
/// carries it in another shape. A key the report adds is never shown.
#[must_use]
fn runtime_params(reported: Option<&Value>) -> ParamsBody {
    let site = reported.and_then(|params| params.get("site_overridable"));
    let fixed = reported.and_then(|params| params.get("fixed"));
    ParamsBody {
        site_overridable: SiteOverridableBody {
            jev_timeout_ms: field(site, "jev_timeout_ms").unwrap_or(2_000),
            session_calls_per_minute: field(site, "session_calls_per_minute").unwrap_or(60),
            address_calls_per_minute: field(site, "address_calls_per_minute").unwrap_or(30),
            allow_cache_minutes: field(site, "allow_cache_minutes").unwrap_or(10),
            secret_fields: field(site, "secret_fields").unwrap_or_else(default_secret_fields),
            synonyms: field(site, "synonyms")
                .unwrap_or_else(|| vec![vec!["card".to_owned(), "payment".to_owned()]]),
        },
        fixed: FixedParamsBody {
            seen_max: field(fixed, "seen_max").unwrap_or(5_000),
            sources_max: field(fixed, "sources_max").unwrap_or(6),
            recent_max: field(fixed, "recent_max").unwrap_or(50),
            idle_hours: field(fixed, "idle_hours").unwrap_or(24),
            sessions_max: field(fixed, "sessions_max").unwrap_or(20_000),
            long_value_chars: field(fixed, "long_value_chars").unwrap_or(8),
            state_bytes_max: field(fixed, "state_bytes_max").unwrap_or(8_192),
            request_body_max: field(fixed, "request_body_max").unwrap_or(49_152),
            response_parse_max: field(fixed, "response_parse_max").unwrap_or(1_048_576),
            request_values_max: field(fixed, "request_values_max").unwrap_or(200),
            queue_capacity: field(fixed, "queue_capacity").unwrap_or(10_000),
        },
    }
}

/// The field names a site treats as secrets when its report names none.
#[must_use]
fn default_secret_fields() -> Vec<String> {
    [
        "authorization",
        "credential",
        "cvv",
        "otp",
        "passwd",
        "password",
        "pwd",
        "secret",
        "token",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// One key of a reported object, read as `T`. A key the report does not carry, a null,
/// or a value of another shape is `None`, so the caller takes its default.
#[must_use]
fn field<T: DeserializeOwned>(object: Option<&Value>, key: &str) -> Option<T> {
    object
        .and_then(|object| object.get(key))
        .filter(|value| !value.is_null())
        .and_then(|value| T::deserialize(value).ok())
}

/// A counter one loss interval carries, or zero when it does not.
#[must_use]
fn count(gap: &Value, key: &str) -> i64 {
    field::<i64>(Some(gap), key).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_reported_value_replaces_its_default_and_unknown_keys_are_dropped() {
        let reported = json!({ "fixed": { "seen_max": 7_000, "not_a_param": 1 } });
        let params = runtime_params(Some(&reported));
        assert_eq!(params.fixed.seen_max, 7_000);
        assert_eq!(params.fixed.sources_max, 6);
        let written = serde_json::to_value(&params).expect("the parameters write JSON");
        assert!(written["fixed"].get("not_a_param").is_none());
    }

    #[test]
    fn without_a_report_the_code_defaults_are_returned() {
        let params = runtime_params(None);
        assert_eq!(params.site_overridable.jev_timeout_ms, 2_000);
        assert_eq!(params.fixed.queue_capacity, 10_000);
    }

    #[test]
    fn a_value_of_another_shape_falls_back_to_its_default() {
        let reported = json!({ "fixed": { "seen_max": "many", "sources_max": null } });
        let params = runtime_params(Some(&reported));
        assert_eq!(params.fixed.seen_max, 5_000);
        assert_eq!(params.fixed.sources_max, 6);
    }

    #[test]
    fn a_gap_is_a_write_error_when_writes_failed_and_counts_every_lost_row() {
        let gaps = json!([
            { "from_ms": 1_000, "to_ms": 2_000, "dropped": 3, "dropped_bypass": 1, "write_errors": 0 },
            { "from_ms": 3_000, "to_ms": 4_000, "dropped": 0, "dropped_bypass": 0, "write_errors": 2 }
        ]);
        assert_eq!(
            storage_gap_rows("edge-a", &gaps),
            vec![
                StorageGapBody {
                    edge: "edge-a".to_owned(),
                    from_millis: 1_000,
                    to_millis: 2_000,
                    rows: 4,
                    reason: GapReason::QueueFull,
                },
                StorageGapBody {
                    edge: "edge-a".to_owned(),
                    from_millis: 3_000,
                    to_millis: 4_000,
                    rows: 2,
                    reason: GapReason::WriteError,
                },
            ]
        );
    }

    #[test]
    fn a_site_keeps_its_version_load_time_and_error_only() {
        let sites = json!({
            "emr": { "version": 13, "loaded_at_millis": 1_793_539_051_500_i64, "state": "loaded", "error": null },
            "juice": { "error": "SITE_CONFIG_ORIGIN_INVALID" },
        });
        let states = site_states(&sites);
        assert_eq!(
            states["emr"],
            SiteStateBody {
                version: Some(13),
                loaded_at_millis: Some(1_793_539_051_500),
                error: None,
            }
        );
        assert_eq!(
            states["juice"],
            SiteStateBody {
                version: None,
                loaded_at_millis: None,
                error: Some("SITE_CONFIG_ORIGIN_INVALID".to_owned()),
            }
        );
    }
}
