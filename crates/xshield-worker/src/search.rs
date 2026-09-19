//! Bounded, scoped analytical queries. Only typed plans enter this adapter;
//! values are bound parameters, and callers must audit attempts and results.

use super::{PublishError, PublisherConfig, valid_event_type, valid_name, validate_id_list};
use chrono::{DateTime, Utc};
use clickhouse::{Client, Row, sql::Identifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use xshield_core::{
    domain::{EventId, RequestId, SiteId, TenantId},
    query::{QueryFilter, QueryPlan, QuerySort},
};

/// One redacted event returned by a bounded cross-request query.
#[derive(Clone, Debug, Deserialize, Serialize, Row)]
pub struct SearchEventSummary {
    /// Stable request identity containing no authorization semantics.
    pub request_id: Option<String>,
    /// Stable immutable event identity.
    pub event_id: String,
    /// Versioned event kind.
    pub event_type: String,
    /// Pipeline stage extracted by the publisher adapter.
    pub stage: Option<String>,
    /// Stable stage outcome.
    pub outcome: Option<String>,
    /// Stable decision or failure reason.
    pub reason_code: Option<String>,
    /// Deterministic, model, observation, or absent proof class.
    pub proof_kind: Option<String>,
    /// Provider confidence when the proof contract permits one.
    pub confidence: Option<f64>,
    /// Explicit confidence availability state.
    pub confidence_status: Option<String>,
    /// Authenticated producer occurrence time.
    #[serde(
        serialize_with = "serialize_event_time",
        deserialize_with = "deserialize_event_time"
    )]
    pub occurred_at: DateTime<Utc>,
    /// Request-local event order.
    pub request_seq: u32,
    /// Stage duration in microseconds when available.
    pub duration_us: u64,
    /// Policy revision used for the recorded decision.
    pub policy_revision: String,
    /// Model revision when the event was model-derived.
    pub model_revision: Option<String>,
    /// Opaque evidence references; content requires separate authorization.
    pub evidence_refs: Vec<String>,
    /// Earlier event identities that directly caused this event.
    pub cause_event_ids: Vec<String>,
    /// Data classification for downstream redaction decisions.
    pub sensitivity: String,
}

fn serialize_event_time<S: Serializer>(
    value: &DateTime<Utc>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&value.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
    } else {
        clickhouse::serde::chrono::datetime64::micros::serialize(value, serializer)
    }
}

fn deserialize_event_time<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<DateTime<Utc>, D::Error> {
    if deserializer.is_human_readable() {
        DateTime::<Utc>::deserialize(deserializer)
    } else {
        clickhouse::serde::chrono::datetime64::micros::deserialize(deserializer)
    }
}

/// Stable keyset position for a cross-request query page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchPosition {
    occurred_at: DateTime<Utc>,
    event_id: EventId,
}

impl SearchPosition {
    /// Builds a position from a validated analytical row.
    ///
    /// # Errors
    /// Returns [`PublishError::InvalidEvent`] when the timestamp would lose
    /// precision in the microsecond-resolution index or cursor.
    pub fn new(occurred_at: DateTime<Utc>, event_id: EventId) -> Result<Self, PublishError> {
        if occurred_at.timestamp_subsec_nanos() >= 1_000_000_000
            || !occurred_at.timestamp_subsec_nanos().is_multiple_of(1_000)
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(Self {
            occurred_at,
            event_id,
        })
    }

    /// Returns the timestamp component of the position.
    #[must_use]
    pub const fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    /// Returns the event identity component of the position.
    #[must_use]
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }
}

/// One bounded cross-request query result.
#[derive(Clone, Debug, Serialize)]
pub struct AuditSearchResult {
    /// Redacted event rows in the requested stable order.
    pub events: Vec<SearchEventSummary>,
    /// True when another page exists after the returned rows.
    pub truncated: bool,
    /// Last row used to continue a keyset page.
    #[serde(skip)]
    pub next_position: Option<SearchPosition>,
    /// Actual scan rows reported by the index, or unknown when not reported.
    pub scanned_rows: Option<u64>,
    /// Actual uncompressed scan bytes, or unknown when not reported.
    pub scanned_bytes: Option<u64>,
}

/// Executes one validated query plan against the retention-aware analytical view.
///
/// The tenant and site are always supplied by the authenticated control-plane
/// composition root. Every predicate is selected from a closed enum and every
/// value is bound separately; no caller-provided SQL fragment is accepted.
/// The read has a five-second client deadline, server execution/scan/memory
/// budgets, and a 16 MiB decoded response ceiling. Dropping the future cancels
/// local work; the caller owns terminal audit and concurrency admission.
///
/// # Errors
/// Returns [`PublishError::InvalidConfig`] for a timestamp conversion failure,
/// [`PublishError::InvalidEvent`] for an invalid analytical row or ordering,
/// [`PublishError::QueryBudgetExceeded`] when a query budget is exhausted,
/// [`PublishError::QueryTimeout`] when the client deadline expires, and
/// [`PublishError::ClickHouse`] when the index is unavailable.
pub async fn query_audit_events(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    plan: &QueryPlan,
    after: Option<&SearchPosition>,
) -> Result<AuditSearchResult, PublishError> {
    // The client deadline also bounds connection/response stalls. Server limits
    // remain necessary because a disconnected client may not cancel all work.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        execute_query(config, client, tenant_id, site_id, plan, after),
    )
    .await
    .map_err(|_| PublishError::QueryTimeout)?
}

#[allow(clippy::too_many_lines)]
async fn execute_query(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    plan: &QueryPlan,
    after: Option<&SearchPosition>,
) -> Result<AuditSearchResult, PublishError> {
    let start = i64::try_from(plan.window().start().value())
        .ok()
        .and_then(|n| n.checked_mul(1_000_000))
        .ok_or(PublishError::InvalidConfig)?;
    let end = i64::try_from(plan.window().end().value())
        .ok()
        .and_then(|n| n.checked_mul(1_000_000))
        .ok_or(PublishError::InvalidConfig)?;
    if after.is_some_and(|p| !(start..end).contains(&p.occurred_at.timestamp_micros())) {
        return Err(PublishError::InvalidConfig);
    }
    let descending = matches!(plan.sort(), QuerySort::OccurredAtDesc);
    let mut sql = String::from(
        "SELECT nullIf(request_id,'') AS request_id,event_id,event_type,\
         nullIf(stage,'') AS stage,nullIf(outcome,'') AS outcome,\
         nullIf(reason_code,'') AS reason_code,nullIf(proof_kind,'') AS proof_kind,confidence,\
         nullIf(confidence_status,'') AS confidence_status,occurred_at,request_seq,duration_us,\
         policy_revision,nullIf(model_revision,'') AS model_revision,\
         evidence_refs,cause_event_ids,sensitivity FROM ? WHERE tenant_id = ? AND site_id = ? \
         AND occurred_at >= fromUnixTimestamp64Micro(?) AND occurred_at < fromUnixTimestamp64Micro(?)",
    );
    for filter in plan.filters() {
        sql.push_str(" AND ");
        match filter {
            QueryFilter::RequestId(_) => sql.push_str("request_id = ?"),
            QueryFilter::EventId(_) => sql.push_str("event_id = ?"),
            QueryFilter::Text { field, .. } => {
                sql.push_str(field.as_str());
                sql.push_str(" = ?");
            }
            QueryFilter::Outcome(_) => sql.push_str("outcome = ?"),
            QueryFilter::ConfidenceAtMost(_) => sql.push_str("confidence <= ?"),
        }
    }
    if after.is_some() {
        sql.push_str(" AND ");
        if descending {
            sql.push_str("tuple(occurred_at,event_id) < tuple(fromUnixTimestamp64Micro(?),?)");
        } else {
            sql.push_str("tuple(occurred_at,event_id) > tuple(fromUnixTimestamp64Micro(?),?)");
        }
    }
    if descending {
        sql.push_str(" ORDER BY occurred_at DESC,event_id DESC LIMIT ?");
    } else {
        sql.push_str(" ORDER BY occurred_at ASC,event_id ASC LIMIT ?");
    }

    let mut query = client
        .query(&sql)
        .bind(Identifier(&config.active_view))
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(start)
        .bind(end);
    for filter in plan.filters() {
        query = match filter {
            QueryFilter::RequestId(value) => query.bind(value.as_str()),
            QueryFilter::EventId(value) => query.bind(value.as_str()),
            QueryFilter::Text { value, .. } => query.bind(value),
            QueryFilter::Outcome(value) => query.bind(value.as_str()),
            QueryFilter::ConfidenceAtMost(value) => query.bind(value.as_f64()),
        };
    }
    if let Some(position) = after {
        query = query
            .bind(position.occurred_at().timestamp_micros())
            .bind(position.event_id().as_str());
    }
    let fetch_limit = u64::from(plan.limit()) + 1;
    let mut cursor = query
        .bind(fetch_limit)
        .with_setting("max_execution_time", "2")
        .with_setting("timeout_before_checking_execution_speed", "0")
        .with_setting("max_rows_to_read", "1000000")
        .with_setting("max_bytes_to_read", "67108864")
        .with_setting("read_overflow_mode", "throw")
        .with_setting("timeout_overflow_mode", "throw")
        .with_setting("max_result_bytes", "16777216")
        .with_setting("result_overflow_mode", "throw")
        .with_setting("max_memory_usage", "268435456")
        .with_setting("max_threads", "2")
        .with_setting("prefer_column_name_to_alias", "1")
        .with_setting("wait_end_of_query", "1")
        .fetch::<SearchEventSummary>()
        .map_err(query_error)?;
    let mut events = Vec::with_capacity(usize::from(plan.limit()) + 1);
    let mut seen_ids: BTreeSet<_> = after
        .map(|p| p.event_id.as_str().to_owned())
        .into_iter()
        .collect();
    while let Some(event) = cursor.next().await.map_err(query_error)? {
        if events.len() > usize::from(plan.limit()) {
            return Err(PublishError::InvalidEvent);
        }
        if cursor.decoded_bytes() > 16 * 1024 * 1024 {
            return Err(PublishError::QueryBudgetExceeded);
        }
        validate_search_event(&event)?;
        let key = (event.occurred_at, event.event_id.as_str());
        let previous = events
            .last()
            .map(|previous: &SearchEventSummary| (previous.occurred_at, previous.event_id.as_str()))
            .or_else(|| after.map(|p| (p.occurred_at, p.event_id.as_str())));
        if !seen_ids.insert(event.event_id.clone())
            || !(start..end).contains(&event.occurred_at.timestamp_micros())
            || previous.is_some_and(|previous| {
                if descending {
                    key >= previous
                } else {
                    key <= previous
                }
            })
        {
            return Err(PublishError::InvalidEvent);
        }
        events.push(event);
    }
    let scanned_rows = cursor
        .summary()
        .and_then(clickhouse::QuerySummary::read_rows);
    let scanned_bytes = cursor
        .summary()
        .and_then(clickhouse::QuerySummary::read_bytes);
    let truncated = events.len() > usize::from(plan.limit());
    events.truncate(usize::from(plan.limit()));
    let next_position = if truncated {
        let last = events.last().ok_or(PublishError::InvalidEvent)?;
        Some(SearchPosition::new(
            last.occurred_at,
            EventId::parse(&last.event_id).map_err(|_| PublishError::InvalidEvent)?,
        )?)
    } else {
        None
    };
    Ok(AuditSearchResult {
        events,
        truncated,
        next_position,
        scanned_rows,
        scanned_bytes,
    })
}

fn query_error(error: clickhouse::error::Error) -> PublishError {
    match &error {
        clickhouse::error::Error::TimedOut => PublishError::QueryTimeout,
        // The SDK erases the typed exception header. Decode only its wire-code
        // prefix (or the server's identical body prefix), never message text.
        clickhouse::error::Error::BadResponse(body)
            if matches!(
                query_exception_code(body),
                Some(158 | 159 | 241 | 307 | 396)
            ) =>
        {
            PublishError::QueryBudgetExceeded
        }
        _ => PublishError::ClickHouse(error),
    }
}

fn query_exception_code(body: &str) -> Option<u16> {
    let prefix = body.strip_prefix("Code: ")?;
    let digits = prefix.split_once(". ").map_or(prefix, |(digits, _)| digits);
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn validate_search_event(event: &SearchEventSummary) -> Result<(), PublishError> {
    if let Some(request) = &event.request_id {
        RequestId::parse(request).map_err(|_| PublishError::InvalidEvent)?;
    }
    EventId::parse(&event.event_id).map_err(|_| PublishError::InvalidEvent)?;
    validate_id_list(&event.evidence_refs, None)?;
    validate_id_list(&event.cause_event_ids, Some("ev_"))?;
    if !valid_event_type(&event.event_type)
        || event
            .stage
            .as_deref()
            .is_some_and(|value| !valid_name(value))
        || event
            .reason_code
            .as_deref()
            .is_some_and(|value| !valid_name(value))
        || event.outcome.as_deref().is_some_and(|value| {
            !matches!(
                value,
                "PASS"
                    | "ALLOW"
                    | "DENY"
                    | "UNKNOWN"
                    | "ERROR"
                    | "SKIPPED"
                    | "CANCELLED"
                    | "not_sent"
                    | "unknown"
                    | "response_received"
            )
        })
        || event.proof_kind.as_deref().is_some_and(|value| {
            !matches!(value, "deterministic" | "model" | "observation" | "none")
        })
        || event.confidence_status.as_deref().is_some_and(|value| {
            !matches!(
                value,
                "provided" | "not_applicable" | "not_provided" | "unavailable"
            )
        })
        || event
            .confidence
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        || (event.confidence.is_some() != (event.confidence_status.as_deref() == Some("provided")))
        || (event.proof_kind.as_deref() == Some("deterministic")
            && (event.confidence.is_some()
                || event.confidence_status.as_deref() != Some("not_applicable")))
        || (matches!(event.outcome.as_deref(), Some("SKIPPED" | "CANCELLED"))
            && event.confidence.is_some())
        || event.request_seq == 0
        || !valid_name(&event.policy_revision)
        || event
            .model_revision
            .as_deref()
            .is_some_and(|value| !valid_name(value))
        || !matches!(
            event.sensitivity.as_str(),
            "PUBLIC" | "INTERNAL" | "SENSITIVE" | "RESTRICTED"
        )
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PublishError, query_error};
    use clickhouse::error::Error;

    #[test]
    fn query_failures_use_only_canonical_wire_codes() {
        for code in [158, 159, 241, 307, 396] {
            for body in [
                format!("Code: {code}"),
                format!("Code: {code}. DB::Exception: details"),
            ] {
                assert!(matches!(
                    query_error(Error::BadResponse(body)),
                    PublishError::QueryBudgetExceeded
                ));
            }
        }
        for body in [
            "Code: 209",
            "Code: 3079",
            "Code: 0158",
            "Code: +158",
            "Code: 158x",
            "Code: 158: details",
            "Code: 158\n",
            "Code: 65536",
            "Code: ",
            " Code: 158",
            "upstream Code: 158",
            "TIMEOUT_EXCEEDED",
        ] {
            assert!(
                matches!(
                    query_error(Error::BadResponse(body.to_owned())),
                    PublishError::ClickHouse(_)
                ),
                "{body}"
            );
        }
        assert!(matches!(
            query_error(Error::TimedOut),
            PublishError::QueryTimeout
        ));
    }
}
