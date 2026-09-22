//! Bounded, scoped analytical queries. Only typed plans enter this adapter;
//! values are bound parameters, and callers must audit attempts and results.

use super::{
    MODEL_CALL_ID_PROJECTION, PublishError, PublisherConfig, valid_confidence, valid_event_type,
    valid_name, validate_id_list,
};
use chrono::{DateTime, Utc};
use clickhouse::{Client, Row, sql::Identifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use xshield_core::{
    domain::{EventId, ModelCallId, RequestId, SiteId, TenantId},
    query::{MAX_LIMIT, QueryFilter, QueryPlan, QuerySort, QueryWindow},
};

/// Maximum number of redacted model-call summaries in one page.
///
/// The list validates each selected lifecycle payload before projecting it, so
/// its page budget is intentionally lower than the generic event-search
/// budget. This keeps a corrupt retained payload from turning a metadata list
/// into an unbounded decoder workload.
pub const MODEL_CALL_LIST_LIMIT_MAX: u16 = 100;

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
    /// Exact model-call reference when the event was model-derived.
    ///
    /// This link is redacted metadata. Consumers must use the separately
    /// authorized model-call endpoint before viewing lifecycle details.
    pub model_call_id: Option<String>,
    /// Opaque evidence references; content requires separate authorization.
    pub evidence_refs: Vec<String>,
    /// Earlier event identities that directly caused this event.
    pub cause_event_ids: Vec<String>,
    /// Data classification for downstream redaction decisions.
    pub sensitivity: String,
}

/// One redacted lifecycle entry for a model call.
#[derive(Clone, Debug, Serialize)]
pub struct ModelCallEventSummary {
    /// Immutable audit event identity.
    pub event_id: String,
    /// Typed lifecycle event kind.
    pub event_type: String,
    /// Request that initiated the model attempt.
    pub request_id: String,
    /// Stable provider route name, when the lifecycle records it.
    pub provider: Option<String>,
    /// Exact wire model identifier, kept separate from internal revision.
    pub provider_model_id: Option<String>,
    /// Authenticated occurrence time.
    #[serde(serialize_with = "serialize_event_time")]
    pub occurred_at: DateTime<Utc>,
    /// Request-local event order.
    pub request_seq: u32,
    /// Typed model lifecycle status.
    pub status: String,
    /// Versioned model identifier.
    pub model_revision: String,
    /// Versioned prompt identifier.
    pub prompt_revision: String,
    /// Jev question type.
    pub question_type: String,
    /// Stable lifecycle reason code.
    pub reason_code: String,
    /// Provider confidence when the contract permits one.
    pub confidence: Option<f64>,
    /// Explicit confidence availability state.
    pub confidence_status: String,
    /// Attempt duration in microseconds.
    pub duration_us: u64,
    /// Input evidence reference, when persisted at this lifecycle point.
    pub input_artifact_id: Option<String>,
    /// Output evidence reference, when persisted at this lifecycle point.
    pub output_artifact_id: Option<String>,
    /// Typed call-record evidence reference, when persisted at this lifecycle point.
    pub call_artifact_id: Option<String>,
    /// All evidence refs authenticated on the enclosing event.
    pub evidence_refs: Vec<String>,
    /// Immediate predecessor, when the call has progressed beyond its start.
    pub cause_event_ids: Vec<String>,
    /// Event sensitivity classification.
    pub sensitivity: String,
}

/// One bounded model-call view assembled from its authenticated lifecycle.
#[derive(Clone, Debug, Serialize)]
pub struct ModelCallSummary {
    /// Stable model attempt identity.
    pub model_call_id: String,
    /// Request that initiated the model attempt.
    pub request_id: String,
    /// Stable provider route name, when the lifecycle records it.
    pub provider: Option<String>,
    /// Exact wire model identifier, kept separate from internal revision.
    pub provider_model_id: Option<String>,
    /// Versioned model identifier.
    pub model_revision: String,
    /// Versioned prompt identifier.
    pub prompt_revision: String,
    /// Supported Jev question type.
    pub question_type: String,
    /// Latest lifecycle status.
    pub status: String,
    /// Latest lifecycle reason code.
    pub reason_code: String,
    /// Latest provider confidence under the typed contract.
    pub confidence: Option<f64>,
    /// Latest confidence availability state.
    pub confidence_status: String,
    /// Latest observed duration in microseconds.
    pub duration_us: u64,
    /// Stable input evidence reference.
    pub input_artifact_id: Option<String>,
    /// Stable output evidence reference.
    pub output_artifact_id: Option<String>,
    /// Stable model-call record evidence reference.
    pub call_artifact_id: Option<String>,
    /// Ordered, redacted lifecycle entries.
    pub events: Vec<ModelCallEventSummary>,
    /// True only when the visible prefix contains start, send, and terminal
    /// (or start and a pre-send failure). Retention may hide an earlier prefix.
    pub lifecycle_complete: bool,
}

/// A validated, bounded request for redacted model-call discovery.
///
/// This type deliberately has no tenant or site field: the authenticated
/// control-plane composition root supplies those values to the query adapter.
/// The window describes what was visible to this page, not a frozen lifecycle
/// snapshot or a grant to read model evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelCallListPlan {
    window: QueryWindow,
    limit: u16,
}

impl ModelCallListPlan {
    /// Validates a model-call discovery page after its UTC window was checked.
    ///
    /// # Errors
    /// Returns [`ModelCallListPlanError::InvalidLimit`] when the page is empty,
    /// exceeds this list's decoder budget, or exceeds the workspace query
    /// maximum. Authorization, scope injection, cursor authentication, and
    /// terminal access audit remain caller responsibilities.
    pub const fn new(window: QueryWindow, limit: u16) -> Result<Self, ModelCallListPlanError> {
        if limit == 0 || limit > MODEL_CALL_LIST_LIMIT_MAX || limit > MAX_LIMIT {
            return Err(ModelCallListPlanError::InvalidLimit);
        }
        Ok(Self { window, limit })
    }

    /// Returns the required half-open UTC investigation window.
    #[must_use]
    pub const fn window(self) -> QueryWindow {
        self.window
    }

    /// Returns the maximum number of redacted summaries to expose.
    #[must_use]
    pub const fn limit(self) -> u16 {
        self.limit
    }
}

/// Static validation failures for [`ModelCallListPlan`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelCallListPlanError {
    /// The requested page size is outside the list's fixed resource budget.
    InvalidLimit,
}

/// Stable keyset position for descending model-call discovery.
///
/// The position is the latest retained lifecycle event for one `mdl_` within
/// the caller's window. It is intentionally not an event cursor: one model
/// call appears at most once on a page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCallListPosition {
    occurred_at: DateTime<Utc>,
    model_call_id: ModelCallId,
}

impl ModelCallListPosition {
    /// Builds a position from a validated list row.
    ///
    /// # Errors
    /// Returns [`PublishError::InvalidEvent`] if the timestamp cannot be
    /// represented without loss in `ClickHouse`'s microsecond cursor boundary.
    pub fn new(
        occurred_at: DateTime<Utc>,
        model_call_id: ModelCallId,
    ) -> Result<Self, PublishError> {
        if occurred_at.timestamp_subsec_nanos() >= 1_000_000_000
            || !occurred_at.timestamp_subsec_nanos().is_multiple_of(1_000)
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(Self {
            occurred_at,
            model_call_id,
        })
    }

    /// Returns the latest visible lifecycle occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    /// Returns the model-call component of the keyset position.
    #[must_use]
    pub fn model_call_id(&self) -> &ModelCallId {
        &self.model_call_id
    }
}

/// One redacted model-call discovery row.
///
/// Every field is derived from the latest lifecycle event visible inside the
/// requested window. The row does not assert that this is the call's current
/// state or that its entire lifecycle is retained. It intentionally excludes
/// evidence references, provider bodies, probabilities, and confidence values.
#[derive(Clone, Debug, Serialize)]
pub struct ModelCallListSummary {
    /// Stable model attempt identity. Opening it requires a separately audited
    /// and re-authorized model-call detail request.
    pub model_call_id: String,
    /// Request that emitted the latest visible model lifecycle event.
    pub request_id: String,
    /// Authenticated occurrence time of the latest visible lifecycle event.
    #[serde(serialize_with = "serialize_event_time")]
    pub occurred_at: DateTime<Utc>,
    /// Stable provider route name, when historical lifecycle data recorded it.
    pub provider: Option<String>,
    /// Exact historical wire model identifier, not an inferred resolved revision.
    pub provider_model_id: Option<String>,
    /// Versioned internal model identifier.
    pub model_revision: String,
    /// Versioned prompt identifier.
    pub prompt_revision: String,
    /// Typed Jev question family.
    pub question_type: String,
    /// Latest lifecycle status visible inside the requested window.
    pub latest_status: String,
    /// Stable reason attached to that latest visible status.
    pub latest_reason_code: String,
    /// Availability semantics for the latest confidence value, without that value.
    pub latest_confidence_status: String,
}

/// One bounded page of redacted model-call discovery results.
#[derive(Clone, Debug, Serialize)]
pub struct ModelCallListResult {
    /// One latest-in-window row for each returned model call.
    pub model_calls: Vec<ModelCallListSummary>,
    /// True when a further descending keyset page exists.
    pub truncated: bool,
    /// Last returned row used to continue discovery. This is never serialized.
    #[serde(skip)]
    pub next_position: Option<ModelCallListPosition>,
    /// Actual index scan rows when `ClickHouse` reports them.
    pub scanned_rows: Option<u64>,
    /// Actual index scan bytes when `ClickHouse` reports them.
    pub scanned_bytes: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Row)]
struct ModelCallRow {
    event_id: String,
    event_type: String,
    request_id: String,
    #[serde(
        deserialize_with = "deserialize_event_time",
        serialize_with = "serialize_event_time"
    )]
    occurred_at: DateTime<Utc>,
    request_seq: u32,
    evidence_refs: Vec<String>,
    cause_event_ids: Vec<String>,
    sensitivity: String,
    payload_json: String,
}

/// One aggregate row used only while constructing a redacted discovery page.
/// Evidence references are fetched to authenticate payload-to-envelope binding,
/// then intentionally discarded before the public list projection is built.
#[derive(Debug, Deserialize, Serialize, Row)]
struct ModelCallListRow {
    model_call_id: String,
    request_id: String,
    event_type: String,
    #[serde(
        deserialize_with = "deserialize_event_time",
        serialize_with = "serialize_event_time"
    )]
    occurred_at: DateTime<Utc>,
    evidence_refs: Vec<String>,
    payload_json: String,
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
/// Reference filters inspect evidence refs and fixed fields of validated event
/// families. They locate direct historical references, not current access rights
/// or transitive case membership. Management targets include failed attempts.
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

/// Reads one model-call lifecycle from the retention-aware analytical view.
///
/// The lookup is exact to the authenticated tenant/site scope and returns only
/// typed lifecycle metadata and evidence references. Model payload JSON is
/// parsed and validated before any field is exposed; provider bodies remain in
/// the separately authorized evidence vault.
///
/// # Errors
/// Returns [`PublishError::InvalidEvent`] for an inconsistent lifecycle or
/// [`PublishError::QueryTimeout`] / [`PublishError::ClickHouse`] for index
/// dependency failures, or [`PublishError::QueryBudgetExceeded`] for exhausted
/// scan/response budgets. Callers own admission and terminal access audit.
pub async fn query_model_call(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    model_call_id: &ModelCallId,
) -> Result<Option<ModelCallSummary>, PublishError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        execute_model_call(config, client, tenant_id, site_id, model_call_id),
    )
    .await
    .map_err(|_| PublishError::QueryTimeout)?
}

/// Lists model calls by their latest lifecycle event visible in one UTC window.
///
/// The tenant and site are injected by the authenticated control-plane root.
/// The query groups only fixed model lifecycle event types, parses each selected
/// payload with the same strict decoder as the detail endpoint, and returns a
/// redacted summary. It neither reconstructs a full lifecycle nor grants
/// evidence access. Results are ordered by `(occurred_at DESC, model_call_id
/// DESC)` and a supplied position is valid only for this plan's window.
///
/// # Errors
/// Returns [`PublishError::InvalidConfig`] when the continuation position lies
/// outside the supplied window, [`PublishError::InvalidEvent`] for a malformed
/// selected aggregate row, [`PublishError::QueryBudgetExceeded`] when a query
/// or decoder budget is exhausted, [`PublishError::QueryTimeout`] for the
/// client deadline, and [`PublishError::ClickHouse`] for index failures.
/// Admission, cursor authentication, and terminal access audit are caller
/// responsibilities.
pub async fn query_model_calls(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    plan: &ModelCallListPlan,
    after: Option<&ModelCallListPosition>,
) -> Result<ModelCallListResult, PublishError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        execute_model_call_list(config, client, tenant_id, site_id, plan, after),
    )
    .await
    .map_err(|_| PublishError::QueryTimeout)?
}

#[allow(clippy::too_many_lines)]
async fn execute_model_call_list(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    plan: &ModelCallListPlan,
    after: Option<&ModelCallListPosition>,
) -> Result<ModelCallListResult, PublishError> {
    let start = i64::try_from(plan.window().start().value())
        .ok()
        .and_then(|value| value.checked_mul(1_000_000))
        .ok_or(PublishError::InvalidConfig)?;
    let end = i64::try_from(plan.window().end().value())
        .ok()
        .and_then(|value| value.checked_mul(1_000_000))
        .ok_or(PublishError::InvalidConfig)?;
    if after
        .is_some_and(|position| !(start..end).contains(&position.occurred_at().timestamp_micros()))
    {
        return Err(PublishError::InvalidConfig);
    }

    // `argMax` uses event_id only to break equal clock readings within one
    // model call. The outer keyset purposefully uses model_call_id instead:
    // one group yields at most one row, making page boundaries stable even
    // when different calls share the same microsecond timestamp.
    let mut sql = format!(
        "SELECT model_call_id,request_id,event_type,occurred_at,evidence_refs,payload_json \
         FROM ( \
           SELECT model_call_id, \
             argMax(request_id,tuple(occurred_at,event_id)) AS request_id, \
             argMax(event_type,tuple(occurred_at,event_id)) AS event_type, \
             argMax(occurred_at,tuple(occurred_at,event_id)) AS occurred_at, \
             argMax(evidence_refs,tuple(occurred_at,event_id)) AS evidence_refs, \
             argMax(payload_json,tuple(occurred_at,event_id)) AS payload_json \
           FROM ( \
             SELECT {MODEL_CALL_ID_PROJECTION},request_id,event_id,event_type,occurred_at, \
                    evidence_refs,payload_json \
             FROM ? \
             WHERE tenant_id = ? AND site_id = ? \
               AND occurred_at >= fromUnixTimestamp64Micro(?) \
               AND occurred_at < fromUnixTimestamp64Micro(?) \
               AND proof_kind = 'model' \
               AND event_type IN ('model.started','model.requested','model.responded', \
                                  'model.failed','model.timeout','model.cancelled') \
           ) \
           WHERE model_call_id IS NOT NULL \
           GROUP BY model_call_id \
         )",
    );
    if after.is_some() {
        sql.push_str(
            " WHERE tuple(occurred_at,model_call_id) < \
             tuple(fromUnixTimestamp64Micro(?),?)",
        );
    }
    sql.push_str(" ORDER BY occurred_at DESC,model_call_id DESC LIMIT ?");

    let mut query = client
        .query(&sql)
        .bind(Identifier(&config.active_view))
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(start)
        .bind(end);
    if let Some(position) = after {
        query = query
            .bind(position.occurred_at().timestamp_micros())
            .bind(position.model_call_id().as_str());
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
        // Returned payloads are re-validated and discarded. Four MiB bounds
        // that internal decoder work while permitting 101 retained envelopes
        // at the fixed page maximum.
        .with_setting("max_result_bytes", "4194304")
        .with_setting("result_overflow_mode", "throw")
        .with_setting("max_memory_usage", "268435456")
        .with_setting("max_threads", "2")
        .with_setting("prefer_column_name_to_alias", "1")
        .with_setting("wait_end_of_query", "1")
        .fetch::<ModelCallListRow>()
        .map_err(query_error)?;
    let mut model_calls = Vec::with_capacity(usize::from(plan.limit()) + 1);
    let mut seen_model_call_ids = BTreeSet::new();
    while let Some(row) = cursor.next().await.map_err(query_error)? {
        if model_calls.len() > usize::from(plan.limit()) {
            return Err(PublishError::InvalidEvent);
        }
        if cursor.decoded_bytes() > 4 * 1024 * 1024 || row.payload_json.len() > 8192 {
            return Err(PublishError::QueryBudgetExceeded);
        }
        let model_call_id =
            ModelCallId::parse(row.model_call_id).map_err(|_| PublishError::InvalidEvent)?;
        let request_id =
            RequestId::parse(row.request_id).map_err(|_| PublishError::InvalidEvent)?;
        validate_id_list(&row.evidence_refs, None)?;
        let payload =
            super::model_eval::ModelEvent::parse_query_event(&row.payload_json, &row.event_type)
                // Indexed payload corruption is an authenticated event-contract
                // violation, not a caller JSON failure. Keep it distinct from a
                // transport dependency failure before the control adapter maps it.
                .map_err(|_| PublishError::InvalidEvent)?;
        if payload.model_call_id != model_call_id.as_str()
            || [
                payload.input_artifact_id.as_deref(),
                payload.output_artifact_id.as_deref(),
                payload.call_artifact_id.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|artifact_id| {
                !row.evidence_refs
                    .iter()
                    .any(|reference| reference == artifact_id)
            })
        {
            return Err(PublishError::InvalidEvent);
        }
        let key = (row.occurred_at, model_call_id.as_str());
        let previous = model_calls
            .last()
            .map(|previous: &ModelCallListSummary| {
                (previous.occurred_at, previous.model_call_id.as_str())
            })
            .or_else(|| {
                after.map(|position| (position.occurred_at(), position.model_call_id().as_str()))
            });
        if !seen_model_call_ids.insert(model_call_id.as_str().to_owned())
            || !(start..end).contains(&row.occurred_at.timestamp_micros())
            || previous.is_some_and(|previous| key >= previous)
        {
            return Err(PublishError::InvalidEvent);
        }
        model_calls.push(ModelCallListSummary {
            model_call_id: model_call_id.as_str().to_owned(),
            request_id: request_id.as_str().to_owned(),
            occurred_at: row.occurred_at,
            provider: payload.provider,
            provider_model_id: payload.provider_model_id,
            model_revision: payload.model_revision,
            prompt_revision: payload.prompt_revision,
            question_type: payload.question_type,
            latest_status: payload.status,
            latest_reason_code: payload.reason_code,
            latest_confidence_status: payload.confidence_status,
        });
    }
    let scanned_rows = cursor
        .summary()
        .and_then(clickhouse::QuerySummary::read_rows);
    let scanned_bytes = cursor
        .summary()
        .and_then(clickhouse::QuerySummary::read_bytes);
    let truncated = model_calls.len() > usize::from(plan.limit());
    model_calls.truncate(usize::from(plan.limit()));
    let next_position = if truncated {
        let last = model_calls.last().ok_or(PublishError::InvalidEvent)?;
        Some(ModelCallListPosition::new(
            last.occurred_at,
            ModelCallId::parse(&last.model_call_id).map_err(|_| PublishError::InvalidEvent)?,
        )?)
    } else {
        None
    };
    Ok(ModelCallListResult {
        model_calls,
        truncated,
        next_position,
        scanned_rows,
        scanned_bytes,
    })
}

#[allow(clippy::too_many_lines)]
async fn execute_model_call(
    config: &PublisherConfig,
    client: &Client,
    tenant_id: &TenantId,
    site_id: &SiteId,
    model_call_id: &ModelCallId,
) -> Result<Option<ModelCallSummary>, PublishError> {
    // ponytail: bounded payload scan; materialize a model-call lookup column
    // when measured retention volumes exceed this adapter's scan budget.
    let mut cursor = client
        .query(
            "SELECT event_id,event_type,request_id,occurred_at,request_seq,
             evidence_refs,cause_event_ids,sensitivity,payload_json FROM ?
             WHERE tenant_id = ? AND site_id = ?
               AND event_type IN ('model.started','model.requested','model.responded',
                                  'model.failed','model.timeout','model.cancelled')
               AND JSONExtractString(payload_json,'model_call_id') = ?
             ORDER BY request_seq,event_id LIMIT 4",
        )
        .bind(Identifier(&config.active_view))
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(model_call_id.as_str())
        .with_setting("max_execution_time", "2")
        .with_setting("timeout_before_checking_execution_speed", "0")
        .with_setting("max_rows_to_read", "1000000")
        .with_setting("max_bytes_to_read", "67108864")
        .with_setting("read_overflow_mode", "throw")
        .with_setting("timeout_overflow_mode", "throw")
        .with_setting("max_result_bytes", "131072")
        .with_setting("result_overflow_mode", "throw")
        .with_setting("max_memory_usage", "268435456")
        .with_setting("max_threads", "2")
        .with_setting("wait_end_of_query", "1")
        .fetch::<ModelCallRow>()
        .map_err(query_error)?;
    let mut events = Vec::with_capacity(3);
    let mut seen_event_ids = BTreeSet::new();
    let mut seen_event_types = BTreeSet::new();
    let mut evidence_ids = BTreeSet::new();
    let mut terminal_seen = false;
    let mut continuous = true;
    while let Some(row) = cursor.next().await.map_err(query_error)? {
        if cursor.decoded_bytes() > 128 * 1024 || row.payload_json.len() > 8192 {
            return Err(PublishError::QueryBudgetExceeded);
        }
        if events.len() == 3
            || !seen_event_ids.insert(row.event_id.clone())
            || !seen_event_types.insert(row.event_type.clone())
            || !matches!(
                row.event_type.as_str(),
                "model.started"
                    | "model.requested"
                    | "model.responded"
                    | "model.failed"
                    | "model.timeout"
                    | "model.cancelled"
            )
            || !matches!(
                row.sensitivity.as_str(),
                "PUBLIC" | "INTERNAL" | "SENSITIVE" | "RESTRICTED"
            )
            || row.request_seq == 0
        {
            return Err(PublishError::InvalidEvent);
        }
        validate_id_list(&row.evidence_refs, None)?;
        validate_id_list(&row.cause_event_ids, Some("ev_"))?;
        evidence_ids.extend(row.evidence_refs.iter().cloned());
        // The caller records every returned reference in one access event.
        if evidence_ids.len() > super::LIST_ITEMS_MAX {
            return Err(PublishError::InvalidEvent);
        }
        let event_id =
            EventId::parse(row.event_id.clone()).map_err(|_| PublishError::InvalidEvent)?;
        let request_id =
            RequestId::parse(row.request_id.clone()).map_err(|_| PublishError::InvalidEvent)?;
        let payload =
            super::model_eval::ModelEvent::parse_query_event(&row.payload_json, &row.event_type)?;
        if payload.model_call_id != model_call_id.as_str()
            || row.cause_event_ids.len() != usize::from(payload.status != "started")
            || row.cause_event_ids.contains(&row.event_id)
            || payload
                .input_artifact_id
                .as_deref()
                .is_some_and(|id| !row.evidence_refs.iter().any(|reference| reference == id))
            || payload
                .output_artifact_id
                .as_deref()
                .is_some_and(|id| !row.evidence_refs.iter().any(|reference| reference == id))
            || payload
                .call_artifact_id
                .as_deref()
                .is_some_and(|id| !row.evidence_refs.iter().any(|reference| reference == id))
        {
            return Err(PublishError::InvalidEvent);
        }
        let terminal = matches!(
            row.event_type.as_str(),
            "model.responded" | "model.failed" | "model.timeout" | "model.cancelled"
        );
        // request_seq survives clock rollback. A retained suffix is valid, but
        // duplicate/reversed states and any event after a terminal are corrupt.
        if terminal_seen
            || events
                .last()
                .is_some_and(|previous: &ModelCallEventSummary| {
                    row.request_seq <= previous.request_seq
                        || row.event_type == "model.started"
                        || (previous.status == "requested"
                            && payload.input_artifact_id != previous.input_artifact_id)
                        // There is no intervening model state before a send or
                        // after it. Both visible endpoints must link directly.
                        || ((previous.status == "requested" || payload.status == "requested")
                            && row.cause_event_ids != [previous.event_id.clone()])
                        || (previous.status == "started"
                            && row.cause_event_ids == [previous.event_id.clone()]
                            && !matches!(payload.status.as_str(), "requested" | "error"))
                })
            || (payload.status == "started"
                && (payload.input_artifact_id.is_some()
                    || payload.output_artifact_id.is_some()
                    || payload.call_artifact_id.is_some()))
            || (payload.status == "requested"
                && (payload.output_artifact_id.is_some() || payload.call_artifact_id.is_some()))
        {
            return Err(PublishError::InvalidEvent);
        }
        if let Some(previous) = events.last() {
            continuous &= row.cause_event_ids == [previous.event_id.clone()];
        }
        terminal_seen |= terminal;
        events.push(ModelCallEventSummary {
            event_id: event_id.as_str().to_owned(),
            event_type: row.event_type,
            request_id: request_id.as_str().to_owned(),
            provider: payload.provider,
            provider_model_id: payload.provider_model_id,
            occurred_at: row.occurred_at,
            request_seq: row.request_seq,
            status: payload.status,
            model_revision: payload.model_revision,
            prompt_revision: payload.prompt_revision,
            question_type: payload.question_type,
            reason_code: payload.reason_code,
            confidence: payload.confidence,
            confidence_status: payload.confidence_status,
            duration_us: payload.duration_us,
            input_artifact_id: payload.input_artifact_id,
            output_artifact_id: payload.output_artifact_id,
            call_artifact_id: payload.call_artifact_id,
            evidence_refs: row.evidence_refs,
            cause_event_ids: row.cause_event_ids,
            sensitivity: row.sensitivity,
        });
    }
    if events.is_empty() {
        return Ok(None);
    }
    // A retained suffix may reference an absent predecessor, but a cause that
    // is visible at the same or a later sequence proves a contradiction.
    if events.iter().enumerate().any(|(index, event)| {
        event
            .cause_event_ids
            .iter()
            .any(|cause| events[index..].iter().any(|later| &later.event_id == cause))
    }) {
        return Err(PublishError::InvalidEvent);
    }
    let first = events.first().ok_or(PublishError::InvalidEvent)?;
    let request_id = first.request_id.clone();
    let model_call_id = model_call_id.as_str().to_owned();
    let model_revision = first.model_revision.clone();
    let provider = first.provider.clone();
    let provider_model_id = first.provider_model_id.clone();
    let prompt_revision = first.prompt_revision.clone();
    let question_type = first.question_type.clone();
    let lifecycle_complete = first.status == "started" && terminal_seen && continuous;
    for event in &events {
        if event.request_id != request_id
            || event.model_revision != model_revision
            || event.provider != provider
            || event.provider_model_id != provider_model_id
            || event.prompt_revision != prompt_revision
            || event.question_type != question_type
        {
            return Err(PublishError::InvalidEvent);
        }
    }
    let mut input_artifact_id = None;
    let mut output_artifact_id = None;
    let mut call_artifact_id = None;
    for event in &events {
        input_artifact_id = merge_model_ref(input_artifact_id, event.input_artifact_id.clone())?;
        output_artifact_id = merge_model_ref(output_artifact_id, event.output_artifact_id.clone())?;
        call_artifact_id = merge_model_ref(call_artifact_id, event.call_artifact_id.clone())?;
    }
    let latest_payload = events.last().ok_or(PublishError::InvalidEvent)?;
    Ok(Some(ModelCallSummary {
        model_call_id,
        request_id,
        provider,
        provider_model_id,
        model_revision,
        prompt_revision,
        question_type,
        status: latest_payload.status.clone(),
        reason_code: latest_payload.reason_code.clone(),
        confidence: latest_payload.confidence,
        confidence_status: latest_payload.confidence_status.clone(),
        duration_us: latest_payload.duration_us,
        input_artifact_id,
        output_artifact_id,
        call_artifact_id,
        events,
        lifecycle_complete,
    }))
}

fn merge_model_ref(
    current: Option<String>,
    next: Option<String>,
) -> Result<Option<String>, PublishError> {
    match (current, next) {
        (Some(current), Some(next)) if current != next => Err(PublishError::InvalidEvent),
        (Some(current), _) => Ok(Some(current)),
        (None, next) => Ok(next),
    }
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
    let mut sql = format!(
        "SELECT nullIf(request_id,'') AS request_id,event_id,event_type,\
         nullIf(stage,'') AS stage,nullIf(outcome,'') AS outcome,\
         nullIf(reason_code,'') AS reason_code,nullIf(proof_kind,'') AS proof_kind,confidence,\
         nullIf(confidence_status,'') AS confidence_status,occurred_at,request_seq,duration_us,\
         policy_revision,nullIf(model_revision,'') AS model_revision,\
         {MODEL_CALL_ID_PROJECTION},\
         evidence_refs,cause_event_ids,sensitivity FROM ? WHERE tenant_id = ? AND site_id = ? \
         AND occurred_at >= fromUnixTimestamp64Micro(?) AND occurred_at < fromUnixTimestamp64Micro(?)",
    );
    for filter in plan.filters() {
        sql.push_str(" AND ");
        match filter {
            QueryFilter::RequestId(_) => sql.push_str("request_id = ?"),
            QueryFilter::EventId(_) => sql.push_str("event_id = ?"),
            // ponytail: bounded payload scan; add indexed columns only when
            // measured retention volumes exceed the existing scan budget.
            QueryFilter::GrantId(_) => sql.push_str(
                "((event_type IN ('grant.issued','response_grant.issued') \
                  AND JSONExtractString(payload_json,'grant_id') = ?) \
                  OR (event_type = 'share.issued' \
                  AND JSONExtractString(payload_json,'issuer_grant_id') = ?))",
            ),
            QueryFilter::AuthBindingId(_) => sql.push_str(
                "((event_type IN ('session.created','binding.created','identity.refreshed',\
                  'epoch.changed','binding.revoked','grant.issued','response_grant.issued') \
                  AND JSONExtractString(payload_json,'binding_id') = ?) \
                  OR (event_type = 'share.issued' \
                  AND JSONExtractString(payload_json,'issuer_binding_id') = ?))",
            ),
            QueryFilter::CaseId(_) => sql.push_str(
                "((tuple(stage,event_type) IN (('case_management','case.created'),\
                  ('case_management','case.closed'),('case_management','case.evidence.added'),\
                  ('evidence_access','evidence.access.requested'),\
                  ('evidence_hold','evidence.hold.created'),('evidence_hold','evidence.hold.released')) \
                  AND JSONExtractString(payload_json,'case_id') = ?) \
                  OR (stage = 'control_access' AND event_type IN ('case.created','case.closed',\
                  'case.evidence.added','console.case.read','evidence.access.requested',\
                  'evidence.access.approved','evidence.access.denied','console.evidence.hold.created',\
                  'console.evidence.hold.released','console.evidence.hold.read',\
                  'console.evidence.access.read') \
                  AND JSONExtractString(payload_json,'target_case_id') = ?))",
            ),
            QueryFilter::ArtifactId(_) => sql.push_str(
                "(has(evidence_refs,?) OR (stage = 'control_access' \
                  AND event_type IN ('console.manifest.read','case.evidence.added',\
                  'evidence.access.requested','evidence.access.approved','evidence.access.denied',\
                  'evidence.read','console.evidence.hold.created','console.evidence.hold.released') \
                  AND JSONExtractString(payload_json,'target_artifact_id') = ?))",
            ),
            QueryFilter::CalibrationReportId(_) => sql.push_str(concat!(
                "((event_type = 'calibration.reported' OR event_type IN (",
                "'calibration.report_retention.purge_requested',",
                "'calibration.report_retention.deleted',",
                "'calibration.report_retention.purge_failed',",
                "'calibration.report_retention.orphan_purge_requested',",
                "'calibration.report_retention.orphan_deleted',",
                "'calibration.report_retention.orphan_purge_failed')) ",
                "AND JSONExtractString(payload_json,'report_id') = ?) ",
                "OR (stage = 'control_access' ",
                "AND event_type = 'console.calibration.report.read' ",
                "AND JSONExtractString(payload_json,'target_calibration_report_id') = ?))",
            )),
            QueryFilter::EvidenceAccessRequestId(_) => sql.push_str(concat!(
                "((event_type IN ('evidence.access.requested','evidence.access.approved',",
                "'evidence.access.denied') ",
                "AND JSONExtractString(payload_json,'access_request_id') = ?) ",
                "OR (stage = 'control_access' ",
                "AND event_type = 'console.evidence.access.read' ",
                "AND JSONExtractString(payload_json,'target_access_request_id') = ?))",
            )),
            QueryFilter::ModelCallId(_) => sql.push_str(concat!(
                "((event_type IN ('model.started','model.requested','model.responded',",
                "'model.failed','model.timeout','model.cancelled') ",
                "AND JSONExtractString(payload_json,'model_call_id') = ?) ",
                "OR (stage = 'control_access' ",
                "AND event_type = 'console.model.read' ",
                "AND JSONExtractString(payload_json,'target_model_call_id') = ?))",
            )),
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
            QueryFilter::GrantId(value) => query.bind(value.as_str()).bind(value.as_str()),
            QueryFilter::AuthBindingId(value) => query.bind(value.as_str()).bind(value.as_str()),
            QueryFilter::CaseId(value) => query.bind(value.as_str()).bind(value.as_str()),
            QueryFilter::ArtifactId(value) => query.bind(value.as_str()).bind(value.as_str()),
            QueryFilter::CalibrationReportId(value) => {
                query.bind(value.as_str()).bind(value.as_str())
            }
            QueryFilter::EvidenceAccessRequestId(value) => {
                query.bind(value.as_str()).bind(value.as_str())
            }
            QueryFilter::ModelCallId(value) => query.bind(value.as_str()).bind(value.as_str()),
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
    let confidence_valid = event.confidence_status.as_deref().map_or(
        event.confidence.is_none() && event.proof_kind.as_deref() != Some("deterministic"),
        |status| {
            valid_confidence(
                event.proof_kind.as_deref().unwrap_or_default(),
                event.outcome.as_deref().unwrap_or_default(),
                event.confidence,
                status,
            )
        },
    );
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
        || !confidence_valid
        || event.request_seq == 0
        || !valid_name(&event.policy_revision)
        || event
            .model_revision
            .as_deref()
            .is_some_and(|value| !valid_name(value) || event.proof_kind.as_deref() != Some("model"))
        || event
            .model_call_id
            .as_deref()
            .is_some_and(|value| ModelCallId::parse(value).is_err())
        || (event.proof_kind.as_deref() == Some("model")) != event.model_call_id.is_some()
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
    use super::{
        MODEL_CALL_ID_PROJECTION, MODEL_CALL_LIST_LIMIT_MAX, ModelCallListPlan,
        ModelCallListPosition, ModelCallListResult, ModelCallListRow, ModelCallRow,
        ModelCallSummary, PublishError, SearchEventSummary, query_error, query_model_call,
        query_model_calls, validate_search_event,
    };
    use crate::PublisherConfig;
    use chrono::{DateTime, Utc};
    use clickhouse::{Client, error::Error, test};
    use xshield_core::{
        domain::{ModelCallId, SiteId, TenantId},
        identity::UnixSeconds,
        query::QueryWindow,
    };

    const MODEL_CALL_ID: &str = "mdl_018f2a3b-4c5d-7000-8000-000000000001";
    const REQUEST_ID: &str = "req_018f2a3b-4c5d-7000-8000-000000000001";
    const INPUT_ID: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000001";
    const OUTPUT_ID: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000002";
    const CALL_ID: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000003";
    const MODEL_CALL_ID_TWO: &str = "mdl_018f2a3b-4c5d-7000-8000-000000000002";
    const MODEL_CALL_ID_THREE: &str = "mdl_018f2a3b-4c5d-7000-8000-000000000003";

    fn model_row(
        event_id: &str,
        event_type: &str,
        request_seq: u32,
        payload: &str,
        refs: Vec<String>,
    ) -> ModelCallRow {
        ModelCallRow {
            event_id: event_id.to_owned(),
            event_type: event_type.to_owned(),
            request_id: REQUEST_ID.to_owned(),
            occurred_at: DateTime::parse_from_rfc3339(&format!(
                "2026-09-19T00:00:0{request_seq}.000Z"
            ))
            .unwrap()
            .with_timezone(&Utc),
            request_seq,
            evidence_refs: refs,
            cause_event_ids: if event_type == "model.started" {
                vec![]
            } else {
                vec![format!(
                    "ev_018f2a3b-4c5d-7000-8000-{:012}",
                    request_seq - 1
                )]
            },
            sensitivity: "RESTRICTED".to_owned(),
            payload_json: payload.to_owned(),
        }
    }

    #[test]
    fn model_search_metadata_keeps_revision_and_confidence_semantics() {
        let mut event: SearchEventSummary = serde_json::from_str(
            r#"{
            "request_id":"req_018f2a3b-4c5d-7000-8000-000000000001",
            "event_id":"ev_018f2a3b-4c5d-7000-8000-000000000001",
            "event_type":"stage.completed","stage":"ui_semantic_match",
            "outcome":"PASS","reason_code":"CANDIDATE_CLASSIFICATION_COMPLETE",
            "proof_kind":"model","confidence":0.86,"confidence_status":"provided",
            "occurred_at":"2026-09-19T00:00:00Z","request_seq":1,"duration_us":120,
            "policy_revision":"policy-r1","model_revision":"jev-1.13.0",
            "model_call_id":"mdl_018f2a3b-4c5d-7000-8000-000000000001",
            "evidence_refs":[],"cause_event_ids":[],"sensitivity":"RESTRICTED"
        }"#,
        )
        .unwrap();
        assert!(validate_search_event(&event).is_ok());
        for proof in [Some("deterministic"), Some("none"), None] {
            let mut invalid = event.clone();
            invalid.proof_kind = proof.map(str::to_owned);
            invalid.confidence = None;
            invalid.confidence_status = Some("not_applicable".to_owned());
            assert!(validate_search_event(&invalid).is_err());
        }
        for status in ["not_applicable", "not_provided", "unavailable"] {
            event.confidence_status = Some(status.to_owned());
            event.confidence = Some(0.86);
            assert!(validate_search_event(&event).is_err());
            event.confidence = None;
            assert!(validate_search_event(&event).is_ok());
        }
        event.model_revision = None;
        assert!(validate_search_event(&event).is_ok());
        event.model_call_id = Some("model_018f2a3b-4c5d-7000-8000-000000000001".to_owned());
        assert!(validate_search_event(&event).is_err());
        event.model_call_id = Some(MODEL_CALL_ID.to_owned());
        assert!(validate_search_event(&event).is_ok());
        event.model_call_id = None;
        assert!(validate_search_event(&event).is_err());
        event.proof_kind = Some("deterministic".to_owned());
        event.confidence_status = None;
        assert!(validate_search_event(&event).is_err());
    }

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

    fn model_rows() -> Vec<ModelCallRow> {
        let started = serde_json::json!({
            "model_call_id": MODEL_CALL_ID,
            "model_revision": "jev-1.13.0",
            "prompt_revision": "evaluation-r1",
            "question_type": "choice",
            "status": "started",
            "reason_code": "MODEL_EVALUATION_STARTED",
            "confidence": null,
            "confidence_status": "unavailable",
            "duration_us": 0,
            "input_artifact_id": null,
            "output_artifact_id": null,
            "call_artifact_id": null
        })
        .to_string();
        let responded = serde_json::json!({
            "model_call_id": MODEL_CALL_ID,
            "model_revision": "jev-1.13.0",
            "prompt_revision": "evaluation-r1",
            "question_type": "choice",
            "status": "success",
            "reason_code": "MODEL_EVALUATED",
            "confidence": 0.8,
            "confidence_status": "provided",
            "duration_us": 1200,
            "input_artifact_id": INPUT_ID,
            "output_artifact_id": OUTPUT_ID,
            "call_artifact_id": CALL_ID
        })
        .to_string();
        let mut requested: serde_json::Value = serde_json::from_str(&started).unwrap();
        requested["status"] = "requested".into();
        requested["reason_code"] = "MODEL_REQUEST_SENT".into();
        requested["input_artifact_id"] = INPUT_ID.into();
        vec![
            model_row(
                "ev_018f2a3b-4c5d-7000-8000-000000000001",
                "model.started",
                1,
                &started,
                vec![],
            ),
            model_row(
                "ev_018f2a3b-4c5d-7000-8000-000000000002",
                "model.requested",
                2,
                &requested.to_string(),
                vec![INPUT_ID.to_owned()],
            ),
            model_row(
                "ev_018f2a3b-4c5d-7000-8000-000000000003",
                "model.responded",
                3,
                &responded,
                vec![
                    INPUT_ID.to_owned(),
                    OUTPUT_ID.to_owned(),
                    CALL_ID.to_owned(),
                ],
            ),
        ]
    }

    async fn query_model_rows(
        rows: Vec<ModelCallRow>,
    ) -> Result<Option<ModelCallSummary>, PublishError> {
        let mock = test::Mock::new();
        mock.add(test::handlers::provide(rows));
        let config = PublisherConfig::new(
            "/tmp/xshield-model-query-journal",
            "/tmp/xshield-model-query-manifest",
            "/tmp/xshield-model-query-checkpoint",
            "target",
            "audit_events",
            30,
            1024,
        )
        .unwrap();
        query_model_call(
            &config,
            &Client::default().with_mock(&mock),
            &TenantId::parse("tenant_demo").unwrap(),
            &SiteId::parse("site_demo").unwrap(),
            &ModelCallId::parse(MODEL_CALL_ID).unwrap(),
        )
        .await
    }

    fn model_list_plan(limit: u16) -> ModelCallListPlan {
        ModelCallListPlan::new(
            QueryWindow::new(
                UnixSeconds::new(1_789_776_000),
                UnixSeconds::new(1_789_776_100),
            )
            .unwrap(),
            limit,
        )
        .unwrap()
    }

    fn model_list_row(model_call_id: &str, second: u8) -> ModelCallListRow {
        let mut row = model_rows().remove(2);
        let mut payload: serde_json::Value = serde_json::from_str(&row.payload_json).unwrap();
        payload["model_call_id"] = model_call_id.into();
        payload["provider"] = "vercel_ai_gateway".into();
        payload["provider_model_id"] = "typesafe-ai/jev".into();
        row.payload_json = payload.to_string();
        ModelCallListRow {
            model_call_id: model_call_id.to_owned(),
            request_id: row.request_id,
            event_type: row.event_type,
            occurred_at: DateTime::parse_from_rfc3339(&format!(
                "2026-09-19T00:00:{second:02}.000Z"
            ))
            .unwrap()
            .with_timezone(&Utc),
            evidence_refs: row.evidence_refs,
            payload_json: row.payload_json,
        }
    }

    async fn query_model_list_rows(
        rows: Vec<ModelCallListRow>,
        limit: u16,
        after: Option<&ModelCallListPosition>,
    ) -> Result<ModelCallListResult, PublishError> {
        let mut mock = test::Mock::new();
        if !rows.is_empty() {
            mock.add(test::handlers::provide(rows));
        }
        // Several negative-path cases deliberately reject before consuming the
        // mock response. Their assertion is the typed local rejection, not a
        // transport exchange.
        mock.non_exhaustive();
        let config = PublisherConfig::new(
            "/tmp/xshield-model-list-query-journal",
            "/tmp/xshield-model-list-query-manifest",
            "/tmp/xshield-model-list-query-checkpoint",
            "target",
            "audit_events",
            30,
            1024,
        )
        .unwrap();
        query_model_calls(
            &config,
            &Client::default().with_mock(&mock),
            &TenantId::parse("tenant_demo").unwrap(),
            &SiteId::parse("site_demo").unwrap(),
            &model_list_plan(limit),
            after,
        )
        .await
    }

    #[test]
    fn model_call_list_plan_enforces_its_decoder_page_budget() {
        let window = QueryWindow::new(
            UnixSeconds::new(1_789_776_000),
            UnixSeconds::new(1_789_776_100),
        )
        .unwrap();
        assert!(ModelCallListPlan::new(window, 1).is_ok());
        assert!(ModelCallListPlan::new(window, MODEL_CALL_LIST_LIMIT_MAX).is_ok());
        for invalid in [0, MODEL_CALL_LIST_LIMIT_MAX + 1] {
            assert!(ModelCallListPlan::new(window, invalid).is_err());
        }
    }

    #[tokio::test]
    async fn model_call_list_returns_one_latest_redacted_window_row_per_call() {
        let rows = vec![
            model_list_row(MODEL_CALL_ID_TWO, 3),
            model_list_row(MODEL_CALL_ID, 3),
            model_list_row(MODEL_CALL_ID_THREE, 2),
        ];
        let page = query_model_list_rows(rows, 2, None).await.unwrap();
        assert!(page.truncated);
        assert_eq!(page.model_calls.len(), 2);
        assert_eq!(page.model_calls[0].model_call_id, MODEL_CALL_ID_TWO);
        assert_eq!(page.model_calls[1].model_call_id, MODEL_CALL_ID);
        assert_eq!(page.model_calls[0].request_id, REQUEST_ID);
        assert_eq!(
            page.model_calls[0].provider_model_id.as_deref(),
            Some("typesafe-ai/jev")
        );
        assert_eq!(page.model_calls[0].latest_status, "success");
        assert_eq!(page.model_calls[0].latest_confidence_status, "provided");
        let position = page.next_position.as_ref().unwrap();
        assert_eq!(position.model_call_id().as_str(), MODEL_CALL_ID);
        assert_eq!(position.occurred_at(), page.model_calls[1].occurred_at);

        let encoded = serde_json::to_value(&page).unwrap();
        let item = &encoded["model_calls"][0];
        assert!(item.get("evidence_refs").is_none());
        assert!(item.get("confidence").is_none());
        assert!(item.get("input_artifact_id").is_none());
        assert_eq!(item["latest_confidence_status"], "provided");

        let after = ModelCallListPosition::new(
            page.model_calls[1].occurred_at,
            ModelCallId::parse(MODEL_CALL_ID).unwrap(),
        )
        .unwrap();
        let next = query_model_list_rows(
            vec![model_list_row(MODEL_CALL_ID_THREE, 2)],
            2,
            Some(&after),
        )
        .await
        .unwrap();
        assert!(!next.truncated);
        assert_eq!(next.model_calls[0].model_call_id, MODEL_CALL_ID_THREE);
    }

    #[tokio::test]
    async fn model_call_list_rejects_bad_window_position_order_and_envelope_binding() {
        let outside = ModelCallListPosition::new(
            DateTime::parse_from_rfc3339("2026-09-20T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            ModelCallId::parse(MODEL_CALL_ID).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            query_model_list_rows(Vec::new(), 2, Some(&outside)).await,
            Err(PublishError::InvalidConfig)
        ));

        let mut out_of_window = model_list_row(MODEL_CALL_ID, 3);
        out_of_window.occurred_at = DateTime::parse_from_rfc3339("2026-09-20T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(matches!(
            query_model_list_rows(vec![out_of_window], 2, None).await,
            Err(PublishError::InvalidEvent)
        ));

        let mut missing_artifact_binding = model_list_row(MODEL_CALL_ID, 3);
        missing_artifact_binding.evidence_refs.remove(2);
        assert!(matches!(
            query_model_list_rows(vec![missing_artifact_binding], 2, None).await,
            Err(PublishError::InvalidEvent)
        ));

        let mut payload_drift = model_list_row(MODEL_CALL_ID, 3);
        let mut payload: serde_json::Value =
            serde_json::from_str(&payload_drift.payload_json).unwrap();
        payload["model_call_id"] = MODEL_CALL_ID_TWO.into();
        payload_drift.payload_json = payload.to_string();
        assert!(matches!(
            query_model_list_rows(vec![payload_drift], 2, None).await,
            Err(PublishError::InvalidEvent)
        ));

        let mut malformed_payload = model_list_row(MODEL_CALL_ID, 3);
        let mut payload: serde_json::Value =
            serde_json::from_str(&malformed_payload.payload_json).unwrap();
        payload["unexpected"] = true.into();
        malformed_payload.payload_json = payload.to_string();
        let result = query_model_list_rows(vec![malformed_payload], 2, None).await;
        assert!(
            matches!(result, Err(PublishError::InvalidEvent)),
            "{result:?}"
        );

        let duplicate = vec![
            model_list_row(MODEL_CALL_ID, 3),
            model_list_row(MODEL_CALL_ID, 2),
        ];
        assert!(matches!(
            query_model_list_rows(duplicate, 2, None).await,
            Err(PublishError::InvalidEvent)
        ));

        let mut oversized_payload = model_list_row(MODEL_CALL_ID, 3);
        oversized_payload.payload_json.push_str(&" ".repeat(8192));
        assert!(matches!(
            query_model_list_rows(vec![oversized_payload], 2, None).await,
            Err(PublishError::QueryBudgetExceeded)
        ));
    }

    #[tokio::test]
    async fn model_call_list_compiles_scoped_latest_keyset_query() {
        let fixture = PublisherConfig::new(
            "/tmp/xshield-model-list-query-journal",
            "/tmp/xshield-model-list-query-manifest",
            "/tmp/xshield-model-list-query-checkpoint",
            "target",
            "audit_events",
            30,
            1024,
        )
        .unwrap();
        let mock = test::Mock::new();
        let recorded = mock.add(test::handlers::record_ddl());
        let position = ModelCallListPosition::new(
            DateTime::parse_from_rfc3339("2026-09-19T00:00:03.000Z")
                .unwrap()
                .with_timezone(&Utc),
            ModelCallId::parse(MODEL_CALL_ID).unwrap(),
        )
        .unwrap();
        let result = query_model_calls(
            &fixture,
            &Client::default().with_mock(&mock),
            &TenantId::parse("tenant_demo").unwrap(),
            &SiteId::parse("site_demo").unwrap(),
            &model_list_plan(2),
            Some(&position),
        )
        .await
        .unwrap();
        assert!(result.model_calls.is_empty());
        let sql = recorded.query().await;
        assert!(
            sql.contains("WHERE tenant_id = 'tenant_demo' AND site_id = 'site_demo'"),
            "{sql}"
        );
        assert!(sql.contains(MODEL_CALL_ID_PROJECTION), "{sql}");
        assert!(sql.contains("AND proof_kind = 'model'"), "{sql}");
        assert!(sql.contains("WHERE model_call_id IS NOT NULL"), "{sql}");
        assert!(sql.contains("GROUP BY model_call_id"), "{sql}");
        assert!(
            sql.contains("argMax(payload_json,tuple(occurred_at,event_id))"),
            "{sql}"
        );
        assert!(sql.contains("tuple(occurred_at,model_call_id) <"), "{sql}");
        assert!(
            sql.contains("ORDER BY occurred_at DESC,model_call_id DESC"),
            "{sql}"
        );
    }

    #[tokio::test]
    async fn model_call_query_returns_typed_lifecycle_and_refs() {
        let mut rows = model_rows();
        for row in &mut rows {
            let mut payload: serde_json::Value = serde_json::from_str(&row.payload_json).unwrap();
            payload["provider"] = "vercel_ai_gateway".into();
            payload["provider_model_id"] = "typesafe-ai/jev".into();
            row.payload_json = payload.to_string();
        }
        let summary = query_model_rows(rows).await.unwrap().unwrap();
        assert_eq!(summary.status, "success");
        assert_eq!(summary.events.len(), 3);
        assert!(summary.lifecycle_complete);
        assert_eq!(summary.provider.as_deref(), Some("vercel_ai_gateway"));
        assert_eq!(
            summary.provider_model_id.as_deref(),
            Some("typesafe-ai/jev")
        );
        assert_eq!(summary.input_artifact_id.as_deref(), Some(INPUT_ID));
        assert_eq!(summary.output_artifact_id.as_deref(), Some(OUTPUT_ID));
        assert_eq!(summary.call_artifact_id.as_deref(), Some(CALL_ID));
    }

    #[tokio::test]
    async fn score_call_query_keeps_provider_confidence_and_missing_confidence() {
        for confidence in [Some(0.6), None] {
            let mut rows = model_rows();
            for row in &mut rows {
                let mut payload: serde_json::Value =
                    serde_json::from_str(&row.payload_json).unwrap();
                payload["question_type"] = "score".into();
                if row.event_type == "model.responded" {
                    payload["confidence"] = serde_json::json!(confidence);
                    payload["confidence_status"] = if confidence.is_some() {
                        "provided"
                    } else {
                        "not_provided"
                    }
                    .into();
                }
                row.payload_json = payload.to_string();
            }
            let summary = query_model_rows(rows).await.unwrap().unwrap();
            assert!(summary.lifecycle_complete);
            assert_eq!(summary.question_type, "score");
            assert_eq!(summary.confidence, confidence);
            assert_eq!(
                summary.confidence_status,
                if confidence.is_some() {
                    "provided"
                } else {
                    "not_provided"
                }
            );
        }
    }

    #[tokio::test]
    async fn model_call_query_rejects_provider_route_drift() {
        let mut rows = model_rows();
        for row in &mut rows {
            let mut payload: serde_json::Value = serde_json::from_str(&row.payload_json).unwrap();
            payload["provider"] = "vercel_ai_gateway".into();
            payload["provider_model_id"] = "typesafe-ai/jev".into();
            row.payload_json = payload.to_string();
        }
        let mut drifted: serde_json::Value = serde_json::from_str(&rows[2].payload_json).unwrap();
        drifted["provider"] = "typesafe".into();
        drifted["provider_model_id"] = "jev-1.13.0".into();
        rows[2].payload_json = drifted.to_string();
        assert!(matches!(
            query_model_rows(rows).await,
            Err(PublishError::InvalidEvent)
        ));
    }

    #[tokio::test]
    async fn model_call_query_distinguishes_partial_pending_and_presend_failure() {
        assert!(query_model_rows(vec![]).await.unwrap().is_none());
        for omitted in [0, 1, 2] {
            let mut rows = model_rows();
            rows.remove(omitted);
            assert!(
                !query_model_rows(rows)
                    .await
                    .unwrap()
                    .unwrap()
                    .lifecycle_complete
            );
        }
        let mut rows = model_rows();
        rows.truncate(2);
        rows[1].event_type = "model.failed".to_owned();
        let mut payload: serde_json::Value = serde_json::from_str(&rows[1].payload_json).unwrap();
        payload["status"] = "error".into();
        payload["reason_code"] = "MODEL_EVIDENCE_UNAVAILABLE".into();
        rows[1].payload_json = payload.to_string();
        assert!(
            query_model_rows(rows)
                .await
                .unwrap()
                .unwrap()
                .lifecycle_complete
        );

        let mut noul = model_rows();
        for row in &mut noul {
            let mut payload: serde_json::Value = serde_json::from_str(&row.payload_json).unwrap();
            payload["question_type"] = "noul".into();
            payload["confidence"] = serde_json::Value::Null;
            payload["confidence_status"] = "not_applicable".into();
            row.payload_json = payload.to_string();
        }
        let summary = query_model_rows(noul).await.unwrap().unwrap();
        assert!(summary.lifecycle_complete);
        assert_eq!(summary.confidence, None);
        assert_eq!(summary.confidence_status, "not_applicable");
    }

    #[tokio::test]
    async fn model_call_query_rejects_corrupt_lifecycle_and_bounds_payloads() {
        for field in [
            "confidence",
            "input_artifact_id",
            "output_artifact_id",
            "call_artifact_id",
        ] {
            let mut rows = model_rows();
            let mut payload: serde_json::Value =
                serde_json::from_str(&rows[0].payload_json).unwrap();
            payload.as_object_mut().unwrap().remove(field);
            rows[0].payload_json = payload.to_string();
            assert!(query_model_rows(rows).await.is_err(), "missing {field}");
        }
        for mutation in 0..13 {
            let mut rows = model_rows();
            let mut payload: serde_json::Value =
                serde_json::from_str(&rows[2].payload_json).unwrap();
            match mutation {
                0 => payload["model_call_id"] = "mdl_018f2a3b-4c5d-7000-8000-000000000002".into(),
                1 => rows[2].request_id = "req_018f2a3b-4c5d-7000-8000-000000000002".into(),
                2 => payload["prompt_revision"] = "other-prompt".into(),
                3 => rows[2].evidence_refs.clear(),
                4 => rows[2].event_id = "ev_018f2a3b-4c5d-7000-8000-000000000001".into(),
                5 => rows[2].request_seq = 2,
                6 => rows[2].cause_event_ids = vec![rows[2].event_id.clone()],
                7 => rows[2].sensitivity = "invalid".into(),
                8 => payload["unexpected"] = true.into(),
                9 => {
                    rows[2].event_type = "model.failed".into();
                    payload["status"] = "error".into();
                    payload["confidence"] = serde_json::Value::Null;
                    payload["confidence_status"] = "unavailable".into();
                    payload["input_artifact_id"] = serde_json::Value::Null;
                }
                10 => payload["question_type"] = "noul".into(),
                11 => payload["provider"] = "typesafe".into(),
                _ => payload["provider_model_id"] = "untrusted/model".into(),
            }
            rows[2].payload_json = payload.to_string();
            assert!(query_model_rows(rows).await.is_err(), "mutation {mutation}");
        }
        for (event_type, status) in [
            ("model.timeout", "timeout"),
            ("model.cancelled", "cancelled"),
        ] {
            let mut rows = model_rows();
            rows.truncate(2);
            rows[1].event_type = event_type.into();
            let mut payload: serde_json::Value =
                serde_json::from_str(&rows[1].payload_json).unwrap();
            payload["status"] = status.into();
            payload["input_artifact_id"] = serde_json::Value::Null;
            rows[1].payload_json = payload.to_string();
            assert!(matches!(
                query_model_rows(rows).await,
                Err(PublishError::InvalidEvent)
            ));
        }
        let mut rows = model_rows();
        rows.push(model_rows().remove(2));
        assert!(matches!(
            query_model_rows(rows).await,
            Err(PublishError::InvalidEvent)
        ));
        let mut rows = model_rows();
        for (index, row) in rows.iter_mut().enumerate() {
            row.evidence_refs.extend((0..128).map(|offset| {
                format!(
                    "artifact_018f2a3b-4c5d-7000-8000-{:012}",
                    100 + index * 128 + offset
                )
            }));
        }
        assert!(matches!(
            query_model_rows(rows).await,
            Err(PublishError::InvalidEvent)
        ));
        let mut rows = model_rows();
        rows[0].payload_json.push_str(&" ".repeat(8192));
        assert!(matches!(
            query_model_rows(rows).await,
            Err(PublishError::QueryBudgetExceeded)
        ));
    }

    #[tokio::test]
    async fn model_call_query_rejects_conflicting_causes_in_complete_and_partial_history() {
        for (index, cause) in [(1, 2), (2, 0)] {
            let mut rows = model_rows();
            rows[index].cause_event_ids = vec![rows[cause].event_id.clone()];
            assert!(matches!(
                query_model_rows(rows).await,
                Err(PublishError::InvalidEvent)
            ));
        }
        for index in [1, 2] {
            let mut rows = model_rows();
            rows[index].cause_event_ids = vec!["ev_018f2a3b-4c5d-7000-8000-000000000004".into()];
            assert!(matches!(
                query_model_rows(rows).await,
                Err(PublishError::InvalidEvent)
            ));
        }
        let mut suffix = model_rows();
        suffix.remove(0);
        suffix[0].cause_event_ids = vec![suffix[1].event_id.clone()];
        assert!(matches!(
            query_model_rows(suffix).await,
            Err(PublishError::InvalidEvent)
        ));
    }
}
