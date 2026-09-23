//! Bounded server-side event causality traversal.
//!
//! The endpoint deliberately walks only recorded `cause_event_ids` inside the
//! caller's fixed scope and time window. It returns the same redacted event
//! projection as structured search; it never infers edges from timestamps or
//! grants content access.

use super::{
    AccessAction, ControlPlane, EndpointResult, ErrorResponse, audit_unavailable, internal_error,
    single_header,
};
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole,
    domain::EventId,
    identity::UnixSeconds,
    query::{QueryFilter, QueryPlan, QuerySort, QueryWindow},
};
use xshield_worker::{
    IndexWatermark, PublishError, SearchEventSummary, inspect_publication_health,
    query_audit_events,
};

pub(super) const PATH: &str = "/control/v1/causality";
pub(super) const BODY_BYTES_MAX: usize = 4 * 1024;
const MAX_DEPTH: u8 = 4;
const MAX_NODES: u8 = 16;
const QUERY_LIMIT: u16 = 17;

const ACCESS: AccessAction = AccessAction {
    event_type: "console.causality.read",
    method: "POST",
    path: PATH,
    role: ManagementRole::Investigator,
};

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Direction {
    Both,
    Predecessors,
    Successors,
}

impl Direction {
    fn includes_predecessors(self) -> bool {
        matches!(self, Self::Both | Self::Predecessors)
    }

    fn includes_successors(self) -> bool {
        matches!(self, Self::Both | Self::Successors)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Predecessors => "predecessors",
            Self::Successors => "successors",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CausalityRequest {
    schema_version: u8,
    start: DateTime<FixedOffset>,
    end: DateTime<FixedOffset>,
    event_id: String,
    direction: Direction,
    max_depth: u8,
    max_nodes: u8,
}

impl CausalityRequest {
    fn into_plan(self) -> Result<CausalityPlan, ()> {
        if self.schema_version != 3
            || !(1..=MAX_DEPTH).contains(&self.max_depth)
            || !(1..=MAX_NODES).contains(&self.max_nodes)
            || self.start.offset().local_minus_utc() != 0
            || self.end.offset().local_minus_utc() != 0
            || self.start.timestamp_subsec_nanos() != 0
            || self.end.timestamp_subsec_nanos() != 0
        {
            return Err(());
        }
        let root = EventId::parse(self.event_id).map_err(|_| ())?;
        let start = u64::try_from(self.start.timestamp()).map_err(|_| ())?;
        let end = u64::try_from(self.end.timestamp()).map_err(|_| ())?;
        let window =
            QueryWindow::new(UnixSeconds::new(start), UnixSeconds::new(end)).map_err(|_| ())?;
        Ok(CausalityPlan {
            window,
            root,
            direction: self.direction,
            max_depth: self.max_depth,
            max_nodes: self.max_nodes,
        })
    }
}

#[derive(Clone)]
struct CausalityPlan {
    window: QueryWindow,
    root: EventId,
    direction: Direction,
    max_depth: u8,
    max_nodes: u8,
}

#[derive(Serialize)]
pub(super) struct CausalityResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    root_event_id: String,
    found: bool,
    direction: &'static str,
    max_depth: u8,
    max_nodes: u8,
    truncated: bool,
    as_of: String,
    index_watermark: Option<IndexWatermark>,
    has_gaps: bool,
    pending_segments: usize,
    scanned_rows: Option<u64>,
    scanned_bytes: Option<u64>,
    nodes: Vec<CausalityNode>,
}

#[derive(Serialize)]
struct CausalityNode {
    event: SearchEventSummary,
    depth: u8,
    direction: &'static str,
}

#[derive(Clone, Copy)]
enum NodeDirection {
    Predecessor,
    Successor,
}

impl NodeDirection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Predecessor => "predecessor",
            Self::Successor => "successor",
        }
    }
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    payload: Result<Json<CausalityRequest>, JsonRejection>,
) -> Response {
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    control
        .causality(authorization, payload.ok().map(|Json(value)| value))
        .await
        .into_response()
}

impl ControlPlane {
    async fn causality(
        self: Arc<Self>,
        authorization: Option<String>,
        payload: Option<CausalityRequest>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request_id, ACCESS)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Some(plan) = payload.and_then(|payload| payload.into_plan().ok()) else {
            return self
                .finish_causality(
                    request_id,
                    subject,
                    None,
                    Err(CausalityFailure::InvalidRequest),
                )
                .await;
        };
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_causality(
                    request_id,
                    subject,
                    Some(&plan),
                    Err(CausalityFailure::Capacity),
                )
                .await;
        };
        let task_request_id = request_id.clone();
        match tokio::spawn(async move {
            let _permit = permit;
            let result = tokio::time::timeout(
                Duration::from_secs(15),
                self.run_causality(&task_request_id, &plan),
            )
            .await
            .map_err(|_| CausalityFailure::Timeout)
            .and_then(|result| result);
            self.finish_causality(task_request_id, subject, Some(&plan), result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn run_causality(
        &self,
        request_id: &str,
        plan: &CausalityPlan,
    ) -> Result<CausalityResponse, CausalityFailure> {
        let mut nodes = BTreeMap::<String, (SearchEventSummary, u8, NodeDirection)>::new();
        let root_result = self
            .query_one(plan, QueryFilter::EventId(plan.root.clone()))
            .await?;
        let mut truncated = root_result.truncated;
        let mut scanned_rows = None;
        let mut scanned_bytes = None;
        merge_scan_stats(&mut scanned_rows, &mut scanned_bytes, &root_result)?;
        let Some(root_event) = root_result.events.into_iter().next() else {
            return self.empty_causality_response(request_id, plan, scanned_rows, scanned_bytes);
        };
        let root_event_id = plan.root.as_str().to_owned();
        let mut loaded = BTreeMap::from([(root_event_id.clone(), root_event)]);
        let mut frontier = VecDeque::new();
        if plan.direction.includes_predecessors() {
            frontier.push_back((plan.root.clone(), 0_u8, NodeDirection::Predecessor));
        }
        if plan.direction.includes_successors() {
            frontier.push_back((plan.root.clone(), 0_u8, NodeDirection::Successor));
        }
        let mut seen_predecessors = BTreeSet::from([root_event_id.clone()]);
        let mut seen_successors = BTreeSet::from([root_event_id]);

        while let Some((event_id, depth, direction)) = frontier.pop_front() {
            if depth >= plan.max_depth {
                // A node at the depth ceiling may still have more recorded
                // edges; report the bounded view as truncated without
                // spending another query merely to prove that fact.
                truncated = true;
                continue;
            }
            if matches!(direction, NodeDirection::Predecessor) {
                let event = if let Some(event) = loaded.get(event_id.as_str()) {
                    event.clone()
                } else {
                    let result = self
                        .query_one(plan, QueryFilter::EventId(event_id.clone()))
                        .await?;
                    truncated |= result.truncated;
                    merge_scan_stats(&mut scanned_rows, &mut scanned_bytes, &result)?;
                    let Some(event) = result.events.into_iter().next() else {
                        continue;
                    };
                    loaded.insert(event_id.as_str().to_owned(), event.clone());
                    event
                };
                for cause_id in event.cause_event_ids {
                    if seen_predecessors.contains(&cause_id) {
                        continue;
                    }
                    if nodes.len() >= usize::from(plan.max_nodes) {
                        truncated = true;
                        break;
                    }
                    let cause = EventId::parse(cause_id.clone())
                        .map_err(|_| CausalityFailure::IndexUnavailable)?;
                    let cause_result = self
                        .query_one(plan, QueryFilter::EventId(cause.clone()))
                        .await?;
                    truncated |= cause_result.truncated;
                    merge_scan_stats(&mut scanned_rows, &mut scanned_bytes, &cause_result)?;
                    let Some(cause_event) = cause_result.events.into_iter().next() else {
                        continue;
                    };
                    seen_predecessors.insert(cause_id.clone());
                    loaded.insert(cause_id.clone(), cause_event.clone());
                    nodes
                        .entry(cause_id)
                        .or_insert_with(|| (cause_event, depth + 1, NodeDirection::Predecessor));
                    frontier.push_back((cause, depth + 1, NodeDirection::Predecessor));
                }
            } else {
                let result = self
                    .query_one(plan, QueryFilter::CausedByEventId(event_id))
                    .await?;
                merge_scan_stats(&mut scanned_rows, &mut scanned_bytes, &result)?;
                truncated |= result.truncated;
                for child in result.events {
                    if seen_successors.contains(&child.event_id) {
                        continue;
                    }
                    if nodes.len() >= usize::from(plan.max_nodes) {
                        truncated = true;
                        break;
                    }
                    let child_id = child.event_id.clone();
                    let child_event_id = EventId::parse(child_id.clone())
                        .map_err(|_| CausalityFailure::IndexUnavailable)?;
                    seen_successors.insert(child_id.clone());
                    loaded.insert(child_id.clone(), child.clone());
                    nodes
                        .entry(child_id)
                        .or_insert_with(|| (child, depth + 1, NodeDirection::Successor));
                    frontier.push_back((child_event_id, depth + 1, NodeDirection::Successor));
                }
            }
        }

        self.project_causality_response(
            request_id,
            plan,
            true,
            truncated,
            scanned_rows,
            scanned_bytes,
            nodes,
        )
    }

    fn empty_causality_response(
        &self,
        request_id: &str,
        plan: &CausalityPlan,
        scanned_rows: Option<u64>,
        scanned_bytes: Option<u64>,
    ) -> Result<CausalityResponse, CausalityFailure> {
        self.project_causality_response(
            request_id,
            plan,
            false,
            false,
            scanned_rows,
            scanned_bytes,
            BTreeMap::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn project_causality_response(
        &self,
        request_id: &str,
        plan: &CausalityPlan,
        found: bool,
        truncated: bool,
        scanned_rows: Option<u64>,
        scanned_bytes: Option<u64>,
        nodes: BTreeMap<String, (SearchEventSummary, u8, NodeDirection)>,
    ) -> Result<CausalityResponse, CausalityFailure> {
        let health = inspect_publication_health(
            &self.config.publisher,
            &self.config.source_journal_key_id,
            &self.source_journal_key,
            &self.seal_key,
        )
        .map_err(|_| CausalityFailure::HealthUnavailable)?;
        let mut projected = nodes
            .into_iter()
            .map(|(_, (event, depth, direction))| CausalityNode {
                event,
                depth,
                direction: direction.as_str(),
            })
            .collect::<Vec<_>>();
        projected.sort_by(|left, right| {
            (
                left.depth,
                left.direction,
                left.event.occurred_at,
                &left.event.event_id,
            )
                .cmp(&(
                    right.depth,
                    right.direction,
                    right.event.occurred_at,
                    &right.event.event_id,
                ))
        });
        Ok(CausalityResponse {
            schema_version: 3,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            root_event_id: plan.root.as_str().to_owned(),
            found,
            direction: plan.direction.as_str(),
            max_depth: plan.max_depth,
            max_nodes: plan.max_nodes,
            truncated,
            as_of: health.as_of,
            index_watermark: health.index_watermark,
            has_gaps: health.has_gaps,
            pending_segments: health.pending_segments,
            scanned_rows,
            scanned_bytes,
            nodes: projected,
        })
    }

    async fn query_one(
        &self,
        plan: &CausalityPlan,
        filter: QueryFilter,
    ) -> Result<xshield_worker::AuditSearchResult, CausalityFailure> {
        let query_plan = QueryPlan::new(
            plan.window,
            vec![filter],
            QuerySort::OccurredAtAsc,
            QUERY_LIMIT,
        )
        .map_err(|_| CausalityFailure::InvalidRequest)?;
        query_audit_events(
            &self.config.publisher,
            &self.index,
            &self.config.tenant_id,
            &self.config.site_id,
            &query_plan,
            None,
        )
        .await
        .map_err(CausalityFailure::from)
    }

    async fn finish_causality(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        plan: Option<&CausalityPlan>,
        result: Result<CausalityResponse, CausalityFailure>,
    ) -> EndpointResult {
        let digest = plan.and_then(|plan| causality_digest(&self.config.cursor_key.0, plan).ok());
        let reason = result
            .as_ref()
            .map_or_else(|error| error.reason(), |_| "CONTROL_CAUSALITY_READ");
        let outcome = match &result {
            Ok(_) => "PASS",
            Err(
                CausalityFailure::InvalidRequest
                | CausalityFailure::Capacity
                | CausalityFailure::Budget,
            ) => "DENY",
            Err(_) => "ERROR",
        };
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || match digest {
            Some(digest) => audit_control.append_query_event(
                &audit_request_id,
                Some(&subject),
                ACCESS,
                None,
                outcome,
                reason,
                &digest,
            ),
            None => audit_control.append_access_event(
                &audit_request_id,
                Some(&subject),
                ACCESS,
                None,
                outcome,
                reason,
            ),
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        match result {
            Ok(response) => EndpointResult::Causality(response),
            Err(error) => error.response(request_id),
        }
    }
}

fn merge_scan_stats(
    rows: &mut Option<u64>,
    bytes: &mut Option<u64>,
    result: &xshield_worker::AuditSearchResult,
) -> Result<(), CausalityFailure> {
    *rows = add_optional(*rows, result.scanned_rows)?;
    *bytes = add_optional(*bytes, result.scanned_bytes)?;
    Ok(())
}

fn add_optional(left: Option<u64>, right: Option<u64>) -> Result<Option<u64>, CausalityFailure> {
    match (left, right) {
        (Some(left), Some(right)) => left
            .checked_add(right)
            .map(Some)
            .ok_or(CausalityFailure::IndexUnavailable),
        _ => Ok(None),
    }
}

fn causality_digest(key: &[u8; 32], plan: &CausalityPlan) -> Result<[u8; 32], ()> {
    let mut canonical = format!(
        "causality|{}|{}|{}|{}|{}|{}",
        plan.root.as_str(),
        plan.window.start().value(),
        plan.window.end().value(),
        plan.direction.as_str(),
        plan.max_depth,
        plan.max_nodes,
    );
    // A dedicated purpose domain keeps this digest distinct from ordinary
    // search cursors even when the same event ID and window are reused.
    let signature = super::component_signature(
        key,
        &[b"xshield/control/causality-plan/v1", canonical.as_bytes()],
    )?;
    canonical.clear();
    Ok(signature)
}

#[derive(Clone, Copy)]
enum CausalityFailure {
    InvalidRequest,
    Capacity,
    Budget,
    Timeout,
    IndexUnavailable,
    HealthUnavailable,
}

impl From<PublishError> for CausalityFailure {
    fn from(error: PublishError) -> Self {
        match error {
            PublishError::QueryBudgetExceeded => Self::Budget,
            PublishError::QueryTimeout => Self::Timeout,
            _ => Self::IndexUnavailable,
        }
    }
}

impl CausalityFailure {
    const fn reason(self) -> &'static str {
        match self {
            Self::InvalidRequest => "CONTROL_CAUSALITY_REQUEST_INVALID",
            Self::Capacity => "CONTROL_QUERY_CAPACITY_EXHAUSTED",
            Self::Budget => "CONTROL_QUERY_BUDGET_EXCEEDED",
            Self::Timeout => "CONTROL_CAUSALITY_TIMEOUT",
            Self::IndexUnavailable => "CONTROL_CAUSALITY_INDEX_UNAVAILABLE",
            Self::HealthUnavailable => "CONTROL_CAUSALITY_HEALTH_UNAVAILABLE",
        }
    }

    fn response(self, request_id: String) -> EndpointResult {
        let (status, message_safe, retryable, next_action) = match self {
            Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                "invalid causality request",
                false,
                "correct_request",
            ),
            Self::Capacity => (
                StatusCode::TOO_MANY_REQUESTS,
                "analytical query capacity exhausted",
                true,
                "retry_later",
            ),
            Self::Budget => (
                StatusCode::TOO_MANY_REQUESTS,
                "causality query budget exceeded",
                false,
                "narrow_query",
            ),
            Self::Timeout => (
                StatusCode::SERVICE_UNAVAILABLE,
                "causality query timed out",
                true,
                "retry_later",
            ),
            Self::IndexUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "audit index is temporarily unavailable",
                true,
                "retry_later",
            ),
            Self::HealthUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "audit health is temporarily unavailable",
                true,
                "retry_later",
            ),
        };
        EndpointResult::Error(
            status,
            ErrorResponse {
                error_code: self.reason(),
                message_safe,
                request_id,
                retryable,
                next_action,
            },
        )
    }
}
