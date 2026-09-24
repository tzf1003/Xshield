//! Management search: strict DTO validation, scoped pagination, and durable audit.
//! The index supplies redacted facts only; search never grants evidence access.

use super::{
    AccessAction, CURSOR_BYTES_MAX, CURSOR_VERSION, ControlPlane, CursorError, EndpointResult,
    ErrorResponse, audit_unavailable, component_signature, internal_error, lower_hex,
    parse_lower_hex_32, single_header,
};
use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, FixedOffset, Utc};
use openssl::{memcmp, sha::sha256};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole,
    domain::{
        AgentRunId, ArtifactId, AuthBindingId, CalibrationReportId, CaseId, EventId,
        EvidenceAccessRequestId, GrantId, JobId, ModelCallId, RequestId, ShareGrantId, SiteId,
        SubjectRef, TenantId, TraceId,
    },
    identity::UnixSeconds,
    query::{
        ConfidenceThreshold, QueryFilter, QueryOutcome, QueryPlan, QuerySort, QueryTextField,
        QueryWindow,
    },
};
use xshield_worker::{
    IndexWatermark, PublishError, SearchEventSummary, SearchPosition, inspect_publication_health,
    query_audit_events,
};

pub(super) const SEARCH_PATH: &str = "/control/v1/search";
pub(super) const SEARCH_BODY_BYTES_MAX: usize = 8 * 1024;
const SEARCH_ACCESS: AccessAction = AccessAction {
    event_type: "console.query.executed",
    method: "POST",
    path: SEARCH_PATH,
    role: ManagementRole::Investigator,
};

impl ControlPlane {
    #[allow(clippy::too_many_lines)]
    async fn search(
        self: Arc<Self>,
        authorization: Option<String>,
        payload: Option<SearchRequest>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let identity = match tokio::task::spawn_blocking(move || {
            auth_control.authorize_identity(
                authorization.as_deref(),
                &auth_request_id,
                SEARCH_ACCESS,
            )
        })
        .await
        {
            Ok(Ok(identity)) => identity,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let has_audit_administrator = identity.principal.authorizes(
            ManagementRole::AuditAdministrator,
            &self.config.tenant_id,
            &self.config.site_id,
        );
        let subject = identity.principal.subject().to_owned();
        let Some((plan, cursor)) = payload.and_then(|mut payload| {
            let cursor = payload.cursor.take();
            payload
                .into_plan(self.config.limits.max_query_events)
                .ok()
                .map(|plan| (plan, cursor))
        }) else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    SEARCH_ACCESS,
                    None,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "CONTROL_QUERY_INVALID",
                    "invalid query plan",
                    false,
                    "correct_request",
                )
                .await;
        };
        if plan.filters().iter().any(|filter| {
            matches!(
                filter,
                QueryFilter::CalibrationReportId(_) | QueryFilter::EvidenceHoldId(_)
            )
        }) && !has_audit_administrator
        {
            // Both retained report and hold facts share their respective
            // administrator visibility boundaries with the source workbenches.
            return self
                .finish_search(
                    request_id,
                    subject,
                    &plan,
                    Err(
                        if plan
                            .filters()
                            .iter()
                            .any(|filter| matches!(filter, QueryFilter::CalibrationReportId(_)))
                        {
                            SearchFailure::CalibrationReportHistoryScopeDenied
                        } else {
                            SearchFailure::EvidenceHoldHistoryScopeDenied
                        },
                    ),
                )
                .await;
        }
        let after = match cursor
            .as_deref()
            .map(|cursor| self.decode_search_cursor(&subject, &plan, cursor))
            .transpose()
        {
            Ok(after) => after,
            Err(error) => {
                return self
                    .finish_search(
                        request_id,
                        subject,
                        &plan,
                        Err(match error {
                            CursorError::Invalid => SearchFailure::InvalidCursor,
                            CursorError::Unavailable => SearchFailure::CursorUnavailable,
                        }),
                    )
                    .await;
            }
        };
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_search(request_id, subject, &plan, Err(SearchFailure::Capacity))
                .await;
        };
        let task_request_id = request_id.clone();
        // Keep the bounded query and its terminal audit alive on client disconnect.
        // The worker's deadline and permit bound this detached work; process exit
        // is still a failure boundary, not a durable job queue.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .run_search(&task_request_id, &subject, &plan, after.as_ref())
                .await;
            self.finish_search(task_request_id, subject, &plan, result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn run_search(
        self: &Arc<Self>,
        request_id: &str,
        subject: &str,
        plan: &QueryPlan,
        after: Option<&SearchPosition>,
    ) -> Result<SearchResponse, SearchFailure> {
        let result = query_audit_events(
            &self.config.publisher,
            &self.index,
            &self.config.tenant_id,
            &self.config.site_id,
            plan,
            after,
        )
        .await
        .map_err(|error| match error {
            PublishError::QueryBudgetExceeded => SearchFailure::Budget,
            PublishError::QueryTimeout => SearchFailure::Timeout,
            _ => SearchFailure::IndexUnavailable,
        })?;
        // ponytail: watermark verification is O(retained journal bytes); use a
        // signed catalog when measured scans exceed the control latency budget.
        let health_control = Arc::clone(self);
        let health = tokio::task::spawn_blocking(move || {
            inspect_publication_health(
                &health_control.config.publisher,
                &health_control.config.source_journal_key_id,
                &health_control.source_journal_key,
                &health_control.seal_key,
            )
        })
        .await
        .map_err(|_| SearchFailure::HealthUnavailable)?
        .map_err(|_| SearchFailure::HealthUnavailable)?;
        let next_cursor = result
            .next_position
            .as_ref()
            .map(|position| self.encode_search_cursor(subject, plan, position))
            .transpose()
            .map_err(|()| SearchFailure::CursorUnavailable)?;
        Ok(SearchResponse {
            schema_version: 3,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            query_digest: lower_hex(
                &query_plan_digest(plan, &self.config.cursor_key.0)
                    .map_err(|()| SearchFailure::CursorUnavailable)?,
            ),
            as_of: health.as_of,
            index_watermark: health.index_watermark,
            has_gaps: health.has_gaps,
            pending_segments: health.pending_segments,
            scanned_rows: result.scanned_rows,
            scanned_bytes: result.scanned_bytes,
            truncated: result.truncated,
            next_cursor,
            events: result.events,
        })
    }

    async fn finish_search(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        plan: &QueryPlan,
        result: Result<SearchResponse, SearchFailure>,
    ) -> EndpointResult {
        let target_request_id = plan.filters().iter().find_map(|filter| match filter {
            QueryFilter::RequestId(request_id) => Some(request_id.clone()),
            _ => None,
        });
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let Ok(audit_plan_digest) = query_plan_digest(plan, &self.config.cursor_key.0) else {
            return audit_unavailable(&request_id);
        };
        let reason = result
            .as_ref()
            .map_or_else(SearchFailure::reason, |_| "CONTROL_QUERY_EXECUTED");
        let outcome = match &result {
            Ok(_) => "PASS",
            Err(
                SearchFailure::InvalidCursor
                | SearchFailure::CalibrationReportHistoryScopeDenied
                | SearchFailure::EvidenceHoldHistoryScopeDenied
                | SearchFailure::Budget
                | SearchFailure::Capacity,
            ) => "DENY",
            Err(_) => "ERROR",
        };
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_query_event(
                &audit_request_id,
                Some(&subject),
                SEARCH_ACCESS,
                target_request_id.as_ref(),
                outcome,
                reason,
                &audit_plan_digest,
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        match result {
            Ok(response) => EndpointResult::Search(response),
            Err(error) => error.response(request_id),
        }
    }

    pub(super) fn encode_search_cursor(
        &self,
        subject: &str,
        plan: &QueryPlan,
        position: &SearchPosition,
    ) -> Result<String, ()> {
        let plan_digest = query_plan_digest(plan, &self.config.cursor_key.0)?;
        let timestamp = position.occurred_at().timestamp_micros();
        let signature = search_cursor_signature(
            &self.config.cursor_key.0,
            &self.config.credential.token_digest,
            subject,
            &self.config.tenant_id,
            &self.config.site_id,
            &plan_digest,
            timestamp,
            position.event_id(),
        )?;
        Ok(format!(
            "{CURSOR_VERSION}.{}.{}.{}",
            timestamp,
            position.event_id().as_str(),
            lower_hex(&signature)
        ))
    }

    pub(super) fn decode_search_cursor(
        &self,
        subject: &str,
        plan: &QueryPlan,
        cursor: &str,
    ) -> Result<SearchPosition, CursorError> {
        if cursor.len() > CURSOR_BYTES_MAX {
            return Err(CursorError::Invalid);
        }
        let mut parts = cursor.split('.');
        let (Some(version), Some(timestamp), Some(event_id), Some(signature)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if parts.next().is_some() || version != CURSOR_VERSION {
            return Err(CursorError::Invalid);
        }
        let timestamp = timestamp
            .parse::<i64>()
            .ok()
            .filter(|value| value.to_string() == timestamp)
            .ok_or(CursorError::Invalid)?;
        let occurred_at =
            DateTime::<Utc>::from_timestamp_micros(timestamp).ok_or(CursorError::Invalid)?;
        let seconds = u64::try_from(occurred_at.timestamp()).map_err(|_| CursorError::Invalid)?;
        if !(plan.window().start().value()..plan.window().end().value()).contains(&seconds) {
            return Err(CursorError::Invalid);
        }
        let event_id = EventId::parse(event_id).map_err(|_| CursorError::Invalid)?;
        let supplied_signature = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let plan_digest = query_plan_digest(plan, &self.config.cursor_key.0)
            .map_err(|()| CursorError::Unavailable)?;
        let expected_signature = search_cursor_signature(
            &self.config.cursor_key.0,
            &self.config.credential.token_digest,
            subject,
            &self.config.tenant_id,
            &self.config.site_id,
            &plan_digest,
            timestamp,
            &event_id,
        )
        .map_err(|()| CursorError::Unavailable)?;
        if !memcmp::eq(&supplied_signature, &expected_signature) {
            return Err(CursorError::Invalid);
        }
        SearchPosition::new(occurred_at, event_id).map_err(|_| CursorError::Invalid)
    }
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    payload: Result<Json<SearchRequest>, JsonRejection>,
) -> Response {
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    control
        .search(authorization, payload.ok().map(|Json(payload)| payload))
        .await
        .into_response()
}

fn query_plan_digest(plan: &QueryPlan, key: &[u8; 32]) -> Result<[u8; 32], ()> {
    let mut canonical = format!(
        "{}|{}|{}|{}",
        plan.window().start().value(),
        plan.window().end().value(),
        match plan.sort() {
            QuerySort::OccurredAtAsc => "asc",
            QuerySort::OccurredAtDesc => "desc",
        },
        plan.limit()
    );
    for filter in plan.filters() {
        canonical.push('|');
        match filter {
            QueryFilter::RequestId(value) => {
                canonical.push_str("request_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::EventId(value) => {
                canonical.push_str("event_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::TraceId(value) => {
                canonical.push_str("trace_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::CausedByEventId(value) => {
                canonical.push_str("caused_by_event_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::SubjectRef(value) => {
                let digest = component_signature(
                    key,
                    &[b"xshield/search/subject-ref/v1", value.as_str().as_bytes()],
                )?;
                canonical.push_str("subject_ref_hmac=");
                canonical.push_str(&lower_hex(&digest));
            }
            QueryFilter::GrantId(value) => {
                canonical.push_str("grant_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::AuthBindingId(value) => {
                canonical.push_str("auth_binding_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::CaseId(value) => {
                canonical.push_str("case_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::ArtifactId(value) => {
                canonical.push_str("artifact_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::CalibrationReportId(value) => {
                canonical.push_str("calibration_report_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::EvidenceHoldId(value) => {
                canonical.push_str("evidence_hold_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::EvidenceAccessRequestId(value) => {
                canonical.push_str("evidence_access_request_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::ModelCallId(value) => {
                canonical.push_str("model_call_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::AgentRunId(value) => {
                canonical.push_str("agent_run_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::JobId(value) => {
                canonical.push_str("job_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::ShareGrantId(value) => {
                canonical.push_str("share_grant_id=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::Text { field, value } => {
                canonical.push_str(field.as_str());
                canonical.push('=');
                canonical.push_str(value);
            }
            QueryFilter::Outcome(value) => {
                canonical.push_str("outcome=");
                canonical.push_str(value.as_str());
            }
            QueryFilter::ConfidenceAtMost(value) => {
                canonical.push_str("confidence<=");
                canonical.push_str(&value.basis_points().to_string());
            }
        }
    }
    Ok(sha256(canonical.as_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn search_cursor_signature(
    key: &[u8; 32],
    credential_digest: &[u8; 32],
    subject: &str,
    tenant_id: &TenantId,
    site_id: &SiteId,
    plan_digest: &[u8; 32],
    timestamp_micros: i64,
    event_id: &EventId,
) -> Result<[u8; 32], ()> {
    component_signature(
        key,
        &[
            b"xshield-control-search-cursor-v1",
            credential_digest,
            subject.as_bytes(),
            tenant_id.as_str().as_bytes(),
            site_id.as_str().as_bytes(),
            plan_digest,
            &timestamp_micros.to_be_bytes(),
            event_id.as_str().as_bytes(),
        ],
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SearchRequest {
    schema_version: u8,
    start: DateTime<FixedOffset>,
    end: DateTime<FixedOffset>,
    #[serde(default)]
    filters: Vec<SearchFilterRequest>,
    sort: SearchSortRequest,
    limit: u16,
    #[serde(default)]
    cursor: Option<String>,
}

impl SearchRequest {
    pub(super) fn into_plan(self, max_limit: u16) -> Result<QueryPlan, ()> {
        if self.schema_version != 3 || self.limit > max_limit {
            return Err(());
        }
        let window =
            QueryWindow::new(query_time(self.start)?, query_time(self.end)?).map_err(|_| ())?;
        let filters = self
            .filters
            .into_iter()
            .map(SearchFilterRequest::into_domain)
            .collect::<Result<Vec<_>, _>>()?;
        QueryPlan::new(window, filters, self.sort.into_domain(), self.limit).map_err(|_| ())
    }
}

fn query_time(time: DateTime<FixedOffset>) -> Result<UnixSeconds, ()> {
    // The plan uses whole UTC seconds; reject precision/offset loss rather than
    // silently changing the investigator's requested bounds.
    if time.offset().local_minus_utc() != 0 || time.timestamp_subsec_nanos() != 0 {
        return Err(());
    }
    u64::try_from(time.timestamp())
        .map(UnixSeconds::new)
        .map_err(|_| ())
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SearchFilterRequest {
    RequestId {
        value: String,
    },
    EventId {
        value: String,
    },
    TraceId {
        value: String,
    },
    CausedByEventId {
        value: String,
    },
    SubjectRef {
        value: String,
    },
    GrantId {
        value: String,
    },
    AuthBindingId {
        value: String,
    },
    CaseId {
        value: String,
    },
    ArtifactId {
        value: String,
    },
    CalibrationReportId {
        value: String,
    },
    EvidenceHoldId {
        value: String,
    },
    EvidenceAccessRequestId {
        value: String,
    },
    ModelCallId {
        value: String,
    },
    AgentRunId {
        value: String,
    },
    JobId {
        value: String,
    },
    ShareGrantId {
        value: String,
    },
    Text {
        field: SearchTextFieldRequest,
        value: String,
    },
    Outcome {
        value: SearchOutcomeRequest,
    },
    ConfidenceAtMost {
        basis_points: u16,
    },
}

impl SearchFilterRequest {
    fn into_domain(self) -> Result<QueryFilter, ()> {
        match self {
            Self::RequestId { value } => RequestId::parse(value)
                .map(QueryFilter::RequestId)
                .map_err(|_| ()),
            Self::EventId { value } => EventId::parse(value)
                .map(QueryFilter::EventId)
                .map_err(|_| ()),
            Self::TraceId { value } => TraceId::parse(value)
                .map(QueryFilter::TraceId)
                .map_err(|_| ()),
            Self::CausedByEventId { value } => EventId::parse(value)
                .map(QueryFilter::CausedByEventId)
                .map_err(|_| ()),
            Self::SubjectRef { value } => SubjectRef::parse(value)
                .map(QueryFilter::SubjectRef)
                .map_err(|_| ()),
            Self::GrantId { value } => GrantId::parse(value)
                .map(QueryFilter::GrantId)
                .map_err(|_| ()),
            Self::AuthBindingId { value } => AuthBindingId::parse(value)
                .map(QueryFilter::AuthBindingId)
                .map_err(|_| ()),
            Self::CaseId { value } => CaseId::parse(value)
                .map(QueryFilter::CaseId)
                .map_err(|_| ()),
            Self::ArtifactId { value } => ArtifactId::parse(value)
                .map(QueryFilter::ArtifactId)
                .map_err(|_| ()),
            Self::CalibrationReportId { value } => CalibrationReportId::parse(value)
                .map(QueryFilter::CalibrationReportId)
                .map_err(|_| ()),
            Self::EvidenceHoldId { value } => EventId::parse(value)
                .map(QueryFilter::EvidenceHoldId)
                .map_err(|_| ()),
            Self::EvidenceAccessRequestId { value } => EvidenceAccessRequestId::parse(value)
                .map(QueryFilter::EvidenceAccessRequestId)
                .map_err(|_| ()),
            Self::ModelCallId { value } => ModelCallId::parse(value)
                .map(QueryFilter::ModelCallId)
                .map_err(|_| ()),
            Self::AgentRunId { value } => AgentRunId::parse(value)
                .map(QueryFilter::AgentRunId)
                .map_err(|_| ()),
            Self::JobId { value } => JobId::parse(value).map(QueryFilter::JobId).map_err(|_| ()),
            Self::ShareGrantId { value } => ShareGrantId::parse(value)
                .map(QueryFilter::ShareGrantId)
                .map_err(|_| ()),
            Self::Text { field, value } => Ok(QueryFilter::Text {
                field: field.into_domain(),
                value,
            }),
            Self::Outcome { value } => Ok(QueryFilter::Outcome(value.into_domain())),
            Self::ConfidenceAtMost { basis_points } => ConfidenceThreshold::new(basis_points)
                .map(QueryFilter::ConfidenceAtMost)
                .map_err(|_| ()),
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SearchTextFieldRequest {
    EventType,
    Stage,
    ReasonCode,
    OperationId,
    ModelRevision,
}

impl SearchTextFieldRequest {
    const fn into_domain(self) -> QueryTextField {
        match self {
            Self::EventType => QueryTextField::EventType,
            Self::Stage => QueryTextField::Stage,
            Self::ReasonCode => QueryTextField::ReasonCode,
            Self::OperationId => QueryTextField::OperationId,
            Self::ModelRevision => QueryTextField::ModelRevision,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum SearchOutcomeRequest {
    Pass,
    Allow,
    Deny,
    Unknown,
    Error,
    Skipped,
    Cancelled,
}

impl SearchOutcomeRequest {
    const fn into_domain(self) -> QueryOutcome {
        match self {
            Self::Pass => QueryOutcome::Pass,
            Self::Allow => QueryOutcome::Allow,
            Self::Deny => QueryOutcome::Deny,
            Self::Unknown => QueryOutcome::Unknown,
            Self::Error => QueryOutcome::Error,
            Self::Skipped => QueryOutcome::Skipped,
            Self::Cancelled => QueryOutcome::Cancelled,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SearchSortRequest {
    OccurredAtAsc,
    OccurredAtDesc,
}

impl SearchSortRequest {
    const fn into_domain(self) -> QuerySort {
        match self {
            Self::OccurredAtAsc => QuerySort::OccurredAtAsc,
            Self::OccurredAtDesc => QuerySort::OccurredAtDesc,
        }
    }
}

#[derive(Serialize)]
pub(super) struct SearchResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    query_digest: String,
    as_of: String,
    index_watermark: Option<IndexWatermark>,
    has_gaps: bool,
    pending_segments: usize,
    scanned_rows: Option<u64>,
    scanned_bytes: Option<u64>,
    truncated: bool,
    next_cursor: Option<String>,
    events: Vec<SearchEventSummary>,
}

pub(super) enum SearchFailure {
    InvalidCursor,
    CalibrationReportHistoryScopeDenied,
    EvidenceHoldHistoryScopeDenied,
    CursorUnavailable,
    Capacity,
    Budget,
    Timeout,
    IndexUnavailable,
    HealthUnavailable,
}

impl SearchFailure {
    pub(super) const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidCursor => "CONTROL_CURSOR_INVALID",
            Self::CalibrationReportHistoryScopeDenied => {
                "CONTROL_CALIBRATION_REPORT_HISTORY_SCOPE_DENIED"
            }
            Self::EvidenceHoldHistoryScopeDenied => "CONTROL_EVIDENCE_HOLD_HISTORY_SCOPE_DENIED",
            Self::CursorUnavailable => "CONTROL_CURSOR_UNAVAILABLE",
            Self::Capacity => "CONTROL_QUERY_CAPACITY_EXHAUSTED",
            Self::Budget => "CONTROL_QUERY_BUDGET_EXCEEDED",
            Self::Timeout => "CONTROL_QUERY_TIMEOUT",
            Self::IndexUnavailable => "CONTROL_INDEX_UNAVAILABLE",
            Self::HealthUnavailable => "CONTROL_HEALTH_UNAVAILABLE",
        }
    }

    pub(super) fn response(&self, request_id: String) -> EndpointResult {
        let (status, message_safe, retryable, next_action) = match self {
            Self::InvalidCursor => (
                StatusCode::BAD_REQUEST,
                "invalid pagination cursor",
                false,
                "restart_query",
            ),
            Self::CalibrationReportHistoryScopeDenied | Self::EvidenceHoldHistoryScopeDenied => (
                StatusCode::FORBIDDEN,
                "management operation forbidden",
                false,
                "request_scope",
            ),
            Self::CursorUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "pagination service is temporarily unavailable",
                true,
                "retry_later",
            ),
            Self::Capacity => (
                StatusCode::TOO_MANY_REQUESTS,
                "analytical query capacity exhausted",
                true,
                "retry_later",
            ),
            Self::Budget => (
                StatusCode::TOO_MANY_REQUESTS,
                "analytical query budget exceeded",
                false,
                "narrow_query",
            ),
            Self::Timeout => (
                StatusCode::SERVICE_UNAVAILABLE,
                "analytical query timed out",
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
