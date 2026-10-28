//! Refusal and coverage statistics for the configured site over a window:
//! traffic and refusals per route and reason, and the endpoints no route
//! covers, listed by method and path shape (docs/29). Like the rollout report
//! it states what the index holds, with a digest a review can cite; an index
//! that has not caught up makes the report incomplete.

use super::{
    AccessAction, ControlPlane, EndpointResult, api_error, audit_unavailable, internal_error,
    lower_hex, single_header,
};
use axum::{
    Json,
    body::Bytes,
    extract::{RawQuery, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use openssl::sha::sha256;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;
use xshield_core::{admin::ManagementRole, identity::UnixSeconds, query::QueryWindow};
use xshield_worker::{
    IndexWatermark, PublishError, RouteRefusal, RouteTraffic, UncoveredEndpoint,
    inspect_publication_health, query_coverage_report,
};

/// Report route for the configured site.
pub(super) const PATH: &str = "/control/v1/coverage-report";
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.coverage_report.read",
    method: "GET",
    path: PATH,
    role: ManagementRole::Observer,
};

/// Everything the digest covers, in a fixed field order.
#[derive(Serialize)]
// The flags are wire facts of the response, not states of one machine.
#[allow(clippy::struct_excessive_bools)]
struct Facts {
    tenant_id: String,
    site_id: String,
    start: String,
    end: String,
    completed_requests: u64,
    refused_requests: u64,
    observed_requests: u64,
    unrouted_refusals: u64,
    unshaped_unrouted_refusals: u64,
    routes: Vec<RouteTraffic>,
    routes_truncated: bool,
    refusals: Vec<RouteRefusal>,
    refusals_truncated: bool,
    uncovered: Vec<UncoveredEndpoint>,
    uncovered_truncated: bool,
    index_watermark: Option<IndexWatermark>,
    has_gaps: bool,
    pending_segments: usize,
}

#[derive(Serialize)]
struct ReportResponse {
    schema_version: u8,
    request_id: String,
    watermark_scope: &'static str,
    as_of: String,
    /// The index had no gap and nothing waiting to publish when it was read.
    index_complete: bool,
    /// Lower-hex SHA-256 of the serialized facts, for the approval record.
    report_digest: String,
    #[serde(flatten)]
    facts: Facts,
}

struct Request {
    window: QueryWindow,
}

/// Each of `start` and `end` exactly once; times are literal UTC RFC 3339
/// seconds, optionally with `:` percent-encoded.
fn parse_request(raw: Option<&str>) -> Result<Request, Failure> {
    let raw = raw.ok_or(Failure::Request)?;
    let (mut start, mut end) = (None, None);
    for parameter in raw.split('&') {
        let (key, value) = parameter.split_once('=').ok_or(Failure::Request)?;
        let slot = match key {
            "start" => &mut start,
            "end" => &mut end,
            _ => return Err(Failure::Request),
        };
        if value.is_empty() || slot.replace(value).is_some() {
            return Err(Failure::Request);
        }
    }
    let time = |value: Option<&str>| -> Result<UnixSeconds, Failure> {
        let value = value.ok_or(Failure::Request)?.replace("%3A", ":");
        let parsed =
            DateTime::<FixedOffset>::parse_from_rfc3339(&value).map_err(|_| Failure::Request)?;
        if parsed.offset().local_minus_utc() != 0
            || parsed.timestamp_subsec_nanos() != 0
            || parsed.to_rfc3339_opts(SecondsFormat::Secs, true) != value
        {
            return Err(Failure::Request);
        }
        u64::try_from(parsed.timestamp())
            .map(UnixSeconds::new)
            .map_err(|_| Failure::Request)
    };
    let window = QueryWindow::new(time(start)?, time(end)?).map_err(|_| Failure::Request)?;
    Ok(Request { window })
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    control
        .coverage_report(
            single_header(&headers, AUTHORIZATION.as_str()),
            raw,
            body.is_ok_and(|body| body.is_empty()),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn coverage_report(
        self: Arc<Self>,
        authorization: Option<String>,
        raw: Option<String>,
        empty: bool,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request, ACCESS)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(result)) => return *result,
            Err(_) => return internal_error(&request_id),
        };
        let (true, Ok(request)) = (empty, parse_request(raw.as_deref())) else {
            return self
                .finish_coverage_report(request_id, subject, Err(Failure::Request))
                .await;
        };
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_coverage_report(request_id, subject, Err(Failure::Capacity))
                .await;
        };
        let task_request = request_id.clone();
        // Admission outlives the HTTP caller, so a disconnected client cannot
        // skip the bounded index read or its terminal audit.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .run_coverage_report(&task_request, request.window)
                .await;
            self.finish_coverage_report(task_request, subject, result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn run_coverage_report(
        self: &Arc<Self>,
        request_id: &str,
        window: QueryWindow,
    ) -> Result<ReportResponse, Failure> {
        let report = query_coverage_report(
            &self.config.publisher,
            &self.index,
            &self.config.tenant_id,
            &self.config.site_id,
            window,
        )
        .await
        .map_err(|error| Failure::from_publish(&error))?;
        // Read after the counts: health that is complete now was complete
        // for every event the counts could have included.
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
        .map_err(|_| Failure::HealthUnavailable)?
        .map_err(|_| Failure::HealthUnavailable)?;
        let facts = Facts {
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            start: timestamp(window.start())?,
            end: timestamp(window.end())?,
            completed_requests: report.completed_requests,
            refused_requests: report.refused_requests,
            observed_requests: report.observed_requests,
            unrouted_refusals: report.unrouted_refusals,
            unshaped_unrouted_refusals: report.unshaped_unrouted_refusals,
            routes: report.routes,
            routes_truncated: report.routes_truncated,
            refusals: report.refusals,
            refusals_truncated: report.refusals_truncated,
            uncovered: report.uncovered,
            uncovered_truncated: report.uncovered_truncated,
            index_watermark: health.index_watermark,
            has_gaps: health.has_gaps,
            pending_segments: health.pending_segments,
        };
        let serialized = serde_json::to_vec(&facts).map_err(|_| Failure::IndexUnavailable)?;
        Ok(ReportResponse {
            schema_version: 1,
            request_id: request_id.to_owned(),
            watermark_scope: "configured_journal",
            as_of: health.as_of,
            index_complete: !facts.has_gaps && facts.pending_segments == 0,
            report_digest: lower_hex(&sha256(&serialized)),
            facts,
        })
    }

    async fn finish_coverage_report(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        result: Result<ReportResponse, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = result.as_ref().map_or_else(
                |failure| failure.audit(),
                |_| ("PASS", "CONTROL_COVERAGE_REPORT_READ"),
            );
            self.append_access_event(
                &audit_request,
                Some(&subject),
                ACCESS,
                None,
                outcome,
                reason,
            )?;
            Ok::<_, super::ControlError>(result)
        })
        .await;
        let Ok(Ok(result)) = audited else {
            return audit_unavailable(&request_id);
        };
        match result {
            Ok(report) => EndpointResult::Raw((StatusCode::OK, Json(report)).into_response()),
            Err(failure) => api_error(
                &request_id,
                failure.status(),
                failure.audit().1,
                failure.message(),
                failure.retryable(),
                failure.next_action(),
            ),
        }
    }
}

fn timestamp(value: UnixSeconds) -> Result<String, Failure> {
    let seconds = i64::try_from(value.value()).map_err(|_| Failure::IndexUnavailable)?;
    let time = DateTime::<Utc>::from_timestamp(seconds, 0).ok_or(Failure::IndexUnavailable)?;
    Ok(time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Request,
    Capacity,
    Budget,
    Timeout,
    IndexUnavailable,
    HealthUnavailable,
}

impl Failure {
    fn from_publish(error: &PublishError) -> Self {
        match error {
            PublishError::QueryBudgetExceeded => Self::Budget,
            PublishError::QueryTimeout => Self::Timeout,
            _ => Self::IndexUnavailable,
        }
    }

    const fn audit(self) -> (&'static str, &'static str) {
        match self {
            Self::Request => ("DENY", "CONTROL_COVERAGE_REPORT_REQUEST_INVALID"),
            Self::Capacity => ("DENY", "CONTROL_QUERY_CAPACITY_EXHAUSTED"),
            Self::Budget => ("DENY", "CONTROL_QUERY_BUDGET_EXCEEDED"),
            Self::Timeout => ("ERROR", "CONTROL_QUERY_TIMEOUT"),
            Self::IndexUnavailable => ("ERROR", "CONTROL_COVERAGE_REPORT_INDEX_UNAVAILABLE"),
            Self::HealthUnavailable => ("ERROR", "CONTROL_COVERAGE_REPORT_HEALTH_UNAVAILABLE"),
        }
    }

    const fn status(self) -> StatusCode {
        match self {
            Self::Request => StatusCode::BAD_REQUEST,
            Self::Capacity | Self::Budget => StatusCode::TOO_MANY_REQUESTS,
            Self::Timeout | Self::IndexUnavailable | Self::HealthUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Request => "invalid coverage report request",
            Self::Capacity => "analytical query capacity exhausted",
            Self::Budget => "coverage report exceeded its query budget",
            Self::Timeout => "coverage report query timed out",
            Self::IndexUnavailable => "audit index is temporarily unavailable",
            Self::HealthUnavailable => "audit health is temporarily unavailable",
        }
    }

    const fn retryable(self) -> bool {
        !matches!(self, Self::Request | Self::Budget)
    }

    const fn next_action(self) -> &'static str {
        match self {
            Self::Request => "correct_request",
            Self::Budget => "narrow_query",
            Self::Capacity | Self::Timeout | Self::IndexUnavailable | Self::HealthUnavailable => {
                "retry_later"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Failure, parse_request};

    #[test]
    fn a_report_covers_one_canonical_utc_window() {
        let request = parse_request(Some(
            "start=2026-09-19T00%3A00%3A00Z&end=2026-09-26T00:00:00Z",
        ))
        .unwrap();
        assert_eq!(request.window.start().value(), 1_789_776_000);
        for raw in [
            "start=2026-09-19T00:00:00Z",
            "start=2026-09-19T00:00:00Z&start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z",
            "start=2026-09-19T00:00:00+00:00&end=2026-09-20T00:00:00Z",
            "start=2026-09-19T00:00:00Z&end=2026-09-19T00:00:00Z",
            "start=2026-09-19T00:00:00Z&end=2026-11-19T00:00:00Z",
            "start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&revision=r1",
            "start=&end=2026-09-20T00:00:00Z",
        ] {
            assert!(
                matches!(parse_request(Some(raw)), Err(Failure::Request)),
                "{raw}"
            );
        }
        assert!(matches!(parse_request(None), Err(Failure::Request)));
    }
}
