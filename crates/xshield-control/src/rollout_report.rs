//! The observe → enforce exit report (docs/32 32.4): what the index holds
//! about one observe window, with a digest an approval can cite. The report
//! states facts only; whether they justify enforcing is the approver's call,
//! and an index that has not caught up makes the report incomplete, never a
//! pass.

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
    IndexWatermark, PublishError, RolloutObservation, RolloutReportPlan,
    inspect_publication_health, query_rollout_report,
};

/// Report route for the configured site.
pub(super) const PATH: &str = "/control/v1/rollout-report";
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.rollout_report.read",
    method: "GET",
    path: PATH,
    role: ManagementRole::Observer,
};

/// Everything the digest covers, in a fixed field order.
#[derive(Serialize)]
struct Facts {
    tenant_id: String,
    site_id: String,
    rollout_revision: String,
    start: String,
    end: String,
    completed_requests: u64,
    observed_requests: u64,
    unrouted_refusals: u64,
    observations: Vec<RolloutObservation>,
    truncated: bool,
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
    plan: RolloutReportPlan,
}

/// Each of `revision`, `start` and `end` exactly once; times are literal UTC
/// RFC 3339 seconds, optionally with `:` percent-encoded.
fn parse_request(raw: Option<&str>) -> Result<Request, Failure> {
    let raw = raw.ok_or(Failure::Request)?;
    let (mut revision, mut start, mut end) = (None, None, None);
    for parameter in raw.split('&') {
        let (key, value) = parameter.split_once('=').ok_or(Failure::Request)?;
        let slot = match key {
            "revision" => &mut revision,
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
    let plan = RolloutReportPlan::new(window, revision.ok_or(Failure::Request)?)
        .map_err(|_| Failure::Request)?;
    Ok(Request { plan })
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    control
        .rollout_report(
            single_header(&headers, AUTHORIZATION.as_str()),
            raw,
            body.is_ok_and(|body| body.is_empty()),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn rollout_report(
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
                .finish_rollout_report(request_id, subject, Err(Failure::Request))
                .await;
        };
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_rollout_report(request_id, subject, Err(Failure::Capacity))
                .await;
        };
        let task_request = request_id.clone();
        // Admission outlives the HTTP caller, so a disconnected client cannot
        // skip the bounded index read or its terminal audit.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self.run_rollout_report(&task_request, &request.plan).await;
            self.finish_rollout_report(task_request, subject, result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn run_rollout_report(
        self: &Arc<Self>,
        request_id: &str,
        plan: &RolloutReportPlan,
    ) -> Result<ReportResponse, Failure> {
        let report = query_rollout_report(
            &self.config.publisher,
            &self.index,
            &self.config.tenant_id,
            &self.config.site_id,
            plan,
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
            rollout_revision: plan.rollout_revision().to_owned(),
            start: timestamp(plan.window().start())?,
            end: timestamp(plan.window().end())?,
            completed_requests: report.completed_requests,
            observed_requests: report.observed_requests,
            unrouted_refusals: report.unrouted_refusals,
            observations: report.observations,
            truncated: report.truncated,
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

    async fn finish_rollout_report(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        result: Result<ReportResponse, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = result.as_ref().map_or_else(
                |failure| failure.audit(),
                |_| ("PASS", "CONTROL_ROLLOUT_REPORT_READ"),
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
            Self::Request => ("DENY", "CONTROL_ROLLOUT_REPORT_REQUEST_INVALID"),
            Self::Capacity => ("DENY", "CONTROL_QUERY_CAPACITY_EXHAUSTED"),
            Self::Budget => ("DENY", "CONTROL_QUERY_BUDGET_EXCEEDED"),
            Self::Timeout => ("ERROR", "CONTROL_QUERY_TIMEOUT"),
            Self::IndexUnavailable => ("ERROR", "CONTROL_ROLLOUT_REPORT_INDEX_UNAVAILABLE"),
            Self::HealthUnavailable => ("ERROR", "CONTROL_ROLLOUT_REPORT_HEALTH_UNAVAILABLE"),
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
            Self::Request => "invalid rollout report request",
            Self::Capacity => "analytical query capacity exhausted",
            Self::Budget => "rollout report exceeded its query budget",
            Self::Timeout => "rollout report query timed out",
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
    fn a_report_names_one_rollout_over_a_canonical_utc_window() {
        let request = parse_request(Some(
            "revision=rollout-1&start=2026-09-19T00%3A00%3A00Z&end=2026-09-26T00:00:00Z",
        ))
        .unwrap();
        assert_eq!(request.plan.rollout_revision(), "rollout-1");
        assert_eq!(request.plan.window().start().value(), 1_789_776_000);
        for raw in [
            "start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z",
            "revision=has%20space&start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z",
            "revision=r1&revision=r2&start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z",
            "revision=r1&start=2026-09-19T00:00:00+00:00&end=2026-09-20T00:00:00Z",
            "revision=r1&start=2026-09-19T00:00:00Z&end=2026-09-19T00:00:00Z",
            "revision=r1&start=2026-09-19T00:00:00Z&end=2026-11-19T00:00:00Z",
            "revision=r1&start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=1",
            "revision=&start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z",
        ] {
            assert!(
                matches!(parse_request(Some(raw)), Err(Failure::Request)),
                "{raw}"
            );
        }
        assert!(matches!(parse_request(None), Err(Failure::Request)));
    }
}
