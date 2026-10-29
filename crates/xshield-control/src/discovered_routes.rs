//! Window-bounded discovery of unmatched `(method, path_template)` traffic
//! for one protected site, so an operator can review and import draft routes.
//!
//! The index is an investigation source, never an authorization or routing
//! source: a discovered group only reflects traffic the gateway could not
//! match to a configured operation (see docs/11 §11.5, docs/30 §30.7).

use super::{
    AccessAction, ControlPlane, EndpointResult, api_error, audit_unavailable, internal_error,
    no_store, single_header,
};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole, domain::SiteId, identity::UnixSeconds, query::QueryWindow,
};
use xshield_worker::{
    DiscoveredRouteSummary, DiscoveredRoutesPlan, IndexWatermark, PublishError,
    inspect_publication_health, query_discovered_routes,
};

/// Per-site discovery route: unmatched `(method, path_template)` groups.
pub(super) const PATH: &str = "/control/v1/sites/{site_id}/discovered-routes";
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.site.routes.discover",
    method: "GET",
    path: PATH,
    role: ManagementRole::SystemAdmin,
};

#[derive(Serialize)]
struct ResponsePage {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    start: String,
    end: String,
    watermark_scope: &'static str,
    as_of: String,
    index_watermark: Option<IndexWatermark>,
    has_gaps: bool,
    pending_segments: usize,
    scanned_rows: Option<u64>,
    scanned_bytes: Option<u64>,
    routes: Vec<DiscoveredRouteSummary>,
    truncated: bool,
}

/// Resolves each known key exactly once before deriving the signed plan.
/// Timestamps are deliberately literal UTC RFC3339 values: rejecting
/// alternate encodings keeps the request audit vocabulary stable without
/// interpreting percent escapes differently from an intermediary. There is
/// no cursor: a discovery page is one bounded set of aggregate groups, not
/// a per-event list.
fn parse_request(raw: Option<&str>) -> Result<DiscoveredRoutesPlan, Failure> {
    let raw = raw.ok_or(Failure::Request)?;
    let mut start = None;
    let mut end = None;
    let mut limit = None;
    for parameter in raw.split('&') {
        let (key, value) = parameter.split_once('=').ok_or(Failure::Request)?;
        if value.is_empty() {
            return Err(Failure::Request);
        }
        let slot = match key {
            "start" => &mut start,
            "end" => &mut end,
            "limit" => &mut limit,
            _ => return Err(Failure::Request),
        };
        if slot.replace(value).is_some() {
            return Err(Failure::Request);
        }
    }
    let start = decode_timestamp_component(start.ok_or(Failure::Request)?)?;
    let end = decode_timestamp_component(end.ok_or(Failure::Request)?)?;
    let limit = limit
        .filter(|value| value.len() <= 3)
        .ok_or(Failure::Request)?;
    let limit = limit
        .parse::<u16>()
        .ok()
        .filter(|value| value.to_string() == limit)
        .ok_or(Failure::Request)?;
    let window =
        QueryWindow::new(query_time(&start)?, query_time(&end)?).map_err(|_| Failure::Request)?;
    DiscoveredRoutesPlan::new(window, limit).map_err(|_| Failure::Request)
}

fn decode_timestamp_component(value: &str) -> Result<String, Failure> {
    // Browsers commonly encode ':' via URLSearchParams. Decode only standard
    // percent octets, then enforce the exact UTC spelling below; `+` is not
    // treated as a space because it is not part of the accepted timestamp.
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = bytes.next().and_then(hex_digit).ok_or(Failure::Request)?;
            let low = bytes.next().and_then(hex_digit).ok_or(Failure::Request)?;
            decoded.push((high << 4) | low);
        } else {
            decoded.push(byte);
        }
    }
    let decoded = String::from_utf8(decoded).map_err(|_| Failure::Request)?;
    if decoded.len() != 20 {
        return Err(Failure::Request);
    }
    Ok(decoded)
}

const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn query_time(value: &str) -> Result<UnixSeconds, Failure> {
    let time = DateTime::<FixedOffset>::parse_from_rfc3339(value).map_err(|_| Failure::Request)?;
    // The investigation domain owns the inclusive/exclusive and maximum-window
    // rules. This boundary only prevents timezone or subsecond truncation from
    // changing a user-visible signed page.
    if time.offset().local_minus_utc() != 0
        || time.timestamp_subsec_nanos() != 0
        || time.to_rfc3339_opts(SecondsFormat::Secs, true) != value
    {
        return Err(Failure::Request);
    }
    u64::try_from(time.timestamp())
        .map(UnixSeconds::new)
        .map_err(|_| Failure::Request)
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    let Ok(site_id) = SiteId::parse(site_id) else {
        let request_id = format!("req_{}", Uuid::now_v7());
        return api_error(
            &request_id,
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    control
        .discover_routes(
            site_id,
            single_header(&headers, AUTHORIZATION.as_str()),
            raw,
            body.is_ok_and(|body| body.is_empty()),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn discover_routes(
        self: Arc<Self>,
        site_id: SiteId,
        authorization: Option<String>,
        raw: Option<String>,
        empty: bool,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request = request_id.clone();
        let auth_site = site_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize_site(authorization.as_deref(), &auth_request, ACCESS, &auth_site)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(result)) => return *result,
            Err(_) => return internal_error(&request_id),
        };
        let (true, Ok(plan)) = (empty, parse_request(raw.as_deref())) else {
            return self
                .finish_discover_routes(request_id, subject, Err(Failure::Request))
                .await;
        };
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_discover_routes(request_id, subject, Err(Failure::Capacity))
                .await;
        };
        let task_request = request_id.clone();
        // Admission outlives the HTTP caller. A disconnected client must not
        // sidestep the bounded index read or mandatory terminal audit.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .run_discover_routes(&task_request, &site_id, &plan)
                .await;
            self.finish_discover_routes(task_request, subject, result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn run_discover_routes(
        self: &Arc<Self>,
        request_id: &str,
        site_id: &SiteId,
        plan: &DiscoveredRoutesPlan,
    ) -> Result<ResponsePage, Failure> {
        let result = query_discovered_routes(
            &self.config.publisher,
            &self.index,
            &self.config.tenant_id,
            site_id,
            plan,
        )
        .await
        .map_err(|error| Failure::from_publish(&error))?;
        // This is intentionally a separate observation from the result page.
        // It reports configured-journal health only and cannot make a group
        // into a complete lifecycle or assert that another producer is caught up.
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
        Ok(ResponsePage {
            schema_version: 1,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: site_id.as_str().to_owned(),
            start: unix_seconds_timestamp(plan.window().start())?,
            end: unix_seconds_timestamp(plan.window().end())?,
            watermark_scope: "configured_journal",
            as_of: health.as_of,
            index_watermark: health.index_watermark,
            has_gaps: health.has_gaps,
            pending_segments: health.pending_segments,
            scanned_rows: result.scanned_rows,
            scanned_bytes: result.scanned_bytes,
            routes: result.routes,
            truncated: result.truncated,
        })
    }

    async fn finish_discover_routes(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        result: Result<ResponsePage, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = result.as_ref().map_or_else(
                |failure| failure.audit(),
                |_| ("PASS", "CONTROL_DISCOVERED_ROUTES_READ"),
            );
            // A discovery group is not a target-bearing access event. In
            // particular, do not turn returned path templates into
            // detail targets or evidence refs.
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
            Ok(page) => EndpointResult::Raw(no_store((StatusCode::OK, Json(page)).into_response())),
            Err(failure) => api_error(
                &request_id,
                failure.status(),
                failure.code(),
                failure.message(),
                failure.retryable(),
                failure.next_action(),
            ),
        }
    }
}

fn unix_seconds_timestamp(value: UnixSeconds) -> Result<String, Failure> {
    let seconds = i64::try_from(value.value()).map_err(|_| Failure::IndexUnavailable)?;
    let time = DateTime::<Utc>::from_timestamp(seconds, 0).ok_or(Failure::IndexUnavailable)?;
    Ok(time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

#[derive(Clone, Copy, Debug)]
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
        if matches!(error, PublishError::QueryBudgetExceeded) {
            Self::Budget
        } else if matches!(error, PublishError::QueryTimeout) {
            Self::Timeout
        } else {
            // Typed-row, configuration, and transport failures are all within
            // the opaque index dependency boundary. Never expose a partially
            // decoded page or an implementation distinction to callers.
            Self::IndexUnavailable
        }
    }

    const fn audit(self) -> (&'static str, &'static str) {
        match self {
            Self::Request => ("DENY", "CONTROL_DISCOVERED_ROUTES_REQUEST_INVALID"),
            Self::Capacity => ("DENY", "CONTROL_QUERY_CAPACITY_EXHAUSTED"),
            Self::Budget => ("DENY", "CONTROL_QUERY_BUDGET_EXCEEDED"),
            Self::Timeout => ("ERROR", "CONTROL_QUERY_TIMEOUT"),
            Self::IndexUnavailable => ("ERROR", "CONTROL_DISCOVERED_ROUTES_INDEX_UNAVAILABLE"),
            Self::HealthUnavailable => ("ERROR", "CONTROL_DISCOVERED_ROUTES_HEALTH_UNAVAILABLE"),
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

    const fn code(self) -> &'static str {
        self.audit().1
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Request => "invalid discovered routes request",
            Self::Capacity => "analytical query capacity exhausted",
            Self::Budget => "discovered routes query exceeded its budget",
            Self::Timeout => "discovered routes query timed out",
            Self::IndexUnavailable => "discovered routes index is temporarily unavailable",
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
    fn request_requires_canonical_bounded_utc_window_and_limit() {
        let plan = parse_request(Some(
            "start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=100",
        ))
        .unwrap();
        assert_eq!(plan.limit(), 100);
        assert_eq!(plan.window().start().value(), 1_789_776_000);
        assert!(
            parse_request(Some(
                "limit=1&end=2026-09-20T00:00:00Z&start=2026-09-19T00:00:00Z",
            ))
            .is_ok()
        );
        assert!(
            parse_request(Some(
                "start=2026-09-19T00%3A00%3A00Z&end=2026-09-20T00%3A00%3A00Z&limit=1",
            ))
            .is_ok()
        );
        for raw in [
            "start=2026-09-19T00:00:00+00:00&end=2026-09-20T00:00:00Z&limit=1",
            "start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=01",
            "start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=201",
            "start=2026-09-19T00:00:00Z&end=2026-09-19T00:00:00Z&limit=1",
            "start=2026-09-19T00:00:00Z&start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=1",
            "start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=1&cursor=x",
        ] {
            assert!(matches!(parse_request(Some(raw)), Err(Failure::Request)));
        }
    }

    #[test]
    fn failures_keep_stable_audit_taxonomy() {
        assert_eq!(
            Failure::Request.audit(),
            ("DENY", "CONTROL_DISCOVERED_ROUTES_REQUEST_INVALID")
        );
        assert_eq!(
            Failure::IndexUnavailable.audit(),
            ("ERROR", "CONTROL_DISCOVERED_ROUTES_INDEX_UNAVAILABLE")
        );
        assert!(!Failure::Budget.retryable());
        assert!(Failure::Capacity.retryable());
    }
}
