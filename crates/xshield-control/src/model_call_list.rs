//! Window-bounded model-call discovery with scoped cursors and durable audit.
//! The index is an investigation source, never an authorization source or a
//! substitute for re-authorizing the separately audited detail endpoint.

use super::{
    AccessAction, CURSOR_BYTES_MAX, CURSOR_VERSION, ControlPlane, CursorError, EndpointResult,
    api_error, audit_unavailable, component_signature, internal_error, lower_hex,
    parse_lower_hex_32, single_header,
};
use axum::{
    Json,
    body::Bytes,
    extract::{RawQuery, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;
use xshield_core::constant_time;
use xshield_core::{
    admin::ManagementRole, domain::ModelCallId, identity::UnixSeconds, query::QueryWindow,
};
use xshield_worker::{
    IndexWatermark, ModelCallListPlan, ModelCallListPosition, ModelCallListSummary, PublishError,
    inspect_publication_health, query_model_calls,
};

/// Collection route for redacted, latest-in-window model-call discovery.
pub(super) const PATH: &str = "/control/v1/model-calls";
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.model.list",
    method: "GET",
    path: PATH,
    role: ManagementRole::Observer,
};

const SORT: &str = "occurred_at_desc,model_call_id_desc";

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
    items: Vec<ModelCallListSummary>,
    truncated: bool,
    next_cursor: Option<String>,
}

#[derive(Clone)]
struct Request {
    plan: ModelCallListPlan,
    cursor: Option<String>,
}

/// Resolves each known key exactly once before deriving the signed plan.
/// Timestamps are deliberately literal UTC RFC3339 values: rejecting alternate
/// encodings keeps the request audit vocabulary stable without interpreting
/// percent escapes differently from an intermediary.
fn parse_request(raw: Option<&str>) -> Result<Request, Failure> {
    let raw = raw.ok_or(Failure::Request)?;
    let mut start = None;
    let mut end = None;
    let mut limit = None;
    let mut cursor = None;
    for parameter in raw.split('&') {
        let (key, value) = parameter.split_once('=').ok_or(Failure::Request)?;
        if value.is_empty() {
            return Err(Failure::Request);
        }
        let slot = match key {
            "start" => &mut start,
            "end" => &mut end,
            "limit" => &mut limit,
            "cursor" => &mut cursor,
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
    let cursor = cursor
        .filter(|value| value.len() <= CURSOR_BYTES_MAX)
        .map(str::to_owned);
    let limit = limit
        .parse::<u16>()
        .ok()
        .filter(|value| value.to_string() == limit)
        .ok_or(Failure::Request)?;
    let window =
        QueryWindow::new(query_time(&start)?, query_time(&end)?).map_err(|_| Failure::Request)?;
    let plan = ModelCallListPlan::new(window, limit).map_err(|_| Failure::Request)?;
    Ok(Request { plan, cursor })
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
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    control
        .list_model_calls(
            single_header(&headers, AUTHORIZATION.as_str()),
            raw,
            body.is_ok_and(|body| body.is_empty()),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn list_model_calls(
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
                .finish_model_call_list(request_id, subject, Err(Failure::Request))
                .await;
        };
        let after = match request
            .cursor
            .as_deref()
            .map(|cursor| self.decode_model_call_list_cursor(&subject, &request.plan, cursor))
            .transpose()
        {
            Ok(after) => after,
            Err(error) => {
                return self
                    .finish_model_call_list(
                        request_id,
                        subject,
                        Err(match error {
                            CursorError::Invalid => Failure::Cursor,
                            CursorError::Unavailable => Failure::CursorUnavailable,
                        }),
                    )
                    .await;
            }
        };
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_model_call_list(request_id, subject, Err(Failure::Capacity))
                .await;
        };
        let task_request = request_id.clone();
        // Admission outlives the HTTP caller. A disconnected client must not
        // sidestep the bounded index read or mandatory terminal audit.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .run_model_call_list(&task_request, &subject, &request.plan, after.as_ref())
                .await;
            self.finish_model_call_list(task_request, subject, result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn run_model_call_list(
        self: &Arc<Self>,
        request_id: &str,
        subject: &str,
        plan: &ModelCallListPlan,
        after: Option<&ModelCallListPosition>,
    ) -> Result<ResponsePage, Failure> {
        let result = query_model_calls(
            &self.config.publisher,
            &self.index,
            &self.config.tenant_id,
            &self.config.site_id,
            plan,
            after,
        )
        .await
        .map_err(|error| Failure::from_publish(&error))?;
        // This is intentionally a separate observation from the result page.
        // It reports configured-journal health only and cannot make a list row
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
        let next_cursor = result
            .next_position
            .as_ref()
            .map(|position| self.encode_model_call_list_cursor(subject, plan, position))
            .transpose()
            .map_err(|()| Failure::CursorUnavailable)?;
        Ok(ResponsePage {
            schema_version: 3,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            start: unix_seconds_timestamp(plan.window().start())?,
            end: unix_seconds_timestamp(plan.window().end())?,
            watermark_scope: "configured_journal",
            as_of: health.as_of,
            index_watermark: health.index_watermark,
            has_gaps: health.has_gaps,
            pending_segments: health.pending_segments,
            scanned_rows: result.scanned_rows,
            scanned_bytes: result.scanned_bytes,
            items: result.model_calls,
            truncated: result.truncated,
            next_cursor,
        })
    }

    async fn finish_model_call_list(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        result: Result<ResponsePage, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = result.as_ref().map_or_else(
                |failure| failure.audit(),
                |_| ("PASS", "CONTROL_MODEL_CALLS_READ"),
            );
            // A collection is not a target-bearing access event. In particular,
            // do not turn returned model IDs into detail targets or evidence refs.
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
            Ok(page) => EndpointResult::Raw((StatusCode::OK, Json(page)).into_response()),
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

    pub(super) fn encode_model_call_list_cursor(
        &self,
        subject: &str,
        plan: &ModelCallListPlan,
        position: &ModelCallListPosition,
    ) -> Result<String, ()> {
        let timestamp = position.occurred_at().timestamp_micros();
        let signature = self.model_call_list_cursor_signature(
            subject,
            plan,
            timestamp,
            position.model_call_id(),
        )?;
        Ok(format!(
            "{CURSOR_VERSION}.{timestamp}.{}.{}",
            position.model_call_id().as_str(),
            lower_hex(&signature)
        ))
    }

    pub(super) fn decode_model_call_list_cursor(
        &self,
        subject: &str,
        plan: &ModelCallListPlan,
        cursor: &str,
    ) -> Result<ModelCallListPosition, CursorError> {
        if cursor.len() > CURSOR_BYTES_MAX {
            return Err(CursorError::Invalid);
        }
        let mut parts = cursor.split('.');
        let (Some(version), Some(timestamp), Some(model_call_id), Some(signature)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if version != CURSOR_VERSION || parts.next().is_some() {
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
        let model_call_id = ModelCallId::parse(model_call_id).map_err(|_| CursorError::Invalid)?;
        let supplied = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let expected = self
            .model_call_list_cursor_signature(subject, plan, timestamp, &model_call_id)
            .map_err(|()| CursorError::Unavailable)?;
        if !constant_time::eq(&supplied, &expected) {
            return Err(CursorError::Invalid);
        }
        ModelCallListPosition::new(occurred_at, model_call_id).map_err(|_| CursorError::Invalid)
    }

    fn model_call_list_cursor_signature(
        &self,
        subject: &str,
        plan: &ModelCallListPlan,
        timestamp: i64,
        model_call_id: &ModelCallId,
    ) -> Result<[u8; 32], ()> {
        component_signature(
            &self.config.cursor_key.0,
            &[
                b"xshield-control-model-call-list-cursor-v1",
                &self.config.credential.token_digest,
                subject.as_bytes(),
                self.config.tenant_id.as_str().as_bytes(),
                self.config.site_id.as_str().as_bytes(),
                &plan.window().start().value().to_be_bytes(),
                &plan.window().end().value().to_be_bytes(),
                &plan.limit().to_be_bytes(),
                SORT.as_bytes(),
                &timestamp.to_be_bytes(),
                model_call_id.as_str().as_bytes(),
            ],
        )
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
    Cursor,
    CursorUnavailable,
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
            Self::Request => ("DENY", "CONTROL_MODEL_CALLS_REQUEST_INVALID"),
            Self::Cursor => ("DENY", "CONTROL_CURSOR_INVALID"),
            Self::Capacity => ("DENY", "CONTROL_QUERY_CAPACITY_EXHAUSTED"),
            Self::Budget => ("DENY", "CONTROL_QUERY_BUDGET_EXCEEDED"),
            Self::CursorUnavailable => ("ERROR", "CONTROL_CURSOR_UNAVAILABLE"),
            Self::Timeout => ("ERROR", "CONTROL_QUERY_TIMEOUT"),
            Self::IndexUnavailable => ("ERROR", "CONTROL_MODEL_CALLS_INDEX_UNAVAILABLE"),
            Self::HealthUnavailable => ("ERROR", "CONTROL_MODEL_CALLS_HEALTH_UNAVAILABLE"),
        }
    }

    const fn status(self) -> StatusCode {
        match self {
            Self::Request | Self::Cursor => StatusCode::BAD_REQUEST,
            Self::Capacity | Self::Budget => StatusCode::TOO_MANY_REQUESTS,
            Self::CursorUnavailable
            | Self::Timeout
            | Self::IndexUnavailable
            | Self::HealthUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    const fn code(self) -> &'static str {
        self.audit().1
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Request => "invalid model call list request",
            Self::Cursor => "invalid pagination cursor",
            Self::CursorUnavailable => "pagination service is temporarily unavailable",
            Self::Capacity => "analytical query capacity exhausted",
            Self::Budget => "model call list exceeded its query budget",
            Self::Timeout => "model call list query timed out",
            Self::IndexUnavailable => "model call index is temporarily unavailable",
            Self::HealthUnavailable => "audit health is temporarily unavailable",
        }
    }

    const fn retryable(self) -> bool {
        !matches!(self, Self::Request | Self::Cursor | Self::Budget)
    }

    const fn next_action(self) -> &'static str {
        match self {
            Self::Request => "correct_request",
            Self::Cursor => "restart_query",
            Self::Budget => "narrow_query",
            Self::CursorUnavailable
            | Self::Capacity
            | Self::Timeout
            | Self::IndexUnavailable
            | Self::HealthUnavailable => "retry_later",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Failure, parse_request};

    #[test]
    fn request_requires_canonical_bounded_utc_window_and_limit() {
        let request = parse_request(Some(
            "start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=100",
        ))
        .unwrap();
        assert_eq!(request.plan.limit(), 100);
        assert_eq!(request.plan.window().start().value(), 1_789_776_000);
        assert!(request.cursor.is_none());
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
            "start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=101",
            "start=2026-09-19T00:00:00Z&end=2026-09-19T00:00:00Z&limit=1",
            "start=2026-09-19T00:00:00Z&end=2026-10-21T00:00:01Z&limit=1",
            "start=2026-09-19T00:00:00Z&start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=1",
            "start=2026-09-19T00:00:00Z&end=2026-09-20T00:00:00Z&limit=1&cursor=x&extra=y",
        ] {
            assert!(matches!(parse_request(Some(raw)), Err(Failure::Request)));
        }
    }

    #[test]
    fn failures_keep_stable_audit_taxonomy() {
        assert_eq!(
            Failure::Request.audit(),
            ("DENY", "CONTROL_MODEL_CALLS_REQUEST_INVALID")
        );
        assert_eq!(Failure::Cursor.audit(), ("DENY", "CONTROL_CURSOR_INVALID"));
        assert_eq!(
            Failure::IndexUnavailable.audit(),
            ("ERROR", "CONTROL_MODEL_CALLS_INDEX_UNAVAILABLE")
        );
        assert!(!Failure::Budget.retryable());
    }
}
