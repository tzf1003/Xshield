//! Owner-scoped durable job discovery with keyset pages:
//! `GET /control/v1/jobs[?cursor=...]`.
//!
//! Purpose: let an investigator find the `job_` identities they created without
//! knowing them in advance. Each row is the same projection the single-job read
//! returns to the same owner; listing grants no other authority.
//!
//! Invariants: tenant and site come from the authenticated principal, never the
//! request. The page size is the server's `max_query_artifacts`. Pages are ordered
//! by bytewise `job_id` descending and continued by an HMAC cursor bound to
//! credential, subject, scope and page size.
//!
//! Errors: stable `CONTROL_JOB_LIST_*` and `CONTROL_CURSOR_*` codes. Audit: every
//! authenticated attempt, including denials and dependency failures, appends one
//! `console.job.list` management event. Resource semantics: an admitted read shares
//! the case/evidence in-flight permit and keeps it through the durable audit.

use super::{
    AccessAction, ControlPlane, CursorError, EndpointResult, api_error, audit_unavailable,
    component_signature, internal_error, lower_hex, parse_lower_hex_32, single_header,
};
use axum::{
    Json,
    body::Bytes,
    extract::{RawQuery, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::constant_time;
use xshield_core::{admin::ManagementRole, domain::JobId};
use xshield_postgres::{ControlJobListPage, ControlJobListQuery};

/// The collection shares its path prefix with the single-job read; methods differ.
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.job.list",
    method: "GET",
    path: PATH,
    role: ManagementRole::Investigator,
};

/// Collection route; the single-job route is `jobs::PATH`.
pub(super) const PATH: &str = "/control/v1/jobs";

const CURSOR_PURPOSE: &[u8] = b"xshield-control-job-list-v1";
// Valid cursors are 111 bytes; the cap only bounds work before HMAC parsing.
const CURSOR_PARAMETER_BYTES_MAX: usize = 256;

#[derive(Serialize)]
struct Page {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    as_of: String,
    items: Vec<Item>,
    truncated: bool,
    next_cursor: Option<String>,
}

// The same fields the single-job read returns to its owner; the owner reference
// itself stays internal because the requester is already the owner.
#[derive(Serialize)]
struct Item {
    job_id: String,
    kind: &'static str,
    status: &'static str,
    checkpoint: String,
    reason_code: String,
    retryable: bool,
    case_id: String,
    artifact_count: i64,
    active_artifact_count: i64,
    created_at: String,
    updated_at: String,
    completed_at: Option<String>,
}

// Only `cursor` is accepted. A canonical query keeps cursor binding unambiguous;
// the signature alphabet is URL-safe, so percent decoding is unnecessary.
fn query(raw: Option<&str>) -> Result<Option<&str>, Failure> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let cursor = raw
        .strip_prefix("cursor=")
        .filter(|value| {
            !value.is_empty() && value.len() <= CURSOR_PARAMETER_BYTES_MAX && !value.contains('&')
        })
        .ok_or(Failure::Request)?;
    Ok(Some(cursor))
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    control
        .list_jobs(
            single_header(&headers, AUTHORIZATION.as_str()),
            raw,
            body.is_ok_and(|body| body.is_empty()),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn list_jobs(
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
        let cursor = match query(raw.as_deref()) {
            Ok(cursor) if empty => cursor,
            _ => {
                return self
                    .finish_job_list(request_id, subject, Err(Failure::Request))
                    .await;
            }
        };
        let before = match cursor
            .map(|cursor| self.decode_job_list_cursor(&subject, cursor))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => {
                return self
                    .finish_job_list(
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
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .finish_job_list(request_id, subject, Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // The task, not the connection, owns the permit: a disconnected client
        // cannot abort the database read or the terminal audit that follows it.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .job_list_page(&task_request, &subject, before.as_ref())
                .await;
            self.finish_job_list(task_request, subject, result).await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn job_list_page(
        &self,
        request_id: &str,
        subject: &str,
        before: Option<&JobId>,
    ) -> Result<Page, Failure> {
        let query = ControlJobListQuery::new(
            &self.config.tenant_id,
            &self.config.site_id,
            subject,
            before,
            self.config.limits.max_query_artifacts,
        )
        .map_err(|_| Failure::Store)?;
        let page: ControlJobListPage = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.list_control_jobs(query),
        )
        .await
        .map_err(|_| Failure::Store)?
        .map_err(|_| Failure::Store)?;
        let next_cursor = page
            .next_job_id()
            .map(|id| self.encode_job_list_cursor(subject, id))
            .transpose()
            .map_err(|()| Failure::CursorUnavailable)?;
        let millis = |value: chrono::DateTime<chrono::Utc>| {
            value.to_rfc3339_opts(SecondsFormat::Millis, true)
        };
        Ok(Page {
            schema_version: 1,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            as_of: page.as_of().to_rfc3339_opts(SecondsFormat::Micros, true),
            items: page
                .items()
                .iter()
                .map(|record| Item {
                    job_id: record.job_id().as_str().to_owned(),
                    kind: record.kind(),
                    status: record.status(),
                    checkpoint: record.checkpoint().to_owned(),
                    reason_code: record.reason_code().to_owned(),
                    retryable: record.retryable(),
                    case_id: record.case_id().as_str().to_owned(),
                    artifact_count: record.artifact_count(),
                    active_artifact_count: record.active_artifact_count(),
                    created_at: millis(record.created_at()),
                    updated_at: millis(record.updated_at()),
                    completed_at: record.completed_at().map(millis),
                })
                .collect(),
            truncated: next_cursor.is_some(),
            next_cursor,
        })
    }

    async fn finish_job_list(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        result: Result<Page, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = result.as_ref().map_or_else(
                |error| (error.outcome(), error.code()),
                |_| ("PASS", "CONTROL_JOBS_READ"),
            );
            // The event carries the caller and the outcome only: the cursor and
            // every listed job stay out of the journal.
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
            Err(error) => api_error(
                &request_id,
                error.status(),
                error.code(),
                error.message(),
                !matches!(error, Failure::Request | Failure::Cursor),
                if matches!(error, Failure::Request | Failure::Cursor) {
                    "restart_query"
                } else {
                    "retry_later"
                },
            ),
        }
    }

    pub(super) fn encode_job_list_cursor(&self, subject: &str, id: &JobId) -> Result<String, ()> {
        Ok(format!(
            "v1.{}.{}",
            id.as_str(),
            lower_hex(&self.job_list_signature(subject, id)?)
        ))
    }

    pub(super) fn decode_job_list_cursor(
        &self,
        subject: &str,
        cursor: &str,
    ) -> Result<JobId, CursorError> {
        let mut parts = cursor.split('.');
        let (Some("v1"), Some(id), Some(signature)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if parts.next().is_some() {
            return Err(CursorError::Invalid);
        }
        let id = JobId::parse(id).map_err(|_| CursorError::Invalid)?;
        let supplied = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let expected = self
            .job_list_signature(subject, &id)
            .map_err(|()| CursorError::Unavailable)?;
        if !constant_time::eq(&supplied, &expected) {
            return Err(CursorError::Invalid);
        }
        Ok(id)
    }

    fn job_list_signature(&self, subject: &str, id: &JobId) -> Result<[u8; 32], ()> {
        component_signature(
            &self.config.cursor_key.0,
            &[
                CURSOR_PURPOSE,
                &self.config.credential.token_digest,
                subject.as_bytes(),
                self.config.tenant_id.as_str().as_bytes(),
                self.config.site_id.as_str().as_bytes(),
                &self.config.limits.max_query_artifacts.to_be_bytes(),
                id.as_str().as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Request,
    Cursor,
    CursorUnavailable,
    Store,
    Busy,
}

impl Failure {
    fn status(self) -> StatusCode {
        match self {
            Self::Request | Self::Cursor => StatusCode::BAD_REQUEST,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
            Self::Store | Self::CursorUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn outcome(self) -> &'static str {
        if self.status().is_server_error() {
            "ERROR"
        } else {
            "DENY"
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Request => "CONTROL_JOB_LIST_REQUEST_INVALID",
            Self::Cursor => "CONTROL_CURSOR_INVALID",
            Self::CursorUnavailable => "CONTROL_CURSOR_UNAVAILABLE",
            Self::Store => "CONTROL_JOB_STORE_UNAVAILABLE",
            Self::Busy => "CONTROL_JOB_LIST_BUSY",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Request => "invalid job list request",
            Self::Cursor => "invalid pagination cursor",
            Self::CursorUnavailable => "pagination service is temporarily unavailable",
            Self::Store => "job service is temporarily unavailable",
            Self::Busy => "job list operation is already in progress",
        }
    }
}

/// Every failure this endpoint records itself, as the (outcome, reason) its
/// audit event carries, so the publisher contract is checked against the
/// producer's own table.
#[cfg(test)]
pub(super) fn recorded_failures() -> Vec<(&'static str, &'static str)> {
    [
        Failure::Request,
        Failure::Cursor,
        Failure::CursorUnavailable,
        Failure::Store,
        Failure::Busy,
    ]
    .into_iter()
    .map(|failure| (failure.outcome(), failure.code()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{Failure, query, recorded_failures};
    use axum::http::StatusCode;

    #[test]
    fn failures_map_to_stable_status_outcome_and_reason_codes() {
        assert_eq!(
            recorded_failures(),
            [
                ("DENY", "CONTROL_JOB_LIST_REQUEST_INVALID"),
                ("DENY", "CONTROL_CURSOR_INVALID"),
                ("ERROR", "CONTROL_CURSOR_UNAVAILABLE"),
                ("ERROR", "CONTROL_JOB_STORE_UNAVAILABLE"),
                ("DENY", "CONTROL_JOB_LIST_BUSY"),
            ]
        );
        for (failure, status) in [
            (Failure::Request, StatusCode::BAD_REQUEST),
            (Failure::Cursor, StatusCode::BAD_REQUEST),
            (Failure::CursorUnavailable, StatusCode::SERVICE_UNAVAILABLE),
            (Failure::Store, StatusCode::SERVICE_UNAVAILABLE),
            (Failure::Busy, StatusCode::TOO_MANY_REQUESTS),
        ] {
            assert_eq!(failure.status(), status, "{}", failure.code());
            assert!(!failure.message().is_empty());
            // Client-safe wording never echoes SQL, identifiers or the scope.
            assert!(!failure.message().contains("job_"));
        }
    }

    const CURSOR: &str = "v1.job_018f2a3b-4c5d-7000-8000-000000000001.aa";

    #[test]
    fn canonical_queries_accept_no_parameters_or_one_cursor() {
        assert!(matches!(query(None), Ok(None)));
        assert!(matches!(
            query(Some(&format!("cursor={CURSOR}"))),
            Ok(Some(CURSOR))
        ));
        let longest = format!("cursor={}", "a".repeat(256));
        assert!(matches!(query(Some(&longest)), Ok(Some(_))));
        // A non-canonical value is not a request error here: its signature check
        // rejects it later as CONTROL_CURSOR_INVALID, after the owner is known.
        assert!(matches!(query(Some("cursor=%61")), Ok(Some("%61"))));
    }

    #[test]
    fn every_other_shape_is_a_request_error_before_any_lookup() {
        let too_long = format!("cursor={}", "a".repeat(257));
        for raw in [
            Some(""),
            Some("?"),
            Some("cursor="),
            Some("cursor"),
            Some("Cursor=a"),
            Some("view=mine"),
            Some("cursor=a&limit=2"),
            Some("cursor=a&cursor=b"),
            Some("limit=2"),
            Some(" cursor=a"),
            Some(too_long.as_str()),
        ] {
            assert!(
                matches!(query(raw), Err(Failure::Request)),
                "accepted {raw:?}"
            );
        }
    }
}
