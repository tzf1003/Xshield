//! Scoped export discovery and the independent approval queue, with live keyset
//! pages: `GET /control/v1/exports?view=mine|review[&cursor=...]`.
//!
//! Purpose: let a requester find their own exports and let an approver find the
//! other principals' exports that still await a decision, without having to know
//! an `export_` identity beforehand. Listing is metadata only; the detail,
//! decision and download endpoints keep their own authorization.
//!
//! Invariants: tenant and site come from the authenticated principal, never the
//! request. The page size is the server's `max_query_artifacts`. Pages are
//! ordered by bytewise `export_id` descending and continued by an HMAC cursor
//! bound to credential, subject, scope, view and page size.
//!
//! Errors: stable `CONTROL_EXPORT_*` and `CONTROL_CURSOR_*` codes. Audit: every
//! authenticated attempt, including denials and dependency failures, appends one
//! `console.export.list` management event. Resource semantics: an admitted read
//! shares the case/evidence in-flight permit and keeps it through the durable
//! audit, so a client disconnect cannot release capacity before the terminal
//! audit exists.

use super::{
    AccessAction, ControlPlane, CursorError, EndpointResult, api_error, audit_unavailable,
    component_signature, exports, internal_error, lower_hex, parse_lower_hex_32, single_header,
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
use xshield_core::{admin::ManagementRole, domain::ExportId};
use xshield_postgres::{InvestigationExportListQuery, InvestigationExportListView};

/// The collection shares its path with export creation; the method differs.
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.export.list",
    method: "GET",
    path: exports::PATH,
    role: ManagementRole::Investigator,
};

const CURSOR_PURPOSE: &[u8] = b"xshield-control-export-list-v1";
// Valid cursors are 111 bytes; the cap only bounds work before HMAC parsing.
const CURSOR_PARAMETER_BYTES_MAX: usize = 256;

#[derive(Serialize)]
struct Page {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    view: &'static str,
    as_of: String,
    items: Vec<Item>,
    truncated: bool,
    next_cursor: Option<String>,
}

// Only fields the single-export response already shows its requester or
// reviewer; purpose, decision reason and every package field stay behind that
// endpoint, so a list page can never disclose them.
#[derive(Serialize)]
struct Item {
    export_id: String,
    case_id: String,
    requested_by: String,
    status: &'static str,
    requested_at: String,
    decided_by: Option<String>,
    decided_at: Option<String>,
    expires_at: Option<String>,
}

// A canonical query keeps view selection and cursor binding unambiguous. The
// signature alphabet is URL-safe, so percent decoding is deliberately unnecessary.
fn query(raw: Option<&str>) -> Result<(InvestigationExportListView, Option<&str>), Failure> {
    let raw = raw.ok_or(Failure::Request)?;
    let (view, tail) = raw
        .split_once('&')
        .map_or((raw, None), |(a, b)| (a, Some(b)));
    let view = match view {
        "view=mine" => InvestigationExportListView::Mine,
        "view=review" => InvestigationExportListView::Review,
        _ => return Err(Failure::Request),
    };
    let cursor = tail
        .map(|tail| {
            tail.strip_prefix("cursor=")
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= CURSOR_PARAMETER_BYTES_MAX
                        && !value.contains('&')
                })
                .ok_or(Failure::Request)
        })
        .transpose()?;
    Ok((view, cursor))
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    control
        .list_exports(
            single_header(&headers, AUTHORIZATION.as_str()),
            raw,
            body.is_ok_and(|body| body.is_empty()),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn list_exports(
        self: Arc<Self>,
        authorization: Option<String>,
        raw: Option<String>,
        empty: bool,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let parsed = query(raw.as_deref());
        // Only an approver may open the review queue. A malformed query is
        // authorized against the wider own-history set and rejected afterwards,
        // so it never reveals more than a well-formed `mine` request would.
        let roles = if matches!(&parsed, Ok((InvestigationExportListView::Review, _))) {
            vec![ManagementRole::SensitiveEvidenceApprover]
        } else {
            vec![
                ManagementRole::SensitiveEvidenceApprover,
                ManagementRole::SensitiveEvidenceReader,
                ManagementRole::Investigator,
            ]
        };
        let auth_control = Arc::clone(&self);
        let auth_request = request_id.clone();
        let identity = match tokio::task::spawn_blocking(move || {
            auth_control.authorize_any_identity(
                authorization.as_deref(),
                &auth_request,
                ACCESS,
                &roles,
            )
        })
        .await
        {
            Ok(Ok(identity)) => identity,
            Ok(Err(result)) => return *result,
            Err(_) => return internal_error(&request_id),
        };
        let subject = identity.principal.subject().to_owned();
        let (view, cursor) = match parsed {
            Ok(value) if empty => value,
            _ => {
                return self
                    .finish_export_list(request_id, subject, Err(Failure::Request))
                    .await;
            }
        };
        let before = match cursor
            .map(|cursor| self.decode_export_list_cursor(&subject, view, cursor))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => {
                return self
                    .finish_export_list(
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
                .finish_export_list(request_id, subject, Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // The task, not the connection, owns the permit: a disconnected client
        // cannot abort the database read or the terminal audit that follows it.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .export_list_page(&task_request, &subject, view, before.as_ref())
                .await;
            self.finish_export_list(task_request, subject, result).await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn export_list_page(
        &self,
        request_id: &str,
        subject: &str,
        view: InvestigationExportListView,
        before: Option<&ExportId>,
    ) -> Result<Page, Failure> {
        let query = InvestigationExportListQuery::new(
            &self.config.tenant_id,
            &self.config.site_id,
            subject,
            view,
            before,
            self.config.limits.max_query_artifacts,
        )
        .map_err(|_| Failure::Store)?;
        let page = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.list_investigation_exports(query),
        )
        .await
        .map_err(|_| Failure::Store)?
        .map_err(|_| Failure::Store)?;
        let next_cursor = page
            .next_export_id()
            .map(|id| self.encode_export_list_cursor(subject, view, id))
            .transpose()
            .map_err(|()| Failure::CursorUnavailable)?;
        // Items use the single-export response precision (milliseconds) so a
        // list value and its detail value compare equal; only the database
        // observation time keeps microseconds, like every other list.
        let millis = |value: chrono::DateTime<chrono::Utc>| {
            value.to_rfc3339_opts(SecondsFormat::Millis, true)
        };
        Ok(Page {
            schema_version: 3,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            view: view.as_str(),
            as_of: page.as_of().to_rfc3339_opts(SecondsFormat::Micros, true),
            items: page
                .items()
                .iter()
                .map(|item| Item {
                    export_id: item.export_id().as_str().to_owned(),
                    case_id: item.case_id().as_str().to_owned(),
                    requested_by: item.requested_by().to_owned(),
                    status: item.status(),
                    requested_at: millis(item.requested_at()),
                    decided_by: item.decided_by().map(str::to_owned),
                    decided_at: item.decided_at().map(millis),
                    expires_at: item.expires_at().map(millis),
                })
                .collect(),
            truncated: next_cursor.is_some(),
            next_cursor,
        })
    }

    async fn finish_export_list(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        result: Result<Page, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = result.as_ref().map_or_else(
                |error| (error.outcome(), error.code()),
                |_| ("PASS", "CONTROL_EXPORTS_READ"),
            );
            // The event carries the caller and the outcome only: the view, the
            // cursor and every listed export or principal stay out of the journal.
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

    pub(super) fn encode_export_list_cursor(
        &self,
        subject: &str,
        view: InvestigationExportListView,
        id: &ExportId,
    ) -> Result<String, ()> {
        Ok(format!(
            "v1.{}.{}",
            id.as_str(),
            lower_hex(&self.export_list_signature(subject, view, id)?)
        ))
    }

    pub(super) fn decode_export_list_cursor(
        &self,
        subject: &str,
        view: InvestigationExportListView,
        cursor: &str,
    ) -> Result<ExportId, CursorError> {
        let mut parts = cursor.split('.');
        let (Some("v1"), Some(id), Some(signature)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if parts.next().is_some() {
            return Err(CursorError::Invalid);
        }
        let id = ExportId::parse(id).map_err(|_| CursorError::Invalid)?;
        let supplied = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let expected = self
            .export_list_signature(subject, view, &id)
            .map_err(|()| CursorError::Unavailable)?;
        if !constant_time::eq(&supplied, &expected) {
            return Err(CursorError::Invalid);
        }
        Ok(id)
    }

    fn export_list_signature(
        &self,
        subject: &str,
        view: InvestigationExportListView,
        id: &ExportId,
    ) -> Result<[u8; 32], ()> {
        component_signature(
            &self.config.cursor_key.0,
            &[
                CURSOR_PURPOSE,
                &self.config.credential.token_digest,
                subject.as_bytes(),
                self.config.tenant_id.as_str().as_bytes(),
                self.config.site_id.as_str().as_bytes(),
                view.as_str().as_bytes(),
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

    // Input, permission and capacity refusals are denials; a failed dependency
    // is an error, matching the management audit contract (docs 29.4).
    fn outcome(self) -> &'static str {
        if self.status().is_server_error() {
            "ERROR"
        } else {
            "DENY"
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Request => "CONTROL_EXPORT_LIST_REQUEST_INVALID",
            Self::Cursor => "CONTROL_CURSOR_INVALID",
            Self::CursorUnavailable => "CONTROL_CURSOR_UNAVAILABLE",
            Self::Store => "CONTROL_EXPORT_STORE_UNAVAILABLE",
            Self::Busy => "CONTROL_EXPORT_BUSY",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Request => "invalid export list request",
            Self::Cursor => "invalid pagination cursor",
            Self::CursorUnavailable => "pagination service is temporarily unavailable",
            Self::Store => "export service is temporarily unavailable",
            Self::Busy => "export operation is already in progress",
        }
    }
}

/// Every failure this endpoint records itself, as the (outcome, reason) its
/// audit event carries, so the publisher contract can be checked against the
/// producer's own table instead of a copy of it.
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
    use super::{Failure, InvestigationExportListView as View, query, recorded_failures};
    use axum::http::StatusCode;

    #[test]
    fn failures_map_to_stable_status_outcome_and_reason_codes() {
        assert_eq!(
            recorded_failures(),
            [
                ("DENY", "CONTROL_EXPORT_LIST_REQUEST_INVALID"),
                ("DENY", "CONTROL_CURSOR_INVALID"),
                ("ERROR", "CONTROL_CURSOR_UNAVAILABLE"),
                ("ERROR", "CONTROL_EXPORT_STORE_UNAVAILABLE"),
                ("DENY", "CONTROL_EXPORT_BUSY"),
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
            assert!(!failure.message().contains("export_"));
        }
    }

    // The signature alphabet is URL-safe, so a canonical cursor never needs decoding.
    const CURSOR: &str = "v1.export_018f2a3b-4c5d-7000-8000-000000000001.aa";

    #[test]
    fn canonical_queries_select_exactly_one_view_and_optional_cursor() {
        assert!(matches!(query(Some("view=mine")), Ok((View::Mine, None))));
        assert!(matches!(
            query(Some("view=review")),
            Ok((View::Review, None))
        ));
        let with_cursor = format!("view=review&cursor={CURSOR}");
        assert!(matches!(
            query(Some(with_cursor.as_str())),
            Ok((View::Review, Some(CURSOR)))
        ));
        let longest = format!("view=mine&cursor={}", "a".repeat(256));
        assert!(matches!(
            query(Some(longest.as_str())),
            Ok((View::Mine, Some(_)))
        ));
    }

    #[test]
    fn every_other_shape_is_a_request_error_before_any_lookup() {
        let too_long = format!("view=mine&cursor={}", "a".repeat(257));
        for raw in [
            None,
            Some(""),
            Some("?"),
            Some("view="),
            Some("view"),
            Some("view=all"),
            Some("view=Mine"),
            Some("view=MINE"),
            Some("view=mine "),
            Some(" view=mine"),
            Some("view=%6dine"),
            Some("view=mine&"),
            Some("view=mine&cursor="),
            Some("view=mine&cursor"),
            Some("cursor=a&view=mine"),
            Some("view=mine&view=review"),
            Some("view=mine&cursor=a&cursor=b"),
            Some("view=mine&cursor=a&limit=2"),
            Some("view=mine&limit=2"),
            Some("view=mine&Cursor=a"),
            Some("view=review&tenant_id=other"),
            Some("view=review&site_id=other"),
            Some(too_long.as_str()),
        ] {
            assert!(
                matches!(query(raw), Err(Failure::Request)),
                "accepted {raw:?}"
            );
        }
    }
}
