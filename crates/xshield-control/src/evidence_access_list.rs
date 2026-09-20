//! Scoped request discovery and independent-review queue, with live keyset pages.
//! Each admitted read retains capacity through its durable management audit.

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
use openssl::memcmp;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::{admin::ManagementRole, domain::EvidenceAccessRequestId};
use xshield_postgres::{EvidenceAccessListQuery, EvidenceAccessListView};

pub(super) const PATH: &str = "/control/v1/evidence-access-requests";
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.evidence.access.list",
    method: "GET",
    path: PATH,
    role: ManagementRole::Investigator,
};

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
#[derive(Serialize)]
struct Item {
    access_request_id: String,
    case_id: String,
    artifact_id: String,
    requested_by: String,
    access_kind: &'static str,
    stored_status: &'static str,
    requested_at: String,
    requested_event_id: String,
}

// A canonical query keeps view selection and cursor binding unambiguous. The
// signature alphabet is URL-safe, so percent decoding is deliberately unnecessary.
fn query(raw: Option<&str>) -> Result<(EvidenceAccessListView, Option<&str>), Failure> {
    let raw = raw.ok_or(Failure::Request)?;
    let (view, tail) = raw
        .split_once('&')
        .map_or((raw, None), |(a, b)| (a, Some(b)));
    let view = match view {
        "view=mine" => EvidenceAccessListView::Mine,
        "view=review" => EvidenceAccessListView::Review,
        _ => return Err(Failure::Request),
    };
    let cursor = tail
        .map(|tail| {
            tail.strip_prefix("cursor=")
                .filter(|value| !value.is_empty() && value.len() <= 256 && !value.contains('&'))
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
        .list_access(
            single_header(&headers, AUTHORIZATION.as_str()),
            raw,
            body.is_ok_and(|body| body.is_empty()),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn list_access(
        self: Arc<Self>,
        authorization: Option<String>,
        raw: Option<String>,
        empty: bool,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let parsed = query(raw.as_deref());
        let role = if matches!(&parsed, Ok((EvidenceAccessListView::Review, _))) {
            ManagementRole::SensitiveEvidenceApprover
        } else {
            [
                ManagementRole::SensitiveEvidenceApprover,
                ManagementRole::SensitiveEvidenceReader,
                ManagementRole::Investigator,
            ]
            .into_iter()
            .find(|role| {
                self.config.principal.authorizes(
                    *role,
                    &self.config.tenant_id,
                    &self.config.site_id,
                )
            })
            .unwrap_or(ManagementRole::Investigator)
        };
        let auth_control = Arc::clone(&self);
        let auth_request = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(
                authorization.as_deref(),
                &auth_request,
                AccessAction { role, ..ACCESS },
            )
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(result)) => return *result,
            Err(_) => return internal_error(&request_id),
        };
        let (view, cursor) = match parsed {
            Ok(value) if empty => value,
            _ => {
                return self
                    .finish_access_list(request_id, subject, Err(Failure::Request))
                    .await;
            }
        };
        let before = match cursor
            .map(|cursor| self.decode_access_list_cursor(&subject, view, cursor))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => {
                return self
                    .finish_access_list(
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
                .finish_access_list(request_id, subject, Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .access_list_page(&task_request, &subject, view, before.as_ref())
                .await;
            self.finish_access_list(task_request, subject, result).await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn access_list_page(
        &self,
        request_id: &str,
        subject: &str,
        view: EvidenceAccessListView,
        before: Option<&EvidenceAccessRequestId>,
    ) -> Result<Page, Failure> {
        let query = EvidenceAccessListQuery::new(
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
            self.catalog.list_evidence_access_requests(query),
        )
        .await
        .map_err(|_| Failure::Store)?
        .map_err(|_| Failure::Store)?;
        let next_cursor = page
            .next_access_request_id()
            .map(|id| self.encode_access_list_cursor(subject, view, id))
            .transpose()
            .map_err(|()| Failure::CursorUnavailable)?;
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
                    access_request_id: item.access_request_id.as_str().to_owned(),
                    case_id: item.case_id.as_str().to_owned(),
                    artifact_id: item.artifact_id.as_str().to_owned(),
                    requested_by: item.requested_by.clone(),
                    access_kind: item.access_kind.as_str(),
                    stored_status: item.stored_status,
                    requested_at: item
                        .requested_at
                        .to_rfc3339_opts(SecondsFormat::Micros, true),
                    requested_event_id: item.requested_event_id.as_str().to_owned(),
                })
                .collect(),
            truncated: next_cursor.is_some(),
            next_cursor,
        })
    }

    async fn finish_access_list(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        result: Result<Page, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = result.as_ref().map_or_else(
                |error| {
                    (
                        if error.status().is_server_error() {
                            "ERROR"
                        } else {
                            "DENY"
                        },
                        error.code(),
                    )
                },
                |_| ("PASS", "CONTROL_EVIDENCE_ACCESS_LIST_READ"),
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

    pub(super) fn encode_access_list_cursor(
        &self,
        subject: &str,
        view: EvidenceAccessListView,
        id: &EvidenceAccessRequestId,
    ) -> Result<String, ()> {
        Ok(format!(
            "v1.{}.{}",
            id.as_str(),
            lower_hex(&self.access_list_signature(subject, view, id)?)
        ))
    }
    pub(super) fn decode_access_list_cursor(
        &self,
        subject: &str,
        view: EvidenceAccessListView,
        cursor: &str,
    ) -> Result<EvidenceAccessRequestId, CursorError> {
        let mut parts = cursor.split('.');
        let (Some("v1"), Some(id), Some(signature)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if parts.next().is_some() {
            return Err(CursorError::Invalid);
        }
        let id = EvidenceAccessRequestId::parse(id).map_err(|_| CursorError::Invalid)?;
        let supplied = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let expected = self
            .access_list_signature(subject, view, &id)
            .map_err(|()| CursorError::Unavailable)?;
        if !memcmp::eq(&supplied, &expected) {
            return Err(CursorError::Invalid);
        }
        Ok(id)
    }
    fn access_list_signature(
        &self,
        subject: &str,
        view: EvidenceAccessListView,
        id: &EvidenceAccessRequestId,
    ) -> Result<[u8; 32], ()> {
        component_signature(
            &self.config.cursor_key.0,
            &[
                b"xshield-control-evidence-access-list-v1",
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
    fn code(self) -> &'static str {
        match self {
            Self::Request => "CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID",
            Self::Cursor => "CONTROL_CURSOR_INVALID",
            Self::CursorUnavailable => "CONTROL_CURSOR_UNAVAILABLE",
            Self::Store => "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE",
            Self::Busy => "CONTROL_EVIDENCE_ACCESS_BUSY",
        }
    }
    fn message(self) -> &'static str {
        match self {
            Self::Request => "invalid evidence access list request",
            Self::Cursor => "invalid pagination cursor",
            Self::CursorUnavailable => "pagination service is temporarily unavailable",
            Self::Store => "evidence access request store is temporarily unavailable",
            Self::Busy => "evidence access operation is already in progress",
        }
    }
}
