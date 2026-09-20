//! Investigator-owned case pages with scoped cursors and durable access audit.
//! Each page observes current database state and grants no evidence capability.

use super::{
    AccessAction, CASES_PATH, CURSOR_VERSION, ControlPlane, CursorError, EndpointResult, api_error,
    audit_unavailable, component_signature, internal_error, lower_hex, parse_cursor_query,
    parse_lower_hex_32,
};
use axum::{
    Json,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;
use openssl::memcmp;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::{admin::ManagementRole, domain::CaseId};
use xshield_postgres::InvestigationCaseQuery;

pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.case.list",
    method: "GET",
    path: CASES_PATH,
    role: ManagementRole::Investigator,
};

#[derive(Serialize)]
struct ListResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    as_of: String,
    items: Vec<CaseResponse>,
    truncated: bool,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct CaseResponse {
    case_id: String,
    status: String,
    purpose: String,
    created_at: String,
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let authorization = values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    control
        .read_cases(authorization, query)
        .await
        .into_response()
}

impl ControlPlane {
    async fn read_cases(
        self: Arc<Self>,
        authorization: Option<String>,
        query: Option<String>,
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
        let before = match parse_cursor_query(query.as_deref()).and_then(|cursor| {
            cursor
                .map(|cursor| self.decode_cases_cursor(&subject, cursor))
                .transpose()
        }) {
            Ok(before) => before,
            Err(error) => {
                return self
                    .finish_case_list(
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
                .finish_case_list(request_id, subject, Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // A disconnected caller cannot release admission before the bounded
        // database read and its mandatory audit have reached a terminal result.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .query_cases(&task_request, &subject, before.as_ref())
                .await;
            self.finish_case_list(task_request, subject, result).await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn query_cases(
        &self,
        request_id: &str,
        subject: &str,
        before: Option<&CaseId>,
    ) -> Result<ListResponse, Failure> {
        let query = InvestigationCaseQuery::new(
            &self.config.tenant_id,
            &self.config.site_id,
            subject,
            before,
            self.config.limits.max_query_artifacts,
        )
        .map_err(|_| Failure::Store)?;
        let page = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.list_investigation_cases(query),
        )
        .await
        .map_err(|_| Failure::Store)?
        .map_err(|_| Failure::Store)?;
        let next_cursor = page
            .next_case_id()
            .map(|case| self.encode_cases_cursor(subject, case))
            .transpose()
            .map_err(|()| Failure::CursorUnavailable)?;
        Ok(ListResponse {
            schema_version: 3,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            as_of: page.as_of().to_rfc3339_opts(SecondsFormat::Micros, true),
            items: page
                .items()
                .iter()
                .map(|case| CaseResponse {
                    case_id: case.case_id().as_str().to_owned(),
                    status: case.status().to_owned(),
                    purpose: case.purpose().to_owned(),
                    created_at: case
                        .created_at()
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                })
                .collect(),
            truncated: next_cursor.is_some(),
            next_cursor,
        })
    }

    async fn finish_case_list(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        result: Result<ListResponse, Failure>,
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
                |_| ("PASS", "CONTROL_CASES_READ"),
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
            Ok(response) => EndpointResult::Raw((StatusCode::OK, Json(response)).into_response()),
            Err(error) => api_error(
                &request_id,
                error.status(),
                error.code(),
                error.message(),
                !matches!(error, Failure::Cursor),
                if matches!(error, Failure::Cursor) {
                    "restart_query"
                } else {
                    "retry_later"
                },
            ),
        }
    }

    pub(super) fn encode_cases_cursor(&self, subject: &str, case: &CaseId) -> Result<String, ()> {
        let signature = self.cases_cursor_signature(subject, case)?;
        Ok(format!(
            "{CURSOR_VERSION}.{}.{}",
            case.as_str(),
            lower_hex(&signature)
        ))
    }

    pub(super) fn decode_cases_cursor(
        &self,
        subject: &str,
        cursor: &str,
    ) -> Result<CaseId, CursorError> {
        let mut parts = cursor.split('.');
        let (Some(version), Some(case), Some(signature)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if version != CURSOR_VERSION || parts.next().is_some() {
            return Err(CursorError::Invalid);
        }
        let case = CaseId::parse(case).map_err(|_| CursorError::Invalid)?;
        let supplied = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let expected = self
            .cases_cursor_signature(subject, &case)
            .map_err(|()| CursorError::Unavailable)?;
        if !memcmp::eq(&supplied, &expected) {
            return Err(CursorError::Invalid);
        }
        Ok(case)
    }

    fn cases_cursor_signature(&self, subject: &str, case: &CaseId) -> Result<[u8; 32], ()> {
        component_signature(
            &self.config.cursor_key.0,
            &[
                b"xshield-control-cases-cursor-v1",
                &self.config.credential.token_digest,
                subject.as_bytes(),
                self.config.tenant_id.as_str().as_bytes(),
                self.config.site_id.as_str().as_bytes(),
                &self.config.limits.max_query_artifacts.to_be_bytes(),
                case.as_str().as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Cursor,
    CursorUnavailable,
    Store,
    Busy,
}

impl Failure {
    fn status(self) -> StatusCode {
        match self {
            Self::Cursor => StatusCode::BAD_REQUEST,
            Self::CursorUnavailable | Self::Store => StatusCode::SERVICE_UNAVAILABLE,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
        }
    }
    fn code(self) -> &'static str {
        match self {
            Self::Cursor => "CONTROL_CURSOR_INVALID",
            Self::CursorUnavailable => "CONTROL_CURSOR_UNAVAILABLE",
            Self::Store => "CONTROL_CASE_STORE_UNAVAILABLE",
            Self::Busy => "CONTROL_CASE_BUSY",
        }
    }
    fn message(self) -> &'static str {
        match self {
            Self::Cursor => "invalid pagination cursor",
            Self::CursorUnavailable => "pagination service is temporarily unavailable",
            Self::Store => "case store is temporarily unavailable",
            Self::Busy => "case operation is already in progress",
        }
    }
}
