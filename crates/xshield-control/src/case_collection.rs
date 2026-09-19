//! Owned case evidence browsing with scoped cursors and mandatory access audit.
//! Catalog availability is metadata, not vault verification or a content grant.

use super::{
    AccessAction, CURSOR_VERSION, ControlPlane, CursorError, EndpointResult, api_error,
    audit_unavailable, case_items, component_signature, internal_error, lower_hex,
    parse_cursor_query, parse_lower_hex_32,
};
use axum::{
    Json,
    extract::{Path, RawQuery, State, rejection::PathRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;
use openssl::memcmp;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole,
    domain::{ArtifactId, CaseId},
};
use xshield_postgres::CaseEvidenceQuery;

const ACCESS: AccessAction = AccessAction {
    event_type: "console.case.read",
    method: "GET",
    path: case_items::PATH,
    role: ManagementRole::Investigator,
};

#[derive(Serialize)]
struct CollectionResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    case: CaseResponse,
    as_of: String,
    items: Vec<ItemResponse>,
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

#[derive(Serialize)]
struct ItemResponse {
    artifact_id: String,
    added_by: String,
    added_at: String,
    catalog_status: &'static str,
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    case_id: Result<Path<String>, PathRejection>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    control
        .read_case_collection(authorization, case_id.ok().map(|Path(id)| id), query)
        .await
        .into_response()
}

impl ControlPlane {
    async fn read_case_collection(
        self: Arc<Self>,
        authorization: Option<String>,
        target: Option<String>,
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
        let Some(case_id) = target.and_then(|id| CaseId::parse(id).ok()) else {
            return self
                .finish_case_collection(request_id, subject, None, Err(Failure::CaseId))
                .await;
        };
        let after = match parse_cursor_query(query.as_deref()).and_then(|cursor| {
            cursor
                .map(|cursor| self.decode_case_cursor(&subject, &case_id, cursor))
                .transpose()
        }) {
            Ok(after) => after,
            Err(error) => {
                return self
                    .finish_case_collection(
                        request_id,
                        subject,
                        Some(case_id),
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
                .finish_case_collection(request_id, subject, Some(case_id), Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // The shared case budget survives a disconnected caller until the
        // bounded query and its access audit have reached a terminal result.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self
                .query_case_collection(&task_request, &subject, &case_id, after.as_ref())
                .await;
            self.finish_case_collection(task_request, subject, Some(case_id), result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn query_case_collection(
        &self,
        request_id: &str,
        subject: &str,
        case_id: &CaseId,
        after: Option<&ArtifactId>,
    ) -> Result<CollectionResponse, Failure> {
        let query = CaseEvidenceQuery::new(
            &self.config.tenant_id,
            &self.config.site_id,
            case_id,
            subject,
            after,
            self.config.limits.max_query_artifacts,
        )
        .map_err(|_| Failure::Store)?;
        let page = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.list_case_evidence(query),
        )
        .await
        .map_err(|_| Failure::Store)?
        .map_err(|_| Failure::Store)?
        .ok_or(Failure::Target)?;
        let next_cursor = page
            .next_artifact_id()
            .map(|artifact| self.encode_case_cursor(subject, case_id, artifact))
            .transpose()
            .map_err(|()| Failure::CursorUnavailable)?;
        Ok(CollectionResponse {
            schema_version: 3,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            case: CaseResponse {
                case_id: page.case().case_id().as_str().to_owned(),
                status: page.case().status().to_owned(),
                purpose: page.case().purpose().to_owned(),
                created_at: page
                    .case()
                    .created_at()
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
            },
            as_of: page.as_of().to_rfc3339_opts(SecondsFormat::Micros, true),
            items: page
                .items()
                .iter()
                .map(|item| ItemResponse {
                    artifact_id: item.record().artifact_id().as_str().to_owned(),
                    added_by: item.record().added_by().to_owned(),
                    added_at: item
                        .record()
                        .added_at()
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                    catalog_status: item.availability().as_str(),
                })
                .collect(),
            truncated: next_cursor.is_some(),
            next_cursor,
        })
    }

    async fn finish_case_collection(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        target: Option<CaseId>,
        result: Result<CollectionResponse, Failure>,
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
                |_| ("PASS", "CONTROL_CASE_EVIDENCE_READ"),
            );
            let refs = result
                .as_ref()
                .map(|page| {
                    page.items
                        .iter()
                        .map(|item| item.artifact_id.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            self.append_access_event_with_evidence(
                &audit_request,
                Some(&subject),
                ACCESS,
                None,
                None,
                target.as_ref(),
                None,
                outcome,
                reason,
                &refs,
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
                matches!(
                    error,
                    Failure::Store | Failure::CursorUnavailable | Failure::Busy
                ),
                error.next_action(),
            ),
        }
    }

    pub(super) fn encode_case_cursor(
        &self,
        subject: &str,
        case_id: &CaseId,
        artifact_id: &ArtifactId,
    ) -> Result<String, ()> {
        let signature = self.case_cursor_signature(subject, case_id, artifact_id)?;
        Ok(format!(
            "{CURSOR_VERSION}.{}.{}",
            artifact_id.as_str(),
            lower_hex(&signature)
        ))
    }

    pub(super) fn decode_case_cursor(
        &self,
        subject: &str,
        case_id: &CaseId,
        cursor: &str,
    ) -> Result<ArtifactId, CursorError> {
        let mut parts = cursor.split('.');
        let (Some(version), Some(artifact), Some(signature)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if version != CURSOR_VERSION || parts.next().is_some() {
            return Err(CursorError::Invalid);
        }
        let artifact = ArtifactId::parse(artifact).map_err(|_| CursorError::Invalid)?;
        let supplied = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let expected = self
            .case_cursor_signature(subject, case_id, &artifact)
            .map_err(|()| CursorError::Unavailable)?;
        if !memcmp::eq(&supplied, &expected) {
            return Err(CursorError::Invalid);
        }
        Ok(artifact)
    }

    fn case_cursor_signature(
        &self,
        subject: &str,
        case_id: &CaseId,
        artifact: &ArtifactId,
    ) -> Result<[u8; 32], ()> {
        component_signature(
            &self.config.cursor_key.0,
            &[
                b"xshield-control-case-evidence-cursor-v1",
                &self.config.credential.token_digest,
                subject.as_bytes(),
                self.config.tenant_id.as_str().as_bytes(),
                self.config.site_id.as_str().as_bytes(),
                case_id.as_str().as_bytes(),
                &self.config.limits.max_query_artifacts.to_be_bytes(),
                artifact.as_str().as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy)]
enum Failure {
    CaseId,
    Cursor,
    CursorUnavailable,
    Store,
    Target,
    Busy,
}

impl Failure {
    fn status(self) -> StatusCode {
        match self {
            Self::CaseId | Self::Cursor => StatusCode::BAD_REQUEST,
            Self::CursorUnavailable | Self::Store => StatusCode::SERVICE_UNAVAILABLE,
            Self::Target => StatusCode::NOT_FOUND,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
        }
    }
    fn code(self) -> &'static str {
        match self {
            Self::CaseId => "CONTROL_CASE_ID_INVALID",
            Self::Cursor => "CONTROL_CURSOR_INVALID",
            Self::CursorUnavailable => "CONTROL_CURSOR_UNAVAILABLE",
            Self::Store => "CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE",
            Self::Target => "CONTROL_CASE_NOT_AVAILABLE",
            Self::Busy => "CONTROL_CASE_EVIDENCE_BUSY",
        }
    }
    fn message(self) -> &'static str {
        match self {
            Self::CaseId => "invalid case identifier",
            Self::Cursor => "invalid pagination cursor",
            Self::CursorUnavailable => "pagination service is temporarily unavailable",
            Self::Store => "case evidence store is temporarily unavailable",
            Self::Target => "case is unavailable",
            Self::Busy => "case evidence operation is already in progress",
        }
    }
    fn next_action(self) -> &'static str {
        match self {
            Self::CaseId => "correct_request",
            Self::Cursor => "restart_query",
            Self::CursorUnavailable | Self::Store | Self::Busy => "retry_later",
            Self::Target => "verify_scope",
        }
    }
}
