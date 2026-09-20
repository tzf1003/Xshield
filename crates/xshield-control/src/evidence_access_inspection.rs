//! Scoped approval metadata inspection with durable management access auditing.
//! Historical state is an observation; content and decisions revalidate their
//! own authority. No evidence bytes or storage metadata are read here.

use super::{
    AccessAction, ControlPlane, EndpointResult, api_error, audit_unavailable, internal_error,
    single_header,
};
use axum::{
    Json,
    body::Bytes,
    extract::{
        Path, RawQuery, State,
        rejection::{BytesRejection, PathRejection},
    },
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::{admin::ManagementRole, domain::EvidenceAccessRequestId};
use xshield_postgres::EvidenceAccessInspection;

pub(super) const PATH: &str = "/control/v1/evidence-access-requests/{access_request_id}";
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.evidence.access.read",
    method: "GET",
    path: PATH,
    role: ManagementRole::Investigator,
};

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    target: Result<Path<String>, PathRejection>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    control
        .inspect_evidence_access(
            single_header(&headers, AUTHORIZATION.as_str()),
            target.ok().map(|Path(id)| id),
            query.is_none() && body.is_ok_and(|body| body.is_empty()),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn inspect_evidence_access(
        self: Arc<Self>,
        authorization: Option<String>,
        target: Option<String>,
        valid_request: bool,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        // Role selection uses only server-provisioned claims. Authentication,
        // scope and rate checks still run once through the common authorizer.
        let role = [
            ManagementRole::SensitiveEvidenceApprover,
            ManagementRole::SensitiveEvidenceReader,
            ManagementRole::Investigator,
        ]
        .into_iter()
        .find(|role| {
            self.config
                .principal
                .authorizes(*role, &self.config.tenant_id, &self.config.site_id)
        })
        .unwrap_or(ManagementRole::Investigator);
        let action = AccessAction { role, ..ACCESS };
        let auth_control = Arc::clone(&self);
        let auth_request = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request, action)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(result)) => return *result,
            Err(_) => return internal_error(&request_id),
        };
        let Some(target) = target.and_then(|id| EvidenceAccessRequestId::parse(id).ok()) else {
            return self
                .finish_evidence_inspection(request_id, subject, None, Err(Failure::Id))
                .await;
        };
        if !valid_request {
            return self
                .finish_evidence_inspection(
                    request_id,
                    subject,
                    Some(target),
                    Err(Failure::Request),
                )
                .await;
        }
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .finish_evidence_inspection(request_id, subject, Some(target), Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // An admitted read keeps its audit obligation and shared capacity when
        // the HTTP waiter disconnects. No database transaction spans the audit.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = tokio::time::timeout(
                Duration::from_secs(15),
                self.catalog.read_evidence_access_request(
                    &self.config.tenant_id,
                    &self.config.site_id,
                    &target,
                    &subject,
                    role == ManagementRole::SensitiveEvidenceApprover,
                ),
            )
            .await;
            let result = match result {
                Ok(Ok(Some(record))) => Ok(record),
                Ok(Ok(None)) => Err(Failure::Unavailable),
                Ok(Err(_)) | Err(_) => Err(Failure::Store),
            };
            self.finish_evidence_inspection(task_request, subject, Some(target), result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn finish_evidence_inspection(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        target: Option<EvidenceAccessRequestId>,
        result: Result<EvidenceAccessInspection, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let max_approval_ttl_seconds = self.config.limits.max_evidence_access_ttl_seconds;
        let tenant_id = self.config.tenant_id.as_str().to_owned();
        let site_id = self.config.site_id.as_str().to_owned();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = match &result {
                Ok(_) => ("PASS", "CONTROL_EVIDENCE_ACCESS_READ"),
                Err(error) => (
                    if error.status().is_server_error() {
                        "ERROR"
                    } else {
                        "DENY"
                    },
                    error.code(),
                ),
            };
            let record = result.as_ref().ok();
            let refs = record.map(|record| [record.artifact_id.as_str()]);
            self.append_access_event_with_evidence(
                &audit_request,
                Some(&subject),
                ACCESS,
                None,
                record.map(|record| &record.artifact_id),
                record.map(|record| &record.case_id),
                target.as_ref(),
                outcome,
                reason,
                refs.as_ref().map_or(&[], |refs| &refs[..]),
            )?;
            Ok::<_, super::ControlError>(result)
        })
        .await;
        let Ok(Ok(result)) = audited else {
            return audit_unavailable(&request_id);
        };
        match result {
            Ok(record) => EndpointResult::Raw(
                (
                    StatusCode::OK,
                    Json(InspectionResponse {
                        schema_version: 3,
                        request_id,
                        tenant_id,
                        site_id,
                        as_of: record.as_of.to_rfc3339_opts(SecondsFormat::Micros, true),
                        max_approval_ttl_seconds,
                        access_request: InspectionDetails::from(record),
                    }),
                )
                    .into_response(),
            ),
            Err(error) => api_error(
                &request_id,
                error.status(),
                error.code(),
                error.message(),
                matches!(error, Failure::Busy | Failure::Store),
                match error {
                    Failure::Busy | Failure::Store => "retry_later",
                    Failure::Unavailable => "verify_access",
                    Failure::Id | Failure::Request => "correct_request",
                },
            ),
        }
    }
}

#[derive(Serialize)]
struct InspectionResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    as_of: String,
    max_approval_ttl_seconds: u32,
    access_request: InspectionDetails,
}

#[derive(Serialize)]
struct InspectionDetails {
    access_request_id: String,
    case_id: String,
    artifact_id: String,
    requested_by: String,
    access_kind: &'static str,
    justification: String,
    stored_status: &'static str,
    requested_at: String,
    requested_event_id: String,
    decided_by: Option<String>,
    decision_reason: Option<String>,
    decision_ttl_seconds: Option<u32>,
    decision_event_id: Option<String>,
    decided_at: Option<String>,
    access_expires_at: Option<String>,
    case_status: &'static str,
    artifact_status: &'static str,
    artifact_expires_at: String,
    artifact_time_expired: bool,
    capability_time_expired: Option<bool>,
}

impl From<EvidenceAccessInspection> for InspectionDetails {
    fn from(record: EvidenceAccessInspection) -> Self {
        Self {
            access_request_id: record.access_request_id.as_str().to_owned(),
            case_id: record.case_id.as_str().to_owned(),
            artifact_id: record.artifact_id.as_str().to_owned(),
            requested_by: record.requested_by,
            access_kind: record.access_kind.as_str(),
            justification: record.justification,
            stored_status: record.stored_status,
            requested_at: record
                .requested_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            requested_event_id: record.requested_event_id.as_str().to_owned(),
            decided_by: record.decided_by,
            decision_reason: record.decision_reason,
            decision_ttl_seconds: record.decision_ttl_seconds,
            decision_event_id: record.decision_event_id.map(|id| id.as_str().to_owned()),
            decided_at: record
                .decided_at
                .map(|time| time.to_rfc3339_opts(SecondsFormat::Micros, true)),
            access_expires_at: record
                .access_expires_at
                .map(|time| time.to_rfc3339_opts(SecondsFormat::Micros, true)),
            case_status: record.case_status,
            artifact_status: record.artifact_status,
            artifact_expires_at: record
                .artifact_expires_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            artifact_time_expired: record.artifact_expires_at <= record.as_of,
            capability_time_expired: record.access_expires_at.map(|time| time <= record.as_of),
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Id,
    Request,
    Busy,
    Unavailable,
    Store,
}

impl Failure {
    fn status(self) -> StatusCode {
        match self {
            Self::Id | Self::Request => StatusCode::BAD_REQUEST,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::NOT_FOUND,
            Self::Store => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Id => "CONTROL_EVIDENCE_ACCESS_ID_INVALID",
            Self::Request => "CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID",
            Self::Busy => "CONTROL_EVIDENCE_ACCESS_BUSY",
            Self::Unavailable => "CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE",
            Self::Store => "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Id => "invalid evidence access request identifier",
            Self::Request => "invalid evidence access inspection request",
            Self::Busy => "evidence access operation is already in progress",
            Self::Unavailable => "evidence access request is unavailable",
            Self::Store => "evidence access request store is temporarily unavailable",
        }
    }
}
