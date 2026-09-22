//! Restricted calibration-report metadata inspection with durable access audit.
//!
//! This endpoint reads the dedicated report projection only. It cannot open a
//! report body, inspect samples or metrics, or create an evidence-read path.

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
use xshield_core::{admin::ManagementRole, domain::CalibrationReportId};
use xshield_postgres::CalibrationReportInspection;

/// Fixed path for one restricted calibration-report metadata projection.
pub(super) const PATH: &str = "/control/v1/calibration-reports/{report_id}";
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.calibration.report.read",
    method: "GET",
    path: PATH,
    role: ManagementRole::AuditAdministrator,
};

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    target: Result<Path<String>, PathRejection>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    control
        .inspect_calibration_report(
            single_header(&headers, AUTHORIZATION.as_str()),
            target.ok().map(|Path(id)| id),
            query.is_none() && body.is_ok_and(|body| body.is_empty()),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn inspect_calibration_report(
        self: Arc<Self>,
        authorization: Option<String>,
        target: Option<String>,
        valid_request: bool,
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
        let Some(target) = target.and_then(|id| CalibrationReportId::parse(id).ok()) else {
            return self
                .finish_calibration_report_inspection(request_id, subject, None, Err(Failure::Id))
                .await;
        };
        if !valid_request {
            return self
                .finish_calibration_report_inspection(
                    request_id,
                    subject,
                    Some(target),
                    Err(Failure::Request),
                )
                .await;
        }
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_calibration_report_inspection(
                    request_id,
                    subject,
                    Some(target),
                    Err(Failure::Busy),
                )
                .await;
        };
        let task_request = request_id.clone();
        // Keep the read permit and terminal audit obligation after a caller
        // disconnects; no database transaction is held during journal append.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = tokio::time::timeout(
                Duration::from_secs(15),
                self.catalog.read_calibration_report(
                    &self.config.tenant_id,
                    &self.config.site_id,
                    &target,
                ),
            )
            .await;
            let result = match result {
                Ok(Ok(report)) => Ok(report),
                Ok(Err(_)) | Err(_) => Err(Failure::Store),
            };
            self.finish_calibration_report_inspection(task_request, subject, Some(target), result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn finish_calibration_report_inspection(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        target: Option<CalibrationReportId>,
        result: Result<Option<CalibrationReportInspection>, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let source_report_id = target.as_ref().map(|report| report.as_str().to_owned());
        let tenant_id = self.config.tenant_id.as_str().to_owned();
        let site_id = self.config.site_id.as_str().to_owned();
        let audited = tokio::task::spawn_blocking(move || {
            let (outcome, reason) = match &result {
                Ok(_) => ("PASS", "CONTROL_CALIBRATION_REPORT_READ"),
                Err(error) => (
                    if error.status().is_server_error() {
                        "ERROR"
                    } else {
                        "DENY"
                    },
                    error.code(),
                ),
            };
            self.append_calibration_report_access_event(
                &audit_request,
                Some(&subject),
                target.as_ref(),
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
            Ok(report) => {
                let Some(source_report_id) = source_report_id else {
                    return internal_error(&request_id);
                };
                EndpointResult::Raw(
                    (
                        StatusCode::OK,
                        Json(InspectionResponse {
                            schema_version: 3,
                            request_id,
                            tenant_id,
                            site_id,
                            source_report_id,
                            found: report.is_some(),
                            as_of: report.as_ref().map(|report| {
                                report.as_of.to_rfc3339_opts(SecondsFormat::Micros, true)
                            }),
                            report: report.map(InspectionDetails::from),
                        }),
                    )
                        .into_response(),
                )
            }
            Err(error) => api_error(
                &request_id,
                error.status(),
                error.code(),
                error.message(),
                matches!(error, Failure::Busy | Failure::Store),
                match error {
                    Failure::Busy | Failure::Store => "retry_later",
                    Failure::Id | Failure::Request => "correct_request",
                },
            ),
        }
    }
}

#[derive(Serialize)]
pub(super) struct InspectionResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    source_report_id: String,
    found: bool,
    as_of: Option<String>,
    report: Option<InspectionDetails>,
}

/// Frozen report metadata, deliberately excluding content-bearing fields.
#[derive(Serialize)]
struct InspectionDetails {
    report_id: String,
    report_artifact_id: String,
    completed_at: String,
    reported_at: String,
    reported_event_id: String,
    body_expires_at: String,
    approval_ref: String,
    dataset_revision: String,
    label_revision: String,
    task_revision: String,
    threshold_policy_revision: String,
    mapping_revision: String,
    evaluation_manifest_artifact_id: String,
    training_manifest_artifact_id: String,
    calibration_manifest_artifact_id: String,
    label_manifest_artifact_id: String,
    provider: String,
    provider_model_id: String,
    model_revision: String,
    prompt_revision: String,
    resolved_model_revision: Option<String>,
    lineage_review_id: Option<String>,
    body_status: &'static str,
}

impl From<CalibrationReportInspection> for InspectionDetails {
    fn from(report: CalibrationReportInspection) -> Self {
        Self {
            report_id: report.report_id.as_str().to_owned(),
            report_artifact_id: report.report_artifact_id.as_str().to_owned(),
            completed_at: report
                .completed_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            reported_at: report
                .reported_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            reported_event_id: report.reported_event_id.as_str().to_owned(),
            body_expires_at: report
                .body_expires_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            approval_ref: report.approval_ref.as_str().to_owned(),
            dataset_revision: report.dataset_revision.as_str().to_owned(),
            label_revision: report.label_revision.as_str().to_owned(),
            task_revision: report.task_revision.as_str().to_owned(),
            threshold_policy_revision: report.threshold_policy_revision.as_str().to_owned(),
            mapping_revision: report.mapping_revision.as_str().to_owned(),
            evaluation_manifest_artifact_id: report
                .evaluation_manifest_artifact_id
                .as_str()
                .to_owned(),
            training_manifest_artifact_id: report.training_manifest_artifact_id.as_str().to_owned(),
            calibration_manifest_artifact_id: report
                .calibration_manifest_artifact_id
                .as_str()
                .to_owned(),
            label_manifest_artifact_id: report.label_manifest_artifact_id.as_str().to_owned(),
            provider: report.provider.as_str().to_owned(),
            provider_model_id: report.provider_model_id,
            model_revision: report.model_revision.as_str().to_owned(),
            prompt_revision: report.prompt_revision.as_str().to_owned(),
            resolved_model_revision: report
                .resolved_model_revision
                .map(|revision| revision.as_str().to_owned()),
            lineage_review_id: report
                .lineage_review_id
                .map(|review| review.as_str().to_owned()),
            body_status: report.body_status.as_str(),
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Id,
    Request,
    Busy,
    Store,
}

impl Failure {
    fn status(self) -> StatusCode {
        match self {
            Self::Id | Self::Request => StatusCode::BAD_REQUEST,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
            Self::Store => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Id => "CONTROL_CALIBRATION_REPORT_ID_INVALID",
            Self::Request => "CONTROL_CALIBRATION_REPORT_READ_REQUEST_INVALID",
            Self::Busy => "CONTROL_CALIBRATION_REPORT_BUSY",
            Self::Store => "CONTROL_CALIBRATION_REPORT_STORE_UNAVAILABLE",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Id => "invalid calibration report identifier",
            Self::Request => "invalid calibration report inspection request",
            Self::Busy => "calibration report inspection is already in progress",
            Self::Store => "calibration report store is temporarily unavailable",
        }
    }
}
