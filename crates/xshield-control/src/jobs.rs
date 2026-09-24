//! Durable case-analysis jobs and owner-scoped job status reads.

use super::{
    AccessAction, ControlPlane, EndpointResult, api_error, audit_unavailable, component_signature,
    internal_error, single_header, valid_idempotency_key,
};
use axum::{
    extract::{Path, State, rejection::PathRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole,
    domain::{CaseId, JobId},
};
use xshield_postgres::{CaseAnalysisJobCreate, ControlJobRecord, ControlJobWriteOutcome};

/// Owner-scoped job status route.
pub(crate) const PATH: &str = "/control/v1/jobs/{job_id}";
/// Bounded, read-only case analysis producer.
pub(crate) const ANALYZE_PATH: &str = "/control/v1/cases/{case_id}/analyze";

pub(crate) const ANALYZE_ACCESS: AccessAction = AccessAction {
    event_type: "console.case.analyze",
    method: "POST",
    path: ANALYZE_PATH,
    role: ManagementRole::Investigator,
};

pub(crate) const READ_ACCESS: AccessAction = AccessAction {
    event_type: "console.job.read",
    method: "GET",
    path: PATH,
    role: ManagementRole::Investigator,
};

pub(crate) async fn analyze_handler(
    State(control): State<Arc<ControlPlane>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let idempotency_key = single_header(&headers, "idempotency-key");
    control
        .analyze_case(
            authorization,
            idempotency_key,
            path.ok().map(|Path(value)| value),
        )
        .await
        .into_response()
}

pub(crate) async fn read_handler(
    State(control): State<Arc<ControlPlane>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    control
        .read_job(authorization, path.ok().map(|Path(value)| value))
        .await
        .into_response()
}

impl ControlPlane {
    async fn analyze_case(
        self: Arc<Self>,
        authorization: Option<String>,
        idempotency_key: Option<String>,
        target: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request_id, ANALYZE_ACCESS)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(result)) => return *result,
            Err(_) => return internal_error(&request_id),
        };
        let Some(case_id) = target.and_then(|value| CaseId::parse(value).ok()) else {
            return self
                .audited_case_error_async(
                    request_id,
                    Some(subject),
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_CASE_ID_INVALID",
                    "invalid case identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some(idempotency_key) = idempotency_key.filter(|value| valid_idempotency_key(value))
        else {
            return self
                .audited_case_error_async(
                    request_id,
                    Some(subject),
                    Some(case_id),
                    StatusCode::BAD_REQUEST,
                    "CONTROL_IDEMPOTENCY_KEY_INVALID",
                    "a valid idempotency key is required",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some((idempotency_digest, request_digest)) =
            self.analysis_digests(&subject, idempotency_key.as_bytes(), &case_id)
        else {
            return self
                .audited_case_error_async(
                    request_id,
                    Some(subject),
                    Some(case_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_IDEMPOTENCY_UNAVAILABLE",
                    "case analysis is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let Ok(job_id) = JobId::parse(format!("job_{}", Uuid::now_v7())) else {
            return internal_error(&request_id);
        };
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .audited_case_error_async(
                    request_id,
                    Some(subject),
                    Some(case_id),
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_CASE_ANALYSIS_BUSY",
                    "case analysis is already in progress",
                    true,
                    "retry_later",
                )
                .await;
        };
        let task_request_id = request_id.clone();
        match tokio::spawn(async move {
            let _permit = permit;
            self.persist_case_analysis(
                task_request_id,
                subject,
                case_id,
                job_id,
                idempotency_digest,
                request_digest,
            )
            .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn persist_case_analysis(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        case_id: CaseId,
        job_id: JobId,
        idempotency_digest: [u8; 32],
        request_digest: [u8; 32],
    ) -> EndpointResult {
        let Ok(command) = CaseAnalysisJobCreate::new(
            &self.config.tenant_id,
            &self.config.site_id,
            &case_id,
            &subject,
            &job_id,
            &idempotency_digest,
            &request_digest,
        ) else {
            return internal_error(&request_id);
        };
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.create_case_analysis_job(command),
        )
        .await;
        let Ok(Ok(outcome)) = result else {
            return self
                .audited_case_error_async(
                    request_id,
                    Some(subject),
                    Some(case_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_CASE_ANALYSIS_STORE_UNAVAILABLE",
                    "case analysis store is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        match outcome {
            ControlJobWriteOutcome::Created(record) => {
                self.finish_analysis(request_id, subject, record, false)
                    .await
            }
            ControlJobWriteOutcome::Existing(record) => {
                self.finish_analysis(request_id, subject, record, true)
                    .await
            }
            ControlJobWriteOutcome::Conflict => {
                self.audited_case_error_async(
                    request_id,
                    Some(subject),
                    Some(case_id),
                    StatusCode::CONFLICT,
                    "CONTROL_IDEMPOTENCY_CONFLICT",
                    "idempotency key is already bound to another request",
                    false,
                    "use_original_request",
                )
                .await
            }
            ControlJobWriteOutcome::TargetUnavailable => {
                self.audited_case_error_async(
                    request_id,
                    Some(subject),
                    Some(case_id),
                    StatusCode::NOT_FOUND,
                    "CONTROL_CASE_ANALYSIS_TARGET_UNAVAILABLE",
                    "case analysis target is unavailable",
                    false,
                    "check_case_scope",
                )
                .await
            }
        }
    }

    async fn finish_analysis(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        record: ControlJobRecord,
        replayed: bool,
    ) -> EndpointResult {
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_case_id = record.case_id().clone();
        let reason = if replayed {
            "CONTROL_CASE_ANALYSIS_REPLAYED"
        } else {
            "CONTROL_CASE_ANALYSIS_CREATED"
        };
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_access_event_with_evidence(
                &audit_request_id,
                Some(&audit_subject),
                ANALYZE_ACCESS,
                None,
                None,
                Some(&audit_case_id),
                None,
                "PASS",
                reason,
                &[],
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::Job(
            StatusCode::ACCEPTED,
            job_response(&request_id, &self, &record, replayed),
        )
    }

    async fn read_job(
        self: Arc<Self>,
        authorization: Option<String>,
        target: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request_id, READ_ACCESS)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(result)) => return *result,
            Err(_) => return internal_error(&request_id),
        };
        let Some(job_id) = target.and_then(|value| JobId::parse(value).ok()) else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    READ_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_JOB_ID_INVALID",
                    "invalid job identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.read_control_job(
                &self.config.tenant_id,
                &self.config.site_id,
                &subject,
                &job_id,
            ),
        )
        .await;
        let Ok(Ok(record)) = result else {
            let audit_control = Arc::clone(&self);
            let audit_request_id = request_id.clone();
            let audit_subject = subject.clone();
            let audit_job_id = job_id.clone();
            let audited = tokio::task::spawn_blocking(move || {
                audit_control.append_job_access_event(
                    &audit_request_id,
                    Some(&audit_subject),
                    &audit_job_id,
                    "ERROR",
                    "CONTROL_JOB_STORE_UNAVAILABLE",
                )
            })
            .await;
            return if matches!(audited, Ok(Ok(()))) {
                api_error(
                    &request_id,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_JOB_STORE_UNAVAILABLE",
                    "job store is temporarily unavailable",
                    true,
                    "retry_later",
                )
            } else {
                audit_unavailable(&request_id)
            };
        };
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_job_id = job_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_job_access_event(
                &audit_request_id,
                Some(&audit_subject),
                &audit_job_id,
                "PASS",
                "CONTROL_JOB_READ",
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::Job(
            StatusCode::OK,
            JobResponse {
                request_id,
                tenant_id: self.config.tenant_id.as_str().to_owned(),
                site_id: self.config.site_id.as_str().to_owned(),
                found: record.is_some(),
                job: record.as_ref().map(|record| job_view(record, false)),
            },
        )
    }

    fn analysis_digests(
        &self,
        subject: &str,
        idempotency_key: &[u8],
        case_id: &CaseId,
    ) -> Option<([u8; 32], [u8; 32])> {
        let common = [
            subject.as_bytes(),
            self.config.tenant_id.as_str().as_bytes(),
            self.config.site_id.as_str().as_bytes(),
        ];
        let idempotency_digest = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-case-analysis-idempotency-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
            ],
        )
        .ok()?;
        let request_digest = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-case-analysis-request-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
                case_id.as_str().as_bytes(),
            ],
        )
        .ok()?;
        Some((idempotency_digest, request_digest))
    }

    #[allow(clippy::too_many_arguments)]
    async fn audited_case_error_async(
        self: &Arc<Self>,
        request_id: String,
        subject: Option<String>,
        target_case_id: Option<CaseId>,
        status: StatusCode,
        reason_code: &'static str,
        message_safe: &'static str,
        retryable: bool,
        next_action: &'static str,
    ) -> EndpointResult {
        let control = Arc::clone(self);
        let fallback_request_id = request_id.clone();
        let audit_fallback_request_id = fallback_request_id.clone();
        let response_request_id = fallback_request_id.clone();
        match tokio::task::spawn_blocking(move || {
            let outcome = if status.is_server_error() {
                "ERROR"
            } else {
                "DENY"
            };
            if control
                .append_access_event_with_evidence(
                    &request_id,
                    subject.as_deref(),
                    ANALYZE_ACCESS,
                    None,
                    None,
                    target_case_id.as_ref(),
                    None,
                    outcome,
                    reason_code,
                    &[],
                )
                .is_err()
            {
                return audit_unavailable(&audit_fallback_request_id);
            }
            api_error(
                &response_request_id,
                status,
                reason_code,
                message_safe,
                retryable,
                next_action,
            )
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&fallback_request_id),
        }
    }
}

#[derive(serde::Serialize)]
pub(crate) struct JobResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    job: Option<JobView>,
}

#[derive(serde::Serialize)]
struct JobView {
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
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    replayed: bool,
}

fn job_response(
    request_id: &str,
    control: &ControlPlane,
    record: &ControlJobRecord,
    replayed: bool,
) -> JobResponse {
    JobResponse {
        request_id: request_id.to_owned(),
        tenant_id: control.config.tenant_id.as_str().to_owned(),
        site_id: control.config.site_id.as_str().to_owned(),
        found: true,
        job: Some(job_view(record, replayed)),
    }
}

fn job_view(record: &ControlJobRecord, replayed: bool) -> JobView {
    JobView {
        job_id: record.job_id().as_str().to_owned(),
        kind: record.kind(),
        status: record.status(),
        checkpoint: record.checkpoint().to_owned(),
        reason_code: record.reason_code().to_owned(),
        retryable: record.retryable(),
        case_id: record.case_id().as_str().to_owned(),
        artifact_count: record.artifact_count(),
        active_artifact_count: record.active_artifact_count(),
        created_at: record
            .created_at()
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        updated_at: record
            .updated_at()
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        completed_at: record
            .completed_at()
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
        replayed,
    }
}
