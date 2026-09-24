//! Metadata-only investigation export requests, approval, and download.

use super::{
    AccessAction, ControlPlane, EndpointResult, api_error, audit_unavailable, component_signature,
    internal_error, single_header, valid_idempotency_key,
};
use axum::{
    Json,
    body::{Body, Bytes},
    extract::{
        Extension, Path, RawQuery, State,
        rejection::{JsonRejection, PathRejection},
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole,
    domain::{ArtifactId, CaseId, ExportId, RequestId},
    investigation::InvestigationExportDraft,
};
use xshield_evidence::EvidenceError;
use xshield_postgres::{
    EvidenceCatalogArtifactQuery, EvidenceCatalogPublish, EvidenceCatalogWriteOutcome,
    InvestigationExportCreate, InvestigationExportDecision, InvestigationExportDecisionOutcome,
    InvestigationExportPackage, InvestigationExportPackageOutcome, InvestigationExportRecord,
    InvestigationExportSnapshot, InvestigationExportWriteOutcome,
};

/// Export request endpoint.
pub(crate) const PATH: &str = "/control/v1/exports";
/// Export status endpoint.
pub(crate) const READ_PATH: &str = "/control/v1/exports/{export_id}";
/// Export approval endpoint.
pub(crate) const APPROVE_PATH: &str = "/control/v1/exports/{export_id}/approve";
/// Export denial endpoint.
pub(crate) const DENY_PATH: &str = "/control/v1/exports/{export_id}/deny";
/// Encrypted export package download endpoint.
pub(crate) const DOWNLOAD_PATH: &str = "/control/v1/exports/{export_id}/download";

pub(crate) const MAX_BODY_BYTES: usize = 4 * 1024;
const EXPORT_TTL_SECONDS: u32 = 900;
const EXPORT_PACKAGE_MAX_BYTES: usize = 8 * 1024 * 1024;

pub(crate) const REQUEST_ACCESS: AccessAction = AccessAction {
    event_type: "export.requested",
    method: "POST",
    path: PATH,
    role: ManagementRole::Investigator,
};
pub(crate) const READ_ACCESS: AccessAction = AccessAction {
    event_type: "console.export.read",
    method: "GET",
    path: READ_PATH,
    role: ManagementRole::Investigator,
};
pub(crate) const APPROVE_ACCESS: AccessAction = AccessAction {
    event_type: "export.approved",
    method: "POST",
    path: APPROVE_PATH,
    role: ManagementRole::SensitiveEvidenceApprover,
};
pub(crate) const DENY_ACCESS: AccessAction = AccessAction {
    event_type: "export.denied",
    method: "POST",
    path: DENY_PATH,
    role: ManagementRole::SensitiveEvidenceApprover,
};
pub(crate) const DOWNLOAD_ACCESS: AccessAction = AccessAction {
    event_type: "export.downloaded",
    method: "GET",
    path: DOWNLOAD_PATH,
    role: ManagementRole::SensitiveEvidenceReader,
};

pub(crate) async fn request_handler(
    State(control): State<Arc<ControlPlane>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    payload: Result<Json<CreateExportRequest>, JsonRejection>,
) -> Response {
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let idempotency_key = single_header(&headers, "idempotency-key");
    control
        .request_export(
            authorization,
            idempotency_key,
            payload
                .ok()
                .filter(|_| query.is_none())
                .map(|Json(value)| value),
        )
        .await
        .into_response()
}

pub(crate) async fn read_handler(
    State(control): State<Arc<ControlPlane>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    control
        .read_export(
            single_header(&headers, AUTHORIZATION.as_str()),
            path.ok().map(|Path(value)| value),
        )
        .await
        .into_response()
}

pub(crate) async fn approve_handler(
    State(control): State<Arc<ControlPlane>>,
    Extension(auth): Extension<super::identity::AuthContext>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    payload: Result<Json<ApproveExportRequest>, JsonRejection>,
) -> Response {
    control
        .decide_export(
            APPROVE_ACCESS,
            single_header(&headers, AUTHORIZATION.as_str()),
            single_header(&headers, "idempotency-key"),
            path.ok().map(|Path(value)| value),
            payload
                .ok()
                .map(|Json(value)| DecisionInput::Approve(value)),
            auth.step_up_valid(),
        )
        .await
        .into_response()
}

pub(crate) async fn deny_handler(
    State(control): State<Arc<ControlPlane>>,
    Extension(auth): Extension<super::identity::AuthContext>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    payload: Result<Json<DenyExportRequest>, JsonRejection>,
) -> Response {
    control
        .decide_export(
            DENY_ACCESS,
            single_header(&headers, AUTHORIZATION.as_str()),
            single_header(&headers, "idempotency-key"),
            path.ok().map(|Path(value)| value),
            payload.ok().map(|Json(value)| DecisionInput::Deny(value)),
            auth.step_up_valid(),
        )
        .await
        .into_response()
}

pub(crate) async fn download_handler(
    State(control): State<Arc<ControlPlane>>,
    Extension(auth): Extension<super::identity::AuthContext>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    control
        .download_export(
            single_header(&headers, AUTHORIZATION.as_str()),
            path.ok().map(|Path(value)| value),
            auth.step_up_valid(),
        )
        .await
        .into_response()
}

impl ControlPlane {
    #[allow(clippy::too_many_lines)]
    async fn request_export(
        self: Arc<Self>,
        authorization: Option<String>,
        idempotency_key: Option<String>,
        input: Option<CreateExportRequest>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request_id, REQUEST_ACCESS)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(error)) => return *error,
            Err(_) => return internal_error(&request_id),
        };
        let Some(input) = input else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    None,
                    REQUEST_ACCESS,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EXPORT_BODY_INVALID",
                    "invalid export request",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some(idempotency_key) = idempotency_key.filter(|value| valid_idempotency_key(value))
        else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    None,
                    REQUEST_ACCESS,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_IDEMPOTENCY_KEY_INVALID",
                    "a valid idempotency key is required",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some(case_id) = CaseId::parse(input.case_id.clone()).ok() else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    None,
                    REQUEST_ACCESS,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_CASE_ID_INVALID",
                    "invalid case identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Ok(export_id) = ExportId::parse(format!("export_{}", Uuid::now_v7())) else {
            return internal_error(&request_id);
        };
        let Ok(draft) = InvestigationExportDraft::new(
            export_id,
            self.config.tenant_id.clone(),
            self.config.site_id.clone(),
            case_id,
            subject.clone(),
            input.purpose,
        ) else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    None,
                    REQUEST_ACCESS,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EXPORT_INPUT_INVALID",
                    "invalid export request",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some((idempotency_digest, request_digest)) =
            self.export_request_digests(&subject, idempotency_key.as_bytes(), &draft)
        else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(draft.export_id().clone()),
                    REQUEST_ACCESS,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_IDEMPOTENCY_UNAVAILABLE",
                    "export service is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let Ok(command) =
            InvestigationExportCreate::new(&draft, &idempotency_digest, &request_digest)
        else {
            return internal_error(&request_id);
        };
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.create_investigation_export(command),
        )
        .await;
        let Ok(Ok(outcome)) = result else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(draft.export_id().clone()),
                    REQUEST_ACCESS,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EXPORT_STORE_UNAVAILABLE",
                    "export service is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let (record, replayed) = match outcome {
            InvestigationExportWriteOutcome::Created(record) => (record, false),
            InvestigationExportWriteOutcome::Existing(record) => (record, true),
            InvestigationExportWriteOutcome::Conflict => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(draft.export_id().clone()),
                        REQUEST_ACCESS,
                        StatusCode::CONFLICT,
                        "CONTROL_IDEMPOTENCY_CONFLICT",
                        "idempotency key is already bound to another export",
                        false,
                        "use_original_request",
                    )
                    .await;
            }
            InvestigationExportWriteOutcome::TargetUnavailable => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(draft.export_id().clone()),
                        REQUEST_ACCESS,
                        StatusCode::NOT_FOUND,
                        "CONTROL_EXPORT_TARGET_UNAVAILABLE",
                        "export target is unavailable",
                        false,
                        "check_case_scope",
                    )
                    .await;
            }
        };
        let export_id = record.export_id().clone();
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_record_id = export_id.clone();
        let audit_case_id = record.case_id().clone();
        let audit_reason = if replayed {
            "EXPORT_REQUEST_REPLAYED"
        } else {
            "EXPORT_REQUESTED"
        };
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_export_access_event(
                &audit_request_id,
                Some(&audit_subject),
                REQUEST_ACCESS,
                &audit_record_id,
                Some(&audit_case_id),
                None,
                "PASS",
                audit_reason,
                &[],
                None,
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::Export(
            if replayed {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            },
            export_response(&request_id, &self, &record, replayed),
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn read_export(
        self: Arc<Self>,
        authorization: Option<String>,
        target: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let identity = match tokio::task::spawn_blocking(move || {
            auth_control.authorize_any_identity(
                authorization.as_deref(),
                &auth_request_id,
                READ_ACCESS,
                &[
                    ManagementRole::Investigator,
                    ManagementRole::SensitiveEvidenceApprover,
                    ManagementRole::SensitiveEvidenceReader,
                    ManagementRole::AuditAdministrator,
                ],
            )
        })
        .await
        {
            Ok(Ok(identity)) => identity,
            Ok(Err(error)) => return *error,
            Err(_) => return internal_error(&request_id),
        };
        let Some(export_id) = target.and_then(|value| ExportId::parse(value).ok()) else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(identity.principal.subject().to_owned()),
                    None,
                    READ_ACCESS,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EXPORT_ID_INVALID",
                    "invalid export identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let subject = identity.principal.subject().to_owned();
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.read_investigation_export(
                &self.config.tenant_id,
                &self.config.site_id,
                &export_id,
            ),
        )
        .await;
        let Ok(Ok(record)) = result else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(export_id),
                    READ_ACCESS,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EXPORT_STORE_UNAVAILABLE",
                    "export service is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let Some(record) = record else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(export_id),
                    READ_ACCESS,
                    StatusCode::NOT_FOUND,
                    "CONTROL_EXPORT_NOT_FOUND",
                    "export is unavailable",
                    false,
                    "verify_scope",
                )
                .await;
        };
        let privileged = identity.principal.authorizes(
            ManagementRole::SensitiveEvidenceApprover,
            &self.config.tenant_id,
            &self.config.site_id,
        ) || identity.principal.authorizes(
            ManagementRole::SensitiveEvidenceReader,
            &self.config.tenant_id,
            &self.config.site_id,
        ) || identity.principal.authorizes(
            ManagementRole::AuditAdministrator,
            &self.config.tenant_id,
            &self.config.site_id,
        );
        if record.requested_by() != subject && !privileged {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(export_id),
                    READ_ACCESS,
                    StatusCode::NOT_FOUND,
                    "CONTROL_EXPORT_NOT_FOUND",
                    "export is unavailable",
                    false,
                    "verify_scope",
                )
                .await;
        }
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_export_id = export_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_export_access_event(
                &audit_request_id,
                Some(&audit_subject),
                READ_ACCESS,
                &audit_export_id,
                None,
                None,
                "PASS",
                "CONTROL_EXPORT_READ",
                &[],
                None,
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::Export(
            StatusCode::OK,
            export_response(&request_id, &self, &record, false),
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn decide_export(
        self: Arc<Self>,
        action: AccessAction,
        authorization: Option<String>,
        idempotency_key: Option<String>,
        target: Option<String>,
        input: Option<DecisionInput>,
        step_up_valid: bool,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let identity = match tokio::task::spawn_blocking(move || {
            auth_control.authorize_identity(authorization.as_deref(), &auth_request_id, action)
        })
        .await
        {
            Ok(Ok(identity)) => identity,
            Ok(Err(error)) => return *error,
            Err(_) => return internal_error(&request_id),
        };
        let subject = identity.principal.subject().to_owned();
        if !identity
            .principal
            .authorizes(action.role, &self.config.tenant_id, &self.config.site_id)
            || !identity.principal.authorizes(
                ManagementRole::SensitiveEvidenceApprover,
                &self.config.tenant_id,
                &self.config.site_id,
            )
        {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    None,
                    action,
                    StatusCode::FORBIDDEN,
                    "CONTROL_SCOPE_DENIED",
                    "management operation forbidden",
                    false,
                    "request_scope",
                )
                .await;
        }
        if !step_up_valid {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    None,
                    action,
                    StatusCode::FORBIDDEN,
                    "CONTROL_EXPORT_STEP_UP_REQUIRED",
                    "high-risk export requires recent reauthentication",
                    false,
                    "reauthenticate",
                )
                .await;
        }
        let Some(export_id) = target.and_then(|value| ExportId::parse(value).ok()) else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    None,
                    action,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EXPORT_ID_INVALID",
                    "invalid export identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some(idempotency_key) = idempotency_key.filter(|value| valid_idempotency_key(value))
        else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(export_id),
                    action,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_IDEMPOTENCY_KEY_INVALID",
                    "a valid idempotency key is required",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some(input) = input else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(export_id),
                    action,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EXPORT_BODY_INVALID",
                    "invalid export decision",
                    false,
                    "correct_request",
                )
                .await;
        };
        let (reason, approve, ttl_seconds) = input.parts();
        let Some((approval_digest, decision_request_digest)) = self.export_decision_digests(
            &subject,
            idempotency_key.as_bytes(),
            &export_id,
            approve,
            reason,
            ttl_seconds,
        ) else {
            return internal_error(&request_id);
        };
        let Ok(command) = InvestigationExportDecision::new(
            &export_id,
            &subject,
            reason,
            &approval_digest,
            &decision_request_digest,
            approve,
            ttl_seconds,
        ) else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(export_id),
                    action,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EXPORT_INPUT_INVALID",
                    "invalid export decision",
                    false,
                    "correct_request",
                )
                .await;
        };
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.decide_investigation_export(
                command,
                &self.config.tenant_id,
                &self.config.site_id,
            ),
        )
        .await;
        let Ok(Ok(outcome)) = result else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(export_id),
                    action,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EXPORT_STORE_UNAVAILABLE",
                    "export service is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let (record, snapshot, replayed) = match outcome {
            InvestigationExportDecisionOutcome::Decided(record, snapshot) => {
                (record, snapshot, false)
            }
            InvestigationExportDecisionOutcome::Existing(record) => (record, None, true),
            InvestigationExportDecisionOutcome::Conflict => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(export_id),
                        action,
                        StatusCode::CONFLICT,
                        "CONTROL_IDEMPOTENCY_CONFLICT",
                        "idempotency key is already bound to another decision",
                        false,
                        "use_original_request",
                    )
                    .await;
            }
            InvestigationExportDecisionOutcome::TargetUnavailable => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(export_id),
                        action,
                        StatusCode::NOT_FOUND,
                        "CONTROL_EXPORT_NOT_FOUND",
                        "export is unavailable",
                        false,
                        "verify_scope",
                    )
                    .await;
            }
            InvestigationExportDecisionOutcome::SelfApproval => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(export_id),
                        action,
                        StatusCode::FORBIDDEN,
                        "CONTROL_EXPORT_SELF_APPROVAL",
                        "export approval requires an independent subject",
                        false,
                        "request_independent_approval",
                    )
                    .await;
            }
            InvestigationExportDecisionOutcome::AlreadyDecided(_record) => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(export_id),
                        action,
                        StatusCode::CONFLICT,
                        "CONTROL_EXPORT_ALREADY_DECIDED",
                        "export already has a terminal decision",
                        false,
                        "read_export_status",
                    )
                    .await;
            }
        };
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_export_id = record.export_id().clone();
        let audit_case_id = record.case_id().clone();
        let reason_code = if replayed {
            if approve {
                "EXPORT_APPROVAL_REPLAYED"
            } else {
                "EXPORT_DENIAL_REPLAYED"
            }
        } else if approve {
            "EXPORT_APPROVED"
        } else {
            "EXPORT_DENIED"
        };
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_export_access_event(
                &audit_request_id,
                Some(&audit_subject),
                action,
                &audit_export_id,
                Some(&audit_case_id),
                None,
                "PASS",
                reason_code,
                &[],
                None,
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        if !approve {
            return EndpointResult::Export(
                StatusCode::OK,
                export_response(&request_id, &self, &record, replayed),
            );
        }
        let snapshot = match snapshot {
            Some(snapshot) => snapshot,
            None if record.status() == "approved" => {
                match self
                    .catalog
                    .snapshot_investigation_export(
                        &self.config.tenant_id,
                        &self.config.site_id,
                        record.export_id(),
                    )
                    .await
                {
                    Ok(Some(snapshot)) => snapshot,
                    Ok(None) | Err(_) => return internal_error(&request_id),
                }
            }
            None => {
                return EndpointResult::Export(
                    StatusCode::OK,
                    export_response(&request_id, &self, &record, true),
                );
            }
        };
        if record.status() == "ready" {
            return EndpointResult::Export(
                StatusCode::OK,
                export_response(&request_id, &self, &record, true),
            );
        }
        self.finish_export_package(request_id, subject, record, snapshot, replayed)
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn finish_export_package(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        record: InvestigationExportRecord,
        snapshot: InvestigationExportSnapshot,
        replayed: bool,
    ) -> EndpointResult {
        let Some(port) = self.evidence_read.clone() else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(record.export_id().clone()),
                    APPROVE_ACCESS,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EXPORT_STORAGE_UNAVAILABLE",
                    "export storage is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let Ok(package_request_id) = RequestId::parse(request_id.clone()) else {
            return internal_error(&request_id);
        };
        let Some(package_expiry) = record.expires_at().filter(|value| *value > Utc::now()) else {
            return internal_error(&request_id);
        };
        let package = match serde_json::to_vec(&package_json(
            &record,
            &snapshot,
            self.config.tenant_id.as_str(),
            self.config.site_id.as_str(),
            &subject,
            package_expiry,
        )) {
            Ok(bytes) if bytes.len() <= EXPORT_PACKAGE_MAX_BYTES => bytes,
            Ok(_) => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(record.export_id().clone()),
                        APPROVE_ACCESS,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "CONTROL_EXPORT_PACKAGE_TOO_LARGE",
                        "export package exceeds its size budget",
                        false,
                        "narrow_scope",
                    )
                    .await;
            }
            Err(_) => return internal_error(&request_id),
        };
        let parent_refs = snapshot
            .artifacts()
            .iter()
            .map(|item| item.artifact_id().as_str().to_owned())
            .collect::<Vec<_>>();
        let tenant = self.config.tenant_id.clone();
        let site = self.config.site_id.clone();
        let package_request_for_write = package_request_id.clone();
        let write_result = tokio::task::spawn_blocking(move || {
            port.write_export_package(
                &tenant,
                &site,
                &package_request_for_write,
                &parent_refs,
                package_expiry,
                &package,
            )
        })
        .await;
        let Ok(Ok(manifest)) = write_result else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(record.export_id().clone()),
                    APPROVE_ACCESS,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EXPORT_STORAGE_UNAVAILABLE",
                    "export storage is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let Ok(event_id) = xshield_core::domain::EventId::parse(format!("ev_{}", Uuid::now_v7()))
        else {
            return internal_error(&request_id);
        };
        let envelope = package_catalog_envelope(
            &event_id,
            self.config.tenant_id.as_str(),
            self.config.site_id.as_str(),
            &manifest.manifest().request_id,
            &manifest.manifest().artifact_id,
        );
        let Ok(catalog_command) = EvidenceCatalogPublish::new(&manifest, &event_id, &envelope)
        else {
            return internal_error(&request_id);
        };
        let published = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.publish_evidence_manifest(catalog_command),
        )
        .await;
        if !matches!(
            published,
            Ok(Ok(
                EvidenceCatalogWriteOutcome::Published | EvidenceCatalogWriteOutcome::Existing
            ))
        ) {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(record.export_id().clone()),
                    APPROVE_ACCESS,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EXPORT_STORE_UNAVAILABLE",
                    "export service is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        }
        let package_bytes = manifest.manifest().bytes_saved;
        let Ok(package_artifact_id) = ArtifactId::parse(manifest.manifest().artifact_id.clone())
        else {
            return internal_error(&request_id);
        };
        let Ok(package_command) = InvestigationExportPackage::new(
            record.export_id(),
            &package_artifact_id,
            &package_request_id,
            &manifest.manifest().integrity.digest,
            package_bytes,
        ) else {
            return internal_error(&request_id);
        };
        let completed = self
            .catalog
            .complete_investigation_export(
                package_command,
                &self.config.tenant_id,
                &self.config.site_id,
            )
            .await;
        let Ok(
            InvestigationExportPackageOutcome::Completed(record)
            | InvestigationExportPackageOutcome::Existing(record),
        ) = completed
        else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(record.export_id().clone()),
                    APPROVE_ACCESS,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EXPORT_STORE_UNAVAILABLE",
                    "export storage is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        EndpointResult::Export(
            StatusCode::OK,
            export_response(&request_id, &self, &record, replayed),
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn download_export(
        self: Arc<Self>,
        authorization: Option<String>,
        target: Option<String>,
        step_up_valid: bool,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request_id, DOWNLOAD_ACCESS)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(error)) => return *error,
            Err(_) => return internal_error(&request_id),
        };
        if !step_up_valid {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    None,
                    DOWNLOAD_ACCESS,
                    StatusCode::FORBIDDEN,
                    "CONTROL_EXPORT_STEP_UP_REQUIRED",
                    "high-risk export requires recent reauthentication",
                    false,
                    "reauthenticate",
                )
                .await;
        }
        let Some(export_id) = target.and_then(|value| ExportId::parse(value).ok()) else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    None,
                    DOWNLOAD_ACCESS,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EXPORT_ID_INVALID",
                    "invalid export identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let record = match self
            .catalog
            .claim_investigation_export_download(
                &self.config.tenant_id,
                &self.config.site_id,
                &export_id,
            )
            .await
        {
            Ok(Some(record)) => record,
            Ok(None) => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(export_id),
                        DOWNLOAD_ACCESS,
                        StatusCode::NOT_FOUND,
                        "CONTROL_EXPORT_NOT_AVAILABLE",
                        "export package is unavailable",
                        false,
                        "verify_approval",
                    )
                    .await;
            }
            Err(_) => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(export_id),
                        DOWNLOAD_ACCESS,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_EXPORT_STORE_UNAVAILABLE",
                        "export service is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await;
            }
        };
        let Some(package_artifact_id) = record.package_artifact_id().cloned() else {
            return internal_error(&request_id);
        };
        let Some(package_request_id) = record.package_request_id().cloned() else {
            return internal_error(&request_id);
        };
        let catalog_artifact = match tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog
                .find_artifact(EvidenceCatalogArtifactQuery::new(
                    &self.config.tenant_id,
                    &self.config.site_id,
                    &package_artifact_id,
                )),
        )
        .await
        {
            Ok(Ok(Some(artifact))) => artifact,
            Ok(Ok(None)) => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(record.export_id().clone()),
                        DOWNLOAD_ACCESS,
                        StatusCode::NOT_FOUND,
                        "CONTROL_EXPORT_NOT_AVAILABLE",
                        "export package is unavailable",
                        false,
                        "verify_approval",
                    )
                    .await;
            }
            _ => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(record.export_id().clone()),
                        DOWNLOAD_ACCESS,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_EXPORT_STORE_UNAVAILABLE",
                        "export service is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await;
            }
        };
        let manifest = catalog_artifact.manifest();
        if manifest.artifact_id != package_artifact_id.as_str()
            || manifest.request_id != package_request_id.as_str()
            || record.package_digest() != Some(manifest.integrity.digest.as_str())
            || record.package_bytes() != Some(manifest.bytes_saved)
        {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(record.export_id().clone()),
                    DOWNLOAD_ACCESS,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EXPORT_STORAGE_CORRUPT",
                    "export package is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        }
        let Some(port) = self.evidence_read.clone() else {
            return internal_error(&request_id);
        };
        let Ok(permit) = Arc::clone(&port.capacity).try_acquire_owned() else {
            return self
                .audited_export_error_async(
                    request_id,
                    Some(subject),
                    Some(record.export_id().clone()),
                    DOWNLOAD_ACCESS,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EXPORT_CAPACITY_EXHAUSTED",
                    "export download capacity is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let tenant = self.config.tenant_id.clone();
        let site = self.config.site_id.clone();
        let artifact_for_read = package_artifact_id.clone();
        let request_for_read = package_request_id.clone();
        let content = match tokio::task::spawn_blocking(move || {
            port.read_export_package(
                &tenant,
                &site,
                &artifact_for_read,
                &request_for_read,
                permit,
            )
        })
        .await
        {
            Ok(Ok(content)) => content,
            Ok(Err(EvidenceError::NotAvailable)) | Err(_) => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(record.export_id().clone()),
                        DOWNLOAD_ACCESS,
                        StatusCode::NOT_FOUND,
                        "CONTROL_EXPORT_NOT_AVAILABLE",
                        "export package is unavailable",
                        false,
                        "verify_approval",
                    )
                    .await;
            }
            Ok(Err(_)) => {
                return self
                    .audited_export_error_async(
                        request_id,
                        Some(subject),
                        Some(record.export_id().clone()),
                        DOWNLOAD_ACCESS,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_EXPORT_STORAGE_CORRUPT",
                        "export package is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await;
            }
        };
        let Ok(bytes_read) = u64::try_from(content.as_ref().len()) else {
            return internal_error(&request_id);
        };
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_export_id = record.export_id().clone();
        let audit_case_id = record.case_id().clone();
        let audit_artifact_id = package_artifact_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_export_access_event(
                &audit_request_id,
                Some(&audit_subject),
                DOWNLOAD_ACCESS,
                &audit_export_id,
                Some(&audit_case_id),
                Some(&audit_artifact_id),
                "PASS",
                "EXPORT_DOWNLOADED",
                &[audit_artifact_id.as_str()],
                Some(bytes_read),
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        let content_length = bytes_read.to_string();
        let metadata = [
            ("x-xshield-request-id", request_id.as_str()),
            ("x-xshield-tenant-id", self.config.tenant_id.as_str()),
            ("x-xshield-site-id", self.config.site_id.as_str()),
            ("x-xshield-export-id", record.export_id().as_str()),
            (
                "x-xshield-package-artifact-id",
                package_artifact_id.as_str(),
            ),
            ("content-length", content_length.as_str()),
        ]
        .into_iter()
        .map(|(name, value)| HeaderValue::from_str(value).map(|value| (name, value)))
        .collect::<Result<Vec<_>, _>>();
        let Ok(metadata) = metadata else {
            return internal_error(&request_id);
        };
        let mut response = Response::new(Body::from(Bytes::from_owner(content)));
        *response.status_mut() = StatusCode::OK;
        for (name, value) in metadata {
            response.headers_mut().insert(name, value);
        }
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response.headers_mut().insert(
            CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"investigation-export.json\""),
        );
        response.headers_mut().insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        EndpointResult::Raw(super::no_store(response))
    }

    fn export_request_digests(
        &self,
        subject: &str,
        idempotency_key: &[u8],
        draft: &InvestigationExportDraft,
    ) -> Option<([u8; 32], [u8; 32])> {
        let common = [
            subject.as_bytes(),
            self.config.tenant_id.as_str().as_bytes(),
            self.config.site_id.as_str().as_bytes(),
        ];
        let idempotency = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-export-idempotency-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
            ],
        )
        .ok()?;
        let request = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-export-request-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
                draft.case_id().as_str().as_bytes(),
                draft.purpose().as_bytes(),
            ],
        )
        .ok()?;
        Some((idempotency, request))
    }

    fn export_decision_digests(
        &self,
        subject: &str,
        idempotency_key: &[u8],
        export_id: &ExportId,
        approve: bool,
        reason: &str,
        ttl_seconds: u32,
    ) -> Option<([u8; 32], [u8; 32])> {
        let common = [
            subject.as_bytes(),
            self.config.tenant_id.as_str().as_bytes(),
            self.config.site_id.as_str().as_bytes(),
        ];
        let action: &[u8] = if approve { b"approve" } else { b"deny" };
        let ttl = ttl_seconds.to_be_bytes();
        let approval = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-export-decision-idempotency-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
            ],
        )
        .ok()?;
        let request = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-export-decision-request-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
                export_id.as_str().as_bytes(),
                action,
                reason.as_bytes(),
                &ttl,
            ],
        )
        .ok()?;
        Some((approval, request))
    }

    #[allow(clippy::too_many_arguments)]
    async fn audited_export_error_async(
        self: &Arc<Self>,
        request_id: String,
        subject: Option<String>,
        target_export_id: Option<ExportId>,
        action: AccessAction,
        status: StatusCode,
        reason_code: &'static str,
        message_safe: &'static str,
        retryable: bool,
        next_action: &'static str,
    ) -> EndpointResult {
        let control = Arc::clone(self);
        let fallback = request_id.clone();
        match tokio::task::spawn_blocking(move || {
            let outcome = if status.is_server_error() {
                "ERROR"
            } else {
                "DENY"
            };
            let audited = if let Some(target_export_id) = target_export_id.as_ref() {
                control.append_export_access_event(
                    &request_id,
                    subject.as_deref(),
                    action,
                    target_export_id,
                    None,
                    None,
                    outcome,
                    reason_code,
                    &[],
                    None,
                )
            } else {
                control.append_access_event(
                    &request_id,
                    subject.as_deref(),
                    action,
                    None,
                    outcome,
                    reason_code,
                )
            };
            if audited.is_err() {
                return audit_unavailable(&request_id);
            }
            api_error(
                &request_id,
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
            Err(_) => internal_error(&fallback),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateExportRequest {
    case_id: String,
    purpose: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApproveExportRequest {
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenyExportRequest {
    reason: String,
}

enum DecisionInput {
    Approve(ApproveExportRequest),
    Deny(DenyExportRequest),
}

impl DecisionInput {
    fn parts(&self) -> (&str, bool, u32) {
        match self {
            Self::Approve(input) => (&input.reason, true, EXPORT_TTL_SECONDS),
            Self::Deny(input) => (&input.reason, false, 0),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct ExportResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    export_id: String,
    case_id: String,
    requested_by: String,
    purpose: String,
    kind: &'static str,
    status: &'static str,
    decided_by: Option<String>,
    decided_at: Option<String>,
    decision_reason: Option<String>,
    expires_at: Option<String>,
    package_artifact_id: Option<String>,
    package_request_id: Option<String>,
    package_digest: Option<String>,
    package_bytes: Option<u64>,
    download_count: i64,
    created_at: String,
    updated_at: String,
    replayed: bool,
}

fn export_response(
    request_id: &str,
    control: &ControlPlane,
    record: &InvestigationExportRecord,
    replayed: bool,
) -> ExportResponse {
    let format_time =
        |value: chrono::DateTime<Utc>| value.to_rfc3339_opts(SecondsFormat::Millis, true);
    ExportResponse {
        request_id: request_id.to_owned(),
        tenant_id: control.config.tenant_id.as_str().to_owned(),
        site_id: control.config.site_id.as_str().to_owned(),
        export_id: record.export_id().as_str().to_owned(),
        case_id: record.case_id().as_str().to_owned(),
        requested_by: record.requested_by().to_owned(),
        purpose: record.purpose().to_owned(),
        kind: record.kind(),
        status: record.status(),
        decided_by: record.decided_by().map(str::to_owned),
        decided_at: record.decided_at().map(format_time),
        decision_reason: record.decision_reason().map(str::to_owned),
        expires_at: record.expires_at().map(format_time),
        package_artifact_id: record
            .package_artifact_id()
            .map(|value| value.as_str().to_owned()),
        package_request_id: record
            .package_request_id()
            .map(|value| value.as_str().to_owned()),
        package_digest: record.package_digest().map(str::to_owned),
        package_bytes: record.package_bytes(),
        download_count: record.download_count(),
        created_at: format_time(record.created_at()),
        updated_at: format_time(record.updated_at()),
        replayed,
    }
}

fn package_json(
    record: &InvestigationExportRecord,
    snapshot: &InvestigationExportSnapshot,
    tenant_id: &str,
    site_id: &str,
    approved_by: &str,
    expires_at: chrono::DateTime<Utc>,
) -> serde_json::Value {
    let artifacts = snapshot
        .artifacts()
        .iter()
        .map(|item| {
            serde_json::json!({
                "artifact_id": item.artifact_id().as_str(),
                "availability": item.availability(),
                "request_id": item.request_id().map(xshield_core::domain::RequestId::as_str),
                "kind": item.kind(),
                "content_type": item.content_type(),
                "classification": item.classification(),
                "bytes_saved": item.bytes_saved(),
                "integrity_digest": item.integrity_digest(),
                "recorded_at": item.recorded_at().map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
                "expires_at": item.expires_at().map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
            })
        })
        .collect::<Vec<_>>();
    let missing = snapshot
        .artifacts()
        .iter()
        .filter(|item| item.availability() != "active")
        .map(|item| {
            serde_json::json!({
                "artifact_id": item.artifact_id().as_str(),
                "reason": format!("catalog_{}", item.availability()),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema_version": 1,
        "package_kind": "investigation_export_metadata",
        "export_id": record.export_id().as_str(),
        "tenant_id": tenant_id,
        "site_id": site_id,
        "case": {
            "case_id": snapshot.case_id().as_str(),
            "status": snapshot.case_status(),
            "purpose": snapshot.purpose(),
            "created_at": snapshot.created_at().to_rfc3339_opts(SecondsFormat::Millis, true),
        },
        "scope": "metadata_only",
        "artifacts": artifacts,
        "missing": missing,
        "omitted": [
            "event_jsonl",
            "request_response_versions",
            "transform_relations",
            "model_io",
            "rules_adapters_build_refs",
        ],
        "approval": {
            "approved_by": approved_by,
            "purpose": record.purpose(),
            "expires_at": expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        },
    })
}

fn package_catalog_envelope(
    event_id: &xshield_core::domain::EventId,
    tenant_id: &str,
    site_id: &str,
    request_id: &str,
    artifact_id: &str,
) -> serde_json::Value {
    let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace_id = Uuid::now_v7().simple().to_string();
    serde_json::json!({
        "schema_version": 3,
        "event_id": event_id.as_str(),
        "event_type": "evidence.cataloged",
        "tenant_id": tenant_id,
        "site_id": site_id,
        "request_id": request_id,
        "trace_id": trace_id,
        "span_id": "0000000000000000",
        "producer_id": "xshield-control",
        "producer_boot_id": request_id,
        "producer_seq": 1,
        "request_seq": 1,
        "occurred_at": occurred_at,
        "observed_at": occurred_at,
        "policy_revision": "control-v1",
        "example_only": false,
        "evidence_refs": [artifact_id],
        "cause_event_ids": [],
        "payload": {
            "stage": "evidence_catalog",
            "outcome": "PASS",
            "reason_code": "EVIDENCE_CATALOG_PUBLISHED",
            "artifact_id": artifact_id
        },
        "sensitivity": "RESTRICTED",
        "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
    })
}
