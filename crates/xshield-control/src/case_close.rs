//! Bounded, audited closure of an investigator-owned case.

use super::{
    AccessAction, ControlPlane, EndpointResult, api_error, audit_unavailable, component_signature,
    internal_error, lower_hex, valid_idempotency_key,
};
use axum::{
    Json,
    extract::{
        Path, State,
        rejection::{JsonRejection, PathRejection},
    },
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole,
    domain::{CaseId, EventId, RequestId},
    investigation::InvestigationCaseCloseDraft,
};
use xshield_postgres::{
    InvestigationCaseClose, InvestigationCaseCloseRecord, InvestigationCaseCloseWriteOutcome,
};

pub(super) const PATH: &str = "/control/v1/cases/{case_id}/close";
const ACCESS: AccessAction = AccessAction {
    event_type: "case.closed",
    method: "POST",
    path: PATH,
    role: ManagementRole::Investigator,
};
const STORE_DEADLINE: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CloseRequest {
    reason: String,
}

#[derive(Serialize)]
struct CloseResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    case_id: String,
    status: &'static str,
    closed_at: String,
    replayed: bool,
}

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    case_id: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    payload: Result<Json<CloseRequest>, JsonRejection>,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut keys = headers.get_all("idempotency-key").iter();
    let key = keys
        .next()
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let key = if keys.next().is_none() { key } else { None };
    control
        .close_case(
            authorization,
            key,
            case_id.ok().map(|Path(id)| id),
            payload.ok().map(|Json(body)| body),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn close_case(
        self: Arc<Self>,
        authorization: Option<String>,
        key: Option<String>,
        target_case: Option<String>,
        payload: Option<CloseRequest>,
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
        let case_id = target_case.and_then(|value| CaseId::parse(value).ok());
        let validated = match (case_id.as_ref(), payload, key) {
            (None, _, _) => Err(Failure::CaseId),
            (_, None, _) => Err(Failure::Request),
            (Some(case), Some(body), Some(key)) if valid_idempotency_key(&key) => {
                InvestigationCaseCloseDraft::new(
                    self.config.tenant_id.clone(),
                    self.config.site_id.clone(),
                    case.clone(),
                    subject.clone(),
                    body.reason,
                )
                .map(|draft| (draft, key))
                .map_err(|_| Failure::Request)
            }
            _ => Err(Failure::Key),
        };
        let (draft, key) = match validated {
            Ok(command) => command,
            Err(error) => {
                return self
                    .finish_case_close(request_id, subject, case_id, Err(error))
                    .await;
            }
        };
        let Some(case_id) = case_id else {
            return internal_error(&request_id);
        };
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .finish_case_close(request_id, subject, Some(case_id), Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // The shared case budget and audit terminal state survive a disconnected caller.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self.persist_case_close(&task_request, &draft, &key).await;
            self.finish_case_close(task_request, subject, Some(case_id), result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn persist_case_close(
        &self,
        request_id: &str,
        draft: &InvestigationCaseCloseDraft,
        key: &str,
    ) -> Result<(InvestigationCaseCloseRecord, bool), Failure> {
        let (idempotency, request_digest) = self.case_close_digests(draft, key)?;
        let request_id = RequestId::parse(request_id).map_err(|_| Failure::Store)?;
        let event_id =
            EventId::parse(format!("ev_{}", Uuid::now_v7())).map_err(|_| Failure::Store)?;
        let event = closed_envelope(&request_id, &event_id, draft, &request_digest);
        let command = InvestigationCaseClose::new(
            draft,
            &idempotency,
            &request_digest,
            &request_id,
            &event_id,
            &event,
        )
        .map_err(|_| Failure::Store)?;
        match tokio::time::timeout(
            STORE_DEADLINE,
            self.catalog.close_investigation_case(command),
        )
        .await
        .map_err(|_| Failure::Store)?
        .map_err(|_| Failure::Store)?
        {
            InvestigationCaseCloseWriteOutcome::Closed(record) => Ok((record, false)),
            InvestigationCaseCloseWriteOutcome::Existing(record) => Ok((record, true)),
            InvestigationCaseCloseWriteOutcome::Conflict => Err(Failure::Conflict),
            InvestigationCaseCloseWriteOutcome::TargetUnavailable => Err(Failure::Target),
        }
    }

    fn case_close_digests(
        &self,
        draft: &InvestigationCaseCloseDraft,
        key: &str,
    ) -> Result<([u8; 32], [u8; 32]), Failure> {
        let common = [
            draft.owner_ref().as_bytes(),
            draft.tenant_id().as_str().as_bytes(),
            draft.site_id().as_str().as_bytes(),
            key.as_bytes(),
        ];
        let idempotency = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-case-close-idempotency-v1",
                common[0],
                common[1],
                common[2],
                common[3],
            ],
        )
        .map_err(|()| Failure::Signing)?;
        let request = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-case-close-request-v1",
                common[0],
                common[1],
                common[2],
                common[3],
                draft.case_id().as_str().as_bytes(),
                draft.reason().as_bytes(),
            ],
        )
        .map_err(|()| Failure::Signing)?;
        Ok((idempotency, request))
    }

    async fn finish_case_close(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        case_id: Option<CaseId>,
        result: Result<(InvestigationCaseCloseRecord, bool), Failure>,
    ) -> EndpointResult {
        let (outcome, reason) = match &result {
            Ok((_, true)) => ("PASS", "CONTROL_CASE_ALREADY_CLOSED"),
            Ok((_, false)) => ("PASS", "CONTROL_CASE_CLOSED"),
            Err(error) => (
                if error.status().is_server_error() {
                    "ERROR"
                } else {
                    "DENY"
                },
                error.code(),
            ),
        };
        let audit_control = Arc::clone(&self);
        let audit_request = request_id.clone();
        let audit_case = case_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_access_event_with_evidence(
                &audit_request,
                Some(&subject),
                ACCESS,
                None,
                None,
                audit_case.as_ref(),
                None,
                outcome,
                reason,
                &[],
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        match result {
            Ok((record, replayed)) => EndpointResult::Raw(
                (
                    StatusCode::OK,
                    Json(CloseResponse {
                        schema_version: 3,
                        request_id,
                        tenant_id: self.config.tenant_id.as_str().to_owned(),
                        site_id: self.config.site_id.as_str().to_owned(),
                        case_id: record.case_id().as_str().to_owned(),
                        status: "closed",
                        closed_at: record
                            .closed_at()
                            .to_rfc3339_opts(SecondsFormat::Millis, true),
                        replayed,
                    }),
                )
                    .into_response(),
            ),
            Err(error) => api_error(
                &request_id,
                error.status(),
                error.code(),
                error.message(),
                matches!(error, Failure::Signing | Failure::Store | Failure::Busy),
                error.next_action(),
            ),
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    CaseId,
    Request,
    Key,
    Signing,
    Store,
    Conflict,
    Target,
    Busy,
}

impl Failure {
    fn status(self) -> StatusCode {
        match self {
            Self::CaseId | Self::Request | Self::Key => StatusCode::BAD_REQUEST,
            Self::Signing | Self::Store => StatusCode::SERVICE_UNAVAILABLE,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Target => StatusCode::NOT_FOUND,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::CaseId => "CONTROL_CASE_ID_INVALID",
            Self::Request => "CONTROL_CASE_CLOSE_REQUEST_INVALID",
            Self::Key => "CONTROL_IDEMPOTENCY_KEY_INVALID",
            Self::Signing => "CONTROL_IDEMPOTENCY_UNAVAILABLE",
            Self::Store => "CONTROL_CASE_STORE_UNAVAILABLE",
            Self::Conflict => "CONTROL_CASE_CLOSE_CONFLICT",
            Self::Target => "CONTROL_CASE_NOT_AVAILABLE",
            Self::Busy => "CONTROL_CASE_CLOSE_BUSY",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::CaseId => "invalid case identifier",
            Self::Request => "invalid case close request",
            Self::Key => "a valid idempotency key is required",
            Self::Signing | Self::Store => "case store is temporarily unavailable",
            Self::Conflict => "case close or idempotency key is already bound",
            Self::Target => "case is unavailable",
            Self::Busy => "case operation is already in progress",
        }
    }

    fn next_action(self) -> &'static str {
        match self {
            Self::CaseId | Self::Request | Self::Key => "correct_request",
            Self::Signing | Self::Store => "retry_same_request",
            Self::Conflict => "use_original_request",
            Self::Target => "verify_scope",
            Self::Busy => "retry_later",
        }
    }
}

fn closed_envelope(
    request_id: &RequestId,
    event_id: &EventId,
    draft: &InvestigationCaseCloseDraft,
    digest: &[u8; 32],
) -> serde_json::Value {
    let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace_id = Uuid::now_v7().simple().to_string();
    serde_json::json!({
        "schema_version": 3, "event_id": event_id.as_str(), "event_type": "case.closed",
        "tenant_id": draft.tenant_id().as_str(), "site_id": draft.site_id().as_str(),
        "request_id": request_id.as_str(), "trace_id": trace_id, "span_id": &trace_id[..16],
        "producer_id": "xshield-control", "producer_boot_id": request_id.as_str(),
        "producer_seq": 1, "request_seq": 1, "occurred_at": occurred_at, "observed_at": occurred_at,
        "policy_revision": "control-v1", "example_only": false,
        "evidence_refs": [], "cause_event_ids": [],
        "payload": {
            "stage": "case_management", "case_id": draft.case_id().as_str(),
            "subject_ref": draft.owner_ref(),
            "request_digest": lower_hex(digest), "outcome": "PASS", "reason_code": "CASE_CLOSED",
            "proof_kind": "deterministic", "confidence": null, "confidence_status": "not_applicable"
        },
        "sensitivity": "INTERNAL", "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
    })
}
