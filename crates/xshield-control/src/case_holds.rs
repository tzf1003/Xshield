//! Administrator-scoped evidence retention management.
//!
//! Validated commands share the case operation budget through their independent
//! access audit. Holding ciphertext never extends content-read authorization.

use super::{
    AccessAction, ControlPlane, EndpointResult, api_error, audit_unavailable, component_signature,
    internal_error, valid_idempotency_key,
};
use axum::{
    Json,
    extract::{
        Path, RawQuery, State,
        rejection::{JsonRejection, PathRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole,
    domain::{ArtifactId, CaseId, EventId},
};
use xshield_postgres::{
    CaseEvidenceHoldCreate, CaseEvidenceHoldCreateOutcome, CaseEvidenceHoldRecord,
    CaseEvidenceHoldRelease, CaseEvidenceHoldReleaseOutcome, StoreError,
};

mod collection;
pub(super) use collection::list_handler;

pub(super) const PATH: &str = "/control/v1/cases/{case_id}/holds";
pub(super) const RELEASE_PATH: &str = "/control/v1/evidence-holds/{hold_id}/release";
const CREATE: AccessAction = AccessAction {
    event_type: "console.evidence.hold.created",
    method: "POST",
    path: PATH,
    role: ManagementRole::AuditAdministrator,
};
const RELEASE: AccessAction = AccessAction {
    event_type: "console.evidence.hold.released",
    method: "POST",
    path: RELEASE_PATH,
    role: ManagementRole::AuditAdministrator,
};
const STORE_DEADLINE: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateRequest {
    artifact_id: String,
    reason: String,
    hold_until: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRequest {
    reason: String,
}

#[derive(Serialize)]
struct HoldResponse {
    hold_id: String,
    case_id: String,
    artifact_id: String,
    created_by: String,
    reason: String,
    created_at: String,
    hold_until: String,
    released_event_id: Option<String>,
    released_by: Option<String>,
    released_reason: Option<String>,
    released_at: Option<String>,
}

impl From<&CaseEvidenceHoldRecord> for HoldResponse {
    fn from(record: &CaseEvidenceHoldRecord) -> Self {
        Self {
            hold_id: record.created_event_id.as_str().to_owned(),
            case_id: record.case_id.as_str().to_owned(),
            artifact_id: record.artifact_id.as_str().to_owned(),
            created_by: record.created_by.clone(),
            reason: record.reason.clone(),
            created_at: record
                .created_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            hold_until: record
                .hold_until
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            released_event_id: record
                .released_event_id
                .as_ref()
                .map(|id| id.as_str().to_owned()),
            released_by: record.released_by.clone(),
            released_reason: record.released_reason.clone(),
            released_at: record
                .released_at
                .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true)),
        }
    }
}

#[derive(Serialize)]
struct MutationResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    #[serde(flatten)]
    hold: HoldResponse,
    replayed: bool,
}

#[derive(Default)]
struct Targets {
    case: Option<CaseId>,
    artifact: Option<ArtifactId>,
    hold: Option<EventId>,
}

enum Input {
    Create(Option<CreateRequest>),
    Release(Option<ReleaseRequest>),
}

enum Mutation {
    Create {
        case: CaseId,
        artifact: ArtifactId,
        reason: String,
        until: DateTime<Utc>,
    },
    Release {
        hold: EventId,
        reason: String,
    },
}

impl Input {
    const fn action(&self) -> AccessAction {
        match self {
            Self::Create(_) => CREATE,
            Self::Release(_) => RELEASE,
        }
    }

    fn validate(self, path: Option<String>, targets: &mut Targets) -> Result<Mutation, Failure> {
        match self {
            Self::Create(body) => {
                let case = path
                    .and_then(|id| CaseId::parse(id).ok())
                    .ok_or(Failure::CaseId)?;
                targets.case = Some(case.clone());
                let body = body.ok_or(Failure::Request)?;
                let artifact = ArtifactId::parse(body.artifact_id).map_err(|_| Failure::Request)?;
                targets.artifact = Some(artifact.clone());
                let until = DateTime::parse_from_rfc3339(&body.hold_until)
                    .map_err(|_| Failure::Request)?
                    .with_timezone(&Utc);
                if !valid_reason(&body.reason)
                    || until.timestamp() < 0
                    || until.timestamp_nanos_opt().is_none()
                    || until.timestamp_subsec_nanos() >= 1_000_000_000
                    || body.hold_until.len() != 24
                    || until.to_rfc3339_opts(SecondsFormat::Millis, true) != body.hold_until
                {
                    return Err(Failure::Request);
                }
                Ok(Mutation::Create {
                    case,
                    artifact,
                    reason: body.reason,
                    until,
                })
            }
            Self::Release(body) => {
                let hold = path
                    .and_then(|id| EventId::parse(id).ok())
                    .ok_or(Failure::HoldId)?;
                targets.hold = Some(hold.clone());
                let body = body
                    .filter(|value| valid_reason(&value.reason))
                    .ok_or(Failure::Request)?;
                Ok(Mutation::Release {
                    hold,
                    reason: body.reason,
                })
            }
        }
    }
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 512
        && reason.trim() == reason
        && !reason.chars().any(char::is_control)
}

fn single_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(value.to_owned())
    }
}

pub(super) async fn create_handler(
    State(control): State<Arc<ControlPlane>>,
    target: Result<Path<String>, PathRejection>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Result<Json<CreateRequest>, JsonRejection>,
) -> Response {
    control
        .mutate_hold(
            single_header(&headers, "authorization"),
            single_header(&headers, "idempotency-key"),
            target.ok().map(|Path(id)| id),
            query,
            Input::Create(body.ok().map(|Json(body)| body)),
        )
        .await
        .into_response()
}

pub(super) async fn release_handler(
    State(control): State<Arc<ControlPlane>>,
    target: Result<Path<String>, PathRejection>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Result<Json<ReleaseRequest>, JsonRejection>,
) -> Response {
    control
        .mutate_hold(
            single_header(&headers, "authorization"),
            single_header(&headers, "idempotency-key"),
            target.ok().map(|Path(id)| id),
            query,
            Input::Release(body.ok().map(|Json(body)| body)),
        )
        .await
        .into_response()
}

impl ControlPlane {
    async fn mutate_hold(
        self: Arc<Self>,
        authorization: Option<String>,
        key: Option<String>,
        path: Option<String>,
        query: Option<String>,
        input: Input,
    ) -> EndpointResult {
        let action = input.action();
        let request_id = format!("req_{}", Uuid::now_v7());
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
        let mut targets = Targets::default();
        let command = input.validate(path, &mut targets).and_then(|command| {
            if query.is_some() {
                return Err(Failure::Request);
            }
            let key = key
                .filter(|value| valid_idempotency_key(value))
                .ok_or(Failure::Key)?;
            Ok((command, key))
        });
        let (command, key) = match command {
            Ok(command) => command,
            Err(error) => {
                return self
                    .finish_hold_mutation(request_id, subject, action, targets, Err(error))
                    .await;
            }
        };
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .finish_hold_mutation(request_id, subject, action, targets, Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // Retain admission through the transaction and audit fsync even if the
        // HTTP caller disconnects. Exact replay resolves an uncertain commit.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self.persist_hold(&subject, &key, &command).await;
            self.finish_hold_mutation(task_request, subject, action, targets, result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn persist_hold(
        &self,
        subject: &str,
        key: &str,
        command: &Mutation,
    ) -> Result<(CaseEvidenceHoldRecord, bool), Failure> {
        let (idempotency, request_digest) = self.hold_digests(subject, key, command)?;
        let event = EventId::parse(format!("ev_{}", Uuid::now_v7())).map_err(|_| Failure::Store)?;
        match command {
            Mutation::Create {
                case,
                artifact,
                reason,
                until,
            } => {
                let command = CaseEvidenceHoldCreate::new(
                    &self.config.tenant_id,
                    &self.config.site_id,
                    case,
                    artifact,
                    subject,
                    reason,
                    &idempotency,
                    &request_digest,
                    &event,
                    *until,
                )
                .map_err(|_| Failure::Store)?;
                match tokio::time::timeout(
                    STORE_DEADLINE,
                    self.catalog.create_case_evidence_hold(command),
                )
                .await
                .map_err(|_| Failure::Store)?
                .map_err(|error| Failure::from_store(&error))?
                {
                    CaseEvidenceHoldCreateOutcome::Created(record) => Ok((record, false)),
                    CaseEvidenceHoldCreateOutcome::Existing(record) => Ok((record, true)),
                    CaseEvidenceHoldCreateOutcome::Conflict => Err(Failure::Conflict),
                    CaseEvidenceHoldCreateOutcome::TargetUnavailable => Err(Failure::Target),
                    CaseEvidenceHoldCreateOutcome::CapacityExceeded => Err(Failure::Capacity),
                }
            }
            Mutation::Release { hold, reason } => {
                let command = CaseEvidenceHoldRelease::new(
                    &self.config.tenant_id,
                    &self.config.site_id,
                    hold,
                    subject,
                    reason,
                    &idempotency,
                    &request_digest,
                    &event,
                )
                .map_err(|_| Failure::Store)?;
                match tokio::time::timeout(
                    STORE_DEADLINE,
                    self.catalog.release_case_evidence_hold(command),
                )
                .await
                .map_err(|_| Failure::Store)?
                .map_err(|error| Failure::from_store(&error))?
                {
                    CaseEvidenceHoldReleaseOutcome::Released(record) => Ok((record, false)),
                    CaseEvidenceHoldReleaseOutcome::Existing(record) => Ok((record, true)),
                    CaseEvidenceHoldReleaseOutcome::Conflict => Err(Failure::Conflict),
                    CaseEvidenceHoldReleaseOutcome::NotFound => Err(Failure::Target),
                }
            }
        }
    }

    fn hold_digests(
        &self,
        subject: &str,
        key: &str,
        command: &Mutation,
    ) -> Result<([u8; 32], [u8; 32]), Failure> {
        let mut components: Vec<&[u8]> = vec![
            match command {
                Mutation::Create { .. } => b"xshield-control-hold-create-idempotency-v1",
                Mutation::Release { .. } => b"xshield-control-hold-release-idempotency-v1",
            },
            subject.as_bytes(),
            self.config.tenant_id.as_str().as_bytes(),
            self.config.site_id.as_str().as_bytes(),
            key.as_bytes(),
        ];
        let idempotency = component_signature(&self.config.idempotency_key.0, &components)
            .map_err(|()| Failure::Signing)?;
        let until;
        match command {
            Mutation::Create {
                case,
                artifact,
                reason,
                until: deadline,
            } => {
                until = deadline.to_rfc3339_opts(SecondsFormat::Millis, true);
                components[0] = b"xshield-control-hold-create-request-v1";
                components.extend([
                    case.as_str().as_bytes(),
                    artifact.as_str().as_bytes(),
                    reason.as_bytes(),
                    until.as_bytes(),
                ]);
            }
            Mutation::Release { hold, reason } => {
                components[0] = b"xshield-control-hold-release-request-v1";
                components.extend([hold.as_str().as_bytes(), reason.as_bytes()]);
            }
        }
        let digest = component_signature(&self.config.idempotency_key.0, &components)
            .map_err(|()| Failure::Signing)?;
        Ok((idempotency, digest))
    }

    async fn finish_hold_mutation(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        action: AccessAction,
        mut targets: Targets,
        result: Result<(CaseEvidenceHoldRecord, bool), Failure>,
    ) -> EndpointResult {
        let is_create = action.event_type == CREATE.event_type;
        let (outcome, reason) = match &result {
            Ok((record, replayed)) => {
                targets.case = Some(record.case_id.clone());
                targets.artifact = Some(record.artifact_id.clone());
                targets.hold = Some(record.created_event_id.clone());
                (
                    "PASS",
                    match (is_create, replayed) {
                        (true, false) => "CONTROL_EVIDENCE_HOLD_CREATED",
                        (true, true) => "CONTROL_EVIDENCE_HOLD_CREATE_REPLAYED",
                        (false, false) => "CONTROL_EVIDENCE_HOLD_RELEASED",
                        (false, true) => "CONTROL_EVIDENCE_HOLD_RELEASE_REPLAYED",
                    },
                )
            }
            Err(error) => (error.outcome(), error.code()),
        };
        let audit_control = Arc::clone(&self);
        let audit_request = request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let refs = if outcome == "PASS" {
                targets
                    .artifact
                    .as_ref()
                    .map(ArtifactId::as_str)
                    .into_iter()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            audit_control.append_access_event_with_evidence_bytes(
                &audit_request,
                Some(&subject),
                action,
                None,
                targets.artifact.as_ref(),
                targets.case.as_ref(),
                None,
                None,
                outcome,
                reason,
                &refs,
                None,
                None,
                None,
                None,
                targets.hold.as_ref(),
                None,
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        match result {
            Ok((record, replayed)) => EndpointResult::Raw(
                (
                    if is_create && !replayed {
                        StatusCode::CREATED
                    } else {
                        StatusCode::OK
                    },
                    Json(MutationResponse {
                        schema_version: 3,
                        request_id,
                        tenant_id: self.config.tenant_id.as_str().to_owned(),
                        site_id: self.config.site_id.as_str().to_owned(),
                        hold: HoldResponse::from(&record),
                        replayed,
                    }),
                )
                    .into_response(),
            ),
            Err(error) => error.response(&request_id),
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    CaseId,
    HoldId,
    Request,
    Key,
    Signing,
    Store,
    Conflict,
    Target,
    Capacity,
    Busy,
    Cursor,
    CursorUnavailable,
}

impl Failure {
    fn from_store(error: &StoreError) -> Self {
        match error {
            StoreError::InvalidCommand => Self::Request,
            _ => Self::Store,
        }
    }
    fn outcome(self) -> &'static str {
        if self.status().is_server_error() {
            "ERROR"
        } else {
            "DENY"
        }
    }
    fn status(self) -> StatusCode {
        match self {
            Self::CaseId | Self::HoldId | Self::Request | Self::Key | Self::Cursor => {
                StatusCode::BAD_REQUEST
            }
            Self::Signing | Self::Store | Self::CursorUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::Conflict => StatusCode::CONFLICT,
            Self::Target => StatusCode::NOT_FOUND,
            Self::Capacity | Self::Busy => StatusCode::TOO_MANY_REQUESTS,
        }
    }
    fn code(self) -> &'static str {
        match self {
            Self::CaseId => "CONTROL_CASE_ID_INVALID",
            Self::HoldId => "CONTROL_EVIDENCE_HOLD_ID_INVALID",
            Self::Request => "CONTROL_EVIDENCE_HOLD_REQUEST_INVALID",
            Self::Key => "CONTROL_IDEMPOTENCY_KEY_INVALID",
            Self::Signing => "CONTROL_IDEMPOTENCY_UNAVAILABLE",
            Self::Store => "CONTROL_EVIDENCE_HOLD_STORE_UNAVAILABLE",
            Self::Conflict => "CONTROL_EVIDENCE_HOLD_CONFLICT",
            Self::Target => "CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE",
            Self::Capacity => "CONTROL_EVIDENCE_HOLD_LIMIT_EXCEEDED",
            Self::Busy => "CONTROL_EVIDENCE_HOLD_BUSY",
            Self::Cursor => "CONTROL_CURSOR_INVALID",
            Self::CursorUnavailable => "CONTROL_CURSOR_UNAVAILABLE",
        }
    }
    fn response(self, request_id: &str) -> EndpointResult {
        let (message, next_action) = match self {
            Self::CaseId | Self::HoldId | Self::Request => {
                ("invalid evidence hold request", "correct_request")
            }
            Self::Key => ("a valid idempotency key is required", "correct_request"),
            Self::Signing | Self::Store => (
                "evidence hold store is temporarily unavailable",
                "retry_same_request",
            ),
            Self::Conflict => (
                "hold or idempotency key is already bound",
                "use_original_request",
            ),
            Self::Target => ("evidence hold target is unavailable", "verify_scope"),
            Self::Capacity => (
                "evidence hold capacity is exhausted",
                "review_hold_capacity",
            ),
            Self::Busy => ("case operation is already in progress", "retry_later"),
            Self::Cursor => ("invalid pagination cursor", "restart_query"),
            Self::CursorUnavailable => (
                "pagination service is temporarily unavailable",
                "retry_later",
            ),
        };
        api_error(
            request_id,
            self.status(),
            self.code(),
            message,
            matches!(
                self,
                Self::Signing | Self::Store | Self::Busy | Self::CursorUnavailable
            ),
            next_action,
        )
    }
}
