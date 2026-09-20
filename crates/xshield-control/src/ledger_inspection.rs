//! Redacted identity and grant investigation with mandatory management audit.
//! Stored lifecycle and database-time expiry are observations, not a request
//! authorization result. Online admission continues to verify all proofs.

use super::{
    AccessAction, ControlPlane, EndpointResult, api_error, audit_unavailable, internal_error,
};
use axum::{
    Json,
    extract::{Path, RawQuery, State, rejection::PathRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::SecondsFormat;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use xshield_core::{
    admin::ManagementRole,
    domain::{AuthBindingId, GrantId},
};
use xshield_postgres::{BindingInspection, GrantInspection, StoreError};

pub(super) const GRANT_PATH: &str = "/control/v1/grants/{grant_id}";
pub(super) const BINDING_PATH: &str = "/control/v1/auth-bindings/{binding_id}";
pub(super) const GRANT_ACCESS: AccessAction = AccessAction {
    event_type: "console.grant.read",
    method: "GET",
    path: GRANT_PATH,
    role: ManagementRole::Observer,
};
pub(super) const BINDING_ACCESS: AccessAction = AccessAction {
    event_type: "console.binding.read",
    method: "GET",
    path: BINDING_PATH,
    role: ManagementRole::Observer,
};

#[derive(Clone, Copy)]
enum Kind {
    Grant,
    Binding,
}

impl Kind {
    fn access(self) -> AccessAction {
        match self {
            Self::Grant => GRANT_ACCESS,
            Self::Binding => BINDING_ACCESS,
        }
    }

    fn target(self, value: String) -> Option<Target> {
        match self {
            Self::Grant => GrantId::parse(value).ok().map(Target::Grant),
            Self::Binding => AuthBindingId::parse(value).ok().map(Target::Binding),
        }
    }

    fn success(self) -> &'static str {
        match self {
            Self::Grant => "CONTROL_GRANT_READ",
            Self::Binding => "CONTROL_BINDING_READ",
        }
    }
}

enum Target {
    Grant(GrantId),
    Binding(AuthBindingId),
}

#[derive(Serialize)]
#[serde(untagged)]
enum Snapshot {
    Grant(GrantResponse),
    Binding(BindingResponse),
}

impl Target {
    async fn read(&self, control: &ControlPlane, request_id: &str) -> Result<Snapshot, StoreError> {
        let tenant = &control.config.tenant_id;
        let site = &control.config.site_id;
        match self {
            Self::Grant(id) => {
                let record = control.catalog.read_grant_summary(tenant, site, id).await?;
                Ok(Snapshot::Grant(GrantResponse {
                    schema_version: 3,
                    request_id: request_id.to_owned(),
                    tenant_id: tenant.as_str().to_owned(),
                    site_id: site.as_str().to_owned(),
                    source_grant_id: id.as_str().to_owned(),
                    found: record.is_some(),
                    as_of: record
                        .as_ref()
                        .map(|record| record.as_of.to_rfc3339_opts(SecondsFormat::Micros, true)),
                    grant: record.map(|record| Box::new(GrantDetails::from(record))),
                }))
            }
            Self::Binding(id) => {
                let record = control
                    .catalog
                    .read_binding_summary(tenant, site, id)
                    .await?;
                Ok(Snapshot::Binding(BindingResponse {
                    schema_version: 3,
                    request_id: request_id.to_owned(),
                    tenant_id: tenant.as_str().to_owned(),
                    site_id: site.as_str().to_owned(),
                    source_binding_id: id.as_str().to_owned(),
                    found: record.is_some(),
                    as_of: record
                        .as_ref()
                        .map(|record| record.as_of.to_rfc3339_opts(SecondsFormat::Micros, true)),
                    binding: record.map(IdentityDetails::from),
                }))
            }
        }
    }
}

#[derive(Serialize)]
struct BindingResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    source_binding_id: String,
    found: bool,
    as_of: Option<String>,
    binding: Option<IdentityDetails>,
}

#[derive(Serialize)]
struct IdentityDetails {
    binding_id: String,
    current_auth_epoch: u64,
    credential_generation: u64,
    stored_status: &'static str,
    time_expired: bool,
    expires_at: String,
    updated_at: String,
}

impl From<BindingInspection> for IdentityDetails {
    fn from(record: BindingInspection) -> Self {
        Self {
            binding_id: record.binding_id.as_str().to_owned(),
            current_auth_epoch: record.auth_epoch.value(),
            credential_generation: record.credential_generation.value(),
            stored_status: record.status.as_str(),
            time_expired: record.expires_at <= record.as_of,
            expires_at: record
                .expires_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            updated_at: record
                .updated_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
        }
    }
}

#[derive(Serialize)]
struct GrantResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    source_grant_id: String,
    found: bool,
    as_of: Option<String>,
    grant: Option<Box<GrantDetails>>,
}

#[derive(Serialize)]
struct GrantDetails {
    grant_id: String,
    auth_epoch: u64,
    stored_status: &'static str,
    time_expired: bool,
    issued_at: String,
    expires_at: String,
    resource_type: String,
    operation_id: String,
    view_id: String,
    policy_revision: String,
    source_event_id: String,
    source_request_id: String,
    binding: BindingDetails,
}

#[derive(Serialize)]
struct BindingDetails {
    binding_id: String,
    current_auth_epoch: u64,
    epoch_matches_grant: bool,
    stored_status: &'static str,
    time_expired: bool,
    expires_at: String,
}

impl From<GrantInspection> for GrantDetails {
    fn from(record: GrantInspection) -> Self {
        Self {
            grant_id: record.grant_id.as_str().to_owned(),
            auth_epoch: record.grant_epoch.value(),
            stored_status: record.grant_status.as_str(),
            time_expired: record.expires_at <= record.as_of,
            issued_at: record
                .issued_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            expires_at: record
                .expires_at
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            resource_type: record.resource_type.as_str().to_owned(),
            operation_id: record.operation_id.as_str().to_owned(),
            view_id: record.view_profile.as_str().to_owned(),
            policy_revision: record.policy_revision.as_str().to_owned(),
            source_event_id: record.source_event_id.as_str().to_owned(),
            source_request_id: record.source_request_id.as_str().to_owned(),
            binding: BindingDetails {
                binding_id: record.binding_id.as_str().to_owned(),
                current_auth_epoch: record.binding_epoch.value(),
                epoch_matches_grant: record.binding_epoch == record.grant_epoch,
                stored_status: record.binding_status.as_str(),
                time_expired: record.binding_expires_at <= record.as_of,
                expires_at: record
                    .binding_expires_at
                    .to_rfc3339_opts(SecondsFormat::Micros, true),
            },
        }
    }
}

pub(super) async fn grant_handler(
    State(control): State<Arc<ControlPlane>>,
    target: Result<Path<String>, PathRejection>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    handler(control, target, query, headers, Kind::Grant).await
}

pub(super) async fn binding_handler(
    State(control): State<Arc<ControlPlane>>,
    target: Result<Path<String>, PathRejection>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    handler(control, target, query, headers, Kind::Binding).await
}

async fn handler(
    control: Arc<ControlPlane>,
    target: Result<Path<String>, PathRejection>,
    query: Option<String>,
    headers: HeaderMap,
    kind: Kind,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    control
        .read_ledger(kind, authorization, target.ok().map(|Path(id)| id), query)
        .await
        .into_response()
}

impl ControlPlane {
    async fn read_ledger(
        self: Arc<Self>,
        kind: Kind,
        authorization: Option<String>,
        target: Option<String>,
        query: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request, kind.access())
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(result)) => return *result,
            Err(_) => return internal_error(&request_id),
        };
        let Some(target) = target.and_then(|id| kind.target(id)) else {
            return self
                .finish_ledger_read(kind, request_id, subject, None, Err(Failure::Id))
                .await;
        };
        if query.is_some_and(|query| !query.is_empty()) {
            return self
                .finish_ledger_read(kind, request_id, subject, Some(target), Err(Failure::Query))
                .await;
        }
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_ledger_read(kind, request_id, subject, Some(target), Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // Retain shared investigation capacity through a disconnected client's
        // database deadline and terminal audit, as for the event search route.
        match tokio::spawn(async move {
            let _permit = permit;
            let result =
                tokio::time::timeout(Duration::from_secs(15), target.read(&self, &task_request))
                    .await
                    .map_err(|_| Failure::Store)
                    .and_then(|result| result.map_err(|_| Failure::Store));
            self.finish_ledger_read(kind, task_request, subject, Some(target), result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn finish_ledger_read(
        self: Arc<Self>,
        kind: Kind,
        request_id: String,
        subject: String,
        target: Option<Target>,
        result: Result<Snapshot, Failure>,
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
                        error.code(kind),
                    )
                },
                |_| ("PASS", kind.success()),
            );
            self.append_access_event_with_evidence_bytes(
                &audit_request,
                Some(&subject),
                kind.access(),
                None,
                None,
                None,
                None,
                None,
                outcome,
                reason,
                &[],
                None,
                None,
                match target.as_ref() {
                    Some(Target::Grant(id)) => Some(id),
                    _ => None,
                },
                match target.as_ref() {
                    Some(Target::Binding(id)) => Some(id),
                    _ => None,
                },
                None,
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
                error.code(kind),
                error.message(kind),
                matches!(error, Failure::Busy | Failure::Store),
                if matches!(error, Failure::Busy | Failure::Store) {
                    "retry_later"
                } else {
                    "correct_request"
                },
            ),
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Id,
    Query,
    Store,
    Busy,
}

impl Failure {
    fn status(self) -> StatusCode {
        match self {
            Self::Id | Self::Query => StatusCode::BAD_REQUEST,
            Self::Store => StatusCode::SERVICE_UNAVAILABLE,
            Self::Busy => StatusCode::TOO_MANY_REQUESTS,
        }
    }
    fn code(self, kind: Kind) -> &'static str {
        match self {
            Self::Id => match kind {
                Kind::Grant => "CONTROL_GRANT_ID_INVALID",
                Kind::Binding => "CONTROL_BINDING_ID_INVALID",
            },
            Self::Query => "CONTROL_QUERY_INVALID",
            Self::Store => match kind {
                Kind::Grant => "CONTROL_GRANT_STORE_UNAVAILABLE",
                Kind::Binding => "CONTROL_BINDING_STORE_UNAVAILABLE",
            },
            Self::Busy => "CONTROL_QUERY_CAPACITY_EXHAUSTED",
        }
    }
    fn message(self, kind: Kind) -> &'static str {
        match self {
            Self::Id => match kind {
                Kind::Grant => "invalid grant identifier",
                Kind::Binding => "invalid binding identifier",
            },
            Self::Query => "invalid query parameters",
            Self::Store => match kind {
                Kind::Grant => "grant ledger is temporarily unavailable",
                Kind::Binding => "binding ledger is temporarily unavailable",
            },
            Self::Busy => "investigation query capacity is exhausted",
        }
    }
}
