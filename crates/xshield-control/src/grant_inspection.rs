//! Redacted grant-ledger investigation with mandatory management access audit.
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
use xshield_core::{admin::ManagementRole, domain::GrantId};
use xshield_postgres::GrantInspection;

pub(super) const PATH: &str = "/control/v1/grants/{grant_id}";
pub(super) const ACCESS: AccessAction = AccessAction {
    event_type: "console.grant.read",
    method: "GET",
    path: PATH,
    role: ManagementRole::Observer,
};

#[derive(Serialize)]
struct GrantResponse {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    source_grant_id: String,
    found: bool,
    as_of: Option<String>,
    grant: Option<GrantDetails>,
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

pub(super) async fn handler(
    State(control): State<Arc<ControlPlane>>,
    target: Result<Path<String>, PathRejection>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    control
        .read_grant(authorization, target.ok().map(|Path(id)| id), query)
        .await
        .into_response()
}

impl ControlPlane {
    async fn read_grant(
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
        let Some(grant) = target.and_then(|id| GrantId::parse(id).ok()) else {
            return self
                .finish_grant_read(request_id, subject, None, Err(Failure::Id))
                .await;
        };
        if query.is_some_and(|query| !query.is_empty()) {
            return self
                .finish_grant_read(request_id, subject, Some(grant), Err(Failure::Query))
                .await;
        }
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_grant_read(request_id, subject, Some(grant), Err(Failure::Busy))
                .await;
        };
        let task_request = request_id.clone();
        // Retain shared investigation capacity through a disconnected client's
        // database deadline and terminal audit, as for the event search route.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = tokio::time::timeout(
                Duration::from_secs(15),
                self.catalog.read_grant_summary(
                    &self.config.tenant_id,
                    &self.config.site_id,
                    &grant,
                ),
            )
            .await
            .map_err(|_| Failure::Store)
            .and_then(|result| result.map_err(|_| Failure::Store));
            self.finish_grant_read(task_request, subject, Some(grant), result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn finish_grant_read(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        target: Option<GrantId>,
        result: Result<Option<GrantInspection>, Failure>,
    ) -> EndpointResult {
        let audit_request = request_id.clone();
        let response_target = target.clone();
        let tenant = self.config.tenant_id.as_str().to_owned();
        let site = self.config.site_id.as_str().to_owned();
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
                |_| ("PASS", "CONTROL_GRANT_READ"),
            );
            self.append_access_event_with_evidence_bytes(
                &audit_request,
                Some(&subject),
                ACCESS,
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
                target.as_ref(),
            )?;
            Ok::<_, super::ControlError>(result)
        })
        .await;
        let Ok(Ok(result)) = audited else {
            return audit_unavailable(&request_id);
        };
        match result {
            Ok(record) => {
                let Some(target) = response_target else {
                    return internal_error(&request_id);
                };
                let response = GrantResponse {
                    schema_version: 3,
                    request_id,
                    tenant_id: tenant,
                    site_id: site,
                    source_grant_id: target.as_str().to_owned(),
                    found: record.is_some(),
                    as_of: record
                        .as_ref()
                        .map(|record| record.as_of.to_rfc3339_opts(SecondsFormat::Micros, true)),
                    grant: record.map(GrantDetails::from),
                };
                EndpointResult::Raw((StatusCode::OK, Json(response)).into_response())
            }
            Err(error) => api_error(
                &request_id,
                error.status(),
                error.code(),
                error.message(),
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
    fn code(self) -> &'static str {
        match self {
            Self::Id => "CONTROL_GRANT_ID_INVALID",
            Self::Query => "CONTROL_QUERY_INVALID",
            Self::Store => "CONTROL_GRANT_STORE_UNAVAILABLE",
            Self::Busy => "CONTROL_QUERY_CAPACITY_EXHAUSTED",
        }
    }
    fn message(self) -> &'static str {
        match self {
            Self::Id => "invalid grant identifier",
            Self::Query => "invalid query parameters",
            Self::Store => "grant ledger is temporarily unavailable",
            Self::Busy => "investigation query capacity is exhausted",
        }
    }
}
