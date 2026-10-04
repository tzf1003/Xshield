//! Management API-key issuance and lifecycle endpoints.
#![allow(
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::format_collect,
    clippy::ignored_unit_patterns
)]

use super::{AccessAction, ControlPlane, no_store, single_header};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use xshield_postgres::ManagementApiKeyScopeInput;

pub const PATH: &str = "/control/v1/agent-api-keys";
const ADMIN_ACCESS: AccessAction = AccessAction {
    event_type: "console.agent_api_key.admin",
    method: "POST",
    path: PATH,
    role: xshield_core::admin::ManagementRole::KeyAdministrator,
};
const LIST_ACCESS: AccessAction = AccessAction {
    event_type: "console.agent_api_key.list",
    method: "GET",
    path: PATH,
    role: xshield_core::admin::ManagementRole::KeyAdministrator,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub subject: String,
    pub display_name: String,
    pub expires_at: String,
    pub scopes: Vec<ScopeRequest>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRequest {
    pub tenant_id: String,
    pub site_id: String,
    pub capabilities: Vec<String>,
}

#[derive(Serialize)]
struct CreateResponse {
    request_id: String,
    api_key_id: String,
    api_key: String,
    key_prefix: String,
    expires_at: DateTime<Utc>,
    scopes: Vec<ScopeRequest>,
}

#[derive(Serialize)]
struct ListResponse {
    request_id: String,
    keys: Vec<ManagementApiKeyView>,
}

#[derive(Serialize)]
struct ManagementApiKeyView {
    api_key_id: String,
    tenant_id: String,
    subject: String,
    display_name: String,
    key_prefix: String,
    status: String,
    expires_at: String,
    created_at: String,
    last_used_at: Option<String>,
}

const CAPABILITIES: &[&str] = &[
    "site.read",
    "site.create",
    "site.config.write",
    "site.config.validate",
    "site.config.apply_direct",
    "site.health.read",
    "site.rollback",
];

pub async fn list_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let auth = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match control.authorize_any_identity(
        auth.as_deref(),
        &request_id,
        LIST_ACCESS,
        &[
            xshield_core::admin::ManagementRole::KeyAdministrator,
            xshield_core::admin::ManagementRole::SystemAdmin,
        ],
    ) {
        Ok(identity) => identity.principal.subject().to_owned(),
        Err(e) => return (*e).into_response(),
    };
    match control
        .catalog
        .list_management_api_keys(control.config.tenant_id.as_str())
        .await
    {
        Ok(keys) => {
            let keys = keys
                .into_iter()
                .map(|key| ManagementApiKeyView {
                    api_key_id: key.api_key_id,
                    tenant_id: key.tenant_id,
                    subject: key.subject,
                    display_name: key.display_name,
                    key_prefix: key.key_prefix,
                    status: key.status,
                    expires_at: key.expires_at.to_rfc3339(),
                    created_at: key.created_at.to_rfc3339(),
                    last_used_at: key.last_used_at.map(|value| value.to_rfc3339()),
                })
                .collect();
            no_store((StatusCode::OK, Json(ListResponse { request_id, keys })).into_response())
        }
        Err(_) => control
            .audited_error_async(
                request_id,
                Some(subject),
                LIST_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_API_KEY_UNAVAILABLE",
                "management service unavailable",
                true,
                "retry_later",
            )
            .await
            .into_response(),
    }
}

pub async fn create_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    issue(control, headers, body, None).await
}

pub async fn rotate_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(api_key_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let tenant = control.config.tenant_id.as_str().to_owned();
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let auth = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match control.authorize_any_identity(
        auth.as_deref(),
        &request_id,
        ADMIN_ACCESS,
        &[
            xshield_core::admin::ManagementRole::KeyAdministrator,
            xshield_core::admin::ManagementRole::SystemAdmin,
        ],
    ) {
        Ok(identity) => identity.principal.subject().to_owned(),
        Err(e) => return (*e).into_response(),
    };
    if !control
        .catalog
        .revoke_management_api_key(&tenant, &api_key_id, &subject)
        .await
        .unwrap_or(false)
    {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                ADMIN_ACCESS,
                None,
                StatusCode::NOT_FOUND,
                "CONTROL_API_KEY_NOT_FOUND",
                "management API key not found",
                false,
                "correct_request",
            )
            .await
            .into_response();
    }
    issue_with_subject(control, headers, body, Some(subject), Some(request_id)).await
}

pub async fn revoke_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(api_key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let auth = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match control.authorize_any_identity(
        auth.as_deref(),
        &request_id,
        ADMIN_ACCESS,
        &[
            xshield_core::admin::ManagementRole::KeyAdministrator,
            xshield_core::admin::ManagementRole::SystemAdmin,
        ],
    ) {
        Ok(identity) => identity.principal.subject().to_owned(),
        Err(e) => return (*e).into_response(),
    };
    match control.catalog.revoke_management_api_key(control.config.tenant_id.as_str(), &api_key_id, &subject).await {
        Ok(true) => no_store((StatusCode::OK, Json(serde_json::json!({"request_id": request_id, "api_key_id": api_key_id, "status": "revoked"}))).into_response()),
        Ok(false) => control.audited_error_async(request_id, Some(subject), ADMIN_ACCESS, None, StatusCode::NOT_FOUND, "CONTROL_API_KEY_NOT_FOUND", "management API key not found", false, "correct_request").await.into_response(),
        Err(_) => control.audited_error_async(request_id, Some(subject), ADMIN_ACCESS, None, StatusCode::SERVICE_UNAVAILABLE, "CONTROL_API_KEY_UNAVAILABLE", "management service unavailable", true, "retry_later").await.into_response(),
    }
}

async fn issue(
    control: Arc<ControlPlane>,
    headers: HeaderMap,
    body: Bytes,
    _unused: Option<String>,
) -> Response {
    issue_with_subject(control, headers, body, None, None).await
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

async fn issue_with_subject(
    control: Arc<ControlPlane>,
    headers: HeaderMap,
    body: Bytes,
    forced_subject: Option<String>,
    forced_request_id: Option<String>,
) -> Response {
    let request_id = forced_request_id.unwrap_or_else(|| format!("req_{}", uuid::Uuid::now_v7()));
    let auth = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match forced_subject.or_else(|| {
        control
            .authorize_any_identity(
                auth.as_deref(),
                &request_id,
                ADMIN_ACCESS,
                &[
                    xshield_core::admin::ManagementRole::KeyAdministrator,
                    xshield_core::admin::ManagementRole::SystemAdmin,
                ],
            )
            .ok()
            .map(|identity| identity.principal.subject().to_owned())
    }) {
        Some(s) => s,
        None => {
            return control
                .audited_error_async(
                    request_id,
                    None,
                    ADMIN_ACCESS,
                    None,
                    StatusCode::UNAUTHORIZED,
                    "CONTROL_AUTH_REQUIRED",
                    "management authentication required",
                    false,
                    "authenticate",
                )
                .await
                .into_response();
        }
    };
    let request: CreateRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    ADMIN_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_API_KEY_REQUEST_INVALID",
                    "invalid API key request",
                    false,
                    "correct_request",
                )
                .await
                .into_response();
        }
    };
    let expires_at =
        match DateTime::parse_from_rfc3339(&request.expires_at).map(|v| v.with_timezone(&Utc)) {
            Ok(v) if v > Utc::now() && v <= Utc::now() + chrono::Duration::days(90) => v,
            _ => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        ADMIN_ACCESS,
                        None,
                        StatusCode::BAD_REQUEST,
                        "CONTROL_API_KEY_EXPIRY_INVALID",
                        "invalid API key expiry",
                        false,
                        "correct_request",
                    )
                    .await
                    .into_response();
            }
        };
    if request.subject.is_empty()
        || request.subject.len() > 256
        || request.display_name.is_empty()
        || request.display_name.len() > 128
        || request.scopes.is_empty()
        || request.scopes.len() > 32
        || request.scopes.iter().any(|s| {
            s.tenant_id != control.config.tenant_id.as_str()
                || s.site_id.is_empty()
                || s.capabilities.is_empty()
                || s.capabilities
                    .iter()
                    .any(|c| !CAPABILITIES.contains(&c.as_str()))
        })
    {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                ADMIN_ACCESS,
                None,
                StatusCode::BAD_REQUEST,
                "CONTROL_API_KEY_SCOPE_INVALID",
                "invalid API key scope",
                false,
                "correct_request",
            )
            .await
            .into_response();
    }
    let Some(hash_key) = control.config.api_key_hash_key.as_deref() else {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                ADMIN_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_API_KEY_UNAVAILABLE",
                "management API key issuance unavailable",
                true,
                "retry_later",
            )
            .await
            .into_response();
    };
    let mut random = [0_u8; 24];
    if rand_bytes(&mut random).is_err() {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                ADMIN_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_API_KEY_UNAVAILABLE",
                "management API key issuance unavailable",
                true,
                "retry_later",
            )
            .await
            .into_response();
    }
    let secret = format!("xsk_{}", hex_bytes(&random));
    let key_prefix = secret[..12].to_owned();
    let fingerprint = match super::component_signature(hash_key, &[secret.as_bytes()]) {
        Ok(v) => v,
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    ADMIN_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_API_KEY_UNAVAILABLE",
                    "management API key issuance unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let api_key_id = format!("key_{}", uuid::Uuid::now_v7());
    let inputs: Vec<_> = request
        .scopes
        .iter()
        .flat_map(|s| {
            s.capabilities.iter().map(|cap| ManagementApiKeyScopeInput {
                tenant_id: s.tenant_id.clone(),
                site_id: s.site_id.clone(),
                capability: cap.clone(),
            })
        })
        .collect();
    if control
        .catalog
        .create_management_api_key(
            &api_key_id,
            control.config.tenant_id.as_str(),
            &request.subject,
            &request.display_name,
            &key_prefix,
            &fingerprint,
            expires_at,
            &subject,
            &inputs,
        )
        .await
        .is_err()
    {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                ADMIN_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_API_KEY_UNAVAILABLE",
                "management service unavailable",
                true,
                "retry_later",
            )
            .await
            .into_response();
    }
    no_store(
        (
            StatusCode::CREATED,
            Json(CreateResponse {
                request_id,
                api_key_id,
                api_key: secret,
                key_prefix,
                expires_at,
                scopes: request.scopes,
            }),
        )
            .into_response(),
    )
}
