//! Management API-key issuance and lifecycle endpoints.
#![allow(
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::format_collect,
    clippy::ignored_unit_patterns
)]

use super::{
    AccessAction, ControlPlane, EndpointResult, api_key_authz, identity, no_store, single_header,
};
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
use std::{collections::BTreeSet, sync::Arc};
use xshield_core::{
    admin::{ApiKeyCapability, ApiKeyGrant, ManagementPrincipal, ManagementRole},
    domain::TenantId,
};
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

/// Most scope rows one key may carry, and so the bound on its grants.
const SCOPES_MAX: usize = 32;

/// Why a requested scope set cannot be issued.
#[derive(Debug, Eq, PartialEq)]
enum ScopeRejection {
    /// Malformed, foreign-tenant, unknown capability, or a tenant-wide marker
    /// used with anything but `site.create` (and vice versa).
    Invalid,
    /// Well formed, but the issuer could not itself exercise it.
    Forbidden,
}

/// Turns the requested scopes into the exact grants to store.
///
/// Duplicates collapse; every grant must be one the issuer could itself
/// exercise, so a key is never more powerful than the person who issued it.
fn validate_scopes(
    scopes: &[ScopeRequest],
    tenant: &TenantId,
    issuer: &ManagementPrincipal,
) -> Result<BTreeSet<ApiKeyGrant>, ScopeRejection> {
    if scopes.is_empty() || scopes.len() > SCOPES_MAX {
        return Err(ScopeRejection::Invalid);
    }
    let mut grants = BTreeSet::new();
    for scope in scopes {
        if scope.tenant_id != tenant.as_str()
            || scope.capabilities.is_empty()
            || scope.capabilities.len() > ApiKeyCapability::ALL.len()
        {
            return Err(ScopeRejection::Invalid);
        }
        for name in &scope.capabilities {
            let capability = ApiKeyCapability::parse(name).ok_or(ScopeRejection::Invalid)?;
            let grant = ApiKeyGrant::from_scope_row(tenant.clone(), &scope.site_id, capability)
                .map_err(|_| ScopeRejection::Invalid)?;
            grants.insert(grant);
        }
    }
    if grants
        .iter()
        .any(|grant| !api_key_authz::issuer_may_grant(issuer, grant))
    {
        return Err(ScopeRejection::Forbidden);
    }
    Ok(grants)
}

/// Authorizes key administration: a browser management session (the
/// authenticator already enforces CSRF for its writes) holding
/// `KeyAdministrator` or `SystemAdmin`, as `docs/15` §15 requires. A key has no
/// roles and the static machine credential is not a browser session, so
/// neither can mint, list, revoke or rotate keys.
fn authorize_key_admin(
    control: &ControlPlane,
    headers: &HeaderMap,
    request_id: &str,
    action: AccessAction,
) -> Result<identity::VerifiedRequestIdentity, Box<EndpointResult>> {
    let auth = single_header(headers, AUTHORIZATION.as_str());
    let identity = control.authorize_any_identity(
        auth.as_deref(),
        request_id,
        action,
        &[
            ManagementRole::KeyAdministrator,
            ManagementRole::SystemAdmin,
        ],
    )?;
    if !identity.browser {
        return Err(Box::new(control.audited_error(
            request_id,
            Some(identity.principal.subject()),
            action,
            None,
            StatusCode::FORBIDDEN,
            "CONTROL_SCOPE_DENIED",
            "management operation forbidden",
            false,
            "request_scope",
        )));
    }
    Ok(identity)
}

pub async fn list_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let subject = match authorize_key_admin(&control, &headers, &request_id, LIST_ACCESS) {
        Ok(identity) => identity.principal.subject().to_owned(),
        Err(response) => return (*response).into_response(),
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
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let identity = match authorize_key_admin(&control, &headers, &request_id, ADMIN_ACCESS) {
        Ok(identity) => identity,
        Err(response) => return (*response).into_response(),
    };
    issue(control, identity.principal, request_id, body).await
}

pub async fn rotate_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(api_key_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let tenant = control.config.tenant_id.as_str().to_owned();
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let identity = match authorize_key_admin(&control, &headers, &request_id, ADMIN_ACCESS) {
        Ok(identity) => identity,
        Err(response) => return (*response).into_response(),
    };
    let subject = identity.principal.subject().to_owned();
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
    issue(control, identity.principal, request_id, body).await
}

pub async fn revoke_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(api_key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let subject = match authorize_key_admin(&control, &headers, &request_id, ADMIN_ACCESS) {
        Ok(identity) => identity.principal.subject().to_owned(),
        Err(response) => return (*response).into_response(),
    };
    match control.catalog.revoke_management_api_key(control.config.tenant_id.as_str(), &api_key_id, &subject).await {
        Ok(true) => no_store((StatusCode::OK, Json(serde_json::json!({"request_id": request_id, "api_key_id": api_key_id, "status": "revoked"}))).into_response()),
        Ok(false) => control.audited_error_async(request_id, Some(subject), ADMIN_ACCESS, None, StatusCode::NOT_FOUND, "CONTROL_API_KEY_NOT_FOUND", "management API key not found", false, "correct_request").await.into_response(),
        Err(_) => control.audited_error_async(request_id, Some(subject), ADMIN_ACCESS, None, StatusCode::SERVICE_UNAVAILABLE, "CONTROL_API_KEY_UNAVAILABLE", "management service unavailable", true, "retry_later").await.into_response(),
    }
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

async fn issue(
    control: Arc<ControlPlane>,
    issuer: ManagementPrincipal,
    request_id: String,
    body: Bytes,
) -> Response {
    let subject = issuer.subject().to_owned();
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
    let identity_invalid = request.subject.is_empty()
        || request.subject.len() > 256
        || request.display_name.is_empty()
        || request.display_name.len() > 128;
    let grants = if identity_invalid {
        Err(ScopeRejection::Invalid)
    } else {
        validate_scopes(&request.scopes, &control.config.tenant_id, &issuer)
    };
    let grants = match grants {
        Ok(grants) => grants,
        Err(rejection) => {
            let (status, reason, message) = match rejection {
                ScopeRejection::Invalid => (
                    StatusCode::BAD_REQUEST,
                    "CONTROL_API_KEY_SCOPE_INVALID",
                    "invalid API key scope",
                ),
                ScopeRejection::Forbidden => (
                    StatusCode::FORBIDDEN,
                    "CONTROL_API_KEY_SCOPE_FORBIDDEN",
                    "API key scope exceeds the issuer's authority",
                ),
            };
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    ADMIN_ACCESS,
                    None,
                    status,
                    reason,
                    message,
                    false,
                    "correct_request",
                )
                .await
                .into_response();
        }
    };
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
    let inputs: Vec<_> = grants
        .iter()
        .map(|grant| ManagementApiKeyScopeInput {
            tenant_id: grant.tenant().as_str().to_owned(),
            site_id: grant.scope_site_id().to_owned(),
            capability: grant.capability().as_str().to_owned(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::admin::API_KEY_TENANT_WIDE_MARKER;

    fn tenant() -> TenantId {
        TenantId::parse("tenant_a").unwrap()
    }

    fn scope(site: &str, capabilities: &[&str]) -> ScopeRequest {
        ScopeRequest {
            tenant_id: "tenant_a".to_owned(),
            site_id: site.to_owned(),
            capabilities: capabilities
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    fn issuer(roles: &[ManagementRole]) -> ManagementPrincipal {
        ManagementPrincipal::new_tenant_scoped("human", roles.iter().copied(), [tenant()]).unwrap()
    }

    fn full_issuer() -> ManagementPrincipal {
        issuer(&[
            ManagementRole::SystemAdmin,
            ManagementRole::Observer,
            ManagementRole::PolicyAuthor,
            ManagementRole::PolicyApprover,
            ManagementRole::ReleaseOperator,
        ])
    }

    #[test]
    fn scopes_are_validated_into_exact_deduplicated_grants() {
        let grants = validate_scopes(
            &[
                scope("site_a", &["site.read", "site.read", "site.config.write"]),
                scope("site_a", &["site.read"]),
                scope(API_KEY_TENANT_WIDE_MARKER, &["site.create"]),
            ],
            &tenant(),
            &full_issuer(),
        )
        .unwrap();
        let described: Vec<_> = grants
            .iter()
            .map(|grant| format!("{}:{}", grant.scope_site_id(), grant.capability().as_str()))
            .collect();
        assert_eq!(described.len(), 3, "{described:?}");
        assert!(described.contains(&"__tenant__:site.create".to_owned()));
        assert!(described.contains(&"site_a:site.read".to_owned()));
        assert!(described.contains(&"site_a:site.config.write".to_owned()));
    }

    #[test]
    fn malformed_scope_sets_are_invalid_before_authority_is_considered() {
        let invalid = |scopes: Vec<ScopeRequest>| {
            assert_eq!(
                validate_scopes(&scopes, &tenant(), &issuer(&[])),
                Err(ScopeRejection::Invalid)
            );
        };
        invalid(vec![]);
        invalid(
            (0..=SCOPES_MAX)
                .map(|_| scope("site_a", &["site.read"]))
                .collect(),
        );
        invalid(vec![scope("site_a", &[])]);
        invalid(vec![scope("site_a", &["site.delete"])]);
        invalid(vec![scope("site_a", &["site.create"])]);
        invalid(vec![scope(API_KEY_TENANT_WIDE_MARKER, &["site.read"])]);
        invalid(vec![scope("", &["site.read"])]);
        invalid(vec![scope("bad site", &["site.read"])]);
        invalid(vec![ScopeRequest {
            tenant_id: "tenant_other".to_owned(),
            site_id: "site_a".to_owned(),
            capabilities: vec!["site.read".to_owned()],
        }]);
    }

    #[test]
    fn well_formed_scopes_beyond_the_issuer_are_forbidden_not_invalid() {
        let admin_only = issuer(&[ManagementRole::SystemAdmin]);
        assert!(
            validate_scopes(
                &[scope("site_a", &["site.config.write"])],
                &tenant(),
                &admin_only
            )
            .is_ok()
        );
        for capability in [
            "site.config.apply_direct",
            "site.rollback",
            "site.config.validate",
        ] {
            assert_eq!(
                validate_scopes(&[scope("site_a", &[capability])], &tenant(), &admin_only),
                Err(ScopeRejection::Forbidden),
                "{capability}"
            );
        }
        // One out-of-authority grant refuses the whole request; nothing is trimmed.
        assert_eq!(
            validate_scopes(
                &[scope("site_a", &["site.config.write", "site.rollback"])],
                &tenant(),
                &admin_only
            ),
            Err(ScopeRejection::Forbidden)
        );
    }
}
