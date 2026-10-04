//! Protected-site administration: validated routing metadata and apply state.
#![allow(missing_docs)]
#![allow(
    clippy::manual_is_variant_and,
    clippy::manual_let_else,
    clippy::too_many_lines
)]

use super::{AccessAction, ControlPlane, no_store, single_header};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use url::Url;
use xshield_core::{
    GatewayApplyAck, GatewayApplyRequest, GatewayApplySite, SecurityEntry, SitePolicyConfig,
    admin::ManagementRole,
    domain::SiteId,
    site::{PublicOrigin, RouteOperation, UpstreamEndpoint},
};
use xshield_postgres::{
    ProtectedSiteApprovalOutcome, ProtectedSiteConfigRecord, ProtectedSiteConfigUpsert,
    ProtectedSiteConfigWriteOutcome,
};
use zeroize::Zeroizing;

/// Authenticated control-to-edge apply client. It sends only signed,
/// validated snapshots and never carries secret material.
pub struct EdgeApplyClient {
    endpoint: String,
    health_endpoint: String,
    key: Zeroizing<[u8; 32]>,
    http: reqwest::Client,
}

impl EdgeApplyClient {
    /// Builds a bounded client for the internal edge endpoint.
    ///
    /// # Errors
    /// Returns an error for an invalid endpoint or HMAC key.
    pub fn new(endpoint: impl Into<String>, key_hex: &str) -> Result<Self, &'static str> {
        let endpoint = endpoint.into();
        let parsed = Url::parse(&endpoint).map_err(|_| "invalid edge apply endpoint")?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err("invalid edge apply endpoint");
        }
        let key = decode_hex_key(key_hex).ok_or("invalid edge apply key")?;
        let mut health_url = parsed.clone();
        if health_url.path().ends_with("/apply") {
            let path = health_url.path().trim_end_matches("/apply").to_owned() + "/health";
            health_url.set_path(&path);
        } else {
            return Err("invalid edge apply endpoint");
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "edge apply client unavailable")?;
        Ok(Self {
            endpoint,
            health_endpoint: health_url.to_string(),
            key: Zeroizing::new(key),
            http,
        })
    }

    async fn apply(&self, request: &GatewayApplyRequest) -> Result<GatewayApplyAck, &'static str> {
        let body = serde_json::to_vec(request).map_err(|_| "EDGE_APPLY_PAYLOAD_INVALID")?;
        let signature = hmac_hex(&self.key, &body).ok_or("EDGE_APPLY_SIGNATURE_UNAVAILABLE")?;
        let response = self
            .http
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header("x-xshield-apply-signature", signature)
            .body(body)
            .send()
            .await
            .map_err(|_| "EDGE_UNAVAILABLE")?;
        if !response.status().is_success() {
            let body = response.json::<serde_json::Value>().await.ok();
            let reason = body
                .as_ref()
                .and_then(|value| value.get("reason_code"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("EDGE_APPLY_REJECTED");
            return Err(match reason {
                "EDGE_APPLY_STALE_REVISION" => "EDGE_APPLY_STALE_REVISION",
                "EDGE_APPLY_VALIDATION_FAILED" => "EDGE_APPLY_VALIDATION_FAILED",
                "EDGE_APPLY_SCOPE_DENIED" => "EDGE_APPLY_SCOPE_DENIED",
                "EDGE_APPLY_LISTENER_UNAVAILABLE" => "EDGE_APPLY_LISTENER_UNAVAILABLE",
                "EDGE_APPLY_IDEMPOTENCY_CONFLICT" => "EDGE_APPLY_IDEMPOTENCY_CONFLICT",
                "EDGE_APPLY_SIGNATURE_INVALID" => "EDGE_APPLY_SIGNATURE_INVALID",
                _ => "EDGE_APPLY_REJECTED",
            });
        }
        let ack = response
            .json::<GatewayApplyAck>()
            .await
            .map_err(|_| "EDGE_APPLY_ACK_INVALID")?;
        validate_apply_ack(request, &ack)?;
        Ok(ack)
    }

    async fn health(&self) -> Result<serde_json::Value, &'static str> {
        let body = b"health-v1";
        let signature = hmac_hex(&self.key, body).ok_or("EDGE_APPLY_SIGNATURE_UNAVAILABLE")?;
        let response = self
            .http
            .get(&self.health_endpoint)
            .header("x-xshield-apply-signature", signature)
            .send()
            .await
            .map_err(|_| "EDGE_UNAVAILABLE")?;
        if !response.status().is_success() {
            return Err("EDGE_HEALTH_UNAVAILABLE");
        }
        response
            .json::<serde_json::Value>()
            .await
            .map_err(|_| "EDGE_HEALTH_INVALID")
    }
}

fn validate_apply_ack(
    request: &GatewayApplyRequest,
    ack: &GatewayApplyAck,
) -> Result<(), &'static str> {
    if ack.apply_id != request.apply_id
        || ack.active_revision != request.snapshot_revision
        || ack.apply_state != "active"
        || ack.reason_code != "EDGE_APPLY_CONFIRMED"
    {
        return Err("EDGE_APPLY_ACK_INVALID");
    }
    Ok(())
}

/// Probes only the persisted, validated upstream socket and health path.
/// Redirects stay disabled so a health check cannot become an open proxy.
async fn probe_upstream(record: &ProtectedSiteConfigRecord) -> serde_json::Value {
    let address = match record.upstream_address().parse::<SocketAddr>() {
        Ok(address) => address,
        Err(_) => {
            return json!({
                "upstream_state": "unavailable",
                "reason_code": "CONTROL_SITE_UPSTREAM_INVALID"
            });
        }
    };
    if upstream_ip_is_unsafe(address.ip()) {
        return json!({
            "upstream_state": "unavailable",
            "reason_code": "CONTROL_SITE_SSRF_BLOCKED"
        });
    }
    let health = &record.policy().health_check;
    let scheme = if record.upstream_tls() {
        "https"
    } else {
        "http"
    };
    let url = format!(
        "{scheme}://{}{}",
        record.upstream_server_name(),
        health.path
    );
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(u64::from(health.timeout_ms)))
        .timeout(Duration::from_millis(u64::from(health.timeout_ms)))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(record.upstream_server_name(), address)
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return json!({
                "upstream_state": "unavailable",
                "reason_code": "CONTROL_SITE_HEALTH_CLIENT_UNAVAILABLE"
            });
        }
    };
    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(_) => {
            return json!({
                "upstream_state": "unavailable",
                "reason_code": "CONTROL_SITE_UPSTREAM_UNAVAILABLE"
            });
        }
    };
    let status = response.status().as_u16();
    let state = if status == health.expected_status {
        "healthy"
    } else {
        "degraded"
    };
    json!({
        "upstream_state": state,
        "status": status,
        "expected_status": health.expected_status,
        "reason_code": if state == "healthy" { "CONTROL_SITE_UPSTREAM_HEALTHY" } else { "CONTROL_SITE_UPSTREAM_STATUS_UNEXPECTED" }
    })
}

fn merged_health_details(
    edge_health: Option<serde_json::Value>,
    upstream_health: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut details = match edge_health {
        Some(serde_json::Value::Object(object)) => serde_json::Value::Object(object),
        _ => json!({}),
    };
    if let Some(upstream) = upstream_health {
        let upstream_state = upstream
            .get("upstream_state")
            .cloned()
            .unwrap_or_else(|| json!("unknown"));
        if let Some(object) = details.as_object_mut() {
            object.insert("upstream_state".to_owned(), upstream_state);
            object.insert("upstream_health".to_owned(), upstream);
        }
    }
    details
}

pub const PATH: &str = "/control/v1/site-config";
pub const SITES_PATH: &str = "/control/v1/sites";
pub const SITE_PATH: &str = "/control/v1/sites/{site_id}";
pub const SITE_CONFIG_PATH: &str = "/control/v1/sites/{site_id}/config";
pub const SITE_REVISIONS_PATH: &str = "/control/v1/sites/{site_id}/revisions";
pub const SITE_STATUS_PATH: &str = "/control/v1/sites/{site_id}/status";
pub const SITE_HEALTH_PATH: &str = "/control/v1/sites/{site_id}/health";
pub const SITE_VALIDATE_PATH: &str = "/control/v1/sites/{site_id}/validate";
pub const SITE_APPLY_PATH: &str = "/control/v1/sites/{site_id}/apply";
pub const SITE_APPROVE_PATH: &str = "/control/v1/sites/{site_id}/approve";
pub const SITE_ROLLBACK_PATH: &str = "/control/v1/sites/{site_id}/rollback";
const ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.write",
    method: "PUT",
    path: PATH,
    role: ManagementRole::SystemAdmin,
};
const READ_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.read",
    method: "GET",
    path: PATH,
    role: ManagementRole::SystemAdmin,
};
const SITE_READ_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.read",
    method: "GET",
    path: SITE_CONFIG_PATH,
    role: ManagementRole::SystemAdmin,
};
const SITE_DETAIL_READ_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.read",
    method: "GET",
    path: SITE_PATH,
    role: ManagementRole::SystemAdmin,
};
const SITE_WRITE_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.write",
    method: "PUT",
    path: SITE_CONFIG_PATH,
    role: ManagementRole::SystemAdmin,
};
const SITE_PATCH_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.write",
    method: "PATCH",
    path: SITE_PATH,
    role: ManagementRole::SystemAdmin,
};
const LIST_ACCESS: AccessAction = AccessAction {
    event_type: "console.sites.list",
    method: "GET",
    path: SITES_PATH,
    role: ManagementRole::SystemAdmin,
};
const CREATE_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.create",
    method: "POST",
    path: SITES_PATH,
    role: ManagementRole::SystemAdmin,
};
const DELETE_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.delete",
    method: "DELETE",
    path: SITE_PATH,
    role: ManagementRole::SystemAdmin,
};
const STATUS_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.status.read",
    method: "GET",
    path: SITE_STATUS_PATH,
    role: ManagementRole::Observer,
};
const HEALTH_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.status.read",
    method: "GET",
    path: SITE_HEALTH_PATH,
    role: ManagementRole::Observer,
};
const REVISIONS_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.status.read",
    method: "GET",
    path: SITE_REVISIONS_PATH,
    role: ManagementRole::Observer,
};
const VALIDATE_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.validate",
    method: "POST",
    path: SITE_VALIDATE_PATH,
    role: ManagementRole::PolicyAuthor,
};
const APPLY_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.apply",
    method: "POST",
    path: SITE_APPLY_PATH,
    role: ManagementRole::ReleaseOperator,
};
const APPROVE_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.approve",
    method: "POST",
    path: SITE_APPROVE_PATH,
    role: ManagementRole::PolicyApprover,
};
const ROLLBACK_ACCESS: AccessAction = AccessAction {
    event_type: "console.site.config.rollback",
    method: "POST",
    path: SITE_ROLLBACK_PATH,
    role: ManagementRole::ReleaseOperator,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfigRequest {
    #[serde(default)]
    site_id: Option<String>,
    display_name: String,
    public_origin: String,
    upstream_address: String,
    upstream_server_name: String,
    upstream_tls: bool,
    #[serde(default)]
    listen_port: u16,
    entry_path: String,
    security_entry: String,
    sensor_enabled: bool,
    policy_revision: String,
    status: String,
    #[serde(default)]
    policy: SitePolicyConfig,
}

#[derive(Serialize)]
struct SiteConfigResponse {
    request_id: String,
    tenant_id: String,
    pub site_id: String,
    found: bool,
    desired_revision: Option<u64>,
    active_revision: Option<u64>,
    apply_state: Option<String>,
    apply_id: Option<String>,
    requires_approval: Option<bool>,
    reason_code: Option<String>,
    config_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    edge_health: Option<serde_json::Value>,
    pub config: Option<SiteConfigView>,
}

#[derive(Serialize)]
pub struct SiteConfigView {
    display_name: String,
    public_origin: String,
    upstream_address: String,
    upstream_server_name: String,
    upstream_tls: bool,
    listen_port: u16,
    entry_path: String,
    security_entry: String,
    sensor_enabled: bool,
    policy_revision: String,
    status: String,
    policy: SitePolicyConfig,
    revision: u64,
    config_digest: String,
    updated_by: String,
    created_at: String,
    updated_at: String,
    gateway_config: serde_json::Value,
}

#[derive(Serialize)]
struct SiteListResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    sites: Vec<SiteListItem>,
    truncated: bool,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct SiteListItem {
    site_id: String,
    display_name: String,
    public_origin: String,
    listen_port: u16,
    security_entry: String,
    sensor_enabled: bool,
    policy_revision: String,
    status: String,
    revision: u64,
    config_digest: String,
    updated_by: String,
    updated_at: String,
    desired_revision: u64,
    active_revision: Option<u64>,
    apply_id: String,
    apply_state: String,
    reason_code: String,
    requires_approval: bool,
}

#[derive(Serialize)]
struct SiteApplyResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    listen_port: u16,
    desired_revision: u64,
    active_revision: Option<u64>,
    config_digest: String,
    apply_state: String,
    apply_id: String,
    reason_code: String,
    requires_approval: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    edge_health: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct SiteRevisionsResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    revisions: Vec<SiteRevisionItem>,
}

#[derive(Serialize)]
struct SiteRevisionItem {
    revision: u64,
    policy_revision: String,
    config_digest: String,
    config: serde_json::Value,
    created_by: String,
    created_at: String,
}

fn parse_site_list_query(raw_query: Option<&str>) -> Result<(Option<String>, u16), ()> {
    let Some(raw_query) = raw_query else {
        return Ok((None, 100));
    };
    if raw_query.len() > 512 {
        return Err(());
    }
    let mut cursor = None;
    let mut limit = 100_u16;
    let mut limit_seen = false;
    for (key, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "cursor" if cursor.is_none() && !value.is_empty() => {
                if value.len() > super::CURSOR_BYTES_MAX {
                    return Err(());
                }
                cursor = Some(value.into_owned());
            }
            "limit" if !limit_seen => {
                limit = value.parse::<u16>().map_err(|_| ())?;
                if !(1..=100).contains(&limit) {
                    return Err(());
                }
                limit_seen = true;
            }
            _ => return Err(()),
        }
    }
    Ok((cursor, limit))
}

fn encode_site_list_cursor(
    control: &ControlPlane,
    subject: &str,
    site_id: &str,
    limit: u16,
) -> Result<String, ()> {
    let signature = super::component_signature(
        &control.config.cursor_key.0,
        &[
            b"xshield-control-sites-cursor-v1",
            &control.config.credential.token_digest,
            subject.as_bytes(),
            control.config.tenant_id.as_str().as_bytes(),
            &limit.to_be_bytes(),
            site_id.as_bytes(),
        ],
    )?;
    Ok(format!("v1.{site_id}.{}", super::lower_hex(&signature)))
}

fn decode_site_list_cursor(
    control: &ControlPlane,
    subject: &str,
    cursor: &str,
    limit: u16,
) -> Result<SiteId, ()> {
    if cursor.len() > super::CURSOR_BYTES_MAX {
        return Err(());
    }
    let Some(cursor) = cursor.strip_prefix("v1.") else {
        return Err(());
    };
    let Some((site_id, signature)) = cursor.rsplit_once('.') else {
        return Err(());
    };
    let site_id = SiteId::parse(site_id).map_err(|_| ())?;
    let supplied = super::parse_lower_hex_32(signature).ok_or(())?;
    let expected = super::component_signature(
        &control.config.cursor_key.0,
        &[
            b"xshield-control-sites-cursor-v1",
            &control.config.credential.token_digest,
            subject.as_bytes(),
            control.config.tenant_id.as_str().as_bytes(),
            &limit.to_be_bytes(),
            site_id.as_str().as_bytes(),
        ],
    )?;
    memcmp::eq(&supplied, &expected)
        .then_some(site_id)
        .ok_or(())
}

pub async fn list_handler(
    State(control): State<Arc<ControlPlane>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match control.authorize_tenant(authorization.as_deref(), &request_id, LIST_ACCESS)
    {
        Ok(subject) => subject,
        Err(response) => return (*response).into_response(),
    };
    let (cursor, limit) = match parse_site_list_query(query.as_deref()) {
        Ok(query) => query,
        Err(()) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    LIST_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_SITE_CURSOR_INVALID",
                    "invalid site list pagination query",
                    false,
                    "correct_request",
                )
                .await
                .into_response();
        }
    };
    let after_site_id = match cursor.as_deref() {
        Some(cursor) => match decode_site_list_cursor(&control, &subject, cursor, limit) {
            Ok(site_id) => Some(site_id),
            Err(()) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        LIST_ACCESS,
                        None,
                        StatusCode::BAD_REQUEST,
                        "CONTROL_SITE_CURSOR_INVALID",
                        "invalid site list pagination cursor",
                        false,
                        "correct_request",
                    )
                    .await
                    .into_response();
            }
        },
        None => None,
    };
    let records = match control
        .catalog
        .list_protected_site_configs(
            &control.config.tenant_id,
            after_site_id.as_ref().map(SiteId::as_str),
            limit.saturating_add(1),
        )
        .await
    {
        Ok(records) => records,
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    LIST_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_CONFIG_UNAVAILABLE",
                    "site configuration is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let truncated = records.len() > usize::from(limit);
    let mut records = records;
    if truncated {
        records.truncate(usize::from(limit));
    }
    let next_cursor = match (truncated, records.last()) {
        (true, Some(record)) => {
            match encode_site_list_cursor(&control, &subject, record.site_id.as_str(), limit) {
                Ok(cursor) => Some(cursor),
                Err(()) => {
                    return control
                        .audited_error_async(
                            request_id,
                            Some(subject),
                            LIST_ACCESS,
                            None,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "CONTROL_CURSOR_UNAVAILABLE",
                            "site list pagination is temporarily unavailable",
                            true,
                            "retry_later",
                        )
                        .await
                        .into_response();
                }
            }
        }
        _ => None,
    };
    if control
        .append_access_event(
            &request_id,
            Some(&subject),
            LIST_ACCESS,
            None,
            "PASS",
            "CONTROL_SITES_LISTED",
        )
        .is_err()
    {
        return super::audit_unavailable(&request_id).into_response();
    }
    let sites = records
        .into_iter()
        .map(|record| SiteListItem {
            site_id: record.site_id,
            display_name: record.display_name,
            public_origin: record.public_origin,
            listen_port: record.listen_port,
            security_entry: record.security_entry,
            sensor_enabled: record.sensor_enabled,
            policy_revision: record.policy_revision,
            status: record.status,
            revision: record.revision,
            config_digest: hex(&record.config_digest),
            updated_by: record.updated_by,
            updated_at: record.updated_at.to_rfc3339(),
            desired_revision: record.desired_revision,
            active_revision: record.active_revision,
            apply_id: record.apply_id,
            apply_state: record.apply_state,
            reason_code: record.reason_code,
            requires_approval: record.requires_approval,
        })
        .collect();
    no_store(
        (
            StatusCode::OK,
            Json(SiteListResponse {
                request_id,
                tenant_id: control.config.tenant_id.as_str().to_owned(),
                site_id: control.config.site_id.as_str().to_owned(),
                sites,
                truncated,
                next_cursor,
            }),
        )
            .into_response(),
    )
}

/// Creates a tenant-scoped site using the strict site configuration contract.
pub async fn create_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let subject =
        match control.authorize_tenant(authorization.as_deref(), &request_id, CREATE_ACCESS) {
            Ok(subject) => subject,
            Err(response) => return (*response).into_response(),
        };
    let site_id = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .get("site_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .and_then(|value| SiteId::parse(value).ok());
    let Some(site_id) = site_id else {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                CREATE_ACCESS,
                None,
                StatusCode::BAD_REQUEST,
                "CONTROL_SITE_ID_INVALID",
                "invalid site identifier",
                false,
                "correct_request",
            )
            .await
            .into_response();
    };
    write_site_handler(control, headers, body, Some(site_id), CREATE_ACCESS).await
}

pub async fn status_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    site_apply_state_handler(
        control,
        site_id,
        headers,
        STATUS_ACCESS,
        false,
        false,
        false,
    )
    .await
}

pub async fn health_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    site_apply_state_handler(control, site_id, headers, HEALTH_ACCESS, false, true, false).await
}

pub async fn revisions_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let Ok(site_id) = SiteId::parse(site_id) else {
        return super::api_error(
            &request_id,
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match control.authorize_site(
        authorization.as_deref(),
        &request_id,
        REVISIONS_ACCESS,
        &site_id,
    ) {
        Ok(subject) => subject,
        Err(response) => return (*response).into_response(),
    };
    let revisions = match control
        .catalog
        .list_protected_site_revisions(&control.config.tenant_id, &site_id, 128)
        .await
    {
        Ok(revisions) => revisions,
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    REVISIONS_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_CONFIG_UNAVAILABLE",
                    "site revision history is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    if control
        .append_access_event(
            &request_id,
            Some(&subject),
            REVISIONS_ACCESS,
            None,
            "PASS",
            "CONTROL_SITE_REVISIONS_READ",
        )
        .is_err()
    {
        return super::audit_unavailable(&request_id).into_response();
    }
    no_store(
        (
            StatusCode::OK,
            Json(SiteRevisionsResponse {
                request_id,
                tenant_id: control.config.tenant_id.as_str().to_owned(),
                site_id: site_id.as_str().to_owned(),
                revisions: revisions
                    .into_iter()
                    .map(|revision| SiteRevisionItem {
                        revision: revision.revision,
                        policy_revision: revision.policy_revision,
                        config_digest: hex(&revision.config_digest),
                        config: revision.config_json,
                        created_by: revision.created_by,
                        created_at: revision.created_at.to_rfc3339(),
                    })
                    .collect(),
            }),
        )
            .into_response(),
    )
}

pub async fn validate_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let Ok(site_id) = SiteId::parse(site_id) else {
        return super::api_error(
            &request_id,
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match control.authorize_site(
        authorization.as_deref(),
        &request_id,
        VALIDATE_ACCESS,
        &site_id,
    ) {
        Ok(subject) => subject,
        Err(response) => return (*response).into_response(),
    };
    let record = match control
        .catalog
        .read_protected_site_config(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    VALIDATE_ACCESS,
                    None,
                    StatusCode::NOT_FOUND,
                    "CONTROL_SITE_NOT_FOUND",
                    "site configuration was not found",
                    false,
                    "correct_request",
                )
                .await
                .into_response();
        }
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    VALIDATE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_CONFIG_UNAVAILABLE",
                    "site configuration is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let payload = SiteConfigRequest {
        site_id: Some(site_id.as_str().to_owned()),
        display_name: record.display_name().to_owned(),
        public_origin: record.public_origin().to_owned(),
        upstream_address: record.upstream_address().to_owned(),
        upstream_server_name: record.upstream_server_name().to_owned(),
        upstream_tls: record.upstream_tls(),
        listen_port: record.listen_port(),
        entry_path: record.entry_path().to_owned(),
        security_entry: record.security_entry().to_owned(),
        sensor_enabled: record.sensor_enabled(),
        policy_revision: record.policy_revision().to_owned(),
        status: record.status().to_owned(),
        policy: record.policy().clone(),
    };
    let valid = validate_request(&payload).is_ok();
    let reason_code = if valid {
        "CONTROL_SITE_VALIDATED"
    } else {
        "CONTROL_SITE_CONFIG_REQUEST_INVALID"
    };
    if control
        .append_access_event(
            &request_id,
            Some(&subject),
            VALIDATE_ACCESS,
            None,
            if valid { "PASS" } else { "DENY" },
            reason_code,
        )
        .is_err()
    {
        return super::audit_unavailable(&request_id).into_response();
    }
    no_store(
        (
            if valid {
                StatusCode::OK
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            },
            Json(json!({
                "request_id": request_id,
                "tenant_id": control.config.tenant_id.as_str(),
                "site_id": site_id.as_str(),
                "revision": record.revision(),
                "config_digest": hex(record.config_digest()),
                "valid": valid,
                "reason_code": reason_code,
            })),
        )
            .into_response(),
    )
}

pub async fn apply_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Extension(auth): Extension<super::identity::AuthContext>,
) -> Response {
    site_apply_state_handler(
        control,
        site_id,
        headers,
        APPLY_ACCESS,
        true,
        false,
        auth.direct_apply,
    )
    .await
}

/// Approves a high-risk desired configuration and immediately attempts the
/// same atomic edge apply used by ordinary saves.
pub async fn approve_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(raw_site_id): Path<String>,
    headers: HeaderMap,
    Extension(auth): Extension<super::identity::AuthContext>,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let Ok(site_id) = SiteId::parse(raw_site_id) else {
        return super::api_error(
            &request_id,
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match control.authorize_site(
        authorization.as_deref(),
        &request_id,
        APPROVE_ACCESS,
        &site_id,
    ) {
        Ok(subject) => subject,
        Err(response) => return (*response).into_response(),
    };
    let Some(idempotency_key) = single_header(&headers, "idempotency-key")
        .filter(|value| super::valid_idempotency_key(value))
    else {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                APPROVE_ACCESS,
                None,
                StatusCode::BAD_REQUEST,
                "CONTROL_IDEMPOTENCY_KEY_INVALID",
                "a valid idempotency key is required",
                false,
                "correct_request",
            )
            .await
            .into_response();
    };
    let apply = match control
        .catalog
        .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(apply)) => apply,
        Ok(None) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    APPROVE_ACCESS,
                    None,
                    StatusCode::NOT_FOUND,
                    "CONTROL_SITE_NOT_FOUND",
                    "site configuration was not found",
                    false,
                    "correct_request",
                )
                .await
                .into_response();
        }
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    APPROVE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    if apply.requires_approval && auth.is_browser_session() && !auth.step_up_valid() {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                APPROVE_ACCESS,
                None,
                StatusCode::UNAUTHORIZED,
                "CONTROL_STEP_UP_REQUIRED",
                "recent management reauthentication is required",
                false,
                "reauthenticate",
            )
            .await
            .into_response();
    }
    let updated_by = match control
        .catalog
        .read_protected_site_config(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(record)) => record.updated_by().to_owned(),
        _ => {
            return super::internal_error(&request_id).into_response();
        }
    };
    if updated_by == subject {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                APPROVE_ACCESS,
                None,
                StatusCode::FORBIDDEN,
                "CONTROL_SITE_APPROVAL_SELF_REJECTED",
                "the configuration author cannot approve the same revision",
                false,
                "independent_approver",
            )
            .await
            .into_response();
    }
    let Some(idempotency_digest) = signature(
        &control,
        b"site-config-approve-idempotency-v1",
        &[
            subject.as_bytes(),
            site_id.as_str().as_bytes(),
            idempotency_key.as_bytes(),
        ],
    ) else {
        return super::internal_error(&request_id).into_response();
    };
    let approval_id = format!("approval_{}", uuid::Uuid::now_v7());
    let approval = match control
        .catalog
        .approve_protected_site_apply(
            &control.config.tenant_id,
            &site_id,
            &approval_id,
            &subject,
            &idempotency_digest,
        )
        .await
    {
        Ok(approval) => approval,
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    APPROVE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    if matches!(&approval, ProtectedSiteApprovalOutcome::Conflict) {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                APPROVE_ACCESS,
                None,
                StatusCode::CONFLICT,
                "CONTROL_IDEMPOTENCY_CONFLICT",
                "idempotency key is bound to a different approval",
                false,
                "use_original_request",
            )
            .await
            .into_response();
    }
    if matches!(&approval, ProtectedSiteApprovalOutcome::NotRequired) && apply.requires_approval {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                APPROVE_ACCESS,
                None,
                StatusCode::CONFLICT,
                "CONTROL_SITE_APPROVAL_NOT_REQUIRED",
                "the desired revision does not require approval",
                false,
                "read_site_status",
            )
            .await
            .into_response();
    }
    let current = match control
        .catalog
        .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(current)) => current,
        _ => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    APPROVE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    if current.apply_state != "active"
        || matches!(&approval, ProtectedSiteApprovalOutcome::Applied { .. })
    {
        let _ = apply_site_snapshot(&control, &site_id, &current, false).await;
    }
    let state = match control
        .catalog
        .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(state)) => state,
        _ => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    APPROVE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let record = match control
        .catalog
        .read_protected_site_config(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(record)) => record,
        _ => {
            return super::internal_error(&request_id).into_response();
        }
    };
    if control
        .append_access_event(
            &request_id,
            Some(&subject),
            APPROVE_ACCESS,
            None,
            "PASS",
            if state.apply_state == "active" {
                "CONTROL_SITE_APPROVED_AND_APPLIED"
            } else {
                "CONTROL_SITE_APPROVED_PENDING"
            },
        )
        .is_err()
    {
        return super::audit_unavailable(&request_id).into_response();
    }
    no_store(
        (
            StatusCode::OK,
            Json(SiteApplyResponse {
                request_id,
                tenant_id: control.config.tenant_id.as_str().to_owned(),
                site_id: site_id.as_str().to_owned(),
                listen_port: record.listen_port(),
                desired_revision: state.desired_revision,
                active_revision: state.active_revision,
                config_digest: hex(record.config_digest()),
                apply_state: state.apply_state,
                apply_id: state.apply_id,
                reason_code: state.reason_code,
                requires_approval: state.requires_approval,
                edge_health: None,
            }),
        )
            .into_response(),
    )
}

pub async fn rollback_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let Ok(site_id) = SiteId::parse(site_id) else {
        return super::api_error(
            &request_id,
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match control.authorize_site(
        authorization.as_deref(),
        &request_id,
        ROLLBACK_ACCESS,
        &site_id,
    ) {
        Ok(subject) => subject,
        Err(response) => return (*response).into_response(),
    };
    if single_header(&headers, "idempotency-key")
        .filter(|value| super::valid_idempotency_key(value))
        .is_none()
    {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                ROLLBACK_ACCESS,
                None,
                StatusCode::BAD_REQUEST,
                "CONTROL_IDEMPOTENCY_KEY_INVALID",
                "a valid idempotency key is required",
                false,
                "correct_request",
            )
            .await
            .into_response();
    }
    let apply = match control
        .catalog
        .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(apply)) => apply,
        Ok(None) | Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    ROLLBACK_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let Some(previous_revision) = rollback_target_revision(&apply) else {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                ROLLBACK_ACCESS,
                None,
                StatusCode::CONFLICT,
                "CONTROL_SITE_ROLLBACK_UNAVAILABLE",
                "no previously active snapshot is available for rollback",
                false,
                "inspect_revisions",
            )
            .await
            .into_response();
    };
    let Some(mut payload) = (match control
        .catalog
        .read_protected_site_revision_config(&control.config.tenant_id, &site_id, previous_revision)
        .await
    {
        Ok(payload) => payload,
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    ROLLBACK_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_CONFIG_UNAVAILABLE",
                    "site revision history is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    }) else {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                ROLLBACK_ACCESS,
                None,
                StatusCode::CONFLICT,
                "CONTROL_SITE_ROLLBACK_UNAVAILABLE",
                "no previously active snapshot is available for rollback",
                false,
                "inspect_revisions",
            )
            .await
            .into_response();
    };
    let Some(object) = payload.as_object_mut() else {
        return super::internal_error(&request_id).into_response();
    };
    object.insert("site_id".to_owned(), json!(site_id.as_str()));
    let Ok(body) = serde_json::to_vec(&payload) else {
        return super::internal_error(&request_id).into_response();
    };
    write_site_handler(
        control,
        headers,
        Bytes::from(body),
        Some(site_id),
        ROLLBACK_ACCESS,
    )
    .await
}

fn rollback_target_revision(apply: &xshield_postgres::ProtectedSiteApplyState) -> Option<u64> {
    match apply.active_revision {
        Some(active) if apply.apply_state != "active" || apply.desired_revision != active => {
            Some(active)
        }
        Some(active) => active.checked_sub(1),
        None => None,
    }
}

async fn site_apply_state_handler(
    control: Arc<ControlPlane>,
    raw_site_id: String,
    headers: HeaderMap,
    action: AccessAction,
    require_idempotency: bool,
    read_health: bool,
    direct_apply: bool,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let Ok(site_id) = SiteId::parse(raw_site_id) else {
        return super::api_error(
            &request_id,
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let subject =
        match control.authorize_site(authorization.as_deref(), &request_id, action, &site_id) {
            Ok(subject) => subject,
            Err(response) => return (*response).into_response(),
        };
    if require_idempotency
        && single_header(&headers, "idempotency-key")
            .filter(|value| super::valid_idempotency_key(value))
            .is_none()
    {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::BAD_REQUEST,
                "CONTROL_IDEMPOTENCY_KEY_INVALID",
                "a valid idempotency key is required",
                false,
                "correct_request",
            )
            .await
            .into_response();
    }
    let record = match control
        .catalog
        .read_protected_site_config(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::NOT_FOUND,
                    "CONTROL_SITE_NOT_FOUND",
                    "site configuration was not found",
                    false,
                    "correct_request",
                )
                .await
                .into_response();
        }
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_CONFIG_UNAVAILABLE",
                    "site configuration is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let apply = match control
        .catalog
        .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(apply)) => apply,
        Ok(None) | Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let edge_health = if read_health {
        Some(match control.gateway_apply.as_ref() {
            Some(client) => client.health().await.unwrap_or_else(
                |reason| json!({ "edge_state": "unavailable", "reason_code": reason }),
            ),
            None => json!({ "edge_state": "unconfigured" }),
        })
    } else {
        None
    };
    let upstream_health = if read_health {
        Some(probe_upstream(&record).await)
    } else {
        None
    };
    let health_details =
        read_health.then(|| merged_health_details(edge_health.clone(), upstream_health));
    if require_idempotency {
        let _ = apply_site_snapshot(&control, &site_id, &apply, direct_apply).await;
    }
    let apply = match control
        .catalog
        .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(apply)) => apply,
        Ok(None) | Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let (audit_outcome, audit_reason) = if require_idempotency {
        if apply.apply_state == "active" {
            ("PASS", "EDGE_APPLY_CONFIRMED")
        } else if apply.requires_approval {
            ("DENY", "CONTROL_SITE_APPROVAL_REQUIRED")
        } else {
            ("ERROR", "EDGE_APPLY_NOT_CONFIRMED")
        }
    } else {
        ("PASS", "CONTROL_SITE_STATUS_READ")
    };
    if control
        .append_access_event(
            &request_id,
            Some(&subject),
            action,
            None,
            audit_outcome,
            audit_reason,
        )
        .is_err()
    {
        return super::audit_unavailable(&request_id).into_response();
    }
    if read_health {
        let details = health_details.clone().unwrap_or_else(|| json!({}));
        let edge_state = details
            .get("edge_state")
            .and_then(serde_json::Value::as_str)
            .map_or("unknown", |state| match state {
                "healthy" | "degraded" | "unavailable" => state,
                _ => "unknown",
            });
        let audit_state = details
            .get("audit_state")
            .and_then(serde_json::Value::as_str)
            .map_or("unknown", |state| match state {
                "healthy" | "degraded" | "unavailable" => state,
                _ => "unknown",
            });
        let upstream_state = details
            .get("upstream_state")
            .and_then(serde_json::Value::as_str)
            .map_or("unknown", |state| match state {
                "healthy" | "degraded" | "unavailable" => state,
                _ => "unknown",
            });
        if control
            .catalog
            .insert_protected_site_health_snapshot(
                &control.config.tenant_id,
                &site_id,
                edge_state,
                upstream_state,
                &apply.apply_state,
                audit_state,
                &apply.reason_code,
                &details,
            )
            .await
            .is_err()
        {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_HEALTH_UNAVAILABLE",
                    "site health observation is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    }
    no_store(
        (
            StatusCode::OK,
            Json(SiteApplyResponse {
                request_id,
                tenant_id: control.config.tenant_id.as_str().to_owned(),
                site_id: site_id.as_str().to_owned(),
                listen_port: record.listen_port(),
                desired_revision: apply.desired_revision,
                active_revision: apply.active_revision,
                config_digest: hex(record.config_digest()),
                apply_state: apply.apply_state,
                apply_id: apply.apply_id,
                reason_code: apply.reason_code,
                requires_approval: apply.requires_approval,
                edge_health: health_details,
            }),
        )
            .into_response(),
    )
}

/// Removes a site only after a configured edge has acknowledged a snapshot
/// without that site's route. If the edge is unavailable, the durable site is
/// left paused and the old edge snapshot remains the serving truth.
pub async fn delete_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let Ok(site_id) = SiteId::parse(site_id) else {
        return super::api_error(
            &request_id,
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let subject = match control.authorize_site(
        authorization.as_deref(),
        &request_id,
        DELETE_ACCESS,
        &site_id,
    ) {
        Ok(subject) => subject,
        Err(response) => return (*response).into_response(),
    };
    let Some(idempotency_key) = single_header(&headers, "idempotency-key")
        .filter(|value| super::valid_idempotency_key(value))
    else {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                DELETE_ACCESS,
                None,
                StatusCode::BAD_REQUEST,
                "CONTROL_IDEMPOTENCY_KEY_INVALID",
                "a valid idempotency key is required",
                false,
                "correct_request",
            )
            .await
            .into_response();
    };
    let record = match control
        .catalog
        .read_protected_site_config(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    DELETE_ACCESS,
                    None,
                    StatusCode::NOT_FOUND,
                    "CONTROL_SITE_NOT_FOUND",
                    "site configuration was not found",
                    false,
                    "correct_request",
                )
                .await
                .into_response();
        }
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    DELETE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_CONFIG_UNAVAILABLE",
                    "site configuration is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    if control.gateway_apply.is_some() {
        let paused_payload = json!({
            "site_id": site_id.as_str(),
            "display_name": record.display_name(),
            "public_origin": record.public_origin(),
            "upstream_address": record.upstream_address(),
            "upstream_server_name": record.upstream_server_name(),
            "upstream_tls": record.upstream_tls(),
            "listen_port": record.listen_port(),
            "entry_path": record.entry_path(),
            "security_entry": record.security_entry(),
            "sensor_enabled": record.sensor_enabled(),
            "policy_revision": record.policy_revision(),
            "status": "paused",
            "policy": record.policy(),
        });
        let Ok(canonical) = serde_json::to_vec(&paused_payload) else {
            return super::internal_error(&request_id).into_response();
        };
        let Some(idempotency_digest) = signature(
            &control,
            b"site-delete-pause-idempotency-v1",
            &[
                subject.as_bytes(),
                site_id.as_str().as_bytes(),
                idempotency_key.as_bytes(),
            ],
        ) else {
            return super::internal_error(&request_id).into_response();
        };
        let Some(request_digest) = signature(
            &control,
            b"site-delete-pause-request-v1",
            &[
                subject.as_bytes(),
                site_id.as_str().as_bytes(),
                idempotency_key.as_bytes(),
                &canonical,
            ],
        ) else {
            return super::internal_error(&request_id).into_response();
        };
        let config_digest = openssl::sha::sha256(&canonical);
        let paused = match control
            .catalog
            .upsert_protected_site_config(ProtectedSiteConfigUpsert {
                tenant_id: &control.config.tenant_id,
                site_id: &site_id,
                display_name: record.display_name(),
                public_origin: record.public_origin(),
                upstream_address: record.upstream_address(),
                upstream_server_name: record.upstream_server_name(),
                upstream_tls: record.upstream_tls(),
                listen_port: record.listen_port(),
                entry_path: record.entry_path(),
                security_entry: record.security_entry(),
                sensor_enabled: record.sensor_enabled(),
                policy_revision: record.policy_revision(),
                status: "paused",
                policy: record.policy(),
                requires_approval: false,
                config_digest: &config_digest,
                updated_by: &subject,
                idempotency_digest: &idempotency_digest,
                request_digest: &request_digest,
            })
            .await
        {
            Ok(
                ProtectedSiteConfigWriteOutcome::Created(record)
                | ProtectedSiteConfigWriteOutcome::Updated(record)
                | ProtectedSiteConfigWriteOutcome::Existing(record),
            ) => record,
            Ok(ProtectedSiteConfigWriteOutcome::Conflict) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        DELETE_ACCESS,
                        None,
                        StatusCode::CONFLICT,
                        "CONTROL_IDEMPOTENCY_CONFLICT",
                        "idempotency key is bound to different configuration",
                        false,
                        "use_original_request",
                    )
                    .await
                    .into_response();
            }
            Ok(ProtectedSiteConfigWriteOutcome::PortConflict) | Err(_) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        DELETE_ACCESS,
                        None,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_SITE_CONFIG_UNAVAILABLE",
                        "site configuration is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await
                    .into_response();
            }
        };
        let paused_apply = match control
            .catalog
            .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
            .await
        {
            Ok(Some(apply)) => apply,
            Ok(None) | Err(_) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        DELETE_ACCESS,
                        None,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                        "site application state is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await
                    .into_response();
            }
        };
        if apply_site_snapshot(&control, &site_id, &paused_apply, false)
            .await
            .is_err()
        {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    DELETE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_DELETE_EDGE_NOT_CONFIRMED",
                    "edge has not confirmed removal of the site route",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
        let still_paused = match control
            .catalog
            .read_protected_site_config(&control.config.tenant_id, &site_id)
            .await
        {
            Ok(Some(current)) => {
                current.revision() == paused.revision() && current.status() == "paused"
            }
            Ok(None) => false,
            Err(_) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        DELETE_ACCESS,
                        None,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_SITE_CONFIG_UNAVAILABLE",
                        "site configuration is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await
                    .into_response();
            }
        };
        if !still_paused {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    DELETE_ACCESS,
                    None,
                    StatusCode::CONFLICT,
                    "CONTROL_SITE_DELETE_CONCURRENT_UPDATE",
                    "site changed while deletion was being applied",
                    false,
                    "refresh_site",
                )
                .await
                .into_response();
        }
    }
    let deleted = match control
        .catalog
        .delete_protected_site_config(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(deleted) => deleted,
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    DELETE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_CONFIG_UNAVAILABLE",
                    "site configuration is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let reason = if deleted {
        "CONTROL_SITE_DELETED"
    } else {
        "CONTROL_SITE_DELETE_REPLAYED"
    };
    if control
        .append_access_event(
            &request_id,
            Some(&subject),
            DELETE_ACCESS,
            None,
            "PASS",
            reason,
        )
        .is_err()
    {
        return super::audit_unavailable(&request_id).into_response();
    }
    no_store(
        (
            if deleted {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            },
            Json(serde_json::json!({
                "request_id": request_id,
                "tenant_id": control.config.tenant_id.as_str(),
                "site_id": site_id.as_str(),
                "reason_code": reason,
            })),
        )
            .into_response(),
    )
}

pub async fn read_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
) -> Response {
    read_site_handler(control, headers, None, READ_ACCESS).await
}

pub async fn read_site_path_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(site_id) = SiteId::parse(site_id) else {
        return super::api_error(
            &format!("req_{}", uuid::Uuid::now_v7()),
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    read_site_handler(control, headers, Some(site_id), SITE_READ_ACCESS).await
}

pub async fn read_site_detail_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(site_id) = SiteId::parse(site_id) else {
        return super::api_error(
            &format!("req_{}", uuid::Uuid::now_v7()),
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    read_site_handler(control, headers, Some(site_id), SITE_DETAIL_READ_ACCESS).await
}

async fn read_site_handler(
    control: Arc<ControlPlane>,
    headers: HeaderMap,
    requested_site: Option<SiteId>,
    action: AccessAction,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let site_id = requested_site.unwrap_or_else(|| control.config.site_id.clone());
    let subject =
        match control.authorize_site(authorization.as_deref(), &request_id, action, &site_id) {
            Ok(subject) => subject,
            Err(response) => return (*response).into_response(),
        };
    let result = control
        .catalog
        .read_protected_site_config(&control.config.tenant_id, &site_id)
        .await;
    let Ok(record) = result else {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_SITE_CONFIG_UNAVAILABLE",
                "site configuration is temporarily unavailable",
                true,
                "retry_later",
            )
            .await
            .into_response();
    };
    if control
        .append_access_event(
            &request_id,
            Some(&subject),
            action,
            None,
            "PASS",
            "CONTROL_SITE_CONFIG_READ",
        )
        .is_err()
    {
        return super::audit_unavailable(&request_id).into_response();
    }
    let config = record.map(|record| view(&control, &site_id, &record));
    let apply = if config.is_some() {
        match control
            .catalog
            .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
            .await
        {
            Ok(Some(apply)) => Some(apply),
            Ok(None) | Err(_) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        action,
                        None,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                        "site application state is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await
                    .into_response();
            }
        }
    } else {
        None
    };
    let response = SiteConfigResponse {
        request_id: request_id.clone(),
        tenant_id: control.config.tenant_id.as_str().to_owned(),
        site_id: site_id.as_str().to_owned(),
        found: config.is_some(),
        desired_revision: apply.as_ref().map(|value| value.desired_revision),
        active_revision: apply.as_ref().and_then(|value| value.active_revision),
        apply_state: apply.as_ref().map(|value| value.apply_state.clone()),
        apply_id: apply.as_ref().map(|value| value.apply_id.clone()),
        requires_approval: apply.as_ref().map(|value| value.requires_approval),
        reason_code: apply.as_ref().map(|value| value.reason_code.clone()),
        config_digest: config.as_ref().map(|value| value.config_digest.clone()),
        edge_health: if config.is_some() {
            Some(edge_health(&control).await)
        } else {
            None
        },
        config,
    };
    no_store((StatusCode::OK, Json(response)).into_response())
}

#[allow(clippy::too_many_lines)]
pub async fn write_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    write_site_handler(control, headers, body, None, ACCESS).await
}

pub async fn write_site_path_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(site_id) = SiteId::parse(site_id) else {
        return super::api_error(
            &format!("req_{}", uuid::Uuid::now_v7()),
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    write_site_handler(control, headers, body, Some(site_id), SITE_WRITE_ACCESS).await
}

pub async fn patch_site_path_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(site_id) = SiteId::parse(site_id) else {
        return super::api_error(
            &format!("req_{}", uuid::Uuid::now_v7()),
            StatusCode::BAD_REQUEST,
            "CONTROL_SITE_ID_INVALID",
            "invalid site identifier",
            false,
            "correct_request",
        )
        .into_response();
    };
    write_site_handler(control, headers, body, Some(site_id), SITE_PATCH_ACCESS).await
}

#[allow(clippy::too_many_lines)]
async fn write_site_handler(
    control: Arc<ControlPlane>,
    headers: HeaderMap,
    body: Bytes,
    requested_site: Option<SiteId>,
    action: AccessAction,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let site_id = requested_site.unwrap_or_else(|| control.config.site_id.clone());
    let subject =
        match control.authorize_site(authorization.as_deref(), &request_id, action, &site_id) {
            Ok(subject) => subject,
            Err(response) => return (*response).into_response(),
        };
    let Some(idempotency_key) = single_header(&headers, "idempotency-key")
        .filter(|value| super::valid_idempotency_key(value))
    else {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::BAD_REQUEST,
                "CONTROL_IDEMPOTENCY_KEY_INVALID",
                "a valid idempotency key is required",
                false,
                "correct_request",
            )
            .await
            .into_response();
    };
    if body.len() > 16 * 1024 {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::BAD_REQUEST,
                "CONTROL_SITE_CONFIG_REQUEST_INVALID",
                "invalid site configuration",
                false,
                "correct_request",
            )
            .await
            .into_response();
    }
    let payload: SiteConfigRequest = if action.method == "PATCH" {
        match merge_patch_payload(&control, &site_id, &body).await {
            Ok(payload) => payload,
            Err("CONTROL_SITE_NOT_FOUND") => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        action,
                        None,
                        StatusCode::NOT_FOUND,
                        "CONTROL_SITE_NOT_FOUND",
                        "site configuration was not found",
                        false,
                        "create_site",
                    )
                    .await
                    .into_response();
            }
            Err("CONTROL_SITE_CONFIG_UNAVAILABLE") => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        action,
                        None,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_SITE_CONFIG_UNAVAILABLE",
                        "site configuration is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await
                    .into_response();
            }
            Err(_) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        action,
                        None,
                        StatusCode::BAD_REQUEST,
                        "CONTROL_SITE_CONFIG_REQUEST_INVALID",
                        "invalid site configuration",
                        false,
                        "correct_request",
                    )
                    .await
                    .into_response();
            }
        }
    } else {
        match serde_json::from_slice(&body) {
            Ok(payload) => payload,
            Err(_) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        action,
                        None,
                        StatusCode::BAD_REQUEST,
                        "CONTROL_SITE_CONFIG_REQUEST_INVALID",
                        "invalid site configuration",
                        false,
                        "correct_request",
                    )
                    .await
                    .into_response();
            }
        }
    };
    if payload
        .site_id
        .as_deref()
        .is_some_and(|value| value != site_id.as_str())
    {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::BAD_REQUEST,
                "CONTROL_SITE_ID_INVALID",
                "site identifier does not match the route",
                false,
                "correct_request",
            )
            .await
            .into_response();
    }
    if let Err(reason) = validate_request(&payload) {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::BAD_REQUEST,
                reason,
                "invalid site configuration",
                false,
                "correct_request",
            )
            .await
            .into_response();
    }
    let previous = match control
        .catalog
        .read_protected_site_config(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(previous) => previous,
        Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_CONFIG_UNAVAILABLE",
                    "site configuration is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let requires_approval = requires_policy_approval(previous.as_ref(), &payload);
    let Ok(canonical) = serde_json::to_vec(&payload) else {
        return super::internal_error(&request_id).into_response();
    };
    let Some(idempotency_digest) = signature(
        &control,
        b"site-config-idempotency-v2",
        &[
            action.event_type.as_bytes(),
            action.method.as_bytes(),
            action.path.as_bytes(),
            subject.as_bytes(),
            site_id.as_str().as_bytes(),
            idempotency_key.as_bytes(),
        ],
    ) else {
        return super::internal_error(&request_id).into_response();
    };
    let Some(request_digest) = signature(
        &control,
        b"site-config-request-v2",
        &[
            action.event_type.as_bytes(),
            action.method.as_bytes(),
            action.path.as_bytes(),
            subject.as_bytes(),
            site_id.as_str().as_bytes(),
            idempotency_key.as_bytes(),
            &canonical,
        ],
    ) else {
        return super::internal_error(&request_id).into_response();
    };
    let config_digest = openssl::sha::sha256(&canonical);
    let result = control
        .catalog
        .upsert_protected_site_config(ProtectedSiteConfigUpsert {
            tenant_id: &control.config.tenant_id,
            site_id: &site_id,
            display_name: &payload.display_name,
            public_origin: &payload.public_origin,
            upstream_address: &payload.upstream_address,
            upstream_server_name: &payload.upstream_server_name,
            upstream_tls: payload.upstream_tls,
            listen_port: payload.listen_port,
            entry_path: &payload.entry_path,
            security_entry: &payload.security_entry,
            sensor_enabled: payload.sensor_enabled,
            policy_revision: &payload.policy_revision,
            status: &payload.status,
            policy: &payload.policy,
            requires_approval,
            config_digest: &config_digest,
            updated_by: &subject,
            idempotency_digest: &idempotency_digest,
            request_digest: &request_digest,
        })
        .await;
    let Ok(outcome) = result else {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_SITE_CONFIG_UNAVAILABLE",
                "site configuration is temporarily unavailable",
                true,
                "retry_later",
            )
            .await
            .into_response();
    };
    let (record, status, reason, replayed) = match outcome {
        ProtectedSiteConfigWriteOutcome::Created(record) => (
            record,
            StatusCode::CREATED,
            "CONTROL_SITE_CONFIG_CREATED",
            false,
        ),
        ProtectedSiteConfigWriteOutcome::Updated(record) => {
            (record, StatusCode::OK, "CONTROL_SITE_CONFIG_UPDATED", false)
        }
        ProtectedSiteConfigWriteOutcome::Existing(record) => {
            (record, StatusCode::OK, "CONTROL_SITE_CONFIG_REPLAYED", true)
        }
        ProtectedSiteConfigWriteOutcome::Conflict => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::CONFLICT,
                    "CONTROL_IDEMPOTENCY_CONFLICT",
                    "idempotency key is bound to different configuration",
                    false,
                    "use_original_request",
                )
                .await
                .into_response();
        }
        ProtectedSiteConfigWriteOutcome::PortConflict => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::CONFLICT,
                    "CONTROL_SITE_PORT_UNAVAILABLE",
                    "requested listener port is unavailable",
                    false,
                    "choose_another_port",
                )
                .await
                .into_response();
        }
    };
    if control
        .append_access_event(&request_id, Some(&subject), action, None, "PASS", reason)
        .is_err()
    {
        return super::audit_unavailable(&request_id).into_response();
    }
    let response = SiteConfigResponse {
        request_id: request_id.clone(),
        tenant_id: control.config.tenant_id.as_str().to_owned(),
        site_id: site_id.as_str().to_owned(),
        found: true,
        desired_revision: None,
        active_revision: None,
        apply_state: None,
        apply_id: None,
        requires_approval: None,
        reason_code: None,
        config_digest: Some(hex(record.config_digest())),
        edge_health: None,
        config: Some(view(&control, &site_id, &record)),
    };
    let apply = match control
        .catalog
        .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(apply)) => apply,
        Ok(None) | Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    if !(replayed && apply.apply_state == "active") {
        let _ = apply_site_snapshot(&control, &site_id, &apply, false).await;
    }
    let apply = match control
        .catalog
        .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
        .await
    {
        Ok(Some(apply)) => apply,
        Ok(None) | Err(_) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await
                .into_response();
        }
    };
    let response = SiteConfigResponse {
        request_id: response.request_id,
        tenant_id: response.tenant_id,
        site_id: response.site_id,
        found: response.found,
        desired_revision: Some(apply.desired_revision),
        active_revision: apply.active_revision,
        apply_state: Some(apply.apply_state),
        apply_id: Some(apply.apply_id),
        requires_approval: Some(apply.requires_approval),
        reason_code: Some(apply.reason_code),
        config_digest: response.config_digest,
        edge_health: Some(edge_health(&control).await),
        config: response.config,
    };
    no_store((status, Json(response)).into_response())
}

/// Sends the complete tenant snapshot and commits exact desired revisions only
/// after the edge confirms an atomic replacement. A missing edge binding is a
/// deliberate `pending` state for development and control-plane-only deploys.
async fn apply_site_snapshot(
    control: &ControlPlane,
    target_site: &SiteId,
    target_apply: &xshield_postgres::ProtectedSiteApplyState,
    direct_apply: bool,
) -> Result<bool, &'static str> {
    if target_apply.requires_approval && !direct_apply {
        return Err("CONTROL_SITE_APPROVAL_REQUIRED");
    }
    let Some(client) = control.gateway_apply.as_ref() else {
        return Ok(false);
    };
    let records = control
        .catalog
        .list_protected_site_config_records(&control.config.tenant_id)
        .await
        .map_err(|_| "CONTROL_SITE_CONFIG_UNAVAILABLE")?;
    let snapshot_revision = control
        .catalog
        .next_protected_site_snapshot_revision(&control.config.tenant_id)
        .await
        .map_err(|_| "CONTROL_SITE_APPLY_STATE_UNAVAILABLE")?;
    let mut sites = Vec::with_capacity(records.len());
    let mut revisions = Vec::with_capacity(records.len());
    for (site_id, record) in records {
        let apply = control
            .catalog
            .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
            .await
            .map_err(|_| "CONTROL_SITE_APPLY_STATE_UNAVAILABLE")?
            .ok_or("CONTROL_SITE_APPLY_STATE_UNAVAILABLE")?;
        // A complete edge snapshot cannot mix an unapproved desired config
        // with other sites. Stop before sending anything so a normal save can
        // never smuggle a high-risk sibling revision past its approver.
        if apply.requires_approval && !(direct_apply && site_id == *target_site) {
            return Err("CONTROL_SITE_APPROVAL_REQUIRED");
        }
        revisions.push((site_id.clone(), apply.desired_revision, apply.apply_id));
        if record.status() == "paused" {
            continue;
        }
        let gateway_config = view(control, &site_id, &record).gateway_config;
        sites.push(GatewayApplySite {
            site_id: site_id.as_str().to_owned(),
            listen_port: record.listen_port(),
            public_origin: record.public_origin().to_owned(),
            gateway_config,
            revision: record.revision(),
        });
    }
    let request = GatewayApplyRequest {
        protocol_version: 1,
        tenant_id: control.config.tenant_id.as_str().to_owned(),
        apply_id: target_apply.apply_id.clone(),
        snapshot_revision,
        sites,
    };
    if let Err(reason) = client.apply(&request).await {
        control
            .catalog
            .mark_protected_site_apply_failed(
                &control.config.tenant_id,
                target_site,
                target_apply.desired_revision,
                &target_apply.apply_id,
                reason,
            )
            .await
            .map_err(|_| "CONTROL_SITE_APPLY_STATE_UNAVAILABLE")?;
        return Err(reason);
    }
    if !control
        .catalog
        .mark_protected_site_applies_active_batch(&control.config.tenant_id, &revisions)
        .await
        .map_err(|_| "CONTROL_SITE_APPLY_STATE_UNAVAILABLE")?
    {
        return Err("CONTROL_SITE_APPLY_STATE_UNAVAILABLE");
    }
    Ok(true)
}

async fn merge_patch_payload(
    control: &ControlPlane,
    site_id: &SiteId,
    body: &[u8],
) -> Result<SiteConfigRequest, &'static str> {
    let patch = serde_json::from_slice::<serde_json::Value>(body)
        .map_err(|_| "CONTROL_SITE_CONFIG_REQUEST_INVALID")?;
    let Some(patch_object) = patch.as_object() else {
        return Err("CONTROL_SITE_CONFIG_REQUEST_INVALID");
    };
    if !patch_is_compatible(patch_object, site_id) {
        return Err("CONTROL_SITE_CONFIG_REQUEST_INVALID");
    }
    let record = control
        .catalog
        .read_protected_site_config(&control.config.tenant_id, site_id)
        .await
        .map_err(|_| "CONTROL_SITE_CONFIG_UNAVAILABLE")?
        .ok_or("CONTROL_SITE_NOT_FOUND")?;
    let mut merged = json!({
        "site_id": site_id.as_str(),
        "display_name": record.display_name(),
        "public_origin": record.public_origin(),
        "upstream_address": record.upstream_address(),
        "upstream_server_name": record.upstream_server_name(),
        "upstream_tls": record.upstream_tls(),
        "listen_port": record.listen_port(),
        "entry_path": record.entry_path(),
        "security_entry": record.security_entry(),
        "sensor_enabled": record.sensor_enabled(),
        "policy_revision": record.policy_revision(),
        "status": record.status(),
        "policy": record.policy(),
    });
    let merged_object = merged
        .as_object_mut()
        .ok_or("CONTROL_SITE_CONFIG_REQUEST_INVALID")?;
    for (key, value) in patch_object {
        if key != "site_id" {
            merged_object.insert(key.clone(), value.clone());
        }
    }
    serde_json::from_value(merged).map_err(|_| "CONTROL_SITE_CONFIG_REQUEST_INVALID")
}

fn patch_is_compatible(
    patch: &serde_json::Map<String, serde_json::Value>,
    site_id: &SiteId,
) -> bool {
    const ALLOWED: &[&str] = &[
        "site_id",
        "display_name",
        "public_origin",
        "upstream_address",
        "upstream_server_name",
        "upstream_tls",
        "listen_port",
        "entry_path",
        "security_entry",
        "sensor_enabled",
        "policy_revision",
        "status",
        "policy",
    ];
    patch.keys().all(|key| ALLOWED.contains(&key.as_str()))
        && patch
            .get("site_id")
            .is_none_or(|value| value.as_str() == Some(site_id.as_str()))
}

pub(super) async fn edge_health(control: &ControlPlane) -> serde_json::Value {
    match control.gateway_apply.as_ref() {
        Some(client) => client
            .health()
            .await
            .unwrap_or_else(|reason| json!({ "edge_state": "unavailable", "reason_code": reason })),
        None => json!({ "edge_state": "unconfigured" }),
    }
}

fn validate_request(request: &SiteConfigRequest) -> Result<(), &'static str> {
    let public =
        Url::parse(&request.public_origin).map_err(|_| "CONTROL_SITE_CONFIG_REQUEST_INVALID")?;
    let upstream = Url::parse(&format!(
        "{}://{}",
        if request.upstream_tls {
            "https"
        } else {
            "http"
        },
        request.upstream_address
    ))
    .map_err(|_| "CONTROL_SITE_UPSTREAM_INVALID")?;
    let public_loopback = public.host().is_some_and(|host| match host {
        url::Host::Domain(name) => name == "localhost",
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    });
    if public.host().is_none()
        || !public.username().is_empty()
        || public.password().is_some()
        || (public.scheme() != "https" && !public_loopback)
        || !matches!(public.path(), "" | "/")
        || public.query().is_some()
        || public.fragment().is_some()
    {
        return Err("CONTROL_SITE_CONFIG_REQUEST_INVALID");
    }
    if public.scheme() == "https" && PublicOrigin::parse(request.public_origin.clone()).is_err() {
        return Err("CONTROL_SITE_CONFIG_REQUEST_INVALID");
    }
    if upstream.host().is_none()
        || upstream.port().is_none()
        || !upstream.username().is_empty()
        || upstream.password().is_some()
        || !matches!(upstream.path(), "" | "/")
        || upstream.query().is_some()
        || upstream.fragment().is_some()
    {
        return Err("CONTROL_SITE_UPSTREAM_INVALID");
    }
    UpstreamEndpoint::parse(
        request.upstream_address.clone(),
        request.upstream_server_name.clone(),
        request.upstream_tls,
    )
    .map_err(|_| "CONTROL_SITE_UPSTREAM_INVALID")?;
    if upstream_host_is_unsafe(&upstream) {
        return Err("CONTROL_SITE_SSRF_BLOCKED");
    }
    if request
        .upstream_address
        .parse::<std::net::SocketAddr>()
        .is_err()
    {
        return Err("CONTROL_SITE_UPSTREAM_INVALID");
    }
    if request.display_name.is_empty()
        || request.display_name.len() > 128
        || request.display_name.trim() != request.display_name
        || request.display_name.chars().any(char::is_control)
        || (request.listen_port != 0 && !(6100..=65535).contains(&request.listen_port))
        || !request
            .upstream_server_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || !matches!(
            request.security_entry.as_str(),
            "public" | "authenticated_root" | "ui_action_required"
        )
        || !matches!(request.status.as_str(), "draft" | "active" | "paused")
        || !request.entry_path.starts_with('/')
        || request.entry_path.contains(['?', '#'])
        || request.policy_revision.is_empty()
        || request.policy_revision.len() > 128
        || !request
            .policy_revision
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("CONTROL_SITE_CONFIG_REQUEST_INVALID");
    }
    let security_entry = SecurityEntry::parse(&request.security_entry)
        .map_err(|_| "CONTROL_SITE_CONFIG_REQUEST_INVALID")?;
    RouteOperation::new(
        "protected.entry",
        "GET",
        request.entry_path.clone(),
        security_entry,
    )
    .map_err(|_| "CONTROL_SITE_CONFIG_REQUEST_INVALID")?;
    request
        .policy
        .validate()
        .map_err(|_| "CONTROL_SITE_POLICY_INVALID")?;
    Ok(())
}

fn requires_policy_approval(
    previous: Option<&xshield_postgres::ProtectedSiteConfigRecord>,
    request: &SiteConfigRequest,
) -> bool {
    let public_route = request
        .policy
        .routes
        .iter()
        .any(|route| route.security_entry == xshield_core::SecurityEntry::Public)
        || (request.policy.routes.is_empty() && request.security_entry == "public");
    let Some(previous) = previous else {
        return public_route
            || request.status == "paused"
            || !request.policy.secret_refs.is_empty()
            || request.policy.crypto.failure_strategy != "fail_closed"
            || request.policy.routes.iter().any(route_has_crypto);
    };
    request.status == "paused"
        || (previous.security_entry() != request.security_entry
            && request.security_entry == "public")
        || (previous.sensor_enabled() && !request.sensor_enabled)
        || previous.public_origin() != request.public_origin
        || previous.upstream_address() != request.upstream_address
        || previous.upstream_server_name() != request.upstream_server_name
        || previous.upstream_tls() != request.upstream_tls
        || previous.policy_revision() != request.policy_revision
        || policy_requires_approval(previous.policy(), &request.policy)
        || (previous.status() == "paused" && request.status == "active")
        || route_publicity_widened(previous.policy(), &request.policy)
        || (public_route && previous.security_entry() != "public")
}

fn policy_requires_approval(previous: &SitePolicyConfig, request: &SitePolicyConfig) -> bool {
    (previous.identity.enabled && !request.identity.enabled)
        || (previous.waf.enabled && !request.waf.enabled)
        || (previous.crypto.failure_strategy != request.crypto.failure_strategy
            && request.crypto.failure_strategy == "observe")
        || previous.crypto.adapter_revision != request.crypto.adapter_revision
        || previous.crypto.protocol_version != request.crypto.protocol_version
        || previous.secret_refs != request.secret_refs
        || route_crypto_changed(previous, request)
}

fn route_crypto_changed(previous: &SitePolicyConfig, request: &SitePolicyConfig) -> bool {
    previous.routes.iter().any(|before| {
        let after = request
            .routes
            .iter()
            .find(|route| same_route(before, route));
        after.map_or_else(
            || route_has_crypto(before),
            |after| {
                before.request_crypto != after.request_crypto
                    || before.response_crypto != after.response_crypto
            },
        )
    }) || request.routes.iter().any(|after| {
        previous
            .routes
            .iter()
            .all(|before| !same_route(before, after))
            && route_has_crypto(after)
    })
}

fn same_route(
    before: &xshield_core::SiteRouteConfig,
    after: &xshield_core::SiteRouteConfig,
) -> bool {
    before.operation_id == after.operation_id
        && before.method == after.method
        && before.path == after.path
}

fn route_has_crypto(route: &xshield_core::SiteRouteConfig) -> bool {
    route.request_crypto.is_some() || route.response_crypto.is_some()
}

fn route_publicity_widened(previous: &SitePolicyConfig, request: &SitePolicyConfig) -> bool {
    request.routes.iter().any(|route| {
        route.security_entry == xshield_core::SecurityEntry::Public
            && previous
                .routes
                .iter()
                .find(|before| {
                    before.operation_id == route.operation_id
                        && before.method == route.method
                        && before.path == route.path
                })
                .is_none_or(|before| before.security_entry != xshield_core::SecurityEntry::Public)
    })
}

fn upstream_host_is_unsafe(upstream: &Url) -> bool {
    let Some(host) = upstream.host_str().map(str::to_ascii_lowercase) else {
        return true;
    };
    if matches!(
        host.as_str(),
        "metadata.google.internal" | "metadata.google"
    ) {
        return true;
    }
    if host.ends_with(".internal")
        || host.ends_with(".localhost")
        || host.strip_suffix(".local").is_some()
        || host == "localhost"
    {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(upstream_ip_is_unsafe)
}

fn upstream_ip_is_unsafe(address: IpAddr) -> bool {
    let allow_loopback = std::env::var("XSHIELD_ALLOW_LOOPBACK_UPSTREAM").as_deref() == Ok("1");
    match address {
        IpAddr::V4(address) => {
            (address.is_loopback() && !allow_loopback)
                || address.is_unspecified()
                || address.is_multicast()
                || (address.octets()[0] == 169 && address.octets()[1] == 254)
                || address.octets()[0] == 10
                || (address.octets()[0] == 192 && address.octets()[1] == 168)
                || (address.octets()[0] == 172 && (16..=31).contains(&address.octets()[1]))
                || (address.octets()[0] == 100 && (64..=127).contains(&address.octets()[1]))
                || (address.octets()[0] == 192
                    && address.octets()[1] == 0
                    && address.octets()[2] == 0)
                || (address.octets()[0] == 198 && (18..=19).contains(&address.octets()[1]))
                || (address.octets()[0] == 198
                    && address.octets()[1] == 51
                    && address.octets()[2] == 100)
                || (address.octets()[0] == 203
                    && address.octets()[1] == 0
                    && address.octets()[2] == 113)
        }
        IpAddr::V6(address) => {
            (address.is_loopback() && !allow_loopback)
                || address.is_unspecified()
                || address.is_multicast()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || (address.segments()[0] == 0x2001 && address.segments()[1] == 0x0db8)
        }
    }
}

fn signature(control: &ControlPlane, label: &[u8], parts: &[&[u8]]) -> Option<[u8; 32]> {
    let key = PKey::hmac(&control.config.idempotency_key.0[..]).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).ok()?;
    signer.update(label).ok()?;
    for part in parts {
        signer.update(&(part.len() as u64).to_be_bytes()).ok()?;
        signer.update(part).ok()?;
    }
    signer.sign_to_vec().ok()?.try_into().ok()
}

fn hmac_hex(key: &[u8; 32], body: &[u8]) -> Option<String> {
    let key = PKey::hmac(key).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).ok()?;
    signer.update(body).ok()?;
    let bytes = signer.sign_to_vec().ok()?;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").ok()?;
    }
    Some(output)
}

fn decode_hex_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut key = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        };
        key[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Some(key)
}

fn view(
    control: &ControlPlane,
    site_id: &SiteId,
    record: &xshield_postgres::ProtectedSiteConfigRecord,
) -> SiteConfigView {
    let policy = effective_policy(record);
    let operations = policy
        .routes
        .iter()
        .map(gateway_operation)
        .collect::<Vec<_>>();
    let mut gateway_config = json!({
        "listen": format!("127.0.0.1:{}", record.listen_port()),
        "origin": { "address": record.upstream_address(), "server_name": record.upstream_server_name(), "tls": record.upstream_tls() },
        "tenant_id": control.config.tenant_id.as_str(),
        "site_id": site_id.as_str(),
        "policy_revision": record.policy_revision(),
        "site_policy": policy.clone(),
        "audit": { "directory": format!("target/xshield-audit-{}", site_id.as_str()), "key_id": "deployment-managed", "producer_id": format!("edge-{}", site_id.as_str()), "max_bytes": 16_777_216_u64, "high_watermark_bytes": 12_582_912_u64, "segment_max_bytes": 4_194_304_u64 },
        "operations": operations
    });
    if let Some(object) = gateway_config.as_object_mut() {
        if policy.identity.enabled || record.security_entry() != "public" || record.sensor_enabled()
        {
            object.insert(
                "identity_store".to_owned(),
                json!({
                    "max_connections": 8,
                    "acquire_timeout_ms": 2000,
                    "anonymous_session_ttl_seconds": policy.identity.session_ttl_seconds,
                    "max_active_anonymous_sessions": 100_000,
                    "anonymous_session_rate_window_seconds": 60,
                    "max_anonymous_session_creations_per_source": 10,
                    "max_anonymous_session_creations_per_site": 1000
                }),
            );
        }
        if record.sensor_enabled() {
            object.insert(
            "sensor".to_owned(),
            json!({ "origin": record.public_origin(), "build_ref": "0000000000000000000000000000000000000000000000000000000000000000", "heartbeat_seconds": 15 }),
        );
        }
    }
    SiteConfigView {
        display_name: record.display_name().to_owned(),
        public_origin: record.public_origin().to_owned(),
        upstream_address: record.upstream_address().to_owned(),
        upstream_server_name: record.upstream_server_name().to_owned(),
        upstream_tls: record.upstream_tls(),
        listen_port: record.listen_port(),
        entry_path: record.entry_path().to_owned(),
        security_entry: record.security_entry().to_owned(),
        sensor_enabled: record.sensor_enabled(),
        policy_revision: record.policy_revision().to_owned(),
        status: record.status().to_owned(),
        policy,
        revision: record.revision(),
        config_digest: hex(record.config_digest()),
        updated_by: record.updated_by().to_owned(),
        created_at: record.created_at().to_rfc3339(),
        updated_at: record.updated_at().to_rfc3339(),
        gateway_config,
    }
}

fn effective_policy(record: &xshield_postgres::ProtectedSiteConfigRecord) -> SitePolicyConfig {
    let mut policy = record.policy().clone();
    if policy.routes.is_empty() {
        policy.routes.push(xshield_core::SiteRouteConfig {
            operation_id: "protected.entry".to_owned(),
            method: "GET".to_owned(),
            path: record.entry_path().to_owned(),
            security_entry: xshield_core::SecurityEntry::parse(record.security_entry())
                .unwrap_or(xshield_core::SecurityEntry::UiActionRequired),
            source_action: (record.security_entry() == "ui_action_required")
                .then(|| "protected.entry".to_owned()),
            resource_type: None,
            view_profile: None,
            resource_query_parameter: None,
            resource_path_parameter: None,
            request_crypto: None,
            response_crypto: None,
            response_mode: String::new(),
            max_response_bytes: 1_048_576,
        });
    }
    policy
}

fn gateway_operation(route: &xshield_core::SiteRouteConfig) -> serde_json::Value {
    let admission = match route.security_entry {
        xshield_core::SecurityEntry::Public => "PUBLIC",
        xshield_core::SecurityEntry::AuthenticatedRoot => "AUTHENTICATED_ROOT",
        xshield_core::SecurityEntry::UiActionRequired => "UI_ACTION_REQUIRED",
    };
    let mut operation = json!({
        "operation_id": route.operation_id,
        "method": route.method,
        "path": route.path,
        "admission": admission,
        "source_action": route.source_action,
        "resource_type": route.resource_type,
        "view_profile": route.view_profile,
        "resource_query_parameter": route.resource_query_parameter,
        "resource_path_parameter": route.resource_path_parameter,
    });
    if let Some(request_crypto) = &route.request_crypto {
        operation["request_crypto"] = serde_json::to_value(request_crypto)
            .unwrap_or_else(|_| json!({ "mode": "OBSERVE", "adapter_revision": "invalid" }));
    }
    if route.response_crypto.is_some() || !route.response_mode.is_empty() {
        let mode = if route.response_mode.is_empty() {
            "BUFFERED_JSON"
        } else {
            route.response_mode.as_str()
        };
        let mut response = json!({ "mode": mode, "max_bytes": route.max_response_bytes });
        if let Some(crypto) = &route.response_crypto {
            response["crypto"] = serde_json::to_value(crypto).unwrap_or_else(|_| json!({}));
        }
        operation["response"] = response;
    }
    operation
}

#[allow(clippy::format_collect)]
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        SiteConfigRequest, SitePolicyConfig, merged_health_details, parse_site_list_query,
        patch_is_compatible, policy_requires_approval, rollback_target_revision,
        validate_apply_ack, validate_request,
    };
    use serde_json::json;
    use xshield_core::{
        GatewayApplyAck, GatewayApplyRequest, SecurityEntry, SiteRequestCrypto, SiteRouteConfig,
        domain::SiteId,
    };

    fn request() -> SiteConfigRequest {
        SiteConfigRequest {
            site_id: None,
            display_name: "demo".to_owned(),
            public_origin: "http://127.0.0.1:8080".to_owned(),
            upstream_address: "8.8.8.8:9000".to_owned(),
            upstream_server_name: "origin.local".to_owned(),
            upstream_tls: false,
            listen_port: 0,
            entry_path: "/".to_owned(),
            security_entry: "ui_action_required".to_owned(),
            sensor_enabled: false,
            policy_revision: "policy-v1".to_owned(),
            status: "draft".to_owned(),
            policy: SitePolicyConfig::default(),
        }
    }

    #[test]
    fn site_config_rejects_non_tls_public_origins() {
        let mut value = request();
        assert!(validate_request(&value).is_ok());
        value.public_origin = "http://public.example".to_owned();
        assert!(validate_request(&value).is_err());
    }

    #[test]
    fn site_config_rejects_ambiguous_public_host_and_revision_text() {
        let mut value = request();
        value.public_origin = "https://public_example.com".to_owned();
        assert!(validate_request(&value).is_err());
        value = request();
        value.policy_revision = "policy version 2".to_owned();
        assert!(validate_request(&value).is_err());
    }

    #[test]
    fn site_config_rejects_metadata_and_link_local_upstreams() {
        let mut value = request();
        value.upstream_address = "127.0.0.1:9000".to_owned();
        assert!(validate_request(&value).is_err());
        value.upstream_address = "169.254.169.254:80".to_owned();
        assert!(validate_request(&value).is_err());
        value.upstream_address = "metadata.google.internal:80".to_owned();
        assert!(validate_request(&value).is_err());
    }

    #[test]
    fn site_config_keeps_listeners_inside_the_private_edge_pool() {
        let mut value = request();
        value.listen_port = 6099;
        assert!(validate_request(&value).is_err());
        value.listen_port = 6100;
        assert!(validate_request(&value).is_ok());
    }

    #[test]
    fn site_config_rejects_ambiguous_entry_paths() {
        let mut value = request();
        value.entry_path = "/../admin".to_owned();
        assert!(validate_request(&value).is_err());
        value.entry_path = "/admin\\panel".to_owned();
        assert!(validate_request(&value).is_err());
    }

    #[test]
    fn site_config_patch_is_scoped_and_closed() {
        let site = SiteId::parse("site_a").unwrap();
        let patch = json!({ "display_name": "renamed", "status": "paused" });
        assert!(patch_is_compatible(patch.as_object().unwrap(), &site));
        let wrong_site = json!({ "site_id": "site_b" });
        assert!(!patch_is_compatible(wrong_site.as_object().unwrap(), &site));
        let unknown = json!({ "secret": "must-not-pass" });
        assert!(!patch_is_compatible(unknown.as_object().unwrap(), &site));
    }

    #[test]
    fn health_details_keep_edge_state_and_record_upstream_state() {
        let details = merged_health_details(
            Some(json!({ "edge_state": "healthy", "site_count": 2 })),
            Some(json!({
                "upstream_state": "degraded",
                "status": 503,
                "expected_status": 200
            })),
        );
        assert_eq!(details["edge_state"], "healthy");
        assert_eq!(details["upstream_state"], "degraded");
        assert_eq!(details["upstream_health"]["status"], 503);
    }

    #[test]
    fn site_list_query_rejects_unknown_and_duplicate_parameters() {
        assert_eq!(parse_site_list_query(None).unwrap(), (None, 100));
        assert_eq!(parse_site_list_query(Some("limit=25")).unwrap(), (None, 25));
        assert!(parse_site_list_query(Some("limit=25&limit=25")).is_err());
        assert!(parse_site_list_query(Some("scope=other")).is_err());
    }

    #[test]
    fn policy_approval_allows_bounded_tuning_but_blocks_security_downgrades() {
        let previous = SitePolicyConfig::default();
        let mut tuned = previous.clone();
        tuned.limits.requests_per_second = 2_000;
        assert!(!policy_requires_approval(&previous, &tuned));

        let mut weakened = previous.clone();
        weakened.crypto.failure_strategy = "observe".to_owned();
        assert!(policy_requires_approval(&previous, &weakened));

        let mut encrypted_route = previous.clone();
        encrypted_route.routes.push(SiteRouteConfig {
            operation_id: "protected.read".to_owned(),
            method: "GET".to_owned(),
            path: "/read".to_owned(),
            security_entry: SecurityEntry::AuthenticatedRoot,
            source_action: None,
            resource_type: None,
            view_profile: None,
            resource_query_parameter: None,
            resource_path_parameter: None,
            request_crypto: Some(SiteRequestCrypto::Observe {
                adapter_revision: "observe-v1".to_owned(),
            }),
            response_crypto: None,
            response_mode: String::new(),
            max_response_bytes: 1_048_576,
        });
        assert!(policy_requires_approval(&previous, &encrypted_route));
        assert!(policy_requires_approval(&encrypted_route, &previous));
    }

    #[test]
    fn apply_ack_must_match_the_sent_request() {
        let request = GatewayApplyRequest {
            protocol_version: 1,
            tenant_id: "tenant_demo".to_owned(),
            apply_id: "apply_demo".to_owned(),
            snapshot_revision: 7,
            sites: Vec::new(),
        };
        let ack = GatewayApplyAck {
            apply_id: "apply_demo".to_owned(),
            active_revision: 7,
            apply_state: "active".to_owned(),
            reason_code: "EDGE_APPLY_CONFIRMED".to_owned(),
        };
        assert!(validate_apply_ack(&request, &ack).is_ok());

        let mut wrong_apply = ack.clone();
        wrong_apply.apply_id = "apply_other".to_owned();
        assert_eq!(
            validate_apply_ack(&request, &wrong_apply),
            Err("EDGE_APPLY_ACK_INVALID")
        );
        let mut wrong_revision = ack.clone();
        wrong_revision.active_revision = 8;
        assert_eq!(
            validate_apply_ack(&request, &wrong_revision),
            Err("EDGE_APPLY_ACK_INVALID")
        );
    }

    #[test]
    fn rollback_restores_last_active_when_desired_apply_is_not_active() {
        let base = xshield_postgres::ProtectedSiteApplyState {
            desired_revision: 3,
            active_revision: Some(2),
            apply_id: "apply_demo".to_owned(),
            apply_state: "failed".to_owned(),
            reason_code: "EDGE_UNAVAILABLE".to_owned(),
            retry_count: 1,
            requires_approval: false,
            approved_by: None,
            approval_id: None,
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(rollback_target_revision(&base), Some(2));

        let active = xshield_postgres::ProtectedSiteApplyState {
            desired_revision: 2,
            apply_state: "active".to_owned(),
            ..base
        };
        assert_eq!(rollback_target_revision(&active), Some(1));
    }
}
