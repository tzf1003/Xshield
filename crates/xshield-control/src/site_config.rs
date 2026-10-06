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
use std::{fmt::Write as _, net::SocketAddr, sync::Arc, time::Duration};
use url::Url;
use xshield_core::{
    GatewayApplyAck, GatewayApplyRequest, GatewayApplySite, SiteConfig, SiteHealthCheckConfig,
    SitePolicyConfig,
    admin::ManagementRole,
    domain::SiteId,
    site::{
        POLICY_REVISION_REUSED, flow,
        upstream::{parse_upstream_socket, refuse_upstream_socket},
    },
};
use xshield_postgres::{
    ProtectedSiteApprovalOutcome, ProtectedSiteConfigUpsert, ProtectedSiteConfigWriteOutcome,
    ProtectedSiteDirectApplyOutcome,
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

    pub(crate) async fn apply(
        &self,
        request: &GatewayApplyRequest,
    ) -> Result<GatewayApplyAck, EdgeApplyRefusal> {
        let body = serde_json::to_vec(request).map_err(|_| "EDGE_APPLY_PAYLOAD_INVALID")?;
        let signature = hmac_hex(&self.key, &body).ok_or("EDGE_APPLY_SIGNATURE_UNAVAILABLE")?;
        let response = self
            .http
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header("x-xshield-apply-signature", &signature)
            .body(body)
            .send()
            .await
            .map_err(|_| "EDGE_UNAVAILABLE")?;
        if !response.status().is_success() {
            let body = response.json::<EdgeRefusalBody>().await.ok();
            return Err(EdgeApplyRefusal::from_body(body));
        }
        // The ack is trusted only if the edge signed these exact bytes as the
        // answer to this request; content is checked after authenticity.
        let ack_headers = response.headers().clone();
        let ack_body = response
            .bytes()
            .await
            .map_err(|_| "EDGE_APPLY_ACK_INVALID")?;
        crate::edge_channel::verify_apply_ack(&self.key, &signature, &ack_headers, &ack_body)?;
        let ack = serde_json::from_slice::<GatewayApplyAck>(&ack_body)
            .map_err(|_| "EDGE_APPLY_ACK_INVALID")?;
        validate_apply_ack(request, &ack)?;
        Ok(ack)
    }

    pub(crate) async fn health(&self) -> Result<serde_json::Value, &'static str> {
        // A constant signature would stay valid forever once captured, so each
        // request is signed over a fresh timestamp and nonce the edge enforces.
        let auth = crate::edge_channel::sign_health_request(&self.key)
            .ok_or("EDGE_APPLY_SIGNATURE_UNAVAILABLE")?;
        let response = self
            .http
            .get(&self.health_endpoint)
            .header("x-xshield-apply-signature", auth.signature)
            .header(
                xshield_core::edge_channel::HEALTH_TIMESTAMP_HEADER,
                auth.timestamp,
            )
            .header(xshield_core::edge_channel::HEALTH_NONCE_HEADER, auth.nonce)
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

/// The members of an edge refusal body this plane reads
/// (`{"error", "reason_code", "site_id"?}`); everything else is ignored.
#[derive(Deserialize)]
struct EdgeRefusalBody {
    reason_code: Option<String>,
    site_id: Option<String>,
}

/// Why an apply did not confirm: an edge refusal or a local failure.
///
/// Refusals are unsigned. `reason` is therefore kept only from a closed set
/// of known codes (anything else is the generic `EDGE_APPLY_REJECTED`), and
/// `site_id`, which the edge sends only with a descriptor conflict, is never
/// evidence of anything: it can only choose which site's intent carries the
/// failure, and only when it names a site this plane itself sent as desired.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct EdgeApplyRefusal {
    pub(crate) reason: &'static str,
    pub(crate) site_id: Option<SiteId>,
}

impl EdgeApplyRefusal {
    fn from_body(body: Option<EdgeRefusalBody>) -> Self {
        let (reason, site_id) = body.map_or((None, None), |body| (body.reason_code, body.site_id));
        let reason = match reason.as_deref() {
            Some("EDGE_APPLY_STALE_REVISION") => "EDGE_APPLY_STALE_REVISION",
            Some("EDGE_APPLY_VALIDATION_FAILED") => "EDGE_APPLY_VALIDATION_FAILED",
            Some("EDGE_APPLY_SCOPE_DENIED") => "EDGE_APPLY_SCOPE_DENIED",
            Some("EDGE_APPLY_LISTENER_UNAVAILABLE") => "EDGE_APPLY_LISTENER_UNAVAILABLE",
            Some("EDGE_APPLY_IDEMPOTENCY_CONFLICT") => "EDGE_APPLY_IDEMPOTENCY_CONFLICT",
            Some("EDGE_APPLY_SIGNATURE_INVALID") => "EDGE_APPLY_SIGNATURE_INVALID",
            Some("EDGE_APPLY_DESCRIPTOR_CONFLICT") => "EDGE_APPLY_DESCRIPTOR_CONFLICT",
            Some("EDGE_APPLY_DESCRIPTOR_UNAVAILABLE") => "EDGE_APPLY_DESCRIPTOR_UNAVAILABLE",
            _ => "EDGE_APPLY_REJECTED",
        };
        // Only a conflict is a property of one site's configuration; an
        // unavailable descriptor store is an outage of every page-issuing
        // site and stays the target's failure.
        let site_id = (reason == "EDGE_APPLY_DESCRIPTOR_CONFLICT")
            .then_some(site_id)
            .flatten()
            .and_then(|site| SiteId::parse(site).ok());
        Self { reason, site_id }
    }
}

impl From<&'static str> for EdgeApplyRefusal {
    fn from(reason: &'static str) -> Self {
        Self {
            reason,
            site_id: None,
        }
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

/// Whether the deployment opted in to loopback upstreams (the local lab only).
///
/// The opt-in is read at each use so a lab restart picks it up without a code
/// path caching a stale answer; it unlocks `127.0.0.0/8` and `::1` and nothing
/// else (see `xshield_core::site::upstream`).
fn loopback_upstream_allowed() -> bool {
    std::env::var("XSHIELD_ALLOW_LOOPBACK_UPSTREAM").as_deref() == Ok("1")
}

/// A health probe whose destination has been re-validated for this request.
#[derive(Debug, Eq, PartialEq)]
struct UpstreamProbePlan {
    /// Absolute URL: DNS-name host, the configured port and the health path.
    url: String,
    /// The URL's canonical host, which the client's resolver override pins.
    host: String,
    /// The only socket the probe may connect to.
    address: SocketAddr,
}

/// Decides, without any network I/O, where a probe may connect.
///
/// The persisted address is parsed and classified again here rather than
/// trusted because it was valid when written: rows from before a rule was
/// tightened, or edited directly in the database, must not turn the health
/// endpoint into a request forwarder. The server name only ever supplies the
/// `Host`/SNI identity; it must be a DNS name under the same URL parser the
/// HTTP client will use, because that client does not apply a resolver
/// override to IP literals (or to names such as `2130706433` that parse as one)
/// and would connect to them directly.
fn plan_upstream_probe(
    address: &str,
    server_name: &str,
    tls: bool,
    health_path: &str,
    allow_loopback: bool,
) -> Result<UpstreamProbePlan, &'static str> {
    let socket = parse_upstream_socket(address).map_err(|_| "CONTROL_SITE_UPSTREAM_INVALID")?;
    if refuse_upstream_socket(socket, allow_loopback).is_some() {
        return Err("CONTROL_SITE_SSRF_BLOCKED");
    }
    if !server_name_is_dns_name(server_name) {
        return Err("CONTROL_SITE_UPSTREAM_INVALID");
    }
    let scheme = if tls { "https" } else { "http" };
    let url = Url::parse(&format!(
        "{scheme}://{server_name}:{}{health_path}",
        socket.port()
    ))
    .map_err(|_| "CONTROL_SITE_UPSTREAM_INVALID")?;
    let Some(url::Host::Domain(host)) = url.host() else {
        return Err("CONTROL_SITE_UPSTREAM_INVALID");
    };
    if url.port_or_known_default() != Some(socket.port()) || !url.username().is_empty() {
        return Err("CONTROL_SITE_UPSTREAM_INVALID");
    }
    Ok(UpstreamProbePlan {
        host: host.to_owned(),
        url: url.to_string(),
        address: socket,
    })
}

/// Probes only the persisted, validated upstream socket and health path.
///
/// The client connects to the validated socket address and nothing else: no
/// proxy, no DNS resolution of operator-supplied names, and redirects stay
/// disabled so a health check cannot become an open proxy.
async fn probe_upstream(
    address: &str,
    server_name: &str,
    tls: bool,
    health: &SiteHealthCheckConfig,
    allow_loopback: bool,
) -> serde_json::Value {
    let plan = match plan_upstream_probe(address, server_name, tls, &health.path, allow_loopback) {
        Ok(plan) => plan,
        Err(reason) => {
            return json!({
                "upstream_state": "unavailable",
                "reason_code": reason
            });
        }
    };
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(u64::from(health.timeout_ms)))
        .timeout(Duration::from_millis(u64::from(health.timeout_ms)))
        .redirect(reqwest::redirect::Policy::none())
        // An environment proxy would receive the request and resolve the name
        // itself, defeating the pinned address.
        .no_proxy()
        .resolve(&plan.host, plan.address)
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
    let response = match client.get(plan.url).send().await {
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

impl SiteConfigRequest {
    fn to_config(&self) -> SiteConfig {
        SiteConfig {
            display_name: self.display_name.clone(),
            public_origin: self.public_origin.clone(),
            upstream_address: self.upstream_address.clone(),
            upstream_server_name: self.upstream_server_name.clone(),
            upstream_tls: self.upstream_tls,
            listen_port: self.listen_port,
            entry_path: self.entry_path.clone(),
            security_entry: self.security_entry.clone(),
            sensor_enabled: self.sensor_enabled,
            policy_revision: self.policy_revision.clone(),
            status: self.status.clone(),
            policy: self.policy.clone(),
        }
    }
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
    /// The edge projection of the stored configuration, for display; `null`
    /// when it cannot be produced (the apply path refuses such a site).
    gateway_config: Option<serde_json::Value>,
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
    let (subject, visibility) = match control.authorize_tenant_with_visibility(
        authorization.as_deref(),
        &request_id,
        LIST_ACCESS,
    ) {
        Ok(authorized) => authorized,
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
    let records = match super::api_key_authz::list_visible_site_configs(
        &control,
        &visibility,
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
    // The same stable reason a write of this content would get, so an
    // operator sees which rule failed instead of a generic refusal. That
    // includes the label binding: a revision written by an older control
    // service may reuse a label for another descriptor set, which the
    // approval and apply paths would refuse.
    let verdict = match validate_request(&payload, &site_id) {
        Ok(()) => match control
            .catalog
            .check_protected_site_label(&control.config.tenant_id, &site_id, &payload.to_config())
            .await
        {
            Ok(None) => Ok(()),
            Ok(Some(reuse)) => Err(validation_reason(reuse.field())),
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
        },
        Err(reason) => Err(reason),
    };
    let valid = verdict.is_ok();
    let reason_code = verdict.err().unwrap_or("CONTROL_SITE_VALIDATED");
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
    // A reviewer can pin the approval to the exact configuration they read by
    // sending its digest; without it the approval covers whatever revision is
    // desired inside the approving transaction, never a revision it did not see
    // there.
    let expected_digest = match single_header(&headers, "x-xshield-expected-config-digest") {
        None => None,
        Some(value) => {
            let Some(digest) = decode_hex_key(&value) else {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        APPROVE_ACCESS,
                        None,
                        StatusCode::BAD_REQUEST,
                        "CONTROL_SITE_CONFIG_REQUEST_INVALID",
                        "invalid expected configuration digest",
                        false,
                        "correct_request",
                    )
                    .await
                    .into_response();
            };
            Some(digest)
        }
    };
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
    // Revision, apply identity, author check and idempotent replay are all
    // decided by the store inside one locked transaction.
    let approval = match control
        .catalog
        .approve_protected_site_apply(
            &control.config.tenant_id,
            &site_id,
            &approval_id,
            &subject,
            &idempotency_digest,
            expected_digest.as_ref(),
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
    let refusal = match &approval {
        ProtectedSiteApprovalOutcome::Applied { .. }
        | ProtectedSiteApprovalOutcome::Existing { .. } => None,
        ProtectedSiteApprovalOutcome::NotFound => Some((
            StatusCode::NOT_FOUND,
            "CONTROL_SITE_NOT_FOUND",
            "site configuration was not found",
            "correct_request",
        )),
        ProtectedSiteApprovalOutcome::NotRequired => Some((
            StatusCode::CONFLICT,
            "CONTROL_SITE_APPROVAL_NOT_REQUIRED",
            "the desired revision does not require approval",
            "read_site_status",
        )),
        ProtectedSiteApprovalOutcome::RevisionMismatch => Some((
            StatusCode::CONFLICT,
            "CONTROL_SITE_APPROVAL_REVISION_MISMATCH",
            "the approval is bound to a different revision than the one now desired",
            "read_site_status",
        )),
        ProtectedSiteApprovalOutcome::SelfApproval => Some((
            StatusCode::FORBIDDEN,
            "CONTROL_SITE_APPROVAL_SELF_REJECTED",
            "the configuration author cannot approve the same revision",
            "independent_approver",
        )),
        // Written by an older control service, or its label was bound since:
        // approving it would only move the refusal to the edge.
        ProtectedSiteApprovalOutcome::PolicyRevisionReused(reuse) => Some((
            StatusCode::CONFLICT,
            validation_reason(reuse.field()),
            POLICY_REVISION_REUSED_MESSAGE,
            POLICY_REVISION_REUSED_NEXT_ACTION,
        )),
        // The rows the approved block would produce clash with a registered
        // one; approving would only move the refusal to the edge.
        ProtectedSiteApprovalOutcome::ShareRuleConflict => Some((
            StatusCode::CONFLICT,
            SHARE_RULE_CONFLICT,
            SHARE_RULE_CONFLICT_MESSAGE,
            SHARE_RULE_CONFLICT_NEXT_ACTION,
        )),
    };
    if let Some((status, reason, message, next_action)) = refusal {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                APPROVE_ACCESS,
                None,
                status,
                reason,
                message,
                false,
                next_action,
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
        let status = match control
            .catalog
            .read_protected_site_config(&control.config.tenant_id, &site_id)
            .await
        {
            Ok(Some(record)) => record.status().to_owned(),
            _ => return super::internal_error(&request_id).into_response(),
        };
        let _ = apply_site_snapshot(&control, &site_id, &current, &status).await;
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
    let Some(idempotency_key) = single_header(&headers, "idempotency-key")
        .filter(|value| super::valid_idempotency_key(value))
    else {
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
    };
    // A replay of this very request is recognised *before* anything that
    // depends on the site's current state is resolved: once the first call has
    // created a revision the "previous" revision is a different one, and a
    // replay must not chase it.
    let Some(idempotency_digest) = write_idempotency_digest(
        &control,
        ROLLBACK_ACCESS,
        &subject,
        &site_id,
        &idempotency_key,
    ) else {
        return super::internal_error(&request_id).into_response();
    };
    let replayed = match control
        .catalog
        .find_protected_site_write(&control.config.tenant_id, &site_id, &idempotency_digest)
        .await
    {
        Ok(replayed) => replayed,
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
    };
    let target_revision = if let Some(found) = replayed {
        // The write path decides what the replay means (an exact replay of the
        // latest write, or a superseded key); it only needs a valid body.
        found.revision
    } else {
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
        let previous_active = match control
            .catalog
            .read_protected_site_previous_active_revision(&control.config.tenant_id, &site_id)
            .await
        {
            Ok(previous) => previous,
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
        };
        let Some(revision) = rollback_target_revision(&apply, previous_active) else {
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
        revision
    };
    let Some(config) = (match control
        .catalog
        .read_protected_site_revision_config(&control.config.tenant_id, &site_id, target_revision)
        .await
    {
        Ok(config) => config,
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
    // The stored revision is a complete configuration (including
    // `policy_revision`), so it deserializes as an ordinary write request.
    let Ok(mut payload) = serde_json::to_value(&config) else {
        return super::internal_error(&request_id).into_response();
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

/// The revision a rollback restores, as the content of a *new* revision.
///
/// With a change still pending (desired differs from active, or the last apply
/// did not complete) it is the active revision: the rollback cancels the
/// pending change. Otherwise it is the revision that was active before the
/// current one, taken from the recorded activation order. `active - 1` is not
/// that: revision numbers are never reused, so the number below the active one
/// can be a revision that failed, was never approved or never served traffic.
fn rollback_target_revision(
    apply: &xshield_postgres::ProtectedSiteApplyState,
    previous_active: Option<u64>,
) -> Option<u64> {
    let active = apply.active_revision?;
    let change_pending = apply.desired_revision != active
        || !matches!(apply.apply_state.as_str(), "active" | "paused");
    if change_pending {
        Some(active)
    } else {
        previous_active
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
        Some(
            probe_upstream(
                record.upstream_address(),
                record.upstream_server_name(),
                record.upstream_tls(),
                &record.policy().health_check,
                loopback_upstream_allowed(),
            )
            .await,
        )
    } else {
        None
    };
    let health_details =
        read_health.then(|| merged_health_details(edge_health.clone(), upstream_health));
    let mut directly_authorized = false;
    let mut apply_failure: Option<&'static str> = None;
    if require_idempotency {
        // A draft is a preparation state and is never routable: refuse with a
        // stable, audited reason instead of publishing or silently ignoring it.
        if record.status() == "draft" {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::CONFLICT,
                    "CONTROL_SITE_DRAFT_NOT_APPLICABLE",
                    "a draft site cannot be applied; change its status first",
                    false,
                    "change_status",
                )
                .await
                .into_response();
        }
        let mut current = apply.clone();
        if apply.requires_approval && direct_apply {
            // The explicit `site.config.apply_direct` capability replaces the
            // second pair of eyes but not the record of it: a durable approval
            // naming this caller and bound to the exact revision, digest and
            // apply id is written, and the requirement is cleared with it.
            let approval_id = format!("approval_{}", uuid::Uuid::now_v7());
            let refusal = match control
                .catalog
                .authorize_protected_site_direct_apply(
                    &control.config.tenant_id,
                    &site_id,
                    &approval_id,
                    &subject,
                    apply.desired_revision,
                    &apply.apply_id,
                )
                .await
            {
                Ok(ProtectedSiteDirectApplyOutcome::Authorized { .. }) => {
                    directly_authorized = true;
                    None
                }
                Ok(ProtectedSiteDirectApplyOutcome::NotRequired) => None,
                Ok(ProtectedSiteDirectApplyOutcome::Stale) => Some((
                    StatusCode::CONFLICT,
                    "CONTROL_SITE_APPROVAL_REVISION_MISMATCH",
                    "the desired revision changed after it was read",
                    false,
                    "read_site_status",
                )),
                Ok(ProtectedSiteDirectApplyOutcome::NotFound) => Some((
                    StatusCode::NOT_FOUND,
                    "CONTROL_SITE_NOT_FOUND",
                    "site configuration was not found",
                    false,
                    "correct_request",
                )),
                // Authentication entries, sensor pages, page-issued actions
                // and resource grants decide who obtains identity and which
                // UI actions exist; the capability cannot stand in for the
                // independent approver there. Nothing was recorded.
                Ok(ProtectedSiteDirectApplyOutcome::IndependentApprovalRequired) => Some((
                    StatusCode::FORBIDDEN,
                    "CONTROL_SITE_INDEPENDENT_APPROVAL_REQUIRED",
                    "this revision changes the browser provenance flow and needs an independent approver",
                    false,
                    "request_approval",
                )),
                Ok(ProtectedSiteDirectApplyOutcome::PolicyRevisionReused(reuse)) => Some((
                    StatusCode::CONFLICT,
                    validation_reason(reuse.field()),
                    POLICY_REVISION_REUSED_MESSAGE,
                    false,
                    POLICY_REVISION_REUSED_NEXT_ACTION,
                )),
                Ok(ProtectedSiteDirectApplyOutcome::ShareRuleConflict) => Some((
                    StatusCode::CONFLICT,
                    SHARE_RULE_CONFLICT,
                    SHARE_RULE_CONFLICT_MESSAGE,
                    false,
                    SHARE_RULE_CONFLICT_NEXT_ACTION,
                )),
                Err(_) => Some((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SITE_APPLY_STATE_UNAVAILABLE",
                    "site application state is temporarily unavailable",
                    true,
                    "retry_later",
                )),
            };
            if let Some((status, reason, message, retryable, next_action)) = refusal {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        action,
                        None,
                        status,
                        reason,
                        message,
                        retryable,
                        next_action,
                    )
                    .await
                    .into_response();
            }
            current = match control
                .catalog
                .read_protected_site_apply_state(&control.config.tenant_id, &site_id)
                .await
            {
                Ok(Some(current)) => current,
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
        }
        apply_failure = apply_site_snapshot(&control, &site_id, &current, record.status())
            .await
            .err();
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
        // A direct apply is named in the terminal audit state so the event
        // stream shows who exercised the capability and with what result.
        if apply.apply_state == "active" {
            (
                "PASS",
                if directly_authorized {
                    "EDGE_DIRECT_APPLY_CONFIRMED"
                } else {
                    "EDGE_APPLY_CONFIRMED"
                },
            )
        } else if apply.requires_approval {
            ("DENY", "CONTROL_SITE_APPROVAL_REQUIRED")
        } else if let Some(
            reason @ ("CONTROL_SITE_POLICY_INVALID"
            | "CONTROL_SITE_PORT_UNAVAILABLE"
            | "CONTROL_SITE_POLICY_REVISION_REUSED"
            | SHARE_RULE_CONFLICT),
        ) = apply_failure
        {
            // The configuration itself is why nothing was published.
            ("ERROR", reason)
        } else {
            (
                "ERROR",
                if directly_authorized {
                    "EDGE_DIRECT_APPLY_NOT_CONFIRMED"
                } else {
                    "EDGE_APPLY_NOT_CONFIRMED"
                },
            )
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
///
/// Deleting takes a protected site off the edge, so it is a high-risk action:
/// it requires the browser session's fresh MFA step-up, the same machinery the
/// evidence reads and export decisions use. Machine credentials (the management
/// bearer and Agent API keys) have no step-up path, so they cannot delete sites
/// whatever capabilities they hold; there is no delete capability to grant.
/// The step-up is the authorization of the takedown pause that precedes the
/// removal, which the store records against that exact revision.
pub async fn delete_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
    Extension(auth): Extension<super::identity::AuthContext>,
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
    if !auth.step_up_valid() {
        return control
            .audited_error_async(
                request_id,
                Some(subject),
                DELETE_ACCESS,
                None,
                StatusCode::FORBIDDEN,
                "CONTROL_SITE_DELETE_STEP_UP_REQUIRED",
                "deleting a site requires recent reauthentication",
                false,
                "reauthenticate",
            )
            .await
            .into_response();
    }
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
                // The caller deleting the site authorizes the takedown pause
                // that precedes the removal; the store records that as an
                // approval bound to this exact revision.
                pre_authorized_by: Some(&subject),
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
            Ok(ProtectedSiteConfigWriteOutcome::Superseded) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        DELETE_ACCESS,
                        None,
                        StatusCode::CONFLICT,
                        "CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED",
                        "idempotency key belongs to an earlier write that a later one superseded",
                        false,
                        "read_site_status",
                    )
                    .await
                    .into_response();
            }
            // The takedown pause is never served, so its label is never
            // checked; the arm keeps the refusal stable should that change.
            Ok(ProtectedSiteConfigWriteOutcome::PolicyRevisionReused(reuse)) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        DELETE_ACCESS,
                        None,
                        StatusCode::CONFLICT,
                        validation_reason(reuse.field()),
                        POLICY_REVISION_REUSED_MESSAGE,
                        false,
                        POLICY_REVISION_REUSED_NEXT_ACTION,
                    )
                    .await
                    .into_response();
            }
            // A pause is never served, so it has no rule rows to conflict.
            Ok(ProtectedSiteConfigWriteOutcome::ShareRuleConflict) => {
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        DELETE_ACCESS,
                        None,
                        StatusCode::CONFLICT,
                        SHARE_RULE_CONFLICT,
                        SHARE_RULE_CONFLICT_MESSAGE,
                        false,
                        SHARE_RULE_CONFLICT_NEXT_ACTION,
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
        if apply_site_snapshot(&control, &site_id, &paused_apply, "paused")
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
    // These handlers are idempotent upserts. A key's creation and write
    // capabilities stay separate: POST must not overwrite, PUT must not create.
    if let Some(response) = control
        .guard_api_key_site_write(
            authorization.as_deref(),
            &request_id,
            &subject,
            action,
            &site_id,
        )
        .await
    {
        return response;
    }
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
    if body.len() > SITE_CONFIG_BODY_BYTES_MAX {
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
                let (reason, message) = rejected_body_reason(&body);
                return control
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        action,
                        None,
                        StatusCode::BAD_REQUEST,
                        reason,
                        message,
                        false,
                        "correct_request",
                    )
                    .await
                    .into_response();
            }
        }
    } else {
        let Ok(payload) = serde_json::from_slice(&body) else {
            let (reason, message) = rejected_body_reason(&body);
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::BAD_REQUEST,
                    reason,
                    message,
                    false,
                    "correct_request",
                )
                .await
                .into_response();
        };
        payload
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
    if let Err(reason) = validate_request(&payload, &site_id) {
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
    let Ok(canonical) = serde_json::to_vec(&payload) else {
        return super::internal_error(&request_id).into_response();
    };
    let Some(idempotency_digest) =
        write_idempotency_digest(&control, action, &subject, &site_id, &idempotency_key)
    else {
        return super::internal_error(&request_id).into_response();
    };
    // A rollback's request is "roll this site back" under this key; which
    // revision that resolved to is an outcome, not part of the request, so a
    // replay after the site has moved on is still the same request.
    let request_basis: &[u8] = if action.event_type == ROLLBACK_ACCESS.event_type {
        b"site-rollback-request-v1"
    } else {
        &canonical
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
            request_basis,
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
            // Whether this revision needs approval is decided inside the write
            // transaction from the active revision, not by the caller.
            pre_authorized_by: None,
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
        ProtectedSiteConfigWriteOutcome::Superseded => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::CONFLICT,
                    "CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED",
                    "idempotency key belongs to an earlier write that a later one superseded",
                    false,
                    "read_site_status",
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
        // Refused here so it never reaches the edge, which would refuse the
        // whole tenant snapshot (`EDGE_APPLY_DESCRIPTOR_CONFLICT`).
        ProtectedSiteConfigWriteOutcome::PolicyRevisionReused(reuse) => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::CONFLICT,
                    validation_reason(reuse.field()),
                    POLICY_REVISION_REUSED_MESSAGE,
                    false,
                    POLICY_REVISION_REUSED_NEXT_ACTION,
                )
                .await
                .into_response();
        }
        // The rule rows the `share_issue` block needs exist differently
        // (immutable): refused at save time so the author hears it before
        // anyone is asked to approve.
        ProtectedSiteConfigWriteOutcome::ShareRuleConflict => {
            return control
                .audited_error_async(
                    request_id,
                    Some(subject),
                    action,
                    None,
                    StatusCode::CONFLICT,
                    SHARE_RULE_CONFLICT,
                    SHARE_RULE_CONFLICT_MESSAGE,
                    false,
                    SHARE_RULE_CONFLICT_NEXT_ACTION,
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
        let _ = apply_site_snapshot(&control, &site_id, &apply, record.status()).await;
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

/// What the edge is asked to serve for one site in a snapshot.
struct ServedSite {
    site_id: SiteId,
    config: SiteConfig,
    /// The revision whose configuration is being served.
    revision: u64,
}

/// What the snapshot builder needs to know about one site, read together under
/// the tenant lock.
struct PlanInput {
    site_id: SiteId,
    desired: SiteConfig,
    desired_revision: u64,
    apply_id: String,
    requires_approval: bool,
    active_revision: Option<u64>,
    /// The stored configuration of `active_revision`: what the edge serves.
    active_config: Option<SiteConfig>,
    /// Why the store, under the tenant lock of the snapshot read, found the
    /// desired revision must not be carried although it is eligible: its
    /// `policy_revision` label already names another action-descriptor set
    /// (the edge would refuse the whole tenant) or a `share_issuance_rules`
    /// row it needs exists differently (the edge would fail every share
    /// issuance closed). The stable reason code.
    conflict: Option<&'static str>,
}

impl PlanInput {
    fn from_store(site: &xshield_postgres::ProtectedSiteSnapshotSite) -> Self {
        Self {
            site_id: site.site_id.clone(),
            desired: site.record.site_config(),
            desired_revision: site.record.revision(),
            apply_id: site.apply_id.clone(),
            requires_approval: site.requires_approval,
            active_revision: site.active_revision,
            active_config: site.active_config.clone(),
            conflict: if site.label_conflict.is_some() {
                Some("CONTROL_SITE_POLICY_REVISION_REUSED")
            } else if site.share_rule_conflict {
                Some(SHARE_RULE_CONFLICT)
            } else {
                None
            },
        }
    }
}

/// The snapshot the edge receives and the intents it confirms.
struct SnapshotPlan {
    served: Vec<ServedSite>,
    /// `(site, desired revision, apply id)` of every site whose *desired*
    /// revision this snapshot carries (or deliberately omits, for a paused
    /// site); only these are marked applied after the edge confirms.
    confirmed: Vec<(SiteId, u64, String)>,
    /// Sites other than the target whose desired revision does not compile
    /// and is not waiting for approval. They are held back, and each is marked
    /// failed so its own status says why instead of the tenant failing as a
    /// whole.
    invalid: Vec<(SiteId, u64, String)>,
    /// Sites other than the target whose desired revision would reuse a
    /// `policy_revision` label for another descriptor set. Held back and
    /// reported the same way, because the edge would refuse the whole
    /// snapshot for them.
    reused: Vec<(SiteId, u64, String, &'static str)>,
}

/// Decides, per site, which configuration the snapshot carries.
///
/// The rule is what keeps one site from freezing or poisoning the tenant:
///
/// - a site whose desired revision is approved (or never needed approval),
///   valid and `active` is served as desired and confirmed;
/// - a site whose desired revision awaits approval, cannot be compiled, or
///   would reuse its `policy_revision` label for another descriptor set, is
///   held at its **last approved (active) configuration**, so the edge keeps
///   serving exactly what was approved and the change never reaches it; the
///   site is not confirmed, so its intent stays pending. A site that was
///   never applied is omitted;
/// - a `paused` desired revision is omitted and confirmed (it applies as
///   paused); a `draft` is omitted and never confirmed, because a draft is
///   not routable and must not look applied.
///
/// The apply *target* is held to the strict form of that rule: it must be
/// approved, not a draft and compilable, otherwise the call fails with a
/// stable reason instead of quietly serving something else.
fn plan_snapshot(
    sites: &[PlanInput],
    target_site: &SiteId,
    target_apply: &xshield_postgres::ProtectedSiteApplyState,
) -> Result<SnapshotPlan, &'static str> {
    let mut served = Vec::new();
    let mut confirmed = Vec::new();
    let mut invalid = Vec::new();
    let mut reused = Vec::new();
    for site in sites {
        let desired = site.desired.clone();
        let is_target = site.site_id == *target_site;
        if is_target {
            // The target's state was read again with the snapshot, under the
            // tenant lock; refuse to act on a revision the caller never saw.
            if site.apply_id != target_apply.apply_id
                || site.desired_revision != target_apply.desired_revision
            {
                return Err("CONTROL_SITE_APPLY_STATE_UNAVAILABLE");
            }
            if site.requires_approval {
                return Err("CONTROL_SITE_APPROVAL_REQUIRED");
            }
            if desired.status == "draft" {
                return Err("CONTROL_SITE_DRAFT_NOT_APPLICABLE");
            }
            if desired.is_serving() && desired.validate_for_site(&site.site_id).is_err() {
                return Err("CONTROL_SITE_POLICY_INVALID");
            }
            if let Some(reason) = site.conflict {
                return Err(reason);
            }
        }
        let desired_is_compilable =
            !desired.is_serving() || desired.validate_for_site(&site.site_id).is_ok();
        if !site.requires_approval && !desired_is_compilable {
            invalid.push((
                site.site_id.clone(),
                site.desired_revision,
                site.apply_id.clone(),
            ));
        } else if let Some(reason) = site.conflict {
            reused.push((
                site.site_id.clone(),
                site.desired_revision,
                site.apply_id.clone(),
                reason,
            ));
        }
        if site.requires_approval || !desired_is_compilable || site.conflict.is_some() {
            // Hold at the last approved configuration if the edge serves one.
            // It is deliberately not validated again: the edge accepted it when
            // it was applied, and dropping a live site because a validator got
            // stricter since would turn a tightening into an outage.
            if let (Some(previous), Some(revision)) =
                (site.active_config.as_ref(), site.active_revision)
                && previous.is_serving()
            {
                served.push(ServedSite {
                    site_id: site.site_id.clone(),
                    config: previous.clone(),
                    revision,
                });
            }
            continue;
        }
        match desired.status.as_str() {
            "active" => {
                served.push(ServedSite {
                    site_id: site.site_id.clone(),
                    config: desired,
                    revision: site.desired_revision,
                });
                confirmed.push((
                    site.site_id.clone(),
                    site.desired_revision,
                    site.apply_id.clone(),
                ));
            }
            "paused" => confirmed.push((
                site.site_id.clone(),
                site.desired_revision,
                site.apply_id.clone(),
            )),
            _ => {}
        }
    }
    // The edge refuses two sites on one listener. A held-back site keeps the
    // port of its last approved revision, which a later site may since have
    // been allocated; surface that instead of sending a snapshot the edge
    // would reject as a whole.
    let mut ports = std::collections::BTreeSet::new();
    if !served
        .iter()
        .all(|site| ports.insert(site.config.listen_port))
    {
        return Err("CONTROL_SITE_PORT_UNAVAILABLE");
    }
    Ok(SnapshotPlan {
        served,
        confirmed,
        invalid,
        reused,
    })
}

/// Sends the complete tenant snapshot and commits exact desired revisions only
/// after the edge confirms an atomic replacement. A missing edge binding is a
/// deliberate `pending` state for development and control-plane-only deploys.
///
/// `target_status` is the status of the revision being applied; applying a
/// draft is refused before anything is allocated or sent.
async fn apply_site_snapshot(
    control: &ControlPlane,
    target_site: &SiteId,
    target_apply: &xshield_postgres::ProtectedSiteApplyState,
    target_status: &str,
) -> Result<bool, &'static str> {
    if target_apply.requires_approval {
        return Err("CONTROL_SITE_APPROVAL_REQUIRED");
    }
    if target_status == "draft" {
        return Err("CONTROL_SITE_DRAFT_NOT_APPLICABLE");
    }
    let Some(client) = control.gateway_apply.as_ref() else {
        return Ok(false);
    };
    let snapshot = control
        .catalog
        .begin_protected_site_snapshot(&control.config.tenant_id)
        .await
        .map_err(|_| "CONTROL_SITE_APPLY_STATE_UNAVAILABLE")?;
    let inputs = snapshot
        .sites
        .iter()
        .map(PlanInput::from_store)
        .collect::<Vec<_>>();
    let plan = match plan_snapshot(&inputs, target_site, target_apply) {
        Ok(plan) => plan,
        Err(reason) => {
            // Failures the target is itself responsible for are recorded on
            // it so its status reports why; approval, draft and state races
            // are already visible in the state they were decided from.
            if matches!(
                reason,
                "CONTROL_SITE_POLICY_INVALID"
                    | "CONTROL_SITE_PORT_UNAVAILABLE"
                    | "CONTROL_SITE_POLICY_REVISION_REUSED"
                    | SHARE_RULE_CONFLICT
            ) {
                let _ = control
                    .catalog
                    .mark_protected_site_apply_failed(
                        &control.config.tenant_id,
                        target_site,
                        target_apply.desired_revision,
                        &target_apply.apply_id,
                        reason,
                    )
                    .await;
            }
            return Err(reason);
        }
    };
    // A site whose projection cannot be produced is never sent with a
    // substitute: nothing is published and the target records why.
    let Ok(sites) = plan
        .served
        .iter()
        .map(|site| {
            Ok(GatewayApplySite {
                site_id: site.site_id.as_str().to_owned(),
                listen_port: site.config.listen_port,
                public_origin: site.config.public_origin.clone(),
                gateway_config: site
                    .config
                    .gateway_config(control.config.tenant_id.as_str(), &site.site_id)?,
                revision: site.revision,
            })
        })
        .collect::<Result<Vec<_>, xshield_core::domain::InvalidValue>>()
    else {
        control
            .catalog
            .mark_protected_site_apply_failed(
                &control.config.tenant_id,
                target_site,
                target_apply.desired_revision,
                &target_apply.apply_id,
                "EDGE_APPLY_PAYLOAD_INVALID",
            )
            .await
            .map_err(|_| "CONTROL_SITE_APPLY_STATE_UNAVAILABLE")?;
        return Err("EDGE_APPLY_PAYLOAD_INVALID");
    };
    let request = GatewayApplyRequest {
        protocol_version: 1,
        tenant_id: control.config.tenant_id.as_str().to_owned(),
        apply_id: target_apply.apply_id.clone(),
        snapshot_revision: snapshot.revision,
        sites,
    };
    if let Err(refusal) = client.apply(&request).await {
        // A descriptor conflict is a property of the one site the edge
        // names, so that site carries it and the target, which caused
        // nothing, stays pending. The unsigned name is honoured only when it
        // is a sibling this snapshot carried as its desired revision;
        // otherwise (no name, the target itself, a site held back or not
        // sent at all) the target carries the failure as before.
        let (site, revision, apply_id) = refusal
            .site_id
            .as_ref()
            .filter(|named| *named != target_site)
            .and_then(|named| plan.confirmed.iter().find(|(site, _, _)| site == named))
            .map_or(
                (
                    target_site,
                    target_apply.desired_revision,
                    target_apply.apply_id.as_str(),
                ),
                |(site, revision, apply_id)| (site, *revision, apply_id.as_str()),
            );
        control
            .catalog
            .mark_protected_site_apply_failed(
                &control.config.tenant_id,
                site,
                revision,
                apply_id,
                refusal.reason,
            )
            .await
            .map_err(|_| "CONTROL_SITE_APPLY_STATE_UNAVAILABLE")?;
        return Err(refusal.reason);
    }
    if !control
        .catalog
        .mark_protected_site_applies_active_batch(&control.config.tenant_id, &plan.confirmed)
        .await
        .map_err(|_| "CONTROL_SITE_APPLY_STATE_UNAVAILABLE")?
    {
        return Err("CONTROL_SITE_APPLY_STATE_UNAVAILABLE");
    }
    // The snapshot is live. Sites that were held back because their desired
    // configuration does not compile, or would reuse a label for another
    // descriptor set, are reported on their own status; this is
    // informational, so a failure to record it does not undo the apply.
    let held_back = plan
        .invalid
        .iter()
        .map(|(site, revision, apply_id)| (site, revision, apply_id, "CONTROL_SITE_POLICY_INVALID"))
        .chain(
            plan.reused
                .iter()
                .map(|(site, revision, apply_id, reason)| (site, revision, apply_id, *reason)),
        );
    for (site, revision, apply_id, reason) in held_back {
        let _ = control
            .catalog
            .mark_protected_site_apply_failed(
                &control.config.tenant_id,
                site,
                *revision,
                apply_id,
                reason,
            )
            .await;
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

/// Hostnames that name internal or metadata services. An upstream *address* is
/// always an IP literal, so these only classify a refusal as a policy block
/// rather than a malformed value.
fn upstream_name_is_internal(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    ["metadata.google.internal", "metadata.google", "localhost"].contains(&host.as_str())
        || [".internal", ".localhost", ".local"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
}

/// Whether `name` is a DNS name under the URL parser the health probe uses.
///
/// WHATWG parsing reads `2130706433`, `0x7f.1` and `127.1` as IPv4 hosts, so a
/// character-class check is not enough; the name is parsed the way it will be
/// used and must come out as a domain.
fn server_name_is_dns_name(name: &str) -> bool {
    Url::parse(&format!("http://{name}/")).is_ok_and(|url| {
        matches!(url.host(), Some(url::Host::Domain(domain)) if domain.eq_ignore_ascii_case(name))
    })
}

/// Validates the origin destination: a literal socket address outside every
/// internal range, and a server name that is a DNS name.
fn validate_upstream_destination(
    address: &str,
    server_name: &str,
    allow_loopback: bool,
) -> Result<(), &'static str> {
    let Ok(socket) = parse_upstream_socket(address) else {
        // Names are never resolved on an operator's behalf. Known internal
        // names are reported as blocked so the audit trail shows intent.
        let host = address
            .rsplit_once(':')
            .map_or(address, |(host, _)| host)
            .trim_matches(['[', ']']);
        return Err(if upstream_name_is_internal(host) {
            "CONTROL_SITE_SSRF_BLOCKED"
        } else {
            "CONTROL_SITE_UPSTREAM_INVALID"
        });
    };
    if refuse_upstream_socket(socket, allow_loopback).is_some() {
        return Err("CONTROL_SITE_SSRF_BLOCKED");
    }
    if !server_name_is_dns_name(server_name) {
        return Err("CONTROL_SITE_UPSTREAM_INVALID");
    }
    Ok(())
}

/// Safe message of `CONTROL_SITE_POLICY_REVISION_REUSED`, the refusal of a
/// served configuration whose `policy_revision` label already names another
/// action-descriptor set for the site (or that the edge holds retired). It
/// names the field and the remedy; it never echoes stored values.
const POLICY_REVISION_REUSED_MESSAGE: &str = "this site's policy_revision label already names \
     a different set of page actions, or the edge has retired it; save the change under a new \
     policy_revision";
/// Next action of `CONTROL_SITE_POLICY_REVISION_REUSED`.
const POLICY_REVISION_REUSED_NEXT_ACTION: &str = "change_policy_revision";

/// Stable reason of a `share_issue` whose `share_issuance_rules` row already
/// exists differently (or whose policy revision cannot carry it); see
/// `xshield_postgres` `share_rules`.
const SHARE_RULE_CONFLICT: &str = "CONTROL_SITE_SHARE_RULE_CONFLICT";
/// Safe message of [`SHARE_RULE_CONFLICT`]; it names the remedy and never
/// echoes stored values.
const SHARE_RULE_CONFLICT_MESSAGE: &str = "the share issuance rule registered for this \
     policy_revision and issuance_rule_id differs from what this configuration needs \
     (another ceiling or view, or retired), or the policy revision cannot carry it; \
     rules are never changed, so use a new issuance_rule_id or policy_revision";
/// Next action of [`SHARE_RULE_CONFLICT`].
const SHARE_RULE_CONFLICT_NEXT_ACTION: &str = "change_share_issuance_rule_id";

/// Largest site configuration body accepted by the site write endpoints.
///
/// 256 routes (the policy limit) with typical provenance-flow blocks fit;
/// the former 16 KiB held about fifty plain routes. The edge parses at most
/// 1 MiB per site and its projection repeats the routes (`site_policy` and
/// `operations`), so a body of this size projects well inside that limit;
/// `SiteConfig::validate_for_site` still checks the projected size itself,
/// because default members expand a terse body. The bound also caps the
/// work of the strict parse and of [`rejected_body_reason`].
pub(crate) const SITE_CONFIG_BODY_BYTES_MAX: usize = 256 * 1024;

/// The stable reason for a body the strict configuration parse refused: a
/// specific one when it asks for an edge feature the control plane
/// deliberately does not manage (evidence capture, compatibility crypto,
/// service entries),
/// so it is never mistaken for a typo; the generic one otherwise.
fn rejected_body_reason(body: &[u8]) -> (&'static str, &'static str) {
    if xshield_core::site::find_unsupported_edge_feature(body).is_some() {
        (
            "CONTROL_SITE_FEATURE_UNSUPPORTED",
            "the configuration uses an edge feature the control plane does not manage",
        )
    } else {
        (
            "CONTROL_SITE_CONFIG_REQUEST_INVALID",
            "invalid site configuration",
        )
    }
}

/// Maps a core validation failure to the stable control reason code. The
/// browser provenance-flow rules each have their own reason so an operator or
/// agent can tell which block to fix.
fn validation_reason(field: &str) -> &'static str {
    match field {
        flow::AUTH_FLOW_INVALID => "CONTROL_SITE_AUTH_FLOW_INVALID",
        flow::SENSOR_HTML_INVALID => "CONTROL_SITE_SENSOR_HTML_INVALID",
        flow::PAGE_ACTIONS_INVALID => "CONTROL_SITE_PAGE_ACTIONS_INVALID",
        flow::RESOURCE_GRANT_INVALID => "CONTROL_SITE_RESOURCE_GRANT_INVALID",
        xshield_core::site::share::SHARE_ISSUE_INVALID => "CONTROL_SITE_SHARE_ISSUE_INVALID",
        xshield_core::query_pagination::QUERY_PAGINATION_INVALID => {
            "CONTROL_SITE_QUERY_PAGINATION_INVALID"
        }
        flow::ACTION_DESCRIPTOR_CONFLICT => "CONTROL_SITE_ACTION_DESCRIPTOR_CONFLICT",
        // Decided by the store against the label's bindings, not by
        // validation; mapped here so every flow refusal has one table.
        POLICY_REVISION_REUSED => "CONTROL_SITE_POLICY_REVISION_REUSED",
        _ if field.starts_with("upstream") => "CONTROL_SITE_UPSTREAM_INVALID",
        _ if field.starts_with("site_policy") => "CONTROL_SITE_POLICY_INVALID",
        "site_id" => "CONTROL_SITE_ID_INVALID",
        _ => "CONTROL_SITE_CONFIG_REQUEST_INVALID",
    }
}

/// Validates a request for `site_id` under the deployment's network policy.
///
/// Everything that does not depend on the deployment lives in
/// [`SiteConfig::validate_for_site`], the single definition the edge compiler
/// is held to by the gateway parity test; this adds only the destination
/// rules, which depend on the loopback opt-in.
fn validate_request(request: &SiteConfigRequest, site_id: &SiteId) -> Result<(), &'static str> {
    validate_request_with(request, site_id, loopback_upstream_allowed())
}

fn validate_request_with(
    request: &SiteConfigRequest,
    site_id: &SiteId,
    allow_loopback: bool,
) -> Result<(), &'static str> {
    let config = request.to_config();
    config
        .validate_for_site(site_id)
        .map_err(|error| validation_reason(error.field()))?;
    // The edge derives the action descriptors of a page-issuing site when it
    // compiles it; the store binds the label to the same derivation, so a
    // configuration it cannot derive is refused here rather than unbound.
    config
        .edge_descriptor_digest()
        .map_err(|error| validation_reason(error.field()))?;
    validate_upstream_destination(
        &request.upstream_address,
        &request.upstream_server_name,
        allow_loopback,
    )
}

/// The identity under which a write is remembered: the action, the caller, the
/// site and the key. It excludes the content, which is compared separately.
fn write_idempotency_digest(
    control: &ControlPlane,
    action: AccessAction,
    subject: &str,
    site_id: &SiteId,
    idempotency_key: &str,
) -> Option<[u8; 32]> {
    signature(
        control,
        b"site-config-idempotency-v2",
        &[
            action.event_type.as_bytes(),
            action.method.as_bytes(),
            action.path.as_bytes(),
            subject.as_bytes(),
            site_id.as_str().as_bytes(),
            idempotency_key.as_bytes(),
        ],
    )
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
    let config = record.site_config();
    SiteConfigView {
        display_name: config.display_name.clone(),
        public_origin: config.public_origin.clone(),
        upstream_address: config.upstream_address.clone(),
        upstream_server_name: config.upstream_server_name.clone(),
        upstream_tls: config.upstream_tls,
        listen_port: config.listen_port,
        entry_path: config.entry_path.clone(),
        security_entry: config.security_entry.clone(),
        sensor_enabled: config.sensor_enabled,
        policy_revision: config.policy_revision.clone(),
        status: config.status.clone(),
        policy: config.effective_policy(),
        revision: record.revision(),
        config_digest: hex(record.config_digest()),
        updated_by: record.updated_by().to_owned(),
        created_at: record.created_at().to_rfc3339(),
        updated_at: record.updated_at().to_rfc3339(),
        gateway_config: config
            .gateway_config(control.config.tenant_id.as_str(), site_id)
            .ok(),
    }
}

#[allow(clippy::format_collect)]
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        PlanInput, SiteConfigRequest, SiteHealthCheckConfig, SitePolicyConfig,
        merged_health_details, parse_site_list_query, patch_is_compatible, plan_upstream_probe,
        probe_upstream, rollback_target_revision, validate_apply_ack, validate_request,
        validate_request_with,
    };
    use serde_json::json;
    use xshield_core::{GatewayApplyAck, GatewayApplyRequest, domain::SiteId};

    fn site() -> SiteId {
        SiteId::parse("site_a").unwrap()
    }

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
        assert!(validate_request(&value, &site()).is_ok());
        value.public_origin = "http://public.example".to_owned();
        assert!(validate_request(&value, &site()).is_err());
    }

    /// The real-browser loop topology as a request body.
    fn browser_loop() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../tests/site-config/browser-loop.json")).unwrap()
    }

    /// Each provenance-flow rule surfaces its own stable reason, distinct from
    /// the generic policy refusal, so the block to fix is named.
    #[test]
    fn flow_violations_are_reported_with_their_own_reasons() {
        let reason = |edit: fn(&mut serde_json::Value)| {
            let mut body = browser_loop();
            edit(&mut body);
            let request: SiteConfigRequest = serde_json::from_value(body).unwrap();
            validate_request_with(&request, &site(), false).err()
        };
        assert_eq!(reason(|_| {}), None);
        for (expected, edit) in [
            (
                "CONTROL_SITE_AUTH_FLOW_INVALID",
                (|b| b["policy"]["routes"][1]["security_entry"] = json!("public"))
                    as fn(&mut serde_json::Value),
            ),
            ("CONTROL_SITE_SENSOR_HTML_INVALID", |b| {
                b["sensor_enabled"] = json!(false);
            }),
            ("CONTROL_SITE_PAGE_ACTIONS_INVALID", |b| {
                b["policy"]["routes"][3]["issued_by"]["ttl_seconds"] = json!(0);
            }),
            ("CONTROL_SITE_RESOURCE_GRANT_INVALID", |b| {
                b["policy"]["routes"][3]["resource_grant"]["max_items"] = json!(0);
            }),
            ("CONTROL_SITE_QUERY_PAGINATION_INVALID", |b| {
                b["policy"]["routes"][3]["query_pagination"] =
                    json!({"parameters": [{"name": "Page", "kind": "page"}]});
            }),
            ("CONTROL_SITE_QUERY_PAGINATION_INVALID", |b| {
                // Applies to a grant-issuing list and a non-resource UI action
                // route only; the page root takes no query.
                b["policy"]["routes"][2]["query_pagination"] =
                    json!({"parameters": [{"name": "page", "kind": "page"}]});
            }),
            ("CONTROL_SITE_ACTION_DESCRIPTOR_CONFLICT", |b| {
                let mut shadow = b["policy"]["routes"][3].clone();
                shadow["operation_id"] = json!("orders.list.shadow");
                shadow["path"] = json!("/orders-shadow");
                shadow.as_object_mut().unwrap().remove("resource_grant");
                b["policy"]["routes"].as_array_mut().unwrap().push(shadow);
            }),
            ("CONTROL_SITE_POLICY_INVALID", |b| {
                b["policy"]["routes"][0]["operation_id"] = json!("login:page");
            }),
        ] {
            assert_eq!(reason(edit), Some(expected), "{expected}");
        }
    }

    /// Share rules surface their own stable reason, and the valid scope
    /// passes request validation untouched.
    #[test]
    fn share_violations_are_reported_with_their_own_reason() {
        let share_flow: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/site-config/share-flow.json"))
                .unwrap();
        let reason = |edit: fn(&mut serde_json::Value, usize, usize)| {
            let mut body = share_flow.clone();
            let index = |body: &serde_json::Value, id: &str| {
                body["policy"]["routes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .position(|route| route["operation_id"] == id)
                    .unwrap()
            };
            let (issuer, entry) = (
                index(&body, "records.share.issue"),
                index(&body, "records.share.read"),
            );
            edit(&mut body, issuer, entry);
            let request: SiteConfigRequest = serde_json::from_value(body).unwrap();
            validate_request_with(&request, &site(), false).err()
        };
        assert_eq!(reason(|_, _, _| {}), None);
        for (expected, edit) in [
            (
                "CONTROL_SITE_SHARE_ISSUE_INVALID",
                (|b, issuer, _| {
                    b["policy"]["routes"][issuer]["share_issue"]["ttl_seconds"] = json!(0);
                }) as fn(&mut serde_json::Value, usize, usize),
            ),
            ("CONTROL_SITE_SHARE_ISSUE_INVALID", |b, issuer, _| {
                b["policy"]["routes"][issuer]["share_issue"]["target_operation_id"] =
                    json!("records.list");
            }),
            ("CONTROL_SITE_SHARE_ISSUE_INVALID", |b, _, entry| {
                b["policy"]["routes"][entry]["resource_type"] = json!("other");
            }),
            ("CONTROL_SITE_POLICY_INVALID", |b, _, entry| {
                b["policy"]["routes"][entry]["source_action"] = json!("records.read");
            }),
        ] {
            assert_eq!(reason(edit), Some(expected), "{expected}");
        }
    }

    #[test]
    fn rejected_bodies_name_unmanaged_edge_features_and_nothing_else() {
        let mut body = browser_loop();
        body["policy"]["routes"][5]["evidence_capture"] = json!({"max_bytes": 1});
        let bytes = serde_json::to_vec(&body).unwrap();
        assert!(serde_json::from_slice::<SiteConfigRequest>(&bytes).is_err());
        assert_eq!(
            super::rejected_body_reason(&bytes).0,
            "CONTROL_SITE_FEATURE_UNSUPPORTED"
        );
        let mut typo = browser_loop();
        typo["policy"]["routes"][5]["auth_revok"] = json!({"success_status": 200});
        assert_eq!(
            super::rejected_body_reason(&serde_json::to_vec(&typo).unwrap()).0,
            "CONTROL_SITE_CONFIG_REQUEST_INVALID"
        );
        assert_eq!(
            super::rejected_body_reason(b"not json").0,
            "CONTROL_SITE_CONFIG_REQUEST_INVALID"
        );
    }

    #[test]
    fn site_config_rejects_ambiguous_public_host_and_revision_text() {
        let mut value = request();
        value.public_origin = "https://public_example.com".to_owned();
        assert!(validate_request(&value, &site()).is_err());
        value = request();
        value.policy_revision = "policy version 2".to_owned();
        assert!(validate_request(&value, &site()).is_err());
    }

    #[test]
    fn site_config_rejects_metadata_and_link_local_upstreams() {
        let mut value = request();
        value.upstream_address = "127.0.0.1:9000".to_owned();
        assert!(validate_request(&value, &site()).is_err());
        value.upstream_address = "169.254.169.254:80".to_owned();
        assert!(validate_request(&value, &site()).is_err());
        value.upstream_address = "metadata.google.internal:80".to_owned();
        assert!(validate_request(&value, &site()).is_err());
    }

    /// Every address below reaches an internal, special-purpose or
    /// translation-capable network. The reviewer reproduced `[::1]`,
    /// `[fd00::1]`, `[fe80::1]` and both IPv4-mapped forms being accepted
    /// because `Url::host_str` brackets IPv6 literals and the textual IP
    /// check never matched.
    #[test]
    fn site_config_blocks_internal_ipv4_ipv6_mapped_and_translated_upstreams() {
        for address in [
            "[::1]:9000",
            "[fd00::1]:9000",
            "[fe80::1]:9000",
            "[fd00:ec2::254]:80",
            "[fec0::1]:80",
            "[ff02::1]:80",
            "[::]:80",
            "[2001:db8::1]:80",
            "[::ffff:127.0.0.1]:8080",
            "[::ffff:169.254.169.254]:8080",
            "[::ffff:10.0.0.5]:8080",
            "[::ffff:8.8.8.8]:8080",
            "[64:ff9b::7f00:1]:80",
            "[64:ff9b::a9fe:a9fe]:80",
            "[2002:7f00:1::]:80",
            "0.0.0.0:80",
            "0.1.2.3:80",
            "127.0.0.1:80",
            "127.255.255.254:80",
            "10.0.0.1:80",
            "172.16.0.1:80",
            "172.31.255.255:80",
            "192.168.1.1:80",
            "169.254.169.254:80",
            "168.63.129.16:80",
            "100.64.0.1:80",
            "100.100.100.200:80",
            "192.0.0.192:80",
            "192.0.2.1:80",
            "198.18.0.1:80",
            "198.51.100.1:80",
            "203.0.113.1:80",
            "224.0.0.1:80",
            "240.0.0.1:80",
            "255.255.255.255:80",
        ] {
            let mut value = request();
            value.upstream_address = address.to_owned();
            assert_eq!(
                validate_request_with(&value, &site(), false),
                Err("CONTROL_SITE_SSRF_BLOCKED"),
                "{address} must be refused as an internal upstream"
            );
        }
    }

    #[test]
    fn site_config_accepts_public_upstreams_and_scheme_default_ports() {
        // `Url::port()` is None for a scheme's default port, which used to make
        // `8.8.8.8:80` over http and `:443` over https "invalid".
        for (address, tls) in [
            ("8.8.8.8:80", false),
            ("8.8.8.8:443", true),
            ("8.8.8.8:443", false),
            ("8.8.8.8:80", true),
            ("[2001:4860:4860::8888]:443", true),
            ("172.15.255.255:80", false),
            ("172.32.0.1:80", false),
            ("100.63.255.255:80", false),
            ("100.128.0.1:80", false),
            ("169.253.255.255:80", false),
            ("169.255.0.1:80", false),
            ("192.169.0.1:80", false),
            ("198.17.255.255:80", false),
            ("198.20.0.1:80", false),
            ("223.255.255.255:80", false),
        ] {
            let mut value = request();
            value.upstream_address = address.to_owned();
            value.upstream_tls = tls;
            assert_eq!(
                validate_request_with(&value, &site(), false),
                Ok(()),
                "{address} tls={tls} is a public upstream"
            );
        }
    }

    #[test]
    fn site_config_loopback_opt_in_allows_only_loopback() {
        let mut value = request();
        value.upstream_address = "127.0.0.1:9000".to_owned();
        assert_eq!(validate_request_with(&value, &site(), true), Ok(()));
        value.upstream_address = "[::1]:9000".to_owned();
        assert_eq!(validate_request_with(&value, &site(), true), Ok(()));
        // The opt-in is for the local lab only; it never unlocks private,
        // metadata, mapped or translated destinations.
        for address in [
            "10.0.0.1:80",
            "169.254.169.254:80",
            "[::ffff:127.0.0.1]:80",
            "[64:ff9b::7f00:1]:80",
            "[fd00::1]:80",
        ] {
            value.upstream_address = address.to_owned();
            assert_eq!(
                validate_request_with(&value, &site(), true),
                Err("CONTROL_SITE_SSRF_BLOCKED"),
                "{address} stays blocked even with the loopback opt-in"
            );
        }
    }

    /// The probe used to build `http://{server_name}/...` and rely on a
    /// resolver override that reqwest ignores for IP literals, so a public
    /// `address` with `upstream_server_name = "127.0.0.1"` made the control
    /// plane dial 127.0.0.1:80. Names the URL parser reads as an IPv4 host
    /// ("2130706433", "0x7f.1", "127.1") have the same effect.
    #[test]
    fn site_config_rejects_server_names_that_a_url_parser_reads_as_an_ip() {
        for name in [
            "127.0.0.1",
            "169.254.169.254",
            "8.8.8.8",
            "2130706433",
            "0x7f.1",
            "0x7f.0.0.1",
            "127.1",
            "1.1.1",
        ] {
            let mut value = request();
            value.upstream_server_name = name.to_owned();
            assert_eq!(
                validate_request_with(&value, &site(), false),
                Err("CONTROL_SITE_UPSTREAM_INVALID"),
                "{name} is not a DNS name"
            );
        }
        for name in ["origin.local", "juice.lab", "a-b.example.test", "localhost"] {
            let mut value = request();
            value.upstream_server_name = name.to_owned();
            assert_eq!(
                validate_request_with(&value, &site(), false),
                Ok(()),
                "{name}"
            );
        }
    }

    #[test]
    fn probe_plan_targets_only_the_validated_socket_and_configured_port() {
        let plan = plan_upstream_probe(
            "8.8.8.8:9000",
            "Origin.Example.Test",
            false,
            "/health",
            false,
        )
        .unwrap();
        // The old probe built `http://{server_name}/health`, which dials the
        // scheme's default port instead of the configured one.
        assert_eq!(plan.url, "http://origin.example.test:9000/health");
        assert_eq!(plan.host, "origin.example.test");
        assert_eq!(plan.address, "8.8.8.8:9000".parse().unwrap());
        let default_port =
            plan_upstream_probe("8.8.8.8:443", "origin.test", true, "/h", false).unwrap();
        assert_eq!(default_port.address.port(), 443);
        assert_eq!(default_port.url, "https://origin.test/h");
    }

    #[test]
    fn probe_plan_refuses_internal_addresses_and_ip_like_server_names_without_io() {
        for address in [
            "[::ffff:127.0.0.1]:8080",
            "[::ffff:169.254.169.254]:80",
            "[::1]:80",
            "[fd00::1]:80",
            "127.0.0.1:80",
            "10.1.2.3:80",
            "169.254.169.254:80",
            "[64:ff9b::7f00:1]:80",
        ] {
            assert_eq!(
                plan_upstream_probe(address, "origin.test", false, "/health", false),
                Err("CONTROL_SITE_SSRF_BLOCKED"),
                "{address}"
            );
        }
        for name in ["127.0.0.1", "2130706433", "0x7f.1", "127.1", "[::1]", "a b"] {
            assert_eq!(
                plan_upstream_probe("8.8.8.8:9000", name, false, "/health", false),
                Err("CONTROL_SITE_UPSTREAM_INVALID"),
                "{name}"
            );
        }
        assert_eq!(
            plan_upstream_probe("origin.test:80", "origin.test", false, "/h", false),
            Err("CONTROL_SITE_UPSTREAM_INVALID")
        );
    }

    /// Accepts connections on 127.0.0.1, records each request head and answers
    /// with `response`. Returns the port and the shared record.
    async fn recording_origin(
        response: &'static str,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorded = std::sync::Arc::clone(&heads);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = std::sync::Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buffer = vec![0_u8; 4096];
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    recorded
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buffer[..read]).into_owned());
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (port, heads)
    }

    #[tokio::test]
    async fn probe_connects_to_the_pinned_socket_and_never_follows_redirects() {
        let (target_port, target_heads) = recording_origin(
            "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/elsewhere\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;
        let health = SiteHealthCheckConfig::default();
        // Only the lab opt-in may reach loopback; the Host header carries the
        // configured server name and port while the socket is the pinned one.
        let result = probe_upstream(
            &format!("127.0.0.1:{target_port}"),
            "origin.example.test",
            false,
            &health,
            true,
        )
        .await;
        assert_eq!(result["upstream_state"], "degraded", "{result}");
        assert_eq!(
            result["status"], 302,
            "redirects are reported, not followed"
        );
        let heads = target_heads.lock().unwrap();
        assert_eq!(heads.len(), 1);
        assert!(
            heads[0].starts_with("GET /health HTTP/1.1\r\n"),
            "{}",
            heads[0]
        );
        assert!(
            heads[0]
                .to_ascii_lowercase()
                .contains(&format!("host: origin.example.test:{target_port}\r\n")),
            "{}",
            heads[0]
        );
    }

    #[tokio::test]
    async fn probe_does_not_dial_mapped_loopback_or_ip_literal_server_names() {
        let (port, heads) =
            recording_origin("HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
        let health = SiteHealthCheckConfig {
            path: "/secret-internal-path".to_owned(),
            ..SiteHealthCheckConfig::default()
        };
        // A legacy or hand-edited row: the mapped loopback form used to pass
        // every textual check and the probe dialled 127.0.0.1:{port}.
        let mapped = probe_upstream(
            &format!("[::ffff:127.0.0.1]:{port}"),
            "origin.example.test",
            false,
            &health,
            false,
        )
        .await;
        assert_eq!(mapped["reason_code"], "CONTROL_SITE_SSRF_BLOCKED");
        assert_eq!(mapped["upstream_state"], "unavailable");
        // A public address with a loopback IP literal as server name used to
        // dial 127.0.0.1:80 because the resolver override skips IP hosts.
        let literal = probe_upstream("8.8.8.8:9000", "127.0.0.1", false, &health, false).await;
        assert_eq!(literal["reason_code"], "CONTROL_SITE_UPSTREAM_INVALID");
        // Even with the lab opt-in the mapped form stays blocked.
        let opted_in = probe_upstream(
            &format!("[::ffff:127.0.0.1]:{port}"),
            "origin.example.test",
            false,
            &health,
            true,
        )
        .await;
        assert_eq!(opted_in["reason_code"], "CONTROL_SITE_SSRF_BLOCKED");
        tokio::task::yield_now().await;
        assert!(
            heads.lock().unwrap().is_empty(),
            "no connection may reach the loopback origin: {:?}",
            heads.lock().unwrap()
        );
    }

    #[test]
    fn site_config_keeps_listeners_inside_the_private_edge_pool() {
        let mut value = request();
        value.listen_port = 6099;
        assert!(validate_request(&value, &site()).is_err());
        value.listen_port = 6100;
        assert!(validate_request(&value, &site()).is_ok());
    }

    #[test]
    fn site_config_rejects_ambiguous_entry_paths() {
        let mut value = request();
        value.entry_path = "/../admin".to_owned();
        assert!(validate_request(&value, &site()).is_err());
        value.entry_path = "/admin\\panel".to_owned();
        assert!(validate_request(&value, &site()).is_err());
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

    // The edge reports its transport (native TLS, PROXY protocol) and the
    // connections that failed before admission only in its health body;
    // the console must receive those fields unchanged.
    #[test]
    fn health_details_pass_edge_transport_fields_through() {
        let edge = json!({
            "edge_state": "healthy",
            "audit_state": "healthy",
            "tls_enabled": true,
            "tls_handshake_failures": 12,
            "proxy_protocol_enabled": true,
            "proxy_header_rejections": 3,
            "connection_setup_shed": 0
        });
        let details = merged_health_details(Some(edge.clone()), None);
        assert_eq!(details, edge);
        let with_upstream =
            merged_health_details(Some(edge), Some(json!({ "upstream_state": "healthy" })));
        assert_eq!(with_upstream["tls_handshake_failures"], 12);
        assert_eq!(with_upstream["proxy_header_rejections"], 3);
        assert_eq!(with_upstream["upstream_state"], "healthy");
    }

    #[test]
    fn site_list_query_rejects_unknown_and_duplicate_parameters() {
        assert_eq!(parse_site_list_query(None).unwrap(), (None, 100));
        assert_eq!(parse_site_list_query(Some("limit=25")).unwrap(), (None, 25));
        assert!(parse_site_list_query(Some("limit=25&limit=25")).is_err());
        assert!(parse_site_list_query(Some("scope=other")).is_err());
    }

    // ---- snapshot planning ------------------------------------------------

    fn config(status: &str, upstream: &str, port: u16) -> xshield_core::SiteConfig {
        xshield_core::SiteConfig {
            display_name: "demo".to_owned(),
            public_origin: "https://demo.example.test".to_owned(),
            upstream_address: upstream.to_owned(),
            upstream_server_name: "origin.example.test".to_owned(),
            upstream_tls: false,
            listen_port: port,
            entry_path: "/".to_owned(),
            security_entry: "public".to_owned(),
            sensor_enabled: false,
            policy_revision: "policy-v1".to_owned(),
            status: status.to_owned(),
            policy: SitePolicyConfig::default(),
        }
    }

    /// A site whose desired revision is 2 and whose active revision (if any)
    /// is 1, with distinct upstreams so the served one is identifiable.
    fn input(id: &str, desired: xshield_core::SiteConfig) -> PlanInput {
        PlanInput {
            site_id: SiteId::parse(id).unwrap(),
            desired,
            desired_revision: 2,
            apply_id: format!("apply_{id}"),
            requires_approval: false,
            active_revision: Some(1),
            active_config: Some(config("active", "1.1.1.1:9000", 6100)),
            conflict: None,
        }
    }

    /// A target whose label the store found bound to another descriptor set
    /// is refused with the stable reason, and nothing is planned for it.
    #[test]
    fn a_target_reusing_its_label_is_refused_before_anything_is_sent() {
        let mut target = input("site_b", config("active", "2.2.2.2:9000", 6101));
        target.conflict = Some("CONTROL_SITE_POLICY_REVISION_REUSED");
        let sibling = input("site_a", config("active", "8.8.4.4:9000", 6100));
        assert_eq!(
            super::plan_snapshot(
                &[sibling, target],
                &SiteId::parse("site_b").unwrap(),
                &apply_state("site_b"),
            )
            .err(),
            Some("CONTROL_SITE_POLICY_REVISION_REUSED")
        );
    }

    /// A rule row the store found to exist differently refuses the target
    /// with its own stable reason, and holds a sibling back alone with the
    /// same reason on its status.
    #[test]
    fn a_share_rule_conflict_has_its_own_reason_for_target_and_sibling() {
        let mut target = input("site_b", config("active", "2.2.2.2:9000", 6101));
        target.conflict = Some(super::SHARE_RULE_CONFLICT);
        let sibling = input("site_a", config("active", "8.8.4.4:9000", 6100));
        assert_eq!(
            super::plan_snapshot(
                &[sibling, target],
                &SiteId::parse("site_b").unwrap(),
                &apply_state("site_b"),
            )
            .err(),
            Some("CONTROL_SITE_SHARE_RULE_CONFLICT")
        );
        let target = input("site_b", config("active", "2.2.2.2:9000", 6101));
        let mut held = input("site_a", config("active", "8.8.4.4:9000", 6100));
        held.conflict = Some(super::SHARE_RULE_CONFLICT);
        let plan = super::plan_snapshot(
            &[held, target],
            &SiteId::parse("site_b").unwrap(),
            &apply_state("site_b"),
        )
        .unwrap();
        assert_eq!(
            plan.reused
                .iter()
                .map(|(site, _, _, reason)| (site.as_str(), *reason))
                .collect::<Vec<_>>(),
            [("site_a", "CONTROL_SITE_SHARE_RULE_CONFLICT")]
        );
        assert_eq!(confirmed(&plan), ["site_b"]);
    }

    /// A sibling whose desired revision reuses its label is held at its last
    /// approved configuration and reported on its own status; the target and
    /// every other site are planned as if it were not there.
    #[test]
    fn a_sibling_reusing_its_label_is_held_back_alone() {
        let target = input("site_b", config("active", "2.2.2.2:9000", 6101));
        let mut reusing = input("site_a", config("active", "8.8.4.4:9000", 6100));
        reusing.conflict = Some("CONTROL_SITE_POLICY_REVISION_REUSED");
        let other = input("site_c", config("active", "9.9.9.9:9000", 6102));
        let plan = super::plan_snapshot(
            &[reusing, target, other],
            &SiteId::parse("site_b").unwrap(),
            &apply_state("site_b"),
        )
        .unwrap();
        assert_eq!(
            served(&plan),
            [
                ("site_a".to_owned(), "1.1.1.1:9000".to_owned(), 1),
                ("site_b".to_owned(), "2.2.2.2:9000".to_owned(), 2),
                ("site_c".to_owned(), "9.9.9.9:9000".to_owned(), 2),
            ]
        );
        assert_eq!(confirmed(&plan), ["site_b", "site_c"]);
        assert_eq!(
            plan.reused
                .iter()
                .map(|(site, revision, _, _)| (site.as_str(), *revision))
                .collect::<Vec<_>>(),
            [("site_a", 2)]
        );
        assert!(plan.invalid.is_empty());
    }

    fn apply_state(id: &str) -> xshield_postgres::ProtectedSiteApplyState {
        xshield_postgres::ProtectedSiteApplyState {
            desired_revision: 2,
            active_revision: Some(1),
            apply_id: format!("apply_{id}"),
            apply_state: "pending".to_owned(),
            reason_code: "EDGE_APPLY_NOT_CONFIRMED".to_owned(),
            retry_count: 0,
            requires_approval: false,
            risk_reasons: Vec::new(),
            approved_by: None,
            approval_id: None,
            updated_at: chrono::Utc::now(),
        }
    }

    fn served(plan: &super::SnapshotPlan) -> Vec<(String, String, u64)> {
        plan.served
            .iter()
            .map(|site| {
                (
                    site.site_id.as_str().to_owned(),
                    site.config.upstream_address.clone(),
                    site.revision,
                )
            })
            .collect()
    }

    fn confirmed(plan: &super::SnapshotPlan) -> Vec<String> {
        plan.confirmed
            .iter()
            .map(|(site, _, _)| site.as_str().to_owned())
            .collect()
    }

    #[test]
    fn a_site_awaiting_approval_stays_on_its_last_approved_configuration() {
        let target = input("site_b", config("active", "2.2.2.2:9000", 6101));
        let mut pending = input("site_a", config("active", "8.8.4.4:9000", 6100));
        pending.requires_approval = true;
        let mut never_applied = input("site_c", config("active", "9.9.9.9:9000", 6102));
        never_applied.requires_approval = true;
        never_applied.active_revision = None;
        never_applied.active_config = None;
        let plan = super::plan_snapshot(
            &[pending, target, never_applied],
            &SiteId::parse("site_b").unwrap(),
            &apply_state("site_b"),
        )
        .unwrap();
        assert_eq!(
            served(&plan),
            [
                // Held at the approved revision 1, not the desired 8.8.4.4.
                ("site_a".to_owned(), "1.1.1.1:9000".to_owned(), 1),
                ("site_b".to_owned(), "2.2.2.2:9000".to_owned(), 2),
            ],
            "the never-applied site is omitted"
        );
        assert_eq!(
            confirmed(&plan),
            ["site_b"],
            "only the applied desired revision"
        );
        assert!(plan.invalid.is_empty());
    }

    #[test]
    fn drafts_are_omitted_and_never_confirmed_while_paused_sites_are_confirmed() {
        let target = input("site_b", config("active", "2.2.2.2:9000", 6101));
        let draft = input("site_a", config("draft", "8.8.4.4:9000", 6100));
        let paused = input("site_c", config("paused", "9.9.9.9:9000", 6102));
        let plan = super::plan_snapshot(
            &[draft, target, paused],
            &SiteId::parse("site_b").unwrap(),
            &apply_state("site_b"),
        )
        .unwrap();
        assert_eq!(served(&plan).len(), 1);
        assert_eq!(
            confirmed(&plan),
            ["site_b", "site_c"],
            "a draft must never look applied; a paused site applies as paused"
        );
    }

    #[test]
    fn a_takedown_awaiting_approval_keeps_the_site_served() {
        let target = input("site_b", config("active", "2.2.2.2:9000", 6101));
        let mut pausing = input("site_a", config("paused", "1.1.1.1:9000", 6100));
        pausing.requires_approval = true;
        let plan = super::plan_snapshot(
            &[pausing, target],
            &SiteId::parse("site_b").unwrap(),
            &apply_state("site_b"),
        )
        .unwrap();
        assert_eq!(served(&plan).len(), 2, "unapproved pause is not applied");
        assert_eq!(confirmed(&plan), ["site_b"]);
    }

    #[test]
    fn an_uncompilable_sibling_is_held_back_and_reported_without_failing_the_tenant() {
        let target = input("site_b", config("active", "2.2.2.2:9000", 6101));
        let mut broken = config("active", "8.8.4.4:9000", 6100);
        broken.policy.routes = vec![xshield_core::SiteRouteConfig {
            operation_id: "bad".to_owned(),
            method: "GET".to_owned(),
            path: "/a b".to_owned(),
            security_entry: xshield_core::SecurityEntry::Public,
            source_action: None,
            resource_type: None,
            view_profile: None,
            resource_query_parameter: None,
            resource_path_parameter: None,
            request_crypto: None,
            response_crypto: None,
            response_mode: String::new(),
            max_response_bytes: 1_048_576,
            auth_binding: None,
            auth_revoke: None,
            sensor_html: None,
            page_actions: None,
            issued_by: None,
            resource_grant: None,
            query_pagination: None,
            share_issue: None,
            auth_refresh: None,
            auth_context_switch: None,
        }];
        let sibling = input("site_a", broken);
        let plan = super::plan_snapshot(
            &[sibling, target],
            &SiteId::parse("site_b").unwrap(),
            &apply_state("site_b"),
        )
        .unwrap();
        assert_eq!(
            served(&plan),
            [
                ("site_a".to_owned(), "1.1.1.1:9000".to_owned(), 1),
                ("site_b".to_owned(), "2.2.2.2:9000".to_owned(), 2),
            ]
        );
        assert_eq!(
            plan.invalid
                .iter()
                .map(|(site, _, _)| site.as_str())
                .collect::<Vec<_>>(),
            ["site_a"]
        );
        assert_eq!(confirmed(&plan), ["site_b"]);
    }

    /// A live site is never dropped because a validator got stricter after the
    /// edge accepted it: the held-back configuration is re-sent as it was.
    #[test]
    fn the_held_back_configuration_is_not_revalidated() {
        let target = input("site_b", config("active", "2.2.2.2:9000", 6101));
        let mut pending = input("site_a", config("active", "8.8.4.4:9000", 6100));
        pending.requires_approval = true;
        // Valid for the edge that applied it, but not under today's rules.
        pending.active_config = Some(xshield_core::SiteConfig {
            public_origin: "https://[::1]".to_owned(),
            ..config("active", "1.1.1.1:9000", 6100)
        });
        assert!(
            pending
                .active_config
                .as_ref()
                .unwrap()
                .validate_for_site(&pending.site_id)
                .is_err()
        );
        let plan = super::plan_snapshot(
            &[pending, target],
            &SiteId::parse("site_b").unwrap(),
            &apply_state("site_b"),
        )
        .unwrap();
        assert_eq!(served(&plan).len(), 2);
    }

    #[test]
    fn the_target_is_held_to_the_strict_rule_with_a_stable_reason() {
        let strict = |target: PlanInput, state: xshield_postgres::ProtectedSiteApplyState| {
            super::plan_snapshot(&[target], &SiteId::parse("site_a").unwrap(), &state).err()
        };
        let base = || input("site_a", config("active", "8.8.4.4:9000", 6100));

        let mut awaiting = base();
        awaiting.requires_approval = true;
        assert_eq!(
            strict(awaiting, apply_state("site_a")),
            Some("CONTROL_SITE_APPROVAL_REQUIRED")
        );
        assert_eq!(
            strict(
                input("site_a", config("draft", "8.8.4.4:9000", 6100)),
                apply_state("site_a")
            ),
            Some("CONTROL_SITE_DRAFT_NOT_APPLICABLE")
        );
        let mut bad_origin = config("active", "8.8.4.4:9000", 6100);
        bad_origin.public_origin = "https://[::1]".to_owned();
        assert_eq!(
            strict(input("site_a", bad_origin), apply_state("site_a")),
            Some("CONTROL_SITE_POLICY_INVALID")
        );
        // The caller read a different revision or apply identity than the one
        // under the lock.
        let mut stale = apply_state("site_a");
        stale.desired_revision = 1;
        assert_eq!(
            strict(base(), stale),
            Some("CONTROL_SITE_APPLY_STATE_UNAVAILABLE")
        );
        let mut other_apply = apply_state("site_a");
        other_apply.apply_id = "apply_other".to_owned();
        assert_eq!(
            strict(base(), other_apply),
            Some("CONTROL_SITE_APPLY_STATE_UNAVAILABLE")
        );
        assert!(strict(base(), apply_state("site_a")).is_none());
    }

    #[test]
    fn two_sites_on_one_listener_are_refused_before_anything_is_sent() {
        // A held-back site keeps its old port, which a later site may now own.
        let mut pending = input("site_a", config("active", "8.8.4.4:9000", 6101));
        pending.requires_approval = true;
        pending.active_config = Some(config("active", "1.1.1.1:9000", 6100));
        let target = input("site_b", config("active", "2.2.2.2:9000", 6100));
        assert_eq!(
            super::plan_snapshot(
                &[pending, target],
                &SiteId::parse("site_b").unwrap(),
                &apply_state("site_b"),
            )
            .err(),
            Some("CONTROL_SITE_PORT_UNAVAILABLE")
        );
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

    fn apply_with(
        desired: u64,
        active: Option<u64>,
        state: &str,
    ) -> xshield_postgres::ProtectedSiteApplyState {
        xshield_postgres::ProtectedSiteApplyState {
            desired_revision: desired,
            active_revision: active,
            apply_id: "apply_demo".to_owned(),
            apply_state: state.to_owned(),
            reason_code: "EDGE_UNAVAILABLE".to_owned(),
            retry_count: 1,
            requires_approval: false,
            risk_reasons: Vec::new(),
            approved_by: None,
            approval_id: None,
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn rollback_cancels_a_pending_change_by_restoring_the_active_revision() {
        // Desired revision 3 never became active: the active one is restored.
        assert_eq!(
            rollback_target_revision(&apply_with(3, Some(2), "failed"), Some(1)),
            Some(2)
        );
        assert_eq!(
            rollback_target_revision(&apply_with(3, Some(2), "pending"), None),
            Some(2)
        );
        // The last apply of the active revision itself did not complete.
        assert_eq!(
            rollback_target_revision(&apply_with(2, Some(2), "failed"), Some(1)),
            Some(2)
        );
    }

    /// `active - 1` is wrong whenever a revision in between never served
    /// traffic; the recorded activation order decides.
    #[test]
    fn rollback_with_nothing_pending_restores_the_previously_active_revision() {
        // Revision 3 was never approved, so revision 4's predecessor in
        // service is revision 2.
        assert_eq!(
            rollback_target_revision(&apply_with(4, Some(4), "active"), Some(2)),
            Some(2)
        );
        // A paused site has nothing pending either; undo the pause.
        assert_eq!(
            rollback_target_revision(&apply_with(4, Some(4), "paused"), Some(3)),
            Some(3)
        );
        // Only one revision has ever been active, or none has.
        assert_eq!(
            rollback_target_revision(&apply_with(1, Some(1), "active"), None),
            None
        );
        assert_eq!(
            rollback_target_revision(&apply_with(1, None, "pending"), None),
            None
        );
    }
}
