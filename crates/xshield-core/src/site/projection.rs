//! The strict JSON the edge compiler consumes for one site.
//!
//! The projection is built from typed values only: every member the edge
//! reads is a field of a `Serialize` struct below, borrowed from the validated
//! configuration. It is total and faithful: nothing is dropped, defaulted or
//! replaced when a value would not compile on the edge (validation, not the
//! projection, decides acceptance), and a serialization failure is returned as
//! an error instead of being papered over. An earlier version replaced
//! unserializable request crypto with `OBSERVE`, which would have turned a
//! decrypting route into a pass-through one without anybody noticing.
//!
//! Unset optional members are omitted rather than written as `null`. The edge
//! DTOs read both the same way, and omission keeps the projection identical to
//! a hand-written edge configuration (the golden test in
//! `crates/xshield-gateway/tests/site_config_parity.rs` compares it with the
//! real-browser loop's configuration).

use super::{
    SecurityEntry, SiteConfig, SitePolicyConfig, SiteRequestCrypto, SiteResponseCrypto,
    SiteRouteConfig,
    flow::{
        SiteAuthBinding, SiteAuthRevoke, SiteIssuedBy, SitePageActions, SiteResourceGrant,
        SiteSensorHtmlAdapter,
    },
};
use crate::domain::{InvalidValue, SiteId};
use serde::Serialize;

/// Gateway `MAX_CONFIG_BYTES`: the largest per-site configuration the edge
/// parses. Pinned by the gateway parity test.
pub const EDGE_MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// [`InvalidValue`] field when the projection cannot be produced.
const PROJECTION_INVALID: &str = "gateway_config";

/// Fixed placeholder build reference: the sensor echoes it in observations,
/// which are recorded as `client_claimed` and never authorize anything.
const SENSOR_BUILD_REF: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize)]
struct GatewayConfig<'a> {
    listen: String,
    origin: Origin<'a>,
    tenant_id: &'a str,
    site_id: &'a str,
    policy_revision: &'a str,
    site_policy: &'a SitePolicyConfig,
    audit: Audit,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_store: Option<IdentityStore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sensor: Option<Sensor<'a>>,
    operations: Vec<EdgeOperation<'a>>,
}

#[derive(Serialize)]
struct Origin<'a> {
    address: &'a str,
    server_name: &'a str,
    tls: bool,
}

#[derive(Serialize)]
struct Audit {
    directory: String,
    key_id: &'static str,
    producer_id: String,
    max_bytes: u64,
    high_watermark_bytes: u64,
    segment_max_bytes: u64,
}

/// Anonymous-session settings for the edge identity store.
#[derive(Debug, Serialize)]
struct IdentityStore {
    max_connections: u32,
    acquire_timeout_ms: u64,
    anonymous_session_ttl_seconds: u64,
    max_active_anonymous_sessions: u64,
    anonymous_session_rate_window_seconds: u64,
    max_anonymous_session_creations_per_source: u64,
    max_anonymous_session_creations_per_site: u64,
}

#[derive(Serialize)]
struct Sensor<'a> {
    origin: &'a str,
    build_ref: &'static str,
    heartbeat_seconds: u16,
}

/// One edge operation (gateway `OperationDto`).
#[derive(Serialize)]
struct EdgeOperation<'a> {
    operation_id: &'a str,
    method: &'a str,
    path: &'a str,
    admission: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    view_profile: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_query_parameter: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_path_parameter: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_crypto: Option<&'a SiteRequestCrypto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_by: Option<&'a SiteIssuedBy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<Response<'a>>,
}

/// One edge response rule (gateway `ResponseDto`, whose `SENSOR_HTML`
/// adapter members are flat rather than nested).
#[derive(Serialize)]
struct Response<'a> {
    mode: &'a str,
    max_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter_revision: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    injection_offset: Option<usize>,
    #[serde(skip_serializing_if = "<[SiteSensorHtmlAdapter]>::is_empty")]
    additional_adapters: &'a [SiteSensorHtmlAdapter],
    #[serde(skip_serializing_if = "Option::is_none")]
    page_actions: Option<&'a SitePageActions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto: Option<&'a SiteResponseCrypto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_grant: Option<&'a SiteResourceGrant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_binding: Option<&'a SiteAuthBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_revoke: Option<&'a SiteAuthRevoke>,
}

/// Projects the effective policy of `config` for `site_id`.
///
/// # Errors
/// Returns [`InvalidValue`] named `gateway_config` when the projection cannot
/// be serialized; nothing partial is ever returned.
pub(super) fn gateway_config(
    config: &SiteConfig,
    tenant_id: &str,
    site_id: &SiteId,
) -> Result<serde_json::Value, InvalidValue> {
    let policy = config.effective_policy();
    // The edge refuses any route that needs identity, any request crypto and
    // the sensor without an identity store, so the store is derived from what
    // the effective routes actually need.
    let needs_identity_store = policy.identity.enabled
        || config.security_entry != "public"
        || config.sensor_enabled
        || policy.routes.iter().any(|route| {
            route.security_entry != SecurityEntry::Public || route.request_crypto.is_some()
        });
    let projection = GatewayConfig {
        listen: format!("127.0.0.1:{}", config.listen_port),
        origin: Origin {
            address: &config.upstream_address,
            server_name: &config.upstream_server_name,
            tls: config.upstream_tls,
        },
        tenant_id,
        site_id: site_id.as_str(),
        policy_revision: &config.policy_revision,
        site_policy: &policy,
        audit: Audit {
            directory: format!("target/xshield-audit-{}", site_id.as_str()),
            key_id: "deployment-managed",
            producer_id: format!("edge-{}", site_id.as_str()),
            max_bytes: 16_777_216,
            high_watermark_bytes: 12_582_912,
            segment_max_bytes: 4_194_304,
        },
        identity_store: needs_identity_store
            .then(|| identity_store(policy.identity.session_ttl_seconds)),
        sensor: config.sensor_enabled.then(|| Sensor {
            // The edge requires a bare `scheme://authority` origin.
            origin: config
                .public_origin
                .strip_suffix('/')
                .unwrap_or(&config.public_origin),
            build_ref: SENSOR_BUILD_REF,
            heartbeat_seconds: 15,
        }),
        operations: policy.routes.iter().map(operation).collect(),
    };
    serde_json::to_value(&projection).map_err(|_| InvalidValue::new(PROJECTION_INVALID))
}

/// Projects one route to the edge's operation DTO.
///
/// # Errors
/// Returns [`InvalidValue`] named `gateway_config` when the operation cannot
/// be serialized.
pub fn gateway_operation(route: &SiteRouteConfig) -> Result<serde_json::Value, InvalidValue> {
    serde_json::to_value(operation(route)).map_err(|_| InvalidValue::new(PROJECTION_INVALID))
}

fn operation(route: &SiteRouteConfig) -> EdgeOperation<'_> {
    EdgeOperation {
        operation_id: &route.operation_id,
        method: &route.method,
        path: &route.path,
        admission: route.security_entry.edge_admission(),
        source_action: route.source_action.as_deref(),
        resource_type: route.resource_type.as_deref(),
        view_profile: route.view_profile.as_deref(),
        resource_query_parameter: route.resource_query_parameter.as_deref(),
        resource_path_parameter: route.resource_path_parameter.as_deref(),
        request_crypto: route.request_crypto.as_ref(),
        issued_by: route.issued_by.as_ref(),
        response: response(route),
    }
}

/// The response rule, emitted whenever the route names a mode or any
/// response block; an empty mode means `BUFFERED_JSON`. Every block is copied
/// as is, including combinations validation refuses, so a validator gap shows
/// up as an edge refusal rather than as a silently weaker rule.
fn response(route: &SiteRouteConfig) -> Option<Response<'_>> {
    let sensor = route.sensor_html.as_ref();
    let any_block = route.response_crypto.is_some()
        || route.resource_grant.is_some()
        || route.auth_binding.is_some()
        || route.auth_revoke.is_some()
        || route.page_actions.is_some()
        || sensor.is_some();
    if route.response_mode.is_empty() && !any_block {
        return None;
    }
    Some(Response {
        mode: if route.response_mode.is_empty() {
            "BUFFERED_JSON"
        } else {
            &route.response_mode
        },
        max_bytes: route.max_response_bytes,
        adapter_revision: sensor.map(|adapter| adapter.adapter_revision.as_str()),
        origin_sha256: sensor.map(|adapter| adapter.origin_sha256.as_str()),
        injection_offset: sensor.map(|adapter| adapter.injection_offset),
        additional_adapters: sensor.map_or(&[], |adapter| &adapter.additional_adapters),
        page_actions: route.page_actions.as_ref(),
        crypto: route.response_crypto.as_ref(),
        resource_grant: route.resource_grant.as_ref(),
        auth_binding: route.auth_binding.as_ref(),
        auth_revoke: route.auth_revoke.as_ref(),
    })
}

/// Anonymous-session settings for the edge identity store.
///
/// Sessions created in one rate window all live for the TTL, so the number
/// alive at once is the per-site creation rate times the windows the TTL
/// spans (plus one); the edge rejects a store whose product exceeds the
/// active-session budget. The creation rate is therefore derived from the TTL
/// instead of being fixed, which keeps every TTL the policy allows applicable.
fn identity_store(session_ttl_seconds: u64) -> IdentityStore {
    const WINDOW_SECONDS: u64 = 60;
    const MAX_ACTIVE_SESSIONS: u64 = 100_000;
    const SITE_RATE: u64 = 1_000;
    const SOURCE_RATE: u64 = 10;
    let windows = session_ttl_seconds
        .div_ceil(WINDOW_SECONDS)
        .saturating_add(1);
    let per_site = SITE_RATE.min(MAX_ACTIVE_SESSIONS / windows).max(1);
    let per_source = SOURCE_RATE.min(per_site);
    IdentityStore {
        max_connections: 8,
        acquire_timeout_ms: 2000,
        anonymous_session_ttl_seconds: session_ttl_seconds,
        max_active_anonymous_sessions: MAX_ACTIVE_SESSIONS,
        anonymous_session_rate_window_seconds: WINDOW_SECONDS,
        max_anonymous_session_creations_per_source: per_source,
        max_anonymous_session_creations_per_site: per_site,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_store_stays_inside_the_edge_capacity_model_for_every_ttl() {
        for ttl in [1_u64, 59, 60, 61, 3_600, 5_940, 5_941, 43_200, 86_400] {
            let store = identity_store(ttl);
            let windows = ttl.div_ceil(60) + 1;
            assert!(
                store.max_anonymous_session_creations_per_site * windows
                    <= store.max_active_anonymous_sessions,
                "ttl {ttl}"
            );
            assert!(
                store.max_anonymous_session_creations_per_source >= 1
                    && store.max_anonymous_session_creations_per_source
                        <= store.max_anonymous_session_creations_per_site,
                "ttl {ttl}"
            );
        }
        // TTLs that already fit keep the original, unreduced rates.
        let default = identity_store(3_600);
        assert_eq!(default.max_anonymous_session_creations_per_site, 1_000);
        assert_eq!(default.max_anonymous_session_creations_per_source, 10);
    }
}
