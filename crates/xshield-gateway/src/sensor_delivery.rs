//! Edge-served sensor scripts and versioned bootstrap documents.
//!
//! Script bytes are immutable per version path and SRI-pinned by delivered
//! HTML, so both the current (1.1.0) and the frozen 1.0.0 pair are served
//! byte-identical. The bootstrap is per request, `private, no-store`: a
//! request without a page handle receives the exact 1.0.0 document (no
//! references; that sensor cannot attach any), while a 1.1.0 request receives
//! only references the identity adapter resolved for its own session and page
//! instance plus non-secret routing hints. References are never logged.

use crate::protected_identity::SensorBootstrapDelivery;
use bytes::Bytes;
use pingora::{Result as PingoraResult, http::ResponseHeader, proxy::Session};
use serde_json::{Value, json};
use uuid::Uuid;
use xshield_core::identity::UnixSeconds;
use xshield_gateway::{
    LEGACY_SENSOR_ASSET_BYTES, LEGACY_SENSOR_LOADER_BYTES, LEGACY_SENSOR_VERSION,
    SENSOR_ASSET_BYTES, SENSOR_LOADER_BYTES, SENSOR_PREPARE_PATH, SENSOR_VERSION, SensorConfig,
    page_actions::{HarvestSource, HarvestTarget, SensorRoutes},
};

/// One immutable sensor script and the version its path names.
#[derive(Clone, Copy)]
pub(crate) struct SensorScript {
    bytes: &'static [u8],
    version: &'static str,
}

impl SensorScript {
    pub(crate) const CURRENT: Self = Self {
        bytes: SENSOR_ASSET_BYTES,
        version: SENSOR_VERSION,
    };
    pub(crate) const LOADER: Self = Self {
        bytes: SENSOR_LOADER_BYTES,
        version: SENSOR_VERSION,
    };
    pub(crate) const LEGACY: Self = Self {
        bytes: LEGACY_SENSOR_ASSET_BYTES,
        version: LEGACY_SENSOR_VERSION,
    };
    pub(crate) const LEGACY_LOADER: Self = Self {
        bytes: LEGACY_SENSOR_LOADER_BYTES,
        version: LEGACY_SENSOR_VERSION,
    };
}

pub(crate) async fn respond_sensor_script(
    session: &mut Session,
    request_id: &str,
    script: SensorScript,
) -> PingoraResult<()> {
    let body = Bytes::from_static(script.bytes);
    let mut response = ResponseHeader::build(200, Some(7))?;
    response.insert_header("Content-Type", "text/javascript; charset=utf-8")?;
    response.insert_header("Cache-Control", "public, max-age=31536000, immutable")?;
    response.insert_header("Cross-Origin-Resource-Policy", "same-origin")?;
    response.insert_header("X-Content-Type-Options", "nosniff")?;
    response.insert_header("X-Xshield-Sensor-Version", script.version)?;
    response.insert_header("X-Xshield-Request-Id", request_id)?;
    response.set_content_length(body.len())?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(Some(body), true).await
}

pub(crate) async fn respond_sensor_bootstrap(
    session: &mut Session,
    request_id: &str,
    document: Value,
) -> PingoraResult<()> {
    let body = Bytes::from(document.to_string());
    let mut response = ResponseHeader::build(200, Some(7))?;
    response.insert_header("Content-Type", "application/json")?;
    response.insert_header("Cache-Control", "private, no-store")?;
    response.insert_header("Pragma", "no-cache")?;
    response.insert_header("Cross-Origin-Resource-Policy", "same-origin")?;
    response.insert_header("X-Content-Type-Options", "nosniff")?;
    response.insert_header("X-Xshield-Request-Id", request_id)?;
    response.set_content_length(body.len())?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(Some(body), true).await
}

/// Builds the bootstrap document for one request.
pub(crate) fn bootstrap_document(
    request_id: &str,
    sensor: &SensorConfig,
    routes: &SensorRoutes,
    delivery: Option<&SensorBootstrapDelivery>,
    now: UnixSeconds,
) -> Value {
    let base = |version: &str, page_handle: String| {
        json!({
            "sensor_version": version,
            "build_ref": sensor.build_ref(),
            "page_handle": page_handle,
            "navigation_id": format!("nav_{}", Uuid::now_v7()),
            "prepare_url": SENSOR_PREPARE_PATH,
            "heartbeat_seconds": sensor.heartbeat_seconds(),
            "request_id": request_id,
        })
    };
    let Some(SensorBootstrapDelivery::Page {
        page_handle,
        actions,
    }) = delivery
    else {
        return base(LEGACY_SENSOR_VERSION, format!("pgh_{}", Uuid::now_v7()));
    };
    let mut document = base(SENSOR_VERSION, page_handle.clone());
    document["actions"] = Value::Array(
        actions
            .iter()
            .filter_map(|action| {
                let remaining = action.expires_at.value().checked_sub(now.value())?;
                (remaining > 0).then(|| {
                    json!({
                        "action_ref": action.action_ref.as_str(),
                        "method": action.method.as_str(),
                        "path_template": action.route.as_str(),
                        "expires_in_seconds": remaining,
                    })
                })
            })
            .collect(),
    );
    document["harvest"] = Value::Array(
        routes
            .harvest()
            .iter()
            .map(|rule| {
                json!({
                    "source": match &rule.source {
                        HarvestSource::Exact(path) => {
                            json!({"method": rule.source_method.as_str(), "path": path})
                        }
                        HarvestSource::Prefix(prefix) => {
                            json!({"method": rule.source_method.as_str(), "prefix": prefix})
                        }
                    },
                    "items_pointer": rule.items_pointer,
                    "resource_pointer": rule.resource_pointer,
                    "ref_field": rule.ref_field.as_str(),
                    "target": match &rule.target {
                        HarvestTarget::PathSegment { prefix } => {
                            json!({"method": rule.target_method.as_str(), "prefix": prefix})
                        }
                        HarvestTarget::Query { path, parameter } => json!({
                            "method": rule.target_method.as_str(),
                            "path": path,
                            "parameter": parameter.as_str(),
                        }),
                    },
                    "ttl_seconds": rule.ttl_seconds,
                    "max_items": rule.max_items,
                })
            })
            .collect(),
    );
    document["invalidate"] = Value::Array(
        routes
            .invalidate()
            .iter()
            .map(|(method, path)| json!({"method": method.as_str(), "path": path}))
            .collect(),
    );
    document
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::{
        domain::ActionRef,
        provenance::{HttpMethod, RouteTemplate},
    };
    use xshield_gateway::GatewayConfig;
    use xshield_postgres::PageActionView;

    const PAGE: &str = "pgh_018f2a3b-4c5d-7000-8000-000000000001";

    fn config() -> GatewayConfig {
        let config = serde_json::json!({
            "listen": "127.0.0.1:6188",
            "origin": {"address": "127.0.0.1:8080", "server_name": "origin.example", "tls": false},
            "tenant_id": "tenant_demo", "site_id": "site_demo", "policy_revision": "policy-r1",
            "audit": {"directory": "target/xshield-audit-test", "key_id": "journal-key-r1",
                      "producer_id": "edge-test", "max_bytes": 1_048_576,
                      "high_watermark_bytes": 786_432, "segment_max_bytes": 262_144},
            "identity_store": {"max_connections": 4, "acquire_timeout_ms": 1000},
            "sensor": {"origin": "https://app.example", "build_ref": "a".repeat(64),
                       "heartbeat_seconds": 15},
            "operations": [
                {"operation_id": "auth.logout", "method": "POST", "path": "/api/logout",
                 "admission": "AUTHENTICATED_ROOT",
                 "response": {"mode": "BUFFERED_JSON", "max_bytes": 64,
                              "auth_revoke": {"success_status": 200}}},
                {"operation_id": "orders.list", "method": "GET", "path": "/orders",
                 "admission": "AUTHENTICATED_ROOT",
                 "response": {"mode": "BUFFERED_JSON", "max_bytes": 4096,
                              "resource_grant": {"success_status": 200, "items_pointer": "/orders",
                                                 "resource_pointer": "/id",
                                                 "action_ref_field": "_xshield_action_ref",
                                                 "target_operation_id": "orders.read",
                                                 "target_mapping_revision": "mapping-r1",
                                                 "ttl_seconds": 900, "max_items": 10,
                                                 "max_active_grants": 100}}},
                {"operation_id": "orders.read", "method": "GET", "path": "/orders/{order_id}",
                 "admission": "UI_ACTION_REQUIRED", "source_action": "orders.open",
                 "resource_type": "order", "view_profile": "detail",
                 "resource_path_parameter": "order_id"}
            ]
        });
        GatewayConfig::from_json(config.to_string().as_bytes()).unwrap()
    }

    fn action(reference: &str, expires_at: u64) -> PageActionView {
        PageActionView {
            action_ref: ActionRef::parse(reference).unwrap(),
            method: HttpMethod::Get,
            route: RouteTemplate::parse("/orders").unwrap(),
            expires_at: UnixSeconds::new(expires_at),
        }
    }

    #[test]
    fn legacy_bootstrap_keeps_the_exact_one_zero_zero_shape() {
        let config = config();
        let sensor = config.sensor().unwrap();
        for delivery in [None, Some(&SensorBootstrapDelivery::Legacy)] {
            let document = bootstrap_document(
                "req_1",
                sensor,
                config.sensor_routes(),
                delivery,
                UnixSeconds::new(100),
            );
            let mut keys = document
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            keys.sort();
            assert_eq!(
                keys,
                [
                    "build_ref",
                    "heartbeat_seconds",
                    "navigation_id",
                    "page_handle",
                    "prepare_url",
                    "request_id",
                    "sensor_version"
                ]
            );
            assert_eq!(document["sensor_version"], "1.0.0");
        }
    }

    #[test]
    fn page_bootstrap_carries_live_references_and_routing_hints_only() {
        let config = config();
        let delivery = SensorBootstrapDelivery::Page {
            page_handle: PAGE.to_owned(),
            actions: vec![action("action.live", 160), action("action.expired", 100)],
        };
        let document = bootstrap_document(
            "req_1",
            config.sensor().unwrap(),
            config.sensor_routes(),
            Some(&delivery),
            UnixSeconds::new(100),
        );
        assert_eq!(document["sensor_version"], "1.1.0");
        assert_eq!(document["page_handle"], PAGE);
        assert_eq!(
            document["actions"],
            json!([{"action_ref": "action.live", "method": "GET", "path_template": "/orders",
                    "expires_in_seconds": 60}])
        );
        assert_eq!(
            document["harvest"],
            json!([{"source": {"method": "GET", "path": "/orders"},
                    "items_pointer": "/orders", "resource_pointer": "/id",
                    "ref_field": "_xshield_action_ref",
                    "target": {"method": "GET", "prefix": "/orders/"},
                    "ttl_seconds": 900, "max_items": 10}])
        );
        assert_eq!(
            document["invalidate"],
            json!([{"method": "POST", "path": "/api/logout"}])
        );
    }

    #[test]
    fn served_sensor_versions_are_pinned_and_frozen() {
        // Every served version path is immutable and SRI-pinned by pages that
        // were delivered with it; any edit must ship as a new version path.
        assert_eq!(
            openssl::sha::sha256(SensorScript::LEGACY.bytes),
            hex32("60dac1e039186a9ae1519c7399d871b1446dd49748a30a9688f9a54ab2288df7")
        );
        assert_eq!(
            openssl::sha::sha256(SensorScript::LEGACY_LOADER.bytes),
            hex32("7e4b2c44e3cff6c7f1c1b15e51f62c8066ae9ef5164fd69693488262e6ff2950")
        );
        assert_eq!(
            openssl::sha::sha256(SensorScript::CURRENT.bytes),
            hex32("31b0537aa333d79e77ed3237a813e78d13fc44dd0048b0acbe49af17fcdacd1f")
        );
        assert_eq!(
            openssl::sha::sha256(SensorScript::LOADER.bytes),
            hex32("bd869b6aab0a506c50a72427c4efc8c9f8fc75c4d6d59597963bd204432e26db")
        );
        assert_eq!(SensorScript::LEGACY.version, "1.0.0");
        assert_eq!(SensorScript::CURRENT.version, "1.1.0");
        assert_ne!(SensorScript::CURRENT.bytes, SensorScript::LEGACY.bytes);
    }

    fn hex32(value: &str) -> [u8; 32] {
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        bytes
    }
}
