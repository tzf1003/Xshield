//! The example bootstrap configuration `dev.sh` copies must give the edge an
//! identity runtime. The edge builds it from the bootstrap file (never from an
//! apply snapshot), so a file without an identity store or without a protected
//! route leaves every protected site delivered by apply unservable. This test
//! pins the shape; it cannot start the Docker stack `dev.sh` drives.

use serde_json::Value;
use xshield_gateway::GatewayConfig;

const BOOTSTRAP: &str = include_str!("../../../examples/gateway-bootstrap-config.json");
const REFERENCE: &str = include_str!("../../../examples/gateway-config.json");

#[test]
fn the_dev_bootstrap_config_gives_the_edge_an_identity_runtime() {
    let config = GatewayConfig::from_json(BOOTSTRAP.as_bytes()).unwrap();
    assert!(config.identity_store().is_some());
    let document: Value = serde_json::from_str(BOOTSTRAP).unwrap();
    let operations = document["operations"].as_array().unwrap();
    // One placeholder that is never served: bootstrap-only mode routes nothing.
    assert!(
        operations
            .iter()
            .any(|operation| operation["admission"] == "AUTHENTICATED_ROOT")
    );
}

/// The reference configuration docs/18 points readers at must keep parsing
/// and keep demonstrating a business WebSocket route (docs/22 M2's "无 WSS"
/// gap): a doc example that silently bit-rots teaches the wrong shape.
#[test]
fn the_reference_config_parses_and_demonstrates_a_business_websocket_route() {
    let config = GatewayConfig::from_json(REFERENCE.as_bytes()).unwrap();
    let policy = config
        .business_websocket_policy("GET", "/ws/chat")
        .expect("reference config documents a business websocket route");
    assert_eq!(policy.adapter_revision(), "chat-ws-r1");
    assert!(config.buffered_response_policy("GET", "/ws/chat").is_none());
}
