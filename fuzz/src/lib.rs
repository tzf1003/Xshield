//! Fuzz targets for the parsers that read bytes from outside the trust
//! boundary (feasibility P1 item 8, docs/20 "Fuzz").
//!
//! Each target is a plain function from bytes to nothing that panics only
//! when the parser breaks its own contract: it must never panic on any input,
//! and every value it accepts must satisfy the invariant stated on the
//! target. The same functions run in two places:
//!
//! - `fuzz_targets/*.rs`, coverage-guided under libFuzzer (`cargo fuzz`), on
//!   a schedule and on demand (`.github/workflows/fuzz.yml`);
//! - `tests/replay.rs`, on the stable toolchain in every CI run, over the
//!   checked-in seeds and a fixed number of deterministic mutations of them.
//!
//! A crash libFuzzer finds is minimized, added under `seeds/<target>/`, and
//! from then on replayed by every CI run.

// Every target panics, by design, exactly when its contract breaks; that is
// stated once here instead of on each function.
#![allow(clippy::missing_panics_doc)]

use pingora::http::RequestHeader;
use serde_json::{Value, json};
use std::sync::OnceLock;
use xshield_audit::{SealVerifyingKey, SignedSegmentManifest};
use xshield_core::{
    audit::ReasonCode,
    identity::UnixSeconds,
    path_shape::{PATH_SHAPE_BYTES_MAX, path_shape as shape, valid_path_shape},
    site::{
        build::fingerprint,
        config::SiteConfig,
        find_unsupported_edge_feature,
        upstream::{UpstreamAllowance, parse_upstream_socket},
    },
};
use xshield_gateway::{
    ACCEPTED_SENSOR_VERSIONS, GatewayConfig, QueryAdmission,
    multi_site::{frozen_origin_target, routing_authority},
    proxy_protocol::{
        HeaderParse, MAX_HEADER_BYTES, V1_MAX_HEADER_BYTES, V2_MAX_HEADER_BYTES, parse_header,
    },
    request_crypto::{KeyAccessPort, KeyAccessQuery},
    response_grant::validate_strict_json,
    sensor::SensorObservationBatch,
};
use zeroize::Zeroizing;

/// One fuzz target: panics only when the parser breaks its contract.
pub type Target = fn(&[u8]);

/// Every target, by the name of its `fuzz_targets/<name>.rs` and
/// `seeds/<name>/` directory.
pub const TARGETS: &[(&str, Target)] = &[
    ("proxy_header", proxy_header),
    ("path_shape", path_shape),
    ("route_admission", route_admission),
    ("query_pagination", query_pagination),
    ("routing_authority", authority),
    ("request_crypto", request_crypto),
    ("auth_binding", auth_binding),
    ("strict_json", strict_json),
    ("sensor_batch", sensor_batch),
    ("site_config", site_config),
    ("page_fingerprint", page_fingerprint),
    ("upstream_address", upstream_address),
    ("seal_manifest", seal_manifest),
];

const BUILD_REF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SEAL_PUBLIC_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// Splits an input into at most `N` text fields at newlines; the last field
/// keeps any further newlines. Invalid UTF-8 is replaced, so every field is
/// text the HTTP layer could have handed over after its own decoding.
fn fields<const N: usize>(data: &[u8]) -> [String; N] {
    let mut out = std::array::from_fn(|_| String::new());
    let mut rest = data;
    for (index, slot) in out.iter_mut().enumerate() {
        let end = if index + 1 == N {
            rest.len()
        } else {
            rest.iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(rest.len())
        };
        *slot = String::from_utf8_lossy(&rest[..end]).into_owned();
        rest = rest.get(end + 1..).unwrap_or_default();
    }
    out
}

/// One edge configuration with a route of every kind the targets reach: a
/// literal and a templated path, query pagination, a request-crypto route
/// and an authentication entry. It is the shape `examples/gateway-config.json`
/// uses; only parsing is exercised, nothing is opened or bound.
pub fn gateway() -> &'static GatewayConfig {
    static CONFIG: OnceLock<GatewayConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let config = json!({
            "listen": "127.0.0.1:6188",
            "origin": {"address": "127.0.0.1:8080", "server_name": "origin.example", "tls": false},
            "tenant_id": "tenant_demo", "site_id": "site_demo", "policy_revision": "policy-r1",
            "audit": {"directory": "target/xshield-fuzz", "key_id": "journal-key-r1",
                "producer_id": "edge-fuzz", "max_bytes": 1_048_576,
                "high_watermark_bytes": 786_432, "segment_max_bytes": 262_144},
            "identity_store": {"max_connections": 4, "acquire_timeout_ms": 1_000},
            "operations": [
                {"operation_id": "health.read", "method": "GET", "path": "/health",
                 "admission": "PUBLIC", "source_action": null, "resource_type": null,
                 "view_profile": null},
                {"operation_id": "orders.path.read", "method": "GET",
                 "path": "/path-orders/{order_id}", "admission": "UI_ACTION_REQUIRED",
                 "source_action": "orders.path.open", "resource_type": "order",
                 "view_profile": "customer_detail", "resource_path_parameter": "order_id"},
                {"operation_id": "orders.list", "method": "GET", "path": "/orders",
                 "admission": "UI_ACTION_REQUIRED", "source_action": "orders.list",
                 "resource_type": null, "view_profile": null,
                 "query_pagination": {"parameters": [
                     {"name": "page", "kind": "page"},
                     {"name": "page_size", "kind": "page_size", "max_value": 50}]}},
                {"operation_id": "orders.create", "method": "POST", "path": "/orders/create",
                 "admission": "AUTHENTICATED_ROOT", "source_action": null,
                 "resource_type": null, "view_profile": null,
                 "request_crypto": {"mode": "DIRECT_DECRYPT",
                     "adapter_revision": "orders-create-json-r1", "key_id": "request-key-r1",
                     "key_not_before": 1, "key_expires_at": 4_102_444_800_u64,
                     "max_envelope_bytes": 65_536, "max_plaintext_bytes": 16_384,
                     "max_message_age_seconds": 60, "max_future_skew_seconds": 5,
                     "max_active_messages": 100_000}},
                {"operation_id": "auth.login", "method": "POST", "path": "/login",
                 "admission": "AUTH_ENTRY", "source_action": null, "resource_type": null,
                 "view_profile": null,
                 "response": {"mode": "BUFFERED_JSON", "max_bytes": 4_096,
                     "auth_binding": {"success_status": 200,
                         "principal_pointer": "/identity/id",
                         "authorization_context_pointer": "/identity/authorization_context",
                         "bearer_pointer": "/access_token",
                         "credential_ttl_seconds": 900, "session_ttl_seconds": 3_600}}}
            ]
        });
        let bytes = serde_json::to_vec(&config).expect("fixture serializes");
        GatewayConfig::from_json(&bytes).expect("fuzz fixture is a valid edge configuration")
    })
}

/// PROXY protocol v1/v2 from a trusted balancer.
///
/// A complete header never claims more bytes than it was given or than its
/// version allows; the header alone parses to the same result; and every
/// strict prefix of it is `Incomplete`, so a reader never stops early.
pub fn proxy_header(data: &[u8]) {
    let Ok(HeaderParse::Complete { length, client }) = parse_header(data) else {
        return;
    };
    assert!(length <= data.len() && length <= MAX_HEADER_BYTES);
    let limit = if data[0] == b'P' {
        V1_MAX_HEADER_BYTES
    } else {
        V2_MAX_HEADER_BYTES
    };
    assert!(length <= limit);
    assert_eq!(
        parse_header(&data[..length]),
        Ok(HeaderParse::Complete { length, client })
    );
    for end in 0..length {
        assert_eq!(parse_header(&data[..end]), Ok(HeaderParse::Incomplete));
    }
}

/// The audit shape of an unrouted path: always a valid, bounded shape, and
/// never a copy of a segment that could carry an identifier.
pub fn path_shape(data: &[u8]) {
    let path = String::from_utf8_lossy(data);
    let result = shape(&path);
    assert!(valid_path_shape(&result), "{result:?}");
    assert!(result.len() <= PATH_SHAPE_BYTES_MAX);
}

/// Route matching on method and path.
///
/// Admission and the admission class agree on whether a route matched, and
/// an unmatched request is always refused as `OPERATION_NOT_MATCHED`.
pub fn route_admission(data: &[u8]) {
    let [method, path] = fields::<2>(data);
    let config = gateway();
    let decision = config.admit(&method, &path, UnixSeconds::new(1_000));
    assert_eq!(
        decision.operation_id.is_some(),
        config.admission_class(&method, &path).is_some()
    );
    if decision.operation_id.is_none() {
        assert_eq!(decision.reason_code, ReasonCode::OperationNotMatched);
    }
    let _ = config.resource_operation(&method, &path);
}

/// Query pagination: a forwarded query is rebuilt, never the raw one, and it
/// is a fixed point: admitting it again forwards exactly the same text.
pub fn query_pagination(data: &[u8]) {
    let query = String::from_utf8_lossy(data);
    let config = gateway();
    if let QueryAdmission::Forward(frozen) =
        config.admit_query_string("GET", "/orders", Some(&query))
    {
        let Some(canonical) = frozen.as_deref() else {
            return;
        };
        assert!(
            canonical
                .split('&')
                .all(|pair| { pair.starts_with("page=") || pair.starts_with("page_size=") })
        );
        match config.admit_query_string("GET", "/orders", Some(canonical)) {
            QueryAdmission::Forward(again) => assert_eq!(again.as_deref(), Some(canonical)),
            other => panic!("canonical query {canonical:?} not readmitted: {other:?}"),
        }
        assert!(frozen_origin_target("/orders", Some(canonical)).is_some());
    }
}

/// `Host` and request-target authority: the routing name is one the client
/// sent, in `Host` or in the target, and an origin-form target never carries a scheme
/// or authority.
pub fn authority(data: &[u8]) {
    let [target, host, second_host] = fields::<3>(data);
    let Ok(mut request) = RequestHeader::build("GET", target.as_bytes(), None) else {
        return;
    };
    if !host.is_empty() && request.append_header("host", host.as_str()).is_err() {
        return;
    }
    if !second_host.is_empty() && request.append_header("host", second_host.as_str()).is_err() {
        return;
    }
    if let Ok(Some(name)) = routing_authority(&request) {
        // The target's authority is either the parsed URI's (HTTP/2) or a
        // slice of the raw absolute-form target (HTTP/1).
        assert!(
            name == host || name == second_host || target.contains(name),
            "{name:?}"
        );
        assert!(second_host.is_empty() || host.is_empty());
    }
    let path = request.uri.path().to_owned();
    if let Some(uri) = frozen_origin_target(&path, request.uri.query()) {
        assert!(uri.scheme().is_none() && uri.authority().is_none());
        assert_eq!(uri.path(), path);
    }
}

struct FixedKey;

impl KeyAccessPort for FixedKey {
    fn request_decryption_key(
        &self,
        _query: KeyAccessQuery<'_>,
    ) -> Result<Zeroizing<[u8; 32]>, ReasonCode> {
        Ok(Zeroizing::new([7; 32]))
    }
}

/// A browser-encrypted request envelope. Without the client key no envelope
/// authenticates, so every input must be refused, by a stable reason and
/// without a panic in the envelope parser.
pub fn request_crypto(data: &[u8]) {
    let rule = gateway()
        .request_crypto_rule("POST", "/orders/create")
        .expect("fixture has a request-crypto route");
    let result = rule.decode(
        "tenant_demo",
        "site_demo",
        "orders.create",
        "POST",
        "/orders/create",
        UnixSeconds::new(1_000_000),
        data,
        &FixedKey,
    );
    if let Ok(frozen) = result {
        assert!(frozen.body_len() <= 16_384);
        assert!(serde_json::from_slice::<Value>(&frozen.into_body()).is_ok());
    }
}

/// The origin's login response, from which the edge binds a session.
pub fn auth_binding(data: &[u8]) {
    let rule = gateway()
        .auth_binding_rule("POST", "/login")
        .expect("fixture has an authentication entry");
    let _ = rule.extract(data);
}

/// Strict JSON for buffered responses: anything it accepts is ordinary JSON.
pub fn strict_json(data: &[u8]) {
    if validate_strict_json(data).is_ok() {
        assert!(serde_json::from_slice::<Value>(data).is_ok());
    }
}

/// A sensor observation batch posted by the page.
///
/// An accepted batch is non-empty, at most 16 events, one sensor version,
/// and its events are consecutive in client sequence.
pub fn sensor_batch(data: &[u8]) {
    let Ok(batch) = SensorObservationBatch::from_json(data, &ACCEPTED_SENSOR_VERSIONS, BUILD_REF)
    else {
        return;
    };
    let observations = batch.observations();
    assert!((1..=16).contains(&observations.len()));
    for pair in observations.windows(2) {
        assert_eq!(
            u64::from(pair[0].client_event_seq()) + 1,
            u64::from(pair[1].client_event_seq())
        );
    }
}

/// A site configuration as the control API receives it: typed parse, then
/// validation, then the classification of refused bodies.
pub fn site_config(data: &[u8]) {
    if let Ok(config) = serde_json::from_slice::<SiteConfig>(data) {
        let _ = config.validate();
    } else {
        let _ = find_unsupported_edge_feature(data);
    }
}

/// A frontend build's page: the injection offset points at the first
/// lowercase `</head>` inside the page.
pub fn page_fingerprint(data: &[u8]) {
    if let Ok(build) = fingerprint(data) {
        assert_eq!(build.bytes, data.len());
        assert_eq!(
            data.get(build.injection_offset..build.injection_offset + 7),
            Some(&b"</head>"[..])
        );
        assert_eq!(build.origin_sha256.len(), 64);
    }
}

/// Upstream socket addresses and the private-network allowance list.
pub fn upstream_address(data: &[u8]) {
    let [address, allowance] = fields::<2>(data);
    let _ = parse_upstream_socket(&address);
    let _ = UpstreamAllowance::parse_admitted(&allowance);
}

/// A segment manifest read back from the object store. Arbitrary bytes are
/// never a valid signature under a fixed key.
pub fn seal_manifest(data: &[u8]) {
    static KEY: OnceLock<SealVerifyingKey> = OnceLock::new();
    let key = KEY.get_or_init(|| {
        SealVerifyingKey::from_hex("seal-key-r1", SEAL_PUBLIC_KEY).expect("valid Ed25519 key")
    });
    assert!(SignedSegmentManifest::verify(data, key).is_err());
}
