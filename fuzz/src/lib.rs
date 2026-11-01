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

use std::sync::OnceLock;
use xshield_audit::{SealVerifyingKey, SignedSegmentManifest};
use xshield_core::{
    path_shape::{PATH_SHAPE_BYTES_MAX, path_shape as shape, valid_path_shape},
    site::{
        build::fingerprint,
        config::SiteConfig,
        find_unsupported_edge_feature,
        upstream::{UpstreamAllowance, parse_upstream_socket},
    },
};

/// One fuzz target: panics only when the parser breaks its contract.
pub type Target = fn(&[u8]);

/// Every target, by the name of its `fuzz_targets/<name>.rs` and
/// `seeds/<name>/` directory.
///
/// `xshield-gateway` was deleted (docs/05-v3-removal.md); the targets that
/// exercised its parsers (`proxy_header`, `route_admission`,
/// `query_pagination`, `routing_authority`, `request_crypto`,
/// `auth_binding`, `strict_json`, `sensor_batch`) went with it. The ones
/// left here only exercise `xshield-core` and `xshield-audit` parsers,
/// which are unaffected.
pub const TARGETS: &[(&str, Target)] = &[
    ("path_shape", path_shape),
    ("site_config", site_config),
    ("page_fingerprint", page_fingerprint),
    ("upstream_address", upstream_address),
    ("seal_manifest", seal_manifest),
];

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

/// The audit shape of an unrouted path: always a valid, bounded shape, and
/// never a copy of a segment that could carry an identifier.
pub fn path_shape(data: &[u8]) {
    let path = String::from_utf8_lossy(data);
    let result = shape(&path);
    assert!(valid_path_shape(&result), "{result:?}");
    assert!(result.len() <= PATH_SHAPE_BYTES_MAX);
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
