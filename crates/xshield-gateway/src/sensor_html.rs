//! Exact-build browser sensor HTML injection.
//!
//! Sensor 1.1.0 is injected as two classic synchronous scripts at the pinned
//! `</head>` offset: the sensor first, so its fetch/XHR hooks exist before any
//! later script of the document runs, then the loader, whose tag carries the
//! per-delivery page handle. The handle is not a credential: the bootstrap
//! returns references for it only to the session that owns the page, and the
//! entity is released `private, no-store`.

use openssl::{
    base64::encode_block,
    sha::{sha256, sha384},
};
use std::sync::LazyLock;
use uuid::{Uuid, Version};

const SENSOR_SCRIPT: &str = "<script src=\"/__xshield/v1/sensor/1.1.0.js\"";
const LOADER_SCRIPT: &str = "<script src=\"/__xshield/v1/sensor/1.1.0-loader.js\"";
const SCRIPT_END: &str = "></script>";
const NONCE_ATTRIBUTE_OVERHEAD: usize = " nonce=\"\"".len();
const NONCE_BYTES: usize = 32;
const INTEGRITY_ATTRIBUTE_OVERHEAD: usize = " integrity=\"\"".len();
const SHA384_INTEGRITY_BYTES: usize = "sha384-".len() + 64;
const PAGE_ATTRIBUTE_OVERHEAD: usize = " data-xshield-page=\"\"".len();
const PAGE_HANDLE_BYTES: usize = "pgh_".len() + 36;
static SENSOR_INTEGRITY: LazyLock<String> = LazyLock::new(|| sri_sha384(crate::SENSOR_ASSET_BYTES));
static LOADER_INTEGRITY: LazyLock<String> =
    LazyLock::new(|| sri_sha384(crate::SENSOR_LOADER_BYTES));
const MAX_INJECTION_BYTES: usize = SENSOR_SCRIPT.len()
    + LOADER_SCRIPT.len()
    + SCRIPT_END.len() * 2
    + (INTEGRITY_ATTRIBUTE_OVERHEAD + SHA384_INTEGRITY_BYTES) * 2
    + (NONCE_ATTRIBUTE_OVERHEAD + NONCE_BYTES) * 2
    + PAGE_ATTRIBUTE_OVERHEAD
    + PAGE_HANDLE_BYTES;

/// Exact static HTML adapter approved by trusted configuration.
#[derive(Clone, Debug)]
pub struct SensorHtmlRule {
    max_bytes: usize,
    adapters: Vec<SensorHtmlAdapter>,
}

#[derive(Clone, Debug)]
struct SensorHtmlAdapter {
    revision: String,
    origin_sha256: String,
    injection_offset: usize,
}

impl SensorHtmlRule {
    pub(crate) fn new(max_bytes: usize, adapters: Vec<(String, String, usize)>) -> Self {
        Self {
            max_bytes,
            adapters: adapters
                .into_iter()
                .map(
                    |(revision, origin_sha256, injection_offset)| SensorHtmlAdapter {
                        revision,
                        origin_sha256,
                        injection_offset,
                    },
                )
                .collect(),
        }
    }

    /// Returns the maximum accepted source HTML size.
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Returns the maximum memory held while source and rewritten entities overlap.
    #[must_use]
    pub fn max_in_flight_bytes(&self) -> Option<usize> {
        self.max_bytes
            .checked_mul(2)?
            .checked_add(MAX_INJECTION_BYTES)
    }

    /// Injects versioned same-origin scripts into the approved HTML entity.
    ///
    /// # Errors
    /// Returns [`SensorHtmlError`] when the entity differs from the approved
    /// digest, the configured insertion point is not a UTF-8 `</head>` tag, or
    /// the page handle is not an edge-generated `pgh_` `UUIDv7`.
    pub fn inject(
        &self,
        source: &[u8],
        nonce: Option<&str>,
        page_handle: &str,
    ) -> Result<InjectedSensorHtml, SensorHtmlError> {
        if source.len() > self.max_bytes
            || std::str::from_utf8(source).is_err()
            || !valid_page_handle(page_handle)
        {
            return Err(SensorHtmlError);
        }
        let origin_sha256 = encode_hex(sha256(source));
        let adapter = self
            .adapters
            .iter()
            .find(|adapter| adapter.origin_sha256 == origin_sha256)
            .ok_or(SensorHtmlError)?;
        if source.get(adapter.injection_offset..adapter.injection_offset + 7) != Some(b"</head>") {
            return Err(SensorHtmlError);
        }
        let injection = build_injection(nonce, page_handle)?;
        let capacity = source
            .len()
            .checked_add(injection.len())
            .ok_or(SensorHtmlError)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(capacity)
            .map_err(|_| SensorHtmlError)?;
        output.extend_from_slice(&source[..adapter.injection_offset]);
        output.extend_from_slice(injection.as_bytes());
        output.extend_from_slice(&source[adapter.injection_offset..]);
        let injected_sha256 = encode_hex(sha256(&output));
        Ok(InjectedSensorHtml {
            body: output,
            adapter_revision: adapter.revision.clone(),
            origin_sha256,
            injected_sha256,
        })
    }
}

fn valid_page_handle(value: &str) -> bool {
    value.len() == PAGE_HANDLE_BYTES
        && value
            .strip_prefix("pgh_")
            .and_then(|uuid| Uuid::parse_str(uuid).ok())
            .is_some_and(|uuid| {
                uuid.get_version() == Some(Version::SortRand)
                    && uuid.hyphenated().to_string() == value[4..]
            })
}

fn build_injection(nonce: Option<&str>, page_handle: &str) -> Result<String, SensorHtmlError> {
    if nonce.is_some_and(|value| {
        value.len() != NONCE_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) || !valid_page_handle(page_handle)
    {
        return Err(SensorHtmlError);
    }
    let nonce_bytes = nonce.map_or(0, str::len);
    let capacity = SENSOR_SCRIPT.len()
        + LOADER_SCRIPT.len()
        + SCRIPT_END.len() * 2
        + (INTEGRITY_ATTRIBUTE_OVERHEAD + SHA384_INTEGRITY_BYTES) * 2
        + (nonce_bytes + NONCE_ATTRIBUTE_OVERHEAD) * usize::from(nonce.is_some()) * 2
        + PAGE_ATTRIBUTE_OVERHEAD
        + page_handle.len();
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| SensorHtmlError)?;
    for (script, integrity, page) in [
        (SENSOR_SCRIPT, SENSOR_INTEGRITY.as_str(), None),
        (LOADER_SCRIPT, LOADER_INTEGRITY.as_str(), Some(page_handle)),
    ] {
        output.push_str(script);
        output.push_str(" integrity=\"");
        output.push_str(integrity);
        output.push('"');
        if let Some(nonce) = nonce {
            output.push_str(" nonce=\"");
            output.push_str(nonce);
            output.push('"');
        }
        if let Some(page) = page {
            output.push_str(" data-xshield-page=\"");
            output.push_str(page);
            output.push('"');
        }
        output.push_str(SCRIPT_END);
    }
    Ok(output)
}

fn sri_sha384(bytes: &[u8]) -> String {
    format!("sha384-{}", encode_block(&sha384(bytes)))
}

/// Rewritten HTML entity and its audit digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InjectedSensorHtml {
    body: Vec<u8>,
    adapter_revision: String,
    origin_sha256: String,
    injected_sha256: String,
}

impl InjectedSensorHtml {
    /// Consumes the result and returns the rewritten entity.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Returns the rewritten entity SHA-256 digest.
    #[must_use]
    pub fn injected_sha256(&self) -> &str {
        &self.injected_sha256
    }

    /// Returns the selected adapter revision.
    #[must_use]
    pub fn adapter_revision(&self) -> &str {
        &self.adapter_revision
    }

    /// Returns the verified source entity SHA-256 digest.
    #[must_use]
    pub fn origin_sha256(&self) -> &str {
        &self.origin_sha256
    }
}

/// Exact HTML injection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SensorHtmlError;

fn encode_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "pgh_018f2a3b-4c5d-7000-8000-000000000001";

    #[test]
    fn injects_only_the_exact_approved_html() {
        assert!(SENSOR_SCRIPT.contains(crate::SENSOR_ASSET_PATH));
        assert!(LOADER_SCRIPT.contains(crate::SENSOR_LOADER_PATH));
        let source = b"<!doctype html><html><head></head><body>ok</body></html>";
        let alternate = b"<!doctype html><head></head>";
        let rule = SensorHtmlRule::new(
            256,
            vec![
                ("home-r1".to_owned(), encode_hex(sha256(source)), 27),
                ("home-r2".to_owned(), encode_hex(sha256(alternate)), 21),
            ],
        );
        let result = rule.inject(source, None, PAGE).unwrap();
        assert_eq!(result.adapter_revision(), "home-r1");
        let injected = result.into_body();
        assert!(
            injected
                .windows(SENSOR_SCRIPT.len())
                .any(|part| part == SENSOR_SCRIPT.as_bytes())
        );
        let injected = std::str::from_utf8(&injected).unwrap();
        assert!(injected.contains(&format!("integrity=\"{}\"", *SENSOR_INTEGRITY)));
        assert!(injected.contains(&format!("integrity=\"{}\"", *LOADER_INTEGRITY)));
        assert_eq!(
            rule.inject(alternate, Some("0123456789abcdef0123456789abcdef"), PAGE)
                .unwrap()
                .adapter_revision(),
            "home-r2"
        );
        assert!(
            rule.inject(b"<!doctype html><html></html>", None, PAGE)
                .is_err()
        );
    }

    #[test]
    fn injects_synchronous_sensor_before_the_page_bound_loader() {
        let source = b"<!doctype html><html><head></head><body>ok</body></html>";
        let rule = SensorHtmlRule::new(
            256,
            vec![("home-r1".to_owned(), encode_hex(sha256(source)), 27)],
        );
        let nonce = "0123456789abcdef0123456789abcdef";
        let injected =
            String::from_utf8(rule.inject(source, Some(nonce), PAGE).unwrap().into_body()).unwrap();
        let sensor = injected.find(SENSOR_SCRIPT).unwrap();
        let loader = injected.find(LOADER_SCRIPT).unwrap();
        // Hooks must exist before any later script runs: no defer/async.
        assert!(sensor < loader && !injected.contains("defer") && !injected.contains("async"));
        assert_eq!(injected.matches("data-xshield-page").count(), 1);
        assert!(injected[loader..].contains(&format!("data-xshield-page=\"{PAGE}\"")));
        assert_eq!(injected.matches(&format!("nonce=\"{nonce}\"")).count(), 2);
        assert!(injected.len() - source.len() <= MAX_INJECTION_BYTES);
        // A forged, non-v7 or attribute-breaking handle never reaches the HTML.
        for handle in [
            "pgh_018f2a3b-4c5d-4000-8000-000000000001",
            "pgh_018F2A3B-4C5D-7000-8000-000000000001",
            "pgh_018f2a3b4c5d70008000000000000001",
            "pgh_\"><script>alert(1)</script>",
            "",
        ] {
            assert!(rule.inject(source, None, handle).is_err(), "{handle}");
        }
    }
}
