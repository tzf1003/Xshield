//! Exact-build browser sensor HTML injection.

use openssl::{
    base64::encode_block,
    sha::{sha256, sha384},
};
use std::sync::LazyLock;

const SENSOR_SCRIPT: &str = "<script defer src=\"/__xshield/v1/sensor/1.0.0.js\"";
const LOADER_SCRIPT: &str = "<script defer src=\"/__xshield/v1/sensor/1.0.0-loader.js\"";
const SCRIPT_END: &str = "></script>";
const NONCE_ATTRIBUTE_OVERHEAD: usize = " nonce=\"\"".len();
const NONCE_BYTES: usize = 32;
const INTEGRITY_ATTRIBUTE_OVERHEAD: usize = " integrity=\"\"".len();
const SHA384_INTEGRITY_BYTES: usize = "sha384-".len() + 64;
static SENSOR_INTEGRITY: LazyLock<String> = LazyLock::new(|| sri_sha384(crate::SENSOR_ASSET_BYTES));
static LOADER_INTEGRITY: LazyLock<String> =
    LazyLock::new(|| sri_sha384(crate::SENSOR_LOADER_BYTES));
const MAX_INJECTION_BYTES: usize = SENSOR_SCRIPT.len()
    + LOADER_SCRIPT.len()
    + SCRIPT_END.len() * 2
    + (INTEGRITY_ATTRIBUTE_OVERHEAD + SHA384_INTEGRITY_BYTES) * 2
    + (NONCE_ATTRIBUTE_OVERHEAD + NONCE_BYTES) * 2;

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
    /// digest or the configured insertion point is not a UTF-8 `</head>` tag.
    pub fn inject(
        &self,
        source: &[u8],
        nonce: Option<&str>,
    ) -> Result<InjectedSensorHtml, SensorHtmlError> {
        if source.len() > self.max_bytes || std::str::from_utf8(source).is_err() {
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
        let injection = build_injection(nonce)?;
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

fn build_injection(nonce: Option<&str>) -> Result<String, SensorHtmlError> {
    if nonce.is_some_and(|value| {
        value.len() != NONCE_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) {
        return Err(SensorHtmlError);
    }
    let nonce_bytes = nonce.map_or(0, str::len);
    let capacity = SENSOR_SCRIPT.len()
        + LOADER_SCRIPT.len()
        + SCRIPT_END.len() * 2
        + (INTEGRITY_ATTRIBUTE_OVERHEAD + SHA384_INTEGRITY_BYTES) * 2
        + (nonce_bytes + NONCE_ATTRIBUTE_OVERHEAD) * usize::from(nonce.is_some()) * 2;
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| SensorHtmlError)?;
    for (script, integrity) in [
        (SENSOR_SCRIPT, SENSOR_INTEGRITY.as_str()),
        (LOADER_SCRIPT, LOADER_INTEGRITY.as_str()),
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

    #[test]
    fn injects_only_the_exact_approved_html() {
        assert!(SENSOR_SCRIPT.contains(crate::SENSOR_ASSET_PATH));
        assert!(LOADER_SCRIPT.contains(crate::SENSOR_LOADER_PATH));
        let source = b"<!doctype html><html><head></head><body>ok</body></html>";
        let alternate = b"<!doctype html><head></head>";
        let rule = SensorHtmlRule::new(
            128,
            vec![
                ("home-r1".to_owned(), encode_hex(sha256(source)), 27),
                ("home-r2".to_owned(), encode_hex(sha256(alternate)), 21),
            ],
        );
        let result = rule.inject(source, None).unwrap();
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
            rule.inject(alternate, Some("0123456789abcdef0123456789abcdef"))
                .unwrap()
                .adapter_revision(),
            "home-r2"
        );
        assert!(rule.inject(b"<!doctype html><html></html>", None).is_err());
    }
}
