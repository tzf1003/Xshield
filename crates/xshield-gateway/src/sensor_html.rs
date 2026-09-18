//! Exact-build browser sensor HTML injection.

use openssl::sha::sha256;

const INJECTION: &str = "<script defer src=\"/__xshield/v1/sensor/1.0.0.js\"></script><script defer src=\"/__xshield/v1/sensor/1.0.0-loader.js\"></script>";

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
        self.max_bytes.checked_mul(2)?.checked_add(INJECTION.len())
    }

    /// Injects versioned same-origin scripts into the approved HTML entity.
    ///
    /// # Errors
    /// Returns [`SensorHtmlError`] when the entity differs from the approved
    /// digest or the configured insertion point is not a UTF-8 `</head>` tag.
    pub fn inject(&self, source: &[u8]) -> Result<InjectedSensorHtml, SensorHtmlError> {
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
        let capacity = source
            .len()
            .checked_add(INJECTION.len())
            .ok_or(SensorHtmlError)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(capacity)
            .map_err(|_| SensorHtmlError)?;
        output.extend_from_slice(&source[..adapter.injection_offset]);
        output.extend_from_slice(INJECTION.as_bytes());
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
        assert!(INJECTION.contains(crate::SENSOR_ASSET_PATH));
        assert!(INJECTION.contains(crate::SENSOR_LOADER_PATH));
        let source = b"<!doctype html><html><head></head><body>ok</body></html>";
        let alternate = b"<!doctype html><head></head>";
        let rule = SensorHtmlRule::new(
            128,
            vec![
                ("home-r1".to_owned(), encode_hex(sha256(source)), 27),
                ("home-r2".to_owned(), encode_hex(sha256(alternate)), 21),
            ],
        );
        let result = rule.inject(source).unwrap();
        assert_eq!(result.adapter_revision(), "home-r1");
        let injected = result.into_body();
        assert_eq!(&injected[27..27 + INJECTION.len()], INJECTION.as_bytes());
        assert_eq!(
            rule.inject(alternate).unwrap().adapter_revision(),
            "home-r2"
        );
        assert!(rule.inject(b"<!doctype html><html></html>").is_err());
    }
}
