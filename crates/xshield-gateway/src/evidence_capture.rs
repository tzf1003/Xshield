//! Versioned JSON evidence capture and mandatory secret exclusion.
//!
//! This adapter transforms only the evidence copy. The original response stays
//! unchanged for identity/grant validation and client delivery. Its encrypted
//! representation includes an inline exclusion manifest, never excluded values.

use crate::{ConfigError, response_grant::strict_json, valid_json_pointer, valid_scoped_value};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use xshield_core::audit::ReasonCode;
use zeroize::Zeroizing;

const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
const MAX_SECRET_POINTERS: usize = 64;
const MAX_REDACTIONS: usize = 1024;
const MAX_POINTER_BYTES: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceCaptureDto {
    pub(crate) profile_revision: String,
    pub(crate) max_bytes: usize,
    pub(crate) retention_seconds: u32,
    pub(crate) secret_pointers: Vec<String>,
}

/// Trusted, bounded JSON capture policy compiled with its operation.
#[derive(Debug)]
pub struct EvidenceCaptureRule {
    profile_revision: String,
    max_bytes: usize,
    retention_seconds: u32,
    secret_pointers: BTreeSet<String>,
}

impl EvidenceCaptureRule {
    pub(crate) fn compile(
        dto: EvidenceCaptureDto,
        bearer_pointer: Option<&str>,
    ) -> Result<Self, ConfigError> {
        if !valid_scoped_value(&dto.profile_revision)
            || !(1..=MAX_CAPTURE_BYTES).contains(&dto.max_bytes)
            || !(1..=86_400).contains(&dto.retention_seconds)
            || dto.secret_pointers.len() > MAX_SECRET_POINTERS
            || dto.secret_pointers.iter().any(|pointer| {
                pointer.is_empty()
                    || pointer.len() > MAX_POINTER_BYTES
                    || !valid_json_pointer(pointer)
            })
        {
            return Err(ConfigError::Invalid("operations.response.evidence_capture"));
        }
        let mut secret_pointers = dto.secret_pointers.into_iter().collect::<BTreeSet<_>>();
        if let Some(pointer) = bearer_pointer {
            secret_pointers.insert(pointer.to_owned());
        }
        Ok(Self {
            profile_revision: dto.profile_revision,
            max_bytes: dto.max_bytes,
            retention_seconds: dto.retention_seconds,
            secret_pointers,
        })
    }

    /// Returns the immutable capture/secret-policy revision for audit.
    #[must_use]
    pub fn profile_revision(&self) -> &str {
        &self.profile_revision
    }

    /// Returns the object's retention lease, bounded to one day.
    #[must_use]
    pub const fn retention_seconds(&self) -> u32 {
        self.retention_seconds
    }

    /// Produces a bounded evidence-only JSON document with inline exclusions.
    ///
    /// Duplicate keys, invalid JSON, excess source size, or an oversized
    /// exclusion manifest fail closed. Authentication secrets are always
    /// excluded by reserved field names and the compiled bearer pointer;
    /// additional site secrets use explicit RFC 6901 pointers. HTTP headers
    /// are not accepted by this body adapter.
    ///
    /// # Errors
    /// Returns a stable capture reason; never returns or logs excluded values.
    pub fn capture(&self, body: &[u8]) -> Result<Zeroizing<Vec<u8>>, ReasonCode> {
        if body.len() > self.max_bytes {
            return Err(ReasonCode::EvidenceCaptureLimitExceeded);
        }
        let mut value = strict_json(body).map_err(|_| ReasonCode::EvidenceCaptureInvalid)?;
        let mut exclusions = Vec::new();
        redact(&mut value, "", &self.secret_pointers, &mut exclusions)?;
        let document = CapturedJson {
            schema_version: 1,
            profile_revision: &self.profile_revision,
            source_representation: "application_json",
            source_bytes_observed: body.len(),
            fidelity: "redacted",
            excluded_http_headers: true,
            exclusions,
            value,
        };
        let bytes =
            serde_json::to_vec(&document).map_err(|_| ReasonCode::EvidenceCaptureInvalid)?;
        // The source and exclusion count/path bounds also bound serialization.
        // Reject any unexpectedly expanded representation before vault I/O.
        if bytes.len() > MAX_CAPTURE_BYTES * 4 {
            return Err(ReasonCode::EvidenceCaptureLimitExceeded);
        }
        Ok(Zeroizing::new(bytes))
    }
}

#[derive(Serialize)]
struct CapturedJson<'a> {
    schema_version: u8,
    profile_revision: &'a str,
    source_representation: &'static str,
    source_bytes_observed: usize,
    fidelity: &'static str,
    excluded_http_headers: bool,
    exclusions: Vec<Exclusion>,
    value: Value,
}

#[derive(Serialize)]
struct Exclusion {
    pointer: String,
    reason_code: &'static str,
}

fn redact(
    value: &mut Value,
    pointer: &str,
    configured: &BTreeSet<String>,
    exclusions: &mut Vec<Exclusion>,
) -> Result<(), ReasonCode> {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                let child = child_pointer(pointer, name)?;
                if secret_field(name) || configured.contains(&child) {
                    exclude(value, child, exclusions)?;
                } else {
                    redact(value, &child, configured, exclusions)?;
                }
            }
        }
        Value::Array(items) => {
            for (index, value) in items.iter_mut().enumerate() {
                let child = child_pointer(pointer, &index.to_string())?;
                if configured.contains(&child) {
                    exclude(value, child, exclusions)?;
                } else {
                    redact(value, &child, configured, exclusions)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn child_pointer(parent: &str, name: &str) -> Result<String, ReasonCode> {
    if parent
        .len()
        .saturating_add(name.len().saturating_mul(2))
        .saturating_add(1)
        > MAX_POINTER_BYTES
    {
        return Err(ReasonCode::EvidenceCaptureLimitExceeded);
    }
    Ok(format!(
        "{parent}/{}",
        name.replace('~', "~0").replace('/', "~1")
    ))
}

fn exclude(
    value: &mut Value,
    pointer: String,
    exclusions: &mut Vec<Exclusion>,
) -> Result<(), ReasonCode> {
    if exclusions.len() >= MAX_REDACTIONS {
        return Err(ReasonCode::EvidenceCaptureLimitExceeded);
    }
    *value = Value::Null;
    exclusions.push(Exclusion {
        pointer,
        reason_code: "EVIDENCE_SECRET_EXCLUDED",
    });
    Ok(())
}

fn secret_field(name: &str) -> bool {
    [
        "password",
        "passwd",
        "pwd",
        "otp",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "set-cookie",
        "secret",
        "api_key",
        "share_token",
    ]
    .iter()
    .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_business_values_and_records_every_secret_exclusion() {
        let rule = EvidenceCaptureRule::compile(
            EvidenceCaptureDto {
                profile_revision: "capture-r1".to_owned(),
                max_bytes: 4096,
                retention_seconds: 3600,
                secret_pointers: vec!["/custom~1key".to_owned(), "/codes/0".to_owned()],
            },
            Some("/session/credential"),
        )
        .unwrap();
        let body = br#"{"value":"<script>hostile()</script>","Password":"one","session":{"credential":"two"},"custom/key":"three","codes":["four","ok"],"rows":[{"TOKEN":"five"}]}"#;
        let captured = rule.capture(body).unwrap();
        let parsed: Value = serde_json::from_slice(&captured).unwrap();
        assert_eq!(parsed["source_bytes_observed"], body.len());
        assert_eq!(parsed["value"]["value"], "<script>hostile()</script>");
        assert_eq!(parsed["value"]["codes"][1], "ok");
        assert_eq!(parsed["exclusions"].as_array().unwrap().len(), 5);
        for secret in ["one", "two", "three", "four", "five"] {
            assert!(!String::from_utf8_lossy(&captured).contains(secret));
        }
        assert!(rule.capture(br#"{"value":1,"value":2}"#).is_err());
        assert_eq!(
            rule.capture(&vec![b' '; 4097]).unwrap_err(),
            ReasonCode::EvidenceCaptureLimitExceeded
        );
        assert!(
            EvidenceCaptureRule::compile(
                EvidenceCaptureDto {
                    profile_revision: "capture-r1".to_owned(),
                    max_bytes: 1,
                    retention_seconds: 86_401,
                    secret_pointers: vec![],
                },
                None
            )
            .is_err()
        );
    }
}
