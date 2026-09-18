//! Strict extraction of one verified authentication response.

use crate::response_grant::strict_json;
use std::fmt;
use xshield_core::audit::ReasonCode;
use zeroize::Zeroizing;

const MAX_PRINCIPAL_BYTES: usize = 256;
const MAX_AUTHORIZATION_CONTEXT_BYTES: usize = 256;
const MAX_BEARER_BYTES: usize = 8192;

/// Validated authentication-response semantics from trusted configuration.
#[derive(Debug)]
pub struct AuthBindingRule {
    pub(crate) success_status: u16,
    pub(crate) principal_pointer: String,
    pub(crate) authorization_context_pointer: String,
    pub(crate) bearer_pointer: String,
    pub(crate) credential_ttl_seconds: u64,
    pub(crate) session_ttl_seconds: u64,
}

/// Validated credential-transition response semantics for an existing binding.
#[derive(Debug)]
pub struct AuthTransitionRule {
    pub(crate) success_status: u16,
    pub(crate) principal_pointer: String,
    pub(crate) authorization_context_pointer: String,
    pub(crate) bearer_pointer: String,
    pub(crate) credential_ttl_seconds: u64,
}

impl AuthBindingRule {
    /// Returns whether this origin response can establish a binding.
    #[must_use]
    pub const fn applies(&self, status: u16) -> bool {
        status == self.success_status
    }

    /// Extracts a bounded principal, authorization context, and bearer.
    ///
    /// The bearer is held in a zeroizing buffer and must only be fingerprinted or
    /// returned to the client. It must not enter ordinary logs or audit envelopes.
    ///
    /// # Errors
    /// Returns [`AuthBindingError`] for malformed JSON, an unexpected response
    /// shape, or an unusable identity-context or bearer value.
    pub fn extract(&self, body: &[u8]) -> Result<VerifiedAuthentication, AuthBindingError> {
        extract_authentication(
            body,
            &self.principal_pointer,
            &self.authorization_context_pointer,
            &self.bearer_pointer,
        )
    }

    /// Returns the server-enforced credential lifetime.
    #[must_use]
    pub const fn credential_ttl_seconds(&self) -> u64 {
        self.credential_ttl_seconds
    }

    /// Returns the absolute WAF session lifetime.
    #[must_use]
    pub const fn session_ttl_seconds(&self) -> u64 {
        self.session_ttl_seconds
    }
}

impl AuthTransitionRule {
    /// Returns whether this origin response can transition the current binding.
    #[must_use]
    pub const fn applies(&self, status: u16) -> bool {
        status == self.success_status
    }

    /// Extracts a bounded principal, authorization context, and bearer.
    ///
    /// # Errors
    /// Returns [`AuthBindingError`] for malformed JSON, an unexpected response
    /// shape, or an unusable identity-context or bearer value.
    pub fn extract(&self, body: &[u8]) -> Result<VerifiedAuthentication, AuthBindingError> {
        extract_authentication(
            body,
            &self.principal_pointer,
            &self.authorization_context_pointer,
            &self.bearer_pointer,
        )
    }

    /// Returns the server-enforced credential lifetime.
    #[must_use]
    pub const fn credential_ttl_seconds(&self) -> u64 {
        self.credential_ttl_seconds
    }
}

fn extract_authentication(
    body: &[u8],
    principal_pointer: &str,
    authorization_context_pointer: &str,
    bearer_pointer: &str,
) -> Result<VerifiedAuthentication, AuthBindingError> {
    let value = strict_json(body)?;
    let principal_ref = value
        .pointer(principal_pointer)
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_value(value, MAX_PRINCIPAL_BYTES))
        .ok_or(AuthBindingError)?
        .to_owned();
    let authorization_context_ref = value
        .pointer(authorization_context_pointer)
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_value(value, MAX_AUTHORIZATION_CONTEXT_BYTES))
        .ok_or(AuthBindingError)?
        .to_owned();
    let bearer = value
        .pointer(bearer_pointer)
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_value(value, MAX_BEARER_BYTES))
        .ok_or(AuthBindingError)?
        .to_owned();
    Ok(VerifiedAuthentication {
        principal_ref,
        authorization_context_ref,
        bearer: Zeroizing::new(bearer),
    })
}

fn valid_value(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.bytes().any(|byte| byte.is_ascii_control())
}

/// Verified origin authentication facts ready for binding establishment.
pub struct VerifiedAuthentication {
    principal_ref: String,
    authorization_context_ref: String,
    bearer: Zeroizing<String>,
}

impl VerifiedAuthentication {
    /// Returns the non-secret principal reference asserted by the approved adapter.
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// Returns the non-secret authorization context asserted by the adapter.
    #[must_use]
    pub fn authorization_context_ref(&self) -> &str {
        &self.authorization_context_ref
    }

    /// Returns the bearer only for immediate fingerprinting.
    #[must_use]
    pub fn bearer(&self) -> &str {
        &self.bearer
    }
}

/// Deterministic authentication-response validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthBindingError;

impl AuthBindingError {
    /// Returns the stable response-stage reason code.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        ReasonCode::ResponseValidationFailed
    }
}

impl From<crate::response_grant::ResponseGrantError> for AuthBindingError {
    fn from(_: crate::response_grant::ResponseGrantError) -> Self {
        Self
    }
}

impl fmt::Display for AuthBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code().as_str())
    }
}

impl std::error::Error for AuthBindingError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> AuthBindingRule {
        AuthBindingRule {
            success_status: 200,
            principal_pointer: "/identity/id".to_owned(),
            authorization_context_pointer: "/identity/authorization_context".to_owned(),
            bearer_pointer: "/access_token".to_owned(),
            credential_ttl_seconds: 900,
            session_ttl_seconds: 3600,
        }
    }

    #[test]
    fn extracts_only_bounded_strict_authentication_facts() {
        let extracted = rule()
            .extract(br#"{"identity":{"id":"principal-1","authorization_context":"tenant-a:user"},"access_token":"token-1"}"#)
            .unwrap();
        assert_eq!(extracted.principal_ref(), "principal-1");
        assert_eq!(extracted.authorization_context_ref(), "tenant-a:user");
        assert_eq!(extracted.bearer(), "token-1");
        assert!(
            rule()
                .extract(br#"{"identity":{"id":"principal-1","authorization_context":"tenant-a:user"},"access_token":""}"#)
                .is_err()
        );
        assert!(
            rule()
                .extract(br#"{"identity":{"id":"a","id":"b","authorization_context":"tenant-a:user"},"access_token":"token"}"#)
                .is_err()
        );
        assert!(
            rule()
                .extract(br#"{"identity":{"id":"a"},"access_token":"token"}"#)
                .is_err()
        );
    }
}
