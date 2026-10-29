//! A pluggable source for the secret values this process needs at startup.
//!
//! [`secret_env`](crate::secret_env) is the default, environment/file-backed
//! [`SecretSource`]. This trait is the seam a KMS-backed source will later
//! implement, so that the `from_env`/`from_hex` constructors elsewhere in
//! this workspace do not have to change when a deployment switches where its
//! secrets come from — only the source passed to them does.
//!
//! Every source must resolve eagerly and fail closed: a secret that is
//! configured but cannot be resolved (network unreachable, access denied, a
//! ciphertext that does not decrypt, ...) is always a hard error, never a
//! fallback to a default, hardcoded, or stale value (docs/19 §19.3). Only a
//! secret that is not configured at all may be treated as absent, and only
//! through [`SecretSource::resolve_opt`], never silently inside `resolve`.

use std::fmt;

use zeroize::Zeroizing;

use crate::secret_env::{self, SecretEnvError};

#[derive(Clone, Debug, Eq, PartialEq)]
enum SecretSourceErrorKind {
    /// Nothing configured this secret at all. [`SecretSource::resolve_opt`]
    /// turns this into `Ok(None)`; a required secret still turns it into an
    /// error.
    NotConfigured,
    /// The secret is configured but did not resolve. Always a hard failure,
    /// even through `resolve_opt`: a source must never let "the backend is
    /// down" or "the ciphertext is wrong" look like "nothing was set".
    Failed,
}

/// Why a [`SecretSource`] could not resolve a secret.
///
/// Carries the secret's name and a value-free detail message, never the
/// secret's value: this is what callers log or turn into a reason code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretSourceError {
    name: String,
    detail: String,
    kind: SecretSourceErrorKind,
}

impl SecretSourceError {
    /// Builds an error for a secret that nothing configured.
    #[must_use]
    pub fn not_configured(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            detail: format!("{name} is not configured"),
            name,
            kind: SecretSourceErrorKind::NotConfigured,
        }
    }

    /// Builds an error for a secret that is configured but failed to
    /// resolve, with a fixed, value-free `detail`.
    #[must_use]
    pub fn failed(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            detail: detail.into(),
            kind: SecretSourceErrorKind::Failed,
        }
    }

    /// The secret's name, exactly as the caller asked for it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether nothing configured this secret, as opposed to a configured
    /// secret that failed to resolve.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(self.kind, SecretSourceErrorKind::NotConfigured)
    }
}

impl fmt::Display for SecretSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for SecretSourceError {}

impl From<SecretEnvError> for SecretSourceError {
    fn from(error: SecretEnvError) -> Self {
        match &error {
            SecretEnvError::NotSet(name) => Self::not_configured(name.clone()),
            SecretEnvError::Ambiguous(name)
            | SecretEnvError::NotUnicode(name)
            | SecretEnvError::Unreadable(name) => Self::failed(name.clone(), error.to_string()),
        }
    }
}

/// Resolves one named secret to its value, or fails closed.
pub trait SecretSource: Send + Sync {
    /// Resolves `name`, or returns a value-free [`SecretSourceError`].
    ///
    /// # Errors
    /// Returns [`SecretSourceError`] when `name` is not configured or could
    /// not be resolved.
    fn resolve(&self, name: &str) -> Result<Zeroizing<String>, SecretSourceError>;

    /// Like [`resolve`](Self::resolve), but a secret nothing configured is
    /// `Ok(None)` instead of an error. A configured secret that failed to
    /// resolve is still `Err`: this never masks that case as "absent".
    ///
    /// # Errors
    /// Returns [`SecretSourceError`] when `name` is configured but could not
    /// be resolved.
    fn resolve_opt(&self, name: &str) -> Result<Option<Zeroizing<String>>, SecretSourceError> {
        match self.resolve(name) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.is_missing() => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// The default [`SecretSource`]: each secret comes from the environment
/// variable `name` or from the file named by `name_FILE`
/// (see [`secret_env`](crate::secret_env)).
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvFileSecretSource;

impl SecretSource for EnvFileSecretSource {
    fn resolve(&self, name: &str) -> Result<Zeroizing<String>, SecretSourceError> {
        secret_env::var(name)
            .map(Zeroizing::new)
            .map_err(SecretSourceError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Result<&'static str, SecretSourceError>);

    impl SecretSource for Fixed {
        fn resolve(&self, name: &str) -> Result<Zeroizing<String>, SecretSourceError> {
            self.0
                .clone()
                .map(|value| Zeroizing::new(value.to_owned()))
                .map_err(|error| SecretSourceError {
                    name: name.to_owned(),
                    ..error
                })
        }
    }

    #[test]
    fn not_configured_becomes_none_through_resolve_opt() {
        let source = Fixed(Err(SecretSourceError::not_configured("S")));
        assert_eq!(source.resolve_opt("S"), Ok(None));
    }

    #[test]
    fn a_failed_resolve_stays_an_error_through_resolve_opt() {
        let source = Fixed(Err(SecretSourceError::failed("S", "kms unreachable")));
        let error = source.resolve_opt("S").unwrap_err();
        assert!(!error.is_missing());
        assert_eq!(error.name(), "S");
        assert_eq!(error.to_string(), "kms unreachable");
    }

    #[test]
    fn a_resolved_secret_passes_through_resolve_opt() {
        let source = Fixed(Ok("abc"));
        let resolved = source.resolve_opt("S").unwrap();
        assert_eq!(resolved.as_deref().map(String::as_str), Some("abc"));
    }

    #[test]
    fn secret_env_errors_classify_not_set_as_missing_and_the_rest_as_failed() {
        let not_set = SecretSourceError::from(SecretEnvError::NotSet("S".to_owned()));
        assert!(not_set.is_missing());
        assert_eq!(not_set.name(), "S");

        for error in [
            SecretEnvError::Ambiguous("S".to_owned()),
            SecretEnvError::NotUnicode("S".to_owned()),
            SecretEnvError::Unreadable("S".to_owned()),
        ] {
            let mapped = SecretSourceError::from(error.clone());
            assert!(!mapped.is_missing(), "{error:?} must not look missing");
            assert_eq!(mapped.name(), "S");
            assert_eq!(mapped.to_string(), error.to_string());
        }
    }

    #[test]
    fn a_failed_error_carries_only_the_fixed_detail_its_caller_gave_it() {
        let error = SecretSourceError::failed("XSHIELD_SOME_KEY_HEX", "kms decrypt failed");
        assert_eq!(error.to_string(), "kms decrypt failed");
    }
}
