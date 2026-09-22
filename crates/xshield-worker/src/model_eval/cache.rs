//! Cache-key admission for model evaluations.
//!
//! A reusable result is safe only when its provider revision is exact and its
//! key covers the entire validated internal input plus an explicitly configured
//! security domain. This module does not read or write cached results; durable
//! lookup and evidence revalidation consume its opaque key in a later adapter.

use super::{transport::ModelPort, wire::Input};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use std::env;
use xshield_core::domain::{SiteId, TenantId};
use zeroize::Zeroizing;

const CACHE_CONFIGURATION_INVALID: &str = "MODEL_CACHE_CONFIG_INVALID";
const EXACT_REVISION_REQUIRED: &str = "MODEL_CACHE_EXACT_REVISION_REQUIRED";
const KEY_HEX_BYTES: usize = 64;
const CACHE_KEY_BYTES: usize = 32;
const KEY_PURPOSE: &[u8] = b"xshield-model-evaluation-cache-key-v1";

/// Immutable, deployment-selected cache boundary for one exact model revision.
///
/// The HMAC key is never serialized, logged, or exposed through `Debug`. The
/// caller validates one fixed-length opaque key derivation per evaluation input.
pub(super) struct ModelCacheConfiguration {
    domain: String,
    key: Zeroizing<[u8; CACHE_KEY_BYTES]>,
    resolved_model_revision: String,
    provider: String,
    provider_model_id: String,
}

/// Opaque HMAC key for a tenant/site-isolated evaluation equivalence class.
///
/// It is intentionally not displayable: a cache lookup receives raw bytes and
/// must retain the scope and domain supplied by [`ModelCacheConfiguration`].
#[cfg(test)]
pub(super) struct ModelCacheKey(Zeroizing<[u8; CACHE_KEY_BYTES]>);

#[cfg(test)]
impl ModelCacheKey {
    /// Borrows the fixed-length database lookup key without formatting it.
    #[must_use]
    pub(super) fn as_bytes(&self) -> &[u8; CACHE_KEY_BYTES] {
        &self.0
    }
}

impl ModelCacheConfiguration {
    /// Parses the optional deployment cache configuration for one fixed route.
    ///
    /// An absent `XSHIELD_MODEL_CACHE_DOMAIN` leaves the cache precondition
    /// inactive. When configured, the domain and separate HMAC key are required
    /// and the selected model route must prove its exact resolved revision.
    /// Gateway aliases deliberately cannot satisfy that requirement.
    ///
    /// # Errors
    /// Returns stable configuration reasons only; no value, secret, or provider
    /// response is included in the error.
    pub(super) fn from_environment(model: &impl ModelPort) -> Result<Option<Self>, &'static str> {
        let Some(domain) = env::var_os("XSHIELD_MODEL_CACHE_DOMAIN") else {
            return Ok(None);
        };
        let domain = domain
            .into_string()
            .map_err(|_| CACHE_CONFIGURATION_INVALID)?;
        let source = Zeroizing::new(
            env::var("XSHIELD_MODEL_CACHE_KEY_HEX").map_err(|_| CACHE_CONFIGURATION_INVALID)?,
        );
        Self::from_values(model, Some(&domain), Some(source.as_str()))
    }

    fn from_values(
        model: &impl ModelPort,
        domain: Option<&str>,
        source: Option<&str>,
    ) -> Result<Option<Self>, &'static str> {
        let Some(domain) = domain else {
            return Ok(None);
        };
        if !valid_domain(domain) {
            return Err(CACHE_CONFIGURATION_INVALID);
        }
        let Some(resolved_model_revision) = model.exact_cache_revision() else {
            return Err(EXACT_REVISION_REQUIRED);
        };
        if !valid_name(resolved_model_revision)
            || !valid_name(model.provider())
            || !valid_provider_model(model.provider_model())
        {
            return Err(CACHE_CONFIGURATION_INVALID);
        }
        let source = source.ok_or(CACHE_CONFIGURATION_INVALID)?;
        let key = parse_key(source)?;
        Ok(Some(Self {
            domain: domain.to_owned(),
            key: Zeroizing::new(key),
            resolved_model_revision: resolved_model_revision.to_owned(),
            provider: model.provider().to_owned(),
            provider_model_id: model.provider_model().to_owned(),
        }))
    }

    /// Checks that an opaque key can be derived for one complete validated input.
    ///
    /// Length-prefixing prevents ambiguous component concatenation. The input
    /// serialization contains every current decision-relevant field; tenant/site
    /// and configured domain prevent reuse across trust scopes. The key is
    /// dropped immediately because durable cache lookup is not enabled yet.
    ///
    /// # Errors
    /// Returns a stable configuration reason if the local crypto provider fails.
    pub(super) fn validate_input_binding(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        input: &Input,
    ) -> Result<(), &'static str> {
        let _derived = self.derive_key(tenant_id, site_id, input)?;
        Ok(())
    }

    #[cfg(test)]
    fn key_for(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        input: &Input,
    ) -> Result<ModelCacheKey, &'static str> {
        self.derive_key(tenant_id, site_id, input)
            .map(ModelCacheKey)
    }

    fn derive_key(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        input: &Input,
    ) -> Result<Zeroizing<[u8; CACHE_KEY_BYTES]>, &'static str> {
        let internal = Zeroizing::new(input.internal_bytes()?);
        let key = PKey::hmac(self.key.as_ref()).map_err(|_| CACHE_CONFIGURATION_INVALID)?;
        let mut signer =
            Signer::new(MessageDigest::sha256(), &key).map_err(|_| CACHE_CONFIGURATION_INVALID)?;
        for component in [
            KEY_PURPOSE,
            self.domain.as_bytes(),
            tenant_id.as_str().as_bytes(),
            site_id.as_str().as_bytes(),
            self.provider.as_bytes(),
            self.provider_model_id.as_bytes(),
            self.resolved_model_revision.as_bytes(),
            internal.as_slice(),
        ] {
            let length = u64::try_from(component.len()).map_err(|_| CACHE_CONFIGURATION_INVALID)?;
            signer
                .update(&length.to_be_bytes())
                .map_err(|_| CACHE_CONFIGURATION_INVALID)?;
            signer
                .update(component)
                .map_err(|_| CACHE_CONFIGURATION_INVALID)?;
        }
        let digest = signer
            .sign_to_vec()
            .map_err(|_| CACHE_CONFIGURATION_INVALID)?;
        let digest: [u8; CACHE_KEY_BYTES] =
            digest.try_into().map_err(|_| CACHE_CONFIGURATION_INVALID)?;
        Ok(Zeroizing::new(digest))
    }

    /// Indicates whether another hex deployment secret is the cache HMAC key.
    ///
    /// The evaluator uses this to reject key-role reuse before it starts an
    /// external provider attempt.
    pub(super) fn matches_hex_secret(&self, value: &str) -> bool {
        parse_key(value)
            .is_ok_and(|candidate| openssl::memcmp::eq(self.key.as_ref(), candidate.as_ref()))
    }

    /// Returns whether a transport credential repeats this cache key.
    ///
    /// The evaluator treats this as a configuration error before any evidence
    /// setup or provider request, so one secret cannot cross credential roles.
    #[must_use]
    pub(super) fn reuses_transport_secret(&self, model: &impl ModelPort) -> bool {
        model.cache_key_reuses_transport_secret(self.key.as_ref())
    }
}

fn parse_key(value: &str) -> Result<[u8; CACHE_KEY_BYTES], &'static str> {
    if value.len() != KEY_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CACHE_CONFIGURATION_INVALID);
    }
    let mut key = [0_u8; CACHE_KEY_BYTES];
    for (index, byte) in key.iter_mut().enumerate() {
        let offset = index.checked_mul(2).ok_or(CACHE_CONFIGURATION_INVALID)?;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| CACHE_CONFIGURATION_INVALID)?;
    }
    Ok(key)
}

fn valid_domain(value: &str) -> bool {
    valid_name(value) && value.starts_with("model-cache-")
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_provider_model(value: &str) -> bool {
    value.len() <= 128
        && !value.is_empty()
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && valid_name(segment))
}

#[cfg(test)]
mod tests {
    use super::{ModelCacheConfiguration, valid_domain, valid_provider_model};
    use crate::model_eval::{transport::ModelPort, wire::Input};
    use std::time::Duration;
    use tokio::sync::oneshot;
    use xshield_core::domain::{SiteId, TenantId};

    const CACHE_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const INPUT: &[u8] = br#"{"schema_version":1,"approval_ref":"cache-test-r1","model_revision":"jev-1.13.0","policy_revision":"policy-r1","prompt_revision":"prompt-r1","untrusted_content":"Synthetic cache input.","question":{"type":"choice","instructions":"Choose one.","criteria":{"NONE":"None.","UNKNOWN":"Unknown."}}}"#;

    struct Direct;
    struct Gateway;
    struct Alternate;
    struct ReusedCredential;

    impl ModelPort for Direct {
        async fn send_with_deadline(
            &self,
            _payload: &[u8],
            _cancel: &mut oneshot::Receiver<()>,
            _deadline: Duration,
        ) -> super::super::transport::Exchange {
            unreachable!("cache configuration tests do not send")
        }

        fn contains_secret(&self, _bytes: &[u8]) -> bool {
            false
        }

        fn exact_cache_revision(&self) -> Option<&str> {
            Some("jev-1.13.0")
        }
    }

    impl ModelPort for Gateway {
        async fn send_with_deadline(
            &self,
            _payload: &[u8],
            _cancel: &mut oneshot::Receiver<()>,
            _deadline: Duration,
        ) -> super::super::transport::Exchange {
            unreachable!("cache configuration tests do not send")
        }

        fn contains_secret(&self, _bytes: &[u8]) -> bool {
            false
        }

        fn provider(&self) -> &'static str {
            "vercel_ai_gateway"
        }

        fn provider_model(&self) -> &'static str {
            "typesafe-ai/jev"
        }
    }

    impl ModelPort for Alternate {
        async fn send_with_deadline(
            &self,
            _payload: &[u8],
            _cancel: &mut oneshot::Receiver<()>,
            _deadline: Duration,
        ) -> super::super::transport::Exchange {
            unreachable!("cache configuration tests do not send")
        }

        fn contains_secret(&self, _bytes: &[u8]) -> bool {
            false
        }

        fn provider(&self) -> &'static str {
            "typesafe_alt"
        }

        fn provider_model(&self) -> &'static str {
            "jev-alt"
        }

        fn exact_cache_revision(&self) -> Option<&str> {
            Some("jev-1.13.1")
        }
    }

    impl ModelPort for ReusedCredential {
        async fn send_with_deadline(
            &self,
            _payload: &[u8],
            _cancel: &mut oneshot::Receiver<()>,
            _deadline: Duration,
        ) -> super::super::transport::Exchange {
            unreachable!("cache configuration tests do not send")
        }

        fn contains_secret(&self, _bytes: &[u8]) -> bool {
            false
        }

        fn cache_key_reuses_transport_secret(&self, _cache_key: &[u8]) -> bool {
            true
        }

        fn exact_cache_revision(&self) -> Option<&str> {
            Some("jev-1.13.0")
        }
    }

    #[test]
    fn cache_configuration_is_explicit_exact_and_scope_bound() {
        assert!(
            ModelCacheConfiguration::from_values(&Direct, None, None)
                .unwrap()
                .is_none()
        );
        let config = ModelCacheConfiguration::from_values(
            &Direct,
            Some("model-cache-offline-r1"),
            Some(CACHE_KEY),
        )
        .unwrap()
        .unwrap();
        let input = Input::parse(INPUT).unwrap();
        let tenant_a = TenantId::parse("tenant_cache_a").unwrap();
        let tenant_b = TenantId::parse("tenant_cache_b").unwrap();
        let site = SiteId::parse("site_cache").unwrap();
        let other_site = SiteId::parse("site_cache_alt").unwrap();
        let first = config.key_for(&tenant_a, &site, &input).unwrap();
        let repeated = config.key_for(&tenant_a, &site, &input).unwrap();
        let cross_tenant = config.key_for(&tenant_b, &site, &input).unwrap();
        let cross_site = config.key_for(&tenant_a, &other_site, &input).unwrap();
        let other_domain = ModelCacheConfiguration::from_values(
            &Direct,
            Some("model-cache-offline-r2"),
            Some(CACHE_KEY),
        )
        .unwrap()
        .unwrap()
        .key_for(&tenant_a, &site, &input)
        .unwrap();
        let other_model = ModelCacheConfiguration::from_values(
            &Alternate,
            Some("model-cache-offline-r1"),
            Some(CACHE_KEY),
        )
        .unwrap()
        .unwrap()
        .key_for(&tenant_a, &site, &input)
        .unwrap();
        assert_eq!(first.as_bytes(), repeated.as_bytes());
        assert_ne!(first.as_bytes(), cross_tenant.as_bytes());
        assert_ne!(first.as_bytes(), cross_site.as_bytes());
        assert_ne!(first.as_bytes(), other_domain.as_bytes());
        assert_ne!(first.as_bytes(), other_model.as_bytes());
        assert!(config.matches_hex_secret(CACHE_KEY));
        assert!(!config.matches_hex_secret(&"f".repeat(64)));
        assert!(config.reuses_transport_secret(&ReusedCredential));
        assert!(!config.reuses_transport_secret(&Direct));
    }

    #[test]
    fn cache_configuration_rejects_gateway_alias_and_bad_key_material() {
        assert!(matches!(
            ModelCacheConfiguration::from_values(
                &Gateway,
                Some("model-cache-offline-r1"),
                Some(CACHE_KEY),
            ),
            Err("MODEL_CACHE_EXACT_REVISION_REQUIRED")
        ));
        assert!(matches!(
            ModelCacheConfiguration::from_values(
                &Direct,
                Some("model-cache-offline-r1"),
                Some("not-a-cache-key"),
            ),
            Err("MODEL_CACHE_CONFIG_INVALID")
        ));
        assert!(matches!(
            ModelCacheConfiguration::from_values(
                &Direct,
                Some("model-cache-offline-r1"),
                Some(&CACHE_KEY.to_uppercase()),
            ),
            Err("MODEL_CACHE_CONFIG_INVALID")
        ));
        assert!(valid_domain("model-cache-r1"));
        assert!(!valid_domain("cache-r1"));
        assert!(valid_provider_model("typesafe-ai/jev"));
        assert!(!valid_provider_model("typesafe-ai//jev"));
    }
}
