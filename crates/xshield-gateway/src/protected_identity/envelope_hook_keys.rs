//! `ENVELOPE_HOOK` session-key derivation (docs/08 §8.1, Option A).
//!
//! The key is never stored: it is recomputed identically wherever it is
//! needed (bootstrap issuance in [`super::page_issue`] and live-request
//! decode in `main.rs`) from the same server secret and the same
//! session-identity values already resolved independently at each site, by
//! HMAC-SHA256 over tenant, site, binding, epoch, and time window, mirroring
//! this module's [`fingerprint`] pattern.

use xshield_core::{
    domain::{AuthBindingId, SiteId, TenantId},
    identity::AuthEpoch,
};
use zeroize::Zeroizing;

use super::{IdentityRuntimeError, ProtectedIdentity, fingerprint};

impl ProtectedIdentity {
    /// Derives the `ENVELOPE_HOOK` session key for one time window.
    ///
    /// Revoked by the existing session-epoch bump on login, logout, or
    /// account switch: a key derived for a stale `epoch` is simply a
    /// different key, never recognized by this session's live requests.
    ///
    /// # Errors
    /// Returns [`IdentityRuntimeError::Crypto`] if the underlying HMAC
    /// primitive fails.
    pub(crate) fn envelope_hook_key(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        binding_id: &AuthBindingId,
        epoch: AuthEpoch,
        window: u64,
    ) -> Result<Zeroizing<[u8; 32]>, IdentityRuntimeError> {
        let mut material = Vec::with_capacity(128);
        material.extend_from_slice(b"xshield-envelope-hook-key-v1\0");
        material.extend_from_slice(tenant_id.as_str().as_bytes());
        material.push(0);
        material.extend_from_slice(site_id.as_str().as_bytes());
        material.push(0);
        material.extend_from_slice(binding_id.as_str().as_bytes());
        material.push(0);
        material.extend_from_slice(&epoch.value().to_be_bytes());
        material.extend_from_slice(&window.to_be_bytes());
        Ok(Zeroizing::new(fingerprint(
            &self.fingerprint_key,
            &material,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::domain::{SiteId, TenantId};

    fn identity() -> ProtectedIdentity {
        // Never connects: this test never calls a method that touches the
        // store, and `PostgresRuntime` connects lazily on first use.
        ProtectedIdentity {
            store: std::sync::Arc::new(crate::PostgresRuntime::new(
                Zeroizing::new(String::new()),
                1,
                std::time::Duration::from_millis(1),
            )),
            fingerprint_key: Zeroizing::new([3; 32]),
            share_tokens: None,
            anonymous_creation_window: std::sync::Mutex::new(None),
        }
    }

    #[test]
    fn the_same_identity_and_window_always_derive_the_same_key() {
        let identity = identity();
        let tenant_id = TenantId::parse("tenant_demo").unwrap();
        let site_id = SiteId::parse("site_demo").unwrap();
        let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000e01").unwrap();
        let first = identity
            .envelope_hook_key(&tenant_id, &site_id, &binding_id, AuthEpoch::new(1), 7)
            .unwrap();
        let second = identity
            .envelope_hook_key(&tenant_id, &site_id, &binding_id, AuthEpoch::new(1), 7)
            .unwrap();
        assert_eq!(*first, *second);
    }

    #[test]
    fn a_different_window_binding_epoch_tenant_or_site_derives_a_different_key() {
        let identity = identity();
        let tenant_id = TenantId::parse("tenant_demo").unwrap();
        let other_tenant_id = TenantId::parse("tenant_other").unwrap();
        let site_id = SiteId::parse("site_demo").unwrap();
        let other_site_id = SiteId::parse("site_other").unwrap();
        let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000e01").unwrap();
        let other_binding_id =
            AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000e02").unwrap();
        let base = identity
            .envelope_hook_key(&tenant_id, &site_id, &binding_id, AuthEpoch::new(1), 7)
            .unwrap();
        for other in [
            identity
                .envelope_hook_key(&tenant_id, &site_id, &binding_id, AuthEpoch::new(1), 8)
                .unwrap(),
            identity
                .envelope_hook_key(&tenant_id, &site_id, &binding_id, AuthEpoch::new(2), 7)
                .unwrap(),
            identity
                .envelope_hook_key(
                    &tenant_id,
                    &site_id,
                    &other_binding_id,
                    AuthEpoch::new(1),
                    7,
                )
                .unwrap(),
            identity
                .envelope_hook_key(
                    &other_tenant_id,
                    &site_id,
                    &binding_id,
                    AuthEpoch::new(1),
                    7,
                )
                .unwrap(),
            identity
                .envelope_hook_key(
                    &tenant_id,
                    &other_site_id,
                    &binding_id,
                    AuthEpoch::new(1),
                    7,
                )
                .unwrap(),
        ] {
            assert_ne!(*base, *other);
        }
    }
}
