//! Opaque, retry-stable limited-share credentials.

use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use std::fmt;
use xshield_core::{
    access::ShareTokenFingerprint,
    domain::{IssuanceKey, SiteId, TenantId},
};
use zeroize::Zeroizing;

const TOKEN_DOMAIN: &str = "xshield-share-token-secret-v1";
const FINGERPRINT_DOMAIN: &str = "xshield-share-token-v1";

/// A plaintext share credential that is redacted and erased on drop.
pub struct ShareToken(Zeroizing<String>);

impl ShareToken {
    /// Borrows the credential for the one authorized client release.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ShareToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShareToken([REDACTED])")
    }
}

/// Derives opaque share credentials with a key distinct from fingerprinting.
pub struct ShareTokenIssuer {
    token_key: Zeroizing<[u8; 32]>,
    fingerprint_key: Zeroizing<[u8; 32]>,
}

impl ShareTokenIssuer {
    /// Parses two lowercase 32-byte keys and enforces purpose separation.
    ///
    /// # Errors
    /// Returns [`ShareTokenError`] when a key is malformed or both purposes use
    /// the same key.
    pub fn from_hex(token_key: &str, fingerprint_key: &str) -> Result<Self, ShareTokenError> {
        let token_key = parse_key(token_key)?;
        let fingerprint_key = parse_key(fingerprint_key)?;
        if token_key == fingerprint_key {
            return Err(ShareTokenError::KeyReuse);
        }
        Ok(Self {
            token_key: Zeroizing::new(token_key),
            fingerprint_key: Zeroizing::new(fingerprint_key),
        })
    }

    /// Derives the same unpredictable credential for one scoped idempotency key.
    ///
    /// # Errors
    /// Returns [`ShareTokenError::Crypto`] when the cryptographic provider fails.
    pub fn issue(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        issuance_key: &IssuanceKey,
    ) -> Result<ShareToken, ShareTokenError> {
        let digest = hmac(
            &self.token_key,
            &canonical(
                TOKEN_DOMAIN,
                tenant_id.as_str(),
                site_id.as_str(),
                issuance_key.as_str(),
            ),
        )?;
        Ok(ShareToken(Zeroizing::new(lower_hex(&digest))))
    }

    /// Fingerprints a derived credential for persistence and later comparison.
    ///
    /// # Errors
    /// Returns [`ShareTokenError::Crypto`] when the cryptographic provider fails.
    pub fn fingerprint(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        token: &ShareToken,
    ) -> Result<ShareTokenFingerprint, ShareTokenError> {
        fingerprint_share_token(
            &self.fingerprint_key,
            tenant_id,
            site_id,
            token.expose_secret(),
        )
    }
}

/// Produces the canonical tenant/site-isolated digest used by `SHARE_ENTRY`.
///
/// # Errors
/// Returns [`ShareTokenError::Crypto`] when the cryptographic provider fails.
pub fn fingerprint_share_token(
    key: &[u8; 32],
    tenant_id: &TenantId,
    site_id: &SiteId,
    token: &str,
) -> Result<ShareTokenFingerprint, ShareTokenError> {
    Ok(ShareTokenFingerprint::from_bytes(hmac(
        key,
        &canonical(
            FINGERPRINT_DOMAIN,
            tenant_id.as_str(),
            site_id.as_str(),
            token,
        ),
    )?))
}

fn canonical(domain: &str, tenant_id: &str, site_id: &str, value: &str) -> Zeroizing<Vec<u8>> {
    let mut canonical = Zeroizing::new(Vec::with_capacity(
        domain.len() + tenant_id.len() + site_id.len() + value.len() + 4,
    ));
    for component in [domain, tenant_id, site_id, value] {
        canonical.extend_from_slice(component.as_bytes());
        canonical.push(0);
    }
    canonical
}

fn hmac(key: &[u8; 32], value: &[u8]) -> Result<[u8; 32], ShareTokenError> {
    let key = PKey::hmac(key).map_err(|_| ShareTokenError::Crypto)?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &key).map_err(|_| ShareTokenError::Crypto)?;
    signer.update(value).map_err(|_| ShareTokenError::Crypto)?;
    signer
        .sign_to_vec()
        .map_err(|_| ShareTokenError::Crypto)?
        .try_into()
        .map_err(|_| ShareTokenError::Crypto)
}

fn parse_key(value: &str) -> Result<[u8; 32], ShareTokenError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ShareTokenError::InvalidKey);
    }
    let mut key = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        key[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(key)
}

const fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn lower_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Share-token key or cryptographic provider failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareTokenError {
    /// A key is not canonical lowercase 32-byte hexadecimal.
    InvalidKey,
    /// Token derivation and credential fingerprinting used the same key.
    KeyReuse,
    /// The cryptographic provider failed.
    Crypto,
}

impl fmt::Display for ShareTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKey => "invalid share-token key",
            Self::KeyReuse => "share-token keys must be distinct",
            Self::Crypto => "share-token cryptography failed",
        })
    }
}

impl std::error::Error for ShareTokenError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> ShareTokenIssuer {
        ShareTokenIssuer::from_hex(&"11".repeat(32), &"22".repeat(32)).unwrap()
    }

    #[test]
    fn token_is_retry_stable_scoped_and_redacted() {
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let key = IssuanceKey::parse("response-item-7").unwrap();
        let first = issuer().issue(&tenant, &site, &key).unwrap();
        let retry = issuer().issue(&tenant, &site, &key).unwrap();
        let other_site = SiteId::parse("site_b").unwrap();
        let other = issuer().issue(&tenant, &other_site, &key).unwrap();

        assert_eq!(first.expose_secret(), retry.expose_secret());
        assert_ne!(first.expose_secret(), other.expose_secret());
        assert_eq!(first.expose_secret().len(), 64);
        assert_eq!(format!("{first:?}"), "ShareToken([REDACTED])");
        assert_eq!(
            issuer().fingerprint(&tenant, &site, &first).unwrap(),
            issuer().fingerprint(&tenant, &site, &retry).unwrap()
        );
    }

    #[test]
    fn rejects_malformed_or_reused_keys() {
        assert_eq!(
            ShareTokenIssuer::from_hex("not-a-key", &"22".repeat(32)).err(),
            Some(ShareTokenError::InvalidKey)
        );
        assert_eq!(
            ShareTokenIssuer::from_hex(&"11".repeat(32), &"11".repeat(32)).err(),
            Some(ShareTokenError::KeyReuse)
        );
    }
}
