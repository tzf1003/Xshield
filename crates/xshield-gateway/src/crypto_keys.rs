//! Request-decryption and response-encryption keys, by tenant, site and key-id.
//!
//! One edge serves the bootstrap site and every site an apply snapshot
//! delivers, and a site rotates its key by publishing a revision that names a
//! new key-id. A single key bound to the bootstrap site could serve neither: a
//! delivered site's encrypted route failed closed, and rotation needed a
//! second edge. Each direction therefore holds a keyring:
//!
//! - `XSHIELD_REQUEST_DECRYPTION_KEYS` / `XSHIELD_RESPONSE_ENCRYPTION_KEYS`
//!   (or `_FILE`, docs/19 19.3): a JSON array of
//!   `{"tenant_id", "site_id", "key_id", "key_hex"}`, at most
//!   [`MAX_KEYS`] entries;
//! - the single `XSHIELD_REQUEST_DECRYPTION_KEY_HEX` /
//!   `XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX` keep their meaning: the key for the
//!   bootstrap site's key-id, read only when that configuration needs one.
//!
//! A lookup matches tenant, site, key-id and purpose exactly; anything else is
//! the stable `*_KEY_UNAVAILABLE` refusal the routes already use. No key is
//! shared between the two directions, and the bootstrap configuration's
//! key-id must be present at startup, as before.

use serde::Deserialize;
use std::{collections::BTreeMap, error::Error};
use xshield_core::{
    audit::ReasonCode,
    domain::{SiteId, TenantId},
};
use xshield_gateway::{
    GatewayConfig,
    request_crypto::{KeyAccessPort, KeyAccessQuery},
    response_crypto::{ResponseKeyAccessPort, ResponseKeyAccessQuery},
};
use zeroize::Zeroizing;

/// Most keys one direction's ring holds.
pub(crate) const MAX_KEYS: usize = 256;

type Scope = (String, String, String);

/// One direction's keys.
pub(crate) struct KeyRing {
    keys: BTreeMap<Scope, Zeroizing<[u8; 32]>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    tenant_id: String,
    site_id: String,
    key_id: String,
    #[serde(deserialize_with = "zeroizing")]
    key_hex: Zeroizing<String>,
}

/// Wraps the key text as soon as it is decoded, so it is wiped on every path.
fn zeroizing<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// The variables of one direction.
struct Source {
    ring: &'static str,
    single: &'static str,
}

const REQUEST: Source = Source {
    ring: "XSHIELD_REQUEST_DECRYPTION_KEYS",
    single: "XSHIELD_REQUEST_DECRYPTION_KEY_HEX",
};
const RESPONSE: Source = Source {
    ring: "XSHIELD_RESPONSE_ENCRYPTION_KEYS",
    single: "XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX",
};

impl KeyRing {
    /// The request-decryption ring for this edge.
    ///
    /// # Errors
    /// A malformed ring, a duplicate scope, or a bootstrap key-id with no key.
    pub(crate) fn requests(config: &GatewayConfig) -> Result<Self, Box<dyn Error>> {
        Self::from_env(&REQUEST, config, config.request_crypto_key_id())
    }

    /// The response-encryption ring for this edge.
    ///
    /// # Errors
    /// A malformed ring, a duplicate scope, or a bootstrap key-id with no key.
    pub(crate) fn responses(config: &GatewayConfig) -> Result<Self, Box<dyn Error>> {
        Self::from_env(&RESPONSE, config, config.response_crypto_key_id())
    }

    fn from_env(
        source: &Source,
        config: &GatewayConfig,
        bootstrap_key_id: Option<&str>,
    ) -> Result<Self, Box<dyn Error>> {
        let ring = xshield_core::secret_env::var_opt(source.ring)?.map(Zeroizing::new);
        let single = match bootstrap_key_id {
            Some(_) => xshield_core::secret_env::var_opt(source.single)?.map(Zeroizing::new),
            None => None,
        };
        let mut keys = match ring {
            Some(text) => Self::parse(source.ring, &text)?,
            None => Self {
                keys: BTreeMap::new(),
            },
        };
        let Some(key_id) = bootstrap_key_id else {
            return Ok(keys);
        };
        let scope = (
            config.tenant_id().as_str().to_owned(),
            config.site_id().as_str().to_owned(),
            key_id.to_owned(),
        );
        if let Some(value) = single {
            let key = parse_key(&value).ok_or_else(|| format!("invalid {}", source.single))?;
            if keys
                .keys
                .insert(scope.clone(), Zeroizing::new(key))
                .is_some()
            {
                return Err(format!(
                    "{} and {} both name the bootstrap key-id",
                    source.single, source.ring
                )
                .into());
            }
        }
        if !keys.keys.contains_key(&scope) {
            return Err(format!(
                "the configuration needs key-id {key_id}: set {} or list it in {}",
                source.single, source.ring
            )
            .into());
        }
        Ok(keys)
    }

    /// Parses a ring. Errors name the variable and the entry, never a key.
    fn parse(name: &str, text: &str) -> Result<Self, Box<dyn Error>> {
        let entries: Vec<KeyEntry> =
            serde_json::from_str(text).map_err(|_| format!("{name} is not a JSON key list"))?;
        if entries.is_empty() || entries.len() > MAX_KEYS {
            return Err(format!("{name} must list 1 to {MAX_KEYS} keys").into());
        }
        let mut keys = BTreeMap::new();
        for (index, entry) in entries.into_iter().enumerate() {
            let invalid = || format!("{name}[{index}] is invalid");
            let tenant = TenantId::parse(entry.tenant_id).map_err(|_| invalid())?;
            let site = SiteId::parse(entry.site_id).map_err(|_| invalid())?;
            if !valid_key_id(&entry.key_id) {
                return Err(invalid().into());
            }
            let key = parse_key(&entry.key_hex).ok_or_else(invalid)?;
            let scope = (
                tenant.as_str().to_owned(),
                site.as_str().to_owned(),
                entry.key_id,
            );
            if keys.insert(scope, Zeroizing::new(key)).is_some() {
                return Err(format!("{name}[{index}] repeats a tenant, site and key-id").into());
            }
        }
        Ok(Self { keys })
    }

    /// Whether any key of this ring is also a key of `other`.
    pub(crate) fn shares_key_with(&self, other: &Self) -> bool {
        self.keys.values().any(|key| {
            other
                .keys
                .values()
                .any(|theirs| xshield_core::constant_time::eq(key.as_ref(), theirs.as_ref()))
        })
    }

    fn get(&self, tenant_id: &str, site_id: &str, key_id: &str) -> Option<Zeroizing<[u8; 32]>> {
        self.keys
            .get(&(tenant_id.to_owned(), site_id.to_owned(), key_id.to_owned()))
            .map(|key| Zeroizing::new(**key))
    }
}

impl KeyAccessPort for KeyRing {
    fn request_decryption_key(
        &self,
        query: KeyAccessQuery<'_>,
    ) -> Result<Zeroizing<[u8; 32]>, ReasonCode> {
        if query.purpose != "request_direct_decrypt" || query.at.value() == 0 {
            return Err(ReasonCode::RequestCryptoKeyUnavailable);
        }
        self.get(query.tenant_id, query.site_id, query.key_id)
            .ok_or(ReasonCode::RequestCryptoKeyUnavailable)
    }
}

impl ResponseKeyAccessPort for KeyRing {
    fn response_encryption_key(
        &self,
        query: ResponseKeyAccessQuery<'_>,
    ) -> Result<Zeroizing<[u8; 32]>, ReasonCode> {
        if query.purpose != "response_direct_encrypt" || query.at.value() == 0 {
            return Err(ReasonCode::ResponseCryptoKeyUnavailable);
        }
        self.get(query.tenant_id, query.site_id, query.key_id)
            .ok_or(ReasonCode::ResponseCryptoKeyUnavailable)
    }
}

/// The key-id rule the configuration applies (`[A-Za-z0-9._-]`, 1 to 128 bytes).
fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// Exactly 64 lowercase hexadecimal digits.
fn parse_key(value: &str) -> Option<[u8; 32]> {
    let digits = value.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut key = [0; 32];
    for (slot, pair) in key.iter_mut().zip(digits.as_chunks::<2>().0) {
        let [high, low] = *pair;
        *slot = (nibble(high)? << 4) | nibble(low)?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::identity::UnixSeconds;

    const A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn entry(site: &str, key_id: &str, key: &str) -> serde_json::Value {
        serde_json::json!({"tenant_id": "tenant_demo", "site_id": site, "key_id": key_id, "key_hex": key})
    }

    fn ring(entries: &[serde_json::Value]) -> Result<KeyRing, Box<dyn Error>> {
        KeyRing::parse("RING", &serde_json::to_string(entries).unwrap())
    }

    fn request<'a>(site: &'a str, key_id: &'a str, purpose: &'static str) -> KeyAccessQuery<'a> {
        KeyAccessQuery {
            tenant_id: "tenant_demo",
            site_id: site,
            key_id,
            purpose,
            at: UnixSeconds::new(5),
        }
    }

    #[test]
    fn serves_every_listed_site_and_key_id_and_nothing_else() {
        let keys = ring(&[
            entry("site_a", "orders-r1", A),
            entry("site_a", "orders-r2", B),
            entry("site_b", "orders-r1", B),
        ])
        .unwrap();
        let get = |site, key_id| {
            keys.request_decryption_key(request(site, key_id, "request_direct_decrypt"))
                .map(|key| *key)
        };
        assert_eq!(get("site_a", "orders-r1"), Ok([0x11; 32]));
        // Rotation: both key-ids of one site are served side by side.
        assert_eq!(get("site_a", "orders-r2"), Ok([0x22; 32]));
        assert_eq!(get("site_b", "orders-r1"), Ok([0x22; 32]));
        for (site, key_id) in [("site_b", "orders-r2"), ("site_c", "orders-r1")] {
            assert_eq!(
                get(site, key_id),
                Err(ReasonCode::RequestCryptoKeyUnavailable)
            );
        }
        let mut other_tenant = request("site_a", "orders-r1", "request_direct_decrypt");
        other_tenant.tenant_id = "tenant_other";
        let mut no_clock = request("site_a", "orders-r1", "request_direct_decrypt");
        no_clock.at = UnixSeconds::new(0);
        for query in [
            other_tenant,
            no_clock,
            request("site_a", "orders-r1", "response_direct_encrypt"),
        ] {
            assert!(keys.request_decryption_key(query).is_err());
        }
        let response = ResponseKeyAccessQuery {
            tenant_id: "tenant_demo",
            site_id: "site_a",
            key_id: "orders-r1",
            purpose: "response_direct_encrypt",
            at: UnixSeconds::new(5),
        };
        assert_eq!(
            keys.response_encryption_key(response).map(|key| *key),
            Ok([0x11; 32])
        );
    }

    #[test]
    fn refuses_malformed_or_ambiguous_rings_without_echoing_a_key() {
        let upper = "AB".repeat(32);
        let cases = [
            serde_json::json!([]),
            serde_json::json!({"tenant_id": "tenant_demo"}),
            serde_json::json!([entry("site_a", "k", &A[..62])]),
            serde_json::json!([entry("site_a", "k", &upper)]),
            serde_json::json!([entry("site/a", "k", A)]),
            serde_json::json!([entry("site_a", "", A)]),
            serde_json::json!([entry("site_a", "k/1", A)]),
            serde_json::json!([entry("site_a", "k", A), entry("site_a", "k", B)]),
            serde_json::json!([{"tenant_id": "tenant_demo", "site_id": "site_a",
                "key_id": "k", "key_hex": A, "note": "unknown fields are refused"}]),
        ];
        for case in cases {
            let error = KeyRing::parse("RING", &case.to_string())
                .err()
                .unwrap_or_else(|| panic!("{case} must be refused"))
                .to_string();
            assert!(error.starts_with("RING"), "{error}");
            assert!(
                !error.contains("1111") && !error.contains("2222"),
                "{error}"
            );
        }
        let too_many: Vec<_> = (0..=MAX_KEYS)
            .map(|index| entry("site_a", &format!("k{index}"), A))
            .collect();
        assert!(ring(&too_many).is_err());
    }

    #[test]
    fn detects_a_key_shared_between_directions() {
        let requests = ring(&[entry("site_a", "request-r1", A)]).unwrap();
        let distinct = ring(&[entry("site_a", "response-r1", B)]).unwrap();
        let reused = ring(&[entry("site_b", "response-r1", A)]).unwrap();
        assert!(!requests.shares_key_with(&distinct));
        assert!(requests.shares_key_with(&reused));
    }
}
