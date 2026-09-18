//! Versioned authenticated request decryption with immutable origin rebuilding.

use bytes::Bytes;
use openssl::{sha::sha256, symm::Cipher};
use serde_json::Value;
use uuid::Uuid;
use xshield_core::{audit::ReasonCode, identity::UnixSeconds};
use zeroize::Zeroizing;

use crate::response_grant::strict_json;

const SCHEMA_VERSION: u64 = 1;
const ALGORITHM: &str = "AES-256-GCM";
const ORIGIN_CONTENT_TYPE: &str = "application/json";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// Server-selected request protocol coverage for one operation.
#[derive(Debug)]
pub enum RequestCryptoPolicy {
    /// Authenticated decryption is mandatory and failures are terminal.
    Enforce(RequestCryptoRule),
    /// The original entity remains opaque and is forwarded unchanged.
    Observe(RequestCryptoObserveRule),
}

/// Validated metadata for an opaque observe-only request path.
#[derive(Debug)]
pub struct RequestCryptoObserveRule {
    pub(crate) adapter_revision: String,
}

impl RequestCryptoObserveRule {
    /// Returns the server-selected candidate adapter revision.
    #[must_use]
    pub fn adapter_revision(&self) -> &str {
        &self.adapter_revision
    }
}

struct ParsedEnvelope {
    message_id: String,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

/// Validated server-side rule for the first direct-decryption adapter.
#[derive(Debug)]
pub struct RequestCryptoRule {
    pub(crate) adapter_revision: String,
    pub(crate) key_id: String,
    pub(crate) key_not_before: UnixSeconds,
    pub(crate) key_expires_at: UnixSeconds,
    pub(crate) max_envelope_bytes: usize,
    pub(crate) max_plaintext_bytes: usize,
    pub(crate) max_message_age_seconds: u64,
    pub(crate) max_future_skew_seconds: u64,
    pub(crate) max_active_messages: u32,
}

/// Exact scope presented to the secret-access port.
pub struct KeyAccessQuery<'a> {
    /// Trusted tenant selected at startup.
    pub tenant_id: &'a str,
    /// Trusted site selected at startup.
    pub site_id: &'a str,
    /// Trusted adapter key identifier.
    pub key_id: &'a str,
    /// Fixed secret purpose; callers cannot request arbitrary material.
    pub purpose: &'static str,
    /// Trusted request time used for key-lease enforcement.
    pub at: UnixSeconds,
}

/// Port that returns one ephemeral, scope-checked request decryption key.
pub trait KeyAccessPort: Send + Sync {
    /// Loads an exact 256-bit key or returns a stable availability reason.
    ///
    /// # Errors
    /// Returns [`ReasonCode::RequestCryptoKeyUnavailable`] when the requested
    /// tenant, site, key identifier, or purpose is unavailable.
    fn request_decryption_key(
        &self,
        query: KeyAccessQuery<'_>,
    ) -> Result<Zeroizing<[u8; 32]>, ReasonCode>;
}

/// Digests and adapter identifiers safe for structured audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestCryptoEvidence {
    algorithm: &'static str,
    adapter_revision: String,
    key_id: String,
    message_id: String,
    nonce_sha256: String,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
    envelope_sha256: String,
    rebuilt_sha256: String,
}

impl RequestCryptoEvidence {
    /// Returns the fixed authenticated-encryption algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// Returns the exact adapter revision selected by trusted configuration.
    #[must_use]
    pub fn adapter_revision(&self) -> &str {
        &self.adapter_revision
    }

    /// Returns the non-secret key identifier used for decryption.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the canonical authenticated message identifier.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Returns the digest of the public nonce consumed by the replay ledger.
    #[must_use]
    pub fn nonce_sha256(&self) -> &str {
        &self.nonce_sha256
    }

    /// Returns the authenticated issue time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixSeconds {
        self.issued_at
    }

    /// Returns the authenticated expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    /// Returns the digest of the received envelope bytes.
    #[must_use]
    pub fn envelope_sha256(&self) -> &str {
        &self.envelope_sha256
    }

    /// Returns the digest of the exact rebuilt origin entity.
    #[must_use]
    pub fn rebuilt_sha256(&self) -> &str {
        &self.rebuilt_sha256
    }
}

/// Authenticated, validated request entity frozen for one origin dispatch.
pub struct FrozenRequest {
    body: Bytes,
    evidence: RequestCryptoEvidence,
    message_id: String,
    nonce: [u8; NONCE_BYTES],
    expires_at: UnixSeconds,
}

impl FrozenRequest {
    /// Returns the exact origin content type covered by the adapter AAD.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        ORIGIN_CONTENT_TYPE
    }

    /// Returns the byte length used to rebuild `Content-Length`.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Borrows audit-safe transformation evidence.
    #[must_use]
    pub const fn evidence(&self) -> &RequestCryptoEvidence {
        &self.evidence
    }

    /// Returns the authenticated canonical identifier consumed before dispatch.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Returns the authenticated key-scoped nonce consumed before dispatch.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// Returns the authenticated replay-record expiry.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    /// Moves the sole frozen entity into the Pingora body pipeline.
    #[must_use]
    pub fn into_body(self) -> Bytes {
        self.body
    }
}

impl RequestCryptoRule {
    /// Returns the fixed authenticated-encryption algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        ALGORITHM
    }

    /// Returns the maximum accepted serialized envelope size.
    #[must_use]
    pub const fn max_envelope_bytes(&self) -> usize {
        self.max_envelope_bytes
    }

    /// Returns the exact configured adapter revision.
    #[must_use]
    pub fn adapter_revision(&self) -> &str {
        &self.adapter_revision
    }

    /// Returns the exact configured key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the site-wide active replay-record bound.
    #[must_use]
    pub const fn max_active_messages(&self) -> u32 {
        self.max_active_messages
    }

    /// Authenticates, decrypts, validates, and freezes one request entity.
    ///
    /// The AAD binds the ciphertext to tenant, site, operation, HTTP semantics,
    /// adapter revision, key identifier, and rebuilt media type. No caller can
    /// construct a [`FrozenRequest`] from unrelated plaintext.
    ///
    /// # Errors
    /// Returns a stable denial reason for invalid envelopes, unavailable scoped
    /// keys, failed authentication, oversized plaintext, or invalid JSON.
    #[allow(clippy::too_many_arguments)]
    pub fn decode(
        &self,
        tenant_id: &str,
        site_id: &str,
        operation_id: &str,
        method: &str,
        path: &str,
        now: UnixSeconds,
        envelope: &[u8],
        keys: &dyn KeyAccessPort,
    ) -> Result<FrozenRequest, ReasonCode> {
        let parsed = parse_envelope(self, now, envelope)?;
        if now < self.key_not_before || now >= self.key_expires_at {
            return Err(ReasonCode::RequestCryptoKeyUnavailable);
        }
        let key = keys.request_decryption_key(KeyAccessQuery {
            tenant_id,
            site_id,
            key_id: &self.key_id,
            purpose: "request_direct_decrypt",
            at: now,
        })?;
        let aad = aad(
            tenant_id,
            site_id,
            operation_id,
            method,
            path,
            &self.adapter_revision,
            &self.key_id,
            &parsed.message_id,
            parsed.issued_at,
            parsed.expires_at,
        )?;
        let plaintext = openssl::symm::decrypt_aead(
            Cipher::aes_256_gcm(),
            key.as_ref(),
            Some(&parsed.nonce),
            &aad,
            &parsed.ciphertext,
            &parsed.tag,
        )
        .map_err(|_| ReasonCode::RequestCryptoAuthenticationFailed)?;
        if plaintext.is_empty() || plaintext.len() > self.max_plaintext_bytes {
            return Err(ReasonCode::RequestEnvelopeInvalid);
        }
        let plaintext = Zeroizing::new(plaintext);
        if !strict_json(&plaintext)
            .map_err(|_| ReasonCode::RequestEnvelopeInvalid)?
            .is_object()
        {
            return Err(ReasonCode::RequestEnvelopeInvalid);
        }
        let evidence = RequestCryptoEvidence {
            algorithm: ALGORITHM,
            adapter_revision: self.adapter_revision.clone(),
            key_id: self.key_id.clone(),
            message_id: parsed.message_id.clone(),
            nonce_sha256: hex(&sha256(&parsed.nonce)),
            issued_at: parsed.issued_at,
            expires_at: parsed.expires_at,
            envelope_sha256: hex(&sha256(envelope)),
            rebuilt_sha256: hex(&sha256(&plaintext)),
        };
        Ok(FrozenRequest {
            body: Bytes::copy_from_slice(&plaintext),
            evidence,
            message_id: parsed.message_id,
            nonce: parsed.nonce,
            expires_at: parsed.expires_at,
        })
    }
}

fn parse_envelope(
    rule: &RequestCryptoRule,
    now: UnixSeconds,
    envelope: &[u8],
) -> Result<ParsedEnvelope, ReasonCode> {
    if envelope.is_empty() || envelope.len() > rule.max_envelope_bytes {
        return Err(ReasonCode::RequestEnvelopeInvalid);
    }
    let value = strict_json(envelope).map_err(|_| ReasonCode::RequestEnvelopeInvalid)?;
    let object = value
        .as_object()
        .ok_or(ReasonCode::RequestEnvelopeInvalid)?;
    let expected = [
        "adapter_revision",
        "ciphertext",
        "expires_at",
        "issued_at",
        "key_id",
        "message_id",
        "nonce",
        "schema_version",
        "tag",
    ];
    if object.len() != expected.len()
        || expected.iter().any(|name| !object.contains_key(*name))
        || object.get("schema_version").and_then(Value::as_u64) != Some(SCHEMA_VERSION)
        || string(object, "adapter_revision")? != rule.adapter_revision
        || string(object, "key_id")? != rule.key_id
    {
        return Err(ReasonCode::RequestEnvelopeInvalid);
    }
    let issued_at = uint(object, "issued_at")?;
    let expires_at = uint(object, "expires_at")?;
    if expires_at <= now {
        return Err(ReasonCode::RequestCryptoMessageExpired);
    }
    if issued_at.value() > now.value().saturating_add(rule.max_future_skew_seconds) {
        return Err(ReasonCode::RequestCryptoMessageFromFuture);
    }
    if expires_at <= issued_at
        || expires_at.value().saturating_sub(issued_at.value()) > rule.max_message_age_seconds
        || issued_at < rule.key_not_before
        || expires_at > rule.key_expires_at
    {
        return Err(ReasonCode::RequestEnvelopeInvalid);
    }
    Ok(ParsedEnvelope {
        message_id: canonical_message_id(string(object, "message_id")?)?,
        issued_at,
        expires_at,
        nonce: decode_hex_exact(string(object, "nonce")?, NONCE_BYTES)?
            .try_into()
            .map_err(|_| ReasonCode::RequestEnvelopeInvalid)?,
        ciphertext: decode_hex(string(object, "ciphertext")?, rule.max_plaintext_bytes)?,
        tag: decode_hex_exact(string(object, "tag")?, TAG_BYTES)?,
    })
}

fn uint(object: &serde_json::Map<String, Value>, name: &str) -> Result<UnixSeconds, ReasonCode> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .map(UnixSeconds::new)
        .ok_or(ReasonCode::RequestEnvelopeInvalid)
}

fn string<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, ReasonCode> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(ReasonCode::RequestEnvelopeInvalid)
}

fn decode_hex_exact(value: &str, expected: usize) -> Result<Vec<u8>, ReasonCode> {
    let bytes = decode_hex(value, expected)?;
    if bytes.len() != expected {
        return Err(ReasonCode::RequestEnvelopeInvalid);
    }
    Ok(bytes)
}

fn decode_hex(value: &str, max_bytes: usize) -> Result<Vec<u8>, ReasonCode> {
    if !value.len().is_multiple_of(2) || value.len() > max_bytes.saturating_mul(2) {
        return Err(ReasonCode::RequestEnvelopeInvalid);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn canonical_message_id(value: &str) -> Result<String, ReasonCode> {
    let uuid = value
        .strip_prefix("msg_")
        .and_then(|value| Uuid::parse_str(value).ok())
        .filter(|uuid| uuid.get_version_num() == 7)
        .ok_or(ReasonCode::RequestEnvelopeInvalid)?;
    let canonical = format!("msg_{uuid}");
    if canonical != value {
        return Err(ReasonCode::RequestEnvelopeInvalid);
    }
    Ok(canonical)
}

fn hex_nibble(value: u8) -> Result<u8, ReasonCode> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ReasonCode::RequestEnvelopeInvalid),
    }
}

#[allow(clippy::too_many_arguments)]
fn aad(
    tenant_id: &str,
    site_id: &str,
    operation_id: &str,
    method: &str,
    path: &str,
    adapter_revision: &str,
    key_id: &str,
    message_id: &str,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
) -> Result<Vec<u8>, ReasonCode> {
    let issued_at = issued_at.value().to_string();
    let expires_at = expires_at.value().to_string();
    let mut output = Vec::new();
    for value in [
        "xshield.request.direct-decrypt.v1",
        tenant_id,
        site_id,
        operation_id,
        method,
        path,
        adapter_revision,
        key_id,
        message_id,
        &issued_at,
        &expires_at,
        ORIGIN_CONTENT_TYPE,
    ] {
        let length = u32::try_from(value.len()).map_err(|_| ReasonCode::RequestEnvelopeInvalid)?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(value.as_bytes());
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::symm::encrypt_aead;
    use serde_json::json;

    struct TestKeys;

    impl KeyAccessPort for TestKeys {
        fn request_decryption_key(
            &self,
            query: KeyAccessQuery<'_>,
        ) -> Result<Zeroizing<[u8; 32]>, ReasonCode> {
            assert_eq!(query.tenant_id, "tenant_demo");
            assert_eq!(query.site_id, "site_demo");
            assert_eq!(query.key_id, "request-key-r1");
            assert_eq!(query.purpose, "request_direct_decrypt");
            assert_eq!(query.at, UnixSeconds::new(5));
            Ok(Zeroizing::new([7; 32]))
        }
    }

    fn rule() -> RequestCryptoRule {
        RequestCryptoRule {
            adapter_revision: "orders-json-r1".to_owned(),
            key_id: "request-key-r1".to_owned(),
            max_envelope_bytes: 4096,
            max_plaintext_bytes: 1024,
            max_message_age_seconds: 5,
            max_future_skew_seconds: 1,
            max_active_messages: 100,
            key_not_before: UnixSeconds::new(1),
            key_expires_at: UnixSeconds::new(10),
        }
    }

    fn envelope(path: &str) -> Vec<u8> {
        let rule = rule();
        let nonce = [3; NONCE_BYTES];
        let message_id = "msg_018f2a3b-4c5d-7000-8000-000000000901";
        let issued_at = UnixSeconds::new(4);
        let expires_at = UnixSeconds::new(9);
        let mut tag = [0; TAG_BYTES];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &[7; 32],
            Some(&nonce),
            &aad(
                "tenant_demo",
                "site_demo",
                "orders.create",
                "POST",
                path,
                rule.adapter_revision(),
                rule.key_id(),
                message_id,
                issued_at,
                expires_at,
            )
            .unwrap(),
            br#"{"sku":"A-1","quantity":2}"#,
            &mut tag,
        )
        .unwrap();
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "adapter_revision": rule.adapter_revision(),
            "key_id": rule.key_id(),
            "message_id": message_id,
            "issued_at": issued_at.value(),
            "expires_at": expires_at.value(),
            "nonce": hex(&nonce),
            "ciphertext": hex(&ciphertext),
            "tag": hex(&tag),
        }))
        .unwrap()
    }

    #[test]
    fn decrypts_only_the_exact_bound_request() {
        let rule = rule();
        let envelope = envelope("/orders");
        let frozen = rule
            .decode(
                "tenant_demo",
                "site_demo",
                "orders.create",
                "POST",
                "/orders",
                UnixSeconds::new(5),
                &envelope,
                &TestKeys,
            )
            .unwrap();
        assert_eq!(
            frozen.body,
            Bytes::from_static(br#"{"sku":"A-1","quantity":2}"#)
        );
        assert_eq!(frozen.content_type(), ORIGIN_CONTENT_TYPE);

        assert!(matches!(
            rule.decode(
                "tenant_demo",
                "site_demo",
                "orders.create",
                "POST",
                "/orders",
                UnixSeconds::new(10),
                &envelope,
                &TestKeys,
            ),
            Err(ReasonCode::RequestCryptoMessageExpired)
        ));

        assert!(matches!(
            rule.decode(
                "tenant_demo",
                "site_demo",
                "orders.create",
                "POST",
                "/orders/other",
                UnixSeconds::new(5),
                &envelope,
                &TestKeys,
            ),
            Err(ReasonCode::RequestCryptoAuthenticationFailed)
        ));
        let mut tampered: Value = serde_json::from_slice(&envelope).unwrap();
        tampered["tag"] = Value::String("00".repeat(TAG_BYTES));
        assert!(matches!(
            rule.decode(
                "tenant_demo",
                "site_demo",
                "orders.create",
                "POST",
                "/orders",
                UnixSeconds::new(5),
                &serde_json::to_vec(&tampered).unwrap(),
                &TestKeys,
            ),
            Err(ReasonCode::RequestCryptoAuthenticationFailed)
        ));
    }
}
