//! Versioned authenticated response encryption with immutable client output.

use bytes::Bytes;
use openssl::{
    rand::rand_bytes,
    sha::sha256,
    symm::{Cipher, Crypter, Mode},
};
use serde::{Serialize, Serializer};
use std::fmt;
use uuid::Uuid;
use xshield_core::{audit::ReasonCode, identity::UnixSeconds};
use zeroize::Zeroizing;

use crate::response_grant::strict_json;

const SCHEMA_VERSION: u64 = 1;
const ALGORITHM: &str = "AES-256-GCM";
const ORIGIN_CONTENT_TYPE: &str = "application/json";
/// Exact media type emitted by the direct-encryption adapter.
pub const ENCRYPTED_RESPONSE_CONTENT_TYPE: &str = "application/vnd.xshield.encrypted+json";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// Validated server-side direct-encryption rule.
#[derive(Debug)]
pub struct ResponseCryptoRule {
    pub(crate) adapter_revision: String,
    pub(crate) key_id: String,
    pub(crate) key_not_before: UnixSeconds,
    pub(crate) key_expires_at: UnixSeconds,
    pub(crate) message_ttl_seconds: u64,
    pub(crate) max_envelope_bytes: usize,
    pub(crate) max_in_flight_bytes: usize,
}

/// Exact scope presented to the response-key access port.
pub struct ResponseKeyAccessQuery<'a> {
    /// Trusted tenant selected at startup.
    pub tenant_id: &'a str,
    /// Trusted site selected at startup.
    pub site_id: &'a str,
    /// Trusted response key identifier.
    pub key_id: &'a str,
    /// Fixed secret purpose; callers cannot request arbitrary material.
    pub purpose: &'static str,
    /// Trusted response time used for key-lease enforcement.
    pub at: UnixSeconds,
}

/// Port returning one ephemeral, scope-checked response encryption key.
pub trait ResponseKeyAccessPort: Send + Sync {
    /// Loads an exact 256-bit response key.
    ///
    /// # Errors
    /// Returns [`ReasonCode::ResponseCryptoKeyUnavailable`] when the exact key
    /// scope or purpose is unavailable.
    fn response_encryption_key(
        &self,
        query: ResponseKeyAccessQuery<'_>,
    ) -> Result<Zeroizing<[u8; 32]>, ReasonCode>;
}

/// Non-secret response transformation evidence for durable audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseCryptoEvidence {
    algorithm: &'static str,
    adapter_revision: String,
    key_id: String,
    message_id: String,
    nonce_sha256: String,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
    origin_sha256: String,
    envelope_sha256: String,
}

impl ResponseCryptoEvidence {
    /// Returns the authenticated-encryption algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// Returns the selected adapter revision.
    #[must_use]
    pub fn adapter_revision(&self) -> &str {
        &self.adapter_revision
    }

    /// Returns the non-secret response key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the generated canonical message identifier.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Returns the generated nonce digest.
    #[must_use]
    pub fn nonce_sha256(&self) -> &str {
        &self.nonce_sha256
    }

    /// Returns the response message issue time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixSeconds {
        self.issued_at
    }

    /// Returns the response message expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    /// Returns the digest of the exact transformed origin entity.
    #[must_use]
    pub fn origin_sha256(&self) -> &str {
        &self.origin_sha256
    }

    /// Returns the digest of the exact client envelope.
    #[must_use]
    pub fn envelope_sha256(&self) -> &str {
        &self.envelope_sha256
    }
}

/// Frozen encrypted client response and its audit evidence.
pub struct EncryptedResponse {
    body: Bytes,
    evidence: ResponseCryptoEvidence,
}

impl EncryptedResponse {
    /// Returns the exact serialized client entity length.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Borrows audit-safe transformation evidence.
    #[must_use]
    pub const fn evidence(&self) -> &ResponseCryptoEvidence {
        &self.evidence
    }

    /// Moves the sole frozen envelope into the response pipeline.
    #[must_use]
    pub fn into_body(self) -> Bytes {
        self.body
    }
}

impl ResponseCryptoRule {
    /// Returns the fixed authenticated-encryption algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> &'static str {
        ALGORITHM
    }

    /// Returns the selected adapter revision.
    #[must_use]
    pub fn adapter_revision(&self) -> &str {
        &self.adapter_revision
    }

    /// Returns the selected response key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the aggregate reservation for plaintext, ciphertext, and envelope buffers.
    #[must_use]
    pub const fn max_in_flight_bytes(&self) -> usize {
        self.max_in_flight_bytes
    }

    /// Encrypts one validated origin JSON entity for the exact client request.
    ///
    /// The AAD binds status and request identity in addition to route, adapter,
    /// key, message, time, and media-type metadata.
    ///
    /// # Errors
    /// Returns a stable reason when the key lease, JSON entity, randomness,
    /// encryption, or configured envelope bound cannot be satisfied.
    #[allow(clippy::too_many_arguments)]
    pub fn encode(
        &self,
        tenant_id: &str,
        site_id: &str,
        operation_id: &str,
        request_id: &str,
        method: &str,
        path: &str,
        status: u16,
        now: UnixSeconds,
        origin: &[u8],
        keys: &dyn ResponseKeyAccessPort,
    ) -> Result<EncryptedResponse, ReasonCode> {
        if !strict_json(origin)
            .map_err(|_| ReasonCode::ResponseValidationFailed)?
            .is_object()
        {
            return Err(ReasonCode::ResponseValidationFailed);
        }
        let expires_at = now
            .value()
            .checked_add(self.message_ttl_seconds)
            .map(UnixSeconds::new)
            .filter(|expires_at| *expires_at <= self.key_expires_at)
            .ok_or(ReasonCode::ResponseCryptoKeyUnavailable)?;
        if now < self.key_not_before || now >= self.key_expires_at {
            return Err(ReasonCode::ResponseCryptoKeyUnavailable);
        }
        let key = keys.response_encryption_key(ResponseKeyAccessQuery {
            tenant_id,
            site_id,
            key_id: &self.key_id,
            purpose: "response_direct_encrypt",
            at: now,
        })?;
        let message_id = format!("msg_{}", Uuid::now_v7());
        let mut nonce = [0; NONCE_BYTES];
        rand_bytes(&mut nonce).map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)?;
        let cipher = Cipher::aes_256_gcm();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, key.as_ref(), Some(&nonce))
            .map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)?;
        visit_aad(
            tenant_id,
            site_id,
            operation_id,
            request_id,
            method,
            path,
            status,
            &self.adapter_revision,
            &self.key_id,
            &message_id,
            now,
            expires_at,
            |part| {
                crypter
                    .aad_update(part)
                    .map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)
            },
        )?;
        let ciphertext_capacity = origin
            .len()
            .checked_add(cipher.block_size())
            .ok_or(ReasonCode::ResponseCryptoEncodingFailed)?;
        let mut ciphertext = Vec::new();
        ciphertext
            .try_reserve_exact(ciphertext_capacity)
            .map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)?;
        ciphertext.resize(ciphertext_capacity, 0);
        let count = crypter
            .update(origin, &mut ciphertext)
            .map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)?;
        let rest = crypter
            .finalize(&mut ciphertext[count..])
            .map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)?;
        let mut tag = [0; TAG_BYTES];
        crypter
            .get_tag(&mut tag)
            .map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)?;
        ciphertext.truncate(count + rest);
        let body = serialize_envelope(
            self,
            &message_id,
            now,
            expires_at,
            &nonce,
            &ciphertext,
            &tag,
        )?;
        if body.len() > self.max_envelope_bytes {
            return Err(ReasonCode::ResponseCryptoEnvelopeTooLarge);
        }
        let evidence = ResponseCryptoEvidence {
            algorithm: ALGORITHM,
            adapter_revision: self.adapter_revision.clone(),
            key_id: self.key_id.clone(),
            message_id,
            nonce_sha256: hex(&sha256(&nonce)),
            issued_at: now,
            expires_at,
            origin_sha256: hex(&sha256(origin)),
            envelope_sha256: hex(&sha256(&body)),
        };
        Ok(EncryptedResponse {
            body: Bytes::from(body),
            evidence,
        })
    }
}

#[derive(Serialize)]
struct Envelope<'a> {
    schema_version: u64,
    adapter_revision: &'a str,
    key_id: &'a str,
    message_id: &'a str,
    issued_at: u64,
    expires_at: u64,
    nonce: Hex<'a>,
    ciphertext: Hex<'a>,
    tag: Hex<'a>,
}

fn serialize_envelope(
    rule: &ResponseCryptoRule,
    message_id: &str,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, ReasonCode> {
    let mut body = Vec::new();
    body.try_reserve_exact(rule.max_envelope_bytes)
        .map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)?;
    serde_json::to_writer(
        &mut body,
        &Envelope {
            schema_version: SCHEMA_VERSION,
            adapter_revision: &rule.adapter_revision,
            key_id: &rule.key_id,
            message_id,
            issued_at: issued_at.value(),
            expires_at: expires_at.value(),
            nonce: Hex(nonce),
            ciphertext: Hex(ciphertext),
            tag: Hex(tag),
        },
    )
    .map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)?;
    Ok(body)
}

struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        const INPUT_CHUNK_BYTES: usize = 512;
        let mut encoded = [0; INPUT_CHUNK_BYTES * 2];
        for chunk in self.0.chunks(INPUT_CHUNK_BYTES) {
            for (index, byte) in chunk.iter().enumerate() {
                encoded[index * 2] = DIGITS[usize::from(byte >> 4)];
                encoded[index * 2 + 1] = DIGITS[usize::from(byte & 0x0f)];
            }
            let encoded =
                std::str::from_utf8(&encoded[..chunk.len() * 2]).map_err(|_| fmt::Error)?;
            formatter.write_str(encoded)?;
        }
        Ok(())
    }
}

impl Serialize for Hex<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

#[allow(clippy::too_many_arguments)]
fn visit_aad(
    tenant_id: &str,
    site_id: &str,
    operation_id: &str,
    request_id: &str,
    method: &str,
    path: &str,
    status: u16,
    adapter_revision: &str,
    key_id: &str,
    message_id: &str,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
    mut visit: impl FnMut(&[u8]) -> Result<(), ReasonCode>,
) -> Result<(), ReasonCode> {
    let status = status.to_string();
    let issued_at = issued_at.value().to_string();
    let expires_at = expires_at.value().to_string();
    for value in [
        "xshield.response.direct-encrypt.v1",
        tenant_id,
        site_id,
        operation_id,
        request_id,
        method,
        path,
        &status,
        adapter_revision,
        key_id,
        message_id,
        &issued_at,
        &expires_at,
        ORIGIN_CONTENT_TYPE,
        ENCRYPTED_RESPONSE_CONTENT_TYPE,
    ] {
        let length =
            u32::try_from(value.len()).map_err(|_| ReasonCode::ResponseCryptoEncodingFailed)?;
        visit(&length.to_be_bytes())?;
        visit(value.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn aad(
    tenant_id: &str,
    site_id: &str,
    operation_id: &str,
    request_id: &str,
    method: &str,
    path: &str,
    status: u16,
    adapter_revision: &str,
    key_id: &str,
    message_id: &str,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
) -> Result<Vec<u8>, ReasonCode> {
    let mut output = Vec::new();
    visit_aad(
        tenant_id,
        site_id,
        operation_id,
        request_id,
        method,
        path,
        status,
        adapter_revision,
        key_id,
        message_id,
        issued_at,
        expires_at,
        |part| {
            output.extend_from_slice(part);
            Ok(())
        },
    )?;
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
    use openssl::symm::decrypt_aead;

    struct TestKeys;

    impl ResponseKeyAccessPort for TestKeys {
        fn response_encryption_key(
            &self,
            query: ResponseKeyAccessQuery<'_>,
        ) -> Result<Zeroizing<[u8; 32]>, ReasonCode> {
            assert_eq!(query.tenant_id, "tenant_demo");
            assert_eq!(query.site_id, "site_demo");
            assert_eq!(query.key_id, "response-key-r1");
            assert_eq!(query.purpose, "response_direct_encrypt");
            assert_eq!(query.at, UnixSeconds::new(5));
            Ok(Zeroizing::new([9; 32]))
        }
    }

    #[test]
    fn encrypts_only_for_the_exact_response_context() {
        let rule = ResponseCryptoRule {
            adapter_revision: "orders-response-r1".to_owned(),
            key_id: "response-key-r1".to_owned(),
            key_not_before: UnixSeconds::new(1),
            key_expires_at: UnixSeconds::new(100),
            message_ttl_seconds: 30,
            max_envelope_bytes: 4096,
            max_in_flight_bytes: 8238,
        };
        assert_eq!(rule.max_in_flight_bytes(), 8238);
        let encrypted = rule
            .encode(
                "tenant_demo",
                "site_demo",
                "orders.read",
                "req_018f2a3b-4c5d-7000-8000-000000000901",
                "GET",
                "/orders",
                200,
                UnixSeconds::new(5),
                br#"{"orders":[1]}"#,
                &TestKeys,
            )
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&encrypted.body).unwrap();
        let nonce = decode_hex(envelope["nonce"].as_str().unwrap());
        let ciphertext = decode_hex(envelope["ciphertext"].as_str().unwrap());
        let tag = decode_hex(envelope["tag"].as_str().unwrap());
        let issued_at = UnixSeconds::new(envelope["issued_at"].as_u64().unwrap());
        let expires_at = UnixSeconds::new(envelope["expires_at"].as_u64().unwrap());
        let aad = aad(
            "tenant_demo",
            "site_demo",
            "orders.read",
            "req_018f2a3b-4c5d-7000-8000-000000000901",
            "GET",
            "/orders",
            200,
            "orders-response-r1",
            "response-key-r1",
            envelope["message_id"].as_str().unwrap(),
            issued_at,
            expires_at,
        )
        .unwrap();
        assert_eq!(
            decrypt_aead(
                Cipher::aes_256_gcm(),
                &[9; 32],
                Some(&nonce),
                &aad,
                &ciphertext,
                &tag,
            )
            .unwrap(),
            br#"{"orders":[1]}"#
        );
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let nibble = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => 0,
                };
                (nibble(pair[0]) << 4) | nibble(pair[1])
            })
            .collect()
    }
}
