//! Versioned authenticated request decryption with immutable origin rebuilding.

use bytes::Bytes;
use openssl::{sha::sha256, symm::Cipher};
use serde_json::Value;
use uuid::Uuid;
use xshield_core::provenance::BuildFingerprint;
use xshield_core::{audit::ReasonCode, identity::UnixSeconds};
use zeroize::Zeroizing;

use crate::response_grant::strict_json;

const SCHEMA_VERSION: u64 = 1;
const ALGORITHM: &str = "AES-256-GCM";
const ORIGIN_CONTENT_TYPE: &str = "application/json";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const DIRECT_DECRYPT_PROTOCOL_LABEL: &str = "xshield.request.direct-decrypt.v1";

/// AAD protocol label for `ENVELOPE_HOOK` (docs/08 §8.1): distinct from
/// [`DIRECT_DECRYPT_PROTOCOL_LABEL`] so the two modes' envelopes can never be
/// cross-decrypted, even if a key happened to collide.
const ENVELOPE_HOOK_PROTOCOL_LABEL: &str = "xshield.request.envelope-hook.v1";

/// Prefix of every `ENVELOPE_HOOK` envelope's presented `key_id`, naming the
/// session-key time window it was encrypted under (see
/// [`envelope_hook_key_window`]). There is no statically configured key, so
/// unlike `DIRECT_DECRYPT` this is a dynamic label, not a fixed value.
pub const ENVELOPE_HOOK_KEY_ID_PREFIX: &str = "ehk.";

/// Rotation period for the `ENVELOPE_HOOK` session key (docs/08 §8.1 / Option
/// A). A message encrypted just before rollover is still accepted during the
/// grace window: [`RequestCryptoEnvelopeHookRule::decode`] accepts the
/// current window's key or the immediately preceding one.
pub const ENVELOPE_HOOK_KEY_WINDOW_SECONDS: u64 = 3600;

/// Returns the window index covering `now`. Key derivation (issued at
/// bootstrap) and decode-time validation (at live-request time) must divide
/// time identically, so both sides call this one function.
#[must_use]
pub const fn envelope_hook_key_window(now: UnixSeconds) -> u64 {
    now.value() / ENVELOPE_HOOK_KEY_WINDOW_SECONDS
}

/// Returns the exact `key_id` a sensor must present for messages encrypted
/// under the session key issued for `window`.
#[must_use]
pub fn envelope_hook_key_id(window: u64) -> String {
    format!("{ENVELOPE_HOOK_KEY_ID_PREFIX}{window}")
}

/// Server-selected request protocol coverage for one operation.
#[derive(Debug)]
pub enum RequestCryptoPolicy {
    /// Authenticated decryption is mandatory and failures are terminal.
    Enforce(RequestCryptoRule),
    /// The original entity remains opaque and is forwarded unchanged.
    Observe(RequestCryptoObserveRule),
    /// A time-bound approved page build may use its original protocol.
    Compatibility(RequestCryptoCompatibilityRule),
    /// Injected business-entry-point encryption, keyed per authenticated
    /// session rather than by a statically configured key (docs/08 §8.1).
    EnvelopeHook(RequestCryptoEnvelopeHookRule),
}

/// Validated server approval for one bounded compatibility scope.
#[derive(Debug)]
pub struct RequestCryptoCompatibilityRule {
    pub(crate) adapter_revision: String,
    pub(crate) approval_ref: String,
    pub(crate) expires_at: UnixSeconds,
    pub(crate) build_fingerprints: Vec<BuildFingerprint>,
}

impl RequestCryptoCompatibilityRule {
    /// Returns the compatibility candidate adapter revision.
    #[must_use]
    pub fn adapter_revision(&self) -> &str {
        &self.adapter_revision
    }

    /// Returns the server-side approval reference used for audit.
    #[must_use]
    pub fn approval_ref(&self) -> &str {
        &self.approval_ref
    }

    /// Checks the approval lease and exact verified page build.
    ///
    /// # Errors
    /// Returns a stable reason when the approval expired or the page build is
    /// absent from the configured allowlist.
    pub fn authorize(
        &self,
        now: UnixSeconds,
        build_fingerprint: &BuildFingerprint,
    ) -> Result<(), ReasonCode> {
        if now >= self.expires_at {
            return Err(ReasonCode::RequestCryptoCompatibilityExpired);
        }
        if !self
            .build_fingerprints
            .iter()
            .any(|approved| approved == build_fingerprint)
        {
            return Err(ReasonCode::RequestCryptoBuildNotApproved);
        }
        Ok(())
    }
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
    key_id: String,
    message_id: String,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

/// Structural bounds [`parse_envelope`] enforces before any cryptography runs.
/// Shared by every [`RequestCryptoPolicy::Enforce`] variant so the envelope
/// shape, size limits, and lifetime checks stay identical; only the key
/// identifier and key-lease window differ per adapter.
struct EnvelopeBounds<'a> {
    adapter_revision: &'a str,
    /// `Some` pins the presented `key_id` to this exact static value
    /// (`DIRECT_DECRYPT`); `None` accepts whatever the caller presents, since
    /// `ENVELOPE_HOOK` has no statically configured key (docs/08 §8.1).
    expected_key_id: Option<&'a str>,
    max_envelope_bytes: usize,
    max_plaintext_bytes: usize,
    max_message_age_seconds: u64,
    max_future_skew_seconds: u64,
    /// `Some` additionally requires the message's lifetime to sit inside this
    /// key's configured lease window (`DIRECT_DECRYPT` only).
    key_lease: Option<(UnixSeconds, UnixSeconds)>,
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
    pub(crate) max_in_flight_bytes: usize,
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

    /// Returns the shared-memory reservation required before buffering.
    #[must_use]
    pub const fn max_in_flight_bytes(&self) -> usize {
        self.max_in_flight_bytes
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
        let bounds = EnvelopeBounds {
            adapter_revision: &self.adapter_revision,
            expected_key_id: Some(&self.key_id),
            max_envelope_bytes: self.max_envelope_bytes,
            max_plaintext_bytes: self.max_plaintext_bytes,
            max_message_age_seconds: self.max_message_age_seconds,
            max_future_skew_seconds: self.max_future_skew_seconds,
            key_lease: Some((self.key_not_before, self.key_expires_at)),
        };
        let parsed = parse_envelope(&bounds, now, envelope)?;
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
            DIRECT_DECRYPT_PROTOCOL_LABEL,
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

/// Validated server-side rule for injected business-entry-point encryption,
/// keyed per authenticated session rather than by a statically configured key
/// (docs/08 §8.1, Option A). Unlike [`RequestCryptoRule`] it carries no
/// `key_id`, no key-lease window, and no [`KeyAccessPort`]: the caller derives
/// the session key independently (see `envelope_hook_key` on the identity
/// adapter) and presents it through [`EnvelopeHookKeys`].
#[derive(Debug)]
pub struct RequestCryptoEnvelopeHookRule {
    pub(crate) adapter_revision: String,
    pub(crate) max_envelope_bytes: usize,
    pub(crate) max_plaintext_bytes: usize,
    pub(crate) max_message_age_seconds: u64,
    pub(crate) max_future_skew_seconds: u64,
    pub(crate) max_active_messages: u32,
    pub(crate) max_in_flight_bytes: usize,
}

/// The session-bound symmetric keys a caller derived for the current and
/// (if distinct) immediately preceding time window, so a message encrypted
/// just before rollover still decodes during the grace period.
pub struct EnvelopeHookKeys {
    current_window: u64,
    current_key: Zeroizing<[u8; 32]>,
    previous: Option<(u64, Zeroizing<[u8; 32]>)>,
}

impl EnvelopeHookKeys {
    /// Builds the two-window key set `decode` validates a presented `key_id`
    /// against.
    #[must_use]
    pub const fn new(
        current_window: u64,
        current_key: Zeroizing<[u8; 32]>,
        previous: Option<(u64, Zeroizing<[u8; 32]>)>,
    ) -> Self {
        Self {
            current_window,
            current_key,
            previous,
        }
    }

    fn key_for_window(&self, window: u64) -> Option<&[u8; 32]> {
        if window == self.current_window {
            return Some(&self.current_key);
        }
        self.previous
            .as_ref()
            .and_then(|(previous_window, key)| (window == *previous_window).then_some(&**key))
    }
}

impl RequestCryptoEnvelopeHookRule {
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

    /// Returns the site-wide active replay-record bound.
    #[must_use]
    pub const fn max_active_messages(&self) -> u32 {
        self.max_active_messages
    }

    /// Returns the shared-memory reservation required before buffering.
    #[must_use]
    pub const fn max_in_flight_bytes(&self) -> usize {
        self.max_in_flight_bytes
    }

    /// Authenticates, decrypts, validates, and freezes one request entity
    /// using a session-derived key rather than a statically configured one.
    ///
    /// The presented `key_id` must name a window `keys` was derived for; any
    /// other value is refused before any cryptography runs. The AAD binds
    /// the ciphertext to tenant, site, operation, HTTP semantics, adapter
    /// revision, the presented key identifier, and rebuilt media type.
    ///
    /// # Errors
    /// Returns a stable denial reason for invalid envelopes, an unrecognized
    /// key window, failed authentication, oversized plaintext, or invalid
    /// JSON.
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
        keys: &EnvelopeHookKeys,
    ) -> Result<FrozenRequest, ReasonCode> {
        let bounds = EnvelopeBounds {
            adapter_revision: &self.adapter_revision,
            expected_key_id: None,
            max_envelope_bytes: self.max_envelope_bytes,
            max_plaintext_bytes: self.max_plaintext_bytes,
            max_message_age_seconds: self.max_message_age_seconds,
            max_future_skew_seconds: self.max_future_skew_seconds,
            key_lease: None,
        };
        let parsed = parse_envelope(&bounds, now, envelope)?;
        let window = parsed
            .key_id
            .strip_prefix(ENVELOPE_HOOK_KEY_ID_PREFIX)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(ReasonCode::RequestCryptoKeyUnavailable)?;
        let key = keys
            .key_for_window(window)
            .ok_or(ReasonCode::RequestCryptoKeyUnavailable)?;
        let aad = aad(
            ENVELOPE_HOOK_PROTOCOL_LABEL,
            tenant_id,
            site_id,
            operation_id,
            method,
            path,
            &self.adapter_revision,
            &parsed.key_id,
            &parsed.message_id,
            parsed.issued_at,
            parsed.expires_at,
        )?;
        let plaintext = openssl::symm::decrypt_aead(
            Cipher::aes_256_gcm(),
            key,
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
            key_id: parsed.key_id.clone(),
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
    bounds: &EnvelopeBounds<'_>,
    now: UnixSeconds,
    envelope: &[u8],
) -> Result<ParsedEnvelope, ReasonCode> {
    if envelope.is_empty() || envelope.len() > bounds.max_envelope_bytes {
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
    let key_id = string(object, "key_id")?;
    if object.len() != expected.len()
        || expected.iter().any(|name| !object.contains_key(*name))
        || object.get("schema_version").and_then(Value::as_u64) != Some(SCHEMA_VERSION)
        || string(object, "adapter_revision")? != bounds.adapter_revision
        || bounds
            .expected_key_id
            .is_some_and(|expected_key_id| key_id != expected_key_id)
    {
        return Err(ReasonCode::RequestEnvelopeInvalid);
    }
    let issued_at = uint(object, "issued_at")?;
    let expires_at = uint(object, "expires_at")?;
    if expires_at <= now {
        return Err(ReasonCode::RequestCryptoMessageExpired);
    }
    if issued_at.value() > now.value().saturating_add(bounds.max_future_skew_seconds) {
        return Err(ReasonCode::RequestCryptoMessageFromFuture);
    }
    let (key_not_before, key_expires_at) = bounds
        .key_lease
        .unwrap_or((UnixSeconds::new(0), UnixSeconds::new(u64::MAX)));
    if expires_at <= issued_at
        || expires_at.value().saturating_sub(issued_at.value()) > bounds.max_message_age_seconds
        || issued_at < key_not_before
        || expires_at > key_expires_at
    {
        return Err(ReasonCode::RequestEnvelopeInvalid);
    }
    Ok(ParsedEnvelope {
        key_id: key_id.to_owned(),
        message_id: canonical_message_id(string(object, "message_id")?)?,
        issued_at,
        expires_at,
        nonce: decode_hex_exact(string(object, "nonce")?, NONCE_BYTES)?
            .try_into()
            .map_err(|_| ReasonCode::RequestEnvelopeInvalid)?,
        ciphertext: decode_hex(string(object, "ciphertext")?, bounds.max_plaintext_bytes)?,
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
        .as_chunks::<2>()
        .0
        .iter()
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
    protocol_label: &str,
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
        protocol_label,
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
            max_in_flight_bytes: 16_384,
            key_not_before: UnixSeconds::new(1),
            key_expires_at: UnixSeconds::new(10),
        }
    }

    /// One named way to damage an otherwise valid envelope.
    type Mutation = (&'static str, fn(&mut Value));

    fn envelope(path: &str) -> Vec<u8> {
        envelope_with_plaintext(path, br#"{"sku":"A-1","quantity":2}"#)
    }

    /// A correctly encrypted and bound envelope around arbitrary plaintext, so a
    /// test can reach the checks that only run after authentication succeeds.
    fn envelope_with_plaintext(path: &str, plaintext: &[u8]) -> Vec<u8> {
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
                DIRECT_DECRYPT_PROTOCOL_LABEL,
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
            plaintext,
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

    fn decode_at_five(
        rule: &RequestCryptoRule,
        envelope: &[u8],
    ) -> Result<FrozenRequest, ReasonCode> {
        rule.decode(
            "tenant_demo",
            "site_demo",
            "orders.create",
            "POST",
            "/orders",
            UnixSeconds::new(5),
            envelope,
            &TestKeys,
        )
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

    // The entity the edge checked is the entity it dispatches: the frozen body
    // can only be moved out whole, its audited digest names exactly those
    // bytes, and the same sealed P cannot be re-aimed at another operation,
    // method or route after the decision, because each is bound by the AAD.
    #[test]
    fn the_dispatched_entity_is_the_checked_plaintext_and_cannot_be_retargeted() {
        let rule = rule();
        let plaintext = br#"{"sku":"A-1","quantity":2}"#;
        let envelope = envelope("/orders");
        let frozen = decode_at_five(&rule, &envelope).unwrap();
        assert_eq!(frozen.evidence().rebuilt_sha256(), hex(&sha256(plaintext)));
        assert_eq!(frozen.evidence().envelope_sha256(), hex(&sha256(&envelope)));
        assert_eq!(frozen.body_len(), plaintext.len());
        let digest = frozen.evidence().rebuilt_sha256().to_owned();
        let dispatched = frozen.into_body();
        assert_eq!(dispatched, Bytes::from_static(plaintext));
        assert_eq!(hex(&sha256(&dispatched)), digest);

        for (operation_id, method, path) in [
            ("orders.delete", "POST", "/orders"),
            ("orders.create", "PUT", "/orders"),
            ("orders.create", "POST", "/orders/1"),
        ] {
            assert!(
                matches!(
                    rule.decode(
                        "tenant_demo",
                        "site_demo",
                        operation_id,
                        method,
                        path,
                        UnixSeconds::new(5),
                        &envelope,
                        &TestKeys,
                    ),
                    Err(ReasonCode::RequestCryptoAuthenticationFailed)
                ),
                "{operation_id} {method} {path}"
            );
        }
    }

    // Envelope members are either structure the edge validates before it spends
    // any cryptography (a refusal for a malformed envelope) or members the AAD
    // binds (authentication fails when they change). Pinning both keeps a
    // tampered version, key, revision, identity or lifetime from being accepted
    // and keeps the two refusals distinguishable in the audit.
    #[test]
    fn tampered_and_malformed_envelope_members_are_refused_with_their_reason() {
        let rule = rule();
        let valid: Value = serde_json::from_slice(&envelope("/orders")).unwrap();
        let malformed: [Mutation; 15] = [
            ("schema version 2", |v| v["schema_version"] = json!(2)),
            ("schema version as text", |v| {
                v["schema_version"] = json!("1");
            }),
            ("missing schema version", |v| {
                v.as_object_mut().unwrap().remove("schema_version");
            }),
            ("another adapter revision", |v| {
                v["adapter_revision"] = json!("orders-json-r2");
            }),
            ("another key id", |v| v["key_id"] = json!("request-key-r2")),
            ("an extra member", |v| v["debug"] = json!(true)),
            ("a malformed message id", |v| {
                v["message_id"] = json!("msg_1");
            }),
            ("a short nonce", |v| {
                v["nonce"] = json!("03".repeat(NONCE_BYTES - 1));
            }),
            ("a non-hex nonce", |v| {
                v["nonce"] = json!("zz".repeat(NONCE_BYTES));
            }),
            ("a short tag", |v| {
                v["tag"] = json!("00".repeat(TAG_BYTES - 1));
            }),
            ("a numeric ciphertext", |v| v["ciphertext"] = json!(7)),
            ("a negative issue time", |v| v["issued_at"] = json!(-1)),
            ("a fractional expiry", |v| v["expires_at"] = json!(9.5)),
            ("a null key id", |v| v["key_id"] = Value::Null),
            // 9 - 3 = 6 seconds, past the rule's 5: refused before any cryptography.
            ("a lifetime beyond the maximum", |v| {
                v["issued_at"] = json!(3);
            }),
        ];
        for (name, mutate) in malformed {
            let mut envelope = valid.clone();
            mutate(&mut envelope);
            assert!(
                matches!(
                    decode_at_five(&rule, &serde_json::to_vec(&envelope).unwrap()),
                    Err(ReasonCode::RequestEnvelopeInvalid)
                ),
                "{name}"
            );
        }
        let bound: [Mutation; 5] = [
            ("another message id", |v| {
                v["message_id"] = json!("msg_018f2a3b-4c5d-7000-8000-000000000902");
            }),
            // Still a valid 4-second lifetime, so only authentication can notice.
            ("a moved issue time", |v| v["issued_at"] = json!(5)),
            ("a moved expiry", |v| v["expires_at"] = json!(8)),
            ("another nonce", |v| {
                v["nonce"] = json!("04".repeat(NONCE_BYTES));
            }),
            ("a flipped ciphertext", |v| {
                let mut bytes = decode_hex(v["ciphertext"].as_str().unwrap(), 4096).unwrap();
                bytes[0] ^= 1;
                v["ciphertext"] = json!(hex(&bytes));
            }),
        ];
        for (name, mutate) in bound {
            let mut envelope = valid.clone();
            mutate(&mut envelope);
            assert!(
                matches!(
                    decode_at_five(&rule, &serde_json::to_vec(&envelope).unwrap()),
                    Err(ReasonCode::RequestCryptoAuthenticationFailed)
                ),
                "{name}"
            );
        }
        let mut from_the_future = valid.clone();
        from_the_future["issued_at"] = json!(8);
        assert!(matches!(
            decode_at_five(&rule, &serde_json::to_vec(&from_the_future).unwrap()),
            Err(ReasonCode::RequestCryptoMessageFromFuture)
        ));
        // Text that is not one JSON object with unique members never reaches the cipher.
        let text = String::from_utf8(envelope("/orders")).unwrap();
        for (name, bytes) in [
            (
                "a repeated member",
                text.replacen('{', "{\"nonce\":\"00\",", 1).into_bytes(),
            ),
            ("trailing data", format!("{text} 1").into_bytes()),
            ("an array", b"[1]".to_vec()),
            ("garbage", vec![0xff, 0xfe, 0x00]),
            ("nothing", Vec::new()),
        ] {
            assert!(
                matches!(
                    decode_at_five(&rule, &bytes),
                    Err(ReasonCode::RequestEnvelopeInvalid)
                ),
                "{name}"
            );
        }
    }

    // What the origin receives is the decrypted plaintext, so only a strict,
    // bounded JSON object may come out: duplicate members are ambiguous (an
    // origin may honor the first or the last), and a scalar, array, empty or
    // oversized body is not an object the adapter promised.
    #[test]
    fn only_a_strict_bounded_json_object_survives_decryption() {
        let rule = rule();
        assert!(decode_at_five(&rule, &envelope_with_plaintext("/orders", br#"{"a":1}"#)).is_ok());
        let oversized = format!(r#"{{"pad":"{}"}}"#, "x".repeat(rule.max_plaintext_bytes));
        for (name, plaintext) in [
            (
                "a duplicate member",
                br#"{"role":"user","role":"admin"}"#.to_vec(),
            ),
            (
                "a nested duplicate member",
                br#"{"a":{"b":1,"b":2}}"#.to_vec(),
            ),
            ("an array", b"[1,2]".to_vec()),
            ("a string", br#""text""#.to_vec()),
            ("a number", b"7".to_vec()),
            ("null", b"null".to_vec()),
            ("malformed JSON", br#"{"a":"#.to_vec()),
            ("trailing data", br#"{"a":1} {"b":2}"#.to_vec()),
            ("empty plaintext", Vec::new()),
            ("an oversized object", oversized.into_bytes()),
        ] {
            assert!(
                matches!(
                    decode_at_five(&rule, &envelope_with_plaintext("/orders", &plaintext)),
                    Err(ReasonCode::RequestEnvelopeInvalid)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn compatibility_requires_an_approved_live_build() {
        let approved = BuildFingerprint::parse(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        let other = BuildFingerprint::parse(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )
        .unwrap();
        let rule = RequestCryptoCompatibilityRule {
            adapter_revision: "orders-legacy-r1".to_owned(),
            approval_ref: "approval-42".to_owned(),
            expires_at: UnixSeconds::new(10),
            build_fingerprints: vec![approved.clone()],
        };
        assert_eq!(rule.authorize(UnixSeconds::new(9), &approved), Ok(()));
        assert_eq!(
            rule.authorize(UnixSeconds::new(9), &other),
            Err(ReasonCode::RequestCryptoBuildNotApproved)
        );
        assert_eq!(
            rule.authorize(UnixSeconds::new(10), &approved),
            Err(ReasonCode::RequestCryptoCompatibilityExpired)
        );
    }

    fn envelope_hook_rule() -> RequestCryptoEnvelopeHookRule {
        RequestCryptoEnvelopeHookRule {
            adapter_revision: "checkout-json-r1".to_owned(),
            max_envelope_bytes: 4096,
            max_plaintext_bytes: 1024,
            max_message_age_seconds: 5,
            max_future_skew_seconds: 1,
            max_active_messages: 100,
            max_in_flight_bytes: 16_384,
        }
    }

    fn envelope_hook_envelope(key_id: &str, path: &str, plaintext: &[u8]) -> Vec<u8> {
        let rule = envelope_hook_rule();
        let nonce = [5; NONCE_BYTES];
        let message_id = "msg_018f2a3b-4c5d-7000-8000-000000000a01";
        let issued_at = UnixSeconds::new(4);
        let expires_at = UnixSeconds::new(9);
        let mut tag = [0; TAG_BYTES];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &[9; 32],
            Some(&nonce),
            &aad(
                ENVELOPE_HOOK_PROTOCOL_LABEL,
                "tenant_demo",
                "site_demo",
                "checkout.submit",
                "POST",
                path,
                rule.adapter_revision(),
                key_id,
                message_id,
                issued_at,
                expires_at,
            )
            .unwrap(),
            plaintext,
            &mut tag,
        )
        .unwrap();
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "adapter_revision": rule.adapter_revision(),
            "key_id": key_id,
            "message_id": message_id,
            "issued_at": issued_at.value(),
            "expires_at": expires_at.value(),
            "nonce": hex(&nonce),
            "ciphertext": hex(&ciphertext),
            "tag": hex(&tag),
        }))
        .unwrap()
    }

    fn decode_envelope_hook_at_five(
        rule: &RequestCryptoEnvelopeHookRule,
        keys: &EnvelopeHookKeys,
        envelope: &[u8],
    ) -> Result<FrozenRequest, ReasonCode> {
        rule.decode(
            "tenant_demo",
            "site_demo",
            "checkout.submit",
            "POST",
            "/checkout",
            UnixSeconds::new(5),
            envelope,
            keys,
        )
    }

    // A message encrypted under the current window's key decodes; one
    // encrypted under the immediately preceding window still decodes during
    // the grace period; and the AAD binding prevents a presented key_id from
    // being paired with any other window's key.
    #[test]
    fn envelope_hook_accepts_the_current_or_previous_window_key() {
        let rule = envelope_hook_rule();
        let keys = EnvelopeHookKeys::new(
            7,
            Zeroizing::new([9; 32]),
            Some((6, Zeroizing::new([1; 32]))),
        );
        let plaintext = br#"{"sku":"A-1"}"#;
        let current = envelope_hook_envelope(&envelope_hook_key_id(7), "/checkout", plaintext);
        let frozen = decode_envelope_hook_at_five(&rule, &keys, &current).unwrap();
        assert_eq!(frozen.evidence().key_id(), "ehk.7");
        assert_eq!(frozen.into_body(), Bytes::from_static(plaintext));

        let unknown_window =
            envelope_hook_envelope(&envelope_hook_key_id(9), "/checkout", plaintext);
        assert!(matches!(
            decode_envelope_hook_at_five(&rule, &keys, &unknown_window),
            Err(ReasonCode::RequestCryptoKeyUnavailable)
        ));

        let malformed_key_id = envelope_hook_envelope("ehk.not-a-number", "/checkout", plaintext);
        assert!(matches!(
            decode_envelope_hook_at_five(&rule, &keys, &malformed_key_id),
            Err(ReasonCode::RequestCryptoKeyUnavailable)
        ));
    }

    #[test]
    fn envelope_hook_previous_window_key_decodes_a_message_encrypted_under_it() {
        let rule = envelope_hook_rule();
        let keys = EnvelopeHookKeys::new(
            7,
            Zeroizing::new([9; 32]),
            Some((6, Zeroizing::new([1; 32]))),
        );
        let plaintext = br#"{"sku":"A-1"}"#;
        let mut rule_previous = envelope_hook_rule();
        rule_previous.adapter_revision = rule.adapter_revision.clone();
        let nonce = [5; NONCE_BYTES];
        let message_id = "msg_018f2a3b-4c5d-7000-8000-000000000a02";
        let issued_at = UnixSeconds::new(4);
        let expires_at = UnixSeconds::new(9);
        let key_id = envelope_hook_key_id(6);
        let mut tag = [0; TAG_BYTES];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &[1; 32],
            Some(&nonce),
            &aad(
                ENVELOPE_HOOK_PROTOCOL_LABEL,
                "tenant_demo",
                "site_demo",
                "checkout.submit",
                "POST",
                "/checkout",
                rule.adapter_revision(),
                &key_id,
                message_id,
                issued_at,
                expires_at,
            )
            .unwrap(),
            plaintext,
            &mut tag,
        )
        .unwrap();
        let envelope = serde_json::to_vec(&json!({
            "schema_version": 1,
            "adapter_revision": rule.adapter_revision(),
            "key_id": key_id,
            "message_id": message_id,
            "issued_at": issued_at.value(),
            "expires_at": expires_at.value(),
            "nonce": hex(&nonce),
            "ciphertext": hex(&ciphertext),
            "tag": hex(&tag),
        }))
        .unwrap();
        let frozen = decode_envelope_hook_at_five(&rule, &keys, &envelope).unwrap();
        assert_eq!(frozen.into_body(), Bytes::from_static(plaintext));

        // With no previous-window key at all (the very first window a
        // session ever used), the same message is refused instead of
        // silently accepted under some other key.
        let no_grace = EnvelopeHookKeys::new(7, Zeroizing::new([9; 32]), None);
        assert!(matches!(
            decode_envelope_hook_at_five(&rule, &no_grace, &envelope),
            Err(ReasonCode::RequestCryptoKeyUnavailable)
        ));
    }

    // ENVELOPE_HOOK has no static key_id to check structurally, so a tampered
    // key_id is only caught once it is paired against the wrong AAD: the
    // ciphertext was bound to the *original* key_id and cannot authenticate
    // under a different one, even when that other one also names a key the
    // caller holds.
    #[test]
    fn envelope_hook_key_id_is_bound_by_the_aad_not_just_presented() {
        let rule = envelope_hook_rule();
        let keys = EnvelopeHookKeys::new(
            7,
            Zeroizing::new([9; 32]),
            Some((6, Zeroizing::new([1; 32]))),
        );
        let plaintext = br#"{"sku":"A-1"}"#;
        let envelope = envelope_hook_envelope(&envelope_hook_key_id(7), "/checkout", plaintext);
        let mut retargeted: Value = serde_json::from_slice(&envelope).unwrap();
        retargeted["key_id"] = json!(envelope_hook_key_id(6));
        assert!(matches!(
            decode_envelope_hook_at_five(&rule, &keys, &serde_json::to_vec(&retargeted).unwrap()),
            Err(ReasonCode::RequestCryptoAuthenticationFailed)
        ));
    }

    #[test]
    fn envelope_hook_rejects_a_different_path_or_operation() {
        let rule = envelope_hook_rule();
        let keys = EnvelopeHookKeys::new(7, Zeroizing::new([9; 32]), None);
        let envelope =
            envelope_hook_envelope(&envelope_hook_key_id(7), "/checkout", br#"{"sku":"A-1"}"#);
        assert!(matches!(
            rule.decode(
                "tenant_demo",
                "site_demo",
                "checkout.submit",
                "POST",
                "/checkout/other",
                UnixSeconds::new(5),
                &envelope,
                &keys,
            ),
            Err(ReasonCode::RequestCryptoAuthenticationFailed)
        ));
    }
}
