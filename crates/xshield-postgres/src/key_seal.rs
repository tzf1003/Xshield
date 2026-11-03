//! Encryption of the model API keys the console stores (docs/03 section 3.3,
//! the model tab of the system page).
//!
//! A key is sealed with AES-256-GCM. The cipher key is derived from the context
//! secret (`XSHIELD_CONTEXT_KEY_HEX`) with HMAC-SHA256 under a fixed label, so a
//! sealed key and the context hashes never share a key. Every seal draws a new
//! 96-bit nonce, and the column name is bound as associated data, so a sealed
//! value cannot be moved to another column and still open.
//!
//! Layout of a sealed value: the nonce (12 bytes), then the ciphertext and its
//! 16-byte tag.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

/// Fixed label that separates this derivation from any other use of the secret.
const LABEL: &[u8] = b"xshield model config key v1";
/// Length of the AEAD tag appended to each ciphertext.
const TAG_LEN: usize = 16;
/// The shortest context secret accepted, in bytes (the gateway requires 32).
const SECRET_MIN_BYTES: usize = 32;

/// Why a value could not be sealed or opened. The text of a failure never
/// includes the secret or the plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The context secret is shorter than 32 bytes.
    SecretTooShort,
    /// The system random source failed.
    Random,
    /// Encryption failed.
    Seal,
    /// The value is too short or its nonce is malformed.
    Layout,
    /// The value did not authenticate: wrong secret, wrong column, or damaged data.
    Open,
}

/// Seals and opens model keys with a cipher derived from the context secret.
pub struct KeySealer {
    key: LessSafeKey,
}

impl KeySealer {
    /// Builds the sealer from the context secret's bytes.
    ///
    /// # Errors
    /// [`SealError::SecretTooShort`] when the secret has fewer than 32 bytes.
    pub fn from_context_secret(secret: &[u8]) -> Result<Self, SealError> {
        if secret.len() < SECRET_MIN_BYTES {
            return Err(SealError::SecretTooShort);
        }
        let prk = hmac::Key::new(hmac::HMAC_SHA256, secret);
        let derived = hmac::sign(&prk, LABEL);
        let unbound =
            UnboundKey::new(&AES_256_GCM, derived.as_ref()).map_err(|_| SealError::Seal)?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
        })
    }

    /// Seals `plaintext` for `column`.
    ///
    /// # Errors
    /// [`SealError::Random`] or [`SealError::Seal`] when the primitives fail.
    pub fn seal(&self, column: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut nonce = [0_u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SealError::Random)?;
        let mut buffer = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(column.as_bytes()),
                &mut buffer,
            )
            .map_err(|_| SealError::Seal)?;
        let mut sealed = Vec::with_capacity(NONCE_LEN + buffer.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&buffer);
        Ok(sealed)
    }

    /// Opens a value sealed for `column` and returns its text.
    ///
    /// # Errors
    /// [`SealError::Layout`] for a malformed value, [`SealError::Open`] when it
    /// does not authenticate or is not UTF-8.
    pub fn open(&self, column: &str, sealed: &[u8]) -> Result<Zeroizing<String>, SealError> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(SealError::Layout);
        }
        let (nonce, body) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| SealError::Layout)?;
        let mut buffer = Zeroizing::new(body.to_vec());
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::from(column.as_bytes()), &mut buffer[..])
            .map_err(|_| SealError::Open)?;
        let text = std::str::from_utf8(plaintext).map_err(|_| SealError::Open)?;
        Ok(Zeroizing::new(text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = &[7_u8; 32];

    fn sealer() -> KeySealer {
        KeySealer::from_context_secret(SECRET).expect("a 32-byte secret")
    }

    #[test]
    fn a_sealed_key_opens_for_its_own_column_only() {
        let sealer = sealer();
        let ciphertext = sealer
            .seal("model_config.jev_key", b"sk-live-a91f")
            .expect("seal");
        assert!(
            !ciphertext
                .windows(12)
                .any(|window| window == b"sk-live-a91f")
        );
        let opened = sealer
            .open("model_config.jev_key", &ciphertext)
            .expect("open");
        assert_eq!(opened.as_str(), "sk-live-a91f");
        assert_eq!(
            sealer.open("model_config.agent_key", &ciphertext).err(),
            Some(SealError::Open)
        );
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let sealer = sealer();
        let first = sealer.seal("c", b"same").expect("first");
        let second = sealer.seal("c", b"same").expect("second");
        assert_ne!(first, second);
    }

    #[test]
    fn a_damaged_or_foreign_value_does_not_open() {
        let sealer = sealer();
        let mut ciphertext = sealer.seal("c", b"key-1234").expect("seal");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        assert_eq!(sealer.open("c", &ciphertext).err(), Some(SealError::Open));
        let other = KeySealer::from_context_secret(&[9_u8; 32]).expect("other secret");
        let fresh = sealer.seal("c", b"key-1234").expect("seal again");
        assert_eq!(other.open("c", &fresh).err(), Some(SealError::Open));
        assert_eq!(sealer.open("c", &[0_u8; 10]).err(), Some(SealError::Layout));
    }

    #[test]
    fn a_short_secret_is_refused() {
        assert!(matches!(
            KeySealer::from_context_secret(&[1_u8; 31]),
            Err(SealError::SecretTooShort)
        ));
    }
}
