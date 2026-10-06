//! Encrypted, bounded local audit journal with crash-tail recovery.
//!
//! The journal accepts already-serialized event bytes, encrypts every record
//! with AES-256-GCM, chains records within a producer segment, and acknowledges
//! a batch only after `sync_data`. It never logs event plaintext or key material.

#![warn(missing_docs)]

use crc32fast::hash as crc32;
use openssl::{
    error::ErrorStack,
    pkey::{Id, PKey, Private, Public},
    rand::rand_bytes,
    sha::{Sha256, sha256},
    sign::{Signer, Verifier},
    symm::{Cipher, Crypter, Mode},
};
use std::{
    collections::BTreeSet,
    fmt, fs,
    fs::{File, OpenOptions, TryLockError},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use xshield_core::domain::EventId;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, fs::PermissionsExt};

const MAGIC: &[u8; 8] = b"XSHJNL01";
const SEAL_MAGIC: &[u8; 8] = b"XSHSL001";
const FORMAT_VERSION: u16 = 1;
const SEAL_VERSION: u16 = 1;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HASH_BYTES: usize = 32;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_BATCH_RECORDS: usize = 64;
const MAX_RECORD_BYTES: usize = MAX_EVENT_BYTES + 256;
const ZERO_HASH: [u8; HASH_BYTES] = [0; HASH_BYTES];
const ED25519_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MAX_SEAL_MANIFEST_BYTES: u64 = 1024;

/// Computes the SHA-256 digest used to bind a durable event to its publisher row.
///
/// This is intentionally a small, allocation-free adapter around the journal's
/// existing cryptographic primitive so other trusted publication ports cannot
/// substitute a weaker digest implementation.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> [u8; HASH_BYTES] {
    sha256(bytes)
}

/// AES-256 key used only for local journal encryption.
pub struct JournalKey([u8; 32]);

impl JournalKey {
    /// Parses exactly 64 lowercase hexadecimal characters.
    ///
    /// # Errors
    /// Returns [`JournalError::InvalidKey`] for non-canonical key material.
    pub fn from_hex(value: &str) -> Result<Self, JournalError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(JournalError::InvalidKey);
        }
        let mut key = [0; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            key[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        Ok(Self(key))
    }
}

/// Ed25519 key held by the separately authorized segment-sealing process.
pub struct SealSigningKey {
    key_id: String,
    key: PKey<Private>,
}

impl SealSigningKey {
    /// Parses a key identifier and exactly 32 bytes of canonical lowercase hex seed material.
    ///
    /// # Errors
    /// Returns [`JournalError::InvalidSealKey`] for invalid key metadata or material.
    pub fn from_hex(key_id: impl Into<String>, value: &str) -> Result<Self, JournalError> {
        let key_id = key_id.into();
        if !valid_key_id(&key_id) {
            return Err(JournalError::InvalidSealKey);
        }
        let mut bytes = Zeroizing::new(decode_32_byte_hex(value)?);
        let key = PKey::private_key_from_raw_bytes(bytes.as_ref(), Id::ED25519)
            .map_err(|_| JournalError::InvalidSealKey)?;
        bytes.zeroize();
        Ok(Self { key_id, key })
    }

    /// Derives the public verifier that may be distributed to readers.
    ///
    /// # Errors
    /// Returns a cryptographic error if OpenSSL cannot export or import the public key.
    pub fn verifying_key(&self) -> Result<SealVerifyingKey, JournalError> {
        let bytes = self.key.raw_public_key()?;
        Ok(SealVerifyingKey {
            key_id: self.key_id.clone(),
            key: PKey::public_key_from_raw_bytes(&bytes, Id::ED25519)?,
        })
    }
}

impl fmt::Debug for SealSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealSigningKey")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Ed25519 public key used to verify a signed segment manifest.
pub struct SealVerifyingKey {
    key_id: String,
    key: PKey<Public>,
}

impl SealVerifyingKey {
    /// Parses a key identifier and exactly 32 bytes of canonical lowercase public-key hex.
    ///
    /// # Errors
    /// Returns [`JournalError::InvalidSealKey`] for invalid key metadata or material.
    pub fn from_hex(key_id: impl Into<String>, value: &str) -> Result<Self, JournalError> {
        let key_id = key_id.into();
        if !valid_key_id(&key_id) {
            return Err(JournalError::InvalidSealKey);
        }
        let bytes = decode_32_byte_hex(value).map_err(|_| JournalError::InvalidSealKey)?;
        let key = PKey::public_key_from_raw_bytes(&bytes, Id::ED25519)
            .map_err(|_| JournalError::InvalidSealKey)?;
        Ok(Self { key_id, key })
    }
}

impl fmt::Debug for SealVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealVerifyingKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

fn decode_32_byte_hex(value: &str) -> Result<[u8; ED25519_BYTES], JournalError> {
    if value.len() != ED25519_BYTES * 2
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(JournalError::InvalidSealKey);
    }
    let mut bytes = [0; ED25519_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(bytes)
}

impl fmt::Debug for JournalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalKey([REDACTED])")
    }
}

impl Drop for JournalKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

/// Hard capacity and warning threshold for one journal directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
    max: u64,
    high_watermark: u64,
    segment_max: u64,
}

impl JournalLimits {
    /// Validates a non-zero capacity and a threshold within that capacity.
    ///
    /// # Errors
    /// Returns [`JournalError::InvalidLimits`] for incoherent byte limits.
    pub const fn new(
        max_bytes: u64,
        high_watermark_bytes: u64,
        segment_max_bytes: u64,
    ) -> Result<Self, JournalError> {
        if max_bytes == 0
            || high_watermark_bytes == 0
            || high_watermark_bytes > max_bytes
            || segment_max_bytes == 0
            || segment_max_bytes > max_bytes
        {
            return Err(JournalError::InvalidLimits);
        }
        Ok(Self {
            max: max_bytes,
            high_watermark: high_watermark_bytes,
            segment_max: segment_max_bytes,
        })
    }
}

/// One typed event and its canonical serialized bytes.
#[derive(Clone, Copy)]
pub struct JournalRecord<'a> {
    /// Immutable event ID retained across publisher retries.
    pub event_id: &'a EventId,
    /// Canonical event bytes; callers remain responsible for event schema validation.
    pub plaintext: &'a [u8],
}

/// Durable acknowledgement for one event in a synced batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalReceipt {
    /// Unique durability acknowledgement ID.
    pub receipt_id: String,
    /// Event accepted by this receipt.
    pub event_id: EventId,
    /// Producer-local sequence within the active segment.
    pub producer_sequence: u64,
}

/// Authenticated summary of one immutable journal segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSegment {
    /// Producer boot ID committed by the segment header and every record AAD.
    pub producer_boot_id: String,
    /// Encryption-key identifier committed by the segment header and every record AAD.
    pub journal_key_id: String,
    /// Number of complete authenticated records.
    pub record_count: u64,
    /// Final producer-local sequence, or zero for an empty segment.
    pub final_sequence: u64,
    /// Final record-body hash, or the all-zero chain root for an empty segment.
    pub chain_head: [u8; HASH_BYTES],
    /// Exact immutable segment length.
    pub segment_bytes: u64,
    /// SHA-256 digest of the entire segment file.
    pub segment_digest: [u8; HASH_BYTES],
}

/// One event released from a fully authenticated and signed journal segment.
///
/// Plaintext remains owned by this value and is zeroized when dropped. The
/// record digest lets an at-least-once consumer reject the same event ID with
/// different canonical bytes.
pub struct AuthenticatedJournalRecord {
    event_id: EventId,
    receipt_id: String,
    producer_boot_id: String,
    producer_sequence: u64,
    plaintext_digest: [u8; HASH_BYTES],
    plaintext: Zeroizing<Vec<u8>>,
}

impl AuthenticatedJournalRecord {
    /// Returns the immutable event ID retained across publisher retries.
    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Returns the local durability receipt committed by record AAD.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    /// Returns the producer boot ID authenticated by the record AAD.
    #[must_use]
    pub fn producer_boot_id(&self) -> &str {
        &self.producer_boot_id
    }

    /// Returns the producer-local sequence committed by record AAD.
    #[must_use]
    pub const fn producer_sequence(&self) -> u64 {
        self.producer_sequence
    }

    /// Returns SHA-256 over the exact canonical plaintext bytes.
    #[must_use]
    pub const fn plaintext_digest(&self) -> &[u8; HASH_BYTES] {
        &self.plaintext_digest
    }

    /// Borrows the canonical event bytes without copying secret-bearing data.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

/// Streaming reader for one closed segment paired with its signed manifest.
///
/// Construction validates the complete immutable segment before any event
/// plaintext becomes available. Each subsequent record is authenticated again
/// while it is decrypted, and its plaintext is zeroized on drop.
pub struct SealedSegmentReader<'a> {
    snapshot: Cursor<Zeroizing<Vec<u8>>>,
    identity: SegmentIdentity,
    key: &'a JournalKey,
    segment: VerifiedSegment,
    remaining_records: u64,
    next_sequence: u64,
    previous_hash: [u8; HASH_BYTES],
}

impl<'a> SealedSegmentReader<'a> {
    /// Opens an immutable in-memory snapshot after verifying its signed manifest.
    ///
    /// The segment must be a private regular file named for its producer boot
    /// ID. Active or writable closed segments are rejected. `max_segment_bytes`
    /// is a caller-owned memory ceiling and must cover the signed segment length.
    ///
    /// # Errors
    /// Returns [`JournalError`] for unsafe paths, key mismatch, an invalid
    /// signature, corruption, or a manifest/segment mismatch.
    pub fn open(
        path: impl AsRef<Path>,
        max_segment_bytes: u64,
        expected_journal_key_id: &str,
        journal_key: &'a JournalKey,
        manifest: &[u8],
        seal_key: &SealVerifyingKey,
    ) -> Result<Self, JournalError> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(JournalError::UnsafePath);
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o277 != 0 {
            return Err(JournalError::UnsafePermissions);
        }
        if max_segment_bytes == 0 || metadata.len() > max_segment_bytes {
            return Err(JournalError::ReadLimitExceeded);
        }
        let segment = verify_sealed_segment(
            path,
            expected_journal_key_id,
            journal_key,
            manifest,
            seal_key,
        )?;
        if segment.segment_bytes > max_segment_bytes {
            return Err(JournalError::ReadLimitExceeded);
        }
        let mut file = File::open(path)?;
        let opened_metadata = file.metadata()?;
        if !opened_metadata.file_type().is_file() || opened_metadata.len() != segment.segment_bytes
        {
            return Err(JournalError::Corrupt("seal segment changed"));
        }
        #[cfg(unix)]
        if opened_metadata.permissions().mode() & 0o277 != 0 {
            return Err(JournalError::UnsafePermissions);
        }
        let snapshot_len =
            usize::try_from(segment.segment_bytes).map_err(|_| JournalError::ReadLimitExceeded)?;
        let mut bytes = Zeroizing::new(vec![0; snapshot_len]);
        file.read_exact(&mut bytes)?;
        if sha256(&bytes) != segment.segment_digest {
            return Err(JournalError::Corrupt("seal segment changed"));
        }
        let mut snapshot = Cursor::new(bytes);
        let identity = read_header(&mut snapshot)?;
        if identity.key_id != expected_journal_key_id {
            return Err(JournalError::KeyMismatch);
        }
        if !segment_path_state(path, &identity)? {
            return Err(JournalError::Corrupt("segment not closed"));
        }
        Ok(Self {
            snapshot,
            identity,
            key: journal_key,
            remaining_records: segment.record_count,
            segment,
            next_sequence: 1,
            previous_hash: ZERO_HASH,
        })
    }

    /// Returns the authenticated segment summary used as the publication scope.
    #[must_use]
    pub const fn segment(&self) -> &VerifiedSegment {
        &self.segment
    }

    /// Authenticates and decrypts the next record in producer order.
    ///
    /// # Errors
    /// Returns [`JournalError`] if a snapshot record fails its CRC, AEAD,
    /// sequence, or hash-chain proof.
    pub fn next_record(&mut self) -> Result<Option<AuthenticatedJournalRecord>, JournalError> {
        if self.remaining_records == 0 {
            return Ok(None);
        }
        let mut length = [0; 4];
        if read_until_full_or_eof(&mut self.snapshot, &mut length)? != length.len() {
            return Err(JournalError::Corrupt("sealed record length"));
        }
        let body_len = usize::try_from(u32::from_le_bytes(length))
            .map_err(|_| JournalError::Corrupt("record length"))?;
        if body_len == 0 || body_len > MAX_RECORD_BYTES {
            return Err(JournalError::Corrupt("record length"));
        }
        let mut body = vec![0; body_len];
        if read_until_full_or_eof(&mut self.snapshot, &mut body)? != body_len {
            return Err(JournalError::Corrupt("sealed record body"));
        }
        let decoded = decode_record(
            &self.identity,
            self.key,
            &body,
            self.next_sequence,
            self.previous_hash,
        )?;
        self.previous_hash = sha256(&body);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(JournalError::Corrupt("record sequence"))?;
        self.remaining_records -= 1;
        Ok(Some(decoded))
    }
}

/// Canonically encoded Ed25519-signed segment manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSegmentManifest(Vec<u8>);

impl SignedSegmentManifest {
    /// Signs a verified segment summary with a separately held sealing key.
    ///
    /// # Errors
    /// Returns [`JournalError`] when canonical encoding or signing fails.
    pub fn sign(segment: &VerifiedSegment, key: &SealSigningKey) -> Result<Self, JournalError> {
        let payload = encode_seal_payload(segment, &key.key_id)?;
        let mut signer = Signer::new_without_digest(&key.key)?;
        let signature = signer.sign_oneshot_to_vec(&payload)?;
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(JournalError::Corrupt("seal signature length"));
        }
        let mut encoded = payload;
        encoded.extend_from_slice(&signature);
        Ok(Self(encoded))
    }

    /// Parses and verifies a manifest, returning its authenticated segment summary.
    ///
    /// # Errors
    /// Returns [`JournalError`] for malformed input, the wrong key identifier, or
    /// an invalid signature.
    pub fn verify(bytes: &[u8], key: &SealVerifyingKey) -> Result<VerifiedSegment, JournalError> {
        if bytes.len() < ED25519_SIGNATURE_BYTES {
            return Err(JournalError::Corrupt("seal manifest"));
        }
        let (payload, signature) = bytes.split_at(bytes.len() - ED25519_SIGNATURE_BYTES);
        let (segment, key_id) = decode_seal_payload(payload)?;
        if key_id != key.key_id {
            return Err(JournalError::SealKeyMismatch);
        }
        let mut verifier = Verifier::new_without_digest(&key.key)?;
        if !verifier.verify_oneshot(signature, payload)? {
            return Err(JournalError::Corrupt("seal signature"));
        }
        Ok(segment)
    }

    /// Returns the stable binary representation suitable for an object store.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Creates and durably syncs a new manifest without replacing existing evidence.
    ///
    /// The caller selects a separately controlled destination. Parent directories
    /// must already exist and be private; this function never overwrites a path.
    ///
    /// # Errors
    /// Returns [`JournalError`] for an unsafe destination or durability failure.
    pub fn write_new(&self, path: impl AsRef<Path>) -> Result<(), JournalError> {
        let path = path.as_ref();
        let parent = path.parent().ok_or(JournalError::UnsafePath)?;
        prepare_existing_private_directory(parent)?;
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(JournalError::UnsafePath),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(JournalError::Io(error)),
        }
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(JournalError::UnsafePath)?;
        let temporary = parent.join(format!(".{file_name}.{}.tmp", Uuid::now_v7()));
        let mut file = private_new_file(&temporary)?;
        file.write_all(&self.0)?;
        file.sync_all()?;
        if let Err(error) = fs::hard_link(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return if error.kind() == io::ErrorKind::AlreadyExists {
                Err(JournalError::UnsafePath)
            } else {
                Err(JournalError::Io(error))
            };
        }
        fs::remove_file(temporary)?;
        sync_directory(parent)
    }
}

/// Fully validates one closed segment without repairing or exposing event plaintext.
///
/// # Errors
/// Returns [`JournalError`] for unsafe paths, key mismatch, truncation, corruption,
/// authentication failure, or filesystem failure.
pub fn verify_segment(
    path: impl AsRef<Path>,
    expected_key_id: &str,
    key: &JournalKey,
) -> Result<VerifiedSegment, JournalError> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(JournalError::UnsafePath);
    }
    let recovered = recover_segment(path, expected_key_id, key, false)?;
    Ok(VerifiedSegment {
        producer_boot_id: Uuid::from_bytes(recovered.identity.boot_id).to_string(),
        journal_key_id: recovered.identity.key_id,
        record_count: recovered.report.recovered_records,
        final_sequence: recovered.report.recovered_records,
        chain_head: recovered.final_hash,
        segment_bytes: metadata.len(),
        segment_digest: hash_file(path)?,
    })
}

/// Verifies both a segment and its signed manifest and requires an exact match.
///
/// This is the preferred boundary for publishers and investigators because it
/// prevents a valid manifest from being paired with another segment.
///
/// # Errors
/// Returns [`JournalError`] when either artifact is invalid or their authenticated
/// summaries differ.
pub fn verify_sealed_segment(
    path: impl AsRef<Path>,
    expected_journal_key_id: &str,
    journal_key: &JournalKey,
    manifest: &[u8],
    seal_key: &SealVerifyingKey,
) -> Result<VerifiedSegment, JournalError> {
    let actual = verify_segment(path, expected_journal_key_id, journal_key)?;
    let sealed = SignedSegmentManifest::verify(manifest, seal_key)?;
    if actual != sealed {
        return Err(JournalError::Corrupt("seal segment mismatch"));
    }
    Ok(actual)
}

/// Verifies and signs every closed segment into a separately controlled directory.
///
/// Existing manifests are verified in place, making repeated runs idempotent.
/// Active segments are ignored until journal rotation closes them. No event
/// plaintext is returned or written.
///
/// # Errors
/// Returns [`JournalError`] if either directory is unsafe, a closed segment or
/// existing manifest is invalid, signing fails, or durable manifest creation fails.
pub fn seal_closed_segments(
    journal_directory: impl AsRef<Path>,
    manifest_directory: impl AsRef<Path>,
    expected_journal_key_id: &str,
    journal_key: &JournalKey,
    seal_key: &SealSigningKey,
) -> Result<Vec<VerifiedSegment>, JournalError> {
    let journal_directory = journal_directory.as_ref();
    let manifest_directory = manifest_directory.as_ref();
    prepare_existing_private_directory(journal_directory)?;
    prepare_existing_private_directory(manifest_directory)?;
    let verifier = seal_key.verifying_key()?;
    let paths = closed_segment_paths(journal_directory)?;

    // ponytail: linear verification is simplest; add a signed checkpoint index
    // when retained segment count makes periodic scans measurably expensive.
    let mut sealed = Vec::with_capacity(paths.len());
    for path in paths {
        let segment = verify_segment(&path, expected_journal_key_id, journal_key)?;
        let manifest_path =
            manifest_directory.join(format!("segment-{}.xjs", segment.producer_boot_id));
        match fs::symlink_metadata(&manifest_path) {
            Ok(_) => {
                let manifest = read_private_bounded(&manifest_path, MAX_SEAL_MANIFEST_BYTES)?;
                verify_sealed_segment(
                    &path,
                    expected_journal_key_id,
                    journal_key,
                    &manifest,
                    &verifier,
                )?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                SignedSegmentManifest::sign(&segment, seal_key)?.write_new(&manifest_path)?;
            }
            Err(error) => return Err(JournalError::Io(error)),
        }
        sealed.push(segment);
    }
    Ok(sealed)
}

fn encode_seal_payload(
    segment: &VerifiedSegment,
    seal_key_id: &str,
) -> Result<Vec<u8>, JournalError> {
    if !valid_key_id(seal_key_id) || !valid_key_id(&segment.journal_key_id) {
        return Err(JournalError::InvalidSealKey);
    }
    if segment.final_sequence != segment.record_count {
        return Err(JournalError::Corrupt("seal sequence"));
    }
    let seal_key_len =
        u16::try_from(seal_key_id.len()).map_err(|_| JournalError::InvalidSealKey)?;
    let journal_key_len =
        u16::try_from(segment.journal_key_id.len()).map_err(|_| JournalError::InvalidKeyId)?;
    let boot_id = Uuid::parse_str(&segment.producer_boot_id)
        .map_err(|_| JournalError::Corrupt("seal producer boot id"))?;
    let mut payload = Vec::with_capacity(118 + seal_key_id.len() + segment.journal_key_id.len());
    payload.extend_from_slice(SEAL_MAGIC);
    payload.extend_from_slice(&SEAL_VERSION.to_le_bytes());
    payload.extend_from_slice(&seal_key_len.to_le_bytes());
    payload.extend_from_slice(seal_key_id.as_bytes());
    payload.extend_from_slice(boot_id.as_bytes());
    payload.extend_from_slice(&journal_key_len.to_le_bytes());
    payload.extend_from_slice(segment.journal_key_id.as_bytes());
    payload.extend_from_slice(&segment.record_count.to_le_bytes());
    payload.extend_from_slice(&segment.final_sequence.to_le_bytes());
    payload.extend_from_slice(&segment.chain_head);
    payload.extend_from_slice(&segment.segment_bytes.to_le_bytes());
    payload.extend_from_slice(&segment.segment_digest);
    Ok(payload)
}

fn decode_seal_payload(payload: &[u8]) -> Result<(VerifiedSegment, String), JournalError> {
    let mut cursor = payload;
    if seal_take(&mut cursor, SEAL_MAGIC.len())? != SEAL_MAGIC {
        return Err(JournalError::Corrupt("seal magic"));
    }
    let version = u16::from_le_bytes(
        seal_take(&mut cursor, 2)?
            .try_into()
            .map_err(|_| JournalError::Corrupt("seal version"))?,
    );
    if version != SEAL_VERSION {
        return Err(JournalError::UnsupportedSealFormat);
    }
    let seal_key_id = decode_seal_key_id(&mut cursor)?;
    let boot_id: [u8; 16] = seal_take(&mut cursor, 16)?
        .try_into()
        .map_err(|_| JournalError::Corrupt("seal producer boot id"))?;
    let journal_key_id = decode_seal_key_id(&mut cursor)?;
    let record_count = decode_seal_u64(&mut cursor, "seal record count")?;
    let final_sequence = decode_seal_u64(&mut cursor, "seal sequence")?;
    if final_sequence != record_count {
        return Err(JournalError::Corrupt("seal sequence"));
    }
    let chain_head = seal_take(&mut cursor, HASH_BYTES)?
        .try_into()
        .map_err(|_| JournalError::Corrupt("seal chain head"))?;
    let segment_bytes = decode_seal_u64(&mut cursor, "seal segment bytes")?;
    let segment_digest = seal_take(&mut cursor, HASH_BYTES)?
        .try_into()
        .map_err(|_| JournalError::Corrupt("seal segment digest"))?;
    if !cursor.is_empty() {
        return Err(JournalError::Corrupt("seal trailing bytes"));
    }
    Ok((
        VerifiedSegment {
            producer_boot_id: Uuid::from_bytes(boot_id).to_string(),
            journal_key_id,
            record_count,
            final_sequence,
            chain_head,
            segment_bytes,
            segment_digest,
        },
        seal_key_id,
    ))
}

fn decode_seal_key_id(cursor: &mut &[u8]) -> Result<String, JournalError> {
    let length = usize::from(u16::from_le_bytes(
        seal_take(cursor, 2)?
            .try_into()
            .map_err(|_| JournalError::Corrupt("seal key id length"))?,
    ));
    if length == 0 || length > MAX_KEY_ID_BYTES {
        return Err(JournalError::Corrupt("seal key id length"));
    }
    let value = std::str::from_utf8(seal_take(cursor, length)?)
        .map_err(|_| JournalError::Corrupt("seal key id"))?;
    if !valid_key_id(value) {
        return Err(JournalError::Corrupt("seal key id"));
    }
    Ok(value.to_owned())
}

fn decode_seal_u64(cursor: &mut &[u8], kind: &'static str) -> Result<u64, JournalError> {
    Ok(u64::from_le_bytes(
        seal_take(cursor, 8)?
            .try_into()
            .map_err(|_| JournalError::Corrupt(kind))?,
    ))
}

fn seal_take<'a>(cursor: &mut &'a [u8], count: usize) -> Result<&'a [u8], JournalError> {
    if cursor.len() < count {
        return Err(JournalError::Corrupt("seal manifest"));
    }
    let (value, rest) = cursor.split_at(count);
    *cursor = rest;
    Ok(value)
}

fn hash_file(path: &Path) -> Result<[u8; HASH_BYTES], JournalError> {
    let mut file = File::open(path)?;
    hash_open_file(&mut file)
}

fn hash_open_file(file: &mut File) -> Result<[u8; HASH_BYTES], JournalError> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let digest = hasher.finish();
    file.seek(SeekFrom::Start(0))?;
    Ok(digest)
}

/// Result of validating old segments before opening a new producer segment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Complete authenticated records found in prior segments.
    pub recovered_records: u64,
    /// Incomplete trailing bytes removed after a crash.
    pub truncated_bytes: u64,
}

/// Current capacity and health state exposed to readiness checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalStatus {
    /// Bytes occupied by journal segments.
    pub used_bytes: u64,
    /// Configured hard directory quota.
    pub max_bytes: u64,
    /// Whether used bytes reached the configured warning threshold.
    pub high_watermark_reached: bool,
    /// False after a write or sync error; reopening is required before more appends.
    pub healthy: bool,
}

struct SegmentIdentity {
    boot_id: [u8; 16],
    key_id: String,
}

/// Single-writer encrypted journal.
///
/// Callers must serialize access. A successful append means the whole batch
/// reached the operating system's durable-file acknowledgement boundary.
pub struct LocalJournal {
    _writer_lock: File,
    directory: PathBuf,
    file: File,
    active_path: PathBuf,
    identity: SegmentIdentity,
    key: JournalKey,
    limits: JournalLimits,
    used_bytes: u64,
    segment_bytes: u64,
    sequence: u64,
    previous_hash: [u8; HASH_BYTES],
    healthy: bool,
    /// Bytes written by `append_batch_unsynced` that no `sync` has made durable yet.
    unsynced: bool,
    /// Durability syncs performed by this handle, for observability and tests.
    syncs: u64,
}

impl LocalJournal {
    /// Recovers existing segments and creates a fresh producer segment.
    ///
    /// The directory must be private to the service. Existing complete
    /// corruption, a key-ID mismatch, insecure Unix permissions, or capacity
    /// exhaustion prevents startup. Only an incomplete final record is
    /// truncated, and that repair is synced before returning.
    ///
    /// # Errors
    /// Returns [`JournalError`] for invalid configuration, filesystem failure,
    /// authentication failure, corruption, or quota exhaustion.
    pub fn open(
        directory: impl AsRef<Path>,
        key_id: impl Into<String>,
        key: JournalKey,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let directory = directory.as_ref();
        prepare_directory(directory)?;
        let writer_lock = open_writer_lock(directory)?;
        let key_id = key_id.into();
        if !valid_key_id(&key_id) {
            return Err(JournalError::InvalidKeyId);
        }

        let (report, mut used_bytes) = recover_directory(directory, &key_id, &key)?;
        let boot_uuid = Uuid::now_v7();
        let identity = SegmentIdentity {
            boot_id: *boot_uuid.as_bytes(),
            key_id,
        };
        let header = encode_header(&identity)?;
        let header_bytes = u64::try_from(header.len()).map_err(|_| JournalError::InvalidLimits)?;
        used_bytes = used_bytes
            .checked_add(header_bytes)
            .ok_or(JournalError::Full)?;
        if used_bytes > limits.max {
            return Err(JournalError::Full);
        }

        let (file, active_path) = create_segment(directory, &boot_uuid.to_string(), &header)?;
        Ok((
            Self {
                _writer_lock: writer_lock,
                directory: directory.to_owned(),
                file,
                active_path,
                identity,
                key,
                limits,
                used_bytes,
                segment_bytes: header_bytes,
                sequence: 0,
                previous_hash: ZERO_HASH,
                healthy: true,
                unsynced: false,
                syncs: 0,
            },
            report,
        ))
    }

    /// Encrypts and appends a bounded batch, then performs one durability sync.
    ///
    /// Records are built completely before the first write. Any write or sync
    /// error poisons this handle because the durable boundary becomes unknown;
    /// callers must stop forwarding and reopen the journal through recovery.
    ///
    /// # Errors
    /// Returns [`JournalError`] for an empty or oversized batch, encryption
    /// failure, quota exhaustion, a poisoned handle, or filesystem failure.
    pub fn append_batch(
        &mut self,
        records: &[JournalRecord<'_>],
    ) -> Result<Vec<JournalReceipt>, JournalError> {
        let receipts = self.append_batch_unsynced(records)?;
        self.sync()?;
        Ok(receipts)
    }

    /// Encrypts and appends a bounded batch without making it durable.
    ///
    /// This is the first half of [`append_batch`](Self::append_batch), for a
    /// writer that appends several batches and then calls [`sync`](Self::sync)
    /// once (group commit): the fsync dominates the cost of an append, so
    /// sharing it among everything that is waiting multiplies throughput without
    /// weakening any caller's guarantee.
    ///
    /// **A receipt returned here is not durable until `sync` returns `Ok`.** The
    /// caller must not release a receipt, forward a request or tell anyone the
    /// event is recorded before that. If the process dies first, the batch may be
    /// lost, which is acceptable only because nothing was acknowledged.
    ///
    /// A refusal that happens before any byte is written (empty or oversized
    /// batch, bad event, quota) leaves the handle untouched and healthy, so one
    /// bad batch cannot fail the others in a group. A write error poisons the
    /// handle, and batches already appended since the last sync are then of
    /// unknown durability: the caller must treat them as failed.
    ///
    /// # Errors
    /// Same as [`append_batch`](Self::append_batch) except for sync failures,
    /// which [`sync`](Self::sync) reports.
    pub fn append_batch_unsynced(
        &mut self,
        records: &[JournalRecord<'_>],
    ) -> Result<Vec<JournalReceipt>, JournalError> {
        if !self.healthy {
            return Err(JournalError::Poisoned);
        }
        if records.is_empty() || records.len() > MAX_BATCH_RECORDS {
            return Err(JournalError::InvalidBatch);
        }

        let mut encoded_batch = Vec::new();
        let mut receipts = Vec::with_capacity(records.len());
        let mut sequence = self.sequence;
        let mut previous_hash = self.previous_hash;
        for record in records {
            if record.plaintext.is_empty() || record.plaintext.len() > MAX_EVENT_BYTES {
                return Err(JournalError::InvalidEvent);
            }
            sequence = sequence.checked_add(1).ok_or(JournalError::Full)?;
            let receipt_id = format!("receipt_{}", Uuid::now_v7());
            let body = encode_record(
                &self.identity,
                &self.key,
                sequence,
                record.event_id,
                &receipt_id,
                previous_hash,
                record.plaintext,
            )?;
            previous_hash = sha256(&body);
            let body_len = u32::try_from(body.len()).map_err(|_| JournalError::InvalidEvent)?;
            encoded_batch.extend_from_slice(&body_len.to_le_bytes());
            encoded_batch.extend_from_slice(&body);
            receipts.push(JournalReceipt {
                receipt_id,
                event_id: record.event_id.clone(),
                producer_sequence: sequence,
            });
        }

        let batch_bytes = u64::try_from(encoded_batch.len()).map_err(|_| JournalError::Full)?;
        let new_used = self
            .used_bytes
            .checked_add(batch_bytes)
            .ok_or(JournalError::Full)?;
        let new_segment_bytes = self
            .segment_bytes
            .checked_add(batch_bytes)
            .ok_or(JournalError::Full)?;
        if new_used > self.limits.max {
            return Err(JournalError::Full);
        }
        if let Err(error) = self.file.write_all(&encoded_batch) {
            self.healthy = false;
            return Err(JournalError::Io(error));
        }
        self.used_bytes = new_used;
        self.segment_bytes = new_segment_bytes;
        self.sequence = sequence;
        self.previous_hash = previous_hash;
        self.unsynced = true;
        Ok(receipts)
    }

    /// Makes every batch appended so far durable with one sync, then rotates
    /// the segment if it has reached its size limit.
    ///
    /// Rotation follows the sync so a closed segment never contains bytes that
    /// were not durable. A sync or rotation error poisons the handle.
    ///
    /// # Errors
    /// Returns [`JournalError::Poisoned`] for an unhealthy handle, or the
    /// filesystem error that made the durable boundary unknown.
    pub fn sync(&mut self) -> Result<(), JournalError> {
        if !self.healthy {
            return Err(JournalError::Poisoned);
        }
        if self.unsynced {
            if let Err(error) = self.file.sync_data() {
                self.healthy = false;
                return Err(JournalError::Io(error));
            }
            self.unsynced = false;
            self.syncs = self.syncs.saturating_add(1);
        }
        if self.segment_bytes >= self.limits.segment_max
            && let Err(error) = self.rotate()
        {
            self.healthy = false;
            return Err(error);
        }
        Ok(())
    }

    /// Number of durability syncs this handle has performed.
    #[must_use]
    pub const fn sync_count(&self) -> u64 {
        self.syncs
    }

    /// Returns quota and readiness information while keeping paths and keys private.
    #[must_use]
    pub const fn status(&self) -> JournalStatus {
        JournalStatus {
            used_bytes: self.used_bytes,
            max_bytes: self.limits.max,
            high_watermark_reached: self.used_bytes >= self.limits.high_watermark,
            healthy: self.healthy,
        }
    }

    /// Returns the producer boot ID stored in the active segment header.
    #[must_use]
    pub fn producer_boot_id(&self) -> String {
        Uuid::from_bytes(self.identity.boot_id).to_string()
    }

    /// Authenticates historical closed records and visits them in segment order.
    ///
    /// This read is intended for startup recovery while the caller owns the
    /// journal writer. The active segment is excluded, and plaintext is
    /// zeroized after each callback. The callback remains responsible for
    /// validating its application event schema.
    ///
    /// # Errors
    /// Returns [`JournalError`] for unsafe storage, corruption, authentication
    /// failure, callback rejection, or when `max_records` is exceeded.
    pub fn visit_closed_records(
        &self,
        max_records: u64,
        mut visit: impl FnMut(&AuthenticatedJournalRecord) -> Result<(), JournalError>,
    ) -> Result<u64, JournalError> {
        if max_records == 0 {
            return Err(JournalError::InvalidLimits);
        }
        let mut visited = 0_u64;
        for path in closed_segment_paths(&self.directory)? {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(JournalError::UnsafePath);
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o277 != 0 {
                return Err(JournalError::UnsafePermissions);
            }
            let mut file = File::open(&path)?;
            let identity = read_header(&mut file)?;
            if identity.key_id != self.identity.key_id {
                return Err(JournalError::KeyMismatch);
            }
            if !segment_path_state(&path, &identity)? {
                return Err(JournalError::Corrupt("segment not closed"));
            }
            let mut expected_sequence = 1_u64;
            let mut previous_hash = ZERO_HASH;
            loop {
                let mut length = [0; 4];
                let read = read_until_full_or_eof(&mut file, &mut length)?;
                if read == 0 {
                    break;
                }
                if read != length.len() {
                    return Err(JournalError::Corrupt("closed record length"));
                }
                let body_len = usize::try_from(u32::from_le_bytes(length))
                    .map_err(|_| JournalError::Corrupt("record length"))?;
                if body_len == 0 || body_len > MAX_RECORD_BYTES {
                    return Err(JournalError::Corrupt("record length"));
                }
                let mut body = vec![0; body_len];
                if read_until_full_or_eof(&mut file, &mut body)? != body_len {
                    return Err(JournalError::Corrupt("closed record body"));
                }
                visited = visited
                    .checked_add(1)
                    .ok_or(JournalError::RecordLimitExceeded)?;
                if visited > max_records {
                    return Err(JournalError::RecordLimitExceeded);
                }
                let record = decode_record(
                    &identity,
                    &self.key,
                    &body,
                    expected_sequence,
                    previous_hash,
                )?;
                visit(&record)?;
                previous_hash = sha256(&body);
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .ok_or(JournalError::Corrupt("record sequence"))?;
            }
        }
        Ok(visited)
    }

    /// Authenticates a bounded snapshot of closed and active journal records
    /// for a read-only investigation. The active file may receive a new batch
    /// during the read; only complete records in the opened snapshot are read.
    /// Closed files must be complete. The caller validates application scope
    /// and schema before releasing any result.
    ///
    /// # Errors
    /// Returns an error for unsafe paths, invalid records, key mismatch, or
    /// exhausted record and byte budgets.
    pub fn visit_committed_records(
        directory: impl AsRef<Path>,
        expected_key_id: &str,
        key: &JournalKey,
        max_records: u64,
        max_bytes: u64,
        mut visit: impl FnMut(&AuthenticatedJournalRecord) -> Result<(), JournalError>,
    ) -> Result<u64, JournalError> {
        if max_records == 0 || max_bytes == 0 {
            return Err(JournalError::InvalidLimits);
        }
        let directory = directory.as_ref();
        prepare_existing_private_directory(directory)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // The extension is compared exactly, so unfinished `.xja.tmp` files
            // are never treated as committed segments.
            if name.starts_with("segment-")
                && Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension == "xja")
            {
                let metadata = fs::symlink_metadata(entry.path())?;
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(JournalError::UnsafePath);
                }
                #[cfg(unix)]
                if metadata.permissions().mode() & 0o277 != 0 {
                    return Err(JournalError::UnsafePermissions);
                }
                paths.push(entry.path());
            }
        }
        paths.sort();
        let mut visited = 0_u64;
        let mut scanned_bytes = 0_u64;
        for path in paths {
            let mut file = File::open(&path)?;
            let snapshot_len = file.metadata()?.len();
            scanned_bytes = scanned_bytes
                .checked_add(snapshot_len)
                .ok_or(JournalError::ReadLimitExceeded)?;
            if scanned_bytes > max_bytes {
                return Err(JournalError::ReadLimitExceeded);
            }
            let identity = read_header(&mut file)?;
            if identity.key_id != expected_key_id {
                return Err(JournalError::KeyMismatch);
            }
            let closed = segment_path_state(&path, &identity)?;
            let mut expected_sequence = 1_u64;
            let mut previous_hash = ZERO_HASH;
            loop {
                let position = file.stream_position()?;
                if position >= snapshot_len {
                    break;
                }
                let mut length = [0; 4];
                let read = read_until_full_or_eof(&mut file, &mut length)?;
                if read != length.len() {
                    if closed {
                        return Err(JournalError::Corrupt("closed record length"));
                    }
                    break;
                }
                let body_len = usize::try_from(u32::from_le_bytes(length))
                    .map_err(|_| JournalError::Corrupt("record length"))?;
                if body_len == 0 || body_len > MAX_RECORD_BYTES {
                    return Err(JournalError::Corrupt("record length"));
                }
                let end = file
                    .stream_position()?
                    .checked_add(
                        u64::try_from(body_len).map_err(|_| JournalError::ReadLimitExceeded)?,
                    )
                    .ok_or(JournalError::ReadLimitExceeded)?;
                if end > snapshot_len {
                    if closed {
                        return Err(JournalError::Corrupt("closed record body"));
                    }
                    break;
                }
                let mut body = vec![0; body_len];
                if read_until_full_or_eof(&mut file, &mut body)? != body_len {
                    return Err(JournalError::Corrupt("record body"));
                }
                visited = visited
                    .checked_add(1)
                    .ok_or(JournalError::RecordLimitExceeded)?;
                if visited > max_records {
                    return Err(JournalError::RecordLimitExceeded);
                }
                let record =
                    decode_record(&identity, key, &body, expected_sequence, previous_hash)?;
                visit(&record)?;
                previous_hash = sha256(&body);
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .ok_or(JournalError::Corrupt("record sequence"))?;
            }
        }
        Ok(visited)
    }

    /// Returns the next sequence available to a caller holding exclusive access.
    #[must_use]
    pub const fn next_sequence(&self) -> Option<u64> {
        self.sequence.checked_add(1)
    }

    fn rotate(&mut self) -> Result<(), JournalError> {
        let boot_uuid = Uuid::now_v7();
        let identity = SegmentIdentity {
            boot_id: *boot_uuid.as_bytes(),
            key_id: self.identity.key_id.clone(),
        };
        let header = encode_header(&identity)?;
        let header_bytes = u64::try_from(header.len()).map_err(|_| JournalError::InvalidLimits)?;
        let new_used = self
            .used_bytes
            .checked_add(header_bytes)
            .ok_or(JournalError::Full)?;
        if new_used > self.limits.max {
            return Err(JournalError::Full);
        }
        let (file, active_path) =
            match create_segment(&self.directory, &boot_uuid.to_string(), &header) {
                Ok(created) => created,
                Err(error) => {
                    self.healthy = false;
                    return Err(error);
                }
            };
        let closed_path = closed_segment_path(&self.active_path, &self.identity)?;
        if let Err(error) = fs::rename(&self.active_path, &closed_path)
            .and_then(|()| make_closed_segment_read_only(&closed_path))
            .and_then(|()| File::open(&self.directory)?.sync_all())
        {
            self.healthy = false;
            return Err(JournalError::Io(error));
        }
        self.file = file;
        self.active_path = active_path;
        self.identity = identity;
        self.used_bytes = new_used;
        self.segment_bytes = header_bytes;
        self.sequence = 0;
        self.previous_hash = ZERO_HASH;
        Ok(())
    }
}

fn prepare_directory(directory: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(JournalError::UnsafePath);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(directory)?;
            #[cfg(unix)]
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            sync_directory(directory)?;
            sync_directory(parent_or_current(directory))?;
        }
        Err(error) => return Err(JournalError::Io(error)),
    }
    #[cfg(unix)]
    {
        let mode = fs::metadata(directory)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(JournalError::UnsafePermissions);
        }
    }
    Ok(())
}

fn closed_segment_paths(directory: &Path) -> Result<Vec<PathBuf>, JournalError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("segment-") && name.ends_with(".closed.xja") {
            if !entry.file_type()?.is_file() {
                return Err(JournalError::UnsafePath);
            }
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn prepare_existing_private_directory(directory: &Path) -> Result<(), JournalError> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(JournalError::UnsafePath);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(JournalError::UnsafePermissions);
    }
    Ok(())
}

fn read_private_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, JournalError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > max_bytes
    {
        return Err(JournalError::UnsafePath);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(JournalError::UnsafePermissions);
    }
    fs::read(path).map_err(JournalError::Io)
}

fn make_closed_segment_read_only(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    File::open(path)?.sync_all()
}

fn parent_or_current(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_directory(path: &Path) -> Result<(), JournalError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn open_writer_lock(directory: &Path) -> Result<File, JournalError> {
    let path = directory.join("writer.lock");
    let existed = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(JournalError::UnsafePath);
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(JournalError::UnsafePermissions);
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(JournalError::Io(error)),
    };
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(JournalError::WriterActive),
        Err(TryLockError::Error(error)) => return Err(JournalError::Io(error)),
    }
    if !existed {
        file.sync_all()?;
        sync_directory(directory)?;
    }
    Ok(file)
}

fn private_new_file(path: &Path) -> Result<File, JournalError> {
    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    Ok(options.open(path)?)
}

fn create_segment(
    directory: &Path,
    boot_id: &str,
    header: &[u8],
) -> Result<(File, PathBuf), JournalError> {
    let final_path = directory.join(format!("segment-{boot_id}.xja"));
    let temporary_path = directory.join(format!("segment-{boot_id}.xja.tmp"));
    let mut file = private_new_file(&temporary_path)?;
    file.write_all(header)?;
    file.sync_all()?;
    match fs::symlink_metadata(&final_path) {
        Ok(_) => return Err(JournalError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(JournalError::Io(error)),
    }
    fs::rename(temporary_path, final_path)?;
    sync_directory(directory)?;
    let active_path = directory.join(format!("segment-{boot_id}.xja"));
    Ok((file, active_path))
}

fn segment_path_state(path: &Path, identity: &SegmentIdentity) -> Result<bool, JournalError> {
    let directory = path.parent().ok_or(JournalError::UnsafePath)?;
    let boot_id = Uuid::from_bytes(identity.boot_id);
    let active = directory.join(format!("segment-{boot_id}.xja"));
    if path == active {
        return Ok(false);
    }
    let closed = directory.join(format!("segment-{boot_id}.closed.xja"));
    if path == closed {
        return Ok(true);
    }
    Err(JournalError::Corrupt("segment filename"))
}

fn closed_segment_path(path: &Path, identity: &SegmentIdentity) -> Result<PathBuf, JournalError> {
    if segment_path_state(path, identity)? {
        return Err(JournalError::Corrupt("segment already closed"));
    }
    let directory = path.parent().ok_or(JournalError::UnsafePath)?;
    Ok(directory.join(format!(
        "segment-{}.closed.xja",
        Uuid::from_bytes(identity.boot_id)
    )))
}

fn recover_directory(
    directory: &Path,
    key_id: &str,
    key: &JournalKey,
) -> Result<(RecoveryReport, u64), JournalError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("segment-")
            && Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "tmp")
        {
            return Err(JournalError::Corrupt("unfinished segment creation"));
        }
        if name.starts_with("segment-")
            && Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "xja")
        {
            if !entry.file_type()?.is_file() {
                return Err(JournalError::UnsafePath);
            }
            paths.push(entry.path());
        }
    }
    paths.sort();

    let mut report = RecoveryReport::default();
    let mut used_bytes = 0_u64;
    let mut boot_ids = BTreeSet::new();
    let mut pending_closures = Vec::new();
    let last_index = paths.len().saturating_sub(1);
    for (index, path) in paths.into_iter().enumerate() {
        let recovered = recover_segment(&path, key_id, key, index == last_index)?;
        if !boot_ids.insert(recovered.identity.boot_id) {
            return Err(JournalError::Corrupt("duplicate producer boot id"));
        }
        if !segment_path_state(&path, &recovered.identity)? {
            pending_closures.push((
                path.clone(),
                closed_segment_path(&path, &recovered.identity)?,
            ));
        }
        report.recovered_records = report
            .recovered_records
            .checked_add(recovered.report.recovered_records)
            .ok_or(JournalError::Full)?;
        report.truncated_bytes = report
            .truncated_bytes
            .checked_add(recovered.report.truncated_bytes)
            .ok_or(JournalError::Full)?;
        used_bytes = used_bytes
            .checked_add(fs::metadata(path)?.len())
            .ok_or(JournalError::Full)?;
    }
    let closed_any = !pending_closures.is_empty();
    for (active, closed) in pending_closures {
        match fs::symlink_metadata(&closed) {
            Ok(_) => return Err(JournalError::Corrupt("duplicate producer boot id")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(JournalError::Io(error)),
        }
        fs::rename(active, &closed)?;
        make_closed_segment_read_only(&closed)?;
    }
    if closed_any {
        sync_directory(directory)?;
    }
    Ok((report, used_bytes))
}

struct RecoveredSegment {
    report: RecoveryReport,
    identity: SegmentIdentity,
    final_hash: [u8; HASH_BYTES],
}

fn recover_segment(
    path: &Path,
    expected_key_id: &str,
    key: &JournalKey,
    allow_tail_repair: bool,
) -> Result<RecoveredSegment, JournalError> {
    let closed_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".closed.xja"));
    #[cfg(unix)]
    {
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 || (closed_name && mode & 0o222 != 0) {
            return Err(JournalError::UnsafePermissions);
        }
    }
    let repair_tail = allow_tail_repair && !closed_name;
    let mut options = OpenOptions::new();
    options.read(true).write(repair_tail);
    let mut file = options.open(path)?;
    let identity = read_header(&mut file)?;
    if identity.key_id != expected_key_id {
        return Err(JournalError::KeyMismatch);
    }
    let mut report = RecoveryReport::default();
    let mut expected_sequence = 1_u64;
    let mut previous_hash = ZERO_HASH;
    loop {
        let record_start = file.stream_position()?;
        let mut length = [0; 4];
        let read = read_until_full_or_eof(&mut file, &mut length)?;
        if read == 0 {
            break;
        }
        if read < length.len() {
            if !repair_tail {
                return Err(JournalError::Corrupt("non-final segment tail"));
            }
            report.truncated_bytes = truncate_tail(&mut file, record_start)?;
            break;
        }
        let body_len = usize::try_from(u32::from_le_bytes(length))
            .map_err(|_| JournalError::Corrupt("record length"))?;
        if body_len == 0 || body_len > MAX_RECORD_BYTES {
            return Err(JournalError::Corrupt("record length"));
        }
        let mut body = vec![0; body_len];
        let read = read_until_full_or_eof(&mut file, &mut body)?;
        if read < body_len {
            if !repair_tail {
                return Err(JournalError::Corrupt("non-final segment tail"));
            }
            report.truncated_bytes = truncate_tail(&mut file, record_start)?;
            break;
        }
        validate_record(&identity, key, &body, expected_sequence, previous_hash)?;
        previous_hash = sha256(&body);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(JournalError::Corrupt("record sequence"))?;
        report.recovered_records = report
            .recovered_records
            .checked_add(1)
            .ok_or(JournalError::Full)?;
    }
    Ok(RecoveredSegment {
        report,
        identity,
        final_hash: previous_hash,
    })
}

fn truncate_tail(file: &mut File, valid_end: u64) -> Result<u64, JournalError> {
    let old_len = file.metadata()?.len();
    file.set_len(valid_end)?;
    file.sync_all()?;
    old_len
        .checked_sub(valid_end)
        .ok_or(JournalError::Corrupt("tail offset"))
}

fn read_until_full_or_eof(file: &mut impl Read, output: &mut [u8]) -> Result<usize, JournalError> {
    let mut read = 0;
    while read < output.len() {
        match file.read(&mut output[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(JournalError::Io(error)),
        }
    }
    Ok(read)
}

fn encode_header(identity: &SegmentIdentity) -> Result<Vec<u8>, JournalError> {
    let key_id_len =
        u16::try_from(identity.key_id.len()).map_err(|_| JournalError::InvalidKeyId)?;
    let mut header = Vec::with_capacity(28 + identity.key_id.len());
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    header.extend_from_slice(&identity.boot_id);
    header.extend_from_slice(&key_id_len.to_le_bytes());
    header.extend_from_slice(identity.key_id.as_bytes());
    Ok(header)
}

fn read_header(file: &mut (impl Read + Seek)) -> Result<SegmentIdentity, JournalError> {
    file.seek(SeekFrom::Start(0))?;
    let mut fixed = [0; 28];
    if read_until_full_or_eof(file, &mut fixed)? != fixed.len() {
        return Err(JournalError::Corrupt("segment header"));
    }
    if &fixed[..8] != MAGIC {
        return Err(JournalError::Corrupt("segment magic"));
    }
    let version = u16::from_le_bytes(
        fixed[8..10]
            .try_into()
            .map_err(|_| JournalError::Corrupt("segment version"))?,
    );
    if version != FORMAT_VERSION {
        return Err(JournalError::UnsupportedFormat);
    }
    let boot_id = fixed[10..26]
        .try_into()
        .map_err(|_| JournalError::Corrupt("producer boot id"))?;
    let key_id_len = usize::from(u16::from_le_bytes(
        fixed[26..28]
            .try_into()
            .map_err(|_| JournalError::Corrupt("key id length"))?,
    ));
    if key_id_len == 0 || key_id_len > MAX_KEY_ID_BYTES {
        return Err(JournalError::Corrupt("key id length"));
    }
    let mut key_id = vec![0; key_id_len];
    if read_until_full_or_eof(file, &mut key_id)? != key_id_len {
        return Err(JournalError::Corrupt("key id"));
    }
    let key_id = String::from_utf8(key_id).map_err(|_| JournalError::Corrupt("key id"))?;
    if !valid_key_id(&key_id) {
        return Err(JournalError::Corrupt("key id"));
    }
    Ok(SegmentIdentity { boot_id, key_id })
}

fn encode_record(
    identity: &SegmentIdentity,
    key: &JournalKey,
    sequence: u64,
    event_id: &EventId,
    receipt_id: &str,
    previous_hash: [u8; HASH_BYTES],
    plaintext: &[u8],
) -> Result<Vec<u8>, JournalError> {
    let event_id_bytes = event_id.as_str().as_bytes();
    let event_id_len =
        u16::try_from(event_id_bytes.len()).map_err(|_| JournalError::InvalidEvent)?;
    let receipt_id_bytes = receipt_id.as_bytes();
    let receipt_id_len =
        u16::try_from(receipt_id_bytes.len()).map_err(|_| JournalError::InvalidEvent)?;
    let mut nonce = [0; NONCE_BYTES];
    rand_bytes(&mut nonce)?;
    let aad = encode_aad(
        identity,
        sequence,
        event_id_bytes,
        receipt_id_bytes,
        &previous_hash,
    )?;
    let (ciphertext, tag) = encrypt(&key.0, &nonce, &aad, plaintext)?;
    let ciphertext_len = u32::try_from(ciphertext.len()).map_err(|_| JournalError::InvalidEvent)?;
    let mut body = Vec::with_capacity(74 + event_id_bytes.len() + ciphertext.len());
    body.extend_from_slice(&sequence.to_le_bytes());
    body.extend_from_slice(&event_id_len.to_le_bytes());
    body.extend_from_slice(event_id_bytes);
    body.extend_from_slice(&receipt_id_len.to_le_bytes());
    body.extend_from_slice(receipt_id_bytes);
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&previous_hash);
    body.extend_from_slice(&ciphertext_len.to_le_bytes());
    body.extend_from_slice(&ciphertext);
    body.extend_from_slice(&tag);
    let checksum = crc32(&body);
    body.extend_from_slice(&checksum.to_le_bytes());
    Ok(body)
}

fn validate_record(
    identity: &SegmentIdentity,
    key: &JournalKey,
    body: &[u8],
    expected_sequence: u64,
    expected_previous_hash: [u8; HASH_BYTES],
) -> Result<(), JournalError> {
    decode_record(
        identity,
        key,
        body,
        expected_sequence,
        expected_previous_hash,
    )?;
    Ok(())
}

fn decode_record(
    identity: &SegmentIdentity,
    key: &JournalKey,
    body: &[u8],
    expected_sequence: u64,
    expected_previous_hash: [u8; HASH_BYTES],
) -> Result<AuthenticatedJournalRecord, JournalError> {
    if body.len() < 80 {
        return Err(JournalError::Corrupt("record body"));
    }
    let (checksummed, checksum_bytes) = body.split_at(body.len() - 4);
    let stored_checksum = u32::from_le_bytes(
        checksum_bytes
            .try_into()
            .map_err(|_| JournalError::Corrupt("record checksum"))?,
    );
    if crc32(checksummed) != stored_checksum {
        return Err(JournalError::Corrupt("record checksum"));
    }

    let mut cursor = checksummed;
    let sequence = u64::from_le_bytes(
        take(&mut cursor, 8)?
            .try_into()
            .map_err(|_| JournalError::Corrupt("record sequence"))?,
    );
    if sequence != expected_sequence {
        return Err(JournalError::Corrupt("record sequence"));
    }
    let event_id_len = usize::from(u16::from_le_bytes(
        take(&mut cursor, 2)?
            .try_into()
            .map_err(|_| JournalError::Corrupt("event id length"))?,
    ));
    let event_id_bytes = take(&mut cursor, event_id_len)?;
    let event_id =
        std::str::from_utf8(event_id_bytes).map_err(|_| JournalError::Corrupt("event id"))?;
    let event_id =
        EventId::parse(event_id.to_owned()).map_err(|_| JournalError::Corrupt("event id"))?;
    let receipt_id_len = usize::from(u16::from_le_bytes(
        take(&mut cursor, 2)?
            .try_into()
            .map_err(|_| JournalError::Corrupt("receipt id length"))?,
    ));
    let receipt_id_bytes = take(&mut cursor, receipt_id_len)?;
    let receipt_id =
        std::str::from_utf8(receipt_id_bytes).map_err(|_| JournalError::Corrupt("receipt id"))?;
    if !valid_receipt_id(receipt_id) {
        return Err(JournalError::Corrupt("receipt id"));
    }
    let nonce: [u8; NONCE_BYTES] = take(&mut cursor, NONCE_BYTES)?
        .try_into()
        .map_err(|_| JournalError::Corrupt("nonce"))?;
    let previous_hash: [u8; HASH_BYTES] = take(&mut cursor, HASH_BYTES)?
        .try_into()
        .map_err(|_| JournalError::Corrupt("previous hash"))?;
    if previous_hash != expected_previous_hash {
        return Err(JournalError::Corrupt("hash chain"));
    }
    let ciphertext_len = usize::try_from(u32::from_le_bytes(
        take(&mut cursor, 4)?
            .try_into()
            .map_err(|_| JournalError::Corrupt("ciphertext length"))?,
    ))
    .map_err(|_| JournalError::Corrupt("ciphertext length"))?;
    let ciphertext = take(&mut cursor, ciphertext_len)?;
    let tag: [u8; TAG_BYTES] = take(&mut cursor, TAG_BYTES)?
        .try_into()
        .map_err(|_| JournalError::Corrupt("authentication tag"))?;
    if !cursor.is_empty() {
        return Err(JournalError::Corrupt("record trailing bytes"));
    }
    let aad = encode_aad(
        identity,
        sequence,
        event_id_bytes,
        receipt_id_bytes,
        &previous_hash,
    )?;
    let plaintext = decrypt(&key.0, &nonce, &aad, ciphertext, &tag)?;
    let plaintext_digest = sha256(&plaintext);
    Ok(AuthenticatedJournalRecord {
        event_id,
        receipt_id: receipt_id.to_owned(),
        producer_boot_id: Uuid::from_bytes(identity.boot_id).to_string(),
        producer_sequence: sequence,
        plaintext_digest,
        plaintext,
    })
}

fn take<'a>(cursor: &mut &'a [u8], count: usize) -> Result<&'a [u8], JournalError> {
    if cursor.len() < count {
        return Err(JournalError::Corrupt("record body"));
    }
    let (value, rest) = cursor.split_at(count);
    *cursor = rest;
    Ok(value)
}

fn encode_aad(
    identity: &SegmentIdentity,
    sequence: u64,
    event_id: &[u8],
    receipt_id: &[u8],
    previous_hash: &[u8; HASH_BYTES],
) -> Result<Vec<u8>, JournalError> {
    let key_id_len =
        u16::try_from(identity.key_id.len()).map_err(|_| JournalError::InvalidKeyId)?;
    let event_id_len = u16::try_from(event_id.len()).map_err(|_| JournalError::InvalidEvent)?;
    let receipt_id_len = u16::try_from(receipt_id.len()).map_err(|_| JournalError::InvalidEvent)?;
    let mut aad = Vec::with_capacity(70 + identity.key_id.len() + event_id.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    aad.extend_from_slice(&identity.boot_id);
    aad.extend_from_slice(&key_id_len.to_le_bytes());
    aad.extend_from_slice(identity.key_id.as_bytes());
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad.extend_from_slice(&event_id_len.to_le_bytes());
    aad.extend_from_slice(event_id);
    aad.extend_from_slice(&receipt_id_len.to_le_bytes());
    aad.extend_from_slice(receipt_id);
    aad.extend_from_slice(previous_hash);
    Ok(aad)
}

fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_BYTES]), JournalError> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce))?;
    crypter.pad(false);
    crypter.aad_update(aad)?;
    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let mut written = crypter.update(plaintext, &mut ciphertext)?;
    written += crypter.finalize(&mut ciphertext[written..])?;
    ciphertext.truncate(written);
    let mut tag = [0; TAG_BYTES];
    crypter.get_tag(&mut tag)?;
    Ok((ciphertext, tag))
}

fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_BYTES],
) -> Result<Zeroizing<Vec<u8>>, JournalError> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce))?;
    crypter.pad(false);
    crypter.aad_update(aad)?;
    crypter.set_tag(tag)?;
    let mut plaintext = Zeroizing::new(vec![0; ciphertext.len() + cipher.block_size()]);
    let mut written = crypter.update(ciphertext, &mut plaintext)?;
    written += crypter.finalize(&mut plaintext[written..])?;
    plaintext.truncate(written);
    Ok(plaintext)
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_receipt_id(value: &str) -> bool {
    value
        .strip_prefix("receipt_")
        .and_then(|uuid| Uuid::parse_str(uuid).ok())
        .is_some_and(|uuid| uuid.get_version_num() == 7)
}

/// Journal startup, integrity, capacity, or durability failure.
#[derive(Debug)]
pub enum JournalError {
    /// Encryption key is not canonical AES-256 material.
    InvalidKey,
    /// Key identifier is empty, oversized, or contains unsupported bytes.
    InvalidKeyId,
    /// Seal key identifier or Ed25519 material is not canonical.
    InvalidSealKey,
    /// Capacity or high-watermark limits are incoherent.
    InvalidLimits,
    /// Batch size is empty or exceeds the hard record-count bound.
    InvalidBatch,
    /// Event bytes are empty or exceed the per-record bound.
    InvalidEvent,
    /// A signed segment exceeds the caller's bounded publication-read limit.
    ReadLimitExceeded,
    /// A historical record scan exceeded the caller's explicit work limit.
    RecordLimitExceeded,
    /// Journal directory or segment resolves to an unsafe object type.
    UnsafePath,
    /// Journal storage is visible to group or other Unix users.
    UnsafePermissions,
    /// Existing segments use another key identifier.
    KeyMismatch,
    /// A signed manifest names another seal verification key.
    SealKeyMismatch,
    /// Another process already owns the single-writer journal lock.
    WriterActive,
    /// Segment format version is unsupported.
    UnsupportedFormat,
    /// Signed manifest format version is unsupported.
    UnsupportedSealFormat,
    /// A complete record or segment failed structural or integrity validation.
    Corrupt(&'static str),
    /// The configured hard quota cannot accept more durable bytes.
    Full,
    /// A previous write failure left this handle's durable boundary unknown.
    Poisoned,
    /// Filesystem operation failed.
    Io(io::Error),
    /// Encryption, authentication, hashing, or randomness operation failed.
    Crypto(ErrorStack),
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => formatter.write_str("invalid journal key"),
            Self::InvalidKeyId => formatter.write_str("invalid journal key id"),
            Self::InvalidSealKey => formatter.write_str("invalid journal seal key"),
            Self::InvalidLimits => formatter.write_str("invalid journal limits"),
            Self::InvalidBatch => formatter.write_str("invalid journal batch"),
            Self::InvalidEvent => formatter.write_str("invalid journal event"),
            Self::ReadLimitExceeded => formatter.write_str("journal read limit exceeded"),
            Self::RecordLimitExceeded => formatter.write_str("journal record limit exceeded"),
            Self::UnsafePath => formatter.write_str("unsafe journal path"),
            Self::UnsafePermissions => formatter.write_str("unsafe journal permissions"),
            Self::KeyMismatch => formatter.write_str("journal key id mismatch"),
            Self::SealKeyMismatch => formatter.write_str("journal seal key id mismatch"),
            Self::WriterActive => formatter.write_str("journal writer already active"),
            Self::UnsupportedFormat => formatter.write_str("unsupported journal format"),
            Self::UnsupportedSealFormat => formatter.write_str("unsupported journal seal format"),
            Self::Corrupt(kind) => write!(formatter, "corrupt journal {kind}"),
            Self::Full => formatter.write_str("journal quota exhausted"),
            Self::Poisoned => formatter.write_str("journal requires recovery"),
            Self::Io(_) => formatter.write_str("journal filesystem failure"),
            Self::Crypto(_) => formatter.write_str("journal cryptographic failure"),
        }
    }
}

impl std::error::Error for JournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for JournalError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ErrorStack> for JournalError {
    fn from(value: ErrorStack) -> Self {
        Self::Crypto(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const KEY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER_KEY_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const SEAL_KEY_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const OTHER_SEAL_KEY_HEX: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";
    const EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000001";

    fn test_directory() -> PathBuf {
        std::env::temp_dir().join(format!("xshield-journal-test-{}", Uuid::now_v7()))
    }

    fn key() -> JournalKey {
        JournalKey::from_hex(KEY_HEX).unwrap()
    }

    fn limits() -> JournalLimits {
        JournalLimits::new(1024 * 1024, 768 * 1024, 256 * 1024).unwrap()
    }

    fn segment(directory: &Path) -> PathBuf {
        fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|extension| extension == "xja"))
            .unwrap()
    }

    #[test]
    fn encrypts_syncs_and_recovers_records() {
        let directory = test_directory();
        let event = EventId::parse(EVENT).unwrap();
        let secret = br#"{"event":"request.accepted","credential":"secret-cookie"}"#;
        let (mut journal, report) =
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()).unwrap();
        assert_eq!(report, RecoveryReport::default());
        let receipts = journal
            .append_batch(&[JournalRecord {
                event_id: &event,
                plaintext: secret,
            }])
            .unwrap();
        assert_eq!(receipts[0].event_id, event);
        let receipt_id = receipts[0].receipt_id.as_bytes().to_vec();
        assert!(matches!(
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()),
            Err(JournalError::WriterActive)
        ));
        drop(journal);
        let bytes = fs::read(segment(&directory)).unwrap();
        assert!(!bytes.windows(secret.len()).any(|window| window == secret));
        assert!(
            bytes
                .windows(receipt_id.len())
                .any(|window| window == receipt_id)
        );
        assert!(matches!(
            LocalJournal::open(
                &directory,
                "journal-key-r1",
                JournalKey::from_hex(OTHER_KEY_HEX).unwrap(),
                limits()
            ),
            Err(JournalError::Crypto(_))
        ));

        let (_journal, report) =
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()).unwrap();
        assert_eq!(report.recovered_records, 1);
        assert_eq!(report.truncated_bytes, 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn truncates_only_an_incomplete_crash_tail() {
        let directory = test_directory();
        let event = EventId::parse(EVENT).unwrap();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()).unwrap();
        journal
            .append_batch(&[JournalRecord {
                event_id: &event,
                plaintext: b"complete event",
            }])
            .unwrap();
        drop(journal);
        let path = segment(&directory);
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(&[32, 0]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let (recovered_journal, report) =
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()).unwrap();
        assert_eq!(report.recovered_records, 1);
        assert_eq!(report.truncated_bytes, 2);
        drop(recovered_journal);

        let mut segments = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "xja"))
            .collect::<Vec<_>>();
        segments.sort();
        #[cfg(unix)]
        fs::set_permissions(&segments[0], fs::Permissions::from_mode(0o600)).unwrap();
        let mut old_segment = OpenOptions::new().append(true).open(&segments[0]).unwrap();
        old_segment.write_all(&[32, 0]).unwrap();
        old_segment.sync_all().unwrap();
        drop(old_segment);
        #[cfg(unix)]
        fs::set_permissions(&segments[0], fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()),
            Err(JournalError::Corrupt("non-final segment tail"))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_tampering_and_quota_exhaustion() {
        let directory = test_directory();
        let event = EventId::parse(EVENT).unwrap();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()).unwrap();
        journal
            .append_batch(&[JournalRecord {
                event_id: &event,
                plaintext: b"authenticated event",
            }])
            .unwrap();
        drop(journal);
        let path = segment(&directory);
        let length = fs::metadata(&path).unwrap().len();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(length - 5)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(matches!(
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()),
            Err(JournalError::Corrupt("record checksum"))
        ));
        fs::remove_dir_all(&directory).unwrap();

        let directory = test_directory();
        let tiny = JournalLimits::new(128, 32, 64).unwrap();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), tiny).unwrap();
        assert!(journal.status().high_watermark_reached);
        assert!(matches!(
            journal.append_batch(&[JournalRecord {
                event_id: &event,
                plaintext: &[0; 64],
            }]),
            Err(JournalError::Full)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn verifies_and_signs_an_immutable_segment_summary() {
        let directory = test_directory();
        let event = EventId::parse(EVENT).unwrap();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()).unwrap();
        journal
            .append_batch(&[JournalRecord {
                event_id: &event,
                plaintext: b"sealed event",
            }])
            .unwrap();
        drop(journal);

        let summary = verify_segment(segment(&directory), "journal-key-r1", &key()).unwrap();
        assert_eq!(summary.record_count, 1);
        assert_eq!(summary.final_sequence, 1);
        assert_ne!(summary.chain_head, ZERO_HASH);

        let signer = SealSigningKey::from_hex("seal-key-r1", SEAL_KEY_HEX).unwrap();
        let verifier = signer.verifying_key().unwrap();
        let manifest = SignedSegmentManifest::sign(&summary, &signer).unwrap();
        assert_eq!(
            SignedSegmentManifest::verify(manifest.as_bytes(), &verifier).unwrap(),
            summary
        );
        assert_eq!(
            verify_sealed_segment(
                segment(&directory),
                "journal-key-r1",
                &key(),
                manifest.as_bytes(),
                &verifier,
            )
            .unwrap(),
            summary
        );

        let mut mismatched = summary.clone();
        mismatched.segment_bytes += 1;
        let mismatched = SignedSegmentManifest::sign(&mismatched, &signer).unwrap();
        assert!(matches!(
            verify_sealed_segment(
                segment(&directory),
                "journal-key-r1",
                &key(),
                mismatched.as_bytes(),
                &verifier,
            ),
            Err(JournalError::Corrupt("seal segment mismatch"))
        ));

        let seal_directory = directory.join("sealed");
        fs::create_dir(&seal_directory).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&seal_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let manifest_path = seal_directory.join("segment.xjs");
        manifest.write_new(&manifest_path).unwrap();
        assert!(matches!(
            manifest.write_new(&manifest_path),
            Err(JournalError::UnsafePath)
        ));
        assert_eq!(
            SignedSegmentManifest::verify(&fs::read(manifest_path).unwrap(), &verifier).unwrap(),
            summary
        );

        let wrong_signer = SealSigningKey::from_hex("seal-key-r2", OTHER_SEAL_KEY_HEX).unwrap();
        assert!(matches!(
            SignedSegmentManifest::verify(
                manifest.as_bytes(),
                &wrong_signer.verifying_key().unwrap()
            ),
            Err(JournalError::SealKeyMismatch)
        ));
        let mut tampered = manifest.as_bytes().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            SignedSegmentManifest::verify(&tampered, &verifier),
            Err(JournalError::Corrupt("seal signature"))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rotates_and_idempotently_seals_closed_segments() {
        let directory = test_directory();
        let manifest_directory = test_directory();
        fs::create_dir(&manifest_directory).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&manifest_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let event = EventId::parse(EVENT).unwrap();
        let rotating_limits = JournalLimits::new(1024 * 1024, 768 * 1024, 1).unwrap();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), rotating_limits).unwrap();
        let first_boot = journal.producer_boot_id();
        journal
            .append_batch(&[JournalRecord {
                event_id: &event,
                plaintext: b"rotation event",
            }])
            .unwrap();
        assert_ne!(journal.producer_boot_id(), first_boot);

        let signer = SealSigningKey::from_hex("seal-key-r1", SEAL_KEY_HEX).unwrap();
        let sealed = seal_closed_segments(
            &directory,
            &manifest_directory,
            "journal-key-r1",
            &key(),
            &signer,
        )
        .unwrap();
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].producer_boot_id, first_boot);
        assert_eq!(
            seal_closed_segments(
                &directory,
                &manifest_directory,
                "journal-key-r1",
                &key(),
                &signer,
            )
            .unwrap(),
            sealed
        );
        assert_eq!(
            fs::read_dir(&manifest_directory).unwrap().count(),
            sealed.len()
        );
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(manifest_directory).unwrap();
    }

    #[test]
    fn streams_only_authenticated_records_from_a_signed_closed_segment() {
        let directory = test_directory();
        let manifest_directory = test_directory();
        fs::create_dir(&manifest_directory).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&manifest_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let event = EventId::parse(EVENT).unwrap();
        let rotating_limits = JournalLimits::new(1024 * 1024, 768 * 1024, 1).unwrap();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), rotating_limits).unwrap();
        journal
            .append_batch(&[
                JournalRecord {
                    event_id: &event,
                    plaintext: b"first canonical event",
                },
                JournalRecord {
                    event_id: &event,
                    plaintext: b"conflicting canonical event",
                },
            ])
            .unwrap();

        let signer = SealSigningKey::from_hex("seal-key-r1", SEAL_KEY_HEX).unwrap();
        let verifier = signer.verifying_key().unwrap();
        let sealed = seal_closed_segments(
            &directory,
            &manifest_directory,
            "journal-key-r1",
            &key(),
            &signer,
        )
        .unwrap();
        let summary = &sealed[0];
        let segment_path =
            directory.join(format!("segment-{}.closed.xja", summary.producer_boot_id));
        let manifest =
            fs::read(manifest_directory.join(format!("segment-{}.xjs", summary.producer_boot_id)))
                .unwrap();
        let journal_key = key();
        assert!(matches!(
            SealedSegmentReader::open(
                &segment_path,
                summary.segment_bytes - 1,
                "journal-key-r1",
                &journal_key,
                &manifest,
                &verifier,
            ),
            Err(JournalError::ReadLimitExceeded)
        ));
        let mut reader = SealedSegmentReader::open(
            &segment_path,
            1024 * 1024,
            "journal-key-r1",
            &journal_key,
            &manifest,
            &verifier,
        )
        .unwrap();
        assert_eq!(reader.segment(), summary);
        #[cfg(unix)]
        fs::set_permissions(&segment_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut changed = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&segment_path)
            .unwrap();
        changed.seek(SeekFrom::End(-1)).unwrap();
        let mut final_byte = [0];
        changed.read_exact(&mut final_byte).unwrap();
        changed.seek(SeekFrom::End(-1)).unwrap();
        changed.write_all(&[final_byte[0] ^ 1]).unwrap();
        changed.sync_all().unwrap();
        drop(changed);
        let first = reader.next_record().unwrap().unwrap();
        let second = reader.next_record().unwrap().unwrap();
        assert_eq!(first.event_id(), &event);
        assert_eq!(first.receipt_id().len(), 44);
        assert_eq!(first.producer_sequence(), 1);
        assert_eq!(first.plaintext(), b"first canonical event");
        assert_eq!(second.event_id(), &event);
        assert_ne!(first.plaintext_digest(), second.plaintext_digest());
        assert!(reader.next_record().unwrap().is_none());

        drop(journal);
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(manifest_directory).unwrap();
    }

    #[test]
    fn rotation_failure_poisons_the_durable_boundary() {
        let directory = test_directory();
        let event = EventId::parse(EVENT).unwrap();
        let limits = JournalLimits::new(230, 100, 1).unwrap();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), limits).unwrap();
        assert!(matches!(
            journal.append_batch(&[JournalRecord {
                event_id: &event,
                plaintext: b"x",
            }]),
            Err(JournalError::Full)
        ));
        assert!(!journal.status().healthy);
        assert!(matches!(
            journal.append_batch(&[JournalRecord {
                event_id: &event,
                plaintext: b"x",
            }]),
            Err(JournalError::Poisoned)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    // Group commit: several batches appended, one sync. The receipts are only
    // meaningful after the sync, so the test reads the journal back from disk.
    #[test]
    fn grouped_batches_are_durable_after_one_sync_and_keep_their_order() {
        let directory = test_directory();
        let events: Vec<EventId> = (1..=3)
            .map(|n| EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-00000000010{n}")).unwrap())
            .collect();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()).unwrap();
        let mut sequences = Vec::new();
        for (index, event) in events.iter().enumerate() {
            let plaintext = format!("group record {index}");
            let receipts = journal
                .append_batch_unsynced(&[JournalRecord {
                    event_id: event,
                    plaintext: plaintext.as_bytes(),
                }])
                .unwrap();
            sequences.push(receipts[0].producer_sequence);
        }
        assert_eq!(sequences, [1, 2, 3]);
        assert_eq!(
            journal.sync_count(),
            0,
            "nothing is durable before the sync"
        );
        journal.sync().unwrap();
        assert_eq!(journal.sync_count(), 1, "three batches shared one sync");
        // A second sync with nothing new is free and does not count.
        journal.sync().unwrap();
        assert_eq!(journal.sync_count(), 1);
        drop(journal);

        let (reopened, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), limits()).unwrap();
        let mut seen = Vec::new();
        reopened
            .visit_closed_records(10, |record| {
                seen.push((
                    record.producer_sequence(),
                    String::from_utf8(record.plaintext().to_vec()).unwrap(),
                ));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            seen,
            [
                (1, "group record 0".to_owned()),
                (2, "group record 1".to_owned()),
                (3, "group record 2".to_owned()),
            ]
        );
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    // One batch the journal refuses before writing a byte must not take the
    // others in its group down: the handle stays healthy and the neighbours are
    // durable after the shared sync.
    #[test]
    fn a_refused_batch_leaves_the_rest_of_its_group_intact() {
        let directory = test_directory();
        let small = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000111").unwrap();
        let big = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000112").unwrap();
        let after = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000113").unwrap();
        // Room for the header and a few small records, not for the large one.
        let tight = JournalLimits::new(6 * 1024, 4 * 1024, 5 * 1024).unwrap();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), tight).unwrap();
        assert!(
            journal
                .append_batch_unsynced(&[JournalRecord {
                    event_id: &small,
                    plaintext: b"first"
                }])
                .is_ok()
        );
        let oversized = vec![b'x'; 8 * 1024];
        assert!(matches!(
            journal.append_batch_unsynced(&[JournalRecord {
                event_id: &big,
                plaintext: &oversized
            }]),
            Err(JournalError::Full | JournalError::InvalidEvent)
        ));
        assert!(
            journal.status().healthy,
            "a refusal before any write must not poison"
        );
        assert!(
            journal
                .append_batch_unsynced(&[JournalRecord {
                    event_id: &after,
                    plaintext: b"third"
                }])
                .is_ok()
        );
        journal.sync().unwrap();
        drop(journal);

        let (reopened, _) = LocalJournal::open(&directory, "journal-key-r1", key(), tight).unwrap();
        let mut plaintexts = Vec::new();
        reopened
            .visit_closed_records(10, |record| {
                plaintexts.push(String::from_utf8(record.plaintext().to_vec()).unwrap());
                Ok(())
            })
            .unwrap();
        assert_eq!(plaintexts, ["first", "third"]);
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    // The size limit is enforced after the sync, so a closed segment never holds
    // bytes that were not durable, and a group may overshoot it by its own size.
    #[test]
    fn rotation_waits_for_the_sync_of_the_group() {
        let directory = test_directory();
        let first = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000121").unwrap();
        let second = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000122").unwrap();
        let rotating = JournalLimits::new(1024 * 1024, 768 * 1024, 1).unwrap();
        let (mut journal, _) =
            LocalJournal::open(&directory, "journal-key-r1", key(), rotating).unwrap();
        let boot = journal.producer_boot_id();
        journal
            .append_batch_unsynced(&[JournalRecord {
                event_id: &first,
                plaintext: b"one",
            }])
            .unwrap();
        journal
            .append_batch_unsynced(&[JournalRecord {
                event_id: &second,
                plaintext: b"two",
            }])
            .unwrap();
        assert_eq!(
            journal.producer_boot_id(),
            boot,
            "no rotation before the sync"
        );
        journal.sync().unwrap();
        assert_ne!(journal.producer_boot_id(), boot, "one rotation after it");
        let mut seen = Vec::new();
        journal
            .visit_closed_records(10, |record| {
                seen.push(String::from_utf8(record.plaintext().to_vec()).unwrap());
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, ["one", "two"]);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }
}
