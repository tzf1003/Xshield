//! Encrypted, bounded local audit journal with crash-tail recovery.
//!
//! The journal accepts already-serialized event bytes, encrypts every record
//! with AES-256-GCM, chains records within a producer segment, and acknowledges
//! a batch only after `sync_data`. It never logs event plaintext or key material.

#![warn(missing_docs)]

use crc32fast::hash as crc32;
use openssl::{
    error::ErrorStack,
    rand::rand_bytes,
    sha::sha256,
    symm::{Cipher, Crypter, Mode},
};
use std::{
    fmt, fs,
    fs::{File, OpenOptions, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};
use uuid::Uuid;
use xshield_core::domain::EventId;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::{fs::OpenOptionsExt, fs::PermissionsExt};

const MAGIC: &[u8; 8] = b"XSHJNL01";
const FORMAT_VERSION: u16 = 1;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HASH_BYTES: usize = 32;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_BATCH_RECORDS: usize = 64;
const MAX_RECORD_BYTES: usize = MAX_EVENT_BYTES + 256;
const ZERO_HASH: [u8; HASH_BYTES] = [0; HASH_BYTES];

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
    max_bytes: u64,
    high_watermark_bytes: u64,
}

impl JournalLimits {
    /// Validates a non-zero capacity and a threshold within that capacity.
    ///
    /// # Errors
    /// Returns [`JournalError::InvalidLimits`] for incoherent byte limits.
    pub const fn new(max_bytes: u64, high_watermark_bytes: u64) -> Result<Self, JournalError> {
        if max_bytes == 0 || high_watermark_bytes == 0 || high_watermark_bytes > max_bytes {
            return Err(JournalError::InvalidLimits);
        }
        Ok(Self {
            max_bytes,
            high_watermark_bytes,
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
    file: File,
    identity: SegmentIdentity,
    key: JournalKey,
    limits: JournalLimits,
    used_bytes: u64,
    sequence: u64,
    previous_hash: [u8; HASH_BYTES],
    healthy: bool,
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
        if used_bytes > limits.max_bytes {
            return Err(JournalError::Full);
        }

        let file = create_segment(directory, &boot_uuid.to_string(), &header)?;
        Ok((
            Self {
                _writer_lock: writer_lock,
                file,
                identity,
                key,
                limits,
                used_bytes,
                sequence: 0,
                previous_hash: ZERO_HASH,
                healthy: true,
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
        if new_used > self.limits.max_bytes {
            return Err(JournalError::Full);
        }
        if let Err(error) = self
            .file
            .write_all(&encoded_batch)
            .and_then(|()| self.file.sync_data())
        {
            self.healthy = false;
            return Err(JournalError::Io(error));
        }
        self.used_bytes = new_used;
        self.sequence = sequence;
        self.previous_hash = previous_hash;
        Ok(receipts)
    }

    /// Returns quota and readiness information while keeping paths and keys private.
    #[must_use]
    pub const fn status(&self) -> JournalStatus {
        JournalStatus {
            used_bytes: self.used_bytes,
            max_bytes: self.limits.max_bytes,
            high_watermark_reached: self.used_bytes >= self.limits.high_watermark_bytes,
            healthy: self.healthy,
        }
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

fn create_segment(directory: &Path, boot_id: &str, header: &[u8]) -> Result<File, JournalError> {
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
    Ok(file)
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
    let last_index = paths.len().saturating_sub(1);
    for (index, path) in paths.into_iter().enumerate() {
        let recovered = recover_segment(&path, key_id, key, index == last_index)?;
        report.recovered_records = report
            .recovered_records
            .checked_add(recovered.recovered_records)
            .ok_or(JournalError::Full)?;
        report.truncated_bytes = report
            .truncated_bytes
            .checked_add(recovered.truncated_bytes)
            .ok_or(JournalError::Full)?;
        used_bytes = used_bytes
            .checked_add(fs::metadata(path)?.len())
            .ok_or(JournalError::Full)?;
    }
    Ok((report, used_bytes))
}

fn recover_segment(
    path: &Path,
    expected_key_id: &str,
    key: &JournalKey,
    allow_tail_repair: bool,
) -> Result<RecoveryReport, JournalError> {
    #[cfg(unix)]
    if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
        return Err(JournalError::UnsafePermissions);
    }
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
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
            if !allow_tail_repair {
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
            if !allow_tail_repair {
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
    Ok(report)
}

fn truncate_tail(file: &mut File, valid_end: u64) -> Result<u64, JournalError> {
    let old_len = file.metadata()?.len();
    file.set_len(valid_end)?;
    file.sync_all()?;
    old_len
        .checked_sub(valid_end)
        .ok_or(JournalError::Corrupt("tail offset"))
}

fn read_until_full_or_eof(file: &mut File, output: &mut [u8]) -> Result<usize, JournalError> {
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

fn read_header(file: &mut File) -> Result<SegmentIdentity, JournalError> {
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
    decrypt(&key.0, &nonce, &aad, ciphertext, &tag)?;
    Ok(())
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
) -> Result<(), JournalError> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce))?;
    crypter.pad(false);
    crypter.aad_update(aad)?;
    crypter.set_tag(tag)?;
    let mut plaintext = Zeroizing::new(vec![0; ciphertext.len() + cipher.block_size()]);
    let mut written = crypter.update(ciphertext, &mut plaintext)?;
    written += crypter.finalize(&mut plaintext[written..])?;
    plaintext.truncate(written);
    Ok(())
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
    /// Capacity or high-watermark limits are incoherent.
    InvalidLimits,
    /// Batch size is empty or exceeds the hard record-count bound.
    InvalidBatch,
    /// Event bytes are empty or exceed the per-record bound.
    InvalidEvent,
    /// Journal directory or segment resolves to an unsafe object type.
    UnsafePath,
    /// Journal storage is visible to group or other Unix users.
    UnsafePermissions,
    /// Existing segments use another key identifier.
    KeyMismatch,
    /// Another process already owns the single-writer journal lock.
    WriterActive,
    /// Segment format version is unsupported.
    UnsupportedFormat,
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
            Self::InvalidLimits => formatter.write_str("invalid journal limits"),
            Self::InvalidBatch => formatter.write_str("invalid journal batch"),
            Self::InvalidEvent => formatter.write_str("invalid journal event"),
            Self::UnsafePath => formatter.write_str("unsafe journal path"),
            Self::UnsafePermissions => formatter.write_str("unsafe journal permissions"),
            Self::KeyMismatch => formatter.write_str("journal key id mismatch"),
            Self::WriterActive => formatter.write_str("journal writer already active"),
            Self::UnsupportedFormat => formatter.write_str("unsupported journal format"),
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
    const EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-000000000001";

    fn test_directory() -> PathBuf {
        std::env::temp_dir().join(format!("xshield-journal-test-{}", Uuid::now_v7()))
    }

    fn key() -> JournalKey {
        JournalKey::from_hex(KEY_HEX).unwrap()
    }

    fn limits() -> JournalLimits {
        JournalLimits::new(1024 * 1024, 768 * 1024).unwrap()
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
        let mut old_segment = OpenOptions::new().append(true).open(&segments[0]).unwrap();
        old_segment.write_all(&[32, 0]).unwrap();
        old_segment.sync_all().unwrap();
        drop(old_segment);
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
        let tiny = JournalLimits::new(128, 32).unwrap();
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
}
