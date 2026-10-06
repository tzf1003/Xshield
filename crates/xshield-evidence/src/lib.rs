//! Local encrypted evidence-object storage and typed manifests.

#![warn(missing_docs)]

use chrono::{DateTime, SecondsFormat, Utc};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rand::rand_bytes,
    sha::sha256,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use xshield_core::constant_time;
use xshield_core::domain::{ArtifactId, RequestId, SiteId, TenantId};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

mod calibration_lineage_review;
mod calibration_lineage_review_retention;
mod calibration_report;
mod calibration_report_retention;

pub use calibration_lineage_review::{
    AttestedCalibrationLineageReviewManifest, CALIBRATION_LINEAGE_REVIEW_CANONICAL_BODY_ENCODING,
    CALIBRATION_LINEAGE_REVIEW_EVIDENCE_MANIFEST_SCHEMA_VERSION,
    CalibrationLineageReviewEvidenceManifest, CalibrationLineageReviewEvidenceWrite,
    VerifiedCalibrationLineageReviewManifest,
};
pub use calibration_lineage_review_retention::CalibrationLineageReviewOrphanCandidate;
pub use calibration_report::{
    AttestedCalibrationReportManifest, CALIBRATION_REPORT_CANONICAL_BODY_ENCODING,
    CALIBRATION_REPORT_EVIDENCE_MANIFEST_SCHEMA_VERSION, CalibrationReportEvidenceManifest,
    CalibrationReportEvidenceWrite, VerifiedCalibrationReportManifest,
};
pub use calibration_report_retention::CalibrationReportOrphanCandidate;

const SCHEMA_VERSION: u8 = 3;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const DIGEST_HEX_BYTES: usize = 64;
const NAME_BYTES_MAX: usize = 128;
const CONTENT_TYPE_BYTES_MAX: usize = 256;
const PARENT_REFS_MAX: usize = 64;
const MANIFEST_BYTES_MAX: u64 = 64 * 1024;
const MAX_SINGLE_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_SINGLE_ENVELOPE_BYTES: u64 =
    MAX_SINGLE_ARTIFACT_BYTES as u64 + 1 + NONCE_BYTES as u64 + TAG_BYTES as u64;
const MAX_VAULT_FILES: usize = 100_000;
const MAX_RETENTION_DAYS: u16 = 3_650;
type EnvelopeParts<'a> = (&'a [u8; NONCE_BYTES], &'a [u8; TAG_BYTES], &'a [u8]);

/// Zeroizing root key used only to derive artifact-scoped AES-256-GCM keys.
pub struct EvidenceKey(Zeroizing<[u8; 32]>);

impl EvidenceKey {
    /// Parses exactly 32 bytes of lowercase hexadecimal key material.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConfig`] for malformed input.
    pub fn from_hex(value: &str) -> Result<Self, EvidenceError> {
        parse_lower_hex_32(value)
            .map(Zeroizing::new)
            .map(Self)
            .ok_or(EvidenceError::InvalidConfig)
    }
}

/// Immutable policy for one local evidence-vault instance.
pub struct EvidenceVaultConfig {
    root: PathBuf,
    key_id: String,
    max_artifact_bytes: usize,
    max_retention: chrono::TimeDelta,
}

impl EvidenceVaultConfig {
    /// Validates the storage root, non-secret key reference, and object ceiling.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConfig`] for unsafe scalar settings.
    pub fn new(
        root: impl Into<PathBuf>,
        key_id: impl Into<String>,
        max_artifact_bytes: usize,
        max_retention_days: u16,
    ) -> Result<Self, EvidenceError> {
        let root = root.into();
        let key_id = key_id.into();
        let max_retention = chrono::TimeDelta::try_days(i64::from(max_retention_days))
            .filter(|_| (1..=MAX_RETENTION_DAYS).contains(&max_retention_days))
            .ok_or(EvidenceError::InvalidConfig)?;
        if root.as_os_str().is_empty()
            || !valid_name(&key_id)
            || max_artifact_bytes == 0
            || max_artifact_bytes > MAX_SINGLE_ARTIFACT_BYTES
        {
            return Err(EvidenceError::InvalidConfig);
        }
        Ok(Self {
            root,
            key_id,
            max_artifact_bytes,
            max_retention,
        })
    }
}

/// Validated command for one complete evidence object.
pub struct EvidenceWrite<'a> {
    /// Authenticated tenant scope.
    pub tenant_id: &'a TenantId,
    /// Authenticated site scope.
    pub site_id: &'a SiteId,
    /// Request whose processing produced the object.
    pub request_id: &'a RequestId,
    /// Versioned evidence kind.
    pub kind: &'a str,
    /// Media type of the plaintext representation.
    pub content_type: &'a str,
    /// Capture fidelity declared by the trusted capture adapter.
    pub fidelity: EvidenceFidelity,
    /// Data classification applied before persistence.
    pub classification: EvidenceClassification,
    /// Earlier evidence objects transformed into this object.
    pub parent_refs: &'a [String],
    /// Exclusive UTC read deadline.
    pub expires_at: DateTime<Utc>,
    /// Exact bytes to encrypt and persist.
    pub plaintext: &'a [u8],
}

/// Supported fidelity states for a complete persisted object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFidelity {
    /// Exact application entity bytes.
    EntityExact,
    /// Semantically equivalent normalized representation.
    Semantic,
    /// Explicitly redacted representation.
    Redacted,
}

/// Evidence confidentiality classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceClassification {
    /// Internal operational data.
    Internal,
    /// Sensitive business data.
    Sensitive,
    /// Restricted evidence requiring explicit approval.
    Restricted,
}

/// Public, non-plaintext metadata for one encrypted object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifest {
    /// Manifest contract version.
    pub schema_version: u8,
    /// Random `UUIDv7` artifact identity.
    pub artifact_id: String,
    /// Request identity bound into object AAD.
    pub request_id: String,
    /// Tenant identity bound into object AAD.
    pub tenant_id: String,
    /// Site identity bound into object AAD.
    pub site_id: String,
    /// Versioned evidence kind.
    pub kind: String,
    /// Plaintext representation media type.
    pub content_type: String,
    /// Complete capture state for this MVP object writer.
    pub capture_status: String,
    /// Declared capture fidelity.
    pub fidelity: EvidenceFidelity,
    /// Plaintext bytes presented to the vault.
    pub bytes_observed: u64,
    /// Plaintext bytes encrypted by the vault.
    pub bytes_saved: u64,
    /// Confidentiality classification.
    pub classification: EvidenceClassification,
    /// Production vaults never produce synthetic fixture objects.
    pub example_only: bool,
    /// Ciphertext storage metadata.
    pub storage: EvidenceStorage,
    /// Ciphertext integrity metadata.
    pub integrity: EvidenceIntegrity,
    /// Validated parent artifact references.
    pub parent_refs: Vec<String>,
    /// Exclusive UTC read deadline.
    pub expires_at: String,
}

/// Non-secret encrypted-object locator and key reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStorage {
    /// Envelope format identifier.
    pub profile: String,
    /// Vault-relative opaque filename.
    pub locator: String,
    /// Root derivation-key reference, never key material.
    pub key_ref: Option<String>,
}

/// Ciphertext digest used for corruption detection before decryption.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIntegrity {
    /// Digest algorithm and covered representation.
    pub algorithm: String,
    /// Lowercase SHA-256 of the complete stored envelope.
    pub digest: String,
}

/// Manifest produced or authenticated by an evidence vault.
///
/// The private wrapper prevents persistence adapters from accepting an
/// untrusted struct that merely has the same public wire fields.
pub struct VerifiedEvidenceManifest(EvidenceManifest);

impl VerifiedEvidenceManifest {
    /// Returns authenticated, non-plaintext manifest metadata.
    #[must_use]
    pub const fn manifest(&self) -> &EvidenceManifest {
        &self.0
    }
}

impl EvidenceManifest {
    /// Validates catalog fields while leaving the current expiry clock to the caller.
    ///
    /// Retention workers use this for an already-expired row; content reads and
    /// publication must still use [`Self::validate_catalog_shape`].
    ///
    /// # Errors
    /// Returns [`EvidenceError`] when typed identity, storage, or manifest
    /// invariants are malformed.
    pub fn validate_catalog_structure(&self) -> Result<(), EvidenceError> {
        let tenant_id =
            TenantId::parse(&self.tenant_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let site_id = SiteId::parse(&self.site_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        validate_artifact_id(&self.artifact_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let key_id = self
            .storage
            .key_ref
            .as_deref()
            .ok_or(EvidenceError::CorruptEvidence)?;
        validate_manifest_fields(self, &tenant_id, &site_id, &self.artifact_id, key_id).map(|_| ())
    }

    /// Validates catalog metadata decoded from durable storage.
    ///
    /// This checks structure only and does not authenticate the manifest or
    /// authorize content access.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] when a field violates the manifest contract or
    /// the entry was already expired when cataloged.
    pub fn validate_catalog_shape(&self, recorded_at: DateTime<Utc>) -> Result<(), EvidenceError> {
        self.validate_catalog_structure()?;
        let expires_at = DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|_| EvidenceError::CorruptEvidence)?
            .with_timezone(&Utc);
        if expires_at <= recorded_at {
            return Err(EvidenceError::NotAvailable);
        }
        Ok(())
    }
}

/// Private local implementation of encrypted evidence storage.
pub struct LocalEvidenceVault {
    config: EvidenceVaultConfig,
    root_key: EvidenceKey,
}

/// Durable result of removing an expired ciphertext while retaining its signed metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidencePurgeOutcome {
    /// The authenticated ciphertext was removed and the directory synced.
    Removed,
    /// Ciphertext was already absent; authenticated metadata and directory sync succeeded.
    AlreadyAbsent,
}

/// A bounded local observation of a ciphertext with no catalog row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceOrphanCandidate {
    artifact_id: String,
    authenticated_manifest: bool,
    observed_bytes: u64,
    observed_modified_seconds: u64,
    observed_modified_nanos: u32,
}

impl EvidenceOrphanCandidate {
    /// Returns the artifact identity encoded by the opaque filename.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Returns whether both sidecars were authenticated at observation time.
    #[must_use]
    pub const fn authenticated_manifest(&self) -> bool {
        self.authenticated_manifest
    }

    /// Returns the observed ciphertext byte length.
    #[must_use]
    pub const fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }

    /// Returns the observed modification timestamp as Unix seconds and nanos.
    #[must_use]
    pub const fn observed_modified(&self) -> (u64, u32) {
        (self.observed_modified_seconds, self.observed_modified_nanos)
    }

    /// Reconstructs a candidate from a durable database observation.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidWrite`] for malformed identity or
    /// impossible byte/time values.
    pub fn from_observation(
        artifact_id: impl Into<String>,
        authenticated_manifest: bool,
        observed_bytes: u64,
        observed_modified_seconds: u64,
        observed_modified_nanos: u32,
    ) -> Result<Self, EvidenceError> {
        let artifact_id = artifact_id.into();
        validate_artifact_id(&artifact_id).map_err(|_| EvidenceError::InvalidWrite)?;
        if observed_bytes > MAX_SINGLE_ENVELOPE_BYTES || observed_modified_nanos >= 1_000_000_000 {
            return Err(EvidenceError::InvalidWrite);
        }
        Ok(Self {
            artifact_id,
            authenticated_manifest,
            observed_bytes,
            observed_modified_seconds,
            observed_modified_nanos,
        })
    }
}

impl LocalEvidenceVault {
    /// Opens an existing private vault directory.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] when the directory is absent, is a symlink, or
    /// grants group/other permissions on Unix.
    pub fn open(config: EvidenceVaultConfig, root_key: EvidenceKey) -> Result<Self, EvidenceError> {
        validate_private_directory(&config.root)?;
        Ok(Self { config, root_key })
    }

    /// Encrypts and durably publishes one object followed by its typed manifest.
    ///
    /// A returned manifest always names a fully synced ciphertext object. A crash
    /// before manifest publication can leave only an unreachable orphan
    /// object, which a later reconciliation pass may remove.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for invalid input, capacity, crypto, or storage
    /// failures. Existing objects are never overwritten.
    pub fn write(
        &self,
        command: &EvidenceWrite<'_>,
    ) -> Result<VerifiedEvidenceManifest, EvidenceError> {
        validate_write(
            command,
            self.config.max_artifact_bytes,
            self.config.max_retention,
            Utc::now(),
        )?;
        let artifact_id = format!("artifact_{}", Uuid::now_v7());
        let locator = format!("{artifact_id}.xev");
        let manifest_locator = format!("{artifact_id}.manifest.json");
        let manifest_auth_locator = format!("{artifact_id}.manifest.hmac");
        let aad = aad(
            command.tenant_id,
            command.site_id,
            command.request_id,
            &artifact_id,
            command.kind,
        )?;
        let data_key = derive_key(&self.root_key.0, &aad)?;
        let mut nonce = [0; NONCE_BYTES];
        rand_bytes(&mut nonce)?;
        let (ciphertext, tag) = encrypt(&data_key, &nonce, &aad, command.plaintext)?;
        let envelope = envelope(&nonce, &tag, &ciphertext)?;
        let digest = lower_hex(&sha256(&envelope));
        let bytes_saved =
            u64::try_from(command.plaintext.len()).map_err(|_| EvidenceError::InvalidWrite)?;
        let manifest = EvidenceManifest {
            schema_version: SCHEMA_VERSION,
            artifact_id,
            request_id: command.request_id.as_str().to_owned(),
            tenant_id: command.tenant_id.as_str().to_owned(),
            site_id: command.site_id.as_str().to_owned(),
            kind: command.kind.to_owned(),
            content_type: command.content_type.to_owned(),
            capture_status: "complete".to_owned(),
            fidelity: command.fidelity,
            bytes_observed: bytes_saved,
            bytes_saved,
            classification: command.classification,
            example_only: false,
            storage: EvidenceStorage {
                profile: "aead_envelope_v1".to_owned(),
                locator: locator.clone(),
                key_ref: Some(self.config.key_id.clone()),
            },
            integrity: EvidenceIntegrity {
                algorithm: "sha256_ciphertext".to_owned(),
                digest,
            },
            parent_refs: command.parent_refs.to_vec(),
            expires_at: command
                .expires_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        };
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let manifest_auth = authenticate_manifest(&self.root_key.0, &manifest_bytes)?;
        // ponytail: object-first sidecars fail closed but may leave an unreachable
        // ciphertext after a crash; add catalog reconciliation with the remote adapter.
        write_new_synced(&self.config.root, &locator, &envelope)?;
        write_new_synced(&self.config.root, &manifest_locator, &manifest_bytes)?;
        write_new_synced(&self.config.root, &manifest_auth_locator, &manifest_auth)?;
        sync_directory(&self.config.root)?;
        Ok(VerifiedEvidenceManifest(manifest))
    }

    /// Loads and validates one scoped manifest while leaving plaintext unread.
    ///
    /// # Errors
    /// Returns [`EvidenceError::NotAvailable`] uniformly for unknown, expired, or
    /// cross-scope IDs; malformed durable metadata returns corruption errors.
    pub fn read_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
    ) -> Result<VerifiedEvidenceManifest, EvidenceError> {
        self.read_manifest_at(tenant_id, site_id, artifact_id, Utc::now())
    }

    fn read_manifest_at(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedEvidenceManifest, EvidenceError> {
        let manifest = self.load_authenticated_manifest(artifact_id)?;
        validate_manifest(
            &manifest,
            tenant_id,
            site_id,
            artifact_id,
            &self.config.key_id,
            now,
        )?;
        Ok(VerifiedEvidenceManifest(manifest))
    }

    fn load_authenticated_manifest(
        &self,
        artifact_id: &str,
    ) -> Result<EvidenceManifest, EvidenceError> {
        validate_artifact_id(artifact_id)?;
        let filename = format!("{artifact_id}.manifest.json");
        let bytes = read_private_bounded(&self.config.root.join(filename), MANIFEST_BYTES_MAX)
            .map_err(hide_absence)?;
        let authentication = read_private_bounded(
            &self
                .config
                .root
                .join(format!("{artifact_id}.manifest.hmac")),
            32,
        )
        .map_err(hide_absence)?;
        let expected = authenticate_manifest(&self.root_key.0, &bytes)?;
        if !constant_time::eq(&authentication, &expected) {
            return Err(EvidenceError::CorruptEvidence);
        }
        serde_json::from_slice(&bytes).map_err(|_| EvidenceError::CorruptEvidence)
    }

    /// Removes only expired ciphertext matching the exact catalog manifest.
    ///
    /// The caller must hold the exclusive vault-directory lock and durably audit
    /// deletion intent before calling. Signed sidecars remain for crash retries;
    /// this does not erase backups, exported copies, or catalog metadata.
    /// Reads at most one configured-size ciphertext; never decrypts content.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] on unexpired, mismatched, unsafe or corrupt
    /// evidence, or failed removal/sync. A sync failure may follow removal;
    /// retry with the same expected manifest before declaring completion.
    pub fn purge_expired(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &EvidenceManifest,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        self.purge_expired_at(tenant_id, site_id, expected, Utc::now())
    }

    /// Finds old ciphertexts which have no catalog entry and are safe to hand
    /// to the durable retention adapter. A complete, authenticated sidecar set
    /// is accepted; partial or malformed sidecars are deliberately skipped.
    ///
    /// The root must already be exclusively locked by the caller. The scan is
    /// bounded by the configured file ceiling and the requested batch size.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for an unsafe root or an invalid bound.
    pub fn list_orphan_candidates(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        grace: Duration,
        limit: u16,
    ) -> Result<Vec<EvidenceOrphanCandidate>, EvidenceError> {
        self.list_orphan_candidates_after(tenant_id, site_id, grace, limit, None)
    }

    /// Finds the next lexical page of old ciphertexts after an artifact ID.
    /// The cursor lets the database adapter skip cataloged files without
    /// starving later local orphans behind a bounded page.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for an unsafe root, invalid bound, or cursor.
    pub fn list_orphan_candidates_after(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        grace: Duration,
        limit: u16,
        after: Option<&str>,
    ) -> Result<Vec<EvidenceOrphanCandidate>, EvidenceError> {
        if !(1..=32).contains(&limit) || grace.is_zero() || grace > Duration::from_hours(720) {
            return Err(EvidenceError::InvalidConfig);
        }
        if after.is_some_and(|cursor| validate_artifact_id(cursor).is_err()) {
            return Err(EvidenceError::InvalidConfig);
        }
        validate_private_directory(&self.config.root)?;
        let now = SystemTime::now();
        let mut names = Vec::new();
        let mut file_count = 0usize;
        for entry in fs::read_dir(&self.config.root)? {
            let entry = entry?;
            file_count = file_count.checked_add(1).ok_or(EvidenceError::UnsafePath)?;
            if file_count > MAX_VAULT_FILES {
                return Err(EvidenceError::UnsafePath);
            }
            let metadata = entry.path().symlink_metadata()?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(EvidenceError::UnsafePath);
            }
            if metadata.len() > self.max_envelope_bytes() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some((artifact_id, extension)) = name.rsplit_once('.') else {
                continue;
            };
            if extension.as_bytes() == b"xev" && !artifact_id.is_empty() {
                names.push((name, metadata));
            }
        }
        names.sort_by(|left, right| left.0.cmp(&right.0));
        let mut candidates = Vec::new();
        for (name, metadata) in names {
            if candidates.len() == usize::from(limit) {
                break;
            }
            let modified = metadata.modified().map_err(EvidenceError::Io)?;
            if now.duration_since(modified).unwrap_or_default() < grace {
                continue;
            }
            let artifact_id = name.strip_suffix(".xev").unwrap_or_default();
            if validate_artifact_id(artifact_id).is_err() {
                continue;
            }
            if after.is_some_and(|cursor| artifact_id <= cursor) {
                continue;
            }
            let has_manifest = sidecar_present(
                &self
                    .config
                    .root
                    .join(format!("{artifact_id}.manifest.json")),
            )?;
            let has_hmac = sidecar_present(
                &self
                    .config
                    .root
                    .join(format!("{artifact_id}.manifest.hmac")),
            )?;
            // Dedicated objects have their own authenticated retention
            // contracts. Generic reconciliation cannot validate either family.
            if dedicated_sidecars_present(&self.config.root, artifact_id)? {
                continue;
            }
            let authenticated_manifest = match (has_manifest, has_hmac) {
                (false, false) => false,
                (true, true) => {
                    let Ok(manifest) = self.load_authenticated_manifest(artifact_id) else {
                        continue;
                    };
                    if validate_manifest_fields(
                        &manifest,
                        tenant_id,
                        site_id,
                        artifact_id,
                        &self.config.key_id,
                    )
                    .is_err()
                    {
                        continue;
                    }
                    true
                }
                _ => continue,
            };
            let modified = modified
                .duration_since(UNIX_EPOCH)
                .map_err(|_| EvidenceError::UnsafePath)?;
            candidates.push(EvidenceOrphanCandidate {
                artifact_id: artifact_id.to_owned(),
                authenticated_manifest,
                observed_bytes: metadata.len(),
                observed_modified_seconds: modified.as_secs(),
                observed_modified_nanos: modified.subsec_nanos(),
            });
        }
        Ok(candidates)
    }

    /// Removes one previously observed orphan ciphertext after rechecking its
    /// path, size, timestamp and optional authenticated sidecars.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] when the file was replaced, sidecars changed,
    /// or the local storage is unsafe. An absent ciphertext is idempotent.
    pub fn purge_orphan(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        candidate: &EvidenceOrphanCandidate,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        validate_private_directory(&self.config.root)?;
        let path = self
            .config
            .root
            .join(format!("{}.xev", candidate.artifact_id));
        let metadata = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(EvidencePurgeOutcome::AlreadyAbsent);
            }
            Err(error) => return Err(EvidenceError::Io(error)),
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != candidate.observed_bytes
        {
            return Err(EvidenceError::UnsafePath);
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(EvidenceError::UnsafePermissions);
        }
        let modified = metadata
            .modified()
            .map_err(EvidenceError::Io)?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| EvidenceError::UnsafePath)?;
        if (modified.as_secs(), modified.subsec_nanos()) != candidate.observed_modified() {
            return Err(EvidenceError::UnsafePath);
        }
        if candidate.authenticated_manifest {
            let manifest = self.load_authenticated_manifest(&candidate.artifact_id)?;
            validate_manifest_fields(
                &manifest,
                tenant_id,
                site_id,
                &candidate.artifact_id,
                &self.config.key_id,
            )?;
            let envelope = read_private_bounded(&path, self.max_envelope_bytes())?;
            if lower_hex(&sha256(&envelope)) != manifest.integrity.digest {
                return Err(EvidenceError::CorruptEvidence);
            }
        } else {
            for suffix in [
                "manifest.json",
                "manifest.hmac",
                calibration_report::MANIFEST_FILENAME_SUFFIX,
                calibration_report::MANIFEST_AUTH_FILENAME_SUFFIX,
                calibration_lineage_review::MANIFEST_FILENAME_SUFFIX,
                calibration_lineage_review::MANIFEST_AUTH_FILENAME_SUFFIX,
            ] {
                if sidecar_present(
                    &self
                        .config
                        .root
                        .join(format!("{}.{}", candidate.artifact_id, suffix)),
                )? {
                    return Err(EvidenceError::CorruptEvidence);
                }
            }
        }
        fs::remove_file(path)?;
        sync_directory(&self.config.root)?;
        Ok(EvidencePurgeOutcome::Removed)
    }

    fn max_envelope_bytes(&self) -> u64 {
        self.config.max_artifact_bytes as u64 + 1 + NONCE_BYTES as u64 + TAG_BYTES as u64
    }

    fn purge_expired_at(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &EvidenceManifest,
        now: DateTime<Utc>,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        validate_private_directory(&self.config.root)?;
        let manifest = self.load_authenticated_manifest(&expected.artifact_id)?;
        let expires_at = validate_manifest_fields(
            &manifest,
            tenant_id,
            site_id,
            &expected.artifact_id,
            &self.config.key_id,
        )?;
        if &manifest != expected {
            return Err(EvidenceError::CorruptEvidence);
        }
        if expires_at > now {
            return Err(EvidenceError::NotAvailable);
        }
        let path = self.config.root.join(&manifest.storage.locator);
        let outcome = match read_private_bounded(
            &path,
            self.config.max_artifact_bytes as u64 + 1 + NONCE_BYTES as u64 + TAG_BYTES as u64,
        ) {
            Ok(envelope) => {
                if lower_hex(&sha256(&envelope)) != manifest.integrity.digest {
                    return Err(EvidenceError::CorruptEvidence);
                }
                fs::remove_file(path)?;
                EvidencePurgeOutcome::Removed
            }
            Err(EvidenceError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                EvidencePurgeOutcome::AlreadyAbsent
            }
            Err(error) => return Err(error),
        };
        sync_directory(&self.config.root)?;
        Ok(outcome)
    }

    /// Authenticates and decrypts one unexpired object in the supplied scope.
    ///
    /// Callers must separately enforce the requested metadata/content approval;
    /// this adapter rechecks scope, expiry, storage identity, digest, and AEAD.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for unavailable, corrupt, oversized, or
    /// unauthentic evidence.
    pub fn read_content(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
        self.read_content_at(tenant_id, site_id, artifact_id, Utc::now())
    }

    fn read_content_at(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
        let verified = self.read_manifest_at(tenant_id, site_id, artifact_id, now)?;
        self.decrypt_verified_manifest(tenant_id, site_id, artifact_id, verified.manifest())
    }

    /// Authenticates, decrypts, and binds content to an already authorized manifest.
    ///
    /// The vault reloads the authenticated sidecars before and after decryption
    /// and compares both observations to `expected`. This keeps a caller's
    /// catalog comparison coupled to the decrypted object even if a privileged
    /// retention or reconciliation process races this read. It does not grant
    /// content access; callers must establish their own authorization first.
    ///
    /// # Errors
    /// Returns [`EvidenceError::CorruptEvidence`] when either authenticated
    /// sidecar observation differs from `expected`, or when digest, AEAD, or
    /// plaintext-length validation fails. Other error semantics match
    /// [`Self::read_content`].
    pub fn read_content_matching_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &VerifiedEvidenceManifest,
    ) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
        let manifest = expected.manifest();
        let artifact_id = manifest.artifact_id.as_str();
        let now = Utc::now();
        let observed = self.read_manifest_at(tenant_id, site_id, artifact_id, now)?;
        if observed.manifest() != manifest {
            return Err(EvidenceError::CorruptEvidence);
        }
        let plaintext =
            self.decrypt_verified_manifest(tenant_id, site_id, artifact_id, manifest)?;
        let current = self.read_manifest_at(tenant_id, site_id, artifact_id, Utc::now())?;
        if current.manifest() != manifest {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(plaintext)
    }

    fn decrypt_verified_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
        manifest: &EvidenceManifest,
    ) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
        let max_envelope = u64::try_from(self.config.max_artifact_bytes)
            .map_err(|_| EvidenceError::InvalidConfig)?
            .checked_add(
                u64::try_from(1 + NONCE_BYTES + TAG_BYTES)
                    .map_err(|_| EvidenceError::InvalidConfig)?,
            )
            .ok_or(EvidenceError::InvalidConfig)?;
        let envelope = read_private_bounded(
            &self.config.root.join(&manifest.storage.locator),
            max_envelope,
        )
        .map_err(hide_absence)?;
        if lower_hex(&sha256(&envelope)) != manifest.integrity.digest {
            return Err(EvidenceError::CorruptEvidence);
        }
        let (nonce, tag, ciphertext) = parse_envelope(&envelope)?;
        let request_id =
            RequestId::parse(&manifest.request_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let aad = aad(tenant_id, site_id, &request_id, artifact_id, &manifest.kind)?;
        let data_key = derive_key(&self.root_key.0, &aad)?;
        let plaintext = decrypt(&data_key, nonce, &aad, ciphertext, tag)?;
        if u64::try_from(plaintext.len()).map_err(|_| EvidenceError::CorruptEvidence)?
            != manifest.bytes_saved
        {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(Zeroizing::new(plaintext))
    }
}

fn validate_write(
    command: &EvidenceWrite<'_>,
    max_bytes: usize,
    max_retention: chrono::TimeDelta,
    now: DateTime<Utc>,
) -> Result<(), EvidenceError> {
    let unique_parents = command.parent_refs.iter().collect::<BTreeSet<_>>();
    let max_expires_at = now
        .checked_add_signed(max_retention)
        .ok_or(EvidenceError::InvalidConfig)?;
    if !valid_name(command.kind)
        || command.content_type.is_empty()
        || command.content_type.len() > CONTENT_TYPE_BYTES_MAX
        || command
            .content_type
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || command.plaintext.len() > max_bytes
        || command.expires_at <= now
        || command.expires_at > max_expires_at
        || command.parent_refs.len() > PARENT_REFS_MAX
        || unique_parents.len() != command.parent_refs.len()
        || command
            .parent_refs
            .iter()
            .any(|value| validate_artifact_id(value).is_err())
    {
        return Err(EvidenceError::InvalidWrite);
    }
    Ok(())
}

fn validate_manifest(
    manifest: &EvidenceManifest,
    tenant_id: &TenantId,
    site_id: &SiteId,
    artifact_id: &str,
    key_id: &str,
    now: DateTime<Utc>,
) -> Result<(), EvidenceError> {
    let expires_at = validate_manifest_fields(manifest, tenant_id, site_id, artifact_id, key_id)?;
    if expires_at <= now {
        return Err(EvidenceError::NotAvailable);
    }
    Ok(())
}

fn validate_manifest_fields(
    manifest: &EvidenceManifest,
    tenant_id: &TenantId,
    site_id: &SiteId,
    artifact_id: &str,
    key_id: &str,
) -> Result<DateTime<Utc>, EvidenceError> {
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .map_err(|_| EvidenceError::CorruptEvidence)?
        .with_timezone(&Utc);
    if manifest.tenant_id != tenant_id.as_str() || manifest.site_id != site_id.as_str() {
        return Err(EvidenceError::NotAvailable);
    }
    let unique_parents = manifest.parent_refs.iter().collect::<BTreeSet<_>>();
    if manifest.schema_version != SCHEMA_VERSION
        || manifest.artifact_id != artifact_id
        || RequestId::parse(&manifest.request_id).is_err()
        || !valid_name(&manifest.kind)
        || manifest.content_type.is_empty()
        || manifest.content_type.len() > CONTENT_TYPE_BYTES_MAX
        || manifest
            .content_type
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || manifest.capture_status != "complete"
        || manifest.bytes_observed != manifest.bytes_saved
        || manifest.bytes_saved > MAX_SINGLE_ARTIFACT_BYTES as u64
        || manifest.example_only
        || manifest.storage.profile != "aead_envelope_v1"
        || manifest.storage.locator != format!("{artifact_id}.xev")
        || manifest.storage.key_ref.as_deref() != Some(key_id)
        || !valid_name(key_id)
        || manifest.integrity.algorithm != "sha256_ciphertext"
        || !valid_lower_hex(&manifest.integrity.digest, DIGEST_HEX_BYTES)
        || manifest.parent_refs.len() > PARENT_REFS_MAX
        || unique_parents.len() != manifest.parent_refs.len()
        || manifest
            .parent_refs
            .iter()
            .any(|value| validate_artifact_id(value).is_err())
    {
        return Err(EvidenceError::CorruptEvidence);
    }
    Ok(expires_at)
}

fn aad(
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
    artifact_id: &str,
    kind: &str,
) -> Result<Vec<u8>, EvidenceError> {
    let mut output = Vec::new();
    for component in [
        b"xshield-evidence-v1".as_slice(),
        &[SCHEMA_VERSION],
        tenant_id.as_str().as_bytes(),
        site_id.as_str().as_bytes(),
        request_id.as_str().as_bytes(),
        artifact_id.as_bytes(),
        kind.as_bytes(),
        b"chunk-0-final",
    ] {
        let length = u64::try_from(component.len()).map_err(|_| EvidenceError::InvalidWrite)?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(component);
    }
    Ok(output)
}

pub(crate) fn derive_key(
    root_key: &[u8; 32],
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>, EvidenceError> {
    let key = PKey::hmac(root_key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(b"xshield-evidence-data-key-v1")?;
    signer.update(aad)?;
    let derived: [u8; 32] = signer
        .sign_to_vec()?
        .try_into()
        .map_err(|_| EvidenceError::Crypto)?;
    Ok(Zeroizing::new(derived))
}

pub(crate) fn authenticate_manifest(
    root_key: &[u8; 32],
    manifest: &[u8],
) -> Result<[u8; 32], EvidenceError> {
    let key = PKey::hmac(root_key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(b"xshield-evidence-manifest-v1")?;
    signer.update(manifest)?;
    signer
        .sign_to_vec()?
        .try_into()
        .map_err(|_| EvidenceError::Crypto)
}

pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_BYTES]), EvidenceError> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce))?;
    crypter.aad_update(aad)?;
    let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
    let mut written = crypter.update(plaintext, &mut ciphertext)?;
    written += crypter.finalize(&mut ciphertext[written..])?;
    ciphertext.truncate(written);
    let mut tag = [0; TAG_BYTES];
    crypter.get_tag(&mut tag)?;
    Ok((ciphertext, tag))
}

pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_BYTES],
) -> Result<Vec<u8>, EvidenceError> {
    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(nonce))?;
    crypter.aad_update(aad)?;
    crypter.set_tag(tag)?;
    let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
    let mut written = crypter.update(ciphertext, &mut plaintext)?;
    written += crypter
        .finalize(&mut plaintext[written..])
        .map_err(|_| EvidenceError::CorruptEvidence)?;
    plaintext.truncate(written);
    Ok(plaintext)
}

pub(crate) fn envelope(
    nonce: &[u8; NONCE_BYTES],
    tag: &[u8; TAG_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EvidenceError> {
    let mut output = Vec::with_capacity(
        1usize
            .checked_add(NONCE_BYTES + TAG_BYTES)
            .and_then(|size| size.checked_add(ciphertext.len()))
            .ok_or(EvidenceError::InvalidWrite)?,
    );
    output.push(1);
    output.extend_from_slice(nonce);
    output.extend_from_slice(tag);
    output.extend_from_slice(ciphertext);
    Ok(output)
}

pub(crate) fn parse_envelope(envelope: &[u8]) -> Result<EnvelopeParts<'_>, EvidenceError> {
    let minimum = 1 + NONCE_BYTES + TAG_BYTES;
    if envelope.len() < minimum || envelope[0] != 1 {
        return Err(EvidenceError::CorruptEvidence);
    }
    let nonce = envelope[1..=NONCE_BYTES]
        .try_into()
        .map_err(|_| EvidenceError::CorruptEvidence)?;
    let tag = envelope[1 + NONCE_BYTES..minimum]
        .try_into()
        .map_err(|_| EvidenceError::CorruptEvidence)?;
    Ok((nonce, tag, &envelope[minimum..]))
}

pub(crate) fn write_new_synced(
    root: &Path,
    filename: &str,
    bytes: &[u8],
) -> Result<(), EvidenceError> {
    let path = root.join(filename);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn read_private_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, EvidenceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(EvidenceError::UnsafePath);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(EvidenceError::UnsafePermissions);
    }
    let file = File::open(path)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| EvidenceError::UnsafePath)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes.checked_add(1).ok_or(EvidenceError::UnsafePath)?)
        .read_to_end(&mut bytes)?;
    if bytes.len() > capacity {
        return Err(EvidenceError::UnsafePath);
    }
    Ok(bytes)
}

fn sidecar_present(path: &Path) -> Result<bool, EvidenceError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(EvidenceError::Io(error)),
    }
}

fn dedicated_sidecars_present(root: &Path, artifact_id: &str) -> Result<bool, EvidenceError> {
    Ok(calibration_report::sidecars_present(root, artifact_id)?
        || calibration_lineage_review::sidecars_present(root, artifact_id)?)
}

fn validate_private_directory(path: &Path) -> Result<(), EvidenceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(EvidenceError::UnsafePath);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(EvidenceError::UnsafePermissions);
    }
    Ok(())
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), EvidenceError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

pub(crate) fn hide_absence(error: EvidenceError) -> EvidenceError {
    match error {
        EvidenceError::Io(ref inner) if inner.kind() == io::ErrorKind::NotFound => {
            EvidenceError::NotAvailable
        }
        other => other,
    }
}

pub(crate) fn validate_artifact_id(value: &str) -> Result<(), EvidenceError> {
    ArtifactId::parse(value)
        .map(|_| ())
        .map_err(|_| EvidenceError::NotAvailable)
}

pub(crate) fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= NAME_BYTES_MAX
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

pub(crate) fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if !valid_lower_hex(value, 64) {
        return None;
    }
    let mut decoded = [0; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        decoded[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Some(decoded)
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

pub(crate) fn lower_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Configuration, validation, crypto, or durable-storage failure.
#[derive(Debug)]
pub enum EvidenceError {
    /// Trusted vault configuration is invalid.
    InvalidConfig,
    /// Capture input violates the complete-object contract.
    InvalidWrite,
    /// Object is absent, expired, or outside the supplied scope.
    NotAvailable,
    /// A filesystem object has an unsafe type or size.
    UnsafePath,
    /// A vault path is readable by group or others on Unix.
    UnsafePermissions,
    /// Stored metadata, digest, or authenticated ciphertext is corrupt.
    CorruptEvidence,
    /// Cryptographic primitive setup failed.
    Crypto,
    /// Filesystem operation failed.
    Io(io::Error),
    /// Manifest serialization or decoding failed.
    Json(serde_json::Error),
    /// OpenSSL operation failed.
    OpenSsl(openssl::error::ErrorStack),
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("invalid evidence vault configuration"),
            Self::InvalidWrite => formatter.write_str("invalid evidence capture"),
            Self::NotAvailable => formatter.write_str("evidence is unavailable"),
            Self::UnsafePath => formatter.write_str("unsafe evidence storage path"),
            Self::UnsafePermissions => formatter.write_str("unsafe evidence storage permissions"),
            Self::CorruptEvidence => formatter.write_str("corrupt evidence"),
            Self::Crypto | Self::OpenSsl(_) => formatter.write_str("evidence cryptography failed"),
            Self::Io(_) => formatter.write_str("evidence storage failed"),
            Self::Json(_) => formatter.write_str("evidence manifest processing failed"),
        }
    }
}

impl std::error::Error for EvidenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::OpenSsl(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for EvidenceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for EvidenceError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<openssl::error::ErrorStack> for EvidenceError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::OpenSsl(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EvidenceClassification, EvidenceError, EvidenceFidelity, EvidenceKey, EvidencePurgeOutcome,
        EvidenceVaultConfig, EvidenceWrite, LocalEvidenceVault, MAX_SINGLE_ARTIFACT_BYTES,
    };
    use chrono::{TimeDelta, Utc};
    use std::{fs, path::PathBuf, time::Duration};
    use uuid::Uuid;
    use xshield_core::domain::{RequestId, SiteId, TenantId};

    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn encrypts_scopes_expires_and_authenticates_evidence() {
        let root = private_temp_directory();
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "evidence-key-r1", 1024, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        let expires_at = Utc::now() + TimeDelta::minutes(5);
        let secret = b"sensitive-body";
        let verified = vault
            .write(&EvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                request_id: &request,
                kind: "request_decoded",
                content_type: "application/json",
                fidelity: EvidenceFidelity::EntityExact,
                classification: EvidenceClassification::Restricted,
                parent_refs: &[],
                expires_at,
                plaintext: secret,
            })
            .unwrap();
        let manifest = verified.manifest();
        assert_eq!(manifest.capture_status, "complete");
        assert_eq!(manifest.bytes_saved, secret.len() as u64);
        assert_eq!(manifest.integrity.digest.len(), 64);
        let ciphertext = fs::read(root.join(&manifest.storage.locator)).unwrap();
        assert!(
            !ciphertext
                .windows(secret.len())
                .any(|window| window == secret)
        );
        assert_eq!(
            vault
                .read_content(&tenant, &site, &manifest.artifact_id)
                .unwrap()
                .as_slice(),
            secret
        );
        assert!(matches!(
            vault.read_manifest(
                &TenantId::parse("tenant_b").unwrap(),
                &site,
                &manifest.artifact_id
            ),
            Err(EvidenceError::NotAvailable)
        ));
        assert!(matches!(
            vault.read_content_at(
                &tenant,
                &site,
                &manifest.artifact_id,
                expires_at + TimeDelta::seconds(1)
            ),
            Err(EvidenceError::NotAvailable)
        ));

        let manifest_path = root.join(format!("{}.manifest.json", manifest.artifact_id));
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        let mut tampered_manifest = manifest_bytes.clone();
        tampered_manifest[0] ^= 1;
        fs::write(&manifest_path, tampered_manifest).unwrap();
        assert!(matches!(
            vault.read_manifest(&tenant, &site, &manifest.artifact_id),
            Err(EvidenceError::CorruptEvidence)
        ));
        fs::write(&manifest_path, manifest_bytes).unwrap();

        let mut tampered = ciphertext;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        fs::write(root.join(&manifest.storage.locator), tampered).unwrap();
        assert!(matches!(
            vault.read_content(&tenant, &site, &manifest.artifact_id),
            Err(EvidenceError::CorruptEvidence)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn content_matching_manifest_rejects_a_different_authenticated_object() {
        let root = private_temp_directory();
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "evidence-key-r1", 1024, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        let first = vault
            .write(&EvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                request_id: &request,
                kind: "request_decoded",
                content_type: "application/json",
                fidelity: EvidenceFidelity::EntityExact,
                classification: EvidenceClassification::Restricted,
                parent_refs: &[],
                expires_at: Utc::now() + TimeDelta::minutes(5),
                plaintext: b"first",
            })
            .unwrap();
        let second = vault
            .write(&EvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                request_id: &request,
                kind: "request_decoded",
                content_type: "application/json",
                fidelity: EvidenceFidelity::EntityExact,
                classification: EvidenceClassification::Restricted,
                parent_refs: &[],
                expires_at: Utc::now() + TimeDelta::minutes(5),
                plaintext: b"second",
            })
            .unwrap();
        assert!(matches!(
            vault.read_content_matching_manifest(&tenant, &site, &first),
            Ok(content) if content.as_slice() == b"first"
        ));
        let first_manifest = root.join(format!("{}.manifest.json", first.manifest().artifact_id));
        let second_manifest = root.join(format!("{}.manifest.json", second.manifest().artifact_id));
        fs::rename(&second_manifest, &first_manifest).unwrap();
        assert!(matches!(
            vault.read_content_matching_manifest(&tenant, &site, &first),
            Err(EvidenceError::CorruptEvidence)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_weak_keys_unsafe_directories_and_oversize_content() {
        assert!(matches!(
            EvidenceKey::from_hex("not-a-key"),
            Err(EvidenceError::InvalidConfig)
        ));
        let root = private_temp_directory();
        assert!(matches!(
            EvidenceVaultConfig::new(&root, "evidence-key-r1", MAX_SINGLE_ARTIFACT_BYTES + 1, 30),
            Err(EvidenceError::InvalidConfig)
        ));
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "evidence-key-r1", 1, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        assert!(matches!(
            vault.write(&EvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                request_id: &request,
                kind: "request_ingress",
                content_type: "application/octet-stream",
                fidelity: EvidenceFidelity::EntityExact,
                classification: EvidenceClassification::Sensitive,
                parent_refs: &[],
                expires_at: Utc::now() + TimeDelta::minutes(1),
                plaintext: b"too large",
            }),
            Err(EvidenceError::InvalidWrite)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn purge_requires_exact_authenticated_expiry_and_retries_after_removal() {
        let root = private_temp_directory();
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "evidence-key-r1", 1024, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_purge").unwrap();
        let site = SiteId::parse("site_purge").unwrap();
        let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
        let expires = Utc::now() + TimeDelta::minutes(5);
        let verified = vault
            .write(&EvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                request_id: &request,
                kind: "response_decoded",
                content_type: "application/json",
                fidelity: EvidenceFidelity::Redacted,
                classification: EvidenceClassification::Restricted,
                parent_refs: &[],
                expires_at: expires,
                plaintext: b"{}",
            })
            .unwrap();
        let manifest = verified.manifest();
        let after = expires + TimeDelta::seconds(1);
        let path = root.join(&manifest.storage.locator);
        let original = fs::read(&path).unwrap();
        assert!(vault.purge_expired(&tenant, &site, manifest).is_err());
        assert!(
            vault
                .purge_expired_at(
                    &TenantId::parse("tenant_other").unwrap(),
                    &site,
                    manifest,
                    after
                )
                .is_err()
        );
        let wrong_key = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "evidence-key-r1", 1024, 30).unwrap(),
            EvidenceKey::from_hex(&"22".repeat(32)).unwrap(),
        )
        .unwrap();
        assert!(
            wrong_key
                .purge_expired_at(&tenant, &site, manifest, after)
                .is_err()
        );
        let mut changed = manifest.clone();
        changed.expires_at = Utc::now().to_rfc3339();
        assert!(
            vault
                .purge_expired_at(&tenant, &site, &changed, after)
                .is_err()
        );
        fs::write(&path, b"corrupt").unwrap();
        assert!(matches!(
            vault.purge_expired_at(&tenant, &site, manifest, after),
            Err(EvidenceError::CorruptEvidence)
        ));
        assert!(path.exists());
        fs::write(&path, &original).unwrap();
        #[cfg(unix)]
        {
            let backup = root.join("backup.xev");
            fs::rename(&path, &backup).unwrap();
            std::os::unix::fs::symlink(&backup, &path).unwrap();
            assert!(
                vault
                    .purge_expired_at(&tenant, &site, manifest, after)
                    .is_err()
            );
            assert_eq!(fs::read(&backup).unwrap(), original);
            fs::remove_file(&path).unwrap();
            fs::rename(&backup, &path).unwrap();
        }
        assert_eq!(
            vault
                .purge_expired_at(&tenant, &site, manifest, after)
                .unwrap(),
            super::EvidencePurgeOutcome::Removed
        );
        assert!(!path.exists());
        assert_eq!(
            vault
                .purge_expired_at(&tenant, &site, manifest, after)
                .unwrap(),
            super::EvidencePurgeOutcome::AlreadyAbsent
        );
        fs::write(
            root.join(format!("{}.manifest.hmac", manifest.artifact_id)),
            [0; 32],
        )
        .unwrap();
        assert!(
            vault
                .purge_expired_at(&tenant, &site, manifest, after)
                .is_err()
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn orphan_scan_is_bounded_and_keeps_partial_sidecars() {
        let root = private_temp_directory();
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "evidence-key-r1", 1024, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_orphan").unwrap();
        let site = SiteId::parse("site_orphan").unwrap();
        let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
        let complete = vault
            .write(&EvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                request_id: &request,
                kind: "response_decoded",
                content_type: "application/json",
                fidelity: EvidenceFidelity::Redacted,
                classification: EvidenceClassification::Restricted,
                parent_refs: &[],
                expires_at: Utc::now() + TimeDelta::hours(1),
                plaintext: b"{}",
            })
            .unwrap();
        let raw_id = format!("artifact_{}", Uuid::now_v7());
        fs::write(root.join(format!("{raw_id}.xev")), b"orphan").unwrap();
        let partial_id = format!("artifact_{}", Uuid::now_v7());
        fs::write(root.join(format!("{partial_id}.xev")), b"partial").unwrap();
        fs::write(root.join(format!("{partial_id}.manifest.json")), b"partial").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                root.join(format!("{raw_id}.xev")),
                root.join(format!("{partial_id}.xev")),
                root.join(format!("{partial_id}.manifest.json")),
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(1_100));
        let candidates = vault
            .list_orphan_candidates(&tenant, &site, Duration::from_secs(1), 2)
            .unwrap();
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.artifact_id() == raw_id)
        );
        assert!(candidates.iter().any(|candidate| {
            candidate.artifact_id() == complete.manifest().artifact_id
                && candidate.authenticated_manifest()
        }));
        let raw = candidates
            .iter()
            .find(|candidate| candidate.artifact_id() == raw_id)
            .unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                root.join("missing-manifest"),
                root.join(format!("{raw_id}.manifest.json")),
            )
            .unwrap();
            assert!(vault.purge_orphan(&tenant, &site, raw).is_err());
            fs::remove_file(root.join(format!("{raw_id}.manifest.json"))).unwrap();
        }
        assert_eq!(
            vault.purge_orphan(&tenant, &site, raw).unwrap(),
            EvidencePurgeOutcome::Removed
        );
        assert!(!root.join(format!("{raw_id}.xev")).exists());
        assert!(root.join(format!("{partial_id}.xev")).exists());
        assert!(root.join(format!("{partial_id}.manifest.json")).exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn private_temp_directory() -> PathBuf {
        let root = std::env::temp_dir().join(format!("xshield-evidence-test-{}", Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }
}
