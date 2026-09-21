//! Expiry-only removal for authenticated calibration-lineage-review ciphertext.
//!
//! Lineage reviews have a request-free sidecar contract. Reusing generic
//! evidence retention here would either require a fabricated request identity
//! or accept the wrong manifest type, so this module verifies the review
//! sidecar before it removes only the encrypted envelope.

use super::{
    EvidenceError, EvidencePurgeOutcome, LocalEvidenceVault, MANIFEST_BYTES_MAX,
    MAX_SINGLE_ENVELOPE_BYTES, MAX_VAULT_FILES, authenticate_manifest, calibration_lineage_review,
    lower_hex, read_private_bounded, sync_directory, validate_private_directory,
};
use chrono::{DateTime, Utc};
use openssl::{memcmp, sha::sha256};
use std::{
    fs, io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use xshield_core::domain::{ArtifactId, CalibrationLineageReviewId, SiteId, TenantId};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// A bounded authenticated lineage-review sidecar observation with no lineage-review metadata row.
///
/// The raw sidecar digest lets a restart reject replacement even when review
/// and artifact identifiers remain unchanged. It is metadata only and does
/// not disclose a lineage-review body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationLineageReviewOrphanCandidate {
    review_id: String,
    artifact_id: String,
    sidecar_digest: String,
    expires_at: String,
    observed_bytes: u64,
    observed_modified_seconds: u64,
    observed_modified_nanos: u32,
}

impl CalibrationLineageReviewOrphanCandidate {
    /// Returns the review identity authenticated by the observed sidecar.
    #[must_use]
    pub fn review_id(&self) -> &str {
        &self.review_id
    }

    /// Returns the lineage-review artifact identity encoded by the opaque filename.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Returns the lowercase SHA-256 of the authenticated sidecar bytes.
    #[must_use]
    pub fn sidecar_digest(&self) -> &str {
        &self.sidecar_digest
    }

    /// Returns the canonical UTC expiry authenticated by the lineage-review sidecar.
    #[must_use]
    pub fn expires_at(&self) -> &str {
        &self.expires_at
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

    /// Reconstructs a candidate from the durable orphan-intent observation.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidWrite`] for malformed identities,
    /// digest, size, or modification time.
    pub fn from_observation(
        review_id: impl Into<String>,
        artifact_id: impl Into<String>,
        sidecar_digest: impl Into<String>,
        expires_at: impl Into<String>,
        observed_bytes: u64,
        observed_modified_seconds: u64,
        observed_modified_nanos: u32,
    ) -> Result<Self, EvidenceError> {
        let review_id = review_id.into();
        let artifact_id = artifact_id.into();
        let sidecar_digest = sidecar_digest.into();
        let expires_at = expires_at.into();
        if CalibrationLineageReviewId::parse(&review_id).is_err()
            || ArtifactId::parse(&artifact_id).is_err()
            || !super::valid_lower_hex(&sidecar_digest, 64)
            || observed_bytes > MAX_SINGLE_ENVELOPE_BYTES
            || observed_modified_nanos >= 1_000_000_000
            || DateTime::parse_from_rfc3339(&expires_at).is_err()
        {
            return Err(EvidenceError::InvalidWrite);
        }
        Ok(Self {
            review_id,
            artifact_id,
            sidecar_digest,
            expires_at,
            observed_bytes,
            observed_modified_seconds,
            observed_modified_nanos,
        })
    }
}

impl LocalEvidenceVault {
    /// Removes one expired calibration-lineage-review ciphertext matching its exact sidecar.
    ///
    /// The caller must hold the vault-directory maintenance lock and durably
    /// record deletion intent before calling. The authenticated lineage-review sidecars
    /// remain in place so a crash after physical removal can be completed as an
    /// idempotent tombstone. This operation never decrypts a lineage-review body and
    /// does not remove backups or database metadata.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for an unexpired, cross-scope, replaced,
    /// unauthentic, unsafe, or unavailable review object. A directory-sync
    /// failure can follow removal; retrying with the same sidecar is safe.
    pub fn purge_expired_calibration_lineage_review(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &calibration_lineage_review::CalibrationLineageReviewEvidenceManifest,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        self.purge_expired_calibration_lineage_review_at(tenant_id, site_id, expected, Utc::now())
    }

    fn purge_expired_calibration_lineage_review_at(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &calibration_lineage_review::CalibrationLineageReviewEvidenceManifest,
        now: DateTime<Utc>,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        validate_private_directory(&self.config.root)?;
        let review_id = CalibrationLineageReviewId::parse(&expected.review_id)
            .map_err(|_| EvidenceError::CorruptEvidence)?;
        let artifact_id =
            ArtifactId::parse(&expected.artifact_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let (manifest, _) = load_authenticated_lineage_review_manifest(self, &artifact_id)?;
        manifest.validate_catalog_structure()?;
        if &manifest != expected {
            return Err(EvidenceError::CorruptEvidence);
        }
        if manifest.tenant_id != tenant_id.as_str()
            || manifest.site_id != site_id.as_str()
            || manifest.review_id != review_id.as_str()
            || manifest.artifact_id != artifact_id.as_str()
            || manifest.storage.key_ref.as_deref() != Some(self.config.key_id.as_str())
        {
            return Err(EvidenceError::NotAvailable);
        }
        let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
            .map_err(|_| EvidenceError::CorruptEvidence)?
            .with_timezone(&Utc);
        if expires_at > now {
            return Err(EvidenceError::NotAvailable);
        }
        let path = self.config.root.join(&manifest.storage.locator);
        let outcome = match read_private_bounded(&path, self.max_envelope_bytes()) {
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

    /// Lists old, complete lineage-review sidecars that have no committed lineage-review metadata.
    ///
    /// The caller must use the returned candidates only with the review-orphan
    /// persistence flow, which verifies the absence of `calibration_lineage_review_artifacts`
    /// before it creates deletion intent. Generic orphan reconciliation skips
    /// these lineage-review sidecars deliberately.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for an unsafe root, invalid paging bound, or
    /// directory traversal failure. Partial or unauthentic lineage-review sidecars are
    /// skipped for forensic handling rather than treated as deletable objects.
    pub fn list_calibration_lineage_review_orphan_candidates_after(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        grace: Duration,
        limit: u16,
        after: Option<&str>,
    ) -> Result<Vec<CalibrationLineageReviewOrphanCandidate>, EvidenceError> {
        if !(1..=32).contains(&limit) || grace.is_zero() || grace > Duration::from_hours(720) {
            return Err(EvidenceError::InvalidConfig);
        }
        if after.is_some_and(|value| ArtifactId::parse(value).is_err()) {
            return Err(EvidenceError::InvalidConfig);
        }
        validate_private_directory(&self.config.root)?;
        let now = SystemTime::now();
        let mut objects = Vec::new();
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
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(artifact_id) = name.strip_suffix(".xev") else {
                continue;
            };
            if ArtifactId::parse(artifact_id).is_err()
                || metadata.len() > self.max_envelope_bytes()
                || after.is_some_and(|cursor| artifact_id <= cursor)
                || now
                    .duration_since(metadata.modified().map_err(EvidenceError::Io)?)
                    .unwrap_or_default()
                    < grace
            {
                continue;
            }
            objects.push((artifact_id.to_owned(), metadata));
        }
        objects.sort_by(|left, right| left.0.cmp(&right.0));
        let mut candidates = Vec::new();
        for (artifact_id, metadata) in objects {
            if candidates.len() == usize::from(limit) {
                break;
            }
            let artifact_id_typed =
                ArtifactId::parse(&artifact_id).map_err(|_| EvidenceError::UnsafePath)?;
            let Ok((manifest, raw_sidecar)) =
                load_authenticated_lineage_review_manifest(self, &artifact_id_typed)
            else {
                continue;
            };
            if manifest.validate_catalog_structure().is_err()
                || manifest.tenant_id != tenant_id.as_str()
                || manifest.site_id != site_id.as_str()
                || manifest.storage.key_ref.as_deref() != Some(self.config.key_id.as_str())
            {
                continue;
            }
            let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
                .map_err(|_| EvidenceError::CorruptEvidence)?
                .with_timezone(&Utc);
            if expires_at > Utc::now() {
                continue;
            }
            let modified = metadata
                .modified()
                .map_err(EvidenceError::Io)?
                .duration_since(UNIX_EPOCH)
                .map_err(|_| EvidenceError::UnsafePath)?;
            candidates.push(CalibrationLineageReviewOrphanCandidate::from_observation(
                manifest.review_id,
                artifact_id,
                lower_hex(&sha256(&raw_sidecar)),
                manifest.expires_at,
                metadata.len(),
                modified.as_secs(),
                modified.subsec_nanos(),
            )?);
        }
        Ok(candidates)
    }

    /// Removes a review-only orphan after exact sidecar and filesystem revalidation.
    ///
    /// A committed lineage-review metadata row must be ruled out by the caller's
    /// persistence transaction before this method runs. The method leaves both
    /// lineage-review sidecars in place for retry and investigation.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] if the observed file or sidecar changed, the
    /// scope/key no longer match, or local removal cannot be completed.
    pub fn purge_calibration_lineage_review_orphan(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        candidate: &CalibrationLineageReviewOrphanCandidate,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        validate_private_directory(&self.config.root)?;
        let artifact_id = ArtifactId::parse(candidate.artifact_id())
            .map_err(|_| EvidenceError::CorruptEvidence)?;
        let path = self
            .config
            .root
            .join(format!("{}.xev", artifact_id.as_str()));
        let metadata = match path.symlink_metadata() {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(EvidencePurgeOutcome::AlreadyAbsent);
            }
            Err(error) => return Err(EvidenceError::Io(error)),
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != candidate.observed_bytes()
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
        let (manifest, raw_sidecar) =
            load_authenticated_lineage_review_manifest(self, &artifact_id)?;
        if manifest.validate_catalog_structure().is_err()
            || manifest.tenant_id != tenant_id.as_str()
            || manifest.site_id != site_id.as_str()
            || manifest.review_id != candidate.review_id()
            || manifest.artifact_id != candidate.artifact_id()
            || manifest.storage.key_ref.as_deref() != Some(self.config.key_id.as_str())
            || lower_hex(&sha256(&raw_sidecar)) != candidate.sidecar_digest()
            || manifest.expires_at != candidate.expires_at()
        {
            return Err(EvidenceError::CorruptEvidence);
        }
        let envelope = read_private_bounded(&path, self.max_envelope_bytes())?;
        if lower_hex(&sha256(&envelope)) != manifest.integrity.digest {
            return Err(EvidenceError::CorruptEvidence);
        }
        fs::remove_file(path)?;
        sync_directory(&self.config.root)?;
        Ok(EvidencePurgeOutcome::Removed)
    }
}

fn load_authenticated_lineage_review_manifest(
    vault: &LocalEvidenceVault,
    artifact_id: &ArtifactId,
) -> Result<
    (
        calibration_lineage_review::CalibrationLineageReviewEvidenceManifest,
        Vec<u8>,
    ),
    EvidenceError,
> {
    let artifact_id = artifact_id.as_str();
    let manifest_bytes = read_private_bounded(
        &vault.config.root.join(format!(
            "{artifact_id}.{}",
            calibration_lineage_review::MANIFEST_FILENAME_SUFFIX
        )),
        MANIFEST_BYTES_MAX,
    )?;
    let authentication = read_private_bounded(
        &vault.config.root.join(format!(
            "{artifact_id}.{}",
            calibration_lineage_review::MANIFEST_AUTH_FILENAME_SUFFIX
        )),
        32,
    )?;
    let expected = authenticate_manifest(&vault.root_key.0, &manifest_bytes)?;
    if authentication.len() != expected.len() || !memcmp::eq(&authentication, &expected) {
        return Err(EvidenceError::CorruptEvidence);
    }
    let manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| EvidenceError::CorruptEvidence)?;
    Ok((manifest, manifest_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EvidenceKey, EvidenceVaultConfig,
        calibration_lineage_review::{
            CALIBRATION_LINEAGE_REVIEW_CANONICAL_BODY_ENCODING,
            CALIBRATION_LINEAGE_REVIEW_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        },
    };
    use chrono::{SecondsFormat, TimeDelta};
    use std::{fs, path::PathBuf};
    use uuid::Uuid;
    use xshield_core::domain::{ArtifactId, CalibrationLineageReviewId};

    const KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn lineage_review_retention_requires_authenticated_expiry_and_is_idempotent_after_removal() {
        let root = private_temp_directory();
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "lineage-review-retention-r1", 1024, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_lineage_review_retention").unwrap();
        let site = SiteId::parse("site_lineage_review_retention").unwrap();
        let (expired, path) =
            write_fixture(&vault, &tenant, &site, Utc::now() - TimeDelta::seconds(1));
        assert_eq!(
            vault
                .purge_expired_calibration_lineage_review(&tenant, &site, &expired)
                .unwrap(),
            EvidencePurgeOutcome::Removed
        );
        assert!(!path.exists());
        assert!(
            root.join(format!(
                "{}.{}",
                expired.artifact_id,
                calibration_lineage_review::MANIFEST_FILENAME_SUFFIX
            ))
            .exists()
        );
        assert_eq!(
            vault
                .purge_expired_calibration_lineage_review(&tenant, &site, &expired)
                .unwrap(),
            EvidencePurgeOutcome::AlreadyAbsent
        );

        let (active, active_path) =
            write_fixture(&vault, &tenant, &site, Utc::now() + TimeDelta::minutes(1));
        assert!(matches!(
            vault.purge_expired_calibration_lineage_review(&tenant, &site, &active),
            Err(EvidenceError::NotAvailable)
        ));
        assert!(active_path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lineage_review_orphan_scanner_is_separate_from_generic_orphans_and_retries_absence() {
        let root = private_temp_directory();
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "lineage-review-retention-r1", 1024, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_lineage_review_orphan_retention").unwrap();
        let site = SiteId::parse("site_lineage_review_orphan_retention").unwrap();
        let (manifest, ciphertext) =
            write_fixture(&vault, &tenant, &site, Utc::now() - TimeDelta::seconds(1));

        assert!(
            vault
                .list_orphan_candidates(&tenant, &site, Duration::from_nanos(1), 1)
                .unwrap()
                .is_empty()
        );
        let candidates = vault
            .list_calibration_lineage_review_orphan_candidates_after(
                &tenant,
                &site,
                Duration::from_nanos(1),
                1,
                None,
            )
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].review_id(), manifest.review_id);
        assert_eq!(candidates[0].artifact_id(), manifest.artifact_id);

        assert_eq!(
            vault
                .purge_calibration_lineage_review_orphan(&tenant, &site, &candidates[0])
                .unwrap(),
            EvidencePurgeOutcome::Removed
        );
        assert!(!ciphertext.exists());
        assert_eq!(
            vault
                .purge_calibration_lineage_review_orphan(&tenant, &site, &candidates[0])
                .unwrap(),
            EvidencePurgeOutcome::AlreadyAbsent
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn write_fixture(
        vault: &LocalEvidenceVault,
        tenant: &TenantId,
        site: &SiteId,
        expires_at: DateTime<Utc>,
    ) -> (
        calibration_lineage_review::CalibrationLineageReviewEvidenceManifest,
        PathBuf,
    ) {
        let review_id =
            CalibrationLineageReviewId::parse(format!("calrev_{}", Uuid::now_v7())).unwrap();
        let artifact_id = ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).unwrap();
        let envelope = b"lineage-review-ciphertext";
        let manifest = calibration_lineage_review::CalibrationLineageReviewEvidenceManifest {
            schema_version: CALIBRATION_LINEAGE_REVIEW_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            review_id: review_id.as_str().to_owned(),
            artifact_id: artifact_id.as_str().to_owned(),
            tenant_id: tenant.as_str().to_owned(),
            site_id: site.as_str().to_owned(),
            kind: "calibration_partition_lineage_review".to_owned(),
            content_type: "application/vnd.xshield.calibration-lineage-review+json".to_owned(),
            canonical_body_encoding: CALIBRATION_LINEAGE_REVIEW_CANONICAL_BODY_ENCODING.to_owned(),
            capture_status: "complete".to_owned(),
            bytes_observed: 1,
            bytes_saved: 1,
            fidelity: crate::EvidenceFidelity::EntityExact,
            classification: crate::EvidenceClassification::Restricted,
            storage: crate::EvidenceStorage {
                profile: "aead_envelope_v1".to_owned(),
                locator: format!("{}.xev", artifact_id.as_str()),
                key_ref: Some(vault.config.key_id.clone()),
            },
            integrity: crate::EvidenceIntegrity {
                algorithm: "sha256_ciphertext".to_owned(),
                digest: lower_hex(&sha256(envelope)),
            },
            expires_at: expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let authentication = authenticate_manifest(&vault.root_key.0, &bytes).unwrap();
        let path = vault.config.root.join(&manifest.storage.locator);
        fs::write(&path, envelope).unwrap();
        fs::write(
            vault.config.root.join(format!(
                "{}.{}",
                artifact_id.as_str(),
                calibration_lineage_review::MANIFEST_FILENAME_SUFFIX
            )),
            bytes,
        )
        .unwrap();
        fs::write(
            vault.config.root.join(format!(
                "{}.{}",
                artifact_id.as_str(),
                calibration_lineage_review::MANIFEST_AUTH_FILENAME_SUFFIX
            )),
            authentication,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in fs::read_dir(&vault.config.root).unwrap() {
                fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }
        (manifest, path)
    }

    fn private_temp_directory() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "xshield-lineage-review-retention-{}",
            Uuid::now_v7()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }
}
