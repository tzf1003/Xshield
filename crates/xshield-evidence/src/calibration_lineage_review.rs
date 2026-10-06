//! Purpose-limited storage for canonical calibration lineage-review artifacts.
//!
//! A lineage review is neither request evidence nor a calibration report. Its
//! `calrev_` review identity and separately generated artifact identity are
//! bound into a dedicated authenticated sidecar and AEAD associated data. The
//! generic evidence writer cannot be used here because it would fabricate a
//! request relationship and permit caller-selected metadata.

use super::{
    DIGEST_HEX_BYTES, EvidenceClassification, EvidenceError, EvidenceFidelity, EvidenceIntegrity,
    EvidenceStorage, LocalEvidenceVault, MANIFEST_BYTES_MAX, MAX_SINGLE_ARTIFACT_BYTES,
    NONCE_BYTES, authenticate_manifest, decrypt, derive_key, encrypt, envelope, hide_absence,
    lower_hex, parse_envelope, read_private_bounded, sync_directory, valid_lower_hex, valid_name,
    write_new_synced,
};
use chrono::{DateTime, SecondsFormat, Utc};
use openssl::{rand::rand_bytes, sha::sha256};
use serde::{Deserialize, Serialize};
use xshield_core::constant_time;
use xshield_core::{
    calibration::lineage_review::{
        CALIBRATION_LINEAGE_REVIEW_ARTIFACT_CONTENT_TYPE, CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND,
        CalibrationLineageReviewArtifact,
    },
    domain::{ArtifactId, CalibrationLineageReviewId, SiteId, TenantId},
};

/// Immutable schema version for a lineage-review evidence sidecar.
pub const CALIBRATION_LINEAGE_REVIEW_EVIDENCE_MANIFEST_SCHEMA_VERSION: u8 = 1;
/// Fixed encoding identifier for the lineage review's canonical JSON body.
pub const CALIBRATION_LINEAGE_REVIEW_CANONICAL_BODY_ENCODING: &str =
    "xshield_calibration_lineage_review_canonical_json_v1";

const CAPTURE_STATUS: &str = "complete";
const ENVELOPE_PROFILE: &str = "aead_envelope_v1";
const INTEGRITY_ALGORITHM: &str = "sha256_ciphertext";
/// File suffix for the authenticated lineage-review metadata sidecar.
pub(crate) const MANIFEST_FILENAME_SUFFIX: &str = "calibration-lineage-review.manifest.json";
/// File suffix for the authentication tag of the lineage-review metadata sidecar.
pub(crate) const MANIFEST_AUTH_FILENAME_SUFFIX: &str = "calibration-lineage-review.manifest.hmac";

/// Validated write command for one completed declaration-review artifact.
///
/// The writer fixes all artifact metadata. It accepts no request ID, generic
/// classification, parent references, or plaintext bytes supplied by a caller.
pub struct CalibrationLineageReviewEvidenceWrite<'a> {
    /// Authenticated tenant scope for this review.
    pub tenant_id: &'a TenantId,
    /// Authenticated site scope for this review.
    pub site_id: &'a SiteId,
    /// Fully validated pure-domain review artifact to persist.
    pub review: &'a CalibrationLineageReviewArtifact,
    /// Exclusive UTC deadline for later content reads.
    pub expires_at: DateTime<Utc>,
}

/// Authenticated non-plaintext sidecar for one lineage-review artifact.
///
/// The fixed kind, media type, canonical body encoding, exact fidelity and
/// restricted classification prevent a generic object from being relabeled as
/// a reviewed lineage declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationLineageReviewEvidenceManifest {
    /// Dedicated sidecar schema version.
    pub schema_version: u8,
    /// Immutable `calrev_` identity bound into AEAD associated data.
    pub review_id: String,
    /// Independent artifact identity bound into AEAD associated data.
    pub artifact_id: String,
    /// Tenant identity bound into AEAD associated data.
    pub tenant_id: String,
    /// Site identity bound into AEAD associated data.
    pub site_id: String,
    /// Fixed lineage review artifact kind.
    pub kind: String,
    /// Fixed canonical lineage review media type.
    pub content_type: String,
    /// Fixed canonical JSON encoding identifier.
    pub canonical_body_encoding: String,
    /// Complete capture state for this dedicated writer.
    pub capture_status: String,
    /// Exact canonical plaintext bytes presented to the vault.
    pub bytes_observed: u64,
    /// Exact canonical plaintext bytes encrypted by the vault.
    pub bytes_saved: u64,
    /// Fixed exact-byte fidelity.
    pub fidelity: EvidenceFidelity,
    /// Fixed restricted classification.
    pub classification: EvidenceClassification,
    /// Non-secret envelope location and derivation-key reference.
    pub storage: EvidenceStorage,
    /// Ciphertext integrity metadata.
    pub integrity: EvidenceIntegrity,
    /// Exclusive UTC deadline for later content reads.
    pub expires_at: String,
}

/// Private authenticated lineage-review sidecar wrapper.
pub struct VerifiedCalibrationLineageReviewManifest(CalibrationLineageReviewEvidenceManifest);

impl VerifiedCalibrationLineageReviewManifest {
    /// Returns authenticated, non-plaintext sidecar metadata.
    #[must_use]
    pub const fn manifest(&self) -> &CalibrationLineageReviewEvidenceManifest {
        &self.0
    }
}

/// Fresh vault attestation accepted by the lineage-review persistence boundary.
///
/// It can only be constructed after authenticated sidecar observations around
/// decryption and exact canonical DTO comparison.
pub struct AttestedCalibrationLineageReviewManifest(VerifiedCalibrationLineageReviewManifest);

impl AttestedCalibrationLineageReviewManifest {
    /// Returns freshly authenticated, non-plaintext sidecar metadata.
    #[must_use]
    pub const fn manifest(&self) -> &CalibrationLineageReviewEvidenceManifest {
        self.0.manifest()
    }
}

impl CalibrationLineageReviewEvidenceManifest {
    /// Validates fixed metadata decoded from durable storage without I/O.
    ///
    /// # Errors
    /// Returns [`EvidenceError::CorruptEvidence`] when any typed identity,
    /// fixed field, locator, integrity field, or expiry representation drifts.
    pub fn validate_catalog_structure(&self) -> Result<(), EvidenceError> {
        let tenant_id =
            TenantId::parse(&self.tenant_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let site_id = SiteId::parse(&self.site_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let review_id = CalibrationLineageReviewId::parse(&self.review_id)
            .map_err(|_| EvidenceError::CorruptEvidence)?;
        let artifact_id =
            ArtifactId::parse(&self.artifact_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let key_id = self
            .storage
            .key_ref
            .as_deref()
            .ok_or(EvidenceError::CorruptEvidence)?;
        validate_manifest_fields(self, &tenant_id, &site_id, &review_id, &artifact_id, key_id)
            .map(|_| ())
    }

    /// Validates metadata against a persistence adapter's trusted clock.
    ///
    /// # Errors
    /// Returns [`EvidenceError::NotAvailable`] when the object would already
    /// have expired at `recorded_at`, or [`EvidenceError::CorruptEvidence`] for
    /// invalid fixed metadata.
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

impl LocalEvidenceVault {
    /// Encrypts and publishes a canonical lineage-review artifact and sidecars.
    ///
    /// The AEAD associated data fixes tenant/site, review identity, artifact
    /// identity, kind and canonical body encoding. Existing ciphertext and
    /// sidecars are never overwritten; a pre-commit crash leaves an orphan for
    /// a later dedicated reconciliation policy and never creates a database
    /// review fact.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for canonical serialization, retention or size
    /// validation, cryptographic failures, unsafe local storage, or durable I/O.
    pub fn write_calibration_lineage_review(
        &self,
        command: &CalibrationLineageReviewEvidenceWrite<'_>,
    ) -> Result<VerifiedCalibrationLineageReviewManifest, EvidenceError> {
        let plaintext = command
            .review
            .canonical_json()
            .map_err(|_| EvidenceError::InvalidWrite)?;
        validate_write(
            command,
            plaintext.len(),
            self.config.max_artifact_bytes,
            self.config.max_retention,
            Utc::now(),
        )?;

        let review_id = command.review.review_id();
        let artifact_id = command.review.review_artifact_id();
        let artifact_id_text = artifact_id.as_str();
        let locator = format!("{artifact_id_text}.xev");
        let aad = calibration_lineage_review_aad(
            command.tenant_id,
            command.site_id,
            review_id,
            artifact_id,
        )?;
        let data_key = derive_key(&self.root_key.0, &aad)?;
        let mut nonce = [0; NONCE_BYTES];
        rand_bytes(&mut nonce)?;
        let (ciphertext, tag) = encrypt(&data_key, &nonce, &aad, &plaintext)?;
        let envelope = envelope(&nonce, &tag, &ciphertext)?;
        let bytes_saved =
            u64::try_from(plaintext.len()).map_err(|_| EvidenceError::InvalidWrite)?;
        let manifest = CalibrationLineageReviewEvidenceManifest {
            schema_version: CALIBRATION_LINEAGE_REVIEW_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            review_id: review_id.as_str().to_owned(),
            artifact_id: artifact_id_text.to_owned(),
            tenant_id: command.tenant_id.as_str().to_owned(),
            site_id: command.site_id.as_str().to_owned(),
            kind: CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND.to_owned(),
            content_type: CALIBRATION_LINEAGE_REVIEW_ARTIFACT_CONTENT_TYPE.to_owned(),
            canonical_body_encoding: CALIBRATION_LINEAGE_REVIEW_CANONICAL_BODY_ENCODING.to_owned(),
            capture_status: CAPTURE_STATUS.to_owned(),
            bytes_observed: bytes_saved,
            bytes_saved,
            fidelity: EvidenceFidelity::EntityExact,
            classification: EvidenceClassification::Restricted,
            storage: EvidenceStorage {
                profile: ENVELOPE_PROFILE.to_owned(),
                locator: locator.clone(),
                key_ref: Some(self.config.key_id.clone()),
            },
            integrity: EvidenceIntegrity {
                algorithm: INTEGRITY_ALGORITHM.to_owned(),
                digest: lower_hex(&sha256(&envelope)),
            },
            expires_at: command
                .expires_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        };
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let manifest_auth = authenticate_manifest(&self.root_key.0, &manifest_bytes)?;
        write_new_synced(&self.config.root, &locator, &envelope)?;
        write_new_synced(
            &self.config.root,
            &manifest_filename(artifact_id_text),
            &manifest_bytes,
        )?;
        write_new_synced(
            &self.config.root,
            &manifest_auth_filename(artifact_id_text),
            &manifest_auth,
        )?;
        sync_directory(&self.config.root)?;
        Ok(VerifiedCalibrationLineageReviewManifest(manifest))
    }

    /// Authenticates one scoped lineage-review sidecar without disclosing data.
    ///
    /// # Errors
    /// Returns [`EvidenceError::NotAvailable`] uniformly for absent, expired,
    /// cross-scope, or mismatched identities. Authentication or shape failures
    /// return [`EvidenceError::CorruptEvidence`].
    pub fn read_calibration_lineage_review_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        review_id: &CalibrationLineageReviewId,
        artifact_id: &ArtifactId,
    ) -> Result<VerifiedCalibrationLineageReviewManifest, EvidenceError> {
        self.read_calibration_lineage_review_manifest_at(
            tenant_id,
            site_id,
            review_id,
            artifact_id,
            Utc::now(),
        )
    }

    /// Authenticates and decrypts one canonical lineage-review artifact.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for unavailable, malformed, replaced, or
    /// unauthentic restricted review evidence.
    pub fn read_calibration_lineage_review(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        review_id: &CalibrationLineageReviewId,
        artifact_id: &ArtifactId,
    ) -> Result<CalibrationLineageReviewArtifact, EvidenceError> {
        let manifest = self.read_calibration_lineage_review_manifest(
            tenant_id,
            site_id,
            review_id,
            artifact_id,
        )?;
        self.read_calibration_lineage_review_matching_manifest(tenant_id, site_id, &manifest)
    }

    /// Decrypts a review only when authenticated sidecars stay unchanged.
    ///
    /// # Errors
    /// Returns [`EvidenceError::CorruptEvidence`] when a fresh sidecar,
    /// ciphertext digest, AAD binding, canonical body, or typed identity differs
    /// from the expected authenticated manifest.
    pub fn read_calibration_lineage_review_matching_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &VerifiedCalibrationLineageReviewManifest,
    ) -> Result<CalibrationLineageReviewArtifact, EvidenceError> {
        let manifest = expected.manifest();
        let review_id = CalibrationLineageReviewId::parse(&manifest.review_id)
            .map_err(|_| EvidenceError::CorruptEvidence)?;
        let artifact_id =
            ArtifactId::parse(&manifest.artifact_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let observed = self.read_calibration_lineage_review_manifest_at(
            tenant_id,
            site_id,
            &review_id,
            &artifact_id,
            Utc::now(),
        )?;
        if observed.manifest() != manifest {
            return Err(EvidenceError::CorruptEvidence);
        }
        let review = self.decrypt_calibration_lineage_review(tenant_id, site_id, manifest)?;
        let current = self.read_calibration_lineage_review_manifest_at(
            tenant_id,
            site_id,
            &review_id,
            &artifact_id,
            Utc::now(),
        )?;
        if current.manifest() != manifest {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(review)
    }

    /// Attests that a durable review exactly matches the supplied canonical DTO.
    ///
    /// The persistence adapter receives only the resulting non-forgeable
    /// wrapper. This method rechecks sidecars before and after decryption,
    /// ciphertext integrity, AEAD binding and canonical DTO equality so an
    /// unavailable or substituted local object cannot become a durable review.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for unavailable, corrupt, expired, replaced,
    /// or non-matching review evidence.
    pub fn attest_calibration_lineage_review(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &CalibrationLineageReviewArtifact,
    ) -> Result<AttestedCalibrationLineageReviewManifest, EvidenceError> {
        let manifest = self.read_calibration_lineage_review_manifest(
            tenant_id,
            site_id,
            expected.review_id(),
            expected.review_artifact_id(),
        )?;
        let observed =
            self.read_calibration_lineage_review_matching_manifest(tenant_id, site_id, &manifest)?;
        if observed != *expected {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(AttestedCalibrationLineageReviewManifest(manifest))
    }

    fn read_calibration_lineage_review_manifest_at(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        review_id: &CalibrationLineageReviewId,
        artifact_id: &ArtifactId,
        now: DateTime<Utc>,
    ) -> Result<VerifiedCalibrationLineageReviewManifest, EvidenceError> {
        let manifest = self.load_authenticated_calibration_lineage_review_manifest(artifact_id)?;
        let expires_at = validate_manifest_fields(
            &manifest,
            tenant_id,
            site_id,
            review_id,
            artifact_id,
            &self.config.key_id,
        )?;
        if expires_at <= now {
            return Err(EvidenceError::NotAvailable);
        }
        Ok(VerifiedCalibrationLineageReviewManifest(manifest))
    }

    fn load_authenticated_calibration_lineage_review_manifest(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<CalibrationLineageReviewEvidenceManifest, EvidenceError> {
        let artifact_id = artifact_id.as_str();
        let bytes = read_private_bounded(
            &self.config.root.join(manifest_filename(artifact_id)),
            MANIFEST_BYTES_MAX,
        )
        .map_err(hide_absence)?;
        let authentication = read_private_bounded(
            &self.config.root.join(manifest_auth_filename(artifact_id)),
            32,
        )
        .map_err(hide_absence)?;
        let expected = authenticate_manifest(&self.root_key.0, &bytes)?;
        if !constant_time::eq(&authentication, &expected) {
            return Err(EvidenceError::CorruptEvidence);
        }
        serde_json::from_slice(&bytes).map_err(|_| EvidenceError::CorruptEvidence)
    }

    fn decrypt_calibration_lineage_review(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        manifest: &CalibrationLineageReviewEvidenceManifest,
    ) -> Result<CalibrationLineageReviewArtifact, EvidenceError> {
        let review_id = CalibrationLineageReviewId::parse(&manifest.review_id)
            .map_err(|_| EvidenceError::CorruptEvidence)?;
        let artifact_id =
            ArtifactId::parse(&manifest.artifact_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let envelope = read_private_bounded(
            &self.config.root.join(&manifest.storage.locator),
            self.max_envelope_bytes(),
        )
        .map_err(hide_absence)?;
        if lower_hex(&sha256(&envelope)) != manifest.integrity.digest {
            return Err(EvidenceError::CorruptEvidence);
        }
        let (nonce, tag, ciphertext) = parse_envelope(&envelope)?;
        let aad = calibration_lineage_review_aad(tenant_id, site_id, &review_id, &artifact_id)?;
        let data_key = derive_key(&self.root_key.0, &aad)?;
        let plaintext = decrypt(&data_key, nonce, &aad, ciphertext, tag)?;
        if u64::try_from(plaintext.len()).map_err(|_| EvidenceError::CorruptEvidence)?
            != manifest.bytes_saved
        {
            return Err(EvidenceError::CorruptEvidence);
        }
        let review = CalibrationLineageReviewArtifact::from_canonical_json(&plaintext)
            .map_err(|_| EvidenceError::CorruptEvidence)?;
        if review.review_id() != &review_id || review.review_artifact_id() != &artifact_id {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(review)
    }
}

fn validate_write(
    command: &CalibrationLineageReviewEvidenceWrite<'_>,
    bytes: usize,
    max_bytes: usize,
    max_retention: chrono::TimeDelta,
    now: DateTime<Utc>,
) -> Result<(), EvidenceError> {
    let max_expires_at = now
        .checked_add_signed(max_retention)
        .ok_or(EvidenceError::InvalidConfig)?;
    if bytes == 0
        || bytes > max_bytes
        || command.expires_at <= now
        || command.expires_at > max_expires_at
    {
        return Err(EvidenceError::InvalidWrite);
    }
    Ok(())
}

fn validate_manifest_fields(
    manifest: &CalibrationLineageReviewEvidenceManifest,
    tenant_id: &TenantId,
    site_id: &SiteId,
    review_id: &CalibrationLineageReviewId,
    artifact_id: &ArtifactId,
    key_id: &str,
) -> Result<DateTime<Utc>, EvidenceError> {
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .map_err(|_| EvidenceError::CorruptEvidence)?
        .with_timezone(&Utc);
    if manifest.tenant_id != tenant_id.as_str()
        || manifest.site_id != site_id.as_str()
        || manifest.review_id != review_id.as_str()
        || manifest.artifact_id != artifact_id.as_str()
    {
        return Err(EvidenceError::NotAvailable);
    }
    if manifest.schema_version != CALIBRATION_LINEAGE_REVIEW_EVIDENCE_MANIFEST_SCHEMA_VERSION
        || manifest.kind != CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND
        || manifest.content_type != CALIBRATION_LINEAGE_REVIEW_ARTIFACT_CONTENT_TYPE
        || manifest.canonical_body_encoding != CALIBRATION_LINEAGE_REVIEW_CANONICAL_BODY_ENCODING
        || manifest.capture_status != CAPTURE_STATUS
        || manifest.bytes_observed == 0
        || manifest.bytes_observed != manifest.bytes_saved
        || manifest.bytes_saved > MAX_SINGLE_ARTIFACT_BYTES as u64
        || manifest.fidelity != EvidenceFidelity::EntityExact
        || manifest.classification != EvidenceClassification::Restricted
        || manifest.storage.profile != ENVELOPE_PROFILE
        || manifest.storage.locator != format!("{}.xev", artifact_id.as_str())
        || manifest.storage.key_ref.as_deref() != Some(key_id)
        || !valid_name(key_id)
        || manifest.integrity.algorithm != INTEGRITY_ALGORITHM
        || !valid_lower_hex(&manifest.integrity.digest, DIGEST_HEX_BYTES)
    {
        return Err(EvidenceError::CorruptEvidence);
    }
    Ok(expires_at)
}

fn calibration_lineage_review_aad(
    tenant_id: &TenantId,
    site_id: &SiteId,
    review_id: &CalibrationLineageReviewId,
    artifact_id: &ArtifactId,
) -> Result<Vec<u8>, EvidenceError> {
    let mut output = Vec::new();
    for component in [
        b"xshield-calibration-lineage-review-evidence-v1".as_slice(),
        &[CALIBRATION_LINEAGE_REVIEW_EVIDENCE_MANIFEST_SCHEMA_VERSION],
        tenant_id.as_str().as_bytes(),
        site_id.as_str().as_bytes(),
        review_id.as_str().as_bytes(),
        artifact_id.as_str().as_bytes(),
        CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND.as_bytes(),
        CALIBRATION_LINEAGE_REVIEW_CANONICAL_BODY_ENCODING.as_bytes(),
    ] {
        let length = u64::try_from(component.len()).map_err(|_| EvidenceError::InvalidWrite)?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(component);
    }
    Ok(output)
}

fn manifest_filename(artifact_id: &str) -> String {
    format!("{artifact_id}.{MANIFEST_FILENAME_SUFFIX}")
}

fn manifest_auth_filename(artifact_id: &str) -> String {
    format!("{artifact_id}.{MANIFEST_AUTH_FILENAME_SUFFIX}")
}

/// Reports whether any dedicated lineage-review sidecar exists for an artifact.
///
/// The generic orphan scanner uses this before considering a ciphertext. It
/// cannot authenticate this object family and must leave it for the dedicated
/// lineage-review retention flow.
pub(crate) fn sidecars_present(
    root: &std::path::Path,
    artifact_id: &str,
) -> Result<bool, EvidenceError> {
    for filename in [
        manifest_filename(artifact_id),
        manifest_auth_filename(artifact_id),
    ] {
        match std::fs::symlink_metadata(root.join(filename)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(EvidenceError::Io(error)),
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::{
        CalibrationLineageReviewEvidenceManifest, CalibrationLineageReviewEvidenceWrite,
        authenticate_manifest, manifest_auth_filename, manifest_filename,
    };
    use crate::{
        EvidenceClassification, EvidenceError, EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault,
    };
    use chrono::{TimeDelta, Utc};
    use std::{fs, path::PathBuf};
    use uuid::Uuid;
    use xshield_core::{
        calibration::{
            dataset::{EvaluationProvenance, ModelIdentity},
            lineage_review::{
                CalibrationLineageReviewArtifact, LineageSourceDeclaration, LineageSourceKind,
                LineageSourceRef, PartitionLineageSubmission, PartitionManifestDeclaration,
                PartitionRole, review_partition_lineage,
            },
        },
        domain::{
            ApprovalRef, ArtifactId, CalibrationLineageReviewId, DatasetRevision, LabelRevision,
            MappingRevision, ModelRevision, PromptRevision, ProviderId, SiteId, TaskRevision,
            TenantId, ThresholdPolicyRevision,
        },
    };

    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn lineage_review_writer_is_dedicated_request_free_and_round_trips() {
        let root = private_temp_directory();
        let vault = vault(&root);
        let tenant = TenantId::parse("tenant_lineage_review").unwrap();
        let site = SiteId::parse("site_lineage_review").unwrap();
        let review = review();
        let verified = vault
            .write_calibration_lineage_review(&CalibrationLineageReviewEvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                review: &review,
                expires_at: Utc::now() + TimeDelta::minutes(5),
            })
            .unwrap();

        let manifest = verified.manifest();
        assert_eq!(manifest.review_id, review.review_id().as_str());
        assert_eq!(manifest.artifact_id, review.review_artifact_id().as_str());
        assert_eq!(manifest.kind, "calibration_partition_lineage_review");
        assert_eq!(
            manifest.content_type,
            "application/vnd.xshield.calibration-lineage-review+json"
        );
        assert_eq!(
            manifest.canonical_body_encoding,
            "xshield_calibration_lineage_review_canonical_json_v1"
        );
        assert_eq!(manifest.classification, EvidenceClassification::Restricted);

        let sidecar = fs::read(root.join(manifest_filename(&manifest.artifact_id))).unwrap();
        assert!(
            !sidecar
                .windows(b"request_id".len())
                .any(|part| part == b"request_id")
        );
        assert!(matches!(
            vault.read_manifest(&tenant, &site, review.review_artifact_id().as_str()),
            Err(EvidenceError::NotAvailable)
        ));
        assert_eq!(
            vault
                .read_calibration_lineage_review_matching_manifest(&tenant, &site, &verified)
                .unwrap(),
            review
        );
        assert_eq!(
            vault
                .read_calibration_lineage_review(
                    &tenant,
                    &site,
                    review.review_id(),
                    review.review_artifact_id(),
                )
                .unwrap(),
            review
        );
        assert!(matches!(
            vault.read_calibration_lineage_review_manifest(
                &TenantId::parse("tenant_other").unwrap(),
                &site,
                review.review_id(),
                review.review_artifact_id(),
            ),
            Err(EvidenceError::NotAvailable)
        ));
        assert!(matches!(
            vault.read_calibration_lineage_review_manifest(
                &tenant,
                &SiteId::parse("site_other").unwrap(),
                review.review_id(),
                review.review_artifact_id(),
            ),
            Err(EvidenceError::NotAvailable)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reauthenticated_review_identity_still_fails_aad_binding() {
        let root = private_temp_directory();
        let vault = vault(&root);
        let tenant = TenantId::parse("tenant_lineage_review").unwrap();
        let site = SiteId::parse("site_lineage_review").unwrap();
        let review = review();
        vault
            .write_calibration_lineage_review(&CalibrationLineageReviewEvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                review: &review,
                expires_at: Utc::now() + TimeDelta::minutes(5),
            })
            .unwrap();

        let other_review_id =
            CalibrationLineageReviewId::parse("calrev_018f2a3b-4c5d-7000-8000-000000000100")
                .unwrap();
        let artifact_id = review.review_artifact_id().as_str();
        let manifest_path = root.join(manifest_filename(artifact_id));
        let mut sidecar: CalibrationLineageReviewEvidenceManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        sidecar.review_id = other_review_id.as_str().to_owned();
        let sidecar_bytes = serde_json::to_vec(&sidecar).unwrap();
        let authentication = authenticate_manifest(&vault.root_key.0, &sidecar_bytes).unwrap();
        fs::write(&manifest_path, sidecar_bytes).unwrap();
        fs::write(
            root.join(manifest_auth_filename(artifact_id)),
            authentication,
        )
        .unwrap();

        let reauthenticated = vault
            .read_calibration_lineage_review_manifest(
                &tenant,
                &site,
                &other_review_id,
                review.review_artifact_id(),
            )
            .unwrap();
        assert!(matches!(
            vault.read_calibration_lineage_review_matching_manifest(
                &tenant,
                &site,
                &reauthenticated,
            ),
            Err(EvidenceError::CorruptEvidence)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reauthenticated_fixed_metadata_drift_is_rejected() {
        let root = private_temp_directory();
        let vault = vault(&root);
        let tenant = TenantId::parse("tenant_lineage_review").unwrap();
        let site = SiteId::parse("site_lineage_review").unwrap();
        let review = review();
        vault
            .write_calibration_lineage_review(&CalibrationLineageReviewEvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                review: &review,
                expires_at: Utc::now() + TimeDelta::minutes(5),
            })
            .unwrap();

        let artifact_id = review.review_artifact_id().as_str();
        let manifest_path = root.join(manifest_filename(artifact_id));
        let mut sidecar: CalibrationLineageReviewEvidenceManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        sidecar.content_type = "application/json".to_owned();
        let sidecar_bytes = serde_json::to_vec(&sidecar).unwrap();
        let authentication = authenticate_manifest(&vault.root_key.0, &sidecar_bytes).unwrap();
        fs::write(&manifest_path, sidecar_bytes).unwrap();
        fs::write(
            root.join(manifest_auth_filename(artifact_id)),
            authentication,
        )
        .unwrap();

        assert!(matches!(
            vault.read_calibration_lineage_review_manifest(
                &tenant,
                &site,
                review.review_id(),
                review.review_artifact_id(),
            ),
            Err(EvidenceError::CorruptEvidence)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attestation_requires_current_untampered_ciphertext() {
        let root = private_temp_directory();
        let vault = vault(&root);
        let tenant = TenantId::parse("tenant_lineage_review").unwrap();
        let site = SiteId::parse("site_lineage_review").unwrap();
        let review = review();
        vault
            .write_calibration_lineage_review(&CalibrationLineageReviewEvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                review: &review,
                expires_at: Utc::now() + TimeDelta::minutes(5),
            })
            .unwrap();
        assert_eq!(
            vault
                .attest_calibration_lineage_review(&tenant, &site, &review)
                .unwrap()
                .manifest()
                .artifact_id,
            review.review_artifact_id().as_str()
        );

        let ciphertext_path = root.join(format!("{}.xev", review.review_artifact_id().as_str()));
        let mut ciphertext = fs::read(&ciphertext_path).unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        fs::write(&ciphertext_path, ciphertext).unwrap();
        assert!(matches!(
            vault.attest_calibration_lineage_review(&tenant, &site, &review),
            Err(EvidenceError::CorruptEvidence)
        ));
        fs::remove_file(&ciphertext_path).unwrap();
        assert!(matches!(
            vault.attest_calibration_lineage_review(&tenant, &site, &review),
            Err(EvidenceError::NotAvailable)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    fn vault(root: &PathBuf) -> LocalEvidenceVault {
        LocalEvidenceVault::open(
            EvidenceVaultConfig::new(root, "evidence-key-r1", 1024 * 1024, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap()
    }

    fn review() -> CalibrationLineageReviewArtifact {
        let provenance = EvaluationProvenance::new(
            ApprovalRef::parse("approval-r1").unwrap(),
            DatasetRevision::parse("dataset-r1").unwrap(),
            LabelRevision::parse("labels-r1").unwrap(),
            TaskRevision::parse("task-r1").unwrap(),
            ThresholdPolicyRevision::parse("threshold-r1").unwrap(),
            MappingRevision::parse("mapping-r1").unwrap(),
            artifact(1),
            artifact(2),
            artifact(3),
            artifact(4),
            ModelIdentity::new(
                ProviderId::parse("vercel_ai_gateway").unwrap(),
                "typesafe-ai/jev",
                ModelRevision::parse("jev-r1").unwrap(),
                PromptRevision::parse("prompt-r1").unwrap(),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        let declarations = vec![
            PartitionManifestDeclaration::new(
                PartitionRole::Training,
                artifact(2),
                vec![source_ref("training")],
            )
            .unwrap(),
            PartitionManifestDeclaration::new(
                PartitionRole::Calibration,
                artifact(3),
                vec![source_ref("calibration")],
            )
            .unwrap(),
            PartitionManifestDeclaration::new(
                PartitionRole::Evaluation,
                artifact(1),
                vec![source_ref("evaluation")],
            )
            .unwrap(),
            PartitionManifestDeclaration::new(
                PartitionRole::Label,
                artifact(4),
                vec![source_ref("labels")],
            )
            .unwrap(),
        ];
        let sources = vec![
            source(
                "training",
                PartitionRole::Training,
                LineageSourceKind::Corpus,
            ),
            source(
                "calibration",
                PartitionRole::Calibration,
                LineageSourceKind::Corpus,
            ),
            source(
                "evaluation",
                PartitionRole::Evaluation,
                LineageSourceKind::Corpus,
            ),
            source(
                "labels",
                PartitionRole::Label,
                LineageSourceKind::ReviewedLabel,
            ),
        ];
        let submission = PartitionLineageSubmission::new(declarations, sources).unwrap();
        let review = review_partition_lineage(
            CalibrationLineageReviewId::parse("calrev_018f2a3b-4c5d-7000-8000-000000000099")
                .unwrap(),
            artifact(99),
            provenance,
            &submission,
        )
        .unwrap();
        CalibrationLineageReviewArtifact::from_review(&review).unwrap()
    }

    fn source(
        source_id: &str,
        partition: PartitionRole,
        kind: LineageSourceKind,
    ) -> LineageSourceDeclaration {
        LineageSourceDeclaration::new(source_ref(source_id), partition, kind, Vec::new()).unwrap()
    }

    fn source_ref(source_id: &str) -> LineageSourceRef {
        LineageSourceRef::new(source_id, "revision-r1").unwrap()
    }

    fn artifact(index: u8) -> ArtifactId {
        ArtifactId::parse(format!(
            "artifact_018f2a3b-4c5d-7000-8000-0000000000{index:02}"
        ))
        .unwrap()
    }

    fn private_temp_directory() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "xshield-lineage-review-evidence-test-{}",
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
