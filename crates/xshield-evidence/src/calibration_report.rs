//! Purpose-limited storage for completed calibration report bodies.
//!
//! A calibration report is not evidence emitted by an HTTP request.  Its
//! report ID and artifact ID are created by the evaluator, so accepting the
//! general [`super::EvidenceWrite`] command would incorrectly introduce a
//! request binding and let callers choose report metadata.  This module keeps
//! the report contract narrow while reusing the vault's private file, AEAD,
//! digest, and manifest-HMAC primitives.

use super::{
    DIGEST_HEX_BYTES, EvidenceClassification, EvidenceError, EvidenceFidelity, EvidenceIntegrity,
    EvidenceStorage, LocalEvidenceVault, MANIFEST_BYTES_MAX, MAX_SINGLE_ARTIFACT_BYTES,
    NONCE_BYTES, authenticate_manifest, decrypt, derive_key, encrypt, envelope, hide_absence,
    lower_hex, parse_envelope, read_private_bounded, sync_directory, valid_lower_hex, valid_name,
    validate_artifact_id, write_new_synced,
};
use chrono::{DateTime, SecondsFormat, Utc};
use openssl::{rand::rand_bytes, sha::sha256};
use serde::{Deserialize, Serialize};
use xshield_core::constant_time;
use xshield_core::{
    calibration::publication::{
        CALIBRATION_REPORT_ARTIFACT_CONTENT_TYPE, CALIBRATION_REPORT_ARTIFACT_KIND,
        CalibrationReportArtifact,
    },
    domain::{ArtifactId, CalibrationReportId, SiteId, TenantId},
};

/// Immutable schema version for a calibration-report evidence manifest.
pub const CALIBRATION_REPORT_EVIDENCE_MANIFEST_SCHEMA_VERSION: u8 = 1;

/// Fixed encoding identifier for the report's canonical JSON body.
pub const CALIBRATION_REPORT_CANONICAL_BODY_ENCODING: &str =
    "xshield_calibration_report_canonical_json_v1";

pub(crate) const MANIFEST_FILENAME_SUFFIX: &str = "calibration-report.manifest.json";
pub(crate) const MANIFEST_AUTH_FILENAME_SUFFIX: &str = "calibration-report.manifest.hmac";

const CAPTURE_STATUS: &str = "complete";
const ENVELOPE_PROFILE: &str = "aead_envelope_v1";
const INTEGRITY_ALGORITHM: &str = "sha256_ciphertext";

/// Validated write command for one completed calibration report.
///
/// The report supplies both its `calr_` identity and its independently chosen
/// report artifact ID.  There is deliberately no request identity, generic
/// kind, caller-controlled classification, parent reference, or plaintext
/// field: the vault serializes the report with its fixed canonical encoder.
pub struct CalibrationReportEvidenceWrite<'a> {
    /// Authenticated tenant scope for the durable report.
    pub tenant_id: &'a TenantId,
    /// Authenticated site scope for the durable report.
    pub site_id: &'a SiteId,
    /// Fully validated pure-domain report body to persist.
    pub report: &'a CalibrationReportArtifact,
    /// Exclusive UTC read deadline for the resulting object.
    pub expires_at: DateTime<Utc>,
}

/// Authenticated, non-plaintext sidecar for one calibration report body.
///
/// This is intentionally distinct from [`super::EvidenceManifest`]: it has a
/// `report_id` and no `request_id`.  All content shape, representation, and
/// classification fields are fixed by the dedicated write command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationReportEvidenceManifest {
    /// Dedicated sidecar schema version.
    pub schema_version: u8,
    /// Immutable completed-report identity bound into the AEAD AAD.
    pub report_id: String,
    /// Immutable report artifact identity bound into the AEAD AAD.
    pub artifact_id: String,
    /// Tenant identity bound into the AEAD AAD.
    pub tenant_id: String,
    /// Site identity bound into the AEAD AAD.
    pub site_id: String,
    /// Fixed calibration report artifact kind.
    pub kind: String,
    /// Fixed canonical report body media type.
    pub content_type: String,
    /// Fixed encoding identifier for the report's canonical JSON body.
    pub canonical_body_encoding: String,
    /// Complete capture state for the fixed report writer.
    pub capture_status: String,
    /// Canonical plaintext bytes presented to the vault.
    pub bytes_observed: u64,
    /// Canonical plaintext bytes encrypted by the vault.
    pub bytes_saved: u64,
    /// Fixed exact-byte fidelity for the canonical report body.
    pub fidelity: EvidenceFidelity,
    /// Fixed restricted classification for a report containing aggregates.
    pub classification: EvidenceClassification,
    /// Non-secret envelope locator and root key reference.
    pub storage: EvidenceStorage,
    /// Ciphertext integrity metadata.
    pub integrity: EvidenceIntegrity,
    /// Exclusive UTC read deadline.
    pub expires_at: String,
}

/// Calibration report manifest authenticated by the local vault.
///
/// The private wrapper prevents a persistence adapter from substituting a
/// deserialized sidecar for one whose HMAC, scope, expiry, and fixed fields
/// have not been checked by the vault.
pub struct VerifiedCalibrationReportManifest(CalibrationReportEvidenceManifest);

impl VerifiedCalibrationReportManifest {
    /// Returns authenticated, non-plaintext report sidecar metadata.
    #[must_use]
    pub const fn manifest(&self) -> &CalibrationReportEvidenceManifest {
        &self.0
    }
}

/// Fresh authenticated report observation for a pending database publication.
///
/// This wrapper is distinct from a writer result. It is issued only after the
/// vault has re-read authenticated sidecars, ciphertext, AEAD data, and the
/// canonical report body immediately before a caller creates a database commit
/// command. It neither authorizes general report reading nor extends retention.
pub struct AttestedCalibrationReportManifest(VerifiedCalibrationReportManifest);

impl AttestedCalibrationReportManifest {
    /// Returns freshly authenticated, non-plaintext report sidecar metadata.
    #[must_use]
    pub const fn manifest(&self) -> &CalibrationReportEvidenceManifest {
        self.0.manifest()
    }
}

impl CalibrationReportEvidenceManifest {
    /// Validates report metadata decoded from durable storage without a clock.
    ///
    /// This is appropriate for a persistence adapter that has its own trusted
    /// database clock.  It validates the report-specific shape but neither
    /// authenticates the sidecar nor authorizes reading the report body.
    ///
    /// # Errors
    /// Returns [`EvidenceError::CorruptEvidence`] for malformed typed IDs,
    /// fixed-field deviations, unsafe locators, or invalid integrity metadata.
    pub fn validate_catalog_structure(&self) -> Result<(), EvidenceError> {
        let tenant_id =
            TenantId::parse(&self.tenant_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let site_id = SiteId::parse(&self.site_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let report_id = CalibrationReportId::parse(&self.report_id)
            .map_err(|_| EvidenceError::CorruptEvidence)?;
        let artifact_id =
            ArtifactId::parse(&self.artifact_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let key_id = self
            .storage
            .key_ref
            .as_deref()
            .ok_or(EvidenceError::CorruptEvidence)?;
        validate_manifest_fields(self, &tenant_id, &site_id, &report_id, &artifact_id, key_id)
            .map(|_| ())
    }

    /// Validates catalog metadata against a trusted recorded time.
    ///
    /// # Errors
    /// Returns [`EvidenceError::NotAvailable`] when the report is expired at
    /// `recorded_at`, or [`EvidenceError::CorruptEvidence`] for an invalid
    /// report sidecar shape.
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
    /// Encrypts and publishes a canonical calibration report and its sidecar.
    ///
    /// The AEAD associated data binds the tenant, site, report ID, report
    /// artifact ID, and fixed kind before the object is written.  Existing
    /// ciphertext or sidecars are never overwritten.  As with generic vault
    /// writes, a crash before sidecar publication may leave an unreachable
    /// ciphertext for an owner-controlled reconciliation pass.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for report serialization/validation, expiry
    /// or size bounds, cryptographic failures, unsafe storage, or durable I/O.
    pub fn write_calibration_report(
        &self,
        command: &CalibrationReportEvidenceWrite<'_>,
    ) -> Result<VerifiedCalibrationReportManifest, EvidenceError> {
        let plaintext = command
            .report
            .to_canonical_json()
            .map_err(|_| EvidenceError::InvalidWrite)?;
        validate_write(
            command,
            plaintext.len(),
            self.config.max_artifact_bytes,
            self.config.max_retention,
            Utc::now(),
        )?;

        let report_id = command.report.report_id();
        let artifact_id = command.report.report_artifact_id();
        let artifact_id_text = artifact_id.as_str();
        let locator = format!("{artifact_id_text}.xev");
        let aad =
            calibration_report_aad(command.tenant_id, command.site_id, report_id, artifact_id)?;
        let data_key = derive_key(&self.root_key.0, &aad)?;
        let mut nonce = [0; NONCE_BYTES];
        rand_bytes(&mut nonce)?;
        let (ciphertext, tag) = encrypt(&data_key, &nonce, &aad, &plaintext)?;
        let envelope = envelope(&nonce, &tag, &ciphertext)?;
        let bytes_saved =
            u64::try_from(plaintext.len()).map_err(|_| EvidenceError::InvalidWrite)?;
        let manifest = CalibrationReportEvidenceManifest {
            schema_version: CALIBRATION_REPORT_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            report_id: report_id.as_str().to_owned(),
            artifact_id: artifact_id_text.to_owned(),
            tenant_id: command.tenant_id.as_str().to_owned(),
            site_id: command.site_id.as_str().to_owned(),
            kind: CALIBRATION_REPORT_ARTIFACT_KIND.to_owned(),
            content_type: CALIBRATION_REPORT_ARTIFACT_CONTENT_TYPE.to_owned(),
            canonical_body_encoding: CALIBRATION_REPORT_CANONICAL_BODY_ENCODING.to_owned(),
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
        Ok(VerifiedCalibrationReportManifest(manifest))
    }

    /// Authenticates one scoped report sidecar without decrypting its body.
    ///
    /// This is the handoff point for a persistence adapter: it receives a
    /// non-forgeable wrapper carrying the exact report/artifact/scope binding,
    /// rather than a generic request evidence manifest.
    ///
    /// # Errors
    /// Returns [`EvidenceError::NotAvailable`] uniformly for unknown, expired,
    /// cross-scope, or mismatched report identities.  HMAC or sidecar shape
    /// failures return [`EvidenceError::CorruptEvidence`].
    pub fn read_calibration_report_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        report_id: &CalibrationReportId,
        artifact_id: &ArtifactId,
    ) -> Result<VerifiedCalibrationReportManifest, EvidenceError> {
        self.read_calibration_report_manifest_at(
            tenant_id,
            site_id,
            report_id,
            artifact_id,
            Utc::now(),
        )
    }

    /// Authenticates and decrypts the report named by the supplied identities.
    ///
    /// This method exposes only the parsed domain DTO.  Its decoder requires
    /// the report's exact canonical bytes, then checks that body and sidecar
    /// have the same report and artifact identities.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for unavailable, malformed, replaced, or
    /// unauthentic report evidence.
    pub fn read_calibration_report(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        report_id: &CalibrationReportId,
        artifact_id: &ArtifactId,
    ) -> Result<CalibrationReportArtifact, EvidenceError> {
        let manifest =
            self.read_calibration_report_manifest(tenant_id, site_id, report_id, artifact_id)?;
        self.read_calibration_report_matching_manifest(tenant_id, site_id, &manifest)
    }

    /// Decrypts a report only when its authenticated sidecars stay unchanged.
    ///
    /// A report persistence workflow can retain the verified wrapper it passed
    /// to its transaction and use this method to ensure a privileged retention
    /// or reconciliation operation did not replace the object before or during
    /// the content check.  The method does not grant authorization beyond the
    /// supplied authenticated report manifest.
    ///
    /// # Errors
    /// Returns [`EvidenceError::CorruptEvidence`] if either authenticated
    /// observation, ciphertext digest, AAD, canonical body, or typed identity
    /// differs from the expected report manifest.
    pub fn read_calibration_report_matching_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &VerifiedCalibrationReportManifest,
    ) -> Result<CalibrationReportArtifact, EvidenceError> {
        let manifest = expected.manifest();
        let report_id = CalibrationReportId::parse(&manifest.report_id)
            .map_err(|_| EvidenceError::CorruptEvidence)?;
        let artifact_id =
            ArtifactId::parse(&manifest.artifact_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let observed = self.read_calibration_report_manifest_at(
            tenant_id,
            site_id,
            &report_id,
            &artifact_id,
            Utc::now(),
        )?;
        if observed.manifest() != manifest {
            return Err(EvidenceError::CorruptEvidence);
        }
        let report = self.decrypt_calibration_report(tenant_id, site_id, manifest)?;
        let current = self.read_calibration_report_manifest_at(
            tenant_id,
            site_id,
            &report_id,
            &artifact_id,
            Utc::now(),
        )?;
        if current.manifest() != manifest {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(report)
    }

    /// Attests that the durable report still exactly matches a completed DTO.
    ///
    /// A report producer calls this after writing its report and directly
    /// before constructing a database publication command. The vault takes two
    /// authenticated sidecar observations around decryption, checks ciphertext
    /// integrity and AEAD binding, and compares the parsed canonical report to
    /// `expected`. A missing, expired, or replaced object therefore cannot
    /// become a completed batch/report database fact.
    ///
    /// The filesystem and `PostgreSQL` cannot share one transaction. A crash
    /// after writing but before database commit leaves an unreachable object
    /// for the dedicated report reconciliation and retention lifecycle; it
    /// does not consume a batch lease.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for report mismatch, unavailable/corrupt
    /// durable state, or expiry.
    pub fn attest_calibration_report(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &CalibrationReportArtifact,
    ) -> Result<AttestedCalibrationReportManifest, EvidenceError> {
        let manifest = self.read_calibration_report_manifest(
            tenant_id,
            site_id,
            expected.report_id(),
            expected.report_artifact_id(),
        )?;
        let observed =
            self.read_calibration_report_matching_manifest(tenant_id, site_id, &manifest)?;
        if observed != *expected {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(AttestedCalibrationReportManifest(manifest))
    }

    fn read_calibration_report_manifest_at(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        report_id: &CalibrationReportId,
        artifact_id: &ArtifactId,
        now: DateTime<Utc>,
    ) -> Result<VerifiedCalibrationReportManifest, EvidenceError> {
        let manifest = self.load_authenticated_calibration_report_manifest(artifact_id)?;
        let expires_at = validate_manifest_fields(
            &manifest,
            tenant_id,
            site_id,
            report_id,
            artifact_id,
            &self.config.key_id,
        )?;
        if expires_at <= now {
            return Err(EvidenceError::NotAvailable);
        }
        Ok(VerifiedCalibrationReportManifest(manifest))
    }

    fn load_authenticated_calibration_report_manifest(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<CalibrationReportEvidenceManifest, EvidenceError> {
        let artifact_id = artifact_id.as_str();
        validate_artifact_id(artifact_id)?;
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

    fn decrypt_calibration_report(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        manifest: &CalibrationReportEvidenceManifest,
    ) -> Result<CalibrationReportArtifact, EvidenceError> {
        let report_id = CalibrationReportId::parse(&manifest.report_id)
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
        let aad = calibration_report_aad(tenant_id, site_id, &report_id, &artifact_id)?;
        let data_key = derive_key(&self.root_key.0, &aad)?;
        let plaintext = decrypt(&data_key, nonce, &aad, ciphertext, tag)?;
        if u64::try_from(plaintext.len()).map_err(|_| EvidenceError::CorruptEvidence)?
            != manifest.bytes_saved
        {
            return Err(EvidenceError::CorruptEvidence);
        }
        let report = CalibrationReportArtifact::from_canonical_json(&plaintext)
            .map_err(|_| EvidenceError::CorruptEvidence)?;
        if report.report_id() != &report_id || report.report_artifact_id() != &artifact_id {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(report)
    }
}

fn validate_write(
    command: &CalibrationReportEvidenceWrite<'_>,
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
    manifest: &CalibrationReportEvidenceManifest,
    tenant_id: &TenantId,
    site_id: &SiteId,
    report_id: &CalibrationReportId,
    artifact_id: &ArtifactId,
    key_id: &str,
) -> Result<DateTime<Utc>, EvidenceError> {
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .map_err(|_| EvidenceError::CorruptEvidence)?
        .with_timezone(&Utc);
    if manifest.tenant_id != tenant_id.as_str()
        || manifest.site_id != site_id.as_str()
        || manifest.report_id != report_id.as_str()
        || manifest.artifact_id != artifact_id.as_str()
    {
        return Err(EvidenceError::NotAvailable);
    }
    if manifest.schema_version != CALIBRATION_REPORT_EVIDENCE_MANIFEST_SCHEMA_VERSION
        || manifest.kind != CALIBRATION_REPORT_ARTIFACT_KIND
        || manifest.content_type != CALIBRATION_REPORT_ARTIFACT_CONTENT_TYPE
        || manifest.canonical_body_encoding != CALIBRATION_REPORT_CANONICAL_BODY_ENCODING
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

fn calibration_report_aad(
    tenant_id: &TenantId,
    site_id: &SiteId,
    report_id: &CalibrationReportId,
    artifact_id: &ArtifactId,
) -> Result<Vec<u8>, EvidenceError> {
    let mut output = Vec::new();
    for component in [
        b"xshield-calibration-report-evidence-v1".as_slice(),
        &[CALIBRATION_REPORT_EVIDENCE_MANIFEST_SCHEMA_VERSION],
        tenant_id.as_str().as_bytes(),
        site_id.as_str().as_bytes(),
        report_id.as_str().as_bytes(),
        artifact_id.as_str().as_bytes(),
        CALIBRATION_REPORT_ARTIFACT_KIND.as_bytes(),
        CALIBRATION_REPORT_CANONICAL_BODY_ENCODING.as_bytes(),
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
        CalibrationReportEvidenceManifest, CalibrationReportEvidenceWrite, authenticate_manifest,
        manifest_auth_filename, manifest_filename,
    };
    use crate::{EvidenceError, EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault};
    use chrono::{TimeDelta, Utc};
    use std::{fs, path::PathBuf, time::Duration};
    use uuid::Uuid;
    use xshield_core::{
        calibration::{
            GroundTruth, Probability, Signal, Thresholds,
            dataset::{DatasetSample, EvaluationProvenance, ModelIdentity, evaluate_dataset},
            publication::{CalibrationReportArtifact, CalibrationReportPublication},
        },
        domain::{
            ApprovalRef, ArtifactId, CalibrationReportId, DatasetRevision, LabelRevision,
            MappingRevision, ModelCallId, ModelRevision, PromptRevision, ProviderId, SiteId,
            TaskRevision, TenantId, ThresholdPolicyRevision,
        },
    };

    const KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn report_writer_uses_a_dedicated_request_free_manifest_and_round_trips() {
        let root = private_temp_directory();
        let vault = vault(&root);
        let tenant = TenantId::parse("tenant_report").unwrap();
        let site = SiteId::parse("site_report").unwrap();
        let report = report(99);
        let manifest = vault
            .write_calibration_report(&CalibrationReportEvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                report: &report,
                expires_at: Utc::now() + TimeDelta::minutes(5),
            })
            .unwrap();
        let value = manifest.manifest();
        assert_eq!(value.report_id, report.report_id().as_str());
        assert_eq!(value.artifact_id, report.report_artifact_id().as_str());
        assert_eq!(value.kind, "calibration_evaluation_report");
        assert_eq!(
            value.content_type,
            "application/vnd.xshield.calibration-report+json"
        );
        assert_eq!(
            value.canonical_body_encoding,
            "xshield_calibration_report_canonical_json_v1"
        );
        let sidecar = fs::read(root.join(manifest_filename(&value.artifact_id))).unwrap();
        assert!(
            !sidecar
                .windows(b"request_id".len())
                .any(|part| part == b"request_id")
        );
        assert!(matches!(
            vault.read_manifest(&tenant, &site, report.report_artifact_id().as_str()),
            Err(EvidenceError::NotAvailable)
        ));
        assert_eq!(
            vault
                .read_calibration_report_matching_manifest(&tenant, &site, &manifest)
                .unwrap(),
            report
        );
        assert_eq!(
            vault
                .read_calibration_report(
                    &tenant,
                    &site,
                    report.report_id(),
                    report.report_artifact_id(),
                )
                .unwrap(),
            report
        );
        assert!(matches!(
            vault.read_calibration_report_manifest(
                &TenantId::parse("tenant_other").unwrap(),
                &site,
                report.report_id(),
                report.report_artifact_id(),
            ),
            Err(EvidenceError::NotAvailable)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn report_id_is_aad_bound_even_when_a_sidecar_is_reauthenticated() {
        let root = private_temp_directory();
        let vault = vault(&root);
        let tenant = TenantId::parse("tenant_report").unwrap();
        let site = SiteId::parse("site_report").unwrap();
        let report = report(99);
        vault
            .write_calibration_report(&CalibrationReportEvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                report: &report,
                expires_at: Utc::now() + TimeDelta::minutes(5),
            })
            .unwrap();
        let artifact_id = report.report_artifact_id().as_str();
        let other_report_id =
            CalibrationReportId::parse("calr_018f2a3b-4c5d-7000-8000-000000000100").unwrap();
        let manifest_path = root.join(manifest_filename(artifact_id));
        let mut sidecar: CalibrationReportEvidenceManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        sidecar.report_id = other_report_id.as_str().to_owned();
        let sidecar_bytes = serde_json::to_vec(&sidecar).unwrap();
        let authentication = authenticate_manifest(&vault.root_key.0, &sidecar_bytes).unwrap();
        fs::write(&manifest_path, sidecar_bytes).unwrap();
        fs::write(
            root.join(manifest_auth_filename(artifact_id)),
            authentication,
        )
        .unwrap();
        let reauthenticated = vault
            .read_calibration_report_manifest(
                &tenant,
                &site,
                &other_report_id,
                report.report_artifact_id(),
            )
            .unwrap();
        assert!(matches!(
            vault.read_calibration_report_matching_manifest(&tenant, &site, &reauthenticated),
            Err(EvidenceError::CorruptEvidence)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attestation_requires_the_current_authenticated_canonical_report() {
        let root = private_temp_directory();
        let vault = vault(&root);
        let tenant = TenantId::parse("tenant_report").unwrap();
        let site = SiteId::parse("site_report").unwrap();
        let report = report(99);
        vault
            .write_calibration_report(&CalibrationReportEvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                report: &report,
                expires_at: Utc::now() + TimeDelta::minutes(5),
            })
            .unwrap();
        assert_eq!(
            vault
                .attest_calibration_report(&tenant, &site, &report)
                .unwrap()
                .manifest()
                .artifact_id,
            report.report_artifact_id().as_str()
        );
        fs::remove_file(root.join(format!("{}.xev", report.report_artifact_id().as_str())))
            .unwrap();
        assert!(matches!(
            vault.attest_calibration_report(&tenant, &site, &report),
            Err(EvidenceError::NotAvailable)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generic_orphan_reconciliation_skips_report_sidecars() {
        let root = private_temp_directory();
        let vault = vault(&root);
        let tenant = TenantId::parse("tenant_report").unwrap();
        let site = SiteId::parse("site_report").unwrap();
        let report = report(99);
        vault
            .write_calibration_report(&CalibrationReportEvidenceWrite {
                tenant_id: &tenant,
                site_id: &site,
                report: &report,
                expires_at: Utc::now() + TimeDelta::minutes(5),
            })
            .unwrap();
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(
            vault
                .list_orphan_candidates(&tenant, &site, Duration::from_secs(1), 1)
                .unwrap()
                .is_empty()
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn vault(root: &PathBuf) -> LocalEvidenceVault {
        LocalEvidenceVault::open(
            EvidenceVaultConfig::new(root, "evidence-key-r1", 1024 * 1024, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap()
    }

    fn report(report_artifact_index: usize) -> CalibrationReportArtifact {
        let model = ModelIdentity::new(
            ProviderId::parse("vercel_ai_gateway").unwrap(),
            "typesafe-ai/jev",
            ModelRevision::parse("jev-1.13.0").unwrap(),
            PromptRevision::parse("prompt-r1").unwrap(),
            None,
        )
        .unwrap();
        let provenance = EvaluationProvenance::new(
            ApprovalRef::parse("approval-r1").unwrap(),
            DatasetRevision::parse("dataset-r1").unwrap(),
            LabelRevision::parse("labels-r1").unwrap(),
            TaskRevision::parse("task-r1").unwrap(),
            ThresholdPolicyRevision::parse("threshold-r1").unwrap(),
            MappingRevision::parse("risk-map-r1").unwrap(),
            artifact(1),
            artifact(2),
            artifact(3),
            artifact(4),
            model.clone(),
        )
        .unwrap();
        let samples = [
            DatasetSample::new(
                ModelCallId::parse("mdl_018f2a3b-4c5d-7000-8000-000000000010").unwrap(),
                artifact(10),
                artifact(11),
                model.clone(),
                MappingRevision::parse("risk-map-r1").unwrap(),
                GroundTruth::Benign,
                Signal::Risk(Probability::new(0.1).unwrap()),
            )
            .unwrap(),
            DatasetSample::new(
                ModelCallId::parse("mdl_018f2a3b-4c5d-7000-8000-000000000012").unwrap(),
                artifact(12),
                artifact(13),
                model,
                MappingRevision::parse("risk-map-r1").unwrap(),
                GroundTruth::Malicious,
                Signal::Risk(Probability::new(0.9).unwrap()),
            )
            .unwrap(),
        ];
        let evaluation = evaluate_dataset(
            provenance,
            &samples,
            Thresholds::new(
                Probability::new(0.2).unwrap(),
                Probability::new(0.8).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let publication = CalibrationReportPublication::new(
            CalibrationReportId::parse("calr_018f2a3b-4c5d-7000-8000-000000000099").unwrap(),
            artifact(report_artifact_index),
            &evaluation,
        )
        .unwrap();
        CalibrationReportArtifact::from_evaluation(&publication, &evaluation).unwrap()
    }

    fn artifact(index: usize) -> ArtifactId {
        ArtifactId::parse(format!("artifact_018f2a3b-4c5d-7000-8000-{index:012x}")).unwrap()
    }

    fn private_temp_directory() -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("xshield-report-evidence-test-{}", Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }
}
