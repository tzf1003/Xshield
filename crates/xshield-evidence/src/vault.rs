//! One evidence vault, local or S3, behind the generic evidence API.

use crate::{
    EvidenceError, EvidenceManifest, EvidenceOrphanCandidate, EvidencePurgeOutcome, EvidenceWrite,
    LocalEvidenceVault, S3EvidenceVault, VerifiedEvidenceManifest,
};
use std::time::Duration;
use xshield_core::domain::{SiteId, TenantId};
use zeroize::Zeroizing;

/// The configured backend for generic evidence objects.
///
/// Both variants store identical encrypted objects and authenticated
/// manifests, so callers and the catalog are backend-agnostic. Calibration
/// report and lineage-review objects are local only; see [`Self::as_local`].
pub enum EvidenceVault {
    /// A private directory with one exclusive writer.
    Local(LocalEvidenceVault),
    /// An S3-compatible bucket, optionally under Object Lock.
    S3(Box<S3EvidenceVault>),
}

impl From<LocalEvidenceVault> for EvidenceVault {
    fn from(vault: LocalEvidenceVault) -> Self {
        Self::Local(vault)
    }
}

impl From<S3EvidenceVault> for EvidenceVault {
    fn from(vault: S3EvidenceVault) -> Self {
        Self::S3(Box::new(vault))
    }
}

impl EvidenceVault {
    /// The local vault, for the calibration families that only it stores.
    #[must_use]
    pub const fn as_local(&self) -> Option<&LocalEvidenceVault> {
        match self {
            Self::Local(vault) => Some(vault),
            Self::S3(_) => None,
        }
    }

    /// See [`LocalEvidenceVault::write`] and [`S3EvidenceVault::write`].
    ///
    /// # Errors
    /// As the backend's `write`.
    pub fn write(
        &self,
        command: &EvidenceWrite<'_>,
    ) -> Result<VerifiedEvidenceManifest, EvidenceError> {
        match self {
            Self::Local(vault) => vault.write(command),
            Self::S3(vault) => vault.write(command),
        }
    }

    /// See [`LocalEvidenceVault::read_manifest`].
    ///
    /// # Errors
    /// As the backend's `read_manifest`.
    pub fn read_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
    ) -> Result<VerifiedEvidenceManifest, EvidenceError> {
        match self {
            Self::Local(vault) => vault.read_manifest(tenant_id, site_id, artifact_id),
            Self::S3(vault) => vault.read_manifest(tenant_id, site_id, artifact_id),
        }
    }

    /// See [`LocalEvidenceVault::read_content`].
    ///
    /// # Errors
    /// As the backend's `read_content`.
    pub fn read_content(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
        match self {
            Self::Local(vault) => vault.read_content(tenant_id, site_id, artifact_id),
            Self::S3(vault) => vault.read_content(tenant_id, site_id, artifact_id),
        }
    }

    /// See [`LocalEvidenceVault::read_content_matching_manifest`].
    ///
    /// # Errors
    /// As the backend's `read_content_matching_manifest`.
    pub fn read_content_matching_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &VerifiedEvidenceManifest,
    ) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
        match self {
            Self::Local(vault) => {
                vault.read_content_matching_manifest(tenant_id, site_id, expected)
            }
            Self::S3(vault) => vault.read_content_matching_manifest(tenant_id, site_id, expected),
        }
    }

    /// See [`LocalEvidenceVault::purge_expired`].
    ///
    /// # Errors
    /// As the backend's `purge_expired`.
    pub fn purge_expired(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &EvidenceManifest,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        match self {
            Self::Local(vault) => vault.purge_expired(tenant_id, site_id, expected),
            Self::S3(vault) => vault.purge_expired(tenant_id, site_id, expected),
        }
    }

    /// See [`LocalEvidenceVault::list_orphan_candidates_after`].
    ///
    /// # Errors
    /// As the backend's `list_orphan_candidates_after`.
    pub fn list_orphan_candidates_after(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        grace: Duration,
        limit: u16,
        after: Option<&str>,
    ) -> Result<Vec<EvidenceOrphanCandidate>, EvidenceError> {
        match self {
            Self::Local(vault) => {
                vault.list_orphan_candidates_after(tenant_id, site_id, grace, limit, after)
            }
            Self::S3(vault) => {
                vault.list_orphan_candidates_after(tenant_id, site_id, grace, limit, after)
            }
        }
    }

    /// See [`LocalEvidenceVault::purge_orphan`].
    ///
    /// # Errors
    /// As the backend's `purge_orphan`.
    pub fn purge_orphan(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        candidate: &EvidenceOrphanCandidate,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        match self {
            Self::Local(vault) => vault.purge_orphan(tenant_id, site_id, candidate),
            Self::S3(vault) => vault.purge_orphan(tenant_id, site_id, candidate),
        }
    }
}
