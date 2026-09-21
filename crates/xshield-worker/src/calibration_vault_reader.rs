//! Purpose-specific local-vault adapter for offline calibration evidence.
//!
//! This adapter joins the durable, purpose-limited `PostgreSQL` authorization
//! check with authenticated local-vault reads. It never accepts a console
//! approval, case, or artifact string as authority. A zeroizing plaintext
//! buffer is returned only after a dedicated encrypted journal records its
//! `PASS` release fact durably.

use crate::calibration_audit::{
    CalibrationAuditBuildError, CalibrationEvidenceReadAuditEvent, CalibrationEvidenceReadOutcome,
};
use std::{
    error::Error,
    fmt,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use xshield_audit::{JournalError, LocalJournal};
use xshield_core::{
    calibration::read_capability::CalibrationEvidenceRole,
    domain::{ArtifactId, CalibrationReadCapabilityId, SiteId, TenantId},
    ports::{
        CalibrationEvidenceReadPort, CalibrationEvidenceReadRequest, CalibrationEvidenceReadState,
    },
};
use xshield_evidence::{EvidenceError, LocalEvidenceVault};
use xshield_postgres::{
    AuthorizedCalibrationEvidence, CalibrationEvidenceReadAuthorizationOutcome,
    CalibrationEvidenceReleaseCommitOutcome, CalibrationEvidenceReleaseReservationOutcome,
    PostgresIdentityStore, StoreError,
};
use zeroize::Zeroizing;

/// An authenticated calibration artifact whose plaintext remains zeroizing.
///
/// The content retains the reader's sole in-flight reservation until it is
/// dropped. Consumers can inspect its bytes but cannot clone or detach them
/// from their bounded lifetime.
pub struct CalibrationEvidenceContent {
    artifact_id: ArtifactId,
    role: CalibrationEvidenceRole,
    sample_index: Option<u16>,
    bytes: Zeroizing<Vec<u8>>,
    _permit: OwnedSemaphorePermit,
}

impl CalibrationEvidenceContent {
    /// Returns the catalog artifact authenticated for this exact read.
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Returns the frozen semantic role that constrains parsing of these bytes.
    #[must_use]
    pub const fn role(&self) -> CalibrationEvidenceRole {
        self.role
    }

    /// Returns the frozen sample slot, absent for partition manifests.
    #[must_use]
    pub const fn sample_index(&self) -> Option<u16> {
        self.sample_index
    }

    /// Borrows zeroizing plaintext while its reservation remains held.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for CalibrationEvidenceContent {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Non-content failure returned by [`LocalCalibrationEvidenceReader`].
///
/// Display and reason codes intentionally exclude artifact identities, vault
/// paths, source bytes, roles, and private lease handles. The audit variants
/// mean a terminal fact could not be made durable, so the reader withheld any
/// plaintext rather than fabricating an `ERROR` event.
#[derive(Debug)]
pub enum CalibrationEvidenceReadError {
    /// Durable capability revalidation could not complete.
    Authorization(StoreError),
    /// The reader's bounded plaintext reservation is unavailable.
    CapacityUnavailable,
    /// The local vault could not authenticate or decrypt the selected object.
    Vault(EvidenceError),
    /// The mandatory encrypted release-audit barrier could not be prepared or appended.
    Audit(CalibrationEvidenceAuditError),
    /// The blocking vault task ended before it returned a result.
    Cancelled(tokio::task::JoinError),
}

impl CalibrationEvidenceReadError {
    /// Returns the payload-free stable reason code for the caller's terminal handling.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Authorization(_) => "CALIBRATION_EVIDENCE_READ_AUTHORIZATION_UNAVAILABLE",
            Self::CapacityUnavailable => "CALIBRATION_EVIDENCE_READ_CAPACITY_UNAVAILABLE",
            Self::Vault(error) => vault_reason_code(error),
            Self::Audit(_) => "CALIBRATION_EVIDENCE_READ_AUDIT_UNAVAILABLE",
            Self::Cancelled(_) => "CALIBRATION_EVIDENCE_READ_CANCELLED",
        }
    }
}

impl fmt::Display for CalibrationEvidenceReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl Error for CalibrationEvidenceReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authorization(error) => Some(error),
            Self::Vault(error) => Some(error),
            Self::Audit(error) => Some(error),
            Self::Cancelled(error) => Some(error),
            Self::CapacityUnavailable => None,
        }
    }
}

/// Failure at the mandatory local calibration-read audit barrier.
///
/// A barrier error never exposes source content. It leaves the journal's own
/// recovery procedure responsible for an uncertain append; another physical
/// plaintext release must start a fresh attempt after recovery.
#[derive(Debug)]
pub enum CalibrationEvidenceAuditError {
    /// A prior panic poisoned the process-local journal mutex.
    LockPoisoned,
    /// The calibrated event could not be frozen into the closed contract.
    Build(CalibrationAuditBuildError),
    /// The encrypted journal did not durably acknowledge the event.
    Journal(JournalError),
    /// The blocking audit task ended before the barrier resolved.
    Cancelled(tokio::task::JoinError),
}

impl fmt::Display for CalibrationEvidenceAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CALIBRATION_EVIDENCE_READ_AUDIT_UNAVAILABLE")
    }
}

impl Error for CalibrationEvidenceAuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Build(error) => Some(error),
            Self::Journal(error) => Some(error),
            Self::Cancelled(error) => Some(error),
            Self::LockPoisoned => None,
        }
    }
}

/// Local-vault implementation of the purpose-specific calibration read port.
///
/// The reader authorizes every attempt with `PostgreSQL` before opening the
/// vault. It then compares the vault-authenticated manifest with the catalog
/// expectation, validates envelope digest and AEAD through the vault, and
/// reserves and commits a durable release boundary around the dedicated
/// terminal fact before returning a plaintext buffer.
/// It does not consume a batch, publish a report, or write a control-plane
/// `evidence.read` event.
pub struct LocalCalibrationEvidenceReader {
    store: PostgresIdentityStore,
    vault: Arc<LocalEvidenceVault>,
    audit_journal: Arc<Mutex<LocalJournal>>,
    capacity: Arc<Semaphore>,
}

impl LocalCalibrationEvidenceReader {
    /// Creates a reader with one retained plaintext object at a time.
    ///
    /// `journal` must be exclusive to this calibration-release writer. A
    /// successful call does not return its content until the journal append
    /// receives an exact durability receipt. This constructor has no I/O or
    /// authorization side effect.
    #[must_use]
    pub fn new(
        store: PostgresIdentityStore,
        vault: LocalEvidenceVault,
        journal: LocalJournal,
    ) -> Self {
        Self {
            store,
            vault: Arc::new(vault),
            audit_journal: Arc::new(Mutex::new(journal)),
            capacity: Arc::new(Semaphore::new(1)),
        }
    }

    async fn append_terminal(
        &self,
        context: &CalibrationEvidenceReadAuditContext,
        outcome: CalibrationEvidenceReadOutcome,
    ) -> Result<(), CalibrationEvidenceAuditError> {
        let journal = Arc::clone(&self.audit_journal);
        let context = context.clone();
        tokio::task::spawn_blocking(move || {
            let mut journal = journal
                .lock()
                .map_err(|_| CalibrationEvidenceAuditError::LockPoisoned)?;
            let event = CalibrationEvidenceReadAuditEvent::prepare(
                &journal,
                &context.tenant,
                &context.site,
                &context.capability,
                outcome,
            )
            .map_err(CalibrationEvidenceAuditError::Build)?;
            event
                .append(&mut journal)
                .map(|_| ())
                .map_err(CalibrationEvidenceAuditError::Journal)
        })
        .await
        .map_err(CalibrationEvidenceAuditError::Cancelled)?
    }

    async fn append_pre_release(
        &self,
        context: &CalibrationEvidenceReadAuditContext,
        bytes_released: u64,
    ) -> Result<(), CalibrationEvidenceAuditError> {
        self.append_terminal(
            context,
            CalibrationEvidenceReadOutcome::ReleasePrepared { bytes_released },
        )
        .await
    }
}

impl CalibrationEvidenceReadPort for LocalCalibrationEvidenceReader {
    type Content = CalibrationEvidenceContent;
    type Error = CalibrationEvidenceReadError;

    #[allow(clippy::too_many_lines)]
    async fn read_calibration_evidence<'a>(
        &'a self,
        request: CalibrationEvidenceReadRequest<'a>,
    ) -> Result<CalibrationEvidenceReadState<Self::Content>, Self::Error> {
        let audit_context = CalibrationEvidenceReadAuditContext::from_request(&request);
        let authorized = match self
            .store
            .authorize_calibration_evidence_read(&request)
            .await
        {
            Ok(authorization) => authorization,
            Err(error) => {
                self.append_terminal(
                    &audit_context,
                    CalibrationEvidenceReadOutcome::AuthorizationUnavailable,
                )
                .await
                .map_err(CalibrationEvidenceReadError::Audit)?;
                return Err(CalibrationEvidenceReadError::Authorization(error));
            }
        };
        let authorized = match authorized {
            CalibrationEvidenceReadAuthorizationOutcome::Authorized(authorized) => authorized,
            CalibrationEvidenceReadAuthorizationOutcome::Denied(denied) => {
                self.append_terminal(
                    &audit_context,
                    CalibrationEvidenceReadOutcome::NotAuthorized,
                )
                .await
                .map_err(CalibrationEvidenceReadError::Audit)?;
                return Ok(CalibrationEvidenceReadState::Denied(denied));
            }
        };
        let Ok(permit) = self.capacity.clone().try_acquire_owned() else {
            self.append_terminal(
                &audit_context,
                CalibrationEvidenceReadOutcome::CapacityUnavailable,
            )
            .await
            .map_err(CalibrationEvidenceReadError::Audit)?;
            return Err(CalibrationEvidenceReadError::CapacityUnavailable);
        };
        let tenant_id = request.tenant_id().clone();
        let site_id = request.site_id().clone();
        let vault = Arc::clone(&self.vault);
        match tokio::task::spawn_blocking(move || {
            read_authorized_vault_content(&vault, &tenant_id, &site_id, &authorized, permit)
        })
        .await
        {
            Ok(Ok(content)) => {
                // Vault authentication covers the immutable object, but the
                // database authorization transaction ended before that I/O.
                // Reserve the database release boundary before the journal
                // barrier; the reservation blocks catalog mutation without
                // holding a database lock across the local journal fsync.
                let reservation = match self
                    .store
                    .reserve_calibration_evidence_release(&request)
                    .await
                {
                    Ok(CalibrationEvidenceReleaseReservationOutcome::Reserved(reservation)) => {
                        reservation
                    }
                    Ok(CalibrationEvidenceReleaseReservationOutcome::Denied(denied)) => {
                        drop(content);
                        self.append_terminal(
                            &audit_context,
                            CalibrationEvidenceReadOutcome::NotAuthorized,
                        )
                        .await
                        .map_err(CalibrationEvidenceReadError::Audit)?;
                        return Ok(CalibrationEvidenceReadState::Denied(denied));
                    }
                    Err(error) => {
                        drop(content);
                        self.append_terminal(
                            &audit_context,
                            CalibrationEvidenceReadOutcome::AuthorizationUnavailable,
                        )
                        .await
                        .map_err(CalibrationEvidenceReadError::Audit)?;
                        return Err(CalibrationEvidenceReadError::Authorization(error));
                    }
                };
                let Ok(bytes_released) = u64::try_from(content.bytes.len()) else {
                    drop(content);
                    self.append_terminal(
                        &audit_context,
                        CalibrationEvidenceReadOutcome::IntegrityFailed,
                    )
                    .await
                    .map_err(CalibrationEvidenceReadError::Audit)?;
                    return Err(CalibrationEvidenceReadError::Vault(
                        EvidenceError::CorruptEvidence,
                    ));
                };
                if let Err(error) = self
                    .append_pre_release(&audit_context, bytes_released)
                    .await
                {
                    drop(content);
                    return Err(CalibrationEvidenceReadError::Audit(error));
                }
                match self
                    .store
                    .commit_calibration_evidence_release(&request, reservation)
                    .await
                {
                    Ok(CalibrationEvidenceReleaseCommitOutcome::Released) => {
                        Ok(CalibrationEvidenceReadState::Read(content))
                    }
                    Ok(CalibrationEvidenceReleaseCommitOutcome::Denied(denied)) => {
                        drop(content);
                        Ok(CalibrationEvidenceReadState::Denied(denied))
                    }
                    Err(error) => {
                        drop(content);
                        Err(CalibrationEvidenceReadError::Authorization(error))
                    }
                }
            }
            Ok(Err(error)) => {
                self.append_terminal(&audit_context, vault_outcome(&error))
                    .await
                    .map_err(CalibrationEvidenceReadError::Audit)?;
                Err(CalibrationEvidenceReadError::Vault(error))
            }
            Err(error) => {
                self.append_terminal(&audit_context, CalibrationEvidenceReadOutcome::Cancelled)
                    .await
                    .map_err(CalibrationEvidenceReadError::Audit)?;
                Err(CalibrationEvidenceReadError::Cancelled(error))
            }
        }
    }
}

fn read_authorized_vault_content(
    vault: &LocalEvidenceVault,
    tenant_id: &TenantId,
    site_id: &SiteId,
    authorized: &AuthorizedCalibrationEvidence,
    permit: OwnedSemaphorePermit,
) -> Result<CalibrationEvidenceContent, EvidenceError> {
    let artifact = authorized.artifact();
    let artifact_id = artifact.artifact_id().clone();
    let manifest = vault.read_manifest(tenant_id, site_id, artifact_id.as_str())?;
    if manifest.manifest() != artifact.manifest() {
        return Err(EvidenceError::CorruptEvidence);
    }
    let bytes = vault.read_content_matching_manifest(tenant_id, site_id, &manifest)?;
    if bytes.is_empty() {
        return Err(EvidenceError::CorruptEvidence);
    }
    Ok(CalibrationEvidenceContent {
        artifact_id,
        role: authorized.role(),
        sample_index: authorized.sample_index(),
        bytes,
        _permit: permit,
    })
}

fn vault_outcome(error: &EvidenceError) -> CalibrationEvidenceReadOutcome {
    match error {
        EvidenceError::CorruptEvidence
        | EvidenceError::UnsafePath
        | EvidenceError::UnsafePermissions
        | EvidenceError::Crypto
        | EvidenceError::Json(_)
        | EvidenceError::OpenSsl(_) => CalibrationEvidenceReadOutcome::IntegrityFailed,
        EvidenceError::NotAvailable
        | EvidenceError::Io(_)
        | EvidenceError::InvalidConfig
        | EvidenceError::InvalidWrite => CalibrationEvidenceReadOutcome::VaultUnavailable,
    }
}

const fn vault_reason_code(error: &EvidenceError) -> &'static str {
    match error {
        EvidenceError::CorruptEvidence
        | EvidenceError::UnsafePath
        | EvidenceError::UnsafePermissions
        | EvidenceError::Crypto
        | EvidenceError::Json(_)
        | EvidenceError::OpenSsl(_) => "CALIBRATION_EVIDENCE_READ_INTEGRITY_FAILED",
        EvidenceError::NotAvailable
        | EvidenceError::Io(_)
        | EvidenceError::InvalidConfig
        | EvidenceError::InvalidWrite => "CALIBRATION_EVIDENCE_READ_VAULT_UNAVAILABLE",
    }
}

#[derive(Clone)]
struct CalibrationEvidenceReadAuditContext {
    tenant: TenantId,
    site: SiteId,
    capability: CalibrationReadCapabilityId,
}

impl CalibrationEvidenceReadAuditContext {
    fn from_request(request: &CalibrationEvidenceReadRequest<'_>) -> Self {
        Self {
            tenant: request.tenant_id().clone(),
            site: request.site_id().clone(),
            capability: request.capability().capability_id().clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CalibrationEvidenceReadError, vault_outcome, vault_reason_code};
    use xshield_evidence::EvidenceError;

    #[test]
    fn vault_failures_have_contract_matched_audit_outcomes_and_reason_codes() {
        for (error, outcome, reason) in [
            (
                EvidenceError::NotAvailable,
                "VaultUnavailable",
                "CALIBRATION_EVIDENCE_READ_VAULT_UNAVAILABLE",
            ),
            (
                EvidenceError::CorruptEvidence,
                "IntegrityFailed",
                "CALIBRATION_EVIDENCE_READ_INTEGRITY_FAILED",
            ),
        ] {
            assert_eq!(format!("{:?}", vault_outcome(&error)), outcome);
            assert_eq!(vault_reason_code(&error), reason);
            assert_eq!(
                CalibrationEvidenceReadError::Vault(error).reason_code(),
                reason
            );
        }
    }
}
