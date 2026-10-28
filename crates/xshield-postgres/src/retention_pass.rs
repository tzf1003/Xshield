//! One bounded maintenance pass over expired and orphan evidence ciphertext.
//!
//! Shared by the one-shot `xshield-evidence-retain` command (xshield-worker) and the gateway's
//! optional in-process retention loop. Every phase first commits a purge
//! intent, then lets the vault re-verify and delete, then commits the outcome,
//! so an interrupted pass is retried by the next one. The caller owns the
//! coordination with writers of the same root: the command holds the root's
//! exclusive lock, the gateway runs beside its own single writer, whose
//! in-flight ciphertext is younger than the orphan grace.

use crate::{
    CalibrationLineageReviewOrphanPurgeResult, CalibrationLineageReviewPurgeResult,
    CalibrationReportOrphanPurgeResult, CalibrationReportPurgeResult, EvidenceOrphanPurgeResult,
    EvidencePurgeResult, PostgresIdentityStore,
};
use std::{collections::HashSet, path::Path, time::Duration};
use xshield_core::domain::{SiteId, TenantId};
use xshield_evidence::{EvidenceError, EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault};

const DEADLINE: Duration = Duration::from_secs(15);

/// Largest batch per phase and pass.
pub const RETENTION_BATCH_LIMIT_MAX: u16 = 32;
/// How old an uncataloged ciphertext must be before it counts as an orphan.
pub const DEFAULT_ORPHAN_GRACE: Duration = Duration::from_hours(1);
/// Longest accepted orphan grace.
pub const MAX_ORPHAN_GRACE: Duration = Duration::from_hours(720);

/// Opens the vault view retention needs: it accepts every artifact size and
/// retention the writers may have used, and only ever deletes.
///
/// # Errors
///
/// Returns the vault's refusal of the root, key id or key.
pub fn open_retention_vault(
    root: &Path,
    key_id: &str,
    key_hex: &str,
) -> Result<LocalEvidenceVault, EvidenceError> {
    LocalEvidenceVault::open(
        EvidenceVaultConfig::new(root, key_id, 64 * 1024 * 1024, 3_650)?,
        EvidenceKey::from_hex(key_hex)?,
    )
}

/// What one pass selected, deleted and failed to delete, per phase.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct RetentionPassReport {
    pub cache_deleted: u64,
    pub selected: usize,
    pub deleted: usize,
    pub failed: usize,
    pub report_selected: usize,
    pub report_deleted: usize,
    pub report_failed: usize,
    pub report_orphan_selected: usize,
    pub report_orphan_deleted: usize,
    pub report_orphan_failed: usize,
    pub lineage_review_selected: usize,
    pub lineage_review_deleted: usize,
    pub lineage_review_failed: usize,
    pub lineage_review_orphan_selected: usize,
    pub lineage_review_orphan_deleted: usize,
    pub lineage_review_orphan_failed: usize,
    pub orphan_selected: usize,
    pub orphan_deleted: usize,
    pub orphan_failed: usize,
}

impl RetentionPassReport {
    /// Ciphertext objects this pass removed or found already absent.
    #[must_use]
    pub const fn deleted_total(&self) -> usize {
        self.deleted
            + self.report_deleted
            + self.report_orphan_deleted
            + self.lineage_review_deleted
            + self.lineage_review_orphan_deleted
            + self.orphan_deleted
    }

    /// The first phase with a rejected or unavailable deletion, which left a
    /// retryable intent behind.
    #[must_use]
    pub const fn failure(&self) -> Option<&'static str> {
        if self.failed > 0 {
            Some("EVIDENCE_PURGE_FAILED")
        } else if self.orphan_failed > 0 {
            Some("EVIDENCE_ORPHAN_PURGE_FAILED")
        } else if self.report_failed > 0 {
            Some("CALIBRATION_REPORT_PURGE_FAILED")
        } else if self.report_orphan_failed > 0 {
            Some("CALIBRATION_REPORT_ORPHAN_PURGE_FAILED")
        } else if self.lineage_review_failed > 0 {
            Some("CALIBRATION_LINEAGE_REVIEW_PURGE_FAILED")
        } else if self.lineage_review_orphan_failed > 0 {
            Some("CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_FAILED")
        } else {
            None
        }
    }
}

impl std::fmt::Display for RetentionPassReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cache_deleted={} selected={} deleted={} failed={} report_selected={} report_deleted={} report_failed={} report_orphan_selected={} report_orphan_deleted={} report_orphan_failed={} lineage_review_selected={} lineage_review_deleted={} lineage_review_failed={} lineage_review_orphan_selected={} lineage_review_orphan_deleted={} lineage_review_orphan_failed={} orphan_selected={} orphan_deleted={} orphan_failed={}",
            self.cache_deleted,
            self.selected,
            self.deleted,
            self.failed,
            self.report_selected,
            self.report_deleted,
            self.report_failed,
            self.report_orphan_selected,
            self.report_orphan_deleted,
            self.report_orphan_failed,
            self.lineage_review_selected,
            self.lineage_review_deleted,
            self.lineage_review_failed,
            self.lineage_review_orphan_selected,
            self.lineage_review_orphan_deleted,
            self.lineage_review_orphan_failed,
            self.orphan_selected,
            self.orphan_deleted,
            self.orphan_failed,
        )
    }
}

/// Runs one pass for a tenant, site and evidence key, at most `limit` items
/// per phase.
///
/// # Errors
///
/// Returns a stable reason code when a phase could not be prepared or its
/// outcome could not be committed; deletions already completed stay
/// completed and remaining intents are retried by the next pass. Per-item
/// refusals are not errors: they are counted in the report.
#[allow(clippy::too_many_lines)]
pub async fn run_retention_pass(
    store: &PostgresIdentityStore,
    vault: &LocalEvidenceVault,
    tenant: &TenantId,
    site: &SiteId,
    key_id: &str,
    limit: u16,
    orphan_grace: Duration,
) -> Result<RetentionPassReport, &'static str> {
    if !(1..=RETENTION_BATCH_LIMIT_MAX).contains(&limit)
        || orphan_grace.is_zero()
        || orphan_grace > MAX_ORPHAN_GRACE
    {
        return Err("EVIDENCE_PURGE_CONFIG_INVALID");
    }
    let cache_deleted = tokio::time::timeout(
        DEADLINE,
        store.purge_expired_model_evaluation_cache(tenant, site, limit),
    )
    .await
    .map_err(|_| "MODEL_CACHE_PURGE_TIMEOUT")?
    .map_err(|_| "MODEL_CACHE_PURGE_UNAVAILABLE")?;
    let jobs = tokio::time::timeout(
        DEADLINE,
        store.prepare_evidence_purge(tenant, site, key_id, limit),
    )
    .await
    .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
    .map_err(|_| "EVIDENCE_PURGE_UNAVAILABLE")?;
    let mut deleted = 0;
    let mut failed = 0;
    for job in &jobs {
        let result = match vault.purge_expired(tenant, site, job.artifact().manifest()) {
            Ok(outcome) => EvidencePurgeResult::Deleted(outcome),
            Err(
                EvidenceError::NotAvailable
                | EvidenceError::CorruptEvidence
                | EvidenceError::UnsafePath
                | EvidenceError::UnsafePermissions
                | EvidenceError::InvalidConfig
                | EvidenceError::InvalidWrite,
            ) => EvidencePurgeResult::Rejected,
            Err(_) => EvidencePurgeResult::Unavailable,
        };
        tokio::time::timeout(DEADLINE, store.finish_evidence_purge(job, result))
            .await
            .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
            .map_err(|_| "EVIDENCE_PURGE_COMPLETION_UNAVAILABLE")?;
        if matches!(result, EvidencePurgeResult::Deleted(_)) {
            deleted += 1;
        } else {
            failed += 1;
        }
    }
    let report_jobs = tokio::time::timeout(
        DEADLINE,
        store.prepare_calibration_report_purge(tenant, site, key_id, limit),
    )
    .await
    .map_err(|_| "CALIBRATION_REPORT_PURGE_TIMEOUT")?
    .map_err(|_| "CALIBRATION_REPORT_PURGE_UNAVAILABLE")?;
    let mut report_deleted = 0;
    let mut report_failed = 0;
    for job in &report_jobs {
        let result = report_result(vault, tenant, site, job.manifest());
        tokio::time::timeout(DEADLINE, store.finish_calibration_report_purge(job, result))
            .await
            .map_err(|_| "CALIBRATION_REPORT_PURGE_TIMEOUT")?
            .map_err(|_| "CALIBRATION_REPORT_PURGE_COMPLETION_UNAVAILABLE")?;
        if matches!(result, CalibrationReportPurgeResult::Deleted(_)) {
            report_deleted += 1;
        } else {
            report_failed += 1;
        }
    }
    let lineage_review_jobs = tokio::time::timeout(
        DEADLINE,
        store.prepare_calibration_lineage_review_purge(tenant, site, key_id, limit),
    )
    .await
    .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_PURGE_TIMEOUT")?
    .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_PURGE_UNAVAILABLE")?;
    let mut lineage_review_deleted = 0;
    let mut lineage_review_failed = 0;
    for job in &lineage_review_jobs {
        let result = lineage_review_result(vault, tenant, site, job.manifest());
        tokio::time::timeout(
            DEADLINE,
            store.finish_calibration_lineage_review_purge(job, result),
        )
        .await
        .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_PURGE_TIMEOUT")?
        .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_PURGE_COMPLETION_UNAVAILABLE")?;
        if matches!(result, CalibrationLineageReviewPurgeResult::Deleted(_)) {
            lineage_review_deleted += 1;
        } else {
            lineage_review_failed += 1;
        }
    }
    let pending_lineage_review_orphans = tokio::time::timeout(
        DEADLINE,
        store.pending_calibration_lineage_review_orphan_purges(tenant, site, limit),
    )
    .await
    .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_TIMEOUT")?
    .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_UNAVAILABLE")?;
    let mut lineage_review_orphan_selected = pending_lineage_review_orphans.len();
    let mut lineage_review_orphan_deleted = 0;
    let mut lineage_review_orphan_failed = 0;
    let mut seen_lineage_review_orphans = HashSet::new();
    for job in &pending_lineage_review_orphans {
        seen_lineage_review_orphans.insert(job.candidate().artifact_id().to_owned());
        let result =
            lineage_review_orphan_result(vault, job.tenant_id(), job.site_id(), job.candidate());
        tokio::time::timeout(
            DEADLINE,
            store.finish_calibration_lineage_review_orphan_purge(job, result),
        )
        .await
        .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_TIMEOUT")?
        .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_COMPLETION_UNAVAILABLE")?;
        if matches!(
            result,
            CalibrationLineageReviewOrphanPurgeResult::Deleted(_)
        ) {
            lineage_review_orphan_deleted += 1;
        } else {
            lineage_review_orphan_failed += 1;
        }
    }
    let mut lineage_review_orphan_remaining =
        usize::from(limit).saturating_sub(pending_lineage_review_orphans.len());
    let mut lineage_review_orphan_cursor = None;
    while lineage_review_orphan_remaining > 0 {
        let page_limit = u16::try_from(lineage_review_orphan_remaining)
            .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_SCAN_UNAVAILABLE")?;
        let page = vault
            .list_calibration_lineage_review_orphan_candidates_after(
                tenant,
                site,
                orphan_grace,
                page_limit,
                lineage_review_orphan_cursor.as_deref(),
            )
            .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_SCAN_UNAVAILABLE")?;
        let Some(last) = page.last() else {
            break;
        };
        lineage_review_orphan_cursor = Some(last.artifact_id().to_owned());
        consume_lineage_review_orphan_scan_budget(&mut lineage_review_orphan_remaining, page.len());
        let candidates = page
            .into_iter()
            .filter(|candidate| !seen_lineage_review_orphans.contains(candidate.artifact_id()))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            continue;
        }
        let jobs = tokio::time::timeout(
            DEADLINE,
            store.prepare_calibration_lineage_review_orphan_purge(tenant, site, &candidates),
        )
        .await
        .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_TIMEOUT")?
        .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_UNAVAILABLE")?;
        lineage_review_orphan_selected += jobs.len();
        for job in &jobs {
            let result = lineage_review_orphan_result(
                vault,
                job.tenant_id(),
                job.site_id(),
                job.candidate(),
            );
            tokio::time::timeout(
                DEADLINE,
                store.finish_calibration_lineage_review_orphan_purge(job, result),
            )
            .await
            .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_TIMEOUT")?
            .map_err(|_| "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_COMPLETION_UNAVAILABLE")?;
            if matches!(
                result,
                CalibrationLineageReviewOrphanPurgeResult::Deleted(_)
            ) {
                lineage_review_orphan_deleted += 1;
            } else {
                lineage_review_orphan_failed += 1;
            }
        }
    }
    let pending_report_orphans = tokio::time::timeout(
        DEADLINE,
        store.pending_calibration_report_orphan_purges(tenant, site, limit),
    )
    .await
    .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_TIMEOUT")?
    .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_UNAVAILABLE")?;
    let mut report_orphan_selected = pending_report_orphans.len();
    let mut report_orphan_deleted = 0;
    let mut report_orphan_failed = 0;
    let mut seen_report_orphans = HashSet::new();
    for job in &pending_report_orphans {
        seen_report_orphans.insert(job.candidate().artifact_id().to_owned());
        let result = report_orphan_result(vault, job.tenant_id(), job.site_id(), job.candidate());
        tokio::time::timeout(
            DEADLINE,
            store.finish_calibration_report_orphan_purge(job, result),
        )
        .await
        .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_TIMEOUT")?
        .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_COMPLETION_UNAVAILABLE")?;
        if matches!(result, CalibrationReportOrphanPurgeResult::Deleted(_)) {
            report_orphan_deleted += 1;
        } else {
            report_orphan_failed += 1;
        }
    }
    let report_orphan_remaining = usize::from(limit).saturating_sub(pending_report_orphans.len());
    let mut report_orphan_scanned = 0usize;
    let mut report_orphan_cursor = None;
    while report_orphan_scanned < report_orphan_remaining {
        let page_limit = u16::try_from(report_orphan_remaining - report_orphan_scanned)
            .map_err(|_| "CALIBRATION_REPORT_ORPHAN_SCAN_UNAVAILABLE")?;
        let page = vault
            .list_calibration_report_orphan_candidates_after(
                tenant,
                site,
                orphan_grace,
                page_limit,
                report_orphan_cursor.as_deref(),
            )
            .map_err(|_| "CALIBRATION_REPORT_ORPHAN_SCAN_UNAVAILABLE")?;
        let Some(last) = page.last() else {
            break;
        };
        report_orphan_cursor = Some(last.artifact_id().to_owned());
        let candidates = page
            .into_iter()
            .filter(|candidate| !seen_report_orphans.contains(candidate.artifact_id()))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            continue;
        }
        let jobs = tokio::time::timeout(
            DEADLINE,
            store.prepare_calibration_report_orphan_purge(tenant, site, &candidates),
        )
        .await
        .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_TIMEOUT")?
        .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_UNAVAILABLE")?;
        report_orphan_selected += jobs.len();
        report_orphan_scanned += jobs.len();
        for job in &jobs {
            let result =
                report_orphan_result(vault, job.tenant_id(), job.site_id(), job.candidate());
            tokio::time::timeout(
                DEADLINE,
                store.finish_calibration_report_orphan_purge(job, result),
            )
            .await
            .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_TIMEOUT")?
            .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_COMPLETION_UNAVAILABLE")?;
            if matches!(result, CalibrationReportOrphanPurgeResult::Deleted(_)) {
                report_orphan_deleted += 1;
            } else {
                report_orphan_failed += 1;
            }
        }
    }
    let pending_orphans = tokio::time::timeout(
        DEADLINE,
        store.pending_evidence_orphan_purges(tenant, site, limit),
    )
    .await
    .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
    .map_err(|_| "EVIDENCE_ORPHAN_PURGE_UNAVAILABLE")?;
    let mut seen_orphans = HashSet::new();
    let mut orphan_selected = pending_orphans.len();
    let mut orphan_deleted = 0;
    let mut orphan_failed = 0;
    for job in &pending_orphans {
        seen_orphans.insert(job.artifact_id().as_str().to_owned());
        let result = orphan_result(vault, job.tenant_id(), job.site_id(), job.candidate());
        tokio::time::timeout(DEADLINE, store.finish_evidence_orphan_purge(job, result))
            .await
            .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
            .map_err(|_| "EVIDENCE_ORPHAN_COMPLETION_UNAVAILABLE")?;
        if matches!(result, EvidenceOrphanPurgeResult::Deleted(_)) {
            orphan_deleted += 1;
        } else {
            orphan_failed += 1;
        }
    }
    let orphan_remaining = usize::from(limit).saturating_sub(pending_orphans.len());
    let mut orphan_scanned = 0usize;
    let mut cursor = None;
    while orphan_scanned < orphan_remaining {
        let page_limit = u16::try_from(orphan_remaining - orphan_scanned)
            .map_err(|_| "EVIDENCE_ORPHAN_SCAN_UNAVAILABLE")?;
        let page = vault
            .list_orphan_candidates_after(tenant, site, orphan_grace, page_limit, cursor.as_deref())
            .map_err(|_| "EVIDENCE_ORPHAN_SCAN_UNAVAILABLE")?;
        let Some(last) = page.last() else {
            break;
        };
        cursor = Some(last.artifact_id().to_owned());
        let candidates = page
            .into_iter()
            .filter(|candidate| !seen_orphans.contains(candidate.artifact_id()))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            continue;
        }
        let orphan_jobs = tokio::time::timeout(
            DEADLINE,
            store.prepare_evidence_orphan_purge(tenant, site, &candidates),
        )
        .await
        .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
        .map_err(|_| "EVIDENCE_ORPHAN_PURGE_UNAVAILABLE")?;
        orphan_selected += orphan_jobs.len();
        orphan_scanned += orphan_jobs.len();
        for job in &orphan_jobs {
            let result = orphan_result(vault, job.tenant_id(), job.site_id(), job.candidate());
            tokio::time::timeout(DEADLINE, store.finish_evidence_orphan_purge(job, result))
                .await
                .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
                .map_err(|_| "EVIDENCE_ORPHAN_COMPLETION_UNAVAILABLE")?;
            if matches!(result, EvidenceOrphanPurgeResult::Deleted(_)) {
                orphan_deleted += 1;
            } else {
                orphan_failed += 1;
            }
        }
    }
    Ok(RetentionPassReport {
        cache_deleted,
        selected: jobs.len(),
        deleted,
        failed,
        report_selected: report_jobs.len(),
        report_deleted,
        report_failed,
        report_orphan_selected,
        report_orphan_deleted,
        report_orphan_failed,
        lineage_review_selected: lineage_review_jobs.len(),
        lineage_review_deleted,
        lineage_review_failed,
        lineage_review_orphan_selected,
        lineage_review_orphan_deleted,
        lineage_review_orphan_failed,
        orphan_selected,
        orphan_deleted,
        orphan_failed,
    })
}

fn report_result(
    vault: &LocalEvidenceVault,
    tenant: &TenantId,
    site: &SiteId,
    manifest: &xshield_evidence::CalibrationReportEvidenceManifest,
) -> CalibrationReportPurgeResult {
    match vault.purge_expired_calibration_report(tenant, site, manifest) {
        Ok(outcome) => CalibrationReportPurgeResult::Deleted(outcome),
        Err(
            EvidenceError::NotAvailable
            | EvidenceError::CorruptEvidence
            | EvidenceError::UnsafePath
            | EvidenceError::UnsafePermissions
            | EvidenceError::InvalidConfig
            | EvidenceError::InvalidWrite,
        ) => CalibrationReportPurgeResult::Rejected,
        Err(_) => CalibrationReportPurgeResult::Unavailable,
    }
}

fn report_orphan_result(
    vault: &LocalEvidenceVault,
    tenant: &TenantId,
    site: &SiteId,
    candidate: &xshield_evidence::CalibrationReportOrphanCandidate,
) -> CalibrationReportOrphanPurgeResult {
    match vault.purge_calibration_report_orphan(tenant, site, candidate) {
        Ok(outcome) => CalibrationReportOrphanPurgeResult::Deleted(outcome),
        Err(
            EvidenceError::NotAvailable
            | EvidenceError::CorruptEvidence
            | EvidenceError::UnsafePath
            | EvidenceError::UnsafePermissions
            | EvidenceError::InvalidConfig
            | EvidenceError::InvalidWrite,
        ) => CalibrationReportOrphanPurgeResult::Rejected,
        Err(_) => CalibrationReportOrphanPurgeResult::Unavailable,
    }
}

fn lineage_review_result(
    vault: &LocalEvidenceVault,
    tenant: &TenantId,
    site: &SiteId,
    manifest: &xshield_evidence::CalibrationLineageReviewEvidenceManifest,
) -> CalibrationLineageReviewPurgeResult {
    match vault.purge_expired_calibration_lineage_review(tenant, site, manifest) {
        Ok(outcome) => CalibrationLineageReviewPurgeResult::Deleted(outcome),
        Err(
            EvidenceError::NotAvailable
            | EvidenceError::CorruptEvidence
            | EvidenceError::UnsafePath
            | EvidenceError::UnsafePermissions
            | EvidenceError::InvalidConfig
            | EvidenceError::InvalidWrite,
        ) => CalibrationLineageReviewPurgeResult::Rejected,
        Err(_) => CalibrationLineageReviewPurgeResult::Unavailable,
    }
}

fn lineage_review_orphan_result(
    vault: &LocalEvidenceVault,
    tenant: &TenantId,
    site: &SiteId,
    candidate: &xshield_evidence::CalibrationLineageReviewOrphanCandidate,
) -> CalibrationLineageReviewOrphanPurgeResult {
    match vault.purge_calibration_lineage_review_orphan(tenant, site, candidate) {
        Ok(outcome) => CalibrationLineageReviewOrphanPurgeResult::Deleted(outcome),
        Err(
            EvidenceError::NotAvailable
            | EvidenceError::CorruptEvidence
            | EvidenceError::UnsafePath
            | EvidenceError::UnsafePermissions
            | EvidenceError::InvalidConfig
            | EvidenceError::InvalidWrite,
        ) => CalibrationLineageReviewOrphanPurgeResult::Rejected,
        Err(_) => CalibrationLineageReviewOrphanPurgeResult::Unavailable,
    }
}

// The per-pass maintenance budget bounds observations, not only database jobs:
// a committed review must not make this synchronous vault scan walk unboundedly.
fn consume_lineage_review_orphan_scan_budget(remaining: &mut usize, observed_candidates: usize) {
    *remaining = remaining.saturating_sub(observed_candidates);
}

fn orphan_result(
    vault: &LocalEvidenceVault,
    tenant: &TenantId,
    site: &SiteId,
    candidate: &xshield_evidence::EvidenceOrphanCandidate,
) -> EvidenceOrphanPurgeResult {
    match vault.purge_orphan(tenant, site, candidate) {
        Ok(outcome) => EvidenceOrphanPurgeResult::Deleted(outcome),
        Err(
            EvidenceError::NotAvailable
            | EvidenceError::CorruptEvidence
            | EvidenceError::UnsafePath
            | EvidenceError::UnsafePermissions
            | EvidenceError::InvalidConfig
            | EvidenceError::InvalidWrite,
        ) => EvidenceOrphanPurgeResult::Rejected,
        Err(_) => EvidenceOrphanPurgeResult::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::consume_lineage_review_orphan_scan_budget;

    #[test]
    fn committed_review_page_consumes_scan_budget_when_prepare_returns_no_jobs() {
        let mut remaining = 2;
        let prepared_jobs = 0;

        consume_lineage_review_orphan_scan_budget(&mut remaining, 2);

        assert_eq!(prepared_jobs, 0);
        assert_eq!(remaining, 0);
    }
}
