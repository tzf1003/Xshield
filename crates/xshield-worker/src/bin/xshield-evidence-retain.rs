//! One bounded, exclusive maintenance pass over expired and orphan evidence ciphertext.

use std::{collections::HashSet, env, fs::File, time::Duration};
use xshield_core::domain::{SiteId, TenantId};
use xshield_evidence::{EvidenceError, EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault};
use xshield_postgres::{
    CalibrationReportOrphanPurgeResult, CalibrationReportPurgeResult, EvidenceOrphanPurgeResult,
    EvidencePurgeResult, PostgresIdentityStore,
};
use zeroize::Zeroizing;

const DEADLINE: Duration = Duration::from_secs(15);
const CONFIG: &str = "EVIDENCE_PURGE_CONFIG_INVALID";
const DEFAULT_ORPHAN_GRACE: Duration = Duration::from_hours(1);

#[allow(clippy::too_many_lines)]
async fn run() -> Result<(), &'static str> {
    let mut args = env::args_os().skip(1);
    let tenant = TenantId::parse(
        args.next()
            .ok_or(CONFIG)?
            .into_string()
            .map_err(|_| CONFIG)?,
    )
    .map_err(|_| CONFIG)?;
    let site = SiteId::parse(
        args.next()
            .ok_or(CONFIG)?
            .into_string()
            .map_err(|_| CONFIG)?,
    )
    .map_err(|_| CONFIG)?;
    let limit: u16 = args
        .next()
        .ok_or(CONFIG)?
        .into_string()
        .map_err(|_| CONFIG)?
        .parse()
        .map_err(|_| CONFIG)?;
    if args.next().is_some() || !(1..=32).contains(&limit) {
        return Err(CONFIG);
    }
    let root = env::var("XSHIELD_EVIDENCE_ROOT").map_err(|_| CONFIG)?;
    let key_id = env::var("XSHIELD_EVIDENCE_KEY_ID").map_err(|_| CONFIG)?;
    let key = Zeroizing::new(env::var("XSHIELD_EVIDENCE_KEY_HEX").map_err(|_| CONFIG)?);
    let database = Zeroizing::new(env::var("XSHIELD_DATABASE_URL").map_err(|_| CONFIG)?);
    let orphan_grace = env::var("XSHIELD_EVIDENCE_ORPHAN_GRACE_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>().map(Duration::from_secs))
        .transpose()
        .map_err(|_| CONFIG)?
        .unwrap_or(DEFAULT_ORPHAN_GRACE);
    if orphan_grace.is_zero() || orphan_grace > Duration::from_hours(720) {
        return Err(CONFIG);
    }
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&root, &key_id, 64 * 1024 * 1024, 3_650).map_err(|_| CONFIG)?,
        EvidenceKey::from_hex(&key).map_err(|_| CONFIG)?,
    )
    .map_err(|_| CONFIG)?;
    // ponytail: one Unix local directory owner, shared with the gateway writer.
    // Run during maintenance; online reclamation needs coordinated byte budgets.
    let root_lock = File::open(&root).map_err(|_| "EVIDENCE_PURGE_UNAVAILABLE")?;
    root_lock.try_lock().map_err(|_| "EVIDENCE_PURGE_BUSY")?;
    let store = tokio::time::timeout(
        DEADLINE,
        PostgresIdentityStore::connect(&database, 1, Duration::from_secs(5)),
    )
    .await
    .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
    .map_err(|_| "EVIDENCE_PURGE_UNAVAILABLE")?;
    let jobs = tokio::time::timeout(
        DEADLINE,
        store.prepare_evidence_purge(&tenant, &site, &key_id, limit),
    )
    .await
    .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
    .map_err(|_| "EVIDENCE_PURGE_UNAVAILABLE")?;
    let mut deleted = 0;
    let mut failed = 0;
    for job in &jobs {
        let result = match vault.purge_expired(&tenant, &site, job.artifact().manifest()) {
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
        store.prepare_calibration_report_purge(&tenant, &site, &key_id, limit),
    )
    .await
    .map_err(|_| "CALIBRATION_REPORT_PURGE_TIMEOUT")?
    .map_err(|_| "CALIBRATION_REPORT_PURGE_UNAVAILABLE")?;
    let mut report_deleted = 0;
    let mut report_failed = 0;
    for job in &report_jobs {
        let result = report_result(&vault, &tenant, &site, job.manifest());
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
    let pending_report_orphans = tokio::time::timeout(
        DEADLINE,
        store.pending_calibration_report_orphan_purges(&tenant, &site, limit),
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
        let result = report_orphan_result(&vault, job.tenant_id(), job.site_id(), job.candidate());
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
                &tenant,
                &site,
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
            store.prepare_calibration_report_orphan_purge(&tenant, &site, &candidates),
        )
        .await
        .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_TIMEOUT")?
        .map_err(|_| "CALIBRATION_REPORT_ORPHAN_PURGE_UNAVAILABLE")?;
        report_orphan_selected += jobs.len();
        report_orphan_scanned += jobs.len();
        for job in &jobs {
            let result =
                report_orphan_result(&vault, job.tenant_id(), job.site_id(), job.candidate());
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
        store.pending_evidence_orphan_purges(&tenant, &site, limit),
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
        let result = orphan_result(&vault, job.tenant_id(), job.site_id(), job.candidate());
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
            .list_orphan_candidates_after(
                &tenant,
                &site,
                orphan_grace,
                page_limit,
                cursor.as_deref(),
            )
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
            store.prepare_evidence_orphan_purge(&tenant, &site, &candidates),
        )
        .await
        .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
        .map_err(|_| "EVIDENCE_ORPHAN_PURGE_UNAVAILABLE")?;
        orphan_selected += orphan_jobs.len();
        orphan_scanned += orphan_jobs.len();
        for job in &orphan_jobs {
            let result = orphan_result(&vault, job.tenant_id(), job.site_id(), job.candidate());
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
    println!(
        "selected={} deleted={deleted} failed={failed} report_selected={} report_deleted={report_deleted} report_failed={report_failed} report_orphan_selected={} report_orphan_deleted={report_orphan_deleted} report_orphan_failed={report_orphan_failed} orphan_selected={} orphan_deleted={orphan_deleted} orphan_failed={orphan_failed}",
        jobs.len(),
        report_jobs.len(),
        report_orphan_selected,
        orphan_selected
    );
    if failed > 0 {
        return Err("EVIDENCE_PURGE_FAILED");
    }
    if orphan_failed > 0 {
        return Err("EVIDENCE_ORPHAN_PURGE_FAILED");
    }
    if report_failed > 0 {
        return Err("CALIBRATION_REPORT_PURGE_FAILED");
    }
    if report_orphan_failed > 0 {
        return Err("CALIBRATION_REPORT_ORPHAN_PURGE_FAILED");
    }
    Ok(())
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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(reason) = run().await {
        eprintln!("{reason}; usage: xshield-evidence-retain TENANT_ID SITE_ID BATCH_LIMIT_1_TO_32");
        std::process::exit(1);
    }
}
