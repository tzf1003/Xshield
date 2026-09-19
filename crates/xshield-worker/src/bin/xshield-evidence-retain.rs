//! One bounded, exclusive maintenance pass over expired local evidence ciphertext.

use std::{env, fs::File, time::Duration};
use xshield_core::domain::{SiteId, TenantId};
use xshield_evidence::{EvidenceError, EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault};
use xshield_postgres::{EvidencePurgeResult, PostgresIdentityStore};
use zeroize::Zeroizing;

const DEADLINE: Duration = Duration::from_secs(15);
const CONFIG: &str = "EVIDENCE_PURGE_CONFIG_INVALID";

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
    println!("selected={} deleted={deleted} failed={failed}", jobs.len());
    if failed > 0 {
        return Err("EVIDENCE_PURGE_FAILED");
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(reason) = run().await {
        eprintln!("{reason}; usage: xshield-evidence-retain TENANT_ID SITE_ID BATCH_LIMIT_1_TO_32");
        std::process::exit(1);
    }
}
