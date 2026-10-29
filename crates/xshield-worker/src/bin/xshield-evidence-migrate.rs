//! One-shot copy of every live, complete generic evidence object out of the
//! local vault into the configured S3 bucket, so operators can finish
//! migrating before switching `XSHIELD_EVIDENCE_BACKEND` (docs/19 19.4)
//! instead of waiting for every local object to expire.
//!
//! Reentrant: every object write at the destination is create-only, so an
//! artifact already copied by an earlier run is a verified no-op. The whole
//! command may always be re-run after a partial failure, a restart, or new
//! writes landing on the local root in the meantime. It never deletes or
//! modifies the local vault; existing local retention keeps cleaning it up
//! on its own schedule.

use std::env;
use xshield_evidence::{
    EvidenceError, EvidenceKey, EvidenceMigrationOutcome, EvidenceVaultConfig, LocalEvidenceVault,
    S3EvidenceStoreConfig, S3EvidenceVault,
};
use zeroize::Zeroizing;

const CONFIG: &str = "EVIDENCE_MIGRATE_CONFIG_INVALID";
const BATCH_LIMIT_MAX: u16 = 256;
const DEFAULT_BATCH_LIMIT: u16 = 32;
// Every size and retention limit any writer may have used; migration only
// ever reads and copies, so there is nothing for a tighter policy to guard.
const VAULT_MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const VAULT_MAX_RETENTION_DAYS: u16 = 3_650;

#[derive(Default)]
struct Report {
    migrated: u64,
    already_migrated: u64,
    skipped: u64,
    failed: u64,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "migrated={} already_migrated={} skipped={} failed={}",
            self.migrated, self.already_migrated, self.skipped, self.failed
        )
    }
}

fn open_local(key_id: &str, key: &str) -> Result<LocalEvidenceVault, &'static str> {
    let root = env::var("XSHIELD_EVIDENCE_ROOT").map_err(|_| CONFIG)?;
    LocalEvidenceVault::open(
        EvidenceVaultConfig::new(
            &root,
            key_id,
            VAULT_MAX_ARTIFACT_BYTES,
            VAULT_MAX_RETENTION_DAYS,
        )
        .map_err(|_| CONFIG)?,
        EvidenceKey::from_hex(key).map_err(|_| CONFIG)?,
    )
    .map_err(|_| "EVIDENCE_MIGRATE_SOURCE_UNAVAILABLE")
}

fn open_destination(key_id: &str, key: &str) -> Result<S3EvidenceVault, &'static str> {
    let store = S3EvidenceStoreConfig::from_env()
        .map_err(|_| CONFIG)?
        .ok_or("EVIDENCE_MIGRATE_DESTINATION_REQUIRED")?;
    S3EvidenceVault::open(
        store,
        key_id,
        VAULT_MAX_ARTIFACT_BYTES,
        VAULT_MAX_RETENTION_DAYS,
        EvidenceKey::from_hex(key).map_err(|_| CONFIG)?,
    )
    .map_err(|_| "EVIDENCE_MIGRATE_DESTINATION_UNAVAILABLE")
}

fn run() -> Result<Report, &'static str> {
    let mut args = env::args_os().skip(1);
    let limit: u16 = match args.next() {
        Some(value) => value
            .into_string()
            .map_err(|_| CONFIG)?
            .parse()
            .map_err(|_| CONFIG)?,
        None => DEFAULT_BATCH_LIMIT,
    };
    if args.next().is_some() || !(1..=BATCH_LIMIT_MAX).contains(&limit) {
        return Err(CONFIG);
    }
    let key_id = env::var("XSHIELD_EVIDENCE_KEY_ID").map_err(|_| CONFIG)?;
    let key = Zeroizing::new(
        xshield_core::secret_env::var("XSHIELD_EVIDENCE_KEY_HEX").map_err(|_| CONFIG)?,
    );
    let local = open_local(&key_id, &key)?;
    let destination = open_destination(&key_id, &key)?;

    let mut report = Report::default();
    let mut cursor: Option<String> = None;
    loop {
        let page = local
            .list_generic_artifact_ids_after(limit, cursor.as_deref())
            .map_err(|_| "EVIDENCE_MIGRATE_LIST_FAILED")?;
        let Some(last) = page.last().cloned() else {
            break;
        };
        for artifact_id in &page {
            match destination.migrate_from_local(&local, artifact_id) {
                Ok(EvidenceMigrationOutcome::Migrated) => {
                    report.migrated += 1;
                    println!("migrated {artifact_id}");
                }
                Ok(EvidenceMigrationOutcome::AlreadyMigrated) => {
                    report.already_migrated += 1;
                }
                // Already expired, or raced a local retention pass; nothing
                // left to migrate either way.
                Err(EvidenceError::NotAvailable) => {
                    report.skipped += 1;
                }
                Err(error) => {
                    report.failed += 1;
                    eprintln!("EVIDENCE_MIGRATE_ITEM_FAILED {artifact_id}: {error}");
                }
            }
        }
        cursor = Some(last);
    }
    Ok(report)
}

fn main() {
    match run() {
        Ok(report) => {
            println!("{report}");
            if report.failed > 0 {
                std::process::exit(1);
            }
        }
        Err(reason) => {
            eprintln!("{reason}; usage: xshield-evidence-migrate [BATCH_LIMIT_1_TO_256]");
            std::process::exit(1);
        }
    }
}
