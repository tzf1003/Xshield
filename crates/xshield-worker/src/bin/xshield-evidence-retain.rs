//! One bounded, exclusive maintenance pass over expired and orphan evidence ciphertext.

use std::{env, fs::File, path::Path, time::Duration};
use xshield_core::domain::{SiteId, TenantId};
use xshield_postgres::PostgresIdentityStore;
use xshield_postgres::retention_pass::{
    DEFAULT_ORPHAN_GRACE, MAX_ORPHAN_GRACE, RETENTION_BATCH_LIMIT_MAX, open_retention_vault,
    run_retention_pass,
};
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
    if args.next().is_some() || !(1..=RETENTION_BATCH_LIMIT_MAX).contains(&limit) {
        return Err(CONFIG);
    }
    let root = env::var("XSHIELD_EVIDENCE_ROOT").map_err(|_| CONFIG)?;
    let key_id = env::var("XSHIELD_EVIDENCE_KEY_ID").map_err(|_| CONFIG)?;
    let key = Zeroizing::new(
        xshield_core::secret_env::var("XSHIELD_EVIDENCE_KEY_HEX").map_err(|_| CONFIG)?,
    );
    let database =
        Zeroizing::new(xshield_core::secret_env::var("XSHIELD_DATABASE_URL").map_err(|_| CONFIG)?);
    let orphan_grace = env::var("XSHIELD_EVIDENCE_ORPHAN_GRACE_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>().map(Duration::from_secs))
        .transpose()
        .map_err(|_| CONFIG)?
        .unwrap_or(DEFAULT_ORPHAN_GRACE);
    if orphan_grace.is_zero() || orphan_grace > MAX_ORPHAN_GRACE {
        return Err(CONFIG);
    }
    let vault = open_retention_vault(Path::new(&root), &key_id, &key).map_err(|_| CONFIG)?;
    // ponytail: one Unix local directory owner, shared with the gateway writer.
    // A gateway with XSHIELD_EVIDENCE_RETENTION_INTERVAL_SECONDS runs these
    // passes itself; this command is for a stopped gateway.
    let root_lock = File::open(&root).map_err(|_| "EVIDENCE_PURGE_UNAVAILABLE")?;
    root_lock.try_lock().map_err(|_| "EVIDENCE_PURGE_BUSY")?;
    let store = tokio::time::timeout(
        DEADLINE,
        PostgresIdentityStore::connect(&database, 1, Duration::from_secs(5)),
    )
    .await
    .map_err(|_| "EVIDENCE_PURGE_TIMEOUT")?
    .map_err(|_| "EVIDENCE_PURGE_UNAVAILABLE")?;
    let report =
        run_retention_pass(&store, &vault, &tenant, &site, &key_id, limit, orphan_grace).await?;
    println!("{report}");
    report.failure().map_or(Ok(()), Err)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(reason) = run().await {
        eprintln!("{reason}; usage: xshield-evidence-retain TENANT_ID SITE_ID BATCH_LIMIT_1_TO_32");
        std::process::exit(1);
    }
}
