//! Optional in-process evidence retention (docs/12 12.8).
//!
//! The evidence root has one owner, the gateway's writer, so the one-shot
//! `xshield-evidence-retain` command needs the gateway stopped. With
//! `XSHIELD_EVIDENCE_RETENTION_INTERVAL_SECONDS` set, the gateway runs the
//! same bounded pass itself, on its own thread, runtime and single database
//! connection, so a slow pass never takes a request worker or a request's
//! pool slot. It runs beside captures without their permit: a capture's
//! ciphertext is uncataloged only for the moments before its catalog
//! commit, far inside the orphan grace, and cataloged ciphertext is purged
//! only once expired. After each pass the writer's budget is recomputed
//! from the root, which is what a restart used to be needed for.

use std::{env, error::Error, sync::Arc, thread, time::Duration};
use xshield_core::domain::{SiteId, TenantId};
use xshield_evidence::LocalEvidenceVault;
use xshield_postgres::PostgresIdentityStore;
use xshield_postgres::retention_pass::{
    DEFAULT_ORPHAN_GRACE, MAX_ORPHAN_GRACE, RETENTION_BATCH_LIMIT_MAX, RetentionPassReport,
    open_retention_vault, run_retention_pass,
};
use zeroize::Zeroizing;

use crate::{evidence_writer::EvidenceWriter, ops_api::EdgeMetrics};

const CONNECT_DEADLINE: Duration = Duration::from_secs(15);
const MAX_INTERVAL_SECONDS: u64 = 86_400;

pub(crate) struct EvidenceRetention {
    interval: Duration,
    limit: u16,
    orphan_grace: Duration,
    key_id: String,
    vault: LocalEvidenceVault,
    writer: Arc<EvidenceWriter>,
    tenant: TenantId,
    site: SiteId,
    database_url: Zeroizing<String>,
}

impl EvidenceRetention {
    /// `None` when the interval is unset. Every setting is checked here, so a
    /// misconfigured retention stops startup instead of failing every pass.
    pub(crate) fn from_env(
        writer: Option<&Arc<EvidenceWriter>>,
        tenant: &TenantId,
        site: &SiteId,
    ) -> Result<Option<Self>, Box<dyn Error>> {
        let Ok(interval) = env::var("XSHIELD_EVIDENCE_RETENTION_INTERVAL_SECONDS") else {
            return Ok(None);
        };
        let interval: u64 = interval.parse()?;
        if !(1..=MAX_INTERVAL_SECONDS).contains(&interval) {
            return Err("evidence retention interval must be 1 to 86400 seconds".into());
        }
        let writer = writer.ok_or("evidence retention needs evidence capture configured")?;
        let limit = match env::var("XSHIELD_EVIDENCE_RETENTION_BATCH_LIMIT") {
            Ok(value) => value.parse()?,
            Err(_) => RETENTION_BATCH_LIMIT_MAX,
        };
        if !(1..=RETENTION_BATCH_LIMIT_MAX).contains(&limit) {
            return Err("evidence retention batch limit must be 1 to 32".into());
        }
        let orphan_grace = match env::var("XSHIELD_EVIDENCE_ORPHAN_GRACE_SECONDS") {
            Ok(value) => Duration::from_secs(value.parse()?),
            Err(_) => DEFAULT_ORPHAN_GRACE,
        };
        if orphan_grace.is_zero() || orphan_grace > MAX_ORPHAN_GRACE {
            return Err("evidence orphan grace must be 1 second to 30 days".into());
        }
        let key_id = env::var("XSHIELD_EVIDENCE_KEY_ID")?;
        let key = Zeroizing::new(xshield_core::secret_env::var("XSHIELD_EVIDENCE_KEY_HEX")?);
        let vault = open_retention_vault(writer.root(), &key_id, &key)?;
        Ok(Some(Self {
            interval: Duration::from_secs(interval),
            limit,
            orphan_grace,
            key_id,
            vault,
            writer: Arc::clone(writer),
            tenant: tenant.clone(),
            site: site.clone(),
            database_url: Zeroizing::new(xshield_core::secret_env::var("XSHIELD_DATABASE_URL")?),
        }))
    }

    /// Starts the retention thread. It runs for the life of the process; a
    /// failed pass is counted and retried after the next interval.
    pub(crate) fn spawn(self, metrics: Arc<EdgeMetrics>) -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        thread::Builder::new()
            .name("evidence-retention".to_owned())
            .spawn(move || {
                runtime.block_on(async move {
                    let mut store = None;
                    loop {
                        tokio::time::sleep(self.interval).await;
                        match self.pass(&mut store).await {
                            Ok(report) => metrics.record_retention_pass(Ok(report.deleted_total())),
                            Err((reason, deleted)) => {
                                eprintln!("xshield evidence retention pass failed: {reason}");
                                metrics.record_retention_pass(Err((reason, deleted)));
                            }
                        }
                    }
                });
            })?;
        Ok(())
    }

    /// One pass, then a budget refresh whatever the pass's outcome, since a
    /// failed pass may still have deleted. The error carries what it deleted.
    async fn pass(
        &self,
        store: &mut Option<PostgresIdentityStore>,
    ) -> Result<RetentionPassReport, (&'static str, usize)> {
        let store = match store {
            Some(store) => store,
            None => store.insert(
                tokio::time::timeout(
                    CONNECT_DEADLINE,
                    PostgresIdentityStore::connect(&self.database_url, 1, Duration::from_secs(5)),
                )
                .await
                .map_err(|_| ("EVIDENCE_PURGE_TIMEOUT", 0))?
                .map_err(|_| ("EVIDENCE_PURGE_UNAVAILABLE", 0))?,
            ),
        };
        let report = run_retention_pass(
            store,
            &self.vault,
            &self.tenant,
            &self.site,
            &self.key_id,
            self.limit,
            self.orphan_grace,
        )
        .await;
        let refreshed = self.writer.refresh_budget();
        let report = report.map_err(|reason| (reason, 0))?;
        refreshed.map_err(|reason| (reason, report.deleted_total()))?;
        match report.failure() {
            Some(reason) => Err((reason, report.deleted_total())),
            None => Ok(report),
        }
    }
}
