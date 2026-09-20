//! Publishes one bounded batch of a selected transactional outbox event family.

use clickhouse::Client;
use std::{env, error::Error, time::Duration};
use xshield_core::domain::{SiteId, TenantId};
use xshield_postgres::{OutboxLeaseConfig, OutboxScope, PostgresIdentityStore};
use xshield_worker::{
    OutboxPublisherConfig, publish_case_outbox_batch, publish_evidence_access_outbox_batch,
    publish_evidence_catalog_outbox_batch, publish_identity_outbox_batch,
    publish_response_grant_outbox_batch,
};
use zeroize::Zeroizing;

const USAGE: &str = "usage: xshield-outbox-worker TENANT_ID SITE_ID (XSHIELD_OUTBOX_FAMILY=case|evidence_catalog|evidence_access|identity|response_grant)";

async fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let tenant_id = TenantId::parse(
        arguments
            .next()
            .ok_or(USAGE)?
            .into_string()
            .map_err(|_| USAGE)?,
    )?;
    let site_id = SiteId::parse(
        arguments
            .next()
            .ok_or(USAGE)?
            .into_string()
            .map_err(|_| USAGE)?,
    )?;
    if arguments.next().is_some() {
        return Err(USAGE.into());
    }
    let family = match env::var("XSHIELD_OUTBOX_FAMILY") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => "case".to_owned(),
        Err(env::VarError::NotUnicode(_)) => return Err(USAGE.into()),
    };
    if !matches!(
        family.as_str(),
        "case" | "evidence_catalog" | "evidence_access" | "identity" | "response_grant"
    ) {
        return Err(USAGE.into());
    }

    let database_url = Zeroizing::new(env::var("XSHIELD_DATABASE_URL")?);
    let database_max_connections: u32 =
        env::var("XSHIELD_OUTBOX_DATABASE_MAX_CONNECTIONS")?.parse()?;
    let database_acquire_timeout =
        Duration::from_millis(env::var("XSHIELD_OUTBOX_DATABASE_ACQUIRE_TIMEOUT_MS")?.parse()?);
    let clickhouse_url = env::var("XSHIELD_CLICKHOUSE_URL")?;
    let clickhouse_database = env::var("XSHIELD_CLICKHOUSE_DATABASE")?;
    let clickhouse_user = env::var("XSHIELD_CLICKHOUSE_USER")?;
    let clickhouse_password = Zeroizing::new(env::var("XSHIELD_CLICKHOUSE_PASSWORD")?);
    let table = env::var("XSHIELD_CLICKHOUSE_TABLE").unwrap_or_else(|_| "audit_events".to_owned());
    let retention_days: u16 = env::var("XSHIELD_AUDIT_METADATA_RETENTION_DAYS")?.parse()?;
    let max_events: u32 = env::var("XSHIELD_OUTBOX_MAX_EVENTS")?.parse()?;
    let max_bytes: u64 = env::var("XSHIELD_OUTBOX_MAX_BYTES")?.parse()?;
    let lease_seconds: u64 = env::var("XSHIELD_OUTBOX_LEASE_SECONDS")?.parse()?;
    let retry_seconds: u64 = env::var("XSHIELD_OUTBOX_RETRY_SECONDS")?.parse()?;

    let lease = OutboxLeaseConfig::new(max_events, max_bytes, Duration::from_secs(lease_seconds))?;
    let config = OutboxPublisherConfig::new(
        table,
        retention_days,
        lease,
        Duration::from_secs(retry_seconds),
    )?;
    let store = PostgresIdentityStore::connect(
        database_url.as_str(),
        database_max_connections,
        database_acquire_timeout,
    )
    .await?;
    let client = Client::default()
        .with_url(clickhouse_url)
        .with_database(clickhouse_database)
        .with_user(clickhouse_user)
        .with_password(clickhouse_password.as_str())
        .with_setting("max_execution_time", "30")
        .with_product_info("xshield-outbox-worker", env!("CARGO_PKG_VERSION"));
    let scope = OutboxScope::new(&tenant_id, &site_id);
    let report = match family.as_str() {
        "case" => publish_case_outbox_batch(&store, &client, &scope, &config).await?,
        "evidence_catalog" => {
            publish_evidence_catalog_outbox_batch(&store, &client, &scope, &config).await?
        }
        "evidence_access" => {
            publish_evidence_access_outbox_batch(&store, &client, &scope, &config).await?
        }
        "identity" => publish_identity_outbox_batch(&store, &client, &scope, &config).await?,
        "response_grant" => {
            publish_response_grant_outbox_batch(&store, &client, &scope, &config).await?
        }
        _ => return Err(USAGE.into()),
    };
    println!(
        "family={} claimed={} published={} table={}",
        family,
        report.claimed,
        report.published,
        config.table(),
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("xshield outbox publication failed: {error}; {USAGE}");
        std::process::exit(1);
    }
}
