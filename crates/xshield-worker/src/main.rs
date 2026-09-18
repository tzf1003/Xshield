use clickhouse::Client;
use std::{env, error::Error, path::PathBuf};
use xshield_audit::{JournalKey, SealVerifyingKey};
use xshield_worker::{PublisherConfig, publish_sealed_segments};
use zeroize::Zeroizing;

const USAGE: &str =
    "usage: xshield-worker JOURNAL_DIRECTORY MANIFEST_DIRECTORY CHECKPOINT_DIRECTORY";

async fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let journal_directory = PathBuf::from(arguments.next().ok_or(USAGE)?);
    let manifest_directory = PathBuf::from(arguments.next().ok_or(USAGE)?);
    let checkpoint_directory = PathBuf::from(arguments.next().ok_or(USAGE)?);
    if arguments.next().is_some() {
        return Err(USAGE.into());
    }

    let journal_key_id = env::var("XSHIELD_JOURNAL_KEY_ID")?;
    let journal_key_hex = Zeroizing::new(env::var("XSHIELD_JOURNAL_KEY_HEX")?);
    let seal_key_id = env::var("XSHIELD_SEAL_KEY_ID")?;
    let seal_public_key_hex = Zeroizing::new(env::var("XSHIELD_SEAL_PUBLIC_KEY_HEX")?);
    let url = env::var("XSHIELD_CLICKHOUSE_URL")?;
    let database = env::var("XSHIELD_CLICKHOUSE_DATABASE")?;
    let user = env::var("XSHIELD_CLICKHOUSE_USER")?;
    let password = Zeroizing::new(env::var("XSHIELD_CLICKHOUSE_PASSWORD")?);
    let target_id = env::var("XSHIELD_INDEX_TARGET_ID")?;
    let table = env::var("XSHIELD_CLICKHOUSE_TABLE").unwrap_or_else(|_| "audit_events".to_owned());
    let metadata_retention_days = env::var("XSHIELD_AUDIT_METADATA_RETENTION_DAYS")?.parse()?;
    let max_segment_bytes = env::var("XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES")?.parse()?;

    let config = PublisherConfig::new(
        journal_directory,
        manifest_directory,
        checkpoint_directory,
        target_id,
        table,
        metadata_retention_days,
        max_segment_bytes,
    )?;
    let journal_key = JournalKey::from_hex(&journal_key_hex)?;
    let seal_key = SealVerifyingKey::from_hex(seal_key_id, &seal_public_key_hex)?;
    let client = Client::default()
        .with_url(url)
        .with_database(database)
        .with_user(user)
        .with_password(password.as_str())
        .with_setting("max_execution_time", "15")
        .with_product_info("xshield-worker", env!("CARGO_PKG_VERSION"));
    let report =
        publish_sealed_segments(&config, &client, &journal_key_id, &journal_key, &seal_key).await?;
    println!(
        "published_segments={} published_events={} checkpointed_segments={} watermark_boot={} watermark_sequence={}",
        report.published_segments,
        report.published_events,
        report.checkpointed_segments,
        report
            .watermark_producer_boot_id
            .as_deref()
            .unwrap_or("none"),
        report.watermark_producer_sequence,
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("xshield audit publication failed: {error}");
        std::process::exit(1);
    }
}
