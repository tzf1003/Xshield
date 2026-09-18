use clickhouse::Client;
use std::{collections::BTreeSet, env, error::Error, net::SocketAddr, path::PathBuf};
use xshield_audit::{JournalKey, JournalLimits, LocalJournal, SealVerifyingKey};
use xshield_control::{ControlConfig, ControlLimits, ControlPlane, ManagementCredential, router};
use xshield_core::{
    admin::{ManagementPrincipal, ManagementRole},
    domain::{SiteId, TenantId},
};
use xshield_worker::PublisherConfig;
use zeroize::Zeroizing;

const USAGE: &str = "usage: xshield-control JOURNAL_DIRECTORY MANIFEST_DIRECTORY CHECKPOINT_DIRECTORY CONTROL_AUDIT_DIRECTORY";

async fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let journal_directory = PathBuf::from(arguments.next().ok_or(USAGE)?);
    let manifest_directory = PathBuf::from(arguments.next().ok_or(USAGE)?);
    let checkpoint_directory = PathBuf::from(arguments.next().ok_or(USAGE)?);
    let control_audit_directory = PathBuf::from(arguments.next().ok_or(USAGE)?);
    if arguments.next().is_some() {
        return Err(USAGE.into());
    }

    let tenant_id = TenantId::parse(env::var("XSHIELD_TENANT_ID")?)?;
    let site_id = SiteId::parse(env::var("XSHIELD_SITE_ID")?)?;
    let subject = env::var("XSHIELD_CONTROL_SUBJECT")?;
    let roles = parse_roles(&env::var("XSHIELD_CONTROL_ROLES")?)?;
    let token = Zeroizing::new(env::var("XSHIELD_CONTROL_TOKEN")?);
    let source_key_id = env::var("XSHIELD_JOURNAL_KEY_ID")?;
    let source_key_hex = Zeroizing::new(env::var("XSHIELD_JOURNAL_KEY_HEX")?);
    let seal_key_id = env::var("XSHIELD_SEAL_KEY_ID")?;
    let seal_key_hex = Zeroizing::new(env::var("XSHIELD_SEAL_PUBLIC_KEY_HEX")?);
    let control_key_id = env::var("XSHIELD_CONTROL_AUDIT_KEY_ID")?;
    let control_key_hex = Zeroizing::new(env::var("XSHIELD_CONTROL_AUDIT_KEY_HEX")?);
    let target_id = env::var("XSHIELD_INDEX_TARGET_ID")?;
    let table = env::var("XSHIELD_CLICKHOUSE_TABLE").unwrap_or_else(|_| "audit_events".to_owned());
    let clickhouse_url = env::var("XSHIELD_CLICKHOUSE_URL")?;
    let clickhouse_database = env::var("XSHIELD_CLICKHOUSE_DATABASE")?;
    let clickhouse_user = env::var("XSHIELD_CLICKHOUSE_USER")?;
    let clickhouse_password = Zeroizing::new(env::var("XSHIELD_CLICKHOUSE_PASSWORD")?);
    let metadata_retention_days = env::var("XSHIELD_AUDIT_METADATA_RETENTION_DAYS")?.parse()?;
    let max_segment_bytes = env::var("XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES")?.parse()?;
    let token_issued_at = env::var("XSHIELD_CONTROL_TOKEN_ISSUED_AT")?.parse()?;
    let token_expires_at = env::var("XSHIELD_CONTROL_TOKEN_EXPIRES_AT")?.parse()?;
    let rate_limit = env::var("XSHIELD_CONTROL_REQUESTS_PER_MINUTE")?.parse()?;
    let max_query_events = env::var("XSHIELD_CONTROL_MAX_QUERY_EVENTS")?.parse()?;
    let listen: SocketAddr = env::var("XSHIELD_CONTROL_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:9443".to_owned())
        .parse()?;
    if !listen.ip().is_loopback() {
        return Err(
            "control listener must use a loopback address behind the management TLS boundary"
                .into(),
        );
    }

    let principal =
        ManagementPrincipal::new(subject, roles, [(tenant_id.clone(), site_id.clone())])?;
    let publisher = PublisherConfig::new(
        journal_directory,
        manifest_directory,
        checkpoint_directory,
        target_id,
        table,
        metadata_retention_days,
        max_segment_bytes,
    )?;
    let credential = ManagementCredential::new(&token, token_issued_at, token_expires_at)?;
    let control_limits = ControlLimits::new(rate_limit, max_query_events)?;
    let config = ControlConfig::new(
        credential,
        principal,
        tenant_id,
        site_id,
        publisher,
        source_key_id.clone(),
        control_limits,
    )?;
    let source_key = JournalKey::from_hex(&source_key_hex)?;
    let seal_key = SealVerifyingKey::from_hex(seal_key_id, &seal_key_hex)?;
    let control_key = JournalKey::from_hex(&control_key_hex)?;
    let journal_limits = JournalLimits::new(
        env::var("XSHIELD_CONTROL_AUDIT_MAX_BYTES")?.parse()?,
        env::var("XSHIELD_CONTROL_AUDIT_HIGH_WATERMARK_BYTES")?.parse()?,
        env::var("XSHIELD_CONTROL_AUDIT_SEGMENT_MAX_BYTES")?.parse()?,
    )?;
    let (access_journal, _) = LocalJournal::open(
        control_audit_directory,
        control_key_id,
        control_key,
        journal_limits,
    )?;
    let index = Client::default()
        .with_url(clickhouse_url)
        .with_database(clickhouse_database)
        .with_user(clickhouse_user)
        .with_password(&*clickhouse_password)
        .with_setting("readonly", "1");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(
        listener,
        router(ControlPlane::new(
            config,
            source_key,
            seal_key,
            index,
            access_journal,
        )),
    )
    .await?;
    Ok(())
}

fn parse_roles(value: &str) -> Result<BTreeSet<ManagementRole>, &'static str> {
    let mut roles = BTreeSet::new();
    for role in value.split(',') {
        let role = match role {
            "observer" => ManagementRole::Observer,
            "investigator" => ManagementRole::Investigator,
            "sensitive_evidence_reader" => ManagementRole::SensitiveEvidenceReader,
            "policy_author" => ManagementRole::PolicyAuthor,
            "policy_approver" => ManagementRole::PolicyApprover,
            "release_operator" => ManagementRole::ReleaseOperator,
            "audit_administrator" => ManagementRole::AuditAdministrator,
            "key_administrator" => ManagementRole::KeyAdministrator,
            "system_admin" => ManagementRole::SystemAdmin,
            _ => return Err("invalid XSHIELD_CONTROL_ROLES"),
        };
        roles.insert(role);
    }
    if roles.is_empty() {
        return Err("invalid XSHIELD_CONTROL_ROLES");
    }
    Ok(roles)
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("xshield control failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_roles;
    use xshield_core::admin::ManagementRole;

    #[test]
    fn roles_are_explicit_and_bounded() {
        let roles = parse_roles("observer,audit_administrator").unwrap();
        assert!(roles.contains(&ManagementRole::Observer));
        assert!(roles.contains(&ManagementRole::AuditAdministrator));
        assert!(parse_roles("observer,unknown").is_err());
        assert!(parse_roles("").is_err());
    }
}
