use clickhouse::Client;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};
use xshield_audit::{JournalKey, JournalLimits, LocalJournal, SealVerifyingKey};
use xshield_control::{
    ControlConfig, ControlLimits, ControlPlane, CursorKey, EvidenceReadPort, IdempotencyKey,
    ManagementCredential, OidcProvider, router,
};
use xshield_core::{
    admin::{ManagementPrincipal, ManagementRole},
    domain::{SiteId, TenantId},
};
use xshield_evidence::{EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault};
use xshield_postgres::PostgresIdentityStore;
use xshield_worker::PublisherConfig;
use zeroize::Zeroizing;

const USAGE: &str = "usage: xshield-control JOURNAL_DIRECTORY MANIFEST_DIRECTORY CHECKPOINT_DIRECTORY CONTROL_AUDIT_DIRECTORY";

#[allow(clippy::too_many_lines)]
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
    let oidc_issuer = env::var("XSHIELD_CONTROL_OIDC_ISSUER")?;
    let oidc_client_id = env::var("XSHIELD_CONTROL_OIDC_CLIENT_ID")?;
    let oidc_client_secret = Zeroizing::new(env::var("XSHIELD_CONTROL_OIDC_CLIENT_SECRET")?);
    let console_origin = env::var("XSHIELD_CONTROL_CONSOLE_ORIGIN")?;
    let required_acr = env::var("XSHIELD_CONTROL_OIDC_REQUIRED_ACR")?;
    let oidc_subject_roles =
        parse_oidc_subject_roles(&env::var("XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON")?)?;
    let token = Zeroizing::new(env::var("XSHIELD_CONTROL_TOKEN")?);
    let cursor_key_hex = Zeroizing::new(env::var("XSHIELD_CONTROL_CURSOR_KEY_HEX")?);
    let idempotency_key_hex = Zeroizing::new(env::var("XSHIELD_CONTROL_IDEMPOTENCY_KEY_HEX")?);
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
    let database_url = Zeroizing::new(env::var("XSHIELD_DATABASE_URL")?);
    let database_max_connections = env::var("XSHIELD_CONTROL_DATABASE_MAX_CONNECTIONS")?.parse()?;
    let database_acquire_timeout =
        Duration::from_millis(env::var("XSHIELD_CONTROL_DATABASE_ACQUIRE_TIMEOUT_MS")?.parse()?);
    let metadata_retention_days = env::var("XSHIELD_AUDIT_METADATA_RETENTION_DAYS")?.parse()?;
    let max_segment_bytes = env::var("XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES")?.parse()?;
    let token_issued_at = env::var("XSHIELD_CONTROL_TOKEN_ISSUED_AT")?.parse()?;
    let token_expires_at = env::var("XSHIELD_CONTROL_TOKEN_EXPIRES_AT")?.parse()?;
    let rate_limit = env::var("XSHIELD_CONTROL_REQUESTS_PER_MINUTE")?.parse()?;
    let max_query_events = env::var("XSHIELD_CONTROL_MAX_QUERY_EVENTS")?.parse()?;
    let max_query_artifacts = env::var("XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS")?.parse()?;
    let max_open_cases = env::var("XSHIELD_CONTROL_MAX_OPEN_CASES")?.parse()?;
    let max_pending_evidence_access_requests =
        env::var("XSHIELD_CONTROL_MAX_PENDING_EVIDENCE_ACCESS_REQUESTS")?.parse()?;
    let max_evidence_access_ttl_seconds =
        env::var("XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS")?.parse()?;
    let evidence_root = PathBuf::from(env::var("XSHIELD_EVIDENCE_ROOT")?);
    let evidence_key_id = env::var("XSHIELD_EVIDENCE_KEY_ID")?;
    let evidence_key_hex = Zeroizing::new(env::var("XSHIELD_EVIDENCE_KEY_HEX")?);
    let evidence_max_artifact_bytes = env::var("XSHIELD_EVIDENCE_MAX_ARTIFACT_BYTES")?.parse()?;
    let evidence_max_retention_days = env::var("XSHIELD_EVIDENCE_MAX_RETENTION_DAYS")?.parse()?;
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
    let cursor_key = CursorKey::from_hex(&cursor_key_hex)?;
    let idempotency_key = IdempotencyKey::from_hex(&idempotency_key_hex)?;
    let control_limits = ControlLimits::new(
        rate_limit,
        max_query_events,
        max_query_artifacts,
        max_open_cases,
        max_pending_evidence_access_requests,
        max_evidence_access_ttl_seconds,
    )?;
    let config = ControlConfig::new(
        credential,
        cursor_key,
        idempotency_key,
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
    let evidence_vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(
            evidence_root,
            evidence_key_id,
            evidence_max_artifact_bytes,
            evidence_max_retention_days,
        )?,
        EvidenceKey::from_hex(&evidence_key_hex)?,
    )?;
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
    let catalog = PostgresIdentityStore::connect(
        &database_url,
        database_max_connections,
        database_acquire_timeout,
    )
    .await?;
    let oidc_provider = OidcProvider::discover(
        &oidc_issuer,
        &oidc_client_id,
        &oidc_client_secret,
        &console_origin,
        &required_acr,
        oidc_subject_roles,
    )
    .await?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(
        listener,
        router(
            ControlPlane::new(config, source_key, seal_key, index, catalog, access_journal)
                .with_evidence_read_port(EvidenceReadPort::new(evidence_vault))
                .with_oidc_provider(oidc_provider)?,
        ),
    )
    .await?;
    Ok(())
}

fn parse_roles(value: &str) -> Result<BTreeSet<ManagementRole>, &'static str> {
    let mut roles = BTreeSet::new();
    for role in value.split(',') {
        let role = parse_role(role).ok_or("invalid XSHIELD_CONTROL_ROLES")?;
        roles.insert(role);
    }
    if roles.is_empty() {
        return Err("invalid XSHIELD_CONTROL_ROLES");
    }
    Ok(roles)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcSubjectRoleEntry {
    subject: String,
    roles: Vec<String>,
}

fn parse_oidc_subject_roles(
    value: &str,
) -> Result<BTreeMap<String, BTreeSet<ManagementRole>>, &'static str> {
    let entries: Vec<OidcSubjectRoleEntry> = serde_json::from_str(value)
        .map_err(|_| "invalid XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON")?;
    if entries.is_empty() {
        return Err("invalid XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON");
    }
    let mut mappings = BTreeMap::new();
    for entry in entries {
        if entry.roles.is_empty() {
            return Err("invalid XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON");
        }
        let mut roles = BTreeSet::new();
        for name in entry.roles {
            let role =
                parse_role(&name).ok_or("invalid XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON")?;
            if !roles.insert(role) {
                return Err("invalid XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON");
            }
        }
        if mappings.insert(entry.subject, roles).is_some() {
            return Err("invalid XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON");
        }
    }
    Ok(mappings)
}

fn parse_role(value: &str) -> Option<ManagementRole> {
    Some(match value {
        "observer" => ManagementRole::Observer,
        "investigator" => ManagementRole::Investigator,
        "sensitive_evidence_reader" => ManagementRole::SensitiveEvidenceReader,
        "sensitive_evidence_approver" => ManagementRole::SensitiveEvidenceApprover,
        "policy_author" => ManagementRole::PolicyAuthor,
        "policy_approver" => ManagementRole::PolicyApprover,
        "release_operator" => ManagementRole::ReleaseOperator,
        "audit_administrator" => ManagementRole::AuditAdministrator,
        "key_administrator" => ManagementRole::KeyAdministrator,
        "system_admin" => ManagementRole::SystemAdmin,
        _ => return None,
    })
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
    use super::{parse_oidc_subject_roles, parse_roles};
    use xshield_core::admin::ManagementRole;

    #[test]
    fn roles_are_explicit_and_bounded() {
        let roles =
            parse_roles("observer,audit_administrator,sensitive_evidence_approver").unwrap();
        assert!(roles.contains(&ManagementRole::Observer));
        assert!(roles.contains(&ManagementRole::AuditAdministrator));
        assert!(roles.contains(&ManagementRole::SensitiveEvidenceApprover));
        assert!(parse_roles("observer,unknown").is_err());
        assert!(parse_roles("").is_err());
    }

    #[test]
    fn oidc_roles_are_exact_subject_mappings_without_duplicates() {
        let mappings = parse_oidc_subject_roles(
            r#"[{"subject":"oidc-sub-1","roles":["observer","investigator"]}]"#,
        )
        .unwrap();
        assert_eq!(mappings.len(), 1);
        assert!(mappings["oidc-sub-1"].contains(&ManagementRole::Observer));
        assert!(
            parse_oidc_subject_roles(
                r#"[{"subject":"a","roles":["observer"]},{"subject":"a","roles":["investigator"]}]"#
            )
            .is_err()
        );
        assert!(
            parse_oidc_subject_roles(r#"[{"subject":"a","roles":["observer","observer"]}]"#)
                .is_err()
        );
        assert!(
            parse_oidc_subject_roles(r#"[{"subject":"a","roles":["system_admin","admin"]}]"#)
                .is_err()
        );
    }
}
