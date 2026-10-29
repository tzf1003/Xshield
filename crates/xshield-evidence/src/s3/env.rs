//! Operator configuration of the S3 backend, shared by every binary that
//! opens the evidence vault (docs/19, "Evidence storage backend").

use super::{
    S3Addressing, S3Credentials, S3EvidenceStoreConfig, S3EvidenceStoreSettings, S3ObjectLockMode,
};
use std::{env, error::Error, time::Duration};
use xshield_core::secret_env;
use zeroize::Zeroizing;

type EnvResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;

impl S3EvidenceStoreConfig {
    /// Reads the evidence backend from the environment: `None` when
    /// `XSHIELD_EVIDENCE_BACKEND` is unset or `local`, the validated bucket
    /// settings when it is `s3`.
    ///
    /// The secret access key and session token may be given inline or as a
    /// `_FILE` path, like every other secret.
    ///
    /// # Errors
    /// Names the missing or invalid variable, never its value.
    pub fn from_env() -> EnvResult<Option<Self>> {
        match env::var("XSHIELD_EVIDENCE_BACKEND").ok().as_deref() {
            None | Some("local") => return Ok(None),
            Some("s3") => {}
            Some(_) => return Err("XSHIELD_EVIDENCE_BACKEND must be local or s3".into()),
        }
        let required = |name: &'static str| {
            env::var(name).map_err(|_| -> Box<dyn Error + Send + Sync> {
                format!("{name} is required for the s3 evidence backend").into()
            })
        };
        let endpoint = required("XSHIELD_EVIDENCE_S3_ENDPOINT")?;
        let region = required("XSHIELD_EVIDENCE_S3_REGION")?;
        let bucket = required("XSHIELD_EVIDENCE_S3_BUCKET")?;
        let prefix = env::var("XSHIELD_EVIDENCE_S3_PREFIX").unwrap_or_default();
        let addressing =
            parse_addressing(env::var("XSHIELD_EVIDENCE_S3_ADDRESSING").ok().as_deref())?;
        let object_lock = parse_object_lock(&required("XSHIELD_EVIDENCE_S3_OBJECT_LOCK")?)?;
        let allow_plain_http = parse_flag(
            env::var("XSHIELD_EVIDENCE_S3_ALLOW_PLAIN_HTTP")
                .ok()
                .as_deref(),
        )?;
        let request_timeout = match env::var("XSHIELD_EVIDENCE_S3_REQUEST_TIMEOUT_SECONDS") {
            Ok(value) => Duration::from_secs(value.parse().map_err(
                |_| "XSHIELD_EVIDENCE_S3_REQUEST_TIMEOUT_SECONDS must be whole seconds",
            )?),
            Err(_) => Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECONDS),
        };
        let credentials = S3Credentials::new(
            secret_env::var("XSHIELD_EVIDENCE_S3_ACCESS_KEY_ID")?,
            Zeroizing::new(secret_env::var("XSHIELD_EVIDENCE_S3_SECRET_ACCESS_KEY")?),
            secret_env::var_opt("XSHIELD_EVIDENCE_S3_SESSION_TOKEN")?.map(Zeroizing::new),
        )
        .map_err(|_| "invalid XSHIELD_EVIDENCE_S3_* credentials")?;
        Self::new(S3EvidenceStoreSettings {
            endpoint: &endpoint,
            region: &region,
            bucket: &bucket,
            prefix: &prefix,
            addressing,
            credentials,
            object_lock,
            allow_plain_http,
            request_timeout,
        })
        .map(Some)
        .map_err(|_| {
            "invalid XSHIELD_EVIDENCE_S3_* settings (endpoint, region, bucket, prefix or timeout)"
                .into()
        })
    }
}

fn parse_addressing(value: Option<&str>) -> EnvResult<S3Addressing> {
    match value {
        None | Some("path") => Ok(S3Addressing::Path),
        Some("virtual-hosted") => Ok(S3Addressing::VirtualHosted),
        Some(_) => Err("XSHIELD_EVIDENCE_S3_ADDRESSING must be path or virtual-hosted".into()),
    }
}

fn parse_object_lock(value: &str) -> EnvResult<Option<S3ObjectLockMode>> {
    match value {
        "compliance" => Ok(Some(S3ObjectLockMode::Compliance)),
        "governance" => Ok(Some(S3ObjectLockMode::Governance)),
        "off" => Ok(None),
        _ => Err("XSHIELD_EVIDENCE_S3_OBJECT_LOCK must be compliance, governance or off".into()),
    }
}

fn parse_flag(value: Option<&str>) -> EnvResult<bool> {
    match value {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err("XSHIELD_EVIDENCE_S3_ALLOW_PLAIN_HTTP must be true or false".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_operator_choices_strictly() {
        assert_eq!(parse_addressing(None).unwrap(), S3Addressing::Path);
        assert_eq!(
            parse_addressing(Some("virtual-hosted")).unwrap(),
            S3Addressing::VirtualHosted
        );
        assert!(parse_addressing(Some("virtual")).is_err());
        assert_eq!(
            parse_object_lock("compliance").unwrap(),
            Some(S3ObjectLockMode::Compliance)
        );
        assert_eq!(
            parse_object_lock("governance").unwrap(),
            Some(S3ObjectLockMode::Governance)
        );
        assert_eq!(parse_object_lock("off").unwrap(), None);
        assert!(parse_object_lock("").is_err());
        assert!(parse_object_lock("COMPLIANCE").is_err());
        assert!(!parse_flag(None).unwrap());
        assert!(parse_flag(Some("true")).unwrap());
        assert!(parse_flag(Some("1")).is_err());
    }
}
