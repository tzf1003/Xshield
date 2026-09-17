use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use pingora::{Result as PingoraResult, http::RequestHeader};
use std::{collections::BTreeMap, env, fmt, time::Duration};
use xshield_core::{
    admission::{AdmissionClass, AdmissionProof},
    audit::ReasonCode,
    domain::WafSessionId,
    identity::{CredentialFingerprint, CredentialSlot, IdentityDenied, UnixSeconds},
    ports::{IdentityProofQuery, IdentityProofState, IdentityProofStore},
};
use xshield_gateway::{GatewayConfig, GatewayDecision, GatewayOutcome, IdentityStoreConfig};
use xshield_postgres::{PostgresIdentityStore, StoreError};
use zeroize::Zeroizing;

const WAF_COOKIE: &str = "__Host-xshield_sid";
const MAX_SESSION_BYTES: usize = 256;
const MAX_BEARER_BYTES: usize = 8192;

pub(crate) fn strip_waf_cookie(request: &mut RequestHeader) -> PingoraResult<()> {
    let mut retained = Vec::new();
    let mut valid_ascii = true;
    for value in request.headers.get_all("cookie") {
        let Ok(value) = value.to_str() else {
            valid_ascii = false;
            break;
        };
        retained.extend(value.split(';').filter_map(|pair| {
            let pair = pair.trim();
            let name = pair.split_once('=').map(|(name, _)| name.trim());
            (!pair.is_empty() && name != Some(WAF_COOKIE)).then(|| pair.to_owned())
        }));
    }
    request.remove_header("cookie");
    if valid_ascii && !retained.is_empty() {
        request.insert_header("Cookie", retained.join("; "))?;
    }
    Ok(())
}

pub(crate) struct ProtectedIdentity {
    database_url: Zeroizing<String>,
    max_connections: u32,
    acquire_timeout: Duration,
    store: tokio::sync::OnceCell<PostgresIdentityStore>,
    fingerprint_key: Zeroizing<[u8; 32]>,
}

impl ProtectedIdentity {
    pub(crate) fn from_env(config: IdentityStoreConfig) -> Result<Self, IdentityRuntimeError> {
        let database_url = Zeroizing::new(env::var("XSHIELD_DATABASE_URL")?);
        let key_hex = Zeroizing::new(env::var("XSHIELD_FINGERPRINT_KEY_HEX")?);
        Ok(Self {
            database_url,
            max_connections: config.max_connections(),
            acquire_timeout: Duration::from_millis(config.acquire_timeout_ms()),
            store: tokio::sync::OnceCell::new(),
            fingerprint_key: Zeroizing::new(parse_key(&key_hex)?),
        })
    }

    pub(crate) async fn admit(
        &self,
        config: &GatewayConfig,
        request: &RequestHeader,
        method: &str,
        path: &str,
        now: UnixSeconds,
    ) -> Result<GatewayDecision, IdentityRuntimeError> {
        if config.admission_class(method, path) != Some(AdmissionClass::AuthenticatedRoot) {
            return Ok(config.admit(method, path, now));
        }
        let presented = match PresentedIdentity::parse(request, &self.fingerprint_key) {
            Ok(presented) => presented,
            Err(IdentityRuntimeError::Missing) => {
                return Ok(denied(
                    config,
                    method,
                    path,
                    now,
                    IdentityDenied::AuthRequired,
                ));
            }
            Err(IdentityRuntimeError::Malformed) => {
                return Ok(denied(
                    config,
                    method,
                    path,
                    now,
                    IdentityDenied::BindingMismatch,
                ));
            }
            Err(error) => return Err(error),
        };
        let store = self
            .store
            .get_or_try_init(|| async {
                PostgresIdentityStore::connect(
                    &self.database_url,
                    self.max_connections,
                    self.acquire_timeout,
                )
                .await
            })
            .await?;
        let state = store
            .load_identity(IdentityProofQuery {
                tenant_id: config.tenant_id(),
                site_id: config.site_id(),
                session_id: &presented.session_id,
                session_fingerprint: &presented.session_fingerprint,
                credentials: &presented.credentials,
                now,
            })
            .await?;
        Ok(match state {
            IdentityProofState::Verified { binding, snapshot } => config.admit_with_proof(
                method,
                path,
                now,
                AdmissionProof::Authenticated {
                    binding: &binding,
                    snapshot: &snapshot,
                },
            ),
            IdentityProofState::Denied(error) => denied(config, method, path, now, error),
        })
    }
}

fn denied(
    config: &GatewayConfig,
    method: &str,
    path: &str,
    now: UnixSeconds,
    error: IdentityDenied,
) -> GatewayDecision {
    let mut decision = config.admit(method, path, now);
    decision.outcome = GatewayOutcome::Denied;
    decision.reason_code = error.reason_code();
    decision
}

struct PresentedIdentity {
    session_id: WafSessionId,
    session_fingerprint: [u8; 32],
    credentials: BTreeMap<CredentialSlot, CredentialFingerprint>,
}

impl PresentedIdentity {
    fn parse(request: &RequestHeader, key: &[u8; 32]) -> Result<Self, IdentityRuntimeError> {
        let session = unique_cookie(request, WAF_COOKIE)?;
        if session.len() > MAX_SESSION_BYTES {
            return Err(IdentityRuntimeError::Malformed);
        }
        let session_id =
            WafSessionId::parse(session).map_err(|_| IdentityRuntimeError::Malformed)?;
        let bearer = unique_bearer(request)?;
        let session_fingerprint = fingerprint(key, session_id.as_str().as_bytes())?;
        let credential = CredentialFingerprint::from_bytes(fingerprint(key, bearer.as_bytes())?);
        Ok(Self {
            session_id,
            session_fingerprint,
            credentials: BTreeMap::from([(CredentialSlot::Bearer, credential)]),
        })
    }
}

fn unique_cookie<'a>(
    request: &'a RequestHeader,
    wanted: &str,
) -> Result<&'a str, IdentityRuntimeError> {
    let mut found = None;
    for value in request.headers.get_all("cookie") {
        let value = value
            .to_str()
            .map_err(|_| IdentityRuntimeError::Malformed)?;
        for pair in value.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                return Err(IdentityRuntimeError::Malformed);
            };
            if name == wanted && (found.replace(value).is_some() || value.is_empty()) {
                return Err(IdentityRuntimeError::Malformed);
            }
        }
    }
    found.ok_or(IdentityRuntimeError::Missing)
}

fn unique_bearer(request: &RequestHeader) -> Result<&str, IdentityRuntimeError> {
    let mut values = request.headers.get_all("authorization").iter();
    let value = values.next().ok_or(IdentityRuntimeError::Missing)?;
    if values.next().is_some() {
        return Err(IdentityRuntimeError::Malformed);
    }
    let value = value
        .to_str()
        .map_err(|_| IdentityRuntimeError::Malformed)?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty() && token.len() <= MAX_BEARER_BYTES)
        .ok_or(IdentityRuntimeError::Malformed)?;
    Ok(token)
}

fn fingerprint(key: &[u8; 32], value: &[u8]) -> Result<[u8; 32], IdentityRuntimeError> {
    let key = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(value)?;
    signer
        .sign_to_vec()?
        .try_into()
        .map_err(|_| IdentityRuntimeError::Crypto)
}

fn parse_key(value: &str) -> Result<[u8; 32], IdentityRuntimeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(IdentityRuntimeError::InvalidKey);
    }
    let mut key = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        key[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(key)
}

const fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

#[derive(Debug)]
pub(crate) enum IdentityRuntimeError {
    Missing,
    Malformed,
    InvalidKey,
    Crypto,
    Environment(env::VarError),
    OpenSsl(openssl::error::ErrorStack),
    Store(StoreError),
}

impl From<env::VarError> for IdentityRuntimeError {
    fn from(value: env::VarError) -> Self {
        Self::Environment(value)
    }
}

impl From<openssl::error::ErrorStack> for IdentityRuntimeError {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::OpenSsl(value)
    }
}

impl From<StoreError> for IdentityRuntimeError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl fmt::Display for IdentityRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("required identity input missing"),
            Self::Malformed => formatter.write_str("identity input malformed"),
            Self::InvalidKey => formatter.write_str("invalid fingerprint key"),
            Self::Crypto | Self::OpenSsl(_) => formatter.write_str("credential fingerprint failed"),
            Self::Environment(_) => formatter.write_str("identity environment unavailable"),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for IdentityRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Environment(error) => Some(error),
            Self::OpenSsl(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Missing | Self::Malformed | Self::InvalidKey | Self::Crypto => None,
        }
    }
}

pub(crate) const fn store_failure_reason() -> ReasonCode {
    ReasonCode::IdentityStoreUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const SESSION: &str = "ses_018f2a3b-4c5d-7000-8000-000000000902";

    fn request() -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/account", Some(2)).unwrap();
        request
            .insert_header("Cookie", format!("theme=dark; {WAF_COOKIE}={SESSION}"))
            .unwrap();
        request
            .insert_header("Authorization", "Bearer business-token")
            .unwrap();
        request
    }

    #[test]
    fn parses_exact_session_and_bearer_combination() {
        let identity = PresentedIdentity::parse(&request(), &KEY).unwrap();
        assert_eq!(identity.session_id.as_str(), SESSION);
        assert_eq!(identity.credentials.len(), 1);
        assert!(identity.credentials.contains_key(&CredentialSlot::Bearer));
    }

    #[test]
    fn rejects_duplicate_session_cookie() {
        let mut request = request();
        request
            .append_header("Cookie", format!("{WAF_COOKIE}={SESSION}"))
            .unwrap();
        assert!(matches!(
            PresentedIdentity::parse(&request, &KEY),
            Err(IdentityRuntimeError::Malformed)
        ));
    }

    #[test]
    fn strips_only_the_edge_session_cookie_before_origin() {
        let mut request = request();
        strip_waf_cookie(&mut request).unwrap();
        assert_eq!(
            request.headers.get("cookie").unwrap().to_str().unwrap(),
            "theme=dark"
        );
    }
}
