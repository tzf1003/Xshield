use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use pingora::{Result as PingoraResult, http::RequestHeader};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    time::Duration,
};
use xshield_core::{
    access::ServiceCredentialFingerprint,
    admission::{AdmissionClass, AdmissionProof},
    audit::ReasonCode,
    domain::{ActionRef, FieldName, ResourceType, WafSessionId},
    grant::ResourceKeyHmac,
    identity::{
        AuthBinding, AuthSnapshot, CredentialFingerprint, CredentialSlot, IdentityDenied,
        UnixSeconds,
    },
    ports::{
        IdentityProofQuery, IdentityProofState, IdentityProofStore, ResourceProofQuery,
        ResourceProofState, ResourceProofStore, ServiceIdentityProofQuery,
        ServiceIdentityProofState, ServiceIdentityProofStore, UiActionProofQuery,
        UiActionProofState, UiActionProofStore,
    },
    provenance::ActionTarget,
};
use xshield_gateway::{
    GatewayConfig, GatewayDecision, GatewayOutcome, IdentityStoreConfig, ResourceOperation,
};
use xshield_postgres::{PostgresIdentityStore, StoreError};
use zeroize::Zeroizing;

mod share_entry;

const WAF_COOKIE: &str = "__Host-xshield_sid";
const ACTION_HEADER: &str = "x-xshield-action-ref";
const SERVICE_CREDENTIAL_HEADER: &str = "x-xshield-service-credential";
const MAX_SESSION_BYTES: usize = 256;
const MAX_BEARER_BYTES: usize = 8192;
const MAX_QUERY_BYTES: usize = 8192;
const MAX_QUERY_PARAMETERS: usize = 64;
const MAX_QUERY_COMPONENT_BYTES: usize = 4096;
const MAX_RESOURCE_BYTES: usize = 512;

pub(crate) fn strip_edge_proofs(request: &mut RequestHeader) -> PingoraResult<()> {
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
    request.remove_header(ACTION_HEADER);
    request.remove_header(SERVICE_CREDENTIAL_HEADER);
    request.remove_header(share_entry::SHARE_TOKEN_HEADER);
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

    async fn store(&self) -> Result<&PostgresIdentityStore, IdentityRuntimeError> {
        self.store
            .get_or_try_init(|| async {
                PostgresIdentityStore::connect(
                    &self.database_url,
                    self.max_connections,
                    self.acquire_timeout,
                )
                .await
            })
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn admit(
        &self,
        config: &GatewayConfig,
        request: &RequestHeader,
        method: &str,
        path: &str,
        now: UnixSeconds,
    ) -> Result<GatewayDecision, IdentityRuntimeError> {
        let class = config.admission_class(method, path);
        if class == Some(AdmissionClass::ServiceIdentity) {
            return self
                .admit_service_identity(config, request, method, path, now)
                .await;
        }
        if class == Some(AdmissionClass::ShareEntry) {
            return self
                .admit_share_entry(config, request, method, path, now)
                .await;
        }
        if !matches!(
            class,
            Some(AdmissionClass::AuthenticatedRoot | AdmissionClass::UiActionRequired)
        ) {
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
        let store = self.store().await?;
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
            IdentityProofState::Verified { binding, snapshot } => match class {
                Some(AdmissionClass::AuthenticatedRoot) => config.admit_with_proof(
                    method,
                    path,
                    now,
                    AdmissionProof::Authenticated {
                        binding: &binding,
                        snapshot: &snapshot,
                    },
                ),
                Some(AdmissionClass::UiActionRequired) => {
                    self.admit_ui_action(
                        config, store, request, method, path, now, &binding, &snapshot,
                    )
                    .await?
                }
                _ => config.admit(method, path, now),
            },
            IdentityProofState::Denied(error) => denied(config, method, path, now, error),
        })
    }

    async fn admit_service_identity(
        &self,
        config: &GatewayConfig,
        request: &RequestHeader,
        method: &str,
        path: &str,
        now: UnixSeconds,
    ) -> Result<GatewayDecision, IdentityRuntimeError> {
        let credential = match service_credential(request, &self.fingerprint_key, config) {
            Ok(credential) => credential,
            Err(IdentityRuntimeError::Missing | IdentityRuntimeError::Malformed) => {
                return Ok(denied_reason(
                    config,
                    method,
                    path,
                    now,
                    ReasonCode::ServiceIdentityMismatch,
                ));
            }
            Err(error) => return Err(error),
        };
        let state = self
            .store()
            .await?
            .load_service_identity(ServiceIdentityProofQuery {
                tenant_id: config.tenant_id(),
                site_id: config.site_id(),
                credential_fingerprint: &credential,
                now,
            })
            .await?;
        Ok(match state {
            ServiceIdentityProofState::Verified(identity) => config.admit_with_proof(
                method,
                path,
                now,
                AdmissionProof::Service {
                    identity: &identity,
                    credential_fingerprint: &credential,
                },
            ),
            ServiceIdentityProofState::Denied(error) => {
                denied_reason(config, method, path, now, error.reason_code())
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn admit_ui_action(
        &self,
        config: &GatewayConfig,
        store: &PostgresIdentityStore,
        request: &RequestHeader,
        method: &str,
        path: &str,
        now: UnixSeconds,
        binding: &AuthBinding,
        snapshot: &AuthSnapshot,
    ) -> Result<GatewayDecision, IdentityRuntimeError> {
        let action_ref = match unique_action_ref(request) {
            Ok(action_ref) => action_ref,
            Err(IdentityRuntimeError::Missing | IdentityRuntimeError::Malformed) => {
                return Ok(config.admit(method, path, now));
            }
            Err(error) => return Err(error),
        };
        let UiActionProofState::Verified(action) = store
            .load_ui_action(UiActionProofQuery {
                binding,
                snapshot,
                action_ref: &action_ref,
                policy_revision: config.policy_revision(),
                now,
            })
            .await?
        else {
            return Ok(denied_reason(
                config,
                method,
                path,
                now,
                ReasonCode::UiActionNotAvailable,
            ));
        };
        let Some(operation) = config.resource_operation(method, path) else {
            if request.uri.query().is_some() {
                return Ok(denied_reason(
                    config,
                    method,
                    path,
                    now,
                    ReasonCode::FieldNotAllowed,
                ));
            }
            return Ok(config.admit_with_proof(
                method,
                path,
                now,
                AdmissionProof::UiAction {
                    binding,
                    snapshot,
                    action: &action,
                    grants: None,
                },
            ));
        };
        self.admit_resource_action(
            config, store, request, method, path, now, binding, snapshot, &action, operation,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn admit_resource_action(
        &self,
        config: &GatewayConfig,
        store: &PostgresIdentityStore,
        request: &RequestHeader,
        method: &str,
        path: &str,
        now: UnixSeconds,
        binding: &AuthBinding,
        snapshot: &AuthSnapshot,
        action: &xshield_core::provenance::ActionGrant,
        operation: ResourceOperation<'_>,
    ) -> Result<GatewayDecision, IdentityRuntimeError> {
        let Ok(scope) = RequestResource::parse(
            request.uri.query(),
            operation.query_parameter,
            operation.resource_type,
            &self.fingerprint_key,
            config,
        ) else {
            return Ok(denied_reason(
                config,
                method,
                path,
                now,
                ReasonCode::CapabilityMissing,
            ));
        };
        let grants = match store
            .load_resource_grant(ResourceProofQuery {
                binding,
                snapshot,
                action_ref: action.action_ref(),
                resource_type: operation.resource_type,
                resource_key: &scope.key,
                operation_id: operation.operation_id,
                view_profile: operation.view_profile,
                policy_revision: config.policy_revision(),
                now,
            })
            .await?
        {
            ResourceProofState::Verified(grants) => grants,
            ResourceProofState::Denied(error) => {
                return Ok(denied_reason(
                    config,
                    method,
                    path,
                    now,
                    error.reason_code(),
                ));
            }
        };
        Ok(config.admit_scoped_with_proof(
            method,
            path,
            now,
            &scope.target,
            &scope.fields,
            Some(&scope.key),
            AdmissionProof::UiAction {
                binding,
                snapshot,
                action,
                grants: Some(&grants),
            },
        ))
    }
}

struct RequestResource {
    key: ResourceKeyHmac,
    target: ActionTarget,
    fields: BTreeSet<FieldName>,
}

impl RequestResource {
    fn parse(
        query: Option<&str>,
        wanted: &FieldName,
        resource_type: &ResourceType,
        key: &[u8; 32],
        config: &GatewayConfig,
    ) -> Result<Self, ()> {
        let (resource, fields) = parse_query(query.ok_or(())?, wanted)?;
        let mut canonical = Vec::with_capacity(128 + resource.len());
        for component in [
            "xshield-resource-v1",
            config.tenant_id().as_str(),
            config.site_id().as_str(),
            resource_type.as_str(),
            &resource,
        ] {
            canonical.extend_from_slice(component.as_bytes());
            canonical.push(0);
        }
        let key = ResourceKeyHmac::from_bytes(fingerprint(key, &canonical).map_err(|_| ())?);
        Ok(Self {
            target: ActionTarget::Resource {
                resource_type: resource_type.clone(),
                resource_key: key.clone(),
            },
            key,
            fields,
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
    denied_reason(config, method, path, now, error.reason_code())
}

fn denied_reason(
    config: &GatewayConfig,
    method: &str,
    path: &str,
    now: UnixSeconds,
    reason: ReasonCode,
) -> GatewayDecision {
    let mut decision = config.admit(method, path, now);
    decision.outcome = GatewayOutcome::Denied;
    decision.reason_code = reason;
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

fn unique_action_ref(request: &RequestHeader) -> Result<ActionRef, IdentityRuntimeError> {
    let mut values = request.headers.get_all(ACTION_HEADER).iter();
    let value = values.next().ok_or(IdentityRuntimeError::Missing)?;
    if values.next().is_some() {
        return Err(IdentityRuntimeError::Malformed);
    }
    ActionRef::parse(
        value
            .to_str()
            .map_err(|_| IdentityRuntimeError::Malformed)?,
    )
    .map_err(|_| IdentityRuntimeError::Malformed)
}

fn service_credential(
    request: &RequestHeader,
    key: &[u8; 32],
    config: &GatewayConfig,
) -> Result<ServiceCredentialFingerprint, IdentityRuntimeError> {
    let mut values = request.headers.get_all(SERVICE_CREDENTIAL_HEADER).iter();
    let value = values.next().ok_or(IdentityRuntimeError::Missing)?;
    if values.next().is_some() {
        return Err(IdentityRuntimeError::Malformed);
    }
    let value = value
        .to_str()
        .map_err(|_| IdentityRuntimeError::Malformed)?;
    if value.is_empty() || value.len() > MAX_BEARER_BYTES {
        return Err(IdentityRuntimeError::Malformed);
    }
    let mut canonical = Vec::with_capacity(64 + value.len());
    for component in [
        "xshield-service-credential-v1",
        config.tenant_id().as_str(),
        config.site_id().as_str(),
        value,
    ] {
        canonical.extend_from_slice(component.as_bytes());
        canonical.push(0);
    }
    Ok(ServiceCredentialFingerprint::from_bytes(fingerprint(
        key, &canonical,
    )?))
}

fn parse_query(query: &str, wanted: &FieldName) -> Result<(String, BTreeSet<FieldName>), ()> {
    if query.is_empty() || query.len() > MAX_QUERY_BYTES || query.contains(';') {
        return Err(());
    }
    let mut fields = BTreeSet::new();
    let mut resource = None;
    for (index, pair) in query.split('&').enumerate() {
        if index >= MAX_QUERY_PARAMETERS || pair.is_empty() {
            return Err(());
        }
        let (name, value) = pair.split_once('=').ok_or(())?;
        let field = FieldName::parse(decode_query_component(name)?).map_err(|_| ())?;
        let value = decode_query_component(value)?;
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(());
        }
        if !fields.insert(field.clone()) {
            return Err(());
        }
        if &field == wanted {
            if value.is_empty() || value.len() > MAX_RESOURCE_BYTES {
                return Err(());
            }
            resource = Some(value);
        }
    }
    Ok((resource.ok_or(())?, fields))
}

fn decode_query_component(value: &str) -> Result<String, ()> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let pair = bytes.get(index + 1..index + 3).ok_or(())?;
                decoded.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
                index += 3;
            }
            b'+' => return Err(()),
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
        if decoded.len() > MAX_QUERY_COMPONENT_BYTES {
            return Err(());
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

const fn hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(()),
    }
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

    fn service_config(site_id: &str) -> GatewayConfig {
        let json = serde_json::json!({
            "listen": "127.0.0.1:6188",
            "origin": {"address": "127.0.0.1:8080", "server_name": "origin.example", "tls": false},
            "tenant_id": "tenant_test",
            "site_id": site_id,
            "policy_revision": "policy-r1",
            "audit": {
                "directory": "target/xshield-service-test",
                "key_id": "journal-key-r1",
                "producer_id": "edge-test",
                "max_bytes": 1_048_576,
                "high_watermark_bytes": 786_432,
                "segment_max_bytes": 262_144
            },
            "identity_store": {"max_connections": 2, "acquire_timeout_ms": 1000},
            "operations": [{
                "operation_id": "reports.ingest",
                "method": "POST",
                "path": "/service/report",
                "admission": "SERVICE_IDENTITY",
                "source_action": null,
                "resource_type": null,
                "view_profile": null,
                "resource_query_parameter": null
            }]
        });
        GatewayConfig::from_json(&serde_json::to_vec(&json).unwrap()).unwrap()
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
        request
            .insert_header(ACTION_HEADER, "action_settings_primary")
            .unwrap();
        request
            .insert_header(SERVICE_CREDENTIAL_HEADER, "service-secret")
            .unwrap();
        request
            .insert_header(share_entry::SHARE_TOKEN_HEADER, "share-secret")
            .unwrap();
        strip_edge_proofs(&mut request).unwrap();
        assert_eq!(
            request.headers.get("cookie").unwrap().to_str().unwrap(),
            "theme=dark"
        );
        assert!(!request.headers.contains_key(ACTION_HEADER));
        assert!(!request.headers.contains_key(SERVICE_CREDENTIAL_HEADER));
        assert!(
            !request
                .headers
                .contains_key(share_entry::SHARE_TOKEN_HEADER)
        );
    }

    #[test]
    fn service_credential_is_exact_bounded_and_site_scoped() {
        let mut request = RequestHeader::build("POST", b"/service/report", Some(1)).unwrap();
        request
            .insert_header(SERVICE_CREDENTIAL_HEADER, "service-secret")
            .unwrap();
        let first = service_credential(&request, &KEY, &service_config("site_first")).unwrap();
        let second = service_credential(&request, &KEY, &service_config("site_second")).unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());

        request
            .append_header(SERVICE_CREDENTIAL_HEADER, "substituted-secret")
            .unwrap();
        assert!(matches!(
            service_credential(&request, &KEY, &service_config("site_first")),
            Err(IdentityRuntimeError::Malformed)
        ));
    }

    #[test]
    fn parses_one_bounded_action_reference() {
        let mut request = request();
        request
            .insert_header(ACTION_HEADER, "action_settings_primary")
            .unwrap();
        assert_eq!(
            unique_action_ref(&request).unwrap().as_str(),
            "action_settings_primary"
        );
        request
            .append_header(ACTION_HEADER, "action_settings_other")
            .unwrap();
        assert!(matches!(
            unique_action_ref(&request),
            Err(IdentityRuntimeError::Malformed)
        ));
    }

    #[test]
    fn query_adapter_decodes_once_and_rejects_ambiguity() {
        let wanted = FieldName::parse("order_id").unwrap();
        let (resource, fields) = parse_query("order_id=order%2D123&view=summary", &wanted).unwrap();
        assert_eq!(resource, "order-123");
        assert_eq!(fields.len(), 2);
        assert!(parse_query("order_id=one&order%5fid=two", &wanted).is_err());
        assert!(parse_query("order_id=%GG", &wanted).is_err());
        assert!(parse_query("order_id=order+123", &wanted).is_err());
        assert!(parse_query("order_id=one;view=full", &wanted).is_err());
    }
}
