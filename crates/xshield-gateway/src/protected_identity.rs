use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use pingora::{Result as PingoraResult, http::RequestHeader};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    time::Duration,
};
use uuid::Uuid;
use xshield_core::{
    access::ServiceCredentialFingerprint,
    admission::{AdmissionClass, AdmissionProof},
    audit::ReasonCode,
    domain::{ActionRef, AuthBindingId, EventId, FieldName, RequestId, ResourceType, WafSessionId},
    grant::ResourceKeyHmac,
    identity::{
        AuthBinding, AuthSnapshot, AuthorizationContextRef, CredentialFingerprint, CredentialSlot,
        IdentityDenied, UnixSeconds,
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
    GatewayConfig, GatewayDecision, GatewayOutcome, IdentityStoreConfig, ResourceLocation,
    ResourceOperation,
    auth_binding::{AuthBindingRule, AuthTransitionRule},
};
use xshield_postgres::{
    BindingEstablishment, ContextSwitchOutcome, CredentialTransition, IdentityContextSwitch,
    PostgresIdentityStore, RefreshOutcome, StoreError,
};
use zeroize::Zeroizing;

mod response_issue;
mod share_entry;

pub(crate) const WAF_COOKIE: &str = "__Host-xshield_sid";
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

pub(crate) struct ResponseIdentity {
    pub(crate) binding: Box<AuthBinding>,
    pub(crate) snapshot: AuthSnapshot,
}

pub(crate) struct PendingAuthBinding {
    binding_id: AuthBindingId,
    session_id: WafSessionId,
    event_id: EventId,
    issued_at: UnixSeconds,
    credential_expires_at: UnixSeconds,
    absolute_expires_at: UnixSeconds,
    session_ttl_seconds: u64,
}

impl PendingAuthBinding {
    pub(crate) fn cookie_header_value(&self) -> String {
        format!(
            "{WAF_COOKIE}={}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
            self.session_id.as_str(),
            self.session_ttl_seconds
        )
    }
}

pub(crate) struct ProtectedAdmission {
    pub(crate) decision: GatewayDecision,
    pub(crate) response_identity: Option<ResponseIdentity>,
}

impl ProtectedAdmission {
    fn without_identity(decision: GatewayDecision) -> Self {
        Self {
            decision,
            response_identity: None,
        }
    }
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

    pub(crate) fn prepare_auth_binding(
        rule: &AuthBindingRule,
        now: UnixSeconds,
    ) -> Result<PendingAuthBinding, ReasonCode> {
        let absolute_expires_at = now
            .value()
            .checked_add(rule.session_ttl_seconds())
            .map(UnixSeconds::new)
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let credential_expires_at = now
            .value()
            .checked_add(rule.credential_ttl_seconds())
            .map(UnixSeconds::new)
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        Ok(PendingAuthBinding {
            binding_id: AuthBindingId::parse(format!("auth_{}", Uuid::now_v7()))
                .map_err(|_| ReasonCode::ResponseValidationFailed)?,
            session_id: WafSessionId::parse(format!("ses_{}", Uuid::now_v7()))
                .map_err(|_| ReasonCode::ResponseValidationFailed)?,
            event_id: EventId::parse(format!("ev_{}", Uuid::now_v7()))
                .map_err(|_| ReasonCode::ResponseValidationFailed)?,
            issued_at: now,
            credential_expires_at,
            absolute_expires_at,
            session_ttl_seconds: rule.session_ttl_seconds(),
        })
    }

    pub(crate) async fn commit_auth_binding(
        &self,
        config: &GatewayConfig,
        rule: &AuthBindingRule,
        pending: &PendingAuthBinding,
        request_id: &RequestId,
        body: &[u8],
    ) -> Result<(), ReasonCode> {
        let authentication = rule
            .extract(body)
            .map_err(xshield_gateway::auth_binding::AuthBindingError::reason_code)?;
        let session_fingerprint = fingerprint(
            &self.fingerprint_key,
            pending.session_id.as_str().as_bytes(),
        )
        .map_err(|_| ReasonCode::IdentityStoreUnavailable)?;
        let bearer_fingerprint = CredentialFingerprint::from_bytes(
            fingerprint(&self.fingerprint_key, authentication.bearer().as_bytes())
                .map_err(|_| ReasonCode::IdentityStoreUnavailable)?,
        );
        let credentials = BTreeMap::from([(CredentialSlot::Bearer, bearer_fingerprint)]);
        let authorization_context_ref =
            AuthorizationContextRef::parse(authentication.authorization_context_ref())
                .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let binding = AuthBinding::new(
            pending.binding_id.clone(),
            pending.session_id.clone(),
            config.tenant_id().clone(),
            config.site_id().clone(),
            authentication.principal_ref(),
            authorization_context_ref,
            xshield_core::identity::AuthEpoch::new(1),
            xshield_core::identity::CredentialGeneration::new(1),
            credentials,
            pending.absolute_expires_at,
        )
        .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let envelope = serde_json::json!({
            "schema_version": 3,
            "event_type": "binding.created",
            "event_id": pending.event_id.as_str(),
            "request_id": request_id.as_str(),
            "binding_id": pending.binding_id.as_str(),
            "principal_ref": authentication.principal_ref(),
            "authorization_context_ref": authentication.authorization_context_ref(),
            "auth_epoch": 1,
            "credential_generation": 1,
        });
        let command = BindingEstablishment::new(
            &binding,
            &session_fingerprint,
            pending.credential_expires_at,
            pending.issued_at,
            &pending.event_id,
            &envelope,
        )
        .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        self.store()
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?
            .establish_binding(command)
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)
    }

    pub(crate) async fn commit_auth_refresh(
        &self,
        rule: &AuthTransitionRule,
        identity: &ResponseIdentity,
        request_id: &RequestId,
        body: &[u8],
        now: UnixSeconds,
    ) -> Result<(), ReasonCode> {
        let authentication = rule
            .extract(body)
            .map_err(xshield_gateway::auth_binding::AuthBindingError::reason_code)?;
        if authentication.principal_ref() != identity.snapshot.principal_ref() {
            return Err(ReasonCode::AuthBindingMismatch);
        }
        if authentication.authorization_context_ref()
            != identity.snapshot.authorization_context_ref().as_str()
        {
            return Err(ReasonCode::AuthBindingMismatch);
        }
        let bearer_fingerprint = CredentialFingerprint::from_bytes(
            fingerprint(&self.fingerprint_key, authentication.bearer().as_bytes())
                .map_err(|_| ReasonCode::IdentityStoreUnavailable)?,
        );
        let credentials = BTreeMap::from([(CredentialSlot::Bearer, bearer_fingerprint)]);
        if &credentials == identity.binding.credentials() {
            return Err(ReasonCode::ResponseValidationFailed);
        }
        let requested_expiry = now
            .value()
            .checked_add(rule.credential_ttl_seconds())
            .map(UnixSeconds::new)
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let credentials_expire_at = requested_expiry.min(identity.binding.absolute_expires_at());
        if credentials_expire_at <= now {
            return Err(ReasonCode::AuthSessionExpired);
        }
        let current_generation = identity
            .snapshot
            .generation()
            .value()
            .checked_add(1)
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7()))
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let previous_credentials = credential_audit_values(identity.binding.credentials());
        let current_credentials = credential_audit_values(&credentials);
        let envelope = serde_json::json!({
            "schema_version": 3,
            "event_type": "identity.refreshed",
            "event_id": event_id.as_str(),
            "request_id": request_id.as_str(),
            "binding_id": identity.snapshot.binding_id().as_str(),
            "principal_ref": identity.snapshot.principal_ref(),
            "authorization_context_ref": identity.snapshot.authorization_context_ref().as_str(),
            "auth_epoch": identity.snapshot.epoch().value(),
            "previous_credential_generation": identity.snapshot.generation().value(),
            "credential_generation": current_generation,
            "previous_credentials": previous_credentials,
            "credentials": current_credentials,
            "rotation_reason": "same_context_refresh",
        });
        let command = CredentialTransition::new(
            &identity.snapshot,
            identity.binding.credentials(),
            &credentials,
            credentials_expire_at,
            now,
            &event_id,
            &envelope,
        )
        .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        match self
            .store()
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?
            .refresh_same_context(command)
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?
        {
            RefreshOutcome::Updated { .. } => Ok(()),
            RefreshOutcome::Conflict => Err(ReasonCode::AuthCredentialGenerationChanged),
        }
    }

    pub(crate) async fn commit_auth_context_switch(
        &self,
        rule: &AuthTransitionRule,
        identity: &ResponseIdentity,
        request_id: &RequestId,
        body: &[u8],
        now: UnixSeconds,
    ) -> Result<(), ReasonCode> {
        let authentication = rule
            .extract(body)
            .map_err(xshield_gateway::auth_binding::AuthBindingError::reason_code)?;
        let authorization_context_ref =
            AuthorizationContextRef::parse(authentication.authorization_context_ref())
                .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        if authentication.principal_ref() == identity.snapshot.principal_ref()
            && &authorization_context_ref == identity.snapshot.authorization_context_ref()
        {
            return Err(ReasonCode::AuthBindingMismatch);
        }
        let bearer_fingerprint = CredentialFingerprint::from_bytes(
            fingerprint(&self.fingerprint_key, authentication.bearer().as_bytes())
                .map_err(|_| ReasonCode::IdentityStoreUnavailable)?,
        );
        let credentials = BTreeMap::from([(CredentialSlot::Bearer, bearer_fingerprint)]);
        if &credentials == identity.binding.credentials() {
            return Err(ReasonCode::AuthBindingMismatch);
        }
        let requested_expiry = now
            .value()
            .checked_add(rule.credential_ttl_seconds())
            .map(UnixSeconds::new)
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let credentials_expire_at = requested_expiry.min(identity.binding.absolute_expires_at());
        if credentials_expire_at <= now {
            return Err(ReasonCode::AuthSessionExpired);
        }
        let current_epoch = identity
            .snapshot
            .epoch()
            .value()
            .checked_add(1)
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let current_generation = identity
            .snapshot
            .generation()
            .value()
            .checked_add(1)
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7()))
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let envelope = serde_json::json!({
            "schema_version": 3,
            "event_type": "epoch.changed",
            "event_id": event_id.as_str(),
            "request_id": request_id.as_str(),
            "binding_id": identity.snapshot.binding_id().as_str(),
            "previous_principal_ref": identity.snapshot.principal_ref(),
            "principal_ref": authentication.principal_ref(),
            "previous_authorization_context_ref": identity.snapshot.authorization_context_ref().as_str(),
            "authorization_context_ref": authorization_context_ref.as_str(),
            "previous_auth_epoch": identity.snapshot.epoch().value(),
            "auth_epoch": current_epoch,
            "previous_credential_generation": identity.snapshot.generation().value(),
            "credential_generation": current_generation,
            "previous_credentials": credential_audit_values(identity.binding.credentials()),
            "credentials": credential_audit_values(&credentials),
            "rotation_reason": "account_context_changed",
        });
        let transition = CredentialTransition::new(
            &identity.snapshot,
            identity.binding.credentials(),
            &credentials,
            credentials_expire_at,
            now,
            &event_id,
            &envelope,
        )
        .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let command = IdentityContextSwitch::new(
            transition,
            authentication.principal_ref(),
            &authorization_context_ref,
        )
        .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        match self
            .store()
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?
            .switch_identity_context(command)
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?
        {
            ContextSwitchOutcome::Updated { .. } => Ok(()),
            ContextSwitchOutcome::Conflict => Err(ReasonCode::AuthEpochChanged),
        }
    }

    pub(crate) async fn admit(
        &self,
        config: &GatewayConfig,
        request: &RequestHeader,
        method: &str,
        path: &str,
        now: UnixSeconds,
    ) -> Result<ProtectedAdmission, IdentityRuntimeError> {
        let class = config.admission_class(method, path);
        if class == Some(AdmissionClass::ServiceIdentity) {
            return self
                .admit_service_identity(config, request, method, path, now)
                .await
                .map(ProtectedAdmission::without_identity);
        }
        if class == Some(AdmissionClass::ShareEntry) {
            return self
                .admit_share_entry(config, request, method, path, now)
                .await
                .map(ProtectedAdmission::without_identity);
        }
        if !matches!(
            class,
            Some(AdmissionClass::AuthenticatedRoot | AdmissionClass::UiActionRequired)
        ) {
            return Ok(ProtectedAdmission::without_identity(
                config.admit(method, path, now),
            ));
        }
        let presented = match PresentedIdentity::parse(request, &self.fingerprint_key) {
            Ok(presented) => presented,
            Err(IdentityRuntimeError::Missing) => {
                return Ok(ProtectedAdmission::without_identity(denied(
                    config,
                    method,
                    path,
                    now,
                    IdentityDenied::AuthRequired,
                )));
            }
            Err(IdentityRuntimeError::Malformed) => {
                return Ok(ProtectedAdmission::without_identity(denied(
                    config,
                    method,
                    path,
                    now,
                    IdentityDenied::BindingMismatch,
                )));
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
            IdentityProofState::Verified { binding, snapshot } => {
                let decision = match class {
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
                };
                ProtectedAdmission {
                    decision,
                    response_identity: Some(ResponseIdentity { binding, snapshot }),
                }
            }
            IdentityProofState::Denied(error) => {
                ProtectedAdmission::without_identity(denied(config, method, path, now, error))
            }
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
            request.uri.path(),
            request.uri.query(),
            operation.location,
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
        path: &str,
        query: Option<&str>,
        location: ResourceLocation<'_>,
        resource_type: &ResourceType,
        key: &[u8; 32],
        config: &GatewayConfig,
    ) -> Result<Self, ()> {
        let (resource, fields) = match location {
            ResourceLocation::Query(parameter) => parse_query(query.ok_or(())?, parameter)?,
            ResourceLocation::FinalPathSegment { prefix, parameter } => {
                if query.is_some() {
                    return Err(());
                }
                let raw = path.strip_prefix(prefix).ok_or(())?;
                if raw.is_empty() || raw.len() > MAX_QUERY_COMPONENT_BYTES || raw.contains('/') {
                    return Err(());
                }
                let resource = decode_path_segment(raw)?;
                if resource.is_empty()
                    || resource.len() > MAX_RESOURCE_BYTES
                    || resource
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
                {
                    return Err(());
                }
                (resource, BTreeSet::from([parameter.clone()]))
            }
        };
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

fn decode_path_segment(value: &str) -> Result<String, ()> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = bytes.get(index + 1..index + 3).ok_or(())?;
            decoded.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
        if decoded.len() > MAX_RESOURCE_BYTES {
            return Err(());
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
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

fn credential_audit_values(
    credentials: &BTreeMap<CredentialSlot, CredentialFingerprint>,
) -> Vec<serde_json::Value> {
    credentials
        .iter()
        .map(|(slot, fingerprint)| {
            serde_json::json!({
                "kind": slot.as_str(),
                "fingerprint": lower_hex(fingerprint.as_bytes()),
            })
        })
        .collect()
}

fn lower_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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

    #[test]
    fn path_adapter_hashes_one_strict_final_segment() {
        let config = service_config("site_path");
        let parameter = FieldName::parse("order_id").unwrap();
        let resource_type = ResourceType::parse("order").unwrap();
        let query = RequestResource::parse(
            "/orders",
            Some("order_id=order-123"),
            ResourceLocation::Query(&parameter),
            &resource_type,
            &KEY,
            &config,
        )
        .unwrap();
        let path = RequestResource::parse(
            "/orders/order%2D123",
            None,
            ResourceLocation::FinalPathSegment {
                prefix: "/orders/",
                parameter: &parameter,
            },
            &resource_type,
            &KEY,
            &config,
        )
        .unwrap();
        assert_eq!(query.key.as_bytes(), path.key.as_bytes());
        assert_eq!(path.fields, BTreeSet::from([parameter.clone()]));
        assert!(
            RequestResource::parse(
                "/orders/order%2F123",
                None,
                ResourceLocation::FinalPathSegment {
                    prefix: "/orders/",
                    parameter: &parameter,
                },
                &resource_type,
                &KEY,
                &config,
            )
            .is_err()
        );
        assert!(
            RequestResource::parse(
                "/orders/order-123",
                Some("expand=admin"),
                ResourceLocation::FinalPathSegment {
                    prefix: "/orders/",
                    parameter: &parameter,
                },
                &resource_type,
                &KEY,
                &config,
            )
            .is_err()
        );
    }
}
