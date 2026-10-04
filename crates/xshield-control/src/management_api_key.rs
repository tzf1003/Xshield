//! Management API-key issuance and lifecycle endpoints.
//!
//! Every administrative change follows one order: validate the request, stage
//! the change in a database transaction, append its durable audit event, then
//! commit. An audit failure therefore rolls the change back (no unaudited key,
//! no revoked key without its record, no rotation that kills the old key and
//! returns no replacement), and a secret is never returned for a key whose
//! creation was not recorded.
#![allow(
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::too_many_lines,
    clippy::format_collect,
    clippy::ignored_unit_patterns
)]

use super::{
    AccessAction, AccessEvent, AccessPayload, ControlError, ControlPlane, EndpointResult,
    PendingIntegrity, api_error, api_key_authz, audit_unavailable, identity, no_store,
    single_header,
};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};
use uuid::Uuid;
use xshield_audit::JournalRecord;
use xshield_core::{
    admin::{ApiKeyCapability, ApiKeyGrant, ManagementPrincipal, ManagementRole},
    domain::{EventId, ManagementApiKeyId, TenantId},
};
use xshield_postgres::{ManagementApiKeyScopeInput, NewManagementApiKey};

pub const PATH: &str = "/control/v1/agent-api-keys";
pub(crate) const ADMIN_ACCESS: AccessAction = AccessAction {
    event_type: "console.agent_api_key.admin",
    method: "POST",
    path: PATH,
    role: xshield_core::admin::ManagementRole::KeyAdministrator,
};
pub(crate) const LIST_ACCESS: AccessAction = AccessAction {
    event_type: "console.agent_api_key.list",
    method: "GET",
    path: PATH,
    role: xshield_core::admin::ManagementRole::KeyAdministrator,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub subject: String,
    pub display_name: String,
    pub expires_at: String,
    pub scopes: Vec<ScopeRequest>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRequest {
    pub tenant_id: String,
    pub site_id: String,
    pub capabilities: Vec<String>,
}

#[derive(Serialize)]
struct CreateResponse {
    request_id: String,
    api_key_id: String,
    api_key: String,
    key_prefix: String,
    expires_at: DateTime<Utc>,
    scopes: Vec<ScopeRequest>,
}

#[derive(Serialize)]
struct ListResponse {
    request_id: String,
    keys: Vec<ManagementApiKeyView>,
}

#[derive(Serialize)]
struct ManagementApiKeyView {
    api_key_id: String,
    tenant_id: String,
    subject: String,
    display_name: String,
    key_prefix: String,
    status: String,
    expires_at: String,
    created_at: String,
    last_used_at: Option<String>,
}

/// Most scope rows one key may carry, and so the bound on its grants.
const SCOPES_MAX: usize = 32;
/// Bounds for the free-text identity fields. They are labels, not identities:
/// the control plane names the principal `apikey:{key_id}:{subject}`.
const SUBJECT_MAX: usize = 128;
const DISPLAY_NAME_MAX: usize = 128;

/// A stable refusal; the caller records it as an audited terminal state.
struct Refusal {
    status: StatusCode,
    reason: &'static str,
    message: &'static str,
    retryable: bool,
    next_action: &'static str,
}

const UNAVAILABLE: Refusal = Refusal {
    status: StatusCode::SERVICE_UNAVAILABLE,
    reason: "CONTROL_API_KEY_UNAVAILABLE",
    message: "management service unavailable",
    retryable: true,
    next_action: "retry_later",
};
const NOT_FOUND: Refusal = Refusal {
    status: StatusCode::NOT_FOUND,
    reason: "CONTROL_API_KEY_NOT_FOUND",
    message: "management API key not found",
    retryable: false,
    next_action: "correct_request",
};
const REQUEST_INVALID: Refusal = Refusal {
    status: StatusCode::BAD_REQUEST,
    reason: "CONTROL_API_KEY_REQUEST_INVALID",
    message: "invalid API key request",
    retryable: false,
    next_action: "correct_request",
};
const EXPIRY_INVALID: Refusal = Refusal {
    status: StatusCode::BAD_REQUEST,
    reason: "CONTROL_API_KEY_EXPIRY_INVALID",
    message: "invalid API key expiry",
    retryable: false,
    next_action: "correct_request",
};
const SCOPE_INVALID: Refusal = Refusal {
    status: StatusCode::BAD_REQUEST,
    reason: "CONTROL_API_KEY_SCOPE_INVALID",
    message: "invalid API key subject, label or scope",
    retryable: false,
    next_action: "correct_request",
};
const SCOPE_FORBIDDEN: Refusal = Refusal {
    status: StatusCode::FORBIDDEN,
    reason: "CONTROL_API_KEY_SCOPE_FORBIDDEN",
    message: "API key scope exceeds the issuer's authority",
    retryable: false,
    next_action: "correct_request",
};
const ISSUANCE_UNAVAILABLE: Refusal = Refusal {
    status: StatusCode::SERVICE_UNAVAILABLE,
    reason: "CONTROL_API_KEY_UNAVAILABLE",
    message: "management API key issuance unavailable",
    retryable: true,
    next_action: "retry_later",
};

/// Why a requested scope set cannot be issued.
#[derive(Debug, Eq, PartialEq)]
enum ScopeRejection {
    /// Malformed, foreign-tenant, unknown capability, or a tenant-wide marker
    /// used with anything but `site.create` (and vice versa).
    Invalid,
    /// Well formed, but the issuer could not itself exercise it.
    Forbidden,
}

/// Turns the requested scopes into the exact grants to store.
///
/// Duplicates collapse; every grant must be one the issuer could itself
/// exercise, so a key is never more powerful than the person who issued it.
fn validate_scopes(
    scopes: &[ScopeRequest],
    tenant: &TenantId,
    issuer: &ManagementPrincipal,
) -> Result<BTreeSet<ApiKeyGrant>, ScopeRejection> {
    if scopes.is_empty() || scopes.len() > SCOPES_MAX {
        return Err(ScopeRejection::Invalid);
    }
    let mut grants = BTreeSet::new();
    for scope in scopes {
        if scope.tenant_id != tenant.as_str()
            || scope.capabilities.is_empty()
            || scope.capabilities.len() > ApiKeyCapability::ALL.len()
        {
            return Err(ScopeRejection::Invalid);
        }
        for name in &scope.capabilities {
            let capability = ApiKeyCapability::parse(name).ok_or(ScopeRejection::Invalid)?;
            let grant = ApiKeyGrant::from_scope_row(tenant.clone(), &scope.site_id, capability)
                .map_err(|_| ScopeRejection::Invalid)?;
            grants.insert(grant);
        }
    }
    if grants
        .iter()
        .any(|grant| !api_key_authz::issuer_may_grant(issuer, grant))
    {
        return Err(ScopeRejection::Forbidden);
    }
    Ok(grants)
}

/// A subject is a label for audit and listings: 1-128 ASCII characters from a
/// conservative set, starting with a letter or digit. Anything else, including
/// whitespace, control and non-ASCII characters (which allow look-alike
/// spoofing of another operator's name), is refused rather than normalized.
fn valid_subject(value: &str) -> bool {
    value.len() <= SUBJECT_MAX
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'/' | b'-')
        })
}

/// A display name may use any language, but no control, bidirectional-override
/// or zero-width characters and no edge whitespace; it is never trimmed for
/// the caller.
fn valid_display_name(value: &str) -> bool {
    let hidden = |character: char| {
        character.is_control()
            || matches!(
                u32::from(character),
                0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xFEFF
            )
    };
    !value.is_empty()
        && value.chars().count() <= DISPLAY_NAME_MAX
        && value.trim() == value
        && !value.chars().any(hidden)
}

/// Authorizes key administration: a browser management session (the
/// authenticator already enforces CSRF for its writes) holding
/// `KeyAdministrator` or `SystemAdmin`, as `docs/15` requires. A key has no
/// roles and the static machine credential is not a browser session, so
/// neither can mint, list, revoke or rotate keys.
fn authorize_key_admin(
    control: &ControlPlane,
    headers: &HeaderMap,
    request_id: &str,
    action: AccessAction,
) -> Result<identity::VerifiedRequestIdentity, Box<EndpointResult>> {
    let auth = single_header(headers, AUTHORIZATION.as_str());
    let identity = control.authorize_any_identity(
        auth.as_deref(),
        request_id,
        action,
        &[
            ManagementRole::KeyAdministrator,
            ManagementRole::SystemAdmin,
        ],
    )?;
    if !identity.browser {
        return Err(Box::new(control.audited_error(
            request_id,
            Some(identity.principal.subject()),
            action,
            None,
            StatusCode::FORBIDDEN,
            "CONTROL_SCOPE_DENIED",
            "management operation forbidden",
            false,
            "request_scope",
        )));
    }
    Ok(identity)
}

/// One key-administration audit event, owned so it can cross into a blocking task.
pub(crate) struct KeyAudit {
    pub(crate) subject: String,
    pub(crate) action: AccessAction,
    pub(crate) target: Option<ManagementApiKeyId>,
    pub(crate) outcome: &'static str,
    pub(crate) reason: &'static str,
}

impl ControlPlane {
    /// Appends key-administration events as one durable batch: either every
    /// event of the request is in the journal or none is. Each carries the
    /// administrator as `subject_ref` and, when known, the key it acted on as
    /// the typed `target_api_key_id`; secrets and fingerprints never appear.
    pub(crate) fn append_api_key_events(
        &self,
        request_id: &str,
        entries: &[KeyAudit],
    ) -> Result<(), ControlError> {
        let mut journal = self
            .access_journal
            .lock()
            .map_err(|_| ControlError::LockPoisoned)?;
        let first = journal
            .next_sequence()
            .ok_or(ControlError::SequenceExhausted)?;
        let producer_boot_id = journal.producer_boot_id();
        let mut built = Vec::with_capacity(entries.len());
        for (offset, entry) in entries.iter().enumerate() {
            let sequence = u64::try_from(offset)
                .ok()
                .and_then(|offset| first.checked_add(offset))
                .ok_or(ControlError::SequenceExhausted)?;
            let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7()))
                .map_err(|_| ControlError::InvalidConfig)?;
            let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            let trace_id = Uuid::now_v7().simple().to_string();
            let span_id = trace_id[..16].to_owned();
            let event = AccessEvent {
                schema_version: 3,
                event_id: event_id.as_str(),
                event_type: entry.action.event_type,
                tenant_id: self.config.tenant_id.as_str(),
                site_id: self.config.site_id.as_str(),
                request_id,
                trace_id: &trace_id,
                span_id: &span_id,
                producer_id: "xshield-control",
                producer_boot_id: &producer_boot_id,
                producer_seq: sequence,
                request_seq: 1,
                occurred_at: &occurred_at,
                observed_at: &occurred_at,
                policy_revision: "control-v1",
                example_only: false,
                evidence_refs: &[],
                cause_event_ids: &[],
                payload: AccessPayload {
                    method: entry.action.method,
                    path: entry.action.path,
                    subject_ref: Some(entry.subject.as_str()),
                    target_request_id: None,
                    target_artifact_id: None,
                    target_case_id: None,
                    target_access_request_id: None,
                    target_model_call_id: None,
                    target_grant_id: None,
                    target_binding_id: None,
                    target_hold_id: None,
                    target_calibration_report_id: None,
                    target_agent_run_id: None,
                    target_job_id: None,
                    target_export_id: None,
                    target_api_key_id: entry.target.as_ref().map(ManagementApiKeyId::as_str),
                    query_digest: None,
                    outcome: entry.outcome,
                    reason_code: entry.reason,
                    bytes_read: None,
                },
                sensitivity: "INTERNAL",
                integrity: PendingIntegrity {
                    state: "pending",
                    previous_hash: None,
                    event_hash: None,
                },
            };
            let bytes = serde_json::to_vec(&event)?;
            built.push((event_id, bytes, sequence));
        }
        let records: Vec<JournalRecord<'_>> = built
            .iter()
            .map(|(event_id, bytes, _)| JournalRecord {
                event_id,
                plaintext: bytes,
            })
            .collect();
        let receipts = journal.append_batch(&records)?;
        if receipts.len() != built.len()
            || receipts
                .iter()
                .zip(&built)
                .any(|(receipt, (_, _, sequence))| receipt.producer_sequence != *sequence)
        {
            return Err(ControlError::ReceiptMismatch);
        }
        Ok(())
    }
}

/// Appends the events on a blocking thread (the journal fsyncs); `false` when
/// the durable append failed, in which case the caller must not apply the change.
async fn record(control: &Arc<ControlPlane>, request_id: &str, entries: Vec<KeyAudit>) -> bool {
    let control = Arc::clone(control);
    let request_id = request_id.to_owned();
    matches!(
        tokio::task::spawn_blocking(move || control.append_api_key_events(&request_id, &entries))
            .await,
        Ok(Ok(()))
    )
}

/// Audits and answers a refusal. The refusal is itself an audited terminal
/// state; if even that cannot be recorded the caller gets the audit failure.
async fn refuse(
    control: &Arc<ControlPlane>,
    request_id: String,
    subject: &str,
    action: AccessAction,
    target: Option<ManagementApiKeyId>,
    refusal: &Refusal,
) -> Response {
    let entry = KeyAudit {
        subject: subject.to_owned(),
        action,
        target,
        outcome: if refusal.status.is_server_error() {
            "ERROR"
        } else {
            "DENY"
        },
        reason: refusal.reason,
    };
    if !record(control, &request_id, vec![entry]).await {
        return audit_unavailable(&request_id).into_response();
    }
    api_error(
        &request_id,
        refusal.status,
        refusal.reason,
        refusal.message,
        refusal.retryable,
        refusal.next_action,
    )
    .into_response()
}

/// Everything needed to store a key, validated and generated before any
/// database work starts.
struct Prepared {
    request: CreateRequest,
    expires_at: DateTime<Utc>,
    api_key_id: ManagementApiKeyId,
    secret: String,
    key_prefix: String,
    fingerprint: [u8; 32],
    scopes: Vec<ManagementApiKeyScopeInput>,
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

/// Validates the issuance body against the issuer's authority and generates
/// the key material. Pure with respect to the database, so a rotation whose
/// body is wrong is refused before anything is touched.
fn prepare(
    control: &ControlPlane,
    issuer: &ManagementPrincipal,
    body: &[u8],
) -> Result<Prepared, Refusal> {
    let request: CreateRequest = serde_json::from_slice(body).map_err(|_| REQUEST_INVALID)?;
    let expires_at = DateTime::parse_from_rfc3339(&request.expires_at)
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .filter(|value| *value > Utc::now() && *value <= Utc::now() + chrono::Duration::days(90))
        .ok_or(EXPIRY_INVALID)?;
    if !valid_subject(&request.subject) || !valid_display_name(&request.display_name) {
        return Err(SCOPE_INVALID);
    }
    let grants = validate_scopes(&request.scopes, &control.config.tenant_id, issuer).map_err(
        |rejection| match rejection {
            ScopeRejection::Invalid => SCOPE_INVALID,
            ScopeRejection::Forbidden => SCOPE_FORBIDDEN,
        },
    )?;
    let hash_key = control
        .config
        .api_key_hash_key
        .as_deref()
        .ok_or(ISSUANCE_UNAVAILABLE)?;
    let mut random = [0_u8; 24];
    rand_bytes(&mut random).map_err(|_| ISSUANCE_UNAVAILABLE)?;
    let secret = format!("xsk_{}", hex_bytes(&random));
    let fingerprint = super::component_signature(hash_key, &[secret.as_bytes()])
        .map_err(|_| ISSUANCE_UNAVAILABLE)?;
    let api_key_id = ManagementApiKeyId::parse(format!("key_{}", Uuid::now_v7()))
        .map_err(|_| ISSUANCE_UNAVAILABLE)?;
    Ok(Prepared {
        key_prefix: secret[..12].to_owned(),
        scopes: grants
            .iter()
            .map(|grant| ManagementApiKeyScopeInput {
                tenant_id: grant.tenant().as_str().to_owned(),
                site_id: grant.scope_site_id().to_owned(),
                capability: grant.capability().as_str().to_owned(),
            })
            .collect(),
        request,
        expires_at,
        api_key_id,
        secret,
        fingerprint,
    })
}

impl Prepared {
    fn as_new_key<'a>(
        &'a self,
        tenant_id: &'a str,
        created_by: &'a str,
    ) -> NewManagementApiKey<'a> {
        NewManagementApiKey {
            api_key_id: self.api_key_id.as_str(),
            tenant_id,
            subject: &self.request.subject,
            display_name: &self.request.display_name,
            key_prefix: &self.key_prefix,
            fingerprint: &self.fingerprint,
            expires_at: self.expires_at,
            created_by,
            scopes: &self.scopes,
        }
    }

    fn into_response(self, request_id: String) -> Response {
        no_store(
            (
                StatusCode::CREATED,
                Json(CreateResponse {
                    request_id,
                    api_key_id: self.api_key_id.as_str().to_owned(),
                    api_key: self.secret,
                    key_prefix: self.key_prefix,
                    expires_at: self.expires_at,
                    scopes: self.request.scopes,
                }),
            )
                .into_response(),
        )
    }
}

pub async fn list_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let subject = match authorize_key_admin(&control, &headers, &request_id, LIST_ACCESS) {
        Ok(identity) => identity.principal.subject().to_owned(),
        Err(response) => return (*response).into_response(),
    };
    let Ok(keys) = control
        .catalog
        .list_management_api_keys(control.config.tenant_id.as_str())
        .await
    else {
        return refuse(
            &control,
            request_id,
            &subject,
            LIST_ACCESS,
            None,
            &UNAVAILABLE,
        )
        .await;
    };
    let listed = KeyAudit {
        subject,
        action: LIST_ACCESS,
        target: None,
        outcome: "PASS",
        reason: "CONTROL_API_KEYS_LISTED",
    };
    // The listing is withheld unless its access is durably recorded.
    if !record(&control, &request_id, vec![listed]).await {
        return audit_unavailable(&request_id).into_response();
    }
    let keys = keys
        .into_iter()
        .map(|key| ManagementApiKeyView {
            api_key_id: key.api_key_id,
            tenant_id: key.tenant_id,
            subject: key.subject,
            display_name: key.display_name,
            key_prefix: key.key_prefix,
            status: key.status,
            expires_at: key.expires_at.to_rfc3339(),
            created_at: key.created_at.to_rfc3339(),
            last_used_at: key.last_used_at.map(|value| value.to_rfc3339()),
        })
        .collect();
    no_store((StatusCode::OK, Json(ListResponse { request_id, keys })).into_response())
}

pub async fn create_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let identity = match authorize_key_admin(&control, &headers, &request_id, ADMIN_ACCESS) {
        Ok(identity) => identity,
        Err(response) => return (*response).into_response(),
    };
    let subject = identity.principal.subject().to_owned();
    let prepared = match prepare(&control, &identity.principal, &body) {
        Ok(prepared) => prepared,
        Err(refusal) => {
            return refuse(&control, request_id, &subject, ADMIN_ACCESS, None, &refusal).await;
        }
    };
    let tenant = control.config.tenant_id.as_str();
    let Ok(staged) = control
        .catalog
        .stage_create_management_api_key(&prepared.as_new_key(tenant, &subject))
        .await
    else {
        return refuse(
            &control,
            request_id,
            &subject,
            ADMIN_ACCESS,
            Some(prepared.api_key_id),
            &UNAVAILABLE,
        )
        .await;
    };
    let created = KeyAudit {
        subject: subject.clone(),
        action: ADMIN_ACCESS,
        target: Some(prepared.api_key_id.clone()),
        outcome: "PASS",
        reason: "CONTROL_API_KEY_CREATED",
    };
    // The key becomes real only after its creation is durably recorded; if the
    // record fails the staged insert is dropped and no secret leaves.
    if !record(&control, &request_id, vec![created]).await {
        drop(staged);
        return audit_unavailable(&request_id).into_response();
    }
    if staged.commit().await.is_err() {
        return refuse(
            &control,
            request_id,
            &subject,
            ADMIN_ACCESS,
            Some(prepared.api_key_id),
            &UNAVAILABLE,
        )
        .await;
    }
    prepared.into_response(request_id)
}

pub async fn rotate_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(api_key_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let identity = match authorize_key_admin(&control, &headers, &request_id, ADMIN_ACCESS) {
        Ok(identity) => identity,
        Err(response) => return (*response).into_response(),
    };
    let subject = identity.principal.subject().to_owned();
    let Ok(old_id) = ManagementApiKeyId::parse(api_key_id) else {
        return refuse(
            &control,
            request_id,
            &subject,
            ADMIN_ACCESS,
            None,
            &NOT_FOUND,
        )
        .await;
    };
    // Validate before touching anything: a bad body must leave the old key alive.
    let prepared = match prepare(&control, &identity.principal, &body) {
        Ok(prepared) => prepared,
        Err(refusal) => {
            return refuse(
                &control,
                request_id,
                &subject,
                ADMIN_ACCESS,
                Some(old_id),
                &refusal,
            )
            .await;
        }
    };
    let tenant = control.config.tenant_id.as_str();
    let staged = match control
        .catalog
        .stage_rotate_management_api_key(old_id.as_str(), &prepared.as_new_key(tenant, &subject))
        .await
    {
        Ok(Some(staged)) => staged,
        Ok(None) => {
            return refuse(
                &control,
                request_id,
                &subject,
                ADMIN_ACCESS,
                Some(old_id),
                &NOT_FOUND,
            )
            .await;
        }
        Err(_) => {
            return refuse(
                &control,
                request_id,
                &subject,
                ADMIN_ACCESS,
                Some(old_id),
                &UNAVAILABLE,
            )
            .await;
        }
    };
    // Both halves of the swap are one batch: the old key's retirement and the
    // new key's creation are recorded together or not at all.
    let entries = vec![
        KeyAudit {
            subject: subject.clone(),
            action: ADMIN_ACCESS,
            target: Some(old_id.clone()),
            outcome: "PASS",
            reason: "CONTROL_API_KEY_ROTATED_OUT",
        },
        KeyAudit {
            subject: subject.clone(),
            action: ADMIN_ACCESS,
            target: Some(prepared.api_key_id.clone()),
            outcome: "PASS",
            reason: "CONTROL_API_KEY_ROTATED_IN",
        },
    ];
    if !record(&control, &request_id, entries).await {
        drop(staged);
        return audit_unavailable(&request_id).into_response();
    }
    if staged.commit().await.is_err() {
        return refuse(
            &control,
            request_id,
            &subject,
            ADMIN_ACCESS,
            Some(old_id),
            &UNAVAILABLE,
        )
        .await;
    }
    prepared.into_response(request_id)
}

pub async fn revoke_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(api_key_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = format!("req_{}", uuid::Uuid::now_v7());
    let subject = match authorize_key_admin(&control, &headers, &request_id, ADMIN_ACCESS) {
        Ok(identity) => identity.principal.subject().to_owned(),
        Err(response) => return (*response).into_response(),
    };
    let Ok(target) = ManagementApiKeyId::parse(api_key_id) else {
        return refuse(
            &control,
            request_id,
            &subject,
            ADMIN_ACCESS,
            None,
            &NOT_FOUND,
        )
        .await;
    };
    let staged = match control
        .catalog
        .stage_revoke_management_api_key(control.config.tenant_id.as_str(), target.as_str())
        .await
    {
        Ok(Some(staged)) => staged,
        Ok(None) => {
            return refuse(
                &control,
                request_id,
                &subject,
                ADMIN_ACCESS,
                Some(target),
                &NOT_FOUND,
            )
            .await;
        }
        Err(_) => {
            return refuse(
                &control,
                request_id,
                &subject,
                ADMIN_ACCESS,
                Some(target),
                &UNAVAILABLE,
            )
            .await;
        }
    };
    let revoked = KeyAudit {
        subject: subject.clone(),
        action: ADMIN_ACCESS,
        target: Some(target.clone()),
        outcome: "PASS",
        reason: "CONTROL_API_KEY_REVOKED",
    };
    if !record(&control, &request_id, vec![revoked]).await {
        drop(staged);
        return audit_unavailable(&request_id).into_response();
    }
    if staged.commit().await.is_err() {
        return refuse(
            &control,
            request_id,
            &subject,
            ADMIN_ACCESS,
            Some(target),
            &UNAVAILABLE,
        )
        .await;
    }
    no_store(
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "request_id": request_id,
                "api_key_id": target.as_str(),
                "status": "revoked",
            })),
        )
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::admin::API_KEY_TENANT_WIDE_MARKER;

    fn tenant() -> TenantId {
        TenantId::parse("tenant_a").unwrap()
    }

    fn scope(site: &str, capabilities: &[&str]) -> ScopeRequest {
        ScopeRequest {
            tenant_id: "tenant_a".to_owned(),
            site_id: site.to_owned(),
            capabilities: capabilities
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }

    fn issuer(roles: &[ManagementRole]) -> ManagementPrincipal {
        ManagementPrincipal::new_tenant_scoped("human", roles.iter().copied(), [tenant()]).unwrap()
    }

    fn full_issuer() -> ManagementPrincipal {
        issuer(&[
            ManagementRole::SystemAdmin,
            ManagementRole::Observer,
            ManagementRole::PolicyAuthor,
            ManagementRole::PolicyApprover,
            ManagementRole::ReleaseOperator,
        ])
    }

    #[test]
    fn scopes_are_validated_into_exact_deduplicated_grants() {
        let grants = validate_scopes(
            &[
                scope("site_a", &["site.read", "site.read", "site.config.write"]),
                scope("site_a", &["site.read"]),
                scope(API_KEY_TENANT_WIDE_MARKER, &["site.create"]),
            ],
            &tenant(),
            &full_issuer(),
        )
        .unwrap();
        let described: Vec<_> = grants
            .iter()
            .map(|grant| format!("{}:{}", grant.scope_site_id(), grant.capability().as_str()))
            .collect();
        assert_eq!(described.len(), 3, "{described:?}");
        assert!(described.contains(&"__tenant__:site.create".to_owned()));
        assert!(described.contains(&"site_a:site.read".to_owned()));
        assert!(described.contains(&"site_a:site.config.write".to_owned()));
    }

    #[test]
    fn malformed_scope_sets_are_invalid_before_authority_is_considered() {
        let invalid = |scopes: Vec<ScopeRequest>| {
            assert_eq!(
                validate_scopes(&scopes, &tenant(), &issuer(&[])),
                Err(ScopeRejection::Invalid)
            );
        };
        invalid(vec![]);
        invalid(
            (0..=SCOPES_MAX)
                .map(|_| scope("site_a", &["site.read"]))
                .collect(),
        );
        invalid(vec![scope("site_a", &[])]);
        invalid(vec![scope("site_a", &["site.delete"])]);
        invalid(vec![scope("site_a", &["site.create"])]);
        invalid(vec![scope(API_KEY_TENANT_WIDE_MARKER, &["site.read"])]);
        invalid(vec![scope("", &["site.read"])]);
        invalid(vec![scope("bad site", &["site.read"])]);
        invalid(vec![ScopeRequest {
            tenant_id: "tenant_other".to_owned(),
            site_id: "site_a".to_owned(),
            capabilities: vec!["site.read".to_owned()],
        }]);
    }

    #[test]
    fn well_formed_scopes_beyond_the_issuer_are_forbidden_not_invalid() {
        let admin_only = issuer(&[ManagementRole::SystemAdmin]);
        assert!(
            validate_scopes(
                &[scope("site_a", &["site.config.write"])],
                &tenant(),
                &admin_only
            )
            .is_ok()
        );
        for capability in [
            "site.config.apply_direct",
            "site.rollback",
            "site.config.validate",
        ] {
            assert_eq!(
                validate_scopes(&[scope("site_a", &[capability])], &tenant(), &admin_only),
                Err(ScopeRejection::Forbidden),
                "{capability}"
            );
        }
        // One out-of-authority grant refuses the whole request; nothing is trimmed.
        assert_eq!(
            validate_scopes(
                &[scope("site_a", &["site.config.write", "site.rollback"])],
                &tenant(),
                &admin_only
            ),
            Err(ScopeRejection::Forbidden)
        );
    }

    #[test]
    fn subjects_are_conservative_ascii_labels() {
        for good in [
            "a",
            "agent-juice-shop",
            "agent.juice_shop:v1@tenant/a",
            "0day",
            &"x".repeat(SUBJECT_MAX),
        ] {
            assert!(valid_subject(good), "{good:?}");
        }
        for bad in [
            "",
            " lead",
            "trail ",
            "in ner",
            "line\nbreak",
            "tab\t",
            "nul\u{0}",
            "-dash",
            ".dot",
            "\u{430}lice",
            "emoji\u{1F600}",
            "\u{202E}rtl",
            &"x".repeat(SUBJECT_MAX + 1),
        ] {
            assert!(!valid_subject(bad), "{bad:?}");
        }
    }

    #[test]
    fn display_names_allow_any_language_but_no_hidden_or_edge_characters() {
        for good in [
            "Juice Shop Agent",
            "\u{6D4B}\u{8BD5} agent",
            "caf\u{e9}",
            &"l".repeat(DISPLAY_NAME_MAX),
        ] {
            assert!(valid_display_name(good), "{good:?}");
        }
        for bad in [
            "",
            "   ",
            " lead",
            "trail ",
            "a\nb",
            "a\u{7f}b",
            "bell\u{7}",
            "zero\u{200B}width",
            "bidi\u{202E}override",
            "\u{FEFF}bom",
            &"l".repeat(DISPLAY_NAME_MAX + 1),
        ] {
            assert!(!valid_display_name(bad), "{bad:?}");
        }
    }
}
