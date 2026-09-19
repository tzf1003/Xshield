//! Strict gateway identity transaction payloads; the index is not identity state.

use super::{
    PayloadSummary, PublishError, WireEvent, valid_lower_hex, valid_prefixed_v7, valid_subject,
};
use serde::Deserialize;
use std::collections::BTreeMap;

pub(super) const EVENT_TYPES: &[&str] = &[
    "session.created",
    "binding.created",
    "identity.refreshed",
    "epoch.changed",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionCreated {
    stage: String,
    outcome: String,
    reason_code: String,
    binding_id: String,
    status: String,
    auth_epoch: u64,
    credential_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingCreated {
    stage: String,
    outcome: String,
    reason_code: String,
    binding_id: String,
    principal_ref: String,
    authorization_context_ref: String,
    auth_epoch: u64,
    credential_generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRefreshed {
    stage: String,
    outcome: String,
    reason_code: String,
    binding_id: String,
    principal_ref: String,
    authorization_context_ref: String,
    auth_epoch: u64,
    previous_credential_generation: u64,
    credential_generation: u64,
    previous_credentials: Vec<CredentialAudit>,
    credentials: Vec<CredentialAudit>,
    rotation_reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochChanged {
    stage: String,
    outcome: String,
    reason_code: String,
    binding_id: String,
    previous_principal_ref: String,
    principal_ref: String,
    previous_authorization_context_ref: String,
    authorization_context_ref: String,
    previous_auth_epoch: u64,
    auth_epoch: u64,
    previous_credential_generation: u64,
    credential_generation: u64,
    previous_credentials: Vec<CredentialAudit>,
    credentials: Vec<CredentialAudit>,
    rotation_reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialAudit {
    kind: String,
    fingerprint: String,
}

// Keep the four closed wire grammars together for contract review.
#[allow(clippy::too_many_lines)]
pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    // Each successful identity transaction is its own producer run. Its request
    // ID correlates with the journal but does not assert a cross-producer order.
    if event.producer_id != "gateway-identity"
        || valid_prefixed_v7(&event.producer_boot_id, "req_").is_err()
        || event.request_id.as_deref() != Some(event.producer_boot_id.as_str())
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.sensitivity != "SENSITIVE"
        || !event.evidence_refs.is_empty()
        || !event.cause_event_ids.is_empty()
    {
        return Err(PublishError::InvalidEvent);
    }
    let (stage, outcome, reason, binding) = match event.event_type.as_str() {
        "session.created" => {
            let value: SessionCreated = serde_json::from_str(event.payload.get())?;
            if value.status != "anonymous"
                || value.auth_epoch != 0
                || value.credential_generation != 0
            {
                return Err(PublishError::InvalidEvent);
            }
            (
                value.stage,
                value.outcome,
                value.reason_code,
                value.binding_id,
            )
        }
        "binding.created" => {
            let value: BindingCreated = serde_json::from_str(event.payload.get())?;
            if value.auth_epoch != 1
                || value.credential_generation != 1
                || !valid_subject(&value.principal_ref)
                || !valid_subject(&value.authorization_context_ref)
            {
                return Err(PublishError::InvalidEvent);
            }
            (
                value.stage,
                value.outcome,
                value.reason_code,
                value.binding_id,
            )
        }
        "identity.refreshed" => {
            let value: IdentityRefreshed = serde_json::from_str(event.payload.get())?;
            if !valid_counter(value.auth_epoch)
                || !is_successor(
                    value.previous_credential_generation,
                    value.credential_generation,
                )
                || !valid_subject(&value.principal_ref)
                || !valid_subject(&value.authorization_context_ref)
                || value.rotation_reason != "same_context_refresh"
                || credentials(value.previous_credentials)? == credentials(value.credentials)?
            {
                return Err(PublishError::InvalidEvent);
            }
            (
                value.stage,
                value.outcome,
                value.reason_code,
                value.binding_id,
            )
        }
        "epoch.changed" => {
            let value: EpochChanged = serde_json::from_str(event.payload.get())?;
            if !is_successor(value.previous_auth_epoch, value.auth_epoch)
                || !is_successor(
                    value.previous_credential_generation,
                    value.credential_generation,
                )
                || !valid_subject(&value.previous_principal_ref)
                || !valid_subject(&value.principal_ref)
                || !valid_subject(&value.previous_authorization_context_ref)
                || !valid_subject(&value.authorization_context_ref)
                || (value.previous_principal_ref == value.principal_ref
                    && value.previous_authorization_context_ref == value.authorization_context_ref)
                || value.rotation_reason != "account_context_changed"
                || credentials(value.previous_credentials)? == credentials(value.credentials)?
            {
                return Err(PublishError::InvalidEvent);
            }
            (
                value.stage,
                value.outcome,
                value.reason_code,
                value.binding_id,
            )
        }
        _ => return Err(PublishError::UnsupportedEventType),
    };
    let expected_reason = match event.event_type.as_str() {
        "session.created" => "SESSION_CREATED",
        "binding.created" => "BINDING_CREATED",
        "identity.refreshed" => "IDENTITY_REFRESHED",
        "epoch.changed" => "IDENTITY_CONTEXT_CHANGED",
        _ => return Err(PublishError::UnsupportedEventType),
    };
    if stage != "identity_lifecycle"
        || outcome != "PASS"
        || reason != expected_reason
        || valid_prefixed_v7(&binding, "auth_").is_err()
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(PayloadSummary {
        stage,
        outcome,
        reason_code: reason,
        proof_kind: "deterministic".to_owned(),
        confidence_status: "not_applicable".to_owned(),
        ..PayloadSummary::default()
    })
}

fn valid_counter(value: u64) -> bool {
    value > 0 && i64::try_from(value).is_ok()
}

fn is_successor(previous: u64, current: u64) -> bool {
    valid_counter(previous) && valid_counter(current) && previous.checked_add(1) == Some(current)
}

fn credentials(values: Vec<CredentialAudit>) -> Result<BTreeMap<String, String>, PublishError> {
    if values.is_empty() || values.len() > 3 {
        return Err(PublishError::InvalidEvent);
    }
    let mut by_kind = BTreeMap::new();
    for value in values {
        if !matches!(value.kind.as_str(), "cookie" | "bearer" | "body_token")
            || !valid_lower_hex(&value.fingerprint, 64)
            || by_kind.insert(value.kind, value.fingerprint).is_some()
        {
            return Err(PublishError::InvalidEvent);
        }
    }
    Ok(by_kind)
}

#[cfg(test)]
pub(super) mod tests;
