use super::{ProtectedIdentity, ResponseIdentity, fingerprint, transaction_envelope};
use chrono::{DateTime, SecondsFormat};
use openssl::sha::sha256;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use uuid::Uuid;
use xshield_core::{
    audit::ReasonCode,
    domain::{
        ActionRef, EventId, FieldName, GrantId, IssuanceKey, OperationId, RequestId,
        ResponseEvidenceId,
    },
    grant::{GrantDraft, ResourceKeyHmac},
    identity::UnixSeconds,
    provenance::{ActionGrant, ActionGrantDraft, ActionTarget, ResponseEvidence},
};
use xshield_gateway::{
    GatewayConfig, ResponseGrantOperation, response_grant::ResponseGrantExtraction,
};
use xshield_postgres::{
    ResponseActionDescriptorQuery, ResponseGrantItem, ResponseGrantPersistence,
    ResponseGrantWriteOutcome,
};

impl ProtectedIdentity {
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(crate) async fn commit_response_grants(
        &self,
        config: &GatewayConfig,
        identity: &ResponseIdentity,
        operation: ResponseGrantOperation<'_>,
        source_request_id: &RequestId,
        trace_id: &str,
        source_operation_id: &OperationId,
        response_status: u16,
        body: &[u8],
        now: UnixSeconds,
    ) -> Result<Option<Vec<ActionRef>>, ReasonCode> {
        let resources = match operation
            .rule
            .extract(response_status, body)
            .map_err(xshield_gateway::response_grant::ResponseGrantError::reason_code)?
        {
            ResponseGrantExtraction::NotApplicable => return Ok(None),
            ResponseGrantExtraction::Resources(resources) if resources.is_empty() => {
                return Ok(None);
            }
            ResponseGrantExtraction::Resources(resources) => resources,
        };
        let store = self
            .store()
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?;
        let descriptor = store
            .load_response_action_descriptor(ResponseActionDescriptorQuery {
                tenant_id: config.tenant_id(),
                site_id: config.site_id(),
                action_id: operation.target_action_id,
                operation_id: operation.rule.target_operation_id(),
                policy_revision: config.policy_revision(),
                mapping_revision: operation.target_mapping_revision,
            })
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?
            .ok_or(ReasonCode::GrantSourceIneligible)?;
        let expires_at = UnixSeconds::new(
            now.value()
                .checked_add(operation.rule.ttl_seconds())
                .map(|expiry| expiry.min(identity.binding.absolute_expires_at().value()))
                .filter(|expiry| *expiry > now.value())
                .ok_or(ReasonCode::GrantSourceIneligible)?,
        );
        let evidence_digest = self.digest(&[
            b"response-evidence-v1",
            source_request_id.as_str().as_bytes(),
            source_operation_id.as_str().as_bytes(),
            operation.rule.target_operation_id().as_str().as_bytes(),
            config.policy_revision().as_str().as_bytes(),
            operation.target_mapping_revision.as_str().as_bytes(),
        ])?;
        let evidence = ResponseEvidence::verified(
            ResponseEvidenceId::parse(prefixed_uuid(
                "response_",
                source_request_id,
                evidence_digest,
            )?)
            .map_err(|_| ReasonCode::ResponseValidationFailed)?,
            &identity.binding,
            identity.snapshot.clone(),
            source_request_id.clone(),
            source_operation_id.clone(),
            operation.rule.target_operation_id().clone(),
            response_status,
            config.policy_revision().clone(),
            expires_at,
            now,
        )
        .map_err(xshield_core::provenance::ProvenanceError::reason_code)?;

        let mut actions = Vec::with_capacity(resources.len());
        let mut grants = Vec::with_capacity(resources.len());
        let mut event_ids = Vec::with_capacity(resources.len());
        let mut envelopes = Vec::with_capacity(resources.len());
        let candidate_count = resources.len();
        let timestamp = i64::try_from(now.value())
            .ok()
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
            .ok_or(ReasonCode::ClockUnavailable)?
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        let response_body_sha256 = hex(sha256(body));
        for (index, resource) in resources.into_iter().enumerate() {
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(ReasonCode::ResponseValidationFailed)?;
            let resource_key =
                self.resource_key(config, operation.resource_type, resource.as_str())?;
            let item_digest = self.digest(&[
                b"response-grant-v1",
                source_request_id.as_str().as_bytes(),
                operation.rule.target_operation_id().as_str().as_bytes(),
                operation.target_mapping_revision.as_str().as_bytes(),
                resource_key.as_bytes(),
            ])?;
            let action_ref = ActionRef::parse(format!("action.{}", hex(item_digest)))
                .map_err(|_| ReasonCode::ResponseValidationFailed)?;
            let resource_key_hex = hex(*resource_key.as_bytes());
            let event_id = EventId::parse(prefixed_uuid(
                "ev_",
                source_request_id,
                self.digest(&[b"response-grant-event-v1", &item_digest])?,
            )?)
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
            let grant_id = GrantId::parse(prefixed_uuid(
                "grant_",
                source_request_id,
                self.digest(&[b"response-grant-id-v1", &item_digest])?,
            )?)
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
            let action = ActionGrant::issue_from_response(
                &identity.binding,
                &identity.snapshot,
                &evidence,
                &descriptor,
                ActionGrantDraft {
                    action_ref,
                    target: ActionTarget::Resource {
                        resource_type: operation.resource_type.clone(),
                        resource_key: resource_key.clone(),
                    },
                    fields: BTreeSet::from([operation.target_field.clone()]),
                    expires_at,
                },
                now,
            )
            .map_err(xshield_core::provenance::ProvenanceError::reason_code)?;
            let grant = GrantDraft {
                grant_id,
                issuance_key: IssuanceKey::parse(format!("response.{}", hex(item_digest)))
                    .map_err(|_| ReasonCode::ResponseValidationFailed)?,
                resource_type: operation.resource_type.clone(),
                resource_key,
                operation_id: operation.rule.target_operation_id().clone(),
                view_profile: operation.view_profile.clone(),
                source_request_id: source_request_id.clone(),
                policy_revision: config.policy_revision().clone(),
                expires_at,
            };
            let payload = json!({
                "stage": "response_grant",
                "outcome": "PASS",
                "reason_code": ReasonCode::GrantIssued.as_str(),
                "grant_id": grant.grant_id.as_str(),
                "binding_id": identity.snapshot.binding_id().as_str(),
                "auth_epoch": identity.snapshot.epoch().value(),
                "response_evidence_id": evidence.evidence_id().as_str(),
                "action_ref": action.action_ref().as_str(),
                "action_id": action.action_id().as_str(),
                "source_operation_id": source_operation_id.as_str(),
                "operation_id": grant.operation_id.as_str(),
                "method": action.method().as_str(),
                "route_template": action.route().as_str(),
                "resource_type": grant.resource_type.as_str(),
                "resource_key_hmac": resource_key_hex,
                "view_profile": grant.view_profile.as_str(),
                "fields": action.fields().iter().map(FieldName::as_str).collect::<Vec<_>>(),
                "mapping_revision": action.mapping_revision().as_str(),
                "response_status": response_status,
                "response_body_sha256": response_body_sha256,
                "candidate_count": candidate_count,
                "issued_at_unix": now.value(),
                "expires_at_unix": grant.expires_at.value(),
            });
            // Reuse the frozen transaction time and batch position so an exact
            // replay retains the same envelope as its stable event identifier.
            envelopes.push(transaction_envelope(
                config,
                source_request_id,
                trace_id,
                &event_id,
                "response_grant.issued",
                "gateway-response-grant",
                sequence,
                &timestamp,
                &payload,
            )?);
            grants.push(grant);
            actions.push(action);
            event_ids.push(event_id);
        }
        let constraints = Value::Object(Map::default());
        let items = actions
            .iter()
            .zip(&grants)
            .zip(&event_ids)
            .zip(&envelopes)
            .map(|(((action, grant), event_id), envelope)| {
                ResponseGrantItem::new(action, grant, &constraints, event_id, envelope)
                    .map_err(|_| ReasonCode::ResponseValidationFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let artifact_ref = format!("sha256.{response_body_sha256}");
        let outcome = store
            .issue_response_grants(
                ResponseGrantPersistence::new(
                    &evidence,
                    &artifact_ref,
                    &items,
                    now,
                    operation.rule.max_active_grants(),
                )
                .map_err(|_| ReasonCode::ResponseValidationFailed)?,
            )
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?;
        match outcome {
            ResponseGrantWriteOutcome::Created(committed)
            | ResponseGrantWriteOutcome::Existing(committed) => Ok(Some(
                committed
                    .into_iter()
                    .map(|grant| grant.action_ref)
                    .collect(),
            )),
            denied => Err(denied.reason_code()),
        }
    }

    fn digest(&self, parts: &[&[u8]]) -> Result<[u8; 32], ReasonCode> {
        let mut canonical = Vec::new();
        for part in parts {
            canonical.extend_from_slice(part);
            canonical.push(0);
        }
        fingerprint(&self.fingerprint_key, &canonical)
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)
    }

    fn resource_key(
        &self,
        config: &GatewayConfig,
        resource_type: &xshield_core::domain::ResourceType,
        resource: &str,
    ) -> Result<ResourceKeyHmac, ReasonCode> {
        self.digest(&[
            b"xshield-resource-v1",
            config.tenant_id().as_str().as_bytes(),
            config.site_id().as_str().as_bytes(),
            resource_type.as_str().as_bytes(),
            resource.as_bytes(),
        ])
        .map(ResourceKeyHmac::from_bytes)
    }
}

fn prefixed_uuid(
    prefix: &str,
    source_request_id: &RequestId,
    digest: [u8; 32],
) -> Result<String, ReasonCode> {
    let source = source_request_id
        .as_str()
        .strip_prefix("req_")
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(ReasonCode::ResponseValidationFailed)?;
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[..6].copy_from_slice(&source.as_bytes()[..6]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!("{prefix}{}", Uuid::from_bytes(bytes)))
}

fn hex(bytes: [u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(64);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}
