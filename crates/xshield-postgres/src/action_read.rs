use crate::{PostgresIdentityStore, StoreError};
use serde::Deserialize;
use serde_json::Value;
use sqlx::Row;
use std::collections::BTreeSet;
use xshield_core::{
    domain::{
        ActionId, FieldName, MappingRevision, OperationId, PageEvidenceId, PageTemplate, RequestId,
        ResourceType, ViewProfile,
    },
    grant::ResourceKeyHmac,
    identity::UnixSeconds,
    ports::{UiActionProofQuery, UiActionProofState, UiActionProofStore},
    provenance::{
        ActionDescriptor, ActionGrant, ActionGrantDraft, ActionTarget, ActionTargetRule,
        BuildFingerprint, HttpMethod, PageEvidence, ProvenanceError, RouteTemplate,
    },
};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TargetRuleDto {
    None,
    VerifiedPrincipal,
    Resource { resource_type: String },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TargetDto {
    None,
    Principal {
        principal_ref: String,
    },
    Resource {
        resource_type: String,
        resource_key_hmac: String,
    },
}

impl UiActionProofStore for PostgresIdentityStore {
    type Error = StoreError;

    async fn load_ui_action<'a>(
        &'a self,
        query: UiActionProofQuery<'a>,
    ) -> Result<UiActionProofState, StoreError> {
        let now = i64::try_from(query.now.value()).map_err(|_| StoreError::NumericRange("now"))?;
        let epoch = i64::try_from(query.snapshot.epoch().value())
            .map_err(|_| StoreError::NumericRange("auth_epoch"))?;
        let row = sqlx::query(
            "SELECT action.source_request_id, action.page_evidence_id,
                    action.source_action_ref, action.operation_id,
                    action.target_constraints, action.field_profile,
                    action.policy_revision, action.mapping_revision, action.method,
                    action.route_template, action.allowed_fields,
                    extract(epoch FROM action.issued_at)::bigint AS action_issued_at,
                    extract(epoch FROM action.expires_at)::bigint AS action_expires_at,
                    evidence.page_template, evidence.build_fingerprint,
                    extract(epoch FROM evidence.verified_at)::bigint AS evidence_verified_at,
                    extract(epoch FROM evidence.expires_at)::bigint AS evidence_expires_at,
                    descriptor.target_rule, descriptor.allowed_fields AS descriptor_fields
             FROM xshield.ui_actions action
             JOIN xshield.page_evidence evidence
               ON evidence.tenant_id = action.tenant_id
              AND evidence.site_id = action.site_id
              AND evidence.page_evidence_id = action.page_evidence_id
              AND evidence.binding_id = action.binding_id
              AND evidence.auth_epoch = action.auth_epoch
              AND evidence.source_request_id = action.source_request_id
              AND evidence.policy_revision = action.policy_revision
              AND evidence.mapping_revision = action.mapping_revision
             JOIN xshield.action_descriptors descriptor
               ON descriptor.tenant_id = action.tenant_id
              AND descriptor.site_id = action.site_id
              AND descriptor.action_id = action.source_action_ref
              AND descriptor.policy_revision = action.policy_revision
              AND descriptor.mapping_revision = action.mapping_revision
              AND descriptor.page_template = evidence.page_template
              AND descriptor.operation_id = action.operation_id
              AND descriptor.method = action.method
              AND descriptor.route_template = action.route_template
              AND descriptor.field_profile = action.field_profile
             JOIN xshield.policy_revisions policy
               ON policy.tenant_id = action.tenant_id
              AND policy.site_id = action.site_id
              AND policy.revision = action.policy_revision
             WHERE action.tenant_id = $1 AND action.site_id = $2
               AND action.action_ref = $3 AND action.binding_id = $4
               AND action.auth_epoch = $5 AND action.policy_revision = $6
               AND action.status = 'active' AND action.expires_at > to_timestamp($7)
               AND evidence.status = 'verified' AND evidence.expires_at > to_timestamp($7)
               AND descriptor.status = 'approved' AND policy.status = 'active'",
        )
        .bind(query.snapshot.tenant_id().as_str())
        .bind(query.snapshot.site_id().as_str())
        .bind(query.action_ref.as_str())
        .bind(query.snapshot.binding_id().as_str())
        .bind(epoch)
        .bind(query.policy_revision.as_str())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(UiActionProofState::Denied(
                ProvenanceError::ActionUnavailable,
            ));
        };
        Ok(UiActionProofState::Verified(Box::new(rehydrate_action(
            &row, &query,
        )?)))
    }
}

fn rehydrate_action(
    row: &sqlx::postgres::PgRow,
    query: &UiActionProofQuery<'_>,
) -> Result<ActionGrant, StoreError> {
    let evidence = PageEvidence::verified(
        parse(
            row.try_get("page_evidence_id")?,
            "page_evidence_id",
            PageEvidenceId::parse,
        )?,
        query.binding,
        query.snapshot.clone(),
        parse(
            row.try_get("source_request_id")?,
            "source_request_id",
            RequestId::parse,
        )?,
        parse(
            row.try_get("page_template")?,
            "page_template",
            PageTemplate::parse,
        )?,
        build_fingerprint(row.try_get("build_fingerprint")?)?,
        query.policy_revision.clone(),
        parse(
            row.try_get("mapping_revision")?,
            "mapping_revision",
            MappingRevision::parse,
        )?,
        time(row, "evidence_expires_at")?,
        time(row, "evidence_verified_at")?,
    )
    .map_err(|_| StoreError::CorruptData("page_evidence"))?;
    let descriptor = ActionDescriptor::approved(
        parse(
            row.try_get("source_action_ref")?,
            "source_action_ref",
            ActionId::parse,
        )?,
        evidence.page_template().clone(),
        parse(
            row.try_get("operation_id")?,
            "operation_id",
            OperationId::parse,
        )?,
        method(row.try_get("method")?)?,
        RouteTemplate::parse(row.try_get::<&str, _>("route_template")?)
            .map_err(|_| StoreError::CorruptData("route_template"))?,
        target_rule(row.try_get("target_rule")?)?,
        fields(row.try_get("descriptor_fields")?, "descriptor_fields")?,
        parse(
            row.try_get("field_profile")?,
            "field_profile",
            ViewProfile::parse,
        )?,
        query.policy_revision.clone(),
        evidence.mapping_revision().clone(),
    );
    ActionGrant::issue(
        query.binding,
        query.snapshot,
        &evidence,
        &descriptor,
        ActionGrantDraft {
            action_ref: query.action_ref.clone(),
            target: target(row.try_get("target_constraints")?)?,
            fields: fields(row.try_get("allowed_fields")?, "allowed_fields")?,
            expires_at: time(row, "action_expires_at")?,
        },
        time(row, "action_issued_at")?,
    )
    .map_err(|_| StoreError::CorruptData("ui_action"))
}

fn parse<T, E>(
    value: &str,
    field: &'static str,
    parser: impl FnOnce(String) -> Result<T, E>,
) -> Result<T, StoreError> {
    parser(value.to_owned()).map_err(|_| StoreError::CorruptData(field))
}

fn time(row: &sqlx::postgres::PgRow, field: &'static str) -> Result<UnixSeconds, StoreError> {
    let value = row.try_get::<i64, _>(field)?;
    Ok(UnixSeconds::new(
        u64::try_from(value).map_err(|_| StoreError::CorruptData(field))?,
    ))
}

fn method(value: &str) -> Result<HttpMethod, StoreError> {
    match value {
        "GET" => Ok(HttpMethod::Get),
        "POST" => Ok(HttpMethod::Post),
        "PUT" => Ok(HttpMethod::Put),
        "PATCH" => Ok(HttpMethod::Patch),
        "DELETE" => Ok(HttpMethod::Delete),
        _ => Err(StoreError::CorruptData("method")),
    }
}

fn fields(value: Value, field: &'static str) -> Result<BTreeSet<FieldName>, StoreError> {
    let values: Vec<String> =
        serde_json::from_value(value).map_err(|_| StoreError::CorruptData(field))?;
    let mut fields = BTreeSet::new();
    for value in values {
        let value = FieldName::parse(value).map_err(|_| StoreError::CorruptData(field))?;
        if !fields.insert(value) {
            return Err(StoreError::CorruptData(field));
        }
    }
    Ok(fields)
}

fn target_rule(value: Value) -> Result<ActionTargetRule, StoreError> {
    match serde_json::from_value(value).map_err(|_| StoreError::CorruptData("target_rule"))? {
        TargetRuleDto::None => Ok(ActionTargetRule::None),
        TargetRuleDto::VerifiedPrincipal => Ok(ActionTargetRule::VerifiedPrincipal),
        TargetRuleDto::Resource { resource_type } => Ok(ActionTargetRule::Resource(
            ResourceType::parse(resource_type)
                .map_err(|_| StoreError::CorruptData("target_rule"))?,
        )),
    }
}

fn target(value: Value) -> Result<ActionTarget, StoreError> {
    match serde_json::from_value(value)
        .map_err(|_| StoreError::CorruptData("target_constraints"))?
    {
        TargetDto::None => Ok(ActionTarget::None),
        TargetDto::Principal { principal_ref } => Ok(ActionTarget::Principal(principal_ref)),
        TargetDto::Resource {
            resource_type,
            resource_key_hmac,
        } => Ok(ActionTarget::Resource {
            resource_type: ResourceType::parse(resource_type)
                .map_err(|_| StoreError::CorruptData("target_constraints"))?,
            resource_key: ResourceKeyHmac::parse(&resource_key_hmac)
                .map_err(|_| StoreError::CorruptData("target_constraints"))?,
        }),
    }
}

fn build_fingerprint(value: Vec<u8>) -> Result<BuildFingerprint, StoreError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| StoreError::CorruptData("build_fingerprint"))?;
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| StoreError::CorruptData("build_fingerprint"))?;
    }
    BuildFingerprint::parse(&encoded).map_err(|_| StoreError::CorruptData("build_fingerprint"))
}
