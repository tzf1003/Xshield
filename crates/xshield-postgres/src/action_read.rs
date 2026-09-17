use crate::{PostgresIdentityStore, StoreError};
use serde::Deserialize;
use serde_json::Value;
use sqlx::Row;
use std::collections::BTreeSet;
use xshield_core::{
    domain::{
        ActionId, FieldName, MappingRevision, OperationId, PageEvidenceId, PageTemplate,
        PolicyRevision, RequestId, ResourceType, ResponseEvidenceId, SiteId, TenantId, ViewProfile,
    },
    grant::ResourceKeyHmac,
    identity::UnixSeconds,
    ports::{UiActionProofQuery, UiActionProofState, UiActionProofStore},
    provenance::{
        ActionDescriptor, ActionGrant, ActionGrantDraft, ActionTarget, ActionTargetRule,
        BuildFingerprint, HttpMethod, PageEvidence, ProvenanceError, ResponseEvidence,
        RouteTemplate,
    },
};

/// Exact versioned descriptor lookup used before response-derived issuance.
pub struct ResponseActionDescriptorQuery<'a> {
    /// Tenant fixed by trusted listener configuration.
    pub tenant_id: &'a TenantId,
    /// Site fixed by trusted listener configuration.
    pub site_id: &'a SiteId,
    /// Action selected by the target operation configuration.
    pub action_id: &'a ActionId,
    /// Exact operation the response may qualify.
    pub operation_id: &'a OperationId,
    /// Active policy revision fixed by gateway configuration.
    pub policy_revision: &'a PolicyRevision,
    /// Exact versioned UI mapping fixed by response configuration.
    pub mapping_revision: &'a MappingRevision,
}

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

impl PostgresIdentityStore {
    /// Loads one exact approved target descriptor for response-derived issuance.
    ///
    /// The issuance transaction rechecks every returned field under a row lock,
    /// so retirement between this read and commit cannot create authority.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or corrupt persisted values.
    pub async fn load_response_action_descriptor(
        &self,
        query: ResponseActionDescriptorQuery<'_>,
    ) -> Result<Option<ActionDescriptor>, StoreError> {
        let row = sqlx::query(
            "SELECT page_template, method, route_template, target_rule,
                    allowed_fields, field_profile
             FROM xshield.action_descriptors
             WHERE tenant_id = $1 AND site_id = $2 AND action_id = $3
               AND operation_id = $4 AND policy_revision = $5
               AND mapping_revision = $6 AND status = 'approved'",
        )
        .bind(query.tenant_id.as_str())
        .bind(query.site_id.as_str())
        .bind(query.action_id.as_str())
        .bind(query.operation_id.as_str())
        .bind(query.policy_revision.as_str())
        .bind(query.mapping_revision.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(ActionDescriptor::approved(
                query.action_id.clone(),
                parse(
                    row.try_get("page_template")?,
                    "page_template",
                    PageTemplate::parse,
                )?,
                query.operation_id.clone(),
                method(row.try_get("method")?)?,
                RouteTemplate::parse(row.try_get::<&str, _>("route_template")?)
                    .map_err(|_| StoreError::CorruptData("route_template"))?,
                target_rule(row.try_get("target_rule")?)?,
                fields(row.try_get("allowed_fields")?, "allowed_fields")?,
                parse(
                    row.try_get("field_profile")?,
                    "field_profile",
                    ViewProfile::parse,
                )?,
                query.policy_revision.clone(),
                query.mapping_revision.clone(),
            ))
        })
        .transpose()
    }
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
                    action.response_evidence_id,
                    action.source_action_ref, action.operation_id,
                    action.target_constraints, action.field_profile,
                    action.policy_revision, action.mapping_revision, action.method,
                    action.route_template, action.allowed_fields,
                    extract(epoch FROM action.issued_at)::bigint AS action_issued_at,
                    extract(epoch FROM action.expires_at)::bigint AS action_expires_at,
                    page.page_template, page.build_fingerprint,
                    extract(epoch FROM page.verified_at)::bigint AS page_verified_at,
                    extract(epoch FROM page.expires_at)::bigint AS page_expires_at,
                    response.source_operation_id, response.target_operation_id,
                    response.response_status,
                    extract(epoch FROM response.verified_at)::bigint AS response_verified_at,
                    extract(epoch FROM response.expires_at)::bigint AS response_expires_at,
                    descriptor.page_template AS descriptor_page_template,
                    descriptor.target_rule, descriptor.allowed_fields AS descriptor_fields
             FROM xshield.ui_actions action
             LEFT JOIN xshield.page_evidence page
               ON page.tenant_id = action.tenant_id
              AND page.site_id = action.site_id
              AND page.page_evidence_id = action.page_evidence_id
              AND page.binding_id = action.binding_id
              AND page.auth_epoch = action.auth_epoch
              AND page.source_request_id = action.source_request_id
              AND page.policy_revision = action.policy_revision
              AND page.mapping_revision = action.mapping_revision
             LEFT JOIN xshield.response_evidence response
               ON response.tenant_id = action.tenant_id
              AND response.site_id = action.site_id
              AND response.response_evidence_id = action.response_evidence_id
              AND response.binding_id = action.binding_id
              AND response.auth_epoch = action.auth_epoch
              AND response.source_request_id = action.source_request_id
              AND response.target_operation_id = action.operation_id
              AND response.policy_revision = action.policy_revision
             JOIN xshield.action_descriptors descriptor
               ON descriptor.tenant_id = action.tenant_id
              AND descriptor.site_id = action.site_id
              AND descriptor.action_id = action.source_action_ref
              AND descriptor.policy_revision = action.policy_revision
              AND descriptor.mapping_revision = action.mapping_revision
              AND descriptor.operation_id = action.operation_id
              AND descriptor.method = action.method
              AND descriptor.route_template = action.route_template
              AND descriptor.field_profile = action.field_profile
              AND (action.response_evidence_id IS NOT NULL
                   OR descriptor.page_template = page.page_template)
             JOIN xshield.policy_revisions policy
               ON policy.tenant_id = action.tenant_id
              AND policy.site_id = action.site_id
              AND policy.revision = action.policy_revision
             WHERE action.tenant_id = $1 AND action.site_id = $2
               AND action.action_ref = $3 AND action.binding_id = $4
               AND action.auth_epoch = $5 AND action.policy_revision = $6
               AND action.status = 'active' AND action.expires_at > to_timestamp($7)
               AND ((page.page_evidence_id IS NOT NULL
                     AND page.status = 'verified' AND page.expires_at > to_timestamp($7))
                    OR (response.response_evidence_id IS NOT NULL
                        AND response.status = 'verified'
                        AND response.expires_at > to_timestamp($7)))
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

#[allow(clippy::too_many_lines)]
fn rehydrate_action(
    row: &sqlx::postgres::PgRow,
    query: &UiActionProofQuery<'_>,
) -> Result<ActionGrant, StoreError> {
    let mapping_revision = parse(
        row.try_get("mapping_revision")?,
        "mapping_revision",
        MappingRevision::parse,
    )?;
    let descriptor = ActionDescriptor::approved(
        parse(
            row.try_get("source_action_ref")?,
            "source_action_ref",
            ActionId::parse,
        )?,
        parse(
            row.try_get("descriptor_page_template")?,
            "descriptor_page_template",
            PageTemplate::parse,
        )?,
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
        mapping_revision.clone(),
    );
    let draft = ActionGrantDraft {
        action_ref: query.action_ref.clone(),
        target: target(row.try_get("target_constraints")?)?,
        fields: fields(row.try_get("allowed_fields")?, "allowed_fields")?,
        expires_at: time(row, "action_expires_at")?,
    };
    let issued_at = time(row, "action_issued_at")?;
    if let Some(page_evidence_id) = row.try_get::<Option<&str>, _>("page_evidence_id")? {
        let evidence = PageEvidence::verified(
            parse(page_evidence_id, "page_evidence_id", PageEvidenceId::parse)?,
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
            mapping_revision,
            time(row, "page_expires_at")?,
            time(row, "page_verified_at")?,
        )
        .map_err(|_| StoreError::CorruptData("page_evidence"))?;
        return ActionGrant::issue(
            query.binding,
            query.snapshot,
            &evidence,
            &descriptor,
            draft,
            issued_at,
        )
        .map_err(|_| StoreError::CorruptData("ui_action"));
    }

    let evidence = ResponseEvidence::verified(
        parse(
            row.try_get("response_evidence_id")?,
            "response_evidence_id",
            ResponseEvidenceId::parse,
        )?,
        query.binding,
        query.snapshot.clone(),
        parse(
            row.try_get("source_request_id")?,
            "source_request_id",
            RequestId::parse,
        )?,
        parse(
            row.try_get("source_operation_id")?,
            "source_operation_id",
            OperationId::parse,
        )?,
        parse(
            row.try_get("target_operation_id")?,
            "target_operation_id",
            OperationId::parse,
        )?,
        u16::try_from(row.try_get::<i32, _>("response_status")?)
            .map_err(|_| StoreError::CorruptData("response_status"))?,
        query.policy_revision.clone(),
        time(row, "response_expires_at")?,
        time(row, "response_verified_at")?,
    )
    .map_err(|_| StoreError::CorruptData("response_evidence"))?;
    ActionGrant::issue_from_response(
        query.binding,
        query.snapshot,
        &evidence,
        &descriptor,
        draft,
        issued_at,
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
