//! Atomic persistence for response-derived action and resource grant batches.

use crate::{PostgresIdentityStore, StoreError, to_i64};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use std::collections::BTreeSet;
use xshield_core::{
    audit::ReasonCode,
    domain::{ActionRef, EventId, GrantId, ResponseEvidenceId},
    grant::GrantDraft,
    identity::UnixSeconds,
    provenance::{ActionEvidenceRef, ActionGrant, ActionTarget, ResponseEvidence},
};

/// One response-derived action/resource pair and its durable audit event.
pub struct ResponseGrantItem<'a> {
    action: &'a ActionGrant,
    grant: &'a GrantDraft,
    constraints: &'a Value,
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> ResponseGrantItem<'a> {
    /// Validates the item-local JSON contracts.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] unless both JSON values are objects.
    pub fn new(
        action: &'a ActionGrant,
        grant: &'a GrantDraft,
        constraints: &'a Value,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        if !constraints.is_object() || !event_envelope.is_object() {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            action,
            grant,
            constraints,
            event_id,
            event_envelope,
        })
    }
}

/// Complete verified response batch ready for one short transaction.
pub struct ResponseGrantPersistence<'a> {
    evidence: &'a ResponseEvidence,
    response_artifact_ref: &'a str,
    items: &'a [ResponseGrantItem<'a>],
    now: UnixSeconds,
    max_active_grants: u32,
}

impl<'a> ResponseGrantPersistence<'a> {
    /// Validates cross-item identity, evidence, scope, lease, and uniqueness.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an incoherent or empty batch.
    pub fn new(
        evidence: &'a ResponseEvidence,
        response_artifact_ref: &'a str,
        items: &'a [ResponseGrantItem<'a>],
        now: UnixSeconds,
        max_active_grants: u32,
    ) -> Result<Self, StoreError> {
        let artifact_valid = !response_artifact_ref.is_empty()
            && response_artifact_ref.len() <= 512
            && response_artifact_ref
                .bytes()
                .all(|byte| !byte.is_ascii_control());
        if !artifact_valid
            || items.is_empty()
            || items.len() > 1_000
            || max_active_grants == 0
            || now < evidence.verified_at()
            || now >= evidence.expires_at()
        {
            return Err(StoreError::InvalidCommand);
        }

        let mut action_refs = BTreeSet::new();
        let mut grant_ids = BTreeSet::new();
        let mut issuance_keys = BTreeSet::new();
        let mut event_ids = BTreeSet::new();
        for item in items {
            let ActionEvidenceRef::Response(response_evidence_id) = item.action.evidence_ref()
            else {
                return Err(StoreError::InvalidCommand);
            };
            let target_matches = matches!(
                item.action.target(),
                ActionTarget::Resource { resource_type, resource_key }
                    if resource_type == &item.grant.resource_type
                        && resource_key == &item.grant.resource_key
            );
            if response_evidence_id != evidence.evidence_id()
                || item.action.snapshot() != evidence.snapshot()
                || item.action.source_request_id() != evidence.source_request_id()
                || item.action.operation_id() != evidence.target_operation_id()
                || item.action.operation_id() != &item.grant.operation_id
                || item.action.field_profile() != &item.grant.view_profile
                || item.action.policy_revision() != evidence.policy_revision()
                || item.action.policy_revision() != &item.grant.policy_revision
                || item.action.expires_at() != item.grant.expires_at
                || item.action.issued_at() != evidence.verified_at()
                || &item.grant.source_request_id != evidence.source_request_id()
                || !target_matches
                || !action_refs.insert(item.action.action_ref())
                || !grant_ids.insert(&item.grant.grant_id)
                || !issuance_keys.insert(&item.grant.issuance_key)
                || !event_ids.insert(item.event_id)
            {
                return Err(StoreError::InvalidCommand);
            }
        }

        Ok(Self {
            evidence,
            response_artifact_ref,
            items,
            now,
            max_active_grants,
        })
    }
}

/// One exact pair made durable by a response-grant transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedResponseGrant {
    /// Persisted resource grant identifier.
    pub grant_id: GrantId,
    /// Opaque action reference the client may present for this resource.
    pub action_ref: ActionRef,
}

/// Deterministic outcome of one all-or-nothing response grant batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseGrantWriteOutcome {
    /// Every action, resource grant, and outbox event was created.
    Created(Vec<CommittedResponseGrant>),
    /// The exact batch was already committed without extending leases.
    Existing(Vec<CommittedResponseGrant>),
    /// The response idempotency scope exists with different semantics.
    Conflict,
    /// Current identity, policy, descriptor, or evidence is no longer eligible.
    Ineligible,
    /// The complete batch would exceed the active-grant ceiling.
    CapacityExceeded,
}

impl ResponseGrantWriteOutcome {
    /// Returns the stable request-stage reason code.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Created(_) => ReasonCode::GrantIssued,
            Self::Existing(_) => ReasonCode::GrantAlreadyIssued,
            Self::Conflict => ReasonCode::GrantIssuanceConflict,
            Self::Ineligible => ReasonCode::GrantSourceIneligible,
            Self::CapacityExceeded => ReasonCode::GrantCapacityExceeded,
        }
    }
}

impl PostgresIdentityStore {
    /// Atomically commits every action/resource pair and its outbox event.
    ///
    /// The binding row serializes capacity and identity changes. Policy and
    /// descriptors are rechecked inside the same transaction; a replay must
    /// match the complete evidence batch before existing references are returned.
    ///
    /// # Errors
    /// Returns [`StoreError`] for numeric overflow, corrupt persisted values,
    /// or any database failure. Database errors leave no partially committed batch.
    pub async fn issue_response_grants(
        &self,
        command: ResponseGrantPersistence<'_>,
    ) -> Result<ResponseGrantWriteOutcome, StoreError> {
        let epoch = to_i64(command.evidence.snapshot().epoch().value(), "auth_epoch")?;
        let now = to_i64(command.now.value(), "now")?;
        let verified_at = to_i64(command.evidence.verified_at().value(), "verified_at")?;
        let expires_at = to_i64(command.evidence.expires_at().value(), "expires_at")?;
        let candidate_count = i32::try_from(command.items.len())
            .map_err(|_| StoreError::NumericRange("candidate_count"))?;
        let mut transaction = self.pool.begin().await?;

        if !lock_binding(&mut transaction, &command, epoch, now, expires_at).await?
            || !lock_policy(&mut transaction, &command).await?
        {
            transaction.rollback().await?;
            return Ok(ResponseGrantWriteOutcome::Ineligible);
        }
        for item in command.items {
            if !descriptor_is_eligible(&mut transaction, &command, item).await? {
                transaction.rollback().await?;
                return Ok(ResponseGrantWriteOutcome::Ineligible);
            }
        }

        match existing_evidence(
            &mut transaction,
            &command,
            epoch,
            verified_at,
            expires_at,
            candidate_count,
        )
        .await?
        {
            ExistingEvidence::Conflict => {
                transaction.rollback().await?;
                return Ok(ResponseGrantWriteOutcome::Conflict);
            }
            ExistingEvidence::Existing(evidence_id) => {
                let Some(existing) =
                    existing_batch(&mut transaction, &command, &evidence_id).await?
                else {
                    transaction.rollback().await?;
                    return Ok(ResponseGrantWriteOutcome::Conflict);
                };
                transaction.rollback().await?;
                return Ok(ResponseGrantWriteOutcome::Existing(existing));
            }
            ExistingEvidence::Missing => {}
        }

        let active = active_grant_count(&mut transaction, &command, epoch, now).await?;
        let requested = i64::from(candidate_count);
        if active
            .checked_add(requested)
            .is_none_or(|total| total > i64::from(command.max_active_grants))
        {
            transaction.rollback().await?;
            return Ok(ResponseGrantWriteOutcome::CapacityExceeded);
        }

        insert_evidence(
            &mut transaction,
            &command,
            epoch,
            verified_at,
            expires_at,
            candidate_count,
        )
        .await?;
        let mut committed = Vec::with_capacity(command.items.len());
        // ponytail: bounded 1000-row transaction; batch SQL when measured commit latency needs it.
        for item in command.items {
            insert_item(&mut transaction, &command, item, epoch, expires_at).await?;
            committed.push(CommittedResponseGrant {
                grant_id: item.grant.grant_id.clone(),
                action_ref: item.action.action_ref().clone(),
            });
        }
        transaction.commit().await?;
        Ok(ResponseGrantWriteOutcome::Created(committed))
    }
}

async fn lock_binding(
    connection: &mut PgConnection,
    command: &ResponseGrantPersistence<'_>,
    epoch: i64,
    now: i64,
    expires_at: i64,
) -> Result<bool, StoreError> {
    let found: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM xshield.auth_bindings
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
           AND principal_ref = $4 AND auth_epoch = $5 AND status = 'active'
           AND absolute_expires_at > to_timestamp($6)
           AND absolute_expires_at >= to_timestamp($7)
         FOR UPDATE",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(command.evidence.snapshot().binding_id().as_str())
    .bind(command.evidence.snapshot().principal_ref())
    .bind(epoch)
    .bind(now)
    .bind(expires_at)
    .fetch_optional(connection)
    .await?;
    Ok(found.is_some())
}

async fn lock_policy(
    connection: &mut PgConnection,
    command: &ResponseGrantPersistence<'_>,
) -> Result<bool, StoreError> {
    let found: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM xshield.policy_revisions
         WHERE tenant_id = $1 AND site_id = $2 AND revision = $3 AND status = 'active'
         FOR SHARE",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(command.evidence.policy_revision().as_str())
    .fetch_optional(connection)
    .await?;
    Ok(found.is_some())
}

async fn descriptor_is_eligible(
    connection: &mut PgConnection,
    command: &ResponseGrantPersistence<'_>,
    item: &ResponseGrantItem<'_>,
) -> Result<bool, StoreError> {
    let target_rule = json!({
        "kind": "resource",
        "resource_type": item.grant.resource_type.as_str(),
    });
    let fields = field_values(item.action);
    let found: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM xshield.action_descriptors
         WHERE tenant_id = $1 AND site_id = $2 AND action_id = $3
           AND operation_id = $4 AND method = $5 AND route_template = $6
           AND target_rule = $7 AND allowed_fields @> $8 AND field_profile = $9
           AND policy_revision = $10 AND mapping_revision = $11 AND status = 'approved'
         FOR SHARE",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(item.action.action_id().as_str())
    .bind(item.action.operation_id().as_str())
    .bind(item.action.method().as_str())
    .bind(item.action.route().as_str())
    .bind(target_rule)
    .bind(fields)
    .bind(item.action.field_profile().as_str())
    .bind(item.action.policy_revision().as_str())
    .bind(item.action.mapping_revision().as_str())
    .fetch_optional(connection)
    .await?;
    Ok(found.is_some())
}

enum ExistingEvidence {
    Missing,
    Existing(ResponseEvidenceId),
    Conflict,
}

#[allow(clippy::too_many_arguments)]
async fn existing_evidence(
    connection: &mut PgConnection,
    command: &ResponseGrantPersistence<'_>,
    epoch: i64,
    verified_at: i64,
    expires_at: i64,
    candidate_count: i32,
) -> Result<ExistingEvidence, StoreError> {
    let row = sqlx::query(
        "SELECT response_evidence_id, binding_id, auth_epoch, response_status,
                response_artifact_ref, candidate_count, status,
                extract(epoch FROM verified_at)::bigint AS verified_at,
                extract(epoch FROM expires_at)::bigint AS expires_at
         FROM xshield.response_evidence
         WHERE tenant_id = $1 AND site_id = $2 AND source_request_id = $3
           AND source_operation_id = $4 AND target_operation_id = $5
           AND policy_revision = $6
         FOR UPDATE",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(command.evidence.source_request_id().as_str())
    .bind(command.evidence.source_operation_id().as_str())
    .bind(command.evidence.target_operation_id().as_str())
    .bind(command.evidence.policy_revision().as_str())
    .fetch_optional(connection)
    .await?;
    let Some(row) = row else {
        return Ok(ExistingEvidence::Missing);
    };
    let same = row.try_get::<&str, _>("binding_id")?
        == command.evidence.snapshot().binding_id().as_str()
        && row.try_get::<i64, _>("auth_epoch")? == epoch
        && row.try_get::<i32, _>("response_status")?
            == i32::from(command.evidence.response_status())
        && row.try_get::<&str, _>("response_artifact_ref")? == command.response_artifact_ref
        && row.try_get::<i32, _>("candidate_count")? == candidate_count
        && row.try_get::<&str, _>("status")? == "verified"
        && row.try_get::<i64, _>("verified_at")? == verified_at
        && row.try_get::<i64, _>("expires_at")? == expires_at;
    if !same {
        return Ok(ExistingEvidence::Conflict);
    }
    ResponseEvidenceId::parse(row.try_get::<&str, _>("response_evidence_id")?)
        .map(ExistingEvidence::Existing)
        .map_err(|_| StoreError::CorruptData("response_evidence_id"))
}

async fn existing_batch(
    connection: &mut PgConnection,
    command: &ResponseGrantPersistence<'_>,
    evidence_id: &ResponseEvidenceId,
) -> Result<Option<Vec<CommittedResponseGrant>>, StoreError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.ui_actions
         WHERE tenant_id = $1 AND site_id = $2 AND response_evidence_id = $3",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(evidence_id.as_str())
    .fetch_one(&mut *connection)
    .await?;
    if usize::try_from(count).ok() != Some(command.items.len()) {
        return Ok(None);
    }
    let mut committed = Vec::with_capacity(command.items.len());
    for item in command.items {
        let Some(value) = existing_item(connection, command, evidence_id, item).await? else {
            return Ok(None);
        };
        committed.push(value);
    }
    Ok(Some(committed))
}

async fn existing_item(
    connection: &mut PgConnection,
    command: &ResponseGrantPersistence<'_>,
    evidence_id: &ResponseEvidenceId,
    item: &ResponseGrantItem<'_>,
) -> Result<Option<CommittedResponseGrant>, StoreError> {
    let row = sqlx::query(
        "SELECT grant_row.grant_id, grant_row.action_ref, grant_row.binding_id,
                grant_row.auth_epoch, grant_row.resource_type, grant_row.resource_key_hmac,
                grant_row.operation_id, grant_row.view_id, grant_row.constraints,
                grant_row.source_event_id, grant_row.policy_revision,
                extract(epoch FROM grant_row.expires_at)::bigint AS grant_expires_at,
                action.source_request_id, action.response_evidence_id,
                action.source_action_ref, action.target_constraints,
                action.field_profile, action.mapping_revision, action.method,
                action.route_template, action.allowed_fields,
                extract(epoch FROM action.issued_at)::bigint AS action_issued_at,
                extract(epoch FROM action.expires_at)::bigint AS action_expires_at,
                event.event_type, event.aggregate_ref, event.envelope
         FROM xshield.resource_grants grant_row
         JOIN xshield.ui_actions action
           ON action.tenant_id = grant_row.tenant_id AND action.site_id = grant_row.site_id
          AND action.action_ref = grant_row.action_ref
         JOIN xshield.audit_outbox event ON event.event_id = grant_row.source_event_id
         WHERE grant_row.tenant_id = $1 AND grant_row.site_id = $2
           AND grant_row.issuance_key = $3",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(item.grant.issuance_key.as_str())
    .fetch_optional(connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let expected_target = target_value(item.action.target())?;
    let same = row.try_get::<&str, _>("binding_id")?
        == command.evidence.snapshot().binding_id().as_str()
        && row.try_get::<i64, _>("auth_epoch")?
            == to_i64(command.evidence.snapshot().epoch().value(), "auth_epoch")?
        && row.try_get::<&str, _>("resource_type")? == item.grant.resource_type.as_str()
        && row.try_get::<Vec<u8>, _>("resource_key_hmac")?.as_slice()
            == item.grant.resource_key.as_bytes()
        && row.try_get::<&str, _>("operation_id")? == item.grant.operation_id.as_str()
        && row.try_get::<&str, _>("view_id")? == item.grant.view_profile.as_str()
        && row.try_get::<Value, _>("constraints")? == *item.constraints
        && row.try_get::<&str, _>("source_event_id")? == item.event_id.as_str()
        && row.try_get::<&str, _>("policy_revision")? == item.grant.policy_revision.as_str()
        && row.try_get::<i64, _>("grant_expires_at")?
            == to_i64(item.grant.expires_at.value(), "expires_at")?
        && row.try_get::<&str, _>("source_request_id")? == item.action.source_request_id().as_str()
        && row.try_get::<Option<&str>, _>("response_evidence_id")? == Some(evidence_id.as_str())
        && row.try_get::<&str, _>("source_action_ref")? == item.action.action_id().as_str()
        && row.try_get::<Value, _>("target_constraints")? == expected_target
        && row.try_get::<&str, _>("field_profile")? == item.action.field_profile().as_str()
        && row.try_get::<&str, _>("mapping_revision")? == item.action.mapping_revision().as_str()
        && row.try_get::<&str, _>("method")? == item.action.method().as_str()
        && row.try_get::<&str, _>("route_template")? == item.action.route().as_str()
        && row.try_get::<Value, _>("allowed_fields")? == field_values(item.action)
        && row.try_get::<i64, _>("action_issued_at")?
            == to_i64(item.action.issued_at().value(), "issued_at")?
        && row.try_get::<i64, _>("action_expires_at")?
            == to_i64(item.action.expires_at().value(), "expires_at")?
        && row.try_get::<&str, _>("event_type")? == "response_grant.issued"
        && row.try_get::<&str, _>("aggregate_ref")? == row.try_get::<&str, _>("grant_id")?
        && row.try_get::<Value, _>("envelope")? == *item.event_envelope;
    if !same {
        return Ok(None);
    }
    Ok(Some(CommittedResponseGrant {
        grant_id: GrantId::parse(row.try_get::<&str, _>("grant_id")?)
            .map_err(|_| StoreError::CorruptData("grant_id"))?,
        action_ref: ActionRef::parse(row.try_get::<&str, _>("action_ref")?)
            .map_err(|_| StoreError::CorruptData("action_ref"))?,
    }))
}

async fn active_grant_count(
    connection: &mut PgConnection,
    command: &ResponseGrantPersistence<'_>,
    epoch: i64,
    now: i64,
) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM xshield.resource_grants
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
           AND auth_epoch = $4 AND status = 'active' AND expires_at > to_timestamp($5)",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(command.evidence.snapshot().binding_id().as_str())
    .bind(epoch)
    .bind(now)
    .fetch_one(connection)
    .await?)
}

#[allow(clippy::too_many_arguments)]
async fn insert_evidence(
    connection: &mut PgConnection,
    command: &ResponseGrantPersistence<'_>,
    epoch: i64,
    verified_at: i64,
    expires_at: i64,
    candidate_count: i32,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO xshield.response_evidence (
            tenant_id, site_id, response_evidence_id, binding_id, auth_epoch,
            source_request_id, source_operation_id, target_operation_id,
            response_status, response_artifact_ref, candidate_count,
            policy_revision, status, verified_at, expires_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, 'verified', to_timestamp($13), to_timestamp($14)
         )",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(command.evidence.evidence_id().as_str())
    .bind(command.evidence.snapshot().binding_id().as_str())
    .bind(epoch)
    .bind(command.evidence.source_request_id().as_str())
    .bind(command.evidence.source_operation_id().as_str())
    .bind(command.evidence.target_operation_id().as_str())
    .bind(i32::from(command.evidence.response_status()))
    .bind(command.response_artifact_ref)
    .bind(candidate_count)
    .bind(command.evidence.policy_revision().as_str())
    .bind(verified_at)
    .bind(expires_at)
    .execute(connection)
    .await?;
    Ok(())
}

async fn insert_item(
    connection: &mut PgConnection,
    command: &ResponseGrantPersistence<'_>,
    item: &ResponseGrantItem<'_>,
    epoch: i64,
    expires_at: i64,
) -> Result<(), StoreError> {
    let target = target_value(item.action.target())?;
    sqlx::query(
        "INSERT INTO xshield.ui_actions (
            tenant_id, site_id, action_ref, binding_id, auth_epoch,
            source_request_id, page_evidence_id, response_evidence_id,
            source_action_ref, operation_id, target_constraints, field_profile,
            source_rule, policy_revision, status, issued_at, expires_at,
            mapping_revision, method, route_template, allowed_fields
         ) VALUES (
            $1, $2, $3, $4, $5, $6, NULL, $7, $8, $9, $10, $11,
            $12, $13, 'active', to_timestamp($14), to_timestamp($15),
            $16, $17, $18, $19
         )",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(item.action.action_ref().as_str())
    .bind(command.evidence.snapshot().binding_id().as_str())
    .bind(epoch)
    .bind(command.evidence.source_request_id().as_str())
    .bind(command.evidence.evidence_id().as_str())
    .bind(item.action.action_id().as_str())
    .bind(item.action.operation_id().as_str())
    .bind(target)
    .bind(item.action.field_profile().as_str())
    .bind(command.evidence.source_operation_id().as_str())
    .bind(item.action.policy_revision().as_str())
    .bind(to_i64(item.action.issued_at().value(), "issued_at")?)
    .bind(expires_at)
    .bind(item.action.mapping_revision().as_str())
    .bind(item.action.method().as_str())
    .bind(item.action.route().as_str())
    .bind(field_values(item.action))
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "INSERT INTO xshield.resource_grants (
            tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref,
            resource_type, resource_key_hmac, operation_id, view_id, constraints,
            source_event_id, issuance_key, policy_revision, status, issued_at, expires_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13, $14, 'active', to_timestamp($15), to_timestamp($16)
         )",
    )
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(item.grant.grant_id.as_str())
    .bind(command.evidence.snapshot().binding_id().as_str())
    .bind(epoch)
    .bind(item.action.action_ref().as_str())
    .bind(item.grant.resource_type.as_str())
    .bind(item.grant.resource_key.as_bytes().as_slice())
    .bind(item.grant.operation_id.as_str())
    .bind(item.grant.view_profile.as_str())
    .bind(item.constraints)
    .bind(item.event_id.as_str())
    .bind(item.grant.issuance_key.as_str())
    .bind(item.grant.policy_revision.as_str())
    .bind(to_i64(item.action.issued_at().value(), "issued_at")?)
    .bind(expires_at)
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, 'response_grant.issued', $5)",
    )
    .bind(item.event_id.as_str())
    .bind(command.evidence.snapshot().tenant_id().as_str())
    .bind(command.evidence.snapshot().site_id().as_str())
    .bind(item.grant.grant_id.as_str())
    .bind(item.event_envelope)
    .execute(connection)
    .await?;
    Ok(())
}

fn field_values(action: &ActionGrant) -> Value {
    Value::Array(
        action
            .fields()
            .iter()
            .map(|field| Value::String(field.as_str().to_owned()))
            .collect(),
    )
}

fn target_value(target: &ActionTarget) -> Result<Value, StoreError> {
    let ActionTarget::Resource {
        resource_type,
        resource_key,
    } = target
    else {
        return Err(StoreError::InvalidCommand);
    };
    Ok(json!({
        "kind": "resource",
        "resource_type": resource_type.as_str(),
        "resource_key_hmac": hex(resource_key.as_bytes()),
    }))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}
