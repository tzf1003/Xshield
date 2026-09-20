use crate::{PostgresIdentityStore, StoreError, to_i64};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use xshield_core::{
    audit::ReasonCode,
    domain::{ActionRef, EventId, GrantId},
    grant::GrantDraft,
    identity::{AuthSnapshot, UnixSeconds},
};

/// Complete, previously verified grant issuance persistence command.
pub struct GrantPersistence<'a> {
    snapshot: &'a AuthSnapshot,
    draft: &'a GrantDraft,
    action_ref: &'a ActionRef,
    constraints: &'a Value,
    event_id: &'a EventId,
    event_envelope: &'a Value,
    now: UnixSeconds,
    max_active_grants: u32,
}

impl<'a> GrantPersistence<'a> {
    /// Validates transaction-local bounds and JSON objects.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an elapsed lease, zero
    /// capacity, or a non-object constraints/event value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot: &'a AuthSnapshot,
        draft: &'a GrantDraft,
        action_ref: &'a ActionRef,
        constraints: &'a Value,
        event_id: &'a EventId,
        event_envelope: &'a Value,
        now: UnixSeconds,
        max_active_grants: u32,
    ) -> Result<Self, StoreError> {
        if draft.expires_at <= now
            || max_active_grants == 0
            || !constraints.is_object()
            || !event_envelope.is_object()
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            snapshot,
            draft,
            action_ref,
            constraints,
            event_id,
            event_envelope,
            now,
            max_active_grants,
        })
    }
}

/// Deterministic result of a serialized grant write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantWriteOutcome {
    /// A new grant and outbox event committed.
    Created(GrantId),
    /// The same issuance was already committed without extending its lease.
    Existing(GrantId),
    /// The issuance key exists with different authorization semantics.
    Conflict,
    /// Identity, approved action, policy, or lease is no longer eligible.
    Ineligible,
    /// The configured active-grant bound has been reached.
    CapacityExceeded,
}

impl GrantWriteOutcome {
    /// Returns the stable reason written by the request-stage audit coordinator.
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
    /// Serializes one exact grant issuance and its outbox event.
    ///
    /// The binding row lock makes capacity checks deterministic across writers.
    /// Every query includes tenant and site scope. Existing issuance keys are
    /// compared field-by-field and never extend the original expiry.
    ///
    /// # Errors
    /// Returns [`StoreError`] for numeric overflow, corrupt stored identifiers,
    /// or a database/transaction failure.
    pub async fn issue_grant(
        &self,
        command: GrantPersistence<'_>,
    ) -> Result<GrantWriteOutcome, StoreError> {
        let epoch = to_i64(command.snapshot.epoch().value(), "auth_epoch")?;
        let now = to_i64(command.now.value(), "now")?;
        let expires_at = to_i64(command.draft.expires_at.value(), "expires_at")?;
        let mut transaction = self.pool.begin().await?;

        if !lock_eligible_binding(&mut transaction, &command, epoch, now, expires_at).await?
            || !action_is_eligible(&mut transaction, &command, epoch, now, expires_at).await?
        {
            transaction.rollback().await?;
            return Ok(GrantWriteOutcome::Ineligible);
        }

        // Row-lock predicates may have run before waiting for another writer.
        // A frozen request timestamp must never extend any authority lease.
        if !lease_is_live(&mut transaction, expires_at).await? {
            transaction.rollback().await?;
            return Ok(GrantWriteOutcome::Ineligible);
        }
        if let Some(outcome) =
            existing_outcome(&mut transaction, &command, epoch, now, expires_at).await?
        {
            transaction.rollback().await?;
            return Ok(outcome);
        }

        let active_count = active_grant_count(&mut transaction, &command, epoch, now).await?;
        if active_count >= i64::from(command.max_active_grants) {
            transaction.rollback().await?;
            return Ok(GrantWriteOutcome::CapacityExceeded);
        }

        insert_grant_and_event(&mut transaction, &command, epoch, now, expires_at).await?;
        // Inserts can wait on uniqueness/FK constraints. Discard both rows if
        // that wait exhausted the requested lease before the commit boundary.
        if !lease_is_live(&mut transaction, expires_at).await? {
            transaction.rollback().await?;
            return Ok(GrantWriteOutcome::Ineligible);
        }
        transaction.commit().await?;
        Ok(GrantWriteOutcome::Created(command.draft.grant_id.clone()))
    }
}

async fn lease_is_live(connection: &mut PgConnection, expires_at: i64) -> Result<bool, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT to_timestamp($1) > clock_timestamp()")
            .bind(expires_at)
            .fetch_one(connection)
            .await?,
    )
}

async fn lock_eligible_binding(
    connection: &mut PgConnection,
    command: &GrantPersistence<'_>,
    epoch: i64,
    now: i64,
    expires_at: i64,
) -> Result<bool, StoreError> {
    let eligible: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM xshield.auth_bindings
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
           AND principal_ref = $4 AND authorization_context_ref = $5
           AND auth_epoch = $6 AND status = 'active'
           AND absolute_expires_at > GREATEST(to_timestamp($7), clock_timestamp())
           AND absolute_expires_at >= to_timestamp($8)
           AND to_timestamp($8) > clock_timestamp()
         FOR UPDATE",
    )
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.snapshot.binding_id().as_str())
    .bind(command.snapshot.principal_ref())
    .bind(command.snapshot.authorization_context_ref().as_str())
    .bind(epoch)
    .bind(now)
    .bind(expires_at)
    .fetch_optional(connection)
    .await?;
    Ok(eligible.is_some())
}

async fn action_is_eligible(
    connection: &mut PgConnection,
    command: &GrantPersistence<'_>,
    epoch: i64,
    now: i64,
    expires_at: i64,
) -> Result<bool, StoreError> {
    let eligible: Option<i32> = sqlx::query_scalar(
        "SELECT 1
         FROM xshield.ui_actions action
         JOIN xshield.policy_revisions policy
           ON policy.tenant_id = action.tenant_id
          AND policy.site_id = action.site_id
          AND policy.revision = action.policy_revision
         WHERE action.tenant_id = $1 AND action.site_id = $2
           AND action.action_ref = $3 AND action.binding_id = $4
           AND action.auth_epoch = $5 AND action.source_request_id = $6
           AND action.operation_id = $7 AND action.field_profile = $8
           AND action.policy_revision = $9
           AND action.status = 'active' AND policy.status = 'active'
           AND action.expires_at > GREATEST(to_timestamp($10), clock_timestamp())
           AND action.expires_at >= to_timestamp($11)
           AND to_timestamp($11) > clock_timestamp()
         FOR SHARE OF action, policy",
    )
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.action_ref.as_str())
    .bind(command.snapshot.binding_id().as_str())
    .bind(epoch)
    .bind(command.draft.source_request_id.as_str())
    .bind(command.draft.operation_id.as_str())
    .bind(command.draft.view_profile.as_str())
    .bind(command.draft.policy_revision.as_str())
    .bind(now)
    .bind(expires_at)
    .fetch_optional(connection)
    .await?;
    Ok(eligible.is_some())
}

async fn existing_outcome(
    connection: &mut PgConnection,
    command: &GrantPersistence<'_>,
    epoch: i64,
    issued_at: i64,
    expires_at: i64,
) -> Result<Option<GrantWriteOutcome>, StoreError> {
    let existing = sqlx::query(
        "SELECT resource_grant.grant_id, resource_grant.binding_id, resource_grant.auth_epoch,
                resource_grant.action_ref, resource_grant.resource_type,
                resource_grant.resource_key_hmac, resource_grant.operation_id,
                resource_grant.view_id, resource_grant.constraints,
                resource_grant.source_event_id, resource_grant.policy_revision,
                resource_grant.status,
                extract(epoch FROM resource_grant.issued_at)::bigint AS issued_at,
                extract(epoch FROM resource_grant.expires_at)::bigint AS expires_at,
                outbox.envelope AS stored_envelope,
                outbox.aggregate_ref AS stored_aggregate_ref,
                outbox.event_type AS stored_event_type
         FROM xshield.resource_grants resource_grant
         LEFT JOIN xshield.audit_outbox outbox
           ON outbox.tenant_id = resource_grant.tenant_id
          AND outbox.site_id = resource_grant.site_id
          AND outbox.event_id = resource_grant.source_event_id
         WHERE resource_grant.tenant_id = $1
           AND resource_grant.site_id = $2
           AND resource_grant.issuance_key = $3
         FOR SHARE OF resource_grant",
    )
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.draft.issuance_key.as_str())
    .fetch_optional(connection)
    .await?;
    let Some(row) = existing else {
        return Ok(None);
    };
    let grant_id = GrantId::parse(row.try_get::<&str, _>("grant_id")?)
        .map_err(|_| StoreError::CorruptData("grant_id"))?;
    if row.try_get::<&str, _>("status")? != "active" {
        return Ok(Some(GrantWriteOutcome::Ineligible));
    }
    let stored_envelope = row
        .try_get::<Option<Value>, _>("stored_envelope")?
        .ok_or(StoreError::CorruptData("grant_outbox"))?;
    if row.try_get::<Option<&str>, _>("stored_aggregate_ref")? != Some(grant_id.as_str())
        || row.try_get::<Option<&str>, _>("stored_event_type")? != Some("grant.issued")
    {
        return Err(StoreError::CorruptData("grant_outbox"));
    }
    let same = row.try_get::<&str, _>("binding_id")? == command.snapshot.binding_id().as_str()
        && row.try_get::<i64, _>("auth_epoch")? == epoch
        && row.try_get::<&str, _>("action_ref")? == command.action_ref.as_str()
        && row.try_get::<&str, _>("resource_type")? == command.draft.resource_type.as_str()
        && row.try_get::<Vec<u8>, _>("resource_key_hmac")?.as_slice()
            == command.draft.resource_key.as_bytes()
        && row.try_get::<&str, _>("operation_id")? == command.draft.operation_id.as_str()
        && row.try_get::<&str, _>("view_id")? == command.draft.view_profile.as_str()
        && row.try_get::<Value, _>("constraints")? == *command.constraints
        && row.try_get::<&str, _>("source_event_id")? == command.event_id.as_str()
        && row.try_get::<&str, _>("policy_revision")? == command.draft.policy_revision.as_str()
        && row.try_get::<i64, _>("issued_at")? == issued_at
        && row.try_get::<i64, _>("expires_at")? == expires_at
        && &stored_envelope == command.event_envelope;
    Ok(Some(if same {
        GrantWriteOutcome::Existing(grant_id)
    } else {
        GrantWriteOutcome::Conflict
    }))
}

async fn active_grant_count(
    connection: &mut PgConnection,
    command: &GrantPersistence<'_>,
    epoch: i64,
    now: i64,
) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM xshield.resource_grants
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
           AND auth_epoch = $4 AND status = 'active'
           AND expires_at > GREATEST(to_timestamp($5), clock_timestamp())",
    )
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.snapshot.binding_id().as_str())
    .bind(epoch)
    .bind(now)
    .fetch_one(connection)
    .await?)
}

async fn insert_grant_and_event(
    connection: &mut PgConnection,
    command: &GrantPersistence<'_>,
    epoch: i64,
    now: i64,
    expires_at: i64,
) -> Result<(), StoreError> {
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
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.draft.grant_id.as_str())
    .bind(command.snapshot.binding_id().as_str())
    .bind(epoch)
    .bind(command.action_ref.as_str())
    .bind(command.draft.resource_type.as_str())
    .bind(command.draft.resource_key.as_bytes().as_slice())
    .bind(command.draft.operation_id.as_str())
    .bind(command.draft.view_profile.as_str())
    .bind(command.constraints)
    .bind(command.event_id.as_str())
    .bind(command.draft.issuance_key.as_str())
    .bind(command.draft.policy_revision.as_str())
    .bind(now)
    .bind(expires_at)
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, 'grant.issued', $5)",
    )
    .bind(command.event_id.as_str())
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.draft.grant_id.as_str())
    .bind(command.event_envelope)
    .execute(connection)
    .await?;
    Ok(())
}
