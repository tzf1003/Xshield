use crate::{PostgresIdentityStore, StoreError, to_i64};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use xshield_core::{
    access::{ShareGrantDraft, ShareIssueAuthority},
    audit::ReasonCode,
    domain::{EventId, ShareGrantId},
    identity::{AuthSnapshot, UnixSeconds},
};

/// Complete, previously validated limited-share issuance command.
pub struct ShareGrantPersistence<'a> {
    snapshot: &'a AuthSnapshot,
    draft: &'a ShareGrantDraft,
    authority: &'a ShareIssueAuthority,
    event_id: &'a EventId,
    event_envelope: &'a Value,
    now: UnixSeconds,
    max_active_shares: u32,
}

impl<'a> ShareGrantPersistence<'a> {
    /// Validates transaction-local time, capacity, and audit bounds.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an elapsed lease, zero
    /// capacity, or a non-object event envelope.
    pub fn new(
        snapshot: &'a AuthSnapshot,
        draft: &'a ShareGrantDraft,
        authority: &'a ShareIssueAuthority,
        event_id: &'a EventId,
        event_envelope: &'a Value,
        now: UnixSeconds,
        max_active_shares: u32,
    ) -> Result<Self, StoreError> {
        if draft.expires_at <= now || max_active_shares == 0 || !event_envelope.is_object() {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            snapshot,
            draft,
            authority,
            event_id,
            event_envelope,
            now,
            max_active_shares,
        })
    }
}

/// Deterministic result of one serialized limited-share write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShareGrantWriteOutcome {
    /// A new limited-share grant and outbox event committed.
    Created(ShareGrantId),
    /// The same issuance was already committed without extending its lease.
    Existing(ShareGrantId),
    /// The issuance key exists with different authorization semantics.
    Conflict,
    /// The issuer identity, resource grant, rule, policy, or lease is ineligible.
    Ineligible,
    /// The configured active-share bound has been reached.
    CapacityExceeded,
}

impl ShareGrantWriteOutcome {
    /// Returns the stable reason written by the request-stage audit coordinator.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Created(_) => ReasonCode::ShareIssued,
            Self::Existing(_) => ReasonCode::ShareAlreadyIssued,
            Self::Conflict => ReasonCode::ShareIssuanceConflict,
            Self::Ineligible => ReasonCode::ShareSourceIneligible,
            Self::CapacityExceeded => ReasonCode::ShareCapacityExceeded,
        }
    }
}

impl PostgresIdentityStore {
    /// Issues one exact limited share after revalidating identity, resource
    /// authority, policy mapping, expiry, idempotency, and capacity.
    ///
    /// The issuer binding row lock serializes capacity checks. The source action,
    /// grant, policy, and issuance rule stay read-locked until the share and outbox event
    /// commit atomically. Exact replays preserve the share ID, issuance time and
    /// original outbox envelope; live database time and revocation still apply.
    ///
    /// # Errors
    /// Returns [`StoreError`] for numeric overflow, corrupt stored identifiers,
    /// or a database/transaction failure.
    pub async fn issue_share_grant(
        &self,
        command: ShareGrantPersistence<'_>,
    ) -> Result<ShareGrantWriteOutcome, StoreError> {
        let epoch = to_i64(command.snapshot.epoch().value(), "auth_epoch")?;
        let now = to_i64(command.now.value(), "now")?;
        let expires_at = to_i64(command.draft.expires_at.value(), "expires_at")?;
        let ttl = expires_at
            .checked_sub(now)
            .ok_or(StoreError::NumericRange("share_ttl"))?;
        let mut transaction = self.pool.begin().await?;

        if !lock_eligible_binding(&mut transaction, &command, epoch, now, expires_at).await?
            || !source_is_eligible(&mut transaction, &command, epoch, now, expires_at, ttl).await?
        {
            transaction.rollback().await?;
            return Ok(ShareGrantWriteOutcome::Ineligible);
        }
        let existing = existing_outcome(&mut transaction, &command, epoch, now, expires_at).await?;
        // Row-lock predicates may have run before waiting for another writer.
        // All locked authority leases contain this share lease, so its live
        // deadline bounds them too. Frozen audit time must not extend it.
        if !lease_is_live(&mut transaction, expires_at).await? {
            transaction.rollback().await?;
            return Ok(ShareGrantWriteOutcome::Ineligible);
        }
        if let Some(outcome) = existing {
            transaction.rollback().await?;
            return Ok(outcome);
        }
        if active_share_count(&mut transaction, &command, epoch, now).await?
            >= i64::from(command.max_active_shares)
        {
            transaction.rollback().await?;
            return Ok(ShareGrantWriteOutcome::CapacityExceeded);
        }

        insert_share_and_event(&mut transaction, &command, epoch, now, expires_at).await?;
        // Inserts can wait on constraints as well; discard both rows if that
        // wait exhausted the lease before the transaction's commit boundary.
        if !lease_is_live(&mut transaction, expires_at).await? {
            transaction.rollback().await?;
            return Ok(ShareGrantWriteOutcome::Ineligible);
        }
        transaction.commit().await?;
        Ok(ShareGrantWriteOutcome::Created(
            command.draft.share_id.clone(),
        ))
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
    command: &ShareGrantPersistence<'_>,
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

async fn source_is_eligible(
    connection: &mut PgConnection,
    command: &ShareGrantPersistence<'_>,
    epoch: i64,
    now: i64,
    expires_at: i64,
    ttl: i64,
) -> Result<bool, StoreError> {
    let eligible: Option<i32> = sqlx::query_scalar(
        "SELECT 1
         FROM xshield.resource_grants resource_grant
         JOIN xshield.ui_actions action
           ON action.tenant_id = resource_grant.tenant_id
          AND action.site_id = resource_grant.site_id
          AND action.action_ref = resource_grant.action_ref
          AND action.binding_id = resource_grant.binding_id
          AND action.auth_epoch = resource_grant.auth_epoch
          AND action.operation_id = resource_grant.operation_id
          AND action.field_profile = resource_grant.view_id
          AND action.policy_revision = resource_grant.policy_revision
          AND resource_grant.issued_at >= action.issued_at
          AND resource_grant.expires_at <= action.expires_at
         JOIN xshield.policy_revisions policy
           ON policy.tenant_id = resource_grant.tenant_id
          AND policy.site_id = resource_grant.site_id
          AND policy.revision = resource_grant.policy_revision
         JOIN xshield.share_issuance_rules rule
           ON rule.tenant_id = resource_grant.tenant_id
          AND rule.site_id = resource_grant.site_id
          AND rule.policy_revision = resource_grant.policy_revision
         WHERE resource_grant.tenant_id = $1 AND resource_grant.site_id = $2
           AND resource_grant.grant_id = $3 AND resource_grant.binding_id = $4
           AND resource_grant.auth_epoch = $5
           AND resource_grant.resource_type = $6 AND resource_grant.resource_key_hmac = $7
           AND resource_grant.operation_id = $8 AND resource_grant.view_id = $9
           AND resource_grant.status = 'active'
           AND action.status = 'active'
           AND action.expires_at > GREATEST(to_timestamp($10), clock_timestamp())
           AND resource_grant.expires_at > GREATEST(to_timestamp($10), clock_timestamp())
           AND resource_grant.expires_at >= to_timestamp($11)
           AND rule.rule_id = $12 AND rule.issuer_operation_id = $8
           AND rule.issuer_view_id = $9 AND rule.share_operation_id = $13
           AND rule.share_view_id = $14 AND rule.max_ttl_seconds >= $15
           AND rule.status = 'active' AND policy.status = 'active'
           AND resource_grant.policy_revision = $16
         FOR SHARE OF resource_grant, action, policy, rule",
    )
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.authority.resource_grant_id.as_str())
    .bind(command.snapshot.binding_id().as_str())
    .bind(epoch)
    .bind(command.draft.resource_type.as_str())
    .bind(command.draft.resource_key.as_bytes().as_slice())
    .bind(command.authority.operation_id.as_str())
    .bind(command.authority.view_profile.as_str())
    .bind(now)
    .bind(expires_at)
    .bind(command.authority.rule_id.as_str())
    .bind(command.draft.operation_id.as_str())
    .bind(command.draft.view_profile.as_str())
    .bind(ttl)
    .bind(command.draft.policy_revision.as_str())
    .fetch_optional(connection)
    .await?;
    Ok(eligible.is_some())
}

async fn existing_outcome(
    connection: &mut PgConnection,
    command: &ShareGrantPersistence<'_>,
    epoch: i64,
    issued_at: i64,
    expires_at: i64,
) -> Result<Option<ShareGrantWriteOutcome>, StoreError> {
    let existing = sqlx::query(
        "SELECT share.share_id, share.issuer_binding_id, share.issuer_auth_epoch,
                share.issuer_grant_id, share.issuance_rule_id, share.token_fingerprint,
                share.resource_type, share.resource_key_hmac, share.operation_id, share.view_id,
                share.source_event_id, share.policy_revision, share.status,
                extract(epoch FROM share.issued_at)::bigint AS issued_at,
                extract(epoch FROM share.expires_at)::bigint AS expires_at,
                outbox.envelope AS stored_envelope, outbox.aggregate_ref AS stored_aggregate_ref,
                outbox.event_type AS stored_event_type
         FROM xshield.share_grants share
         LEFT JOIN xshield.audit_outbox outbox
           ON outbox.tenant_id = share.tenant_id AND outbox.site_id = share.site_id
          AND outbox.event_id = share.source_event_id
         WHERE share.tenant_id = $1 AND share.site_id = $2 AND share.issuance_key = $3
         FOR SHARE OF share",
    )
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.draft.issuance_key.as_str())
    .fetch_optional(connection)
    .await?;
    let Some(row) = existing else {
        return Ok(None);
    };
    let share_id = ShareGrantId::parse(row.try_get::<&str, _>("share_id")?)
        .map_err(|_| StoreError::CorruptData("share_id"))?;
    if row.try_get::<&str, _>("status")? != "active" {
        return Ok(Some(ShareGrantWriteOutcome::Ineligible));
    }
    let stored_envelope = row
        .try_get::<Option<Value>, _>("stored_envelope")?
        .ok_or(StoreError::CorruptData("share_outbox"))?;
    if row.try_get::<Option<&str>, _>("stored_aggregate_ref")? != Some(share_id.as_str())
        || row.try_get::<Option<&str>, _>("stored_event_type")? != Some("share.issued")
    {
        return Err(StoreError::CorruptData("share_outbox"));
    }
    let same = share_id == command.draft.share_id
        && row.try_get::<&str, _>("issuer_binding_id")? == command.snapshot.binding_id().as_str()
        && row.try_get::<Option<i64>, _>("issuer_auth_epoch")? == Some(epoch)
        && row.try_get::<Option<&str>, _>("issuer_grant_id")?
            == Some(command.authority.resource_grant_id.as_str())
        && row.try_get::<Option<&str>, _>("issuance_rule_id")?
            == Some(command.authority.rule_id.as_str())
        && row.try_get::<Vec<u8>, _>("token_fingerprint")?.as_slice()
            == command.draft.token_fingerprint.as_bytes()
        && row.try_get::<&str, _>("resource_type")? == command.draft.resource_type.as_str()
        && row.try_get::<Vec<u8>, _>("resource_key_hmac")?.as_slice()
            == command.draft.resource_key.as_bytes()
        && row.try_get::<&str, _>("operation_id")? == command.draft.operation_id.as_str()
        && row.try_get::<&str, _>("view_id")? == command.draft.view_profile.as_str()
        && row.try_get::<&str, _>("source_event_id")? == command.event_id.as_str()
        && row.try_get::<&str, _>("policy_revision")? == command.draft.policy_revision.as_str()
        && row.try_get::<i64, _>("expires_at")? == expires_at
        && row.try_get::<i64, _>("issued_at")? == issued_at
        && &stored_envelope == command.event_envelope;
    Ok(Some(if same {
        ShareGrantWriteOutcome::Existing(share_id)
    } else {
        ShareGrantWriteOutcome::Conflict
    }))
}

async fn active_share_count(
    connection: &mut PgConnection,
    command: &ShareGrantPersistence<'_>,
    epoch: i64,
    now: i64,
) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM xshield.share_grants
         WHERE tenant_id = $1 AND site_id = $2 AND issuer_binding_id = $3
           AND issuer_auth_epoch = $4 AND status = 'active'
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

async fn insert_share_and_event(
    connection: &mut PgConnection,
    command: &ShareGrantPersistence<'_>,
    epoch: i64,
    now: i64,
    expires_at: i64,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO xshield.share_grants (
            tenant_id, site_id, share_id, issuer_binding_id, issuer_auth_epoch,
            issuer_grant_id, issuance_rule_id, issuance_key, token_fingerprint,
            resource_type, resource_key_hmac, operation_id, view_id, use_policy,
            source_event_id, policy_revision, status, issued_at, expires_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            'reusable_read', $14, $15, 'active', to_timestamp($16), to_timestamp($17)
         )",
    )
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.draft.share_id.as_str())
    .bind(command.snapshot.binding_id().as_str())
    .bind(epoch)
    .bind(command.authority.resource_grant_id.as_str())
    .bind(command.authority.rule_id.as_str())
    .bind(command.draft.issuance_key.as_str())
    .bind(command.draft.token_fingerprint.as_bytes().as_slice())
    .bind(command.draft.resource_type.as_str())
    .bind(command.draft.resource_key.as_bytes().as_slice())
    .bind(command.draft.operation_id.as_str())
    .bind(command.draft.view_profile.as_str())
    .bind(command.event_id.as_str())
    .bind(command.draft.policy_revision.as_str())
    .bind(now)
    .bind(expires_at)
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, 'share.issued', $5)",
    )
    .bind(command.event_id.as_str())
    .bind(command.snapshot.tenant_id().as_str())
    .bind(command.snapshot.site_id().as_str())
    .bind(command.draft.share_id.as_str())
    .bind(command.event_envelope)
    .execute(connection)
    .await?;
    Ok(())
}
