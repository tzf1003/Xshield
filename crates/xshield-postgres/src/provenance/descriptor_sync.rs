//! Edge-managed action descriptors bound to one policy revision digest.
//!
//! The gateway derives descriptors from its validated configuration and calls
//! [`PostgresIdentityStore::sync_edge_descriptors`] before that configuration
//! serves traffic. The policy revision row records the canonical digest of the
//! whole descriptor set; a later configuration that derives different
//! descriptors under the same revision is refused instead of overwriting rows
//! that already-issued references point at. Rows are never updated here: an
//! existing row is accepted only when it is semantically identical.

use super::target_rule_value;
use crate::{PostgresIdentityStore, StoreError};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use std::collections::BTreeSet;
use xshield_core::{
    audit::ReasonCode,
    domain::{PolicyRevision, SiteId, TenantId},
    provenance::ActionDescriptor,
};

const MAX_EDGE_DESCRIPTORS: usize = 1_024;

/// One complete descriptor set to provision for a policy revision.
pub struct EdgeDescriptorSync<'a> {
    tenant_id: &'a TenantId,
    site_id: &'a SiteId,
    policy_revision: &'a PolicyRevision,
    content_digest: &'a str,
    descriptors: &'a [ActionDescriptor],
}

impl<'a> EdgeDescriptorSync<'a> {
    /// Validates the digest shape and that every descriptor is active, belongs
    /// to `policy_revision` and has a unique `(action, mapping)` key.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an empty or oversized set, a
    /// malformed digest, a retired descriptor, a descriptor of another
    /// revision or a duplicate key.
    pub fn new(
        tenant_id: &'a TenantId,
        site_id: &'a SiteId,
        policy_revision: &'a PolicyRevision,
        content_digest: &'a str,
        descriptors: &'a [ActionDescriptor],
    ) -> Result<Self, StoreError> {
        let keys = descriptors
            .iter()
            .map(|descriptor| {
                (
                    descriptor.action_id().as_str(),
                    descriptor.mapping_revision().as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        if descriptors.is_empty()
            || descriptors.len() > MAX_EDGE_DESCRIPTORS
            || keys.len() != descriptors.len()
            || content_digest.len() != 64
            || !content_digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || descriptors.iter().any(|descriptor| {
                !descriptor.is_active() || descriptor.policy_revision() != policy_revision
            })
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant_id,
            site_id,
            policy_revision,
            content_digest,
            descriptors,
        })
    }
}

/// Deterministic result of provisioning an edge descriptor set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeDescriptorSyncOutcome {
    /// The policy revision was created and its descriptors written.
    Created,
    /// The revision already carried this exact digest and descriptor set.
    Existing,
    /// The revision exists with another digest or is not active.
    PolicyConflict,
    /// A descriptor key exists with different semantics.
    DescriptorConflict,
}

impl EdgeDescriptorSyncOutcome {
    /// Returns whether the configuration may serve traffic.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Created | Self::Existing)
    }

    /// Returns the stable reason code recorded for a refusal.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::Created | Self::Existing => ReasonCode::UiActionIssued,
            Self::PolicyConflict | Self::DescriptorConflict => ReasonCode::UiDescriptorConflict,
        }
    }
}

impl PostgresIdentityStore {
    /// Provisions an edge-derived descriptor set before its configuration
    /// serves traffic.
    ///
    /// Runs in one transaction: the policy revision is created as `active`
    /// with the set digest when absent, then locked and compared; each
    /// descriptor is inserted when absent and then compared field by field
    /// under a share lock. Any difference rolls back and is reported as a
    /// conflict. Concurrent edges with the same configuration converge on
    /// [`EdgeDescriptorSyncOutcome::Existing`]. No row is ever updated.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure.
    pub async fn sync_edge_descriptors(
        &self,
        command: EdgeDescriptorSync<'_>,
    ) -> Result<EdgeDescriptorSyncOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let created = sqlx::query(
            "INSERT INTO xshield.policy_revisions (
                tenant_id, site_id, revision, status, content_digest, artifact_ref
             ) VALUES ($1, $2, $3, 'active', $4, $5)
             ON CONFLICT (tenant_id, site_id, revision) DO NOTHING",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(command.policy_revision.as_str())
        .bind(command.content_digest)
        .bind(format!(
            "edge.descriptors.sha256.{}",
            command.content_digest
        ))
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        let policy = sqlx::query(
            "SELECT status, content_digest FROM xshield.policy_revisions
             WHERE tenant_id = $1 AND site_id = $2 AND revision = $3
             FOR UPDATE",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(command.policy_revision.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        if policy.try_get::<&str, _>("status")? != "active"
            || policy.try_get::<&str, _>("content_digest")? != command.content_digest
        {
            transaction.rollback().await?;
            return Ok(EdgeDescriptorSyncOutcome::PolicyConflict);
        }
        for descriptor in command.descriptors {
            if !provision_descriptor(&mut transaction, &command, descriptor).await? {
                transaction.rollback().await?;
                return Ok(EdgeDescriptorSyncOutcome::DescriptorConflict);
            }
        }
        transaction.commit().await?;
        Ok(if created {
            EdgeDescriptorSyncOutcome::Created
        } else {
            EdgeDescriptorSyncOutcome::Existing
        })
    }
}

/// Inserts one descriptor when absent and reports whether the stored row is
/// semantically identical (allowed fields compare as a set).
async fn provision_descriptor(
    connection: &mut PgConnection,
    command: &EdgeDescriptorSync<'_>,
    descriptor: &ActionDescriptor,
) -> Result<bool, StoreError> {
    let target_rule = target_rule_value(descriptor.target_rule());
    let fields = Value::Array(
        descriptor
            .allowed_fields()
            .iter()
            .map(|field| Value::String(field.as_str().to_owned()))
            .collect(),
    );
    sqlx::query(
        "INSERT INTO xshield.action_descriptors (
            tenant_id, site_id, action_id, page_template, operation_id, method,
            route_template, target_rule, allowed_fields, field_profile,
            policy_revision, mapping_revision, status
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'approved')
         ON CONFLICT (tenant_id, site_id, action_id, policy_revision, mapping_revision)
         DO NOTHING",
    )
    .bind(command.tenant_id.as_str())
    .bind(command.site_id.as_str())
    .bind(descriptor.action_id().as_str())
    .bind(descriptor.page_template().as_str())
    .bind(descriptor.operation_id().as_str())
    .bind(descriptor.method().as_str())
    .bind(descriptor.route().as_str())
    .bind(&target_rule)
    .bind(&fields)
    .bind(descriptor.field_profile().as_str())
    .bind(command.policy_revision.as_str())
    .bind(descriptor.mapping_revision().as_str())
    .execute(&mut *connection)
    .await?;
    let same: Option<bool> = sqlx::query_scalar(
        "SELECT page_template = $6 AND operation_id = $7 AND method = $8
                AND route_template = $9 AND target_rule = $10
                AND allowed_fields @> $11 AND $11 @> allowed_fields
                AND jsonb_array_length(allowed_fields) = jsonb_array_length($11)
                AND field_profile = $12 AND status = 'approved'
         FROM xshield.action_descriptors
         WHERE tenant_id = $1 AND site_id = $2 AND action_id = $3
           AND policy_revision = $4 AND mapping_revision = $5
         FOR SHARE",
    )
    .bind(command.tenant_id.as_str())
    .bind(command.site_id.as_str())
    .bind(descriptor.action_id().as_str())
    .bind(command.policy_revision.as_str())
    .bind(descriptor.mapping_revision().as_str())
    .bind(descriptor.page_template().as_str())
    .bind(descriptor.operation_id().as_str())
    .bind(descriptor.method().as_str())
    .bind(descriptor.route().as_str())
    .bind(&target_rule)
    .bind(&fields)
    .bind(descriptor.field_profile().as_str())
    .fetch_optional(connection)
    .await?;
    Ok(same == Some(true))
}
