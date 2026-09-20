use crate::{PostgresIdentityStore, StoreError, to_i64};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use xshield_core::{
    audit::ReasonCode,
    domain::PageEvidenceId,
    provenance::{ActionGrant, ActionTarget, PageEvidence},
};

/// One verified page evidence and exact action grant persistence command.
pub struct ProvenancePersistence<'a> {
    evidence: &'a PageEvidence,
    action: &'a ActionGrant,
    action_page_evidence_id: &'a PageEvidenceId,
    response_artifact_ref: &'a str,
    event_id: &'a xshield_core::domain::EventId,
    event_envelope: &'a Value,
    now: xshield_core::identity::UnixSeconds,
}

impl<'a> ProvenancePersistence<'a> {
    /// Validates cross-object identity, source, version, time, and event bounds.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when the evidence and action do
    /// not form one bounded issuance or contain an invalid artifact/event value.
    pub fn new(
        evidence: &'a PageEvidence,
        action: &'a ActionGrant,
        response_artifact_ref: &'a str,
        event_id: &'a xshield_core::domain::EventId,
        event_envelope: &'a Value,
        now: xshield_core::identity::UnixSeconds,
    ) -> Result<Self, StoreError> {
        let artifact_valid = !response_artifact_ref.is_empty()
            && response_artifact_ref.len() <= 512
            && response_artifact_ref
                .bytes()
                .all(|byte| !byte.is_ascii_control());
        let Some(action_page_evidence_id) = action.page_evidence_id() else {
            return Err(StoreError::InvalidCommand);
        };
        if !artifact_valid
            || !event_envelope.is_object()
            || evidence.evidence_id() != action_page_evidence_id
            || evidence.source_request_id() != action.source_request_id()
            || evidence.snapshot() != action.snapshot()
            || evidence.policy_revision() != action.policy_revision()
            || evidence.mapping_revision() != action.mapping_revision()
            || action.issued_at() < evidence.verified_at()
            || now < action.issued_at()
            || now >= action.expires_at()
            || action.expires_at() > evidence.expires_at()
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            evidence,
            action,
            action_page_evidence_id,
            response_artifact_ref,
            event_id,
            event_envelope,
            now,
        })
    }
}

/// Deterministic result of an atomic UI provenance write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenanceWriteOutcome {
    /// Page evidence, action grant, and outbox event committed.
    Created,
    /// The same page evidence and action grant were already committed.
    Existing,
    /// A page evidence or action reference exists with different semantics.
    Conflict,
    /// Current identity, policy, or action descriptor is not eligible.
    Ineligible,
}

impl ProvenanceWriteOutcome {
    /// Returns the stable stage reason code.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::Created => ReasonCode::UiActionIssued,
            Self::Existing => ReasonCode::UiActionAlreadyIssued,
            Self::Conflict => ReasonCode::UiActionIssuanceConflict,
            Self::Ineligible => ReasonCode::UiActionNotAvailable,
        }
    }
}

impl PostgresIdentityStore {
    /// Atomically persists verified page evidence, one action grant, and outbox event.
    ///
    /// The current binding row is locked before checking the active signed-policy
    /// descriptor. Existing references are compared exactly and never extend TTL.
    ///
    /// # Errors
    /// Returns [`StoreError`] for numeric overflow or database failure.
    pub async fn persist_provenance(
        &self,
        command: ProvenancePersistence<'_>,
    ) -> Result<ProvenanceWriteOutcome, StoreError> {
        let epoch = to_i64(command.action.snapshot().epoch().value(), "auth_epoch")?;
        let now = to_i64(command.now.value(), "now")?;
        let evidence_verified_at = to_i64(
            command.evidence.verified_at().value(),
            "evidence_verified_at",
        )?;
        let evidence_expires_at =
            to_i64(command.evidence.expires_at().value(), "evidence_expires_at")?;
        let action_issued_at = to_i64(command.action.issued_at().value(), "action_issued_at")?;
        let action_expires_at = to_i64(command.action.expires_at().value(), "action_expires_at")?;
        let fields = field_values(command.action);
        let (target_rule, target) = target_values(command.action.target());
        let mut transaction = self.pool.begin().await?;

        if !lock_binding(&mut transaction, &command, epoch, now, evidence_expires_at).await?
            || !descriptor_is_eligible(&mut transaction, &command, &target_rule, &fields).await?
        {
            transaction.rollback().await?;
            return Ok(ProvenanceWriteOutcome::Ineligible);
        }

        match persist_evidence(
            &mut transaction,
            &command,
            epoch,
            evidence_verified_at,
            evidence_expires_at,
        )
        .await?
        {
            ExistingState::Conflict => {
                transaction.rollback().await?;
                return Ok(ProvenanceWriteOutcome::Conflict);
            }
            ExistingState::Same | ExistingState::New => {}
        }

        match existing_action(
            &mut transaction,
            &command,
            epoch,
            action_issued_at,
            action_expires_at,
            &target,
            &fields,
        )
        .await?
        {
            Some(true) => {
                if !action_outbox_exists(&mut transaction, &command).await? {
                    return Err(StoreError::CorruptData("ui_action_outbox"));
                }
                transaction.rollback().await?;
                return Ok(ProvenanceWriteOutcome::Existing);
            }
            Some(false) => {
                transaction.rollback().await?;
                return Ok(ProvenanceWriteOutcome::Conflict);
            }
            None => {}
        }

        insert_action_and_event(
            &mut transaction,
            &command,
            epoch,
            action_issued_at,
            action_expires_at,
            &target,
            &fields,
        )
        .await?;
        transaction.commit().await?;
        Ok(ProvenanceWriteOutcome::Created)
    }
}

async fn action_outbox_exists(
    connection: &mut PgConnection,
    command: &ProvenancePersistence<'_>,
) -> Result<bool, StoreError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM xshield.audit_outbox
            WHERE tenant_id = $1 AND site_id = $2 AND aggregate_ref = $3
              AND event_type = 'ui_action.issued'
         )",
    )
    .bind(command.action.snapshot().tenant_id().as_str())
    .bind(command.action.snapshot().site_id().as_str())
    .bind(command.action.action_ref().as_str())
    .fetch_one(connection)
    .await?;
    Ok(exists)
}

async fn lock_binding(
    connection: &mut PgConnection,
    command: &ProvenancePersistence<'_>,
    epoch: i64,
    now: i64,
    evidence_expires_at: i64,
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
    .bind(command.action.snapshot().tenant_id().as_str())
    .bind(command.action.snapshot().site_id().as_str())
    .bind(command.action.snapshot().binding_id().as_str())
    .bind(command.action.snapshot().principal_ref())
    .bind(
        command
            .action
            .snapshot()
            .authorization_context_ref()
            .as_str(),
    )
    .bind(epoch)
    .bind(now)
    .bind(evidence_expires_at)
    .fetch_optional(connection)
    .await?;
    Ok(eligible.is_some())
}

async fn descriptor_is_eligible(
    connection: &mut PgConnection,
    command: &ProvenancePersistence<'_>,
    target_rule: &Value,
    fields: &Value,
) -> Result<bool, StoreError> {
    let eligible: Option<i32> = sqlx::query_scalar(
        "SELECT 1
         FROM xshield.action_descriptors descriptor
         JOIN xshield.policy_revisions policy
           ON policy.tenant_id = descriptor.tenant_id
          AND policy.site_id = descriptor.site_id
          AND policy.revision = descriptor.policy_revision
         WHERE descriptor.tenant_id = $1 AND descriptor.site_id = $2
           AND descriptor.action_id = $3 AND descriptor.page_template = $4
           AND descriptor.operation_id = $5 AND descriptor.method = $6
           AND descriptor.route_template = $7 AND descriptor.target_rule = $8
           AND descriptor.allowed_fields @> $9
           AND descriptor.field_profile = $10 AND descriptor.policy_revision = $11
           AND descriptor.mapping_revision = $12
           AND descriptor.status = 'approved' AND policy.status = 'active'",
    )
    .bind(command.action.snapshot().tenant_id().as_str())
    .bind(command.action.snapshot().site_id().as_str())
    .bind(command.action.action_id().as_str())
    .bind(command.evidence.page_template().as_str())
    .bind(command.action.operation_id().as_str())
    .bind(command.action.method().as_str())
    .bind(command.action.route().as_str())
    .bind(target_rule)
    .bind(fields)
    .bind(command.action.field_profile().as_str())
    .bind(command.action.policy_revision().as_str())
    .bind(command.action.mapping_revision().as_str())
    .fetch_optional(connection)
    .await?;
    Ok(eligible.is_some())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingState {
    New,
    Same,
    Conflict,
}

async fn persist_evidence(
    connection: &mut PgConnection,
    command: &ProvenancePersistence<'_>,
    epoch: i64,
    verified_at: i64,
    expires_at: i64,
) -> Result<ExistingState, StoreError> {
    let existing = sqlx::query(
        "SELECT binding_id, auth_epoch, source_request_id, response_artifact_ref,
                page_template, build_fingerprint, policy_revision, mapping_revision,
                status, extract(epoch FROM verified_at)::bigint AS verified_at,
                extract(epoch FROM expires_at)::bigint AS expires_at
         FROM xshield.page_evidence
         WHERE tenant_id = $1 AND site_id = $2 AND page_evidence_id = $3",
    )
    .bind(command.action.snapshot().tenant_id().as_str())
    .bind(command.action.snapshot().site_id().as_str())
    .bind(command.evidence.evidence_id().as_str())
    .fetch_optional(&mut *connection)
    .await?;
    if let Some(row) = existing {
        let same = row.try_get::<&str, _>("binding_id")?
            == command.action.snapshot().binding_id().as_str()
            && row.try_get::<i64, _>("auth_epoch")? == epoch
            && row.try_get::<&str, _>("source_request_id")?
                == command.evidence.source_request_id().as_str()
            && row.try_get::<&str, _>("response_artifact_ref")? == command.response_artifact_ref
            && row.try_get::<&str, _>("page_template")?
                == command.evidence.page_template().as_str()
            && row.try_get::<Vec<u8>, _>("build_fingerprint")?.as_slice()
                == command.evidence.build_fingerprint().as_bytes()
            && row.try_get::<&str, _>("policy_revision")?
                == command.evidence.policy_revision().as_str()
            && row.try_get::<&str, _>("mapping_revision")?
                == command.evidence.mapping_revision().as_str()
            && row.try_get::<&str, _>("status")? == "verified"
            && row.try_get::<i64, _>("verified_at")? == verified_at
            && row.try_get::<i64, _>("expires_at")? == expires_at;
        return Ok(if same {
            ExistingState::Same
        } else {
            ExistingState::Conflict
        });
    }
    sqlx::query(
        "INSERT INTO xshield.page_evidence (
            tenant_id, site_id, page_evidence_id, binding_id, auth_epoch,
            source_request_id, response_artifact_ref, page_template, build_fingerprint,
            policy_revision, mapping_revision, status, verified_at, expires_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, 'verified', to_timestamp($12), to_timestamp($13)
         )",
    )
    .bind(command.action.snapshot().tenant_id().as_str())
    .bind(command.action.snapshot().site_id().as_str())
    .bind(command.evidence.evidence_id().as_str())
    .bind(command.action.snapshot().binding_id().as_str())
    .bind(epoch)
    .bind(command.evidence.source_request_id().as_str())
    .bind(command.response_artifact_ref)
    .bind(command.evidence.page_template().as_str())
    .bind(command.evidence.build_fingerprint().as_bytes().as_slice())
    .bind(command.evidence.policy_revision().as_str())
    .bind(command.evidence.mapping_revision().as_str())
    .bind(verified_at)
    .bind(expires_at)
    .execute(connection)
    .await?;
    Ok(ExistingState::New)
}

#[allow(clippy::too_many_arguments)]
async fn existing_action(
    connection: &mut PgConnection,
    command: &ProvenancePersistence<'_>,
    epoch: i64,
    issued_at: i64,
    expires_at: i64,
    target: &Value,
    fields: &Value,
) -> Result<Option<bool>, StoreError> {
    let existing = sqlx::query(
        "SELECT binding_id, auth_epoch, source_request_id, page_evidence_id,
                source_action_ref, operation_id, target_constraints, field_profile,
                source_rule, policy_revision, status, mapping_revision, method,
                route_template, allowed_fields,
                extract(epoch FROM issued_at)::bigint AS issued_at,
                extract(epoch FROM expires_at)::bigint AS expires_at
         FROM xshield.ui_actions
         WHERE tenant_id = $1 AND site_id = $2 AND action_ref = $3",
    )
    .bind(command.action.snapshot().tenant_id().as_str())
    .bind(command.action.snapshot().site_id().as_str())
    .bind(command.action.action_ref().as_str())
    .fetch_optional(connection)
    .await?;
    let Some(row) = existing else {
        return Ok(None);
    };
    Ok(Some(
        row.try_get::<&str, _>("binding_id")? == command.action.snapshot().binding_id().as_str()
            && row.try_get::<i64, _>("auth_epoch")? == epoch
            && row.try_get::<&str, _>("source_request_id")?
                == command.action.source_request_id().as_str()
            && row.try_get::<&str, _>("page_evidence_id")?
                == command.action_page_evidence_id.as_str()
            && row.try_get::<&str, _>("source_action_ref")? == command.action.action_id().as_str()
            && row.try_get::<&str, _>("operation_id")? == command.action.operation_id().as_str()
            && row.try_get::<Value, _>("target_constraints")? == *target
            && row.try_get::<&str, _>("field_profile")? == command.action.field_profile().as_str()
            && row.try_get::<&str, _>("source_rule")? == command.action.mapping_revision().as_str()
            && row.try_get::<&str, _>("policy_revision")?
                == command.action.policy_revision().as_str()
            && row.try_get::<&str, _>("status")? == "active"
            && row.try_get::<&str, _>("mapping_revision")?
                == command.action.mapping_revision().as_str()
            && row.try_get::<&str, _>("method")? == command.action.method().as_str()
            && row.try_get::<&str, _>("route_template")? == command.action.route().as_str()
            && row.try_get::<Value, _>("allowed_fields")? == *fields
            && row.try_get::<i64, _>("issued_at")? == issued_at
            && row.try_get::<i64, _>("expires_at")? == expires_at,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn insert_action_and_event(
    connection: &mut PgConnection,
    command: &ProvenancePersistence<'_>,
    epoch: i64,
    issued_at: i64,
    expires_at: i64,
    target: &Value,
    fields: &Value,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO xshield.ui_actions (
            tenant_id, site_id, action_ref, binding_id, auth_epoch,
            source_request_id, page_evidence_id, source_action_ref, operation_id,
            target_constraints, field_profile, source_rule, policy_revision,
            status, issued_at, expires_at, mapping_revision, method, route_template,
            allowed_fields
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, 'active', to_timestamp($14), to_timestamp($15),
            $16, $17, $18, $19
         )",
    )
    .bind(command.action.snapshot().tenant_id().as_str())
    .bind(command.action.snapshot().site_id().as_str())
    .bind(command.action.action_ref().as_str())
    .bind(command.action.snapshot().binding_id().as_str())
    .bind(epoch)
    .bind(command.action.source_request_id().as_str())
    .bind(command.action_page_evidence_id.as_str())
    .bind(command.action.action_id().as_str())
    .bind(command.action.operation_id().as_str())
    .bind(target)
    .bind(command.action.field_profile().as_str())
    .bind(command.action.mapping_revision().as_str())
    .bind(command.action.policy_revision().as_str())
    .bind(issued_at)
    .bind(expires_at)
    .bind(command.action.mapping_revision().as_str())
    .bind(command.action.method().as_str())
    .bind(command.action.route().as_str())
    .bind(fields)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, 'ui_action.issued', $5)",
    )
    .bind(command.event_id.as_str())
    .bind(command.action.snapshot().tenant_id().as_str())
    .bind(command.action.snapshot().site_id().as_str())
    .bind(command.action.action_ref().as_str())
    .bind(command.event_envelope)
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

fn target_values(target: &ActionTarget) -> (Value, Value) {
    match target {
        ActionTarget::None => (json!({"kind": "none"}), json!({"kind": "none"})),
        ActionTarget::Principal(principal) => (
            json!({"kind": "verified_principal"}),
            json!({"kind": "principal", "principal_ref": principal}),
        ),
        ActionTarget::Resource {
            resource_type,
            resource_key,
        } => {
            let key = hex(resource_key.as_bytes());
            (
                json!({"kind": "resource", "resource_type": resource_type.as_str()}),
                json!({
                    "kind": "resource",
                    "resource_type": resource_type.as_str(),
                    "resource_key_hmac": key,
                }),
            )
        }
    }
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

#[cfg(test)]
mod tests {
    use super::target_values;
    use serde_json::json;
    use xshield_core::{domain::ResourceType, grant::ResourceKeyHmac, provenance::ActionTarget};

    #[test]
    fn resource_target_is_serialized_without_raw_identifier() {
        let target = ActionTarget::Resource {
            resource_type: ResourceType::parse("order").unwrap(),
            resource_key: ResourceKeyHmac::parse(
                "abababababababababababababababababababababababababababababababab",
            )
            .unwrap(),
        };
        let (rule, exact) = target_values(&target);
        assert_eq!(rule, json!({"kind": "resource", "resource_type": "order"}));
        assert_eq!(
            exact,
            json!({
                "kind": "resource",
                "resource_type": "order",
                "resource_key_hmac":
                    "abababababababababababababababababababababababababababababababab",
            })
        );
    }
}
