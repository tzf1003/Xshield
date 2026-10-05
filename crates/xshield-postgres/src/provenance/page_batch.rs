//! Atomic page-delivery issuance: one verified page evidence record and every
//! first-hop action the page declares, committed in one transaction.
//!
//! The single-action [`super::ProvenancePersistence`] command is reused per
//! item so each action keeps exactly the cross-object checks of the library
//! entry point; this module adds the batch invariant (one shared evidence
//! object), a per-binding live-page bound and all-or-nothing commit. A partial
//! batch would leave a page with only some of its declared actions, which the
//! sensor could not distinguish from a configuration change.

use super::{
    ExistingState, ProvenancePersistence, action_outbox_exists, descriptor_is_eligible,
    existing_action, field_values, insert_action_and_event, lock_binding, persist_evidence,
    target_values,
};
use crate::{PostgresIdentityStore, StoreError, lease_is_live, to_i64};
use std::collections::BTreeSet;
use xshield_core::audit::ReasonCode;

/// Maximum actions one page delivery may commit.
pub const MAX_PAGE_PROVENANCE_ACTIONS: usize = 16;
const MAX_ACTIVE_PAGES: u32 = 1_000;

/// One page evidence record with all of its first-hop actions.
pub struct PageProvenanceBatch<'a> {
    items: Vec<ProvenancePersistence<'a>>,
    max_active_pages: u32,
}

impl<'a> PageProvenanceBatch<'a> {
    /// Validates that every item shares one evidence object and artifact, and
    /// that references, events and bounds are unique and finite.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an empty or oversized batch,
    /// items naming different evidence, duplicate action references or event
    /// IDs, or an out-of-range live-page bound.
    pub fn new(
        items: Vec<ProvenancePersistence<'a>>,
        max_active_pages: u32,
    ) -> Result<Self, StoreError> {
        let Some(first) = items.first() else {
            return Err(StoreError::InvalidCommand);
        };
        let action_refs = items
            .iter()
            .map(|item| item.action.action_ref().as_str())
            .collect::<BTreeSet<_>>();
        let event_ids = items
            .iter()
            .map(|item| item.event_id.as_str())
            .collect::<BTreeSet<_>>();
        if items.len() > MAX_PAGE_PROVENANCE_ACTIONS
            || !(1..=MAX_ACTIVE_PAGES).contains(&max_active_pages)
            || action_refs.len() != items.len()
            || event_ids.len() != items.len()
            || items.iter().any(|item| {
                item.evidence != first.evidence
                    || item.response_artifact_ref != first.response_artifact_ref
                    || item.now != first.now
            })
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            items,
            max_active_pages,
        })
    }
}

/// Deterministic result of an atomic page-delivery issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageProvenanceOutcome {
    /// The evidence and every action and outbox event committed.
    Created,
    /// The identical evidence and actions were already committed.
    Existing,
    /// An evidence or action reference exists with different semantics.
    Conflict,
    /// Identity, policy, descriptor or lease is not eligible; nothing committed.
    Ineligible,
    /// The binding already holds the configured number of live page instances.
    CapacityExceeded,
}

impl PageProvenanceOutcome {
    /// Returns the stable stage reason code.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::Created => ReasonCode::UiActionIssued,
            Self::Existing => ReasonCode::UiActionAlreadyIssued,
            Self::Conflict => ReasonCode::UiActionIssuanceConflict,
            Self::Ineligible => ReasonCode::UiActionNotAvailable,
            Self::CapacityExceeded => ReasonCode::UiActionCapacityExceeded,
        }
    }
}

impl PostgresIdentityStore {
    /// Atomically persists one verified page delivery and all of its actions.
    ///
    /// The binding row is locked first, which serializes issuance per binding
    /// and makes the live-page count exact. Every descriptor is rechecked under
    /// a share lock against the active signed policy; any ineligible item,
    /// semantic conflict or expiry observed by the database clock rolls back
    /// the whole batch, so a page either receives every declared action or
    /// none. Exact retries return [`PageProvenanceOutcome::Existing`] without
    /// extending any lease. Callers audit
    /// [`PageProvenanceOutcome::reason_code`].
    ///
    /// # Errors
    /// Returns [`StoreError`] for numeric overflow, database failure or a
    /// committed action whose outbox event is missing.
    pub async fn persist_page_provenance(
        &self,
        batch: PageProvenanceBatch<'_>,
    ) -> Result<PageProvenanceOutcome, StoreError> {
        let first = batch.items.first().ok_or(StoreError::InvalidCommand)?;
        let epoch = to_i64(first.action.snapshot().epoch().value(), "auth_epoch")?;
        let now = to_i64(first.now.value(), "now")?;
        let verified_at = to_i64(first.evidence.verified_at().value(), "evidence_verified_at")?;
        let evidence_expires_at =
            to_i64(first.evidence.expires_at().value(), "evidence_expires_at")?;
        let earliest_action_expiry = batch
            .items
            .iter()
            .map(|item| item.action.expires_at().value())
            .min()
            .ok_or(StoreError::InvalidCommand)?;
        let earliest_action_expiry = to_i64(earliest_action_expiry, "action_expires_at")?;
        let mut transaction = self.pool.begin().await?;
        if !lock_binding(&mut transaction, first, epoch, now, evidence_expires_at).await? {
            transaction.rollback().await?;
            return Ok(PageProvenanceOutcome::Ineligible);
        }
        if live_pages(&mut transaction, first, epoch).await? >= i64::from(batch.max_active_pages) {
            transaction.rollback().await?;
            return Ok(PageProvenanceOutcome::CapacityExceeded);
        }
        if persist_evidence(
            &mut transaction,
            first,
            epoch,
            verified_at,
            evidence_expires_at,
        )
        .await?
            == ExistingState::Conflict
        {
            transaction.rollback().await?;
            return Ok(PageProvenanceOutcome::Conflict);
        }
        let mut created = false;
        for item in &batch.items {
            let fields = field_values(item.action);
            let (target_rule, target) = target_values(item.action.target());
            if !descriptor_is_eligible(&mut transaction, item, &target_rule, &fields).await? {
                transaction.rollback().await?;
                return Ok(PageProvenanceOutcome::Ineligible);
            }
            let issued_at = to_i64(item.action.issued_at().value(), "action_issued_at")?;
            let expires_at = to_i64(item.action.expires_at().value(), "action_expires_at")?;
            match existing_action(
                &mut transaction,
                item,
                epoch,
                issued_at,
                expires_at,
                &target,
                &fields,
            )
            .await?
            {
                Some(true) => {
                    if !action_outbox_exists(&mut transaction, item).await? {
                        return Err(StoreError::CorruptData("ui_action_outbox"));
                    }
                }
                Some(false) => {
                    transaction.rollback().await?;
                    return Ok(PageProvenanceOutcome::Conflict);
                }
                None => {
                    insert_action_and_event(
                        &mut transaction,
                        item,
                        epoch,
                        issued_at,
                        expires_at,
                        &target,
                        &fields,
                    )
                    .await?;
                    created = true;
                }
            }
        }
        // Lock and unique-key waits above may cross the earliest lease.
        if !lease_is_live(&mut transaction, earliest_action_expiry).await? {
            transaction.rollback().await?;
            return Ok(PageProvenanceOutcome::Ineligible);
        }
        if created {
            transaction.commit().await?;
            Ok(PageProvenanceOutcome::Created)
        } else {
            transaction.rollback().await?;
            Ok(PageProvenanceOutcome::Existing)
        }
    }
}

/// Counts other live page instances of the same template for this identity
/// epoch; the caller holds the binding row lock, so the count cannot race.
async fn live_pages(
    connection: &mut sqlx::PgConnection,
    command: &ProvenancePersistence<'_>,
    epoch: i64,
) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM xshield.page_evidence
         WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
           AND auth_epoch = $4 AND page_template = $5
           AND status = 'verified' AND expires_at > clock_timestamp()
           AND page_evidence_id <> $6",
    )
    .bind(command.action.snapshot().tenant_id().as_str())
    .bind(command.action.snapshot().site_id().as_str())
    .bind(command.action.snapshot().binding_id().as_str())
    .bind(epoch)
    .bind(command.evidence.page_template().as_str())
    .bind(command.evidence.evidence_id().as_str())
    .fetch_one(connection)
    .await?)
}
