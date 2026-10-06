//! Which action-descriptor set each `policy_revision` label of a site
//! denotes, as far as the control plane may have told the edge.
//!
//! The edge binds `(tenant, site, policy_revision)` to the digest of the
//! descriptor set it supplies for a configuration with page issuance, and
//! refuses any other set under that label for the whole tenant snapshot
//! (docs/19 §19.2). The control plane keeps the same rule one step earlier so
//! the mistake never reaches the edge.
//!
//! # Which revisions bind a label
//! A label is bound to a digest from the moment a revision carrying both
//! becomes *eligible to reach the edge*: it is served (`status = active`) and
//! needs no further approval. That happens in exactly three places, each of
//! which records the binding in its own transaction under the tenant lock:
//! - a save whose revision needs no approval ([`BoundBy::Save`]);
//! - the approval or direct-apply authorization that clears a revision's
//!   approval requirement ([`BoundBy::Approval`]);
//! - the snapshot read that is about to carry a revision written before this
//!   rule existed, or by an older control service ([`BoundBy::Snapshot`]).
//!
//! This is sound: a snapshot carries, per site, either the desired revision
//! (only when it is eligible, so it was bound before or by that very read,
//! which holds the same lock) or the active revision (carried as desired by an
//! earlier confirmed snapshot, so bound then), and bindings are never updated
//! or deleted. A revision that never becomes eligible (a draft, a pause, a
//! revision still awaiting approval when a later save supersedes it) binds
//! nothing: no snapshot carried it and none can, because snapshots only carry
//! the desired or the active revision. Eligible revisions that were never
//! actually sent (no edge configured, superseded before any snapshot read,
//! or refused before the edge supplied them) still bind: the control plane
//! cannot tell them from sent ones, because an edge refusal is unsigned and a
//! transport failure leaves the outcome unknown.
//!
//! The edge's own `policy_revisions` row for the label counts as well. It is
//! the record of what the edge actually supplied, including bindings made
//! outside the control plane (a bootstrap `XSHIELD_CONFIG`, a directly signed
//! snapshot, a seed) and labels an operator retired, which the edge never
//! reactivates. Reading it never refuses what the edge would accept: the edge
//! refuses exactly a row that is not `active` or names another digest.
//!
//! # What is checked
//! Every write that would be served is checked against both sources before
//! anything is written. A draft or a pause is never supplied and taking a site
//! down must never be blocked, so neither is checked or bound. A configuration
//! without page issuance has no digest and never conflicts.

use super::ProtectedSiteSnapshotSite;
use crate::StoreError;
use sqlx::{PgConnection, Row};
use xshield_core::{
    SiteConfig,
    domain::{SiteId, TenantId},
    site::{DescriptorDigest, LabelBinding, LabelReuse, check_label_binding},
};

/// How a label came to be bound (the `bound_by` column).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BoundBy {
    /// A save whose revision needs no approval.
    Save,
    /// An approval or a direct-apply authorization.
    Approval,
    /// A snapshot read carrying a revision that was not bound yet.
    Snapshot,
}

impl BoundBy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Save => "save",
            Self::Approval => "approval",
            Self::Snapshot => "snapshot",
        }
    }
}

/// The verdict for one configuration's label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LabelCheck {
    /// Nothing to bind: the configuration is not served, has no page
    /// issuance, or its descriptors cannot be derived (validation and the
    /// edge compiler both refuse such a configuration before anything could
    /// be supplied).
    Free,
    /// The label is unbound or already bound to this digest; `recorded` says
    /// whether the control plane's own binding row already exists.
    Bindable {
        /// Digest of the configuration's descriptor set.
        digest: DescriptorDigest,
        /// Whether `site_descriptor_bindings` already holds the label.
        recorded: bool,
    },
    /// The label already denotes something else.
    Reused(LabelReuse),
}

/// Checks the label of `config` for `site` against every known binding.
///
/// Read-only. Callers that act on the verdict hold the tenant lock, which
/// every writer of `site_descriptor_bindings` holds too, so the verdict
/// stays true until their transaction ends.
///
/// # Errors
/// [`StoreError`] when a binding cannot be read or a stored digest is
/// malformed.
pub(super) async fn check(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    site_id: &SiteId,
    config: &SiteConfig,
) -> Result<LabelCheck, StoreError> {
    if !config.is_serving() {
        return Ok(LabelCheck::Free);
    }
    let Ok(Some(digest)) = config.edge_descriptor_digest() else {
        return Ok(LabelCheck::Free);
    };
    let recorded = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT descriptor_digest FROM xshield.site_descriptor_bindings
         WHERE tenant_id = $1 AND site_id = $2 AND policy_revision = $3",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(&config.policy_revision)
    .fetch_optional(&mut *connection)
    .await?
    .map(|bytes| {
        <[u8; 32]>::try_from(bytes)
            .map(DescriptorDigest::from_bytes)
            .map_err(|_| StoreError::CorruptData("site_descriptor_bindings"))
    })
    .transpose()?;
    // A plain read: the edge's supply holds its row lock only for its own
    // short transaction, and a row the edge commits after this read is the
    // edge's refusal to make, as it was before this check existed.
    let edge = sqlx::query(
        "SELECT status, content_digest FROM xshield.policy_revisions
         WHERE tenant_id = $1 AND site_id = $2 AND revision = $3",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(&config.policy_revision)
    .fetch_optional(&mut *connection)
    .await?
    .map(|row| {
        Ok::<_, StoreError>((
            row.try_get::<String, _>("status")?,
            row.try_get::<String, _>("content_digest")?,
        ))
    })
    .transpose()?;
    let mut known = Vec::with_capacity(2);
    known.extend(recorded.map(LabelBinding::Recorded));
    if let Some((status, content_digest)) = &edge {
        known.push(LabelBinding::Edge {
            status,
            content_digest,
        });
    }
    Ok(match check_label_binding(Some(&digest), &known) {
        Ok(()) => LabelCheck::Bindable {
            digest,
            recorded: recorded.is_some(),
        },
        Err(reuse) => LabelCheck::Reused(reuse),
    })
}

/// The apply path's re-check, run by the snapshot read under its tenant lock.
///
/// A desired revision the snapshot may carry (served, nothing left to
/// approve) was bound when it became eligible, unless an older control
/// service wrote it or the edge bound its label since. Such a revision is
/// bound now; one whose label already denotes another set gets
/// `label_conflict`, so the plan holds that site back instead of sending a
/// snapshot the edge would refuse for the whole tenant. Revisions awaiting
/// approval are left alone: the approval checks them.
///
/// # Errors
/// [`StoreError`] when a binding cannot be read or written; the caller's
/// transaction then commits nothing.
pub(super) async fn bind_snapshot_labels(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    sites: &mut [ProtectedSiteSnapshotSite],
) -> Result<(), StoreError> {
    for site in sites.iter_mut().filter(|site| !site.requires_approval) {
        let config = site.record.site_config();
        match check(connection, tenant_id, &site.site_id, &config).await? {
            LabelCheck::Reused(reuse) => site.label_conflict = Some(reuse),
            LabelCheck::Bindable {
                digest,
                recorded: false,
            } => {
                record(
                    connection,
                    tenant_id,
                    &site.site_id,
                    &config.policy_revision,
                    &digest,
                    site.record.revision(),
                    BoundBy::Snapshot,
                )
                .await?;
            }
            LabelCheck::Free | LabelCheck::Bindable { recorded: true, .. } => {}
        }
    }
    Ok(())
}

/// Records that `label` of `site` denotes `digest`, first bound by site
/// revision `revision`.
///
/// Call it only after [`check`] answered [`LabelCheck::Bindable`] in the
/// same transaction under the tenant lock. An existing row for the label is
/// kept (it carries the revision that bound it first); it must name the same
/// digest, which the lock guarantees, and anything else is reported as
/// corruption rather than overwritten.
///
/// # Errors
/// [`StoreError`] when the row cannot be written, or
/// [`StoreError::CorruptData`] when the label is bound to another digest.
pub(super) async fn record(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    site_id: &SiteId,
    label: &str,
    digest: &DescriptorDigest,
    revision: u64,
    bound_by: BoundBy,
) -> Result<(), StoreError> {
    let revision = i64::try_from(revision).map_err(|_| StoreError::InvalidCommand)?;
    sqlx::query(
        "INSERT INTO xshield.site_descriptor_bindings
             (tenant_id, site_id, policy_revision, descriptor_digest, bound_revision, bound_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (tenant_id, site_id, policy_revision) DO NOTHING",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(label)
    .bind(digest.as_bytes().as_slice())
    .bind(revision)
    .bind(bound_by.as_str())
    .execute(&mut *connection)
    .await?;
    let stored = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT descriptor_digest FROM xshield.site_descriptor_bindings
         WHERE tenant_id = $1 AND site_id = $2 AND policy_revision = $3",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(label)
    .fetch_one(&mut *connection)
    .await?;
    if stored.as_slice() == digest.as_bytes().as_slice() {
        Ok(())
    } else {
        Err(StoreError::CorruptData("site_descriptor_bindings"))
    }
}
