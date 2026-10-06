//! The `share_issuance_rules` rows a site revision needs, written when the
//! revision becomes eligible to reach the edge.
//!
//! A `share_issue` route block makes the edge issue share credentials, but
//! only under an independently approved rule row keyed by
//! `(tenant, site, policy_revision, rule_id)` (docs/05, docs/29). The row is a
//! pure function of the typed block and the two routes it names
//! ([`xshield_core::site::issuance_rules`]); nothing request-supplied reaches
//! it.
//!
//! # Where this runs, and why
//! In exactly the transactions that make a revision *eligible to reach the
//! edge*, under the tenant lock, next to `descriptor_binding` (which has the
//! same eligibility rule and the same reasons):
//! - a save whose revision needs no approval;
//! - the approval or direct-apply authorization that clears the requirement;
//! - the snapshot read that is about to carry a revision written before this
//!   module existed (or by an older control service).
//!
//! Not in a save that is held for approval. The rule rows are the authority
//! the edge checks, keyed by the `policy_revision` label, which a later
//! revision may share with the one the edge serves today (retuning keeps the
//! label). Rows written at save time would therefore exist before anyone
//! approved the block that produces them, and would stay behind when the
//! revision is rejected or superseded. Written at eligibility, the rows are
//! created by the same transaction that clears `SHARE_ISSUE_CHANGED`, from the
//! exact configuration the approver's `(revision, digest, apply id)` names, so
//! approving the block approves the rows, and the revision cannot be carried
//! to the edge without them: every path that makes it carriable calls
//! [`ensure`].
//!
//! # Immutable history
//! Rows are only ever inserted. A row that exists is accepted only if it
//! equals the derived one and is `active`; anything else (another ceiling,
//! another view, a rule the operator retired) is a conflict and nothing is
//! written. Issued shares reference their rule row by key, so no row they
//! rely on can change; a new revision under a new label, or a new rule id
//! under the same label, adds rows and leaves the old ones, which is also what
//! makes a rollback to an older revision find its rows. A conflict is
//! resolved by the author choosing a new `issuance_rule_id` (or label), the
//! same remedy shape as a reused `policy_revision`.
//!
//! # The policy revision row
//! The rule row has a foreign key to the edge's `policy_revisions` row for the
//! label. When the configuration issues pages the edge would create that row
//! with the descriptor digest when it first supplies the set; the control
//! plane creates the identical row (same status and digest, so the edge's own
//! supply then answers `Existing`) because the rule rows could not be written
//! before the edge connects. `descriptor_binding::check` has already shown
//! that no other digest or status is bound to the label. A configuration
//! without page issuance has externally provisioned descriptors and no digest
//! the control plane could write; its row must already exist and be `active`,
//! otherwise the write is a conflict rather than a guess.

use super::ProtectedSiteSnapshotSite;
use crate::StoreError;
use sqlx::{PgConnection, Row};
use xshield_core::{
    SiteConfig,
    domain::{SiteId, TenantId},
    site::{DescriptorDigest, ShareIssuanceRule, issuance_rules},
};

/// What the configuration's rule rows come to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuleCheck {
    /// Nothing to write: not served, no `share_issue`, or a configuration
    /// that cannot be compiled (it is never carried to the edge).
    Free,
    /// Every needed row exists as derived, or (when asked to write) was just
    /// inserted.
    Ready,
    /// A needed row, or the policy revision it hangs on, exists differently
    /// or cannot exist; nothing was written.
    Conflict,
}

/// Checks, and with `write` inserts, the rows `config` needs.
///
/// With `write == false` it is read-only: the early refusal of a save that
/// will be held for approval. With `write == true` the caller's transaction
/// must be the one that makes the revision eligible, and must roll back on
/// [`RuleCheck::Conflict`] (a conflict can still arise between the read and
/// the insert when an operator registers a row by hand; the insert never
/// overwrites).
///
/// # Errors
/// [`StoreError`] when a row cannot be read or written, or stored values
/// are not representable.
pub(super) async fn ensure(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    site_id: &SiteId,
    config: &SiteConfig,
    write: bool,
) -> Result<RuleCheck, StoreError> {
    if !config.is_serving() {
        return Ok(RuleCheck::Free);
    }
    let Ok(rules) = issuance_rules(&config.effective_policy().routes) else {
        return Ok(RuleCheck::Free);
    };
    if rules.is_empty() {
        return Ok(RuleCheck::Free);
    }
    if !ensure_policy_revision(connection, tenant_id, site_id, config, write).await? {
        return Ok(RuleCheck::Conflict);
    }
    for rule in &rules {
        if !ensure_rule(
            connection,
            tenant_id,
            site_id,
            &config.policy_revision,
            rule,
            write,
        )
        .await?
        {
            return Ok(RuleCheck::Conflict);
        }
    }
    Ok(RuleCheck::Ready)
}

/// Runs [`ensure`] for every site of a snapshot read whose desired revision
/// may be carried, and marks the ones that conflict so the caller holds them
/// back instead of sending a snapshot whose share issuance would fail closed
/// at the edge.
///
/// # Errors
/// [`StoreError`] when a row cannot be read or written; nothing is committed
/// then.
pub(super) async fn bind_snapshot_rules(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    sites: &mut [ProtectedSiteSnapshotSite],
) -> Result<(), StoreError> {
    for site in sites
        .iter_mut()
        .filter(|site| !site.requires_approval && site.label_conflict.is_none())
    {
        let config = site.record.site_config();
        if ensure(connection, tenant_id, &site.site_id, &config, true).await? == RuleCheck::Conflict
        {
            site.share_rule_conflict = true;
        }
    }
    Ok(())
}

/// The policy revision row under the label: `true` when it is (or, when
/// asked to write, now is) an `active` row for the digest the configuration
/// denotes.
async fn ensure_policy_revision(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    site_id: &SiteId,
    config: &SiteConfig,
    write: bool,
) -> Result<bool, StoreError> {
    let label = &config.policy_revision;
    // An undecidable digest is a configuration the edge refuses to compile.
    let hex = config
        .edge_descriptor_digest()
        .ok()
        .flatten()
        .as_ref()
        .map(DescriptorDigest::to_hex);
    let accepts = |row: &Option<(String, String)>| match (row, &hex) {
        (Some((status, stored)), Some(hex)) => status == "active" && stored == hex,
        (Some((status, _)), None) => status == "active",
        (None, _) => false,
    };
    let row = read_policy_revision(connection, tenant_id, site_id, label).await?;
    if accepts(&row) {
        return Ok(true);
    }
    let (None, Some(hex)) = (&row, &hex) else {
        return Ok(false);
    };
    if !write {
        // Absent and creatable: the writing call will create it.
        return Ok(true);
    }
    sqlx::query(
        "INSERT INTO xshield.policy_revisions
             (tenant_id, site_id, revision, status, content_digest, artifact_ref)
         VALUES ($1, $2, $3, 'active', $4, $5)
         ON CONFLICT (tenant_id, site_id, revision) DO NOTHING",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(label)
    .bind(hex)
    .bind(format!("control.descriptors.sha256.{hex}"))
    .execute(&mut *connection)
    .await?;
    // Re-read: an edge or an operator may have created it since the check.
    let row = read_policy_revision(connection, tenant_id, site_id, label).await?;
    Ok(accepts(&row))
}

async fn read_policy_revision(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    site_id: &SiteId,
    label: &str,
) -> Result<Option<(String, String)>, StoreError> {
    sqlx::query(
        "SELECT status, content_digest FROM xshield.policy_revisions
         WHERE tenant_id = $1 AND site_id = $2 AND revision = $3",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(label)
    .fetch_optional(&mut *connection)
    .await?
    .map(|row| Ok((row.try_get("status")?, row.try_get("content_digest")?)))
    .transpose()
}

/// One rule row: `true` when it is (or, when asked to write, now is) the
/// derived row and `active`.
async fn ensure_rule(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    site_id: &SiteId,
    label: &str,
    rule: &ShareIssuanceRule,
    write: bool,
) -> Result<bool, StoreError> {
    let ceiling =
        i64::try_from(rule.max_ttl_seconds).map_err(|_| StoreError::NumericRange("share_ttl"))?;
    let matches = |row: Option<RuleRow>| {
        row.is_some_and(|row| {
            row.status == "active"
                && row.issuer_operation_id == rule.issuer_operation_id
                && row.issuer_view_id == rule.issuer_view_id
                && row.share_operation_id == rule.share_operation_id
                && row.share_view_id == rule.share_view_id
                && row.max_ttl_seconds == ceiling
        })
    };
    let existing = read_rule(connection, tenant_id, site_id, label, &rule.rule_id).await?;
    if existing.is_some() {
        return Ok(matches(existing));
    }
    if !write {
        return Ok(true);
    }
    sqlx::query(
        "INSERT INTO xshield.share_issuance_rules (
             tenant_id, site_id, policy_revision, rule_id, issuer_operation_id,
             issuer_view_id, share_operation_id, share_view_id, max_ttl_seconds, status
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active')
         ON CONFLICT (tenant_id, site_id, policy_revision, rule_id) DO NOTHING",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(label)
    .bind(&rule.rule_id)
    .bind(&rule.issuer_operation_id)
    .bind(&rule.issuer_view_id)
    .bind(&rule.share_operation_id)
    .bind(&rule.share_view_id)
    .bind(ceiling)
    .execute(&mut *connection)
    .await?;
    // Whoever won a race for the key, what is stored must be the derived row.
    Ok(matches(
        read_rule(connection, tenant_id, site_id, label, &rule.rule_id).await?,
    ))
}

struct RuleRow {
    issuer_operation_id: String,
    issuer_view_id: String,
    share_operation_id: String,
    share_view_id: String,
    max_ttl_seconds: i64,
    status: String,
}

async fn read_rule(
    connection: &mut PgConnection,
    tenant_id: &TenantId,
    site_id: &SiteId,
    label: &str,
    rule_id: &str,
) -> Result<Option<RuleRow>, StoreError> {
    sqlx::query(
        "SELECT issuer_operation_id, issuer_view_id, share_operation_id,
                share_view_id, max_ttl_seconds, status
         FROM xshield.share_issuance_rules
         WHERE tenant_id = $1 AND site_id = $2 AND policy_revision = $3 AND rule_id = $4",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(label)
    .bind(rule_id)
    .fetch_optional(&mut *connection)
    .await?
    .map(|row| {
        Ok(RuleRow {
            issuer_operation_id: row.try_get("issuer_operation_id")?,
            issuer_view_id: row.try_get("issuer_view_id")?,
            share_operation_id: row.try_get("share_operation_id")?,
            share_view_id: row.try_get("share_view_id")?,
            max_ttl_seconds: row.try_get("max_ttl_seconds")?,
            status: row.try_get("status")?,
        })
    })
    .transpose()
}
