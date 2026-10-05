//! Live page-issued actions for the browser sensor bootstrap.
//!
//! The bootstrap identifies the session from the `HttpOnly` WAF cookie only,
//! so this read returns references solely for page evidence that belongs to
//! that session's current binding and identity epoch. Returning a reference is
//! not authorization: every use is re-verified against the complete credential
//! set, policy, descriptor, evidence and lease by the UI action proof store.

use crate::{PostgresIdentityStore, StoreError};
use sqlx::Row;
use xshield_core::{
    domain::{ActionRef, AuthBindingId, PageEvidenceId, PolicyRevision, SiteId, TenantId},
    identity::{AuthEpoch, UnixSeconds},
    provenance::{HttpMethod, RouteTemplate},
};

/// Upper bound on references one bootstrap may return.
const MAX_PAGE_ACTIONS: i64 = 16;

/// Exact page-instance lookup bound to a session-derived binding.
pub struct PageActionQuery<'a> {
    /// Tenant fixed by trusted listener configuration.
    pub tenant_id: &'a TenantId,
    /// Site fixed by trusted listener configuration.
    pub site_id: &'a SiteId,
    /// Binding resolved from the presented WAF session.
    pub binding_id: &'a AuthBindingId,
    /// Current epoch of that binding.
    pub epoch: AuthEpoch,
    /// Page evidence named by the page handle delivered with the HTML.
    pub page_evidence_id: &'a PageEvidenceId,
    /// Active policy revision fixed by gateway configuration.
    pub policy_revision: &'a PolicyRevision,
    /// Server time used for expiry checks.
    pub now: UnixSeconds,
}

/// One live reference the sensor may attach to an exact first-hop request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageActionView {
    /// Opaque server-issued reference.
    pub action_ref: ActionRef,
    /// Exact method the reference was issued for.
    pub method: HttpMethod,
    /// Exact route template the reference was issued for.
    pub route: RouteTemplate,
    /// Server-side expiry of the reference.
    pub expires_at: UnixSeconds,
}

impl PostgresIdentityStore {
    /// Loads the live actions issued with one page instance of one binding.
    ///
    /// Joins the same evidence, descriptor and policy constraints as the UI
    /// action proof store, plus the binding's current status and epoch, so a
    /// handle copied to another session, a revoked or switched identity, an
    /// expired page or a retired mapping yields no reference. Results are
    /// ordered and bounded to 16 rows.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt stored values.
    pub async fn load_page_actions(
        &self,
        query: PageActionQuery<'_>,
    ) -> Result<Vec<PageActionView>, StoreError> {
        let now = i64::try_from(query.now.value()).map_err(|_| StoreError::NumericRange("now"))?;
        let epoch = i64::try_from(query.epoch.value())
            .map_err(|_| StoreError::NumericRange("auth_epoch"))?;
        let rows = sqlx::query(
            "SELECT action.action_ref, action.method, action.route_template,
                    extract(epoch FROM action.expires_at)::bigint AS expires_at
             FROM xshield.ui_actions action
             JOIN xshield.page_evidence page
               ON page.tenant_id = action.tenant_id
              AND page.site_id = action.site_id
              AND page.page_evidence_id = action.page_evidence_id
              AND page.binding_id = action.binding_id
              AND page.auth_epoch = action.auth_epoch
              AND page.source_request_id = action.source_request_id
              AND page.policy_revision = action.policy_revision
              AND page.mapping_revision = action.mapping_revision
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
              AND descriptor.page_template = page.page_template
             JOIN xshield.policy_revisions policy
               ON policy.tenant_id = action.tenant_id
              AND policy.site_id = action.site_id
              AND policy.revision = action.policy_revision
             JOIN xshield.auth_bindings binding
               ON binding.tenant_id = action.tenant_id
              AND binding.site_id = action.site_id
              AND binding.binding_id = action.binding_id
              AND binding.auth_epoch = action.auth_epoch
             WHERE action.tenant_id = $1 AND action.site_id = $2
               AND action.page_evidence_id = $3 AND action.binding_id = $4
               AND action.auth_epoch = $5 AND action.policy_revision = $6
               AND action.status = 'active'
               AND action.expires_at > GREATEST(to_timestamp($7), clock_timestamp())
               AND page.status = 'verified'
               AND page.expires_at > GREATEST(to_timestamp($7), clock_timestamp())
               AND descriptor.status = 'approved' AND policy.status = 'active'
               AND binding.status = 'active'
               AND binding.absolute_expires_at > GREATEST(to_timestamp($7), clock_timestamp())
             ORDER BY action.action_ref
             LIMIT $8",
        )
        .bind(query.tenant_id.as_str())
        .bind(query.site_id.as_str())
        .bind(query.page_evidence_id.as_str())
        .bind(query.binding_id.as_str())
        .bind(epoch)
        .bind(query.policy_revision.as_str())
        .bind(now)
        .bind(MAX_PAGE_ACTIONS)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(PageActionView {
                    action_ref: ActionRef::parse(row.try_get::<&str, _>("action_ref")?)
                        .map_err(|_| StoreError::CorruptData("action_ref"))?,
                    method: match row.try_get::<&str, _>("method")? {
                        "GET" => HttpMethod::Get,
                        "POST" => HttpMethod::Post,
                        "PUT" => HttpMethod::Put,
                        "PATCH" => HttpMethod::Patch,
                        "DELETE" => HttpMethod::Delete,
                        _ => return Err(StoreError::CorruptData("method")),
                    },
                    route: RouteTemplate::parse(row.try_get::<&str, _>("route_template")?)
                        .map_err(|_| StoreError::CorruptData("route_template"))?,
                    expires_at: UnixSeconds::new(
                        u64::try_from(row.try_get::<i64, _>("expires_at")?)
                            .map_err(|_| StoreError::CorruptData("expires_at"))?,
                    ),
                })
            })
            .collect()
    }
}
