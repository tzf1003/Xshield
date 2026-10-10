//! Site-wide durable job listing for audit administrators:
//! `GET /control/v1/admin/jobs[?cursor=...]`.
//!
//! Purpose: let an audit administrator find any job in the fixed tenant and site,
//! with the owner reference that submitted it, so access reviews can start from
//! the job list. Rows reuse the single-job projection plus the owner reference.
//!
//! Invariants: tenant and site are bound parameters from the authenticated scope.
//! Pages are ordered by bytewise `job_id` descending; the same strict-order and
//! lookahead checks as the owner listing apply. One read-only statement runs
//! inside a transaction with bounded lock and statement time.

use crate::{
    PostgresIdentityStore, StoreError, control_job::ControlJobRecord, control_job::decode_job,
};
use chrono::{DateTime, Utc};
use sqlx::Row;
use xshield_core::domain::{JobId, SiteId, TenantId};

/// Site-wide job page query.
pub struct ControlJobAdminListQuery<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    before: Option<&'a JobId>,
    limit: u16,
}

impl<'a> ControlJobAdminListQuery<'a> {
    /// Validates a page size of 1–128 before database I/O.
    ///
    /// The caller authorizes the fixed scope and the audit role and verifies the
    /// cursor binding. Construction has no storage or audit effects.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an invalid limit.
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        before: Option<&'a JobId>,
        limit: u16,
    ) -> Result<Self, StoreError> {
        if !(1..=128).contains(&limit) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            before,
            limit,
        })
    }
}

/// One job and the owner reference that submitted it.
pub struct ControlJobAdminListItem {
    record: ControlJobRecord,
    owner_ref: String,
}

impl ControlJobAdminListItem {
    /// Returns the single-job projection shared with the owner read.
    #[must_use]
    pub const fn record(&self) -> &ControlJobRecord {
        &self.record
    }

    /// Returns the owner reference that submitted the job.
    #[must_use]
    pub fn owner_ref(&self) -> &str {
        &self.owner_ref
    }
}

/// One snapshot page of every job in the scope, newest identity first.
pub struct ControlJobAdminListPage {
    as_of: DateTime<Utc>,
    items: Vec<ControlJobAdminListItem>,
    next_job_id: Option<JobId>,
}

impl ControlJobAdminListPage {
    /// Database observation time, present even when the page is empty.
    #[must_use]
    pub const fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    /// Fully validated items in strictly descending bytewise identity order.
    #[must_use]
    pub fn items(&self) -> &[ControlJobAdminListItem] {
        &self.items
    }

    /// Last emitted identity when a fully validated lookahead row exists.
    #[must_use]
    pub const fn next_job_id(&self) -> Option<&JobId> {
        self.next_job_id.as_ref()
    }
}

impl PostgresIdentityStore {
    /// Lists every job in one tenant and site in one read-only snapshot.
    ///
    /// No locks beyond the snapshot, mutations, claims or outbox writes occur.
    /// SQL and lock waits are bounded to five seconds; the caller supplies the
    /// overall timeout and writes the management audit.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or a corrupt visible row,
    /// including the lookahead row used to discover another page.
    pub async fn list_control_jobs_for_site(
        &self,
        query: ControlJobAdminListQuery<'_>,
    ) -> Result<ControlJobAdminListPage, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        let as_of: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let mut statement = sqlx::QueryBuilder::new(
            "SELECT job_id, kind, case_id, status, checkpoint, reason_code,
                    retryable, artifact_count, active_artifact_count,
                    created_at, updated_at, completed_at, owner_ref
             FROM xshield.control_jobs
             WHERE tenant_id = ",
        );
        statement
            .push_bind(query.tenant.as_str())
            .push(" AND site_id = ")
            .push_bind(query.site.as_str());
        if let Some(before) = query.before {
            statement
                .push(" AND job_id COLLATE \"C\" < ")
                .push_bind(before.as_str());
        }
        statement
            .push(" ORDER BY job_id COLLATE \"C\" DESC LIMIT ")
            .push_bind(i64::from(query.limit) + 1);
        let rows = statement.build().fetch_all(&mut *tx).await?;
        let page = decode_page(&rows, as_of, &query).map_err(|error| match error {
            StoreError::Database(_) => StoreError::CorruptData("control_job_admin_list_row"),
            other => other,
        });
        tx.rollback().await?;
        page
    }
}

fn decode_page(
    rows: &[sqlx::postgres::PgRow],
    as_of: DateTime<Utc>,
    query: &ControlJobAdminListQuery<'_>,
) -> Result<ControlJobAdminListPage, StoreError> {
    if rows.len() > usize::from(query.limit) + 1 {
        return Err(StoreError::CorruptData("control_job_admin_list_count"));
    }
    let mut items = Vec::with_capacity(rows.len());
    let mut previous: Option<String> = query.before.map(|id| id.as_str().to_owned());
    for row in rows {
        let record = decode_job(row)?;
        let owner_ref: String = row.try_get("owner_ref")?;
        if owner_ref.is_empty() || owner_ref.len() > 256 || owner_ref.chars().any(char::is_control)
        {
            return Err(StoreError::CorruptData("control_job_admin_owner"));
        }
        // Strict order is re-checked here, so an index or planner change fails the
        // page instead of returning duplicated or skipped jobs.
        if previous
            .as_deref()
            .is_some_and(|prior| record.job_id().as_str() >= prior)
        {
            return Err(StoreError::CorruptData("control_job_admin_list_order"));
        }
        previous = Some(record.job_id().as_str().to_owned());
        items.push(ControlJobAdminListItem { record, owner_ref });
    }
    let next_job_id = if items.len() > usize::from(query.limit) {
        items.truncate(usize::from(query.limit));
        items.last().map(|item| item.record.job_id().clone())
    } else {
        None
    };
    Ok(ControlJobAdminListPage {
        as_of,
        items,
        next_job_id,
    })
}
