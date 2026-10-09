//! Owner-scoped listing of durable control-plane jobs, one page per snapshot:
//! `GET /control/v1/jobs[?cursor=...]`.
//!
//! Purpose: let an investigator find the job ids they created without knowing
//! them in advance. Rows reuse the single-job projection, so the page shows no
//! more than the detail read already shows the same owner.
//!
//! Invariants: tenant, site and owner are bound parameters, never inferred from
//! input. Pages are ordered by bytewise `job_id` descending. `UUIDv7` identities
//! are time ordered, so the order is creation order in practice; it is not a
//! strict guarantee across concurrent writers. One read-only statement runs
//! inside a transaction with bounded lock and statement time.

use crate::{
    PostgresIdentityStore, StoreError, control_job::ControlJobRecord, control_job::decode_job,
    evidence_access_inspection::valid_subject,
};
use chrono::{DateTime, Utc};
use xshield_core::domain::{JobId, SiteId, TenantId};

/// Owner-scoped job page query.
pub struct ControlJobListQuery<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    owner: &'a str,
    before: Option<&'a JobId>,
    limit: u16,
}

impl<'a> ControlJobListQuery<'a> {
    /// Validates a canonical owner and a page size of 1–128 before database I/O.
    ///
    /// The caller authorizes the fixed scope and owner and verifies the cursor
    /// binding. Construction has no storage or audit effects.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an invalid owner or limit.
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        owner: &'a str,
        before: Option<&'a JobId>,
        limit: u16,
    ) -> Result<Self, StoreError> {
        if !valid_subject(owner) || !(1..=128).contains(&limit) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            owner,
            before,
            limit,
        })
    }
}

/// One snapshot page of the owner's jobs, newest identity first.
pub struct ControlJobListPage {
    as_of: DateTime<Utc>,
    items: Vec<ControlJobRecord>,
    next_job_id: Option<JobId>,
}

impl ControlJobListPage {
    /// Database observation time, present even when the page is empty.
    #[must_use]
    pub const fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    /// Fully validated records in strictly descending bytewise identity order.
    #[must_use]
    pub fn items(&self) -> &[ControlJobRecord] {
        &self.items
    }

    /// Last emitted identity when a fully validated lookahead row exists.
    #[must_use]
    pub const fn next_job_id(&self) -> Option<&JobId> {
        self.next_job_id.as_ref()
    }
}

impl PostgresIdentityStore {
    /// Lists one owner's jobs in a single read-only snapshot.
    ///
    /// No locks beyond the snapshot, mutations, claims or outbox writes occur.
    /// SQL and lock waits are bounded to five seconds; the caller supplies the
    /// overall timeout and writes the management audit.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or a corrupt visible row,
    /// including the lookahead row used to discover another page.
    pub async fn list_control_jobs(
        &self,
        query: ControlJobListQuery<'_>,
    ) -> Result<ControlJobListPage, StoreError> {
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
                    created_at, updated_at, completed_at
             FROM xshield.control_jobs
             WHERE tenant_id = ",
        );
        statement
            .push_bind(query.tenant.as_str())
            .push(" AND site_id = ")
            .push_bind(query.site.as_str())
            .push(" AND owner_ref = ")
            .push_bind(query.owner);
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
            StoreError::Database(_) => StoreError::CorruptData("control_job_list_row"),
            other => other,
        });
        tx.rollback().await?;
        page
    }
}

fn decode_page(
    rows: &[sqlx::postgres::PgRow],
    as_of: DateTime<Utc>,
    query: &ControlJobListQuery<'_>,
) -> Result<ControlJobListPage, StoreError> {
    if rows.len() > usize::from(query.limit) + 1 {
        return Err(StoreError::CorruptData("control_job_list_count"));
    }
    let mut records = Vec::with_capacity(rows.len());
    let mut previous: Option<String> = query.before.map(|id| id.as_str().to_owned());
    for row in rows {
        let record = decode_job(row)?;
        // The row order is enforced again here, so a broken index or planner
        // change fails the page instead of returning duplicated or skipped jobs.
        if previous
            .as_deref()
            .is_some_and(|prior| record.job_id().as_str() >= prior)
        {
            return Err(StoreError::CorruptData("control_job_list_order"));
        }
        previous = Some(record.job_id().as_str().to_owned());
        records.push(record);
    }
    let next_job_id = if records.len() > usize::from(query.limit) {
        records.truncate(usize::from(query.limit));
        records.last().map(|record| record.job_id().clone())
    } else {
        None
    };
    Ok(ControlJobListPage {
        as_of,
        items: records,
        next_job_id,
    })
}
