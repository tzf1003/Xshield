//! Bounded scoped request discovery with the same validation as detail reads.

use crate::{
    EvidenceAccessInspection, PostgresIdentityStore, StoreError,
    evidence_access_inspection::{JOINS, PROJECTION, decode, supported_time, valid_subject},
};
use chrono::{DateTime, Utc};
use sqlx::{Row, postgres::PgRow};
use xshield_core::domain::{EvidenceAccessRequestId, SiteId, TenantId};

/// Fixed server-authorized request discovery purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceAccessListView {
    /// The authenticated subject's requests, including all historical states.
    Mine,
    /// Pending requests belonging to other subjects in the authenticated scope.
    Review,
}

impl EvidenceAccessListView {
    /// Stable query and response spelling of this discovery purpose.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mine => "mine",
            Self::Review => "review",
        }
    }
}

/// Validated immutable scope, subject and exclusive descending identity cursor.
pub struct EvidenceAccessListQuery<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    subject: &'a str,
    view: EvidenceAccessListView,
    before: Option<&'a EvidenceAccessRequestId>,
    limit: u16,
}

impl<'a> EvidenceAccessListQuery<'a> {
    /// Validates a canonical subject and a page size of 1–128 before database I/O.
    ///
    /// The caller authenticates the fixed scope and subject, verifies cursor
    /// bindings and requires the sensitive-evidence approver role for Review.
    /// Construction has no storage or audit effects.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an invalid subject or limit.
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        subject: &'a str,
        view: EvidenceAccessListView,
        before: Option<&'a EvidenceAccessRequestId>,
        limit: u16,
    ) -> Result<Self, StoreError> {
        if !valid_subject(subject) || !(1..=128).contains(&limit) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            subject,
            view,
            before,
            limit,
        })
    }
}

/// Metadata from one statement snapshot; grants no content or decision authority.
pub struct EvidenceAccessPage {
    as_of: DateTime<Utc>,
    items: Vec<EvidenceAccessInspection>,
    next_access_request_id: Option<EvidenceAccessRequestId>,
}

impl EvidenceAccessPage {
    /// Database observation time, present even when the page is empty.
    #[must_use]
    pub const fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    /// Fully validated metadata in strictly descending bytewise identity order.
    #[must_use]
    pub fn items(&self) -> &[EvidenceAccessInspection] {
        &self.items
    }

    /// Last emitted identity when a fully validated lookahead row exists.
    #[must_use]
    pub const fn next_access_request_id(&self) -> Option<&EvidenceAccessRequestId> {
        self.next_access_request_id.as_ref()
    }
}

impl PostgresIdentityStore {
    /// Lists own history or other subjects' pending requests in one snapshot.
    ///
    /// Closed cases and deleted artifacts remain observable. Pages are live:
    /// inserts above the cursor appear on refresh, and approvals can remove a
    /// pending item between pages. No business locks, mutations, content reads
    /// or outbox writes occur. SQL and lock waits are bounded to five seconds;
    /// the caller supplies a 15-second overall timeout including pool access,
    /// and durably audits the result. Cancellation rolls back the transaction.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or any corrupt visible row,
    /// including the additional row used to discover another page.
    pub async fn list_evidence_access_requests(
        &self,
        query: EvidenceAccessListQuery<'_>,
    ) -> Result<EvidenceAccessPage, StoreError> {
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
        // Fixed predicates preserve the partial pending index. All variable
        // input remains bound. The clock seed keeps empty-page time observable.
        let visibility = match query.view {
            EvidenceAccessListView::Mine => "requested_by = $3",
            EvidenceAccessListView::Review => "status = 'pending' AND requested_by <> $3",
        };
        let mut statement = sqlx::QueryBuilder::new("SELECT clock.as_of, ");
        statement
            .push(PROJECTION)
            .push(
                "
             FROM (SELECT statement_timestamp() AS as_of) clock
             LEFT JOIN LATERAL (
                 SELECT * FROM xshield.evidence_access_requests
                 WHERE tenant_id = $1 AND site_id = $2 AND ",
            )
            .push(visibility)
            .push(
                "
                   AND ($4::text IS NULL OR access_request_id COLLATE \"C\" < $4)
                 ORDER BY access_request_id COLLATE \"C\" DESC LIMIT $5
             ) access ON true ",
            )
            .push(JOINS)
            .push(" ORDER BY access.access_request_id COLLATE \"C\" DESC");
        let rows = statement
            .build()
            .bind(query.tenant.as_str())
            .bind(query.site.as_str())
            .bind(query.subject)
            .bind(query.before.map(EvidenceAccessRequestId::as_str))
            .bind(i64::from(query.limit) + 1)
            .fetch_all(&mut *tx)
            .await?;
        let page = decode_page(&rows, &query).map_err(|error| match error {
            StoreError::Database(_) => StoreError::CorruptData("evidence_access_list_row"),
            other => other,
        });
        tx.rollback().await?;
        page
    }
}

fn decode_page(
    rows: &[PgRow],
    query: &EvidenceAccessListQuery<'_>,
) -> Result<EvidenceAccessPage, StoreError> {
    let first = rows
        .first()
        .ok_or(StoreError::CorruptData("evidence_access_list_clock"))?;
    let as_of = supported_time(first.try_get("as_of")?)?;
    if rows.len() > usize::from(query.limit) + 1 {
        return Err(StoreError::CorruptData("evidence_access_list_count"));
    }
    let mut items = Vec::with_capacity(rows.len());
    let mut previous = query.before.map(EvidenceAccessRequestId::as_str);
    for row in rows {
        if row.try_get::<DateTime<Utc>, _>("as_of")? != as_of {
            return Err(StoreError::CorruptData("evidence_access_list_clock"));
        }
        let Some(id) = row.try_get::<Option<&str>, _>("access_request_id")? else {
            if rows.len() != 1 {
                return Err(StoreError::CorruptData("evidence_access_list_empty_row"));
            }
            continue;
        };
        if previous.is_some_and(|previous| previous <= id) {
            return Err(StoreError::CorruptData("evidence_access_list_order"));
        }
        let item = decode(row, query.tenant, query.site)?;
        let visible = match query.view {
            EvidenceAccessListView::Mine => item.requested_by == query.subject,
            EvidenceAccessListView::Review => {
                item.requested_by != query.subject && item.stored_status == "pending"
            }
        };
        if !visible {
            return Err(StoreError::CorruptData("evidence_access_list_visibility"));
        }
        previous = Some(id);
        items.push(item);
    }
    let has_more = items.len() > usize::from(query.limit);
    items.truncate(usize::from(query.limit));
    let next_access_request_id = if has_more {
        items.last().map(|item| item.access_request_id.clone())
    } else {
        None
    };
    Ok(EvidenceAccessPage {
        as_of,
        items,
        next_access_request_id,
    })
}
