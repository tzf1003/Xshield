//! Bounded hold history with case and outbox facts from one read-only snapshot.

use super::{
    CASE_EVIDENCE_HOLD_HISTORY_MAX, CaseEvidenceHoldRecord,
    record::{decode_hold, event},
};
use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Row, postgres::PgRow};
use xshield_core::domain::{CaseId, EventId, SiteId, TenantId};

/// Exact case/scope lookup with an exclusive hold identity cursor.
pub struct CaseEvidenceHoldQuery<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    case: &'a CaseId,
    after: Option<&'a EventId>,
    limit: u16,
}

impl<'a> CaseEvidenceHoldQuery<'a> {
    /// Validates a page size of 1–128 historical holds.
    ///
    /// The caller authenticates an `AuditAdministrator` in this exact scope and
    /// verifies cursor bindings. Construction has no storage or audit effects.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when the page size is out of bounds.
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        case: &'a CaseId,
        after: Option<&'a EventId>,
        limit: u16,
    ) -> Result<Self, StoreError> {
        if !(1..=CASE_EVIDENCE_HOLD_HISTORY_MAX).contains(&i64::from(limit)) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            case,
            after,
            limit,
        })
    }
}

/// Case state and ordered hold history from one database statement snapshot.
pub struct CaseEvidenceHoldPage {
    case_id: CaseId,
    case_status: &'static str,
    as_of: DateTime<Utc>,
    items: Vec<CaseEvidenceHoldRecord>,
    next_hold_id: Option<EventId>,
}

impl CaseEvidenceHoldPage {
    /// Returns the case identity, independently of case ownership.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the observed `open` or `closed` case state.
    #[must_use]
    pub const fn case_status(&self) -> &'static str {
        self.case_status
    }

    /// Returns the database statement time; no local clock determines status.
    #[must_use]
    pub const fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    /// Returns original deadlines and release fields in ascending hold ID order.
    #[must_use]
    pub fn items(&self) -> &[CaseEvidenceHoldRecord] {
        &self.items
    }

    /// Returns the last emitted ID only when a validated lookahead row exists.
    #[must_use]
    pub const fn next_hold_id(&self) -> Option<&EventId> {
        self.next_hold_id.as_ref()
    }
}

impl PostgresIdentityStore {
    /// Reads bounded hold history and both transition facts in one SQL snapshot.
    ///
    /// Existing open and closed cases are visible to the authenticated scope;
    /// missing or foreign-scope cases return `None`. An existing case with no
    /// matching holds returns an empty page. Subsequent pages are live snapshots.
    ///
    /// The read-only transaction bounds statements and lock waits to five seconds.
    /// Callers must bound the complete operation, including pool acquisition, to
    /// 15 seconds and durably audit access before returning its result. This read
    /// changes no case, hold, expiry, content permission, or outbox state; dropping
    /// a cancelled future rolls back the read transaction.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt history/outbox facts,
    /// including a corrupt lookahead row that would not be emitted in this page.
    pub async fn list_case_evidence_holds(
        &self,
        query: CaseEvidenceHoldQuery<'_>,
    ) -> Result<Option<CaseEvidenceHoldPage>, StoreError> {
        let mut tx = self.retention_transaction().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        // One statement prevents a concurrent release from mixing its updated
        // hold row with the preceding snapshot's absent release outbox event.
        let rows = sqlx::query(
            "SELECT case_record.case_id AS queried_case_id,
                    case_record.status AS case_status, statement_timestamp() AS as_of,
                    page.*, created.envelope AS created_envelope,
                    released.envelope AS released_envelope
             FROM xshield.investigation_cases case_record
             LEFT JOIN LATERAL (
                 SELECT hold.* FROM xshield.case_evidence_holds hold
                 WHERE hold.tenant_id=case_record.tenant_id
                   AND hold.site_id=case_record.site_id AND hold.case_id=case_record.case_id
                   AND ($4::text IS NULL OR hold.created_event_id>$4)
                 ORDER BY hold.created_event_id LIMIT $5
             ) page ON true
             LEFT JOIN xshield.audit_outbox created
               ON created.event_id=page.created_event_id
              AND created.tenant_id=case_record.tenant_id AND created.site_id=case_record.site_id
              AND created.aggregate_ref=page.artifact_id AND created.event_type='evidence.hold.created'
             LEFT JOIN xshield.audit_outbox released
               ON released.event_id=page.released_event_id
              AND released.tenant_id=case_record.tenant_id AND released.site_id=case_record.site_id
              AND released.aggregate_ref=page.artifact_id AND released.event_type='evidence.hold.released'
             WHERE case_record.tenant_id=$1 AND case_record.site_id=$2 AND case_record.case_id=$3
             ORDER BY page.created_event_id",
        )
        .bind(query.tenant.as_str()).bind(query.site.as_str()).bind(query.case.as_str())
        .bind(query.after.map(EventId::as_str)).bind(i64::from(query.limit) + 1)
        .fetch_all(&mut *tx).await?;
        let page = decode_page(&rows, &query).map_err(|error| match error {
            StoreError::Database(_) => StoreError::CorruptData("hold_read_row"),
            other => other,
        });
        tx.rollback().await?;
        page
    }
}

fn decode_page(
    rows: &[PgRow],
    query: &CaseEvidenceHoldQuery<'_>,
) -> Result<Option<CaseEvidenceHoldPage>, StoreError> {
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    if rows.len() > usize::from(query.limit) + 1 {
        return Err(StoreError::CorruptData("hold_read_count"));
    }
    let case_id = CaseId::parse(first.try_get::<&str, _>("queried_case_id")?)
        .map_err(|_| StoreError::CorruptData("hold_read_case_id"))?;
    if case_id != *query.case {
        return Err(StoreError::CorruptData("hold_read_scope"));
    }
    let case_status = match first.try_get::<&str, _>("case_status")? {
        "open" => "open",
        "closed" => "closed",
        _ => return Err(StoreError::CorruptData("hold_read_case_status")),
    };
    let mut items = Vec::with_capacity(rows.len());
    let mut previous = query.after.map(EventId::as_str);
    for row in rows {
        let id: Option<&str> = row.try_get("created_event_id")?;
        let created: Option<Value> = row.try_get("created_envelope")?;
        let released: Option<Value> = row.try_get("released_envelope")?;
        let Some(id) = id else {
            if rows.len() != 1
                || created.is_some()
                || released.is_some()
                || row.try_get::<Option<&str>, _>("artifact_id")?.is_some()
            {
                return Err(StoreError::CorruptData("hold_read_empty_row"));
            }
            continue;
        };
        let record = decode_hold(row)?;
        if record.tenant_id != *query.tenant
            || record.site_id != *query.site
            || record.case_id != *query.case
        {
            return Err(StoreError::CorruptData("hold_read_scope"));
        }
        if previous.is_some_and(|previous| previous >= id) {
            return Err(StoreError::CorruptData("hold_read_order"));
        }
        if created.as_ref() != Some(&event(row, false)?.2)
            || (record.released_event_id.is_some()
                && released.as_ref() != Some(&event(row, true)?.2))
        {
            return Err(StoreError::CorruptData("hold_outbox"));
        }
        previous = Some(id);
        items.push(record);
    }
    let has_more = items.len() > usize::from(query.limit);
    items.truncate(usize::from(query.limit));
    let next_hold_id = if has_more {
        items.last().map(|item| item.created_event_id.clone())
    } else {
        None
    };
    Ok(Some(CaseEvidenceHoldPage {
        case_id,
        case_status,
        as_of: first.try_get("as_of")?,
        items,
        next_hold_id,
    }))
}
