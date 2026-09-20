//! Bounded owner-scoped case discovery from one read-only database snapshot.
//!
//! Case summaries and their creation-event associations are validated together;
//! listing grants no evidence-content capability and emits no outbox events.

use crate::{InvestigationCaseRecord, PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use sqlx::{Row, postgres::PgRow};
use xshield_core::{
    domain::{CaseId, EventId, SiteId, TenantId},
    investigation::InvestigationCaseDraft,
};

/// An authenticated owner's fixed scope and exclusive descending case cursor.
pub struct InvestigationCaseQuery<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    owner: &'a str,
    before: Option<&'a CaseId>,
    limit: u16,
}

impl<'a> InvestigationCaseQuery<'a> {
    /// Validates the owner and a page size of 1–128 case summaries.
    ///
    /// The caller authenticates owner/scope and verifies cursor bindings.
    /// Construction has no storage or audit effects.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an invalid owner or limit.
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        owner: &'a str,
        before: Option<&'a CaseId>,
        limit: u16,
    ) -> Result<Self, StoreError> {
        if owner.is_empty()
            || owner.len() > 256
            || owner.chars().any(char::is_control)
            || !(1..=128).contains(&limit)
        {
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

/// Open and closed case summaries observed in one database statement.
pub struct InvestigationCasePage {
    as_of: DateTime<Utc>,
    items: Vec<InvestigationCaseRecord>,
    next_case_id: Option<CaseId>,
}

impl InvestigationCasePage {
    /// Returns the database statement time, including when the page is empty.
    #[must_use]
    pub const fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    /// Returns owned case summaries in strictly descending case identity order.
    #[must_use]
    pub fn items(&self) -> &[InvestigationCaseRecord] {
        &self.items
    }

    /// Returns the last emitted identity if a validated lookahead exists.
    #[must_use]
    pub const fn next_case_id(&self) -> Option<&CaseId> {
        self.next_case_id.as_ref()
    }
}

impl PostgresIdentityStore {
    /// Lists the authenticated owner's open and closed cases in one snapshot.
    ///
    /// Pages are live observations. Later inserts above the exclusive cursor
    /// appear on refresh; inserts below it can appear on subsequent pages.
    /// Each statement and lock wait is limited to 5 seconds in a read-only
    /// transaction. The caller supplies a 15-second overall database budget,
    /// including pool acquisition, and durable management-access auditing.
    /// Cancellation rolls back the read; this method changes no durable state.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or any corrupt visible row,
    /// including the extra row used to determine whether another page exists.
    pub async fn list_investigation_cases(
        &self,
        query: InvestigationCaseQuery<'_>,
    ) -> Result<InvestigationCasePage, StoreError> {
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
        // A clock seed preserves the database observation even for an empty
        // page. LEFT JOIN keeps broken creation associations visible to the
        // decoder instead of silently removing them before pagination.
        let rows = sqlx::query(
            "SELECT clock.as_of, page.case_id, page.owner_ref, page.status,
                    page.purpose, page.created_at, outbox.event_id AS outbox_event_id
             FROM (SELECT statement_timestamp() AS as_of) clock
             LEFT JOIN LATERAL (
                 SELECT tenant_id, site_id, case_id, owner_ref, status, purpose,
                        created_at, created_event_id
                 FROM xshield.investigation_cases
                 WHERE tenant_id = $1 AND site_id = $2 AND owner_ref = $3
                   AND ($4::text IS NULL OR case_id COLLATE \"C\" < $4)
                 ORDER BY case_id COLLATE \"C\" DESC LIMIT $5
             ) page ON true
             LEFT JOIN xshield.audit_outbox outbox
               ON outbox.event_id = page.created_event_id
              AND outbox.tenant_id = page.tenant_id AND outbox.site_id = page.site_id
              AND outbox.aggregate_ref = page.case_id AND outbox.event_type = 'case.created'
             ORDER BY page.case_id COLLATE \"C\" DESC",
        )
        .bind(query.tenant.as_str())
        .bind(query.site.as_str())
        .bind(query.owner)
        .bind(query.before.map(CaseId::as_str))
        .bind(i64::from(query.limit) + 1)
        .fetch_all(&mut *tx)
        .await?;
        let page = decode_page(&rows, &query).map_err(|error| match error {
            StoreError::Database(_) => StoreError::CorruptData("case_list_row"),
            other => other,
        });
        tx.rollback().await?;
        page
    }
}

fn decode_page(
    rows: &[PgRow],
    query: &InvestigationCaseQuery<'_>,
) -> Result<InvestigationCasePage, StoreError> {
    let first = rows
        .first()
        .ok_or(StoreError::CorruptData("case_list_clock"))?;
    if rows.len() > usize::from(query.limit) + 1 {
        return Err(StoreError::CorruptData("case_list_count"));
    }
    let as_of = first.try_get("as_of")?;
    let mut items = Vec::with_capacity(rows.len());
    let mut previous = query.before.map(CaseId::as_str);
    for row in rows {
        if row.try_get::<DateTime<Utc>, _>("as_of")? != as_of {
            return Err(StoreError::CorruptData("case_list_clock"));
        }
        let case_id: Option<&str> = row.try_get("case_id")?;
        let Some(case_id) = case_id else {
            if rows.len() != 1
                || row.try_get::<Option<&str>, _>("owner_ref")?.is_some()
                || row.try_get::<Option<&str>, _>("status")?.is_some()
                || row.try_get::<Option<&str>, _>("purpose")?.is_some()
                || row
                    .try_get::<Option<DateTime<Utc>>, _>("created_at")?
                    .is_some()
                || row.try_get::<Option<&str>, _>("outbox_event_id")?.is_some()
            {
                return Err(StoreError::CorruptData("case_list_empty_row"));
            }
            continue;
        };
        if previous.is_some_and(|previous| previous <= case_id) {
            return Err(StoreError::CorruptData("case_list_order"));
        }
        let draft = InvestigationCaseDraft::new(
            CaseId::parse(case_id).map_err(|_| StoreError::CorruptData("case_id"))?,
            query.tenant.clone(),
            query.site.clone(),
            row.try_get::<&str, _>("owner_ref")?,
            row.try_get::<&str, _>("purpose")?,
        )
        .map_err(|_| StoreError::CorruptData("case_header"))?;
        if draft.owner_ref() != query.owner {
            return Err(StoreError::CorruptData("case_scope"));
        }
        let status = match row.try_get::<&str, _>("status")? {
            "open" => "open",
            "closed" => "closed",
            _ => return Err(StoreError::CorruptData("case_status")),
        };
        let outbox = row
            .try_get::<Option<&str>, _>("outbox_event_id")?
            .ok_or(StoreError::CorruptData("investigation_case_outbox"))?;
        EventId::parse(outbox).map_err(|_| StoreError::CorruptData("investigation_case_outbox"))?;
        items.push(InvestigationCaseRecord {
            case_id: draft.case_id().clone(),
            status,
            purpose: draft.purpose().to_owned(),
            created_at: row.try_get("created_at")?,
        });
        previous = Some(case_id);
    }
    let has_more = items.len() > usize::from(query.limit);
    items.truncate(usize::from(query.limit));
    let next_case_id = if has_more {
        items.last().map(|item| item.case_id().clone())
    } else {
        None
    };
    Ok(InvestigationCasePage {
        as_of,
        items,
        next_case_id,
    })
}

#[cfg(test)]
mod tests {
    use super::InvestigationCaseQuery;
    use crate::StoreError;
    use xshield_core::domain::{CaseId, SiteId, TenantId};

    #[test]
    fn query_validates_owner_bytes_controls_and_page_boundaries() {
        let tenant = TenantId::parse("tenant_case_list").unwrap();
        let site = SiteId::parse("site_case_list").unwrap();
        let before = CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        for owner in ["owner".to_owned(), "x".repeat(256), "中".repeat(85)] {
            for limit in [1, 128] {
                for cursor in [None, Some(&before)] {
                    assert!(
                        InvestigationCaseQuery::new(&tenant, &site, &owner, cursor, limit).is_ok()
                    );
                }
            }
        }
        for owner in [
            String::new(),
            "x".repeat(257),
            "中".repeat(86),
            "a\n".to_owned(),
        ] {
            assert!(matches!(
                InvestigationCaseQuery::new(&tenant, &site, &owner, None, 1),
                Err(StoreError::InvalidCommand)
            ));
        }
        for limit in [0, 129, u16::MAX] {
            assert!(matches!(
                InvestigationCaseQuery::new(&tenant, &site, "owner", None, limit),
                Err(StoreError::InvalidCommand)
            ));
        }
    }
}
