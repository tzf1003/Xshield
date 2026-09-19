//! Owner-scoped, bounded case evidence collection reads.
//!
//! One database snapshot authorizes the case and supplies membership metadata;
//! catalog availability is not an object integrity or content-access guarantee.

use crate::{
    CASE_EVIDENCE_ITEMS_MAX, CaseEvidenceRecord, InvestigationCaseRecord, PostgresIdentityStore,
    StoreError,
};
use chrono::{DateTime, Utc};
use sqlx::{Row, postgres::PgRow};
use xshield_core::{
    domain::{ArtifactId, CaseId, SiteId, TenantId},
    investigation::InvestigationCaseDraft,
};

/// Exact owner/scope lookup with a bounded, exclusive artifact cursor.
pub struct CaseEvidenceQuery<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    case: &'a CaseId,
    owner: &'a str,
    after: Option<&'a ArtifactId>,
    limit: u16,
}

impl<'a> CaseEvidenceQuery<'a> {
    /// Validates an authenticated owner and a page size of 1–128 references.
    ///
    /// The caller must authenticate scope/owner and verify cursor bindings.
    /// Construction has no storage or audit side effects.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an invalid owner or limit.
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        case: &'a CaseId,
        owner: &'a str,
        after: Option<&'a ArtifactId>,
        limit: u16,
    ) -> Result<Self, StoreError> {
        if !valid_actor(owner) || !(1..=CASE_EVIDENCE_ITEMS_MAX).contains(&u32::from(limit)) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            case,
            owner,
            after,
            limit,
        })
    }
}

/// Catalog state at the page's database observation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseEvidenceAvailability {
    /// The catalog row is active and not yet expired; content is unverified.
    Active,
    /// The catalog expiry has passed, independently of physical deletion.
    Expired,
    /// The catalog has recorded a deletion tombstone.
    Deleted,
    /// The historical membership has no catalog row in this scope.
    Unavailable,
}

impl CaseEvidenceAvailability {
    /// Returns the stable API value, without implying content completeness.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Deleted => "deleted",
            Self::Unavailable => "unavailable",
        }
    }
}

/// One historical membership and its independently observed catalog state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseEvidenceItem {
    record: CaseEvidenceRecord,
    availability: CaseEvidenceAvailability,
}

impl CaseEvidenceItem {
    /// Returns membership identity, original actor, and original addition time.
    #[must_use]
    pub const fn record(&self) -> &CaseEvidenceRecord {
        &self.record
    }

    /// Returns catalog availability, not a manifest or content capability.
    #[must_use]
    pub const fn availability(&self) -> CaseEvidenceAvailability {
        self.availability
    }
}

/// One case header and reference page from the same read-only snapshot.
pub struct CaseEvidencePage {
    case: InvestigationCaseRecord,
    as_of: DateTime<Utc>,
    items: Vec<CaseEvidenceItem>,
    next_artifact_id: Option<ArtifactId>,
}

impl CaseEvidencePage {
    /// Returns the current owned case, including closed historical cases.
    #[must_use]
    pub const fn case(&self) -> &InvestigationCaseRecord {
        &self.case
    }

    /// Returns the case state without exposing any content capability.
    #[must_use]
    pub const fn case_status(&self) -> &'static str {
        self.case.status()
    }

    /// Returns the database statement time used for every availability result.
    #[must_use]
    pub const fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    /// Returns references in ascending artifact identity order.
    #[must_use]
    pub fn items(&self) -> &[CaseEvidenceItem] {
        &self.items
    }

    /// Returns the last emitted identity when the lookahead found another item.
    #[must_use]
    pub const fn next_artifact_id(&self) -> Option<&ArtifactId> {
        self.next_artifact_id.as_ref()
    }
}

impl PostgresIdentityStore {
    /// Reads an owner's case and bounded evidence metadata in one SQL snapshot.
    ///
    /// Missing, foreign-scope, and non-owned cases uniformly return `None`.
    /// Open and closed cases remain investigable. Pages are live observations;
    /// subsequent pages may reflect newly added items or retention changes.
    ///
    /// A read-only transaction bounds each statement and lock wait to 5 seconds;
    /// the caller must bound overall pool/transaction time and durably audit
    /// access before releasing results. No content is read or authorized, and
    /// no expiry or membership is changed. Cancellation rolls back the read.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or any corrupt visible row,
    /// including the lookahead used to determine whether another page exists.
    pub async fn list_case_evidence(
        &self,
        query: CaseEvidenceQuery<'_>,
    ) -> Result<Option<CaseEvidencePage>, StoreError> {
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
        // The lateral page is evaluated within the same MVCC statement as
        // ownership, so a concurrent transfer cannot split authorization from
        // the returned records. No row lock spans the caller's audit barrier.
        let rows = sqlx::query(
            "SELECT case_record.case_id, case_record.owner_ref,
                    case_record.status AS case_status, case_record.purpose,
                    case_record.created_at, statement_timestamp() AS as_of,
                    page.artifact_id, page.added_by, page.added_at,
                    catalog.artifact_id AS catalog_artifact_id,
                    catalog.status AS catalog_status, catalog.expires_at, catalog.deleted_at,
                    outbox.event_id AS outbox_event_id
             FROM xshield.investigation_cases case_record
             LEFT JOIN LATERAL (
                 SELECT item.artifact_id, item.added_by, item.added_at, item.added_event_id
                 FROM xshield.case_items item
                 WHERE item.tenant_id = case_record.tenant_id
                   AND item.site_id = case_record.site_id AND item.case_id = case_record.case_id
                   AND ($5::text IS NULL OR item.artifact_id > $5)
                 ORDER BY item.artifact_id LIMIT $6
             ) page ON true
             LEFT JOIN xshield.artifact_catalog catalog
               ON catalog.tenant_id = case_record.tenant_id
              AND catalog.site_id = case_record.site_id AND catalog.artifact_id = page.artifact_id
             LEFT JOIN xshield.audit_outbox outbox
               ON outbox.event_id = page.added_event_id
              AND outbox.tenant_id = case_record.tenant_id
              AND outbox.site_id = case_record.site_id
              AND outbox.aggregate_ref = case_record.case_id
              AND outbox.event_type = 'case.evidence.added'
             WHERE case_record.tenant_id = $1 AND case_record.site_id = $2
               AND case_record.case_id = $3 AND case_record.owner_ref = $4
             ORDER BY page.artifact_id",
        )
        .bind(query.tenant.as_str())
        .bind(query.site.as_str())
        .bind(query.case.as_str())
        .bind(query.owner)
        .bind(query.after.map(ArtifactId::as_str))
        .bind(i64::from(query.limit) + 1)
        .fetch_all(&mut *tx)
        .await?;
        let page = decode_page(&rows, &query).map_err(|error| match error {
            StoreError::Database(_) => StoreError::CorruptData("case_evidence_row"),
            other => other,
        });
        tx.rollback().await?;
        page
    }
}

fn decode_page(
    rows: &[PgRow],
    query: &CaseEvidenceQuery<'_>,
) -> Result<Option<CaseEvidencePage>, StoreError> {
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    if rows.len() > usize::from(query.limit) + 1 {
        return Err(StoreError::CorruptData("case_evidence_count"));
    }
    let draft = InvestigationCaseDraft::new(
        CaseId::parse(first.try_get::<&str, _>("case_id")?)
            .map_err(|_| StoreError::CorruptData("case_id"))?,
        query.tenant.clone(),
        query.site.clone(),
        first.try_get::<&str, _>("owner_ref")?,
        first.try_get::<&str, _>("purpose")?,
    )
    .map_err(|_| StoreError::CorruptData("case_header"))?;
    if draft.case_id() != query.case || draft.owner_ref() != query.owner {
        return Err(StoreError::CorruptData("case_scope"));
    }
    let status = match first.try_get::<&str, _>("case_status")? {
        "open" => "open",
        "closed" => "closed",
        _ => return Err(StoreError::CorruptData("case_status")),
    };
    let as_of = first.try_get("as_of")?;
    let mut items = Vec::with_capacity(rows.len());
    let mut previous = query.after.map(ArtifactId::as_str);
    for row in rows {
        let artifact: Option<&str> = row.try_get("artifact_id")?;
        let added_by: Option<&str> = row.try_get("added_by")?;
        let added_at: Option<DateTime<Utc>> = row.try_get("added_at")?;
        let outbox: Option<&str> = row.try_get("outbox_event_id")?;
        let catalog_artifact: Option<&str> = row.try_get("catalog_artifact_id")?;
        let availability = catalog_availability(
            catalog_artifact,
            row.try_get("catalog_status")?,
            row.try_get("expires_at")?,
            row.try_get("deleted_at")?,
            as_of,
        )?;
        let Some(artifact) = artifact else {
            if rows.len() != 1
                || added_by.is_some()
                || added_at.is_some()
                || outbox.is_some()
                || availability != CaseEvidenceAvailability::Unavailable
            {
                return Err(StoreError::CorruptData("case_evidence_empty_row"));
            }
            continue;
        };
        if previous.is_some_and(|previous| previous >= artifact)
            || catalog_artifact.is_some_and(|catalog| catalog != artifact)
        {
            return Err(StoreError::CorruptData("case_evidence_order"));
        }
        if outbox.is_none() {
            return Err(StoreError::CorruptData("case_evidence_outbox"));
        }
        let added_by = added_by
            .filter(|value| valid_actor(value))
            .ok_or(StoreError::CorruptData("case_evidence_actor"))?;
        if added_by != query.owner {
            return Err(StoreError::CorruptData("case_evidence_actor"));
        }
        items.push(CaseEvidenceItem {
            record: CaseEvidenceRecord {
                artifact_id: ArtifactId::parse(artifact)
                    .map_err(|_| StoreError::CorruptData("artifact_id"))?,
                added_by: added_by.to_owned(),
                added_at: added_at.ok_or(StoreError::CorruptData("case_evidence_added_at"))?,
            },
            availability,
        });
        previous = Some(artifact);
    }
    let has_more = items.len() > usize::from(query.limit);
    items.truncate(usize::from(query.limit));
    let next_artifact_id = if has_more {
        items.last().map(|item| item.record.artifact_id.clone())
    } else {
        None
    };
    Ok(Some(CaseEvidencePage {
        case: InvestigationCaseRecord {
            case_id: draft.case_id().clone(),
            status,
            purpose: draft.purpose().to_owned(),
            created_at: first.try_get("created_at")?,
        },
        as_of,
        items,
        next_artifact_id,
    }))
}

fn catalog_availability(
    artifact: Option<&str>,
    status: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
    deleted_at: Option<DateTime<Utc>>,
    as_of: DateTime<Utc>,
) -> Result<CaseEvidenceAvailability, StoreError> {
    match (artifact, status, expires_at, deleted_at) {
        (None, None, None, None) => Ok(CaseEvidenceAvailability::Unavailable),
        (Some(_), Some("deleted"), Some(_), Some(_)) => Ok(CaseEvidenceAvailability::Deleted),
        (Some(_), Some("active"), Some(expiry), None) => Ok(if expiry <= as_of {
            CaseEvidenceAvailability::Expired
        } else {
            CaseEvidenceAvailability::Active
        }),
        _ => Err(StoreError::CorruptData("case_evidence_catalog_state")),
    }
}

fn valid_actor(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::{CaseEvidenceAvailability as Availability, catalog_availability};
    use chrono::{Duration, Utc};

    #[test]
    fn catalog_states_are_explicit_and_incoherent_states_fail() {
        let now = Utc::now();
        let future = now + Duration::seconds(60);
        assert_eq!(
            catalog_availability(None, None, None, None, now).unwrap(),
            Availability::Unavailable
        );
        for (status, expires, deleted, expected) in [
            ("active", future, None, Availability::Active),
            ("active", now, None, Availability::Expired),
            (
                "active",
                now - Duration::seconds(1),
                None,
                Availability::Expired,
            ),
            ("deleted", future, Some(now), Availability::Deleted),
            ("deleted", now, Some(now), Availability::Deleted),
        ] {
            assert_eq!(
                catalog_availability(Some("artifact"), Some(status), Some(expires), deleted, now)
                    .unwrap(),
                expected
            );
        }
        for (artifact, status, expires, deleted) in [
            (None, Some("active"), Some(future), None),
            (Some("artifact"), None, None, None),
            (Some("artifact"), Some("active"), None, None),
            (Some("artifact"), Some("active"), Some(future), Some(now)),
            (Some("artifact"), Some("deleted"), Some(future), None),
            (Some("artifact"), Some("expired"), Some(now), None),
        ] {
            assert!(catalog_availability(artifact, status, expires, deleted, now).is_err());
        }
    }
}
