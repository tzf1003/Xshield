//! Bounded export discovery: a requester's own history and the independent
//! approval queue, projected as metadata only from one read-only statement.
//!
//! Purpose text, decision reasons and package identity stay behind the detail
//! read. This module never selects them, so no later change to a row mapper can
//! leak them into a list page. Listing grants no download or approval authority.

use crate::{PostgresIdentityStore, StoreError, evidence_access_inspection::valid_subject};
use chrono::{DateTime, Utc};
use sqlx::{Row, postgres::PgRow};
use xshield_core::domain::{CaseId, ExportId, SiteId, TenantId};

const EXPORT_KIND: &str = "metadata_only";

/// Fixed server-authorized export discovery purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvestigationExportListView {
    /// The authenticated subject's exports, in every persisted state.
    Mine,
    /// Other subjects' exports that still await an independent decision.
    Review,
}

impl InvestigationExportListView {
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
pub struct InvestigationExportListQuery<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    subject: &'a str,
    view: InvestigationExportListView,
    before: Option<&'a ExportId>,
    limit: u16,
}

impl<'a> InvestigationExportListQuery<'a> {
    /// Validates a canonical subject and a page size of 1–128 before database I/O.
    ///
    /// The caller authenticates the fixed scope and subject, verifies cursor
    /// bindings and requires the approver role for [`InvestigationExportListView::Review`].
    /// Construction has no storage or audit effects.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an invalid subject or limit.
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        subject: &'a str,
        view: InvestigationExportListView,
        before: Option<&'a ExportId>,
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

/// One export's discovery metadata; it carries no purpose, reason or package data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationExportListItem {
    export_id: ExportId,
    case_id: CaseId,
    requested_by: String,
    status: &'static str,
    requested_at: DateTime<Utc>,
    decided_by: Option<String>,
    decided_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

impl InvestigationExportListItem {
    /// Returns the export identity.
    #[must_use]
    pub const fn export_id(&self) -> &ExportId {
        &self.export_id
    }

    /// Returns the case the export was requested for.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the authenticated requester, who also owns the case.
    #[must_use]
    pub fn requested_by(&self) -> &str {
        &self.requested_by
    }

    /// Returns the persisted lifecycle state, independent of any observed expiry.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        self.status
    }

    /// Returns the database-assigned request time (the detail `created_at`).
    #[must_use]
    pub const fn requested_at(&self) -> DateTime<Utc> {
        self.requested_at
    }

    /// Returns the independent deciding subject, if decided.
    #[must_use]
    pub fn decided_by(&self) -> Option<&str> {
        self.decided_by.as_deref()
    }

    /// Returns the database decision time, if decided.
    #[must_use]
    pub const fn decided_at(&self) -> Option<DateTime<Utc>> {
        self.decided_at
    }

    /// Returns the short-lived package deadline, if the export was approved.
    #[must_use]
    pub const fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }
}

/// Metadata from one statement snapshot; it grants no download or decision authority.
pub struct InvestigationExportPage {
    as_of: DateTime<Utc>,
    items: Vec<InvestigationExportListItem>,
    next_export_id: Option<ExportId>,
}

impl InvestigationExportPage {
    /// Database observation time, present even when the page is empty.
    #[must_use]
    pub const fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    /// Fully validated metadata in strictly descending bytewise identity order.
    #[must_use]
    pub fn items(&self) -> &[InvestigationExportListItem] {
        &self.items
    }

    /// Last emitted identity when a fully validated lookahead row exists.
    #[must_use]
    pub const fn next_export_id(&self) -> Option<&ExportId> {
        self.next_export_id.as_ref()
    }
}

impl PostgresIdentityStore {
    /// Lists own history or other subjects' pending exports in one snapshot.
    ///
    /// Terminal and expired states stay observable. Pages are live: inserts
    /// above the cursor appear on refresh and a decision can remove a pending
    /// item between pages. No business locks, mutations, package reads, claims
    /// or outbox writes occur. SQL and lock waits are bounded to five seconds;
    /// the caller supplies a 15-second overall timeout including pool access
    /// and durably audits the result. Cancellation rolls the transaction back.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or any corrupt visible row,
    /// including the additional row used to discover another page.
    pub async fn list_investigation_exports(
        &self,
        query: InvestigationExportListQuery<'_>,
    ) -> Result<InvestigationExportPage, StoreError> {
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
        // The fixed predicates let the planner use the two ordered indexes of
        // migration 0050; every variable value is bound. The clock seed keeps
        // the database observation time available for an empty page, and the
        // package columns are reduced to one flag so identities never leave SQL.
        let mut statement = sqlx::QueryBuilder::new(
            "SELECT clock.as_of, page.export_id, page.case_id, page.requested_by, page.kind,
                    page.status, page.decided_by, page.decided_at, page.expires_at,
                    page.created_at, page.package_attached
             FROM (SELECT statement_timestamp() AS as_of) clock
             LEFT JOIN LATERAL (
                 SELECT export_id, case_id, requested_by, kind, status, decided_by,
                        decided_at, expires_at, created_at,
                        (package_artifact_id IS NOT NULL AND package_request_id IS NOT NULL
                         AND package_digest IS NOT NULL AND package_bytes IS NOT NULL)
                            AS package_attached
                 FROM xshield.investigation_exports
                 WHERE tenant_id = ",
        );
        statement
            .push_bind(query.tenant.as_str())
            .push(" AND site_id = ")
            .push_bind(query.site.as_str());
        match query.view {
            InvestigationExportListView::Mine => {
                statement
                    .push(" AND requested_by = ")
                    .push_bind(query.subject);
            }
            InvestigationExportListView::Review => {
                statement
                    .push(" AND status = 'pending_approval' AND requested_by <> ")
                    .push_bind(query.subject);
            }
        }
        if let Some(before) = query.before {
            statement
                .push(" AND export_id COLLATE \"C\" < ")
                .push_bind(before.as_str());
        }
        statement
            .push(" ORDER BY export_id COLLATE \"C\" DESC LIMIT ")
            .push_bind(i64::from(query.limit) + 1)
            .push(") page ON true ORDER BY page.export_id COLLATE \"C\" DESC");
        let rows = statement.build().fetch_all(&mut *tx).await?;
        let page = decode_page(&rows, &query).map_err(|error| match error {
            StoreError::Database(_) => StoreError::CorruptData("investigation_export_list_row"),
            other => other,
        });
        tx.rollback().await?;
        page
    }
}

fn decode_page(
    rows: &[PgRow],
    query: &InvestigationExportListQuery<'_>,
) -> Result<InvestigationExportPage, StoreError> {
    let first = rows
        .first()
        .ok_or(StoreError::CorruptData("investigation_export_list_clock"))?;
    let as_of = supported_time(first.try_get("as_of")?)?;
    if rows.len() > usize::from(query.limit) + 1 {
        return Err(StoreError::CorruptData("investigation_export_list_count"));
    }
    let mut items = Vec::with_capacity(rows.len());
    let mut previous = query.before.map(ExportId::as_str);
    for row in rows {
        if row.try_get::<DateTime<Utc>, _>("as_of")? != as_of {
            return Err(StoreError::CorruptData("investigation_export_list_clock"));
        }
        let Some(export_id) = row.try_get::<Option<&str>, _>("export_id")? else {
            // The clock seed survives an empty scan as exactly one all-NULL row;
            // anything else would be a page that silently lost its identity.
            if rows.len() != 1 || !empty_marker(row)? {
                return Err(StoreError::CorruptData(
                    "investigation_export_list_empty_row",
                ));
            }
            continue;
        };
        if previous.is_some_and(|previous| previous <= export_id) {
            return Err(StoreError::CorruptData("investigation_export_list_order"));
        }
        let item = validate(
            &RawRow {
                export_id,
                case_id: row.try_get("case_id")?,
                requested_by: row.try_get("requested_by")?,
                kind: row.try_get("kind")?,
                status: row.try_get("status")?,
                decided_by: row.try_get("decided_by")?,
                decided_at: row.try_get("decided_at")?,
                expires_at: row.try_get("expires_at")?,
                created_at: row.try_get("created_at")?,
                package_attached: row.try_get("package_attached")?,
            },
            query.view,
            query.subject,
        )?;
        previous = Some(export_id);
        items.push(item);
    }
    let has_more = items.len() > usize::from(query.limit);
    items.truncate(usize::from(query.limit));
    let next_export_id = if has_more {
        items.last().map(|item| item.export_id.clone())
    } else {
        None
    };
    Ok(InvestigationExportPage {
        as_of,
        items,
        next_export_id,
    })
}

fn empty_marker(row: &PgRow) -> Result<bool, StoreError> {
    Ok(row.try_get::<Option<&str>, _>("case_id")?.is_none()
        && row.try_get::<Option<&str>, _>("requested_by")?.is_none()
        && row.try_get::<Option<&str>, _>("kind")?.is_none()
        && row.try_get::<Option<&str>, _>("status")?.is_none()
        && row.try_get::<Option<&str>, _>("decided_by")?.is_none()
        && row
            .try_get::<Option<DateTime<Utc>>, _>("decided_at")?
            .is_none()
        && row
            .try_get::<Option<DateTime<Utc>>, _>("expires_at")?
            .is_none()
        && row
            .try_get::<Option<DateTime<Utc>>, _>("created_at")?
            .is_none()
        && row
            .try_get::<Option<bool>, _>("package_attached")?
            .is_none())
}

/// Untrusted column values of one visible row, before any invariant is applied.
struct RawRow<'a> {
    export_id: &'a str,
    case_id: &'a str,
    requested_by: &'a str,
    kind: &'a str,
    status: &'a str,
    decided_by: Option<&'a str>,
    decided_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    package_attached: bool,
}

// Mirrors the invariants of the detail decoder and of the table constraints, so
// a row that the detail read would refuse cannot be advertised by a list page.
fn validate(
    raw: &RawRow<'_>,
    view: InvestigationExportListView,
    subject: &str,
) -> Result<InvestigationExportListItem, StoreError> {
    let corrupt = |field| StoreError::CorruptData(field);
    let export_id = ExportId::parse(raw.export_id)
        .map_err(|_| corrupt("investigation_export_list_export_id"))?;
    let case_id =
        CaseId::parse(raw.case_id).map_err(|_| corrupt("investigation_export_list_case_id"))?;
    let status = match raw.status {
        "pending_approval" => "pending_approval",
        "approved" => "approved",
        "ready" => "ready",
        "rejected" => "rejected",
        "expired" => "expired",
        "failed" => "failed",
        _ => return Err(corrupt("investigation_export_list_status")),
    };
    if raw.kind != EXPORT_KIND || !valid_subject(raw.requested_by) {
        return Err(corrupt("investigation_export_list_record"));
    }
    let requested_at = supported_time(raw.created_at)?;
    let decided_at = raw.decided_at.map(supported_time).transpose()?;
    let expires_at = raw.expires_at.map(supported_time).transpose()?;
    let state_is_valid = match status {
        "pending_approval" => {
            raw.decided_by.is_none()
                && decided_at.is_none()
                && expires_at.is_none()
                && !raw.package_attached
        }
        // Approval stamps the package deadline before the package exists.
        "approved" => {
            raw.decided_by.is_some()
                && decided_at.is_some()
                && expires_at.is_some()
                && !raw.package_attached
        }
        "ready" => {
            raw.decided_by.is_some()
                && decided_at.is_some()
                && expires_at.is_some()
                && raw.package_attached
        }
        _ => raw.decided_by.is_some() && decided_at.is_some() && !raw.package_attached,
    };
    // Independent approval is a hard rule: a stored self-decision is corruption,
    // not a state that discovery may paper over.
    if !state_is_valid
        || raw
            .decided_by
            .is_some_and(|actor| !valid_subject(actor) || actor == raw.requested_by)
        || decided_at.is_some_and(|at| at < requested_at)
    {
        return Err(corrupt("investigation_export_list_state"));
    }
    let visible = match view {
        InvestigationExportListView::Mine => raw.requested_by == subject,
        InvestigationExportListView::Review => {
            raw.requested_by != subject && status == "pending_approval"
        }
    };
    if !visible {
        return Err(corrupt("investigation_export_list_visibility"));
    }
    Ok(InvestigationExportListItem {
        export_id,
        case_id,
        requested_by: raw.requested_by.to_owned(),
        status,
        requested_at,
        decided_by: raw.decided_by.map(str::to_owned),
        decided_at,
        expires_at,
    })
}

fn supported_time(value: DateTime<Utc>) -> Result<DateTime<Utc>, StoreError> {
    if value.timestamp() < 0
        || value.timestamp_nanos_opt().is_none()
        || value.timestamp_subsec_nanos() >= 1_000_000_000
    {
        return Err(StoreError::CorruptData("investigation_export_list_time"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        InvestigationExportListQuery, InvestigationExportListView as View, RawRow, validate,
    };
    use crate::StoreError;
    use chrono::{DateTime, TimeDelta, Utc};
    use xshield_core::domain::{ExportId, SiteId, TenantId};

    const EXPORT: &str = "export_018f2a3b-4c5d-7000-8000-000000000001";
    const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000002";

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + seconds, 0).unwrap()
    }

    fn pending() -> RawRow<'static> {
        RawRow {
            export_id: EXPORT,
            case_id: CASE,
            requested_by: "requester",
            kind: "metadata_only",
            status: "pending_approval",
            decided_by: None,
            decided_at: None,
            expires_at: None,
            created_at: at(0),
            package_attached: false,
        }
    }

    fn decided(status: &'static str) -> RawRow<'static> {
        RawRow {
            status,
            decided_by: Some("approver"),
            decided_at: Some(at(60)),
            expires_at: matches!(status, "approved" | "ready").then(|| at(960)),
            package_attached: status == "ready",
            ..pending()
        }
    }

    #[test]
    fn query_validates_subject_bytes_controls_and_page_boundaries() {
        let tenant = TenantId::parse("tenant_export_list").unwrap();
        let site = SiteId::parse("site_export_list").unwrap();
        let before = ExportId::parse(EXPORT).unwrap();
        for view in [View::Mine, View::Review] {
            for subject in ["actor".to_owned(), "x".repeat(256), "中".repeat(85)] {
                for limit in [1, 128] {
                    for cursor in [None, Some(&before)] {
                        assert!(
                            InvestigationExportListQuery::new(
                                &tenant, &site, &subject, view, cursor, limit
                            )
                            .is_ok()
                        );
                    }
                }
            }
            for subject in [
                String::new(),
                "x".repeat(257),
                "中".repeat(86),
                " actor".to_owned(),
                "actor\u{a0}".to_owned(),
                "actor\n".to_owned(),
            ] {
                assert!(matches!(
                    InvestigationExportListQuery::new(&tenant, &site, &subject, view, None, 1),
                    Err(StoreError::InvalidCommand)
                ));
            }
            for limit in [0, 129, u16::MAX] {
                assert!(matches!(
                    InvestigationExportListQuery::new(&tenant, &site, "actor", view, None, limit),
                    Err(StoreError::InvalidCommand)
                ));
            }
        }
        assert_eq!(View::Mine.as_str(), "mine");
        assert_eq!(View::Review.as_str(), "review");
    }

    #[test]
    fn every_persisted_state_projects_exactly_its_metadata() {
        for (status, expires) in [
            ("pending_approval", false),
            ("approved", true),
            ("ready", true),
            ("rejected", false),
            ("expired", false),
            ("failed", false),
        ] {
            let raw = if status == "pending_approval" {
                pending()
            } else {
                decided(status)
            };
            let item = validate(&raw, View::Mine, "requester").unwrap();
            assert_eq!(item.status(), status);
            assert_eq!(item.export_id().as_str(), EXPORT);
            assert_eq!(item.case_id().as_str(), CASE);
            assert_eq!(item.requested_by(), "requester");
            assert_eq!(item.requested_at(), at(0));
            assert_eq!(item.expires_at().is_some(), expires, "{status}");
            assert_eq!(
                item.decided_by(),
                (status != "pending_approval").then_some("approver")
            );
            assert_eq!(
                item.decided_at(),
                (status != "pending_approval").then(|| at(60))
            );
        }
        // A terminal state with a stale deadline is still observable history.
        let mut rejected = decided("rejected");
        rejected.expires_at = Some(at(120));
        assert!(validate(&rejected, View::Mine, "requester").is_ok());
    }

    #[test]
    fn views_enforce_ownership_and_pending_state_on_every_visible_row() {
        assert!(validate(&pending(), View::Mine, "requester").is_ok());
        assert!(matches!(
            validate(&pending(), View::Mine, "someone-else"),
            Err(StoreError::CorruptData(
                "investigation_export_list_visibility"
            ))
        ));
        assert!(validate(&pending(), View::Review, "approver").is_ok());
        assert!(matches!(
            validate(&pending(), View::Review, "requester"),
            Err(StoreError::CorruptData(
                "investigation_export_list_visibility"
            ))
        ));
        for status in ["approved", "ready", "rejected", "expired", "failed"] {
            assert!(matches!(
                validate(&decided(status), View::Review, "someone-else"),
                Err(StoreError::CorruptData(
                    "investigation_export_list_visibility"
                ))
            ));
        }
    }

    #[test]
    fn corrupt_rows_fail_closed_instead_of_being_advertised() {
        let corrupt = |raw: RawRow<'_>| {
            assert!(
                matches!(
                    validate(&raw, View::Mine, "requester"),
                    Err(StoreError::CorruptData(_))
                ),
                "row accepted"
            );
        };
        corrupt(RawRow {
            export_id: "export_not-a-uuid",
            ..pending()
        });
        corrupt(RawRow {
            case_id: EXPORT,
            ..pending()
        });
        corrupt(RawRow {
            status: "unknown",
            ..pending()
        });
        corrupt(RawRow {
            kind: "full_package",
            ..pending()
        });
        corrupt(RawRow {
            requested_by: " requester",
            ..pending()
        });
        corrupt(RawRow {
            requested_by: "",
            ..pending()
        });
        // Pending rows carry no decision, deadline or package.
        corrupt(RawRow {
            decided_by: Some("approver"),
            ..pending()
        });
        corrupt(RawRow {
            decided_at: Some(at(60)),
            ..pending()
        });
        corrupt(RawRow {
            expires_at: Some(at(960)),
            ..pending()
        });
        corrupt(RawRow {
            package_attached: true,
            ..pending()
        });
        // Decided rows need both decision fields; approved/ready need a deadline.
        corrupt(RawRow {
            decided_by: None,
            ..decided("rejected")
        });
        corrupt(RawRow {
            decided_at: None,
            ..decided("rejected")
        });
        corrupt(RawRow {
            expires_at: None,
            ..decided("approved")
        });
        corrupt(RawRow {
            expires_at: None,
            ..decided("ready")
        });
        // Only a ready export owns a package, and a ready export always does.
        corrupt(RawRow {
            package_attached: false,
            ..decided("ready")
        });
        corrupt(RawRow {
            package_attached: true,
            ..decided("approved")
        });
        corrupt(RawRow {
            package_attached: true,
            ..decided("failed")
        });
        // Independent approval and the monotone clock are hard invariants.
        corrupt(RawRow {
            decided_by: Some("requester"),
            ..decided("rejected")
        });
        corrupt(RawRow {
            decided_by: Some("approver\n"),
            ..decided("rejected")
        });
        corrupt(RawRow {
            decided_at: Some(at(0) - TimeDelta::seconds(1)),
            ..decided("rejected")
        });
        corrupt(RawRow {
            created_at: DateTime::from_timestamp(-1, 0).unwrap(),
            ..pending()
        });
    }
}
