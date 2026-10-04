//! `PostgreSQL` wire regression for export discovery.

use chrono::{Duration as Age, Utc};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    env,
    time::{Duration, Instant},
};
use uuid::Uuid;
use xshield_core::domain::{ExportId, SiteId, TenantId};
use xshield_postgres::{
    InvestigationExportListItem, InvestigationExportListQuery, InvestigationExportListView as View,
    InvestigationExportPage, PostgresIdentityStore, StoreError,
};

const SITE: &str = "site_export_list";

fn id(prefix: &str, number: u32) -> String {
    format!("{prefix}_018f2a3b-4c5d-7000-8000-000000{number:06x}")
}

async fn list(
    store: &PostgresIdentityStore,
    tenant: &str,
    subject: &str,
    view: View,
    before: Option<&ExportId>,
    limit: u16,
) -> Result<InvestigationExportPage, StoreError> {
    let tenant = TenantId::parse(tenant).unwrap();
    let site = SiteId::parse(SITE).unwrap();
    store
        .list_investigation_exports(InvestigationExportListQuery::new(
            &tenant, &site, subject, view, before, limit,
        )?)
        .await
}

fn statuses(page: &InvestigationExportPage) -> Vec<&'static str> {
    page.items()
        .iter()
        .map(InvestigationExportListItem::status)
        .collect()
}

#[tokio::test]
async fn query_validation_precedes_database_io() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    pool.close().await;
    let store = PostgresIdentityStore::from_pool(pool);
    for view in [View::Mine, View::Review] {
        for subject in [
            String::new(),
            "a".repeat(257),
            "中".repeat(86),
            " actor".into(),
            "actor\u{a0}".into(),
            "actor\n".into(),
        ] {
            assert!(matches!(
                list(&store, "tenant_unused", &subject, view, None, 1).await,
                Err(StoreError::InvalidCommand)
            ));
        }
        for limit in [0, 129, u16::MAX] {
            assert!(matches!(
                list(&store, "tenant_unused", "actor", view, None, limit).await,
                Err(StoreError::InvalidCommand)
            ));
        }
    }
    assert_eq!(View::Mine.as_str(), "mine");
    assert_eq!(View::Review.as_str(), "review");
}

struct Fixture {
    pool: PgPool,
    store: PostgresIdentityStore,
    tenant: String,
}

impl Fixture {
    async fn new() -> Self {
        let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL");
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&url)
            .await
            .unwrap();
        // Each run owns one tenant, so concurrent suites never see these rows.
        let tenant = format!("tenant_exlist_{}", Uuid::now_v7().simple());
        Self {
            store: PostgresIdentityStore::from_pool(pool.clone()),
            pool,
            tenant,
        }
    }

    async fn list(
        &self,
        subject: &str,
        view: View,
        before: Option<&ExportId>,
        limit: u16,
    ) -> Result<InvestigationExportPage, StoreError> {
        list(&self.store, &self.tenant, subject, view, before, limit).await
    }

    async fn seed_case(&self, number: u32, owner: &str) -> String {
        let case = id("case", number);
        sqlx::query(
            "INSERT INTO xshield.investigation_cases (
                 tenant_id, site_id, case_id, owner_ref, purpose, status,
                 idempotency_digest, request_digest, created_event_id
             ) VALUES ($1, $2, $3, $4, 'Export list regression', 'open', $5, $5, $6)",
        )
        .bind(&self.tenant)
        .bind(SITE)
        .bind(&case)
        .bind(owner)
        .bind(vec![u8::try_from(number % 251).unwrap(); 32])
        .bind(id("ev", number))
        .execute(&self.pool)
        .await
        .unwrap();
        case
    }

    // Shapes each persisted state exactly as the table constraints and the
    // production writers shape it. `purpose` and `decision_reason` are seeded
    // with recognizable text so a leaking projection would be visible.
    async fn seed_export(&self, number: u32, owner: &str, case: &str, status: &str) {
        let now = Utc::now();
        let decided = status != "pending_approval";
        let ready = status == "ready";
        let digest = vec![u8::try_from(number % 251).unwrap(); 32];
        sqlx::query(
            "INSERT INTO xshield.investigation_exports (
                 tenant_id, site_id, export_id, case_id, requested_by, purpose, kind, status,
                 decided_by, decided_at, decision_reason, expires_at,
                 package_artifact_id, package_request_id, package_digest, package_bytes,
                 idempotency_digest, request_digest, approval_digest, decision_request_digest,
                 created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, 'Private seeded purpose', 'metadata_only', $6,
                 $7, $8, $9, $10, $11, $12, $13, $14, $15, $15, $16, $16, $17, $17)",
        )
        .bind(&self.tenant)
        .bind(SITE)
        .bind(id("export", number))
        .bind(case)
        .bind(owner)
        .bind(status)
        .bind(decided.then_some("independent-approver"))
        .bind(decided.then(|| now - Age::hours(1)))
        .bind(decided.then_some("Private seeded decision reason"))
        .bind(match status {
            "approved" | "ready" => Some(now + Age::minutes(10)),
            "expired" => Some(now - Age::minutes(10)),
            _ => None,
        })
        .bind(ready.then(|| id("artifact", number)))
        .bind(ready.then(|| id("req", number)))
        .bind(ready.then(|| "a".repeat(64)))
        .bind(ready.then_some(12_i64))
        .bind(digest.as_slice())
        .bind(decided.then_some(digest.as_slice()))
        .bind(now - Age::hours(2))
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn versions(&self) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT export_id, xmin::text FROM xshield.investigation_exports WHERE tenant_id = $1
             UNION ALL SELECT case_id, xmin::text FROM xshield.investigation_cases WHERE tenant_id = $1
             UNION ALL SELECT export_id, xmin::text FROM xshield.investigation_export_package_claims WHERE tenant_id = $1
             ORDER BY 1",
        )
        .bind(&self.tenant)
        .fetch_all(&self.pool)
        .await
        .unwrap()
    }

    async fn cleanup(&self) {
        for statement in [
            "DELETE FROM xshield.investigation_export_package_claims WHERE tenant_id = $1",
            "DELETE FROM xshield.investigation_exports WHERE tenant_id = $1",
            "DELETE FROM xshield.investigation_cases WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(&self.tenant)
                .execute(&self.pool)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn export_discovery_is_scoped_historical_paginated_validated_and_read_only() {
    let fixture = Fixture::new().await;
    let case_1 = fixture.seed_case(0xeb01, "requester-1").await;
    let case_2 = fixture.seed_case(0xeb02, "requester-2").await;
    let case_3 = fixture.seed_case(0xeb03, "reviewer-1").await;
    // requester-1 holds one export per persisted state; the numbers fix the order.
    for (number, owner, case, status) in [
        (0xeb10, "requester-1", &case_1, "pending_approval"),
        (0xeb20, "requester-1", &case_1, "approved"),
        (0xeb30, "requester-1", &case_1, "ready"),
        (0xeb40, "requester-1", &case_1, "rejected"),
        (0xeb50, "requester-1", &case_1, "expired"),
        (0xeb60, "requester-1", &case_1, "failed"),
        (0xeb70, "requester-2", &case_2, "pending_approval"),
        (0xeb80, "requester-2", &case_2, "rejected"),
        (0xeb90, "reviewer-1", &case_3, "pending_approval"),
    ] {
        fixture.seed_export(number, owner, case, status).await;
    }
    assert_visibility_and_paging(&fixture).await;
    assert_projection_is_metadata_only(&fixture).await;
    assert_empty_scope(&fixture).await;
    assert_read_only(&fixture).await;
    assert_corrupt_lookahead(&fixture).await;
    assert_lock_timeout(&fixture).await;
    fixture.cleanup().await;
    fixture.pool.close().await;
}

async fn assert_visibility_and_paging(fixture: &Fixture) {
    let first = fixture
        .list("requester-1", View::Mine, None, 2)
        .await
        .unwrap();
    assert_eq!(statuses(&first), ["failed", "expired"]);
    assert_eq!(
        first.next_export_id().unwrap().as_str(),
        id("export", 0xeb50)
    );
    let second = fixture
        .list("requester-1", View::Mine, first.next_export_id(), 2)
        .await
        .unwrap();
    assert_eq!(statuses(&second), ["rejected", "ready"]);
    let third = fixture
        .list("requester-1", View::Mine, second.next_export_id(), 2)
        .await
        .unwrap();
    assert_eq!(statuses(&third), ["approved", "pending_approval"]);
    // Exactly full and exactly last: no lookahead row, so no further cursor.
    assert!(third.next_export_id().is_none());
    let terminal = fixture
        .list(
            "requester-1",
            View::Mine,
            Some(third.items()[1].export_id()),
            128,
        )
        .await
        .unwrap();
    assert!(terminal.items().is_empty());
    assert!(terminal.next_export_id().is_none());
    assert!(terminal.as_of() >= third.as_of());
    // One shared database observation per page, not one per row.
    assert!(
        first
            .items()
            .iter()
            .all(|item| item.requested_at() <= first.as_of())
    );

    // The queue: other principals' undecided exports, newest first.
    let review = fixture
        .list("reviewer-1", View::Review, None, 128)
        .await
        .unwrap();
    assert_eq!(
        review
            .items()
            .iter()
            .map(InvestigationExportListItem::requested_by)
            .collect::<Vec<_>>(),
        ["requester-2", "requester-1"]
    );
    assert!(
        statuses(&review)
            .iter()
            .all(|status| *status == "pending_approval")
    );
    assert!(review.items().iter().all(|item| {
        item.decided_by().is_none() && item.decided_at().is_none() && item.expires_at().is_none()
    }));
    // A reviewer's own pending export is excluded from their own queue, and
    // mine shows only their own rows.
    let own = fixture
        .list("reviewer-1", View::Mine, None, 128)
        .await
        .unwrap();
    assert_eq!(own.items().len(), 1);
    assert_eq!(own.items()[0].requested_by(), "reviewer-1");
    let requester_queue = fixture
        .list("requester-1", View::Review, None, 128)
        .await
        .unwrap();
    assert_eq!(
        requester_queue
            .items()
            .iter()
            .map(InvestigationExportListItem::requested_by)
            .collect::<Vec<_>>(),
        ["reviewer-1", "requester-2"]
    );
    // A cursor may name a row that does not exist; the comparison is exclusive.
    let nonexistent = ExportId::parse(id("export", 0xeb35)).unwrap();
    let below = fixture
        .list("requester-1", View::Mine, Some(&nonexistent), 128)
        .await
        .unwrap();
    assert_eq!(statuses(&below), ["ready", "approved", "pending_approval"]);
}

// The page exposes the decision actors and times that the detail endpoint
// shows, and nothing from the private purpose, reason or package columns.
async fn assert_projection_is_metadata_only(fixture: &Fixture) {
    let page = fixture
        .list("requester-1", View::Mine, None, 128)
        .await
        .unwrap();
    let ready = page
        .items()
        .iter()
        .find(|item| item.status() == "ready")
        .unwrap();
    assert_eq!(ready.export_id().as_str(), id("export", 0xeb30));
    assert_eq!(ready.case_id().as_str(), id("case", 0xeb01));
    assert_eq!(ready.decided_by(), Some("independent-approver"));
    assert!(ready.decided_at().is_some() && ready.expires_at().is_some());
    let expired = page
        .items()
        .iter()
        .find(|item| item.status() == "expired")
        .unwrap();
    assert!(expired.expires_at().unwrap() < page.as_of());
    for item in page.items() {
        let rendered = format!("{item:?}");
        for private in [
            "Private seeded",
            "purpose",
            "reason",
            "artifact",
            "digest",
            "package",
        ] {
            assert!(!rendered.contains(private), "projection leaked {private}");
        }
    }
}

async fn assert_empty_scope(fixture: &Fixture) {
    for (tenant, site) in [
        ("tenant_exlist_other", SITE),
        (fixture.tenant.as_str(), "site_other"),
    ] {
        for view in [View::Mine, View::Review] {
            let page = fixture
                .store
                .list_investigation_exports(
                    InvestigationExportListQuery::new(
                        &TenantId::parse(tenant).unwrap(),
                        &SiteId::parse(site).unwrap(),
                        "requester-1",
                        view,
                        None,
                        128,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert!(page.items().is_empty());
            assert!(page.next_export_id().is_none());
            assert!(page.as_of().timestamp() > 0);
        }
    }
    let unknown = fixture
        .list("unknown", View::Mine, None, 128)
        .await
        .unwrap();
    assert!(unknown.items().is_empty());
}

async fn assert_read_only(fixture: &Fixture) {
    let before = fixture.versions().await;
    let mut lock = fixture.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM xshield.investigation_exports WHERE tenant_id = $1 FOR UPDATE")
        .bind(&fixture.tenant)
        .execute(&mut *lock)
        .await
        .unwrap();
    sqlx::query("UPDATE xshield.investigation_cases SET status = 'closed' WHERE tenant_id = $1")
        .bind(&fixture.tenant)
        .execute(&mut *lock)
        .await
        .unwrap();
    for view in [View::Mine, View::Review] {
        let page = tokio::time::timeout(
            Duration::from_secs(2),
            fixture.list("requester-1", view, None, 128),
        )
        .await
        .expect("no business row lock waits")
        .unwrap();
        assert!(!page.items().is_empty());
    }
    lock.rollback().await.unwrap();
    assert_eq!(fixture.versions().await, before);
}

// Each row is corrupted where the table constraints cannot object, shown to be
// refused even as a hidden lookahead (a page must not advertise a continuation
// that the detail read would reject), and restored afterwards.
async fn assert_corrupt_lookahead(fixture: &Fixture) {
    // (corrupted number, corrupted decider, page size that makes it the lookahead)
    for (number, decider, limit) in [
        // The table allows a deadline on a pending row; the decoder does not.
        (0xeb10, None, 5),
        // Independent approval: the table cannot express this rule.
        (0xeb50, Some("requester-1"), 1),
        // Subjects are canonical text; the table only forbids control characters.
        (0xeb50, Some("approver "), 1),
    ] {
        match decider {
            None => set_deadline(fixture, number, true).await,
            Some(decider) => set_decider(fixture, number, decider).await,
        }
        assert!(
            matches!(
                fixture.list("requester-1", View::Mine, None, limit).await,
                Err(StoreError::CorruptData(_))
            ),
            "corrupt lookahead {number:#x} {decider:?} was advertised"
        );
        match decider {
            None => set_deadline(fixture, number, false).await,
            Some(_) => set_decider(fixture, number, "independent-approver").await,
        }
        assert!(
            fixture
                .list("requester-1", View::Mine, None, limit)
                .await
                .is_ok()
        );
    }
    // The queue validates its lookahead too, and never inspects the caller's
    // own rows: 0xeb10 is requester-1's, so only other viewers can trip on it.
    set_deadline(fixture, 0xeb10, true).await;
    assert!(matches!(
        fixture.list("reviewer-1", View::Review, None, 1).await,
        Err(StoreError::CorruptData(_))
    ));
    let own_excluded = fixture
        .list("requester-1", View::Review, None, 128)
        .await
        .unwrap();
    assert_eq!(own_excluded.items().len(), 2);
    set_deadline(fixture, 0xeb10, false).await;
}

async fn set_deadline(fixture: &Fixture, number: u32, present: bool) {
    sqlx::query(
        "UPDATE xshield.investigation_exports
         SET expires_at = CASE WHEN $2 THEN now() + interval '1 hour' END
         WHERE export_id = $1",
    )
    .bind(id("export", number))
    .bind(present)
    .execute(&fixture.pool)
    .await
    .unwrap();
}

async fn set_decider(fixture: &Fixture, number: u32, decider: &str) {
    sqlx::query("UPDATE xshield.investigation_exports SET decided_by = $2 WHERE export_id = $1")
        .bind(id("export", number))
        .bind(decider)
        .execute(&fixture.pool)
        .await
        .unwrap();
}

async fn assert_lock_timeout(fixture: &Fixture) {
    let mut lock = fixture.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE xshield.investigation_exports IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let start = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        fixture.list("requester-1", View::Mine, None, 128),
    )
    .await
    .expect("five-second database timeout");
    assert!(matches!(result, Err(StoreError::Database(_))));
    assert!(start.elapsed() >= Duration::from_secs(4));
    lock.rollback().await.unwrap();
}
