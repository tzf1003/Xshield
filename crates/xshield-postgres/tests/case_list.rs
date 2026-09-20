use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::{
    domain::{CaseId, EventId, RequestId, SiteId, TenantId},
    investigation::InvestigationCaseDraft,
};
use xshield_postgres::{
    InvestigationCaseCreate, InvestigationCasePage, InvestigationCaseQuery,
    InvestigationCaseRecord, InvestigationCaseWriteOutcome, PostgresIdentityStore, StoreError,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn case_listing_is_owned_paginated_snapshot_read_only_and_rejects_corruption() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let store = PostgresIdentityStore::connect(&database_url, 3, Duration::from_secs(5))
        .await
        .unwrap();
    let pool = PgPool::connect(&database_url).await.unwrap();
    let tenant = TenantId::parse("tenant_case_listing").unwrap();
    let site = SiteId::parse("site_case_listing").unwrap();

    assert_empty_database_clock(&pool, &store, &tenant, &site).await;
    assert_owner_scope_and_live_pages(&pool, &store, &tenant, &site).await;
    assert_corrupt_lookahead_and_outbox(&pool, &store, &tenant, &site).await;
    assert_read_only_without_outbox_side_effects(&pool, &store, &tenant, &site).await;

    // The integration suite shares one database; release this test's three scopes.
    let mut cleanup = pool.begin().await.unwrap();
    for statement in [
        "DELETE FROM xshield.investigation_cases
         WHERE (tenant_id, site_id) IN (($1, $2), ($3, $2), ($1, $4))",
        "DELETE FROM xshield.audit_outbox
         WHERE (tenant_id, site_id) IN (($1, $2), ($3, $2), ($1, $4))",
    ] {
        let deleted = sqlx::query(statement)
            .bind(tenant.as_str())
            .bind(site.as_str())
            .bind("tenant_case_listing_other")
            .bind("site_case_listing_other")
            .execute(&mut *cleanup)
            .await
            .unwrap();
        assert_eq!(deleted.rows_affected(), 10);
    }
    cleanup.commit().await.unwrap();
}

async fn assert_empty_database_clock(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let lower: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    let page = list(store, tenant, site, "owner", None, 128).await;
    let upper: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(page.items().is_empty());
    assert!(page.next_case_id().is_none());
    assert!((lower..=upper).contains(&page.as_of()));
}

async fn assert_owner_scope_and_live_pages(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let first = seed_case(store, tenant, site, "owner", 100).await;
    let middle = seed_case(store, tenant, site, "owner", 200).await;
    let last = seed_case(store, tenant, site, "owner", 300).await;
    seed_case(store, tenant, site, "someone-else", 800).await;
    seed_case(
        store,
        &TenantId::parse("tenant_case_listing_other").unwrap(),
        site,
        "owner",
        900,
    )
    .await;
    seed_case(
        store,
        tenant,
        &SiteId::parse("site_case_listing_other").unwrap(),
        "owner",
        1000,
    )
    .await;
    sqlx::query("UPDATE xshield.investigation_cases SET status = 'closed' WHERE case_id = $1")
        .bind(middle.case_id().as_str())
        .execute(pool)
        .await
        .unwrap();
    let page = list(store, tenant, site, "owner", None, 2).await;
    assert_eq!(page.items().len(), 2);
    assert_eq!(page.items()[0], last);
    assert_eq!(page.items()[1].case_id(), middle.case_id());
    assert_eq!(page.items()[1].status(), "closed");
    assert_eq!(page.items()[1].purpose(), middle.purpose());
    assert_eq!(page.items()[1].created_at(), middle.created_at());
    assert_eq!(page.next_case_id(), Some(middle.case_id()));

    // Other writers commit on both sides of the already returned cursor.
    let (newer, below_cursor) = tokio::join!(
        seed_case(store, tenant, site, "owner", 400),
        seed_case(store, tenant, site, "owner", 150),
    );
    let next = list(store, tenant, site, "owner", page.next_case_id(), 2).await;
    assert_eq!(next.items(), &[below_cursor, first.clone()]);
    assert!(next.next_case_id().is_none());
    assert!(next.as_of() >= page.as_of());
    let refresh = list(store, tenant, site, "owner", None, 2).await;
    assert_eq!(refresh.items(), &[newer, last]);
    let empty = list(store, tenant, site, "owner", Some(first.case_id()), 2).await;
    assert!(empty.items().is_empty());
    assert!(empty.next_case_id().is_none());
    assert!(empty.as_of() >= next.as_of());
    let outsider = list(store, tenant, site, "no-cases", None, 128).await;
    assert!(outsider.items().is_empty());
}

async fn assert_corrupt_lookahead_and_outbox(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let lookahead = seed_case(store, tenant, site, "corrupt-owner", 500).await;
    let first = seed_case(store, tenant, site, "corrupt-owner", 600).await;
    let page = list(store, tenant, site, "corrupt-owner", None, 1).await;
    assert_eq!(page.items(), &[first]);
    assert!(page.next_case_id().is_some());
    // SQL btrim does not remove NBSP; the domain's Unicode trim rejects it.
    sqlx::query("UPDATE xshield.investigation_cases SET purpose = $2 WHERE case_id = $1")
        .bind(lookahead.case_id().as_str())
        .bind("\u{a0}padded purpose")
        .execute(pool)
        .await
        .unwrap();
    assert_corrupt(store, tenant, site, "case_header").await;
    let empty = list(
        store,
        tenant,
        site,
        "corrupt-owner",
        Some(lookahead.case_id()),
        1,
    )
    .await;
    assert!(empty.items().is_empty());
    sqlx::query("UPDATE xshield.investigation_cases SET purpose = $2 WHERE case_id = $1")
        .bind(lookahead.case_id().as_str())
        .bind(lookahead.purpose())
        .execute(pool)
        .await
        .unwrap();

    let event: String = sqlx::query_scalar(
        "SELECT created_event_id FROM xshield.investigation_cases WHERE case_id = $1",
    )
    .bind(lookahead.case_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    let envelope: serde_json::Value =
        sqlx::query_scalar("SELECT envelope FROM xshield.audit_outbox WHERE event_id = $1")
            .bind(&event)
            .fetch_one(pool)
            .await
            .unwrap();
    for (statement, original) in [
        (
            "UPDATE xshield.audit_outbox SET tenant_id = $2 WHERE event_id = $1",
            tenant.as_str(),
        ),
        (
            "UPDATE xshield.audit_outbox SET site_id = $2 WHERE event_id = $1",
            site.as_str(),
        ),
        (
            "UPDATE xshield.audit_outbox SET aggregate_ref = $2 WHERE event_id = $1",
            lookahead.case_id().as_str(),
        ),
        (
            "UPDATE xshield.audit_outbox SET event_type = $2 WHERE event_id = $1",
            "case.created",
        ),
    ] {
        sqlx::query(statement)
            .bind(&event)
            .bind("wrong_association")
            .execute(pool)
            .await
            .unwrap();
        assert_corrupt(store, tenant, site, "investigation_case_outbox").await;
        sqlx::query(statement)
            .bind(&event)
            .bind(original)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(&event)
        .execute(pool)
        .await
        .unwrap();
    assert_corrupt(store, tenant, site, "investigation_case_outbox").await;
    // Restore the fixture association so later read-only assertions can inspect it.
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1, $2, $3, $4, 'case.created', $5)",
    )
    .bind(&event)
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(lookahead.case_id().as_str())
    .bind(envelope)
    .execute(pool)
    .await
    .unwrap();
}

async fn assert_corrupt(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    reason: &str,
) {
    for limit in [1, 128] {
        let query =
            InvestigationCaseQuery::new(tenant, site, "corrupt-owner", None, limit).unwrap();
        assert!(matches!(
            store.list_investigation_cases(query).await,
            Err(StoreError::CorruptData(code)) if code == reason
        ));
    }
    // Damage owned by another subject never changes this subject's result.
    assert_eq!(
        list(store, tenant, site, "owner", None, 128)
            .await
            .items()
            .len(),
        5
    );
}

async fn assert_read_only_without_outbox_side_effects(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let before = durable_rows(pool, tenant).await;
    // Holding a row write lock does not block a snapshot read or change it.
    let mut writer = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE xshield.investigation_cases SET purpose = 'uncommitted purpose'
         WHERE tenant_id = $1 AND owner_ref = 'owner'",
    )
    .bind(tenant.as_str())
    .execute(&mut *writer)
    .await
    .unwrap();
    let page = tokio::time::timeout(
        Duration::from_secs(2),
        list(store, tenant, site, "owner", None, 128),
    )
    .await
    .unwrap();
    assert_eq!(page.items().len(), 5);
    assert!(
        page.items()
            .iter()
            .all(|case| case.purpose().starts_with("List case "))
    );
    writer.rollback().await.unwrap();
    assert_eq!(durable_rows(pool, tenant).await, before);
}

async fn durable_rows(pool: &PgPool, tenant: &TenantId) -> (serde_json::Value, serde_json::Value) {
    sqlx::query_as(
        "SELECT
            (SELECT jsonb_agg(to_jsonb(c) ORDER BY c.case_id)
             FROM xshield.investigation_cases c WHERE tenant_id = $1),
            (SELECT jsonb_agg(to_jsonb(o) ORDER BY o.event_id)
             FROM xshield.audit_outbox o WHERE tenant_id = $1)",
    )
    .bind(tenant.as_str())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn list(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    owner: &str,
    before: Option<&CaseId>,
    limit: u16,
) -> InvestigationCasePage {
    store
        .list_investigation_cases(
            InvestigationCaseQuery::new(tenant, site, owner, before, limit).unwrap(),
        )
        .await
        .unwrap()
}

async fn seed_case(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    owner: &str,
    serial: u16,
) -> InvestigationCaseRecord {
    let case = CaseId::parse(format!("case_0190ca5e-0000-7000-8000-{serial:012x}")).unwrap();
    let draft = InvestigationCaseDraft::new(
        case,
        tenant.clone(),
        site.clone(),
        owner,
        format!("List case {serial}"),
    )
    .unwrap();
    let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
    let event = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
    let mut key = [0; 32];
    key[..2].copy_from_slice(&serial.to_be_bytes());
    let envelope = json!({
        "schema_version": 3,
        "event_id": event.as_str(),
        "event_type": "case.created",
        "tenant_id": tenant.as_str(),
        "site_id": site.as_str(),
        "request_id": request.as_str(),
        "evidence_refs": [],
        "payload": {
            "case_id": draft.case_id().as_str(),
            "subject_ref": owner,
            "stage": "case_management",
            "request_digest": "01".repeat(32),
            "outcome": "PASS",
            "reason_code": "CASE_CREATED"
        }
    });
    let result = store
        .create_investigation_case(
            InvestigationCaseCreate::new(&draft, &key, &[1; 32], &request, &event, &envelope, 128)
                .unwrap(),
        )
        .await
        .unwrap();
    let InvestigationCaseWriteOutcome::Created(record) = result else {
        panic!("fixture case creation must succeed");
    };
    record
}
