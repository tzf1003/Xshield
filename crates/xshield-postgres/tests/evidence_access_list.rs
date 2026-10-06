use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    env,
    time::{Duration, Instant},
};
use xshield_core::domain::{EvidenceAccessRequestId, SiteId, TenantId};
use xshield_postgres::{
    EvidenceAccessListQuery, EvidenceAccessListView as View, EvidenceAccessPage,
    PostgresIdentityStore, StoreError,
};

const TENANT: &str = "tenant_access_list";
const SITE: &str = "site_access_list";

fn id(prefix: &str, number: u32) -> String {
    format!("{prefix}_018f2a3b-4c5d-7000-8000-000000{number:06x}")
}

async fn list(
    store: &PostgresIdentityStore,
    subject: &str,
    view: View,
    before: Option<&EvidenceAccessRequestId>,
    limit: u16,
) -> Result<EvidenceAccessPage, StoreError> {
    let tenant = TenantId::parse(TENANT).unwrap();
    let site = SiteId::parse(SITE).unwrap();
    store
        .list_evidence_access_requests(EvidenceAccessListQuery::new(
            &tenant, &site, subject, view, before, limit,
        )?)
        .await
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
                list(&store, &subject, view, None, 1).await,
                Err(StoreError::InvalidCommand)
            ));
        }
        for limit in [0, 129, u16::MAX] {
            assert!(matches!(
                list(&store, "actor", view, None, limit).await,
                Err(StoreError::InvalidCommand)
            ));
        }
    }
    assert_eq!(View::Mine.as_str(), "mine");
    assert_eq!(View::Review.as_str(), "review");
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn access_discovery_is_scoped_historical_paginated_validated_and_read_only() {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL");
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .unwrap();
    let store = PostgresIdentityStore::from_pool(pool.clone());
    cleanup(&pool).await;
    for (number, owner, status) in [
        (0xeb10, "requester-1", "pending"),
        (0xeb20, "requester-1", "approved"),
        (0xeb30, "requester-1", "denied"),
        (0xeb40, "requester-1", "expired"),
        (0xeb50, "requester-1", "revoked"),
        (0xeb60, "requester-2", "pending"),
        (0xeb70, "reviewer-1", "pending"),
    ] {
        seed(&pool, number, owner, status).await;
    }
    assert_visibility_and_paging(&store).await;
    assert_empty_scope(&store).await;
    assert_read_only(&pool, &store).await;
    assert_corrupt_lookahead(&pool, &store).await;
    assert_lock_timeout(&pool, &store).await;
    cleanup(&pool).await;
    pool.close().await;
}

async fn assert_visibility_and_paging(store: &PostgresIdentityStore) {
    let first = list(store, "requester-1", View::Mine, None, 2)
        .await
        .unwrap();
    assert_eq!(
        first
            .items()
            .iter()
            .map(|i| i.stored_status)
            .collect::<Vec<_>>(),
        ["revoked", "expired"]
    );
    assert!(first.items().iter().all(|i| i.as_of == first.as_of()
        && i.case_status == "closed"
        && i.artifact_status == "deleted"));
    assert_eq!(
        first.next_access_request_id().unwrap().as_str(),
        id("access", 0xeb40)
    );
    let second = list(
        store,
        "requester-1",
        View::Mine,
        first.next_access_request_id(),
        2,
    )
    .await
    .unwrap();
    assert_eq!(
        second
            .items()
            .iter()
            .map(|i| i.stored_status)
            .collect::<Vec<_>>(),
        ["denied", "approved"]
    );
    let third = list(
        store,
        "requester-1",
        View::Mine,
        second.next_access_request_id(),
        2,
    )
    .await
    .unwrap();
    assert_eq!(third.items().len(), 1);
    assert_eq!(third.items()[0].stored_status, "pending");
    assert!(third.next_access_request_id().is_none());
    let terminal = list(
        store,
        "requester-1",
        View::Mine,
        Some(&third.items()[0].access_request_id),
        128,
    )
    .await
    .unwrap();
    assert_eq!(terminal.items(), []);
    assert!(terminal.next_access_request_id().is_none());
    assert!(terminal.as_of() >= third.as_of());
    let review = list(store, "reviewer-1", View::Review, None, 128)
        .await
        .unwrap();
    assert_eq!(
        review
            .items()
            .iter()
            .map(|i| i.requested_by.as_str())
            .collect::<Vec<_>>(),
        ["requester-2", "requester-1"]
    );
    assert!(review.items().iter().all(|i| i.stored_status == "pending"));
    let mine = list(store, "reviewer-1", View::Mine, None, 128)
        .await
        .unwrap();
    assert_eq!(mine.items().len(), 1);
    assert_eq!(mine.items()[0].requested_by, "reviewer-1");
    let nonexistent = EvidenceAccessRequestId::parse(id("access", 0xeb35)).unwrap();
    let below = list(store, "requester-1", View::Mine, Some(&nonexistent), 128)
        .await
        .unwrap();
    assert_eq!(below.items().len(), 3);
}

async fn assert_empty_scope(store: &PostgresIdentityStore) {
    for (tenant, site) in [("tenant_other", SITE), (TENANT, "site_other")] {
        for view in [View::Mine, View::Review] {
            let page = store
                .list_evidence_access_requests(
                    EvidenceAccessListQuery::new(
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
            assert_eq!(page.items(), []);
            assert!(page.next_access_request_id().is_none());
            assert!(page.as_of().timestamp() > 0);
        }
    }
    let unknown = list(store, "unknown", View::Mine, None, 128).await.unwrap();
    assert_eq!(unknown.items(), []);
}

async fn versions(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT access_request_id, xmin::text FROM xshield.evidence_access_requests WHERE tenant_id = $1
        UNION ALL SELECT case_id, xmin::text FROM xshield.investigation_cases WHERE tenant_id = $1
        UNION ALL SELECT artifact_id, xmin::text FROM xshield.artifact_catalog WHERE tenant_id = $1
        UNION ALL SELECT event_id, xmin::text FROM xshield.audit_outbox WHERE tenant_id = $1 ORDER BY 1")
        .bind(TENANT).fetch_all(pool).await.unwrap()
}

async fn assert_read_only(pool: &PgPool, store: &PostgresIdentityStore) {
    let before = versions(pool).await;
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM xshield.evidence_access_requests WHERE tenant_id = $1 FOR UPDATE")
        .bind(TENANT)
        .execute(&mut *lock)
        .await
        .unwrap();
    sqlx::query("UPDATE xshield.investigation_cases SET status = 'open' WHERE tenant_id = $1")
        .bind(TENANT)
        .execute(&mut *lock)
        .await
        .unwrap();
    for view in [View::Mine, View::Review] {
        let page = tokio::time::timeout(
            Duration::from_secs(2),
            list(store, "requester-1", view, None, 128),
        )
        .await
        .expect("no business row lock waits")
        .unwrap();
        assert!(page.items().iter().all(|i| i.case_status == "closed"));
    }
    lock.rollback().await.unwrap();
    assert_eq!(versions(pool).await, before);
}

async fn assert_corrupt_lookahead(pool: &PgPool, store: &PostgresIdentityStore) {
    // eb40 is hidden lookahead for mine(limit=1), but must still fail validation.
    for corruption in [
        "UPDATE xshield.audit_outbox SET aggregate_ref = 'wrong' WHERE event_id = $1",
        "UPDATE xshield.audit_outbox SET site_id = 'site_other' WHERE event_id = $1",
        "UPDATE xshield.audit_outbox SET event_type = 'evidence.access.denied' WHERE event_id = $1",
    ] {
        let event = id("ev", 0xeb44);
        sqlx::query(corruption)
            .bind(&event)
            .execute(pool)
            .await
            .unwrap();
        assert!(matches!(
            list(store, "requester-1", View::Mine, None, 1).await,
            Err(StoreError::CorruptData(_))
        ));
        sqlx::query("UPDATE xshield.audit_outbox SET aggregate_ref = $2, site_id = $3, event_type = 'evidence.access.requested' WHERE event_id = $1")
            .bind(event).bind(id("access", 0xeb40)).bind(SITE).execute(pool).await.unwrap();
    }
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET expires_at = 'infinity' WHERE artifact_id = $1",
    )
    .bind(id("artifact", 0xeb43))
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        list(store, "requester-1", View::Mine, None, 1).await,
        Err(StoreError::CorruptData(_))
    ));
    sqlx::query("UPDATE xshield.artifact_catalog SET expires_at = clock_timestamp() - interval '1 hour' WHERE artifact_id = $1").bind(id("artifact", 0xeb43)).execute(pool).await.unwrap();
    // Review must validate its lookahead too and must not inspect excluded self.
    sqlx::query("UPDATE xshield.audit_outbox SET aggregate_ref = 'wrong' WHERE event_id = $1")
        .bind(id("ev", 0xeb14))
        .execute(pool)
        .await
        .unwrap();
    assert!(matches!(
        list(store, "reviewer-1", View::Review, None, 1).await,
        Err(StoreError::CorruptData(_))
    ));
    let owner_excluded = list(store, "requester-1", View::Review, None, 128)
        .await
        .unwrap();
    assert_eq!(owner_excluded.items().len(), 2);
}

async fn assert_lock_timeout(pool: &PgPool, store: &PostgresIdentityStore) {
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE xshield.evidence_access_requests IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let start = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        list(store, "requester-1", View::Mine, None, 128),
    )
    .await
    .expect("five-second database timeout");
    assert!(matches!(result, Err(StoreError::Database(_))));
    assert!(start.elapsed() >= Duration::from_secs(4));
    lock.rollback().await.unwrap();
}

async fn cleanup(pool: &PgPool) {
    for statement in [
        "DELETE FROM xshield.evidence_access_requests WHERE tenant_id = $1",
        "DELETE FROM xshield.investigation_cases WHERE tenant_id = $1",
        "DELETE FROM xshield.artifact_catalog WHERE tenant_id = $1",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(TENANT)
            .execute(pool)
            .await
            .unwrap();
    }
}

async fn seed(pool: &PgPool, number: u32, owner: &str, status: &str) {
    let access = id("access", number);
    let case = id("case", number + 1);
    let artifact = id("artifact", number + 3);
    let requested = id("ev", number + 4);
    let digest = format!("{number:064x}");
    sqlx::query("INSERT INTO xshield.investigation_cases
        (tenant_id, site_id, case_id, owner_ref, purpose, status, idempotency_digest, request_digest, created_event_id)
        VALUES ($1,$2,$3,$4,'Review incident','closed',decode($5,'hex'),decode($5,'hex'),$6)")
        .bind(TENANT).bind(SITE).bind(&case).bind(owner).bind(&digest).bind(id("ev", number+2)).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO xshield.artifact_catalog (
        tenant_id, site_id, artifact_id, request_id, schema_version, kind,
        content_type, capture_status, fidelity, bytes_observed, bytes_saved,
        classification, example_only, storage_profile, storage_locator,
        key_ref, integrity_algorithm, integrity_digest, parent_refs,
        recorded_at, expires_at, catalog_event_id, status, deleted_at)
        VALUES ($1,$2,$3,$4,3,'response_from_origin','application/json','complete','entity_exact',2,2,
        'RESTRICTED',false,'aead_envelope_v1',$3 || '.xev','evidence-key-r1','sha256_ciphertext',repeat('a',64),'{}',
        clock_timestamp() - interval '2 days',clock_timestamp() - interval '1 hour',$5,'deleted',clock_timestamp())")
        .bind(TENANT).bind(SITE).bind(&artifact).bind(id("req",number+5)).bind(id("ev",number+6)).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO xshield.evidence_access_requests
        (tenant_id, site_id, access_request_id, case_id, artifact_id, requested_by, access_kind,
         justification, status, idempotency_digest, request_digest, requested_event_id, requested_at)
        VALUES ($1,$2,$3,$4,$5,$6,'sensitive_raw','Review source response','pending',decode($7,'hex'),decode($7,'hex'),$8,clock_timestamp() - interval '3 hours')")
        .bind(TENANT).bind(SITE).bind(&access).bind(&case).bind(&artifact).bind(owner).bind(&digest).bind(&requested).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope)
        VALUES ($1,$2,$3,$4,'evidence.access.requested','{}')")
        .bind(requested).bind(TENANT).bind(SITE).bind(&access).execute(pool).await.unwrap();
    if status != "pending" {
        let decision = id("ev", number + 7);
        sqlx::query("UPDATE xshield.evidence_access_requests SET status = $2, decided_by = 'independent-approver',
            decision_reason = 'Reviewed evidence purpose', decision_idempotency_digest = decode($3,'hex'),
            decision_request_digest = decode($3,'hex'), decision_event_id = $4,
            decided_at = clock_timestamp() - interval '2 hours',
            decision_ttl_seconds = CASE WHEN $2 = 'denied' THEN NULL ELSE 120 END,
            access_expires_at = CASE WHEN $2 = 'denied' THEN NULL ELSE clock_timestamp() - interval '2 hours' + interval '60 seconds' END
            WHERE access_request_id = $1")
            .bind(&access).bind(status).bind(&digest).bind(&decision).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope)
            VALUES ($1,$2,$3,$4,$5,'{}')")
            .bind(decision).bind(TENANT).bind(SITE).bind(&access).bind(if status == "denied" {"evidence.access.denied"} else {"evidence.access.approved"}).execute(pool).await.unwrap();
    }
}
