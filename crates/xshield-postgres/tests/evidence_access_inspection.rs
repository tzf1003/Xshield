use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, time::Duration};
use xshield_core::domain::{EvidenceAccessRequestId, SiteId, TenantId};
use xshield_postgres::{EvidenceAccessInspection, PostgresIdentityStore, StoreError};

const TENANT: &str = "tenant_access_inspection";
const SITE: &str = "site_access_inspection";
const ACCESS: &str = "access_018f2a3b-4c5d-7000-8000-00000000ea11";
const CASE: &str = "case_018f2a3b-4c5d-7000-8000-00000000ea12";
const ARTIFACT: &str = "artifact_018f2a3b-4c5d-7000-8000-00000000ea13";
const REQUEST_EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-00000000ea14";
const DECISION_EVENT: &str = "ev_018f2a3b-4c5d-7000-8000-00000000ea15";

async fn read(
    store: &PostgresIdentityStore,
    subject: &str,
    reviewer: bool,
) -> Result<Option<EvidenceAccessInspection>, StoreError> {
    store
        .read_evidence_access_request(
            &TenantId::parse(TENANT).unwrap(),
            &SiteId::parse(SITE).unwrap(),
            &EvidenceAccessRequestId::parse(ACCESS).unwrap(),
            subject,
            reviewer,
        )
        .await
}

#[tokio::test]
async fn invalid_subject_is_rejected_before_pool_access() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    pool.close().await;
    let store = PostgresIdentityStore::from_pool(pool);
    for subject in [
        String::new(),
        "x".repeat(257),
        "中".repeat(86),
        " actor".into(),
        "actor\u{a0}".into(),
        "actor\n".into(),
    ] {
        for reviewer in [false, true] {
            assert!(matches!(
                read(&store, &subject, reviewer).await,
                Err(StoreError::InvalidCommand)
            ));
        }
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_access_inspection_is_scoped_historical_consistent_and_read_only() {
    let database_url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL");
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .unwrap();
    let store = PostgresIdentityStore::from_pool(pool.clone());
    seed(&pool).await;
    assert_visibility(&store).await;
    assert_read_only(&store, &pool).await;
    assert_history(&store, &pool).await;
    assert_corruption(&store, &pool).await;
    seed(&pool).await;
    assert_table_lock_timeout(&store, &pool).await;
    cleanup(&pool).await;
    pool.close().await;
}

async fn assert_visibility(store: &PostgresIdentityStore) {
    let owner = read(store, "investigator-1", false).await.unwrap().unwrap();
    assert_eq!(owner.access_request_id.as_str(), ACCESS);
    assert_eq!(owner.case_id.as_str(), CASE);
    assert_eq!(owner.artifact_id.as_str(), ARTIFACT);
    assert_eq!(owner.stored_status, "pending");
    assert_eq!(owner.requested_event_id.as_str(), REQUEST_EVENT);
    assert_eq!(owner.access_kind.as_str(), "sensitive_raw");
    assert_eq!(owner.justification, "Review source response");
    assert!(owner.decided_at.is_none());
    assert!(owner.as_of > owner.requested_at);
    assert!(owner.as_of < owner.artifact_expires_at);
    let reviewer = read(store, "approver-1", true).await.unwrap().unwrap();
    assert_eq!(reviewer.requested_by, owner.requested_by);
    assert!(
        read(store, "investigator-2", false)
            .await
            .unwrap()
            .is_none()
    );
    assert!(read(store, "approver-1", false).await.unwrap().is_none());
    for (tenant, site, access) in [
        ("tenant_other", SITE, ACCESS),
        (TENANT, "site_other", ACCESS),
        (TENANT, SITE, "access_018f2a3b-4c5d-7000-8000-00000000eaff"),
    ] {
        for reviewer in [false, true] {
            assert!(
                store
                    .read_evidence_access_request(
                        &TenantId::parse(tenant).unwrap(),
                        &SiteId::parse(site).unwrap(),
                        &EvidenceAccessRequestId::parse(access).unwrap(),
                        "investigator-1",
                        reviewer,
                    )
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
    let debug = format!("{owner:?}");
    for omitted in [
        ".xev",
        "evidence-key-r1",
        "sha256_ciphertext",
        "request_digest",
        "integrity_digest",
    ] {
        assert!(!debug.contains(omitted));
    }
}

async fn versions(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT 'access', xmin::text FROM xshield.evidence_access_requests WHERE tenant_id = $1
         UNION ALL SELECT 'case', xmin::text FROM xshield.investigation_cases WHERE tenant_id = $1
         UNION ALL SELECT 'artifact', xmin::text FROM xshield.artifact_catalog WHERE tenant_id = $1
         UNION ALL SELECT event_id, xmin::text FROM xshield.audit_outbox WHERE tenant_id = $1 ORDER BY 1",
    ).bind(TENANT).fetch_all(pool).await.unwrap()
}

async fn assert_read_only(store: &PostgresIdentityStore, pool: &PgPool) {
    let before = versions(pool).await;
    let mut pending = pool.begin().await.unwrap();
    sqlx::query("UPDATE xshield.investigation_cases SET status = 'closed' WHERE tenant_id = $1")
        .bind(TENANT)
        .execute(&mut *pending)
        .await
        .unwrap();
    sqlx::query("UPDATE xshield.artifact_catalog SET status = 'deleted', deleted_at = clock_timestamp() WHERE tenant_id = $1")
        .bind(TENANT).execute(&mut *pending).await.unwrap();
    sqlx::query("SELECT 1 FROM xshield.evidence_access_requests WHERE tenant_id = $1 FOR UPDATE")
        .bind(TENANT)
        .execute(&mut *pending)
        .await
        .unwrap();
    let observed =
        tokio::time::timeout(Duration::from_secs(2), read(store, "investigator-1", false))
            .await
            .expect("metadata reads do not wait for business row locks")
            .unwrap()
            .unwrap();
    assert_eq!(observed.case_status, "open");
    assert_eq!(observed.artifact_status, "active");
    assert_eq!(observed.stored_status, "pending");
    pending.rollback().await.unwrap();
    assert_eq!(versions(pool).await, before);
}

async fn assert_history(store: &PostgresIdentityStore, pool: &PgPool) {
    change(
        pool,
        "UPDATE xshield.investigation_cases SET status = 'closed' WHERE tenant_id = $1",
    )
    .await;
    change(pool, "UPDATE xshield.artifact_catalog SET status = 'deleted', deleted_at = clock_timestamp(), expires_at = clock_timestamp() - interval '1 hour' WHERE tenant_id = $1").await;
    for status in ["pending", "approved", "denied", "expired", "revoked"] {
        set_status(pool, status).await;
        let before = versions(pool).await;
        let record = read(store, "investigator-1", false).await.unwrap().unwrap();
        assert_eq!(record.stored_status, status);
        assert_eq!(record.case_status, "closed");
        assert_eq!(record.artifact_status, "deleted");
        assert!(record.artifact_expires_at < record.as_of);
        if ["approved", "expired", "revoked"].contains(&status) {
            assert!(record.access_expires_at.unwrap() < record.as_of);
            assert_eq!(record.decision_ttl_seconds, Some(60));
        }
        assert_eq!(versions(pool).await, before);
    }
    seed(pool).await;
    set_status(pool, "approved").await;
    change(pool, "UPDATE xshield.evidence_access_requests SET requested_at = clock_timestamp() + interval '1 hour' WHERE tenant_id = $1").await;
    let record = read(store, "investigator-1", false).await.unwrap().unwrap();
    assert!(
        record.requested_at > record.decided_at.unwrap(),
        "independent wall clocks need not be monotonic"
    );
    assert_eq!(record.artifact_status, "active");
    assert!(
        record.access_expires_at.unwrap() < record.as_of,
        "stored approval and observed expiry remain separate"
    );
}

async fn assert_corruption(store: &PostgresIdentityStore, pool: &PgPool) {
    for statement in [
        "UPDATE xshield.evidence_access_requests SET requested_by = ' investigator-1' WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET justification = U&'\\00A0reason' WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET decided_by = ' approver-1' WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET decision_reason = U&'reason\\00A0' WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET decision_ttl_seconds = 86401 WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET decision_ttl_seconds = 1 WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET access_expires_at = NULL WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET requested_at = 'infinity' WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET requested_at = '-infinity' WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET requested_at = '1969-12-31T23:59:59Z' WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET requested_at = '2500-01-01T00:00:00Z' WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET decided_at = '-infinity' WHERE tenant_id = $1",
        "UPDATE xshield.evidence_access_requests SET access_expires_at = 'infinity' WHERE tenant_id = $1",
        "UPDATE xshield.artifact_catalog SET expires_at = 'infinity' WHERE tenant_id = $1",
        "UPDATE xshield.artifact_catalog SET expires_at = clock_timestamp() - interval '3 hours' WHERE tenant_id = $1",
        "UPDATE xshield.artifact_catalog SET status = 'deleted', deleted_at = 'infinity' WHERE tenant_id = $1",
        "UPDATE xshield.investigation_cases SET owner_ref = 'other-owner' WHERE tenant_id = $1",
        "UPDATE xshield.audit_outbox SET aggregate_ref = 'other-request' WHERE tenant_id = $1",
        "UPDATE xshield.audit_outbox SET site_id = 'other_site' WHERE tenant_id = $1",
        "UPDATE xshield.audit_outbox SET tenant_id = 'tenant_access_inspection_other' WHERE tenant_id = $1",
        "UPDATE xshield.audit_outbox SET event_type = 'evidence.access.denied' WHERE tenant_id = $1 AND event_type = 'evidence.access.approved'",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id = $1 AND event_type = 'evidence.access.requested'",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id = $1 AND event_type = 'evidence.access.approved'",
    ] {
        seed(pool).await;
        set_status(pool, "approved").await;
        change(pool, statement).await;
        assert!(
            matches!(
                read(store, "approver-1", true).await,
                Err(StoreError::CorruptData(_))
            ),
            "{statement}"
        );
        assert!(
            read(store, "unrelated-subject", false)
                .await
                .unwrap()
                .is_none(),
            "invisible corruption: {statement}"
        );
    }
}

async fn assert_table_lock_timeout(store: &PostgresIdentityStore, pool: &PgPool) {
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE xshield.evidence_access_requests IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let error = tokio::time::timeout(Duration::from_secs(8), read(store, "investigator-1", false))
        .await
        .expect("SQL lock wait is bounded")
        .unwrap_err();
    let StoreError::Database(sqlx::Error::Database(error)) = error else {
        panic!("database lock timeout expected");
    };
    assert!(matches!(error.code().as_deref(), Some("57014" | "55P03")));
    assert!(started.elapsed() >= Duration::from_secs(4));
    blocker.rollback().await.unwrap();
    assert!(
        read(store, "investigator-1", false)
            .await
            .unwrap()
            .is_some()
    );
}

async fn change(pool: &PgPool, statement: &'static str) {
    sqlx::query(statement)
        .bind(TENANT)
        .execute(pool)
        .await
        .unwrap();
}

async fn set_status(pool: &PgPool, status: &str) {
    sqlx::query(
        "UPDATE xshield.evidence_access_requests SET status = $2,
            decided_by = CASE WHEN $2 = 'pending' THEN NULL ELSE 'approver-1' END,
            decision_reason = CASE WHEN $2 = 'pending' THEN NULL ELSE 'Independent review' END,
            decision_ttl_seconds = CASE WHEN $2 IN ('pending', 'denied') THEN NULL ELSE 60 END,
            decision_idempotency_digest = CASE WHEN $2 = 'pending' THEN NULL ELSE decode(repeat('33',32),'hex') END,
            decision_request_digest = CASE WHEN $2 = 'pending' THEN NULL ELSE decode(repeat('44',32),'hex') END,
            decision_event_id = CASE WHEN $2 = 'pending' THEN NULL ELSE $3 END,
            decided_at = CASE WHEN $2 = 'pending' THEN NULL ELSE statement_timestamp() - interval '2 hours' END,
            access_expires_at = CASE WHEN $2 IN ('pending', 'denied') THEN NULL ELSE statement_timestamp() - interval '2 hours' + interval '60 seconds' END
         WHERE tenant_id = $1",
    ).bind(TENANT).bind(status).bind(DECISION_EVENT).execute(pool).await.unwrap();
    if status != "pending" {
        sqlx::query("INSERT INTO xshield.audit_outbox (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
            VALUES ($1,$2,$3,$4,$5,'{}') ON CONFLICT (event_id) DO UPDATE SET event_type = EXCLUDED.event_type")
            .bind(DECISION_EVENT).bind(TENANT).bind(SITE).bind(ACCESS)
            .bind(if status == "denied" { "evidence.access.denied" } else { "evidence.access.approved" })
            .execute(pool).await.unwrap();
    }
}

async fn cleanup(pool: &PgPool) {
    for statement in [
        "DELETE FROM xshield.evidence_access_requests WHERE tenant_id IN ($1, 'tenant_access_inspection_other')",
        "DELETE FROM xshield.artifact_catalog WHERE tenant_id IN ($1, 'tenant_access_inspection_other')",
        "DELETE FROM xshield.investigation_cases WHERE tenant_id IN ($1, 'tenant_access_inspection_other')",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id IN ($1, 'tenant_access_inspection_other')",
    ] {
        sqlx::query(statement)
            .bind(TENANT)
            .execute(pool)
            .await
            .unwrap();
    }
}

async fn seed(pool: &PgPool) {
    cleanup(pool).await;
    sqlx::query("INSERT INTO xshield.investigation_cases
        (tenant_id, site_id, case_id, owner_ref, purpose, status, idempotency_digest, request_digest, created_event_id)
        VALUES ($1,$2,$3,'investigator-1','Review incident','open',decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),'ev_018f2a3b-4c5d-7000-8000-00000000ea16')")
        .bind(TENANT).bind(SITE).bind(CASE).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO xshield.artifact_catalog (
        tenant_id, site_id, artifact_id, request_id, schema_version, kind,
        content_type, capture_status, fidelity, bytes_observed, bytes_saved,
        classification, example_only, storage_profile, storage_locator,
        key_ref, integrity_algorithm, integrity_digest, parent_refs,
        recorded_at, expires_at, catalog_event_id, status)
        VALUES ($1,$2,$3,'req_018f2a3b-4c5d-7000-8000-00000000ea17',3,'response_from_origin',
        'application/json','complete','entity_exact',2,2,'RESTRICTED',false,'aead_envelope_v1',$3 || '.xev',
        'evidence-key-r1','sha256_ciphertext',repeat('a',64),'{}',
        clock_timestamp() - interval '2 days',clock_timestamp() + interval '1 hour',
        'ev_018f2a3b-4c5d-7000-8000-00000000ea18','active')")
        .bind(TENANT).bind(SITE).bind(ARTIFACT).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO xshield.evidence_access_requests
        (tenant_id, site_id, access_request_id, case_id, artifact_id, requested_by, access_kind,
         justification, status, idempotency_digest, request_digest, requested_event_id, requested_at)
        VALUES ($1,$2,$3,$4,$5,'investigator-1','sensitive_raw','Review source response','pending',
        decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),$6,clock_timestamp() - interval '3 hours')")
        .bind(TENANT).bind(SITE).bind(ACCESS).bind(CASE).bind(ARTIFACT).bind(REQUEST_EVENT)
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
        VALUES ($1,$2,$3,$4,'evidence.access.requested','{}')")
        .bind(REQUEST_EVENT).bind(TENANT).bind(SITE).bind(ACCESS).execute(pool).await.unwrap();
}
