use serde_json::{Value, json};
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::{
    domain::{ArtifactId, CaseId, EventId, RequestId, SiteId, TenantId},
    investigation::CaseEvidenceDraft,
};
use xshield_postgres::{
    CASE_EVIDENCE_ITEMS_MAX, CaseEvidenceAdd, CaseEvidenceAvailability, CaseEvidenceQuery,
    CaseEvidenceWriteOutcome, PostgresIdentityStore,
};

const TENANT: &str = "tenant_case_evidence";
const SITE: &str = "site_case_evidence";

struct AddRequest {
    draft: CaseEvidenceDraft,
    request: RequestId,
    event: EventId,
    key: [u8; 32],
    digest: [u8; 32],
    envelope: Value,
}

impl AddRequest {
    fn new(draft: CaseEvidenceDraft, key: u8, digest: u8) -> Self {
        let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
        let event = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
        let envelope = json!({
            "schema_version": 3,
            "event_id": event.as_str(),
            "event_type": "case.evidence.added",
            "tenant_id": draft.tenant_id().as_str(),
            "site_id": draft.site_id().as_str(),
            "request_id": request.as_str(),
            "evidence_refs": [draft.artifact_id().as_str()],
            "payload": {
                "case_id": draft.case_id().as_str(),
                "artifact_id": draft.artifact_id().as_str(),
                "subject_ref": draft.added_by(),
                "stage": "case_management",
                "request_digest": format!("{digest:02x}").repeat(32),
                "outcome": "PASS",
                "reason_code": "CASE_EVIDENCE_ADDED"
            }
        });
        Self {
            draft,
            request,
            event,
            key: [key; 32],
            digest: [digest; 32],
            envelope,
        }
    }

    fn command(&self) -> CaseEvidenceAdd<'_> {
        CaseEvidenceAdd::new(
            &self.draft,
            &self.key,
            &self.digest,
            &self.request,
            &self.event,
            &self.envelope,
        )
        .unwrap()
    }
}

#[test]
fn association_command_binds_every_audit_target() {
    let case = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    let artifact = ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).unwrap();
    let request = AddRequest::new(draft(&case, &artifact, "investigator"), 1, 2);
    request.command();
    for pointer in [
        "/schema_version",
        "/event_id",
        "/event_type",
        "/tenant_id",
        "/site_id",
        "/request_id",
        "/evidence_refs/0",
        "/payload/case_id",
        "/payload/artifact_id",
        "/payload/subject_ref",
        "/payload/stage",
        "/payload/request_digest",
        "/payload/outcome",
        "/payload/reason_code",
    ] {
        let mut envelope = request.envelope.clone();
        *envelope.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(
            CaseEvidenceAdd::new(
                &request.draft,
                &request.key,
                &request.digest,
                &request.request,
                &request.event,
                &envelope,
            )
            .is_err(),
            "mismatched {pointer}"
        );
    }
    for refs in [json!([]), json!([artifact.as_str(), artifact.as_str()])] {
        let mut envelope = request.envelope.clone();
        envelope["evidence_refs"] = refs;
        assert!(
            CaseEvidenceAdd::new(
                &request.draft,
                &request.key,
                &request.digest,
                &request.request,
                &request.event,
                &envelope,
            )
            .is_err()
        );
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn case_membership_is_atomic_scoped_bounded_and_concurrent() {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&url, 4, Duration::from_secs(5))
        .await
        .unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    assert_idempotency_and_target_state(&pool, &store).await;
    assert_concurrent_keys_and_uniqueness(&pool, &store).await;
    assert_capacity(&pool, &store).await;
    assert_outbox_failure_rolls_back(&pool, &store).await;
    assert_expiry_after_lock_wait(&pool, &store).await;
    assert_lock_deadline(&pool, &store).await;
    for statement in [
        "DELETE FROM xshield.case_items WHERE tenant_id = $1",
        "DELETE FROM xshield.artifact_catalog WHERE tenant_id = $1",
        "DELETE FROM xshield.investigation_cases WHERE tenant_id = $1",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id = $1",
    ] {
        sqlx::query(statement)
            .bind(TENANT)
            .execute(&pool)
            .await
            .unwrap();
    }
}

async fn assert_idempotency_and_target_state(pool: &PgPool, store: &PostgresIdentityStore) {
    let case = seed_case(pool, "owner-1").await;
    let other_case = seed_case(pool, "owner-1").await;
    let artifact = seed_artifact(pool).await;
    let request = AddRequest::new(draft(&case, &artifact, "owner-1"), 1, 2);
    let expires_before: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT expires_at FROM xshield.artifact_catalog WHERE artifact_id = $1",
    )
    .bind(artifact.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    let CaseEvidenceWriteOutcome::Added(record) =
        store.add_case_evidence(request.command()).await.unwrap()
    else {
        panic!("first association must commit");
    };
    assert_eq!(record.artifact_id(), &artifact);
    assert_eq!(record.added_by(), "owner-1");
    let retry = AddRequest::new(request.draft.clone(), 1, 2);
    assert_eq!(
        store.add_case_evidence(retry.command()).await.unwrap(),
        CaseEvidenceWriteOutcome::Existing(record.clone())
    );
    for conflict in [
        AddRequest::new(request.draft.clone(), 1, 3),
        AddRequest::new(request.draft.clone(), 2, 2),
        AddRequest::new(draft(&other_case, &artifact, "owner-1"), 1, 2),
    ] {
        assert_eq!(
            store.add_case_evidence(conflict.command()).await.unwrap(),
            CaseEvidenceWriteOutcome::Conflict
        );
    }
    let expires_after: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT expires_at FROM xshield.artifact_catalog WHERE artifact_id = $1",
    )
    .bind(artifact.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(expires_before, expires_after);
    let approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.evidence_access_requests WHERE tenant_id = $1",
    )
    .bind(TENANT)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(approvals, 0);
    assert_unavailable_targets(pool, store, &case, &artifact).await;
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET recorded_at = clock_timestamp() - interval '2 hours',
         expires_at = clock_timestamp() - interval '1 hour' WHERE artifact_id = $1",
    )
    .bind(artifact.as_str())
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        store.add_case_evidence(retry.command()).await.unwrap(),
        CaseEvidenceWriteOutcome::Existing(record.clone())
    );
    let new_membership = AddRequest::new(draft(&other_case, &artifact, "owner-1"), 3, 4);
    assert_unavailable(store, &new_membership).await;
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET status = 'deleted', deleted_at = clock_timestamp(),
         expires_at = clock_timestamp() + interval '1 hour'
         WHERE artifact_id = $1",
    )
    .bind(artifact.as_str())
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        store.add_case_evidence(retry.command()).await.unwrap(),
        CaseEvidenceWriteOutcome::Existing(record)
    );
    assert_unavailable(store, &new_membership).await;
    sqlx::query("UPDATE xshield.investigation_cases SET status = 'closed' WHERE case_id = $1")
        .bind(case.as_str())
        .execute(pool)
        .await
        .unwrap();
    assert_unavailable(store, &retry).await;
    let outbox: (i64, Option<Value>) = sqlx::query_as(
        "SELECT count(*), jsonb_agg(envelope)->0 FROM xshield.audit_outbox
         WHERE aggregate_ref = $1 AND event_type = 'case.evidence.added'",
    )
    .bind(case.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(outbox, (1, Some(request.envelope)));
}

async fn assert_unavailable_targets(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    case: &CaseId,
    artifact: &ArtifactId,
) {
    for (tenant, site) in [("other_tenant", SITE), (TENANT, "other_site")] {
        let unavailable = CaseEvidenceDraft::new(
            TenantId::parse(tenant).unwrap(),
            SiteId::parse(site).unwrap(),
            case.clone(),
            artifact.clone(),
            "owner-1",
        )
        .unwrap();
        assert_unavailable(store, &AddRequest::new(unavailable, 3, 4)).await;
    }
    for unavailable in [
        draft(case, artifact, "other-owner"),
        draft(
            &CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap(),
            artifact,
            "owner-1",
        ),
        draft(
            case,
            &ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).unwrap(),
            "owner-1",
        ),
    ] {
        assert_unavailable(store, &AddRequest::new(unavailable, 3, 4)).await;
    }
    let foreign = seed_artifact(pool).await;
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET site_id = 'other_site' WHERE artifact_id = $1",
    )
    .bind(foreign.as_str())
    .execute(pool)
    .await
    .unwrap();
    assert_unavailable(
        store,
        &AddRequest::new(draft(case, &foreign, "owner-1"), 3, 4),
    )
    .await;
    sqlx::query(
        "UPDATE xshield.investigation_cases SET owner_ref = 'transferred-owner' WHERE case_id = $1",
    )
    .bind(case.as_str())
    .execute(pool)
    .await
    .unwrap();
    assert_unavailable(
        store,
        &AddRequest::new(draft(case, artifact, "owner-1"), 1, 2),
    )
    .await;
    sqlx::query("UPDATE xshield.investigation_cases SET owner_ref = 'owner-1' WHERE case_id = $1")
        .bind(case.as_str())
        .execute(pool)
        .await
        .unwrap();
}

async fn assert_concurrent_keys_and_uniqueness(pool: &PgPool, store: &PostgresIdentityStore) {
    let case = seed_case(pool, "owner-concurrent").await;
    let other = seed_case(pool, "owner-concurrent").await;
    let artifact = seed_artifact(pool).await;
    let first = AddRequest::new(draft(&case, &artifact, "owner-concurrent"), 1, 2);
    let second = AddRequest::new(draft(&case, &artifact, "owner-concurrent"), 1, 2);
    let (a, b) = tokio::join!(
        store.add_case_evidence(first.command()),
        store.add_case_evidence(second.command())
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, CaseEvidenceWriteOutcome::Added(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, CaseEvidenceWriteOutcome::Existing(_)))
            .count(),
        1
    );
    let artifact = seed_artifact(pool).await;
    let first = AddRequest::new(draft(&case, &artifact, "owner-concurrent"), 3, 4);
    let second = AddRequest::new(draft(&other, &artifact, "owner-concurrent"), 3, 4);
    let (a, b) = tokio::join!(
        store.add_case_evidence(first.command()),
        store.add_case_evidence(second.command())
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, CaseEvidenceWriteOutcome::Added(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| **r == CaseEvidenceWriteOutcome::Conflict)
            .count(),
        1
    );
    let artifact = seed_artifact(pool).await;
    let first = AddRequest::new(draft(&case, &artifact, "owner-concurrent"), 5, 6);
    let second = AddRequest::new(draft(&case, &artifact, "owner-concurrent"), 7, 8);
    let (a, b) = tokio::join!(
        store.add_case_evidence(first.command()),
        store.add_case_evidence(second.command())
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, CaseEvidenceWriteOutcome::Added(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| **r == CaseEvidenceWriteOutcome::Conflict)
            .count(),
        1
    );
}

async fn assert_capacity(pool: &PgPool, store: &PostgresIdentityStore) {
    let case = seed_case(pool, "owner-capacity").await;
    for key in 1..CASE_EVIDENCE_ITEMS_MAX {
        let artifact = seed_artifact(pool).await;
        let key = u8::try_from(key).unwrap();
        let request = AddRequest::new(draft(&case, &artifact, "owner-capacity"), key, key);
        assert!(matches!(
            store.add_case_evidence(request.command()).await.unwrap(),
            CaseEvidenceWriteOutcome::Added(_)
        ));
    }
    let first = AddRequest::new(
        draft(&case, &seed_artifact(pool).await, "owner-capacity"),
        128,
        128,
    );
    let second = AddRequest::new(
        draft(&case, &seed_artifact(pool).await, "owner-capacity"),
        129,
        129,
    );
    let (a, b) = tokio::join!(
        store.add_case_evidence(first.command()),
        store.add_case_evidence(second.command())
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, CaseEvidenceWriteOutcome::Added(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| **r == CaseEvidenceWriteOutcome::CapacityExceeded)
            .count(),
        1
    );
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM xshield.case_items WHERE case_id = $1),
                (SELECT count(*) FROM xshield.audit_outbox WHERE aggregate_ref = $1)",
    )
    .bind(case.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(counts, (128, 128));
    let committed = if matches!(outcomes[0], CaseEvidenceWriteOutcome::Added(_)) {
        first
    } else {
        second
    };
    assert!(matches!(
        store.add_case_evidence(committed.command()).await.unwrap(),
        CaseEvidenceWriteOutcome::Existing(_)
    ));
}

async fn assert_outbox_failure_rolls_back(pool: &PgPool, store: &PostgresIdentityStore) {
    let case = seed_case(pool, "owner-fault").await;
    let artifact = seed_artifact(pool).await;
    let request = AddRequest::new(draft(&case, &artifact, "owner-fault"), 1, 2);
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1, $2, $3, 'collision', 'fixture', '{}')",
    )
    .bind(request.event.as_str())
    .bind(TENANT)
    .bind(SITE)
    .execute(pool)
    .await
    .unwrap();
    assert!(store.add_case_evidence(request.command()).await.is_err());
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM xshield.case_items WHERE case_id = $1")
            .bind(case.as_str())
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    let retry = AddRequest::new(request.draft, 1, 2);
    assert!(matches!(
        store.add_case_evidence(retry.command()).await.unwrap(),
        CaseEvidenceWriteOutcome::Added(_)
    ));
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(retry.event.as_str())
        .execute(pool)
        .await
        .unwrap();
    assert!(matches!(
        store.add_case_evidence(retry.command()).await,
        Err(xshield_postgres::StoreError::CorruptData(
            "case_evidence_outbox"
        ))
    ));
}

async fn assert_expiry_after_lock_wait(pool: &PgPool, store: &PostgresIdentityStore) {
    let case = seed_case(pool, "owner-lock-expiry").await;
    let artifact = seed_artifact(pool).await;
    sqlx::query(
        "UPDATE xshield.artifact_catalog SET recorded_at = clock_timestamp() - interval '1 hour',
         expires_at = clock_timestamp() + interval '200 milliseconds' WHERE artifact_id = $1",
    )
    .bind(artifact.as_str())
    .execute(pool)
    .await
    .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM xshield.artifact_catalog WHERE artifact_id = $1 FOR UPDATE")
        .bind(artifact.as_str())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let request = AddRequest::new(draft(&case, &artifact, "owner-lock-expiry"), 1, 2);
    let (outcome, ()) = tokio::join!(store.add_case_evidence(request.command()), async {
        tokio::time::sleep(Duration::from_millis(400)).await;
        blocker.commit().await.unwrap();
    });
    assert_eq!(
        outcome.unwrap(),
        CaseEvidenceWriteOutcome::TargetUnavailable
    );
}

async fn assert_lock_deadline(pool: &PgPool, store: &PostgresIdentityStore) {
    let case = seed_case(pool, "owner-lock-deadline").await;
    let artifact = seed_artifact(pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM xshield.investigation_cases WHERE case_id = $1 FOR UPDATE")
        .bind(case.as_str())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let request = AddRequest::new(draft(&case, &artifact, "owner-lock-deadline"), 1, 2);
    assert!(
        tokio::time::timeout(
            Duration::from_secs(8),
            store.add_case_evidence(request.command())
        )
        .await
        .unwrap()
        .is_err()
    );
    blocker.rollback().await.unwrap();
    assert!(matches!(
        store.add_case_evidence(request.command()).await.unwrap(),
        CaseEvidenceWriteOutcome::Added(_)
    ));
}

async fn assert_unavailable(store: &PostgresIdentityStore, request: &AddRequest) {
    assert_eq!(
        store.add_case_evidence(request.command()).await.unwrap(),
        CaseEvidenceWriteOutcome::TargetUnavailable
    );
}

fn draft(case: &CaseId, artifact: &ArtifactId, actor: &str) -> CaseEvidenceDraft {
    CaseEvidenceDraft::new(
        TenantId::parse(TENANT).unwrap(),
        SiteId::parse(SITE).unwrap(),
        case.clone(),
        artifact.clone(),
        actor,
    )
    .unwrap()
}

async fn seed_case(pool: &PgPool, owner: &str) -> CaseId {
    let case = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
             tenant_id, site_id, case_id, owner_ref, purpose, status,
             idempotency_digest, request_digest, created_event_id
         ) VALUES ($1, $2, $3, $4, 'Investigate evidence', 'open', $5, $5, $6)",
    )
    .bind(TENANT)
    .bind(SITE)
    .bind(case.as_str())
    .bind(owner)
    .bind(Uuid::now_v7().as_bytes().repeat(2))
    .bind(format!("ev_{}", Uuid::now_v7()))
    .execute(pool)
    .await
    .unwrap();
    case
}

async fn seed_artifact(pool: &PgPool) -> ArtifactId {
    let artifact = ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).unwrap();
    sqlx::query(
        "INSERT INTO xshield.artifact_catalog (
             tenant_id, site_id, artifact_id, request_id, schema_version, kind,
             content_type, capture_status, fidelity, bytes_observed, bytes_saved,
             classification, example_only, storage_profile, storage_locator,
             key_ref, integrity_algorithm, integrity_digest, parent_refs,
             recorded_at, expires_at, catalog_event_id, status, deleted_at
         ) VALUES ($1, $2, $3, $4, 3, 'response_from_origin',
             'application/json', 'complete', 'entity_exact', 2, 2,
             'RESTRICTED', false, 'aead_envelope_v1', $3 || '.xev',
             'evidence-key-r1', 'sha256_ciphertext', repeat('a', 64), '{}',
             clock_timestamp(), clock_timestamp() + interval '1 hour', $5, 'active', NULL)",
    )
    .bind(TENANT)
    .bind(SITE)
    .bind(artifact.as_str())
    .bind(format!("req_{}", Uuid::now_v7()))
    .bind(format!("ev_{}", Uuid::now_v7()))
    .execute(pool)
    .await
    .unwrap();
    artifact
}

#[test]
fn collection_query_rejects_unbounded_or_invalid_owner() {
    let tenant = TenantId::parse(TENANT).unwrap();
    let site = SiteId::parse(SITE).unwrap();
    let case_id = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    let artifact_id = ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).unwrap();
    for (owner, limit) in [("", 1), ("owner\n", 1), ("owner", 0), ("owner", 129)] {
        assert!(
            CaseEvidenceQuery::new(&tenant, &site, &case_id, owner, Some(&artifact_id), limit,)
                .is_err()
        );
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn collection_query_is_scoped_snapshot_paginated_and_availability_aware() {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&url, 4, Duration::from_secs(5))
        .await
        .unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    let suffix = Uuid::now_v7().to_string().replace('-', "");
    let tenant = format!("tenant_case_read_{suffix}");
    let site = format!("site_case_read_{suffix}");
    let owner = "investigator-read";
    let tenant_id = TenantId::parse(&tenant).unwrap();
    let site_id = SiteId::parse(&site).unwrap();
    let case_id = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    insert_read_case(&pool, &tenant, &site, &case_id, owner).await;

    let first = insert_read_artifact(&pool, &tenant, &site, &case_id, owner, "active", 1).await;
    let second = insert_read_artifact(&pool, &tenant, &site, &case_id, owner, "expired", 2).await;
    let third = insert_read_artifact(&pool, &tenant, &site, &case_id, owner, "deleted", 3).await;
    let query = CaseEvidenceQuery::new(&tenant_id, &site_id, &case_id, owner, None, 2).unwrap();
    let page = store.list_case_evidence(query).await.unwrap().unwrap();
    assert_eq!(page.case_status(), "open");
    assert_eq!(page.case().purpose(), "Read case collection");
    assert_eq!(page.items().len(), 2);
    assert_eq!(page.items()[0].record().artifact_id(), &first);
    assert_eq!(
        page.items()[0].availability(),
        CaseEvidenceAvailability::Active
    );
    assert_eq!(page.items()[1].record().artifact_id(), &second);
    assert_eq!(
        page.items()[1].availability(),
        CaseEvidenceAvailability::Expired
    );
    let cursor = page.next_artifact_id().cloned().expect("lookahead cursor");

    let fourth = insert_read_artifact(&pool, &tenant, &site, &case_id, owner, "active", 4).await;
    let query =
        CaseEvidenceQuery::new(&tenant_id, &site_id, &case_id, owner, Some(&cursor), 2).unwrap();
    let page = store.list_case_evidence(query).await.unwrap().unwrap();
    assert_eq!(page.items().len(), 2);
    assert_eq!(page.items()[0].record().artifact_id(), &third);
    assert_eq!(
        page.items()[0].availability(),
        CaseEvidenceAvailability::Deleted
    );
    assert_eq!(page.items()[1].record().artifact_id(), &fourth);
    assert_eq!(
        page.items()[1].availability(),
        CaseEvidenceAvailability::Active
    );
    assert!(page.next_artifact_id().is_none());

    sqlx::query("UPDATE xshield.investigation_cases SET status = 'closed' WHERE tenant_id = $1 AND site_id = $2 AND case_id = $3")
        .bind(&tenant)
        .bind(&site)
        .bind(case_id.as_str())
        .execute(&pool)
        .await
        .unwrap();
    let query = CaseEvidenceQuery::new(&tenant_id, &site_id, &case_id, owner, None, 1).unwrap();
    assert_eq!(
        store
            .list_case_evidence(query)
            .await
            .unwrap()
            .unwrap()
            .case_status(),
        "closed"
    );

    let wrong_owner =
        CaseEvidenceQuery::new(&tenant_id, &site_id, &case_id, "other-owner", None, 1).unwrap();
    assert!(
        store
            .list_case_evidence(wrong_owner)
            .await
            .unwrap()
            .is_none()
    );
    let missing = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    let missing = CaseEvidenceQuery::new(&tenant_id, &site_id, &missing, owner, None, 1).unwrap();
    assert!(store.list_case_evidence(missing).await.unwrap().is_none());
    let foreign_tenant = TenantId::parse(format!("tenant_foreign_{suffix}")).unwrap();
    let foreign =
        CaseEvidenceQuery::new(&foreign_tenant, &site_id, &case_id, owner, None, 1).unwrap();
    assert!(store.list_case_evidence(foreign).await.unwrap().is_none());

    sqlx::query("DELETE FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2 AND aggregate_ref = $3 AND event_type = 'case.evidence.added'")
        .bind(&tenant)
        .bind(&site)
        .bind(case_id.as_str())
        .execute(&pool)
        .await
        .unwrap();
    let corrupt = CaseEvidenceQuery::new(&tenant_id, &site_id, &case_id, owner, None, 1).unwrap();
    assert!(matches!(
        store.list_case_evidence(corrupt).await,
        Err(xshield_postgres::StoreError::CorruptData(
            "case_evidence_outbox"
        ))
    ));

    sqlx::query("DELETE FROM xshield.case_items WHERE tenant_id = $1 AND site_id = $2")
        .bind(&tenant)
        .bind(&site)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.artifact_catalog WHERE tenant_id = $1 AND site_id = $2")
        .bind(&tenant)
        .bind(&site)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.investigation_cases WHERE tenant_id = $1 AND site_id = $2")
        .bind(&tenant)
        .bind(&site)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2")
        .bind(&tenant)
        .bind(&site)
        .execute(&pool)
        .await
        .unwrap();
}

async fn insert_read_case(pool: &PgPool, tenant: &str, site: &str, case: &CaseId, owner: &str) {
    let event = format!("ev_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
             tenant_id, site_id, case_id, owner_ref, purpose, status,
             idempotency_digest, request_digest, created_event_id
         ) VALUES ($1, $2, $3, $4, 'Read case collection', 'open', $5, $5, $6)",
    )
    .bind(tenant)
    .bind(site)
    .bind(case.as_str())
    .bind(owner)
    .bind([11_u8; 32].as_slice())
    .bind(&event)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1, $2, $3, $4, 'case.created', '{}')",
    )
    .bind(event)
    .bind(tenant)
    .bind(site)
    .bind(case.as_str())
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_read_artifact(
    pool: &PgPool,
    tenant: &str,
    site: &str,
    case: &CaseId,
    owner: &str,
    state: &str,
    nonce: u8,
) -> ArtifactId {
    let artifact = ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).unwrap();
    let request = format!("req_{}", Uuid::now_v7());
    let catalog_event = format!("ev_{}", Uuid::now_v7());
    let added_event = format!("ev_{}", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO xshield.artifact_catalog (
             tenant_id, site_id, artifact_id, request_id, schema_version, kind,
             content_type, capture_status, fidelity, bytes_observed, bytes_saved,
             classification, example_only, storage_profile, storage_locator,
             key_ref, integrity_algorithm, integrity_digest, parent_refs,
             recorded_at, expires_at, catalog_event_id, status, deleted_at
         ) VALUES ($1, $2, $3, $4, 3, 'response_from_origin',
             'application/json', 'complete', 'entity_exact', 2, 2,
             'RESTRICTED', false, 'aead_envelope_v1', $3 || '.xev',
             'evidence-key-r1', 'sha256_ciphertext', repeat('a', 64), '{}',
             clock_timestamp() - interval '2 hours',
             CASE WHEN $6 = 'expired'
                  THEN clock_timestamp() - interval '1 hour'
                  ELSE clock_timestamp() + interval '1 hour' END,
             $5,
             CASE WHEN $6 = 'deleted' THEN 'deleted' ELSE 'active' END,
             CASE WHEN $6 = 'deleted' THEN clock_timestamp() ELSE NULL END)",
    )
    .bind(tenant)
    .bind(site)
    .bind(artifact.as_str())
    .bind(request)
    .bind(catalog_event)
    .bind(state)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.case_items (
             tenant_id, site_id, case_id, artifact_id, added_by,
             idempotency_digest, request_digest, added_event_id
         ) VALUES ($1, $2, $3, $4, $5, $6, $6, $7)",
    )
    .bind(tenant)
    .bind(site)
    .bind(case.as_str())
    .bind(artifact.as_str())
    .bind(owner)
    .bind([nonce; 32])
    .bind(&added_event)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1, $2, $3, $4, 'case.evidence.added', '{}')",
    )
    .bind(added_event)
    .bind(tenant)
    .bind(site)
    .bind(case.as_str())
    .execute(pool)
    .await
    .unwrap();
    artifact
}
