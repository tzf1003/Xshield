use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{env, time::Duration};
use xshield_core::{
    domain::{ArtifactId, CaseId, EventId, EvidenceAccessRequestId, RequestId, SiteId, TenantId},
    investigation::{EvidenceAccessKind, EvidenceAccessRequestDraft},
};
use xshield_postgres::{
    EvidenceAccessRequestCreate, EvidenceAccessRequestWriteOutcome, PostgresIdentityStore,
    StoreError,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_access_request_is_atomic_idempotent_scoped_and_bounded() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 3, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    seed_targets(&pool).await;
    let draft = access_draft("000000000941", "Verify source response");
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000942").unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000943").unwrap();
    let envelope = access_envelope(&draft, &request, &event, &[2; 32]);

    let created = store
        .create_evidence_access_request(
            EvidenceAccessRequestCreate::new(
                &draft, &[1; 32], &[2; 32], &request, &event, &envelope, 1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        created,
        EvidenceAccessRequestWriteOutcome::Created(_)
    ));
    assert_exact_retry_conflict_and_capacity(&store).await;
    assert_unavailable_targets(&store).await;
    assert_outbox_collision_rolls_back(&pool, &store).await;
    assert_concurrent_capacity(&store).await;
    assert_lock_timeout_and_post_lock_expiry(&pool, &store).await;
    let retried = store
        .create_evidence_access_request(
            EvidenceAccessRequestCreate::new(
                &draft, &[1; 32], &[2; 32], &request, &event, &envelope, 1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let EvidenceAccessRequestWriteOutcome::Created(original) = created else {
        panic!("request was created");
    };
    assert_eq!(
        retried,
        EvidenceAccessRequestWriteOutcome::Existing(original)
    );
    cleanup_targets(&pool).await;
}

async fn assert_lock_timeout_and_post_lock_expiry(pool: &PgPool, store: &PostgresIdentityStore) {
    for (index, expires_during_wait) in [false, true].into_iter().enumerate() {
        let expiry: DateTime<Utc> = sqlx::query_scalar(
            "UPDATE xshield.artifact_catalog
             SET expires_at = clock_timestamp() + make_interval(secs => $1)
             WHERE tenant_id = 'tenant_access' RETURNING expires_at",
        )
        .bind(if expires_during_wait { 2.0 } else { 3600.0 })
        .fetch_one(pool)
        .await
        .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        // A pure row lock never replaces the tuple: EvalPlanQual cannot hide
        // a clock predicate evaluated before the lock wait.
        let blocker_pid: i32 = sqlx::query_scalar(
            "SELECT pg_backend_pid() FROM xshield.artifact_catalog
             WHERE tenant_id = 'tenant_access' FOR UPDATE",
        )
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
        let draft = access_draft(&format!("{:012}", 968 + index), "Wait for evidence lock");
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000970").unwrap();
        let event =
            EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{:012}", 970 + index)).unwrap();
        let envelope = access_envelope(&draft, &request, &event, &[21; 32]);
        let command = EvidenceAccessRequestCreate::new(
            &draft, &[20; 32], &[21; 32], &request, &event, &envelope, 10,
        )
        .unwrap();
        let operation = store.create_evidence_access_request(command);
        if expires_during_wait {
            let release = async {
                wait_until_blocked(pool, blocker_pid).await;
                sqlx::query("SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM $1::timestamptz - clock_timestamp())) + 0.05)")
                    .bind(expiry)
                    .execute(&mut *blocker)
                    .await
                    .unwrap();
                blocker.rollback().await.unwrap();
            };
            let (outcome, ()) = tokio::join!(operation, release);
            assert_eq!(
                outcome.unwrap(),
                EvidenceAccessRequestWriteOutcome::TargetUnavailable
            );
        } else {
            let started = std::time::Instant::now();
            let result = tokio::time::timeout(Duration::from_secs(7), operation).await;
            blocker.rollback().await.unwrap();
            let StoreError::Database(sqlx::Error::Database(error)) = result
                .expect("request lock wait is bounded")
                .expect_err("locked request must time out")
            else {
                panic!("expected a PostgreSQL timeout");
            };
            assert!(matches!(error.code().as_deref(), Some("57014" | "55P03")));
            assert!(started.elapsed() >= Duration::from_secs(4));
        }
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM xshield.evidence_access_requests WHERE access_request_id = $1),
                    (SELECT count(*) FROM xshield.audit_outbox WHERE event_id = $2)",
        )
        .bind(draft.access_request_id().as_str())
        .bind(event.as_str())
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(counts, (0, 0));
    }
}

async fn wait_until_blocked(pool: &PgPool, blocker_pid: i32) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                 WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker_pid)
            .fetch_one(pool)
            .await
            .unwrap();
            if blocked {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("operation reached the held row lock");
}

async fn cleanup_targets(pool: &PgPool) {
    sqlx::query("DELETE FROM xshield.evidence_access_requests WHERE tenant_id = 'tenant_access'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.artifact_catalog WHERE tenant_id = 'tenant_access'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.investigation_cases WHERE tenant_id = 'tenant_access'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE tenant_id = 'tenant_access'")
        .execute(pool)
        .await
        .unwrap();
}

async fn seed_targets(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
            tenant_id, site_id, case_id, owner_ref, purpose, status,
            idempotency_digest, request_digest, created_event_id
         ) VALUES (
            'tenant_access', 'site_access',
            'case_018f2a3b-4c5d-7000-8000-000000000944',
            'investigator-1', 'Investigate evidence', 'open',
            decode(repeat('11', 32), 'hex'), decode(repeat('12', 32), 'hex'),
            'ev_018f2a3b-4c5d-7000-8000-000000000945'
         )",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
            tenant_id, site_id, case_id, owner_ref, purpose, status,
            idempotency_digest, request_digest, created_event_id
         ) VALUES (
            'tenant_access', 'site_access',
            'case_018f2a3b-4c5d-7000-8000-000000000960',
            'investigator-concurrent', 'Concurrent access', 'open',
            decode(repeat('21', 32), 'hex'), decode(repeat('22', 32), 'hex'),
            'ev_018f2a3b-4c5d-7000-8000-000000000961'
         )",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.artifact_catalog (
            tenant_id, site_id, artifact_id, request_id, schema_version, kind,
            content_type, capture_status, fidelity, bytes_observed, bytes_saved,
            classification, example_only, storage_profile, storage_locator,
            key_ref, integrity_algorithm, integrity_digest, parent_refs,
            recorded_at, expires_at, catalog_event_id, status, deleted_at
         ) VALUES (
            'tenant_access', 'site_access',
            'artifact_018f2a3b-4c5d-7000-8000-000000000946',
            'req_018f2a3b-4c5d-7000-8000-000000000947', 3, 'response_from_origin',
            'application/json', 'complete', 'entity_exact', 2, 2,
            'RESTRICTED', false, 'aead_envelope_v1',
            'artifact_018f2a3b-4c5d-7000-8000-000000000946.xev',
            'evidence-key-r1', 'sha256_ciphertext', repeat('a', 64), '{}',
            clock_timestamp(), clock_timestamp() + interval '1 hour',
            'ev_018f2a3b-4c5d-7000-8000-000000000948', 'active', NULL
         )",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn assert_exact_retry_conflict_and_capacity(store: &PostgresIdentityStore) {
    let retry = access_draft("000000000949", "Verify source response");
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000950").unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000951").unwrap();
    let envelope = access_envelope(&retry, &request, &event, &[2; 32]);
    assert!(matches!(
        store
            .create_evidence_access_request(
                EvidenceAccessRequestCreate::new(
                    &retry, &[1; 32], &[2; 32], &request, &event, &envelope, 1,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        EvidenceAccessRequestWriteOutcome::Existing(_)
    ));

    let conflict = access_draft("000000000952", "Different justification");
    let envelope = access_envelope(&conflict, &request, &event, &[3; 32]);
    assert_eq!(
        store
            .create_evidence_access_request(
                EvidenceAccessRequestCreate::new(
                    &conflict, &[1; 32], &[3; 32], &request, &event, &envelope, 1,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        EvidenceAccessRequestWriteOutcome::Conflict
    );

    let full = access_draft("000000000953", "Second request");
    let envelope = access_envelope(&full, &request, &event, &[5; 32]);
    assert_eq!(
        store
            .create_evidence_access_request(
                EvidenceAccessRequestCreate::new(
                    &full, &[4; 32], &[5; 32], &request, &event, &envelope, 1,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        EvidenceAccessRequestWriteOutcome::CapacityExceeded
    );
}

async fn assert_unavailable_targets(store: &PostgresIdentityStore) {
    let mut draft = access_draft("000000000954", "Wrong case");
    draft = EvidenceAccessRequestDraft::new(
        draft.access_request_id().clone(),
        draft.tenant_id().clone(),
        draft.site_id().clone(),
        CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000999").unwrap(),
        draft.artifact_id().clone(),
        draft.requested_by(),
        draft.kind(),
        draft.justification(),
    )
    .unwrap();
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000955").unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000956").unwrap();
    let envelope = access_envelope(&draft, &request, &event, &[7; 32]);
    assert_eq!(
        store
            .create_evidence_access_request(
                EvidenceAccessRequestCreate::new(
                    &draft, &[6; 32], &[7; 32], &request, &event, &envelope, 2,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        EvidenceAccessRequestWriteOutcome::TargetUnavailable
    );
}

async fn assert_outbox_collision_rolls_back(pool: &PgPool, store: &PostgresIdentityStore) {
    let draft = access_draft("000000000957", "Collision request");
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000958").unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000959").unwrap();
    let envelope = access_envelope(&draft, &request, &event, &[9; 32]);
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, 'tenant_access', 'site_access', 'collision', 'fixture', '{}')",
    )
    .bind(event.as_str())
    .execute(pool)
    .await
    .unwrap();
    assert!(
        store
            .create_evidence_access_request(
                EvidenceAccessRequestCreate::new(
                    &draft, &[8; 32], &[9; 32], &request, &event, &envelope, 2,
                )
                .unwrap(),
            )
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.evidence_access_requests
         WHERE access_request_id = $1",
    )
    .bind(draft.access_request_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}

async fn assert_concurrent_capacity(store: &PostgresIdentityStore) {
    let first = access_draft_for(
        "000000000962",
        "case_018f2a3b-4c5d-7000-8000-000000000960",
        "investigator-concurrent",
        "Concurrent first",
    );
    let second = access_draft_for(
        "000000000963",
        "case_018f2a3b-4c5d-7000-8000-000000000960",
        "investigator-concurrent",
        "Concurrent second",
    );
    let first_request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000964").unwrap();
    let second_request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000965").unwrap();
    let first_event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000966").unwrap();
    let second_event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000967").unwrap();
    let first_envelope = access_envelope(&first, &first_request, &first_event, &[11; 32]);
    let second_envelope = access_envelope(&second, &second_request, &second_event, &[13; 32]);
    let first_command = EvidenceAccessRequestCreate::new(
        &first,
        &[10; 32],
        &[11; 32],
        &first_request,
        &first_event,
        &first_envelope,
        1,
    )
    .unwrap();
    let second_command = EvidenceAccessRequestCreate::new(
        &second,
        &[12; 32],
        &[13; 32],
        &second_request,
        &second_event,
        &second_envelope,
        1,
    )
    .unwrap();
    let (first_outcome, second_outcome) = tokio::join!(
        store.create_evidence_access_request(first_command),
        store.create_evidence_access_request(second_command),
    );
    let outcomes = [first_outcome.unwrap(), second_outcome.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EvidenceAccessRequestWriteOutcome::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                matches!(outcome, EvidenceAccessRequestWriteOutcome::CapacityExceeded)
            })
            .count(),
        1
    );
}

fn access_draft(suffix: &str, justification: &str) -> EvidenceAccessRequestDraft {
    access_draft_for(
        suffix,
        "case_018f2a3b-4c5d-7000-8000-000000000944",
        "investigator-1",
        justification,
    )
}

fn access_draft_for(
    suffix: &str,
    case_id: &str,
    requested_by: &str,
    justification: &str,
) -> EvidenceAccessRequestDraft {
    EvidenceAccessRequestDraft::new(
        EvidenceAccessRequestId::parse(format!("access_018f2a3b-4c5d-7000-8000-{suffix}")).unwrap(),
        TenantId::parse("tenant_access").unwrap(),
        SiteId::parse("site_access").unwrap(),
        CaseId::parse(case_id).unwrap(),
        ArtifactId::parse("artifact_018f2a3b-4c5d-7000-8000-000000000946").unwrap(),
        requested_by,
        EvidenceAccessKind::SensitiveRaw,
        justification,
    )
    .unwrap()
}

fn access_envelope(
    draft: &EvidenceAccessRequestDraft,
    request: &RequestId,
    event: &EventId,
    request_digest: &[u8; 32],
) -> Value {
    json!({
        "schema_version": 3,
        "event_id": event.as_str(),
        "event_type": "evidence.access.requested",
        "tenant_id": draft.tenant_id().as_str(),
        "site_id": draft.site_id().as_str(),
        "request_id": request.as_str(),
        "evidence_refs": [draft.artifact_id().as_str()],
        "payload": {
            "access_request_id": draft.access_request_id().as_str(),
            "case_id": draft.case_id().as_str(),
            "artifact_id": draft.artifact_id().as_str(),
            "subject_ref": draft.requested_by(),
            "access_kind": draft.kind().as_str(),
            "stage": "evidence_access",
            "request_digest": lower_hex(request_digest),
            "outcome": "PASS",
            "reason_code": "EVIDENCE_ACCESS_REQUESTED"
        }
    })
}

fn lower_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
