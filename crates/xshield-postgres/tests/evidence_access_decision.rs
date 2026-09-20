use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Transaction};
use std::{env, time::Duration};
use xshield_core::{
    domain::{ArtifactId, EventId, EvidenceAccessRequestId, RequestId, SiteId, TenantId},
    investigation::{EvidenceAccessDecisionDraft, EvidenceAccessDecisionKind},
};
use xshield_postgres::{
    EvidenceAccessDecisionCreate, EvidenceAccessDecisionWriteOutcome, PostgresIdentityStore,
    StoreError,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn evidence_access_decision_is_independent_atomic_and_idempotent() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 4, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    seed_targets(&pool).await;

    let approval = decision(
        "000000000981",
        "approver-1",
        EvidenceAccessDecisionKind::Approved,
        "Approve scoped incident review",
    );
    let created = apply(&store, &approval, [1; 32], [2; 32], "000000000982").await;
    let EvidenceAccessDecisionWriteOutcome::Created(record) = created else {
        panic!("approval must be created");
    };
    assert_eq!(record.status(), "approved");
    assert_eq!(record.decided_by(), "approver-1");
    assert!(record.access_expires_at().is_some());
    let tenant = TenantId::parse("tenant_decision").unwrap();
    let site = SiteId::parse("site_decision").unwrap();
    let artifact = ArtifactId::parse("artifact_018f2a3b-4c5d-7000-8000-000000000978").unwrap();
    let capability = store
        .find_evidence_access_capability(
            &tenant,
            &site,
            record.access_request_id(),
            &artifact,
            "investigator-1",
        )
        .await
        .expect("capability lookup succeeds")
        .expect("approved capability is live");
    assert_eq!(capability.requested_by(), "investigator-1");
    assert_eq!(capability.artifact().artifact_id(), &artifact);
    assert!(
        store
            .find_evidence_access_capability(
                &tenant,
                &site,
                record.access_request_id(),
                &artifact,
                "approver-1",
            )
            .await
            .expect("wrong subject lookup succeeds")
            .is_none()
    );

    assert_lock_timeouts(&pool, &store, record.access_request_id()).await;
    assert_post_lock_decision_time(&pool, &store).await;
    assert_post_lock_capability_expiry(&pool, &store, record.access_request_id()).await;
    assert_post_lock_approval_expiry(&pool, &store).await;

    sqlx::query(
        "UPDATE xshield.artifact_catalog
         SET status = 'deleted', deleted_at = clock_timestamp()
         WHERE tenant_id = 'tenant_decision'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        store
            .find_evidence_access_capability(
                &tenant,
                &site,
                record.access_request_id(),
                &artifact,
                "investigator-1",
            )
            .await
            .expect("deleted capability lookup succeeds")
            .is_none()
    );
    assert!(matches!(
        apply(&store, &approval, [1; 32], [2; 32], "000000000983").await,
        EvidenceAccessDecisionWriteOutcome::Existing(_)
    ));
    let changed = decision(
        "000000000981",
        "approver-1",
        EvidenceAccessDecisionKind::Approved,
        "Changed reason",
    );
    assert_eq!(
        apply(&store, &changed, [1; 32], [3; 32], "000000000984").await,
        EvidenceAccessDecisionWriteOutcome::Conflict
    );

    assert_self_approval_and_stale_target(&store).await;
    assert_denial_and_concurrent_terminal_decision(&store).await;
    assert_outbox_collision_rolls_back(&pool, &store).await;
    cleanup(&pool).await;
}

async fn assert_post_lock_decision_time(pool: &PgPool, store: &PostgresIdentityStore) {
    set_artifact_expiry(pool, 3600.0).await;
    let approval = EvidenceAccessDecisionDraft::approve(
        TenantId::parse("tenant_decision").unwrap(),
        SiteId::parse("site_decision").unwrap(),
        EvidenceAccessRequestId::parse("access_018f2a3b-4c5d-7000-8000-000000000998").unwrap(),
        "fresh-clock-approver",
        "Use post-lock time",
        1,
        900,
    )
    .unwrap();
    let (mut blocker, blocker_pid) = lock_artifact(pool).await;
    let release = async {
        wait_until_blocked(pool, blocker_pid).await;
        let released_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        blocker.rollback().await.unwrap();
        released_at
    };
    let (outcome, released_at) = tokio::join!(
        apply(store, &approval, [20; 32], [21; 32], "000000001020"),
        release,
    );
    let EvidenceAccessDecisionWriteOutcome::Created(record) = outcome else {
        panic!("valid post-lock approval is created");
    };
    assert!(record.decided_at() >= released_at);
    assert_eq!(
        record.access_expires_at(),
        Some(record.decided_at() + TimeDelta::seconds(1))
    );
    wait_past_expiry(pool, record.access_expires_at().unwrap()).await;
    assert_eq!(
        apply(store, &approval, [20; 32], [21; 32], "000000001021").await,
        EvidenceAccessDecisionWriteOutcome::Existing(record),
        "exact retry preserves the original, now-expired lease",
    );
}

async fn assert_post_lock_approval_expiry(pool: &PgPool, store: &PostgresIdentityStore) {
    let expiry = set_artifact_expiry(pool, 2.0).await;
    let approval = decision(
        "000000000985",
        "expiry-approver",
        EvidenceAccessDecisionKind::Approved,
        "Evidence expires while approval waits",
    );
    let (blocker, blocker_pid) = lock_artifact(pool).await;
    let release = async {
        wait_until_blocked(pool, blocker_pid).await;
        wait_past_expiry(pool, expiry).await;
        blocker.rollback().await.unwrap();
    };
    let (outcome, ()) = tokio::join!(
        apply(store, &approval, [22; 32], [23; 32], "000000001022"),
        release,
    );
    assert_eq!(
        outcome,
        EvidenceAccessDecisionWriteOutcome::TargetUnavailable
    );
    let state: (String, Option<DateTime<Utc>>, i64) = sqlx::query_as(
        "SELECT status, decided_at,
                (SELECT count(*) FROM xshield.audit_outbox WHERE event_id = 'ev_018f2a3b-4c5d-7000-8000-000000001122')
         FROM xshield.evidence_access_requests WHERE tenant_id = 'tenant_decision' AND access_request_id = $1",
    )
    .bind(approval.access_request_id().as_str()).fetch_one(pool).await.unwrap();
    assert_eq!(state, ("pending".into(), None, 0));
}

async fn assert_post_lock_capability_expiry(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    access: &EvidenceAccessRequestId,
) {
    let tenant = TenantId::parse("tenant_decision").unwrap();
    let site = SiteId::parse("site_decision").unwrap();
    let artifact = ArtifactId::parse("artifact_018f2a3b-4c5d-7000-8000-000000000978").unwrap();
    for artifact_expires in [false, true] {
        let artifact_expiry =
            set_artifact_expiry(pool, if artifact_expires { 2.0 } else { 3600.0 }).await;
        let access_expiry: DateTime<Utc> = sqlx::query_scalar(
            "UPDATE xshield.evidence_access_requests
             SET access_expires_at = clock_timestamp() + make_interval(secs => $2)
             WHERE tenant_id = 'tenant_decision' AND access_request_id = $1
             RETURNING access_expires_at",
        )
        .bind(access.as_str())
        .bind(if artifact_expires { 3600.0 } else { 2.0 })
        .fetch_one(pool)
        .await
        .unwrap();
        let (blocker, blocker_pid) = lock_artifact(pool).await;
        let release = async {
            wait_until_blocked(pool, blocker_pid).await;
            wait_past_expiry(
                pool,
                if artifact_expires {
                    artifact_expiry
                } else {
                    access_expiry
                },
            )
            .await;
            blocker.rollback().await.unwrap();
        };
        let (capability, ()) = tokio::join!(
            store.find_evidence_access_capability(
                &tenant,
                &site,
                access,
                &artifact,
                "investigator-1"
            ),
            release,
        );
        assert!(
            capability.unwrap().is_none(),
            "both independent deadlines are checked after locking"
        );
    }
}

async fn assert_lock_timeouts(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    access: &EvidenceAccessRequestId,
) {
    let tenant = TenantId::parse("tenant_decision").unwrap();
    let site = SiteId::parse("site_decision").unwrap();
    let artifact = ArtifactId::parse("artifact_018f2a3b-4c5d-7000-8000-000000000978").unwrap();
    let approval = decision(
        "000000000985",
        "timeout-approver",
        EvidenceAccessDecisionKind::Approved,
        "Bound the row lock wait",
    );
    let (blocker, _) = lock_artifact(pool).await;
    let started = std::time::Instant::now();
    let results = tokio::time::timeout(Duration::from_secs(7), async {
        tokio::join!(
            try_apply(store, &approval, [24; 32], [25; 32], "000000001024"),
            store.find_evidence_access_capability(
                &tenant,
                &site,
                access,
                &artifact,
                "investigator-1"
            ),
        )
    })
    .await;
    blocker.rollback().await.unwrap();
    let (decision, capability) = results.expect("decision and capability waits are bounded");
    for error in [decision.unwrap_err(), capability.unwrap_err()] {
        let StoreError::Database(sqlx::Error::Database(error)) = error else {
            panic!("expected PostgreSQL timeout");
        };
        assert!(matches!(error.code().as_deref(), Some("57014" | "55P03")));
    }
    assert!(started.elapsed() >= Duration::from_secs(4));
}

async fn set_artifact_expiry(pool: &PgPool, seconds: f64) -> DateTime<Utc> {
    sqlx::query_scalar(
        "UPDATE xshield.artifact_catalog
         SET expires_at = clock_timestamp() + make_interval(secs => $1)
         WHERE tenant_id = 'tenant_decision' RETURNING expires_at",
    )
    .bind(seconds)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn lock_artifact(pool: &PgPool) -> (Transaction<'_, Postgres>, i32) {
    let mut transaction = pool.begin().await.unwrap();
    // Pure row locking avoids an updated tuple triggering EvalPlanQual and
    // accidentally re-evaluating an otherwise stale clock predicate.
    let pid = sqlx::query_scalar(
        "SELECT pg_backend_pid() FROM xshield.artifact_catalog
         WHERE tenant_id = 'tenant_decision' FOR UPDATE",
    )
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    (transaction, pid)
}

async fn wait_until_blocked(pool: &PgPool, blocker_pid: i32) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker_pid).fetch_one(pool).await.unwrap();
            if blocked {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("operation reached the held row lock");
}

async fn wait_past_expiry(pool: &PgPool, expiry: DateTime<Utc>) {
    sqlx::query("SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM $1::timestamptz - clock_timestamp())) + 0.05)")
        .bind(expiry).execute(pool).await.unwrap();
}

async fn assert_self_approval_and_stale_target(store: &PostgresIdentityStore) {
    let self_approval = decision(
        "000000000985",
        "investigator-1",
        EvidenceAccessDecisionKind::Approved,
        "Self approval",
    );
    assert_eq!(
        apply(store, &self_approval, [4; 32], [5; 32], "000000000986",).await,
        EvidenceAccessDecisionWriteOutcome::SelfApprovalDenied
    );
    let stale = decision(
        "000000000985",
        "approver-2",
        EvidenceAccessDecisionKind::Approved,
        "Stale evidence",
    );
    assert_eq!(
        apply(store, &stale, [6; 32], [7; 32], "000000000987").await,
        EvidenceAccessDecisionWriteOutcome::TargetUnavailable
    );
}

async fn assert_denial_and_concurrent_terminal_decision(store: &PostgresIdentityStore) {
    let denied = decision(
        "000000000988",
        "approver-1",
        EvidenceAccessDecisionKind::Denied,
        "Insufficient justification",
    );
    let created = apply(store, &denied, [8; 32], [9; 32], "000000000989").await;
    let EvidenceAccessDecisionWriteOutcome::Created(record) = created else {
        panic!("denial must be created");
    };
    assert_eq!(record.status(), "denied");
    assert!(record.access_expires_at().is_none());

    let approve = decision(
        "000000000990",
        "approver-a",
        EvidenceAccessDecisionKind::Denied,
        "Concurrent first decision",
    );
    let deny = decision(
        "000000000990",
        "approver-b",
        EvidenceAccessDecisionKind::Denied,
        "Concurrent second decision",
    );
    let (first, second) = tokio::join!(
        apply(store, &approve, [10; 32], [11; 32], "000000000991"),
        apply(store, &deny, [12; 32], [13; 32], "000000000992"),
    );
    let outcomes = [first, second];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EvidenceAccessDecisionWriteOutcome::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EvidenceAccessDecisionWriteOutcome::Conflict))
            .count(),
        1
    );
}

async fn assert_outbox_collision_rolls_back(pool: &PgPool, store: &PostgresIdentityStore) {
    let draft = decision(
        "000000000993",
        "approver-3",
        EvidenceAccessDecisionKind::Denied,
        "Collision denial",
    );
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000994").unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000995").unwrap();
    let envelope = envelope(&draft, &request, &event, &[15; 32]);
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, 'tenant_decision', 'site_decision', 'collision', 'fixture', '{}')",
    )
    .bind(event.as_str())
    .execute(pool)
    .await
    .unwrap();
    assert!(
        store
            .decide_evidence_access(
                EvidenceAccessDecisionCreate::new(
                    &draft, &[14; 32], &[15; 32], &request, &event, &envelope,
                )
                .unwrap(),
            )
            .await
            .is_err()
    );
    let status: String = sqlx::query_scalar(
        "SELECT status FROM xshield.evidence_access_requests
         WHERE tenant_id = 'tenant_decision' AND access_request_id = $1",
    )
    .bind(draft.access_request_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(status, "pending");
}

async fn apply(
    store: &PostgresIdentityStore,
    draft: &EvidenceAccessDecisionDraft,
    idempotency_digest: [u8; 32],
    request_digest: [u8; 32],
    suffix: &str,
) -> EvidenceAccessDecisionWriteOutcome {
    try_apply(store, draft, idempotency_digest, request_digest, suffix)
        .await
        .unwrap()
}

async fn try_apply(
    store: &PostgresIdentityStore,
    draft: &EvidenceAccessDecisionDraft,
    idempotency_digest: [u8; 32],
    request_digest: [u8; 32],
    suffix: &str,
) -> Result<EvidenceAccessDecisionWriteOutcome, StoreError> {
    let request = RequestId::parse(format!("req_018f2a3b-4c5d-7000-8000-{suffix}")).unwrap();
    let event_suffix = suffix.parse::<u64>().unwrap() + 100;
    let event = EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{event_suffix:012}")).unwrap();
    let envelope = envelope(draft, &request, &event, &request_digest);
    store
        .decide_evidence_access(
            EvidenceAccessDecisionCreate::new(
                draft,
                &idempotency_digest,
                &request_digest,
                &request,
                &event,
                &envelope,
            )
            .unwrap(),
        )
        .await
}

fn decision(
    suffix: &str,
    decided_by: &str,
    kind: EvidenceAccessDecisionKind,
    reason: &str,
) -> EvidenceAccessDecisionDraft {
    let tenant = TenantId::parse("tenant_decision").unwrap();
    let site = SiteId::parse("site_decision").unwrap();
    let access =
        EvidenceAccessRequestId::parse(format!("access_018f2a3b-4c5d-7000-8000-{suffix}")).unwrap();
    match kind {
        EvidenceAccessDecisionKind::Approved => {
            EvidenceAccessDecisionDraft::approve(tenant, site, access, decided_by, reason, 600, 900)
                .unwrap()
        }
        EvidenceAccessDecisionKind::Denied => {
            EvidenceAccessDecisionDraft::deny(tenant, site, access, decided_by, reason).unwrap()
        }
    }
}

fn envelope(
    draft: &EvidenceAccessDecisionDraft,
    request: &RequestId,
    event: &EventId,
    request_digest: &[u8; 32],
) -> Value {
    json!({
        "schema_version": 3,
        "event_id": event.as_str(),
        "event_type": draft.kind().event_type(),
        "tenant_id": draft.tenant_id().as_str(),
        "site_id": draft.site_id().as_str(),
        "request_id": request.as_str(),
        "payload": {
            "access_request_id": draft.access_request_id().as_str(),
            "subject_ref": draft.decided_by(),
            "decision": draft.kind().as_str(),
            "ttl_seconds": draft.requested_ttl_seconds(),
            "stage": "evidence_access_decision",
            "request_digest": lower_hex(request_digest),
            "outcome": "PASS",
            "reason_code": draft.kind().reason_code()
        }
    })
}

async fn seed_targets(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
            tenant_id, site_id, case_id, owner_ref, purpose, status,
            idempotency_digest, request_digest, created_event_id
         ) VALUES (
            'tenant_decision', 'site_decision',
            'case_018f2a3b-4c5d-7000-8000-000000000980',
            'investigator-1', 'Decision test', 'open',
            decode(repeat('31', 32), 'hex'), decode(repeat('32', 32), 'hex'),
            'ev_018f2a3b-4c5d-7000-8000-000000000979'
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
            'tenant_decision', 'site_decision',
            'artifact_018f2a3b-4c5d-7000-8000-000000000978',
            'req_018f2a3b-4c5d-7000-8000-000000000977', 3, 'response_from_origin',
            'application/json', 'complete', 'entity_exact', 2, 2,
            'RESTRICTED', false, 'aead_envelope_v1',
            'artifact_018f2a3b-4c5d-7000-8000-000000000978.xev',
            'evidence-key-r1', 'sha256_ciphertext', repeat('b', 64), '{}',
            clock_timestamp(), clock_timestamp() + interval '2 minutes',
            'ev_018f2a3b-4c5d-7000-8000-000000000976', 'active', NULL
         )",
    )
    .execute(pool)
    .await
    .unwrap();
    for suffix in [
        "000000000981",
        "000000000985",
        "000000000988",
        "000000000990",
        "000000000993",
        "000000000998",
    ] {
        sqlx::query(
            "INSERT INTO xshield.evidence_access_requests (
                tenant_id, site_id, access_request_id, case_id, artifact_id,
                requested_by, access_kind, justification, status,
                idempotency_digest, request_digest, requested_event_id
             ) VALUES (
                'tenant_decision', 'site_decision', $1,
                'case_018f2a3b-4c5d-7000-8000-000000000980',
                'artifact_018f2a3b-4c5d-7000-8000-000000000978',
                'investigator-1', 'sensitive_raw', 'Test access', 'pending',
                decode(md5($1) || md5($1), 'hex'),
                decode(md5($1 || 'request') || md5($1 || 'request'), 'hex'),
                'ev_018f2a3b-4c5d-7000-8000-' || right($1, 12)
             )",
        )
        .bind(format!("access_018f2a3b-4c5d-7000-8000-{suffix}"))
        .execute(pool)
        .await
        .unwrap();
    }
}

async fn cleanup(pool: &PgPool) {
    sqlx::query("DELETE FROM xshield.evidence_access_requests WHERE tenant_id = 'tenant_decision'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.artifact_catalog WHERE tenant_id = 'tenant_decision'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.investigation_cases WHERE tenant_id = 'tenant_decision'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE tenant_id = 'tenant_decision'")
        .execute(pool)
        .await
        .unwrap();
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
