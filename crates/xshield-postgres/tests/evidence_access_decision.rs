use serde_json::{Value, json};
use sqlx::PgPool;
use std::{env, time::Duration};
use xshield_core::{
    domain::{EventId, EvidenceAccessRequestId, RequestId, SiteId, TenantId},
    investigation::{EvidenceAccessDecisionDraft, EvidenceAccessDecisionKind},
};
use xshield_postgres::{
    EvidenceAccessDecisionCreate, EvidenceAccessDecisionWriteOutcome, PostgresIdentityStore,
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

    sqlx::query(
        "UPDATE xshield.artifact_catalog
         SET status = 'deleted', deleted_at = clock_timestamp()
         WHERE tenant_id = 'tenant_decision'",
    )
    .execute(&pool)
    .await
    .unwrap();
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
        .unwrap()
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
