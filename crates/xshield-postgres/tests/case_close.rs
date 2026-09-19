//! `PostgreSQL` case lifecycle regressions using isolated synthetic scopes.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::{
    domain::{ArtifactId, CaseId, EventId, EvidenceAccessRequestId, RequestId, SiteId, TenantId},
    investigation::{
        CaseEvidenceDraft, EvidenceAccessDecisionDraft, EvidenceAccessKind,
        EvidenceAccessRequestDraft, InvestigationCaseCloseDraft,
    },
};
use xshield_postgres::{
    CaseEvidenceAdd, CaseEvidenceQuery, CaseEvidenceWriteOutcome, EvidenceAccessDecisionCreate,
    EvidenceAccessDecisionWriteOutcome, EvidenceAccessRequestCreate,
    EvidenceAccessRequestWriteOutcome, InvestigationCaseClose, InvestigationCaseCloseWriteOutcome,
    PostgresIdentityStore, StoreError,
};

struct CloseRequest {
    draft: InvestigationCaseCloseDraft,
    key: [u8; 32],
    digest: [u8; 32],
    request: RequestId,
    event: EventId,
    envelope: Value,
}

impl CloseRequest {
    fn new(draft: InvestigationCaseCloseDraft, key: u8, digest: u8) -> Self {
        let (request, event, envelope) = audit_event(
            &draft,
            "case.closed",
            &[],
            json!({
                "stage": "case_management", "case_id": draft.case_id().as_str(),
                "subject_ref": draft.owner_ref(),
                "request_digest": format!("{digest:02x}").repeat(32),
                "outcome": "PASS", "reason_code": "CASE_CLOSED"
            }),
        );
        Self {
            draft,
            key: [key; 32],
            digest: [digest; 32],
            request,
            event,
            envelope,
        }
    }

    fn command(&self) -> InvestigationCaseClose<'_> {
        InvestigationCaseClose::new(
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
fn closure_command_binds_every_audit_target() {
    let draft = InvestigationCaseCloseDraft::new(
        TenantId::parse("tenant_close_contract").unwrap(),
        SiteId::parse("site_close_contract").unwrap(),
        CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap(),
        "investigator",
        "Review completed",
    )
    .unwrap();
    let request = CloseRequest::new(draft, 1, 2);
    request.command();
    for pointer in [
        "/schema_version",
        "/event_id",
        "/event_type",
        "/tenant_id",
        "/site_id",
        "/request_id",
        "/evidence_refs",
        "/payload/case_id",
        "/payload/subject_ref",
        "/payload/stage",
        "/payload/request_digest",
        "/payload/outcome",
        "/payload/reason_code",
        "/payload/proof_kind",
        "/payload/confidence_status",
    ] {
        let mut envelope = request.envelope.clone();
        *envelope.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(
            InvestigationCaseClose::new(
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
    let mut envelope = request.envelope.clone();
    envelope["payload"]["confidence"] = json!(1.0);
    assert!(
        InvestigationCaseClose::new(
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

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn case_closure_is_atomic_idempotent_scoped_and_concurrent() {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&url, 4, Duration::from_secs(5))
        .await
        .unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    let tenant = TenantId::parse(format!("tenant_close_{}", Uuid::now_v7().simple())).unwrap();
    let site = SiteId::parse("site_close").unwrap();
    let foreign_tenant = TenantId::parse(format!("{}_foreign", tenant.as_str())).unwrap();

    assert_exact_retries_and_conflicts(&pool, &store, &tenant, &site).await;
    assert_unavailable_targets(&pool, &store, &tenant, &site, &foreign_tenant).await;
    assert_retry_rechecks_current_case(&pool, &store, &tenant, &site).await;
    assert_concurrent_closure(&pool, &store, &tenant, &site).await;
    assert_outbox_failure_rolls_back(&pool, &store, &tenant, &site).await;
    assert_closed_case_evidence_boundaries(&pool, &store, &tenant, &site).await;
    assert_denial_releases_closed_case_pending_capacity(&pool, &store, &tenant, &site).await;

    for statement in [
        "DELETE FROM xshield.case_closures WHERE tenant_id IN ($1, $2)",
        "DELETE FROM xshield.case_items WHERE tenant_id IN ($1, $2)",
        "DELETE FROM xshield.evidence_access_requests WHERE tenant_id IN ($1, $2)",
        "DELETE FROM xshield.artifact_catalog WHERE tenant_id IN ($1, $2)",
        "DELETE FROM xshield.investigation_cases WHERE tenant_id IN ($1, $2)",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id IN ($1, $2)",
    ] {
        sqlx::query(statement)
            .bind(tenant.as_str())
            .bind(foreign_tenant.as_str())
            .execute(&pool)
            .await
            .unwrap();
    }
}

async fn assert_exact_retries_and_conflicts(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let draft = seed_case(pool, tenant, site, "owner-retry").await;
    let other = seed_case(pool, tenant, site, draft.owner_ref()).await;
    let request = CloseRequest::new(draft.clone(), 1, 2);
    let InvestigationCaseCloseWriteOutcome::Closed(record) = store
        .close_investigation_case(request.command())
        .await
        .unwrap()
    else {
        panic!("first closure must commit");
    };
    assert_eq!(record.case_id(), draft.case_id());
    let stored: (DateTime<Utc>, String, Value) = sqlx::query_as(
        "SELECT closure.closed_at, closure.reason, outbox.envelope
         FROM xshield.case_closures closure
         JOIN xshield.audit_outbox outbox ON outbox.event_id = closure.closed_event_id
         WHERE closure.tenant_id = $1 AND closure.site_id = $2 AND closure.case_id = $3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(draft.case_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        (
            record.closed_at(),
            draft.reason().to_owned(),
            request.envelope
        )
    );
    let retry = CloseRequest::new(draft.clone(), 1, 2);
    assert_eq!(
        store
            .close_investigation_case(retry.command())
            .await
            .unwrap(),
        InvestigationCaseCloseWriteOutcome::Existing(record)
    );
    let changed_reason = InvestigationCaseCloseDraft::new(
        tenant.clone(),
        site.clone(),
        draft.case_id().clone(),
        draft.owner_ref(),
        "Review superseded",
    )
    .unwrap();
    for conflict in [
        CloseRequest::new(draft.clone(), 1, 3),
        CloseRequest::new(changed_reason, 1, 2),
        CloseRequest::new(other.clone(), 1, 2),
    ] {
        assert_eq!(
            store
                .close_investigation_case(conflict.command())
                .await
                .unwrap(),
            InvestigationCaseCloseWriteOutcome::Conflict
        );
    }
    let other_key = CloseRequest::new(draft.clone(), 3, 2);
    assert_eq!(
        store
            .close_investigation_case(other_key.command())
            .await
            .unwrap(),
        InvestigationCaseCloseWriteOutcome::TargetUnavailable
    );
    assert_eq!(case_state(pool, &draft).await, ("closed".to_owned(), 1, 1));
    assert_eq!(case_state(pool, &other).await, ("open".to_owned(), 0, 0));
}

async fn assert_unavailable_targets(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    foreign_tenant: &TenantId,
) {
    let own = seed_case(pool, tenant, site, "owner-scope").await;
    let other_tenant = seed_case(pool, foreign_tenant, site, own.owner_ref()).await;
    let foreign_site = SiteId::parse("site_close_foreign").unwrap();
    let other_site = seed_case(pool, tenant, &foreign_site, own.owner_ref()).await;
    let missing = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    for (case, owner) in [
        (own.case_id(), "different-owner"),
        (other_tenant.case_id(), own.owner_ref()),
        (other_site.case_id(), own.owner_ref()),
        (&missing, own.owner_ref()),
    ] {
        let draft = InvestigationCaseCloseDraft::new(
            tenant.clone(),
            site.clone(),
            case.clone(),
            owner,
            own.reason(),
        )
        .unwrap();
        let request = CloseRequest::new(draft, 1, 2);
        assert_eq!(
            store
                .close_investigation_case(request.command())
                .await
                .unwrap(),
            InvestigationCaseCloseWriteOutcome::TargetUnavailable
        );
    }
    for draft in [&own, &other_tenant, &other_site] {
        assert_eq!(case_state(pool, draft).await, ("open".to_owned(), 0, 0));
    }
}

async fn assert_retry_rechecks_current_case(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let draft = seed_case(pool, tenant, site, "owner-current").await;
    let request = CloseRequest::new(draft.clone(), 1, 2);
    assert!(matches!(
        store
            .close_investigation_case(request.command())
            .await
            .unwrap(),
        InvestigationCaseCloseWriteOutcome::Closed(_)
    ));
    sqlx::query(
        "UPDATE xshield.investigation_cases SET owner_ref = 'new-owner' WHERE case_id = $1",
    )
    .bind(draft.case_id().as_str())
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        store
            .close_investigation_case(request.command())
            .await
            .unwrap(),
        InvestigationCaseCloseWriteOutcome::TargetUnavailable
    );
    sqlx::query(
        "UPDATE xshield.investigation_cases SET owner_ref = $2, status = 'open' WHERE case_id = $1",
    )
    .bind(draft.case_id().as_str())
    .bind(draft.owner_ref())
    .execute(pool)
    .await
    .unwrap();
    assert!(matches!(
        store.close_investigation_case(request.command()).await,
        Err(StoreError::CorruptData("case_closure_status"))
    ));
    sqlx::query("UPDATE xshield.investigation_cases SET status = 'closed' WHERE case_id = $1")
        .bind(draft.case_id().as_str())
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(case_state(pool, &draft).await, ("closed".to_owned(), 1, 1));
}

async fn assert_concurrent_closure(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let draft = seed_case(pool, tenant, site, "owner-concurrent").await;
    let first = CloseRequest::new(draft.clone(), 1, 2);
    let second = CloseRequest::new(draft.clone(), 1, 2);
    let (a, b) = tokio::join!(
        store.close_investigation_case(first.command()),
        store.close_investigation_case(second.command())
    );
    match (a.unwrap(), b.unwrap()) {
        (
            InvestigationCaseCloseWriteOutcome::Closed(a),
            InvestigationCaseCloseWriteOutcome::Existing(b),
        )
        | (
            InvestigationCaseCloseWriteOutcome::Existing(a),
            InvestigationCaseCloseWriteOutcome::Closed(b),
        ) => assert_eq!(a, b),
        outcomes => panic!("exact concurrent closures must commit once: {outcomes:?}"),
    }
    assert_eq!(case_state(pool, &draft).await, ("closed".to_owned(), 1, 1));
}

async fn assert_outbox_failure_rolls_back(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let draft = seed_case(pool, tenant, site, "owner-outbox").await;
    let request = CloseRequest::new(draft.clone(), 1, 2);
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1, $2, $3, 'collision', 'fixture', $4)",
    )
    .bind(request.event.as_str())
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(&request.envelope)
    .execute(pool)
    .await
    .unwrap();
    assert!(
        store
            .close_investigation_case(request.command())
            .await
            .is_err()
    );
    assert_eq!(case_state(pool, &draft).await, ("open".to_owned(), 0, 0));
    let retry = CloseRequest::new(draft.clone(), 1, 2);
    assert!(matches!(
        store
            .close_investigation_case(retry.command())
            .await
            .unwrap(),
        InvestigationCaseCloseWriteOutcome::Closed(_)
    ));
    assert_eq!(case_state(pool, &draft).await, ("closed".to_owned(), 1, 1));
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(retry.event.as_str())
        .execute(pool)
        .await
        .unwrap();
    assert!(matches!(
        store.close_investigation_case(retry.command()).await,
        Err(StoreError::CorruptData("case_closure_outbox"))
    ));
}

async fn assert_closed_case_evidence_boundaries(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let draft = seed_case(pool, tenant, site, "owner-evidence").await;
    let (artifact, access) = seed_approved_evidence(pool, &draft).await;
    let capability = store
        .find_evidence_access_capability(tenant, site, &access, &artifact, draft.owner_ref())
        .await
        .unwrap()
        .expect("approved capability is live before closure");
    let add = CaseEvidenceDraft::new(
        tenant.clone(),
        site.clone(),
        draft.case_id().clone(),
        artifact.clone(),
        draft.owner_ref(),
    )
    .unwrap();
    let (request, event, envelope) = audit_event(
        &draft,
        "case.evidence.added",
        &[artifact.as_str()],
        json!({
            "stage": "case_management", "case_id": draft.case_id().as_str(),
            "artifact_id": artifact.as_str(), "subject_ref": draft.owner_ref(),
            "request_digest": "02".repeat(32), "outcome": "PASS",
            "reason_code": "CASE_EVIDENCE_ADDED"
        }),
    );
    let command =
        || CaseEvidenceAdd::new(&add, &[1; 32], &[2; 32], &request, &event, &envelope).unwrap();
    assert!(matches!(
        store.add_case_evidence(command()).await.unwrap(),
        CaseEvidenceWriteOutcome::Added(_)
    ));
    let close = CloseRequest::new(draft.clone(), 1, 2);
    assert!(matches!(
        store
            .close_investigation_case(close.command())
            .await
            .unwrap(),
        InvestigationCaseCloseWriteOutcome::Closed(_)
    ));
    assert_eq!(
        store.add_case_evidence(command()).await.unwrap(),
        CaseEvidenceWriteOutcome::TargetUnavailable
    );
    assert!(
        store
            .find_evidence_access_capability(tenant, site, &access, &artifact, draft.owner_ref())
            .await
            .unwrap()
            .is_none()
    );
    let query =
        CaseEvidenceQuery::new(tenant, site, draft.case_id(), draft.owner_ref(), None, 1).unwrap();
    let page = store.list_case_evidence(query).await.unwrap().unwrap();
    assert_eq!(page.case_status(), "closed");
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].record().artifact_id(), &artifact);
    let history: (String, DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "SELECT access.status, access.access_expires_at, artifact.expires_at
         FROM xshield.evidence_access_requests access
         JOIN xshield.artifact_catalog artifact USING (tenant_id, site_id, artifact_id)
         WHERE access.access_request_id = $1",
    )
    .bind(access.as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(history.0, "approved");
    assert_eq!(history.1, capability.access_expires_at());
    assert_eq!(
        history
            .2
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        capability.artifact().manifest().expires_at
    );
}

async fn seed_case(
    pool: &PgPool,
    tenant: &TenantId,
    site: &SiteId,
    owner: &str,
) -> InvestigationCaseCloseDraft {
    let case = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    sqlx::query(
        "INSERT INTO xshield.investigation_cases (
             tenant_id, site_id, case_id, owner_ref, purpose, status,
             idempotency_digest, request_digest, created_event_id
         ) VALUES ($1, $2, $3, $4, 'Review synthetic evidence', 'open', $5, $5, $6)",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(case.as_str())
    .bind(owner)
    .bind(Uuid::now_v7().as_bytes().repeat(2))
    .bind(format!("ev_{}", Uuid::now_v7()))
    .execute(pool)
    .await
    .unwrap();
    InvestigationCaseCloseDraft::new(
        tenant.clone(),
        site.clone(),
        case,
        owner,
        "Review completed",
    )
    .unwrap()
}

async fn assert_denial_releases_closed_case_pending_capacity(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let case = seed_case(pool, tenant, site, "owner-pending-capacity").await;
    let next_case = seed_case(pool, tenant, site, case.owner_ref()).await;
    let artifact = seed_artifact(pool, &case).await;
    let EvidenceAccessRequestWriteOutcome::Created(pending) =
        create_pending_access(store, &case, &artifact, 1).await
    else {
        panic!("first access request must occupy the pending slot");
    };
    assert_eq!(pending.status(), "pending");
    let close = CloseRequest::new(case.clone(), 1, 2);
    assert!(matches!(
        store
            .close_investigation_case(close.command())
            .await
            .unwrap(),
        InvestigationCaseCloseWriteOutcome::Closed(_)
    ));
    assert_eq!(
        create_pending_access(store, &next_case, &artifact, 2).await,
        EvidenceAccessRequestWriteOutcome::CapacityExceeded
    );

    let approval = EvidenceAccessDecisionDraft::approve(
        tenant.clone(),
        site.clone(),
        pending.access_request_id().clone(),
        "capacity-approver",
        "Review evidence",
        600,
        600,
    )
    .unwrap();
    assert_eq!(
        decide_pending_access(store, &case, &approval, 3).await,
        EvidenceAccessDecisionWriteOutcome::TargetUnavailable
    );
    let decision = EvidenceAccessDecisionDraft::deny(
        tenant.clone(),
        site.clone(),
        pending.access_request_id().clone(),
        "capacity-approver",
        "Case review completed",
    )
    .unwrap();
    let EvidenceAccessDecisionWriteOutcome::Created(denied) =
        decide_pending_access(store, &case, &decision, 4).await
    else {
        panic!("independent denial must terminate the closed case request");
    };
    assert_eq!(denied.status(), "denied");
    assert!(denied.access_expires_at().is_none());
    let EvidenceAccessRequestWriteOutcome::Created(next) =
        create_pending_access(store, &next_case, &artifact, 2).await
    else {
        panic!("denial must release the pending slot");
    };
    assert_eq!(next.status(), "pending");
    assert_ne!(next.access_request_id(), pending.access_request_id());
    let history: (String, String, String, DateTime<Utc>) = sqlx::query_as(
        "SELECT status, case_id, decided_by, requested_at
         FROM xshield.evidence_access_requests
         WHERE tenant_id = $1 AND site_id = $2 AND access_request_id = $3",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(pending.access_request_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        history,
        (
            "denied".to_owned(),
            case.case_id().as_str().to_owned(),
            decision.decided_by().to_owned(),
            pending.requested_at(),
        )
    );
    assert_eq!(case_state(pool, &case).await, ("closed".to_owned(), 1, 1));
    assert_eq!(
        case_state(pool, &next_case).await,
        ("open".to_owned(), 0, 0)
    );
}

async fn create_pending_access(
    store: &PostgresIdentityStore,
    case: &InvestigationCaseCloseDraft,
    artifact: &ArtifactId,
    key: u8,
) -> EvidenceAccessRequestWriteOutcome {
    let draft = EvidenceAccessRequestDraft::new(
        EvidenceAccessRequestId::parse(format!("access_{}", Uuid::now_v7())).unwrap(),
        case.tenant_id().clone(),
        case.site_id().clone(),
        case.case_id().clone(),
        artifact.clone(),
        case.owner_ref(),
        EvidenceAccessKind::SensitiveRaw,
        "Review evidence",
    )
    .unwrap();
    let (request, event, envelope) = audit_event(
        case,
        "evidence.access.requested",
        &[artifact.as_str()],
        json!({
            "stage": "evidence_access", "access_request_id": draft.access_request_id().as_str(),
            "case_id": case.case_id().as_str(), "artifact_id": artifact.as_str(),
            "subject_ref": case.owner_ref(), "access_kind": "sensitive_raw",
            "request_digest": format!("{key:02x}").repeat(32), "outcome": "PASS",
            "reason_code": "EVIDENCE_ACCESS_REQUESTED"
        }),
    );
    store
        .create_evidence_access_request(
            EvidenceAccessRequestCreate::new(
                &draft, &[key; 32], &[key; 32], &request, &event, &envelope, 1,
            )
            .unwrap(),
        )
        .await
        .unwrap()
}

async fn decide_pending_access(
    store: &PostgresIdentityStore,
    case: &InvestigationCaseCloseDraft,
    decision: &EvidenceAccessDecisionDraft,
    key: u8,
) -> EvidenceAccessDecisionWriteOutcome {
    let (request, event, envelope) = audit_event(
        case,
        decision.kind().event_type(),
        &[],
        json!({
            "stage": "evidence_access_decision",
            "access_request_id": decision.access_request_id().as_str(),
            "subject_ref": decision.decided_by(), "decision": decision.kind().as_str(),
            "ttl_seconds": decision.requested_ttl_seconds(),
            "request_digest": format!("{key:02x}").repeat(32), "outcome": "PASS",
            "reason_code": decision.kind().reason_code()
        }),
    );
    store
        .decide_evidence_access(
            EvidenceAccessDecisionCreate::new(
                decision, &[key; 32], &[key; 32], &request, &event, &envelope,
            )
            .unwrap(),
        )
        .await
        .unwrap()
}

async fn case_state(pool: &PgPool, draft: &InvestigationCaseCloseDraft) -> (String, i64, i64) {
    sqlx::query_as(
        "SELECT status,
             (SELECT count(*) FROM xshield.case_closures
              WHERE tenant_id = $1 AND site_id = $2 AND case_id = $3),
             (SELECT count(*) FROM xshield.audit_outbox
              WHERE tenant_id = $1 AND site_id = $2 AND aggregate_ref = $3
                AND event_type = 'case.closed')
         FROM xshield.investigation_cases
         WHERE tenant_id = $1 AND site_id = $2 AND case_id = $3",
    )
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(draft.case_id().as_str())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn seed_artifact(pool: &PgPool, draft: &InvestigationCaseCloseDraft) -> ArtifactId {
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
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(artifact.as_str())
    .bind(format!("req_{}", Uuid::now_v7()))
    .bind(format!("ev_{}", Uuid::now_v7()))
    .execute(pool)
    .await
    .unwrap();
    artifact
}

async fn seed_approved_evidence(
    pool: &PgPool,
    draft: &InvestigationCaseCloseDraft,
) -> (ArtifactId, EvidenceAccessRequestId) {
    let artifact = seed_artifact(pool, draft).await;
    let access = EvidenceAccessRequestId::parse(format!("access_{}", Uuid::now_v7())).unwrap();
    sqlx::query(
        "INSERT INTO xshield.evidence_access_requests (
             tenant_id, site_id, access_request_id, case_id, artifact_id, requested_by,
             access_kind, justification, status, idempotency_digest, request_digest,
             requested_event_id, decided_by, decision_reason, decision_ttl_seconds,
             decision_idempotency_digest, decision_request_digest, decision_event_id,
             decided_at, access_expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6, 'sensitive_raw', 'Review evidence', 'approved',
             $7, $7, $8, 'independent-approver', 'Approved review', 600, $7, $7, $9,
             clock_timestamp(), clock_timestamp() + interval '10 minutes')",
    )
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .bind(access.as_str())
    .bind(draft.case_id().as_str())
    .bind(artifact.as_str())
    .bind(draft.owner_ref())
    .bind([1_u8; 32].as_slice())
    .bind(format!("ev_{}", Uuid::now_v7()))
    .bind(format!("ev_{}", Uuid::now_v7()))
    .execute(pool)
    .await
    .unwrap();
    (artifact, access)
}

fn audit_event(
    draft: &InvestigationCaseCloseDraft,
    event_type: &str,
    evidence_refs: &[&str],
    mut payload: Value,
) -> (RequestId, EventId, Value) {
    let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
    let event = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
    let trace = Uuid::now_v7().simple().to_string();
    let now = Utc::now().to_rfc3339();
    payload["proof_kind"] = json!("deterministic");
    payload["confidence"] = Value::Null;
    payload["confidence_status"] = json!("not_applicable");
    let envelope = json!({
        "schema_version": 3, "event_id": event.as_str(), "event_type": event_type,
        "tenant_id": draft.tenant_id().as_str(), "site_id": draft.site_id().as_str(),
        "request_id": request.as_str(), "trace_id": trace, "span_id": &trace[..16],
        "producer_id": "case-close-tests", "producer_boot_id": request.as_str(),
        "producer_seq": 1, "request_seq": 1, "occurred_at": now, "observed_at": now,
        "policy_revision": "control-v1", "example_only": true,
        "evidence_refs": evidence_refs, "cause_event_ids": [], "payload": payload,
        "sensitivity": "SYNTHETIC", "integrity": {"state": "fixture_unsealed"}
    });
    (request, event, envelope)
}
