use serde_json::{Value, json};
use sqlx::PgPool;
use std::{env, time::Duration};
use xshield_core::{
    domain::{CaseId, EventId, RequestId, SiteId, TenantId},
    investigation::InvestigationCaseDraft,
};
use xshield_postgres::{
    InvestigationCaseCreate, InvestigationCaseWriteOutcome, PostgresIdentityStore,
};

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
async fn case_creation_is_atomic_idempotent_scoped_and_bounded() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 3, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let tenant = TenantId::parse("tenant_case").unwrap();
    let site = SiteId::parse("site_case").unwrap();
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000911").unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000912").unwrap();
    let draft = case_draft(&tenant, &site, "000000000913", "Review evidence anomaly");
    let envelope = case_envelope(&draft, &request, &event, &[2; 32]);

    assert_audit_collision_rolls_back(&pool, &store, &draft, &request, &event, &envelope).await;
    let created = store
        .create_investigation_case(
            InvestigationCaseCreate::new(
                &draft, &[1; 32], &[2; 32], &request, &event, &envelope, 1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let InvestigationCaseWriteOutcome::Created(created) = created else {
        panic!("case must be created");
    };
    assert_eq!(created.case_id(), draft.case_id());
    assert_eq!(created.status(), "open");

    assert_exact_retry_and_conflict(&store, &tenant, &site, &created).await;
    assert_capacity_is_scoped(&store, &tenant, &site).await;
    assert_concurrent_capacity(&store).await;
}

async fn assert_audit_collision_rolls_back(
    pool: &PgPool,
    store: &PostgresIdentityStore,
    draft: &InvestigationCaseDraft,
    request: &RequestId,
    event: &EventId,
    envelope: &Value,
) {
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, 'collision', 'fixture', '{}')",
    )
    .bind(event.as_str())
    .bind(draft.tenant_id().as_str())
    .bind(draft.site_id().as_str())
    .execute(pool)
    .await
    .unwrap();
    assert!(
        store
            .create_investigation_case(
                InvestigationCaseCreate::new(
                    draft, &[1; 32], &[2; 32], request, event, envelope, 1,
                )
                .unwrap(),
            )
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM xshield.investigation_cases")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(event.as_str())
        .execute(pool)
        .await
        .unwrap();
}

async fn assert_exact_retry_and_conflict(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
    created: &xshield_postgres::InvestigationCaseRecord,
) {
    let retry = case_draft(tenant, site, "000000000914", created.purpose());
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000915").unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000916").unwrap();
    let envelope = case_envelope(&retry, &request, &event, &[2; 32]);
    let outcome = store
        .create_investigation_case(
            InvestigationCaseCreate::new(
                &retry, &[1; 32], &[2; 32], &request, &event, &envelope, 1,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let InvestigationCaseWriteOutcome::Existing(existing) = outcome else {
        panic!("retry must return the existing case");
    };
    assert_eq!(existing.case_id(), created.case_id());

    let conflict = case_draft(tenant, site, "000000000917", "Different purpose");
    let envelope = case_envelope(&conflict, &request, &event, &[3; 32]);
    assert_eq!(
        store
            .create_investigation_case(
                InvestigationCaseCreate::new(
                    &conflict, &[1; 32], &[3; 32], &request, &event, &envelope, 1,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        InvestigationCaseWriteOutcome::Conflict
    );
}

async fn assert_capacity_is_scoped(
    store: &PostgresIdentityStore,
    tenant: &TenantId,
    site: &SiteId,
) {
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000918").unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000919").unwrap();
    let full = case_draft(tenant, site, "000000000920", "Second case");
    let envelope = case_envelope(&full, &request, &event, &[5; 32]);
    assert_eq!(
        store
            .create_investigation_case(
                InvestigationCaseCreate::new(
                    &full, &[4; 32], &[5; 32], &request, &event, &envelope, 1,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        InvestigationCaseWriteOutcome::CapacityExceeded
    );

    let other_site = SiteId::parse("site_case_other").unwrap();
    let scoped = case_draft(tenant, &other_site, "000000000921", "Scoped case");
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000922").unwrap();
    let envelope = case_envelope(&scoped, &request, &event, &[5; 32]);
    assert!(matches!(
        store
            .create_investigation_case(
                InvestigationCaseCreate::new(
                    &scoped, &[4; 32], &[5; 32], &request, &event, &envelope, 1,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
        InvestigationCaseWriteOutcome::Created(_)
    ));
}

async fn assert_concurrent_capacity(store: &PostgresIdentityStore) {
    let tenant = TenantId::parse("tenant_case_concurrent").unwrap();
    let site = SiteId::parse("site_case_concurrent").unwrap();
    let first = case_draft(&tenant, &site, "000000000923", "Concurrent first");
    let second = case_draft(&tenant, &site, "000000000924", "Concurrent second");
    let first_request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000925").unwrap();
    let second_request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000926").unwrap();
    let first_event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000927").unwrap();
    let second_event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000928").unwrap();
    let first_envelope = case_envelope(&first, &first_request, &first_event, &[7; 32]);
    let second_envelope = case_envelope(&second, &second_request, &second_event, &[9; 32]);
    let first_command = InvestigationCaseCreate::new(
        &first,
        &[6; 32],
        &[7; 32],
        &first_request,
        &first_event,
        &first_envelope,
        1,
    )
    .unwrap();
    let second_command = InvestigationCaseCreate::new(
        &second,
        &[8; 32],
        &[9; 32],
        &second_request,
        &second_event,
        &second_envelope,
        1,
    )
    .unwrap();
    let (first_outcome, second_outcome) = tokio::join!(
        store.create_investigation_case(first_command),
        store.create_investigation_case(second_command),
    );
    let outcomes = [first_outcome.unwrap(), second_outcome.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, InvestigationCaseWriteOutcome::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, InvestigationCaseWriteOutcome::CapacityExceeded))
            .count(),
        1
    );
}

fn case_draft(
    tenant: &TenantId,
    site: &SiteId,
    suffix: &str,
    purpose: &str,
) -> InvestigationCaseDraft {
    InvestigationCaseDraft::new(
        CaseId::parse(format!("case_018f2a3b-4c5d-7000-8000-{suffix}")).unwrap(),
        tenant.clone(),
        site.clone(),
        "investigator-1",
        purpose,
    )
    .unwrap()
}

fn case_envelope(
    draft: &InvestigationCaseDraft,
    request: &RequestId,
    event: &EventId,
    request_digest: &[u8; 32],
) -> Value {
    json!({
        "schema_version": 3,
        "event_id": event.as_str(),
        "event_type": "case.created",
        "tenant_id": draft.tenant_id().as_str(),
        "site_id": draft.site_id().as_str(),
        "request_id": request.as_str(),
        "evidence_refs": [],
        "payload": {
            "case_id": draft.case_id().as_str(),
            "subject_ref": draft.owner_ref(),
            "stage": "case_management",
            "request_digest": lower_hex(request_digest),
            "outcome": "PASS",
            "reason_code": "CASE_CREATED"
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
