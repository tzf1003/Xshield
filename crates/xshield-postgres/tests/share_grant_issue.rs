use serde_json::json;
use sqlx::PgPool;
use std::{collections::BTreeMap, env, time::Duration};
use xshield_core::{
    access::{ShareGrantDraft, ShareIssueAuthority, ShareTokenFingerprint},
    domain::{
        AuthBindingId, EventId, GrantId, IssuanceKey, OperationId, PolicyRevision, ResourceType,
        ShareGrantId, ShareIssuanceRuleId, SiteId, TenantId, ViewProfile, WafSessionId,
    },
    grant::ResourceKeyHmac,
    identity::{
        AuthBinding, AuthEpoch, AuthSnapshot, CredentialFingerprint, CredentialGeneration,
        CredentialSlot, UnixSeconds,
    },
};
use xshield_postgres::{
    PostgresIdentityStore, ShareGrantPersistence, ShareGrantWriteOutcome, StoreError,
};

const NOW: u64 = 1_800_000_000;
const SESSION_EXPIRES: u64 = NOW + 2_000;
const SOURCE_EXPIRES: u64 = NOW + 1_000;

struct Fixture {
    tenant: TenantId,
    site: SiteId,
    binding_id: AuthBindingId,
    snapshot: AuthSnapshot,
    authority: ShareIssueAuthority,
}

fn fixture() -> Fixture {
    let tenant = TenantId::parse("tenant_share_issue").unwrap();
    let site = SiteId::parse("site_share_issue").unwrap();
    let binding_id = AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000a01").unwrap();
    let session_id = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000a02").unwrap();
    let credentials = BTreeMap::from([(
        CredentialSlot::Cookie,
        CredentialFingerprint::from_bytes([61; 32]),
    )]);
    let binding = AuthBinding::new(
        binding_id.clone(),
        session_id.clone(),
        tenant.clone(),
        site.clone(),
        "principal_share_issue",
        AuthEpoch::new(4),
        CredentialGeneration::new(1),
        credentials.clone(),
        UnixSeconds::new(SESSION_EXPIRES),
    )
    .unwrap();
    let snapshot = binding
        .verify(
            &tenant,
            &site,
            &session_id,
            &credentials,
            UnixSeconds::new(NOW),
        )
        .unwrap();
    Fixture {
        tenant,
        site,
        binding_id,
        snapshot,
        authority: ShareIssueAuthority {
            resource_grant_id: GrantId::parse("grant_018f2a3b-4c5d-7000-8000-000000000a05")
                .unwrap(),
            rule_id: ShareIssuanceRuleId::parse("record-summary-share-r1").unwrap(),
            operation_id: OperationId::parse("records.share.issue").unwrap(),
            view_profile: ViewProfile::parse("share_controls").unwrap(),
        },
    }
}

fn draft(value: u64, issuance_key: &str, token: u8, resource: u8) -> ShareGrantDraft {
    ShareGrantDraft {
        share_id: ShareGrantId::parse(format!("share_018f2a3b-4c5d-7000-8000-{value:012x}"))
            .unwrap(),
        issuance_key: IssuanceKey::parse(issuance_key).unwrap(),
        token_fingerprint: ShareTokenFingerprint::from_bytes([token; 32]),
        resource_type: ResourceType::parse("record").unwrap(),
        resource_key: ResourceKeyHmac::from_bytes([resource; 32]),
        operation_id: OperationId::parse("records.share.read").unwrap(),
        view_profile: ViewProfile::parse("shared_summary").unwrap(),
        policy_revision: PolicyRevision::parse("policy-share-r1").unwrap(),
        expires_at: UnixSeconds::new(NOW + 300),
    }
}

fn event_id(value: u64) -> EventId {
    EventId::parse(format!("ev_018f2a3b-4c5d-7000-8000-{value:012x}")).unwrap()
}

async fn issue(
    store: &PostgresIdentityStore,
    fixture: &Fixture,
    draft: &ShareGrantDraft,
    event_id: &EventId,
    capacity: u32,
) -> Result<ShareGrantWriteOutcome, StoreError> {
    let envelope = json!({"schema_version": 3, "event_type": "share.issued"});
    store
        .issue_share_grant(ShareGrantPersistence::new(
            &fixture.snapshot,
            draft,
            &fixture.authority,
            event_id,
            &envelope,
            UnixSeconds::new(NOW),
            capacity,
        )?)
        .await
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn share_issue_is_qualified_atomic_idempotent_and_bounded() {
    let database_url =
        env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let store = PostgresIdentityStore::connect(&database_url, 4, Duration::from_secs(5))
        .await
        .expect("test database connects");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("assertion pool connects");
    let fixture = fixture();
    seed(&pool, &fixture).await;

    let rollback_event = event_id(0xa10);
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, 'fixture', 'fixture', '{}')",
    )
    .bind(rollback_event.as_str())
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        issue(
            &store,
            &fixture,
            &draft(0xa11, "share-rollback", 62, 63),
            &rollback_event,
            1,
        )
        .await,
        Err(StoreError::Database(_))
    ));
    assert_eq!(share_count(&pool).await, 0);

    assert_eq!(
        issue(
            &store,
            &fixture,
            &draft(0xa12, "share-unknown-resource", 64, 99),
            &event_id(0xa13),
            1,
        )
        .await
        .unwrap(),
        ShareGrantWriteOutcome::Ineligible
    );

    let mut excessive_lease = draft(0xa21, "share-excessive-lease", 71, 63);
    excessive_lease.expires_at = UnixSeconds::new(NOW + 601);
    assert_eq!(
        issue(&store, &fixture, &excessive_lease, &event_id(0xa22), 1,)
            .await
            .unwrap(),
        ShareGrantWriteOutcome::Ineligible
    );

    let first = draft(0xa14, "share-first", 65, 63);
    let first_event = event_id(0xa15);
    assert_eq!(
        issue(&store, &fixture, &first, &first_event, 1)
            .await
            .unwrap(),
        ShareGrantWriteOutcome::Created(first.share_id.clone())
    );
    assert_eq!(
        issue(&store, &fixture, &first, &first_event, 1)
            .await
            .unwrap(),
        ShareGrantWriteOutcome::Existing(first.share_id.clone())
    );
    assert_eq!(outbox_count(&pool, first_event.as_str()).await, 1);

    assert_eq!(
        issue(
            &store,
            &fixture,
            &draft(0xa16, "share-first", 66, 63),
            &first_event,
            1,
        )
        .await
        .unwrap(),
        ShareGrantWriteOutcome::Conflict
    );
    sqlx::query("DELETE FROM xshield.share_grants")
        .execute(&pool)
        .await
        .unwrap();
    let left = draft(0xa17, "share-capacity-left", 67, 63);
    let right = draft(0xa18, "share-capacity-right", 68, 63);
    let left_event = event_id(0xa19);
    let right_event = event_id(0xa20);
    let (left_outcome, right_outcome) = tokio::join!(
        issue(&store, &fixture, &left, &left_event, 1),
        issue(&store, &fixture, &right, &right_event, 1),
    );
    let outcomes = [left_outcome.unwrap(), right_outcome.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ShareGrantWriteOutcome::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ShareGrantWriteOutcome::CapacityExceeded))
            .count(),
        1
    );

    sqlx::query(
        "UPDATE xshield.resource_grants SET status = 'revoked'
         WHERE tenant_id = $1 AND site_id = $2 AND grant_id = $3",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.authority.resource_grant_id.as_str())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        issue(
            &store,
            &fixture,
            &draft(0xa23, "share-revoked-source", 72, 63),
            &event_id(0xa24),
            2,
        )
        .await
        .unwrap(),
        ShareGrantWriteOutcome::Ineligible
    );
}

async fn share_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM xshield.share_grants")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn outbox_count(pool: &PgPool, event_id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM xshield.audit_outbox WHERE event_id = $1")
        .bind(event_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[allow(clippy::too_many_lines)]
async fn seed(pool: &PgPool, fixture: &Fixture) {
    sqlx::query(
        "INSERT INTO xshield.policy_revisions (
            tenant_id, site_id, revision, status, content_digest, artifact_ref
         ) VALUES ($1, $2, 'policy-share-r1', 'active', $3, 'artifact_share_policy_r1')",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind("d".repeat(64))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.auth_bindings (
            tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
            auth_epoch, credential_generation, status, absolute_expires_at
         ) VALUES ($1, $2, $3, $4, 'principal_share_issue', 4, 1, 'active', to_timestamp($5))",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .bind([69_u8; 32].as_slice())
    .bind(i64::try_from(SESSION_EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.page_evidence (
            tenant_id, site_id, page_evidence_id, binding_id, auth_epoch,
            source_request_id, response_artifact_ref, page_template, build_fingerprint,
            policy_revision, mapping_revision, status, verified_at, expires_at
         ) VALUES ($1, $2, $3, $4, 4, $5, 'artifact_share_page', 'record_page', $6,
                   'policy-share-r1', 'mapping-r1', 'verified', to_timestamp($7), to_timestamp($8))",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind("page_018f2a3b-4c5d-7000-8000-000000000a03")
    .bind(fixture.binding_id.as_str())
    .bind("req_018f2a3b-4c5d-7000-8000-000000000a04")
    .bind([70_u8; 32].as_slice())
    .bind(i64::try_from(NOW - 1).unwrap())
    .bind(i64::try_from(SOURCE_EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.action_descriptors (
            tenant_id, site_id, action_id, page_template, operation_id, method,
            route_template, target_rule, allowed_fields, field_profile,
            policy_revision, mapping_revision, status
         ) VALUES ($1, $2, 'records.share', 'record_page', 'records.share.issue', 'POST',
                   '/records/share', '{\"kind\":\"resource\",\"resource_type\":\"record\"}',
                   '[]', 'share_controls', 'policy-share-r1', 'mapping-r1', 'approved')",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.ui_actions (
            tenant_id, site_id, action_ref, binding_id, auth_epoch,
            source_request_id, page_evidence_id, source_action_ref, operation_id,
            target_constraints, field_profile, source_rule, policy_revision,
            status, issued_at, expires_at, mapping_revision, method, route_template,
            allowed_fields
         ) VALUES ($1, $2, 'action_record_share', $3, 4, $4, $5, 'records.share',
                   'records.share.issue', '{}', 'share_controls', 'mapping-r1',
                   'policy-share-r1', 'active', to_timestamp($6), to_timestamp($7),
                   'mapping-r1', 'POST', '/records/share', '[]')",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.binding_id.as_str())
    .bind("req_018f2a3b-4c5d-7000-8000-000000000a04")
    .bind("page_018f2a3b-4c5d-7000-8000-000000000a03")
    .bind(i64::try_from(NOW - 1).unwrap())
    .bind(i64::try_from(SOURCE_EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.resource_grants (
            tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref,
            resource_type, resource_key_hmac, operation_id, view_id, constraints,
            source_event_id, issuance_key, policy_revision, status, issued_at, expires_at
         ) VALUES ($1, $2, $3, $4, 4, 'action_record_share', 'record', $5,
                   'records.share.issue', 'share_controls', '{}', $6, 'record-share-authority',
                   'policy-share-r1', 'active', to_timestamp($7), to_timestamp($8))",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.authority.resource_grant_id.as_str())
    .bind(fixture.binding_id.as_str())
    .bind([63_u8; 32].as_slice())
    .bind("ev_018f2a3b-4c5d-7000-8000-000000000a06")
    .bind(i64::try_from(NOW - 1).unwrap())
    .bind(i64::try_from(SOURCE_EXPIRES).unwrap())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO xshield.share_issuance_rules (
            tenant_id, site_id, policy_revision, rule_id, issuer_operation_id,
            issuer_view_id, share_operation_id, share_view_id, max_ttl_seconds, status
         ) VALUES ($1, $2, 'policy-share-r1', $3, 'records.share.issue',
                   'share_controls', 'records.share.read', 'shared_summary', 600, 'active')",
    )
    .bind(fixture.tenant.as_str())
    .bind(fixture.site.as_str())
    .bind(fixture.authority.rule_id.as_str())
    .execute(pool)
    .await
    .unwrap();
}
