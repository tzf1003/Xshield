//! Actual share issuance, credential redemption, and optional production index delivery.

use clickhouse::{Client, sql::Identifier};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::{collections::BTreeMap, env, fmt::Write, time::Duration};
use uuid::Uuid;
use xshield_core::{
    access::ShareIssueAuthority,
    audit::ReasonCode,
    domain::{
        AuthBindingId, EventId, GrantId, IssuanceKey, OperationId, PolicyRevision, RequestId,
        ResourceType, ShareIssuanceRuleId, SiteId, TenantId, ViewProfile, WafSessionId,
    },
    grant::ResourceKeyHmac,
    identity::{
        AuthBinding, AuthEpoch, AuthSnapshot, AuthorizationContextRef, CredentialFingerprint,
        CredentialGeneration, CredentialSlot, UnixSeconds,
    },
    ports::{ShareGrantProofQuery, ShareGrantProofState, ShareGrantProofStore},
    provenance::HttpMethod,
};
use xshield_gateway::{
    share_issue::{ShareIssueApi, ShareIssueError, ShareIssueRequest, ShareIssueResponse},
    share_token::ShareTokenIssuer,
};
use xshield_postgres::{OutboxLeaseConfig, OutboxScope, PostgresIdentityStore, StoreError};
use xshield_worker::{
    OutboxPublishReport, OutboxPublisherConfig, publish_share_grant_outbox_batch,
};

const BINDING: &str = "auth_018f2a3b-4c5d-7000-8000-000000000b01";
const GRANT: &str = "grant_018f2a3b-4c5d-7000-8000-000000000b05";
const TRACE: &str = "1234567890abcdef1234567890abcdef";

struct Fixture {
    scope: OutboxScope,
    snapshot: AuthSnapshot,
    authority: ShareIssueAuthority,
    now: UnixSeconds,
    request_id: RequestId,
    event_id: EventId,
}

impl Fixture {
    fn new(now: u64) -> Self {
        let tenant =
            TenantId::parse(format!("tenant_share_api_{}", Uuid::now_v7().simple())).unwrap();
        let site = SiteId::parse("site_share_api").unwrap();
        let session = WafSessionId::parse(format!("ses_{}", Uuid::now_v7())).unwrap();
        let credentials = BTreeMap::from([(
            CredentialSlot::Cookie,
            CredentialFingerprint::from_bytes([61; 32]),
        )]);
        let binding = AuthBinding::new(
            AuthBindingId::parse(BINDING).unwrap(),
            session.clone(),
            tenant.clone(),
            site.clone(),
            "share-api-issuer",
            AuthorizationContextRef::parse("share-api-context").unwrap(),
            AuthEpoch::new(4),
            CredentialGeneration::new(1),
            credentials.clone(),
            UnixSeconds::new(now + 2_000),
        )
        .unwrap();
        Self {
            snapshot: binding
                .verify(
                    &tenant,
                    &site,
                    &session,
                    &credentials,
                    UnixSeconds::new(now),
                )
                .unwrap(),
            scope: OutboxScope::new(&tenant, &site),
            authority: ShareIssueAuthority {
                resource_grant_id: GrantId::parse(GRANT).unwrap(),
                rule_id: ShareIssuanceRuleId::parse("share-api-rule").unwrap(),
                operation_id: OperationId::parse("records.share.issue").unwrap(),
                view_profile: ViewProfile::parse("share_controls").unwrap(),
            },
            now: UnixSeconds::new(now),
            request_id: RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap(),
            event_id: EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap(),
        }
    }

    fn request(&self) -> ShareIssueRequest<'_> {
        ShareIssueRequest {
            snapshot: &self.snapshot,
            authority: &self.authority,
            issuance_key: IssuanceKey::parse("share-api-issuance").unwrap(),
            resource_type: ResourceType::parse("record").unwrap(),
            resource_key: ResourceKeyHmac::from_bytes([63; 32]),
            operation_id: OperationId::parse("records.share.read").unwrap(),
            view_profile: ViewProfile::parse("shared_summary").unwrap(),
            policy_revision: PolicyRevision::parse("share-api-policy").unwrap(),
            expires_at: UnixSeconds::new(self.now.value() + 300),
            event_id: &self.event_id,
            request_id: &self.request_id,
            trace_id: TRACE,
            now: self.now,
            max_active_shares: 1,
        }
    }
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL; optionally XSHIELD_TEST_CLICKHOUSE_URL"]
async fn share_api_commits_replays_and_publishes_exact_facts() {
    let pool = PgPool::connect(&env::var("XSHIELD_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&pool)
            .await
            .unwrap();
    let fixture = Fixture::new(u64::try_from(now).unwrap());
    let scope = fixture.scope.clone();
    let test_pool = pool.clone();
    // Await scope cleanup even when a seed, API, or publication assertion panics.
    let result = tokio::spawn(async move {
        seed(&test_pool, &fixture).await;
        exercise(&test_pool, &fixture).await;
    })
    .await;
    for statement in [
        "DELETE FROM xshield.share_grants WHERE tenant_id = $1 AND site_id = $2",
        "DELETE FROM xshield.resource_grants WHERE tenant_id = $1 AND site_id = $2",
        "DELETE FROM xshield.ui_actions WHERE tenant_id = $1 AND site_id = $2",
        "DELETE FROM xshield.action_descriptors WHERE tenant_id = $1 AND site_id = $2",
        "DELETE FROM xshield.page_evidence WHERE tenant_id = $1 AND site_id = $2",
        "DELETE FROM xshield.share_issuance_rules WHERE tenant_id = $1 AND site_id = $2",
        "DELETE FROM xshield.auth_bindings WHERE tenant_id = $1 AND site_id = $2",
        "DELETE FROM xshield.policy_revisions WHERE tenant_id = $1 AND site_id = $2",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2",
    ] {
        sqlx::query(statement)
            .bind(scope.tenant_id().as_str())
            .bind(scope.site_id().as_str())
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
    result.unwrap();
}

#[allow(clippy::too_many_lines)]
async fn exercise(pool: &PgPool, fixture: &Fixture) {
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let issuer = ShareTokenIssuer::from_hex(&"11".repeat(32), &"22".repeat(32)).unwrap();
    let api = ShareIssueApi::new(&store, &issuer);
    for change in 0..5 {
        let mut invalid = fixture.request();
        match change {
            0 => invalid.trace_id = "invalid-trace",
            1 => invalid.expires_at = invalid.now,
            2 => invalid.expires_at = UnixSeconds::new(invalid.now.value() + 86_401),
            3 => invalid.max_active_shares = 0,
            _ => invalid.now = UnixSeconds::new(u64::MAX),
        }
        assert!(matches!(
            api.issue(invalid).await,
            Err(ShareIssueError::InvalidAudit)
        ));
    }
    assert_counts(pool, &fixture.scope, (0, 0)).await;

    let collision = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope) VALUES ($1, $2, $3, 'rollback-fixture', 'fixture', '{}')")
        .bind(collision.as_str()).bind(fixture.scope.tenant_id().as_str()).bind(fixture.scope.site_id().as_str())
        .execute(pool).await.unwrap();
    let mut failed = fixture.request();
    failed.event_id = &collision;
    assert!(matches!(
        api.issue(failed).await,
        Err(ShareIssueError::Store(StoreError::Database(_)))
    ));
    assert_counts(pool, &fixture.scope, (0, 1)).await;
    sqlx::query(
        "DELETE FROM xshield.audit_outbox WHERE event_id = $1 AND tenant_id = $2 AND site_id = $3",
    )
    .bind(collision.as_str())
    .bind(fixture.scope.tenant_id().as_str())
    .bind(fixture.scope.site_id().as_str())
    .execute(pool)
    .await
    .unwrap();

    let ShareIssueResponse::Granted {
        share_id,
        token,
        created,
        expires_at,
    } = api.issue(fixture.request()).await.unwrap()
    else {
        panic!("qualified issuance was denied")
    };
    assert!(created);
    assert_eq!(expires_at, fixture.request().expires_at);
    let envelope = committed_envelope(pool, fixture).await;
    assert_eq!(envelope["payload"]["share_id"], share_id.as_str());
    let serialized = serde_json::to_string(&envelope).unwrap();
    for excluded in [
        token.expose_secret(),
        "share-api-issuance",
        "issuance_key",
        "token_fingerprint",
    ] {
        assert!(!serialized.contains(excluded));
    }
    let fingerprint = issuer
        .fingerprint(fixture.scope.tenant_id(), fixture.scope.site_id(), &token)
        .unwrap();
    let request = fixture.request();
    let query = ShareGrantProofQuery {
        tenant_id: fixture.scope.tenant_id(),
        site_id: fixture.scope.site_id(),
        token_fingerprint: &fingerprint,
        resource_type: &request.resource_type,
        resource_key: &request.resource_key,
        operation_id: &request.operation_id,
        view_profile: &request.view_profile,
        now: fixture.now,
    };
    let ShareGrantProofState::Verified(grant) = store.load_share_grant(query).await.unwrap() else {
        panic!("committed token could not redeem its grant")
    };
    assert_eq!(grant.share_id(), &share_id);
    for (method, allowed) in [(HttpMethod::Get, true), (HttpMethod::Post, false)] {
        assert_eq!(
            grant
                .authorize(
                    fixture.scope.tenant_id(),
                    fixture.scope.site_id(),
                    &fingerprint,
                    &request.resource_type,
                    &request.resource_key,
                    &request.operation_id,
                    &request.view_profile,
                    method,
                    fixture.now
                )
                .is_ok(),
            allowed
        );
    }
    assert!(
        grant
            .authorize(
                fixture.scope.tenant_id(),
                fixture.scope.site_id(),
                &fingerprint,
                &request.resource_type,
                &ResourceKeyHmac::from_bytes([99; 32]),
                &request.operation_id,
                &request.view_profile,
                HttpMethod::Get,
                fixture.now
            )
            .is_err()
    );

    let (left, right) = tokio::join!(api.issue(fixture.request()), api.issue(fixture.request()));
    for replay in [left.unwrap(), right.unwrap()] {
        let ShareIssueResponse::Granted {
            share_id: replay_id,
            token: replay_token,
            created,
            expires_at: replay_expiry,
        } = replay
        else {
            panic!("exact concurrent replay was denied")
        };
        assert!(!created);
        assert_eq!(replay_id, share_id);
        assert_eq!(replay_token.expose_secret(), token.expose_secret());
        assert_eq!(replay_expiry, expires_at);
    }
    let changed_request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
    for change in 0..3 {
        let mut replay = fixture.request();
        match change {
            0 => replay.trace_id = "abcdef1234567890abcdef1234567890",
            1 => replay.request_id = &changed_request,
            _ => replay.now = UnixSeconds::new(fixture.now.value() + 1),
        }
        assert!(matches!(
            api.issue(replay).await.unwrap(),
            ShareIssueResponse::Denied {
                reason_code: ReasonCode::ShareIssuanceConflict
            }
        ));
    }
    let capacity_event = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
    let mut capacity = fixture.request();
    capacity.event_id = &capacity_event;
    capacity.issuance_key = IssuanceKey::parse("share-api-capacity").unwrap();
    assert!(matches!(
        api.issue(capacity).await.unwrap(),
        ShareIssueResponse::Denied {
            reason_code: ReasonCode::ShareCapacityExceeded
        }
    ));
    assert_counts(pool, &fixture.scope, (1, 1)).await;
    assert_eq!(committed_envelope(pool, fixture).await, envelope);
    if env::var("XSHIELD_TEST_CLICKHOUSE_URL").is_ok() {
        publish_actual_event(pool.clone(), fixture.scope.clone(), envelope).await;
    } else {
        eprintln!(
            "Share API ClickHouse integration skipped: XSHIELD_TEST_CLICKHOUSE_URL is not configured."
        );
    }
}

async fn assert_counts(pool: &PgPool, scope: &OutboxScope, expected: (i64, i64)) {
    let actual: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM xshield.share_grants WHERE tenant_id = $1 AND site_id = $2), (SELECT count(*) FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2)")
        .bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str()).fetch_one(pool).await.unwrap();
    assert_eq!(actual, expected);
}

async fn committed_envelope(pool: &PgPool, fixture: &Fixture) -> Value {
    let row = sqlx::query(r"
        SELECT outbox.envelope, outbox.aggregate_ref, share.share_id,
          jsonb_build_object(
            'stage', 'share_grant', 'outcome', 'PASS', 'reason_code', 'SHARE_ISSUED',
            'share_id', share.share_id, 'issuer_binding_id', share.issuer_binding_id,
            'issuer_auth_epoch', share.issuer_auth_epoch, 'issuer_grant_id', share.issuer_grant_id,
            'issuance_rule_id', share.issuance_rule_id, 'issuer_operation_id', rule.issuer_operation_id,
            'issuer_view_profile', rule.issuer_view_id, 'resource_type', share.resource_type,
            'resource_key_hmac', encode(share.resource_key_hmac, 'hex'), 'operation_id', share.operation_id,
            'view_profile', share.view_id, 'method', 'GET', 'use_policy', share.use_policy,
            'issued_at_unix', extract(epoch FROM share.issued_at)::bigint,
            'expires_at_unix', extract(epoch FROM share.expires_at)::bigint) AS payload
        FROM xshield.share_grants share JOIN xshield.audit_outbox outbox
          ON outbox.tenant_id = share.tenant_id AND outbox.site_id = share.site_id
         AND outbox.event_id = share.source_event_id
        JOIN xshield.share_issuance_rules rule
          ON rule.tenant_id = share.tenant_id AND rule.site_id = share.site_id
         AND rule.policy_revision = share.policy_revision AND rule.rule_id = share.issuance_rule_id
        WHERE share.tenant_id = $1 AND share.site_id = $2 AND outbox.event_id = $3
    ").bind(fixture.scope.tenant_id().as_str()).bind(fixture.scope.site_id().as_str())
        .bind(fixture.event_id.as_str()).fetch_one(pool).await.unwrap();
    let envelope: Value = row.get("envelope");
    assert_eq!(envelope["payload"], row.get::<Value, _>("payload"));
    assert_eq!(
        row.get::<String, _>("share_id"),
        row.get::<String, _>("aggregate_ref")
    );
    assert_eq!(envelope["request_id"], fixture.request_id.as_str());
    assert_eq!(envelope["event_id"], fixture.event_id.as_str());
    assert_eq!(envelope["tenant_id"], fixture.scope.tenant_id().as_str());
    assert_eq!(envelope["site_id"], fixture.scope.site_id().as_str());
    assert_eq!(envelope["trace_id"], TRACE);
    assert_eq!(
        envelope["policy_revision"],
        fixture.request().policy_revision.as_str()
    );
    envelope
}

#[derive(Deserialize, clickhouse::Row)]
struct IndexedShare {
    event_id: String,
    request_id: String,
    producer_id: String,
    payload_json: String,
    digest: String,
    event_hash: String,
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    confidence: Option<f64>,
    confidence_status: String,
    method: String,
    operation_id: String,
    is_terminal: u8,
    issued_at: u32,
}

async fn publish_actual_event(pool: PgPool, scope: OutboxScope, envelope: Value) {
    let mut admin = Client::default().with_url(env::var("XSHIELD_TEST_CLICKHOUSE_URL").unwrap());
    if let Ok(user) = env::var("XSHIELD_TEST_CLICKHOUSE_USER") {
        admin = admin.with_user(user);
    }
    if let Ok(password) = env::var("XSHIELD_TEST_CLICKHOUSE_PASSWORD") {
        admin = admin.with_password(password);
    }
    let database = format!("xshield_share_api_{}", Uuid::now_v7().simple());
    admin
        .query("CREATE DATABASE ?")
        .bind(Identifier(&database))
        .execute()
        .await
        .unwrap();
    let client = admin.clone().with_database(database.clone());
    let schema_database = database.clone();
    let result = tokio::spawn(async move {
        let schema = include_str!("../../../sql/clickhouse.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n")
            .replace("xshield.", &format!("{schema_database}."));
        for _ in 0..2 {
            for statement in schema.split(';').map(str::trim) {
                if !statement.is_empty() && statement != "CREATE DATABASE IF NOT EXISTS xshield" {
                    client.query(statement).execute().await.unwrap();
                }
            }
        }
        verify_publication(&pool, &scope, &client, &envelope).await;
    })
    .await;
    let cleanup = admin
        .query("DROP DATABASE ? SYNC")
        .bind(Identifier(&database))
        .execute()
        .await;
    assert!(
        cleanup.is_ok(),
        "owned share API ClickHouse database cleanup failed"
    );
    result.unwrap();
}

async fn verify_publication(pool: &PgPool, scope: &OutboxScope, client: &Client, envelope: &Value) {
    let store = PostgresIdentityStore::from_pool(pool.clone());
    let config = OutboxPublisherConfig::new(
        "audit_events",
        30,
        OutboxLeaseConfig::new(16, 64 * 1024, Duration::from_mins(1)).unwrap(),
        Duration::from_mins(1),
    )
    .unwrap();
    assert_eq!(
        publish_share_grant_outbox_batch(&store, client, scope, &config)
            .await
            .unwrap(),
        OutboxPublishReport {
            claimed: 1,
            published: 1
        }
    );
    let digest = xshield_audit::sha256_digest(&serde_json::to_vec(envelope).unwrap())
        .iter()
        .fold(String::new(), |mut value, byte| {
            write!(&mut value, "{byte:02x}").unwrap();
            value
        });
    for table in [
        "audit_events",
        "events_by_time",
        "audit_events_active",
        "events_by_time_active",
    ] {
        let rows = client.query("SELECT event_id, request_id, producer_id, payload_json, toString(content_digest) AS digest, event_hash, stage, outcome, reason_code, proof_kind, confidence, confidence_status, method, operation_id, is_terminal, toUnixTimestamp(occurred_at) AS issued_at FROM ?")
            .bind(Identifier(table)).fetch_all::<IndexedShare>().await.unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.event_id, envelope["event_id"]);
        assert_eq!(row.request_id, envelope["request_id"]);
        assert_eq!(row.producer_id, "gateway-share-grant");
        assert_eq!(
            serde_json::from_str::<Value>(&row.payload_json).unwrap(),
            envelope["payload"]
        );
        assert_eq!(row.digest, digest);
        assert_eq!(row.event_hash, digest);
        assert_eq!(row.stage, "share_grant");
        assert_eq!(row.outcome, "PASS");
        assert_eq!(row.reason_code, "SHARE_ISSUED");
        assert_eq!(row.proof_kind, "deterministic");
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status, "not_applicable");
        assert_eq!(row.method, "GET");
        assert_eq!(row.operation_id, "records.share.read");
        assert_eq!(row.is_terminal, 0);
        assert_eq!(
            u64::from(row.issued_at),
            envelope["payload"]["issued_at_unix"].as_u64().unwrap()
        );
    }
    let acknowledged: bool = sqlx::query_scalar("SELECT published_at IS NOT NULL AND lease_token IS NULL AND lease_until IS NULL AND delivery_attempts = 1 FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2 AND event_id = $3")
        .bind(scope.tenant_id().as_str()).bind(scope.site_id().as_str()).bind(envelope["event_id"].as_str().unwrap())
        .fetch_one(pool).await.unwrap();
    assert!(acknowledged);
    assert_eq!(
        publish_share_grant_outbox_batch(&store, client, scope, &config)
            .await
            .unwrap(),
        OutboxPublishReport {
            claimed: 0,
            published: 0
        }
    );
}

async fn seed(pool: &PgPool, fixture: &Fixture) {
    sqlx::query("INSERT INTO xshield.policy_revisions (tenant_id, site_id, revision, status, content_digest, artifact_ref) VALUES ($1, $2, 'share-api-policy', 'active', repeat('d', 64), 'artifact_share_api_policy')")
        .bind(fixture.scope.tenant_id().as_str()).bind(fixture.scope.site_id().as_str()).execute(pool).await.unwrap();
    sqlx::query(r#"INSERT INTO xshield.action_descriptors (tenant_id, site_id, action_id, page_template, operation_id, method, route_template, target_rule, allowed_fields, field_profile, policy_revision, mapping_revision, status) VALUES ($1, $2, 'records.share', 'record_page', 'records.share.issue', 'POST', '/records/share', '{"kind":"resource","resource_type":"record"}', '[]', 'share_controls', 'share-api-policy', 'mapping-r1', 'approved')"#)
        .bind(fixture.scope.tenant_id().as_str()).bind(fixture.scope.site_id().as_str()).execute(pool).await.unwrap();
    for statement in [
        r"INSERT INTO xshield.auth_bindings (tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref, authorization_context_ref, auth_epoch, credential_generation, status, absolute_expires_at)
          VALUES ($1, $2, 'auth_018f2a3b-4c5d-7000-8000-000000000b01', decode(repeat('3d', 32), 'hex'), 'share-api-issuer', 'share-api-context', 4, 1, 'active', to_timestamp($3 + 2000))",
        r"INSERT INTO xshield.page_evidence (tenant_id, site_id, page_evidence_id, binding_id, auth_epoch, source_request_id, response_artifact_ref, page_template, build_fingerprint, policy_revision, mapping_revision, status, verified_at, expires_at)
          VALUES ($1, $2, 'page_018f2a3b-4c5d-7000-8000-000000000b03', 'auth_018f2a3b-4c5d-7000-8000-000000000b01', 4, 'req_018f2a3b-4c5d-7000-8000-000000000b04', 'artifact_share_api_page', 'record_page', decode(repeat('46', 32), 'hex'), 'share-api-policy', 'mapping-r1', 'verified', to_timestamp($3 - 1), to_timestamp($3 + 1000))",
        r"INSERT INTO xshield.ui_actions (tenant_id, site_id, action_ref, binding_id, auth_epoch, source_request_id, page_evidence_id, source_action_ref, operation_id, target_constraints, field_profile, source_rule, policy_revision, status, issued_at, expires_at, mapping_revision, method, route_template, allowed_fields)
          VALUES ($1, $2, 'action_share_api', 'auth_018f2a3b-4c5d-7000-8000-000000000b01', 4, 'req_018f2a3b-4c5d-7000-8000-000000000b04', 'page_018f2a3b-4c5d-7000-8000-000000000b03', 'records.share', 'records.share.issue', '{}', 'share_controls', 'mapping-r1', 'share-api-policy', 'active', to_timestamp($3 - 1), to_timestamp($3 + 1000), 'mapping-r1', 'POST', '/records/share', '[]')",
        r"INSERT INTO xshield.resource_grants (tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref, resource_type, resource_key_hmac, operation_id, view_id, constraints, source_event_id, issuance_key, policy_revision, status, issued_at, expires_at)
          VALUES ($1, $2, 'grant_018f2a3b-4c5d-7000-8000-000000000b05', 'auth_018f2a3b-4c5d-7000-8000-000000000b01', 4, 'action_share_api', 'record', decode(repeat('3f', 32), 'hex'), 'records.share.issue', 'share_controls', '{}', 'ev_018f2a3b-4c5d-7000-8000-000000000b06', 'share-api-source', 'share-api-policy', 'active', to_timestamp($3 - 1), to_timestamp($3 + 1000))",
    ] {
        sqlx::query(statement)
            .bind(fixture.scope.tenant_id().as_str())
            .bind(fixture.scope.site_id().as_str())
            .bind(i64::try_from(fixture.now.value()).unwrap())
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO xshield.share_issuance_rules (tenant_id, site_id, policy_revision, rule_id, issuer_operation_id, issuer_view_id, share_operation_id, share_view_id, max_ttl_seconds, status) VALUES ($1, $2, 'share-api-policy', 'share-api-rule', 'records.share.issue', 'share_controls', 'records.share.read', 'shared_summary', 600, 'active')")
        .bind(fixture.scope.tenant_id().as_str()).bind(fixture.scope.site_id().as_str()).execute(pool).await.unwrap();
}
