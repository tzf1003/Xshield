//! Real vault/catalog fixtures and `PostgreSQL` hold/purge serialization regressions.

use chrono::{DateTime, Duration as TimeDelta, SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, fs, path::Path, time::Duration};
use uuid::Uuid;
use xshield_core::{
    domain::{ArtifactId, CaseId, EventId, RequestId, SiteId, TenantId},
    investigation::CaseEvidenceDraft,
};
use xshield_evidence::{
    EvidenceClassification, EvidenceFidelity, EvidenceKey, EvidenceVaultConfig, EvidenceWrite,
    LocalEvidenceVault,
};
use xshield_postgres::{
    CaseEvidenceAdd, CaseEvidenceHoldCreate, CaseEvidenceHoldCreateOutcome as CreateOutcome,
    CaseEvidenceHoldPage, CaseEvidenceHoldQuery, CaseEvidenceHoldRecord, CaseEvidenceHoldRelease,
    CaseEvidenceHoldReleaseOutcome as ReleaseOutcome, CaseEvidenceWriteOutcome,
    EvidenceCatalogArtifactQuery, EvidenceCatalogPublish, EvidenceCatalogWriteOutcome,
    EvidencePurgeResult, PostgresIdentityStore, StoreError,
};

const KEY_ID: &str = "hold-regression-key";
const KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn hold_commands_reject_noncanonical_time_and_unbounded_text() {
    let tenant = TenantId::parse("tenant_hold_constructor").unwrap();
    let site = SiteId::parse("site_hold_constructor").unwrap();
    let case = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    let artifact = ArtifactId::parse(format!("artifact_{}", Uuid::now_v7())).unwrap();
    let event = event_id();
    let release = event_id();
    let deadline = DateTime::from_timestamp_millis(2_000_000_000_000).unwrap();
    for time in [
        DateTime::from_timestamp_millis(-1).unwrap(),
        deadline + TimeDelta::microseconds(1),
        DateTime::<Utc>::MAX_UTC,
        DateTime::parse_from_rfc3339("2030-01-01T23:59:60.000Z")
            .unwrap()
            .with_timezone(&Utc),
    ] {
        assert!(
            CaseEvidenceHoldCreate::new(
                &tenant, &site, &case, &artifact, "actor", "reason", &[1; 32], &[2; 32], &event,
                time,
            )
            .is_err()
        );
    }
    for (actor, reason) in [
        (String::new(), "reason".into()),
        ("actor\n".into(), "reason".into()),
        ("x".repeat(257), "reason".into()),
        ("actor".into(), String::new()),
        ("actor".into(), "reason\n".into()),
        ("actor".into(), "x".repeat(513)),
    ] {
        assert!(
            CaseEvidenceHoldCreate::new(
                &tenant, &site, &case, &artifact, &actor, &reason, &[1; 32], &[2; 32], &event,
                deadline,
            )
            .is_err()
        );
        assert!(
            CaseEvidenceHoldRelease::new(
                &tenant, &site, &event, &actor, &reason, &[1; 32], &[2; 32], &release,
            )
            .is_err()
        );
    }
}

#[test]
fn hold_history_query_bounds_are_enforced() {
    let tenant = TenantId::parse("tenant_hold_constructor").unwrap();
    let site = SiteId::parse("site_hold_constructor").unwrap();
    let case = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    let after = event_id();
    for limit in [0, 129, u16::MAX] {
        assert!(CaseEvidenceHoldQuery::new(&tenant, &site, &case, Some(&after), limit).is_err());
    }
    for limit in [1, 128] {
        assert!(CaseEvidenceHoldQuery::new(&tenant, &site, &case, None, limit).is_ok());
    }
}

#[derive(Clone)]
struct HoldRequest {
    tenant: TenantId,
    site: SiteId,
    case: CaseId,
    artifact: ArtifactId,
    actor: String,
    reason: String,
    key: [u8; 32],
    digest: [u8; 32],
    event: EventId,
    until: DateTime<Utc>,
}

impl HoldRequest {
    fn command(&self) -> CaseEvidenceHoldCreate<'_> {
        CaseEvidenceHoldCreate::new(
            &self.tenant,
            &self.site,
            &self.case,
            &self.artifact,
            &self.actor,
            &self.reason,
            &self.key,
            &self.digest,
            &self.event,
            self.until,
        )
        .unwrap()
    }
}

#[derive(Clone)]
struct ReleaseRequest {
    tenant: TenantId,
    site: SiteId,
    hold: EventId,
    actor: String,
    reason: String,
    key: [u8; 32],
    digest: [u8; 32],
    event: EventId,
}

impl ReleaseRequest {
    fn new(hold: &HoldRequest) -> Self {
        Self {
            tenant: hold.tenant.clone(),
            site: hold.site.clone(),
            hold: hold.event.clone(),
            actor: "second-audit-admin".into(),
            reason: "Investigation complete".into(),
            key: digest(),
            digest: digest(),
            event: event_id(),
        }
    }

    fn command(&self) -> CaseEvidenceHoldRelease<'_> {
        CaseEvidenceHoldRelease::new(
            &self.tenant,
            &self.site,
            &self.hold,
            &self.actor,
            &self.reason,
            &self.key,
            &self.digest,
            &self.event,
        )
        .unwrap()
    }
}

struct Fixture {
    pool: PgPool,
    store: PostgresIdentityStore,
    url: String,
    tenant: TenantId,
    site: SiteId,
    vault: LocalEvidenceVault,
}

#[tokio::test]
#[ignore = "requires script-owned XSHIELD_TEST_DATABASE_URL"]
async fn case_evidence_holds_are_atomic_scoped_bounded_and_serialize_with_purge() {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("script test database URL");
    let pool = PgPool::connect(&url).await.unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        database.starts_with("xshield_test_"),
        "requires script-owned test database"
    );
    let tenant = TenantId::parse(format!("tenant_hold_{}", Uuid::now_v7().simple())).unwrap();
    let root = env::temp_dir().join(format!("xshield-hold-test-{}", Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let fixture = Fixture {
        store: PostgresIdentityStore::from_pool(pool.clone()),
        pool: pool.clone(),
        url,
        tenant: tenant.clone(),
        site: SiteId::parse("site_hold_basic").unwrap(),
        vault: LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, KEY_ID, 1024, 30).unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap(),
    };
    // Catch assertion panics in the child so scoped rows and vault files are still
    // removed; the owning script's database trap also covers process termination.
    let result = tokio::spawn(run_regressions(fixture)).await;
    cleanup(&pool, &tenant, &root).await;
    pool.close().await;
    if let Err(error) = result {
        std::panic::resume_unwind(error.into_panic());
    }
}

async fn run_regressions(mut f: Fixture) {
    assert_idempotency_and_scope(&f).await;
    f.site = SiteId::parse("site_hold_read").unwrap();
    assert_history_pages(&f).await;
    f.site = SiteId::parse("site_hold_read_snapshot").unwrap();
    assert_release_read_snapshot(&f).await;
    f.site = SiteId::parse("site_hold_state").unwrap();
    assert_target_state_and_read_expiry(&f).await;
    f.site = SiteId::parse("site_hold_fault").unwrap();
    assert_outbox_atomicity_and_integrity(&f).await;
    f.site = SiteId::parse("site_hold_first").unwrap();
    assert_purge_lock_order(&f, true).await;
    f.site = SiteId::parse("site_purge_first").unwrap();
    assert_purge_lock_order(&f, false).await;
    f.site = SiteId::parse("site_hold_expiry").unwrap();
    assert_expiry_and_multiple_cases(&f).await;
    f.site = SiteId::parse("site_hold_wait_expiry").unwrap();
    assert_deadline_after_lock_wait(&f, false).await;
    assert_deadline_after_lock_wait(&f, true).await;
    f.site = SiteId::parse("site_hold_dst").unwrap();
    assert_database_duration_across_dst(&f).await;
    f.site = SiteId::parse("site_hold_history").unwrap();
    assert_history_capacity(&f).await;
    f.site = SiteId::parse("site_hold_capacity").unwrap();
    assert_scope_capacity(&f).await;
}

impl Fixture {
    async fn case(&self) -> CaseId {
        let case = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
        sqlx::query(
            "INSERT INTO xshield.investigation_cases
             (tenant_id,site_id,case_id,owner_ref,purpose,status,idempotency_digest,
              request_digest,created_event_id)
             VALUES ($1,$2,$3,'case-owner','Hold regression','open',$4,$4,$5)",
        )
        .bind(self.tenant.as_str())
        .bind(self.site.as_str())
        .bind(case.as_str())
        .bind(digest().as_slice())
        .bind(event_id().as_str())
        .execute(&self.pool)
        .await
        .unwrap();
        case
    }

    async fn artifact(&self) -> ArtifactId {
        let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
        let verified = self
            .vault
            .write(&EvidenceWrite {
                tenant_id: &self.tenant,
                site_id: &self.site,
                request_id: &request,
                kind: "request_decoded",
                content_type: "application/json",
                fidelity: EvidenceFidelity::EntityExact,
                classification: EvidenceClassification::Restricted,
                parent_refs: &[],
                expires_at: Utc::now() + TimeDelta::hours(1),
                plaintext: br#"{"hold":true}"#,
            })
            .unwrap();
        let artifact = ArtifactId::parse(&verified.manifest().artifact_id).unwrap();
        let event = event_id();
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let envelope = json!({
            "schema_version":3,"event_id":event.as_str(),"event_type":"evidence.cataloged",
            "tenant_id":self.tenant.as_str(),"site_id":self.site.as_str(),
            "request_id":request.as_str(),"trace_id":"018f2a3b4c5d70008000000000000902",
            "span_id":"018f2a3b4c5d7000","producer_id":"hold-regression",
            "producer_boot_id":"boot-test","producer_seq":1,"request_seq":1,
            "occurred_at":now,"observed_at":now,"policy_revision":"hold-test-v1",
            "example_only":false,"evidence_refs":[artifact.as_str()],"cause_event_ids":[],
            "payload":{"stage":"evidence_catalog","outcome":"PASS",
                "reason_code":"EVIDENCE_CATALOG_PUBLISHED","artifact_id":artifact.as_str()},
            "sensitivity":"RESTRICTED",
            "integrity":{"state":"pending","previous_hash":null,"event_hash":null}
        });
        assert_eq!(
            self.store
                .publish_evidence_manifest(
                    EvidenceCatalogPublish::new(&verified, &event, &envelope).unwrap(),
                )
                .await
                .unwrap(),
            EvidenceCatalogWriteOutcome::Published
        );
        artifact
    }

    async fn member(&self, case: &CaseId, artifact: &ArtifactId) {
        let draft = CaseEvidenceDraft::new(
            self.tenant.clone(),
            self.site.clone(),
            case.clone(),
            artifact.clone(),
            "case-owner",
        )
        .unwrap();
        let request = RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap();
        let event = event_id();
        let key = digest();
        let request_digest = [7_u8; 32];
        let envelope = json!({
            "schema_version":3,"event_id":event.as_str(),"event_type":"case.evidence.added",
            "tenant_id":self.tenant.as_str(),"site_id":self.site.as_str(),
            "request_id":request.as_str(),"evidence_refs":[artifact.as_str()],
            "payload":{"case_id":case.as_str(),"artifact_id":artifact.as_str(),
                "subject_ref":"case-owner","stage":"case_management",
                "request_digest":"07".repeat(32),"outcome":"PASS",
                "reason_code":"CASE_EVIDENCE_ADDED"}
        });
        assert!(matches!(
            self.store
                .add_case_evidence(
                    CaseEvidenceAdd::new(
                        &draft,
                        &key,
                        &request_digest,
                        &request,
                        &event,
                        &envelope,
                    )
                    .unwrap()
                )
                .await
                .unwrap(),
            CaseEvidenceWriteOutcome::Added(_)
        ));
    }

    async fn hold(&self, case: &CaseId, artifact: &ArtifactId) -> HoldRequest {
        HoldRequest {
            tenant: self.tenant.clone(),
            site: self.site.clone(),
            case: case.clone(),
            artifact: artifact.clone(),
            actor: "audit-admin".into(),
            reason: "Preserve investigation evidence".into(),
            key: digest(),
            digest: digest(),
            event: event_id(),
            until: self.now().await + TimeDelta::days(1),
        }
    }

    async fn target(&self) -> HoldRequest {
        let case = self.case().await;
        let artifact = self.artifact().await;
        self.member(&case, &artifact).await;
        self.hold(&case, &artifact).await
    }

    async fn now(&self) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT date_trunc('milliseconds',clock_timestamp())")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn expire_artifact(&self, artifact: &ArtifactId) -> DateTime<Utc> {
        // Exercise database read/purge policy without altering the vault's signed
        // manifest. Physical deletion is deliberately outside this store test.
        sqlx::query_scalar(
            "UPDATE xshield.artifact_catalog
             SET recorded_at=date_trunc('milliseconds',clock_timestamp())-interval '2 hours',
                 expires_at=date_trunc('milliseconds',clock_timestamp())-interval '1 hour'
             WHERE artifact_id=$1 RETURNING expires_at",
        )
        .bind(artifact.as_str())
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn create(&self, request: &HoldRequest) -> CreateOutcome {
        self.store
            .create_case_evidence_hold(request.command())
            .await
            .unwrap()
    }

    async fn release(&self, request: &ReleaseRequest) -> ReleaseOutcome {
        self.store
            .release_case_evidence_hold(request.command())
            .await
            .unwrap()
    }

    async fn created(&self, request: &HoldRequest) -> CaseEvidenceHoldRecord {
        let result = self.create(request).await;
        let CreateOutcome::Created(record) = result else {
            panic!("expected new hold: {result:?}");
        };
        record
    }

    async fn released(&self, request: &ReleaseRequest) -> CaseEvidenceHoldRecord {
        let result = self.release(request).await;
        let ReleaseOutcome::Released(record) = result else {
            panic!("expected release: {result:?}");
        };
        record
    }

    async fn event(&self, id: &EventId) -> (String, String, Value) {
        sqlx::query_as(
            "SELECT aggregate_ref,event_type,envelope FROM xshield.audit_outbox WHERE event_id=$1",
        )
        .bind(id.as_str())
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn counts(&self) -> (i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT count(*) FROM xshield.case_evidence_holds WHERE tenant_id=$1 AND site_id=$2),
                    (SELECT count(*) FROM xshield.audit_outbox WHERE tenant_id=$1 AND site_id=$2
                     AND event_type IN ('evidence.hold.created','evidence.hold.released'))",
        ).bind(self.tenant.as_str()).bind(self.site.as_str()).fetch_one(&self.pool).await.unwrap()
    }

    async fn page(
        &self,
        case: &CaseId,
        after: Option<&EventId>,
        limit: u16,
    ) -> CaseEvidenceHoldPage {
        self.store
            .list_case_evidence_holds(
                CaseEvidenceHoldQuery::new(&self.tenant, &self.site, case, after, limit).unwrap(),
            )
            .await
            .unwrap()
            .unwrap()
    }
}

#[allow(clippy::too_many_lines)]
async fn assert_history_pages(f: &Fixture) {
    let case = f.case().await;
    let empty = f.page(&case, None, 1).await;
    assert_eq!(empty.case_id(), &case);
    assert_eq!(empty.case_status(), "open");
    assert!(empty.items().is_empty());
    assert!(empty.next_hold_id().is_none());
    let missing = CaseId::parse(format!("case_{}", Uuid::now_v7())).unwrap();
    let foreign_tenant = TenantId::parse("tenant_hold_read_other").unwrap();
    let foreign_site = SiteId::parse("site_hold_read_other").unwrap();
    for (tenant, site, target) in [
        (&f.tenant, &f.site, &missing),
        (&foreign_tenant, &f.site, &case),
        (&f.tenant, &foreign_site, &case),
    ] {
        assert!(
            f.store
                .list_case_evidence_holds(
                    CaseEvidenceHoldQuery::new(tenant, site, target, None, 128).unwrap(),
                )
                .await
                .unwrap()
                .is_none()
        );
    }
    let mut requests = Vec::new();
    let mut records = Vec::new();
    for index in 0..3 {
        let artifact = f.artifact().await;
        f.member(&case, &artifact).await;
        let mut hold = f.hold(&case, &artifact).await;
        if index == 2 {
            hold.until = f.now().await + TimeDelta::milliseconds(300);
        }
        records.push(f.created(&hold).await);
        requests.push(hold);
    }
    let release = ReleaseRequest::new(&requests[1]);
    records[1] = f.released(&release).await;
    wait_until(f, requests[2].until).await;
    assert!(
        records
            .windows(2)
            .all(|pair| pair[0].created_event_id.as_str() < pair[1].created_event_id.as_str())
    );
    let before = history_snapshot(f).await;
    let page_one = f.page(&case, None, 1).await;
    assert_eq!(page_one.items(), &records[..1]);
    assert_eq!(page_one.next_hold_id(), Some(&records[0].created_event_id));
    let page_two = f.page(&case, page_one.next_hold_id(), 1).await;
    assert_eq!(page_two.items(), &records[1..2]);
    assert_eq!(page_two.next_hold_id(), Some(&records[1].created_event_id));
    let page_three = f.page(&case, page_two.next_hold_id(), 1).await;
    assert_eq!(page_three.items(), &records[2..]);
    assert!(page_three.next_hold_id().is_none());
    assert!(page_three.as_of() >= records[2].hold_until);
    assert!(page_one.as_of() <= page_two.as_of() && page_two.as_of() <= page_three.as_of());
    let after_last = f.page(&case, Some(&records[2].created_event_id), 128).await;
    assert!(after_last.items().is_empty());
    assert!(after_last.next_hold_id().is_none());
    let all = f.page(&case, None, 128).await;
    assert_eq!(all.items(), records);
    assert!(all.next_hold_id().is_none());
    assert_eq!(
        before,
        history_snapshot(f).await,
        "history reads preserve all scoped rows"
    );
    sqlx::query("UPDATE xshield.investigation_cases SET status='closed' WHERE case_id=$1")
        .bind(case.as_str())
        .execute(&f.pool)
        .await
        .unwrap();
    let before = history_snapshot(f).await;
    let closed = f.page(&case, None, 128).await;
    assert_eq!(closed.case_status(), "closed");
    assert_eq!(closed.items(), records);
    assert_eq!(before, history_snapshot(f).await);
    assert_lookahead_integrity(f, &requests[1], &release).await;
}

async fn history_snapshot(f: &Fixture) -> Value {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(
            'cases',(SELECT jsonb_agg(to_jsonb(c) ORDER BY case_id) FROM xshield.investigation_cases c WHERE tenant_id=$1 AND site_id=$2),
            'holds',(SELECT jsonb_agg(to_jsonb(h) ORDER BY created_event_id) FROM xshield.case_evidence_holds h WHERE tenant_id=$1 AND site_id=$2),
            'items',(SELECT jsonb_agg(to_jsonb(i) ORDER BY case_id,artifact_id) FROM xshield.case_items i WHERE tenant_id=$1 AND site_id=$2),
            'catalog',(SELECT jsonb_agg(to_jsonb(a) ORDER BY artifact_id) FROM xshield.artifact_catalog a WHERE tenant_id=$1 AND site_id=$2),
            'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY event_id) FROM xshield.audit_outbox o WHERE tenant_id=$1 AND site_id=$2))",
    ).bind(f.tenant.as_str()).bind(f.site.as_str()).fetch_one(&f.pool).await.unwrap()
}

async fn assert_bad_history(f: &Fixture, case: &CaseId) {
    assert!(matches!(
        f.store
            .list_case_evidence_holds(
                CaseEvidenceHoldQuery::new(&f.tenant, &f.site, case, None, 1).unwrap(),
            )
            .await,
        Err(StoreError::CorruptData("hold_outbox"))
    ));
}

async fn assert_lookahead_integrity(
    f: &Fixture,
    lookahead: &HoldRequest,
    release: &ReleaseRequest,
) {
    for id in [&lookahead.event, &release.event] {
        let (aggregate, event_type, envelope) = f.event(id).await;
        for mutation in ["tenant", "site", "aggregate", "type", "envelope", "missing"] {
            let statement = match mutation {
                "tenant" => Some(
                    "UPDATE xshield.audit_outbox SET tenant_id='tenant_other' WHERE event_id=$1",
                ),
                "site" => {
                    Some("UPDATE xshield.audit_outbox SET site_id='site_other' WHERE event_id=$1")
                }
                "aggregate" => Some(
                    "UPDATE xshield.audit_outbox SET aggregate_ref='wrong-target' WHERE event_id=$1",
                ),
                "type" => {
                    Some("UPDATE xshield.audit_outbox SET event_type='fixture' WHERE event_id=$1")
                }
                "envelope" => Some(
                    "UPDATE xshield.audit_outbox SET envelope=jsonb_set(envelope,'{producer_seq}','99') WHERE event_id=$1",
                ),
                "missing" => None,
                _ => unreachable!(),
            };
            if let Some(statement) = statement {
                sqlx::query(statement)
                    .bind(id.as_str())
                    .execute(&f.pool)
                    .await
                    .unwrap();
            } else {
                delete_event(f, id).await;
            }
            assert_bad_history(f, &lookahead.case).await;
            sqlx::query(
                "INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope)
                 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (event_id)
                 DO UPDATE SET tenant_id=$2,site_id=$3,aggregate_ref=$4,event_type=$5,envelope=$6",
            ).bind(id.as_str()).bind(f.tenant.as_str()).bind(f.site.as_str())
                .bind(&aggregate).bind(&event_type).bind(&envelope).execute(&f.pool).await.unwrap();
        }
    }
    sqlx::query("UPDATE xshield.case_evidence_holds SET hold_until=hold_until+interval '1 millisecond' WHERE created_event_id=$1")
        .bind(lookahead.event.as_str()).execute(&f.pool).await.unwrap();
    assert_bad_history(f, &lookahead.case).await;
    sqlx::query("UPDATE xshield.case_evidence_holds SET hold_until=$2 WHERE created_event_id=$1")
        .bind(lookahead.event.as_str())
        .bind(lookahead.until)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(f.page(&lookahead.case, None, 1).await.items().len(), 1);
}

async fn assert_release_read_snapshot(f: &Fixture) {
    let hold = f.target().await;
    let original = f.created(&hold).await;
    let release = ReleaseRequest::new(&hold);
    let (pool, store, pid) = actor_pool(&f.url).await;
    let mut blocker = f.pool.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope)
         VALUES ($1,$2,$3,'collision','fixture','{}')",
    ).bind(release.event.as_str()).bind(f.tenant.as_str()).bind(f.site.as_str())
        .execute(&mut *blocker).await.unwrap();
    let (released, ()) = tokio::join!(store.release_case_evidence_hold(release.command()), async {
        wait_blocked(&f.pool, pid, blocker_pid).await;
        // The production transaction has changed its hold row and is waiting
        // to insert outbox. The reader must see the complete preceding state.
        let preceding = tokio::time::timeout(Duration::from_secs(2), f.page(&hold.case, None, 128))
            .await
            .unwrap();
        assert_eq!(preceding.items(), std::slice::from_ref(&original));
        blocker.rollback().await.unwrap();
    },);
    let ReleaseOutcome::Released(record) = released.unwrap() else {
        panic!("release commits after the fixture collision rolls back");
    };
    assert_eq!(f.page(&hold.case, None, 128).await.items(), &[record]);
    pool.close().await;
}

#[allow(clippy::too_many_lines)]
async fn assert_idempotency_and_scope(f: &Fixture) {
    let hold = f.target().await;
    let record = f.created(&hold).await;
    assert_eq!(record.created_by, "audit-admin"); // An administrator need not own the case.
    assert_eq!(record.hold_until, hold.until);
    assert_eq!(
        f.create(&hold).await,
        CreateOutcome::Existing(record.clone())
    );
    let mut retry = hold.clone();
    retry.event = event_id();
    assert_eq!(
        f.create(&retry).await,
        CreateOutcome::Existing(record.clone())
    );
    for field in [
        "case", "artifact", "reason", "digest", "deadline", "key", "actor",
    ] {
        let mut changed = hold.clone();
        match field {
            "case" => changed.case = f.case().await,
            "artifact" => changed.artifact = f.artifact().await,
            "reason" => changed.reason.push_str(" changed"),
            "digest" => changed.digest = digest(),
            "deadline" => changed.until += TimeDelta::seconds(1),
            "key" => changed.key = digest(),
            "actor" => changed.actor = "other-admin".into(),
            _ => unreachable!(),
        }
        assert_eq!(f.create(&changed).await, CreateOutcome::Conflict, "{field}");
    }
    for tenant_scope in [true, false] {
        let mut changed = hold.clone();
        if tenant_scope {
            changed.tenant = TenantId::parse("tenant_other").unwrap();
        } else {
            changed.site = SiteId::parse("site_other").unwrap();
        }
        assert_eq!(f.create(&changed).await, CreateOutcome::TargetUnavailable);
        let release = ReleaseRequest::new(&changed);
        assert_eq!(f.release(&release).await, ReleaseOutcome::NotFound);
    }
    let release = ReleaseRequest::new(&hold);
    let released = f.released(&release).await;
    assert_eq!(released.released_by.as_deref(), Some("second-audit-admin"));
    assert_eq!(released.released_event_id.as_ref(), Some(&release.event));
    assert_eq!(
        f.release(&release).await,
        ReleaseOutcome::Existing(released.clone())
    );
    let mut retry = release.clone();
    retry.event = event_id();
    assert_eq!(
        f.release(&retry).await,
        ReleaseOutcome::Existing(released.clone())
    );
    for field in ["actor", "reason", "digest", "key"] {
        let mut changed = release.clone();
        match field {
            "actor" => changed.actor = "other-admin".into(),
            "reason" => changed.reason.push_str(" changed"),
            "digest" => changed.digest = digest(),
            "key" => changed.key = digest(),
            _ => unreachable!(),
        }
        assert_eq!(
            f.release(&changed).await,
            ReleaseOutcome::Conflict,
            "{field}"
        );
    }
    assert_eq!(f.create(&hold).await, CreateOutcome::Existing(released));
    let renewed = f.hold(&hold.case, &hold.artifact).await;
    f.created(&renewed).await;
    let mut reused_release = release.clone();
    reused_release.hold = renewed.event.clone();
    assert_eq!(f.release(&reused_release).await, ReleaseOutcome::Conflict);
    assert_eq!(f.counts().await, (2, 3));
    assert_event(f, &hold, &hold.event, "evidence.hold.created").await;
    assert_event(f, &hold, &release.event, "evidence.hold.released").await;
}

async fn assert_event(f: &Fixture, hold: &HoldRequest, event: &EventId, event_type: &str) {
    let (aggregate, stored_type, envelope) = f.event(event).await;
    assert_eq!(aggregate, hold.artifact.as_str());
    assert_eq!(stored_type, event_type);
    assert_eq!(envelope["schema_version"], 3);
    assert_eq!(envelope["event_id"], event.as_str());
    assert_eq!(envelope["event_type"], event_type);
    assert_eq!(envelope["tenant_id"], hold.tenant.as_str());
    assert_eq!(envelope["site_id"], hold.site.as_str());
    assert_eq!(envelope["evidence_refs"], json!([hold.artifact.as_str()]));
    assert_eq!(envelope["payload"]["artifact_id"], hold.artifact.as_str());
    assert_eq!(envelope["payload"]["case_id"], hold.case.as_str());
    assert_eq!(envelope["payload"]["outcome"], "PASS");
    assert_eq!(envelope["payload"]["confidence"], Value::Null);
    assert_eq!(envelope["payload"]["confidence_status"], "not_applicable");
    for key in [
        "occurred_at",
        "observed_at",
        "trace_id",
        "span_id",
        "producer_id",
        "producer_boot_id",
        "policy_revision",
    ] {
        assert!(
            envelope[key]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "{key}"
        );
    }
    assert!(envelope["producer_seq"].as_u64().is_some());
    assert!(envelope["request_seq"].as_u64().is_some());
}

async fn assert_target_state_and_read_expiry(f: &Fixture) {
    let hold = f.target().await;
    let missing = f.hold(&f.case().await, &hold.artifact).await;
    assert_eq!(f.create(&missing).await, CreateOutcome::TargetUnavailable);
    sqlx::query("UPDATE xshield.investigation_cases SET status='closed' WHERE case_id=$1")
        .bind(hold.case.as_str())
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(f.create(&hold).await, CreateOutcome::TargetUnavailable);
    sqlx::query("UPDATE xshield.investigation_cases SET status='open' WHERE case_id=$1")
        .bind(hold.case.as_str())
        .execute(&f.pool)
        .await
        .unwrap();
    let expiry = f.expire_artifact(&hold.artifact).await;
    let record = f.created(&hold).await;
    assert!(
        f.store
            .find_artifact(EvidenceCatalogArtifactQuery::new(
                &f.tenant,
                &f.site,
                &hold.artifact,
            ))
            .await
            .unwrap()
            .is_none()
    );
    let (deadline, access): (DateTime<Utc>, i64) = sqlx::query_as(
        "SELECT expires_at,(SELECT count(*) FROM xshield.evidence_access_requests WHERE artifact_id=$1)
         FROM xshield.artifact_catalog WHERE artifact_id=$1",
    ).bind(hold.artifact.as_str()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(expiry, deadline);
    assert_eq!(access, 0);
    assert!(
        f.store
            .prepare_evidence_purge(&f.tenant, &f.site, KEY_ID, 8)
            .await
            .unwrap()
            .is_empty()
    );
    sqlx::query("UPDATE xshield.investigation_cases SET status='closed' WHERE case_id=$1")
        .bind(hold.case.as_str())
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(f.create(&hold).await, CreateOutcome::Existing(record));
    f.released(&ReleaseRequest::new(&hold)).await;
    let jobs = f
        .store
        .prepare_evidence_purge(&f.tenant, &f.site, KEY_ID, 8)
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].artifact().artifact_id(), &hold.artifact);
    f.store
        .finish_evidence_purge(&jobs[0], EvidencePurgeResult::Unavailable)
        .await
        .unwrap();
    sqlx::query("UPDATE xshield.investigation_cases SET status='open' WHERE case_id=$1")
        .bind(hold.case.as_str())
        .execute(&f.pool)
        .await
        .unwrap();
    let after_intent = f.hold(&hold.case, &hold.artifact).await;
    assert_eq!(
        f.create(&after_intent).await,
        CreateOutcome::TargetUnavailable
    );
    assert_eq!(
        f.store
            .prepare_evidence_purge(&f.tenant, &f.site, KEY_ID, 8)
            .await
            .unwrap()
            .len(),
        1
    );
    let deleted = f.target().await;
    sqlx::query("UPDATE xshield.artifact_catalog SET status='deleted',deleted_at=clock_timestamp() WHERE artifact_id=$1")
        .bind(deleted.artifact.as_str()).execute(&f.pool).await.unwrap();
    assert_eq!(f.create(&deleted).await, CreateOutcome::TargetUnavailable);
    let mut invalid = f.target().await;
    for until in [
        f.now().await - TimeDelta::seconds(1),
        f.now().await + TimeDelta::days(31),
    ] {
        invalid.until = until;
        assert!(matches!(
            f.store.create_case_evidence_hold(invalid.command()).await,
            Err(StoreError::InvalidCommand)
        ));
    }
}

async fn insert_collision(f: &Fixture, event: &EventId) {
    sqlx::query("INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope) VALUES ($1,$2,$3,'collision','fixture','{}')")
        .bind(event.as_str()).bind(f.tenant.as_str()).bind(f.site.as_str())
        .execute(&f.pool).await.unwrap();
}

async fn delete_event(f: &Fixture, event: &EventId) {
    sqlx::query("DELETE FROM xshield.audit_outbox WHERE event_id=$1")
        .bind(event.as_str())
        .execute(&f.pool)
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)]
async fn assert_outbox_atomicity_and_integrity(f: &Fixture) {
    let hold = f.target().await;
    insert_collision(f, &hold.event).await;
    assert!(
        f.store
            .create_case_evidence_hold(hold.command())
            .await
            .is_err()
    );
    assert_eq!(f.counts().await, (0, 0));
    delete_event(f, &hold.event).await;
    let created = f.created(&hold).await;
    let release = ReleaseRequest::new(&hold);
    insert_collision(f, &release.event).await;
    assert!(
        f.store
            .release_case_evidence_hold(release.command())
            .await
            .is_err()
    );
    assert_eq!(f.create(&hold).await, CreateOutcome::Existing(created));
    assert_eq!(f.counts().await, (1, 1));
    delete_event(f, &release.event).await;
    f.released(&release).await;
    for (event, creation) in [(&hold.event, true), (&release.event, false)] {
        let (aggregate, event_type, envelope) = f.event(event).await;
        for mutation in ["aggregate", "type", "payload", "missing"] {
            match mutation {
                "aggregate" => {
                    sqlx::query("UPDATE xshield.audit_outbox SET aggregate_ref='wrong-target' WHERE event_id=$1")
                        .bind(event.as_str()).execute(&f.pool).await.unwrap();
                }
                "type" => {
                    sqlx::query(
                        "UPDATE xshield.audit_outbox SET event_type='fixture' WHERE event_id=$1",
                    )
                    .bind(event.as_str())
                    .execute(&f.pool)
                    .await
                    .unwrap();
                }
                "payload" => {
                    sqlx::query("UPDATE xshield.audit_outbox SET envelope=jsonb_set(envelope,'{payload,artifact_id}','\"wrong-target\"') WHERE event_id=$1")
                        .bind(event.as_str()).execute(&f.pool).await.unwrap();
                }
                "missing" => delete_event(f, event).await,
                _ => unreachable!(),
            }
            if creation {
                assert!(
                    f.store
                        .create_case_evidence_hold(hold.command())
                        .await
                        .is_err(),
                    "{mutation}"
                );
            } else {
                assert!(
                    f.store
                        .release_case_evidence_hold(release.command())
                        .await
                        .is_err(),
                    "{mutation}"
                );
            }
            sqlx::query(
                "INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope)
                 VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (event_id)
                 DO UPDATE SET aggregate_ref=$4,event_type=$5,envelope=$6",
            ).bind(event.as_str()).bind(f.tenant.as_str()).bind(f.site.as_str())
                .bind(&aggregate).bind(&event_type).bind(&envelope).execute(&f.pool).await.unwrap();
        }
    }
    assert_eq!(f.counts().await, (1, 2));
}

async fn actor_pool(url: &str) -> (PgPool, PostgresIdentityStore, i32) {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let store = PostgresIdentityStore::from_pool(pool.clone());
    (pool, store, pid)
}

async fn wait_blocked(pool: &PgPool, waiter: i32, blocker: i32) {
    // Eventually-true observation of the lock queue: generous so a loaded machine
    // does not fail the test; a real regression still fails at the bound.
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let queued: bool = sqlx::query_scalar("SELECT $2=ANY(pg_blocking_pids($1))")
                .bind(waiter)
                .bind(blocker)
                .fetch_one(pool)
                .await
                .unwrap();
            if queued {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("production transaction reached the expected database lock");
}

async fn assert_purge_lock_order(f: &Fixture, hold_first: bool) {
    let hold = f.target().await;
    f.expire_artifact(&hold.artifact).await;
    let (hold_pool, hold_store, hold_pid) = actor_pool(&f.url).await;
    let (purge_pool, purge_store, purge_pid) = actor_pool(&f.url).await;
    let mut blocker = f.pool.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT 1 FROM xshield.artifact_catalog WHERE artifact_id=$1 FOR UPDATE")
        .bind(hold.artifact.as_str())
        .execute(&mut *blocker)
        .await
        .unwrap();
    if hold_first {
        let (created, purged, ()) = tokio::join!(
            hold_store.create_case_evidence_hold(hold.command()),
            async {
                wait_blocked(&f.pool, hold_pid, blocker_pid).await;
                purge_store
                    .prepare_evidence_purge(&f.tenant, &f.site, KEY_ID, 8)
                    .await
            },
            async {
                wait_blocked(&f.pool, purge_pid, hold_pid).await;
                blocker.commit().await.unwrap();
            },
        );
        assert!(matches!(created.unwrap(), CreateOutcome::Created(_)));
        assert!(
            purged.unwrap().is_empty(),
            "post-lock snapshot must see the committed hold"
        );
    } else {
        let (purged, created, ()) = tokio::join!(
            purge_store.prepare_evidence_purge(&f.tenant, &f.site, KEY_ID, 8),
            async {
                wait_blocked(&f.pool, purge_pid, blocker_pid).await;
                hold_store.create_case_evidence_hold(hold.command()).await
            },
            async {
                wait_blocked(&f.pool, hold_pid, purge_pid).await;
                blocker.commit().await.unwrap();
            },
        );
        assert_eq!(purged.unwrap().len(), 1);
        assert_eq!(created.unwrap(), CreateOutcome::TargetUnavailable);
    }
    hold_pool.close().await;
    purge_pool.close().await;
}

async fn assert_expiry_and_multiple_cases(f: &Fixture) {
    let first = f.target().await;
    let second_case = f.case().await;
    f.member(&second_case, &first.artifact).await;
    let mut second = f.hold(&second_case, &first.artifact).await;
    second.until = f.now().await + TimeDelta::seconds(1);
    f.expire_artifact(&first.artifact).await;
    f.created(&first).await;
    let second_record = f.created(&second).await;
    f.released(&ReleaseRequest::new(&first)).await;
    assert!(
        f.store
            .prepare_evidence_purge(&f.tenant, &f.site, KEY_ID, 8)
            .await
            .unwrap()
            .is_empty()
    );
    wait_until(f, second.until).await;
    assert_eq!(
        f.create(&second).await,
        CreateOutcome::Existing(second_record)
    );
    let third = f.hold(&second.case, &second.artifact).await;
    assert_eq!(
        f.create(&third).await,
        CreateOutcome::Conflict,
        "expired holds require explicit release"
    );
    let jobs = f
        .store
        .prepare_evidence_purge(&f.tenant, &f.site, KEY_ID, 8)
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    let intent: String = sqlx::query_scalar(
        "SELECT purge_requested_event_id FROM xshield.artifact_catalog WHERE artifact_id=$1",
    )
    .bind(first.artifact.as_str())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    // This explicit row injection models a wall-clock rollback making an old,
    // unreleased hold active again after the purge intent was already committed.
    sqlx::query("UPDATE xshield.case_evidence_holds SET hold_until=$2 WHERE created_event_id=$1")
        .bind(second.event.as_str())
        .bind(f.now().await + TimeDelta::hours(1))
        .execute(&f.pool)
        .await
        .unwrap();
    let retries = f
        .store
        .prepare_evidence_purge(&f.tenant, &f.site, KEY_ID, 8)
        .await
        .unwrap();
    assert_eq!(retries.len(), 1);
    f.store
        .finish_evidence_purge(&retries[0], EvidencePurgeResult::Unavailable)
        .await
        .unwrap();
    let retried_intent: String = sqlx::query_scalar(
        "SELECT purge_requested_event_id FROM xshield.artifact_catalog WHERE artifact_id=$1",
    )
    .bind(first.artifact.as_str())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(intent, retried_intent);
    sqlx::query("UPDATE xshield.case_evidence_holds SET hold_until=$2 WHERE created_event_id=$1")
        .bind(second.event.as_str())
        .bind(second.until)
        .execute(&f.pool)
        .await
        .unwrap();
    f.released(&ReleaseRequest::new(&second)).await;
    assert_eq!(f.create(&third).await, CreateOutcome::TargetUnavailable);
    assert_eq!(
        f.store
            .prepare_evidence_purge(&f.tenant, &f.site, KEY_ID, 8)
            .await
            .unwrap()
            .len(),
        1
    );
}

async fn assert_deadline_after_lock_wait(f: &Fixture, outbox_wait: bool) {
    let mut hold = f.target().await;
    let (pool, store, pid) = actor_pool(&f.url).await;
    let mut blocker = f.pool.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    if outbox_wait {
        sqlx::query("INSERT INTO xshield.audit_outbox (event_id,tenant_id,site_id,aggregate_ref,event_type,envelope)
                     VALUES ($1,$2,$3,'collision','fixture','{}')")
            .bind(hold.event.as_str()).bind(f.tenant.as_str()).bind(f.site.as_str())
            .execute(&mut *blocker).await.unwrap();
    } else {
        sqlx::query("SELECT 1 FROM xshield.artifact_catalog WHERE artifact_id=$1 FOR UPDATE")
            .bind(hold.artifact.as_str())
            .execute(&mut *blocker)
            .await
            .unwrap();
    }
    hold.until = f.now().await + TimeDelta::milliseconds(300);
    let (result, ()) = tokio::join!(store.create_case_evidence_hold(hold.command()), async {
        wait_blocked(&f.pool, pid, blocker_pid).await;
        wait_until(f, hold.until).await;
        blocker.rollback().await.unwrap();
    },);
    assert!(matches!(result, Err(StoreError::InvalidCommand)));
    assert_eq!(f.counts().await, (0, 0));
    pool.close().await;
}

async fn assert_database_duration_across_dst(f: &Fixture) {
    let hold = f.target().await;
    for start in ["2026-03-01T00:00:00Z", "2026-10-20T00:00:00Z"] {
        let created = DateTime::parse_from_rfc3339(start)
            .unwrap()
            .with_timezone(&Utc);
        for extra_millis in [0, 1] {
            let mut transaction = f.pool.begin().await.unwrap();
            sqlx::query("SET LOCAL TIME ZONE 'America/New_York'")
                .execute(&mut *transaction)
                .await
                .unwrap();
            // Direct rolled-back rows isolate the migration's interval check
            // from command validation, including spring and autumn DST changes.
            let result = sqlx::query(
                "INSERT INTO xshield.case_evidence_holds
                 (tenant_id,site_id,case_id,artifact_id,created_event_id,created_by,reason,
                  created_at,hold_until,idempotency_digest,request_digest)
                 VALUES ($1,$2,$3,$4,$5,'audit-admin','DST boundary',$6,$7,$8,$9)",
            )
            .bind(f.tenant.as_str())
            .bind(f.site.as_str())
            .bind(hold.case.as_str())
            .bind(hold.artifact.as_str())
            .bind(hold.event.as_str())
            .bind(created)
            .bind(created + TimeDelta::hours(720) + TimeDelta::milliseconds(extra_millis))
            .bind(hold.key.as_slice())
            .bind(hold.digest.as_slice())
            .execute(&mut *transaction)
            .await;
            if extra_millis == 0 {
                assert!(result.is_ok(), "exact 720 hours across {start}: {result:?}");
            } else {
                assert!(matches!(result, Err(sqlx::Error::Database(error))
                    if error.code().as_deref() == Some("23514")));
            }
            transaction.rollback().await.unwrap();
        }
    }
    assert_eq!(f.counts().await, (0, 0));
}

async fn wait_until(f: &Fixture, deadline: DateTime<Utc>) {
    tokio::time::timeout(Duration::from_secs(4), async {
        while f.now().await <= deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn assert_history_capacity(f: &Fixture) {
    let first = f.target().await;
    for _ in 0..127 {
        let hold = f.hold(&first.case, &first.artifact).await;
        f.created(&hold).await;
        f.released(&ReleaseRequest::new(&hold)).await;
    }
    let last = f.hold(&first.case, &first.artifact).await;
    let record = f.created(&last).await;
    assert_eq!(f.create(&last).await, CreateOutcome::Existing(record));
    f.released(&ReleaseRequest::new(&last)).await;
    let overflow = f.hold(&first.case, &first.artifact).await;
    assert_eq!(f.create(&overflow).await, CreateOutcome::CapacityExceeded);
    assert_eq!(f.counts().await, (128, 256));
}

async fn assert_scope_capacity(f: &Fixture) {
    let artifact = f.artifact().await;
    let mut first = None;
    // Share one authenticated catalog object; capacity is holds per scope and
    // history per case, so no duplicate ciphertext fixture is necessary.
    for _ in 0..999 {
        let case = f.case().await;
        f.member(&case, &artifact).await;
        let hold = f.hold(&case, &artifact).await;
        f.created(&hold).await;
        first.get_or_insert(hold);
    }
    let left_case = f.case().await;
    let right_case = f.case().await;
    f.member(&left_case, &artifact).await;
    f.member(&right_case, &artifact).await;
    let left = f.hold(&left_case, &artifact).await;
    let right = f.hold(&right_case, &artifact).await;
    let expiring_case = f.case().await;
    f.member(&expiring_case, &artifact).await;
    let mut expiring = f.hold(&expiring_case, &artifact).await;
    expiring.until = f.now().await + TimeDelta::seconds(1);
    f.created(&expiring).await;
    assert_eq!(f.create(&left).await, CreateOutcome::CapacityExceeded);
    wait_until(f, expiring.until).await;
    let (a, b) = tokio::join!(f.create(&left), f.create(&right));
    assert_eq!(
        [&a, &b]
            .iter()
            .filter(|r| matches!(r, CreateOutcome::Created(_)))
            .count(),
        1
    );
    assert_eq!(
        [&a, &b]
            .iter()
            .filter(|r| matches!(r, CreateOutcome::CapacityExceeded))
            .count(),
        1
    );
    let rejected = if matches!(a, CreateOutcome::Created(_)) {
        &right
    } else {
        &left
    };
    assert_eq!(f.counts().await, (1001, 1001));
    f.released(&ReleaseRequest::new(&first.unwrap())).await;
    f.created(rejected).await;
    assert_eq!(f.counts().await, (1002, 1003));
}

async fn cleanup(pool: &PgPool, tenant: &TenantId, root: &Path) {
    for statement in [
        "DELETE FROM xshield.case_evidence_holds WHERE tenant_id=$1",
        "DELETE FROM xshield.case_items WHERE tenant_id=$1",
        "DELETE FROM xshield.artifact_catalog WHERE tenant_id=$1",
        "DELETE FROM xshield.investigation_cases WHERE tenant_id=$1",
        "DELETE FROM xshield.audit_outbox WHERE tenant_id=$1",
    ] {
        sqlx::query(statement)
            .bind(tenant.as_str())
            .execute(pool)
            .await
            .unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

fn event_id() -> EventId {
    EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap()
}

fn digest() -> [u8; 32] {
    Uuid::now_v7().as_bytes().repeat(2).try_into().unwrap()
}
