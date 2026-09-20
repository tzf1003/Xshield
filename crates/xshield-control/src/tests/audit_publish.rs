//! Producer contracts from control access journals through the sealed publisher.

use super::*;
use clickhouse::sql::Identifier;
use serde::Deserialize;
use std::{collections::BTreeSet, path::PathBuf};
use xshield_core::{
    domain::{ArtifactId, CaseId, EvidenceAccessRequestId, GrantId, ModelCallId},
    identity::UnixSeconds,
    query::{QueryFilter, QueryPlan, QuerySort, QueryTextField, QueryWindow},
};
use xshield_worker::{
    PublicationHealth, PublishError, PublishReport, SearchEventSummary, inspect_publication_health,
    publish_sealed_segments, query_audit_events, query_request_events, query_request_summary,
};

const CASE: &str = "case_018f2a3b-4c5d-7000-8000-000000000951";
const ACCESS_REQUEST: &str = "access_018f2a3b-4c5d-7000-8000-000000000952";

struct AccessJournal {
    root: PathBuf,
    config: PublisherConfig,
    events: Vec<Value>,
}

impl AccessJournal {
    async fn publish(&self, client: &Client) -> PublishReport {
        publish_sealed_segments(
            &self.config,
            client,
            "control-key-r1",
            &JournalKey::from_hex(JOURNAL_KEY).unwrap(),
            &test_seal_key(),
        )
        .await
        .unwrap()
    }

    fn health(&self) -> PublicationHealth {
        inspect_publication_health(
            &self.config,
            "control-key-r1",
            &JournalKey::from_hex(JOURNAL_KEY).unwrap(),
            &test_seal_key(),
        )
        .unwrap()
    }

    fn assert_checkpointed(&self, report: &PublishReport) {
        assert_eq!(report.published_events, 0);
        assert_eq!(report.published_segments, 0);
        assert_eq!(report.checkpointed_segments, self.events.len());
        let health = self.health();
        assert_eq!(health.published_segments, self.events.len());
        assert_eq!(health.pending_segments, 0);
        assert_eq!(health.unsealed_segments, 0);
        assert!(!health.has_gaps);
        let watermark = health.index_watermark.unwrap();
        assert_eq!(
            report.watermark_producer_boot_id.as_deref(),
            Some(watermark.producer_boot_id.as_str())
        );
        assert_eq!(
            report.watermark_producer_sequence,
            watermark.producer_sequence
        );
    }
}

impl Drop for AccessJournal {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root) {
            assert!(
                std::thread::panicking(),
                "control journal cleanup failed: {error}"
            );
        }
    }
}

async fn access_journal() -> AccessJournal {
    let mock = test::Mock::new();
    mock.add(test::handlers::provide(Vec::<SearchEventSummary>::new()));
    mock.add(test::handlers::exception(209));
    let mut fixture = Fixture::with_index(
        100,
        ManagementRole::Investigator,
        Client::default().with_mock(&mock),
    );
    fixture.control.config.principal = ManagementPrincipal::new(
        "operator-1",
        [ManagementRole::Investigator, ManagementRole::Observer],
        [(
            TenantId::parse("tenant_a").unwrap(),
            SiteId::parse("site_a").unwrap(),
        )],
    )
    .unwrap();
    let root = fixture.access_directory.parent().unwrap().to_owned();
    let mut journal = AccessJournal {
        config: PublisherConfig::new(
            &fixture.access_directory,
            root.join("access-manifests"),
            root.join("access-checkpoints"),
            "control-index",
            "audit_events",
            30,
            1024 * 1024,
        )
        .unwrap(),
        root,
        events: Vec::new(),
    };
    append_access_contracts(&fixture.control);
    let app = router(fixture.control);
    for (method, path, body) in [
        (
            "GET",
            format!("/control/v1/cases/{CASE}/items?cursor=bad"),
            String::new(),
        ),
        ("GET", "/control/v1/grants/bad".to_owned(), String::new()),
        (
            "GET",
            "/control/v1/auth-bindings/bad".to_owned(),
            String::new(),
        ),
        (
            "POST",
            format!("/control/v1/cases/{CASE}/items"),
            json!({"artifact_id": MISSING_ARTIFACT_ID}).to_string(),
        ),
        (
            "POST",
            format!("/control/v1/cases/{CASE}/close"),
            r#"{"reason":"review complete"}"#.to_owned(),
        ),
    ] {
        for authorized in [false, true] {
            let mut request = Request::builder()
                .method(method)
                .uri(&path)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.clone()))
                .unwrap();
            let expected = if authorized {
                request
                    .headers_mut()
                    .insert(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                expected
            );
        }
    }
    for expected in [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE] {
        let response = app
            .clone()
            .oneshot(search_http_request(&search_payload()))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let response = app.oneshot(search_http_request(&json!({}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    journal.events = read_access_events(&fixture.access_directory);
    assert_access_families(&journal.events);
    journal
}

fn assert_access_families(events: &[Value]) {
    assert_eq!(
        events
            .iter()
            .map(|event| event["event_type"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "console.health.read",
            "console.request.read",
            "console.events.read",
            "console.manifest.read",
            "console.model.read",
            "console.grant.read",
            "console.binding.read",
            "console.query.executed",
            "console.case.read",
            "case.created",
            "case.closed",
            "case.evidence.added",
            "evidence.access.requested",
            "evidence.access.approved",
            "evidence.access.denied",
            "evidence.read",
        ])
    );
    assert!(
        events
            .iter()
            .any(|event| event["payload"]["outcome"] == "ERROR")
    );
}

// The table pairs production actions with their successful target shapes.
#[allow(clippy::too_many_lines)]
fn append_access_contracts(control: &ControlPlane) {
    use crate::{
        ARTIFACT_ACCESS, CASE_CREATE_ACCESS, EVIDENCE_ACCESS_APPROVE, EVIDENCE_ACCESS_DENY,
        EVIDENCE_ACCESS_REQUEST, EVIDENCE_CONTENT_ACCESS, HEALTH_ACCESS, MODEL_CALL_ACCESS,
        REQUEST_EVENTS_ACCESS, REQUEST_EVIDENCE_ACCESS, REQUEST_SUMMARY_ACCESS,
    };
    let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
    let artifact = ArtifactId::parse(MISSING_ARTIFACT_ID).unwrap();
    let case = CaseId::parse(CASE).unwrap();
    let access = EvidenceAccessRequestId::parse(ACCESS_REQUEST).unwrap();
    control
        .append_access_event_with_evidence_bytes(
            &format!("req_{}", Uuid::now_v7()),
            Some("operator-1"),
            crate::ledger_inspection::GRANT_ACCESS,
            None,
            None,
            None,
            None,
            None,
            "PASS",
            "CONTROL_GRANT_READ",
            &[],
            None,
            None,
            Some(&GrantId::parse("grant_018f2a3b-4c5d-7000-8000-000000000953").unwrap()),
            None,
        )
        .unwrap();
    control
        .append_access_event_with_evidence_bytes(
            &format!("req_{}", Uuid::now_v7()),
            Some("operator-1"),
            crate::ledger_inspection::BINDING_ACCESS,
            None,
            None,
            None,
            None,
            None,
            "PASS",
            "CONTROL_BINDING_READ",
            &[],
            None,
            None,
            None,
            Some(
                &crate::AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000954").unwrap(),
            ),
        )
        .unwrap();
    for action in [
        HEALTH_ACCESS,
        REQUEST_EVENTS_ACCESS,
        REQUEST_SUMMARY_ACCESS,
        REQUEST_EVIDENCE_ACCESS,
        ARTIFACT_ACCESS,
        MODEL_CALL_ACCESS,
        CASE_CREATE_ACCESS,
        EVIDENCE_ACCESS_REQUEST,
        EVIDENCE_ACCESS_APPROVE,
        EVIDENCE_ACCESS_DENY,
        EVIDENCE_CONTENT_ACCESS,
    ] {
        control
            .append_access_event(
                &format!("req_{}", Uuid::now_v7()),
                None,
                action,
                None,
                "DENY",
                "CONTROL_AUTH_REQUIRED",
            )
            .unwrap();
    }
    for (action, target_request, target_artifact, target_case, target_access, reason, refs) in [
        (
            HEALTH_ACCESS,
            None,
            None,
            None,
            None,
            "CONTROL_HEALTH_READ",
            vec![],
        ),
        (
            REQUEST_EVENTS_ACCESS,
            Some(&request),
            None,
            None,
            None,
            "CONTROL_EVENTS_READ",
            vec![],
        ),
        (
            REQUEST_SUMMARY_ACCESS,
            Some(&request),
            None,
            None,
            None,
            "CONTROL_REQUEST_READ",
            vec![],
        ),
        (
            REQUEST_EVIDENCE_ACCESS,
            Some(&request),
            None,
            None,
            None,
            "CONTROL_MANIFESTS_READ",
            vec![artifact.as_str()],
        ),
        (
            ARTIFACT_ACCESS,
            None,
            Some(&artifact),
            None,
            None,
            "CONTROL_MANIFEST_READ",
            vec![artifact.as_str()],
        ),
        (
            CASE_CREATE_ACCESS,
            None,
            None,
            Some(&case),
            None,
            "CONTROL_CASE_CREATED",
            vec![],
        ),
        (
            EVIDENCE_ACCESS_REQUEST,
            None,
            Some(&artifact),
            Some(&case),
            Some(&access),
            "CONTROL_EVIDENCE_ACCESS_REQUESTED",
            vec![artifact.as_str()],
        ),
        (
            EVIDENCE_ACCESS_APPROVE,
            None,
            Some(&artifact),
            Some(&case),
            Some(&access),
            "CONTROL_EVIDENCE_ACCESS_APPROVED",
            vec![artifact.as_str()],
        ),
        (
            EVIDENCE_ACCESS_DENY,
            None,
            Some(&artifact),
            Some(&case),
            Some(&access),
            "CONTROL_EVIDENCE_ACCESS_DENIED",
            vec![artifact.as_str()],
        ),
    ] {
        control
            .append_access_event_with_evidence(
                &format!("req_{}", Uuid::now_v7()),
                Some("operator-1"),
                action,
                target_request,
                target_artifact,
                target_case,
                target_access,
                "PASS",
                reason,
                &refs,
            )
            .unwrap();
    }
    control
        .append_model_access_event(
            &format!("req_{}", Uuid::now_v7()),
            Some("operator-1"),
            &ModelCallId::parse(MODEL_CALL_ID).unwrap(),
            "PASS",
            "CONTROL_MODEL_CALL_READ",
            &[artifact.as_str()],
        )
        .unwrap();
    for bytes_read in [0, 64 * 1024 * 1024] {
        control
            .append_access_event_with_evidence_bytes(
                &format!("req_{}", Uuid::now_v7()),
                Some("operator-1"),
                EVIDENCE_CONTENT_ACCESS,
                None,
                Some(&artifact),
                None,
                Some(&access),
                None,
                "PASS",
                "CONTROL_EVIDENCE_READ",
                &[artifact.as_str()],
                Some(bytes_read),
                None,
                None,
                None,
            )
            .unwrap();
    }
}

#[tokio::test]
async fn management_audit_producer_payloads_publish_and_reuse_checkpoints() {
    let journal = access_journal().await;
    let mock = test::Mock::new();
    mock.add(test::handlers::provide(Vec::<AuditEventSummary>::new()));
    mock.add(test::handlers::exception(209));
    let client = Client::default().with_mock(&mock);
    let failed = publish_sealed_segments(
        &journal.config,
        &client,
        "control-key-r1",
        &JournalKey::from_hex(JOURNAL_KEY).unwrap(),
        &test_seal_key(),
    )
    .await;
    assert!(matches!(failed, Err(PublishError::ClickHouse(_))));
    let health = journal.health();
    assert_eq!(health.published_segments, 0);
    assert_eq!(health.pending_segments, journal.events.len());
    assert_eq!(health.index_watermark, None);
    for _ in &journal.events {
        // Empty RowBinary results cover the two digest lookups and insert acknowledgement.
        for _ in 0..3 {
            mock.add(test::handlers::provide(Vec::<AuditEventSummary>::new()));
        }
    }
    let published = journal.publish(&client).await;
    assert_eq!(published.published_segments, journal.events.len());
    assert_eq!(
        published.published_events,
        u64::try_from(journal.events.len()).unwrap()
    );
    journal.assert_checkpointed(&journal.publish(&client).await);
}

#[derive(Deserialize, Row)]
struct PublishedAccess {
    event_id: String,
    stage: String,
    method: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    confidence: Option<f64>,
    confidence_status: String,
    is_terminal: u8,
    evidence_refs: Vec<String>,
    payload_json: String,
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_CLICKHOUSE_URL"]
async fn management_audit_real_schema_publish_query_scope_and_replay() {
    let url = std::env::var("XSHIELD_TEST_CLICKHOUSE_URL")
        .expect("XSHIELD_TEST_CLICKHOUSE_URL must identify a test ClickHouse server");
    let mut admin = Client::default().with_url(url);
    if let Ok(user) = std::env::var("XSHIELD_TEST_CLICKHOUSE_USER") {
        admin = admin.with_user(user);
    }
    if let Ok(password) = std::env::var("XSHIELD_TEST_CLICKHOUSE_PASSWORD") {
        admin = admin.with_password(password);
    }
    let database = format!("xshield_control_audit_test_{}", Uuid::now_v7().simple());
    admin
        .query("CREATE DATABASE ?")
        .bind(Identifier(&database))
        .execute()
        .await
        .unwrap();
    let client = admin.clone().with_database(database.clone());
    let schema_database = database.clone();
    let outcome = tokio::spawn(async move {
        let schema = include_str!("../../../../sql/clickhouse.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n")
            .replace("xshield.", &format!("{schema_database}."));
        for statement in schema.split(';').map(str::trim) {
            if statement.is_empty() || statement == "CREATE DATABASE IF NOT EXISTS xshield" {
                continue;
            }
            client.query(statement).execute().await.unwrap();
        }
        assert_real_control_publication(&client).await;
    })
    .await;
    admin
        .query("DROP DATABASE ? SYNC")
        .bind(Identifier(&database))
        .execute()
        .await
        .expect("cleanup owned control audit database");
    if let Err(error) = outcome {
        if error.is_panic() {
            std::panic::resume_unwind(error.into_panic());
        }
        panic!("control audit regression task was cancelled");
    }
}

async fn assert_real_control_publication(client: &Client) {
    let journal = access_journal().await;
    let published = journal.publish(client).await;
    assert_eq!(
        published.published_events,
        u64::try_from(journal.events.len()).unwrap()
    );
    journal.assert_checkpointed(&journal.publish(client).await);
    assert_index_projections(&journal, client).await;
    assert_control_queries(&journal, client).await;
}

async fn assert_index_projections(journal: &AccessJournal, client: &Client) {
    for table in ["audit_events", "events_by_time"] {
        let rows = client
            .query("SELECT ?fields FROM ?")
            .bind(Identifier(table))
            .fetch_all::<PublishedAccess>()
            .await
            .unwrap();
        assert_eq!(rows.len(), journal.events.len());
        for row in rows {
            let source = journal
                .events
                .iter()
                .find(|event| event["event_id"] == row.event_id)
                .unwrap();
            assert_eq!(row.stage, "control_access");
            assert_eq!(row.proof_kind, "deterministic");
            assert_eq!(row.confidence, None);
            assert_eq!(row.confidence_status, "not_applicable");
            assert_eq!(row.is_terminal, 0);
            assert_eq!(row.method, source["payload"]["method"]);
            assert_eq!(row.outcome, source["payload"]["outcome"]);
            assert_eq!(row.reason_code, source["payload"]["reason_code"]);
            assert_eq!(
                serde_json::to_value(row.evidence_refs).unwrap(),
                source["evidence_refs"]
            );
            assert_eq!(
                serde_json::from_str::<Value>(&row.payload_json).unwrap(),
                source["payload"]
            );
        }
    }
}

async fn assert_control_queries(journal: &AccessJournal, client: &Client) {
    let tenant = TenantId::parse("tenant_a").unwrap();
    let site = SiteId::parse("site_a").unwrap();
    for source in &journal.events {
        let request = RequestId::parse(source["request_id"].as_str().unwrap()).unwrap();
        let timeline =
            query_request_events(&journal.config, client, &tenant, &site, &request, None, 1)
                .await
                .unwrap();
        assert!(!timeline.truncated);
        assert_eq!(timeline.events.len(), 1);
        assert_eq!(timeline.events[0].event_id, source["event_id"]);
        assert_eq!(timeline.events[0].stage, "control_access");
        assert_eq!(timeline.events[0].outcome, source["payload"]["outcome"]);
    }
    let request = RequestId::parse(journal.events[0]["request_id"].as_str().unwrap()).unwrap();
    let summary = query_request_summary(&journal.config, client, &tenant, &site, &request)
        .await
        .unwrap()
        .unwrap();
    assert!(!summary.terminal);
    assert!(!summary.forwarded);
    assert!(!summary.business_result_confirmed);
    assert_eq!(summary.decision, None);
    assert_eq!(
        summary.method.as_deref(),
        journal.events[0]["payload"]["method"].as_str()
    );
    assert_eq!(summary.operation_id, None);
    let now = u64::try_from(Utc::now().timestamp()).unwrap();
    let plan = QueryPlan::new(
        QueryWindow::new(UnixSeconds::new(now - 3600), UnixSeconds::new(now + 3600)).unwrap(),
        vec![QueryFilter::Text {
            field: QueryTextField::Stage,
            value: "control_access".to_owned(),
        }],
        QuerySort::OccurredAtAsc,
        100,
    )
    .unwrap();
    let result = query_audit_events(&journal.config, client, &tenant, &site, &plan, None)
        .await
        .unwrap();
    assert!(!result.truncated);
    assert_eq!(result.events.len(), journal.events.len());
    for row in result.events {
        assert_eq!(row.stage.as_deref(), Some("control_access"));
        assert_eq!(row.proof_kind.as_deref(), Some("deterministic"));
        assert_eq!(row.confidence, None);
        assert_eq!(row.confidence_status.as_deref(), Some("not_applicable"));
    }
    for (other_tenant, other_site) in [
        (TenantId::parse("tenant_b").unwrap(), site.clone()),
        (tenant, SiteId::parse("site_b").unwrap()),
    ] {
        assert!(
            query_request_events(
                &journal.config,
                client,
                &other_tenant,
                &other_site,
                &request,
                None,
                1
            )
            .await
            .unwrap()
            .events
            .is_empty()
        );
        assert!(
            query_audit_events(
                &journal.config,
                client,
                &other_tenant,
                &other_site,
                &plan,
                None
            )
            .await
            .unwrap()
            .events
            .is_empty()
        );
    }
}
