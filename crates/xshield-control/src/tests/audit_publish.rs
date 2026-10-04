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
const TARGET_GRANT_ID: &str = "grant_018f2a3b-4c5d-7000-8000-000000000953";
const TARGET_BINDING_ID: &str = "auth_018f2a3b-4c5d-7000-8000-000000000954";
const HOLD: &str = "ev_018f2a3b-4c5d-7000-8000-000000000955";

struct AccessJournal {
    root: PathBuf,
    config: PublisherConfig,
    events: Vec<Value>,
}

impl AccessJournal {
    fn for_fixture(fixture: &Fixture) -> Self {
        let root = fixture.access_directory.parent().unwrap().to_owned();
        Self {
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
        }
    }

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

#[allow(clippy::too_many_lines)]
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
        [
            ManagementRole::Investigator,
            ManagementRole::Observer,
            ManagementRole::AuditAdministrator,
        ],
        [(
            TenantId::parse("tenant_a").unwrap(),
            SiteId::parse("site_a").unwrap(),
        )],
    )
    .unwrap();
    let mut journal = AccessJournal::for_fixture(&fixture);
    append_access_contracts(&fixture.control);
    append_hold_access_contracts(&fixture.control);
    let app = router(fixture.control);
    for (method, path, body) in [
        (
            "GET",
            "/control/v1/cases?cursor=bad".to_owned(),
            String::new(),
        ),
        (
            "GET",
            format!("/control/v1/cases/{CASE}/items?cursor=bad"),
            String::new(),
        ),
        ("GET", "/control/v1/grants/bad".to_owned(), String::new()),
        (
            "GET",
            "/control/v1/evidence-access-requests?view=invalid".to_owned(),
            String::new(),
        ),
        (
            "GET",
            "/control/v1/exports?view=invalid".to_owned(),
            String::new(),
        ),
        (
            "GET",
            "/control/v1/evidence-access-requests/bad".to_owned(),
            String::new(),
        ),
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
        (
            "POST",
            "/control/v1/cases/bad/holds".to_owned(),
            "{}".to_owned(),
        ),
        (
            "POST",
            "/control/v1/evidence-holds/bad/release".to_owned(),
            "{}".to_owned(),
        ),
        (
            "GET",
            "/control/v1/cases/bad/holds".to_owned(),
            String::new(),
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
            "console.case.list",
            "console.evidence.hold.created",
            "console.evidence.hold.released",
            "console.evidence.hold.read",
            "console.evidence.access.read",
            "console.evidence.access.list",
            "console.export.list",
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
            Some(&GrantId::parse(TARGET_GRANT_ID).unwrap()),
            None,
            None,
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
            Some(&crate::AuthBindingId::parse(TARGET_BINDING_ID).unwrap()),
            None,
            None,
        )
        .unwrap();
    for action in [
        HEALTH_ACCESS,
        crate::case_list::ACCESS,
        crate::evidence_access_inspection::ACCESS,
        crate::evidence_access_list::ACCESS,
        crate::export_list::ACCESS,
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
            crate::evidence_access_list::ACCESS,
            None,
            None,
            None,
            None,
            "CONTROL_EVIDENCE_ACCESS_LIST_READ",
            vec![],
        ),
        (
            crate::export_list::ACCESS,
            None,
            None,
            None,
            None,
            "CONTROL_EXPORTS_READ",
            vec![],
        ),
        (
            crate::evidence_access_inspection::ACCESS,
            None,
            Some(&artifact),
            Some(&case),
            Some(&access),
            "CONTROL_EVIDENCE_ACCESS_READ",
            vec![artifact.as_str()],
        ),
        (
            crate::case_list::ACCESS,
            None,
            None,
            None,
            None,
            "CONTROL_CASES_READ",
            vec![],
        ),
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
    // An event the publisher rejects stops its whole segment, so every failure
    // the export list records itself must be publishable. The shared
    // authentication refusals are covered by the worker's exact-reason tests;
    // the real-ClickHouse variant of this journal caps a query at 100 events.
    for (outcome, reason) in crate::export_list::recorded_failures() {
        control
            .append_access_event(
                &format!("req_{}", Uuid::now_v7()),
                Some("operator-1"),
                crate::export_list::ACCESS,
                None,
                outcome,
                reason,
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
                None,
                None,
            )
            .unwrap();
    }
}

fn append_hold_access_contracts(control: &ControlPlane) {
    let create = crate::AccessAction {
        event_type: "console.evidence.hold.created",
        method: "POST",
        path: "/control/v1/cases/{case_id}/holds",
        role: ManagementRole::AuditAdministrator,
    };
    let release = crate::AccessAction {
        event_type: "console.evidence.hold.released",
        method: "POST",
        path: "/control/v1/evidence-holds/{hold_id}/release",
        role: ManagementRole::AuditAdministrator,
    };
    let read = crate::AccessAction {
        event_type: "console.evidence.hold.read",
        method: "GET",
        path: "/control/v1/cases/{case_id}/holds",
        role: ManagementRole::AuditAdministrator,
    };
    let case = CaseId::parse(CASE).unwrap();
    let hold = EventId::parse(HOLD).unwrap();
    let artifact = ArtifactId::parse(MISSING_ARTIFACT_ID).unwrap();
    for (action, reason, evidence) in [
        (create, "CONTROL_EVIDENCE_HOLD_CREATED", true),
        (create, "CONTROL_EVIDENCE_HOLD_CREATE_REPLAYED", true),
        (release, "CONTROL_EVIDENCE_HOLD_RELEASED", true),
        (release, "CONTROL_EVIDENCE_HOLD_RELEASE_REPLAYED", true),
        (read, "CONTROL_EVIDENCE_HOLD_READ", true),
        (read, "CONTROL_EVIDENCE_HOLD_READ", false),
    ] {
        let mutation = action.method == "POST";
        let refs = if evidence {
            vec![artifact.as_str()]
        } else {
            vec![]
        };
        control
            .append_access_event_with_evidence_bytes(
                &format!("req_{}", Uuid::now_v7()),
                Some("operator-1"),
                action,
                None,
                mutation.then_some(&artifact),
                Some(&case),
                None,
                None,
                "PASS",
                reason,
                &refs,
                None,
                None,
                None,
                None,
                mutation.then_some(&hold),
                None,
            )
            .unwrap();
    }
    for action in [create, release, read] {
        for (outcome, reason) in [
            ("DENY", "CONTROL_AUTH_REQUIRED"),
            ("ERROR", "CONTROL_EVIDENCE_HOLD_STORE_UNAVAILABLE"),
        ] {
            control
                .append_access_event_with_evidence_bytes(
                    &format!("req_{}", Uuid::now_v7()),
                    Some("operator-1"),
                    action,
                    None,
                    None,
                    None,
                    None,
                    None,
                    outcome,
                    reason,
                    &[],
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();
        }
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
    assert_reference_search_http(&journal, client).await;
}

/// Exercise the HTTP plan and cursor against published production access records.
#[allow(clippy::too_many_lines)]
async fn assert_reference_search_http(journal: &AccessJournal, client: &Client) {
    let mut fixture = Fixture::with_index(200, ManagementRole::Investigator, client.clone());
    let mut searches = AccessJournal::for_fixture(&fixture);
    fixture.control.config.principal = ManagementPrincipal::new(
        "operator-1",
        [
            ManagementRole::Investigator,
            ManagementRole::AuditAdministrator,
        ],
        [(
            fixture.control.config.tenant_id.clone(),
            fixture.control.config.site_id.clone(),
        )],
    )
    .unwrap();
    fixture.control.config.publisher = journal.config.clone();
    fixture.control.config.source_journal_key_id = "control-key-r1".to_owned();
    let app = router(fixture.control);
    let now = Utc::now();
    let start = (now - chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let end = (now + chrono::Duration::hours(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let mut query_count = 0;
    for (by_case, by_artifact) in [(true, false), (false, true), (true, true)] {
        let mut expected = journal
            .events
            .iter()
            .filter(|event| {
                let case_matches = event["payload"]["target_case_id"] == CASE;
                let artifact_matches = event["payload"]["target_artifact_id"]
                    == MISSING_ARTIFACT_ID
                    || event["evidence_refs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|value| value == MISSING_ARTIFACT_ID);
                (!by_case || case_matches) && (!by_artifact || artifact_matches)
            })
            .collect::<Vec<_>>();
        assert!(!expected.is_empty());
        expected.sort_by_key(|event| {
            (
                DateTime::parse_from_rfc3339(event["occurred_at"].as_str().unwrap()).unwrap(),
                event["event_id"].as_str().unwrap(),
            )
        });
        for descending in [false, true] {
            let mut filters = Vec::new();
            if by_case {
                filters.push(json!({"kind": "case_id", "value": CASE}));
            }
            if by_artifact {
                filters.push(json!({"kind": "artifact_id", "value": MISSING_ARTIFACT_ID}));
            }
            let mut payload = json!({
                "schema_version": 3, "start": start, "end": end,
                "sort": if descending { "occurred_at_desc" } else { "occurred_at_asc" },
                "limit": 1, "filters": filters,
            });
            let mut expected_ids = expected
                .iter()
                .map(|event| event["event_id"].clone())
                .collect::<Vec<_>>();
            if descending {
                expected_ids.reverse();
            }
            for (index, event_id) in expected_ids.iter().enumerate() {
                let response = app
                    .clone()
                    .oneshot(search_http_request(&payload))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()["cache-control"], "private, no-store");
                let body: Value = serde_json::from_slice(
                    &to_bytes(response.into_body(), 64 * 1024).await.unwrap(),
                )
                .unwrap();
                query_count += 1;
                assert_eq!(body["events"].as_array().unwrap().len(), 1);
                assert_eq!(body["events"][0]["event_id"], *event_id);
                assert!(body["events"][0].get("payload_json").is_none());
                assert!(body["events"][0].get("target_case_id").is_none());
                assert!(!body["index_watermark"].is_null());
                assert_eq!(body["has_gaps"], false);
                let more = index + 1 < expected_ids.len();
                assert_eq!(body["truncated"], more);
                assert_eq!(body["next_cursor"].is_string(), more);
                payload["cursor"] = body["next_cursor"].clone();
            }
        }
    }
    for (kind, target, target_field) in [
        ("grant_id", TARGET_GRANT_ID, "target_grant_id"),
        ("auth_binding_id", TARGET_BINDING_ID, "target_binding_id"),
    ] {
        let expected = journal
            .events
            .iter()
            .filter(|event| event["payload"][target_field] == target)
            .collect::<Vec<_>>();
        assert_eq!(expected.len(), 1);
        let payload = json!({
            "schema_version": 3,
            "start": start,
            "end": end,
            "sort": "occurred_at_asc",
            "limit": 1,
            "filters": [{"kind": kind, "value": target}],
        });
        let response = app
            .clone()
            .oneshot(search_http_request(&payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        query_count += 1;
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"][0]["event_id"], expected[0]["event_id"]);
        assert!(body["events"][0].get(target_field).is_none());
        assert!(!body["events"][0].to_string().contains(target));
        assert_eq!(body["truncated"], false);
        assert!(body["next_cursor"].is_null());
        assert!(!body["index_watermark"].is_null());
    }
    let mut expected_hold = journal
        .events
        .iter()
        .filter(|event| {
            matches!(
                event["event_type"].as_str(),
                Some("console.evidence.hold.created" | "console.evidence.hold.released")
            ) && event["payload"]["target_hold_id"] == HOLD
        })
        .collect::<Vec<_>>();
    assert_eq!(expected_hold.len(), 4);
    expected_hold.sort_by_key(|event| {
        (
            DateTime::parse_from_rfc3339(event["occurred_at"].as_str().unwrap()).unwrap(),
            event["event_id"].as_str().unwrap(),
        )
    });
    for descending in [false, true] {
        let mut expected_ids = expected_hold
            .iter()
            .map(|event| event["event_id"].clone())
            .collect::<Vec<_>>();
        if descending {
            expected_ids.reverse();
        }
        let mut payload = json!({
            "schema_version": 3,
            "start": start,
            "end": end,
            "sort": if descending { "occurred_at_desc" } else { "occurred_at_asc" },
            "limit": 1,
            "filters": [{"kind": "evidence_hold_id", "value": HOLD}],
        });
        for (index, event_id) in expected_ids.iter().enumerate() {
            let response = app
                .clone()
                .oneshot(search_http_request(&payload))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                    .unwrap();
            query_count += 1;
            assert_eq!(body["events"].as_array().unwrap().len(), 1);
            assert_eq!(body["events"][0]["event_id"], *event_id);
            assert!(body["events"][0].get("payload_json").is_none());
            assert!(body["events"][0].get("target_hold_id").is_none());
            assert!(!body["events"][0].to_string().contains(HOLD));
            let more = index + 1 < expected_ids.len();
            assert_eq!(body["truncated"], more);
            assert_eq!(body["next_cursor"].is_string(), more);
            payload["cursor"] = body["next_cursor"].clone();
        }
    }
    drop(app);
    searches.events = read_access_events(&fixture.access_directory);
    assert_eq!(searches.events.len(), query_count);
    for event in &searches.events {
        assert_eq!(event["event_type"], "console.query.executed");
        assert_eq!(event["payload"]["reason_code"], "CONTROL_QUERY_EXECUTED");
        assert_eq!(event["payload"]["query_digest"].as_str().unwrap().len(), 64);
        assert_eq!(event["evidence_refs"], json!([]));
        let encoded = event.to_string();
        assert!(!encoded.contains(CASE));
        assert!(!encoded.contains(MISSING_ARTIFACT_ID));
        assert!(!encoded.contains(TARGET_GRANT_ID));
        assert!(!encoded.contains(TARGET_BINDING_ID));
        assert!(!encoded.contains(HOLD));
        assert!(event["payload"]["target_grant_id"].is_null());
        assert!(event["payload"]["target_binding_id"].is_null());
    }
    assert_eq!(
        searches.publish(client).await.published_events,
        u64::try_from(query_count).unwrap()
    );
    searches.assert_checkpointed(&searches.publish(client).await);
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
