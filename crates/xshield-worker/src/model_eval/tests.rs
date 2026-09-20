use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use xshield_audit::{JournalKey, JournalLimits, LocalJournal};
use xshield_evidence::{EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault};
use xshield_postgres::EvidenceCatalogQuery;

const KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const JOURNAL_KEY: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const API_KEY: &str = "synthetic-evaluation-api-key";
const RESPONSE: &str = r#"{"model":"jev-1.13.0","answers":{"evaluation":{"type":"choice","choice":"UNKNOWN","probabilities":{"NONE":0.2,"UNKNOWN":0.8},"confidence":0.75}},"usage":{"input_tokens":100,"output_tokens":20}}"#;

fn input() -> Input {
    Input::parse(br#"{"schema_version":1,"approval_ref":"synthetic-test-r1","model_revision":"jev-1.13.0","policy_revision":"policy-r1","prompt_revision":"prompt-r1","untrusted_content":"untrusted synthetic content","question":{"type":"choice","instructions":"Choose one candidate.","criteria":{"NONE":"No matching candidate.","UNKNOWN":"Insufficient evidence."}}}"#).unwrap()
}

fn score_input() -> Input {
    let mut approved: serde_json::Value =
        serde_json::from_slice(&input().internal_bytes().unwrap()).unwrap();
    approved["question"] = json!({
        "type": "score",
        "instructions": "Score the synthetic content using the ordered criteria.",
        "criteria": ["Low risk.", "Medium risk.", "High risk."]
    });
    approved["risk_mapping"] = json!({
        "revision":"risk-map-r1", "classes":{"0":"benign","1":"unknown","2":"malicious"}
    });
    Input::parse(&serde_json::to_vec(&approved).unwrap()).unwrap()
}

fn score_response() -> serde_json::Value {
    json!({
        "model": "typesafe-ai/jev",
        "answers": {"evaluation": {
            "type": "score",
            // The expected score differs from the most probable index, zero.
            "score": 0.7,
            "legend": {"0": "Low risk.", "1": "Medium risk.", "2": "High risk."},
            "probabilities": {"0": 0.6, "1": 0.1, "2": 0.3},
            "confidence": 0.75
        }},
        "usage": {"input_tokens": 100, "output_tokens": 20},
        "provider_metadata": {"gateway": {
            "routing": {"originalModelId": "typesafe-ai/jev", "resolvedProvider": "typesafe-ai",
                "canonicalSlug": "typesafe-ai/jev", "finalProvider": "typesafe-ai"},
            "generationId": "gen_synthetic", "cost": "0.00001155",
            "marketCost": "0.00001155", "surchargeCost": "0", "gatewayCost": "0.00001155"
        }}
    })
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = env::temp_dir().join(format!("xshield-model-test-{}", Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        let evidence = root.join("evidence");
        fs::create_dir(&evidence).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { root }
    }
    fn journal(&self) -> LocalJournal {
        LocalJournal::open(
            self.root.join("journal"),
            "model-journal-r1",
            JournalKey::from_hex(JOURNAL_KEY).unwrap(),
            JournalLimits::new(16 * 1024 * 1024, 12 * 1024 * 1024, 1).unwrap(),
        )
        .unwrap()
        .0
    }
    fn storage(&self) -> Storage {
        Storage::open(
            &self.root.join("evidence"),
            "model-evidence-r1",
            KEY,
            32 * 1024 * 1024,
            self.journal(),
        )
        .unwrap()
    }
    fn vault(&self) -> LocalEvidenceVault {
        LocalEvidenceVault::open(
            EvidenceVaultConfig::new(
                self.root.join("evidence"),
                "model-evidence-r1",
                512 * 1024,
                1,
            )
            .unwrap(),
            EvidenceKey::from_hex(KEY).unwrap(),
        )
        .unwrap()
    }
    fn events(&self) -> Vec<serde_json::Value> {
        let journal = self.journal();
        let mut events = Vec::new();
        journal
            .visit_closed_records(1000, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext()).unwrap();
                let indexed = crate::IndexRow::parse(
                    record.plaintext(),
                    record.event_id(),
                    record.producer_sequence(),
                    record.producer_boot_id(),
                    "0".repeat(64),
                    chrono::TimeDelta::days(1),
                )
                .unwrap();
                assert_eq!(indexed.model_revision, "jev-1.13.0");
                assert_eq!(
                    indexed.is_terminal, 0,
                    "a model evaluation is not a business request terminal"
                );
                events.push(event);
                Ok(())
            })
            .unwrap();
        events
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn scope() -> (TenantId, SiteId) {
    (
        TenantId::parse("tenant_model_eval").unwrap(),
        SiteId::parse("site_model_eval").unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_attempt_is_closed_once_and_never_replayed() {
    let fixture = Fixture::new();
    let (tenant, site) = scope();
    let input = input();
    let mut attempt = Attempt::new(&input, tenant, site).unwrap();
    {
        let mut storage = fixture.storage();
        let event = ModelEvent::new(&attempt, &input);
        storage
            .event(&mut attempt, "model.started", &event)
            .unwrap();
    }
    {
        let mut storage = fixture.storage();
        storage.recover().unwrap();
        storage.recover().unwrap();
    }
    let events = fixture.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["event_type"], "model.failed");
    assert_eq!(events[1]["payload"]["reason_code"], "MODEL_OUTCOME_UNKNOWN");
    assert_eq!(events[1]["request_seq"], 9);
    assert_eq!(events[1]["cause_event_ids"][0], events[0]["event_id"]);
    assert_eq!(events[1]["payload"]["confidence"], serde_json::Value::Null);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_capacity_exclusivity_and_input_permissions_are_enforced() {
    let fixture = Fixture::new();
    let lock = File::open(fixture.root.join("evidence")).unwrap();
    lock.try_lock().unwrap();
    assert!(matches!(
        Storage::open(
            &fixture.root.join("evidence"),
            "key-r1",
            KEY,
            32 * 1024 * 1024,
            fixture.journal()
        ),
        Err("MODEL_EVALUATION_BUSY")
    ));
    drop(lock);
    fs::write(fixture.root.join("evidence/full"), vec![0; 3 * 1024 * 1024]).unwrap();
    let (tenant, site) = scope();
    let approved = input();
    let mut attempt = Attempt::new(&approved, tenant, site).unwrap();
    let mut event = ModelEvent::new(&attempt, &approved);
    {
        let mut storage = fixture.storage();
        storage
            .event(&mut attempt, "model.started", &event)
            .unwrap();
    }
    {
        let mut storage = Storage::open(
            &fixture.root.join("evidence"),
            "key-r1",
            KEY,
            3 * 1024 * 1024,
            fixture.journal(),
        )
        .unwrap();
        storage.recover().unwrap();
    }
    assert_eq!(fixture.events().len(), 2);
    // References must remain in the scoped model envelope presented to the index.
    let artifact = format!("artifact_{}", Uuid::now_v7());
    event.input_artifact_id = Some(artifact.clone());
    "requested".clone_into(&mut event.status);
    let (_, envelope) = attempt.envelope("model.requested", &event, &[]).unwrap();
    let mut envelope: crate::WireEvent = serde_json::from_value(envelope).unwrap();
    assert!(ModelEvent::validate_envelope(&envelope).is_err());
    envelope.evidence_refs.push(artifact);
    assert!(ModelEvent::validate_envelope(&envelope).is_ok());
    envelope.request_id = None;
    assert!(ModelEvent::validate_envelope(&envelope).is_err());
    let path = fixture.root.join("approved.json");
    fs::write(&path, approved.internal_bytes().unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_input(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_input(&path).is_ok());
        let link = fixture.root.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_input(&link).is_err());
    }
    fs::write(&path, vec![b' '; 8193]).unwrap();
    assert!(read_input(&path).is_err());
}

#[test]
fn model_event_contract_rejects_confidence_and_lifecycle_contradictions() {
    let (tenant, site) = scope();
    let input = input();
    let attempt = Attempt::new(&input, tenant, site).unwrap();
    let event = ModelEvent::new(&attempt, &input);
    assert!(event.clone().validate("model.started").is_ok());
    assert!(event.clone().validate("model.responded").is_err());
    let mut bad = event.clone();
    bad.confidence = Some(0.9);
    assert!(bad.validate("model.started").is_err());
    let mut bad = event;
    "requested".clone_into(&mut bad.status);
    assert!(bad.validate("model.requested").is_err());
    let mut bad = ModelEvent::new(&attempt, &input);
    bad.provider_model_id = None;
    assert!(bad.validate("model.started").is_err());
    let mut bad = ModelEvent::new(&attempt, &input);
    bad.provider_model_id = Some("untrusted/model".to_owned());
    assert!(bad.validate("model.started").is_err());
    let mut bad = ModelEvent::new(&attempt, &input);
    bad.provider = Some("vercel_ai_gateway".to_owned());
    assert!(bad.validate("model.started").is_err());
    let mut null_fields = serde_json::to_value(ModelEvent::new(&attempt, &input)).unwrap();
    null_fields["provider"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ModelEvent>(null_fields).is_err());
}

async fn server(status: u16, body: &str) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
    let body = body.to_owned();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let (end, length) = loop {
            let mut bytes = [0; 4096];
            let read = socket.read(&mut bytes).await.unwrap();
            assert!(read > 0);
            received.extend_from_slice(&bytes[..read]);
            if let Some(end) = received.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&received[..end])
                    .unwrap()
                    .to_ascii_lowercase();
                assert!(headers.contains(&format!("authorization: bearer {API_KEY}")));
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                break (end + 4, length);
            }
        };
        while received.len() < end + length {
            let mut bytes = [0; 4096];
            let read = socket.read(&mut bytes).await.unwrap();
            assert!(read > 0);
            received.extend_from_slice(&bytes[..read]);
        }
        socket.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nRetry-After: 3\r\nx-request-id: synthetic-call\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        received[end..end + length].to_vec()
    });
    (endpoint, server)
}

struct CountingPort {
    calls: AtomicUsize,
    payload: Arc<Mutex<Vec<u8>>>,
    fail_after_send: Option<sqlx::PgPool>,
}
impl ModelPort for CountingPort {
    async fn send<'a>(
        &'a self,
        payload: &'a [u8],
        _: &'a mut oneshot::Receiver<()>,
    ) -> transport::Exchange {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.payload.lock().unwrap() = payload.to_vec();
        if let Some(pool) = &self.fail_after_send {
            sqlx::query("ALTER TABLE xshield.audit_outbox ADD CONSTRAINT test_model_capture_failure CHECK (tenant_id <> 'tenant_model_eval_capture_failure' OR envelope->>'request_seq' <> '5')")
                .execute(pool).await.unwrap();
        }
        transport::Exchange {
            status: Some(200),
            body: Zeroizing::new(RESPONSE.as_bytes().to_vec()),
            capture_status: "complete",
            failure: None,
            retry_after_seconds: None,
            provider_request_id: None,
            bytes_observed: RESPONSE.len() as u64,
        }
    }
    fn contains_secret(&self, bytes: &[u8]) -> bool {
        bytes
            .windows(API_KEY.len())
            .any(|part| part == API_KEY.as_bytes())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn postgres_evaluation_captures_actual_io_and_dependency_failures() {
    let database = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&database).await.unwrap();
    let store = PostgresIdentityStore::connect(&database, 2, Duration::from_secs(5))
        .await
        .unwrap();
    for (status, body, expected, confidence, objects) in [
        (200, RESPONSE, "MODEL_EVALUATED", Some(0.75), 4),
        (429, r#"{"error":"quota"}"#, "MODEL_RATE_LIMITED", None, 4),
        (
            200,
            r#"{"unexpected":true}"#,
            "MODEL_RESPONSE_INVALID",
            None,
            4,
        ),
        (200, API_KEY, "MODEL_SECRET_EXCLUDED", None, 3),
    ] {
        let fixture = Fixture::new();
        let mut storage = fixture.storage();
        let (tenant, site) = scope();
        let (endpoint, server) = server(status, body).await;
        let client = JevClient::for_test(
            Zeroizing::new(API_KEY.to_owned()),
            &endpoint,
            Duration::from_secs(2),
        )
        .unwrap();
        let (_sender, mut cancel) = oneshot::channel();
        let report = evaluate(
            &input(),
            &client,
            &mut storage,
            &store,
            tenant.clone(),
            site.clone(),
            &mut cancel,
        )
        .await
        .unwrap();
        let actual_sent = server.await.unwrap();
        assert_eq!(report.reason_code, expected);
        let vault = fixture.vault();
        let request = RequestId::parse(&report.request_id).unwrap();
        let catalog = store
            .list_request_artifacts(
                EvidenceCatalogQuery::new(&tenant, &site, &request, None, 16).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(catalog.artifacts().len(), objects);
        let saved_input = vault
            .read_content(&tenant, &site, report.input_artifact_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(*saved_input, actual_sent);
        assert!(!client.contains_secret(&saved_input));
        let call: serde_json::Value = serde_json::from_slice(
            &vault
                .read_content(&tenant, &site, report.call_artifact_id.as_deref().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(call["provider_confidence"], json!(confidence));
        assert_eq!(call["retry_after_seconds"], 3);
        if let Some(output_id) = &report.output_artifact_id {
            let capture: serde_json::Value =
                serde_json::from_slice(&vault.read_content(&tenant, &site, output_id).unwrap())
                    .unwrap();
            assert_eq!(capture["body"], json!(body.as_bytes()));
            assert_eq!(capture["capture_status"], "complete");
        } else {
            assert_eq!(call["capture_status"], "excluded_policy");
        }
        drop(storage);
        let events = fixture.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[2]["payload"]["reason_code"], expected);
        assert_eq!(events[2]["payload"]["confidence"], json!(confidence));
        assert_eq!(events[1]["event_type"], "model.requested");
        assert_eq!(events[1]["evidence_refs"].as_array().unwrap().len(), 2);
        let mut recovered = fixture.storage();
        recovered.recover().unwrap();
        drop(recovered);
        assert_eq!(fixture.events().len(), 3);
    }
    // A catalog insert failure keeps the provider untouched and records a terminal.
    sqlx::query("ALTER TABLE xshield.audit_outbox ADD CONSTRAINT test_model_catalog_failure CHECK (tenant_id <> 'tenant_model_eval_failure')").execute(&pool).await.unwrap();
    let fixture = Fixture::new();
    let mut storage = fixture.storage();
    let client = CountingPort {
        calls: AtomicUsize::new(0),
        payload: Arc::default(),
        fail_after_send: None,
    };
    let (_sender, mut cancel) = oneshot::channel();
    let report = evaluate(
        &input(),
        &client,
        &mut storage,
        &store,
        TenantId::parse("tenant_model_eval_failure").unwrap(),
        scope().1,
        &mut cancel,
    )
    .await
    .unwrap();
    sqlx::query("ALTER TABLE xshield.audit_outbox DROP CONSTRAINT test_model_catalog_failure")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(report.reason_code, "MODEL_CATALOG_UNAVAILABLE");
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    assert!(report.input_artifact_id.is_none());
    drop(storage);
    assert_eq!(fixture.events().len(), 2);

    // Dependency failure after an actual send must still close the attempt.
    let fixture = Fixture::new();
    let mut storage = fixture.storage();
    let client = CountingPort {
        calls: AtomicUsize::new(0),
        payload: Arc::default(),
        fail_after_send: Some(pool.clone()),
    };
    let report = evaluate(
        &input(),
        &client,
        &mut storage,
        &store,
        TenantId::parse("tenant_model_eval_capture_failure").unwrap(),
        scope().1,
        &mut cancel,
    )
    .await
    .unwrap();
    sqlx::query("ALTER TABLE xshield.audit_outbox DROP CONSTRAINT test_model_capture_failure")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(report.reason_code, "MODEL_CATALOG_UNAVAILABLE");
    assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    assert!(report.input_artifact_id.is_some());
    assert!(report.output_artifact_id.is_none());
    drop(storage);
    let events = fixture.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2]["event_type"], "model.failed");
    assert_eq!(events[2]["payload"]["confidence"], serde_json::Value::Null);
}

struct CountedGateway {
    client: JevClient,
    calls: AtomicUsize,
}

impl ModelPort for CountedGateway {
    async fn send<'a>(
        &'a self,
        payload: &'a [u8],
        cancel: &'a mut oneshot::Receiver<()>,
    ) -> transport::Exchange {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.client.send(payload, cancel).await
    }

    fn contains_secret(&self, bytes: &[u8]) -> bool {
        self.client.contains_secret(bytes)
    }

    fn provider(&self) -> &'static str {
        self.client.provider()
    }

    fn provider_model(&self) -> &'static str {
        self.client.provider_model()
    }
}

fn score_exchange_cases() -> Vec<(u16, serde_json::Value, &'static str)> {
    let mut cases = vec![(200, score_response(), "MODEL_EVALUATED")];
    let mut missing_confidence = score_response();
    missing_confidence["answers"]["evaluation"]
        .as_object_mut()
        .unwrap()
        .remove("confidence");
    cases.push((200, missing_confidence, "MODEL_EVALUATED"));
    for (field, invalid) in [
        ("probabilities", json!({"0": 0.6, "1": 0.1, "2": 0.2})),
        ("probabilities", json!({"0": 0.6, "1": 0.4})),
        ("score", json!(0)),
        ("score", json!(3)),
        (
            "legend",
            json!({"0": "High risk.", "1": "Medium risk.", "2": "Low risk."}),
        ),
    ] {
        let mut invalid_response = score_response();
        invalid_response["answers"]["evaluation"][field] = invalid;
        cases.push((200, invalid_response, "MODEL_RESPONSE_INVALID"));
    }
    cases.push((429, json!({"error": "quota"}), "MODEL_RATE_LIMITED"));
    cases
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn postgres_evaluation_score_preserves_gateway_evidence_and_failure_terminals() {
    let database = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&database).await.unwrap();
    let store = PostgresIdentityStore::connect(&database, 2, Duration::from_secs(5))
        .await
        .unwrap();
    let input = score_input();
    for (status, response, expected) in score_exchange_cases() {
        let fixture = Fixture::new();
        let mut storage = fixture.storage();
        let (tenant, site) = scope();
        let body = serde_json::to_string(&response).unwrap();
        let (endpoint, server) = server(status, &body).await;
        let client = CountedGateway {
            client: JevClient::for_test_with_route(
                transport::JevRoute::Gateway,
                Zeroizing::new(API_KEY.to_owned()),
                &endpoint,
                Duration::from_secs(2),
            )
            .unwrap(),
            calls: AtomicUsize::new(0),
        };
        let (_sender, mut cancel) = oneshot::channel();
        let report = evaluate(
            &input,
            &client,
            &mut storage,
            &store,
            tenant.clone(),
            site.clone(),
            &mut cancel,
        )
        .await
        .unwrap();
        assert_eq!(report.reason_code, expected);
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
        let actual_sent = server.await.unwrap();
        let request = RequestId::parse(&report.request_id).unwrap();
        let catalog = store
            .list_request_artifacts(
                EvidenceCatalogQuery::new(&tenant, &site, &request, None, 16).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(catalog.artifacts().len(), 4);
        let outbox_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM xshield.audit_outbox WHERE tenant_id = $1 AND site_id = $2 AND event_type = 'evidence.cataloged' AND envelope->>'request_id' = $3",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(request.as_str())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(outbox_count, 4);
        let vault = fixture.vault();
        let saved_input = vault
            .read_content(&tenant, &site, report.input_artifact_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(*saved_input, actual_sent);
        assert!(!client.contains_secret(&saved_input));
        let sent: serde_json::Value = serde_json::from_slice(&actual_sent).unwrap();
        assert_eq!(sent["model"], "typesafe-ai/jev");
        let internal: serde_json::Value =
            serde_json::from_slice(&input.internal_bytes().unwrap()).unwrap();
        assert_eq!(sent["questions"]["evaluation"], internal["question"]);
        let internal_id = sent["state"]["trace_context"]["input_artifact_id"]
            .as_str()
            .unwrap();
        assert_eq!(
            *vault.read_content(&tenant, &site, internal_id).unwrap(),
            input.internal_bytes().unwrap()
        );
        let output_id = report.output_artifact_id.as_deref().unwrap();
        let call_id = report.call_artifact_id.as_deref().unwrap();
        let capture: serde_json::Value =
            serde_json::from_slice(&vault.read_content(&tenant, &site, output_id).unwrap())
                .unwrap();
        assert_eq!(capture["representation"], "entity_bytes_array");
        assert_eq!(capture["capture_status"], "complete");
        assert_eq!(capture["body"], json!(body.as_bytes()));
        assert_eq!(capture["bytes_observed"], body.len());
        assert_eq!(capture["bytes_saved"], body.len());
        assert_eq!(capture["http_status"], status);
        let call: serde_json::Value =
            serde_json::from_slice(&vault.read_content(&tenant, &site, call_id).unwrap()).unwrap();
        let successful = expected == "MODEL_EVALUATED";
        let confidence = if successful {
            response["answers"]["evaluation"]["confidence"].clone()
        } else {
            serde_json::Value::Null
        };
        let confidence_status = match (successful, confidence.is_null()) {
            (false, _) => "unavailable",
            (true, true) => "not_provided",
            (true, false) => "provided",
        };
        assert_eq!(call["model_call_id"], report.model_call_id);
        assert_eq!(call["request_id"], report.request_id);
        assert_eq!(call["provider"], "vercel_ai_gateway");
        assert_eq!(call["provider_model_id"], "typesafe-ai/jev");
        assert_eq!(call["model_revision"], "jev-1.13.0");
        assert!(call["resolved_model_revision"].is_null());
        assert_eq!(call["question_type"], "score");
        assert_eq!(call["schema_version"], 3);
        assert_eq!(call["prompt_revision"], "prompt-r1");
        assert_eq!(call["example_only"], false);
        assert_eq!(call["status"], report.status);
        assert_eq!(call["reason_code"], expected);
        assert_eq!(call["input_artifact_id"], json!(report.input_artifact_id));
        assert_eq!(call["output_artifact_id"], output_id);
        assert_eq!(call["provider_confidence"], confidence);
        assert_eq!(call["confidence_status"], confidence_status);
        assert_eq!(
            call["probability_semantics"],
            "provider_reported_uncalibrated"
        );
        assert_eq!(call["retry_after_seconds"], 3);
        assert_eq!(call["provider_request_id"], "synthetic-call");
        assert_eq!(call["http_status"], status);
        assert_eq!(call["capture_status"], "complete");
        assert_eq!(call["provider_internal"], "unavailable");
        assert!(call["duration_ms"].as_u64().is_some());
        if successful {
            assert_eq!(call["result"], 0.7);
            assert_eq!(
                call["risk_projection"],
                json!({
                    "mapping_revision":"risk-map-r1", "benign_probability":0.6,
                    "unknown_probability":0.1,"malicious_probability":0.3,
                    "abstained":true,"reason_code":"MODEL_RISK_ABSTAINED"
                })
            );
            assert_eq!(call["legend"], response["answers"]["evaluation"]["legend"]);
            assert_eq!(
                call["probabilities"],
                response["answers"]["evaluation"]["probabilities"]
            );
            assert_eq!(call["schema_validation"], "valid");
            assert_eq!(call["usage"]["input_tokens"], 100);
            assert_eq!(call["usage"]["output_tokens"], 20);
            assert_eq!(call["usage"]["source"], "provider");
        } else {
            assert!(call.get("risk_projection").is_none());
            assert!(call["result"].is_null());
            assert!(call.get("legend").is_none());
            assert_eq!(call["probabilities"], json!({}));
            assert_eq!(
                call["schema_validation"],
                if status == 200 {
                    "invalid"
                } else {
                    "unavailable"
                }
            );
            assert!(call["usage"]["input_tokens"].is_null());
            assert!(call["usage"]["output_tokens"].is_null());
            assert_eq!(call["usage"]["source"], "unavailable");
        }
        for (id, expected_kind, parents) in [
            (internal_id, "model_internal_input", vec![]),
            (
                report.input_artifact_id.as_deref().unwrap(),
                "model_input",
                vec![internal_id],
            ),
            (
                output_id,
                "model_output",
                vec![internal_id, report.input_artifact_id.as_deref().unwrap()],
            ),
            (
                call_id,
                "model_call",
                vec![
                    internal_id,
                    report.input_artifact_id.as_deref().unwrap(),
                    output_id,
                ],
            ),
        ] {
            let artifact = catalog
                .artifacts()
                .iter()
                .find(|artifact| artifact.artifact_id().as_str() == id)
                .unwrap();
            assert_eq!(artifact.manifest().kind, expected_kind);
            assert_eq!(artifact.manifest().parent_refs, parents);
            assert_eq!(
                vault.read_manifest(&tenant, &site, id).unwrap().manifest(),
                artifact.manifest()
            );
        }
        drop(storage);
        let events = fixture.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["event_type"], "model.started");
        assert_eq!(events[1]["event_type"], "model.requested");
        assert_eq!(
            events[2]["event_type"],
            if successful {
                "model.responded"
            } else {
                "model.failed"
            }
        );
        assert_eq!(events[2]["payload"]["reason_code"], expected);
        assert_eq!(events[2]["payload"]["confidence"], confidence);
        assert_eq!(events[2]["payload"]["confidence_status"], confidence_status);
        assert_eq!(events[2]["evidence_refs"].as_array().unwrap().len(), 4);
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event["payload"]["provider"], "vercel_ai_gateway");
            assert_eq!(event["payload"]["provider_model_id"], "typesafe-ai/jev");
            assert_eq!(event["payload"]["question_type"], "score");
            if index > 0 {
                assert_eq!(event["cause_event_ids"][0], events[index - 1]["event_id"]);
            }
        }
        let mut recovered = fixture.storage();
        recovered.recover().unwrap();
        drop(recovered);
        assert_eq!(fixture.events().len(), 3);
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_score_gateway_attempt_is_closed_once_without_retry() {
    for requested in [false, true] {
        let fixture = Fixture::new();
        let (tenant, site) = scope();
        let input = score_input();
        let mut attempt = Attempt::new(&input, tenant, site).unwrap();
        let mut event =
            ModelEvent::new_for_provider(&attempt, &input, "vercel_ai_gateway", "typesafe-ai/jev");
        {
            let mut storage = fixture.storage();
            storage
                .event(&mut attempt, "model.started", &event)
                .unwrap();
            if requested {
                attempt.input = Some(format!("artifact_{}", Uuid::now_v7()));
                event.input_artifact_id.clone_from(&attempt.input);
                "requested".clone_into(&mut event.status);
                "MODEL_REQUESTED".clone_into(&mut event.reason_code);
                storage
                    .event(&mut attempt, "model.requested", &event)
                    .unwrap();
            }
        }
        for _ in 0..2 {
            let mut storage = fixture.storage();
            storage.recover().unwrap();
        }
        let events = fixture.events();
        assert_eq!(events.len(), if requested { 3 } else { 2 });
        let terminal = events.last().unwrap();
        assert_eq!(terminal["event_type"], "model.failed");
        assert_eq!(terminal["payload"]["reason_code"], "MODEL_OUTCOME_UNKNOWN");
        assert_eq!(terminal["payload"]["question_type"], "score");
        assert_eq!(terminal["payload"]["provider"], "vercel_ai_gateway");
        assert_eq!(terminal["payload"]["provider_model_id"], "typesafe-ai/jev");
        assert!(terminal["payload"]["confidence"].is_null());
        assert_eq!(terminal["payload"]["confidence_status"], "unavailable");
        assert_eq!(
            terminal["payload"]["input_artifact_id"],
            json!(attempt.input)
        );
        assert!(terminal["payload"]["output_artifact_id"].is_null());
        assert!(terminal["payload"]["call_artifact_id"].is_null());
        assert_eq!(
            terminal["cause_event_ids"][0],
            events[events.len() - 2]["event_id"]
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event_type"] == "model.requested")
                .count(),
            usize::from(requested)
        );
    }
}
