//! Real HTTP → encrypted vault → `PostgreSQL` catalog/outbox → journal barrier.
use serde_json::{Value, json};
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use uuid::Uuid;
use xshield_audit::{JournalError, JournalKey, LocalJournal};
use xshield_core::domain::{RequestId, SiteId, TenantId};
use xshield_evidence::{EvidenceFidelity, EvidenceKey, EvidenceVaultConfig, LocalEvidenceVault};
use xshield_gateway::GatewayConfig;
use xshield_postgres::{EvidenceCatalogQuery, PostgresIdentityStore};

const KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const JOURNAL_KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const BODY: &[u8] = br#"{"message":"<script>hostile()</script>","password":"exclude-this-secret","custom":"exclude-custom-secret"}"#;

struct Runtime {
    root: PathBuf,
    gateway: Option<Child>,
    stop: Arc<AtomicBool>,
    origin: Option<thread::JoinHandle<()>>,
}

impl Runtime {
    fn stop_gateway(&mut self) {
        if let Some(mut child) = self.gateway.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop_gateway();
        self.stop.store(true, Ordering::Release);
        if let Some(origin) = self.origin.take() {
            origin.join().unwrap();
        }
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL and curl"]
#[allow(clippy::too_many_lines)]
async fn response_capture_is_durable_redacted_and_fail_closed() {
    let database = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let root = env::temp_dir().join(format!("xshield-capture-{}", Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let vault_root = root.join("vault");
    fs::create_dir(&vault_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&vault_root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_address = origin.local_addr().unwrap();
    origin.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_origin = Arc::clone(&stop);
    let forwarded_request = Arc::new(Mutex::new(None));
    let origin_request = Arc::clone(&forwarded_request);
    let origin_thread = thread::spawn(move || {
        while !stop_origin.load(Ordering::Acquire) {
            let Ok((mut stream, _)) = origin.accept() else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                request.push(byte[0]);
            }
            *origin_request.lock().unwrap() =
                String::from_utf8_lossy(&request).lines().find_map(|line| {
                    line.split_once(':')
                        .filter(|(key, _)| key.eq_ignore_ascii_case("x-xshield-request-id"))
                        .map(|(_, value)| value.trim().to_owned())
                });
            let oversized = format!("{{\"value\":\"{}\"}}", "a".repeat(2048));
            let body = if request.starts_with(b"GET /oversize ") {
                oversized.as_bytes()
            } else {
                BODY
            };
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            let _ = stream.write_all(body);
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut runtime = Runtime {
        root: root.clone(),
        gateway: None,
        stop,
        origin: Some(origin_thread),
    };
    let config_json = json!({
        "listen":address.to_string(), "origin":{"address":origin_address.to_string(), "server_name":"origin.local", "tls":false},
        "tenant_id":"tenant_capture", "site_id":"site_capture", "policy_revision":"policy-r1",
        "audit":{"directory":root.join("journal"), "key_id":"journal-r1", "producer_id":"edge-capture", "max_bytes":1_048_576, "high_watermark_bytes":786_432, "segment_max_bytes":262_144},
        "identity_store":{"max_connections":2, "acquire_timeout_ms":1000},
        "operations":(["/data", "/oversize", "/dbfail"].map(|path| json!({
            "operation_id":path.trim_start_matches('/'), "method":"GET", "path":path, "admission":"PUBLIC",
            "response":{"mode":"BUFFERED_JSON", "max_bytes":4096,
                "evidence_capture":{"profile_revision":"capture-r1", "max_bytes":1024, "retention_seconds":3600, "secret_pointers":["/custom"]}}
        })))
    });
    let config_bytes = serde_json::to_vec(&config_json).unwrap();
    let config = GatewayConfig::from_json(&config_bytes).unwrap();
    fs::write(root.join("config.json"), config_bytes).unwrap();
    let start = || {
        Command::new(env!("CARGO_BIN_EXE_xshield-gateway"))
            .env("XSHIELD_CONFIG", root.join("config.json"))
            .env("XSHIELD_DATABASE_URL", &database)
            .env("XSHIELD_JOURNAL_KEY_HEX", JOURNAL_KEY)
            .env("XSHIELD_EVIDENCE_ROOT", &vault_root)
            .env("XSHIELD_EVIDENCE_KEY_ID", "evidence-r1")
            .env("XSHIELD_EVIDENCE_KEY_HEX", KEY)
            .env("XSHIELD_EVIDENCE_MAX_TOTAL_BYTES", "8388608")
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                fs::File::create(root.join("gateway.log")).unwrap(),
            ))
            .spawn()
            .unwrap()
    };
    runtime.gateway = Some(start());
    wait_for_listener(address);
    let fetch = |path: &str| {
        let result = Command::new("curl")
            .args(["--silent", "--max-time", "5", "--http1.0", "-D"])
            .arg(root.join("headers"))
            .arg("-o")
            .arg(root.join("body"))
            .arg(format!("http://{address}{path}"))
            .output()
            .unwrap();
        let headers = fs::read_to_string(root.join("headers")).unwrap();
        let request_id = headers
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.eq_ignore_ascii_case("x-xshield-request-id"))
                    .map(|(_, value)| value.trim().to_owned())
            })
            .or_else(|| forwarded_request.lock().unwrap().clone())
            .expect("origin receives the server-generated request identity");
        (
            result.status.success(),
            RequestId::parse(request_id).unwrap(),
            fs::read(root.join("body")).unwrap_or_default(),
        )
    };
    let (ok, request, body) = fetch("/data");
    assert!(ok);
    assert_eq!(body, BODY);
    let store = PostgresIdentityStore::connect(&database, 2, Duration::from_secs(2))
        .await
        .unwrap();
    let tenant = TenantId::parse("tenant_capture").unwrap();
    let site = SiteId::parse("site_capture").unwrap();
    let manifests = store
        .list_request_artifacts(
            EvidenceCatalogQuery::new(&tenant, &site, &request, None, 10).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(manifests.artifacts().len(), 1);
    let manifest = manifests.artifacts()[0].manifest();
    assert_eq!(manifest.fidelity, EvidenceFidelity::Redacted);
    let vault = LocalEvidenceVault::open(
        EvidenceVaultConfig::new(&vault_root, "evidence-r1", 4 * 1024 * 1024, 1).unwrap(),
        EvidenceKey::from_hex(KEY).unwrap(),
    )
    .unwrap();
    let content = vault
        .read_content(&tenant, &site, &manifest.artifact_id)
        .unwrap();
    let document: Value = serde_json::from_slice(&content).unwrap();
    assert_eq!(document["value"]["message"], "<script>hostile()</script>");
    assert_eq!(document["value"]["password"], Value::Null);
    assert_eq!(document["exclusions"].as_array().unwrap().len(), 2);
    assert!(!String::from_utf8_lossy(&content).contains("exclude-"));
    let (_, oversized_request, body) = fetch("/oversize");
    assert!(!body.windows(16).any(|part| part == b"aaaaaaaaaaaaaaaa"));
    assert!(
        store
            .list_request_artifacts(
                EvidenceCatalogQuery::new(&tenant, &site, &oversized_request, None, 10).unwrap()
            )
            .await
            .unwrap()
            .artifacts()
            .is_empty()
    );
    // A targeted database constraint rejects only this test's new catalog rows.
    let pool = sqlx::PgPool::connect(&database).await.unwrap();
    let mut blocked_catalog = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE xshield.artifact_catalog IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocked_catalog)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let (_, timed_out_request, body) = fetch("/dbfail");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(!body.windows(8).any(|part| part == b"hostile("));
    blocked_catalog.rollback().await.unwrap();
    sqlx::query("ALTER TABLE xshield.artifact_catalog ADD CONSTRAINT capture_test_failure CHECK (tenant_id <> 'tenant_capture') NOT VALID").execute(&pool).await.unwrap();
    let (_, failed_request, body) = fetch("/dbfail");
    sqlx::query("ALTER TABLE xshield.artifact_catalog DROP CONSTRAINT capture_test_failure")
        .execute(&pool)
        .await
        .unwrap();
    assert!(!body.windows(8).any(|part| part == b"hostile("));
    assert!(
        store
            .list_request_artifacts(
                EvidenceCatalogQuery::new(&tenant, &site, &failed_request, None, 10).unwrap()
            )
            .await
            .unwrap()
            .artifacts()
            .is_empty()
    );
    // Logging runs after the body filter; wait for its short durability handoff.
    thread::sleep(Duration::from_millis(200));
    runtime.stop_gateway();
    let (journal, _) = LocalJournal::open(
        config.audit_directory(),
        config.audit_key_id(),
        JournalKey::from_hex(JOURNAL_KEY).unwrap(),
        config.audit_limits(),
    )
    .unwrap();
    let mut events = Vec::new();
    journal
        .visit_closed_records(1000, |record| {
            events.push(
                serde_json::from_slice::<Value>(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?,
            );
            Ok(())
        })
        .unwrap();
    let captured = events
        .iter()
        .find(|event| {
            event["request_id"] == request.as_str() && event["event_type"] == "evidence.captured"
        })
        .unwrap();
    assert_eq!(captured["evidence_refs"][0], manifest.artifact_id);
    let envelope: Value =
        sqlx::query_scalar("SELECT envelope FROM xshield.audit_outbox WHERE event_id = $1")
            .bind(captured["cause_event_ids"][0].as_str().unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(envelope["event_type"], "evidence.cataloged");
    assert_eq!(envelope["evidence_refs"], captured["evidence_refs"]);
    for (id, reason) in [
        (&oversized_request, "EVIDENCE_CAPTURE_LIMIT_EXCEEDED"),
        (&failed_request, "EVIDENCE_CAPTURE_UNAVAILABLE"),
        (&timed_out_request, "EVIDENCE_CAPTURE_UNAVAILABLE"),
    ] {
        assert!(events.iter().any(|event| event["request_id"] == id.as_str()
            && event["event_type"] == "request.aborted"
            && event["payload"]["reason_code"] == reason));
    }
    assert!(!serde_json::to_string(&events).unwrap().contains("exclude-"));
    drop(journal);
    runtime.gateway = Some(start());
    wait_for_listener(address);
    let (ok, _, body) = fetch("/data");
    assert!(ok);
    assert_eq!(body, BODY);
}

fn wait_for_listener(address: std::net::SocketAddr) {
    for _ in 0..200 {
        if TcpStream::connect(address).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("gateway listener did not start");
}
