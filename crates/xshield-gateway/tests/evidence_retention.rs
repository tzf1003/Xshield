//! A running gateway deletes its own expired evidence ciphertext and gets the
//! capture budget back, without a restart and while it keeps serving.
use serde_json::json;
use std::{
    env, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const KEY: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const JOURNAL_KEY: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const BODY: &[u8] = br#"{"message":"retained briefly"}"#;
const MAX_TOTAL_BYTES: u64 = 8_388_608;

struct Gateway(Child);

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn get(address: SocketAddr, path: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(stream, "GET {path} HTTP/1.0\r\nHost: {address}\r\n\r\n").unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(response.len(), |index| index + 4);
    let status = String::from_utf8_lossy(&response[..split])
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, response[split..].to_vec())
}

fn metric(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')?.parse().ok())
}

fn root_files(root: &Path) -> (u64, usize) {
    let mut bytes = 0;
    let mut ciphertexts = 0;
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        bytes += entry.metadata().unwrap().len();
        if entry.file_name().to_string_lossy().ends_with(".xev") {
            ciphertexts += 1;
        }
    }
    (bytes, ciphertexts)
}

#[test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
fn running_gateway_purges_expired_evidence_and_reclaims_its_budget() {
    let database = env::var("XSHIELD_TEST_DATABASE_URL").unwrap();
    let root = env::temp_dir().join(format!("xshield-retention-{}", Uuid::now_v7()));
    let vault_root = root.join("vault");
    fs::create_dir_all(&vault_root).unwrap();
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
    let origin_thread = thread::spawn(move || {
        while !stop_origin.load(Ordering::Acquire) {
            let Ok((mut stream, _)) = origin.accept() else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
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
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                BODY.len()
            );
            let _ = stream.write_all(BODY);
        }
    });
    let address = free_address();
    let ops = free_address();
    // A tenant of its own per run: a previous run's last capture expired in a
    // root that no longer exists, and would fail this run's passes.
    let tenant = format!("tenant_edge_retention_{}", Uuid::now_v7().simple());
    let config = json!({
        "listen":address.to_string(), "origin":{"address":origin_address.to_string(), "server_name":"origin.local", "tls":false},
        "tenant_id":tenant, "site_id":"site_edge_retention", "policy_revision":"policy-r1",
        "audit":{"directory":root.join("journal"), "key_id":"journal-r1", "producer_id":"edge-retention", "max_bytes":1_048_576, "high_watermark_bytes":786_432, "segment_max_bytes":262_144},
        "identity_store":{"max_connections":2, "acquire_timeout_ms":1000},
        "operations":[{
            "operation_id":"data", "method":"GET", "path":"/data", "admission":"PUBLIC",
            "response":{"mode":"BUFFERED_JSON", "max_bytes":4096,
                "evidence_capture":{"profile_revision":"capture-r1", "max_bytes":1024, "retention_seconds":1, "secret_pointers":[]}}
        }]
    });
    fs::write(
        root.join("config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let gateway = Gateway(
        Command::new(env!("CARGO_BIN_EXE_xshield-gateway"))
            .env("XSHIELD_CONFIG", root.join("config.json"))
            .env("XSHIELD_DATABASE_URL", &database)
            .env("XSHIELD_JOURNAL_KEY_HEX", JOURNAL_KEY)
            .env("XSHIELD_EVIDENCE_ROOT", &vault_root)
            .env("XSHIELD_EVIDENCE_KEY_ID", "evidence-r1")
            .env("XSHIELD_EVIDENCE_KEY_HEX", KEY)
            .env(
                "XSHIELD_EVIDENCE_MAX_TOTAL_BYTES",
                MAX_TOTAL_BYTES.to_string(),
            )
            .env("XSHIELD_EVIDENCE_RETENTION_INTERVAL_SECONDS", "1")
            .env("XSHIELD_EDGE_OPS_LISTEN", ops.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                fs::File::create(root.join("gateway.log")).unwrap(),
            ))
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    while TcpStream::connect(address).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "gateway did not start: {}",
            fs::read_to_string(root.join("gateway.log")).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(25));
    }

    let (status, body) = get(address, "/data");
    assert_eq!((status, body.as_slice()), (200, BODY));
    let (_, ciphertexts) = root_files(&vault_root);
    assert_eq!(ciphertexts, 1, "the capture is on disk before it expires");

    // Expired after a second, then deleted by the next pass; the budget the
    // capture charged comes back without a restart.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (_, text) = get(ops, "/metrics");
        let text = String::from_utf8_lossy(&text).into_owned();
        assert!(
            !text.contains("xshield_edge_evidence_retention_failures_total{"),
            "{text}\n{}",
            fs::read_to_string(root.join("gateway.log")).unwrap_or_default()
        );
        let (bytes, ciphertexts) = root_files(&vault_root);
        if ciphertexts == 0
            && metric(&text, "xshield_edge_evidence_retention_deleted_total") >= Some(1)
            && metric(&text, "xshield_edge_evidence_capacity_remaining_bytes")
                == Some(MAX_TOTAL_BYTES - bytes)
        {
            assert_eq!(
                metric(&text, "xshield_edge_evidence_retention_deleted_total"),
                Some(1)
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "expired evidence was not purged: {text}\n{}",
            fs::read_to_string(root.join("gateway.log")).unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(250));
    }

    // Still serving and capturing.
    let (status, body) = get(address, "/data");
    assert_eq!((status, body.as_slice()), (200, BODY));
    drop(gateway);
    stop.store(true, Ordering::Release);
    origin_thread.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}
