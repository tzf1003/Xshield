//! docs/04 section 4.3 end to end: a real Pingora edge, a plain-socket origin
//! that has no authorization at all, and a scripted Jev.
//!
//! Every test uses its own session cookie and paths, so they share one edge.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::prelude::Opt;
use serde_json::{Value, json};
use xshield_core::context::trace::{TRACE_BYTES_MAX, TRACE_PATH_BYTES_MAX};
use xshield_core::context::{DecisionPath, DecisionRecord, Outcome, SiteSpec, Skip};
use xshield_edge::proxy::EdgeProxy;
use xshield_edge::server::build_server;
use xshield_edge::sink::DecisionSink;
use xshield_edge::sites::{EdgeSite, SiteTable};
use xshield_judge::context::ContextKey;
use xshield_judge::engine::Judge;
use xshield_judge::jev::{JevFailure, JevPort};
use xshield_judge::state::{ACCESS_OPTIONS, ATTACK_OPTIONS};

/// Answers like a sensible model: an object value named `patient-...` that was
/// never shown to the session is denied, `union select` is an attack, and the
/// word `jevfail` makes the provider time out.
struct ScriptedJev;

fn probabilities(options: [&str; 3], winner: &str) -> Value {
    let mut map = serde_json::Map::new();
    for option in options {
        map.insert(
            option.to_owned(),
            json!(if option == winner { 0.9 } else { 0.05 }),
        );
    }
    Value::Object(map)
}

#[async_trait]
impl JevPort for ScriptedJev {
    fn model(&self) -> String {
        "scripted".to_owned()
    }

    fn route(&self) -> String {
        "scripted".to_owned()
    }

    fn endpoint(&self) -> String {
        "https://scripted.test/v1/systemone".to_owned()
    }

    fn endpoint_host(&self) -> String {
        "scripted.test".to_owned()
    }

    fn default_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }

    async fn ask(&self, body: Vec<u8>, _timeout: Duration) -> Result<Vec<u8>, JevFailure> {
        let document: Value = serde_json::from_slice(&body).expect("request is JSON");
        let request = &document["state"]["request"];
        let text = request.to_string().to_ascii_lowercase();
        if text.contains("jevfail") {
            return Err(JevFailure::Timeout);
        }
        let unseen_patient = request["values"].as_array().is_some_and(|values| {
            values.iter().any(|value| {
                value["value"]
                    .as_str()
                    .is_some_and(|v| v.starts_with("patient-"))
                    && value["seen_as"].as_array().is_some_and(Vec::is_empty)
            })
        });
        let access = if unseen_patient { "DENY" } else { "ALLOW" };
        let attack = if text.contains("union select") {
            "ATTACK"
        } else {
            "BENIGN"
        };
        Ok(json!({"model":"scripted","answers":{
            "access":{"type":"choice","choice":access,"probabilities":probabilities(ACCESS_OPTIONS, access)},
            "attack":{"type":"choice","choice":attack,"probabilities":probabilities(ATTACK_OPTIONS, attack)},
        }})
        .to_string()
        .into_bytes())
    }
}

struct Harness {
    edge_port: u16,
    origin_hits: Arc<Mutex<Vec<(String, usize)>>>,
    records: Arc<Mutex<Vec<DecisionRecord>>>,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn read_head(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    while !buffer.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).ok()? == 0 {
            return None;
        }
        buffer.push(byte[0]);
    }
    Some((String::from_utf8_lossy(&buffer).into_owned(), buffer))
}

fn header_of<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// A tiny origin with no authorization: anyone may read any patient.
fn origin(hits: Arc<Mutex<Vec<(String, usize)>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let hits = Arc::clone(&hits);
            std::thread::spawn(move || {
                let Some((head, _)) = read_head(&mut stream) else {
                    return;
                };
                let length: usize = header_of(&head, "content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0u8; length];
                if stream.read_exact(&mut body).is_err() {
                    return;
                }
                let mut parts = head.lines().next().unwrap_or("").split(' ');
                let method = parts.next().unwrap_or("").to_owned();
                let target = parts.next().unwrap_or("").to_owned();
                hits.lock().unwrap().push((target.clone(), body.len()));
                let path = target.split('?').next().unwrap_or("");
                let (status, extra, content_type, payload): (u16, String, &str, Vec<u8>) =
                    match (method.as_str(), path) {
                        ("POST", "/login") => {
                            let form = String::from_utf8_lossy(&body).into_owned();
                            let user = form
                                .split('&')
                                .find_map(|pair| pair.strip_prefix("user="))
                                .unwrap_or("nobody")
                                .to_owned();
                            (
                                302,
                                format!(
                                    "Set-Cookie: SID=sess-{user}; Path=/\r\nLocation: /api/home\r\n"
                                ),
                                "text/plain",
                                Vec::new(),
                            )
                        }
                        ("GET", "/api/home") => (
                            200,
                            String::new(),
                            "application/json",
                            br#"{"ok":true}"#.to_vec(),
                        ),
                        ("GET", "/api/patients") => {
                            let who = target.split("who=").nth(1).unwrap_or("x");
                            let list = json!({"patients":[
                                {"id": format!("patient-B-{who}")},
                                {"id": format!("patient-C-{who}")}]});
                            (
                                200,
                                String::new(),
                                "application/json",
                                list.to_string().into_bytes(),
                            )
                        }
                        ("POST", "/share/redeem") => (
                            200,
                            String::new(),
                            "application/json",
                            br#"{"patient":{"id":"patient-S-shared"}}"#.to_vec(),
                        ),
                        ("POST", p)
                            if p.starts_with("/api/notes") || p.starts_with("/static/upload") =>
                        {
                            (200, String::new(), "text/plain", body.clone())
                        }
                        ("GET", p) if p.starts_with("/api/patients/") => {
                            let id = p.trim_start_matches("/api/patients/");
                            (
                                200,
                                String::new(),
                                "application/json",
                                json!({"id": id, "name": "n"}).to_string().into_bytes(),
                            )
                        }
                        ("GET", p) if p.starts_with("/static/") => (
                            200,
                            String::new(),
                            "application/javascript",
                            b"console.log(1)".to_vec(),
                        ),
                        _ => (404, String::new(), "text/plain", b"nope".to_vec()),
                    };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&payload);
            });
        }
    });
    port
}

fn site(name: &str, host: &str, origin_port: u16, extra: &str) -> Arc<EdgeSite> {
    let json = format!(
        r#"{{"name":"{name}","hosts":["{host}"],"origin":"http://127.0.0.1:{origin_port}",
           "session":{{"cookie":"SID"}},
           "entries":["/login","/api/home","/api/patients","/share/*"],
           "bypass":["/static/*"]{extra}}}"#
    );
    Arc::new(EdgeSite::new(SiteSpec::from_json(&json).expect("spec"), 1, 1_700).expect("site"))
}

fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let origin_hits = Arc::new(Mutex::new(Vec::new()));
        let origin_port = origin(Arc::clone(&origin_hits));
        let table = Arc::new(SiteTable::new());
        // A port with nothing listening: the origin refuses the connection.
        let closed_port = free_port();
        table.replace(vec![
            site(
                "enforce",
                "enforce.test",
                origin_port,
                r#","mode":"enforce""#,
            ),
            site("observe", "observe.test", origin_port, ""),
            site("down", "down.test", closed_port, ""),
            site(
                "lenient",
                "lenient.test",
                origin_port,
                r#","mode":"enforce","on_jev_unavailable":"allow""#,
            ),
        ]);
        let (sink, mut rx) = DecisionSink::channel(1000);
        let records = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&records);
        std::thread::spawn(move || {
            while let Some(record) = rx.blocking_recv() {
                collected.lock().unwrap().push(record);
            }
        });
        let judge = Arc::new(Judge::new(ContextKey::new(vec![9; 32]), ScriptedJev));
        let edge_port = free_port();
        let server = build_server(
            EdgeProxy::new(table, judge, sink, "edge-test".to_owned()),
            &[format!("127.0.0.1:{edge_port}")],
            None,
            Some(Opt::default()),
        )
        .expect("server");
        std::thread::spawn(move || server.run_forever());
        let started = Instant::now();
        while TcpStream::connect(("127.0.0.1", edge_port)).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "edge did not start"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Harness {
            edge_port,
            origin_hits,
            records,
        }
    })
}

struct Reply {
    status: u16,
    request_id: String,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn call(host: &str, method: &str, target: &str, cookie: Option<&str>, body: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", harness().edge_port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let mut request =
        format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(cookie) = cookie {
        write!(request, "Cookie: SID={cookie}\r\n").unwrap();
    }
    if method == "POST" {
        write!(
            request,
            "Content-Type: application/json
Content-Length: {}
",
            body.len()
        )
        .unwrap();
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head")
        + 4;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status");
    Reply {
        status,
        request_id: header_of(&head, "x-xshield-request-id")
            .unwrap_or("")
            .to_owned(),
        body: raw[split..].to_vec(),
    }
}

fn get(host: &str, target: &str, cookie: Option<&str>) -> Reply {
    call(host, "GET", target, cookie, b"")
}

fn origin_saw(prefix: &str) -> usize {
    harness()
        .origin_hits
        .lock()
        .unwrap()
        .iter()
        .filter(|(target, _)| target.starts_with(prefix))
        .count()
}

fn record(reply: &Reply) -> DecisionRecord {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = harness()
            .records
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.request_id == reply.request_id)
            .cloned();
        if let Some(found) = found {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "no decision row for {}",
            reply.request_id
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a1_a_patient_from_the_list_is_opened_without_asking_jev() {
    let listed = get("enforce.test", "/api/patients?who=a1", Some("s-a1"));
    assert_eq!(listed.status, 200);
    let opened = get("enforce.test", "/api/patients/patient-B-a1", Some("s-a1"));
    assert_eq!(opened.status, 200);
    assert!(opened.text().contains("patient-B-a1"));
    let row = record(&opened);
    assert_eq!(row.decision_path, DecisionPath::FastAllow);
    assert_eq!(row.outcome, Outcome::Allowed);
    assert_eq!(row.status, Some(200));
    assert!(row.jev.is_none());
    // The id was shown by the list, so its source is that list request.
    let id = row
        .trace
        .values
        .iter()
        .find(|value| value.at == "path[2]")
        .expect("the patient id");
    assert_eq!(
        id.sources[0].request_id.as_deref(),
        Some(listed.request_id.as_str())
    );
    assert_eq!(row.site_version, Some(1));
    assert_eq!(row.edge, "edge-test");
    assert_eq!(row.host, "enforce.test");
}

#[test]
fn a2_a_patient_the_session_never_saw_is_refused_before_the_origin() {
    get("enforce.test", "/api/patients?who=a2", Some("s-a2"));
    let refused = get("enforce.test", "/api/patients/patient-D-a2", Some("s-a2"));
    assert_eq!(refused.status, 403);
    assert!(refused.text().contains("forbidden"));
    assert_eq!(origin_saw("/api/patients/patient-D-a2"), 0);
    let row = record(&refused);
    assert_eq!(row.decision_path, DecisionPath::JevDeny);
    assert_eq!(row.outcome, Outcome::Blocked);
    assert_eq!(row.status, Some(403));
}

#[test]
fn a3_a_session_that_never_listed_anything_is_refused() {
    let refused = get(
        "enforce.test",
        "/api/patients/patient-B-a3",
        Some("s-a3-fresh"),
    );
    assert_eq!(refused.status, 403);
    assert_eq!(origin_saw("/api/patients/patient-B-a3"), 0);
    let anonymous = get("enforce.test", "/api/patients/patient-B-a3", None);
    assert_eq!(anonymous.status, 401);
    let row = record(&anonymous);
    assert_eq!(row.decision_path, DecisionPath::NoSession);
    let response = row.trace.response.expect("a refused request says so");
    assert_eq!(response.skip, Some(Skip::NotForwarded));
}

#[test]
fn a6_a7_a_redeemed_share_opens_and_an_unredeemed_one_does_not() {
    let blocked = get(
        "enforce.test",
        "/api/patients/patient-S-shared",
        Some("s-a7"),
    );
    assert_eq!(blocked.status, 403);
    let redeemed = call(
        "enforce.test",
        "POST",
        "/share/redeem",
        Some("s-a6"),
        br#"{"code":"abc123xyz"}"#,
    );
    assert_eq!(redeemed.status, 200);
    let opened = get(
        "enforce.test",
        "/api/patients/patient-S-shared",
        Some("s-a6"),
    );
    assert_eq!(opened.status, 200);
    let still_blocked = get(
        "enforce.test",
        "/api/patients/patient-S-shared",
        Some("s-a7"),
    );
    assert_eq!(still_blocked.status, 403);
}

#[test]
fn b2_injection_in_an_allowed_place_is_refused() {
    get("enforce.test", "/api/patients?who=b2", Some("s-b2"));
    let attack = get(
        "enforce.test",
        "/api/patients/patient-B-b2?q=1%27%20UNION%20SELECT%20password%20FROM%20users",
        Some("s-b2"),
    );
    assert_eq!(attack.status, 403);
    assert_eq!(origin_saw("/api/patients/patient-B-b2?q="), 0);
}

#[test]
fn c1_c2_when_jev_is_down_the_site_policy_decides() {
    let denied = get("enforce.test", "/api/patients/jevfail-c1", Some("s-c1"));
    assert_eq!(denied.status, 403);
    assert_eq!(record(&denied).decision_path, DecisionPath::JevUnavailable);
    assert_eq!(origin_saw("/api/patients/jevfail-c1"), 0);

    let allowed = get("lenient.test", "/api/patients/jevfail-c2", Some("s-c2"));
    assert_eq!(allowed.status, 200);
    let row = record(&allowed);
    assert_eq!(row.outcome, Outcome::Unjudged);
    assert_eq!(row.status, Some(200));
}

#[test]
fn c3_observe_mode_forwards_and_logs_would_block() {
    get("observe.test", "/api/patients?who=c3", Some("s-c3"));
    let reply = get("observe.test", "/api/patients/patient-D-c3", Some("s-c3"));
    assert_eq!(reply.status, 200);
    assert_eq!(origin_saw("/api/patients/patient-D-c3"), 1);
    let row = record(&reply);
    assert_eq!(row.outcome, Outcome::WouldBlock);
    let response = row.trace.response.expect("the response was observed");
    assert!(response.after_would_block);
}

#[test]
fn a_login_redirect_creates_the_session_the_next_requests_use() {
    let login = call(
        "enforce.test",
        "POST",
        "/login",
        None,
        b"user=nurse1&password=hunter2hunter2",
    );
    assert_eq!(login.status, 302);
    get(
        "enforce.test",
        "/api/patients?who=nurse1",
        Some("sess-nurse1"),
    );
    let opened = get(
        "enforce.test",
        "/api/patients/patient-B-nurse1",
        Some("sess-nurse1"),
    );
    assert_eq!(opened.status, 200);
    let next = record(&opened);
    assert_eq!(next.decision_path, DecisionPath::FastAllow);
    // The session the login issued is the one the later requests carry.
    let issued = record(&login)
        .trace
        .response
        .and_then(|response| response.issued_session);
    assert_eq!(issued.as_deref(), Some(next.session.as_str()));
}

#[test]
fn request_bodies_reach_the_origin_intact_and_oversized_ones_are_refused() {
    get("enforce.test", "/api/patients?who=body", Some("s-body"));
    let body = br#"{"title":"visit notes 2024","text":"all good"}"#;
    let echoed = call("enforce.test", "POST", "/api/notes", Some("s-body"), body);
    assert_eq!(echoed.status, 200);
    assert_eq!(echoed.body, body);

    let big = vec![b'a'; 60_000];
    let refused = call(
        "enforce.test",
        "POST",
        "/api/notes-big",
        Some("s-body"),
        &big,
    );
    assert_eq!(refused.status, 413);
    assert_eq!(origin_saw("/api/notes-big"), 0);
    let row = record(&refused);
    assert_eq!(row.decision_path, DecisionPath::BodyNotInspectable);
    assert_eq!(row.outcome, Outcome::Blocked);
    assert_eq!(row.status, Some(413));
    assert_eq!(row.site.as_deref(), Some("enforce"));
    assert_eq!(row.site_version, Some(1));
    assert_eq!(row.trace.refused.as_deref(), Some("body_not_inspectable"));

    // Bypass paths are not judged, so large uploads stream through untouched.
    let upload = call(
        "enforce.test",
        "POST",
        "/static/upload",
        Some("s-body"),
        &big,
    );
    assert_eq!(upload.status, 200);
    assert_eq!(upload.body.len(), 60_000);
    assert_eq!(record(&upload).decision_path, DecisionPath::Bypass);
}

#[test]
fn static_paths_are_forwarded_and_logged_as_bypass() {
    let asset = get("enforce.test", "/static/app.js", None);
    assert_eq!(asset.status, 200);
    assert_eq!(asset.text(), "console.log(1)");
    let row = record(&asset);
    assert_eq!(row.decision_path, DecisionPath::Bypass);
    assert_eq!(row.outcome, Outcome::Allowed);
    assert_eq!(row.trace.bypass.as_deref(), Some("/static/*"));
    assert_eq!(row.status, Some(200));
    let response = row.trace.response.expect("the response summary");
    assert_eq!(response.skip, Some(Skip::Bypass));
}

#[test]
fn d1_a_request_with_many_long_values_is_written_within_the_trace_limit() {
    // Sixty values of 256 characters put the trace well over 16 KiB. The gateway
    // trims it before it writes the row, and the rest of the row is untouched.
    let values: Vec<String> = (0..60)
        .map(|index| format!("{index:03}{}", "x".repeat(253)))
        .collect();
    let body = json!({ "items": values }).to_string();
    let reply = call(
        "observe.test",
        "POST",
        "/api/notes?who=d1",
        Some("s-d1"),
        body.as_bytes(),
    );
    assert_eq!(reply.status, 200);
    let row = record(&reply);
    assert!(row.trace.trimmed, "an oversized trace says it was trimmed");
    let encoded = serde_json::to_vec(&row.trace).expect("the trace encodes");
    assert!(
        encoded.len() <= TRACE_BYTES_MAX,
        "the written trace is {} bytes",
        encoded.len()
    );
    assert!(row.trace.timing.total_ms.is_some(), "timing is set by then");
    assert!(row.trace.response.is_some(), "the response was recorded");
}

#[test]
fn d2_long_request_paths_stay_out_of_the_rows_that_follow() {
    // Ten requests with 3 KB paths enter the session's recent list. The next
    // judged request is still written within the limit, with each path cut.
    let long = "p".repeat(3000);
    for _ in 0..10 {
        let listed = get(
            "observe.test",
            &format!("/api/patients/{long}"),
            Some("s-d2"),
        );
        assert_eq!(listed.status, 200);
    }
    let values: Vec<String> = (0..60)
        .map(|index| format!("d2{index:03}{}", "y".repeat(253)))
        .collect();
    let body = json!({ "items": values }).to_string();
    let reply = call(
        "observe.test",
        "POST",
        "/api/notes?who=d2",
        Some("s-d2"),
        body.as_bytes(),
    );
    let row = record(&reply);
    let encoded = serde_json::to_vec(&row.trace).expect("the trace encodes");
    assert!(
        encoded.len() <= TRACE_BYTES_MAX,
        "the written trace is {} bytes",
        encoded.len()
    );
    let recent = row
        .trace
        .session
        .as_ref()
        .and_then(|session| session.recent.as_ref())
        .expect("a judged row lists the recent requests");
    assert!(!recent.is_empty(), "the session has recent requests");
    assert!(
        recent
            .iter()
            .all(|request| request.path.len() <= TRACE_PATH_BYTES_MAX),
        "every recent path is cut"
    );
}

#[test]
fn unknown_hosts_are_refused_with_a_simple_row() {
    let unknown = get("nobody.test", "/", None);
    assert_eq!(unknown.status, 404);
    let row = record(&unknown);
    assert_eq!(row.decision_path, DecisionPath::UnknownSite);
    assert_eq!(row.outcome, Outcome::Blocked);
    assert_eq!(row.site, None);
    assert_eq!(row.status, Some(404));
    assert_eq!(row.host, "nobody.test");
    assert_eq!(row.trace.refused.as_deref(), Some("unknown_site"));
}

#[test]
fn an_unreachable_origin_is_a_502_with_its_cause() {
    let reply = get("down.test", "/api/home", None);
    assert_eq!(reply.status, 502);
    let row = record(&reply);
    assert_eq!(row.status, Some(502));
    assert_eq!(row.trace.upstream_error.as_deref(), Some("connect_refused"));
    assert_eq!(row.outcome, Outcome::Allowed);
}
