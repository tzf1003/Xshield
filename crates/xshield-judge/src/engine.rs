//! The decision flow of docs/01 section 1.4.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::Instant;

use xshield_core::context::SessionCredential;
use xshield_core::context::{
    DecisionPath, DecisionRecord, JevRecord, Mode, OnJevUnavailable, Outcome, SiteSpec,
};

use crate::context::{ContextKey, ContextStore, Digest16, Recent, label};
use crate::jev::{JevFailure, JevPort};
use crate::state::{
    Conclusion, StateInput, StateValue, build_state, conclude, parse_response, request_body,
};
use crate::values::{ExtractedRequest, extract_request, extract_response};

/// Jev calls allowed per session per minute (docs/02 section 2.5).
pub const SESSION_CALLS_PER_MINUTE: u32 = 60;
/// Jev calls allowed per client address per minute for requests without a session.
pub const ADDRESS_CALLS_PER_MINUTE: u32 = 30;
const WINDOW_MS: u64 = 60_000;
const LIMITER_MAX: usize = 50_000;
const RECENT_IN_STATE: usize = 10;

/// One request as the gateway sees it, before forwarding.
#[derive(Debug, Clone)]
pub struct RequestFacts<'a> {
    /// Gateway-assigned id.
    pub request_id: &'a str,
    /// HTTP method.
    pub method: &'a str,
    /// Path without query.
    pub path: &'a str,
    /// Raw query string, if any.
    pub query: Option<&'a str>,
    /// `Content-Type` header.
    pub content_type: Option<&'a str>,
    /// Buffered request body.
    pub body: &'a [u8],
    /// The session credential value (cookie or header), if present.
    pub credential: Option<&'a str>,
    /// Client address text, used only to rate limit sessionless requests.
    pub client: &'a str,
    /// Unix time in milliseconds.
    pub now_ms: u64,
}

/// What to do with the request.
#[derive(Debug, Clone, PartialEq)]
pub struct Judgement {
    /// Forward to the origin.
    pub forward: bool,
    /// Status to answer with when not forwarding (401 or 403).
    pub refuse_status: u16,
    /// The log row, completed by the gateway with the origin status. `None`
    /// for bypassed paths, which are not logged.
    pub record: Option<DecisionRecord>,
}

/// A response the origin returned, for [`Judge::observe`].
#[derive(Debug, Clone)]
pub struct Observation<'a> {
    /// The request's credential, if it had one.
    pub credential: Option<&'a str>,
    /// Client address; the context of requests that have no credential.
    pub client: &'a str,
    /// A credential the origin issued in this response (new `Set-Cookie`).
    pub issued_credential: Option<&'a str>,
    /// HTTP method.
    pub method: &'a str,
    /// Path without query.
    pub path: &'a str,
    /// Origin status.
    pub status: u16,
    /// Response `Content-Type`.
    pub content_type: Option<&'a str>,
    /// Buffered response body (empty when too large to buffer).
    pub body: &'a [u8],
    /// Unix time in milliseconds.
    pub now_ms: u64,
}

#[derive(Default)]
struct Limiter {
    windows: HashMap<Digest16, (u64, u32)>,
}

impl Limiter {
    fn allow(&mut self, key: Digest16, limit: u32, now_ms: u64) -> bool {
        if self.windows.len() >= LIMITER_MAX {
            self.windows
                .retain(|_, (start, _)| now_ms.saturating_sub(*start) < WINDOW_MS);
        }
        let entry = self.windows.entry(key).or_insert((now_ms, 0));
        if now_ms.saturating_sub(entry.0) >= WINDOW_MS {
            *entry = (now_ms, 0);
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

struct Inner {
    store: ContextStore,
    limiter: Limiter,
}

/// The judge: one per gateway process.
pub struct Judge<J: JevPort> {
    key: ContextKey,
    jev: J,
    inner: Mutex<Inner>,
}

enum Plan {
    Done(Verdict),
    Ask {
        limit_key: Digest16,
        values: Vec<StateValue>,
    },
}

#[derive(Clone, Copy)]
enum Verdict {
    Safe(DecisionPath),
    Unsafe(DecisionPath),
    Unjudged(DecisionPath),
}

impl<J: JevPort> Judge<J> {
    /// A judge with empty context.
    #[must_use]
    pub fn new(key: ContextKey, jev: J) -> Self {
        Self {
            key,
            jev,
            inner: Mutex::new(Inner {
                store: ContextStore::new(),
                limiter: Limiter::default(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Decides one request (docs/01 section 1.4 steps 1 to 7).
    pub async fn judge(&self, site: &SiteSpec, request: &RequestFacts<'_>) -> Judgement {
        if site.is_bypass(request.path) {
            return Judgement {
                forward: true,
                refuse_status: 0,
                record: None,
            };
        }
        let entry = site.is_entry(request.path);
        let session_id = request
            .credential
            .filter(|c| !c.is_empty())
            .map(|c| self.key.mac("session", c.as_bytes()));
        let extracted = extract_request(
            request.path,
            request.query,
            request.content_type,
            request.body,
        );
        let cache_key = self.cache_key(request, &extracted.values);

        let mut jev_record = None;
        let verdict = match self.plan(request, entry, session_id, &extracted, &cache_key) {
            Plan::Done(verdict) => verdict,
            Plan::Ask { limit_key, values } => {
                let (verdict, record) = self
                    .ask_jev(
                        request,
                        entry,
                        session_id,
                        limit_key,
                        values,
                        extracted.truncated,
                        &cache_key,
                    )
                    .await;
                jev_record = Some(record);
                verdict
            }
        };
        let (decision_path, outcome, forward, refuse_status) = apply_policy(site, verdict);
        Judgement {
            forward,
            refuse_status,
            record: Some(DecisionRecord {
                at_millis: request.now_ms,
                site: site.name().to_owned(),
                request_id: request.request_id.to_owned(),
                session: session_id.map(|id| label(&id)).unwrap_or_default(),
                method: request.method.to_owned(),
                path: request.path.to_owned(),
                status: None,
                decision_path,
                outcome,
                jev: jev_record,
            }),
        }
    }

    /// Steps 2 to 5: everything that can be settled without calling Jev.
    fn plan(
        &self,
        request: &RequestFacts<'_>,
        entry: bool,
        session_id: Option<Digest16>,
        extracted: &ExtractedRequest,
        cache_key: &Digest16,
    ) -> Plan {
        // Without a credential only an entry may pass (a login, a sign-up
        // step). Its context is the client address: what the origin showed
        // that address earlier (a new user's id, the security questions) is
        // the only evidence that the next sign-up request names its own data.
        let session_id = match session_id {
            Some(id) => id,
            None if entry => self.key.mac("address", request.client.as_bytes()),
            None => return Plan::Done(Verdict::Unsafe(DecisionPath::NoSession)),
        };
        let mut inner = self.lock();
        let session = inner.store.session(session_id, request.now_ms);
        let mut all_known = true;
        let mut values = Vec::new();
        for value in extracted.values.iter().filter(|v| !v.inert) {
            let seen = session.lookup(&self.key, &value.value);
            all_known &= seen.is_some_and(|seen| {
                seen.is_specific(&value.value, request.path, value.key.as_deref())
            });
            values.push(StateValue {
                at: value.at.clone(),
                value: value.value.clone(),
                key: value.key.clone(),
                seen_as: seen
                    .map(|seen| {
                        seen.ranked(request.path, value.key.as_deref())
                            .into_iter()
                            .map(|o| format!("{} @ {}", o.field, o.request))
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }
        if all_known && !extracted.truncated {
            Plan::Done(Verdict::Safe(DecisionPath::FastAllow))
        } else if session.cached_allow(cache_key, request.now_ms) {
            Plan::Done(Verdict::Safe(DecisionPath::CachedAllow))
        } else {
            Plan::Ask {
                limit_key: session_id,
                values,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn ask_jev(
        &self,
        request: &RequestFacts<'_>,
        entry: bool,
        session_id: Option<Digest16>,
        limit_key: Digest16,
        values: Vec<StateValue>,
        truncated: bool,
        cache_key: &Digest16,
    ) -> (Verdict, JevRecord) {
        let failed = |code: &str, state: String| {
            (
                Verdict::Unjudged(DecisionPath::JevUnavailable),
                JevRecord {
                    state,
                    access: BTreeMap::new(),
                    attack: BTreeMap::new(),
                    millis: 0,
                    failure: Some(code.to_owned()),
                },
            )
        };
        let (age, entries, recent) = {
            let mut inner = self.lock();
            let limit = if session_id.is_some() {
                SESSION_CALLS_PER_MINUTE
            } else {
                ADDRESS_CALLS_PER_MINUTE
            };
            if !inner.limiter.allow(limit_key, limit, request.now_ms) {
                return failed("JEV_CALL_LIMIT", String::new());
            }
            match session_id {
                Some(id) => {
                    let session = inner.store.session(id, request.now_ms);
                    let recent = session
                        .recent(RECENT_IN_STATE)
                        .into_iter()
                        .cloned()
                        .collect::<Vec<Recent>>();
                    (
                        session.age_seconds(request.now_ms),
                        session.entries_passed().to_vec(),
                        recent,
                    )
                }
                None => (0, Vec::new(), Vec::new()),
            }
        };
        let input = StateInput {
            entry_matched: entry,
            session_age_seconds: age,
            entries_passed: &entries,
            recent: recent.iter().collect(),
            method: request.method,
            path: request.path,
            values,
            truncated,
            credential: request.credential,
        };
        let state = match build_state(&input) {
            Ok(state) => state,
            Err(error) => return failed(&error.to_string(), String::new()),
        };
        let started = Instant::now();
        let reply = self.jev.ask(request_body(self.jev.model(), &state)).await;
        let millis = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
        let body = match reply {
            Ok(body) => body,
            Err(failure) => {
                let (verdict, mut record) = failed(failure_code(failure), state);
                record.millis = millis;
                return (verdict, record);
            }
        };
        let answers = match parse_response(&body) {
            Ok(answers) => answers,
            Err(error) => {
                let (verdict, mut record) = failed(&error.to_string(), state);
                record.millis = millis;
                return (verdict, record);
            }
        };
        let mut record = JevRecord {
            state,
            access: answers.access.clone(),
            attack: answers.attack.clone(),
            millis,
            failure: None,
        };
        let verdict = match conclude(&answers) {
            Conclusion::Allow => {
                self.lock()
                    .store
                    .session(session_id.unwrap_or(limit_key), request.now_ms)
                    .cache_allow(*cache_key, request.now_ms);
                Verdict::Safe(DecisionPath::JevAllow)
            }
            Conclusion::Deny => Verdict::Unsafe(DecisionPath::JevDeny),
            Conclusion::Unknown => {
                record.failure = Some("JEV_UNKNOWN".to_owned());
                Verdict::Unjudged(DecisionPath::JevUnavailable)
            }
        };
        (verdict, record)
    }

    fn cache_key(
        &self,
        request: &RequestFacts<'_>,
        values: &[crate::values::RequestValue],
    ) -> Digest16 {
        let mut parts: Vec<String> = values
            .iter()
            .map(|v| format!("{}={}", v.at, v.value))
            .collect();
        parts.sort_unstable();
        let text = format!("{}\0{}\0{}", request.method, request.path, parts.join("\0"));
        self.key.mac("cache", text.as_bytes())
    }

    /// Remembers what the origin returned (docs/01 section 1.4 step 8).
    ///
    /// Only 2xx responses count; a failed request teaches the session nothing.
    /// The one exception is a redirect that issues a credential (a login form
    /// answering `302` with `Set-Cookie`): the new session is created, empty.
    pub fn observe(&self, site: &SiteSpec, observation: &Observation<'_>) {
        let success = (200..300).contains(&observation.status);
        let issuing_redirect =
            (300..400).contains(&observation.status) && observation.issued_credential.is_some();
        if !(success || issuing_redirect) || site.is_bypass(observation.path) {
            return;
        }
        let values = if success {
            extract_response(observation.content_type, observation.body)
        } else {
            Vec::new()
        };
        let request = format!("{} {}", observation.method, observation.path);
        let entry = site.is_entry(observation.path);
        let mut inner = self.lock();
        let seeded = if success {
            observation.credential
        } else {
            None
        };
        if success && entry && !observation.client.is_empty() && seeded.is_none_or(str::is_empty) {
            // A sign-up page shows a new user's id to a client that has no
            // session yet; the next sign-up request is judged against that.
            inner
                .store
                .session(
                    self.key.mac("address", observation.client.as_bytes()),
                    observation.now_ms,
                )
                .remember(&self.key, &request, &values);
        }
        for credential in [seeded, observation.issued_credential]
            .into_iter()
            .flatten()
            .filter(|c| !c.is_empty())
        {
            let session = inner.store.session(
                self.key.mac("session", credential.as_bytes()),
                observation.now_ms,
            );
            session.remember(&self.key, &request, &values);
            session.record_request(Recent {
                method: observation.method.to_owned(),
                path: observation.path.to_owned(),
                status: observation.status,
            });
            if entry {
                session.pass_entry(observation.path);
            }
        }
    }

    /// Extracts the configured credential from `cookie_header` / header values.
    #[must_use]
    pub fn credential_from<'a>(
        site: &SiteSpec,
        cookie_header: Option<&'a str>,
        named_header: Option<&'a str>,
    ) -> Option<&'a str> {
        match site.session() {
            SessionCredential::Header(_) => named_header.filter(|value| !value.is_empty()),
            SessionCredential::Cookie(name) => cookie_header.and_then(|cookies| {
                cookies.split(';').find_map(|pair| {
                    let (key, value) = pair.trim().split_once('=')?;
                    (key == name && !value.is_empty()).then_some(value)
                })
            }),
        }
    }

    /// Number of sessions currently held.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.lock().store.len()
    }
}

fn failure_code(failure: JevFailure) -> &'static str {
    match failure {
        JevFailure::Timeout => "JEV_TIMEOUT",
        JevFailure::RateLimited => "JEV_RATE_LIMITED",
        JevFailure::Transport => "JEV_TRANSPORT",
        JevFailure::Http(_) => "JEV_HTTP_ERROR",
        JevFailure::TooLarge => "JEV_RESPONSE_TOO_LARGE",
    }
}

fn apply_policy(site: &SiteSpec, verdict: Verdict) -> (DecisionPath, Outcome, bool, u16) {
    let observing = site.mode() == Mode::Observe;
    let refuse = |path: DecisionPath, status: u16| {
        if observing {
            (path, Outcome::WouldBlock, true, 0)
        } else {
            (path, Outcome::Blocked, false, status)
        }
    };
    match verdict {
        Verdict::Safe(path) => (path, Outcome::Allowed, true, 0),
        Verdict::Unsafe(DecisionPath::NoSession) => refuse(DecisionPath::NoSession, 401),
        Verdict::Unsafe(path) => refuse(path, 403),
        Verdict::Unjudged(path) => match site.on_jev_unavailable() {
            OnJevUnavailable::Allow => (path, Outcome::Unjudged, true, 0),
            OnJevUnavailable::Deny => refuse(path, 403),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jev::JevFailure;
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct FakeJev {
        calls: Arc<AtomicUsize>,
        sent: Arc<Mutex<Vec<String>>>,
        reply: Arc<Mutex<Result<(&'static str, &'static str), JevFailure>>>,
    }

    impl FakeJev {
        fn new() -> Self {
            Self {
                calls: Arc::default(),
                sent: Arc::default(),
                reply: Arc::new(Mutex::new(Ok(("ALLOW", "BENIGN")))),
            }
        }
        fn answer(&self, access: &'static str, attack: &'static str) {
            *self.reply.lock().unwrap() = Ok((access, attack));
        }
        fn fail(&self, failure: JevFailure) {
            *self.reply.lock().unwrap() = Err(failure);
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    fn probabilities(options: [&str; 3], winner: &str) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for option in options {
            map.insert(
                option.to_owned(),
                json!(if option == winner { 0.9 } else { 0.05 }),
            );
        }
        serde_json::Value::Object(map)
    }

    #[async_trait]
    impl JevPort for FakeJev {
        fn model(&self) -> &'static str {
            "fake"
        }
        async fn ask(&self, body: Vec<u8>) -> Result<Vec<u8>, JevFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.sent
                .lock()
                .unwrap()
                .push(String::from_utf8(body).unwrap());
            let (access, attack) = (*self.reply.lock().unwrap())?;
            Ok(json!({"model":"fake","answers":{
                "access":{"type":"choice","choice":access,"probabilities":probabilities(crate::state::ACCESS_OPTIONS, access)},
                "attack":{"type":"choice","choice":attack,"probabilities":probabilities(crate::state::ATTACK_OPTIONS, attack)},
            }})
            .to_string()
            .into_bytes())
        }
    }

    fn site(extra: &str) -> SiteSpec {
        SiteSpec::from_json(&format!(
            r#"{{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{{"cookie":"SID"}},
               "entries":["/login","/api/home","/api/patients","/share/*"],"bypass":["/static/*"]{extra}}}"#
        ))
        .unwrap()
    }

    fn judge(fake: &FakeJev) -> Judge<FakeJev> {
        Judge::new(ContextKey::new(vec![1; 32]), fake.clone())
    }

    fn get<'a>(
        path: &'a str,
        query: Option<&'a str>,
        credential: Option<&'a str>,
        now_ms: u64,
    ) -> RequestFacts<'a> {
        RequestFacts {
            request_id: "r1",
            method: "GET",
            path,
            query,
            content_type: None,
            body: b"",
            credential,
            client: "10.0.0.9",
            now_ms,
        }
    }

    fn list_response(credential: &str, now_ms: u64) -> Observation<'_> {
        Observation {
            credential: Some(credential),
            client: "10.0.0.1",
            issued_credential: None,
            method: "GET",
            path: "/api/patients",
            status: 200,
            content_type: Some("application/json"),
            body: br#"{"items":[{"id":"7","name":"A","age":8},{"id":"9","name":"B"}]}"#,
            now_ms,
        }
    }

    #[tokio::test]
    async fn a1_objects_shown_by_the_list_are_allowed_without_jev() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice", 0));
        let verdict = judge
            .judge(&site, &get("/api/patients/7", None, Some("alice"), 1_000))
            .await;
        assert!(verdict.forward);
        assert_eq!(
            verdict.record.unwrap().decision_path,
            DecisionPath::FastAllow
        );
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn a2_an_unseen_object_goes_to_jev_and_is_blocked_on_deny() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice", 0));
        let verdict = judge
            .judge(
                &site,
                &get("/api/patients/D4411", None, Some("alice"), 1_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.refuse_status, 403);
        let record = verdict.record.unwrap();
        assert_eq!(
            (record.decision_path, record.outcome),
            (DecisionPath::JevDeny, Outcome::Blocked)
        );
        let sent = fake.sent.lock().unwrap();
        assert!(sent[0].contains("D4411") && sent[0].contains("\"seen_as\":[]"));
    }

    #[tokio::test]
    async fn a3_a_new_session_cannot_jump_to_an_object() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice-browser-1", 0));
        let verdict = judge
            .judge(
                &site,
                &get("/api/patients/7", None, Some("alice-browser-2"), 1_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a7_a_short_value_seen_only_as_an_age_is_not_a_reference() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice", 0));
        let verdict = judge
            .judge(&site, &get("/api/patients/8", None, Some("alice"), 1_000))
            .await;
        assert!(!verdict.forward);
        let sent = fake.sent.lock().unwrap();
        assert!(sent[0].contains("age @ GET /api/patients"));
    }

    #[tokio::test]
    async fn a6_a_share_redemption_seeds_the_context() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let redeem = Observation {
            credential: Some("bob"),
            client: "10.0.0.1",
            issued_credential: None,
            method: "GET",
            path: "/share/CODE",
            status: 200,
            content_type: Some("application/json"),
            body: br#"{"patient":{"id":"P-0000001"}}"#,
            now_ms: 0,
        };
        judge.observe(&site, &redeem);
        let verdict = judge
            .judge(
                &site,
                &get("/api/patients/P-0000001", None, Some("bob"), 1_000),
            )
            .await;
        assert!(verdict.forward);
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn a7_without_a_redemption_the_same_request_is_judged() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let verdict = judge
            .judge(
                &site(r#","mode":"enforce""#),
                &get("/api/patients/P-0000001", None, Some("bob"), 0),
            )
            .await;
        assert!(!verdict.forward);
    }

    #[tokio::test]
    async fn b2_attack_content_is_blocked_even_for_seen_ids() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "ATTACK");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice", 0));
        let verdict = judge
            .judge(
                &site,
                &get(
                    "/api/patients/7",
                    Some("q=1%27%20OR%20%271%27%3D%271"),
                    Some("alice"),
                    1_000,
                ),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.unwrap().decision_path, DecisionPath::JevDeny);
    }

    #[tokio::test]
    async fn b1_benign_input_passes_and_is_cached_for_the_same_request() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let first = judge
            .judge(
                &site,
                &get(
                    "/api/search",
                    Some("q=%E6%82%A3%E8%80%85"),
                    Some("alice"),
                    0,
                ),
            )
            .await;
        assert!(first.forward);
        assert_eq!(first.record.unwrap().decision_path, DecisionPath::JevAllow);
        let second = judge
            .judge(
                &site,
                &get(
                    "/api/search",
                    Some("q=%E6%82%A3%E8%80%85"),
                    Some("alice"),
                    60_000,
                ),
            )
            .await;
        assert_eq!(
            second.record.unwrap().decision_path,
            DecisionPath::CachedAllow
        );
        assert_eq!(fake.calls(), 1);
        let third = judge
            .judge(
                &site,
                &get(
                    "/api/search",
                    Some("q=%E6%82%A3%E8%80%85"),
                    Some("alice"),
                    700_000,
                ),
            )
            .await;
        assert_eq!(third.record.unwrap().decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn denials_are_never_cached() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        for now in [0, 1_000] {
            judge
                .judge(&site, &get("/api/patients/D4411", None, Some("alice"), now))
                .await;
        }
        assert_eq!(fake.calls(), 2);
        fake.answer("ALLOW", "BENIGN");
        let verdict = judge
            .judge(
                &site,
                &get("/api/patients/D4411", None, Some("alice"), 2_000),
            )
            .await;
        assert!(verdict.forward);
    }

    #[tokio::test]
    async fn c1_c2_unavailable_jev_follows_the_site_policy() {
        let fake = FakeJev::new();
        fake.fail(JevFailure::Timeout);
        let judge = judge(&fake);
        let denied = judge
            .judge(
                &site(r#","mode":"enforce""#),
                &get("/api/patients/D4411", None, Some("alice"), 0),
            )
            .await;
        assert!(!denied.forward);
        let record = denied.record.unwrap();
        assert_eq!(record.decision_path, DecisionPath::JevUnavailable);
        assert_eq!(record.jev.unwrap().failure.as_deref(), Some("JEV_TIMEOUT"));
        let allowed = judge
            .judge(
                &site(r#","mode":"enforce","on_jev_unavailable":"allow""#),
                &get("/api/patients/D4411", None, Some("alice"), 0),
            )
            .await;
        assert!(allowed.forward);
        assert_eq!(allowed.record.unwrap().outcome, Outcome::Unjudged);
    }

    #[tokio::test]
    async fn unknown_answers_count_as_unavailable() {
        let fake = FakeJev::new();
        fake.answer("UNKNOWN", "BENIGN");
        let judge = judge(&fake);
        let verdict = judge
            .judge(
                &site(r#","mode":"enforce""#),
                &get("/api/patients/D4411", None, Some("alice"), 0),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(
            verdict.record.unwrap().jev.unwrap().failure.as_deref(),
            Some("JEV_UNKNOWN")
        );
    }

    #[tokio::test]
    async fn c3_observe_mode_forwards_but_records_would_block() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let verdict = judge
            .judge(
                &site(""),
                &get("/api/patients/D4411", None, Some("alice"), 0),
            )
            .await;
        assert!(verdict.forward);
        let record = verdict.record.unwrap();
        assert_eq!(
            (record.decision_path, record.outcome),
            (DecisionPath::JevDeny, Outcome::WouldBlock)
        );
    }

    #[tokio::test]
    async fn c4_secrets_never_reach_jev() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site("");
        let login = RequestFacts {
            method: "POST",
            path: "/login",
            content_type: Some("application/json"),
            body: br#"{"username":"alice","password":"hunter2"}"#,
            ..get("/login", None, None, 0)
        };
        let verdict = judge.judge(&site, &login).await;
        assert!(verdict.forward);
        {
            let sent = fake.sent.lock().unwrap();
            assert!(
                !sent[0].contains("hunter2")
                    && sent[0].contains("alice")
                    && sent[0].contains("<redacted>")
            );
        }
        let cookie_in_query = get("/api/x", Some("next=SECRETCOOKIE"), Some("SECRETCOOKIE"), 1);
        judge.judge(&site, &cookie_in_query).await;
        assert!(!fake.sent.lock().unwrap()[1].contains("SECRETCOOKIE"));
    }

    #[tokio::test]
    async fn a_clean_entry_request_without_a_session_is_judged_once() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let poll = RequestFacts {
            method: "GET",
            path: "/login",
            query: Some("name=Score%20Board"),
            ..get("/login", None, None, 0)
        };
        for index in 0..(ADDRESS_CALLS_PER_MINUTE * 2) {
            let at = RequestFacts {
                now_ms: 1_000 + u64::from(index),
                ..poll
            };
            let verdict = judge.judge(&site, &at).await;
            assert!(verdict.forward, "poll {index}");
        }
        assert_eq!(fake.calls(), 1);
        // The injection that follows still reaches Jev with budget left.
        fake.answer("ALLOW", "ATTACK");
        let attack = RequestFacts {
            query: Some("name=%27%20OR%201%3D1--"),
            now_ms: 9_000,
            ..poll
        };
        let verdict = judge.judge(&site, &attack).await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn an_entry_request_is_judged_against_what_its_address_was_shown() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        // A sign-up page: no credential yet, the origin shows the new id.
        let sign_up = |client| RequestFacts {
            client,
            ..get("/api/patients", Some("id=7"), None, 5_000)
        };
        let blind = judge.judge(&site, &sign_up("10.0.0.9")).await;
        assert!(!blind.forward, "an id nobody showed this address");
        assert_eq!(fake.calls(), 1);
        judge.observe(
            &site,
            &Observation {
                credential: None,
                client: "10.0.0.9",
                ..list_response("unused", 1_000)
            },
        );
        let shown = judge.judge(&site, &sign_up("10.0.0.9")).await;
        assert!(shown.forward);
        assert_eq!(shown.record.unwrap().decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
        // Another address was shown nothing.
        let other = judge.judge(&site, &sign_up("10.0.0.2")).await;
        assert!(!other.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn c5_calls_beyond_the_session_limit_follow_the_unavailable_policy() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        for index in 0..SESSION_CALLS_PER_MINUTE {
            let query = format!("q=v{index}x");
            assert!(
                judge
                    .judge(
                        &site,
                        &get("/api/search", Some(&query), Some("alice"), 1_000)
                    )
                    .await
                    .forward
            );
        }
        let over = judge
            .judge(
                &site,
                &get("/api/search", Some("q=over1x"), Some("alice"), 2_000),
            )
            .await;
        assert!(!over.forward);
        assert_eq!(
            over.record.unwrap().jev.unwrap().failure.as_deref(),
            Some("JEV_CALL_LIMIT")
        );
        assert_eq!(fake.calls(), SESSION_CALLS_PER_MINUTE as usize);
        let later = judge
            .judge(
                &site,
                &get("/api/search", Some("q=later1x"), Some("alice"), 62_000),
            )
            .await;
        assert!(later.forward);
    }

    #[tokio::test]
    async fn requests_without_a_session_may_only_reach_entries() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let enforcing = site(r#","mode":"enforce""#);
        let blocked = judge
            .judge(&enforcing, &get("/api/patients/7", None, None, 0))
            .await;
        assert!(!blocked.forward);
        assert_eq!(blocked.refuse_status, 401);
        assert_eq!(
            blocked.record.unwrap().decision_path,
            DecisionPath::NoSession
        );
        let entry = judge
            .judge(&enforcing, &get("/api/home", None, None, 0))
            .await;
        assert!(entry.forward);
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn bypassed_paths_are_forwarded_unlogged_and_unjudged() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let verdict = judge
            .judge(
                &site(r#","mode":"enforce""#),
                &get("/static/app.js", Some("v=abcdefghij"), None, 0),
            )
            .await;
        assert!(verdict.forward && verdict.record.is_none());
        assert_eq!(fake.calls(), 0);
        assert_eq!(judge.session_count(), 0);
    }

    #[tokio::test]
    async fn a_login_redirect_that_issues_a_cookie_seeds_the_new_session() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site("");
        judge.observe(
            &site,
            &Observation {
                credential: None,
                client: "10.0.0.1",
                issued_credential: Some("fresh"),
                method: "POST",
                path: "/login",
                status: 302,
                content_type: None,
                body: b"",
                now_ms: 1,
            },
        );
        assert_eq!(judge.session_count(), 1);
        judge.observe(
            &site,
            &Observation {
                credential: Some("other"),
                client: "10.0.0.1",
                issued_credential: None,
                method: "GET",
                path: "/missing",
                status: 302,
                content_type: None,
                body: b"",
                now_ms: 2,
            },
        );
        assert_eq!(judge.session_count(), 1, "a plain redirect teaches nothing");
    }

    #[tokio::test]
    async fn the_login_response_seeds_the_new_session() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &Observation {
                credential: None,
                client: "10.0.0.1",
                issued_credential: Some("fresh"),
                method: "POST",
                path: "/login",
                status: 200,
                content_type: Some("application/json"),
                body: br#"{"user":{"id":"U-0000001"}}"#,
                now_ms: 0,
            },
        );
        let verdict = judge
            .judge(&site, &get("/api/users/U-0000001", None, Some("fresh"), 1))
            .await;
        assert!(verdict.forward);
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn failed_origin_responses_teach_nothing() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let mut failed = list_response("alice", 0);
        failed.status = 500;
        judge.observe(&site, &failed);
        let verdict = judge
            .judge(&site, &get("/api/patients/7", None, Some("alice"), 1))
            .await;
        assert!(!verdict.forward);
    }

    #[tokio::test]
    async fn unstructured_bodies_always_go_to_jev() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site("");
        let upload = RequestFacts {
            method: "POST",
            content_type: Some("application/octet-stream"),
            body: b"\x00\x01data",
            ..get("/api/upload", None, Some("alice"), 0)
        };
        judge.judge(&site, &upload).await;
        assert_eq!(fake.calls(), 1);
    }

    #[test]
    fn credentials_are_read_from_the_configured_place() {
        let cookie = site("");
        assert_eq!(
            Judge::<FakeJev>::credential_from(&cookie, Some("a=1; SID=abc; b=2"), Some("ignored")),
            Some("abc")
        );
        assert_eq!(
            Judge::<FakeJev>::credential_from(&cookie, Some("SIDX=abc"), None),
            None
        );
        assert_eq!(Judge::<FakeJev>::credential_from(&cookie, None, None), None);
        let header = SiteSpec::from_json(
            r#"{"name":"h","hosts":["h.test"],"origin":"http://o:1","session":{"header":"Authorization"},"entries":["/login"]}"#,
        )
        .unwrap();
        assert_eq!(
            Judge::<FakeJev>::credential_from(&header, Some("SID=x"), Some("Bearer t")),
            Some("Bearer t")
        );
    }
}
