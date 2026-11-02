//! The decision flow of docs/01 section 1.4, and the row that describes each
//! decision (docs/07 sections 7.4 and 7.5).

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use xshield_core::context::{
    Conclusion, ContextKind, DecisionPath, DecisionRecord, FieldCount, JevRecord, Mode,
    ObservationSummary, Observed, OnJevUnavailable, Outcome, SessionCredential, SiteSpec, Skip,
    Trace, TraceSession,
};

use crate::context::{
    CACHE_MINUTES, ContextKey, ContextStore, Digest16, EntryPass, Recent, SENT_MAX, SentRecord,
    Source, label, request_number, request_text, site_synonym,
};
use crate::jev::{JevFailure, JevPort, REPLY_BYTES_MAX};
use crate::state::{
    Answers, Prompt, StateInput, StateValue, build_state, conclude, parse_response, request_body,
};
use crate::trace::{entry_trace, recent_trace, redacted_query, value_entry};
use crate::values::{
    ExtractedRequest, ResponseValue, extract_request, extract_response, percent_decode,
};

/// Jev calls allowed per session per minute (docs/02 section 2.5).
pub const SESSION_CALLS_PER_MINUTE: u32 = 60;
/// Jev calls allowed per client address per minute for requests without a session.
pub const ADDRESS_CALLS_PER_MINUTE: u32 = 30;
const WINDOW_MS: u64 = 60_000;
const LIMITER_MAX: usize = 50_000;
const RECENT_IN_STATE: usize = 10;
/// Field names listed in a response summary (docs/07 section 7.4.3).
const FIELDS_IN_SUMMARY: usize = 12;

/// One request as the gateway sees it, before forwarding.
#[derive(Debug, Clone)]
pub struct RequestFacts<'a> {
    /// Gateway-assigned id, `req_` and 32 hex digits.
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
    /// The row that describes the request (docs/07 section 7.4.1). Every
    /// request gets one, bypassed paths included. The gateway completes the
    /// edge fields and the status before the row is written.
    pub record: DecisionRecord,
    /// Digests of the values the request sent that the session had not seen as
    /// references, or of every token of the request when its values were not all
    /// extracted. Empty unless the request is forwarded. The edge hands them back
    /// in the [`Observation`] of the response, which teaches the session nothing
    /// from an echo of them.
    pub sent: Vec<Digest16>,
}

/// A response the origin returned, for [`Judge::observe`].
#[derive(Debug, Clone)]
pub struct Observation<'a> {
    /// Gateway-assigned id of the request this response answers.
    pub request_id: &'a str,
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
    /// Buffered response body (empty when it was not read).
    pub body: &'a [u8],
    /// Why the body was not read, when the gateway knows: compressed, too
    /// large, or a HEAD request.
    pub unread: Option<Skip>,
    /// The request was judged to be refused and was forwarded because the site
    /// is in observe mode.
    pub would_block: bool,
    /// Unix time in milliseconds.
    pub now_ms: u64,
    /// The digests of the values the request sent (see [`Judgement::sent`]).
    pub sent: &'a [Digest16],
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
    prompt: Prompt,
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

/// The session context a Jev state and its trace are built from, copied out of
/// the lock.
#[derive(Default)]
struct Snapshot {
    age: u64,
    entries: Vec<EntryPass>,
    recent: Vec<Recent>,
}

/// The judging parameters in effect for one request: the code defaults, each
/// replaced by the site's `advanced` section where the site sets it
/// (docs/07 section 7.6.3).
struct Tuning<'a> {
    jev_timeout: Duration,
    session_calls: u32,
    address_calls: u32,
    /// Allow reuse window in milliseconds; 0 turns the cache off.
    cache_ms: u64,
    /// The site's synonym pairs, reduced as the context compares them.
    synonyms: Vec<(String, String)>,
    secret_words: &'a [String],
}

impl<'a> Tuning<'a> {
    fn new(site: &'a SiteSpec, jev_default: Duration) -> Self {
        let advanced = site.advanced();
        let default_ms = u32::try_from(jev_default.as_millis()).unwrap_or(u32::MAX);
        Self {
            jev_timeout: Duration::from_millis(u64::from(advanced.jev_timeout_ms_or(default_ms))),
            session_calls: advanced.session_calls_per_minute_or(SESSION_CALLS_PER_MINUTE),
            address_calls: advanced.address_calls_per_minute_or(ADDRESS_CALLS_PER_MINUTE),
            cache_ms: u64::from(advanced.allow_cache_minutes_or(CACHE_MINUTES)) * 60_000,
            synonyms: advanced
                .synonyms()
                .iter()
                .filter_map(|(first, second)| site_synonym(first, second))
                .collect(),
            secret_words: advanced.secret_fields(),
        }
    }
}

/// One request as the judge works on it: the facts, the entry it matched, the
/// session it names and the parameters of its site.
struct Turn<'a> {
    request: &'a RequestFacts<'a>,
    entry: bool,
    session_id: Option<Digest16>,
    extracted: &'a ExtractedRequest,
    cache_key: &'a Digest16,
    tuning: &'a Tuning<'a>,
}

impl<J: JevPort> Judge<J> {
    /// A judge with empty context.
    #[must_use]
    pub fn new(key: ContextKey, jev: J) -> Self {
        Self {
            key,
            jev,
            prompt: Prompt::new(),
            inner: Mutex::new(Inner {
                store: ContextStore::new(),
                limiter: Limiter::default(),
            }),
        }
    }

    /// The Jev port this judge calls, for the configuration the gateway reports.
    #[must_use]
    pub fn jev(&self) -> &J {
        &self.jev
    }

    /// The fixed questions this judge asks, with their version id.
    #[must_use]
    pub fn prompt(&self) -> &Prompt {
        &self.prompt
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Decides one request (docs/01 section 1.4 steps 1 to 7) and returns the
    /// row that describes the decision.
    pub async fn judge(&self, site: &SiteSpec, request: &RequestFacts<'_>) -> Judgement {
        let started = Instant::now();
        let mut record = base_row(Some(site), request);
        if let Some(pattern) = site.matching_bypass(request.path) {
            record.decision_path = DecisionPath::Bypass;
            record.outcome = Outcome::Allowed;
            record.trace.bypass = Some(pattern.to_owned());
            record.trace.timing.judge_ms = elapsed_millis(started);
            return Judgement {
                forward: true,
                refuse_status: 0,
                record,
                sent: Vec::new(),
            };
        }
        let entry = site.matching_entry(request.path);
        let session_id = request
            .credential
            .filter(|credential| !credential.is_empty())
            .map(|credential| self.key.mac("session", credential.as_bytes()));
        let extracted = extract_request(
            request.path,
            request.query,
            request.content_type,
            request.body,
        );
        let cache_key = self.cache_key(request, &extracted.values);
        let tuning = Tuning::new(site, self.jev.default_timeout());
        record.session = session_id.map(|id| label(&id)).unwrap_or_default();
        record.context = match (session_id, entry) {
            (Some(_), _) => Some(ContextKind::Session),
            (None, Some(_)) => Some(ContextKind::Address),
            (None, None) => None,
        };
        record.trace.entry = entry.map(str::to_owned);
        record.trace.values_truncated = extracted.truncated;
        let turn = Turn {
            request,
            entry: entry.is_some(),
            session_id,
            extracted: &extracted,
            cache_key: &cache_key,
            tuning: &tuning,
        };
        let mut jev = None;
        let mut sent = Vec::new();
        let verdict = match self.plan(&turn, &mut record.trace, &mut sent) {
            Plan::Done(verdict) => verdict,
            Plan::Ask { limit_key, values } => {
                let (verdict, row) = self
                    .ask_jev(&turn, limit_key, values, &mut record.trace)
                    .await;
                jev = Some(row);
                verdict
            }
        };
        let (decision_path, outcome, forward, refuse_status) = apply_policy(site, verdict);
        if forward && extracted.truncated {
            // Values the extraction did not reach are echoed like any other, so
            // every token of the request is noted instead. When they do not fit,
            // the session stops learning from responses.
            match self.token_digests(request) {
                Some(digests) => sent.extend(digests),
                None => self.stop_learning(
                    session_id.or_else(|| {
                        entry.map(|_| self.key.mac("address", request.client.as_bytes()))
                    }),
                    request.now_ms,
                ),
            }
        }
        record.decision_path = decision_path;
        record.outcome = outcome;
        record.jev = jev;
        if outcome == Outcome::Blocked {
            record.trace.refused = Some(
                if refuse_status == 401 {
                    "unauthenticated"
                } else {
                    "forbidden"
                }
                .to_owned(),
            );
        }
        if !forward {
            record.trace.response = Some(not_forwarded());
        }
        record.trace.timing.judge_ms = elapsed_millis(started);
        Judgement {
            forward,
            refuse_status,
            record,
            sent: if forward { sent } else { Vec::new() },
        }
    }

    /// Steps 2 to 5: everything that can be settled without calling Jev. Fills
    /// the trace's values and session as it goes, and collects into `sent` the
    /// digests of the values the session had not seen as references.
    fn plan(&self, turn: &Turn<'_>, trace: &mut Trace, sent: &mut Vec<Digest16>) -> Plan {
        let request = turn.request;
        let tuning = turn.tuning;
        // Without a credential only an entry may pass (a login, a sign-up
        // step). Its context is the client address: what the origin showed
        // that address earlier (a new user's id, the security questions) is
        // the only evidence that the next sign-up request names its own data.
        let session_id = match turn.session_id {
            Some(id) => id,
            None if turn.entry => self.key.mac("address", request.client.as_bytes()),
            None => return Plan::Done(Verdict::Unsafe(DecisionPath::NoSession)),
        };
        let mut inner = self.lock();
        let session = inner.store.session(session_id, request.now_ms);
        let mut all_known = true;
        let mut values = Vec::new();
        let mut shown = Vec::with_capacity(turn.extracted.values.len());
        for value in &turn.extracted.values {
            let key = value.key.as_deref();
            let seen = session.lookup(&self.key, &value.value);
            // The state and the trace both take their sources from this one
            // ranking, so `seen_as[j]` and `sources[j]` always name the same origin.
            let ranked = seen
                .map(|seen| seen.ranked(request.path, key, &tuning.synonyms))
                .unwrap_or_default();
            let verified = !value.inert
                && seen.is_some_and(|seen| {
                    seen.is_specific(&value.value, request.path, key, &tuning.synonyms)
                });
            if !verified {
                // An origin that echoes this value would otherwise teach it.
                sent.push(self.key.mac("value", value.value.as_bytes()));
            }
            if !value.inert {
                all_known &= verified;
                values.push(StateValue {
                    verified,
                    at: value.at.clone(),
                    value: value.value.clone(),
                    key: value.key.clone(),
                    seen_as: ranked
                        .iter()
                        .map(|origin| format!("{} @ {}", origin.field, origin.request))
                        .collect(),
                });
            }
            shown.push(value_entry(
                value,
                seen.is_some(),
                verified,
                &ranked,
                request.credential,
                tuning.secret_words,
            ));
        }
        trace.values = shown;
        trace.session = Some(TraceSession {
            age_seconds: session.age_seconds(request.now_ms),
            known_values: session.seen_len(),
            entries_passed: None,
            recent: None,
        });
        if all_known && !turn.extracted.truncated {
            return Plan::Done(Verdict::Safe(DecisionPath::FastAllow));
        }
        if tuning.cache_ms > 0
            && let Some(source) = session.cached_allow(turn.cache_key, request.now_ms)
        {
            trace.cache_source = request_text(source);
            return Plan::Done(Verdict::Safe(DecisionPath::CachedAllow));
        }
        Plan::Ask {
            limit_key: session_id,
            values,
        }
    }

    /// Steps 6 and 7: asks Jev within the limits and reads its answer. Returns
    /// the verdict with the record of the call.
    async fn ask_jev(
        &self,
        turn: &Turn<'_>,
        limit_key: Digest16,
        values: Vec<StateValue>,
        trace: &mut Trace,
    ) -> (Verdict, JevRecord) {
        let request = turn.request;
        let tuning = turn.tuning;
        let mut row = JevRecord {
            prompt: self.prompt.id().to_owned(),
            model: self.jev.model().to_owned(),
            route: self.jev.route().to_owned(),
            timeout_ms: millis_u32(tuning.jev_timeout),
            ..JevRecord::default()
        };
        let snapshot = match self.admit(request, turn.session_id, limit_key, tuning) {
            Ok(snapshot) => snapshot,
            Err(code) => return unjudged(row, code),
        };
        if let Some(session) = trace.session.as_mut() {
            session.entries_passed = Some(snapshot.entries.iter().map(entry_trace).collect());
            session.recent = Some(snapshot.recent.iter().map(recent_trace).collect());
        }
        let entries: Vec<String> = snapshot
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        let input = StateInput {
            entry_matched: turn.entry,
            session_age_seconds: snapshot.age,
            entries_passed: &entries,
            recent: snapshot.recent.iter().collect(),
            method: request.method,
            path: request.path,
            values,
            truncated: turn.extracted.truncated,
            credential: request.credential,
            secret_words: tuning.secret_words,
        };
        let (state, trim) = match build_state(&input) {
            Ok(built) => built,
            Err(error) => return unjudged(row, &error.to_string()),
        };
        let body = request_body(self.jev.model(), &state, &self.prompt);
        row.trim = Some(trim);
        row.request_bytes = u32::try_from(body.len()).ok();
        row.state = Some(state);
        let started = Instant::now();
        let reply = self.jev.ask(body, tuning.jev_timeout).await;
        row.millis = elapsed_millis(started);
        let reply = match reply {
            Ok(reply) => reply,
            Err(failure) => {
                if let Some((status, body)) = failure_reply(&failure) {
                    row.http_status = Some(status);
                    row.response = Some(lenient_text(body));
                }
                return unjudged(row, failure_code(&failure));
            }
        };
        row.http_status = Some(200);
        row.response = Some(lenient_text(&reply));
        let answers = match parse_response(&reply) {
            Ok(answers) => answers,
            Err(error) => return unjudged(row, &error.to_string()),
        };
        let conclusion = conclude(&answers);
        let Answers {
            access,
            attack,
            usage,
        } = answers;
        row.access = access;
        row.attack = attack;
        row.usage = usage;
        row.conclusion = Some(conclusion);
        let verdict = match conclusion {
            Conclusion::Allow => {
                if tuning.cache_ms > 0 {
                    self.lock()
                        .store
                        .session(turn.session_id.unwrap_or(limit_key), request.now_ms)
                        .cache_allow(
                            *turn.cache_key,
                            request.now_ms,
                            tuning.cache_ms,
                            request_number(request.request_id),
                        );
                }
                Verdict::Safe(DecisionPath::JevAllow)
            }
            Conclusion::Deny => Verdict::Unsafe(DecisionPath::JevDeny),
            Conclusion::Unknown => return unjudged(row, "JEV_UNKNOWN"),
        };
        (verdict, row)
    }

    /// Spends one Jev call from the limiter and copies the session context the
    /// state and the trace are built from. The error is the code of the reason
    /// no call may be made.
    fn admit(
        &self,
        request: &RequestFacts<'_>,
        session_id: Option<Digest16>,
        limit_key: Digest16,
        tuning: &Tuning<'_>,
    ) -> Result<Snapshot, &'static str> {
        let mut inner = self.lock();
        let limit = if session_id.is_some() {
            tuning.session_calls
        } else {
            tuning.address_calls
        };
        if !inner.limiter.allow(limit_key, limit, request.now_ms) {
            return Err("JEV_CALL_LIMIT");
        }
        let Some(id) = session_id else {
            return Ok(Snapshot::default());
        };
        let session = inner.store.session(id, request.now_ms);
        Ok(Snapshot {
            age: session.age_seconds(request.now_ms),
            entries: session.entries_passed().to_vec(),
            recent: session
                .recent(RECENT_IN_STATE)
                .into_iter()
                .cloned()
                .collect(),
        })
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

    /// Remembers what the origin returned (docs/01 section 1.4 step 8) and
    /// says what it taught (docs/07 section 7.4.3).
    ///
    /// Only 2xx responses teach values. A redirect that issues a credential (a
    /// login form answering `302` with `Set-Cookie`) creates the new session,
    /// empty. A failed request teaches nothing.
    pub fn observe(&self, site: &SiteSpec, observation: &Observation<'_>) -> ObservationSummary {
        let bytes = u64::try_from(observation.body.len()).unwrap_or(u64::MAX);
        let mut summary = ObservationSummary::new(
            observation.content_type.map(str::to_owned),
            bytes,
            Observed::Skipped,
        );
        summary.after_would_block = observation.would_block;
        let issued = observation
            .issued_credential
            .filter(|credential| !credential.is_empty());
        summary.issued_session =
            issued.map(|credential| label(&self.key.mac("session", credential.as_bytes())));
        if site.is_bypass(observation.path) {
            summary.skip = Some(Skip::Bypass);
            return summary;
        }
        // The origin answered the request, so an echo of what it sent teaches
        // nothing, whatever the status. A 401 or 403 means the request never
        // reached the application, so nothing it sent can have been echoed.
        let refused = matches!(observation.status, 401 | 403);
        let inherited = if refused {
            None
        } else {
            self.note_request_sent(observation, issued.is_some())
        };
        let success = (200..300).contains(&observation.status);
        let issuing_redirect = (300..400).contains(&observation.status) && issued.is_some();
        if !success {
            summary.skip = Some(Skip::Status);
        }
        if !(success || issuing_redirect) {
            return summary;
        }
        let mut values = Vec::new();
        if success {
            match (observation.unread, response_kind(observation.content_type)) {
                (Some(reason), _) => summary.skip = Some(reason),
                (None, Some(kind)) => {
                    summary.observed = kind;
                    values = extract_response(observation.content_type, observation.body);
                }
                (None, None) => summary.skip = Some(Skip::ContentType),
            }
        }
        summary.values = values.len();
        summary.fields = field_counts(&values);

        let request = format!("{} {}", observation.method, observation.path);
        let request_id = request_number(observation.request_id);
        let source = Source {
            request: &request,
            request_id,
            at_ms: observation.now_ms,
        };
        let entry = site.is_entry(observation.path);
        let seeded = if success {
            observation
                .credential
                .filter(|credential| !credential.is_empty())
        } else {
            None
        };
        let mut inner = self.lock();
        // The new-value count is the one of the first context the response
        // reaches: the address (a sign-up page) or the session.
        let mut new_values = None;
        if success && entry && seeded.is_none() && !observation.client.is_empty() {
            // A sign-up page shows a new user's id to a client that has no
            // session yet; the next sign-up request is judged against that.
            let added = inner
                .store
                .session(
                    self.key.mac("address", observation.client.as_bytes()),
                    observation.now_ms,
                )
                .remember(&self.key, &source, &values);
            new_values = Some(added);
        }
        for credential in [seeded, issued].into_iter().flatten() {
            let session = inner.store.session(
                self.key.mac("session", credential.as_bytes()),
                observation.now_ms,
            );
            if issued == Some(credential) {
                if let Some(record) = &inherited {
                    session.inherit_sent(record);
                }
                session.note_sent(observation.sent);
            }
            let added = session.remember(&self.key, &source, &values);
            if new_values.is_none() {
                new_values = Some(added);
            }
            session.record_request(Recent {
                method: observation.method.to_owned(),
                path: observation.path.to_owned(),
                status: observation.status,
                request_id,
                at_ms: observation.now_ms,
            });
            if entry && session.pass_entry(observation.path, observation.now_ms, request_id) {
                summary.entry_passed = true;
            }
        }
        summary.new_values = new_values.unwrap_or(0);
        summary
    }

    /// Stops the session that `context` names from learning from responses.
    fn stop_learning(&self, context: Option<Digest16>, now_ms: u64) {
        if let Some(context) = context {
            let mut inner = self.lock();
            inner.store.session(context, now_ms).stop_learning();
        }
    }

    /// The digests of every token of a request's path, query and body, for a
    /// request whose values were not all extracted: an echo of any token is then
    /// not learned either. `None` when the tokens do not fit in what a session
    /// may have sent.
    fn token_digests(&self, request: &RequestFacts<'_>) -> Option<Vec<Digest16>> {
        let query = request
            .query
            .map(|query| percent_decode(query, true))
            .unwrap_or_default();
        let body = percent_decode(&String::from_utf8_lossy(request.body), false);
        let text = format!("{} {query} {body}", request.path);
        let mut digests = Vec::new();
        for token in text
            .split(|c: char| {
                !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+'))
            })
            .filter(|token| !token.is_empty())
        {
            if digests.len() == SENT_MAX {
                return None;
            }
            digests.push(self.key.mac("value", token.as_bytes()));
        }
        Some(digests)
    }

    /// Records the values the request sent in the session it was judged in: its
    /// credential, or the client address when it had none. When the response
    /// issues a credential, returns what the request's session sent, for the new
    /// session to inherit.
    fn note_request_sent(
        &self,
        observation: &Observation<'_>,
        issuing: bool,
    ) -> Option<SentRecord> {
        let request_context = match observation
            .credential
            .filter(|credential| !credential.is_empty())
        {
            Some(credential) => self.key.mac("session", credential.as_bytes()),
            None => self.key.mac("address", observation.client.as_bytes()),
        };
        let mut inner = self.lock();
        let inherited = issuing.then(|| inner.store.sent_record(&request_context));
        if !observation.sent.is_empty() {
            inner
                .store
                .session(request_context, observation.now_ms)
                .note_sent(observation.sent);
        }
        inherited
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

/// The row before judging: the request as the gateway read it. `judge` settles
/// the decision fields before the row is returned.
fn base_row(site: Option<&SiteSpec>, request: &RequestFacts<'_>) -> DecisionRecord {
    let secret_words = site.map_or(&[][..], |site| site.advanced().secret_fields());
    DecisionRecord {
        at_millis: request.now_ms,
        request_id: request.request_id.to_owned(),
        site: site.map(|site| site.name().to_owned()),
        site_version: None,
        edge: String::new(),
        host: String::new(),
        client: request.client.to_owned(),
        session: String::new(),
        context: None,
        method: request.method.to_owned(),
        path: request.path.to_owned(),
        query: request
            .query
            .map(|query| redacted_query(query, request.credential, secret_words)),
        status: None,
        decision_path: DecisionPath::NoSession,
        outcome: Outcome::Blocked,
        trace: Trace::new(),
        jev: None,
    }
}

/// The response summary of a request the gateway did not forward.
fn not_forwarded() -> ObservationSummary {
    let mut summary = ObservationSummary::new(None, 0, Observed::Skipped);
    summary.skip = Some(Skip::NotForwarded);
    summary
}

/// The row for a request the gateway refuses before judging, with no Jev call
/// and nothing learned: no site owns its host (`unknown_site`, 404), or its
/// body cannot be inspected (`body_not_inspectable`, 413). Both are refusals
/// that happen whatever the site's mode (docs/07 section 7.4.1).
#[must_use]
pub fn refused_row(
    site: Option<&SiteSpec>,
    request: &RequestFacts<'_>,
    decision_path: DecisionPath,
    status: u16,
) -> DecisionRecord {
    let mut record = base_row(site, request);
    record.decision_path = decision_path;
    record.outcome = Outcome::Blocked;
    record.status = Some(status);
    record.trace.refused = Some(
        if decision_path == DecisionPath::UnknownSite {
            "unknown_site"
        } else {
            "body_not_inspectable"
        }
        .to_owned(),
    );
    record.trace.response = Some(not_forwarded());
    record
}

fn unjudged(mut row: JevRecord, code: &str) -> (Verdict, JevRecord) {
    row.failure = Some(code.to_owned());
    (Verdict::Unjudged(DecisionPath::JevUnavailable), row)
}

fn failure_code(failure: &JevFailure) -> &'static str {
    match failure {
        JevFailure::Timeout => "JEV_TIMEOUT",
        JevFailure::RateLimited { .. } => "JEV_RATE_LIMITED",
        JevFailure::Transport => "JEV_TRANSPORT",
        JevFailure::Http { .. } => "JEV_HTTP_ERROR",
        JevFailure::TooLarge => "JEV_RESPONSE_TOO_LARGE",
    }
}

/// The status and the start of the reply a refused call got back, if any.
fn failure_reply(failure: &JevFailure) -> Option<(u16, &[u8])> {
    match failure {
        JevFailure::RateLimited { body } => Some((429, body.as_slice())),
        JevFailure::Http { status, body } => Some((*status, body.as_slice())),
        _ => None,
    }
}

/// The first [`REPLY_BYTES_MAX`] bytes of a reply, decoded leniently.
fn lenient_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(REPLY_BYTES_MAX)]).into_owned()
}

/// JSON or HTML by content type; anything else is not read.
fn response_kind(content_type: Option<&str>) -> Option<Observed> {
    let lower = content_type?.to_ascii_lowercase();
    if lower.contains("json") {
        Some(Observed::Json)
    } else if lower.starts_with("text/html") {
        Some(Observed::Html)
    } else {
        None
    }
}

/// The most frequent field names of a response with their counts. No values.
fn field_counts(values: &[ResponseValue]) -> Vec<FieldCount> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for value in values {
        *counts.entry(value.field.as_str()).or_default() += 1;
    }
    let mut ranked: Vec<FieldCount> = counts
        .into_iter()
        .map(|(field, count)| FieldCount {
            field: field.to_owned(),
            count,
        })
        .collect();
    ranked.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.field.cmp(&b.field)));
    ranked.truncate(FIELDS_IN_SUMMARY);
    ranked
}

fn elapsed_millis(started: Instant) -> u32 {
    millis_u32(started.elapsed())
}

fn millis_u32(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
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

    /// The gateway id of the origin responses the tests observe.
    const RID: &str = "req_00000000000000000000000000000001";

    #[derive(Clone)]
    struct FakeJev {
        calls: Arc<AtomicUsize>,
        sent: Arc<Mutex<Vec<String>>>,
        timeouts: Arc<Mutex<Vec<Duration>>>,
        reply: Arc<Mutex<Result<(&'static str, &'static str), JevFailure>>>,
    }

    impl FakeJev {
        fn new() -> Self {
            Self {
                calls: Arc::default(),
                sent: Arc::default(),
                timeouts: Arc::default(),
                reply: Arc::new(Mutex::new(Ok(("ALLOW", "BENIGN")))),
            }
        }
        fn timeouts(&self) -> Vec<Duration> {
            self.timeouts.lock().unwrap().clone()
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
        fn route(&self) -> &'static str {
            "fake"
        }
        fn endpoint_host(&self) -> &'static str {
            "fake.test"
        }
        fn default_timeout(&self) -> Duration {
            crate::jev::TIMEOUT
        }
        async fn ask(&self, body: Vec<u8>, timeout: Duration) -> Result<Vec<u8>, JevFailure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.timeouts.lock().unwrap().push(timeout);
            self.sent
                .lock()
                .unwrap()
                .push(String::from_utf8(body).unwrap());
            let (access, attack) = self.reply.lock().unwrap().clone()?;
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
            request_id: "req_00000000000000000000000000000002",
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
            request_id: RID,
            unread: None,
            would_block: false,
            credential: Some(credential),
            client: "10.0.0.1",
            issued_credential: None,
            method: "GET",
            path: "/api/patients",
            status: 200,
            content_type: Some("application/json"),
            body: br#"{"items":[{"id":"7","name":"A","age":8},{"id":"9","name":"B"}]}"#,
            now_ms,
            sent: &[],
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
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
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
        let record = verdict.record;
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

    /// What the origin showed `credential` for `GET path`.
    fn shown<'a>(path: &'a str, body: &'a [u8], credential: &'a str) -> Observation<'a> {
        Observation {
            request_id: RID,
            unread: None,
            would_block: false,
            credential: Some(credential),
            client: "10.0.0.1",
            issued_credential: None,
            method: "GET",
            path,
            status: 200,
            content_type: Some("application/json"),
            body,
            now_ms: 0,
            sent: &[],
        }
    }

    /// What the origin showed the session of `verdict` for `GET path`: the
    /// response to that request, with the digests the judgement sent.
    fn answered<'a>(
        verdict: &'a Judgement,
        path: &'a str,
        body: &'a [u8],
        credential: &'a str,
    ) -> Observation<'a> {
        Observation {
            sent: &verdict.sent,
            ..shown(path, body, credential)
        }
    }

    #[tokio::test]
    async fn a_doctor_id_the_origin_showed_passes_the_same_number_on_the_doctor_path() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor_id":1,"name":"Dr A"}"#, "doctor-a"),
        );
        let verdict = judge
            .judge(&site, &get("/doctor/1", None, Some("doctor-a"), 1_000))
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn a_doctor_id_the_session_never_saw_on_the_doctor_path_goes_to_jev() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor_id":1,"name":"Dr A"}"#, "doctor-a"),
        );
        let verdict = judge
            .judge(&site, &get("/doctor/2", None, Some("doctor-a"), 1_000))
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.refuse_status, 403);
        assert_eq!(fake.calls(), 1);
        let sent = fake.sent.lock().unwrap();
        assert!(sent[0].contains(r#""value":"2""#) && sent[0].contains(r#""seen_as":[]"#));
    }

    #[tokio::test]
    async fn a_document_id_does_not_unlock_a_doctor_path() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor_id":1,"name":"Dr A"}"#, "doctor-a"),
        );
        judge.observe(&site, &shown("/api/docs", br#"{"doc_id":2}"#, "doctor-a"));
        let verdict = judge
            .judge(&site, &get("/doctor/2", None, Some("doctor-a"), 1_000))
            .await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_search_that_echoes_its_query_does_not_make_the_id_seen() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        // Jev allows the search, and the origin echoes the query back.
        let search = judge
            .judge(
                &site,
                &get("/api/search", Some("q=P-0000099"), Some("alice"), 1_000),
            )
            .await;
        assert!(search.forward);
        judge.observe(
            &site,
            &answered(
                &search,
                "/api/search",
                br#"{"query":"P-0000099","results":[]}"#,
                "alice",
            ),
        );
        // The id is not known, so Jev is asked again; its DENY blocks the request.
        fake.answer("DENY", "BENIGN");
        let object = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("alice"), 2_000),
            )
            .await;
        assert!(!object.forward);
        assert_eq!(object.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn an_id_field_that_echoes_a_sent_value_does_not_make_it_seen() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let search = judge
            .judge(
                &site,
                &get(
                    "/api/search",
                    Some("patientId=P-0000099"),
                    Some("alice"),
                    1_000,
                ),
            )
            .await;
        assert!(search.forward);
        judge.observe(
            &site,
            &answered(
                &search,
                "/api/search",
                br#"{"patientId":"P-0000099","results":[]}"#,
                "alice",
            ),
        );
        fake.answer("DENY", "BENIGN");
        let object = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("alice"), 2_000),
            )
            .await;
        assert!(!object.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_later_listing_of_an_earlier_search_does_not_make_the_id_seen() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let search = judge
            .judge(
                &site,
                &get("/api/search", Some("q=P-0000099"), Some("alice"), 1_000),
            )
            .await;
        assert!(search.forward);
        judge.observe(
            &site,
            &answered(&search, "/api/search", br#"{"results":[]}"#, "alice"),
        );
        // Later the origin lists the searches it ran, with the id under an id field.
        let history = judge
            .judge(
                &site,
                &get("/api/search/history", None, Some("alice"), 2_000),
            )
            .await;
        assert!(history.forward);
        judge.observe(
            &site,
            &answered(
                &history,
                "/api/search/history",
                br#"{"recent":[{"patientId":"P-0000099"}]}"#,
                "alice",
            ),
        );
        fake.answer("DENY", "BENIGN");
        let object = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("alice"), 3_000),
            )
            .await;
        assert!(!object.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_long_value_in_a_free_text_field_is_not_an_object_reference() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &shown(
                "/api/comments",
                br#"{"items":[{"text":"P-0000077"}]}"#,
                "alice",
            ),
        );
        let comment = judge
            .judge(
                &site,
                &get("/api/patients/P-0000077", None, Some("alice"), 1_000),
            )
            .await;
        assert!(!comment.forward);
        assert_eq!(fake.calls(), 1);
        // The same id under an id field is an object the origin showed.
        judge.observe(
            &site,
            &shown(
                "/api/patients",
                br#"{"items":[{"patient_id":"P-0000077"}]}"#,
                "carol",
            ),
        );
        let listed = judge
            .judge(
                &site,
                &get("/api/patients/P-0000077", None, Some("carol"), 2_000),
            )
            .await;
        assert!(listed.forward);
        assert_eq!(listed.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_login_that_echoes_its_input_does_not_seed_the_session_it_issues() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let login = RequestFacts {
            method: "POST",
            content_type: Some("application/json"),
            body: br#"{"userId":"P-0000099"}"#,
            client: "10.0.0.1",
            ..get("/login", None, None, 1_000)
        };
        let judged = judge.judge(&site, &login).await;
        assert!(judged.forward);
        judge.observe(
            &site,
            &Observation {
                request_id: RID,
                unread: None,
                would_block: false,
                credential: None,
                client: "10.0.0.1",
                issued_credential: Some("fresh"),
                method: "POST",
                path: "/login",
                status: 200,
                content_type: Some("application/json"),
                body: br#"{"userId":"P-0000099","token":"t"}"#,
                now_ms: 1_001,
                sent: &judged.sent,
            },
        );
        fake.answer("DENY", "BENIGN");
        let object = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("fresh"), 2_000),
            )
            .await;
        assert!(!object.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_renewed_credential_does_not_learn_what_the_old_one_sent() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let search = judge
            .judge(
                &site,
                &get("/api/search", Some("q=P-0000099"), Some("alice"), 1_000),
            )
            .await;
        judge.observe(
            &site,
            &answered(&search, "/api/search", br#"{"results":[]}"#, "alice"),
        );
        // A later response renews the session and echoes the id under the new credential.
        let renew = judge
            .judge(
                &site,
                &RequestFacts {
                    method: "POST",
                    ..get("/api/session/renew", None, Some("alice"), 2_000)
                },
            )
            .await;
        assert!(renew.forward);
        judge.observe(
            &site,
            &Observation {
                request_id: RID,
                unread: None,
                would_block: false,
                credential: Some("alice"),
                client: "10.0.0.1",
                issued_credential: Some("renewed"),
                method: "POST",
                path: "/api/session/renew",
                status: 200,
                content_type: Some("application/json"),
                body: br#"{"patientId":"P-0000099"}"#,
                now_ms: 2_001,
                sent: &renew.sent,
            },
        );
        fake.answer("DENY", "BENIGN");
        let object = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("renewed"), 3_000),
            )
            .await;
        assert!(!object.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_request_with_more_tokens_than_a_session_can_hold_stops_its_learning() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        // Its tokens cannot all be recorded as sent, so no later echo can be told apart.
        let body = (0..=SENT_MAX)
            .map(|index| format!("t{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let upload = RequestFacts {
            method: "POST",
            content_type: Some("text/plain"),
            body: body.as_bytes(),
            ..get("/api/import", None, Some("alice"), 1_000)
        };
        assert!(judge.judge(&site, &upload).await.forward);
        judge.observe(
            &site,
            &shown(
                "/api/patients",
                br#"{"items":[{"id":"P-0000042"}]}"#,
                "alice",
            ),
        );
        fake.answer("DENY", "BENIGN");
        let object = judge
            .judge(
                &site,
                &get("/api/patients/P-0000042", None, Some("alice"), 2_000),
            )
            .await;
        assert!(!object.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_body_declared_as_text_that_the_origin_parses_teaches_its_echo_nothing() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        // The gateway cannot read this body, but the origin parses it and echoes the id.
        let search = RequestFacts {
            method: "POST",
            content_type: Some("text/plain"),
            body: br#"{"patientId":"P-0000099"}"#,
            ..get("/api/search", None, Some("alice"), 1_000)
        };
        let searched = judge.judge(&site, &search).await;
        assert!(searched.forward);
        judge.observe(
            &site,
            &Observation {
                method: "POST",
                ..answered(
                    &searched,
                    "/api/search",
                    br#"{"patientId":"P-0000099","results":[]}"#,
                    "alice",
                )
            },
        );
        fake.answer("DENY", "BENIGN");
        let object = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("alice"), 2_000),
            )
            .await;
        assert!(!object.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a6_a_share_redemption_seeds_the_context() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let redeem = Observation {
            request_id: RID,
            unread: None,
            would_block: false,
            credential: Some("bob"),
            client: "10.0.0.1",
            issued_credential: None,
            method: "GET",
            path: "/share/CODE",
            status: 200,
            content_type: Some("application/json"),
            body: br#"{"patient":{"id":"P-0000001"}}"#,
            now_ms: 0,
            sent: &[],
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
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
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
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
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
        assert_eq!(second.record.decision_path, DecisionPath::CachedAllow);
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
        assert_eq!(third.record.decision_path, DecisionPath::JevAllow);
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
        let record = denied.record;
        assert_eq!(record.decision_path, DecisionPath::JevUnavailable);
        assert_eq!(record.jev.unwrap().failure.as_deref(), Some("JEV_TIMEOUT"));
        let allowed = judge
            .judge(
                &site(r#","mode":"enforce","on_jev_unavailable":"allow""#),
                &get("/api/patients/D4411", None, Some("alice"), 0),
            )
            .await;
        assert!(allowed.forward);
        assert_eq!(allowed.record.outcome, Outcome::Unjudged);
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
            verdict.record.jev.unwrap().failure.as_deref(),
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
        let record = verdict.record;
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
                request_id: RID,
                unread: None,
                would_block: false,
                credential: None,
                client: "10.0.0.9",
                ..list_response("unused", 1_000)
            },
        );
        let shown = judge.judge(&site, &sign_up("10.0.0.9")).await;
        assert!(shown.forward);
        assert_eq!(shown.record.decision_path, DecisionPath::FastAllow);
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
            over.record.jev.unwrap().failure.as_deref(),
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
        assert_eq!(blocked.record.decision_path, DecisionPath::NoSession);
        let entry = judge
            .judge(&enforcing, &get("/api/home", None, None, 0))
            .await;
        assert!(entry.forward);
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn bypassed_paths_are_forwarded_unjudged_and_still_logged() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let verdict = judge
            .judge(
                &site(r#","mode":"enforce""#),
                &get("/static/app.js", Some("v=abcdefghij"), None, 0),
            )
            .await;
        assert!(verdict.forward);
        let record = verdict.record;
        assert_eq!(
            (record.decision_path, record.outcome),
            (DecisionPath::Bypass, Outcome::Allowed)
        );
        assert_eq!(record.trace.bypass.as_deref(), Some("/static/*"));
        assert!(record.jev.is_none());
        assert_eq!(record.query.as_deref(), Some("v=abcdefghij"));
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
                request_id: RID,
                unread: None,
                would_block: false,
                credential: None,
                client: "10.0.0.1",
                issued_credential: Some("fresh"),
                method: "POST",
                path: "/login",
                status: 302,
                content_type: None,
                body: b"",
                now_ms: 1,
                sent: &[],
            },
        );
        assert_eq!(judge.session_count(), 1);
        judge.observe(
            &site,
            &Observation {
                request_id: RID,
                unread: None,
                would_block: false,
                credential: Some("other"),
                client: "10.0.0.1",
                issued_credential: None,
                method: "GET",
                path: "/missing",
                status: 302,
                content_type: None,
                body: b"",
                now_ms: 2,
                sent: &[],
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
                request_id: RID,
                unread: None,
                would_block: false,
                credential: None,
                client: "10.0.0.1",
                issued_credential: Some("fresh"),
                method: "POST",
                path: "/login",
                status: 200,
                content_type: Some("application/json"),
                body: br#"{"user":{"id":"U-0000001"}}"#,
                now_ms: 0,
                sent: &[],
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

    #[tokio::test]
    async fn a_site_without_advanced_keeps_the_code_defaults() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        judge
            .judge(
                &site(""),
                &get("/api/search", Some("q=default1x"), Some("alice"), 0),
            )
            .await;
        assert_eq!(fake.timeouts(), [crate::jev::TIMEOUT]);
    }

    #[tokio::test]
    async fn a_site_jev_timeout_replaces_the_default() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let plain = site(r#","mode":"enforce""#);
        let tuned = site(r#","mode":"enforce","advanced":{"jev_timeout_ms":3000}"#);
        judge
            .judge(&plain, &get("/api/patients/D1", None, Some("alice"), 0))
            .await;
        judge
            .judge(&tuned, &get("/api/patients/D2", None, Some("bob"), 0))
            .await;
        assert_eq!(
            fake.timeouts(),
            [crate::jev::TIMEOUT, Duration::from_millis(3000)]
        );
    }

    #[tokio::test]
    async fn a_site_session_limit_replaces_the_default() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce","advanced":{"session_calls_per_minute":2}"#);
        for index in 0..2 {
            let query = format!("q=v{index}x");
            let verdict = judge
                .judge(
                    &site,
                    &get("/api/search", Some(&query), Some("alice"), 1_000),
                )
                .await;
            assert!(verdict.forward);
        }
        let over = judge
            .judge(
                &site,
                &get("/api/search", Some("q=over1x"), Some("alice"), 2_000),
            )
            .await;
        assert!(!over.forward);
        assert_eq!(
            over.record.jev.unwrap().failure.as_deref(),
            Some("JEV_CALL_LIMIT")
        );
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_site_address_limit_replaces_the_default() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce","advanced":{"address_calls_per_minute":1}"#);
        // Sessionless entry requests are limited by client address.
        let first = judge
            .judge(&site, &get("/login", Some("name=first1"), None, 0))
            .await;
        assert!(first.forward);
        let second = judge
            .judge(&site, &get("/login", Some("name=second1"), None, 1_000))
            .await;
        assert!(!second.forward);
        assert_eq!(
            second.record.jev.unwrap().failure.as_deref(),
            Some("JEV_CALL_LIMIT")
        );
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_zero_cache_minutes_judges_every_repeat() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","advanced":{"allow_cache_minutes":0}"#);
        for now in [0, 60_000] {
            let verdict = judge
                .judge(
                    &site,
                    &get("/api/search", Some("q=same1x"), Some("alice"), now),
                )
                .await;
            assert_eq!(verdict.record.decision_path, DecisionPath::JevAllow);
        }
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn site_secret_fields_are_redacted_before_jev_sees_them() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let plain = site("");
        let guarded = site(r#","advanced":{"secret_fields":["ssn"]}"#);
        let login = |body: &'static [u8]| RequestFacts {
            method: "POST",
            path: "/login",
            content_type: Some("application/json"),
            body,
            ..get("/login", None, None, 0)
        };
        judge.judge(&plain, &login(br#"{"ssn":"123456789"}"#)).await;
        judge
            .judge(&guarded, &login(br#"{"ssn":"987654321"}"#))
            .await;
        let sent = fake.sent.lock().unwrap();
        assert!(
            sent[0].contains("123456789"),
            "the built-in words do not cover ssn"
        );
        assert!(!sent[1].contains("987654321"));
        assert!(sent[1].contains("<redacted>"));
    }

    #[tokio::test]
    async fn a_site_synonym_lets_a_short_value_count_as_shown() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let plain = site(r#","mode":"enforce""#);
        let synonym = site(r#","mode":"enforce","advanced":{"synonyms":[["wallet","account"]]}"#);
        // The account list showed id 7 to this session.
        judge.observe(
            &plain,
            &Observation {
                request_id: RID,
                unread: None,
                would_block: false,
                credential: Some("alice"),
                client: "10.0.0.1",
                issued_credential: None,
                method: "GET",
                path: "/api/Accounts",
                status: 200,
                content_type: Some("application/json"),
                body: br#"{"id":7,"name":"Acme"}"#,
                now_ms: 0,
                sent: &[],
            },
        );
        let request = get(
            "/api/accounts/7/transfers",
            Some("walletId=7"),
            Some("alice"),
            1_000,
        );
        let without = judge.judge(&plain, &request).await;
        assert!(!without.forward, "walletId does not name an account");
        assert_eq!(fake.calls(), 1);
        let with = judge
            .judge(
                &synonym,
                &RequestFacts {
                    now_ms: 2_000,
                    ..request.clone()
                },
            )
            .await;
        assert!(with.forward);
        assert_eq!(with.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
    }

    #[test]
    fn a_list_response_is_summarized_without_its_values() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let summary = judge.observe(&site, &list_response("alice", 0));
        assert_eq!(summary.observed, Observed::Json);
        assert_eq!(summary.skip, None);
        assert_eq!(summary.values, 5);
        assert_eq!(summary.new_values, 5);
        assert!(summary.entry_passed);
        let fields: Vec<(&str, usize)> = summary
            .fields
            .iter()
            .map(|field| (field.field.as_str(), field.count))
            .collect();
        assert_eq!(fields, [("id", 2), ("name", 2), ("age", 1)]);
    }

    #[test]
    fn a_response_that_is_not_read_says_why() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let mut failed = list_response("alice", 0);
        failed.status = 500;
        let summary = judge.observe(&site, &failed);
        assert_eq!(summary.skip, Some(Skip::Status));
        assert_eq!(summary.values, 0);
        assert_eq!(judge.session_count(), 0);

        let mut large = list_response("alice", 0);
        large.unread = Some(Skip::TooLarge);
        large.body = &[];
        let summary = judge.observe(&site, &large);
        assert_eq!(summary.skip, Some(Skip::TooLarge));
        assert_eq!(summary.values, 0);
    }

    #[tokio::test]
    async fn a_jev_record_says_what_was_asked_and_answered() {
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
        let jev = verdict.record.jev.expect("Jev was asked");
        assert!(jev.prompt.starts_with("jq_") && jev.prompt.len() == 19);
        assert_eq!((jev.route.as_str(), jev.model.as_str()), ("fake", "fake"));
        assert_eq!(jev.timeout_ms, 2_000);
        assert_eq!(jev.trim, Some(0));
        assert_eq!(jev.conclusion, Some(Conclusion::Deny));
        assert_eq!(jev.http_status, Some(200));
        assert!(jev.access["DENY"] > 0.5);
        assert!(jev.request_bytes.is_some_and(|bytes| bytes > 0));
        assert!(
            jev.state
                .as_deref()
                .is_some_and(|state| state.contains("D4411"))
        );
        assert!(jev.failure.is_none());
    }

    #[tokio::test]
    async fn a_refused_jev_call_keeps_its_status_and_reply() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice", 0));
        let cases = [
            (
                JevFailure::Http {
                    status: 503,
                    body: b"busy, try later".to_vec(),
                },
                503,
                "busy, try later",
                "JEV_HTTP_ERROR",
            ),
            (
                JevFailure::RateLimited {
                    body: b"slow down".to_vec(),
                },
                429,
                "slow down",
                "JEV_RATE_LIMITED",
            ),
        ];
        for (failure, status, reply, code) in cases {
            fake.fail(failure);
            let verdict = judge
                .judge(
                    &site,
                    &get("/api/patients/D4411", None, Some("alice"), 1_000),
                )
                .await;
            let record = verdict.record;
            let jev = record.jev.expect("Jev was asked");
            assert_eq!(jev.http_status, Some(status));
            assert_eq!(jev.response.as_deref(), Some(reply));
            assert_eq!(jev.failure.as_deref(), Some(code));
            assert_eq!(record.decision_path, DecisionPath::JevUnavailable);
            assert_eq!(record.outcome, Outcome::Blocked);
        }
    }

    #[tokio::test]
    async fn a_cached_allow_names_the_request_that_was_allowed() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let first = judge
            .judge(
                &site,
                &get("/api/patients/D4411", None, Some("alice"), 1_000),
            )
            .await;
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
        let second = judge
            .judge(
                &site,
                &get("/api/patients/D4411", None, Some("alice"), 2_000),
            )
            .await;
        assert_eq!(second.record.decision_path, DecisionPath::CachedAllow);
        assert_eq!(
            second.record.trace.cache_source.as_deref(),
            Some("req_00000000000000000000000000000002")
        );
    }

    #[tokio::test]
    async fn the_state_and_the_trace_line_up_value_by_value() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice", 5_000));
        let query = format!("token=Sekr3t&note={}", "x".repeat(300));
        let request = RequestFacts {
            request_id: "req_00000000000000000000000000000003",
            method: "POST",
            path: "/api/patients/7/notes",
            query: Some(&query),
            content_type: Some("application/json"),
            body: br#"{"ids":[7,9,42],"text":"hello"}"#,
            credential: Some("alice"),
            client: "10.0.0.9",
            now_ms: 1_000,
        };
        let verdict = judge.judge(&site, &request).await;
        let record = verdict.record;
        let jev = record.jev.expect("Jev was asked");
        let state_text = jev.state.expect("the state was sent");
        assert!(!state_text.contains("Sekr3t"));
        let state: serde_json::Value = serde_json::from_str(&state_text).unwrap();
        let shown = state["request"]["values"].as_array().unwrap();
        let traced: Vec<&xshield_core::context::TraceValue> = record
            .trace
            .values
            .iter()
            .filter(|value| !value.inert)
            .collect();
        assert_eq!(shown.len(), traced.len());
        for (state_value, trace_value) in shown.iter().zip(&traced) {
            assert_eq!(state_value["at"].as_str(), Some(trace_value.at.as_str()));
            for (index, text) in state_value["seen_as"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
            {
                let source = trace_value
                    .sources
                    .get(index)
                    .expect("a source per seen_as");
                let expected = format!("{} @ {}", source.field, source.request);
                assert_eq!(text.as_str(), Some(expected.as_str()));
            }
        }
        assert_eq!(shown.iter().filter(|v| v["at"] == "body.ids[]").count(), 3);
        assert_eq!(traced.iter().filter(|v| v.at == "body.ids[]").count(), 3);

        // Inert values stay out of the state but still appear in the trace; the
        // secret is redacted in both.
        let token = record
            .trace
            .values
            .iter()
            .find(|v| v.at == "query.token")
            .expect("token");
        assert_eq!((token.value.as_str(), token.len), ("<redacted>", Some(6)));
        let state_token = shown
            .iter()
            .find(|v| v["at"] == "query.token")
            .expect("token");
        assert_eq!(state_token["value"], "<redacted>");

        let note = traced.iter().find(|v| v.at == "query.note").expect("note");
        assert!(note.clipped);
        assert_eq!((note.value.chars().count(), note.len), (256, Some(300)));
        let state_note = shown
            .iter()
            .find(|v| v["at"] == "query.note")
            .expect("note");
        assert_eq!(state_note["value"].as_str().map(str::len), Some(300));

        let seven = traced.iter().find(|v| v.at == "path[2]").expect("path[2]");
        assert_eq!(seven.sources[0].request_id.as_deref(), Some(RID));
        assert_eq!(seven.sources[0].at_millis, Some(5_000));

        let state_recent = state["recent"].as_array().map_or(0, Vec::len);
        let traced_recent = record
            .trace
            .session
            .as_ref()
            .and_then(|session| session.recent.as_ref())
            .map_or(0, Vec::len);
        assert!(state_recent <= traced_recent);
        assert!(!record.query.unwrap_or_default().contains("Sekr3t"));
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
