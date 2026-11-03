//! The decision flow of docs/01 section 1.4, and the row that describes each
//! decision (docs/07 sections 7.4 and 7.5).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use xshield_core::context::{
    Conclusion, ContextKind, DecisionPath, DecisionRecord, FINGERPRINT_SLOTS_MAX,
    FINGERPRINTS_PER_SLOT_MAX, FieldCount, JevRecord, Mode, ObjectMap, ObservationSummary,
    Observed, OnJevUnavailable, Outcome, Reliability, Resolved, SessionCredential, ShapeField,
    SiteSpec, Skip, Tier, Trace, TraceSession, TraceValue,
};
use xshield_core::kind::{Rules, Used};

use crate::context::{
    CACHE_MINUTES, ContextKey, ContextStore, Digest16, EntryPass, Origin, Recent, SENT_MAX,
    SentRecord, SessionContext, Source, label, request_number, request_text,
};
use crate::exposure;
use crate::jev::{JevFailure, JevPort, REPLY_BYTES_MAX, failure_code};
use crate::slots::{
    identity_claims, origin_object, origin_tier, reliability_name, request_access, request_slot,
    response_slot, route_template, tier_name,
};
use crate::state::{
    Answers, Prompt, StateInput, StateValue, build_state, conclude, parse_response, request_body,
};
use crate::tiers;
use crate::trace::{Place, entry_trace, recent_trace, redacted_query, value_entry};
use crate::values::{
    ExtractedRequest, ResponseValue, extract_request, extract_response_facts, json_unescape,
    path_segment, percent_decode,
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
    /// The route resolution of the request: its logical path and interface name.
    /// `None` when no route covers it, which is a plain resolution of `path`.
    pub route: Option<&'a Resolved>,
    /// The request's header names, lower case, as the decision row keeps them.
    pub request_headers: &'a [String],
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
    /// Digests of the values the request sent that the site's tiers turn down: an attempt, or a
    /// sighting that proves no right (docs/01 section 1.4). Empty unless the request is forwarded.
    /// The edge hands them back in the [`Observation`] of this request's response only: that
    /// response teaches nothing from them, but a later response may show such a value as the
    /// object it is (a listing of the session's own objects).
    pub echo: Vec<Digest16>,
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
    /// The request's route resolution; `None` when no route covers it.
    pub route: Option<&'a Resolved>,
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
    /// The digests of the values the tiers turned down for this request (see [`Judgement::echo`]).
    pub echo: &'a [Digest16],
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
    /// The last structure reported per route: route digest to structure digest.
    shapes: HashMap<Digest16, Digest16>,
}

/// Routes whose structure is remembered; the memory starts again when full.
const SHAPES_MAX: usize = 4_096;

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

/// What settling a request's values came to: the values the state lists, the
/// values the trace lists, whether every value was verified, and whether one of
/// them is an attempt.
struct PlannedValues {
    values: Vec<StateValue>,
    shown: Vec<TraceValue>,
    all_known: bool,
    attempted: bool,
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
    /// The site's kind rules: synonym pairs and declared field kinds.
    rules: Rules,
    secret_words: &'a [String],
    /// The site's object map: the kind of object each confirmed position carries.
    objects: &'a ObjectMap,
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
            rules: Rules::of(advanced),
            secret_words: advanced.secret_fields(),
            objects: site.objects(),
        }
    }
}

/// One request as the judge works on it: the facts, the entry it matched, the
/// session it names and the parameters of its site.
struct Turn<'a> {
    request: &'a RequestFacts<'a>,
    /// The request's logical path and interface name.
    resolved: &'a Resolved,
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
                shapes: HashMap::new(),
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
    // The steps for one request stay in one function, in the order they happen, as observe() does.
    #[allow(clippy::too_many_lines)]
    pub async fn judge(&self, site: &SiteSpec, request: &RequestFacts<'_>) -> Judgement {
        let started = Instant::now();
        let routed = resolved_of(request);
        let resolved: &Resolved = &routed;
        let mut record = base_row(Some(site), request, resolved);
        // Entries and bypass patterns see the logical path (URL path plus the
        // interface name). An unknown interface has no such path: it is never an
        // entry and never bypassed.
        let logical = resolved.entry_path();
        if let Some(pattern) = logical.and_then(|path| site.matching_bypass(path)) {
            record.decision_path = DecisionPath::Bypass;
            record.outcome = Outcome::Allowed;
            record.trace.bypass = Some(pattern.to_owned());
            record.trace.timing.judge_ms = elapsed_millis(started);
            return Judgement {
                forward: true,
                refuse_status: 0,
                record,
                sent: Vec::new(),
                echo: Vec::new(),
            };
        }
        let entry = logical.and_then(|path| site.matching_entry(path));
        let session_id = request
            .credential
            .filter(|credential| !credential.is_empty())
            .map(|credential| self.key.mac("session", credential.as_bytes()));
        let mut extracted = extract_request(
            request.path,
            request.query,
            request.content_type,
            request.body,
        );
        settle_values(&mut extracted, resolved);
        let tuning = Tuning::new(site, self.jev.default_timeout());
        let admin = self.is_administrator(session_id, request.now_ms);
        let cache_key = self.cache_key(request, resolved, &extracted.values, tuning.objects, admin);
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
            resolved,
            entry: entry.is_some(),
            session_id,
            extracted: &extracted,
            cache_key: &cache_key,
            tuning: &tuning,
        };
        let mut jev = None;
        let mut sent = Vec::new();
        let mut echo = Vec::new();
        let verdict = match self.plan(&turn, &mut record.trace, &mut sent, &mut echo) {
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
            echo: if forward { echo } else { Vec::new() },
        }
    }

    /// Steps 2 to 5: everything that can be settled without calling Jev. Fills
    /// the trace's values and session as it goes, and collects into `sent` the
    /// digests of the values the session had not seen as references, and into
    /// `echo` the digests of the values the tiers turned down.
    fn plan(
        &self,
        turn: &Turn<'_>,
        trace: &mut Trace,
        sent: &mut Vec<Digest16>,
        echo: &mut Vec<Digest16>,
    ) -> Plan {
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
        let PlannedValues {
            values,
            shown,
            all_known,
            attempted,
        } = self.plan_values(turn, session, sent, echo);
        trace.values = shown;
        trace.session = Some(TraceSession {
            age_seconds: session.age_seconds(request.now_ms),
            known_values: session.seen_len(),
            entries_passed: None,
            recent: None,
            identity: session.identity().tag(),
        });
        // An unknown interface always goes to Jev: neither its values nor a cached
        // allow of another request can settle it.
        let unknown = turn.resolved.is_unknown();
        if all_known && !attempted && !turn.extracted.truncated && !unknown {
            return Plan::Done(Verdict::Safe(DecisionPath::FastAllow));
        }
        // An attempt goes to Jev, whatever an earlier allow of the same request said.
        if tuning.cache_ms > 0
            && !unknown
            && !attempted
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

    /// Settles each value of the request against what the session saw: fills the
    /// state's values and the trace's values, and collects into `sent` the digests
    /// of the values the session had not seen as references, and into `echo` the
    /// digests of the values the tiers turned down.
    fn plan_values(
        &self,
        turn: &Turn<'_>,
        session: &SessionContext,
        sent: &mut Vec<Digest16>,
        echo: &mut Vec<Digest16>,
    ) -> PlannedValues {
        let request = turn.request;
        let tuning = turn.tuning;
        let mut all_known = true;
        let mut attempted = false;
        let mut values = Vec::new();
        let mut shown = Vec::with_capacity(turn.extracted.values.len());
        let admin = session.identity().is_admin();
        for value in &turn.extracted.values {
            let used = Used {
                value: &value.value,
                path: turn.resolved.logical_path(),
                key: value.key.as_deref(),
                segment: path_segment(&value.at),
            };
            let seen = session.lookup(&self.key, &value.value);
            // The state and the trace both take their sources from this one
            // ranking, so `seen_as[j]` and `sources[j]` always name the same origin.
            let ranked = seen
                .map(|seen| seen.ranked(used, &tuning.rules))
                .unwrap_or_default();
            // The position is named by the logical path, as the response positions are: the URL
            // path plus the interface name of a routed request (docs/07 section 7.4.7).
            let slot = request_slot(request.method, turn.resolved.logical_path(), &value.at);
            let request_object = tuning.objects.class_of(&slot);
            let access = request_access(tuning.objects, &slot);
            // The origins that show the value as the kind of object the request names for
            // it; the site's tiers then say which of them prove a right (docs/01 section 1.4).
            let shown_as_object = seen
                .map(|seen| {
                    seen.shown_origins(used, &tuning.rules, request_object, |origin| {
                        origin_object(tuning.objects, origin)
                    })
                })
                .unwrap_or_default();
            let judged = tiers::judge(&ranked, &shown_as_object, access, tuning.objects, admin);
            let verified = !value.inert && judged.verified;
            // An attempt goes to Jev marked as one; the gateway never allows it on its own.
            let attempt = judged.attempt.filter(|_| !value.inert);
            if !verified {
                // An origin that echoes this value would otherwise teach it. A value the tiers
                // turn down was shown to the session, so only this request's own response is kept
                // from learning it: a later listing may show the value as the session's own.
                // Any other value stays out of the session's learning, as before tiers.
                let digest = self.key.mac("value", value.value.as_bytes());
                let turned_down =
                    attempt.is_some() || (!value.inert && !shown_as_object.is_empty());
                if turned_down {
                    echo.push(digest);
                } else {
                    sent.push(digest);
                }
            }
            let origin_objects: Vec<Option<String>> = ranked
                .iter()
                .map(|origin| origin_object(tuning.objects, origin).map(str::to_owned))
                .collect();
            let origin_tiers: Vec<Option<(Tier, Reliability)>> = ranked
                .iter()
                .map(|origin| origin_tier(tuning.objects, origin))
                .collect();
            if !value.inert {
                all_known &= verified;
                attempted |= attempt.is_some();
                values.push(StateValue {
                    verified,
                    at: value.at.clone(),
                    value: value.value.clone(),
                    key: value.key.clone(),
                    seen_as: ranked
                        .iter()
                        .zip(&origin_objects)
                        .zip(&origin_tiers)
                        .map(|((origin, object), tier)| seen_text(origin, object.as_deref(), *tier))
                        .collect(),
                    object: request_object.map(str::to_owned),
                    public_access: access,
                    attempt,
                });
            }
            let place = Place {
                slot,
                object: request_object.map(str::to_owned),
                origin_objects,
                origin_tiers,
                public_access: access,
                attempt,
            };
            shown.push(value_entry(
                value,
                seen.is_some(),
                verified,
                &ranked,
                request.credential,
                tuning.secret_words,
                place,
            ));
        }
        PlannedValues {
            values,
            shown,
            all_known,
            attempted,
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
            model: self.jev.model(),
            route: self.jev.route(),
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
            path: turn.resolved.logical_path(),
            values,
            truncated: turn.extracted.truncated,
            credential: request.credential,
            secret_words: tuning.secret_words,
        };
        let (state, trim) = match build_state(&input) {
            Ok(built) => built,
            Err(error) => return unjudged(row, &error.to_string()),
        };
        let body = request_body(&self.jev.model(), &state, &self.prompt);
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
                if tuning.cache_ms > 0 && !turn.resolved.is_unknown() {
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

    /// Whether the session is an administrator's: its declared role is the administrator's
    /// (docs/07 section 7.4.7). A request without a session is not.
    fn is_administrator(&self, session_id: Option<Digest16>, now_ms: u64) -> bool {
        session_id.is_some_and(|id| self.lock().store.session(id, now_ms).identity().is_admin())
    }

    /// The allow cache key: the method, the logical path and the request values.
    /// The interface name is part of the logical path, so two methods that take
    /// the same values never share an allow. The key also names the site's object
    /// map: a map change can turn the same request into a different judgement, so
    /// an allow made under the old map must not be reused under the new one. And it
    /// names whether the session is an administrator's: an administrator's admin-tier
    /// proofs stop proving once the role changes, so an allow made under one flag is
    /// not reused under the other.
    fn cache_key(
        &self,
        request: &RequestFacts<'_>,
        resolved: &Resolved,
        values: &[crate::values::RequestValue],
        objects: &ObjectMap,
        admin: bool,
    ) -> Digest16 {
        let mut parts: Vec<String> = values
            .iter()
            .map(|v| format!("{}={}", v.at, v.value))
            .collect();
        parts.sort_unstable();
        let text = format!(
            "{}\0{}\0{}\0{}",
            request.method,
            resolved.logical_path(),
            u8::from(admin),
            parts.join("\0")
        );
        let map = serde_json::to_string(objects).unwrap_or_default();
        let map = self.key.mac("objects", map.as_bytes());
        self.key
            .mac("cache", &[map.as_slice(), text.as_bytes()].concat())
    }

    /// Remembers what the origin returned (docs/01 section 1.4 step 8) and
    /// says what it taught (docs/07 section 7.4.3).
    ///
    /// Only 2xx responses teach values. A redirect that issues a credential (a
    /// login form answering `302` with `Set-Cookie`) creates the new session,
    /// empty. A failed request teaches nothing.
    // The steps for one response stay in one function, in the order they happen: learning, then
    // the identity and the exposure alert that read what was just learned.
    #[allow(clippy::too_many_lines)]
    pub fn observe(&self, site: &SiteSpec, observation: &Observation<'_>) -> ObservationSummary {
        let routed = routed_observation(observation);
        let resolved: &Resolved = &routed;
        let logical = resolved.entry_path();
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
        if logical.is_some_and(|path| site.is_bypass(path)) {
            summary.skip = Some(Skip::Bypass);
            return summary;
        }
        // The origin answered the request, so an echo of what it sent teaches
        // nothing, whatever the status: a refused request's values can still come
        // back in a later response, such as a list of recent attempts.
        let inherited = self.note_request_sent(observation, issued.is_some());
        let success = (200..300).contains(&observation.status);
        let issuing_redirect = (300..400).contains(&observation.status) && issued.is_some();
        if !success {
            summary.skip = Some(Skip::Status);
        }
        if !(success || issuing_redirect) {
            return summary;
        }
        let (mut values, shape) = if success {
            read_body(&mut summary, observation)
        } else {
            (Vec::new(), None)
        };
        self.count_values(site, observation, resolved, &values, &mut summary);
        // The exposure alert reads the response as the origin sent it, echo included: an origin
        // that returns another user's contact details with the id the client asked for still
        // discloses them. Learning and the identity claims read it without the echo.
        let as_sent = values.clone();
        self.without_echo(&mut values, observation.echo);

        let request = format!("{} {}", observation.method, resolved.logical_path());
        let request_id = request_number(observation.request_id);
        let source = Source {
            request: &request,
            request_id,
            at_ms: observation.now_ms,
        };
        let entry = logical.is_some_and(|path| site.is_entry(path));
        let seeded = observation
            .credential
            .filter(|credential| success && !credential.is_empty());
        let claims = identity_claims(site.objects(), &request, &values);
        let mut inner = self.lock();
        if let Some(shape) = shape {
            summary.shape = shape_if_new(
                &mut inner.shapes,
                &self.key,
                site.name(),
                observation.method,
                observation.path,
                shape,
            );
        }
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
            session.declare_identity(&self.key, &claims);
            if summary.exposure.is_none() {
                summary.exposure = exposure::exposure(
                    site.objects(),
                    observation.method,
                    resolved.logical_path(),
                    &as_sent,
                    |value| session.identity().is_other_user(&self.key, value),
                );
            }
            if new_values.is_none() {
                new_values = Some(added);
            }
            session.record_request(Recent {
                method: observation.method.to_owned(),
                path: resolved.logical_path().to_owned(),
                status: observation.status,
                request_id,
                at_ms: observation.now_ms,
            });
            if entry && session.pass_entry(resolved.logical_path(), observation.now_ms, request_id)
            {
                summary.entry_passed = true;
            }
        }
        summary.new_values = new_values.unwrap_or(0);
        summary
    }

    /// Counts a response's values and fingerprints them into its summary. This is done before the
    /// echo of the request is dropped, so the counts describe the response as the origin sent it.
    fn count_values(
        &self,
        site: &SiteSpec,
        observation: &Observation<'_>,
        resolved: &Resolved,
        values: &[ResponseValue],
        summary: &mut ObservationSummary,
    ) {
        summary.values = values.len();
        summary.fields = field_counts(values);
        summary.fingerprints = fingerprints(&self.key, site, observation, resolved, values);
    }

    /// Drops the values of a response that are an echo of the request it answers: the tiers turned
    /// those request values down, so the response teaches nothing from them and declares no
    /// identity from them (see [`Judgement::echo`]).
    fn without_echo(&self, values: &mut Vec<ResponseValue>, echo: &[Digest16]) {
        if !echo.is_empty() {
            values.retain(|value| !echo.contains(&self.key.mac("value", value.value.as_bytes())));
        }
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
    /// not learned either. Each token is taken from the text as sent and as the
    /// origin may decode it: percent escapes in the path, query and body, and
    /// JSON `\uXXXX` escapes in the body. `None` when the distinct tokens do not
    /// fit in what a session may have sent.
    fn token_digests(&self, request: &RequestFacts<'_>) -> Option<Vec<Digest16>> {
        let query = request.query.unwrap_or("");
        let body = String::from_utf8_lossy(request.body);
        let texts = [
            request.path.to_owned(),
            percent_decode(request.path, false),
            query.to_owned(),
            percent_decode(query, true),
            body.to_string(),
            percent_decode(&body, false),
            json_unescape(&body),
        ];
        let mut digests = HashSet::new();
        for text in &texts {
            for token in text
                .split(|c: char| {
                    !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+'))
                })
                .filter(|token| !token.is_empty())
            {
                digests.insert(self.key.mac("value", token.as_bytes()));
                if digests.len() > SENT_MAX {
                    return None;
                }
            }
        }
        Some(digests.into_iter().collect())
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

/// The route resolution of an observed response: the one the edge computed, or the
/// plain one when no route covers its request.
fn routed_observation<'a>(observation: &Observation<'a>) -> Cow<'a, Resolved> {
    observation.route.map_or_else(
        || Cow::Owned(Resolved::plain(observation.path)),
        Cow::Borrowed,
    )
}

/// The request's route resolution: the one the edge computed, or the plain one
/// when no route covers the request.
fn resolved_of<'a>(request: &RequestFacts<'a>) -> Cow<'a, Resolved> {
    request
        .route
        .map_or_else(|| Cow::Owned(Resolved::plain(request.path)), Cow::Borrowed)
}

/// Takes out of the request's values the ones that are the interface name (they
/// are the name now, not values to verify), and marks the URL path segments a
/// route fixes as inert: they are configuration.
fn settle_values(extracted: &mut ExtractedRequest, resolved: &Resolved) {
    extracted
        .values
        .retain(|value| !resolved.name_locations().contains(&value.at));
    for value in &mut extracted.values {
        let fixed = value
            .at
            .strip_prefix("path[")
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|index| index.parse::<usize>().ok())
            .is_some_and(|index| index < resolved.fixed_segments());
        if fixed {
            value.inert = true;
        }
    }
}

/// What `seen_as` says of one origin: `field @ request`, then the kind of object its response
/// position carries, then, where the map gives the position a tier, the tier and how sure the
/// map is of it. A site without tiers reads exactly as it did before tiers.
fn seen_text(origin: &Origin, object: Option<&str>, tier: Option<(Tier, Reliability)>) -> String {
    let base = match object {
        Some(kind) => format!("{} @ {} [{kind}]", origin.field, origin.request),
        None => format!("{} @ {}", origin.field, origin.request),
    };
    match tier {
        Some((tier, reliability)) => format!(
            "{base} (tier {}, reliability {})",
            tier_name(tier),
            reliability_name(reliability)
        ),
        None => base,
    }
}

/// The row before judging: the request as the gateway read it. `judge` settles
/// the decision fields before the row is returned.
fn base_row(
    site: Option<&SiteSpec>,
    request: &RequestFacts<'_>,
    resolved: &Resolved,
) -> DecisionRecord {
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
        logical_path: resolved.logical_path().to_owned(),
        api: resolved.api().cloned(),
        request_headers: request.request_headers.to_vec(),
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
    let routed = resolved_of(request);
    let mut record = base_row(site, request, &routed);
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

/// Reads the body of a successful response: its values and, for a JSON document
/// that parsed, its structure. Says in `summary` why a body was not read.
fn read_body(
    summary: &mut ObservationSummary,
    observation: &Observation<'_>,
) -> (Vec<ResponseValue>, Option<Vec<ShapeField>>) {
    match (observation.unread, response_kind(observation.content_type)) {
        (Some(reason), _) => summary.skip = Some(reason),
        (None, Some(kind)) => {
            summary.observed = kind;
            let facts = extract_response_facts(observation.content_type, observation.body);
            return (facts.values, facts.shape);
        }
        (None, None) => summary.skip = Some(Skip::ContentType),
    }
    (Vec::new(), None)
}

/// The structure to report for a route of a site: `Some` when it is new or
/// differs from the one last reported, `None` when it repeats. Only digests are
/// kept. One judge serves every site, so the site is part of the route.
fn shape_if_new(
    shapes: &mut HashMap<Digest16, Digest16>,
    key: &ContextKey,
    site: &str,
    method: &str,
    path: &str,
    shape: Vec<ShapeField>,
) -> Option<Vec<ShapeField>> {
    let route = key.mac(
        "shape-route",
        format!("{site}\0{method} {}", route_template(path)).as_bytes(),
    );
    let mut text = String::new();
    for field in &shape {
        text.push_str(&field.path);
        text.push('\0');
        text.push_str(&field.kind);
        text.push('\n');
    }
    let signature = key.mac("shape", text.as_bytes());
    if shapes.get(&route) == Some(&signature) {
        return None;
    }
    if shapes.len() >= SHAPES_MAX {
        shapes.clear();
    }
    shapes.insert(route, signature);
    Some(shape)
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

/// The fingerprints of the values a response showed, per response position
/// (docs/07 section 7.4.3): the first positions in the order the response shows
/// them, and of each position's values the smallest fingerprints.
fn fingerprints(
    key: &ContextKey,
    site: &SiteSpec,
    observation: &Observation<'_>,
    resolved: &Resolved,
    values: &[ResponseValue],
) -> BTreeMap<String, Vec<String>> {
    let (method, path) = (observation.method, resolved.logical_path());
    let mut kept: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for value in values {
        let Some(slot) = response_slot(method, path, &value.at) else {
            continue;
        };
        if !kept.contains_key(&slot) && kept.len() >= FINGERPRINT_SLOTS_MAX {
            continue;
        }
        let digests = kept.entry(slot).or_default();
        digests.insert(site_fingerprint(key, site.name(), &value.value));
        if digests.len() > FINGERPRINTS_PER_SLOT_MAX {
            digests.pop_last();
        }
    }
    kept.into_iter()
        .map(|(slot, digests)| (slot, digests.into_iter().collect::<Vec<String>>()))
        .collect()
}

/// The keyed fingerprint of a response value at one site: 16 hex digits, the
/// form the log uses for labels. The site is part of the keyed message, so the
/// same value fingerprints differently at another site.
fn site_fingerprint(key: &ContextKey, site: &str, value: &str) -> String {
    let mut message = Vec::with_capacity(8 + site.len() + value.len());
    message.extend_from_slice(&u64::try_from(site.len()).unwrap_or(u64::MAX).to_be_bytes());
    message.extend_from_slice(site.as_bytes());
    message.extend_from_slice(value.as_bytes());
    label(&key.mac("fingerprint", &message))
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
        fn model(&self) -> String {
            "fake".to_owned()
        }
        fn route(&self) -> String {
            "fake".to_owned()
        }
        fn endpoint(&self) -> String {
            "https://fake.test/v1".to_owned()
        }
        fn endpoint_host(&self) -> String {
            "fake.test".to_owned()
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
            route: None,
            request_headers: &[],
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
            route: None,
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
            echo: &[],
        }
    }

    /// A site with one route: the interface name is the `x-method` header.
    fn routed_site(extra: &str) -> SiteSpec {
        SiteSpec::from_json(&format!(
            r#"{{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{{"cookie":"SID"}},
               "entries":["/api/rpc/login"],
               "routes":[{{"path":"/api/rpc","name_from":[["header.x-method"]]}}]{extra}}}"#
        ))
        .expect("the test site is valid")
    }

    /// The route resolution of a request to `path` whose `x-method` header is
    /// `name`; `None` leaves the header out.
    fn resolved(site: &SiteSpec, path: &str, name: Option<&str>) -> Resolved {
        let headers: Vec<(&str, &str)> = name.map(|name| ("x-method", name)).into_iter().collect();
        site.resolve(&xshield_core::context::RequestView {
            path,
            query: None,
            headers: &headers,
            body: xshield_core::context::Body::Unread,
        })
    }

    #[tokio::test]
    async fn a_routed_delete_is_placed_by_its_logical_path() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = routed_site(
            r#","mode":"enforce","objects":{"classes":[{"id":"patient","name":"患者"}],"slots":[
                {"key":"GET /api/search results[].id","class":"patient","source":"admin","tier":"public","reliability":"high"},
                {"key":"POST /api/rpc/deletePatient body.patient_id","class":"patient","source":"admin","accepts_public":false,"reliability":"high"}
            ]}"#,
        );
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        let delete = resolved(&site, "/api/rpc", Some("deletePatient"));
        let verdict = judge
            .judge(
                &site,
                &RequestFacts {
                    route: Some(&delete),
                    method: "POST",
                    content_type: Some("application/json"),
                    body: br#"{"patient_id":"7005"}"#,
                    ..get("/api/rpc", None, Some("alice"), 2_000)
                },
            )
            .await;
        // The public search showed the patient, and the routed delete names the closed position
        // at its logical path, so the sighting is an attempt: Jev judges it, no fast allow.
        assert_ne!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_route_judges_an_entry_by_its_logical_path() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = routed_site(r#","mode":"enforce""#);
        // The login method is the entry; another method at the same URL path is not.
        let login = resolved(&site, "/api/rpc", Some("login"));
        let other = resolved(&site, "/api/rpc", Some("getDoctor"));
        let verdict = judge
            .judge(
                &site,
                &RequestFacts {
                    route: Some(&login),
                    method: "POST",
                    ..get("/api/rpc", None, None, 1_000)
                },
            )
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.logical_path, "/api/rpc/login");
        assert_eq!(verdict.record.context, Some(ContextKind::Address));
        let verdict = judge
            .judge(
                &site,
                &RequestFacts {
                    route: Some(&other),
                    ..get("/api/rpc", None, None, 1_000)
                },
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::NoSession);
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn an_unknown_interface_always_goes_to_jev() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = routed_site(r#","mode":"enforce""#);
        // Without the header the interface name is missing: an unknown interface.
        // It has no values to check, yet only Jev may allow it.
        let unknown = resolved(&site, "/api/rpc", None);
        let verdict = judge
            .judge(
                &site,
                &RequestFacts {
                    route: Some(&unknown),
                    ..get("/api/rpc", None, Some("alice"), 1_000)
                },
            )
            .await;
        assert_eq!(verdict.record.logical_path, "/api/rpc");
        assert!(matches!(
            verdict.record.api,
            Some(xshield_core::context::Api::Unknown { .. })
        ));
        assert_eq!(verdict.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 1);
    }

    #[test]
    fn the_allow_cache_key_names_the_interface() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = routed_site("");
        let login = resolved(&site, "/api/rpc", Some("login"));
        let other = resolved(&site, "/api/rpc", Some("getDoctor"));
        let request = get("/api/rpc", Some("id=7"), Some("alice"), 1_000);
        // Two interfaces at one URL path, taking the same values, never share an allow.
        assert_ne!(
            judge.cache_key(&request, &login, &[], site.objects(), false),
            judge.cache_key(&request, &other, &[], site.objects(), false)
        );
    }

    #[tokio::test]
    async fn a_paused_entry_leaves_its_position_to_the_name() {
        let entry = |paused: &str| {
            site(&format!(
                r#","mode":"enforce","objects":{{
                    "classes":[{{"id":"patient","name":"患者"}},{{"id":"document","name":"文档"}}],
                    "slots":[{{"key":"GET /api/patients/{{id}} path[2]","class":"document","source":"admin"{paused}}}]}}"#
            ))
        };
        // Declared as a document, the position is not a patient the list showed: Jev decides.
        let declared_fake = FakeJev::new();
        let declared_judge = judge(&declared_fake);
        let declared = entry("");
        declared_judge.observe(&declared, &list_response("alice", 0));
        let verdict = declared_judge
            .judge(
                &declared,
                &get("/api/patients/7", None, Some("alice"), 1_000),
            )
            .await;
        assert_ne!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(declared_fake.calls(), 1);
        // Paused, the entry is not used, so the position is judged by its name as it was before.
        let paused_fake = FakeJev::new();
        let paused_judge = judge(&paused_fake);
        let paused = entry(r#","paused":true"#);
        paused_judge.observe(&paused, &list_response("alice", 0));
        let verdict = paused_judge
            .judge(&paused, &get("/api/patients/7", None, Some("alice"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(paused_fake.calls(), 0);
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
            route: None,
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
            echo: &[],
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
            route: None,
            sent: &verdict.sent,
            echo: &verdict.echo,
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
            route: None,
            request_headers: &[],
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
                route: None,
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
                echo: &judged.echo,
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
                    route: None,
                    request_headers: &[],
                    method: "POST",
                    ..get("/api/session/renew", None, Some("alice"), 2_000)
                },
            )
            .await;
        assert!(renew.forward);
        judge.observe(
            &site,
            &Observation {
                route: None,
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
                echo: &renew.echo,
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
            route: None,
            request_headers: &[],
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
            route: None,
            request_headers: &[],
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
                route: None,
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
    async fn a_value_a_refused_request_sent_is_not_learned_from_a_later_echo() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        // Jev allows the request, and the origin refuses it with 403.
        let refused = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("alice"), 1_000),
            )
            .await;
        assert!(refused.forward);
        judge.observe(
            &site,
            &Observation {
                route: None,
                status: 403,
                ..answered(
                    &refused,
                    "/api/patients/P-0000099",
                    br#"{"error":"forbidden"}"#,
                    "alice",
                )
            },
        );
        // A later response lists the refused id under an id field.
        let home = judge
            .judge(&site, &get("/api/home", None, Some("alice"), 2_000))
            .await;
        assert!(home.forward);
        judge.observe(
            &site,
            &answered(
                &home,
                "/api/home",
                br#"{"recent":[{"id":"P-0000099"}]}"#,
                "alice",
            ),
        );
        fake.answer("DENY", "BENIGN");
        // The first request's allow is cached for minutes, so the same request an
        // hour on is judged afresh.
        let object = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("alice"), 3_600_000),
            )
            .await;
        assert!(!object.forward);
        // Jev was asked for the refused request and for the object; the list needed none.
        assert_eq!(fake.calls(), 2);
        assert_eq!(home.record.decision_path, DecisionPath::FastAllow);
    }

    #[tokio::test]
    async fn a_truncated_body_with_a_json_escape_teaches_its_echo_nothing() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        // The gateway cannot read this body as JSON, but the origin does, and it
        // decodes the escaped id before echoing it. The body is `{"patientId":"\u0050-0000099"}`.
        let search = RequestFacts {
            route: None,
            request_headers: &[],
            method: "POST",
            content_type: Some("text/plain"),
            body: b"{\"patientId\":\"\\u0050-0000099\"}",
            ..get("/api/search", None, Some("alice"), 1_000)
        };
        let searched = judge.judge(&site, &search).await;
        assert!(searched.forward);
        judge.observe(
            &site,
            &Observation {
                route: None,
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

    /// Whether the origin's response `body` at `origin_path` lets the request to
    /// `path` pass without Jev. The session is new, so only this response counts.
    async fn fast_allowed(
        judge: &Judge<FakeJev>,
        site: &SiteSpec,
        session: &str,
        (origin_path, body): (&str, &[u8]),
        path: &str,
    ) -> bool {
        judge.observe(site, &shown(origin_path, body, session));
        let verdict = judge
            .judge(site, &get(path, None, Some(session), 1_000))
            .await;
        verdict.forward && verdict.record.decision_path == DecisionPath::FastAllow
    }

    #[tokio::test]
    async fn a_declared_field_kind_decides_which_path_a_value_unlocks() {
        // The rows of docs/field-kinds-design.md section 3, where `doc_id` names a doctor.
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let everywhere = site(
            r#","mode":"enforce","advanced":{"field_kinds":[{"field":"doc_id","kind":"doctor"}]}"#,
        );
        // The declaration's name and kind are written differently; both still match.
        let appointments = site(
            r#","mode":"enforce","advanced":{"field_kinds":[{"field":"DocID","kind":"doctors","in":["/api/appointments*"]}]}"#,
        );
        let appointment = ("/api/appointments", br#"{"doc_id":2}"#.as_slice());
        // A: the appointment's doc_id is a doctor, so the doctor path passes.
        assert!(fast_allowed(&judge, &everywhere, "a", appointment, "/doctor/2").await);
        assert!(fast_allowed(&judge, &appointments, "a2", appointment, "/doctor/2").await);
        // B: a document id from the documents list is not a doctor.
        let documents = ("/api/docs", br#"{"id":5}"#.as_slice());
        assert!(!fast_allowed(&judge, &everywhere, "b", documents, "/doctor/5").await);
        // C: the declared doctor is not a document.
        assert!(!fast_allowed(&judge, &everywhere, "c", appointment, "/docs/2").await);
        // D: a record's doc_id names a document. Without a scope the declaration
        // makes it a doctor everywhere; the scope is what keeps it out of doctor paths.
        let record = (
            "/api/records/7",
            br#"{"attachments":{"doc_id":5}}"#.as_slice(),
        );
        assert!(fast_allowed(&judge, &everywhere, "d", record, "/doctor/5").await);
        assert!(!fast_allowed(&judge, &appointments, "d2", record, "/doctor/5").await);
        // D': on a document path the record's id is a document again.
        assert!(!fast_allowed(&judge, &everywhere, "d3", record, "/docs/5").await);
        assert!(fast_allowed(&judge, &appointments, "d4", record, "/docs/5").await);
    }

    #[tokio::test]
    async fn a_declared_kind_on_a_query_key_decides_by_the_key() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let plain = site(r#","mode":"enforce""#);
        let declared = site(
            r#","mode":"enforce","advanced":{"field_kinds":[{"field":"doc","kind":"doctor"}]}"#,
        );
        let scheduled = site(
            r#","mode":"enforce","advanced":{"field_kinds":[{"field":"doc","kind":"doctor","in":["/api/schedule*"]}]}"#,
        );
        // Without a declaration the abbreviated `doc` names a document, not a doctor.
        judge.observe(&plain, &shown("/api/home", br#"{"doctor_id":2}"#, "plain"));
        let verdict = judge
            .judge(
                &plain,
                &get("/doctor/2", Some("doc=2"), Some("plain"), 1_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 1);
        // With the declaration the key names a doctor, so the value passes.
        judge.observe(
            &declared,
            &shown("/api/home", br#"{"doctor_id":2}"#, "declared"),
        );
        let verdict = judge
            .judge(
                &declared,
                &get("/doctor/2", Some("doc=2"), Some("declared"), 1_000),
            )
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
        // A scope limited to schedule paths does not cover this request's path.
        judge.observe(
            &scheduled,
            &shown("/api/home", br#"{"doctor_id":2}"#, "scheduled"),
        );
        let verdict = judge
            .judge(
                &scheduled,
                &get("/doctor/2", Some("doc=2"), Some("scheduled"), 1_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_path_id_is_judged_by_the_route_word_before_it() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &shown(
                "/api/doctors",
                br#"[{"id":7,"name":"Dr A"},{"id":9,"name":"Dr B"}]"#,
                "doctor-a",
            ),
        );
        let verdict = judge
            .judge(&site, &get("/api/doctors/9", None, Some("doctor-a"), 1_000))
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
        // Under `files` the 9 is a file id, which no doctor list showed.
        let verdict = judge
            .judge(
                &site,
                &get("/api/doctors/7/files/9", None, Some("doctor-a"), 2_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_bare_id_is_judged_by_its_object_or_the_route_word_at_the_end() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &shown(
                "/api/doctors",
                br#"[{"id":7,"name":"Dr A"},{"id":9,"name":"Dr B"}]"#,
                "bare",
            ),
        );
        // `?id=9` on a file path names the file the path addresses, so doctor 9 does not pass.
        let verdict = judge
            .judge(
                &site,
                &get("/api/doctors/7/files", Some("id=9"), Some("bare"), 1_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 1);
        // On the doctors path the same key names a doctor, and 9 is one.
        let verdict = judge
            .judge(
                &site,
                &get("/api/doctors", Some("id=9"), Some("bare"), 2_000),
            )
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
        // A bare body id takes the file as well, but a doctor named by its parent passes.
        let body_id = RequestFacts {
            method: "POST",
            content_type: Some("application/json"),
            body: br#"{"id":9}"#,
            ..get("/api/doctors/7/files", None, Some("bare"), 3_000)
        };
        assert!(!judge.judge(&site, &body_id).await.forward);
        assert_eq!(fake.calls(), 2);
        let nested = RequestFacts {
            body: br#"{"doctor":{"id":9}}"#,
            now_ms: 4_000,
            ..body_id
        };
        let verdict = judge.judge(&site, &nested).await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 2);
        // A document id under `doc` is a document wherever the record is.
        judge.observe(
            &site,
            &shown("/api/docs", br#"[{"id":5,"title":"Consent"}]"#, "bare"),
        );
        let record = RequestFacts {
            method: "POST",
            content_type: Some("application/json"),
            body: br#"{"doc":{"id":5}}"#,
            ..get("/api/records", None, Some("bare"), 5_000)
        };
        let verdict = judge.judge(&site, &record).await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_bare_id_in_a_file_list_is_a_file_not_a_doctor() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        // The bare ids of doctor 7's file list are files, whatever the path also names.
        judge.observe(
            &site,
            &shown(
                "/api/doctors/7/files",
                br#"[{"id":8,"name":"a.pdf"},{"id":9,"name":"b.pdf"}]"#,
                "files",
            ),
        );
        // Doctor 9 was never shown as a doctor, so the doctor path does not pass.
        let verdict = judge
            .judge(&site, &get("/api/doctors/9", None, Some("files"), 1_000))
            .await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 1);
        // The file 9 passes on a file path, as the list showed it.
        let verdict = judge
            .judge(&site, &get("/api/files/9", None, Some("files"), 2_000))
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a6_a_share_redemption_seeds_the_context() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let redeem = Observation {
            route: None,
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
            echo: &[],
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
    async fn an_allow_made_under_the_old_object_map_is_not_reused_under_a_new_one() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let query = Some("q=%E6%82%A3%E8%80%85");
        let first = judge
            .judge(
                &site(r#","mode":"enforce""#),
                &get("/api/search", query, Some("alice"), 0),
            )
            .await;
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
        let mapped = site(
            r#","mode":"enforce","objects":{
                "classes":[{"id":"doctor","name":"医生"}],
                "slots":[{"key":"GET /doctor/{id} path[1]","class":"doctor","source":"admin"}]}"#,
        );
        let second = judge
            .judge(&mapped, &get("/api/search", query, Some("alice"), 1_000))
            .await;
        assert_eq!(second.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 2);
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
            route: None,
            request_headers: &[],
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
            route: None,
            request_headers: &[],
            method: "GET",
            path: "/login",
            query: Some("name=Score%20Board"),
            ..get("/login", None, None, 0)
        };
        for index in 0..(ADDRESS_CALLS_PER_MINUTE * 2) {
            let at = RequestFacts {
                route: None,
                request_headers: &[],
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
            route: None,
            request_headers: &[],
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
            route: None,
            request_headers: &[],
            client,
            ..get("/api/patients", Some("id=7"), None, 5_000)
        };
        let blind = judge.judge(&site, &sign_up("10.0.0.9")).await;
        assert!(!blind.forward, "an id nobody showed this address");
        assert_eq!(fake.calls(), 1);
        judge.observe(
            &site,
            &Observation {
                route: None,
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
                route: None,
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
                echo: &[],
            },
        );
        assert_eq!(judge.session_count(), 1);
        judge.observe(
            &site,
            &Observation {
                route: None,
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
                echo: &[],
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
                route: None,
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
                echo: &[],
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
            route: None,
            request_headers: &[],
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
            route: None,
            request_headers: &[],
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
                route: None,
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
                echo: &[],
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
                    route: None,
                    request_headers: &[],
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

    /// The same site under another name: its values fingerprint differently.
    fn other_site() -> SiteSpec {
        SiteSpec::from_json(
            r#"{"name":"clinic","hosts":["clinic.test"],"origin":"http://o:1","session":{"cookie":"SID"},
               "entries":["/login","/api/home","/api/patients","/share/*"],"bypass":["/static/*"],"mode":"enforce"}"#,
        )
        .unwrap()
    }

    const ITEM_ID_SLOT: &str = "GET /api/patients items[].id";

    #[test]
    fn a_value_fingerprints_alike_in_every_session_of_a_site_and_apart_across_sites() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let alice = judge.observe(&site, &list_response("alice", 0));
        let bob = judge.observe(&site, &list_response("bob", 1));
        assert_eq!(alice.fingerprints.get(ITEM_ID_SLOT).map(Vec::len), Some(2));
        assert_eq!(alice.fingerprints, bob.fingerprints);
        let clinic = judge.observe(&other_site(), &list_response("alice", 2));
        assert!(clinic.fingerprints.keys().eq(alice.fingerprints.keys()));
        assert_ne!(clinic.fingerprints, alice.fingerprints);
    }

    #[test]
    fn a_position_keeps_its_smallest_fingerprints_whatever_order_they_come_in() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let items: Vec<String> = (0..20).map(|i| format!(r#"{{"id":"id-{i}"}}"#)).collect();
        let listed = format!(r#"{{"items":[{}]}}"#, items.join(","));
        let together = Observation {
            body: listed.as_bytes(),
            ..list_response("alice", 0)
        };
        let summary = judge.observe(&site, &together);
        // Each id observed alone, in a session of its own, gives every
        // fingerprint the position has; the smallest eight of them are expected.
        let mut alone = Vec::new();
        for i in 0..20 {
            let single_body = format!(r#"{{"items":[{{"id":"id-{i}"}}]}}"#);
            let credential = format!("solo-{i}");
            let single = Observation {
                body: single_body.as_bytes(),
                ..list_response(&credential, 1)
            };
            alone.extend(judge.observe(&site, &single).fingerprints[ITEM_ID_SLOT].clone());
        }
        alone.sort();
        alone.truncate(FINGERPRINTS_PER_SLOT_MAX);
        assert_eq!(summary.fingerprints[ITEM_ID_SLOT], alone);
    }

    #[test]
    fn a_response_records_at_most_sixteen_positions_and_never_the_values() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let fields: Vec<String> = (0..20)
            .map(|i| format!(r#""field{i:02}":"Ada Lovelace {i}""#))
            .collect();
        let body = format!("{{{}}}", fields.join(","));
        let observed = Observation {
            body: body.as_bytes(),
            ..list_response("alice", 0)
        };
        let summary = judge.observe(&site, &observed);
        assert_eq!(summary.values, 20);
        assert_eq!(summary.fingerprints.len(), FINGERPRINT_SLOTS_MAX);
        assert!(summary.fingerprints.values().all(|digests| {
            digests.len() == 1
                && digests[0].len() == 16
                && digests[0].bytes().all(|byte| byte.is_ascii_hexdigit())
        }));
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("Ada Lovelace"));
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
            route: None,
            request_headers: &[],
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

    #[test]
    fn a_response_structure_is_reported_when_it_is_new_or_changes() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let first = judge.observe(&site, &list_response("alice", 0));
        let shape = first
            .shape
            .expect("the first structure of a route is reported");
        assert!(
            shape
                .iter()
                .any(|field| field.path == "items[].id" && field.kind == "string")
        );
        assert!(
            judge
                .observe(&site, &list_response("alice", 1))
                .shape
                .is_none()
        );
        // Values change, the structure does not: nothing new to report.
        let other_values = Observation {
            body: br#"{"items":[{"id":"8","name":"C","age":3}]}"#,
            ..list_response("alice", 2)
        };
        assert!(judge.observe(&site, &other_values).shape.is_none());
        // A new field is a new structure, reported again.
        let changed = Observation {
            body: br#"{"items":[{"id":"7","name":"A","age":8,"ward":3}]}"#,
            ..list_response("alice", 3)
        };
        assert!(judge.observe(&site, &changed).shape.is_some());
    }

    #[test]
    fn each_site_reports_a_route_structure_once() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let emr = site(r#","mode":"enforce""#);
        let billing = SiteSpec::from_json(
            r#"{"name":"billing","hosts":["billing.test"],"origin":"http://o:2","session":{"cookie":"SID"},"entries":["/login"],"mode":"enforce"}"#,
        )
        .unwrap();
        assert!(
            judge
                .observe(&emr, &list_response("alice", 0))
                .shape
                .is_some()
        );
        // The same route of another site has not reported its structure yet.
        assert!(
            judge
                .observe(&billing, &list_response("alice", 1))
                .shape
                .is_some()
        );
        assert!(
            judge
                .observe(&billing, &list_response("alice", 2))
                .shape
                .is_none()
        );
    }

    #[test]
    fn a_json_body_that_does_not_parse_reports_no_structure() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let broken = Observation {
            body: b"{bad",
            ..list_response("alice", 0)
        };
        let summary = judge.observe(&site, &broken);
        assert_eq!(summary.observed, Observed::Json);
        assert!(summary.shape.is_none());
        // The first well-formed response of the route is the first structure.
        assert!(
            judge
                .observe(&site, &list_response("alice", 1))
                .shape
                .is_some()
        );
    }

    #[tokio::test]
    async fn trace_values_name_their_position_and_the_position_they_were_seen_at() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice", 0));
        let verdict = judge
            .judge(&site, &get("/api/patients/7", None, Some("alice"), 1_000))
            .await;
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7")
            .expect("the id is recorded");
        assert_eq!(
            value.slot.as_deref(),
            Some("GET /api/patients/{id} path[2]")
        );
        assert!(value.verified);
        assert_eq!(
            value.sources[0].slot.as_deref(),
            Some("GET /api/patients items[].id")
        );
        assert_eq!(value.object, None);
    }

    /// A request of `method` to `path` from alice's session, with no body.
    fn call<'a>(method: &'a str, path: &'a str, now_ms: u64) -> RequestFacts<'a> {
        RequestFacts {
            method,
            ..get(path, None, Some("alice"), now_ms)
        }
    }

    /// A site whose search shows every patient to any logged-in session, and whose
    /// DELETE of a patient takes no such source. The note on a patient takes them.
    /// The session's own listing is tier self.
    fn tiers_site(search_reliability: &str) -> SiteSpec {
        tiers_site_in("enforce", search_reliability)
    }

    /// [`tiers_site`] in `mode`.
    fn tiers_site_in(mode: &str, search_reliability: &str) -> SiteSpec {
        site(&format!(
            r#","mode":"{mode}","objects":{{
                "classes":[{{"id":"patient","name":"患者"}}],
                "slots":[
                    {{"key":"GET /api/search results[].id","class":"patient","source":"admin","tier":"public","reliability":"{search_reliability}"}},
                    {{"key":"GET /api/patients patients[].id","class":"patient","source":"admin","tier":"self","reliability":"high"}},
                    {{"key":"DELETE /api/patients/{{id}} path[2]","class":"patient","source":"admin","accepts_public":false,"reliability":"high"}},
                    {{"key":"POST /api/patients/{{id}}/notes path[2]","class":"patient","source":"admin","accepts_public":true,"reliability":"high"}}
                ]}}"#
        ))
    }

    const SEARCH_BODY: &[u8] = br#"{"results":[{"id":"7005","name":"B"}]}"#;

    /// The state part of the prompt Jev was sent. The questions carry the
    /// instructions, which name every field, so a check that a field is absent
    /// looks past them.
    fn state_of(sent: &str) -> &str {
        &sent[sent.find(r#""state""#).expect("the prompt carries a state")..]
    }

    #[tokio::test]
    async fn a_public_search_shows_an_object_but_proves_no_delete_of_it() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        fake.answer("DENY", "BENIGN");
        let verdict = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 1_000))
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(
            fake.calls(),
            1,
            "an attempt goes to Jev, never allowed on its own"
        );
        let sent = fake.sent.lock().unwrap()[0].clone();
        assert!(sent.contains(r#""attempt":"over_privilege""#), "{sent}");
        assert!(
            sent.contains(r#""public_access":{"accepts":false,"reliability":"high"}"#),
            "{sent}"
        );
        assert!(sent.contains("(tier public, reliability high)"), "{sent}");
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7005")
            .expect("the id is recorded");
        assert_eq!(
            value.attempt,
            Some(xshield_core::context::Attempt::OverPrivilege)
        );
        assert!(!value.verified);
        assert_eq!(value.sources[0].tier, Some(Tier::Public));
        assert_eq!(value.sources[0].reliability, Some(Reliability::High));
    }

    #[tokio::test]
    async fn an_attempt_is_not_served_from_the_allow_cache() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        // Jev allows the first DELETE; the second identical DELETE must still go to Jev.
        let first = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 1_000))
            .await;
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
        let second = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 2_000))
            .await;
        assert_eq!(second.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn an_administrators_allow_is_not_reused_once_the_role_changes() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = admin_site();
        judge.observe(
            &site,
            &home_for("root", br#"{"doctor":{"id":"DR-A"},"role":"admin"}"#),
        );
        judge.observe(
            &site,
            &Observation {
                path: "/api/admin/patients",
                body: br#"{"patients":[{"id":"7005"}]}"#,
                ..list_response("root", 1_000)
            },
        );
        // The patient is proven by the administrator listing, but the query names a patient the
        // session has never seen, so Jev judges the request and allows it, and the allow is cached.
        let first = judge
            .judge(
                &site,
                &RequestFacts {
                    query: Some("ref=PT-7009"),
                    ..call_as("DELETE", "/api/patients/7005", "root", 2_000)
                },
            )
            .await;
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
        // The home page now declares another role. The patient is no longer proven for this
        // session, so the same request goes to Jev again rather than reusing the admin's allow.
        judge.observe(
            &site,
            &home_for("root", br#"{"doctor":{"id":"DR-A"},"role":"staff"}"#),
        );
        let second = judge
            .judge(
                &site,
                &RequestFacts {
                    query: Some("ref=PT-7009"),
                    ..call_as("DELETE", "/api/patients/7005", "root", 3_000)
                },
            )
            .await;
        assert_eq!(second.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn equivalent_spellings_of_a_delete_are_the_same_attempt() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        fake.answer("DENY", "BENIGN");
        // A trailing slash, a doubled slash and an escaped digit name the same patient on the
        // same route, so each is an attempt at the same position and goes to Jev once.
        for (now_ms, path) in [
            (1_000, "/api/patients/7005/"),
            (2_000, "/api/patients//7005"),
            (3_000, "/api/patients/%37005"),
        ] {
            let verdict = judge.judge(&site, &call("DELETE", path, now_ms)).await;
            assert_eq!(
                verdict.record.decision_path,
                DecisionPath::JevDeny,
                "{path}"
            );
            let value = verdict
                .record
                .trace
                .values
                .iter()
                .find(|value| value.value == "7005")
                .expect("the id is recorded");
            assert_eq!(
                value.slot.as_deref(),
                Some("DELETE /api/patients/{id} path[2]"),
                "{path}"
            );
            assert_eq!(
                value.attempt,
                Some(xshield_core::context::Attempt::OverPrivilege),
                "{path}"
            );
        }
        assert_eq!(fake.calls(), 3, "each spelling goes to Jev once");
    }

    #[tokio::test]
    async fn an_attempt_echoed_by_its_own_response_teaches_the_session_nothing() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site_in("observe", "high");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        fake.answer("DENY", "BENIGN");
        // Observe mode forwards the attempt. Its answer echoes the id it deleted under a field
        // the map does not classify, which would prove the id if the session learned it.
        let attempt = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 1_000))
            .await;
        assert!(attempt.forward, "observe mode forwards the request");
        assert_eq!(attempt.record.decision_path, DecisionPath::JevDeny);
        judge.observe(
            &site,
            &Observation {
                method: "DELETE",
                path: "/api/patients/7005",
                body: br#"{"deleted":"7005"}"#,
                sent: &attempt.sent,
                echo: &attempt.echo,
                ..list_response("alice", 1_001)
            },
        );
        let again = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 2_000))
            .await;
        assert_eq!(again.record.decision_path, DecisionPath::JevDeny);
        let value = again
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7005")
            .expect("the id is recorded");
        assert_eq!(
            value.attempt,
            Some(xshield_core::context::Attempt::OverPrivilege)
        );
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_later_listing_of_the_sessions_own_patient_ends_the_attempt() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        fake.answer("DENY", "BENIGN");
        let attempt = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 1_000))
            .await;
        assert_eq!(attempt.record.decision_path, DecisionPath::JevDeny);
        // The session then lists its own patients, and 7005 is one of them: the listing is a
        // source of the value now, so the value is no longer only public.
        judge.observe(
            &site,
            &shown_by(
                "/api/patients",
                br#"{"patients":[{"id":"7005","name":"B"}]}"#,
            ),
        );
        let verdict = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 2_000))
            .await;
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7005")
            .expect("the id is recorded");
        assert_eq!(value.attempt, None, "the own listing is a source");
        assert!(!value.verified, "a self sighting never allows on its own");
        assert_eq!(fake.calls(), 2);
        let sent = fake.sent.lock().unwrap()[1].clone();
        assert!(
            !state_of(&sent).contains(r#""attempt""#),
            "the value is no attempt any more: {sent}"
        );
    }

    /// A site whose admin listing shows its patients only to administrator sessions, and whose
    /// DELETE of a patient takes no public source. The session's role is the `role` position.
    fn admin_site() -> SiteSpec {
        site(
            r#","mode":"enforce","objects":{
                "classes":[{"id":"doctor","name":"医生"},{"id":"staff","name":"员工"},{"id":"patient","name":"患者"}],
                "slots":[
                    {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"},
                    {"key":"GET /api/home role","class":"staff","source":"admin","identity":"role"},
                    {"key":"GET /api/admin/patients patients[].id","class":"patient","source":"admin","tier":"admin","reliability":"high"},
                    {"key":"DELETE /api/patients/{id} path[2]","class":"patient","source":"admin","accepts_public":false,"reliability":"high"}
                ]}"#,
        )
    }

    /// A `method` request to `path` from `credential`'s session, with no body.
    fn call_as<'a>(
        method: &'a str,
        path: &'a str,
        credential: &'a str,
        now_ms: u64,
    ) -> RequestFacts<'a> {
        RequestFacts {
            method,
            ..get(path, None, Some(credential), now_ms)
        }
    }

    #[tokio::test]
    async fn an_administrator_who_found_a_patient_in_the_admin_listing_may_delete_it() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = admin_site();
        judge.observe(
            &site,
            &home_for("root", br#"{"doctor":{"id":"DR-A"},"role":"admin"}"#),
        );
        judge.observe(
            &site,
            &Observation {
                path: "/api/admin/patients",
                body: br#"{"patients":[{"id":"7005"}]}"#,
                ..list_response("root", 1_000)
            },
        );
        let verdict = judge
            .judge(
                &site,
                &call_as("DELETE", "/api/patients/7005", "root", 2_000),
            )
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7005")
            .expect("the id is recorded");
        assert!(value.verified);
        assert_eq!(value.attempt, None);
    }

    #[tokio::test]
    async fn an_administrator_who_never_saw_the_patient_is_still_blocked() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = admin_site();
        judge.observe(
            &site,
            &home_for("root", br#"{"doctor":{"id":"DR-A"},"role":"admin"}"#),
        );
        fake.answer("DENY", "BENIGN");
        let verdict = judge
            .judge(
                &site,
                &call_as("DELETE", "/api/patients/7005", "root", 2_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(fake.calls(), 1, "an object nobody showed goes to Jev");
        let sent = fake.sent.lock().unwrap()[0].clone();
        assert!(
            !state_of(&sent).contains(r#""attempt""#),
            "no sighting, so no attempt: {sent}"
        );
    }

    #[tokio::test]
    async fn an_admin_listing_proves_nothing_to_a_session_without_the_role() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = admin_site();
        judge.observe(
            &site,
            &Observation {
                path: "/api/admin/patients",
                body: br#"{"patients":[{"id":"7005"}]}"#,
                ..list_response("alice", 1_000)
            },
        );
        fake.answer("DENY", "BENIGN");
        let verdict = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 2_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(fake.calls(), 1);
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7005")
            .expect("the id is recorded");
        assert!(!value.verified);
        assert_eq!(value.attempt, None);
    }

    #[tokio::test]
    async fn a_public_sighting_still_proves_a_note_on_the_patient() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        let verdict = judge
            .judge(&site, &call("POST", "/api/patients/7005/notes", 1_000))
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7005")
            .expect("the id is recorded");
        assert!(value.verified);
        assert!(value.attempt.is_none());
    }

    #[tokio::test]
    async fn a_weak_public_tier_proves_the_delete_as_it_did_before_tiers() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("low");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        let verdict = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 1_000))
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn a_site_without_tiers_judges_the_same_search_then_delete_as_before() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        let verdict = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 1_000))
            .await;
        // The search does not name the kind of the id, so the id is unverified and Jev decides.
        assert_eq!(fake.calls(), 1);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevAllow);
        let sent = fake.sent.lock().unwrap()[0].clone();
        let state = state_of(&sent);
        assert!(
            !state.contains(r#""attempt""#) && !state.contains(r#""public_access""#),
            "{sent}"
        );
        assert!(!state.contains("tier"), "{sent}");
        assert!(
            state.contains(r#""seen_as":["id @ GET /api/search"]"#),
            "{sent}"
        );
    }

    #[tokio::test]
    async fn a_value_no_response_showed_is_not_an_attempt() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        fake.answer("DENY", "BENIGN");
        let verdict = judge
            .judge(&site, &call("DELETE", "/api/patients/7006", 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(fake.calls(), 1);
        let sent = fake.sent.lock().unwrap()[0].clone();
        assert!(!state_of(&sent).contains(r#""attempt""#), "{sent}");
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7006")
            .expect("the id is recorded");
        assert!(value.attempt.is_none());
    }

    #[tokio::test]
    async fn an_administrator_listing_is_no_public_sighting_and_no_attempt() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(
            r#","mode":"enforce","objects":{
                "classes":[{"id":"patient","name":"患者"}],
                "slots":[
                    {"key":"GET /api/admin/search results[].id","class":"patient","source":"admin","tier":"admin","reliability":"high"},
                    {"key":"DELETE /api/patients/{id} path[2]","class":"patient","source":"admin","accepts_public":false,"reliability":"high"}
                ]}"#,
        );
        judge.observe(&site, &shown_by("/api/admin/search", SEARCH_BODY));
        fake.answer("DENY", "BENIGN");
        let verdict = judge
            .judge(&site, &call("DELETE", "/api/patients/7005", 1_000))
            .await;
        assert_eq!(fake.calls(), 1);
        let sent = fake.sent.lock().unwrap()[0].clone();
        let state = state_of(&sent);
        assert!(state.contains("(tier admin, reliability high)"), "{sent}");
        assert!(!state.contains(r#""attempt""#), "{sent}");
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
    }

    /// A site whose `GET /api/home` declares the doctor id as the session's user and its `role` as
    /// the session's role (docs/07 section 7.9.15).
    fn identity_site() -> SiteSpec {
        site(
            r#","mode":"enforce","objects":{
                "classes":[{"id":"doctor","name":"医生"},{"id":"staff","name":"员工"}],
                "slots":[
                    {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"},
                    {"key":"GET /api/home role","class":"staff","source":"admin","identity":"role"}
                ]}"#,
        )
    }

    /// A successful `GET /api/home` answered to `credential` with `body`.
    fn home_for<'a>(credential: &'a str, body: &'a [u8]) -> Observation<'a> {
        Observation {
            path: "/api/home",
            body,
            ..list_response(credential, 0)
        }
    }

    /// The identity a decision record carries, when it carries one.
    fn identity_of(record: &DecisionRecord) -> Option<xshield_core::context::TraceIdentity> {
        record
            .trace
            .session
            .as_ref()
            .and_then(|session| session.identity.clone())
    }

    #[tokio::test]
    async fn a_declared_identity_tags_the_decisions_of_its_session() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = identity_site();
        let before = judge
            .judge(&site, &get("/api/patients", None, Some("alice"), 0))
            .await;
        assert_eq!(identity_of(&before.record), None, "nothing shown yet");
        judge.observe(
            &site,
            &home_for("alice", br#"{"doctor":{"id":"DR-A"},"role":"Admin"}"#),
        );
        let alice = judge
            .judge(&site, &get("/api/patients", None, Some("alice"), 1))
            .await;
        let tag = identity_of(&alice.record).expect("the response declared the identity");
        assert_eq!(tag.org, None);
        assert_eq!(tag.role.as_deref(), Some("admin"));
        let user = tag.user.clone().expect("the user is tagged");
        assert_eq!(user.len(), 16);
        assert!(
            user.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        // The id itself never reaches the record.
        assert!(
            !serde_json::to_string(&alice.record.trace)
                .unwrap()
                .contains("DR-A")
        );

        judge.observe(&site, &home_for("bob", br#"{"doctor":{"id":"DR-B"}}"#));
        let bob = judge
            .judge(&site, &get("/api/patients", None, Some("bob"), 2))
            .await;
        let bob_tag = identity_of(&bob.record).expect("bob's session shows its identity");
        assert_ne!(bob_tag.user, tag.user, "another account is another user");
        assert_eq!(
            bob_tag.role, None,
            "a response without a role declares none"
        );

        // The next identity response replaces the user, so a switch of organization needs no new
        // login. A kind that response does not declare is kept.
        judge.observe(&site, &home_for("alice", br#"{"doctor":{"id":"DR-C"}}"#));
        let switched = judge
            .judge(&site, &get("/api/patients", None, Some("alice"), 3))
            .await;
        let switched_tag = identity_of(&switched.record).expect("alice still shows an identity");
        assert_ne!(switched_tag.user, tag.user);
        assert_eq!(switched_tag.role.as_deref(), Some("admin"));
    }

    /// A site whose comment list names each author, a doctor, as a user-class object, next to the
    /// `GET /api/home` that declares the session's own doctor (docs/07 section 7.9.17).
    fn comment_site() -> SiteSpec {
        site(
            r#","mode":"enforce","objects":{
                "classes":[{"id":"doctor","name":"医生"}],
                "slots":[
                    {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"},
                    {"key":"GET /api/comments comments[].author.id","class":"doctor","source":"admin"}
                ]}"#,
        )
    }

    /// The same site without any identity or object position.
    fn plain_site() -> SiteSpec {
        site("")
    }

    /// A successful `GET /api/comments` answered to `credential` with `body`.
    fn comments_for<'a>(credential: &'a str, body: &'a [u8]) -> Observation<'a> {
        Observation {
            path: "/api/comments",
            body,
            ..list_response(credential, 0)
        }
    }

    #[tokio::test]
    async fn another_doctors_contact_details_are_alerted_and_nothing_is_refused() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = comment_site();
        judge.observe(&site, &home_for("alice", br#"{"doctor":{"id":"DR-A"}}"#));
        let by_b = br#"{"comments":[{"id":"CM-1","author":{"id":"DR-B","name":"B","phone":"13800000002","email":"dr-b@emr.example"}}]}"#;
        let shown = judge.observe(&site, &comments_for("alice", by_b));
        let found = shown
            .exposure
            .clone()
            .expect("another doctor's contact details are an exposure");
        assert_eq!(
            found.users,
            vec!["GET /api/comments comments[].author.id".to_owned()]
        );
        assert_eq!(found.attributes.len(), 2, "the phone and the email");
        // The alert keeps positions and kinds, never the values.
        assert!(
            !serde_json::to_string(&shown)
                .unwrap()
                .contains("13800000002")
        );

        // The session's own doctor is not another, so its contact details alert nothing.
        let own = br#"{"comments":[{"id":"CM-2","author":{"id":"DR-A","name":"A","phone":"13800000001"}}]}"#;
        assert_eq!(
            judge.observe(&site, &comments_for("alice", own)).exposure,
            None
        );
        // A session that has not shown its doctor cannot tell whose the author is.
        assert_eq!(
            judge.observe(&site, &comments_for("carol", by_b)).exposure,
            None
        );
        // A site without identity positions states no exposure at all.
        let plain = plain_site();
        judge.observe(&plain, &home_for("dave", br#"{"doctor":{"id":"DR-D"}}"#));
        assert_eq!(
            judge.observe(&plain, &comments_for("dave", by_b)).exposure,
            None
        );
    }

    #[tokio::test]
    async fn an_id_the_request_named_still_raises_the_exposure_alert() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = comment_site();
        judge.observe(&site, &home_for("alice", br#"{"doctor":{"id":"DR-A"}}"#));
        // The client named DR-B, a turned-down value, so the response echoes it. The echo keeps
        // the value out of learning, but the origin still discloses DR-B's contact details.
        let echoed = [judge.key.mac("value", b"DR-B")];
        let by_b = br#"{"comments":[{"id":"CM-1","author":{"id":"DR-B","name":"B","phone":"13800000002","email":"dr-b@emr.example"}}]}"#;
        let shown = judge.observe(
            &site,
            &Observation {
                echo: &echoed,
                ..comments_for("alice", by_b)
            },
        );
        assert!(
            shown.exposure.is_some(),
            "an echoed id still discloses its contact details"
        );
    }

    #[tokio::test]
    async fn an_echo_or_a_list_of_ids_declares_no_identity() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = identity_site();
        // The client sent DR-B and the origin echoes it back: an echo is not who the session is.
        let sent = [judge.key.mac("value", b"DR-B")];
        judge.observe(
            &site,
            &Observation {
                sent: &sent,
                echo: &[],
                ..home_for("alice", br#"{"doctor":{"id":"DR-B"}}"#)
            },
        );
        let echoed = judge
            .judge(&site, &get("/api/patients", None, Some("alice"), 1))
            .await;
        assert_eq!(identity_of(&echoed.record), None);

        // A response that lists several ids does not say which one is the session's: a site whose
        // list position is the identity.
        let list = SiteSpec::from_json(
            r#"{"name":"list","hosts":["list.test"],"origin":"http://o:1","session":{"cookie":"SID"},
               "entries":["/login","/api/home","/api/patients"],"mode":"enforce",
               "objects":{"classes":[{"id":"doctor","name":"医生"}],
                 "slots":[{"key":"GET /api/home [].id","class":"doctor","source":"admin","identity":"user"}]}}"#,
        )
        .unwrap();
        judge.observe(
            &list,
            &home_for("carol", br#"[{"id":"DR-A"},{"id":"DR-B"}]"#),
        );
        let several = judge
            .judge(&list, &get("/api/patients", None, Some("carol"), 2))
            .await;
        assert_eq!(identity_of(&several.record), None);
        judge.observe(
            &list,
            &home_for("carol", br#"[{"id":"DR-A"},{"id":"DR-A"}]"#),
        );
        let once = judge
            .judge(&list, &get("/api/patients", None, Some("carol"), 3))
            .await;
        assert!(
            identity_of(&once.record).is_some(),
            "one distinct id is the session's"
        );
    }

    #[tokio::test]
    async fn a_site_without_identity_positions_writes_no_identity() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &home_for("alice", br#"{"doctor":{"id":"DR-A"},"role":"admin"}"#),
        );
        let verdict = judge
            .judge(&site, &get("/api/patients", None, Some("alice"), 1))
            .await;
        let trace = serde_json::to_value(&verdict.record.trace).unwrap();
        assert!(trace["session"].get("identity").is_none());
    }

    /// A site whose object map says what the positions of the kind tests carry:
    /// appointments and `/doctor/{id}` are doctors, `/api/docs` and `/docs/{id}`
    /// and record attachments are documents.
    fn kinds_site() -> SiteSpec {
        site(
            r#","mode":"enforce","objects":{
                "classes":[{"id":"doctor","name":"医生"},{"id":"document","name":"文档"}],
                "slots":[
                    {"key":"GET /api/appointments [].doc_id","class":"doctor","source":"rule"},
                    {"key":"GET /doctor/{id} path[1]","class":"doctor","source":"admin"},
                    {"key":"GET /api/docs [].id","class":"document","source":"admin"},
                    {"key":"GET /docs/{id} path[1]","class":"document","source":"admin"},
                    {"key":"GET /api/records/{id} attachments[].doc_id","class":"document","source":"rule"}
                ]}"#,
        )
    }

    /// A successful response of `path` to alice's session.
    fn shown_by(path: &'static str, body: &'static [u8]) -> Observation<'static> {
        Observation {
            path,
            body,
            ..list_response("alice", 0)
        }
    }

    #[tokio::test]
    async fn a_doctor_shown_as_a_doctor_is_allowed_without_jev_and_says_so() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = kinds_site();
        judge.observe(&site, &shown_by("/api/appointments", br#"[{"doc_id":2}]"#));
        let verdict = judge
            .judge(&site, &get("/doctor/2", None, Some("alice"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
        let value = &verdict.record.trace.values[1];
        assert_eq!(value.slot.as_deref(), Some("GET /doctor/{id} path[1]"));
        assert_eq!(value.object.as_deref(), Some("doctor"));
        assert_eq!(
            value.object_from,
            Some(xshield_core::context::ObjectFrom::Map)
        );
        assert_eq!(value.sources[0].object.as_deref(), Some("doctor"));
    }

    #[tokio::test]
    async fn a_document_id_is_not_a_doctor_and_jev_is_told_both_kinds() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = kinds_site();
        judge.observe(&site, &shown_by("/api/docs", br#"[{"id":5}]"#));
        let verdict = judge
            .judge(&site, &get("/doctor/5", None, Some("alice"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 1);
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "5")
            .unwrap();
        assert!(!value.verified);
        let sent = fake.sent.lock().unwrap();
        assert!(sent[0].contains(r#""object":"doctor""#));
        assert!(sent[0].contains("id @ GET /api/docs [document]"));
    }

    #[tokio::test]
    async fn a_doctor_id_is_not_a_document_on_a_document_route() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = kinds_site();
        judge.observe(&site, &shown_by("/api/appointments", br#"[{"doc_id":2}]"#));
        let verdict = judge
            .judge(&site, &get("/docs/2", None, Some("alice"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_document_attachment_is_judged_by_its_own_kind() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = kinds_site();
        judge.observe(
            &site,
            &shown_by("/api/records/7", br#"{"attachments":[{"doc_id":5}]}"#),
        );
        // Named as a doctor: the attachment is a document, so Jev decides.
        let as_doctor = judge
            .judge(&site, &get("/doctor/5", None, Some("alice"), 1_000))
            .await;
        assert_eq!(as_doctor.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 1);
        // Named as a document: the same value is allowed without Jev.
        let as_document = judge
            .judge(&site, &get("/docs/5", None, Some("alice"), 2_000))
            .await;
        assert_eq!(as_document.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_mapped_request_still_matches_an_unmapped_position_by_name() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = kinds_site();
        // `/api/doctors` is not in the map, so its id is judged by its name.
        judge.observe(&site, &shown_by("/api/doctors", br#"[{"id":3}]"#));
        let verdict = judge
            .judge(&site, &get("/doctor/3", None, Some("alice"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
    }
}
