//! The decision flow of docs/01 section 1.4, and the row that describes each
//! decision (docs/07 sections 7.4 and 7.5).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::{StreamExt, stream};
use xshield_core::context::trace::{TRACE_PATH_BYTES_MAX, TraceFunction};
use xshield_core::context::{
    Attempt, Conclusion, ContextKind, DecisionPath, DecisionRecord, FINGERPRINT_SLOTS_MAX,
    FINGERPRINTS_PER_SLOT_MAX, FieldCount, IdentityRole, JevRecord, LoginUnbound, Mode, ObjectMap,
    ObservationSummary, Observed, OnJevUnavailable, Outcome, Reliability, Resolved,
    SessionCredential, ShapeField, SiteSpec, Skip, Tier, Trace, TraceSession, TraceValue,
};
use xshield_core::kind::{Rules, Used};
use xshield_core::path_template::is_templatable;

use crate::context::{
    CACHE_MINUTES, ContextKey, ContextStore, Digest16, EntryPass, HeldValue,
    LOGIN_CREDENTIAL_CHARS, Origin, Recent, SENT_MAX, SentRecord, SessionContext, SessionIdentity,
    Source, label, request_number, request_text,
};
use crate::exposure;
use crate::jev::{JevFailure, JevPort, REPLY_BYTES_MAX, failure_code};
use crate::slots::{
    function_templates, identity_claims, origin_object, origin_tier, reliability_name,
    request_place, response_slot, route_template, tier_name,
};
use crate::state::{
    Answers, Batched, JudgeError, Prompt, StateFunction, StateInput, StateValue, build_states,
    conclude, parse_response, request_body,
};
use crate::tiers;
use crate::trace::{
    Place, cut, entry_trace, recent_trace, redacted_path, redacted_query, value_entry,
};
use crate::values::{
    ExtractedRequest, ResponseFacts, ResponseValue, extract_request, extract_response_facts,
    json_unescape, path_segment, percent_decode,
};

/// Jev calls allowed per session per minute (docs/02 section 2.5).
pub const SESSION_CALLS_PER_MINUTE: u32 = 60;
/// Jev calls allowed per client address per minute for requests without a session.
pub const ADDRESS_CALLS_PER_MINUTE: u32 = 30;
/// All the sessions created from one source address together may make this many times the
/// per-session limit of Jev calls per minute (docs/02 section 2.5). A fixed value, not a setting.
const ADDRESS_SESSIONS_FACTOR: u32 = 10;
const WINDOW_MS: u64 = 60_000;
const LIMITER_MAX: usize = 50_000;
const RECENT_IN_STATE: usize = 10;
/// Field names listed in a response summary (docs/07 section 7.4.3).
const FIELDS_IN_SUMMARY: usize = 12;
/// Calls to Jev in flight at once for one request whose state is cut into batches (docs/02
/// section 2.5).
pub const JEV_PARALLEL_MAX: usize = 8;

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
    /// The values of the method override headers the request carries (`X-HTTP-Method-Override`,
    /// `X-HTTP-Method`, `X-Method-Override`), one per occurrence, as sent (docs/07 section 7.9.18).
    /// Empty when the request has none.
    pub method_overrides: &'a [String],
}

/// What to do with the request.
#[derive(Debug, Clone, PartialEq)]
pub struct Judgement {
    /// Forward to the origin.
    pub forward: bool,
    /// Status to answer with when not forwarding: 401, 403, or 429 when the call budget is spent.
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
    /// is in observe mode. Its response teaches nothing (docs/07 section 7.4.6).
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
    /// Counts one call against the window of `key`, which allows `limit` calls a minute.
    #[cfg(test)]
    fn allow(&mut self, key: Digest16, limit: u32, now_ms: u64) -> bool {
        self.allow_all(&[(key, limit)], now_ms)
    }

    /// Counts one call against each of the windows `wanted` names (a key and its limit), but only
    /// when none of them is full: a refused call counts against none, and creates no window. A
    /// new key gets a window only while the map has room, so the map never passes its cap.
    fn allow_all(&mut self, wanted: &[(Digest16, u32)], now_ms: u64) -> bool {
        let new_keys = |windows: &HashMap<Digest16, (u64, u32)>| {
            wanted
                .iter()
                .filter(|(key, _)| !windows.contains_key(key))
                .count()
        };
        if self.windows.len() + new_keys(&self.windows) > LIMITER_MAX {
            self.windows
                .retain(|_, (start, _)| now_ms.saturating_sub(*start) < WINDOW_MS);
            // Every window is still running: a new key gets no call, so the map
            // stays at its cap and is not scanned again for each known key.
            if self.windows.len() + new_keys(&self.windows) > LIMITER_MAX {
                return false;
            }
        }
        let room = wanted.iter().all(|(key, limit)| {
            let used = match self.windows.get(key) {
                Some((start, used)) if now_ms.saturating_sub(*start) < WINDOW_MS => *used,
                _ => 0,
            };
            used < *limit
        });
        if !room {
            return false;
        }
        for (key, _) in wanted {
            let entry = self.windows.entry(*key).or_insert((now_ms, 0));
            if now_ms.saturating_sub(entry.0) >= WINDOW_MS {
                *entry = (now_ms, 0);
            }
            entry.1 += 1;
        }
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
/// values the trace lists, whether every value was verified, whether one of
/// them is an attempt, and whether the request's path cannot be templated on a
/// site that judges public access (such a request is never fast-allowed).
struct PlannedValues {
    values: Vec<StateValue>,
    shown: Vec<TraceValue>,
    all_known: bool,
    attempted: bool,
    unplaceable: bool,
}

#[derive(Clone, Copy)]
enum Verdict {
    Safe(DecisionPath),
    Unsafe(DecisionPath),
    Unjudged(DecisionPath),
    /// The session's or address's Jev calls for this minute are used up. No call is made, and the
    /// request is refused with 429 whatever `on_jev_unavailable` says (docs/02 section 2.5).
    CallLimited,
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
    /// The credential's session, when the store holds a live one (docs/01 section 1.2). A credential no
    /// session holds is judged as no credential at all.
    session_id: Option<Digest16>,
    /// The context of the client address on this site, for a request without a session.
    address: Digest16,
    /// The source address group of the request, which a session it creates is recorded under
    /// (see [`address_group`]).
    origin: Digest16,
    /// Why the held login that should have started the credential's session did not (docs/07 section
    /// 7.4.3). Set for a credential that no session holds; the trace of an entry keeps it.
    unbound: Option<LoginUnbound>,
    extracted: &'a ExtractedRequest,
    cache_key: &'a Digest16,
    tuning: &'a Tuning<'a>,
    /// The session credential as it must be redacted (see [`redaction_secret`]).
    secret: Option<&'a str>,
    /// What the site's function table says about the request, when the table guards functions.
    function: Option<FunctionView>,
}

/// What the site's function table says about one request (docs/07 section 7.9.18). Worked out once in
/// [`Judge::judge`] for a site whose map guards functions; `plan`, `ask_jev` and `remember_allow` read it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionView {
    /// The function the request is looked up as: the upper-case transport method, one space, and the
    /// route template of the redacted path. The trace keeps it, so no credential reaches it.
    key: String,
    /// The key of the administrator-only function of the table the request reaches, when it reaches one.
    admin_entry: Option<String>,
    /// The request reaches an administrator-only function and the session is not an administrator's.
    attempt: bool,
    /// The site asks about unknown functions and the table does not list the request's function.
    unknown: bool,
}

impl FunctionView {
    /// The `function` of the state: present only for an attempt or an unknown function.
    fn state(&self) -> Option<StateFunction> {
        (self.attempt || self.unknown).then_some(StateFunction {
            admin_attempt: self.attempt,
            unknown: self.unknown,
        })
    }

    /// The `function` of the trace: present when the request reaches an administrator-only function, or
    /// when its function is unknown (docs/07 section 7.4.3).
    fn trace(&self) -> Option<TraceFunction> {
        (self.admin_entry.is_some() || self.unknown).then(|| TraceFunction {
            key: self.key.clone(),
            entry: self.admin_entry.clone(),
            tier: self.admin_entry.as_ref().map(|_| "admin".to_owned()),
            attempt: self.attempt.then_some(Attempt::OverPrivilege),
            known: self.unknown.then_some(false),
        })
    }
}

/// The function view of one request, or `None` when the site's table does not guard functions. A site
/// without a guarding table is judged exactly as before, and runs no lookup for it (docs/07 section 7.9.18).
fn function_view(
    objects: &ObjectMap,
    request: &RequestFacts<'_>,
    extracted: &ExtractedRequest,
    logical: &str,
    secret: Option<&str>,
    admin: bool,
) -> Option<FunctionView> {
    if !objects.guards_functions() {
        return None;
    }
    let method = request.method.to_ascii_uppercase();
    let templates = function_templates(logical);
    let first = templates.first().map_or("", String::as_str);
    // The administrator-only function the request reaches: the transport method first, then each method
    // the request names for itself, each with every template, in that order. The first hit names it.
    let overrides = override_methods(&method, request, extracted);
    let mut admin_entry = None;
    'search: for candidate in
        std::iter::once(method.as_str()).chain(overrides.iter().map(String::as_str))
    {
        for template in &templates {
            if objects.admin_only(candidate, template) {
                admin_entry = objects
                    .function_of(candidate, template)
                    .map(|function| function.key.clone());
                break 'search;
            }
        }
    }
    let attempt = admin_entry.is_some() && !admin;
    // Unknown is judged on the transport method and the first template only: the table was learned from
    // the traffic's methods and paths, not from the overrides or the decoded slashes. An administrator's
    // session is not asked about an unknown function: the table does not list every administrator
    // interface, so such a request is judged by its values alone (docs/07 section 7.9.18).
    let unknown = !admin
        && objects.asks_unknown_functions()
        && (!is_templatable(logical) || !objects.knows_function(&method, first));
    let redacted = redacted_path(logical, secret);
    let key = cut(
        format!("{method} {}", route_template(&redacted)),
        TRACE_PATH_BYTES_MAX,
    );
    Some(FunctionView {
        key,
        admin_entry,
        attempt,
        unknown,
    })
}

/// The methods a request names for itself other than its transport method (docs/07 section 7.9.18): the
/// values of its method override headers and of its `_method` field in the query or the body. Each value is
/// trimmed and upper-cased; one that is 3 to 7 ASCII letters counts, once, and the transport method is left out.
fn override_methods(
    method: &str,
    request: &RequestFacts<'_>,
    extracted: &ExtractedRequest,
) -> Vec<String> {
    let fields = extracted
        .values
        .iter()
        .filter(|value| value.at == "query._method" || value.at == "body._method")
        .map(|value| value.value.as_str());
    let mut methods: Vec<String> = Vec::new();
    for raw in request
        .method_overrides
        .iter()
        .map(String::as_str)
        .chain(fields)
    {
        let named = raw.trim().to_ascii_uppercase();
        let letters =
            (3..=7).contains(&named.len()) && named.bytes().all(|byte| byte.is_ascii_uppercase());
        if letters && named != method && !methods.contains(&named) {
            methods.push(named);
        }
    }
    methods
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

    /// The key of the context a credential's session keeps on `site`. Each site learns its own
    /// context, so the same credential on another site starts from nothing (docs/01 section 1.2).
    fn session_key(&self, site: &str, credential: &str) -> Digest16 {
        self.key
            .mac("site-session", format!("{site}\0{credential}").as_bytes())
    }

    /// The key of the context a client address keeps on `site`, for the requests that carry no
    /// credential (docs/01 section 1.2).
    fn address_key(&self, site: &str, client: &str) -> Digest16 {
        self.key
            .mac("site-address", format!("{site}\0{client}").as_bytes())
    }

    /// The key a Jev call is counted against: the credential's while its session is live, and the
    /// client address group's otherwise. These budgets are shared by all sites (docs/02 section
    /// 2.5).
    fn budget_key(&self, request: &RequestFacts<'_>, session_live: bool) -> Digest16 {
        match request
            .credential
            .filter(|credential| session_live && !credential.is_empty())
        {
            Some(credential) => self.key.mac("session", credential.as_bytes()),
            None => self
                .key
                .mac("address", address_group(request.client).as_bytes()),
        }
    }

    /// The key of the address group of `client`: what a session records as the source that
    /// created it, and what the calls of all the sessions of that source are counted under
    /// (docs/02 section 2.5). A keyed hash, so no address is kept.
    fn origin_key(&self, client: &str) -> Digest16 {
        self.key
            .mac("address-group", address_group(client).as_bytes())
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
        let address = self.address_key(site.name(), request.client);
        let origin = self.origin_key(request.client);
        let credential = request
            .credential
            .filter(|credential| !credential.is_empty());
        let credential_id = credential.map(|credential| self.session_key(site.name(), credential));
        // A credential that no session holds starts its session from the JSON login response that
        // issued it, when one is held, on any path (docs/01 section 1.7). This runs before anything
        // reads the session, so a session that does start is created already knowing what the login
        // returned. The credential is recognized only by a live session: one the origin answered
        // earlier, or the one the login just started (docs/01 section 1.2). Any other credential is
        // judged as no credential, so a made-up one cannot push real sessions out of the store or draw
        // a Jev budget of its own.
        let mut session_id = None;
        let mut unbound = None;
        if let (Some(id), Some(credential)) = (credential_id, credential) {
            let token = self
                .key
                .mac("value", credential_token(site, credential).as_bytes());
            let mut inner = self.lock();
            unbound = inner
                .store
                .start_from_login(site.name(), id, origin, token, request.now_ms);
            session_id = inner.store.contains(&id, request.now_ms).then_some(id);
        }
        let unrecognized = credential_id.is_some() && session_id.is_none();
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
        let function = function_view(
            tuning.objects,
            request,
            &extracted,
            resolved.logical_path(),
            redaction_secret(Some(site), request),
            admin,
        );
        record.session = session_id.map(|id| label(&id)).unwrap_or_default();
        record.context = match (session_id, entry) {
            (Some(_), _) => Some(ContextKind::Session),
            (None, Some(_)) => Some(ContextKind::Address),
            (None, None) => None,
        };
        record.trace.entry = entry.map(str::to_owned);
        record.trace.values_truncated = extracted.truncated;
        record.trace.unrecognized_credential = unrecognized;
        let turn = Turn {
            request,
            resolved,
            entry: entry.is_some(),
            session_id,
            address,
            origin,
            unbound,
            extracted: &extracted,
            cache_key: &cache_key,
            tuning: &tuning,
            secret: redaction_secret(Some(site), request),
            function,
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
            // the learning stops: for a credential no session holds, where its
            // values wait (see `ContextStore::note_sent`), and for the context the
            // request was judged in, which is the address for an entry.
            if let Some(digests) = self.token_digests(request) {
                sent.extend(digests);
            } else {
                if session_id.is_none() {
                    self.stop_learning(credential_id, request.now_ms);
                }
                self.stop_learning(
                    session_id.or_else(|| entry.map(|_| address)),
                    request.now_ms,
                );
            }
        }
        record.decision_path = decision_path;
        record.outcome = outcome;
        record.jev = jev;
        if outcome == Outcome::Blocked {
            record.trace.refused = Some(
                match refuse_status {
                    401 => "unauthenticated",
                    429 => "rate_limited",
                    _ => "forbidden",
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
        // Without a session (a credential no session holds counts as none) only an entry may pass (a
        // login, a sign-up step). Its context is the client address: what the origin showed that address
        // earlier (a new user's id, the security questions) is the only evidence that the next sign-up
        // request names its own data.
        if turn.session_id.is_none() && !turn.entry {
            // A request that carries a credential no session holds sends all its values, as `plan_values`
            // sends the unseen ones: the credential takes them if the origin answers it later (see
            // `note_request_sent`), so an echo of them is not learned. A request without a credential sends
            // nothing and starts no context, as before.
            if turn.request.credential.is_some_and(|c| !c.is_empty()) {
                sent.extend(
                    turn.extracted
                        .values
                        .iter()
                        .map(|value| self.key.mac("value", value.value.as_bytes())),
                );
            }
            return Plan::Done(Verdict::Unsafe(DecisionPath::NoSession));
        }
        let mut inner = self.lock();
        // `session_id` is live as judge found it a moment ago, so `session` returns that session and
        // creates nothing. A request without one is judged against its address, and its Jev calls are
        // counted against the address, as for a request without a credential.
        let (session, limit_key): (&SessionContext, Digest16) = match turn.session_id {
            Some(id) => (
                inner.store.session(id, turn.origin, request.now_ms),
                self.budget_key(request, true),
            ),
            None => (
                inner
                    .store
                    .session(turn.address, turn.origin, request.now_ms),
                self.budget_key(request, false),
            ),
        };
        let PlannedValues {
            values,
            shown,
            all_known,
            attempted,
            unplaceable,
        } = self.plan_values(turn, session, sent, echo);
        trace.values = shown;
        trace.session = Some(TraceSession {
            age_seconds: session.age_seconds(request.now_ms),
            known_values: session.seen_len(),
            entries_passed: None,
            recent: None,
            identity: session.identity().tag(),
            login_request_id: session.login_request().and_then(request_text),
            // A credential no session holds was judged in its address; the reason its login did not bind
            // is still the one the entry records (docs/01 section 1.7).
            login_unbound: session.login_unbound().or(turn.unbound),
        });
        let function = turn.function.as_ref();
        trace.function = function.and_then(FunctionView::trace);
        // A function the table makes an attempt, or does not know, is never fast-allowed: it goes to Jev,
        // even when every value of it was verified (docs/01 section 1.4).
        let attempt = function.is_some_and(|view| view.attempt);
        let unknown_function = function.is_some_and(|view| view.unknown);
        // An unknown interface always goes to Jev: neither its values nor a cached
        // allow of another request can settle it. A path the map cannot place does too.
        let unknown = turn.resolved.is_unknown();
        if all_known
            && !attempted
            && !unplaceable
            && !turn.extracted.truncated
            && !unknown
            && !attempt
            && !unknown_function
        {
            return Plan::Done(Verdict::Safe(DecisionPath::FastAllow));
        }
        // An attempt goes to Jev, whatever an earlier allow of the same request said.
        // A request with unread values is never settled by an earlier allow either:
        // the key covers only the values that were read.
        if tuning.cache_ms > 0
            && !unknown
            && !attempted
            && !unplaceable
            && !attempt
            && !turn.extracted.truncated
            && let Some(source) = session.cached_allow(turn.cache_key, request.now_ms)
        {
            trace.cache_source = request_text(source);
            return Plan::Done(Verdict::Safe(DecisionPath::CachedAllow));
        }
        Plan::Ask { limit_key, values }
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
        let path = turn.resolved.logical_path();
        // A path that cannot be templated has no position the map can name. On a site that judges
        // public access such a request is never fast-allowed (docs/07 section 7.4.7).
        let unplaceable = tuning.objects.judges_public_access() && !is_templatable(path);
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
            // path plus the interface name of a routed request (docs/07 section 7.4.7). On a site
            // that judges public access, a declared position whose route covers the path governs
            // the value, so a slug id, a `;` parameter or an escaped slash at a declared `{id}` is
            // judged as that position.
            let placed = request_place(tuning.objects, request.method, path, &value.at);
            let unplaced = !value.inert && unplaceable && placed.key.is_none();
            let slot = placed.slot(request.method, path, &value.at);
            let request_object = tuning.objects.class_of(&slot);
            let access = placed.access;
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
            // A value no position governs is neither verified nor an attempt: the map cannot say
            // where it sits, so Jev decides it, and the trace labels it unplaced.
            let verified = !value.inert && !unplaced && judged.verified;
            // An attempt goes to Jev marked as one; the gateway never allows it on its own.
            let attempt = judged.attempt.filter(|_| !value.inert && !unplaced);
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
                    part: None,
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
                    whole_kind: None,
                });
            }
            let place = Place {
                slot,
                object: request_object.map(str::to_owned),
                origin_objects,
                origin_tiers,
                public_access: access,
                attempt,
                unplaced,
            };
            shown.push(value_entry(
                value,
                seen.is_some(),
                verified,
                &ranked,
                turn.secret,
                tuning.secret_words,
                place,
            ));
        }
        PlannedValues {
            values,
            shown,
            all_known,
            attempted,
            unplaceable,
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
            // The budget is spent: no call is made, and the request is refused with 429 whatever
            // the site allows (docs/02 section 2.5).
            Err(code) => {
                row.failure = Some(code.to_owned());
                return (Verdict::CallLimited, row);
            }
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
            path: &redacted_path(turn.resolved.logical_path(), turn.secret),
            values,
            truncated: turn.extracted.truncated,
            credential: turn.secret,
            secret_words: tuning.secret_words,
            function: turn.function.as_ref().and_then(FunctionView::state),
        };
        let batched = match build_states(&input) {
            Ok(batched) => batched,
            // A state that does not fit even in batches is refused with 403 whatever the site
            // allows. No call is made, and `on_jev_unavailable` does not apply (docs/02 section 2.4).
            Err(error @ JudgeError::StateTooLarge) => {
                row.failure = Some(error.to_string());
                return (Verdict::Unsafe(DecisionPath::JevUnavailable), row);
            }
            Err(error) => return unjudged(row, &error.to_string()),
        };
        self.call_batches(turn, &row, batched).await
    }

    /// Makes one call per batch, at most [`JEV_PARALLEL_MAX`] at a time, and merges the answers
    /// (docs/02 section 2.5). The verdict does not depend on the order the calls finish in. A
    /// denial decides the request at once: the calls still waiting are dropped, not awaited. Values
    /// left out of the batches are counted in the record and keep the request out of the cache.
    async fn call_batches(
        &self,
        turn: &Turn<'_>,
        template: &JevRecord,
        batched: Batched,
    ) -> (Verdict, JevRecord) {
        let Batched { states, left_out } = batched;
        let started = Instant::now();
        let sent = AtomicU64::new(0);
        let timeout = turn.tuning.jev_timeout;
        let total = states.len();
        let mut calls = stream::iter(states.into_iter().enumerate())
            .map(|(index, (state, trim))| {
                self.call_batch(index, state, trim, template, timeout, &sent)
            })
            .buffer_unordered(JEV_PARALLEL_MAX);
        let mut answers = Vec::with_capacity(total);
        while let Some(answer) = calls.next().await {
            let denied = answer.kind == Kind::Deny;
            answers.push(answer);
            if denied {
                break;
            }
        }
        drop(calls);
        let Some(position) = decisive(&answers) else {
            return unjudged(template.clone(), "JEV_UNKNOWN");
        };
        let usage = if total > 1 {
            merged_usage(&answers, position)
        } else {
            None
        };
        let BatchAnswer {
            index,
            kind,
            mut row,
        } = answers.swap_remove(position);
        row.request_bytes = u32::try_from(sent.load(Ordering::Relaxed)).ok();
        row.millis = elapsed_millis(started);
        if total > 1 {
            row.batches = u16::try_from(total).ok();
            row.batch = u16::try_from(index + 1).ok();
            row.usage = usage;
        }
        row.left_out = (left_out > 0).then_some(left_out);
        match kind {
            Kind::Allow => {
                // A verdict that judged only part of the request is not kept for the cache window.
                if left_out == 0 {
                    self.remember_allow(turn);
                }
                (Verdict::Safe(DecisionPath::JevAllow), row)
            }
            Kind::Deny => (Verdict::Unsafe(DecisionPath::JevDeny), row),
            Kind::Unknown | Kind::Failed => {
                let code = row
                    .failure
                    .clone()
                    .unwrap_or_else(|| "JEV_UNKNOWN".to_owned());
                unjudged(row, &code)
            }
        }
    }

    /// One call for one batch: its state goes to Jev, and the reply is read into the batch's
    /// record, which fills the same fields a single call always filled.
    async fn call_batch(
        &self,
        index: usize,
        state: String,
        trim: u8,
        template: &JevRecord,
        timeout: Duration,
        sent: &AtomicU64,
    ) -> BatchAnswer {
        let body = request_body(&self.jev.model(), &state, &self.prompt);
        let mut row = JevRecord {
            trim: Some(trim),
            state: Some(state),
            request_bytes: u32::try_from(body.len()).ok(),
            ..template.clone()
        };
        sent.fetch_add(
            u64::try_from(body.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        let started = Instant::now();
        let reply = self.jev.ask(body, timeout).await;
        row.millis = elapsed_millis(started);
        let reply = match reply {
            Ok(reply) => reply,
            Err(failure) => {
                if let Some((status, body)) = failure_reply(&failure) {
                    row.http_status = Some(status);
                    row.response = Some(lenient_text(body));
                }
                row.failure = Some(failure_code(&failure).to_owned());
                return BatchAnswer {
                    index,
                    kind: Kind::Failed,
                    row,
                };
            }
        };
        row.http_status = Some(200);
        row.response = Some(lenient_text(&reply));
        let answers = match parse_response(&reply) {
            Ok(answers) => answers,
            Err(error) => {
                row.failure = Some(error.to_string());
                return BatchAnswer {
                    index,
                    kind: Kind::Failed,
                    row,
                };
            }
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
        let kind = match conclusion {
            Conclusion::Allow => Kind::Allow,
            Conclusion::Deny => Kind::Deny,
            Conclusion::Unknown => {
                row.failure = Some("JEV_UNKNOWN".to_owned());
                Kind::Unknown
            }
        };
        BatchAnswer { index, kind, row }
    }

    /// Keeps Jev's allow for the cache window under the session that asked (docs/01 section 1.4
    /// step 5). A request with unread values or an unknown interface is never cached.
    fn remember_allow(&self, turn: &Turn<'_>) {
        let request = turn.request;
        let tuning = turn.tuning;
        // An attempt is never remembered: a model that did not answer DENY for it must not settle the next one.
        let attempt = turn.function.as_ref().is_some_and(|view| view.attempt);
        if tuning.cache_ms == 0 || turn.resolved.is_unknown() || turn.extracted.truncated || attempt
        {
            return;
        }
        // A credential without a session has nowhere to keep the allow.
        let mut inner = self.lock();
        let session = match turn.session_id {
            Some(id) => inner.store.existing(id, request.now_ms),
            None => Some(
                inner
                    .store
                    .session(turn.address, turn.origin, request.now_ms),
            ),
        };
        if let Some(session) = session {
            session.cache_allow(
                *turn.cache_key,
                request.now_ms,
                tuning.cache_ms,
                request_number(request.request_id),
            );
        }
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
        // The session's budget is for a session the store holds; a credential without one
        // spends the budget of its address (`limit_key` is then the address).
        let session_id = session_id.filter(|id| inner.store.contains(id, request.now_ms));
        let origin = session_id.and_then(|id| inner.store.origin_of(&id, request.now_ms));
        let allowed = match origin {
            // A session's call also counts against all the sessions of the address that created
            // it. Either budget being spent refuses the call and neither is charged, so a session
            // that used up its own does not use up its neighbours' share of the address's.
            Some(origin) => inner.limiter.allow_all(
                &[
                    (
                        self.key.mac("address-sessions", &origin),
                        tuning.session_calls.saturating_mul(ADDRESS_SESSIONS_FACTOR),
                    ),
                    (limit_key, tuning.session_calls),
                ],
                request.now_ms,
            ),
            None => inner
                .limiter
                .allow_all(&[(limit_key, tuning.address_calls)], request.now_ms),
        };
        if !allowed {
            return Err("JEV_CALL_LIMIT");
        }
        let Some(session) = session_id.and_then(|id| inner.store.existing(id, request.now_ms))
        else {
            return Ok(Snapshot::default());
        };
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
        session_id.is_some_and(|id| {
            self.lock()
                .store
                .existing(id, now_ms)
                .is_some_and(|session| session.identity().is_admin())
        })
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
    /// empty. A failed request teaches nothing. Nor does a response to a request
    /// the gateway would refuse (observe mode forwards it): its values are not
    /// learned and nothing it declares is kept, as if the request had never
    /// reached the origin (docs/07 section 7.4.6).
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
            issued.map(|credential| label(&self.session_key(site.name(), credential)));
        if logical.is_some_and(|path| site.is_bypass(path)) {
            summary.skip = Some(Skip::Bypass);
            return summary;
        }
        let success = (200..300).contains(&observation.status);
        let origin = self.origin_key(observation.client);
        let entry = logical.is_some_and(|path| site.is_entry(path));
        // The origin answered the request, so an echo of what it sent teaches
        // nothing, whatever the status: a refused request's values can still come
        // back in a later response, such as a list of recent attempts.
        let inherited = self.note_request_sent(site.name(), observation, issued.is_some(), entry);
        let issuing_redirect = (300..400).contains(&observation.status) && issued.is_some();
        if !success {
            summary.skip = Some(Skip::Status);
        }
        if !(success || issuing_redirect) {
            return summary;
        }
        // A request the gateway would refuse teaches its response nothing (docs/07 section 7.4.6).
        // The values it sent are still noted: a credential it issued inherits them, as before, so
        // the session does not learn them back from an echo later.
        if observation.would_block {
            // A redirect that issues a credential is not a 2xx, so its status reason stays. Nothing here
            // recognizes a credential (docs/07 section 7.4.6): the values the request sent wait for the
            // credential it issues, as they do for a credential the origin has not answered.
            summary.skip = summary.skip.or(Some(Skip::WouldBlock));
            if let Some(credential) = issued {
                self.lock().store.stage_issued(
                    self.session_key(site.name(), credential),
                    observation.now_ms,
                    inherited.as_ref(),
                    observation.sent,
                );
            }
            return summary;
        }
        let ResponseFacts {
            mut values,
            credentials,
            shape,
        } = if success {
            read_body(&mut summary, observation)
        } else {
            ResponseFacts::default()
        };
        self.count_values(site, observation, resolved, &values, &mut summary);
        // The exposure alert reads the response as the origin sent it, echo included: an origin
        // that returns another user's contact details with the id the client asked for still
        // discloses them. Learning and the identity claims read it without the echo.
        let as_sent = values.clone();
        self.without_echo(&mut values, observation.echo);

        // The recent requests are only ever shown (to Jev and in the log), so a path that carries
        // the credential is remembered redacted. An origin keeps its request as it was: positions
        // are matched on it, and it is scrubbed where it is shown.
        let secret = observation
            .credential
            .map(|credential| credential_token(site, credential))
            .filter(|secret| !secret.is_empty());
        let shown_path = redacted_path(resolved.logical_path(), secret);
        let request = format!("{} {}", observation.method, resolved.logical_path());
        let request_id = request_number(observation.request_id);
        let source = Source {
            request: &request,
            request_id,
            at_ms: observation.now_ms,
        };
        let claims = identity_claims(site.objects(), &request, &values);
        let mut inner = self.lock();
        // The origin recognizes the request's credential (docs/01 section 1.2) when it answers an entry
        // with 2xx and the site has no user identity position, or, with one, when the response declares a
        // user the request did not send itself. The session starts with the values the request sent,
        // which `note_request_sent` staged for the credential, so an echo of them is not learned.
        if let Some(credential) = observation
            .credential
            .filter(|credential| success && entry && !credential.is_empty())
        {
            let declared = claims.iter().any(|(role, value)| {
                *role == IdentityRole::User
                    && !observation
                        .sent
                        .contains(&self.key.mac("value", value.as_bytes()))
            });
            if declared || !site.objects().declares_user_identity() {
                let token = self
                    .key
                    .mac("value", credential_token(site, credential).as_bytes());
                inner.store.start_session(
                    site.name(),
                    self.session_key(site.name(), credential),
                    origin,
                    token,
                    observation.now_ms,
                );
            }
        }
        // Only a credential that has a live session, one the origin answered earlier or one just recognized,
        // learns from this response (docs/01 section 1.2). Any other is judged as no credential.
        let seeded = observation.credential.filter(|credential| {
            success
                && !credential.is_empty()
                && inner.store.contains(
                    &self.session_key(site.name(), credential),
                    observation.now_ms,
                )
        });
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
        // A JSON login answered to a client with no credential is held until the credential it
        // issues starts a session (docs/01 section 1.7). Values the request sent are left out, as
        // an echo teaches nothing. Only a login with a candidate credential is worth holding. A
        // long candidate is a credential too, but no value: it is held by its keyed hash only.
        if success
            && entry
            && seeded.is_none()
            && issued.is_none()
            && summary.observed == Observed::Json
        {
            let held: Vec<HeldValue> = values
                .iter()
                .filter_map(|value| {
                    let digest = self.key.mac("value", value.value.as_bytes());
                    (!observation.sent.contains(&digest)).then(|| HeldValue {
                        digest,
                        field: value.field.clone(),
                        at: value.at.clone(),
                        candidate: value.value.chars().count() >= LOGIN_CREDENTIAL_CHARS,
                    })
                })
                .collect();
            let long: Vec<Digest16> = credentials
                .iter()
                .map(|candidate| self.key.mac("value", candidate.value.as_bytes()))
                .filter(|digest| !observation.sent.contains(digest))
                .collect();
            if held.iter().any(|value| value.candidate) || !long.is_empty() {
                summary.pending_values = Some(held.len() + long.len());
                // The identity the response declares is held as the values are: keyed, and without
                // what the request sent, which says nothing about who answers.
                let shown: Vec<_> = claims
                    .iter()
                    .copied()
                    .filter(|(_, value)| {
                        !observation
                            .sent
                            .contains(&self.key.mac("value", value.as_bytes()))
                    })
                    .collect();
                let identity = SessionIdentity::declared(&self.key, &shown);
                inner.store.hold_login(
                    site.name(),
                    request_id,
                    observation.now_ms,
                    held,
                    long,
                    identity,
                );
            }
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
                    self.address_key(site.name(), observation.client),
                    origin,
                    observation.now_ms,
                )
                .remember(&self.key, &source, &values);
            new_values = Some(added);
        }
        for credential in [seeded, issued].into_iter().flatten() {
            let session = inner.store.session(
                self.session_key(site.name(), credential),
                origin,
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
                path: shown_path.clone().into_owned(),
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

    /// Stops the session that `context` names from learning from responses. A credential with no
    /// session yet keeps the stop for the session it starts, so judging a request creates none.
    fn stop_learning(&self, context: Option<Digest16>, now_ms: u64) {
        if let Some(context) = context {
            self.lock().store.stop_learning(context, now_ms);
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

    /// Records the values the request sent in the context it was judged in on `site`: the session
    /// of its credential, or the address's context when it had none. A credential's values wait for
    /// its session, which only an answer that accepts the credential starts (see `observe`), so a
    /// refused request starts no session. When the response issues a credential, returns what that
    /// context sent, for the new session to inherit.
    fn note_request_sent(
        &self,
        site: &str,
        observation: &Observation<'_>,
        issuing: bool,
        entry: bool,
    ) -> Option<SentRecord> {
        let credential = observation
            .credential
            .filter(|credential| !credential.is_empty());
        let request_context = match credential {
            Some(credential) => self.session_key(site, credential),
            None => self.address_key(site, observation.client),
        };
        let mut inner = self.lock();
        let inherited = issuing.then(|| inner.store.sent_record(&request_context));
        match credential {
            Some(_) => {
                // A credential no session holds keeps the values in its staging (see `ContextStore::note_sent`).
                // On an entry it was judged in its address, and that address may learn from this response, so the
                // address notes the values as well (docs/01 section 1.4 step 8).
                let recognized = inner.store.contains(&request_context, observation.now_ms);
                inner
                    .store
                    .note_sent(request_context, observation.now_ms, observation.sent);
                if !recognized && entry && !observation.sent.is_empty() {
                    inner
                        .store
                        .session(
                            self.address_key(site, observation.client),
                            self.origin_key(observation.client),
                            observation.now_ms,
                        )
                        .note_sent(observation.sent);
                }
            }
            None if !observation.sent.is_empty() => {
                inner
                    .store
                    .session(
                        request_context,
                        self.origin_key(observation.client),
                        observation.now_ms,
                    )
                    .note_sent(observation.sent);
            }
            None => {}
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

/// The group a client address belongs to, for the limits on what one source can do (docs/02
/// section 2.5): an IPv4 address by itself, an IPv6 address by its first 64 bits (a /64 is one
/// user or one site, and an attacker holds the whole of it), an IPv4-mapped IPv6 address as the
/// IPv4 address it carries. Text that is not an address, an empty one included, is a group of its
/// own as it stands.
fn address_group(client: &str) -> Cow<'_, str> {
    match client
        .parse::<IpAddr>()
        .map(|address| address.to_canonical())
    {
        Ok(IpAddr::V4(address)) => Cow::Owned(address.to_string()),
        Ok(IpAddr::V6(address)) => {
            let [first, second, third, fourth, ..] = address.segments();
            Cow::Owned(format!("{first:x}:{second:x}:{third:x}:{fourth:x}::/64"))
        }
        Err(_) => Cow::Borrowed(client),
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

/// The text a login response must carry to be this credential (docs/01 section 1.7). Only the
/// `Authorization` header carries an authentication scheme in HTTP, so only its value is cut
/// down to the token. Any other header, and a cookie, is the credential as it is: a custom header
/// may hold a raw value with a space in it, and that value is not a scheme.
fn credential_token<'a>(site: &SiteSpec, credential: &'a str) -> &'a str {
    match site.session() {
        SessionCredential::Header(name) if name.eq_ignore_ascii_case("authorization") => {
            without_scheme(credential)
        }
        SessionCredential::Header(_) | SessionCredential::Cookie(_) => credential,
    }
}

/// The text that must never reach Jev or the log for this request: the session credential, and for
/// an `Authorization` header its token without the scheme. A client that repeats its bearer token
/// in the query, the body or the path sends the bare token, never `Bearer <token>`, and the bare
/// token is part of the full header value, so matching on it covers both.
fn redaction_secret<'a>(site: Option<&SiteSpec>, request: &RequestFacts<'a>) -> Option<&'a str> {
    let credential = request.credential?;
    let secret = site.map_or(credential, |site| credential_token(site, credential));
    (!secret.is_empty()).then_some(secret)
}

/// `value` without a leading authentication scheme, such as `Bearer `. A scheme is a token
/// (RFC 9110 section 11.1), so digits and some symbols may be in it.
fn without_scheme(value: &str) -> &str {
    match value.split_once(' ') {
        Some((scheme, rest)) if !scheme.is_empty() && scheme.bytes().all(is_token_char) => {
            rest.trim_start()
        }
        _ => value,
    }
}

/// A character of an HTTP token (RFC 9110 section 5.6.2).
fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
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
    let secret = redaction_secret(site, request);
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
        path: redacted_path(request.path, secret).into_owned(),
        logical_path: redacted_path(resolved.logical_path(), secret).into_owned(),
        api: resolved.api().cloned(),
        request_headers: request.request_headers.to_vec(),
        query: request
            .query
            .map(|query| redacted_query(query, secret, secret_words)),
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

/// How one batch's call ended, for the merge in [`Judge::call_batches`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Jev allowed the batch: `access` is ALLOW and `attack` is BENIGN.
    Allow,
    /// Jev denied the batch: `access` is DENY or `attack` is ATTACK.
    Deny,
    /// The top option of a question is UNKNOWN, or two options tie.
    Unknown,
    /// No usable answer: a timeout, a transport or HTTP failure, or an invalid reply.
    Failed,
}

/// What one batch's call came to: the batch's place in the request, how the call ended, and the
/// record of the call.
struct BatchAnswer {
    index: usize,
    kind: Kind,
    row: JevRecord,
}

impl BatchAnswer {
    /// The weaker of the two probabilities an allow rests on: `min(P(ALLOW), P(BENIGN))`.
    fn assurance(&self) -> f64 {
        let access = self.row.access.get("ALLOW").copied().unwrap_or(0.0);
        let attack = self.row.attack.get("BENIGN").copied().unwrap_or(0.0);
        access.min(attack)
    }
}

/// The position in `answers` of the batch whose answer decides the request (docs/02 section 2.5).
/// A denial decides first, then a failure, then an UNKNOWN; among several of one kind the lowest
/// batch wins. When every batch allows, the least assured one decides, the lowest batch on a tie.
fn decisive(answers: &[BatchAnswer]) -> Option<usize> {
    let first = |kind: Kind| {
        answers
            .iter()
            .enumerate()
            .filter(|(_, answer)| answer.kind == kind)
            .min_by_key(|(_, answer)| answer.index)
            .map(|(position, _)| position)
    };
    first(Kind::Deny)
        .or_else(|| first(Kind::Failed))
        .or_else(|| first(Kind::Unknown))
        .or_else(|| {
            answers
                .iter()
                .enumerate()
                .filter(|(_, answer)| answer.kind == Kind::Allow)
                .min_by(|(_, left), (_, right)| {
                    left.assurance()
                        .total_cmp(&right.assurance())
                        .then(left.index.cmp(&right.index))
                })
                .map(|(position, _)| position)
        })
}

/// The usage of several calls: each top-level number is added up by name, and every other field
/// is the one the decisive batch reports (docs/02 section 2.5).
fn merged_usage(answers: &[BatchAnswer], decisive: usize) -> Option<serde_json::Value> {
    let shown = answers.get(decisive)?.row.usage.as_ref()?.as_object()?;
    let mut merged = serde_json::Map::new();
    for usage in answers
        .iter()
        .filter_map(|answer| answer.row.usage.as_ref()?.as_object())
    {
        for (name, amount) in usage {
            let Some(number) = amount.as_number() else {
                continue;
            };
            let total = match merged.get(name).and_then(serde_json::Value::as_number) {
                Some(sum) => add_numbers(sum, number),
                None => number.clone(),
            };
            merged.insert(name.clone(), serde_json::Value::Number(total));
        }
    }
    for (name, value) in shown {
        if !value.is_number() {
            merged.insert(name.clone(), value.clone());
        }
    }
    Some(serde_json::Value::Object(merged))
}

/// The sum of two JSON numbers: exact for whole numbers, floating point otherwise.
fn add_numbers(left: &serde_json::Number, right: &serde_json::Number) -> serde_json::Number {
    if let (Some(a), Some(b)) = (left.as_u64(), right.as_u64()) {
        return serde_json::Number::from(a.saturating_add(b));
    }
    let sum = left.as_f64().unwrap_or(0.0) + right.as_f64().unwrap_or(0.0);
    serde_json::Number::from_f64(sum).unwrap_or_else(|| left.clone())
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
    let kind = crate::values::media_kind(content_type?);
    if crate::values::is_json_media(&kind) {
        Some(Observed::Json)
    } else if kind.starts_with("text/html") {
        Some(Observed::Html)
    } else {
        None
    }
}

/// Reads the body of a successful response: its values, its long credential candidates and, for a
/// JSON document that parsed, its structure. Says in `summary` why a body was not read.
fn read_body(summary: &mut ObservationSummary, observation: &Observation<'_>) -> ResponseFacts {
    match (observation.unread, response_kind(observation.content_type)) {
        (Some(reason), _) => summary.skip = Some(reason),
        (None, Some(kind)) => {
            summary.observed = kind;
            return extract_response_facts(observation.content_type, observation.body);
        }
        (None, None) => summary.skip = Some(Skip::ContentType),
    }
    ResponseFacts::default()
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
        // A spent call budget is refused with 429 whatever `on_jev_unavailable` says (docs/02 section 2.5).
        Verdict::CallLimited => refuse(DecisionPath::JevUnavailable, 429),
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
    use xshield_core::context::{Attempt, LoginUnbound};

    #[test]
    fn a_full_limiter_refuses_new_keys_and_does_not_grow() {
        let mut limiter = Limiter::default();
        for n in 0..LIMITER_MAX {
            let mut key = [0_u8; 16];
            key[..8].copy_from_slice(&(n as u64).to_be_bytes());
            assert!(limiter.allow(key, 2, 1_000));
        }
        let fresh = [0xFF_u8; 16];
        assert!(!limiter.allow(fresh, 2, 1_000));
        assert_eq!(limiter.windows.len(), LIMITER_MAX);
        // A known key keeps its own budget while the map is full.
        assert!(limiter.allow([0; 16], 2, 1_000));
        assert!(!limiter.allow([0; 16], 2, 1_000));
        // Once the windows have run out the map is pruned and the new key is served.
        assert!(limiter.allow(fresh, 2, 1_000 + WINDOW_MS));
        assert_eq!(limiter.windows.len(), 1);
    }

    /// The gateway id of the origin responses the tests observe.
    const RID: &str = "req_00000000000000000000000000000001";

    /// What a call to the fake answers: the two choices, or a failure.
    type Reply = Result<(&'static str, &'static str), JevFailure>;

    /// A rule that answers a call from its body, or returns None to leave that call to the other answers.
    type Rule = fn(&str) -> Option<(&'static str, &'static str)>;

    #[derive(Clone)]
    struct FakeJev {
        calls: Arc<AtomicUsize>,
        sent: Arc<Mutex<Vec<String>>>,
        timeouts: Arc<Mutex<Vec<Duration>>>,
        reply: Arc<Mutex<Reply>>,
        /// Replies for the calls whose body contains a marker, looked up before `reply`.
        marked: Arc<Mutex<Vec<(&'static str, Reply)>>>,
        /// Rules that answer the calls whose body they pick, looked up before `marked` and `reply`.
        rules: Arc<Mutex<Vec<Rule>>>,
        in_flight: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl FakeJev {
        fn new() -> Self {
            Self {
                calls: Arc::default(),
                sent: Arc::default(),
                timeouts: Arc::default(),
                reply: Arc::new(Mutex::new(Ok(("ALLOW", "BENIGN")))),
                marked: Arc::default(),
                rules: Arc::default(),
                in_flight: Arc::default(),
                peak: Arc::default(),
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
        /// The calls whose body `rule` picks answer what the rule returns; it returns None for the others.
        fn answer_by(&self, rule: Rule) {
            self.rules.lock().unwrap().push(rule);
        }
        /// The calls whose body contains `marker` answer `access` and `attack`.
        fn answer_marked(&self, marker: &'static str, access: &'static str, attack: &'static str) {
            self.marked
                .lock()
                .unwrap()
                .push((marker, Ok((access, attack))));
        }
        /// The calls whose body contains `marker` fail with `failure`.
        fn fail_marked(&self, marker: &'static str, failure: JevFailure) {
            self.marked.lock().unwrap().push((marker, Err(failure)));
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
        /// The bodies sent, in arrival order.
        fn sent(&self) -> Vec<String> {
            self.sent.lock().unwrap().clone()
        }
        /// The most calls that were in flight at the same time.
        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
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
            let text = String::from_utf8(body).unwrap();
            self.sent.lock().unwrap().push(text.clone());
            let in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(in_flight, Ordering::SeqCst);
            // The call waits here, so that calls made together are in flight together.
            tokio::task::yield_now().await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            let ruled: Option<Reply> = self
                .rules
                .lock()
                .unwrap()
                .iter()
                .find_map(|rule| rule(&text))
                .map(Ok);
            let marked = self
                .marked
                .lock()
                .unwrap()
                .iter()
                .find(|(marker, _)| text.contains(marker))
                .map(|(_, reply)| reply.clone());
            let reply = match ruled.or(marked) {
                Some(reply) => reply,
                None => self.reply.lock().unwrap().clone(),
            };
            let (access, attack) = reply?;
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
            method_overrides: &[],
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

    /// The origin answers an entry with 2xx and nothing to learn, which is what gives the credential a
    /// session (docs/01 section 1.2, on a site without an identity position): until then it is judged as
    /// no credential, on its address's budget.
    fn confirm(judge: &Judge<FakeJev>, site: &SiteSpec, credential: &str) {
        confirm_from(judge, site, credential, "10.0.0.1");
    }

    /// As [`confirm`], for a response to a request from `client`: the session is created from
    /// that address.
    fn confirm_from<'a>(
        judge: &Judge<FakeJev>,
        site: &SiteSpec,
        credential: &'a str,
        client: &'a str,
    ) {
        judge.observe(
            site,
            &Observation {
                path: "/login",
                body: b"{}",
                client,
                ..list_response(credential, 0)
            },
        );
    }

    /// As [`confirm`], for a site whose entry is not `/login`: the origin answers `path`, one of its entries.
    fn confirm_at<'a>(judge: &Judge<FakeJev>, site: &SiteSpec, path: &'a str, credential: &'a str) {
        judge.observe(
            site,
            &Observation {
                path,
                body: b"{}",
                ..list_response(credential, 0)
            },
        );
    }

    /// As [`confirm`], for a site with a user identity position on `GET /api/home`: the answer declares a
    /// user the request did not send, which recognizes the credential (docs/01 section 1.2, rule S3).
    fn confirm_identity(judge: &Judge<FakeJev>, site: &SiteSpec, credential: &str) {
        judge.observe(
            site,
            &home_for(credential, br#"{"doctor":{"id":"DR-CONFIRM"}}"#),
        );
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
        confirm_at(&judge, &site, "/api/rpc/login", "alice");
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
        confirm_at(&judge, &site, "/api/rpc/login", "alice");
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
    async fn objects_shown_by_a_json_suffix_response_are_allowed_without_jev() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &Observation {
                content_type: Some("application/hal+json"),
                ..list_response("alice", 0)
            },
        );
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
        confirm(&judge, &site, "alice-browser-2");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
            method_overrides: &[],
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
        confirm(&judge, &site, "alice");
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
                    method_overrides: &[],
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
        confirm(&judge, &site, "alice");
        // Its tokens cannot all be recorded as sent, so no later echo can be told apart.
        let body = (0..=SENT_MAX)
            .map(|index| format!("t{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let upload = RequestFacts {
            route: None,
            request_headers: &[],
            method_overrides: &[],
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
        confirm(&judge, &site, "alice");
        // The gateway cannot read this body, but the origin parses it and echoes the id.
        let search = RequestFacts {
            route: None,
            request_headers: &[],
            method_overrides: &[],
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
        // The gateway cannot read this body as JSON, but the origin does, and it
        // decodes the escaped id before echoing it. The body is `{"patientId":"\u0050-0000099"}`.
        let search = RequestFacts {
            route: None,
            request_headers: &[],
            method_overrides: &[],
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
        confirm(judge, site, session);
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
        confirm(&judge, &site, "doctor-a");
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
        confirm(&judge, &site, "bare");
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
        confirm(&judge, &site, "files");
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
        confirm(&judge, &site(r#","mode":"enforce""#), "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site(r#","mode":"enforce""#), "alice");
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
        confirm(&judge, &site(r#","mode":"enforce""#), "alice");
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
        confirm(&judge, &site(""), "alice");
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
    async fn a_response_to_a_request_that_would_be_refused_teaches_nothing() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"observe""#);
        let refused = judge
            .judge(&site, &get("/api/patients/D4411", None, Some("alice"), 0))
            .await;
        assert!(refused.forward);
        assert_eq!(refused.record.outcome, Outcome::WouldBlock);
        let observed = judge.observe(
            &site,
            &Observation {
                would_block: true,
                sent: &refused.sent,
                echo: &refused.echo,
                ..list_response("alice", 1_000)
            },
        );
        assert_eq!(observed.new_values, 0);
        assert_eq!(observed.skip, Some(Skip::WouldBlock));
        assert!(observed.after_would_block);
        let later = judge
            .judge(&site, &get("/api/patients/7", None, Some("alice"), 2_000))
            .await;
        assert_ne!(later.record.decision_path, DecisionPath::FastAllow);
    }

    #[tokio::test]
    async fn the_same_response_is_learned_when_the_request_would_not_be_refused() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"observe""#);
        let refused = judge
            .judge(&site, &get("/api/patients/D4411", None, Some("alice"), 0))
            .await;
        let observed = judge.observe(
            &site,
            &Observation {
                sent: &refused.sent,
                echo: &refused.echo,
                ..list_response("alice", 1_000)
            },
        );
        assert!(observed.new_values > 0);
        assert_eq!(observed.skip, None);
        assert!(!observed.after_would_block);
        let later = judge
            .judge(&site, &get("/api/patients/7", None, Some("alice"), 2_000))
            .await;
        assert_eq!(later.record.decision_path, DecisionPath::FastAllow);
    }

    #[tokio::test]
    async fn a_refused_login_that_issues_a_credential_gives_its_session_nothing_seen() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"observe""#);
        let login = RequestFacts {
            route: None,
            request_headers: &[],
            method: "POST",
            path: "/login",
            content_type: Some("application/json"),
            body: br#"{"username":"alice","password":"hunter2"}"#,
            ..get("/login", None, None, 1_000)
        };
        let judged = judge.judge(&site, &login).await;
        assert!(judged.forward);
        let observed = judge.observe(
            &site,
            &Observation {
                route: None,
                request_id: RID,
                unread: None,
                would_block: true,
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
        assert_eq!(observed.skip, Some(Skip::WouldBlock));
        assert!(observed.issued_session.is_some());
        assert_eq!(observed.new_values, 0);
        assert!(!observed.entry_passed);
        // The refused response starts no session for the credential it issued (docs/07 section 7.4.6): the
        // request that uses it is judged as no credential, so Jev is not asked.
        let calls = fake.calls();
        let object = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("fresh"), 2_000),
            )
            .await;
        assert_eq!(object.record.decision_path, DecisionPath::NoSession);
        assert_eq!(fake.calls(), calls);
    }

    #[tokio::test]
    async fn a_refused_anonymous_entry_response_is_not_learned_by_its_address() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"observe""#);
        // A sign-up page: no credential yet, the origin shows the new id.
        let sign_up = |client| RequestFacts {
            route: None,
            request_headers: &[],
            client,
            ..get("/api/patients", Some("id=7"), None, 5_000)
        };
        let blind = judge.judge(&site, &sign_up("10.0.0.9")).await;
        assert_eq!(blind.record.outcome, Outcome::WouldBlock);
        let observed = judge.observe(
            &site,
            &Observation {
                would_block: true,
                credential: None,
                client: "10.0.0.9",
                ..list_response("unused", 1_000)
            },
        );
        assert_eq!(observed.new_values, 0);
        assert_eq!(observed.skip, Some(Skip::WouldBlock));
        let shown = judge.judge(&site, &sign_up("10.0.0.9")).await;
        assert_ne!(shown.record.decision_path, DecisionPath::FastAllow);
    }

    #[tokio::test]
    async fn a_refused_json_login_is_not_held_and_its_token_learns_nothing() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(
            r#","mode":"observe","advanced":{"field_kinds":[{"field":"bid","kind":"basket"}]}"#,
        );
        let body = login_body(LOGIN_TOKEN, 6);
        let login = judge.observe(
            &site,
            &Observation {
                would_block: true,
                ..json_login(body.as_bytes(), "10.0.0.1", 0)
            },
        );
        assert_eq!(login.pending_values, None);
        assert_eq!(login.skip, Some(Skip::WouldBlock));
        assert_eq!(login.new_values, 0);
        // The token's session was not set up from the values of the refused login.
        let entry = judge
            .judge(&site, &get("/api/home", None, Some(LOGIN_TOKEN), 1))
            .await;
        assert!(
            entry
                .record
                .trace
                .session
                .as_ref()
                .is_none_or(|session| session.login_request_id.is_none())
        );
        let own = judge
            .judge(&site, &get("/rest/basket/6", None, Some(LOGIN_TOKEN), 2))
            .await;
        assert_ne!(own.record.decision_path, DecisionPath::FastAllow);
        // The address context learned nothing from it either.
        let anon = judge
            .judge(
                &site,
                &RequestFacts {
                    client: "10.0.0.1",
                    ..get("/api/patients", Some("id=6"), None, 3)
                },
            )
            .await;
        assert_ne!(anon.record.decision_path, DecisionPath::FastAllow);
    }

    #[tokio::test]
    async fn a_refused_response_leaves_no_trace_in_a_live_session() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"observe""#);
        confirm(&judge, &site, "alice");
        let refused = judge.observe(
            &site,
            &Observation {
                would_block: true,
                path: "/api/home",
                ..list_response("alice", 1_000)
            },
        );
        assert!(!refused.entry_passed);
        assert_eq!(refused.new_values, 0);
        assert_eq!(refused.values, 0);
        assert!(refused.fingerprints.is_empty());
        assert!(refused.shape.is_none());
        assert!(refused.exposure.is_none());
        // The same response, not refused, passes the entry for the first time: the refused one kept
        // nothing.
        let learned = judge.observe(
            &site,
            &Observation {
                path: "/api/home",
                ..list_response("alice", 2_000)
            },
        );
        assert!(learned.entry_passed);
        assert!(learned.new_values > 0);
    }

    #[tokio::test]
    async fn a_refused_redirect_and_bypass_keep_their_skip_reasons() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"observe""#);
        let redirect = judge.observe(
            &site,
            &Observation {
                would_block: true,
                credential: None,
                issued_credential: Some("fresh"),
                status: 302,
                path: "/login",
                ..list_response("x", 1_000)
            },
        );
        assert_eq!(redirect.skip, Some(Skip::Status));
        assert!(redirect.issued_session.is_some());
        let bypass = judge.observe(
            &site,
            &Observation {
                would_block: true,
                path: "/static/app.js",
                ..list_response("alice", 1_000)
            },
        );
        assert_eq!(bypass.skip, Some(Skip::Bypass));
        let failed = judge.observe(
            &site,
            &Observation {
                would_block: true,
                status: 500,
                ..list_response("alice", 1_000)
            },
        );
        assert_eq!(failed.skip, Some(Skip::Status));
    }

    #[tokio::test]
    async fn c4_secrets_never_reach_jev() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site("");
        let login = RequestFacts {
            route: None,
            request_headers: &[],
            method_overrides: &[],
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
        confirm(&judge, &site, "SECRETCOOKIE");
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
            method_overrides: &[],
            method: "GET",
            path: "/login",
            query: Some("name=Score%20Board"),
            ..get("/login", None, None, 0)
        };
        for index in 0..(ADDRESS_CALLS_PER_MINUTE * 2) {
            let at = RequestFacts {
                route: None,
                request_headers: &[],
                method_overrides: &[],
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
            method_overrides: &[],
            query: Some("name=%27%20OR%201%3D1--"),
            now_ms: 9_000,
            ..poll
        };
        let verdict = judge.judge(&site, &attack).await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_repeated_body_key_judges_each_of_its_values() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice", 0));
        // The origin may read the first `patient` and the gateway the last. The last one was
        // shown to this session, the first one never was: the first still goes to Jev.
        let first_unseen = RequestFacts {
            route: None,
            request_headers: &[],
            method_overrides: &[],
            method: "POST",
            content_type: Some("application/json"),
            body: br#"{"patient":"42","patient":"7"}"#,
            ..get("/api/orders", None, Some("alice"), 1_000)
        };
        let verdict = judge.judge(&site, &first_unseen).await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 1);
        assert!(fake.sent.lock().unwrap()[0].contains(r#""value":"42""#));
        // The other order: the first one was shown, the last one never was.
        let last_unseen = RequestFacts {
            body: br#"{"patient":"7","patient":"42"}"#,
            ..first_unseen
        };
        let verdict = judge.judge(&site, &last_unseen).await;
        assert!(!verdict.forward);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_session_learned_on_one_site_does_not_serve_another() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let emr = site(r#","mode":"enforce""#);
        let clinic = other_site();
        judge.observe(&emr, &list_response("alice", 0));
        let known = judge
            .judge(&emr, &get("/api/patients/7", None, Some("alice"), 1_000))
            .await;
        assert_eq!(known.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
        // The credential has a session on the other site too, which has never shown this id.
        confirm(&judge, &clinic, "alice");
        let unseen = judge
            .judge(&clinic, &get("/api/patients/7", None, Some("alice"), 1_000))
            .await;
        assert!(!unseen.forward);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn an_address_context_learned_on_one_site_is_not_used_on_another() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let emr = site(r#","mode":"enforce""#);
        let clinic = other_site();
        // A sign-up page of the first site shows a new id to this client, which has no credential.
        judge.observe(
            &emr,
            &Observation {
                route: None,
                request_id: RID,
                unread: None,
                would_block: false,
                credential: None,
                client: "10.0.0.9",
                ..list_response("unused", 0)
            },
        );
        let sign_up = get("/api/patients", Some("id=7"), None, 1_000);
        let shown = judge.judge(&emr, &sign_up).await;
        assert!(shown.forward);
        assert_eq!(shown.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
        // The other site showed this client nothing.
        let other = judge.judge(&clinic, &sign_up).await;
        assert!(!other.forward);
        assert_eq!(fake.calls(), 1);
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
            method_overrides: &[],
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
    async fn c5_calls_beyond_the_session_limit_are_refused_with_429() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        confirm(&judge, &site, "alice");
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
        assert_eq!(over.refuse_status, 429);
        assert_eq!(over.record.trace.refused.as_deref(), Some("rate_limited"));
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
    async fn a_spent_call_limit_is_refused_with_429_whatever_the_site_allows() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        fake.answer("DENY", "ATTACK");
        let lenient = site(r#","mode":"enforce","on_jev_unavailable":"allow""#);
        confirm(&judge, &lenient, "mallory");
        for index in 0..SESSION_CALLS_PER_MINUTE {
            let query = format!("q=junk{index}%27");
            let _ = judge
                .judge(
                    &lenient,
                    &get("/api/records", Some(&query), Some("mallory"), 1_000),
                )
                .await;
        }
        assert_eq!(fake.calls(), SESSION_CALLS_PER_MINUTE as usize);
        let over = judge
            .judge(
                &lenient,
                &get(
                    "/api/patients/8",
                    Some("q=%27%20OR%201%3D1--"),
                    Some("mallory"),
                    1_500,
                ),
            )
            .await;
        assert!(!over.forward);
        assert_eq!(over.refuse_status, 429);
        assert_eq!(over.record.outcome, Outcome::Blocked);
        assert_eq!(over.record.decision_path, DecisionPath::JevUnavailable);
        assert_eq!(over.record.trace.refused.as_deref(), Some("rate_limited"));
        assert_eq!(
            over.record
                .jev
                .as_ref()
                .and_then(|jev| jev.failure.as_deref()),
            Some("JEV_CALL_LIMIT")
        );
        assert_eq!(fake.calls(), SESSION_CALLS_PER_MINUTE as usize);
    }

    #[tokio::test]
    async fn a_spent_call_limit_is_only_a_would_block_in_observe_mode() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let observing = site(r#","on_jev_unavailable":"allow""#);
        confirm(&judge, &observing, "mallory");
        for index in 0..SESSION_CALLS_PER_MINUTE {
            let query = format!("q=junk{index}x");
            let _ = judge
                .judge(
                    &observing,
                    &get("/api/records", Some(&query), Some("mallory"), 1_000),
                )
                .await;
        }
        let over = judge
            .judge(
                &observing,
                &get("/api/records", Some("q=over1x"), Some("mallory"), 1_500),
            )
            .await;
        assert!(over.forward);
        assert_eq!(over.record.outcome, Outcome::WouldBlock);
        assert_eq!(over.record.decision_path, DecisionPath::JevUnavailable);
        assert!(over.record.trace.refused.is_none());
        assert_eq!(
            over.record
                .jev
                .as_ref()
                .and_then(|jev| jev.failure.as_deref()),
            Some("JEV_CALL_LIMIT")
        );
        assert_eq!(fake.calls(), SESSION_CALLS_PER_MINUTE as usize);
    }

    /// A survey whose answers alone need more than the 8 KiB a `state` may hold.
    fn oversized_survey() -> String {
        let answers: Vec<String> = (0..120)
            .map(|index| {
                format!(
                    "\"answer_{index}\":\"This is a perfectly ordinary sentence number {index} typed by a user.\""
                )
            })
            .collect();
        format!("{{{},\"done\":\"1\"}}", answers.join(","))
    }

    /// A survey request of `alice`, sent with a JSON body.
    fn survey_request(body: &[u8], now_ms: u64) -> RequestFacts<'_> {
        RequestFacts {
            method: "POST",
            content_type: Some("application/json"),
            body,
            ..get("/api/survey", None, Some("alice"), now_ms)
        }
    }

    /// [`oversized_survey`] with its last answer set to `last`, so a marker lands in the last batch.
    fn survey_ending_with(last: &str) -> String {
        oversized_survey().replace("\"done\":\"1\"", &format!("\"done\":\"{last}\""))
    }

    #[tokio::test]
    async fn a_large_survey_is_judged_in_batches_and_allowed_when_every_batch_allows() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let body = oversized_survey();
        let lenient = site(r#","mode":"enforce","on_jev_unavailable":"allow""#);
        confirm(&judge, &lenient, "alice");
        let verdict = judge
            .judge(&lenient, &survey_request(body.as_bytes(), 1_000))
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevAllow);
        assert!(fake.calls() >= 2, "{} calls", fake.calls());
        let jev = verdict.record.jev.as_ref().unwrap();
        assert_eq!(jev.batches, u16::try_from(fake.calls()).ok());
        assert_eq!(
            jev.batch,
            Some(1),
            "all allow: the first batch is the least assured"
        );
        assert!(jev.failure.is_none());
    }

    #[tokio::test]
    async fn a_large_request_counts_once_against_the_call_limit() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let limited = site(r#","mode":"enforce","advanced":{"session_calls_per_minute":1}"#);
        confirm(&judge, &limited, "alice");
        let body = oversized_survey();
        let first = judge
            .judge(&limited, &survey_request(body.as_bytes(), 1_000))
            .await;
        assert!(first.forward);
        assert!(fake.calls() >= 2);
        let next = judge
            .judge(
                &limited,
                &get("/api/search", Some("q=next1x"), Some("alice"), 1_500),
            )
            .await;
        assert!(!next.forward);
        assert_eq!(next.refuse_status, 429);
        assert_eq!(next.record.trace.refused.as_deref(), Some("rate_limited"));
    }

    #[tokio::test]
    async fn an_injection_past_the_first_piece_of_a_long_value_is_sent_and_refused() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        fake.answer_marked("OR 1=1", "ALLOW", "ATTACK");
        let enforced = site(r#","mode":"enforce""#);
        confirm(&judge, &enforced, "alice");
        let query = format!("comment={}%27%20OR%201%3D1--", "A".repeat(600));
        let verdict = judge
            .judge(
                &enforced,
                &get("/api/comments", Some(query.as_str()), Some("alice"), 1_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        assert!(fake.sent().iter().any(|body| body.contains("OR 1=1")));
    }

    #[tokio::test]
    async fn one_denying_batch_refuses_the_request_and_the_record_shows_that_batch() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        fake.answer_marked("DENY_HERE", "DENY", "BENIGN");
        let enforced = site(r#","mode":"enforce""#);
        confirm(&judge, &enforced, "alice");
        let body = survey_ending_with("DENY_HERE");
        let verdict = judge
            .judge(&enforced, &survey_request(body.as_bytes(), 1_000))
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.refuse_status, 403);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        let jev = verdict.record.jev.as_ref().unwrap();
        let batches = jev.batches.unwrap();
        assert!(batches >= 2);
        assert_eq!(
            jev.batch,
            Some(batches),
            "the last batch holds the denied value"
        );
        assert!(
            jev.state
                .as_deref()
                .unwrap_or_default()
                .contains("DENY_HERE")
        );
        assert_eq!(jev.conclusion, Some(Conclusion::Deny));
    }

    #[tokio::test]
    async fn a_timed_out_batch_follows_the_site_policy_and_a_denial_in_another_batch_wins() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        fake.fail_marked("TIMEOUT_HERE", JevFailure::Timeout);
        let lenient = site(r#","mode":"enforce","on_jev_unavailable":"allow""#);
        let strict = site(r#","mode":"enforce""#);
        confirm(&judge, &lenient, "alice");
        let body = survey_ending_with("TIMEOUT_HERE");
        let survey = survey_request(body.as_bytes(), 1_000);
        let forwarded = judge.judge(&lenient, &survey).await;
        assert!(forwarded.forward);
        assert_eq!(forwarded.record.outcome, Outcome::Unjudged);
        let jev = forwarded.record.jev.as_ref().unwrap();
        assert_eq!(jev.failure.as_deref(), Some("JEV_TIMEOUT"));
        assert_eq!(
            jev.batch, jev.batches,
            "the timed out batch is the last one"
        );
        let refused = judge.judge(&strict, &survey).await;
        assert!(!refused.forward);
        assert_eq!(refused.refuse_status, 403);
        // A denial in the first batch wins over the timeout in the last one.
        fake.answer_marked("DENY_HERE", "DENY", "BENIGN");
        let both = oversized_survey()
            .replace("\"done\":\"1\"", "\"done\":\"TIMEOUT_HERE\"")
            .replace("number 0 typed", "DENY_HERE number 0 typed");
        let verdict = judge
            .judge(&lenient, &survey_request(both.as_bytes(), 2_000))
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        let shown = verdict.record.jev.as_ref().unwrap();
        assert!(
            shown
                .state
                .as_deref()
                .unwrap_or_default()
                .contains("DENY_HERE")
        );
    }

    #[tokio::test]
    async fn batches_are_asked_together_and_never_more_than_eight_at_once() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let enforced = site(r#","mode":"enforce""#);
        confirm(&judge, &enforced, "alice");
        // Words are inert and never reach the state, so each value has spaces: 2000 characters.
        // Twenty-five of them stay under the 64 KiB the body is parsed up to.
        let fields: Vec<String> = (0..25)
            .map(|n| format!("\"f{n}\":\"{}\"", "x ".repeat(1_000)))
            .collect();
        let body = format!("{{{}}}", fields.join(","));
        let verdict = judge
            .judge(&enforced, &survey_request(body.as_bytes(), 1_000))
            .await;
        assert!(verdict.forward);
        let batches = usize::from(verdict.record.jev.as_ref().unwrap().batches.unwrap());
        assert!(batches > JEV_PARALLEL_MAX, "{batches} batches");
        assert_eq!(fake.calls(), batches);
        assert_eq!(fake.peak(), JEV_PARALLEL_MAX);
    }

    #[tokio::test]
    async fn a_request_allowed_in_batches_is_served_from_the_cache_next_time() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let enforced = site(r#","mode":"enforce""#);
        confirm(&judge, &enforced, "alice");
        let body = oversized_survey();
        let survey = survey_request(body.as_bytes(), 1_000);
        assert!(judge.judge(&enforced, &survey).await.forward);
        let calls = fake.calls();
        assert!(calls >= 2);
        let again = judge.judge(&enforced, &survey).await;
        assert!(again.forward);
        assert_eq!(again.record.decision_path, DecisionPath::CachedAllow);
        assert_eq!(fake.calls(), calls);
    }

    #[tokio::test]
    async fn the_largest_body_of_distinct_short_numbers_is_judged_in_batches() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let enforced = site(r#","mode":"enforce""#);
        confirm(&judge, &enforced, "alice");
        let numbers: Vec<String> = (0..8_000).map(|n| n.to_string()).collect();
        let body = format!("[{}]", numbers.join(","));
        assert!(body.len() <= 48 * 1024, "{} bytes", body.len());
        let verdict = judge
            .judge(&enforced, &survey_request(body.as_bytes(), 1_000))
            .await;
        assert!(verdict.forward, "{:?}", verdict.record.decision_path);
        let batches = verdict
            .record
            .jev
            .as_ref()
            .and_then(|jev| jev.batches)
            .map_or(1, usize::from);
        assert_eq!(fake.calls(), batches);
        // The 200-value cap (REQUEST_VALUES_MAX) keeps this body to two batches. That is not the worst
        // case: without the cap the same body takes JEV_BATCHES_MAX calls, and the rest is left out.
        assert_eq!(batches, 2);
    }

    #[tokio::test]
    async fn a_single_call_record_has_no_batch_fields() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let enforced = site(r#","mode":"enforce""#);
        confirm(&judge, &enforced, "alice");
        let verdict = judge
            .judge(
                &enforced,
                &get("/api/search", Some("q=one1x"), Some("alice"), 1_000),
            )
            .await;
        assert_eq!(fake.calls(), 1);
        let json = serde_json::to_value(verdict.record.jev.as_ref().unwrap()).unwrap();
        assert!(json.get("batches").is_none() && json.get("batch").is_none());
        assert!(json.get("left_out").is_none());
    }

    /// A query whose `comment` is `length` characters of `A`, followed by `tail` (already encoded).
    fn long_comment_query(length: usize, tail: &str) -> String {
        format!("comment={}&tail={tail}", "A".repeat(length))
    }

    #[tokio::test]
    async fn a_long_value_past_the_batch_limit_leaves_out_the_rest_and_still_sends_the_short_value()
    {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        fake.answer_marked("OR 1=1", "ALLOW", "ATTACK");
        let enforced = site(r#","mode":"enforce""#);
        confirm(&judge, &enforced, "alice");
        let query = long_comment_query(300_000, "%27%20OR%201%3D1--");
        let verdict = judge
            .judge(
                &enforced,
                &get("/api/comments", Some(query.as_str()), Some("alice"), 1_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        // The denial comes from the first batch, where the short value is, so the calls not yet
        // started are never made (docs/02 section 2.5): the first wave ran, and nothing past the cap.
        assert!(
            (JEV_PARALLEL_MAX..=crate::state::JEV_BATCHES_MAX).contains(&fake.calls()),
            "{} calls",
            fake.calls()
        );
        assert!(fake.sent().iter().any(|body| body.contains("OR 1=1")));
    }

    #[tokio::test]
    async fn a_request_judged_in_part_of_its_batches_is_allowed_but_not_cached() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let enforced = site(r#","mode":"enforce""#);
        confirm(&judge, &enforced, "alice");
        let query = long_comment_query(300_000, "plain1x");
        let first = judge
            .judge(
                &enforced,
                &get("/api/comments", Some(query.as_str()), Some("alice"), 1_000),
            )
            .await;
        assert!(first.forward);
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
        let jev = first.record.jev.as_ref().unwrap();
        assert_eq!(
            jev.batches,
            u16::try_from(crate::state::JEV_BATCHES_MAX).ok()
        );
        assert!(jev.left_out.is_some_and(|left| left > 0));
        let calls = fake.calls();
        let second = judge
            .judge(
                &enforced,
                &get("/api/comments", Some(query.as_str()), Some("alice"), 1_500),
            )
            .await;
        assert!(second.forward);
        assert_eq!(second.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(
            fake.calls(),
            2 * calls,
            "the second request is judged again"
        );
    }

    #[tokio::test]
    async fn a_state_that_cannot_fit_is_refused_with_403_whatever_the_site_allows() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        // A path number of 200 000 digits: Jev must judge its pieces, and 16 batches cannot hold
        // them (docs/02 section 2.4). A survey of many answers is batched instead.
        let path = format!("/api/survey/{}", "7".repeat(200_000));
        let survey = get(&path, None, Some("alice"), 1_000);
        let lenient = site(r#","mode":"enforce","on_jev_unavailable":"allow""#);
        confirm(&judge, &lenient, "alice");
        let verdict = judge.judge(&lenient, &survey).await;
        assert!(!verdict.forward);
        assert_eq!(verdict.refuse_status, 403);
        assert_eq!(verdict.record.outcome, Outcome::Blocked);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevUnavailable);
        assert_eq!(
            verdict
                .record
                .jev
                .as_ref()
                .and_then(|jev| jev.failure.as_deref()),
            Some("JEV_STATE_TOO_LARGE")
        );
        assert_eq!(fake.calls(), 0);
        // Observe mode forwards the same request and notes that it would have been refused.
        let watched = judge
            .judge(&site(r#","on_jev_unavailable":"allow""#), &survey)
            .await;
        assert!(watched.forward);
        assert_eq!(watched.record.outcome, Outcome::WouldBlock);
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn every_piece_of_a_long_path_number_is_judged_as_a_reference() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let enforced = site(r#","mode":"enforce""#);
        confirm(&judge, &enforced, "alice");
        let path = format!("/api/patients/{}7", "a".repeat(600));
        let verdict = judge
            .judge(&enforced, &get(&path, None, Some("alice"), 1_000))
            .await;
        let state = verdict
            .record
            .jev
            .as_ref()
            .and_then(|jev| jev.state.clone())
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&state).unwrap();
        let pieces: Vec<&serde_json::Value> = json["request"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item.get("part").is_some())
            .collect();
        assert!(pieces.len() >= 2, "{} pieces", pieces.len());
        assert!(pieces.iter().all(|item| item["kind"] == "reference"));
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

    /// The credential a JSON login issues in its body (docs/01 section 1.7).
    const LOGIN_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.session-token";

    /// A sessionless `POST /login` the origin answered with `body`.
    fn json_login<'a>(body: &'a [u8], client: &'a str, now_ms: u64) -> Observation<'a> {
        Observation {
            route: None,
            request_id: RID,
            unread: None,
            would_block: false,
            credential: None,
            client,
            issued_credential: None,
            method: "POST",
            path: "/login",
            status: 200,
            content_type: Some("application/json"),
            body,
            now_ms,
            sent: &[],
            echo: &[],
        }
    }

    /// A site whose `bid` field is the basket, as the juice site declares it.
    fn basket_site() -> SiteSpec {
        site(r#","mode":"enforce","advanced":{"field_kinds":[{"field":"bid","kind":"basket"}]}"#)
    }

    /// The login body of a user whose basket is `bid`.
    fn login_body(token: &str, bid: u32) -> String {
        format!(r#"{{"authentication":{{"token":"{token}","bid":{bid}}}}}"#)
    }

    /// The login body of a user whose basket is `bid` and whose e-mail address, the identity the
    /// login states, is `umail`.
    fn login_with_user(token: &str, bid: u32, umail: &str) -> String {
        format!(r#"{{"authentication":{{"token":"{token}","bid":{bid},"umail":"{umail}"}}}}"#)
    }

    #[tokio::test]
    async fn a_login_response_declares_its_identity_once_its_credential_starts_the_session() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let spec = site(
            r#","mode":"enforce","objects":{
                "classes":[{"id":"account","name":"账号"}],
                "slots":[{"key":"POST /login authentication.umail","class":"account","source":"admin","identity":"user"}]}"#,
        );
        let body = login_with_user(LOGIN_TOKEN, 6, "alice@example.test");
        judge.observe(&spec, &json_login(body.as_bytes(), "10.0.0.1", 0));
        let entry = judge
            .judge(&spec, &get("/api/home", None, Some(LOGIN_TOKEN), 1))
            .await;
        assert!(
            identity_of(&entry.record).is_some_and(|identity| identity.user.is_some()),
            "the user the login stated is the session's user"
        );
        // A credential the login did not issue declares no identity.
        let forged = judge
            .judge(
                &spec,
                &get("/api/home", None, Some("forged-session-token"), 2),
            )
            .await;
        assert_eq!(identity_of(&forged.record), None);
    }

    #[tokio::test]
    async fn a_json_login_gives_the_session_its_credential_starts_the_values_it_returned() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = basket_site();
        let body = login_body(LOGIN_TOKEN, 6);
        let login = judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        assert_eq!(
            login.pending_values,
            Some(2),
            "the token and the basket id are held"
        );
        // The first request after the login is the entry, and its credential starts the session.
        let entry = judge
            .judge(&site, &get("/api/home", None, Some(LOGIN_TOKEN), 1))
            .await;
        assert!(entry.forward);
        let traced = entry.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
        assert_eq!(traced.login_unbound, None);
        // The user's own basket is known to the session, so it is read without Jev.
        let own = judge
            .judge(&site, &get("/rest/basket/6", None, Some(LOGIN_TOKEN), 2))
            .await;
        assert!(own.forward);
        assert_eq!(own.record.decision_path, DecisionPath::FastAllow);
        // Another basket was never shown to the session: it goes to Jev.
        let other = judge
            .judge(&site, &get("/rest/basket/7", None, Some(LOGIN_TOKEN), 3))
            .await;
        assert!(!other.forward);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn two_logins_from_one_address_keep_their_values_apart() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = basket_site();
        let alice = "alice-session-token-01";
        let bob = "bobs-session-token-002";
        judge.observe(
            &site,
            &json_login(login_body(alice, 6).as_bytes(), "10.0.0.1", 0),
        );
        judge.observe(
            &site,
            &json_login(login_body(bob, 7).as_bytes(), "10.0.0.1", 1),
        );
        judge
            .judge(&site, &get("/api/home", None, Some(alice), 2))
            .await;
        judge
            .judge(&site, &get("/api/home", None, Some(bob), 3))
            .await;
        let alice_own = judge
            .judge(&site, &get("/rest/basket/6", None, Some(alice), 4))
            .await;
        assert_eq!(alice_own.record.decision_path, DecisionPath::FastAllow);
        let alice_other = judge
            .judge(&site, &get("/rest/basket/7", None, Some(alice), 5))
            .await;
        assert!(!alice_other.forward, "bob's basket is not alice's");
        let bob_own = judge
            .judge(&site, &get("/rest/basket/7", None, Some(bob), 6))
            .await;
        assert_eq!(bob_own.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_credential_no_login_issued_takes_no_values_and_says_why() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = basket_site();
        let body = login_body(LOGIN_TOKEN, 6);
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        let forged = judge
            .judge(
                &site,
                &get("/api/home", None, Some("forged-session-token"), 1),
            )
            .await;
        let traced = forged.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_unbound, Some(LoginUnbound::Unmatched));
        assert_eq!(traced.login_request_id, None);
        // The held login is still there for the credential it issued.
        let own = judge
            .judge(&site, &get("/api/home", None, Some(LOGIN_TOKEN), 2))
            .await;
        assert_eq!(
            own.record
                .trace
                .session
                .and_then(|s| s.login_request_id)
                .as_deref(),
            Some(RID)
        );
    }

    #[tokio::test]
    async fn a_custom_header_credential_is_matched_as_it_is_sent() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = SiteSpec::from_json(
            r#"{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{"header":"X-Session"},
               "entries":["/login","/api/home"],"mode":"enforce"}"#,
        )
        .expect("the test site is valid");
        // The value has a space in it and its first word looks like a scheme. It is not an
        // Authorization header, so the word is part of the credential, not a scheme to cut.
        let token = format!("user-1 {LOGIN_TOKEN}");
        let body = login_body(&token, 6);
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        let verdict = judge
            .judge(&site, &get("/api/home", None, Some(token.as_str()), 1))
            .await;
        let traced = verdict.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
        assert_eq!(traced.login_unbound, None);
    }

    #[tokio::test]
    async fn a_credential_first_seen_on_a_request_that_is_not_an_entry_takes_the_login() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = basket_site();
        let body = login_body(LOGIN_TOKEN, 6);
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        // A login binds on the first request of its credential, whatever its path (docs/01 section 1.7).
        let first = judge
            .judge(&site, &get("/rest/basket/6", None, Some(LOGIN_TOKEN), 1))
            .await;
        let traced = first.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
        assert_eq!(traced.login_unbound, None, "the login was bound");
        // The origin answers that request, and the session the login started keeps the login.
        judge.observe(
            &site,
            &Observation {
                path: "/rest/basket/6",
                body: b"{}",
                ..list_response(LOGIN_TOKEN, 1)
            },
        );
        let entry = judge
            .judge(&site, &get("/api/home", None, Some(LOGIN_TOKEN), 2))
            .await;
        let later = entry.record.trace.session.expect("the session is traced");
        assert_eq!(later.login_request_id.as_deref(), Some(RID));
    }

    #[test]
    fn a_scheme_is_a_token_so_digits_and_symbols_may_be_in_it() {
        assert_eq!(without_scheme("Bearer abc-123"), "abc-123");
        assert_eq!(without_scheme("Token2 abc-123"), "abc-123");
        assert_eq!(without_scheme("Key-v2.0   abc"), "abc");
        assert_eq!(without_scheme("abc-123"), "abc-123", "no scheme, no change");
        assert_eq!(
            without_scheme("a=b c"),
            "a=b c",
            "= is not a token character"
        );
        assert_eq!(
            without_scheme(" abc"),
            " abc",
            "an empty scheme is not a scheme"
        );
    }

    #[tokio::test]
    async fn two_held_logins_issuing_one_credential_take_nothing() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = basket_site();
        let body = login_body(LOGIN_TOKEN, 6);
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.2", 1));
        let verdict = judge
            .judge(&site, &get("/api/home", None, Some(LOGIN_TOKEN), 2))
            .await;
        let traced = verdict.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_unbound, Some(LoginUnbound::Ambiguous));
        assert_eq!(traced.login_request_id, None);
    }

    #[tokio::test]
    async fn a_login_held_past_its_window_is_expired_for_its_credential() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = basket_site();
        let body = login_body(LOGIN_TOKEN, 6);
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        let late = crate::context::HELD_LOGIN_MS + 1;
        let verdict = judge
            .judge(&site, &get("/api/home", None, Some(LOGIN_TOKEN), late))
            .await;
        let traced = verdict.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_unbound, Some(LoginUnbound::Expired));
        assert_eq!(traced.login_request_id, None);
    }

    #[tokio::test]
    async fn a_session_that_already_exists_takes_no_login_seen_later() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = basket_site();
        // The origin answers before any login is seen, so the session exists and the login is not taken into it.
        confirm(&judge, &site, LOGIN_TOKEN);
        judge
            .judge(&site, &get("/api/home", None, Some(LOGIN_TOKEN), 0))
            .await;
        let body = login_body(LOGIN_TOKEN, 6);
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 1));
        let basket = judge
            .judge(&site, &get("/rest/basket/6", None, Some(LOGIN_TOKEN), 2))
            .await;
        assert!(
            !basket.forward,
            "the login was not taken into the existing session"
        );
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_login_that_echoes_what_it_was_sent_holds_only_what_it_issued() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = basket_site();
        let body = format!(
            r#"{{"authentication":{{"token":"{LOGIN_TOKEN}","bid":6,"umail":"alice@example.test"}}}}"#
        );
        let sent = [judge.key.mac("value", b"alice@example.test")];
        let login = judge.observe(
            &site,
            &Observation {
                sent: &sent,
                ..json_login(body.as_bytes(), "10.0.0.1", 0)
            },
        );
        assert_eq!(
            login.pending_values,
            Some(2),
            "the echoed address is not held"
        );
    }

    #[tokio::test]
    async fn a_bearer_header_credential_is_matched_without_its_scheme() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = SiteSpec::from_json(
            r#"{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{"header":"Authorization"},
               "entries":["/login","/api/home"],"mode":"enforce"}"#,
        )
        .expect("the test site is valid");
        let body = login_body(LOGIN_TOKEN, 6);
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        let bearer = format!("Bearer {LOGIN_TOKEN}");
        let verdict = judge
            .judge(&site, &get("/api/home", None, Some(bearer.as_str()), 1))
            .await;
        let traced = verdict.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
    }

    /// A credential of the length a JWT has (over 128 characters, docs/01 section 1.7): a standard
    /// header and two base64url-looking segments generated from `seed`, about 740 characters in
    /// all. It is built here, so that no real token is kept in the repository.
    fn long_login_token(seed: usize) -> String {
        const BASE64URL: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let segment = |offset: usize| -> String {
            (0..350)
                .map(|index| char::from(BASE64URL[(index * 7 + offset) % BASE64URL.len()]))
                .collect()
        };
        format!(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.{}.{}",
            segment(seed),
            segment(seed + 13)
        )
    }

    #[tokio::test]
    async fn a_json_login_with_a_long_token_binds_its_session() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = basket_site();
        let token = long_login_token(1);
        let login = judge.observe(
            &site,
            &json_login(login_body(&token, 6).as_bytes(), "10.0.0.1", 0),
        );
        assert_eq!(
            login.pending_values,
            Some(2),
            "the long token and the basket id are held"
        );
        let entry = judge
            .judge(&site, &get("/api/home", None, Some(token.as_str()), 1))
            .await;
        assert!(entry.forward);
        let traced = entry.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
        assert_eq!(traced.login_unbound, None);
        // The user's own basket is known to the session, so it is read without Jev.
        let own = judge
            .judge(&site, &get("/rest/basket/6", None, Some(token.as_str()), 2))
            .await;
        assert!(own.forward);
        assert_eq!(own.record.decision_path, DecisionPath::FastAllow);
        // Another basket was never shown to the session: it goes to Jev.
        let other = judge
            .judge(&site, &get("/rest/basket/7", None, Some(token.as_str()), 3))
            .await;
        assert!(!other.forward);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_long_token_is_never_a_seen_value() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = basket_site();
        let token = long_login_token(1);
        judge.observe(
            &site,
            &json_login(login_body(&token, 6).as_bytes(), "10.0.0.1", 0),
        );
        let entry = judge
            .judge(&site, &get("/api/home", None, Some(token.as_str()), 1))
            .await;
        let traced = entry.record.trace.session.expect("the session is traced");
        assert_eq!(
            traced.known_values, 1,
            "only the basket id is a value the session has seen"
        );
    }

    #[tokio::test]
    async fn a_long_token_beside_the_credential_is_held_but_not_learned() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = basket_site();
        let access = long_login_token(1);
        let refresh = long_login_token(2);
        let body =
            format!(r#"{{"authentication":{{"token":"{access}","refresh":"{refresh}","bid":6}}}}"#);
        let login = judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        assert_eq!(
            login.pending_values,
            Some(3),
            "the access token, the refresh token and the basket id are held"
        );
        let entry = judge
            .judge(&site, &get("/api/home", None, Some(access.as_str()), 1))
            .await;
        let traced = entry.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
        assert_eq!(traced.login_unbound, None);
        assert_eq!(
            traced.known_values, 1,
            "the refresh token is not learned as a value"
        );
    }

    #[tokio::test]
    async fn a_login_whose_only_candidate_is_long_is_still_held() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        // Plain site: no basket declared, and the single-digit id is no candidate at all.
        let site = site(r#","mode":"enforce""#);
        let token = long_login_token(1);
        let login = judge.observe(
            &site,
            &json_login(login_body(&token, 6).as_bytes(), "10.0.0.1", 0),
        );
        assert_eq!(
            login.pending_values,
            Some(2),
            "held although the long token is the only candidate"
        );
        let entry = judge
            .judge(&site, &get("/api/home", None, Some(token.as_str()), 1))
            .await;
        let traced = entry.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
    }

    #[tokio::test]
    async fn a_long_token_the_request_sent_is_not_held() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = basket_site();
        let token = long_login_token(1);
        let body = login_body(&token, 6);
        // The login request goes through judgement, as it does on the real path. Its verdict
        // hands back the digests of the values it sent, and the origin's echo is checked
        // against them.
        let request = RequestFacts {
            route: None,
            request_headers: &[],
            method_overrides: &[],
            request_id: RID,
            method: "POST",
            path: "/login",
            query: None,
            content_type: Some("application/json"),
            body: body.as_bytes(),
            credential: None,
            client: "10.0.0.1",
            now_ms: 0,
        };
        let verdict = judge.judge(&site, &request).await;
        assert!(
            verdict.forward,
            "the login is forwarded, so its values are sent"
        );
        assert!(
            verdict
                .sent
                .contains(&judge.key.mac("value", token.as_bytes())),
            "the token the login sent is among the digests the verdict hands back"
        );
        let login = judge.observe(
            &site,
            &Observation {
                sent: verdict.sent.as_slice(),
                echo: verdict.echo.as_slice(),
                ..json_login(body.as_bytes(), "10.0.0.1", 0)
            },
        );
        assert_eq!(
            login.pending_values, None,
            "the echoed token is no candidate, so nothing is held"
        );
        let entry = judge
            .judge(&site, &get("/api/home", None, Some(token.as_str()), 1))
            .await;
        let traced = entry.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_unbound, Some(LoginUnbound::Unmatched));
        assert_eq!(traced.login_request_id, None);
    }

    #[tokio::test]
    async fn a_bearer_scheme_is_removed_before_a_long_token_is_matched() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = SiteSpec::from_json(
            r#"{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{"header":"Authorization"},
               "entries":["/login","/api/home"],"mode":"enforce"}"#,
        )
        .expect("the test site is valid");
        let token = long_login_token(1);
        judge.observe(
            &site,
            &json_login(login_body(&token, 6).as_bytes(), "10.0.0.1", 0),
        );
        let bearer = format!("Bearer {token}");
        let verdict = judge
            .judge(&site, &get("/api/home", None, Some(bearer.as_str()), 1))
            .await;
        let traced = verdict.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
    }

    #[tokio::test]
    async fn two_held_logins_issuing_one_long_credential_take_nothing() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = basket_site();
        let token = long_login_token(1);
        let body = login_body(&token, 6);
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.2", 1));
        let verdict = judge
            .judge(&site, &get("/api/home", None, Some(token.as_str()), 2))
            .await;
        let traced = verdict.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_unbound, Some(LoginUnbound::Ambiguous));
        assert_eq!(traced.login_request_id, None);
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
        confirm(&judge, &site, "alice");
        let upload = RequestFacts {
            route: None,
            request_headers: &[],
            method_overrides: &[],
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
        confirm(&judge, &site(""), "alice");
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
        confirm(&judge, &plain, "alice");
        confirm(&judge, &tuned, "bob");
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
        confirm(&judge, &site, "alice");
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
        assert_eq!(over.refuse_status, 429);
        assert_eq!(over.record.trace.refused.as_deref(), Some("rate_limited"));
        assert_eq!(
            over.record.jev.unwrap().failure.as_deref(),
            Some("JEV_CALL_LIMIT")
        );
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_credential_the_origin_has_not_answered_starts_no_session() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        confirm(&judge, &site, "alice");
        assert_eq!(judge.lock().store.len(), 1);
        // Made-up credentials: on a page without values, on an entry, and with a value for Jev.
        for index in 0..50 {
            let credential = format!("made-up-{index}");
            for (path, query) in [
                ("/api/home", None),
                ("/login", None),
                ("/api/search", Some("q=word1x")),
            ] {
                judge
                    .judge(&site, &get(path, query, Some(&credential), 1_000))
                    .await;
            }
        }
        assert_eq!(
            judge.session_count(),
            2,
            "only the answered session and the address's context are kept"
        );
        // The origin answers one of them: that one has a session from then on.
        confirm(&judge, &site, "made-up-7");
        assert_eq!(judge.session_count(), 3);
    }

    #[tokio::test]
    async fn a_forged_credential_the_origin_refuses_starts_no_session() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce","advanced":{"address_calls_per_minute":1}"#);
        // The request carries a made-up credential and a value the origin has not shown. Jev
        // allows it, it is forwarded, and the origin refuses it with 401.
        let forged = judge
            .judge(
                &site,
                &get(
                    "/api/patients",
                    Some("q=hello%20world"),
                    Some("forged-credential-1"),
                    1_000,
                ),
            )
            .await;
        assert!(forged.forward);
        // Judging the request created the address's context, and nothing for the credential.
        let before = judge.session_count();
        judge.observe(
            &site,
            &Observation {
                client: "10.0.0.9",
                path: "/api/patients",
                status: 401,
                content_type: None,
                body: b"",
                now_ms: 1_001,
                sent: &forged.sent,
                echo: &forged.echo,
                ..list_response("forged-credential-1", 0)
            },
        );
        assert_eq!(
            judge.session_count(),
            before,
            "a refused credential gets no session"
        );
        // The next request, with a value the address has not sent, still draws on its address's one call,
        // which is spent: an identical request would be answered from the allow cache instead.
        let again = judge
            .judge(
                &site,
                &get(
                    "/api/patients",
                    Some("q=other%20word"),
                    Some("forged-credential-1"),
                    2_000,
                ),
            )
            .await;
        assert!(!again.forward);
        assert_eq!(again.refuse_status, 429);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_forged_credential_whose_long_request_the_origin_refuses_starts_no_session() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        // More distinct tokens than a session may hold, so the request's values cannot all be
        // recorded and the session it would start stops learning.
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
            ..get("/api/patients", None, Some("forged-credential-2"), 1_000)
        };
        let forged = judge.judge(&site, &upload).await;
        assert!(forged.forward);
        // Judging it starts no session for its credential: the address's context is the only one.
        assert_eq!(
            judge.session_count(),
            1,
            "judging a forwarded request starts no session for its credential"
        );
        judge.observe(
            &site,
            &Observation {
                method: "POST",
                client: "10.0.0.9",
                path: "/api/patients",
                status: 401,
                content_type: None,
                body: b"",
                now_ms: 1_001,
                sent: &forged.sent,
                echo: &forged.echo,
                ..list_response("forged-credential-2", 0)
            },
        );
        assert_eq!(judge.session_count(), 1);
    }

    #[tokio::test]
    async fn a_credential_without_a_session_spends_the_budget_of_its_address() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce","advanced":{"address_calls_per_minute":2}"#);
        // Each request names a new credential and a new value: without a session they share the address's
        // calls, and an identical request would be answered from the address's allow cache instead.
        for index in 0..2 {
            let credential = format!("made-up-{index}");
            let query = format!("q=word{index}x");
            let verdict = judge
                .judge(
                    &site,
                    &get(
                        "/api/patients",
                        Some(query.as_str()),
                        Some(&credential),
                        1_000,
                    ),
                )
                .await;
            assert!(verdict.forward);
        }
        let over = judge
            .judge(
                &site,
                &get("/api/patients", Some("q=word2x"), Some("made-up-2"), 2_000),
            )
            .await;
        assert!(!over.forward);
        assert_eq!(over.refuse_status, 429);
        assert_eq!(over.record.trace.refused.as_deref(), Some("rate_limited"));
        assert_eq!(
            over.record.jev.unwrap().failure.as_deref(),
            Some("JEV_CALL_LIMIT")
        );
        assert_eq!(fake.calls(), 2);
        // A session the origin answered keeps its own budget.
        confirm(&judge, &site, "alice");
        let own = judge
            .judge(
                &site,
                &get("/api/search", Some("q=word1x"), Some("alice"), 3_000),
            )
            .await;
        assert!(own.forward);
    }

    #[tokio::test]
    async fn a_credential_without_a_session_hits_the_default_address_limit() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        // No credential here has a session, so all thirty calls draw on the address's default budget.
        for index in 0..30 {
            let credential = format!("made-up-{index}");
            let query = format!("q=word{index}x");
            let verdict = judge
                .judge(
                    &site,
                    &get(
                        "/api/patients",
                        Some(query.as_str()),
                        Some(&credential),
                        1_000 + index,
                    ),
                )
                .await;
            assert!(
                verdict.forward,
                "request {index} should be judged and allowed"
            );
        }
        assert_eq!(fake.calls(), 30);
        let over = judge
            .judge(
                &site,
                &get(
                    "/api/patients",
                    Some("q=word30x"),
                    Some("made-up-30"),
                    2_000,
                ),
            )
            .await;
        assert!(!over.forward);
        assert_eq!(over.refuse_status, 429);
        assert_eq!(over.record.outcome, Outcome::Blocked);
        assert_eq!(over.record.decision_path, DecisionPath::JevUnavailable);
        assert_eq!(over.record.trace.refused.as_deref(), Some("rate_limited"));
        assert_eq!(
            over.record.jev.unwrap().failure.as_deref(),
            Some("JEV_CALL_LIMIT")
        );
        assert_eq!(fake.calls(), 30);
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
        assert_eq!(second.refuse_status, 429);
        assert_eq!(second.record.trace.refused.as_deref(), Some("rate_limited"));
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
        confirm(&judge, &site, "alice");
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
            method_overrides: &[],
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
        confirm(&judge, &plain, "alice");
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
                    method_overrides: &[],
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
        confirm(&judge, &site, "alice");
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
    async fn a_truncated_request_is_never_allowed_from_the_cache() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        confirm(&judge, &site, "alice");
        // The gateway cannot read this body, so the same visible values can hide any
        // remainder: the allow of one such request says nothing about the next.
        for now_ms in [1_000, 2_000] {
            let request = RequestFacts {
                method: "POST",
                content_type: Some("application/json"),
                body: b"{broken",
                ..get("/api/patients/D4411", None, Some("alice"), now_ms)
            };
            let verdict = judge.judge(&site, &request).await;
            assert!(verdict.record.trace.values_truncated);
            assert_eq!(verdict.record.decision_path, DecisionPath::JevAllow);
        }
        assert_eq!(fake.calls(), 2);
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
            method_overrides: &[],
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

    #[tokio::test]
    async fn a_bearer_token_repeated_without_its_scheme_reaches_neither_jev_nor_the_log() {
        use crate::state::REDACTED;
        const TOKEN: &str = "tok-5ecret-0123456789";
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = SiteSpec::from_json(
            r#"{"name":"h","hosts":["h.test"],"origin":"http://o:1","session":{"header":"Authorization"},"entries":["/login"],"mode":"enforce"}"#,
        )
        .unwrap();
        let credential = format!("Bearer {TOKEN}");
        confirm(&judge, &site, &credential);
        let path = format!("/api/echo/{TOKEN}/detail");
        let query = format!("t={TOKEN}&page=2");
        let body = format!(r#"{{"jwt":"{TOKEN}","note":"x"}}"#);
        let request = RequestFacts {
            method: "POST",
            content_type: Some("application/json"),
            body: body.as_bytes(),
            ..get(&path, Some(&query), Some(&credential), 1_000)
        };
        let first = judge.judge(&site, &request).await;
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
        // The origin answers, so the request joins the session's recent requests and origins.
        judge.observe(
            &site,
            &Observation {
                path: &path,
                method: "POST",
                body: br#"{"id":"41"}"#,
                ..list_response(&credential, 1_500)
            },
        );
        let second = judge
            .judge(&site, &get("/api/items/41", None, Some(&credential), 2_000))
            .await;
        let third = judge
            .judge(&site, &get("/api/items/77", None, Some(&credential), 3_000))
            .await;
        assert!(fake.calls() >= 2, "later requests are asked about too");
        assert!(
            fake.sent
                .lock()
                .unwrap()
                .iter()
                .skip(1)
                .any(|sent| sent.contains("/api/echo/<redacted>/detail")),
            "a later state quotes the earlier request, without the token"
        );

        for sent in fake.sent.lock().unwrap().iter() {
            assert!(!sent.contains(TOKEN), "Jev was sent the token: {sent}");
        }
        for judgement in [&first, &second, &third] {
            let row = serde_json::to_string(&judgement.record).unwrap();
            assert!(!row.contains(TOKEN), "the log row carries the token: {row}");
        }
        assert_eq!(first.record.path, format!("/api/echo/{REDACTED}/detail"));
        assert_eq!(
            first.record.query.as_deref(),
            Some(format!("{REDACTED}&page=2").as_str())
        );
        // A row refused before judging redacts the same way.
        let refused = refused_row(Some(&site), &request, DecisionPath::BodyNotInspectable, 413);
        assert!(!serde_json::to_string(&refused).unwrap().contains(TOKEN));
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
        confirm(&judge, &site, "alice");
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
    async fn a_slug_id_at_a_declared_id_is_judged_as_that_closed_position() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        confirm(&judge, &site, "alice");
        judge.observe(
            &site,
            &shown_by(
                "/api/search",
                br#"{"results":[{"id":"PT-7004","name":"C"}]}"#,
            ),
        );
        fake.answer("DENY", "BENIGN");
        let verdict = judge
            .judge(&site, &call("DELETE", "/api/patients/PT-7004", 1_000))
            .await;
        // The public search showed the slug, and the declared closed id governs it: an attempt,
        // not a fast allow of an open read.
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(fake.calls(), 1);
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "PT-7004")
            .expect("the slug is recorded");
        assert_eq!(
            value.slot.as_deref(),
            Some("DELETE /api/patients/{id} path[2]")
        );
        assert_eq!(
            value.attempt,
            Some(xshield_core::context::Attempt::OverPrivilege)
        );
        assert!(!value.unplaced);
    }

    #[tokio::test]
    async fn a_parameter_on_a_declared_id_is_judged_as_that_closed_position() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        confirm(&judge, &site, "alice");
        judge.observe(
            &site,
            &shown_by(
                "/api/search",
                br#"{"results":[{"id":"7005;jsessionid=a","name":"B"}]}"#,
            ),
        );
        fake.answer("DENY", "BENIGN");
        let verdict = judge
            .judge(
                &site,
                &call("DELETE", "/api/patients/7005;jsessionid=a", 1_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7005;jsessionid=a")
            .expect("the id is recorded");
        assert_eq!(
            value.slot.as_deref(),
            Some("DELETE /api/patients/{id} path[2]")
        );
        assert_eq!(
            value.attempt,
            Some(xshield_core::context::Attempt::OverPrivilege)
        );
    }

    #[tokio::test]
    async fn an_escaped_slash_in_a_declared_id_is_judged_as_that_closed_position() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        confirm(&judge, &site, "alice");
        judge.observe(
            &site,
            &shown_by(
                "/api/search",
                br#"{"results":[{"id":"PT/7004","name":"C"}]}"#,
            ),
        );
        fake.answer("DENY", "BENIGN");
        let verdict = judge
            .judge(&site, &call("DELETE", "/api/patients/PT%2F7004", 1_000))
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "PT/7004")
            .expect("the id is recorded");
        assert_eq!(
            value.slot.as_deref(),
            Some("DELETE /api/patients/{id} path[2]")
        );
        assert_eq!(
            value.attempt,
            Some(xshield_core::context::Attempt::OverPrivilege)
        );
    }

    #[tokio::test]
    async fn a_path_that_cannot_be_templated_goes_to_jev_and_its_id_is_labelled_unplaced() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        confirm(&judge, &site, "alice");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        // Longer than the canonical bound, so the path has no template the map can name. Its
        // other segments are route words, so the id it ends with is the only value, and the
        // public search showed it to this session.
        let filler = "/abcdefghijklmnopqrstuvwxyz".repeat(10);
        let path = format!("/api/patients{filler}/7005");
        let verdict = judge
            .judge(&site, &get(&path, None, Some("alice"), 1_000))
            .await;
        assert_ne!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1, "an unplaced request goes to Jev");
        let value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7005")
            .expect("the id is recorded");
        assert!(value.unplaced);
        assert!(!value.verified);
        assert_eq!(value.attempt, None);
    }

    #[tokio::test]
    async fn an_attempt_is_not_served_from_the_allow_cache() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = tiers_site("high");
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        // The own listing proves the value, as an untiered listing would, so the delete is a fast
        // allow and Jev is not called a second time.
        assert!(value.verified, "the own listing proves the value");
        assert!(verdict.forward, "a verified delete is forwarded");
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1, "the second delete does not reach Jev");
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
        confirm_identity(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
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
        confirm(&judge, &site, "alice");
        // `/api/doctors` is not in the map, so its id is judged by its name.
        judge.observe(&site, &shown_by("/api/doctors", br#"[{"id":3}]"#));
        let verdict = judge
            .judge(&site, &get("/doctor/3", None, Some("alice"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
    }

    /// A request of `credential` that Jev has to decide: its query value is new to every session.
    async fn ask(
        judge: &Judge<FakeJev>,
        site: &SiteSpec,
        credential: &str,
        tag: &str,
        now_ms: u64,
    ) -> Judgement {
        let query = format!("q={tag}x");
        judge
            .judge(
                site,
                &get("/api/search", Some(&query), Some(credential), now_ms),
            )
            .await
    }

    /// Asserts that the call was refused for the spent call limit and made no Jev call.
    fn assert_call_limited(verdict: &Judgement) {
        assert!(!verdict.forward);
        assert_eq!(verdict.refuse_status, 429);
        assert_eq!(
            verdict.record.trace.refused.as_deref(),
            Some("rate_limited")
        );
        assert_eq!(
            verdict.record.jev.as_ref().unwrap().failure.as_deref(),
            Some("JEV_CALL_LIMIT")
        );
    }

    #[test]
    fn a_client_address_is_grouped_by_its_source() {
        let group = |client: &str| address_group(client).into_owned();
        // An IPv4 address is a group of its own.
        assert_eq!(group("203.0.113.7"), "203.0.113.7");
        assert_ne!(group("203.0.113.7"), group("203.0.113.8"));
        // An IPv6 address is grouped by its first 64 bits, however it is written.
        assert_eq!(
            group("2001:db8:1:2:aaaa::1"),
            group("2001:db8:1:2:bbbb:cccc:dddd:eeee")
        );
        assert_eq!(group("2001:0db8:0001:0002::1"), group("2001:db8:1:2::1"));
        assert_ne!(group("2001:db8:1:2::1"), group("2001:db8:1:3::1"));
        assert_ne!(group("2001:db8:1:2::1"), group("2001:db9:1:2::1"));
        // An IPv4-mapped IPv6 address is the IPv4 address it carries.
        assert_eq!(group("::ffff:203.0.113.7"), group("203.0.113.7"));
        assert_eq!(group("::FFFF:203.0.113.7"), group("203.0.113.7"));
        // What is not an address is a group of its own as it stands, and nothing panics.
        for text in [
            "",
            "unknown",
            "2001:db8::zz",
            "203.0.113",
            "999.1.1.1",
            "203.0.113.7:8080",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "\0",
            &"9".repeat(10_000),
        ] {
            assert_eq!(group(text), text);
        }
    }

    #[tokio::test]
    async fn addresses_in_one_64_share_the_budget_of_requests_without_a_session() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce","advanced":{"address_calls_per_minute":1}"#);
        let from = |client: &'static str, query: &'static str| RequestFacts {
            client,
            ..get("/login", Some(query), None, 1_000)
        };
        assert!(
            judge
                .judge(&site, &from("2001:db8:1:2::1", "user=zed1x"))
                .await
                .forward
        );
        // Another address of the same /64 spends the same budget.
        assert_call_limited(
            &judge
                .judge(&site, &from("2001:db8:1:2:f::2", "user=zed2x"))
                .await,
        );
        // Another /64, and an IPv4 address, have their own.
        assert!(
            judge
                .judge(&site, &from("2001:db8:1:3::1", "user=zed3x"))
                .await
                .forward
        );
        assert!(
            judge
                .judge(&site, &from("10.0.0.5", "user=zed4x"))
                .await
                .forward
        );
        assert_eq!(fake.calls(), 3);
    }

    #[tokio::test]
    async fn the_sessions_of_one_address_share_ten_times_the_session_limit() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        // Each session may call twice a minute, so the sessions of one address may call twenty
        // times together.
        let site = site(r#","mode":"enforce","advanced":{"session_calls_per_minute":2}"#);
        // The sessions were created from 10.0.0.1 and their requests come from 10.0.0.9: the
        // total follows the address that created them.
        for index in 0..11 {
            confirm_from(&judge, &site, &format!("forged-{index}"), "10.0.0.1");
        }
        confirm_from(&judge, &site, "neighbour", "10.0.0.2");
        for index in 0..10 {
            for call in 0..2 {
                let credential = format!("forged-{index}");
                let tag = format!("s{index}c{call}");
                assert!(ask(&judge, &site, &credential, &tag, 1_000).await.forward);
            }
        }
        assert_eq!(fake.calls(), 20);
        // The eleventh session has not used its own two calls, and is refused all the same.
        assert_call_limited(&ask(&judge, &site, "forged-10", "s10c0", 2_000).await);
        assert_eq!(fake.calls(), 20, "no Jev call was made for it");
        // A session of another address is not affected.
        assert!(ask(&judge, &site, "neighbour", "n0", 2_000).await.forward);
        assert_eq!(fake.calls(), 21);
        // The minute runs out and the address's budget starts again.
        assert!(
            ask(&judge, &site, "forged-10", "s10c1", 62_000)
                .await
                .forward
        );
        assert_eq!(fake.calls(), 22);
    }

    #[tokio::test]
    async fn a_session_over_its_own_limit_does_not_use_up_its_addresses_total() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce","advanced":{"session_calls_per_minute":2}"#);
        for index in 0..11 {
            confirm_from(&judge, &site, &format!("forged-{index}"), "10.0.0.1");
        }
        for call in 0..2 {
            assert!(
                ask(&judge, &site, "forged-0", &format!("a{call}"), 1_000)
                    .await
                    .forward
            );
        }
        // The first session goes on asking: each of these is refused by its own limit.
        for call in 2..7 {
            assert_call_limited(&ask(&judge, &site, "forged-0", &format!("a{call}"), 1_500).await);
        }
        // So the nine others can still make their two calls each, which is all that is left of
        // twenty, and the eleventh session finds the total spent.
        for index in 1..10 {
            for call in 0..2 {
                let credential = format!("forged-{index}");
                let tag = format!("s{index}c{call}");
                assert!(ask(&judge, &site, &credential, &tag, 2_000).await.forward);
            }
        }
        assert_eq!(fake.calls(), 20);
        assert_call_limited(&ask(&judge, &site, "forged-10", "s10c0", 3_000).await);
        assert_eq!(fake.calls(), 20);
    }

    #[tokio::test]
    async fn the_budget_of_an_address_without_a_session_and_the_total_of_its_sessions_are_apart() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(
            r#","mode":"enforce","advanced":{"session_calls_per_minute":2,"address_calls_per_minute":3}"#,
        );
        let login = |client: &'static str, index: usize, now_ms: u64| {
            let query = format!("user=zed{index}x");
            let judge = &judge;
            let site = &site;
            async move {
                judge
                    .judge(
                        site,
                        &RequestFacts {
                            client,
                            ..get("/login", Some(&query), None, now_ms)
                        },
                    )
                    .await
            }
        };
        // 10.0.0.1: the sessions spend the whole total of twenty, and requests without a session
        // still have their three calls.
        for index in 0..10 {
            confirm_from(&judge, &site, &format!("forged-{index}"), "10.0.0.1");
        }
        for index in 0..10 {
            for call in 0..2 {
                let credential = format!("forged-{index}");
                let tag = format!("s{index}c{call}");
                assert!(ask(&judge, &site, &credential, &tag, 1_000).await.forward);
            }
        }
        for index in 0..3 {
            assert!(login("10.0.0.1", index, 1_000).await.forward);
        }
        assert_call_limited(&login("10.0.0.1", 3, 1_000).await);
        // 10.0.0.3: requests without a session spend their three calls, and its sessions still
        // have the whole total.
        for index in 10..13 {
            assert!(login("10.0.0.3", index, 1_000).await.forward);
        }
        assert_call_limited(&login("10.0.0.3", 13, 1_000).await);
        confirm_from(&judge, &site, "late", "10.0.0.3");
        for call in 0..2 {
            assert!(
                ask(&judge, &site, "late", &format!("l{call}"), 1_000)
                    .await
                    .forward
            );
        }
        assert_call_limited(&ask(&judge, &site, "late", "l2", 1_000).await);
    }

    #[tokio::test]
    async fn forged_credentials_that_a_public_page_answers_start_sessions_of_their_address() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce","advanced":{"session_calls_per_minute":2}"#);
        // The origin answers `GET /login` with 200 whatever the credential: the sessions start,
        // as they have always done, without a Jev call.
        for index in 0..11 {
            let credential = format!("forged-{index}");
            let request = RequestFacts {
                client: "10.0.0.1",
                ..get("/login", None, Some(&credential), 1_000)
            };
            let verdict = judge.judge(&site, &request).await;
            assert!(verdict.forward);
            judge.observe(
                &site,
                &Observation {
                    path: "/login",
                    status: 200,
                    content_type: Some("text/html"),
                    body: b"<html></html>",
                    now_ms: 1_001,
                    ..list_response(&credential, 0)
                },
            );
        }
        assert_eq!(fake.calls(), 0);
        // The first request was judged in its address, which keeps a context of its own (docs/01 section 1.4).
        assert_eq!(judge.session_count(), 12);
        // They are all recorded as made from that one address, so the calls they make together
        // stop at twenty.
        for index in 0..10 {
            for call in 0..2 {
                let credential = format!("forged-{index}");
                let tag = format!("s{index}c{call}");
                assert!(ask(&judge, &site, &credential, &tag, 2_000).await.forward);
            }
        }
        assert_call_limited(&ask(&judge, &site, "forged-10", "s10c0", 2_000).await);
        assert_eq!(fake.calls(), 20);
    }

    /// The objects of a site: its classes and slots (the home page names the role, the patient path is
    /// an object), then `tail`, which is empty or a comma and the members that follow the slots.
    fn objects_with(tail: &str) -> String {
        format!(
            r#"{{"classes":[{{"id":"doctor","name":"医生"}},{{"id":"staff","name":"员工"}},{{"id":"patient","name":"患者"}}],
                "slots":[
                    {{"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"}},
                    {{"key":"GET /api/home role","class":"staff","source":"admin","identity":"role"}},
                    {{"key":"DELETE /api/patients/{{id}} path[2]","class":"patient","source":"admin","accepts_public":false,"reliability":"high"}}
                ]{tail}}}"#
        )
    }

    /// The administrator-only functions (docs/07 section 7.9.18): the export and the delete are high, the
    /// search is medium, so it tightens nothing.
    const ADMIN_FUNCTIONS: &str = r#"[
        {"key":"POST /api/admin/export","source":"rule","tier":"admin","reliability":"high"},
        {"key":"DELETE /api/patients/{id}","source":"rule","tier":"admin","reliability":"high"},
        {"key":"GET /api/admin/search","source":"rule","tier":"admin","reliability":"medium"}
    ]"#;

    /// The objects of a site with [`ADMIN_FUNCTIONS`]. `switch` adds `ask_unknown_functions`.
    fn functions_objects(switch: bool) -> String {
        let ask = if switch {
            r#","ask_unknown_functions":true"#
        } else {
            ""
        };
        objects_with(&format!(r#"{ask},"functions":{ADMIN_FUNCTIONS}"#))
    }

    /// A site in `head` (its mode and other settings, starting with a comma) with [`functions_objects`].
    fn functions_site_in(head: &str, switch: bool) -> SiteSpec {
        site(&format!(
            r#"{head},"objects":{}"#,
            functions_objects(switch)
        ))
    }

    fn functions_site(switch: bool) -> SiteSpec {
        functions_site_in(r#","mode":"enforce""#, switch)
    }

    /// A site that asks about unknown functions and lists two of them, with no tier.
    fn asking_site() -> SiteSpec {
        site(
            r#","mode":"enforce","objects":{"ask_unknown_functions":true,"functions":[{"key":"GET /api/patients","source":"rule"},{"key":"GET /api/home","source":"rule"}]}"#,
        )
    }

    /// The `function` of the state Jev was shown for the judgement at `index`, as JSON.
    fn function_shown(fake: &FakeJev, index: usize) -> serde_json::Value {
        let sent = fake.sent.lock().unwrap();
        let body: serde_json::Value = serde_json::from_str(&sent[index]).unwrap();
        body["state"]["request"]["function"].clone()
    }

    #[tokio::test]
    async fn a_non_administrator_on_an_admin_function_is_sent_to_jev_as_an_attempt() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor":{"id":"DR-A"}}"#, "doctor-a"),
        );
        let verdict = judge
            .judge(
                &site,
                &call_as("POST", "/api/admin/export", "doctor-a", 1_000),
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.refuse_status, 403);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(fake.calls(), 1);
        assert_eq!(
            function_shown(&fake, 0),
            json!({"tier": "admin", "attempt": "over_privilege"})
        );
        let trace = verdict
            .record
            .trace
            .function
            .clone()
            .expect("the trace names the function");
        assert_eq!(trace.key, "POST /api/admin/export");
        assert_eq!(trace.entry.as_deref(), Some("POST /api/admin/export"));
        assert_eq!(trace.tier.as_deref(), Some("admin"));
        assert_eq!(trace.attempt, Some(Attempt::OverPrivilege));
        assert_eq!(trace.known, None);
    }

    #[tokio::test]
    async fn an_attempt_on_an_admin_function_is_never_fast_allowed_with_verified_values() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        confirm_identity(&judge, &site, "doctor-a");
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7005"}]}"#, "doctor-a"),
        );
        let verdict = judge
            .judge(
                &site,
                &call_as("DELETE", "/api/patients/7005", "doctor-a", 1_000),
            )
            .await;
        assert_ne!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 1);
        let shown_value = verdict
            .record
            .trace
            .values
            .iter()
            .find(|value| value.value == "7005")
            .expect("the id is traced");
        assert!(shown_value.verified, "the id was shown to the session");
        assert_eq!(
            function_shown(&fake, 0),
            json!({"tier": "admin", "attempt": "over_privilege"})
        );
    }

    #[tokio::test]
    async fn every_batch_of_a_request_on_an_admin_function_carries_the_function() {
        // A request split into batches (docs/02 section 2.4) names its function in each batch's
        // state, not only in the first one.
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        confirm_identity(&judge, &site, "doctor-a");
        let numbers: Vec<String> = (0..8_000).map(|n| n.to_string()).collect();
        let body = format!("[{}]", numbers.join(","));
        let request = RequestFacts {
            method: "POST",
            content_type: Some("application/json"),
            body: body.as_bytes(),
            ..get("/api/admin/export", None, Some("doctor-a"), 1_000)
        };
        let verdict = judge.judge(&site, &request).await;
        assert!(verdict.forward, "{:?}", verdict.record.decision_path);
        assert!(fake.calls() >= 2, "{} calls", fake.calls());
        assert_eq!(
            verdict.record.jev.as_ref().and_then(|jev| jev.batches),
            Some(u16::try_from(fake.calls()).unwrap())
        );
        for index in 0..fake.calls() {
            assert_eq!(
                function_shown(&fake, index),
                json!({"tier": "admin", "attempt": "over_privilege"}),
                "batch {}",
                index + 1
            );
        }
    }

    /// The scripted model of the lab (tests/security-lab/fake_jev.py, plan 3.5): a batch whose values
    /// carry no verified id at the path position is denied, since the id has no evidence in it.
    fn id_unshown_in_a_batch(body: &str) -> Option<(&'static str, &'static str)> {
        let document: serde_json::Value = serde_json::from_str(body).ok()?;
        let carried = document["state"]["request"]["values"]
            .as_array()?
            .iter()
            .any(|value| value["at"] == "path[2]" && value["verified"] == true);
        (!carried).then_some(("DENY", "BENIGN"))
    }

    /// A note of 24 fields of 420 characters and one of 1,500 (docs/02 section 2.4), as a JSON object:
    /// its state is cut into two batches or more.
    fn long_note() -> String {
        let fields: Vec<String> = (0..24)
            .map(|index| format!(r#""field{index:02}":"{}""#, "正常的文字".repeat(84)))
            .collect();
        format!(
            r#"{{{},"remark":"{}"}}"#,
            fields.join(","),
            "正常的文字".repeat(300)
        )
    }

    #[tokio::test]
    async fn every_batch_of_a_note_on_an_id_route_carries_the_verified_id() {
        // The public search showed patient 7005 to the session, and a note takes that sighting. The note
        // is cut into batches (docs/02 section 2.4) and each one names the id in its path, so each one
        // must carry the id with its verification, not only the first.
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        fake.answer_by(id_unshown_in_a_batch);
        let judge = judge(&fake);
        let site = tiers_site("high");
        confirm(&judge, &site, "alice");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        let body = long_note();
        let request = RequestFacts {
            method: "POST",
            content_type: Some("application/json"),
            body: body.as_bytes(),
            ..get("/api/patients/7005/notes", None, Some("alice"), 1_000)
        };
        let verdict = judge.judge(&site, &request).await;
        assert!(verdict.forward, "{:?}", verdict.record.decision_path);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevAllow);
        let batches = verdict
            .record
            .jev
            .as_ref()
            .and_then(|jev| jev.batches)
            .unwrap_or(0);
        assert!(batches >= 2, "{batches} batches");
        assert_eq!(fake.calls(), usize::from(batches));
    }

    #[tokio::test]
    async fn the_same_note_on_a_patient_the_session_was_never_shown_is_refused() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        fake.answer_by(id_unshown_in_a_batch);
        let judge = judge(&fake);
        let site = tiers_site("high");
        confirm(&judge, &site, "alice");
        judge.observe(&site, &shown_by("/api/search", SEARCH_BODY));
        let body = long_note();
        let request = RequestFacts {
            method: "POST",
            content_type: Some("application/json"),
            body: body.as_bytes(),
            ..get("/api/patients/7006/notes", None, Some("alice"), 1_000)
        };
        let verdict = judge.judge(&site, &request).await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
    }

    #[tokio::test]
    async fn an_attempt_on_an_admin_function_neither_reads_nor_writes_the_allow_cache() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor":{"id":"DR-A"}}"#, "doctor-a"),
        );
        let first = judge
            .judge(
                &site,
                &call_as("POST", "/api/admin/export", "doctor-a", 1_000),
            )
            .await;
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
        let second = judge
            .judge(
                &site,
                &call_as("POST", "/api/admin/export", "doctor-a", 2_000),
            )
            .await;
        assert_eq!(second.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn an_administrator_uses_an_admin_function_as_before() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = functions_site(false);
        judge.observe(
            &site,
            &home_for("root", br#"{"doctor":{"id":"DR-A"},"role":"admin"}"#),
        );
        let exported = judge
            .judge(&site, &call_as("POST", "/api/admin/export", "root", 1_000))
            .await;
        assert_eq!(exported.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
        let trace = exported
            .record
            .trace
            .function
            .clone()
            .expect("the trace names the tier");
        assert_eq!(trace.tier.as_deref(), Some("admin"));
        assert_eq!(trace.attempt, None);
        // An unseen reference is still judged, and its state carries no function: the administrator is
        // not an attempt, so the function is left out of the state.
        fake.answer("DENY", "BENIGN");
        let unseen = judge
            .judge(
                &site,
                &call_as("DELETE", "/api/patients/7009", "root", 2_000),
            )
            .await;
        assert_eq!(unseen.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(fake.calls(), 1);
        assert_eq!(function_shown(&fake, 0), serde_json::Value::Null);
    }

    #[tokio::test]
    async fn an_admin_function_of_medium_reliability_tightens_nothing() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = functions_site(false);
        confirm_identity(&judge, &site, "doctor-a");
        let verdict = judge
            .judge(
                &site,
                &call_as("GET", "/api/admin/search", "doctor-a", 1_000),
            )
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert!(verdict.record.trace.function.is_none());
    }

    #[tokio::test]
    async fn a_method_override_header_is_judged_by_the_stricter_method() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        confirm_identity(&judge, &site, "doctor-a");
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7005"}]}"#, "doctor-a"),
        );
        let overrides = ["delete".to_owned()];
        let verdict = judge
            .judge(
                &site,
                &RequestFacts {
                    method_overrides: &overrides,
                    ..call_as("POST", "/api/patients/7005", "doctor-a", 1_000)
                },
            )
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        let trace = verdict
            .record
            .trace
            .function
            .clone()
            .expect("the trace names the function");
        assert_eq!(trace.key, "POST /api/patients/{id}");
        assert_eq!(trace.entry.as_deref(), Some("DELETE /api/patients/{id}"));
        assert_eq!(trace.attempt, Some(Attempt::OverPrivilege));
    }

    #[tokio::test]
    async fn a_method_field_in_the_form_or_the_query_is_judged_by_the_stricter_method() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        confirm_identity(&judge, &site, "doctor-a");
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7005"}]}"#, "doctor-a"),
        );
        let form = RequestFacts {
            content_type: Some("application/x-www-form-urlencoded"),
            body: b"_method=DELETE",
            ..call_as("POST", "/api/patients/7005", "doctor-a", 1_000)
        };
        let in_form = judge.judge(&site, &form).await;
        assert_eq!(in_form.record.decision_path, DecisionPath::JevDeny);
        let query = RequestFacts {
            query: Some("_method=DELETE"),
            ..call_as("POST", "/api/patients/7005", "doctor-a", 2_000)
        };
        let in_query = judge.judge(&site, &query).await;
        assert_eq!(in_query.record.decision_path, DecisionPath::JevDeny);
        for verdict in [in_form, in_query] {
            let trace = verdict
                .record
                .trace
                .function
                .expect("the trace names the function");
            assert_eq!(trace.attempt, Some(Attempt::OverPrivilege));
            assert_eq!(trace.entry.as_deref(), Some("DELETE /api/patients/{id}"));
        }
    }

    #[tokio::test]
    async fn an_override_that_is_no_method_is_ignored() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = functions_site(false);
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7005"}]}"#, "doctor-a"),
        );
        let plain = judge
            .judge(
                &site,
                &call_as("POST", "/api/patients/7005", "doctor-a", 1_000),
            )
            .await;
        for (index, value) in ["DELETE FROM", "", "X", "TOOLONGMETHOD"]
            .into_iter()
            .enumerate()
        {
            let overrides = [value.to_owned()];
            let verdict = judge
                .judge(
                    &site,
                    &RequestFacts {
                        method_overrides: &overrides,
                        ..call_as(
                            "POST",
                            "/api/patients/7005",
                            "doctor-a",
                            2_000 + index as u64,
                        )
                    },
                )
                .await;
            assert!(verdict.record.trace.function.is_none(), "{value:?}");
            assert_eq!(
                verdict.record.decision_path, plain.record.decision_path,
                "{value:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_lower_case_transport_method_is_looked_up_in_upper_case() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        confirm_identity(&judge, &site, "doctor-a");
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7005"}]}"#, "doctor-a"),
        );
        let verdict = judge
            .judge(
                &site,
                &call_as("delete", "/api/patients/7005", "doctor-a", 1_000),
            )
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        let trace = verdict
            .record
            .trace
            .function
            .expect("the trace names the function");
        assert_eq!(trace.key, "DELETE /api/patients/{id}");
        assert_eq!(trace.attempt, Some(Attempt::OverPrivilege));
    }

    #[tokio::test]
    async fn an_encoded_slash_is_looked_up_as_a_slash_too() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor":{"id":"DR-A"}}"#, "doctor-a"),
        );
        for (now_ms, path) in [
            (1_000, "/api/admin%2Fexport"),
            (2_000, "/api/x/..%2Fadmin/export"),
        ] {
            let verdict = judge
                .judge(&site, &call_as("POST", path, "doctor-a", now_ms))
                .await;
            assert_eq!(
                verdict.record.decision_path,
                DecisionPath::JevDeny,
                "{path}"
            );
            let trace = verdict
                .record
                .trace
                .function
                .expect("the trace names the function");
            assert_eq!(
                trace.entry.as_deref(),
                Some("POST /api/admin/export"),
                "{path}"
            );
            assert_eq!(trace.attempt, Some(Attempt::OverPrivilege), "{path}");
        }
    }

    #[tokio::test]
    async fn a_head_on_an_admin_get_function_is_an_attempt_and_options_is_not() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(
            r#","mode":"enforce","objects":{"functions":[{"key":"GET /api/admin/search","source":"rule","tier":"admin","reliability":"high"}]}"#,
        );
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor":{"id":"DR-A"}}"#, "doctor-a"),
        );
        let head = judge
            .judge(
                &site,
                &call_as("HEAD", "/api/admin/search", "doctor-a", 1_000),
            )
            .await;
        assert_eq!(head.record.decision_path, DecisionPath::JevDeny);
        let trace = head
            .record
            .trace
            .function
            .expect("the trace names the function");
        assert_eq!(trace.entry.as_deref(), Some("GET /api/admin/search"));
        assert_eq!(trace.attempt, Some(Attempt::OverPrivilege));
        let options = judge
            .judge(
                &site,
                &call_as("OPTIONS", "/api/admin/search", "doctor-a", 2_000),
            )
            .await;
        assert!(options.record.trace.function.is_none());
        assert_ne!(options.record.decision_path, DecisionPath::JevDeny);
    }

    #[tokio::test]
    async fn observe_mode_forwards_an_attempt_as_would_block() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site_in(r#","mode":"observe""#, false);
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor":{"id":"DR-A"}}"#, "doctor-a"),
        );
        let verdict = judge
            .judge(
                &site,
                &call_as("POST", "/api/admin/export", "doctor-a", 1_000),
            )
            .await;
        assert!(verdict.forward);
        assert_eq!(verdict.record.outcome, Outcome::WouldBlock);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
    }

    #[tokio::test]
    async fn an_attempt_follows_the_site_policy_when_jev_is_down() {
        let fake = FakeJev::new();
        fake.fail(JevFailure::Timeout);
        let judge = judge(&fake);
        let denying = functions_site_in(r#","mode":"enforce","on_jev_unavailable":"deny""#, false);
        judge.observe(
            &denying,
            &shown("/api/home", br#"{"doctor":{"id":"DR-A"}}"#, "doctor-a"),
        );
        let refused = judge
            .judge(
                &denying,
                &call_as("POST", "/api/admin/export", "doctor-a", 1_000),
            )
            .await;
        assert!(!refused.forward);
        assert_eq!(refused.refuse_status, 403);
        let allowing =
            functions_site_in(r#","mode":"enforce","on_jev_unavailable":"allow""#, false);
        judge.observe(
            &allowing,
            &shown("/api/home", br#"{"doctor":{"id":"DR-A"}}"#, "doctor-a"),
        );
        let forwarded = judge
            .judge(
                &allowing,
                &call_as("POST", "/api/admin/export", "doctor-a", 2_000),
            )
            .await;
        assert!(forwarded.forward);
        assert_eq!(forwarded.record.outcome, Outcome::Unjudged);
    }

    #[tokio::test]
    async fn a_request_without_a_session_off_an_entry_is_still_no_session() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = functions_site(false);
        let verdict = judge
            .judge(
                &site,
                &RequestFacts {
                    method: "POST",
                    ..get("/api/admin/export", None, None, 1_000)
                },
            )
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.refuse_status, 401);
        assert_eq!(verdict.record.decision_path, DecisionPath::NoSession);
        assert_eq!(fake.calls(), 0);
        assert!(verdict.record.trace.function.is_none());
    }

    #[tokio::test]
    async fn a_bypassed_path_is_not_guarded_by_the_function_table() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(
            r#","mode":"enforce","objects":{"functions":[{"key":"POST /static/export","source":"rule","tier":"admin","reliability":"high"}]}"#,
        );
        let verdict = judge
            .judge(&site, &call_as("POST", "/static/export", "doctor-a", 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::Bypass);
        assert!(verdict.record.trace.function.is_none());
    }

    #[tokio::test]
    async fn the_credential_in_a_path_never_reaches_the_function_trace() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let credential = "tok-5ecret-0123456789";
        let site = site(
            r#","mode":"enforce","objects":{"functions":[{"key":"POST /api/{id}/export","source":"rule","tier":"admin","reliability":"high"}]}"#,
        );
        confirm(&judge, &site, credential);
        let path = format!("/api/{credential}/export");
        let verdict = judge
            .judge(&site, &call_as("POST", &path, credential, 1_000))
            .await;
        let trace = verdict
            .record
            .trace
            .function
            .clone()
            .expect("the trace names the function");
        assert_eq!(trace.key, "POST /api/<redacted>/export");
        assert_eq!(trace.entry.as_deref(), Some("POST /api/{id}/export"));
        let text = serde_json::to_string(&verdict.record).unwrap();
        assert!(!text.contains(credential), "{text}");
    }

    #[tokio::test]
    async fn an_unknown_function_is_sent_to_jev_when_the_site_asks() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = asking_site();
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7"}]}"#, "doctor-a"),
        );
        let verdict = judge
            .judge(&site, &call_as("GET", "/metrics", "doctor-a", 1_000))
            .await;
        assert!(!verdict.forward);
        assert_eq!(verdict.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(function_shown(&fake, 0), json!({"known": false}));
        let trace = verdict
            .record
            .trace
            .function
            .expect("the trace names the unknown function");
        assert_eq!(trace.key, "GET /metrics");
        assert_eq!(trace.known, Some(false));
        assert_eq!(trace.entry, None);
    }

    #[tokio::test]
    async fn an_unknown_function_jev_allows_is_served_from_the_cache_next_time() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = asking_site();
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7"}]}"#, "doctor-a"),
        );
        let first = judge
            .judge(&site, &call_as("GET", "/metrics", "doctor-a", 1_000))
            .await;
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
        let second = judge
            .judge(&site, &call_as("GET", "/metrics", "doctor-a", 2_000))
            .await;
        assert_eq!(second.record.decision_path, DecisionPath::CachedAllow);
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_cached_allow_does_not_settle_a_request_that_names_an_administrator_function() {
        // The cache key leaves out the method overrides, so the plain request's cached allow has
        // the same key as the override. The read guard in `plan` keeps that allow from settling it.
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor":{"id":"DR-A"}}"#, "doctor-a"),
        );
        let plain = judge
            .judge(
                &site,
                &call_as("POST", "/api/patients/8", "doctor-a", 1_000),
            )
            .await;
        assert_eq!(plain.record.decision_path, DecisionPath::JevAllow);
        let cached = judge
            .judge(
                &site,
                &call_as("POST", "/api/patients/8", "doctor-a", 2_000),
            )
            .await;
        assert_eq!(cached.record.decision_path, DecisionPath::CachedAllow);
        assert_eq!(fake.calls(), 1);
        let overrides = ["DELETE".to_owned()];
        let attempt = judge
            .judge(
                &site,
                &RequestFacts {
                    method_overrides: &overrides,
                    ..call_as("POST", "/api/patients/8", "doctor-a", 3_000)
                },
            )
            .await;
        assert_eq!(attempt.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 2);
        assert_eq!(
            function_shown(&fake, 1),
            json!({"tier": "admin", "attempt": "over_privilege"})
        );
    }

    #[tokio::test]
    async fn an_allow_of_a_request_that_names_an_administrator_function_is_not_cached() {
        // The attempt is judged and Jev allows it. That allow must not settle the plain request,
        // which shares its cache key: the write guard in `remember_allow` keeps it out of the cache.
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(false);
        judge.observe(
            &site,
            &shown("/api/home", br#"{"doctor":{"id":"DR-A"}}"#, "doctor-a"),
        );
        let overrides = ["DELETE".to_owned()];
        let attempt = judge
            .judge(
                &site,
                &RequestFacts {
                    method_overrides: &overrides,
                    ..call_as("POST", "/api/patients/8", "doctor-a", 1_000)
                },
            )
            .await;
        assert_eq!(attempt.record.decision_path, DecisionPath::JevAllow);
        let plain = judge
            .judge(
                &site,
                &call_as("POST", "/api/patients/8", "doctor-a", 2_000),
            )
            .await;
        assert_eq!(plain.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_route_word_under_an_id_function_is_asked_as_unknown() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = site(
            r#","mode":"enforce","objects":{"ask_unknown_functions":true,"functions":[{"key":"GET /api/patients/{id}","source":"rule"}]}"#,
        );
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7005"}]}"#, "doctor-a"),
        );
        let numbered = judge
            .judge(
                &site,
                &call_as("GET", "/api/patients/7005", "doctor-a", 1_000),
            )
            .await;
        assert_eq!(numbered.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
        // A route word is no value: the `{id}` entry does not cover it, so Jev is asked with the
        // function unknown and refuses it.
        let route_word = judge
            .judge(
                &site,
                &call_as("GET", "/api/patients/export-all", "doctor-a", 2_000),
            )
            .await;
        assert_eq!(route_word.record.decision_path, DecisionPath::JevDeny);
        assert_eq!(fake.calls(), 1);
        assert_eq!(function_shown(&fake, 0), json!({"known": false}));
    }

    #[tokio::test]
    async fn an_administrator_session_is_not_asked_about_an_unknown_function() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(true);
        judge.observe(
            &site,
            &home_for("root", br#"{"doctor":{"id":"DR-A"},"role":"admin"}"#),
        );
        let reports = judge
            .judge(&site, &call_as("GET", "/api/admin/reports", "root", 1_000))
            .await;
        assert_eq!(reports.record.decision_path, DecisionPath::FastAllow);
        assert!(reports.record.trace.function.is_none());
        assert_eq!(fake.calls(), 0);
        // The ordinary session is recognized first: the origin answers an entry with the credential (docs/01
        // section 1.2), so its request is judged as a session's.
        judge.observe(&site, &home_for("doctor-a", br#"{"doctor":{"id":"DR-A"}}"#));
        // The same request from an ordinary session is asked, with the function unknown.
        let doctor = judge
            .judge(
                &site,
                &call_as("GET", "/api/admin/reports", "doctor-a", 2_000),
            )
            .await;
        assert_eq!(fake.calls(), 1);
        assert_eq!(function_shown(&fake, 0), json!({"known": false}));
        assert_eq!(
            doctor.record.trace.function.and_then(|trace| trace.known),
            Some(false)
        );
    }

    #[tokio::test]
    async fn an_administrator_override_to_an_unlisted_method_is_not_unknown() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = functions_site(true);
        judge.observe(
            &site,
            &home_for("root", br#"{"doctor":{"id":"DR-A"},"role":"admin"}"#),
        );
        let overrides = ["PUT".to_owned()];
        let verdict = judge
            .judge(
                &site,
                &RequestFacts {
                    method_overrides: &overrides,
                    ..call_as("GET", "/api/admin/reports", "root", 1_000)
                },
            )
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert!(verdict.record.trace.function.is_none());
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn a_known_function_is_judged_as_before() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        // GET /api/notes/{id} is not in the table, but the object map declares a position on that route.
        let site = site(
            r#","mode":"enforce","objects":{"classes":[{"id":"patient","name":"患者"}],"slots":[{"key":"GET /api/notes/{id} path[2]","class":"patient","source":"admin"}],"ask_unknown_functions":true,"functions":[{"key":"GET /api/patients","source":"rule"}]}"#,
        );
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7"}]}"#, "doctor-a"),
        );
        let listed = judge
            .judge(&site, &call_as("GET", "/api/patients", "doctor-a", 1_000))
            .await;
        assert_eq!(listed.record.decision_path, DecisionPath::FastAllow);
        let positioned = judge
            .judge(&site, &call_as("GET", "/api/notes/7", "doctor-a", 2_000))
            .await;
        assert_eq!(positioned.record.decision_path, DecisionPath::FastAllow);
        assert!(listed.record.trace.function.is_none());
        assert!(positioned.record.trace.function.is_none());
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn a_site_that_does_not_ask_leaves_unknown_functions_alone() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = functions_site(false);
        confirm_identity(&judge, &site, "doctor-a");
        let verdict = judge
            .judge(&site, &call_as("GET", "/metrics", "doctor-a", 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert!(verdict.record.trace.function.is_none());
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn a_path_without_a_canonical_spelling_is_an_unknown_function() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = asking_site();
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7"}]}"#, "doctor-a"),
        );
        let verdict = judge
            .judge(
                &site,
                &call_as("GET", "/api/patients/%zz", "doctor-a", 1_000),
            )
            .await;
        assert_eq!(fake.calls(), 1);
        assert_eq!(function_shown(&fake, 0), json!({"known": false}));
        assert_eq!(
            verdict.record.trace.function.and_then(|trace| trace.known),
            Some(false)
        );
    }

    #[tokio::test]
    async fn an_entry_request_without_a_credential_on_an_unlearned_method_is_asked() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = asking_site();
        let verdict = judge
            .judge(&site, &call_as("DELETE", "/api/patients", "", 1_000))
            .await;
        assert_eq!(fake.calls(), 1);
        let document: serde_json::Value =
            serde_json::from_str(&fake.sent.lock().unwrap()[0]).unwrap();
        assert_eq!(document["state"]["entry"], json!({"matched": true}));
        assert_eq!(function_shown(&fake, 0), json!({"known": false}));
        assert_eq!(
            verdict.record.trace.function.and_then(|trace| trace.known),
            Some(false)
        );
    }

    #[tokio::test]
    async fn an_override_onto_an_admin_function_from_an_unknown_one_carries_both() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = site(
            r#","mode":"enforce","objects":{"ask_unknown_functions":true,"functions":[{"key":"DELETE /api/patients/{id}","source":"rule","tier":"admin","reliability":"high"}]}"#,
        );
        judge.observe(
            &site,
            &shown("/api/patients", br#"{"items":[{"id":"7005"}]}"#, "doctor-a"),
        );
        let overrides = ["DELETE".to_owned()];
        let request = RequestFacts {
            method_overrides: &overrides,
            ..call_as("POST", "/api/patients/7005", "doctor-a", 1_000)
        };
        let first = judge.judge(&site, &request).await;
        assert_eq!(first.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(
            function_shown(&fake, 0),
            json!({"tier": "admin", "attempt": "over_privilege", "known": false})
        );
        let trace = first
            .record
            .trace
            .function
            .expect("the trace names the function");
        assert_eq!(trace.entry.as_deref(), Some("DELETE /api/patients/{id}"));
        assert_eq!(trace.attempt, Some(Attempt::OverPrivilege));
        assert_eq!(trace.known, Some(false));
        // An attempt is never cached, so the same request is judged again.
        let again = judge
            .judge(
                &site,
                &RequestFacts {
                    method_overrides: &overrides,
                    ..call_as("POST", "/api/patients/7005", "doctor-a", 2_000)
                },
            )
            .await;
        assert_eq!(again.record.decision_path, DecisionPath::JevAllow);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn a_function_table_that_guards_nothing_leaves_the_state_and_the_record_as_they_were() {
        // The same objects with no function table, and with a table that guards nothing: a plain
        // function and a medium administrator function, the switch off.
        let ordinary = r#","functions":[{"key":"GET /api/patients","source":"rule"},{"key":"GET /api/admin/search","source":"rule","tier":"admin","reliability":"medium"}]"#;
        let mut records = Vec::new();
        for objects in [objects_with(""), objects_with(ordinary)] {
            let site = site(&format!(r#","mode":"enforce","objects":{objects}"#));
            let fake = FakeJev::new();
            fake.answer("DENY", "BENIGN");
            let judge = judge(&fake);
            confirm_identity(&judge, &site, "doctor-a");
            judge.observe(
                &site,
                &shown("/api/patients", br#"{"items":[{"id":"7005"}]}"#, "doctor-a"),
            );
            let mut rows = Vec::new();
            for (now_ms, method, path) in [
                (1_000, "DELETE", "/api/patients/7005"),
                (2_000, "GET", "/api/patients"),
                (3_000, "POST", "/api/patients/7005"),
                // An id never shown to the session: judged by Jev, so its state is compared too.
                (4_000, "DELETE", "/api/patients/7009"),
            ] {
                let verdict = judge
                    .judge(&site, &call_as(method, path, "doctor-a", now_ms))
                    .await;
                let mut row = serde_json::to_value(&verdict.record).unwrap();
                row["at_millis"] = json!(0);
                row["trace"]["timing"] = json!({});
                if let Some(jev) = row
                    .get_mut("jev")
                    .and_then(serde_json::Value::as_object_mut)
                {
                    jev.remove("millis");
                }
                rows.push(row);
            }
            records.push(rows);
        }
        assert_eq!(records[0].len(), records[1].len());
        assert!(
            records[0].iter().any(|row| row["jev"]["state"].is_string()),
            "at least one judgement must reach Jev, or the comparison proves nothing"
        );
        for (left, right) in records[0].iter().zip(&records[1]) {
            assert_eq!(left["jev"]["state"], right["jev"]["state"]);
            assert_eq!(left["decision_path"], right["decision_path"]);
            assert!(left["trace"].get("function").is_none());
            assert!(right["trace"].get("function").is_none());
        }
    }

    #[test]
    fn a_session_that_an_answer_issues_records_the_address_that_created_it() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"observe""#);
        // The answer issues a credential: the session it creates is recorded under the address it was made
        // from. A refused response starts no session at all (docs/07 section 7.4.6).
        let observed = judge.observe(
            &site,
            &Observation {
                route: None,
                request_id: RID,
                unread: None,
                would_block: false,
                credential: None,
                client: "2001:db8:1:2::9",
                issued_credential: Some("fresh"),
                method: "POST",
                path: "/login",
                status: 200,
                content_type: Some("application/json"),
                body: b"{}",
                now_ms: 1_001,
                sent: &[],
                echo: &[],
            },
        );
        assert!(observed.issued_session.is_some());
        let id = judge.session_key(site.name(), "fresh");
        let inner = judge.lock();
        // Any address of the same /64 is the same origin; another /64 is not.
        assert_eq!(
            inner.store.origin_of(&id, 1_001),
            Some(judge.origin_key("2001:db8:1:2:f::1"))
        );
        assert_ne!(
            inner.store.origin_of(&id, 1_001),
            Some(judge.origin_key("2001:db8:1:3::9"))
        );
    }

    /// A request off an entry that carries a credential no session holds is refused without a Jev call,
    /// without any context, and the record says the credential was unrecognized (docs/01 section 1.4).
    #[tokio::test]
    async fn an_unrecognized_credential_is_refused_off_an_entry() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        for (path, query) in [
            ("/metrics", None),
            ("/api/admin/export", None),
            ("/users/alice", None),
            ("/api/patients/8", Some("q=word1x")),
        ] {
            let verdict = judge
                .judge(&site, &get(path, query, Some("made-up"), 1_000))
                .await;
            assert_eq!(
                verdict.record.decision_path,
                DecisionPath::NoSession,
                "{path}"
            );
            assert!(!verdict.forward, "{path}");
            assert_eq!(verdict.refuse_status, 401, "{path}");
            assert!(verdict.record.session.is_empty(), "{path}");
            assert!(verdict.record.trace.unrecognized_credential, "{path}");
        }
        assert_eq!(fake.calls(), 0);
        assert_eq!(judge.session_count(), 0);
    }

    /// On an entry an unrecognized credential is judged as its address: the record names the address
    /// context, and the Jev calls draw on the address's budget.
    #[tokio::test]
    async fn an_unrecognized_credential_on_an_entry_is_judged_as_its_address() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce","advanced":{"address_calls_per_minute":1}"#);
        let first = judge
            .judge(
                &site,
                &get("/login", Some("name=first1"), Some("made-up"), 0),
            )
            .await;
        assert!(first.forward);
        assert_eq!(first.record.context, Some(ContextKind::Address));
        assert!(first.record.trace.unrecognized_credential);
        assert!(first.record.session.is_empty());
        let second = judge
            .judge(
                &site,
                &get("/login", Some("name=second1"), Some("made-up-2"), 1_000),
            )
            .await;
        assert!(!second.forward);
        assert_eq!(second.refuse_status, 429);
        assert_eq!(fake.calls(), 1);
    }

    /// An answer to a request off an entry recognizes nothing, whatever its status.
    #[tokio::test]
    async fn an_origin_2xx_off_an_entry_recognizes_nothing() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(
            &site,
            &Observation {
                path: "/metrics",
                status: 200,
                ..list_response("made-up", 0)
            },
        );
        assert_eq!(judge.session_count(), 0);
        let verdict = judge
            .judge(&site, &get("/metrics", None, Some("made-up"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::NoSession);
    }

    /// A response the gateway would refuse recognizes no credential: not on an entry of a site without a
    /// user identity position, not with a user declared on a site that has one, and not the credential it
    /// issues (docs/07 section 7.4.6).
    #[tokio::test]
    async fn a_would_block_response_recognizes_nothing() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let open = site(r#","mode":"observe""#);
        let identity = identity_site();
        judge.observe(
            &open,
            &Observation {
                would_block: true,
                path: "/login",
                body: b"{}",
                ..list_response("made-up-1", 0)
            },
        );
        judge.observe(
            &identity,
            &Observation {
                would_block: true,
                ..home_for("made-up-2", br#"{"doctor":{"id":"DR-A"}}"#)
            },
        );
        judge.observe(
            &open,
            &Observation {
                would_block: true,
                credential: None,
                issued_credential: Some("made-up-3"),
                path: "/login",
                body: b"{}",
                ..list_response("unused", 0)
            },
        );
        assert_eq!(judge.session_count(), 0);
        for credential in ["made-up-1", "made-up-2", "made-up-3"] {
            let verdict = judge
                .judge(
                    &open,
                    &get("/api/patients/7", None, Some(credential), 1_000),
                )
                .await;
            assert_eq!(
                verdict.record.decision_path,
                DecisionPath::NoSession,
                "{credential}"
            );
        }
        assert_eq!(fake.calls(), 0);
    }

    /// A held login is not claimed by an answer the gateway would refuse: the login stays held, and the
    /// credential it issued takes it on the next request (docs/01 section 1.7).
    #[tokio::test]
    async fn a_would_block_entry_response_claims_no_held_login() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = basket_site();
        let body = login_body(LOGIN_TOKEN, 6);
        judge.observe(&site, &json_login(body.as_bytes(), "10.0.0.1", 0));
        let before = judge.session_count();
        judge.observe(
            &site,
            &Observation {
                would_block: true,
                ..list_response(LOGIN_TOKEN, 1)
            },
        );
        assert_eq!(
            judge.session_count(),
            before,
            "the refused answer starts no session"
        );
        let basket = judge
            .judge(&site, &get("/rest/basket/6", None, Some(LOGIN_TOKEN), 2))
            .await;
        let traced = basket.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
        assert_eq!(traced.login_unbound, None);
        assert_eq!(basket.record.decision_path, DecisionPath::FastAllow);
    }

    /// Values an unrecognized credential sent before the origin recognized it are not learned from an
    /// echo once it is recognized: by an entry's 2xx on a site without a user identity position (S4), by a
    /// user the response declares (S3), and by a login that binds on the next request (docs/01 section 1.2).
    #[tokio::test]
    async fn values_sent_before_recognition_are_not_learned_from_an_echo() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        sent_before_an_entry_recognizes(&fake).await;
        sent_before_a_declared_user_recognizes(&fake).await;
        sent_before_a_login_binds(&fake).await;
    }

    /// S4: the entry's 2xx recognizes the credential, and echoes the id it sent before.
    async fn sent_before_an_entry_recognizes(fake: &FakeJev) {
        let judge = judge(fake);
        let open = site(r#","mode":"observe""#);
        let early = judge
            .judge(
                &open,
                &get("/api/patients/P-0000099", None, Some("late"), 1_000),
            )
            .await;
        assert!(early.forward, "observe mode forwards the attempt");
        assert_eq!(early.record.decision_path, DecisionPath::NoSession);
        judge.observe(
            &open,
            &Observation {
                would_block: true,
                client: "10.0.0.9",
                ..answered(
                    &early,
                    "/api/patients/P-0000099",
                    br#"{"id":"P-0000099"}"#,
                    "late",
                )
            },
        );
        let entry = judge
            .judge(&open, &get("/login", None, Some("late"), 2_000))
            .await;
        judge.observe(
            &open,
            &Observation {
                client: "10.0.0.9",
                ..answered(&entry, "/login", br#"{"id":"P-0000099"}"#, "late")
            },
        );
        let later = judge
            .judge(
                &open,
                &get("/api/patients/P-0000099", None, Some("late"), 3_000),
            )
            .await;
        assert_eq!(later.record.decision_path, DecisionPath::JevAllow, "S4");
    }

    /// S3: the entry declares a user the request did not send, and echoes the id.
    async fn sent_before_a_declared_user_recognizes(fake: &FakeJev) {
        let judge = judge(fake);
        let identity = site(
            r#","mode":"observe","objects":{"classes":[{"id":"doctor","name":"医生"}],"slots":[{"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"}]}"#,
        );
        let early = judge
            .judge(
                &identity,
                &get("/api/patients/P-0000099", None, Some("late"), 1_000),
            )
            .await;
        assert!(early.forward, "observe mode forwards the attempt");
        judge.observe(
            &identity,
            &Observation {
                would_block: true,
                client: "10.0.0.9",
                ..answered(
                    &early,
                    "/api/patients/P-0000099",
                    br#"{"id":"P-0000099"}"#,
                    "late",
                )
            },
        );
        let entry = judge
            .judge(&identity, &get("/api/home", None, Some("late"), 2_000))
            .await;
        judge.observe(
            &identity,
            &Observation {
                client: "10.0.0.9",
                ..answered(
                    &entry,
                    "/api/home",
                    br#"{"doctor":{"id":"DR-A"},"id":"P-0000099"}"#,
                    "late",
                )
            },
        );
        let later = judge
            .judge(
                &identity,
                &get("/api/patients/P-0000099", None, Some("late"), 3_000),
            )
            .await;
        assert_eq!(later.record.decision_path, DecisionPath::JevAllow, "S3");
    }

    /// The login: the value is sent before the login binds, and the session the login starts takes it
    /// with it, so the echo in a later response teaches nothing.
    async fn sent_before_a_login_binds(fake: &FakeJev) {
        let judge = judge(fake);
        let basket = site(
            r#","mode":"observe","advanced":{"field_kinds":[{"field":"bid","kind":"basket"}]}"#,
        );
        let early = judge
            .judge(
                &basket,
                &get("/api/patients/P-0000099", None, Some(LOGIN_TOKEN), 1_000),
            )
            .await;
        assert!(early.forward, "observe mode forwards the attempt");
        judge.observe(
            &basket,
            &Observation {
                would_block: true,
                client: "10.0.0.9",
                ..answered(
                    &early,
                    "/api/patients/P-0000099",
                    br#"{"id":"P-0000099"}"#,
                    LOGIN_TOKEN,
                )
            },
        );
        judge.observe(
            &basket,
            &json_login(login_body(LOGIN_TOKEN, 6).as_bytes(), "10.0.0.1", 1_500),
        );
        let bound = judge
            .judge(
                &basket,
                &get("/rest/basket/6", None, Some(LOGIN_TOKEN), 2_000),
            )
            .await;
        assert_eq!(
            bound.record.decision_path,
            DecisionPath::FastAllow,
            "the login is bound"
        );
        judge.observe(
            &basket,
            &Observation {
                client: "10.0.0.9",
                ..answered(
                    &bound,
                    "/rest/basket/6",
                    br#"{"id":"P-0000099"}"#,
                    LOGIN_TOKEN,
                )
            },
        );
        let later = judge
            .judge(
                &basket,
                &get("/api/patients/P-0000099", None, Some(LOGIN_TOKEN), 3_000),
            )
            .await;
        assert_eq!(later.record.decision_path, DecisionPath::JevAllow, "login");
    }

    /// An unrecognized credential's request on an entry notes what it sent in its address too, so the
    /// address's own response does not teach the address the value (docs/01 section 1.4 step 8).
    #[tokio::test]
    async fn an_unrecognized_entry_request_notes_what_it_sent_in_the_address_context() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        // The allow cache is off, so the later request is judged rather than answered from the first one's allow.
        let site = site(
            r#","mode":"enforce","advanced":{"allow_cache_minutes":0},"objects":{"classes":[{"id":"doctor","name":"医生"}],"slots":[{"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"}]}"#,
        );
        let request = judge
            .judge(
                &site,
                &get("/api/home", Some("q=P-0000099"), Some("made-up"), 1_000),
            )
            .await;
        assert!(request.forward);
        judge.observe(
            &site,
            &Observation {
                client: "10.0.0.9",
                ..answered(&request, "/api/home", br#"{"id":"P-0000099"}"#, "made-up")
            },
        );
        let later = judge
            .judge(&site, &get("/api/home", Some("q=P-0000099"), None, 2_000))
            .await;
        assert_eq!(
            later.record.decision_path,
            DecisionPath::JevAllow,
            "the echoed id was not learned"
        );
    }

    /// On a site without a user identity position, an entry the origin answers with 2xx recognizes the
    /// credential, and a later request without values is fast allowed.
    #[tokio::test]
    async fn an_entry_2xx_recognizes_a_credential_on_a_site_without_user_identity() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        confirm(&judge, &site, "alice");
        assert_eq!(judge.session_count(), 1);
        let verdict = judge
            .judge(&site, &get("/metrics", None, Some("alice"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::FastAllow);
        assert!(!verdict.record.trace.unrecognized_credential);
        assert_eq!(fake.calls(), 0);
    }

    /// On a site with a user identity position, an entry's 2xx that declares no user recognizes nothing.
    #[tokio::test]
    async fn an_entry_2xx_does_not_recognize_on_a_user_identity_site() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = identity_site();
        judge.observe(
            &site,
            &Observation {
                path: "/login",
                body: b"{}",
                ..list_response("alice", 0)
            },
        );
        // Only the address's context of the answer exists: the credential has no session.
        assert_eq!(judge.session_count(), 1);
        let verdict = judge
            .judge(&site, &get("/metrics", None, Some("alice"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::NoSession);
        assert_eq!(verdict.refuse_status, 401);
        assert_eq!(fake.calls(), 0);
    }

    /// A request without a credential off an entry is refused with nothing kept: it sends nothing a credential
    /// could later take, and starts no address context, so an observed refusal of it leaves the store as it was
    /// (docs/01 section 1.2).
    #[tokio::test]
    async fn a_request_without_a_credential_off_an_entry_sends_nothing_and_starts_no_context() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let open = site(r#","mode":"observe""#);
        let before = judge.session_count();
        let early = judge
            .judge(&open, &get("/api/patients/P-0000099", None, None, 1_000))
            .await;
        assert!(early.forward, "observe mode forwards the attempt");
        assert_eq!(early.record.decision_path, DecisionPath::NoSession);
        assert!(early.sent.is_empty(), "no value waits for a credential");
        judge.observe(
            &open,
            &Observation {
                would_block: true,
                credential: None,
                client: "10.0.0.9",
                sent: &early.sent,
                echo: &early.echo,
                path: "/api/patients/P-0000099",
                body: br#"{"id":"P-0000099"}"#,
                ..list_response("", 1_000)
            },
        );
        assert_eq!(
            judge.session_count(),
            before,
            "no address context is started"
        );
    }

    /// A login the gateway would refuse in observe mode sends a value and is issued a credential. The value
    /// waits for the credential (docs/07 section 7.4.6), so when an entry later recognizes it, the echo of the
    /// value in that entry's answer teaches the session nothing.
    #[tokio::test]
    async fn a_refused_login_that_issues_a_credential_stages_what_it_sent() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let open = site(r#","mode":"observe""#);
        let login = judge
            .judge(
                &open,
                &RequestFacts {
                    method: "POST",
                    content_type: Some("application/json"),
                    body: br#"{"id":"P-0000077"}"#,
                    ..get("/login", None, None, 1_000)
                },
            )
            .await;
        assert!(login.forward, "observe mode forwards the attempt");
        judge.observe(
            &open,
            &Observation {
                would_block: true,
                issued_credential: Some("fresh"),
                sent: &login.sent,
                echo: &login.echo,
                ..json_login(br#"{"ok":true}"#, "10.0.0.9", 1_100)
            },
        );
        let entry = judge
            .judge(&open, &get("/api/home", None, Some("fresh"), 2_000))
            .await;
        judge.observe(
            &open,
            &Observation {
                client: "10.0.0.9",
                ..answered(&entry, "/api/home", br#"{"id":"P-0000077"}"#, "fresh")
            },
        );
        let later = judge
            .judge(
                &open,
                &get("/api/patients/P-0000077", None, Some("fresh"), 3_000),
            )
            .await;
        assert_eq!(
            later.record.decision_path,
            DecisionPath::JevAllow,
            "the echo of a value sent before recognition is not learned"
        );
    }

    /// An unrecognized credential's entry request that sends more tokens than a session can record stops the
    /// learning of the address it was judged in. The credential's session stops too, the stop waiting for the
    /// session the credential starts: neither learns from a later answer (docs/01 section 1.2).
    #[tokio::test]
    async fn a_request_too_long_to_record_stops_the_learning_of_its_address_and_its_credential() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let open = site(r#","mode":"enforce""#);
        let body = (0..=SENT_MAX)
            .map(|index| format!("t{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let upload = RequestFacts {
            route: None,
            request_headers: &[],
            method_overrides: &[],
            method: "POST",
            content_type: Some("text/plain"),
            body: body.as_bytes(),
            ..get("/login", None, Some("late"), 1_000)
        };
        assert!(judge.judge(&open, &upload).await.forward);
        let seen = judge.observe(
            &open,
            &Observation {
                credential: None,
                client: "10.0.0.9",
                body: br#"{"items":[{"id":"P-0000066"}]}"#,
                ..list_response("", 1_500)
            },
        );
        assert_eq!(
            seen.new_values, 0,
            "the address learns nothing from its next answer"
        );
        judge.observe(
            &open,
            &Observation {
                client: "10.0.0.9",
                path: "/api/home",
                body: br"{}",
                ..list_response("late", 2_000)
            },
        );
        let learned = judge.observe(
            &open,
            &Observation {
                client: "10.0.0.9",
                body: br#"{"items":[{"id":"P-0000055"}]}"#,
                ..list_response("late", 2_100)
            },
        );
        assert_eq!(
            learned.new_values, 0,
            "the session the credential starts keeps the stop"
        );
    }

    /// On a site with a user identity position, an entry that declares a role and no user recognizes nothing:
    /// only a user the response declares starts the session (docs/01 section 1.2, rule S3).
    #[tokio::test]
    async fn an_entry_that_declares_only_a_role_does_not_recognize_on_a_user_identity_site() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = identity_site();
        judge.observe(&site, &home_for("alice", br#"{"role":"admin"}"#));
        assert_eq!(
            judge.session_count(),
            1,
            "only the address's context of the answer exists"
        );
        let verdict = judge
            .judge(&site, &get("/metrics", None, Some("alice"), 1_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::NoSession);
        assert_eq!(fake.calls(), 0);
    }

    /// A page that holds an expired token logs in again. On a site with a user identity position, a login
    /// answer that declares no user does not recognize the old credential, so the login it sends is held as
    /// usual and the new token binds on its next request (docs/01 sections 1.2 and 1.7, rule R8).
    #[tokio::test]
    async fn a_login_sent_with_an_old_unrecognized_credential_still_holds_its_login() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = identity_site();
        let body = login_body(LOGIN_TOKEN, 6);
        judge.observe(
            &site,
            &Observation {
                credential: Some("expired"),
                ..json_login(body.as_bytes(), "10.0.0.1", 0)
            },
        );
        let bound = judge
            .judge(&site, &get("/metrics", None, Some(LOGIN_TOKEN), 1_000))
            .await;
        let traced = bound.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
    }

    /// On a site with a user identity position, a response on an entry that declares a user recognizes the
    /// credential, and the session carries the identity the response declares.
    #[tokio::test]
    async fn an_identity_response_recognizes_the_credential() {
        let fake = FakeJev::new();
        let judge = judge(&fake);
        let site = identity_site();
        judge.observe(&site, &home_for("alice", br#"{"doctor":{"id":"DR-A"}}"#));
        assert_eq!(judge.session_count(), 1);
        let verdict = judge
            .judge(&site, &get("/metrics", None, Some("alice"), 1_000))
            .await;
        assert_ne!(verdict.record.decision_path, DecisionPath::NoSession);
        assert!(
            identity_of(&verdict.record).is_some(),
            "the declared identity is carried"
        );
    }

    /// A user the request itself sent is not a user the response declares: an answer that echoes it
    /// recognizes nothing.
    #[tokio::test]
    async fn an_echoed_user_does_not_recognize() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = identity_site();
        let request = judge
            .judge(
                &site,
                &get("/api/home", Some("q=P-0000099"), Some("alice"), 1_000),
            )
            .await;
        assert!(request.forward);
        judge.observe(
            &site,
            &Observation {
                client: "10.0.0.9",
                ..answered(
                    &request,
                    "/api/home",
                    br#"{"doctor":{"id":"P-0000099"}}"#,
                    "alice",
                )
            },
        );
        assert_eq!(
            judge.session_count(),
            1,
            "only the address's context exists"
        );
        let verdict = judge
            .judge(&site, &get("/metrics", None, Some("alice"), 2_000))
            .await;
        assert_eq!(verdict.record.decision_path, DecisionPath::NoSession);
    }

    /// A JSON login binds on the first request of its credential, whatever its path (docs/01 section 1.7):
    /// the values the login returned are known to the session from then on.
    #[tokio::test]
    async fn a_login_binds_on_the_first_request_wherever_it_lands() {
        let fake = FakeJev::new();
        fake.answer("DENY", "BENIGN");
        let judge = judge(&fake);
        let site = basket_site();
        judge.observe(
            &site,
            &json_login(login_body(LOGIN_TOKEN, 6).as_bytes(), "10.0.0.1", 0),
        );
        let basket = judge
            .judge(&site, &get("/rest/basket/6", None, Some(LOGIN_TOKEN), 1))
            .await;
        let traced = basket.record.trace.session.expect("the session is traced");
        assert_eq!(traced.login_request_id.as_deref(), Some(RID));
        assert_eq!(traced.login_unbound, None);
        assert_eq!(basket.record.decision_path, DecisionPath::FastAllow);
        assert_eq!(fake.calls(), 0);
    }

    /// A recognized session is judged as before: a seen value is fast allowed, an unseen one goes to Jev,
    /// an allow is cached for the next identical request, and a denial is never cached.
    #[tokio::test]
    async fn a_recognized_session_is_judged_as_before() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        judge.observe(&site, &list_response("alice", 0));
        let seen = judge
            .judge(&site, &get("/api/patients/7", None, Some("alice"), 1_000))
            .await;
        assert_eq!(seen.record.decision_path, DecisionPath::FastAllow);
        assert!(!seen.record.trace.unrecognized_credential);
        let allowed = judge
            .judge(
                &site,
                &get("/api/search", Some("q=word1x"), Some("alice"), 2_000),
            )
            .await;
        assert_eq!(allowed.record.decision_path, DecisionPath::JevAllow);
        let cached = judge
            .judge(
                &site,
                &get("/api/search", Some("q=word1x"), Some("alice"), 3_000),
            )
            .await;
        assert_eq!(cached.record.decision_path, DecisionPath::CachedAllow);
        assert_eq!(fake.calls(), 1);
        fake.answer("DENY", "BENIGN");
        for now in [4_000, 5_000] {
            let denied = judge
                .judge(
                    &site,
                    &get("/api/search", Some("q=word2x"), Some("alice"), now),
                )
                .await;
            assert_eq!(denied.record.decision_path, DecisionPath::JevDeny);
            assert!(!denied.forward);
        }
        assert_eq!(fake.calls(), 3);
    }

    /// The answer that starts a session by an entry (S4) echoes a value the request sent: the value is not
    /// learned, as an echo of the request's own values never is.
    #[tokio::test]
    async fn the_first_request_of_a_new_session_notes_what_it_sent() {
        let fake = FakeJev::new();
        fake.answer("ALLOW", "BENIGN");
        let judge = judge(&fake);
        let site = site(r#","mode":"enforce""#);
        let request = judge
            .judge(
                &site,
                &get("/login", Some("q=P-0000099"), Some("alice"), 1_000),
            )
            .await;
        assert!(request.forward);
        judge.observe(
            &site,
            &Observation {
                client: "10.0.0.9",
                ..answered(&request, "/login", br#"{"q":"P-0000099"}"#, "alice")
            },
        );
        let later = judge
            .judge(
                &site,
                &get("/api/patients/P-0000099", None, Some("alice"), 2_000),
            )
            .await;
        assert_eq!(
            later.record.decision_path,
            DecisionPath::JevAllow,
            "the echo taught nothing"
        );
        assert_eq!(fake.calls(), 2);
    }
}
