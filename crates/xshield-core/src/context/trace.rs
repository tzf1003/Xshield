//! The decision trace: the evidence behind one decision, and the links that
//! let the console follow it to the requests that supplied the evidence
//! (docs/07 section 7.4.3).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::objects::{Reliability, Tier};

/// Largest serialized trace; [`Trace::fit`] trims anything bigger.
pub const TRACE_BYTES_MAX: usize = 16 * 1024;
/// Longest value text kept before it is clipped.
pub const VALUE_CHARS_MAX: usize = 256;
/// Longest request path a session entry or recent request keeps, in bytes. The
/// same bound as a configured path (`MAX_PATH_BYTES`); longer paths are cut.
pub const TRACE_PATH_BYTES_MAX: usize = 256;
/// Longest name a value keeps in the trace, in bytes: its location, its key and
/// its position. Like a session path, a longer name is cut, so one very long key
/// cannot push every value of its request out of the row. The console aligns
/// with the same bound (`TRACE_NAME_BYTES_MAX` in `align.ts`).
pub const TRACE_NAME_BYTES_MAX: usize = 256;
/// Value text length after [`Trace::fit`] has run out of gentler cuts.
const FIT_VALUE_CHARS: usize = 64;
/// Most response positions whose value fingerprints one response records. The
/// first ones in the order the response shows them are kept.
pub const FINGERPRINT_SLOTS_MAX: usize = 16;
/// Fingerprints kept for one response position: the smallest, so the choice does
/// not depend on the order in which the response lists its values.
pub const FINGERPRINTS_PER_SLOT_MAX: usize = 8;

/// The trace of one decision.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Trace {
    /// 1 for rows the gateway writes; 0 for rows imported from the earlier
    /// format, which carry no trace.
    pub v: u8,
    /// The entry pattern that covers the path, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    /// The bypass pattern that covers the path, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bypass: Option<String>,
    /// The refusal the gateway answered itself: `unauthenticated`,
    /// `forbidden`, `body_not_inspectable` or `unknown_site`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    /// The request was not fully read into values: the body was not
    /// structured, exceeded the parse limit, or had more values than the limit.
    #[serde(skip_serializing_if = "is_false")]
    pub values_truncated: bool,
    /// Every value the request was split into, in extraction order, inert
    /// ones included.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<TraceValue>,
    /// The session context the decision was made against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<TraceSession>,
    /// For a cached allow: the request whose Jev allow the cache reuses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_source: Option<String>,
    /// What the site's function table says about the request (docs/07 section 7.9.18). Absent unless
    /// the table decides it: an attempt, a function the table does not know, or an administrator's use
    /// of an administrator-only function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<TraceFunction>,
    /// Durations in milliseconds.
    pub timing: Timing,
    /// What the origin's response taught the session; absent when the
    /// request was never judged or the response never reached the judge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ObservationSummary>,
    /// The upstream failure class when the origin could not answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_error: Option<String>,
    /// Detail was removed to keep the trace within [`TRACE_BYTES_MAX`].
    #[serde(skip_serializing_if = "is_false")]
    pub trimmed: bool,
}

impl Trace {
    /// An empty trace as the gateway writes it (version 1).
    #[must_use]
    pub fn new() -> Self {
        Self {
            v: 1,
            ..Self::default()
        }
    }

    /// Trims the trace until it fits [`TRACE_BYTES_MAX`]. The inert values go
    /// first, then every value keeps one source, then values are cut to 64
    /// characters (docs/07 section 7.4.4). Next the response's learning detail
    /// (its structure and fingerprints) goes, but only when that alone is enough,
    /// because the values are the evidence. Then the values themselves go. Last,
    /// if the trace is still too big, the rest of the detail goes: the field
    /// counts, the content type, and the session's recent requests and entries.
    /// What remains is small. Sets `trimmed` when anything was removed, and
    /// `values_truncated` when values were cleared.
    pub fn fit(&mut self) {
        if self.encoded_len() <= TRACE_BYTES_MAX {
            return;
        }
        self.trimmed = true;
        self.values.retain(|value| !value.inert);
        if self.encoded_len() > TRACE_BYTES_MAX {
            for value in &mut self.values {
                value.sources.truncate(1);
            }
        }
        if self.encoded_len() > TRACE_BYTES_MAX {
            for value in &mut self.values {
                if value.value.chars().count() > FIT_VALUE_CHARS {
                    value.value = value.value.chars().take(FIT_VALUE_CHARS).collect();
                }
            }
        }
        if self.encoded_len() > TRACE_BYTES_MAX {
            let mut slim = self.clone();
            slim.strip_learning();
            if slim.encoded_len() <= TRACE_BYTES_MAX {
                *self = slim;
            }
        }
        if self.encoded_len() > TRACE_BYTES_MAX && !self.values.is_empty() {
            self.values.clear();
            self.values_truncated = true;
        }
        if self.encoded_len() > TRACE_BYTES_MAX {
            self.strip_learning();
        }
        if self.encoded_len() > TRACE_BYTES_MAX {
            self.strip_detail();
        }
    }

    /// Removes the response's structure and its fingerprints.
    fn strip_learning(&mut self) {
        if let Some(response) = self.response.as_mut() {
            response.shape = None;
            response.fingerprints.clear();
        }
    }

    /// Removes the response's field counts and content type, and the session's
    /// recent requests and entries.
    fn strip_detail(&mut self) {
        if let Some(response) = self.response.as_mut() {
            response.fields.clear();
            response.content_type = None;
        }
        if let Some(session) = self.session.as_mut() {
            session.recent = None;
            session.entries_passed = None;
        }
    }

    fn encoded_len(&self) -> usize {
        serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len())
    }
}

/// One request value as the trace shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // the flags are the trace's own vocabulary
pub struct TraceValue {
    /// Location, for example `path[2]` or `query.doctor`; cut to
    /// [`TRACE_NAME_BYTES_MAX`] bytes (see `at_len`).
    pub at: String,
    /// The original length in bytes of `at`, when it was cut.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_len: Option<usize>,
    /// Key it travels under, when it has one. Cut to [`TRACE_NAME_BYTES_MAX`] bytes.
    pub key: Option<String>,
    /// The value, `<redacted>` for a secret, clipped to 256 characters.
    pub value: String,
    /// The original length in characters, when the value was redacted or clipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<usize>,
    /// The text was clipped to [`VALUE_CHARS_MAX`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub clipped: bool,
    /// `reference`, `route` or `input`.
    pub kind: String,
    /// Route-like words that never select an object.
    pub inert: bool,
    /// The session had seen this value.
    pub seen: bool,
    /// The gateway matched it with a response that showed this exact value as
    /// the same kind of object.
    pub verified: bool,
    /// Where the session saw it, most useful first, at most three.
    pub sources: Vec<TraceSource>,
    /// The position the value sits at: method, route template and location,
    /// for example `GET /doctor/{id} path[1]`. Absent in rows written before
    /// positions were recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
    /// The kind of object the object map gives this position, for example
    /// `doctor`. Absent when no map entry applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Where `object` came from. Only `map` (a confirmed map entry) is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_from: Option<ObjectFrom>,
    /// Whether the request position takes a value that only a public response
    /// showed, and how sure the map is. Absent when the map gives no such entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_access: Option<PublicAccess>,
    /// `over_privilege` when the gateway found the value to be an attempt: every
    /// response that showed it was public, and the position takes none of those.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<Attempt>,
    /// The request path has no template the map can name (no canonical spelling, or one over
    /// 256 bytes), and no declared position governs the value. A site that judges public access
    /// never fast-allows such a request, and the value is no attempt (docs/07 section 7.4.7).
    /// Absent otherwise.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unplaced: bool,
}

/// What a request position says of public sources, with how sure the map is: whether
/// normal traffic sends values from public positions there, and the reliability of that
/// judgement (docs/07 section 7.9.16). Written into the trace and the judge's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAccess {
    /// `false` marks a position that takes no value from a public response.
    pub accepts: bool,
    /// How sure the map is of `accepts`. Only `high` tightens a decision.
    pub reliability: Reliability,
}

/// What the gateway found a request value to be (docs/01 section 1.4, step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attempt {
    /// The value was shown to the session only by public responses, and the
    /// position it is used at takes no value from a public response: an attempt
    /// to act on an object the session has no right to.
    OverPrivilege,
}

impl Attempt {
    /// The word the judge's state and the trace use for the attempt.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OverPrivilege => "over_privilege",
        }
    }
}

/// A response that showed a value to the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSource {
    /// The field the value appeared under.
    pub field: String,
    /// The request that returned it, for example `GET /api/patients`.
    pub request: String,
    /// The gateway request id; null for values learned before a restart.
    pub request_id: Option<String>,
    /// When the response was observed, Unix milliseconds.
    pub at_millis: Option<u64>,
    /// The response position the value came from: method, route template and
    /// the field path, for example `GET /api/appointments [].doc_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
    /// The kind of object the object map gives that response position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Where `object` came from; see [`TraceValue::object_from`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_from: Option<ObjectFrom>,
    /// The tier the map gives that response position, when it gives one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// How sure the map is of `tier`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<Reliability>,
}

/// Where a recorded object kind came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectFrom {
    /// A confirmed entry of the site's object map.
    Map,
}

/// One field of a response's structure: where it sits and what it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeField {
    /// The field path: `[].doc_id`, `attachments[].doc_id`, or `$` for a bare
    /// scalar. Array items are `[]`.
    pub path: String,
    /// `string`, `number`, `boolean` or `null`.
    #[serde(rename = "type")]
    pub kind: String,
}

/// Most fields a response structure records; the first in path order are kept.
pub const SHAPE_FIELDS_MAX: usize = 64;

/// The session context a decision was made against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSession {
    /// Seconds since the session was first seen.
    pub age_seconds: u64,
    /// Values the session has seen.
    pub known_values: usize,
    /// Entry paths the session passed, with the request that first passed each.
    /// Present on Jev records only, matching what `state` carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries_passed: Option<Vec<TraceEntry>>,
    /// The latest requests of the session, oldest first. Present on Jev
    /// records only; the trim level says how many of them `state` carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent: Option<Vec<TraceRecent>>,
    /// Who the session was when the decision was made, as the site's identity positions
    /// said (docs/07 section 7.4.3). Absent when the site declares none, or the session has
    /// shown none, so records of such sites are written as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<TraceIdentity>,
    /// The login response whose values this session took when its credential set it up
    /// (docs/01 section 1.7, JSON-credential sites). Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_request_id: Option<String>,
    /// Why the credential that set this session up took no login response's values
    /// (docs/01 section 1.7). Absent when it took them, or when a response set the session up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_unbound: Option<LoginUnbound>,
}

/// What the site's function table says about one request (docs/07 section 7.9.18). Written only when
/// the table decides the request: it names an administrator-only function, or it does not know the
/// request's function on a site that asks about unknown ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFunction {
    /// The function the request is looked up as: the upper-case transport method, one space, and the
    /// route template of the path with the session credential redacted.
    pub key: String,
    /// The function of the table the request reaches, when that function is administrator-only. It can
    /// differ from `key`: an `{id}` covers the request, a method override or an escaped slash names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    /// The tier of that function. Only `admin` is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// `over_privilege` when a session that is not an administrator's reached that function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<Attempt>,
    /// `false` when the table does not list the function and the site asks about unknown functions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known: Option<bool>,
}

/// Why a credential that set a session up took no login response's values (docs/01 section 1.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginUnbound {
    /// Two held logins carry the credential, so neither is taken.
    #[serde(rename = "login_ambiguous")]
    Ambiguous,
    /// The held login that carries the credential has expired.
    #[serde(rename = "login_expired")]
    Expired,
    /// No held login carries the credential.
    #[serde(rename = "login_unmatched")]
    Unmatched,
}

/// The identity a session showed. The user and the organization are labels of keyed
/// hashes, never the ids; the role is its label (see `role_label` in the object map).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceIdentity {
    /// Label of the keyed hash of the user id: 16 hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Label of the keyed hash of the organization id: 16 hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// The role the session holds, for example `admin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// An entry the session passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEntry {
    /// The entry path.
    pub path: String,
    /// When the session first passed it, Unix milliseconds.
    pub at_millis: Option<u64>,
    /// The request that passed it.
    pub request_id: Option<String>,
}

/// A request the session made recently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRecent {
    /// HTTP method.
    pub method: String,
    /// Path without query.
    pub path: String,
    /// Origin status.
    pub status: u16,
    /// The request id.
    pub request_id: Option<String>,
    /// When the response was observed, Unix milliseconds.
    pub at_millis: Option<u64>,
}

/// Durations of one request, in milliseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    /// From the request headers arriving to the response being written.
    pub total_ms: Option<u32>,
    /// Time spent judging, Jev included.
    pub judge_ms: u32,
    /// From the upstream request starting to its response headers arriving.
    pub origin_ms: Option<u32>,
}

/// What the origin's response taught the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationSummary {
    /// The response's `Content-Type`.
    pub content_type: Option<String>,
    /// Response body bytes.
    pub bytes: u64,
    /// `json`, `html`, or `skipped`.
    pub observed: Observed,
    /// Why the body was not observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip: Option<Skip>,
    /// Values found in the response.
    pub values: usize,
    /// Of those, values the session had not seen before.
    pub new_values: usize,
    /// The most frequent field names, up to twelve. No values are kept.
    pub fields: Vec<FieldCount>,
    /// The label of the session the response issued, when it issued one.
    pub issued_session: Option<String>,
    /// The response let the session pass an entry it had not passed before.
    pub entry_passed: bool,
    /// The request would have been refused but was forwarded (observe mode).
    pub after_would_block: bool,
    /// The response's structure, reported only when this route's structure is
    /// new or differs from the last one reported. Field paths and types, never
    /// values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<Vec<ShapeField>>,
    /// Keyed fingerprints of the values the response showed, per response
    /// position (`GET /api/appointments [].doc_id`): at most
    /// [`FINGERPRINTS_PER_SLOT_MAX`] per position, the smallest ones, and at most
    /// [`FINGERPRINT_SLOTS_MAX`] positions. Each is 16 hex digits of a hash keyed
    /// per site, so the same value fingerprints alike in every session of one
    /// site and apart in another. The values themselves are not kept.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fingerprints: BTreeMap<String, Vec<String>>,
    /// A suspected attribute-level over-exposure ([`Exposure`], W6): the response showed a
    /// user-class object the session does not own, next to sensitive attributes. Observe only:
    /// the response is forwarded as it is. Absent when the response showed none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<Exposure>,
    /// A JSON login response held until a credential takes its values (docs/01 section 1.7):
    /// how many values it holds. Absent when the response was not held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_values: Option<usize>,
}

impl ObservationSummary {
    /// A summary with nothing learned yet.
    #[must_use]
    pub fn new(content_type: Option<String>, bytes: u64, observed: Observed) -> Self {
        Self {
            content_type,
            bytes,
            observed,
            skip: None,
            values: 0,
            new_values: 0,
            fields: Vec::new(),
            issued_session: None,
            entry_passed: false,
            after_would_block: false,
            shape: None,
            fingerprints: BTreeMap::new(),
            exposure: None,
            pending_values: None,
        }
    }
}

/// Most user-class positions one [`Exposure`] lists.
pub const EXPOSURE_USERS_MAX: usize = 4;
/// Most sensitive attributes one [`Exposure`] lists.
pub const EXPOSURE_ATTRIBUTES_MAX: usize = 8;

/// A suspected attribute-level over-exposure (W6, docs/07 section 7.9.17): the response showed a
/// user-class object that is not the session's own, and sensitive attributes such as phone
/// numbers, emails or ID numbers. Only positions and kinds are kept, never values. This is an
/// alert: the request is judged and forwarded as before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposure {
    /// Positions of the user-class objects the session does not own, sorted, at most
    /// [`EXPOSURE_USERS_MAX`].
    pub users: Vec<String>,
    /// The sensitive attributes the response showed, sorted, at most
    /// [`EXPOSURE_ATTRIBUTES_MAX`].
    pub attributes: Vec<ExposedAttribute>,
    /// Whether either list was cut at its limit.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

/// One sensitive attribute a response showed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExposedAttribute {
    /// The position, `GET /api/comments comments[].author.phone`.
    pub slot: String,
    /// What the attribute is.
    pub kind: ExposureKind,
    /// How the gateway recognised it.
    pub by: ExposureBasis,
}

/// The kinds of sensitive attribute the alert recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureKind {
    /// A mobile phone number.
    Phone,
    /// An email address.
    Email,
    /// A resident ID number.
    IdCard,
}

/// How a sensitive attribute was recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureBasis {
    /// By the field's name.
    Name,
    /// By the shape of the value.
    Format,
}

/// How the response body was treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observed {
    /// Read as JSON.
    Json,
    /// Read as HTML.
    Html,
    /// Not read.
    Skipped,
}

/// Why a response body was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Skip {
    /// The status is not 2xx.
    Status,
    /// The content type is neither JSON nor HTML.
    ContentType,
    /// The response is compressed, so it cannot be read.
    Compressed,
    /// The body is larger than the observation limit.
    TooLarge,
    /// The request was a HEAD, which has no body.
    Head,
    /// The path is a bypass path, which is never observed.
    Bypass,
    /// The request was refused before it reached the origin.
    NotForwarded,
}

/// How often a field name occurred in a response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldCount {
    /// The field name.
    pub field: String,
    /// Occurrences in the response.
    pub count: usize,
}

// serde hands `skip_serializing_if` a reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(at: &str, text: &str, inert: bool, sources: usize) -> TraceValue {
        TraceValue {
            at: at.to_owned(),
            at_len: None,
            key: None,
            value: text.to_owned(),
            len: None,
            clipped: false,
            kind: "route".to_owned(),
            inert,
            seen: true,
            verified: false,
            sources: (0..sources)
                .map(|i| TraceSource {
                    field: format!("field{i}"),
                    request: "GET /api/x".to_owned(),
                    request_id: Some("req_0".to_owned()),
                    at_millis: Some(1),
                    slot: None,
                    object: None,
                    object_from: None,
                    tier: None,
                    reliability: None,
                })
                .collect(),
            slot: None,
            object: None,
            object_from: None,
            public_access: None,
            attempt: None,
            unplaced: false,
        }
    }

    fn encoded(trace: &Trace) -> usize {
        serde_json::to_vec(trace).unwrap().len()
    }

    #[test]
    fn a_small_trace_is_left_alone() {
        let mut trace = Trace::new();
        trace.values.push(value("path[0]", "api", true, 1));
        let before = trace.clone();
        trace.fit();
        assert_eq!(trace, before);
    }

    #[test]
    fn inert_values_go_first_and_keep_every_source() {
        let mut trace = Trace::new();
        trace.values = (0..40)
            .map(|i| value(&format!("path[{i}]"), &"r".repeat(300), true, 0))
            .collect();
        trace
            .values
            .extend((0..10).map(|i| value(&format!("query.k{i}"), &"v".repeat(200), false, 3)));
        trace.fit();
        assert!(encoded(&trace) <= TRACE_BYTES_MAX);
        assert!(trace.trimmed);
        assert_eq!(trace.values.len(), 10);
        assert!(trace.values.iter().all(|value| !value.inert));
        assert!(trace.values.iter().all(|value| value.sources.len() == 3));
    }

    #[test]
    fn sources_go_before_the_text_is_cut() {
        let mut trace = Trace::new();
        trace.values = (0..40)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(200), false, 3))
            .collect();
        assert!(
            encoded(&trace) > TRACE_BYTES_MAX,
            "the fixture must need trimming"
        );
        trace.fit();
        assert!(encoded(&trace) <= TRACE_BYTES_MAX);
        assert!(trace.trimmed);
        assert_eq!(trace.values.len(), 40);
        assert!(trace.values.iter().all(|value| value.sources.len() == 1));
        assert!(trace.values.iter().all(|value| value.value.len() == 200));
        assert!(!trace.values_truncated);
    }

    #[test]
    fn values_go_last_and_say_so() {
        let mut trace = Trace::new();
        trace.values = (0..200)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(256), false, 3))
            .collect();
        trace.fit();
        assert!(encoded(&trace) <= TRACE_BYTES_MAX);
        assert!(trace.values_truncated);
        assert!(trace.values.is_empty());
        assert!(trace.trimmed);
    }

    fn fingerprinted(slots: usize, key_chars: usize) -> ObservationSummary {
        let mut response = ObservationSummary::new(None, 0, Observed::Json);
        for slot in 0..slots {
            let key = format!("GET /{} items[].id{slot}", "r".repeat(key_chars));
            let digests = (0..FINGERPRINTS_PER_SLOT_MAX)
                .map(|digest| format!("{:016x}", slot * 8 + digest))
                .collect();
            response.fingerprints.insert(key, digests);
        }
        response
    }

    #[test]
    fn learning_detail_goes_before_the_values_when_that_is_enough() {
        let mut trace = Trace::new();
        trace.values = (0..80)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(256), false, 0))
            .collect();
        trace.response = Some(fingerprinted(FINGERPRINT_SLOTS_MAX, 400));
        assert!(
            encoded(&trace) > TRACE_BYTES_MAX,
            "the fixture must need trimming"
        );
        trace.fit();
        assert!(encoded(&trace) <= TRACE_BYTES_MAX);
        assert!(trace.trimmed);
        assert_eq!(
            trace.values.len(),
            80,
            "the values are the evidence and stay"
        );
        assert!(!trace.values_truncated);
        let response = trace.response.expect("the response summary stays");
        assert!(response.fingerprints.is_empty());
    }

    #[test]
    fn the_values_go_before_the_session_lists_when_learning_is_not_enough() {
        let mut trace = Trace::new();
        trace.values = (0..200)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(256), false, 0))
            .collect();
        trace.session = Some(TraceSession {
            age_seconds: 1,
            known_values: 1,
            identity: None,
            login_request_id: None,
            login_unbound: None,
            entries_passed: None,
            recent: Some(vec![TraceRecent {
                method: "GET".to_owned(),
                path: "/api/x".to_owned(),
                status: 200,
                request_id: None,
                at_millis: None,
            }]),
        });
        trace.fit();
        assert!(encoded(&trace) <= TRACE_BYTES_MAX);
        assert!(trace.values.is_empty());
        assert!(trace.values_truncated);
        let session = trace.session.expect("the session stays");
        assert!(session.recent.is_some(), "the recent requests stay");
    }

    #[test]
    fn detail_at_its_limits_still_fits_within_the_limit() {
        let path = "p".repeat(TRACE_PATH_BYTES_MAX);
        let mut trace = Trace::new();
        trace.session = Some(TraceSession {
            age_seconds: 1,
            known_values: 1,
            identity: None,
            login_request_id: None,
            login_unbound: None,
            entries_passed: Some(
                (0..16)
                    .map(|index| TraceEntry {
                        path: path.clone(),
                        at_millis: Some(1),
                        request_id: Some(format!("req_{index:032x}")),
                    })
                    .collect(),
            ),
            recent: Some(
                (0..10)
                    .map(|index| TraceRecent {
                        method: "GET".to_owned(),
                        path: path.clone(),
                        status: 200,
                        request_id: Some(format!("req_{index:032x}")),
                        at_millis: Some(1),
                    })
                    .collect(),
            ),
        });
        let mut response = fingerprinted(FINGERPRINT_SLOTS_MAX, 400);
        response.content_type = Some("c".repeat(8 * 1024));
        response.fields = (0..12)
            .map(|index| FieldCount {
                field: format!("{index:0>32}"),
                count: 1,
            })
            .collect();
        response.shape = Some(
            (0..SHAPE_FIELDS_MAX)
                .map(|index| ShapeField {
                    path: format!("{index:0>128}"),
                    kind: "string".to_owned(),
                })
                .collect(),
        );
        trace.response = Some(response);
        assert!(
            encoded(&trace) > TRACE_BYTES_MAX,
            "the fixture must need trimming"
        );
        trace.fit();
        assert!(encoded(&trace) <= TRACE_BYTES_MAX);
        assert!(trace.trimmed);
        assert!(!trace.values_truncated, "there were no values to clear");
        let response = trace.response.expect("the response summary stays");
        assert!(response.shape.is_none() && response.fingerprints.is_empty());
        assert!(response.fields.is_empty() && response.content_type.is_none());
        let session = trace.session.expect("the session stays");
        assert!(session.recent.is_none() && session.entries_passed.is_none());
    }

    #[test]
    fn the_worst_case_fits_and_what_is_left_is_small() {
        // Every field at the largest the gateway writes: the longest patterns the
        // configuration allows, a key too long to keep, and detail at its limits.
        let mut trace = Trace::new();
        trace.entry = Some(format!("/{}", "e".repeat(255)));
        trace.bypass = Some(format!("/{}", "b".repeat(255)));
        trace.cache_source = Some(format!("req_{:032x}", u128::MAX));
        trace.refused = Some("unknown_site".to_owned());
        trace.upstream_error = Some("timeout".to_owned());
        let mut long_key = value("body.key", &"v".repeat(256), false, 3);
        long_key.key = Some("k".repeat(40 * 1024));
        trace.values = std::iter::once(long_key)
            .chain((0..40).map(|i| value(&format!("query.k{i}"), &"v".repeat(256), false, 3)))
            .collect();
        trace.session = Some(TraceSession {
            age_seconds: u64::MAX,
            known_values: usize::MAX,
            identity: Some(TraceIdentity {
                user: Some("u".repeat(16)),
                org: Some("o".repeat(16)),
                role: Some("r".repeat(32)),
            }),
            login_request_id: Some(format!("req_{:032x}", u128::MAX)),
            login_unbound: Some(LoginUnbound::Ambiguous),
            entries_passed: Some(
                (0..16)
                    .map(|index| TraceEntry {
                        path: "p".repeat(TRACE_PATH_BYTES_MAX),
                        at_millis: Some(u64::MAX),
                        request_id: Some(format!("req_{index:032x}")),
                    })
                    .collect(),
            ),
            recent: Some(
                (0..10)
                    .map(|index| TraceRecent {
                        method: "GET".to_owned(),
                        path: "p".repeat(TRACE_PATH_BYTES_MAX),
                        status: u16::MAX,
                        request_id: Some(format!("req_{index:032x}")),
                        at_millis: Some(u64::MAX),
                    })
                    .collect(),
            ),
        });
        let mut response = fingerprinted(FINGERPRINT_SLOTS_MAX, 2048);
        response.content_type = Some("c".repeat(8 * 1024));
        response.skip = Some(Skip::TooLarge);
        response.issued_session = Some(format!("{:016x}", u64::MAX));
        response.fields = (0..12)
            .map(|index| FieldCount {
                field: format!("{index:0>1024}"),
                count: 1,
            })
            .collect();
        response.shape = Some(
            (0..SHAPE_FIELDS_MAX)
                .map(|index| ShapeField {
                    path: format!("{index:0>1024}"),
                    kind: "string".to_owned(),
                })
                .collect(),
        );
        trace.response = Some(response);
        assert!(
            encoded(&trace) > TRACE_BYTES_MAX,
            "the fixture must need trimming"
        );
        trace.fit();
        assert!(
            encoded(&trace) <= TRACE_BYTES_MAX,
            "the written trace is {} bytes",
            encoded(&trace)
        );
        assert!(trace.trimmed && trace.values_truncated && trace.values.is_empty());
        assert!(
            trace.entry.is_some() && trace.bypass.is_some(),
            "the patterns stay"
        );
        let response = trace.response.as_ref().expect("the response summary stays");
        assert!(response.shape.is_none() && response.fingerprints.is_empty());
        assert!(response.fields.is_empty() && response.content_type.is_none());
        let session = trace.session.as_ref().expect("the session stays");
        assert!(session.recent.is_none() && session.entries_passed.is_none());
        assert!(
            encoded(&trace) <= 2 * 1024,
            "what is left is {} bytes",
            encoded(&trace)
        );
    }

    #[test]
    fn fingerprints_stay_out_of_summaries_that_have_none() {
        let plain = ObservationSummary::new(None, 0, Observed::Json);
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("fingerprints"));
        let old: ObservationSummary = serde_json::from_str(&json).unwrap();
        assert!(old.fingerprints.is_empty());

        let mut with = plain;
        with.fingerprints.insert(
            "GET /api/patients items[].id".to_owned(),
            vec!["0123456789abcdef".to_owned()],
        );
        let json = serde_json::to_string(&with).unwrap();
        assert!(
            json.contains(
                r#""fingerprints":{"GET /api/patients items[].id":["0123456789abcdef"]}"#
            )
        );
        let back: ObservationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, with);
    }

    #[test]
    fn a_legacy_row_without_trace_reads_as_version_zero() {
        let row = r#"{"at_millis":1,"site":"s","request_id":"r","session":"abcd","method":"GET",
            "path":"/","status":200,"decision_path":"fast_allow","outcome":"allowed","jev":null}"#;
        let record: crate::context::DecisionRecord = serde_json::from_str(row).unwrap();
        assert_eq!(record.trace.v, 0);
        assert_eq!(record.site.as_deref(), Some("s"));
        assert!(record.context.is_none());
    }

    #[test]
    fn positions_stay_out_of_rows_that_do_not_have_them() {
        let mut row = value("path[1]", "5", false, 0);
        let plain = serde_json::to_string(&row).unwrap();
        assert!(!plain.contains("slot") && !plain.contains("object"));
        row.slot = Some("GET /doctor/{id} path[1]".to_owned());
        row.object = Some("doctor".to_owned());
        row.object_from = Some(ObjectFrom::Map);
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains(r#""object_from":"map""#));
        let back: TraceValue = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);
        let old: TraceValue = serde_json::from_str(&plain).unwrap();
        assert_eq!(old.slot, None);
    }

    #[test]
    fn an_attempt_and_a_public_access_are_written_only_when_present() {
        let mut row = value("path[2]", "7005", false, 1);
        let plain = serde_json::to_string(&row).unwrap();
        assert!(!plain.contains("attempt") && !plain.contains("public_access"));
        row.public_access = Some(PublicAccess {
            accepts: false,
            reliability: Reliability::High,
        });
        row.attempt = Some(Attempt::OverPrivilege);
        let json = serde_json::to_string(&row).unwrap();
        assert!(
            json.contains(r#""public_access":{"accepts":false,"reliability":"high"}"#),
            "{json}"
        );
        assert!(json.contains(r#""attempt":"over_privilege""#), "{json}");
        let back: TraceValue = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);
        assert_eq!(Attempt::OverPrivilege.as_str(), "over_privilege");
    }

    #[test]
    fn a_trace_function_is_written_only_when_present_and_reads_back_equal() {
        let plain = serde_json::to_string(&Trace::new()).unwrap();
        assert!(!plain.contains("function"), "{plain}");
        let read: Trace = serde_json::from_str(&plain).unwrap();
        assert_eq!(read.function, None);

        let mut row = Trace::new();
        row.function = Some(TraceFunction {
            key: "POST /api/admin/export".to_owned(),
            entry: Some("POST /api/admin/export".to_owned()),
            tier: Some("admin".to_owned()),
            attempt: Some(Attempt::OverPrivilege),
            known: None,
        });
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains(r#""attempt":"over_privilege""#), "{json}");
        assert!(!json.contains("known"), "{json}");
        let back: Trace = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);

        let unknown = TraceFunction {
            key: "GET /metrics".to_owned(),
            entry: None,
            tier: None,
            attempt: None,
            known: Some(false),
        };
        assert_eq!(
            serde_json::to_string(&unknown).unwrap(),
            r#"{"key":"GET /metrics","known":false}"#
        );
    }

    #[test]
    fn a_shape_field_serializes_its_type_under_type() {
        let field = ShapeField {
            path: "[].doc_id".to_owned(),
            kind: "number".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&field).unwrap(),
            r#"{"path":"[].doc_id","type":"number"}"#
        );
    }

    #[test]
    fn an_unbound_login_is_written_under_its_reason_and_only_when_present() {
        let mut session = TraceSession {
            age_seconds: 1,
            known_values: 0,
            identity: None,
            login_request_id: None,
            login_unbound: None,
            entries_passed: None,
            recent: None,
        };
        let json = serde_json::to_string(&session).unwrap();
        assert!(!json.contains("login_"), "{json}");
        session.login_unbound = Some(LoginUnbound::Expired);
        let json = serde_json::to_string(&session).unwrap();
        assert!(
            json.contains(r#""login_unbound":"login_expired""#),
            "{json}"
        );
        let back: TraceSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back, session);
    }
}
