//! The decision trace: the evidence behind one decision, and the links that
//! let the console follow it to the requests that supplied the evidence
//! (docs/07 section 7.4.3).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Largest serialized trace; [`Trace::fit`] trims anything bigger.
pub const TRACE_BYTES_MAX: usize = 16 * 1024;
/// Longest value text kept before it is clipped.
pub const VALUE_CHARS_MAX: usize = 256;
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

    /// Trims the trace until it fits [`TRACE_BYTES_MAX`], in this order: the
    /// inert values go, then every value keeps one source, then values are cut
    /// to 64 characters, and last the values themselves go. Sets `trimmed`
    /// when anything was removed.
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
            self.values.clear();
            self.values_truncated = true;
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
    /// Location, for example `path[2]` or `query.doctor`.
    pub at: String,
    /// Key it travels under, when it has one.
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
        }
    }
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
                })
                .collect(),
            slot: None,
            object: None,
            object_from: None,
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
}
