//! The judge's share of a decision trace (docs/07 sections 7.4.3 and 7.4.4):
//! request values as the session saw them, the links to the requests that
//! showed them, and the query string with secrets removed.

use xshield_core::context::trace::{TRACE_PATH_BYTES_MAX, VALUE_CHARS_MAX};
use xshield_core::context::{ObjectFrom, TraceEntry, TraceRecent, TraceSource, TraceValue};

use crate::context::{EntryPass, Origin, Recent, request_text};
use crate::slots::origin_slot;
use crate::state::{REDACTED, is_secret_name};
use crate::values::{RequestValue, value_kind};

/// Largest query string a row keeps, in bytes.
pub const QUERY_BYTES_MAX: usize = 2 * 1024;
/// Most sources shown per value.
const SOURCES_SHOWN: usize = 3;

/// Where a request value sits and what the object map says about it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Place {
    /// The position the value sits at (see [`crate::slots::request_slot`]).
    pub slot: String,
    /// The kind of object the map gives that position.
    pub object: Option<String>,
    /// The kind of object the map gives each origin's position, in the order of
    /// the ranked origins.
    pub origin_objects: Vec<Option<String>>,
}

/// One request value as the trace shows it. `ranked` is the session's origins
/// for the value in the order the state lists them (most useful last).
#[must_use]
pub fn value_entry(
    value: &RequestValue,
    seen: bool,
    verified: bool,
    ranked: &[&Origin],
    credential: Option<&str>,
    secret_words: &[String],
    place: Place,
) -> TraceValue {
    let key = value.key.as_deref();
    let (text, len, clipped) = shown(&value.at, key, &value.value, credential, secret_words);
    TraceValue {
        at: value.at.clone(),
        key: value.key.clone(),
        value: text,
        len,
        clipped,
        kind: value_kind(&value.at, key, &value.value).to_owned(),
        inert: value.inert,
        seen,
        verified,
        // The state shows the last origins first; the trace shows the same ones
        // in the same order.
        sources: ranked
            .iter()
            .enumerate()
            .rev()
            .take(SOURCES_SHOWN)
            .map(|(index, origin)| {
                let object = place.origin_objects.get(index).cloned().flatten();
                TraceSource {
                    field: origin.field.clone(),
                    request: origin.request.clone(),
                    request_id: request_text(origin.request_id),
                    at_millis: nonzero(origin.at_ms),
                    slot: origin_slot(origin),
                    object_from: object.as_ref().map(|_| ObjectFrom::Map),
                    object,
                }
            })
            .collect(),
        slot: Some(place.slot),
        object_from: place.object.as_ref().map(|_| ObjectFrom::Map),
        object: place.object,
    }
}

/// The text a value is shown as: `<redacted>` for a secret (with its length),
/// clipped to [`VALUE_CHARS_MAX`] characters otherwise (with its length).
fn shown(
    at: &str,
    key: Option<&str>,
    value: &str,
    credential: Option<&str>,
    secret_words: &[String],
) -> (String, Option<usize>, bool) {
    let length = value.chars().count();
    let secret = key.is_some_and(|key| is_secret_name(key, secret_words))
        || is_secret_name(at, secret_words)
        || credential
            .is_some_and(|credential| !credential.is_empty() && value.contains(credential));
    if secret {
        (REDACTED.to_owned(), Some(length), false)
    } else if length > VALUE_CHARS_MAX {
        (
            value.chars().take(VALUE_CHARS_MAX).collect(),
            Some(length),
            true,
        )
    } else {
        (value.to_owned(), None, false)
    }
}

/// The query string with every secret pair redacted, pair by pair, and cut to
/// [`QUERY_BYTES_MAX`] bytes. A pair is secret when its name is one of the
/// secret words or it carries the session credential.
#[must_use]
pub fn redacted_query(query: &str, credential: Option<&str>, secret_words: &[String]) -> String {
    let carries_credential = |text: &str| {
        credential.is_some_and(|credential| !credential.is_empty() && text.contains(credential))
    };
    let mut out = String::with_capacity(query.len().min(QUERY_BYTES_MAX));
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        if carries_credential(pair) {
            out.push_str(REDACTED);
        } else if is_secret_name(name, secret_words) {
            out.push_str(name);
            out.push('=');
            out.push_str(REDACTED);
        } else {
            out.push_str(pair);
        }
    }
    cut(out, QUERY_BYTES_MAX)
}

fn cut(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// An entry the session passed, as the trace lists it. Its path is cut to
/// [`TRACE_PATH_BYTES_MAX`] bytes, since a request path has no length limit.
#[must_use]
pub fn entry_trace(pass: &EntryPass) -> TraceEntry {
    TraceEntry {
        path: cut(pass.path.clone(), TRACE_PATH_BYTES_MAX),
        at_millis: nonzero(pass.at_ms),
        request_id: request_text(pass.request_id),
    }
}

/// A recent request of the session, as the trace lists it. Its path is cut the
/// same way as an entry's.
#[must_use]
pub fn recent_trace(recent: &Recent) -> TraceRecent {
    TraceRecent {
        method: recent.method.clone(),
        path: cut(recent.path.clone(), TRACE_PATH_BYTES_MAX),
        status: recent.status,
        request_id: request_text(recent.request_id),
        at_millis: nonzero(recent.at_ms),
    }
}

/// `None` for the unknown value 0.
fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_pairs_are_redacted_and_the_rest_is_kept() {
        let words = ["ssn".to_owned()];
        let query = "q=a%20b&password=hunter2&ssn=123&next=/home?sid=SESS1&x";
        assert_eq!(
            redacted_query(query, Some("SESS1"), &words),
            "q=a%20b&password=<redacted>&ssn=<redacted>&<redacted>&x"
        );
    }

    #[test]
    fn long_queries_are_cut_on_a_character_boundary() {
        let query = format!("q={}", "é".repeat(QUERY_BYTES_MAX));
        let cut = redacted_query(&query, None, &[]);
        assert!(cut.len() <= QUERY_BYTES_MAX);
        assert!(cut.is_char_boundary(cut.len()));
    }

    #[test]
    fn values_are_clipped_and_secrets_hidden_with_their_length() {
        let (text, len, clipped) = shown("query.q", Some("q"), &"a".repeat(300), None, &[]);
        assert_eq!(text.chars().count(), VALUE_CHARS_MAX);
        assert_eq!((len, clipped), (Some(300), true));
        let (text, len, clipped) = shown("body.token", Some("token"), "t0k", None, &[]);
        assert_eq!((text.as_str(), len, clipped), (REDACTED, Some(3), false));
    }

    #[test]
    fn session_paths_are_cut_and_short_ones_kept() {
        let long = format!("/{}", "a".repeat(5000));
        let pass = EntryPass {
            path: long.clone(),
            at_ms: 1,
            request_id: 2,
        };
        assert_eq!(entry_trace(&pass).path.len(), TRACE_PATH_BYTES_MAX);
        let recent = Recent {
            method: "GET".to_owned(),
            path: long,
            status: 200,
            request_id: 2,
            at_ms: 1,
        };
        assert_eq!(recent_trace(&recent).path.len(), TRACE_PATH_BYTES_MAX);
        let short = Recent {
            path: "/api/x".to_owned(),
            ..recent
        };
        assert_eq!(recent_trace(&short).path, "/api/x");
    }

    #[test]
    fn a_cut_session_path_stays_on_a_character_boundary() {
        let pass = EntryPass {
            path: "é".repeat(200),
            at_ms: 1,
            request_id: 2,
        };
        let cut = entry_trace(&pass).path;
        assert!(cut.len() <= TRACE_PATH_BYTES_MAX);
        assert!(cut.chars().all(|letter| letter == 'é'));
    }
}
