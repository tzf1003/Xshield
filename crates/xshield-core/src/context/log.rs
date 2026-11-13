//! The decision log row (docs/03 section 3.4, docs/07 section 7.4).
//!
//! One row per request the gateway handled. The gateway produces it, the
//! control plane stores and queries it. Nothing here is an authorization input.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::route::Api;
use super::trace::Trace;

/// Which step settled the request: docs/01 section 1.4, or one of the early
/// refusals and bypasses of docs/07 section 7.4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionPath {
    /// The path matches a bypass pattern and is forwarded unjudged.
    Bypass,
    /// The body could not be judged (too large or of unknown size); refused with 413.
    BodyNotInspectable,
    /// The host belongs to no site; refused with 404.
    UnknownSite,
    /// Every request value was already shown to this session (step 4).
    FastAllow,
    /// The same request was judged safe within the cache window (step 5).
    CachedAllow,
    /// Jev judged the request safe (step 6).
    JevAllow,
    /// Jev judged the request an out-of-path access or an attack (step 6).
    JevDeny,
    /// Jev failed, timed out, answered UNKNOWN, or was not asked (step 7). A spent call limit is
    /// refused with 429 and a state too large with 403, whatever `on_jev_unavailable` says; the
    /// other failures follow `on_jev_unavailable`.
    JevUnavailable,
    /// No session credential on a non-entry path (step 2).
    NoSession,
}

/// What the gateway did with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Forwarded after a positive judgement, or as a bypass.
    Allowed,
    /// Refused with 403 (or 401 without a session, or 429 when the Jev calls of the session or
    /// address for the minute are used up), or 404 and 413.
    Blocked,
    /// Observe mode: the request would have been refused but was forwarded.
    WouldBlock,
    /// Forwarded without a judgement because `on_jev_unavailable` is `allow`.
    Unjudged,
}

/// What the two Jev answers amount to (docs/02 section 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conclusion {
    /// Both questions came out safe.
    Allow,
    /// `access` is DENY or `attack` is ATTACK.
    Deny,
    /// No denial, but a question was UNKNOWN or tied.
    Unknown,
}

/// Where the context a decision was made against came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    /// The session credential.
    Session,
    /// The client address, for an entry request without a credential.
    Address,
}

/// What was sent to Jev and what came back (docs/07 section 7.5.1).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct JevRecord {
    /// The redacted `state` that was sent; `None` when none was built or sent.
    pub state: Option<String>,
    /// The instruction version: `jq_` and 16 hex digits.
    pub prompt: String,
    /// The model name on the wire.
    pub model: String,
    /// `gateway`, `direct`, or `custom` for a private endpoint.
    pub route: String,
    /// The timeout this call used, in milliseconds.
    pub timeout_ms: u32,
    /// The trim level of `state`, 0 to 4; `None` when no state was built.
    pub trim: Option<u8>,
    /// Size of the whole request body sent to the provider.
    pub request_bytes: Option<u32>,
    /// The provider's HTTP status; `None` for timeouts and transport failures.
    pub http_status: Option<u16>,
    /// The provider's reply, decoded leniently, at most 8 KiB.
    pub response: Option<String>,
    /// The reply's `usage` object, as it came.
    pub usage: Option<serde_json::Value>,
    /// Probabilities of the `access` question, keyed by option.
    pub access: BTreeMap<String, f64>,
    /// Probabilities of the `attack` question, keyed by option.
    pub attack: BTreeMap<String, f64>,
    /// The conclusion of a usable answer.
    pub conclusion: Option<Conclusion>,
    /// Round trip time in milliseconds.
    pub millis: u32,
    /// Stable failure code (`JEV_TIMEOUT`, `JEV_UNKNOWN`, ...) when no usable
    /// answer came back.
    pub failure: Option<String>,
}

/// One decision log row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// Unix time in milliseconds the request reached the gateway.
    pub at_millis: u64,
    /// Gateway-assigned request id, `req_` and 32 hex digits.
    pub request_id: String,
    /// Site name; `None` when the host belongs to no site.
    pub site: Option<String>,
    /// Version of the site configuration the gateway judged with.
    #[serde(default)]
    pub site_version: Option<i64>,
    /// Gateway instance name.
    #[serde(default)]
    pub edge: String,
    /// The `Host` header, lower case, at most 253 characters.
    #[serde(default)]
    pub host: String,
    /// Client address.
    #[serde(default)]
    pub client: String,
    /// Label of the session the context belongs to: 16 hex digits of the keyed
    /// session hash. Empty when the decision had no session context.
    #[serde(default)]
    pub session: String,
    /// Whether the context came from the session or from the client address.
    #[serde(default)]
    pub context: Option<ContextKind>,
    /// HTTP method.
    pub method: String,
    /// Request path without query, as sent.
    pub path: String,
    /// The path the request was judged by: `path`, followed by the interface
    /// name a route read from the request (docs/header-routes-design section 2).
    /// Without a route it equals `path`.
    #[serde(default)]
    pub logical_path: String,
    /// The interface name, or why there is none. `None` when no route covers the
    /// request.
    #[serde(default)]
    pub api: Option<Api>,
    /// Request header names: lower case, no values, at most 64 of them.
    #[serde(default)]
    pub request_headers: Vec<String>,
    /// The query string with secrets redacted, at most 2 KiB.
    #[serde(default)]
    pub query: Option<String>,
    /// Status returned to the client.
    pub status: Option<u16>,
    /// The deciding step.
    pub decision_path: DecisionPath,
    /// What the gateway did.
    pub outcome: Outcome,
    /// Why the decision was made; see docs/07 section 7.4.3.
    #[serde(default)]
    pub trace: Trace,
    /// Present when Jev was asked, or when the call was skipped because the call budget was spent or
    /// the state did not fit.
    pub jev: Option<JevRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_paths_use_their_documented_names() {
        for (path, name) in [
            (DecisionPath::Bypass, "bypass"),
            (DecisionPath::BodyNotInspectable, "body_not_inspectable"),
            (DecisionPath::UnknownSite, "unknown_site"),
            (DecisionPath::JevUnavailable, "jev_unavailable"),
        ] {
            assert_eq!(serde_json::to_value(path).unwrap(), name);
        }
    }

    #[test]
    fn a_jev_record_without_a_state_says_so() {
        let record = JevRecord {
            prompt: "jq_0000000000000000".to_owned(),
            failure: Some("JEV_CALL_LIMIT".to_owned()),
            ..JevRecord::default()
        };
        let json = serde_json::to_value(&record).unwrap();
        assert!(json["state"].is_null());
        assert_eq!(json["failure"], "JEV_CALL_LIMIT");
        let back: JevRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back, record);
    }
}
