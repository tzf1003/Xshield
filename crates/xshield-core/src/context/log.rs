//! The decision log row (docs/03 section 3.4).
//!
//! One row per judged request. The gateway produces it, the control plane stores
//! and queries it. Nothing here is an authorization input.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Which step of docs/01 section 1.4 settled the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionPath {
    /// Every request value was already shown to this session (step 4).
    FastAllow,
    /// The same request was judged safe within the cache window (step 5).
    CachedAllow,
    /// Jev judged the request safe (step 6).
    JevAllow,
    /// Jev judged the request an out-of-path access or an attack (step 6).
    JevDeny,
    /// Jev failed, timed out, answered UNKNOWN or was rate limited (step 7).
    JevUnavailable,
    /// No session credential on a non-entry path (step 2).
    NoSession,
}

/// What the gateway did with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Forwarded after a positive judgement.
    Allowed,
    /// Refused with 403 (or 401 without a session).
    Blocked,
    /// Observe mode: the request would have been refused but was forwarded.
    WouldBlock,
    /// Forwarded without a judgement because `on_jev_unavailable` is `allow`.
    Unjudged,
}

/// What was sent to Jev and what came back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JevRecord {
    /// The redacted `state` document that was sent.
    pub state: String,
    /// Probabilities of the `access` question, keyed by option.
    pub access: BTreeMap<String, f64>,
    /// Probabilities of the `attack` question, keyed by option.
    pub attack: BTreeMap<String, f64>,
    /// Round trip time in milliseconds.
    pub millis: u32,
}

/// One decision log row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// Unix time in milliseconds.
    pub at_millis: u64,
    /// Site name.
    pub site: String,
    /// Gateway-assigned request id.
    pub request_id: String,
    /// First 8 hex digits of the session key; never the credential.
    pub session: String,
    /// HTTP method.
    pub method: String,
    /// Request path without query.
    pub path: String,
    /// Origin status, when the request was forwarded and answered.
    pub status: Option<u16>,
    /// The deciding step.
    pub decision_path: DecisionPath,
    /// What the gateway did.
    pub outcome: Outcome,
    /// Present when Jev was called.
    pub jev: Option<JevRecord>,
}
