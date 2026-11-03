//! Test calls made from the console's model page (the model page design, section
//! 2.4). Each sends one minimal request with the values on the form and reports
//! whether the answer could be read.
//!
//! The Jev probe sends a fixed state of an ordinary request that holds no real data,
//! and checks that both questions come back with probabilities (docs/02). The agent
//! probe sends a one-line prompt to an OpenAI-compatible chat completions endpoint
//! and checks that the answer is a JSON object with `ok` set to true. The model's
//! own words appear only in `detail`, as text the console shows as untrusted.

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use xshield_core::model::ApiKey;

use crate::jev::{JevFailure, JevPort, Transport, failure_code};
use crate::state::{Prompt, parse_response, request_body};

/// Longest model reply kept for display, in characters.
const DETAIL_CHARS_MAX: usize = 300;

/// The fixed state the Jev probe sends: a login followed by a look at one's own
/// profile. It holds no real data.
const JEV_PROBE_STATE: &str = r#"{"entry":{"matched":false},"session":{"age_seconds":300,"entries_passed":["/login"]},"recent":[{"method":"POST","path":"/login","status":200}],"request":{"method":"GET","path":"/api/me","values":[],"truncated":false}}"#;

/// The prompt of the agent probe.
const AGENT_PROBE_PROMPT: &str = "Reply with the JSON object {\"ok\": true} and nothing else.";

/// The outcome of one test call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The call reached the model and its answer could be read.
    pub ok: bool,
    /// Time the call took, in milliseconds.
    pub latency_ms: u64,
    /// The HTTP status the service answered, when it answered.
    pub status: Option<u16>,
    /// The stable failure code, when the call failed.
    pub failure: Option<&'static str>,
    /// The start of the service's own error text, capped. Untrusted.
    pub detail: Option<String>,
    /// Whether the answer could be read; `None` when no answer came.
    pub answer_valid: Option<bool>,
    /// A short sentence the server wrote about the answer. Never the model's words.
    pub answer_reason: Option<&'static str>,
}

impl Probe {
    fn answered(latency_ms: u64, valid: bool) -> Self {
        Self {
            ok: valid,
            latency_ms,
            status: Some(200),
            failure: None,
            detail: None,
            answer_valid: Some(valid),
            answer_reason: (!valid).then_some("能连上，但回答不能按协议解析"),
        }
    }

    fn failed(latency_ms: u64, failure: &JevFailure) -> Self {
        let (status, detail) = match failure {
            JevFailure::RateLimited { body } => (Some(429), Some(body)),
            JevFailure::Http { status, body } => (Some(*status), Some(body)),
            _ => (None, None),
        };
        Self {
            ok: false,
            latency_ms,
            status,
            failure: Some(failure_code(failure)),
            detail: detail.map(|body| capped(body)),
            answer_valid: None,
            answer_reason: None,
        }
    }
}

/// Runs the Jev probe with `port`, which must be built from the form's values.
pub async fn jev(port: &impl JevPort, timeout: Duration) -> Probe {
    let body = request_body(&port.model(), JEV_PROBE_STATE, &Prompt::new());
    let started = Instant::now();
    let reply = port.ask(body, timeout).await;
    let latency_ms = elapsed_millis(started);
    match reply {
        Ok(bytes) => Probe::answered(latency_ms, parse_response(&bytes).is_ok()),
        Err(failure) => Probe::failed(latency_ms, &failure),
    }
}

/// Runs the agent probe against `base_url` (`{base}/chat/completions` is called).
pub async fn chat(base_url: &str, api_key: &ApiKey, model: &str, timeout: Duration) -> Probe {
    let started = Instant::now();
    let outcome = call_chat(base_url, api_key, model, timeout).await;
    let latency_ms = elapsed_millis(started);
    match outcome {
        Ok(bytes) => Probe::answered(latency_ms, answer_is_json_ok(&bytes)),
        Err(failure) => Probe::failed(latency_ms, &failure),
    }
}

async fn call_chat(
    base_url: &str,
    api_key: &ApiKey,
    model: &str,
    timeout: Duration,
) -> Result<Vec<u8>, JevFailure> {
    let endpoint: http::Uri = format!("{base_url}/chat/completions")
        .parse()
        .map_err(|_| JevFailure::Transport)?;
    let body = json!({
        "model": model,
        "messages": [{ "role": "user", "content": AGENT_PROBE_PROMPT }],
        "max_tokens": 32,
        "temperature": 0,
    })
    .to_string()
    .into_bytes();
    let transport = Transport::new();
    tokio::time::timeout(timeout, transport.post(&endpoint, api_key.expose(), body))
        .await
        .unwrap_or(Err(JevFailure::Timeout))
}

/// Whether the first choice of a chat reply holds a JSON object with `ok` true.
fn answer_is_json_ok(reply: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(reply) else {
        return false;
    };
    let content = value
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .unwrap_or_default();
    serde_json::from_str::<Value>(content.trim())
        .ok()
        .and_then(|answer| answer.get("ok").and_then(Value::as_bool))
        == Some(true)
}

fn capped(body: &[u8]) -> String {
    String::from_utf8_lossy(body)
        .chars()
        .take(DETAIL_CHARS_MAX)
        .collect()
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_answer_must_be_a_json_object_with_ok_true() {
        let good = br#"{"choices":[{"message":{"content":"{\"ok\": true}"}}]}"#;
        assert!(answer_is_json_ok(good));
        let wrong = br#"{"choices":[{"message":{"content":"{\"ok\": false}"}}]}"#;
        assert!(!answer_is_json_ok(wrong));
        let prose = br#"{"choices":[{"message":{"content":"Sure, here you go."}}]}"#;
        assert!(!answer_is_json_ok(prose));
        assert!(!answer_is_json_ok(b"not json"));
    }

    #[test]
    fn a_refused_reply_keeps_its_status_and_a_capped_text() {
        let long = "x".repeat(DETAIL_CHARS_MAX + 50);
        let probe = Probe::failed(
            12,
            &JevFailure::Http {
                status: 401,
                body: long.into_bytes(),
            },
        );
        assert_eq!(probe.status, Some(401));
        assert_eq!(probe.failure, Some("JEV_HTTP_ERROR"));
        assert_eq!(
            probe.detail.map(|text| text.chars().count()),
            Some(DETAIL_CHARS_MAX)
        );
        assert!(!probe.ok);
    }

    #[test]
    fn a_timeout_has_no_status_and_no_detail() {
        let probe = Probe::failed(2000, &JevFailure::Timeout);
        assert_eq!(probe.status, None);
        assert_eq!(probe.failure, Some("JEV_TIMEOUT"));
        assert_eq!(probe.detail, None);
    }

    #[test]
    fn an_unreadable_answer_is_reached_but_not_ok() {
        let probe = Probe::answered(40, false);
        assert!(!probe.ok);
        assert_eq!(probe.answer_valid, Some(false));
        assert!(probe.answer_reason.is_some());
    }
}
