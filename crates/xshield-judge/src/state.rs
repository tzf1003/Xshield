//! The Jev request document and the rules that turn its answer into a verdict
//! (docs/02 sections 2.2 to 2.4).

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::context::Recent;

/// Largest serialized `state` sent to Jev.
pub const STATE_BYTES_MAX: usize = 8 * 1024;
/// Largest Jev response read.
pub const RESPONSE_BYTES_MAX: usize = 64 * 1024;
const REDACTED: &str = "<redacted>";
const SECRET_WORDS: [&str; 9] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "otp",
    "credential",
    "authorization",
    "cvv",
];

/// The `access` question options.
pub const ACCESS_OPTIONS: [&str; 3] = ["ALLOW", "DENY", "UNKNOWN"];
/// The `attack` question options.
pub const ATTACK_OPTIONS: [&str; 3] = ["BENIGN", "ATTACK", "UNKNOWN"];

const ACCESS_INSTRUCTIONS: &str = "You are a web application firewall. state.request is one HTTP request from a logged-in browser session. state.session and state.recent describe what the origin server already showed this session. For every value in state.request.values that selects or names an existing business object (record id, account, owner, file, order), check state.request.values[].seen_as: it lists where the origin showed that same value to this session, with the field name. Answer ALLOW only if every object-selecting value was shown earlier as that kind of object, or if state.entry.matched is true and the values are only the input that entry needs (login form, share code, search text). A value only needs to have been shown when its path position or field name refers to an existing object (an id, owner, account, file, basket). A value in a field that does not refer to an object (couponData, cardNum, expMonth, expYear, message) is form input and never needs to have been shown, even when seen_as is empty. seen_as may list unrelated fields because small numbers repeat everywhere: a match only counts when the field or request in seen_as is the same kind of object as the one the request selects. Free text that a user writes (note, title, comment, message, description, search words, names typed into a new record, dates, amounts, drug names) does not select any object and never needs to have been shown. Answer DENY if any object-selecting value was never shown to this session, or was shown only as an unrelated field (for example a number that appeared only as an age, now used as a patient id), or if an entry request tries to name someone else's object. Answer UNKNOWN only if the evidence is insufficient.";
const ATTACK_INSTRUCTIONS: &str = "You are a web application firewall. Inspect every value in state.request.values and the request path for attack content: SQL injection, NoSQL injection, command or code execution, path traversal, template injection, XSS, SSRF, header or log injection. Values marked <redacted> are secrets and are not attack content. Answer ATTACK if any value carries attack content, BENIGN if none does, UNKNOWN only if the evidence is insufficient.";

/// Why a state could not be built or an answer could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JudgeError {
    /// The state exceeds [`STATE_BYTES_MAX`] even after trimming.
    StateTooLarge,
    /// The provider response is malformed or inconsistent.
    ResponseInvalid,
}

impl std::fmt::Display for JudgeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::StateTooLarge => "JEV_STATE_TOO_LARGE",
            Self::ResponseInvalid => "JEV_RESPONSE_INVALID",
        })
    }
}

impl std::error::Error for JudgeError {}

/// One request value as shown to Jev.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateValue {
    /// Location, for example `path[2]` or `query.doctor`.
    pub at: String,
    /// Raw value; redacted while building.
    pub value: String,
    /// Key it travels under.
    pub key: Option<String>,
    /// Where the origin showed this value to the session, `field @ request`.
    pub seen_as: Vec<String>,
}

/// Everything the `state` document is made of.
#[derive(Debug, Clone)]
pub struct StateInput<'a> {
    /// Whether the path is a registered entry.
    pub entry_matched: bool,
    /// Session age in seconds.
    pub session_age_seconds: u64,
    /// Entry paths the session already passed.
    pub entries_passed: &'a [String],
    /// Recent requests, oldest first.
    pub recent: Vec<&'a Recent>,
    /// HTTP method.
    pub method: &'a str,
    /// Path without query.
    pub path: &'a str,
    /// The request values.
    pub values: Vec<StateValue>,
    /// The body was summarised or capped.
    pub truncated: bool,
    /// A secret that must never leave the gateway (the session credential).
    pub credential: Option<&'a str>,
}

fn is_secret_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|word| lower.contains(word))
}

fn render_value(
    input: &StateInput<'_>,
    value: &StateValue,
    cap: usize,
    seen_per_value: usize,
) -> Value {
    let secret_name = value.key.as_deref().is_some_and(is_secret_name) || is_secret_name(&value.at);
    let secret_value = input
        .credential
        .is_some_and(|credential| !credential.is_empty() && value.value.contains(credential));
    let text = if secret_name || secret_value {
        REDACTED.to_owned()
    } else if value.value.chars().count() > cap {
        let clipped: String = value.value.chars().take(cap).collect();
        format!("{clipped}...[truncated]")
    } else {
        value.value.clone()
    };
    let seen: Vec<&String> = value.seen_as.iter().rev().take(seen_per_value).collect();
    json!({ "at": value.at, "value": text, "seen_as": seen })
}

fn render(input: &StateInput<'_>, recent: usize, seen_per_value: usize, cap: usize) -> String {
    let recent: Vec<Value> = input
        .recent
        .iter()
        .skip(input.recent.len().saturating_sub(recent))
        .map(|item| json!({ "method": item.method, "path": item.path, "status": item.status }))
        .collect();
    let values: Vec<Value> = input
        .values
        .iter()
        .map(|value| render_value(input, value, cap, seen_per_value))
        .collect();
    json!({
        "entry": { "matched": input.entry_matched },
        "session": { "age_seconds": input.session_age_seconds, "entries_passed": input.entries_passed },
        "recent": recent,
        "request": {
            "method": input.method,
            "path": input.path,
            "values": values,
            "truncated": input.truncated,
        },
    })
    .to_string()
}

/// Serializes the `state`, trimming `recent`, `seen_as` and long values in that
/// order until it fits [`STATE_BYTES_MAX`].
///
/// # Errors
/// [`JudgeError::StateTooLarge`] when nothing more can be dropped without
/// hiding request content.
pub fn build_state(input: &StateInput<'_>) -> Result<String, JudgeError> {
    for (recent, seen, cap) in [
        (10, 3, 512),
        (3, 3, 512),
        (0, 3, 512),
        (0, 1, 512),
        (0, 1, 128),
    ] {
        let text = render(input, recent, seen, cap);
        if text.len() <= STATE_BYTES_MAX {
            return Ok(text);
        }
    }
    Err(JudgeError::StateTooLarge)
}

fn choice_question(instructions: &str, options: [&str; 3], meanings: [&str; 3]) -> Value {
    let criteria: BTreeMap<&str, &str> = options.into_iter().zip(meanings).collect();
    json!({ "type": "choice", "instructions": instructions, "criteria": criteria })
}

/// The full request body for the provider.
#[must_use]
pub fn request_body(model: &str, state_json: &str) -> Vec<u8> {
    let state: Value = serde_json::from_str(state_json).unwrap_or(Value::Null);
    json!({
        "model": model,
        "state": state,
        "questions": {
            "access": choice_question(
                ACCESS_INSTRUCTIONS,
                ACCESS_OPTIONS,
                [
                    "Every object the request selects was shown to this session, or this is an entry request with only its own input.",
                    "Some object the request selects was never shown to this session as that kind of object.",
                    "Insufficient evidence.",
                ],
            ),
            "attack": choice_question(
                ATTACK_INSTRUCTIONS,
                ATTACK_OPTIONS,
                ["No attack content.", "Attack content present.", "Insufficient evidence."],
            ),
        },
    })
    .to_string()
    .into_bytes()
}

/// Probabilities returned for the two questions.
#[derive(Debug, Clone, PartialEq)]
pub struct Answers {
    /// `access` probabilities keyed by option.
    pub access: BTreeMap<String, f64>,
    /// `attack` probabilities keyed by option.
    pub attack: BTreeMap<String, f64>,
}

#[derive(Deserialize)]
struct ResponseDto {
    answers: AnswersDto,
}

#[derive(Deserialize)]
struct AnswersDto {
    access: ChoiceDto,
    attack: ChoiceDto,
}

#[derive(Deserialize)]
struct ChoiceDto {
    #[serde(rename = "type")]
    kind: String,
    choice: String,
    probabilities: BTreeMap<String, f64>,
}

fn checked(choice: ChoiceDto, options: [&str; 3]) -> Result<BTreeMap<String, f64>, JudgeError> {
    let selected = choice.probabilities.get(&choice.choice).copied();
    let valid = choice.kind == "choice"
        && choice
            .probabilities
            .keys()
            .map(String::as_str)
            .eq(sorted(options))
        && choice
            .probabilities
            .values()
            .all(|p| (0.0..=1.0).contains(p))
        && (choice.probabilities.values().sum::<f64>() - 1.0).abs() <= 1e-3
        && selected.is_some_and(|p| choice.probabilities.values().all(|other| *other <= p));
    if valid {
        Ok(choice.probabilities)
    } else {
        Err(JudgeError::ResponseInvalid)
    }
}

fn sorted(options: [&str; 3]) -> [&str; 3] {
    let mut copy = options;
    copy.sort_unstable();
    copy
}

/// Parses and validates a provider response.
///
/// # Errors
/// [`JudgeError::ResponseInvalid`] for oversized bodies, bad JSON, missing
/// answers, extra or missing options, out-of-range probabilities, or a chosen
/// option that is not the most probable.
pub fn parse_response(body: &[u8]) -> Result<Answers, JudgeError> {
    if body.len() > RESPONSE_BYTES_MAX {
        return Err(JudgeError::ResponseInvalid);
    }
    let dto: ResponseDto = serde_json::from_slice(body).map_err(|_| JudgeError::ResponseInvalid)?;
    Ok(Answers {
        access: checked(dto.answers.access, ACCESS_OPTIONS)?,
        attack: checked(dto.answers.attack, ATTACK_OPTIONS)?,
    })
}

/// What the two answers amount to (docs/02 section 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conclusion {
    /// Both questions came out safe.
    Allow,
    /// `access=DENY` or `attack=ATTACK`.
    Deny,
    /// No denial, but a question was UNKNOWN or tied.
    Unknown,
}

fn top(probabilities: &BTreeMap<String, f64>) -> Option<&str> {
    let best = probabilities.values().copied().fold(f64::MIN, f64::max);
    let mut winners = probabilities
        .iter()
        .filter(|(_, p)| (**p - best).abs() < 1e-12);
    let first = winners.next()?;
    winners.next().is_none().then_some(first.0.as_str())
}

/// Takes the most probable option of each question; a tie counts as UNKNOWN.
#[must_use]
pub fn conclude(answers: &Answers) -> Conclusion {
    let access = top(&answers.access).unwrap_or("UNKNOWN");
    let attack = top(&answers.attack).unwrap_or("UNKNOWN");
    if access == "DENY" || attack == "ATTACK" {
        Conclusion::Deny
    } else if access == "ALLOW" && attack == "BENIGN" {
        Conclusion::Allow
    } else {
        Conclusion::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(at: &str, text: &str, key: Option<&str>, seen: &[&str]) -> StateValue {
        StateValue {
            at: at.to_owned(),
            value: text.to_owned(),
            key: key.map(str::to_owned),
            seen_as: seen.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn input<'a>(
        values: Vec<StateValue>,
        credential: Option<&'a str>,
        recent: Vec<&'a Recent>,
    ) -> StateInput<'a> {
        StateInput {
            entry_matched: false,
            session_age_seconds: 640,
            entries_passed: &[],
            recent,
            method: "GET",
            path: "/api/patients/8",
            values,
            truncated: false,
            credential,
        }
    }

    #[test]
    fn state_carries_values_and_where_they_were_seen() {
        let state = build_state(&input(
            vec![value("path[2]", "8", None, &["age @ GET /api/patients/7"])],
            None,
            vec![],
        ))
        .unwrap();
        let json: Value = serde_json::from_str(&state).unwrap();
        assert_eq!(json["request"]["values"][0]["value"], "8");
        assert_eq!(
            json["request"]["values"][0]["seen_as"][0],
            "age @ GET /api/patients/7"
        );
        assert_eq!(json["session"]["age_seconds"], 640);
    }

    #[test]
    fn secret_named_fields_and_the_credential_are_redacted() {
        let values = vec![
            value("body.password", "hunter2", Some("password"), &[]),
            value("query.next", "https://x/?sid=SESS123", Some("next"), &[]),
            value("body.Auth_Token", "t0k", Some("Auth_Token"), &[]),
            value("body.note", "fine", Some("note"), &[]),
        ];
        let state = build_state(&input(values, Some("SESS123"), vec![])).unwrap();
        assert!(!state.contains("hunter2") && !state.contains("SESS123") && !state.contains("t0k"));
        assert!(state.contains("fine"));
        assert_eq!(state.matches(REDACTED).count(), 3);
    }

    #[test]
    fn long_values_are_clipped_and_marked() {
        let long = "a".repeat(2_000);
        let state = build_state(&input(
            vec![value("body.x", &long, Some("x"), &[])],
            None,
            vec![],
        ))
        .unwrap();
        assert!(state.len() < STATE_BYTES_MAX);
        assert!(state.contains("...[truncated]"));
    }

    #[test]
    fn oversized_states_trim_history_before_failing() {
        let recent: Vec<Recent> = (0..50)
            .map(|i| Recent {
                method: "GET".into(),
                path: format!("/api/very/long/path/{i}/{}", "p".repeat(80)),
                status: 200,
            })
            .collect();
        let refs: Vec<&Recent> = recent.iter().collect();
        let values: Vec<StateValue> = (0..40)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(60), Some("k"), &[]))
            .collect();
        let state = build_state(&input(values, None, refs)).unwrap();
        assert!(state.len() <= STATE_BYTES_MAX);
        let json: Value = serde_json::from_str(&state).unwrap();
        assert_eq!(json["request"]["values"].as_array().unwrap().len(), 40);
    }

    #[test]
    fn requests_that_cannot_fit_fail_instead_of_dropping_values() {
        let values: Vec<StateValue> = (0..200)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(120), Some("k"), &[]))
            .collect();
        assert_eq!(
            build_state(&input(values, None, vec![])).unwrap_err(),
            JudgeError::StateTooLarge
        );
    }

    #[test]
    fn request_body_has_both_questions_with_their_options() {
        let body = request_body("typesafe-ai/jev", "{\"a\":1}");
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["model"], "typesafe-ai/jev");
        assert_eq!(json["state"]["a"], 1);
        assert_eq!(
            json["questions"]["access"]["criteria"]
                .as_object()
                .unwrap()
                .len(),
            3
        );
        assert!(json["questions"]["attack"]["criteria"]["ATTACK"].is_string());
    }

    fn response(access: (&str, [f64; 3]), attack: (&str, [f64; 3])) -> Vec<u8> {
        json!({
            "model": "m",
            "answers": {
                "access": { "type": "choice", "choice": access.0,
                    "probabilities": { "ALLOW": access.1[0], "DENY": access.1[1], "UNKNOWN": access.1[2] } },
                "attack": { "type": "choice", "choice": attack.0,
                    "probabilities": { "BENIGN": attack.1[0], "ATTACK": attack.1[1], "UNKNOWN": attack.1[2] } },
            },
            "usage": { "input_tokens": 1 }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn verdicts_follow_the_most_probable_options() {
        let cases = [
            (
                ("ALLOW", [0.9, 0.05, 0.05]),
                ("BENIGN", [0.9, 0.05, 0.05]),
                Conclusion::Allow,
            ),
            (
                ("DENY", [0.1, 0.8, 0.1]),
                ("BENIGN", [0.9, 0.05, 0.05]),
                Conclusion::Deny,
            ),
            (
                ("ALLOW", [0.9, 0.05, 0.05]),
                ("ATTACK", [0.1, 0.8, 0.1]),
                Conclusion::Deny,
            ),
            (
                ("UNKNOWN", [0.2, 0.2, 0.6]),
                ("BENIGN", [0.9, 0.05, 0.05]),
                Conclusion::Unknown,
            ),
            (
                ("DENY", [0.1, 0.8, 0.1]),
                ("UNKNOWN", [0.1, 0.1, 0.8]),
                Conclusion::Deny,
            ),
            (
                ("ALLOW", [0.5, 0.5, 0.0]),
                ("BENIGN", [0.9, 0.05, 0.05]),
                Conclusion::Unknown,
            ),
        ];
        for (access, attack, expected) in cases {
            let answers = parse_response(&response(access, attack));
            let answers = answers.unwrap_or_else(|_| panic!("{access:?}"));
            assert_eq!(conclude(&answers), expected, "{access:?} {attack:?}");
        }
    }

    #[test]
    fn inconsistent_responses_are_rejected() {
        let good = response(("ALLOW", [0.9, 0.05, 0.05]), ("BENIGN", [0.9, 0.05, 0.05]));
        assert!(parse_response(&good).is_ok());
        let bad = [
            response(("DENY", [0.9, 0.05, 0.05]), ("BENIGN", [0.9, 0.05, 0.05])),
            response(("ALLOW", [0.9, 0.5, 0.05]), ("BENIGN", [0.9, 0.05, 0.05])),
            response(("ALLOW", [1.5, -0.4, -0.1]), ("BENIGN", [0.9, 0.05, 0.05])),
            b"{}".to_vec(),
            b"not json".to_vec(),
            vec![b' '; RESPONSE_BYTES_MAX + 1],
            br#"{"answers":{"access":{"type":"choice","choice":"ALLOW","probabilities":{"ALLOW":1.0}},"attack":{}}}"#.to_vec(),
        ];
        for body in bad {
            assert_eq!(
                parse_response(&body).unwrap_err(),
                JudgeError::ResponseInvalid
            );
        }
    }
}
