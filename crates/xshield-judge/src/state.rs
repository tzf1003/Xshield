//! The Jev request document and the rules that turn its answer into a verdict
//! (docs/02 sections 2.2 to 2.4).

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use xshield_core::context::{Attempt, Conclusion, PublicAccess};

use crate::context::Recent;
use crate::slots::reliability_name;

/// Largest serialized `state` sent to Jev in one call.
pub const STATE_BYTES_MAX: usize = 8 * 1024;
/// Longest piece of a long value sent as one `part` (docs/02 section 2.2).
pub const VALUE_PART_CHARS: usize = 512;
/// Characters that two neighbouring pieces of one value share.
pub const VALUE_PART_OVERLAP: usize = 64;
/// Most batches one request is judged in (docs/02 section 2.4). The values after them are left out.
pub const JEV_BATCHES_MAX: usize = 16;
/// Longest location or source text sent; a longer one is cut and marked with `...`.
const TEXT_CHARS_MAX: usize = 256;
/// Largest Jev response read.
pub const RESPONSE_BYTES_MAX: usize = 64 * 1024;
/// What a secret value is shown as in the state and the trace.
pub const REDACTED: &str = "<redacted>";
/// The words that mark a field name as a secret on every site, sorted. The
/// heartbeat and the console report this same list (docs/07 section 7.9.8).
pub const SECRET_WORDS: [&str; 9] = [
    "authorization",
    "credential",
    "cvv",
    "otp",
    "passwd",
    "password",
    "pwd",
    "secret",
    "token",
];

/// The `access` question options.
pub const ACCESS_OPTIONS: [&str; 3] = ["ALLOW", "DENY", "UNKNOWN"];
/// The `attack` question options.
pub const ATTACK_OPTIONS: [&str; 3] = ["BENIGN", "ATTACK", "UNKNOWN"];
/// The lowest probability an allow may rest on: an allow needs both `P(ALLOW)` and `P(BENIGN)` to
/// reach it, and a probability equal to it counts (docs/02 section 2.3). A constant of the code,
/// not a setting.
pub const ALLOW_CONFIDENCE_MIN: f64 = 0.60;

const ACCESS_INSTRUCTIONS: &str = "You are a web application firewall. state.request is one HTTP request from a logged-in browser session. state.session and state.recent describe what the origin server already showed this session. For every value in state.request.values that selects or names an existing business object (record id, account, owner, file, order), check state.request.values[].seen_as: it lists where the origin showed that same value to this session, with the field name. Answer ALLOW only if every object-selecting value was shown earlier as that kind of object, or if state.entry.matched is true and the values are only the input that entry needs (login form, share code, search text). Each value has kind: reference when it looks like an object reference (an id in the path, or a field named like an id, owner or file), route for a plain word in the URL path, input otherwise. A route word that is a collection name (Addresss, Cards, Users) selects no object and never needs to have been shown; it selects one only when it is plainly a person or record name. A value of kind input (couponData, cardNum, expMonth, message) is form content and does not need to have been shown, unless it plainly names someone else's account or record. seen_as may list unrelated fields because small numbers repeat everywhere: a match only counts when the field or request in seen_as is the same kind of object as the one the request selects. A field may name the object by its role instead of by the endpoint that showed it (paymentId for an id shown by /api/Cards, deliveryMethodId for /api/Deliverys, owner for a user list); that still counts as the same kind of object. A value with verified true was already matched by the gateway with a response that showed this exact value as the same kind of object: treat it as shown and judge only the other values. A value may carry object: the kind of object the site's object map gives its position. A seen_as entry in brackets gives the kind of the position that showed it. A value shown only as a different kind of object was never shown as this kind, even when its field name looks similar. Free text that a user writes (note, title, comment, message, description, search words, names typed into a new record, dates, amounts, drug names) does not select any object and never needs to have been shown. A seen_as entry may end with the tier of the response that showed the value and how sure the map is of it. Tier public is a search or listing that any logged-in session receives, so a sighting there proves no right to the object it names. Tier self and tier org are the session's own records or its organisation's. Tier admin is a response that only administrator sessions receive. Reliability low is weak evidence. A value may carry public_access: accepts false marks a position that never takes a value from a public sighting, such as a write or a private read. A value with attempt over_privilege was shown to this session only by public responses, and its position takes none of them, so answer DENY for that value. state.request.function is present only on a site that keeps a table of its functions; a function is the method and the path with ids replaced. function.known false means the table does not list this method and path. Most such requests are ordinary: a new page, a new API, a static file. Answer DENY for function.known false only when the path or interface name itself shows a privileged or operational function that an application page for ordinary users would not call: administration (admin, manage, staff roles, audit), operations and monitoring (metrics, actuator, server-status, health internals), debugging and developer tooling (debug, swagger, console, phpinfo), internal or configuration endpoints, backups, directory or file listings (ftp), bulk export or bulk delete of a whole collection. Otherwise function.known false changes nothing: judge the values as above. function.attempt over_privilege means an administrator confirmed this function as administrators-only and this session is not an administrator session: answer DENY. Answer DENY if any object-selecting value was never shown to this session, or was shown only as an unrelated field (for example a number that appeared only as an age, now used as a patient id), or if an entry request tries to name someone else's object. Answer UNKNOWN only if the evidence is insufficient. A request may come as several documents: this one lists only some of its values, so judge only the values listed. A value with a part field (for example part 2/5) is one piece of a longer value: judge it like a short value at the same position and of the same kind. Long free text selects no object, but a long value in an object position (a number in a path, an identifier-like field) is a reference to an object this session was never shown.";
const ATTACK_INSTRUCTIONS: &str = "You are a web application firewall. Inspect every value in state.request.values and the request path for attack content: SQL injection, NoSQL injection, command or code execution, path traversal, template injection, XSS, SSRF, header or log injection. Values marked <redacted> are secrets and are not attack content. A value with a part field (for example part 2/5) is one piece of a long value, and neighbouring pieces overlap a little: check each piece, and count a payload that starts or ends at the edge of a piece as present. Answer ATTACK if any value carries attack content, BENIGN if none does, UNKNOWN only if the evidence is insufficient.";

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
    /// The gateway already matched it with a response that showed this exact
    /// value as the same kind of object.
    pub verified: bool,
    /// The kind of object the site's object map gives this position, when it does.
    pub object: Option<String>,
    /// Whether the request position takes a value that only a public response
    /// showed, with how sure the map is. Absent when the map says nothing.
    pub public_access: Option<PublicAccess>,
    /// Set when the gateway found the value to be an attempt (docs/01 section 1.4).
    pub attempt: Option<Attempt>,
    /// Set when the value is one piece of a longer value: the piece's number and the number of
    /// pieces, from 1. A piece shows no source and is never verified (docs/02 section 2.2).
    pub part: Option<(u16, u16)>,
    /// The kind of the whole value, kept on each of its pieces so that they agree. Absent for a
    /// value that is not cut: its kind is read from its own text.
    pub whole_kind: Option<&'static str>,
}

impl StateValue {
    /// `reference`, `route` or `input`: the kind Jev is told (docs/02 section 2.2).
    fn kind(&self) -> &'static str {
        self.whole_kind.unwrap_or_else(|| {
            crate::values::value_kind(&self.at, self.key.as_deref(), &self.value)
        })
    }
}

/// What the site's function table says about the request, as `state.request.function` shows it
/// (docs/02 section 2.2). Present only when the table decides the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateFunction {
    /// The function is administrator-only and this session is not an administrator's: `tier` is
    /// `admin` and `attempt` is `over_privilege`.
    pub admin_attempt: bool,
    /// The table does not list the request's function: `known` is false.
    pub unknown: bool,
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
    /// Redaction words the site adds to the built-in ones (`advanced.secret_fields`).
    pub secret_words: &'a [String],
    /// What the site's function table says about the request, when it decides it.
    pub function: Option<StateFunction>,
}

/// Whether a field name or a location names a secret: a built-in word or one
/// of the site's words appears in it.
#[must_use]
pub fn is_secret_name(name: &str, site_words: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|word| lower.contains(word))
        || site_words.iter().any(|word| lower.contains(word.as_str()))
}

/// Whether a value is shown as [`REDACTED`] whole: its field name or location names a secret, or
/// it holds the session credential. Such a value is never cut into pieces (docs/02 section 2.4).
fn is_secret_value(input: &StateInput<'_>, value: &StateValue) -> bool {
    let secret_name = value
        .key
        .as_deref()
        .is_some_and(|key| is_secret_name(key, input.secret_words))
        || is_secret_name(&value.at, input.secret_words);
    let secret_value = input
        .credential
        .is_some_and(|credential| !credential.is_empty() && value.value.contains(credential));
    secret_name || secret_value
}

/// The first `max` characters of `text`, followed by `...` when it is cut.
fn clip(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        let head: String = text.chars().take(max).collect();
        format!("{head}...")
    } else {
        text.to_owned()
    }
}

/// The values of the state: each `(at, value)` pair once, in order, and each long value cut into
/// pieces (docs/02 section 2.2).
fn state_values(input: &StateInput<'_>) -> Vec<StateValue> {
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    input
        .values
        .iter()
        .filter(|value| seen.insert((value.at.as_str(), value.value.as_str())))
        .flat_map(|value| value_pieces(input, value))
        .collect()
}

/// The pieces of one value. A value of at most [`VALUE_PART_CHARS`] characters, and a secret, is
/// one piece as it is. A longer one is cut at character boundaries into pieces that share
/// [`VALUE_PART_OVERLAP`] characters, so that removing the overlap from each later piece gives the
/// value back. Each piece keeps the location, the key, the object and the public access of the
/// value, and shows no source.
fn value_pieces(input: &StateInput<'_>, value: &StateValue) -> Vec<StateValue> {
    let chars: Vec<char> = value.value.chars().collect();
    if chars.len() <= VALUE_PART_CHARS || is_secret_value(input, value) {
        return vec![value.clone()];
    }
    let mut texts = Vec::new();
    let mut start = 0;
    loop {
        let end = (start + VALUE_PART_CHARS).min(chars.len());
        texts.push(chars[start..end].iter().collect::<String>());
        if end == chars.len() {
            break;
        }
        start += VALUE_PART_CHARS - VALUE_PART_OVERLAP;
    }
    let total = u16::try_from(texts.len()).unwrap_or(u16::MAX);
    // The pieces keep the kind of the whole value, not the kind their own text would give.
    let whole_kind = value.kind();
    texts
        .into_iter()
        .enumerate()
        .map(|(index, text)| StateValue {
            at: value.at.clone(),
            value: text,
            key: value.key.clone(),
            seen_as: Vec::new(),
            verified: false,
            object: value.object.clone(),
            public_access: value.public_access,
            attempt: None,
            part: Some((u16::try_from(index + 1).unwrap_or(u16::MAX), total)),
            whole_kind: Some(whole_kind),
        })
        .collect()
}

fn render_value(input: &StateInput<'_>, value: &StateValue, seen_per_value: usize) -> Value {
    let text = if is_secret_value(input, value) {
        REDACTED.to_owned()
    } else {
        value.value.clone()
    };
    let seen: Vec<String> = value
        .seen_as
        .iter()
        .rev()
        .take(seen_per_value)
        .map(|source| clip(source, TEXT_CHARS_MAX))
        .collect();
    let kind = value.kind();
    let mut rendered = json!({
        "at": clip(&value.at, TEXT_CHARS_MAX),
        "kind": kind,
        "value": text,
        "seen_as": seen,
    });
    if value.verified {
        rendered["verified"] = Value::Bool(true);
    }
    if let Some(object) = &value.object {
        rendered["object"] = Value::String(object.clone());
    }
    if let Some(access) = value.public_access {
        rendered["public_access"] = json!({
            "accepts": access.accepts,
            "reliability": reliability_name(access.reliability),
        });
    }
    if let Some(attempt) = value.attempt {
        rendered["attempt"] = Value::String(attempt.as_str().to_owned());
    }
    if let Some((piece, pieces)) = value.part {
        rendered["part"] = Value::String(format!("{piece}/{pieces}"));
    }
    rendered
}

/// One way of trimming a `state` (docs/07 section 7.5.3): how many recent requests it keeps, how
/// many sources it keeps per value, and whether it also drops the entries passed and cuts the path.
#[derive(Clone, Copy)]
struct Trim {
    recent: usize,
    seen: usize,
    compact: bool,
}

/// Levels 0 to 3: every value goes in one `state` at one of these.
const WHOLE_TRIMS: [Trim; 4] = [
    Trim {
        recent: 10,
        seen: 3,
        compact: false,
    },
    Trim {
        recent: 3,
        seen: 3,
        compact: false,
    },
    Trim {
        recent: 0,
        seen: 3,
        compact: false,
    },
    Trim {
        recent: 0,
        seen: 1,
        compact: false,
    },
];
/// Level 3, the trim the batches of a large request are cut at.
const BATCH: Trim = Trim {
    recent: 0,
    seen: 1,
    compact: false,
};
/// Level 4, used only for one value that does not fit in a batch at level 3.
const COMPACT: Trim = Trim {
    recent: 0,
    seen: 0,
    compact: true,
};
const BATCH_LEVEL: u8 = 3;
const COMPACT_LEVEL: u8 = 4;

/// The `function` of a request: `tier` and `attempt` for an attempt, `known` false for an unknown
/// function, both keys together when both hold.
fn function_json(function: StateFunction) -> Value {
    let mut rendered = json!({});
    if function.admin_attempt {
        rendered["tier"] = json!("admin");
        rendered["attempt"] = json!(Attempt::OverPrivilege.as_str());
    }
    if function.unknown {
        rendered["known"] = json!(false);
    }
    rendered
}

/// The `state` text of `values` at one trim. The text is the same bytes for the same input, and
/// its values and path are redacted by the caller; `seen_as` and `recent` quote earlier requests,
/// so the finished text is checked for the credential once more.
fn render(input: &StateInput<'_>, values: &[StateValue], trim: Trim) -> String {
    let recent: Vec<Value> = input
        .recent
        .iter()
        .skip(input.recent.len().saturating_sub(trim.recent))
        .map(|item| json!({ "method": item.method, "path": item.path, "status": item.status }))
        .collect();
    let rendered: Vec<Value> = values
        .iter()
        .map(|value| render_value(input, value, trim.seen))
        .collect();
    let (entries, path) = if trim.compact {
        (Vec::new(), clip(input.path, TEXT_CHARS_MAX))
    } else {
        (input.entries_passed.to_vec(), input.path.to_owned())
    };
    // The function is part of the request's own shell: every batch carries it, and the compact
    // level keeps it.
    let mut request = json!({
        "method": input.method,
        "path": path,
        "values": rendered,
        "truncated": input.truncated,
    });
    if let Some(function) = input.function {
        request["function"] = function_json(function);
    }
    let state = json!({
        "entry": { "matched": input.entry_matched },
        "session": { "age_seconds": input.session_age_seconds, "entries_passed": entries },
        "recent": recent,
        "request": request,
    })
    .to_string();
    crate::trace::scrubbed(&state, input.credential).into_owned()
}

/// Cuts `values` into runs, in order, that each fit one `state` at `trim`. The sizes are counted
/// from the rendered values; [`fit`] checks each run again on the text it sends.
fn pack<'a>(input: &StateInput<'_>, values: &'a [StateValue], trim: Trim) -> Vec<&'a [StateValue]> {
    let base = render(input, &[], trim).len();
    let mut runs = Vec::new();
    let mut start = 0;
    let mut size = base;
    for (index, value) in values.iter().enumerate() {
        // One value's text and the comma that follows it.
        let cost = render_value(input, value, trim.seen).to_string().len() + 1;
        if index > start && size + cost > STATE_BYTES_MAX {
            runs.push(&values[start..index]);
            start = index;
            size = base;
        }
        size += cost;
    }
    runs.push(&values[start..]);
    runs
}

/// One `state` text of a batch, with its trim level and the number of values it carries.
struct Batch {
    text: String,
    level: u8,
    values: usize,
}

/// The `state` texts of one run: the run whole at `trim` when it fits, else each half of it, until
/// a single value is left. A single value that does not fit at `trim` is sent at the compact trim;
/// that fails only when even that does not fit.
fn fit(
    input: &StateInput<'_>,
    run: &[StateValue],
    trim: Trim,
    level: u8,
) -> Result<Vec<Batch>, JudgeError> {
    let text = render(input, run, trim);
    if text.len() <= STATE_BYTES_MAX {
        return Ok(vec![Batch {
            text,
            level,
            values: run.len(),
        }]);
    }
    if run.len() <= 1 {
        let text = render(input, run, COMPACT);
        return if text.len() <= STATE_BYTES_MAX {
            Ok(vec![Batch {
                text,
                level: COMPACT_LEVEL,
                values: run.len(),
            }])
        } else {
            Err(JudgeError::StateTooLarge)
        };
    }
    let (left, right) = run.split_at(run.len() / 2);
    let mut batches = fit(input, left, trim, level)?;
    batches.extend(fit(input, right, trim, level)?);
    Ok(batches)
}

/// The trim every batch is cut at (docs/02 section 2.4): level 3, or level 4 when the request
/// without its values is already more than half a state. Then each batch could carry only a few
/// values, so the entries and the path are cut as well.
fn batch_trim(input: &StateInput<'_>) -> (Trim, u8) {
    if render(input, &[], BATCH).len() > STATE_BYTES_MAX / 2 {
        (COMPACT, COMPACT_LEVEL)
    } else {
        (BATCH, BATCH_LEVEL)
    }
}

/// The order values are sent in when a request is batched (docs/02 section 2.4). Class 1 is a value
/// that was not shown and is not form input, with its pieces: Jev must judge it, so it goes first.
/// Class 2 is the other whole values and class 3 the other pieces. A value left out is one of the
/// last ones.
fn send_class(value: &StateValue) -> u8 {
    if value.kind() != "input" && !value.verified {
        1
    } else if value.part.is_none() {
        2
    } else {
        3
    }
}

/// The `state` texts of one request, and the values that did not fit in them (docs/02 section 2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batched {
    /// The texts in send order, each with its trim level. At most [`JEV_BATCHES_MAX`].
    pub states: Vec<(String, u8)>,
    /// Values and pieces that are in none of `states`.
    pub left_out: u32,
}

/// Builds the `state` texts of one request, each with its trim level (docs/07 section 7.5.3).
/// When every value fits in one text at levels 0 to 3, that is the only text, and it is the same
/// as before batches existed. Otherwise the values are sent in batches, each one call to Jev. The
/// batches share the entry, the session, the method, the path and the truncation flag; only their
/// values differ. Values are taken in [`send_class`] order, and only the first
/// [`JEV_BATCHES_MAX`] batches are kept.
///
/// # Errors
/// [`JudgeError::StateTooLarge`] when a class 1 value does not fit in the kept batches, or a single
/// value does not fit even at level 4 (docs/02 section 2.4). Nothing is sent in either case.
pub fn build_states(input: &StateInput<'_>) -> Result<Batched, JudgeError> {
    let values = state_values(input);
    for (level, trim) in WHOLE_TRIMS.into_iter().enumerate() {
        let text = render(input, &values, trim);
        if text.len() <= STATE_BYTES_MAX {
            let level = u8::try_from(level).unwrap_or(u8::MAX);
            return Ok(Batched {
                states: vec![(text, level)],
                left_out: 0,
            });
        }
    }
    let (trim, level) = batch_trim(input);
    let mut ordered = values;
    ordered.sort_by_key(send_class);
    let must = ordered
        .iter()
        .filter(|value| send_class(value) == 1)
        .count();
    let mut batches = Vec::new();
    for run in pack(input, &ordered, trim) {
        batches.extend(fit(input, run, trim, level)?);
    }
    let sent: usize = batches
        .iter()
        .take(JEV_BATCHES_MAX)
        .map(|batch| batch.values)
        .sum();
    if sent < must {
        return Err(JudgeError::StateTooLarge);
    }
    let left_out = u32::try_from(ordered.len() - sent).unwrap_or(u32::MAX);
    let states = batches
        .into_iter()
        .take(JEV_BATCHES_MAX)
        .map(|batch| (batch.text, batch.level))
        .collect();
    Ok(Batched { states, left_out })
}

fn choice_question(instructions: &str, options: [&str; 3], meanings: [&str; 3]) -> Value {
    let criteria: BTreeMap<&str, &str> = options.into_iter().zip(meanings).collect();
    json!({ "type": "choice", "instructions": instructions, "criteria": criteria })
}

/// The two fixed questions asked of Jev, built once per process, with their
/// version id (docs/07 section 7.5.5).
#[derive(Debug, Clone)]
pub struct Prompt {
    questions: Value,
    id: String,
}

impl Prompt {
    /// Builds the questions and derives their id.
    #[must_use]
    pub fn new() -> Self {
        let questions = json!({
            "access": choice_question(
                ACCESS_INSTRUCTIONS,
                ACCESS_OPTIONS,
                [
                    "Every object the request selects was shown to this session, or this is an entry request with only its own input.",
                    "Some object the request selects was never shown to this session as that kind of object, or the request reaches a privileged or operational function.",
                    "Insufficient evidence.",
                ],
            ),
            "attack": choice_question(
                ATTACK_INSTRUCTIONS,
                ATTACK_OPTIONS,
                ["No attack content.", "Attack content present.", "Insufficient evidence."],
            ),
        });
        let digest = Sha256::digest(questions.to_string().as_bytes());
        let id = format!("jq_{}", hex(&digest[..8]));
        Self { questions, id }
    }

    /// The version id: `jq_` and the first 16 hex digits of the SHA-256 of the
    /// questions JSON. A changed instruction gets a new id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The questions as JSON text, for the `jev_prompts` table.
    #[must_use]
    pub fn questions_json(&self) -> String {
        self.questions.to_string()
    }
}

impl Default for Prompt {
    fn default() -> Self {
        Self::new()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// The full request body for the provider.
#[must_use]
pub fn request_body(model: &str, state_json: &str, prompt: &Prompt) -> Vec<u8> {
    let state: Value = serde_json::from_str(state_json).unwrap_or(Value::Null);
    json!({
        "model": model,
        "state": state,
        "questions": prompt.questions,
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
    /// The reply's `usage` object, as it came.
    pub usage: Option<Value>,
}

#[derive(Deserialize)]
struct ResponseDto {
    answers: AnswersDto,
    #[serde(default)]
    usage: Option<Value>,
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
        usage: dto.usage,
    })
}

fn top(probabilities: &BTreeMap<String, f64>) -> Option<&str> {
    let best = probabilities.values().copied().fold(f64::MIN, f64::max);
    let mut winners = probabilities
        .iter()
        .filter(|(_, p)| (**p - best).abs() < 1e-12);
    let first = winners.next()?;
    winners.next().is_none().then_some(first.0.as_str())
}

/// The weaker of the two probabilities an allow rests on: `min(P(ALLOW), P(BENIGN))`, the value the
/// decision log keeps as `jev_confidence`. An option the answer does not carry counts as 0.
#[must_use]
pub fn assurance(access: &BTreeMap<String, f64>, attack: &BTreeMap<String, f64>) -> f64 {
    let access = access.get("ALLOW").copied().unwrap_or(0.0);
    let attack = attack.get("BENIGN").copied().unwrap_or(0.0);
    access.min(attack)
}

/// Takes the most probable option of each question; a tie counts as UNKNOWN. An allow also needs
/// its [`assurance`] to reach [`ALLOW_CONFIDENCE_MIN`]. A denial is never held to the floor.
#[must_use]
pub fn conclude(answers: &Answers) -> Conclusion {
    let access = top(&answers.access).unwrap_or("UNKNOWN");
    let attack = top(&answers.attack).unwrap_or("UNKNOWN");
    if access == "DENY" || attack == "ATTACK" {
        Conclusion::Deny
    } else if access == "ALLOW"
        && attack == "BENIGN"
        && assurance(&answers.access, &answers.attack) >= ALLOW_CONFIDENCE_MIN
    {
        Conclusion::Allow
    } else {
        Conclusion::Unknown
    }
}

/// Whether the two most probable options are ALLOW and BENIGN while one of them is below
/// [`ALLOW_CONFIDENCE_MIN`]. Such an answer is not decidable and fails as `JEV_LOW_CONFIDENCE`
/// rather than `JEV_UNKNOWN`.
#[must_use]
pub fn low_confidence(answers: &Answers) -> bool {
    top(&answers.access) == Some("ALLOW")
        && top(&answers.attack) == Some("BENIGN")
        && assurance(&answers.access, &answers.attack) < ALLOW_CONFIDENCE_MIN
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
            verified: false,
            object: None,
            public_access: None,
            attempt: None,
            part: None,
            whole_kind: None,
        }
    }

    /// The one `state` of an input that fits a single call.
    fn build_state(input: &StateInput<'_>) -> Result<(String, u8), JudgeError> {
        let mut states = build_states(input)?.states;
        assert_eq!(states.len(), 1, "the input fits one call");
        states.pop().ok_or(JudgeError::StateTooLarge)
    }

    /// The value text and the `part` of each item the state carries for `at`, in order.
    fn parts_of(state: &str, at: &str) -> Vec<(String, Option<String>)> {
        let json: Value = serde_json::from_str(state).unwrap();
        json["request"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["at"] == at)
            .map(|item| {
                (
                    item["value"].as_str().unwrap().to_owned(),
                    item["part"].as_str().map(str::to_owned),
                )
            })
            .collect()
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
            secret_words: &[],
            function: None,
        }
    }

    #[test]
    fn site_secret_words_redact_like_the_built_in_ones() {
        let words = ["ssn".to_owned()];
        let values = vec![
            value("body.ssn", "123456789", Some("ssn"), &[]),
            value("body.idcard", "fine", Some("idcard"), &[]),
        ];
        let mut site_input = input(values, None, vec![]);
        site_input.secret_words = &words;
        let (state, _) = build_state(&site_input).unwrap();
        assert!(!state.contains("123456789"));
        assert!(state.contains("fine"), "only the site's words are added");
        assert!(state.contains(REDACTED));
    }

    #[test]
    fn state_carries_values_and_where_they_were_seen() {
        let (state, _) = build_state(&input(
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
    fn only_matched_values_are_marked_verified() {
        let mut matched = value("path[2]", "8", None, &["id @ GET /api/patients"]);
        matched.verified = true;
        let (state, _) = build_state(&input(
            vec![matched, value("query.q", "x", Some("q"), &[])],
            None,
            vec![],
        ))
        .unwrap();
        let json: Value = serde_json::from_str(&state).unwrap();
        assert_eq!(json["request"]["values"][0]["verified"], true);
        assert!(json["request"]["values"][1].get("verified").is_none());
    }

    #[test]
    fn a_public_access_and_an_attempt_are_rendered_only_when_set() {
        let mut attempted = value(
            "path[2]",
            "7005",
            None,
            &["id @ GET /api/search [patient] (tier public, reliability high)"],
        );
        attempted.public_access = Some(PublicAccess {
            accepts: false,
            reliability: xshield_core::context::Reliability::High,
        });
        attempted.attempt = Some(Attempt::OverPrivilege);
        let (state, _) = build_state(&input(
            vec![attempted, value("query.q", "x", Some("q"), &[])],
            None,
            vec![],
        ))
        .unwrap();
        let json: Value = serde_json::from_str(&state).unwrap();
        let first = &json["request"]["values"][0];
        assert_eq!(first["public_access"]["accepts"], false);
        assert_eq!(first["public_access"]["reliability"], "high");
        assert_eq!(first["attempt"], "over_privilege");
        assert_eq!(
            first["seen_as"][0],
            "id @ GET /api/search [patient] (tier public, reliability high)"
        );
        let plain = &json["request"]["values"][1];
        assert!(plain.get("public_access").is_none() && plain.get("attempt").is_none());
    }

    #[test]
    fn secret_named_fields_and_the_credential_are_redacted() {
        let values = vec![
            value("body.password", "hunter2", Some("password"), &[]),
            value("query.next", "https://x/?sid=SESS123", Some("next"), &[]),
            value("body.Auth_Token", "t0k", Some("Auth_Token"), &[]),
            value("body.note", "fine", Some("note"), &[]),
        ];
        let (state, _) = build_state(&input(values, Some("SESS123"), vec![])).unwrap();
        assert!(!state.contains("hunter2") && !state.contains("SESS123") && !state.contains("t0k"));
        assert!(state.contains("fine"));
        assert_eq!(state.matches(REDACTED).count(), 3);
    }

    #[test]
    fn a_long_value_is_sent_in_overlapping_pieces_that_join_back_to_it() {
        let long = "abcdefghij".repeat(200);
        let (state, trim) = build_state(&input(
            vec![value("body.x", &long, Some("x"), &[])],
            None,
            vec![],
        ))
        .unwrap();
        assert_eq!(trim, 0);
        assert!(!state.contains("[truncated]"));
        let pieces = parts_of(&state, "body.x");
        // 2000 characters: starts at 0, 448, 896, 1344 and 1792.
        assert_eq!(pieces.len(), 5);
        assert_eq!(pieces[0].1.as_deref(), Some("1/5"));
        assert_eq!(pieces[4].1.as_deref(), Some("5/5"));
        assert!(
            pieces
                .iter()
                .all(|(text, _)| text.chars().count() <= VALUE_PART_CHARS)
        );
        // Each later piece starts with the 64 characters the piece before it ends with.
        assert!(
            pieces[1].0.chars().take(VALUE_PART_OVERLAP).eq(pieces[0]
                .0
                .chars()
                .skip(VALUE_PART_CHARS - VALUE_PART_OVERLAP))
        );
        let mut joined = pieces[0].0.clone();
        for (text, _) in &pieces[1..] {
            joined.extend(text.chars().skip(VALUE_PART_OVERLAP));
        }
        assert_eq!(joined, long);
    }

    #[test]
    fn long_pieces_are_cut_at_character_boundaries() {
        let long: String = (0..1_300)
            .map(|index| if index % 3 == 0 { '😀' } else { '中' })
            .collect();
        let (state, _) = build_state(&input(
            vec![value("body.note", &long, Some("note"), &[])],
            None,
            vec![],
        ))
        .unwrap();
        let pieces = parts_of(&state, "body.note");
        assert_eq!(pieces.len(), 3);
        let mut joined = pieces[0].0.clone();
        for (text, _) in &pieces[1..] {
            joined.extend(text.chars().skip(VALUE_PART_OVERLAP));
        }
        assert_eq!(joined, long);
    }

    #[test]
    fn a_value_of_one_piece_is_not_cut() {
        let text = "a".repeat(VALUE_PART_CHARS);
        let (state, _) = build_state(&input(
            vec![value("body.x", &text, Some("x"), &[])],
            None,
            vec![],
        ))
        .unwrap();
        assert_eq!(parts_of(&state, "body.x"), vec![(text, None)]);
    }

    #[test]
    fn a_secret_value_is_never_cut_and_shows_once_as_redacted() {
        let long_secret = "s".repeat(1_200);
        let credential = "T".repeat(700);
        let by_name = value("body.password", &long_secret, Some("password"), &[]);
        let holding = value(
            "body.note",
            &format!("prefix {credential} suffix {}", "n".repeat(600)),
            Some("note"),
            &[],
        );
        let (state, _) = build_state(&input(
            vec![by_name, holding],
            Some(credential.as_str()),
            vec![],
        ))
        .unwrap();
        assert!(!state.contains(&long_secret) && !state.contains(&credential));
        assert_eq!(state.matches(REDACTED).count(), 2);
        assert!(!state.contains("\"part\""));
    }

    #[test]
    fn requests_too_large_for_one_state_are_sent_in_batches_that_hold_every_value_once() {
        let values: Vec<StateValue> = (0..200)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(120), Some("k"), &[]))
            .collect();
        let states = build_states(&input(values.clone(), None, vec![]))
            .unwrap()
            .states;
        assert!(
            states.len() >= 2,
            "200 values of 120 characters need several calls"
        );
        let mut sent = Vec::new();
        for (state, trim) in &states {
            assert!(state.len() <= STATE_BYTES_MAX);
            assert_eq!(*trim, 3);
            let json: Value = serde_json::from_str(state).unwrap();
            assert_eq!(json["request"]["path"], "/api/patients/8");
            for item in json["request"]["values"].as_array().unwrap() {
                sent.push((
                    item["at"].as_str().unwrap().to_owned(),
                    item["value"].as_str().unwrap().to_owned(),
                ));
            }
        }
        let expected: Vec<(String, String)> = values
            .iter()
            .map(|value| (value.at.clone(), value.value.clone()))
            .collect();
        assert_eq!(sent, expected);
    }

    #[test]
    fn every_batch_of_a_request_with_a_function_carries_the_function() {
        // The function is part of the request's shell (docs/02 section 2.4): every batch carries
        // it, and a request whose shell is large keeps it at level 4.
        let values: Vec<StateValue> = (0..200)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(120), Some("k"), &[]))
            .collect();
        let long_path = format!("/share/{}", "x".repeat(7_400));
        let cases = [
            (
                StateFunction {
                    admin_attempt: true,
                    unknown: false,
                },
                json!({"tier": "admin", "attempt": "over_privilege"}),
            ),
            (
                StateFunction {
                    admin_attempt: false,
                    unknown: true,
                },
                json!({"known": false}),
            ),
            (
                StateFunction {
                    admin_attempt: true,
                    unknown: true,
                },
                json!({"tier": "admin", "attempt": "over_privilege", "known": false}),
            ),
        ];
        let shapes: [(&str, u8); 2] = [("/api/patients/8", 3), (long_path.as_str(), 4)];
        for (path, level) in shapes {
            for (function, expected) in &cases {
                let mut request = input(values.clone(), None, vec![]);
                request.path = path;
                request.function = Some(*function);
                let built = build_states(&request).unwrap();
                assert!(built.states.len() >= 2, "{} calls", built.states.len());
                for (state, trim) in &built.states {
                    assert_eq!(*trim, level, "{state}");
                    let json: Value = serde_json::from_str(state).unwrap();
                    assert_eq!(json["request"]["function"], *expected, "{state}");
                }
            }
        }
    }

    #[test]
    fn one_value_that_fills_a_batch_is_sent_at_the_compact_trim() {
        let control = "\u{1}".repeat(VALUE_PART_CHARS);
        let long_at = format!("body.{}", "k".repeat(400));
        let long_source = format!("id @ GET /api/very/{}", "p".repeat(300));
        let entries: Vec<String> = (0..16)
            .map(|i| format!("/api/entry/{i}/{}", "e".repeat(300)))
            .collect();
        let long_path = format!("/api/patients/{}", "7".repeat(9_000));
        let mut heavy = input(
            vec![value(&long_at, &control, Some("note"), &[&long_source])],
            None,
            vec![],
        );
        heavy.entries_passed = &entries;
        heavy.path = &long_path;
        let states = build_states(&heavy).unwrap().states;
        assert_eq!(states.len(), 1);
        let (state, trim) = &states[0];
        assert_eq!(*trim, 4);
        assert!(state.len() <= STATE_BYTES_MAX);
        let json: Value = serde_json::from_str(state).unwrap();
        assert!(
            json["session"]["entries_passed"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(json["request"]["path"].as_str().unwrap().chars().count() <= TEXT_CHARS_MAX + 3);
        let item = &json["request"]["values"][0];
        assert!(item["at"].as_str().unwrap().chars().count() <= TEXT_CHARS_MAX + 3);
    }

    #[test]
    fn a_repeated_location_and_value_is_sent_once() {
        let (state, _) = build_state(&input(
            vec![
                value("query.q", "x", Some("q"), &[]),
                value("query.q", "x", Some("q"), &[]),
                value("query.q", "y", Some("q"), &[]),
            ],
            None,
            vec![],
        ))
        .unwrap();
        let json: Value = serde_json::from_str(&state).unwrap();
        assert_eq!(json["request"]["values"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn oversized_states_trim_history_before_failing() {
        let recent: Vec<Recent> = (0..50)
            .map(|i| Recent {
                method: "GET".into(),
                path: format!("/api/very/long/path/{i}/{}", "p".repeat(80)),
                status: 200,
                request_id: 0,
                at_ms: 0,
            })
            .collect();
        let refs: Vec<&Recent> = recent.iter().collect();
        let values: Vec<StateValue> = (0..40)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(60), Some("k"), &[]))
            .collect();
        let (state, _) = build_state(&input(values, None, refs)).unwrap();
        assert!(state.len() <= STATE_BYTES_MAX);
        let json: Value = serde_json::from_str(&state).unwrap();
        assert_eq!(json["request"]["values"].as_array().unwrap().len(), 40);
    }

    /// The bytes of a `state` for one fixed input. Jev reads this text, so a
    /// change here changes what the model is asked.
    const GOLDEN_STATE: &str = r#"{"entry":{"matched":false},"recent":[{"method":"GET","path":"/api/patients","status":200}],"request":{"method":"GET","path":"/api/patients/8","truncated":false,"values":[{"at":"path[2]","kind":"reference","seen_as":["id @ GET /api/patients"],"value":"7"}]},"session":{"age_seconds":640,"entries_passed":["/login"]}}"#;

    #[test]
    fn the_state_bytes_are_fixed_and_carry_no_request_ids() {
        let recent = Recent {
            method: "GET".into(),
            path: "/api/patients".into(),
            status: 200,
            request_id: 0,
            at_ms: 0,
        };
        let entries = ["/login".to_owned()];
        let mut fixed = input(
            vec![value("path[2]", "7", None, &["id @ GET /api/patients"])],
            Some("SESS123"),
            vec![&recent],
        );
        fixed.entries_passed = &entries;
        let (state, trim) = build_state(&fixed).unwrap();
        assert_eq!(trim, 0);
        assert_eq!(state, GOLDEN_STATE);
        assert!(!state.contains("req_"));
    }

    #[test]
    fn the_trim_level_counts_the_steps_taken() {
        let (_, level) =
            build_state(&input(vec![value("query.q", "x", None, &[])], None, vec![])).unwrap();
        assert_eq!(level, 0);
        let recent: Vec<Recent> = (0..50)
            .map(|i| Recent {
                method: "GET".into(),
                path: format!("/api/very/long/path/{i}/{}", "p".repeat(80)),
                status: 200,
                request_id: 0,
                at_ms: 0,
            })
            .collect();
        let refs: Vec<&Recent> = recent.iter().collect();
        let values: Vec<StateValue> = (0..40)
            .map(|i| value(&format!("query.k{i}"), &"v".repeat(120), Some("k"), &[]))
            .collect();
        let (state, level) = build_state(&input(values, None, refs)).unwrap();
        assert!(level > 0 && level < 4, "trimmed to level {level}");
        assert!(state.len() <= STATE_BYTES_MAX);
    }

    #[test]
    fn the_function_is_rendered_only_when_present_and_as_the_table_says() {
        let plain = input(Vec::new(), None, Vec::new());
        let (text, _) = build_state(&plain).unwrap();
        let state: Value = serde_json::from_str(&text).unwrap();
        assert!(state["request"].get("function").is_none(), "{text}");
        let cases = [
            (
                StateFunction {
                    admin_attempt: true,
                    unknown: false,
                },
                json!({"tier": "admin", "attempt": "over_privilege"}),
            ),
            (
                StateFunction {
                    admin_attempt: false,
                    unknown: true,
                },
                json!({"known": false}),
            ),
            (
                StateFunction {
                    admin_attempt: true,
                    unknown: true,
                },
                json!({"tier": "admin", "attempt": "over_privilege", "known": false}),
            ),
        ];
        for (function, expected) in cases {
            let mut with_function = input(Vec::new(), None, Vec::new());
            with_function.function = Some(function);
            let (text, _) = build_state(&with_function).unwrap();
            let state: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(state["request"]["function"], expected, "{text}");
        }
    }

    #[test]
    fn the_function_paragraph_keeps_its_tested_wording() {
        // The paragraph was tried against the real model in this wording (design note section 16,
        // probe variant draft3). Change it only with a new probe.
        let paragraph = ACCESS_INSTRUCTIONS
            .find(" state.request.function is present only")
            .expect("the paragraph is in the access instructions");
        let denial = ACCESS_INSTRUCTIONS
            .find(" Answer DENY if any object-selecting value was never shown")
            .expect("the denial sentence is in the access instructions");
        assert!(paragraph < denial);
        assert!(
            ACCESS_INSTRUCTIONS
                .contains("Most such requests are ordinary: a new page, a new API, a static file.")
        );
        assert!(ACCESS_INSTRUCTIONS.contains(
            "Otherwise function.known false changes nothing: judge the values as above."
        ));
    }

    #[test]
    fn the_prompt_id_is_fixed_and_follows_the_questions() {
        let prompt = Prompt::new();
        assert_eq!(prompt.id(), "jq_d5df87392a92b44d");
        assert_eq!(Prompt::new().id(), prompt.id());
        assert!(prompt.questions_json().contains("\"access\""));
    }

    #[test]
    fn the_pieces_of_a_value_keep_the_kind_of_the_whole_value() {
        // Judged by its own text, the first piece of "000…07" would be a reference and the first
        // piece of "aaa…a7" a route word; the whole value is a reference in both.
        let digits = format!("{}7", "0".repeat(600));
        let letters = format!("{}7", "a".repeat(600));
        let values = vec![
            value("path[2]", &digits, None, &[]),
            value("path[3]", &letters, None, &[]),
        ];
        let (state, _) = build_state(&input(values, None, vec![])).unwrap();
        let json: Value = serde_json::from_str(&state).unwrap();
        let pieces: Vec<&Value> = json["request"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item.get("part").is_some())
            .collect();
        assert_eq!(pieces.len(), 4);
        assert!(
            pieces.iter().all(|item| item["kind"] == "reference"),
            "{pieces:?}"
        );
    }

    #[test]
    fn a_long_value_beyond_the_batch_limit_leaves_the_rest_out_after_the_short_value() {
        let long = "a".repeat(300_000);
        let values = vec![
            value("query.comment", &long, Some("comment"), &[]),
            value("query.tail", "' OR 1=1--", Some("tail"), &[]),
        ];
        let built = build_states(&input(values, None, vec![])).unwrap();
        assert_eq!(built.states.len(), JEV_BATCHES_MAX);
        assert!(built.left_out > 0);
        assert!(
            built.states[0].0.contains("OR 1=1"),
            "the short value is sent in the first batch"
        );
        assert!(
            built
                .states
                .iter()
                .all(|(text, _)| text.len() <= STATE_BYTES_MAX)
        );
    }

    #[test]
    fn requests_that_cannot_fit_fail_instead_of_dropping_values() {
        // Values that 16 batches can hold are sent in batches (see
        // `requests_too_large_for_one_state_are_sent_in_batches_that_hold_every_value_once`). A path
        // number that they cannot hold fails, and no value is dropped (docs/02 section 2.4).
        let digits = "7".repeat(200_000);
        let values = vec![value("path[2]", &digits, None, &[])];
        assert_eq!(
            build_state(&input(values, None, vec![])).unwrap_err(),
            JudgeError::StateTooLarge
        );
    }

    #[test]
    fn a_request_whose_own_shell_is_large_is_batched_at_level_four() {
        let long_path = format!("/share/{}", "x".repeat(7_400));
        let values: Vec<StateValue> = (0..150)
            .map(|index| value(&format!("query.p{index}"), "abcdefgh", Some("p"), &[]))
            .collect();
        let mut request = input(values, None, vec![]);
        request.path = &long_path;
        let built = build_states(&request).unwrap();
        assert!(built.states.len() <= 4, "{} batches", built.states.len());
        assert_eq!(built.left_out, 0);
        assert!(built.states.iter().all(|(_, level)| *level == 4));
    }

    #[test]
    fn request_body_has_both_questions_with_their_options() {
        let body = request_body("typesafe-ai/jev", "{\"a\":1}", &Prompt::new());
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
            // An allow must reach the floor on both questions (docs/02 section 2.3).
            (
                ("ALLOW", [0.6, 0.4, 0.0]),
                ("BENIGN", [0.6, 0.4, 0.0]),
                Conclusion::Allow,
            ),
            (
                ("ALLOW", [0.9, 0.05, 0.05]),
                ("BENIGN", [0.55, 0.43, 0.02]),
                Conclusion::Unknown,
            ),
            (
                ("ALLOW", [0.55, 0.45, 0.0]),
                ("BENIGN", [0.9, 0.05, 0.05]),
                Conclusion::Unknown,
            ),
            // A denial is not held to the floor, however sure Jev is of it.
            (
                ("DENY", [0.3, 0.4, 0.3]),
                ("BENIGN", [0.9, 0.05, 0.05]),
                Conclusion::Deny,
            ),
            (
                ("ALLOW", [0.9, 0.05, 0.05]),
                ("ATTACK", [0.3, 0.4, 0.3]),
                Conclusion::Deny,
            ),
        ];
        for (access, attack, expected) in cases {
            let answers = parse_response(&response(access, attack));
            let answers = answers.unwrap_or_else(|_| panic!("{access:?}"));
            assert_eq!(conclude(&answers), expected, "{access:?} {attack:?}");
        }
    }

    #[test]
    fn an_allow_needs_both_questions_at_the_floor_and_the_floor_counts() {
        // Exactly at the floor is an allow.
        let at = parse_response(&response(
            ("ALLOW", [0.6, 0.4, 0.0]),
            ("BENIGN", [0.6, 0.4, 0.0]),
        ))
        .unwrap();
        assert_eq!(conclude(&at), Conclusion::Allow);
        assert!(!low_confidence(&at));
        // Just under it, on either question alone, is not decidable.
        for (access, attack) in [
            (("ALLOW", [0.59, 0.41, 0.0]), ("BENIGN", [0.9, 0.05, 0.05])),
            (("ALLOW", [0.9, 0.05, 0.05]), ("BENIGN", [0.59, 0.41, 0.0])),
        ] {
            let answers = parse_response(&response(access, attack)).unwrap();
            assert_eq!(
                conclude(&answers),
                Conclusion::Unknown,
                "{access:?} {attack:?}"
            );
            assert!(low_confidence(&answers), "{access:?} {attack:?}");
            assert!(assurance(&answers.access, &answers.attack) < ALLOW_CONFIDENCE_MIN);
        }
    }

    #[test]
    fn the_open_redirect_judged_benign_at_055_is_not_decidable() {
        // The shop's open redirect (GET /redirect?to=https://example.org/x) came back from the real
        // model three times as BENIGN 0.53 to 0.56 with ATTACK 0.41 to 0.45. It was allowed before
        // the floor existed; now the answer is not decidable and the site's policy applies.
        let answers = parse_response(&response(
            ("ALLOW", [0.9, 0.05, 0.05]),
            ("BENIGN", [0.55, 0.43, 0.02]),
        ))
        .unwrap();
        assert_eq!(conclude(&answers), Conclusion::Unknown);
        assert!(low_confidence(&answers));
        assert!((assurance(&answers.access, &answers.attack) - 0.55).abs() < 1e-9);
    }

    #[test]
    fn a_tie_or_an_unknown_top_is_not_a_low_confidence_allow() {
        // Only a top ALLOW with a top BENIGN is held to the floor; anything else keeps JEV_UNKNOWN.
        let tied = parse_response(&response(
            ("ALLOW", [0.5, 0.5, 0.0]),
            ("BENIGN", [0.55, 0.43, 0.02]),
        ))
        .unwrap();
        assert_eq!(conclude(&tied), Conclusion::Unknown);
        assert!(!low_confidence(&tied));
        let unknown = parse_response(&response(
            ("UNKNOWN", [0.2, 0.2, 0.6]),
            ("BENIGN", [0.55, 0.43, 0.02]),
        ))
        .unwrap();
        assert_eq!(conclude(&unknown), Conclusion::Unknown);
        assert!(!low_confidence(&unknown));
    }

    #[test]
    fn a_denial_below_the_floor_still_denies() {
        // Access options are ALLOW, DENY, UNKNOWN in that order: DENY 0.4 is the top choice.
        let denied = parse_response(&response(
            ("DENY", [0.3, 0.4, 0.3]),
            ("BENIGN", [0.55, 0.43, 0.02]),
        ))
        .unwrap();
        assert_eq!(conclude(&denied), Conclusion::Deny);
        assert!(!low_confidence(&denied));
    }

    #[test]
    fn a_denial_beside_a_benign_at_058_stays_a_denial() {
        // Path-only attack probes come back near BENIGN 0.58 on the current prompt. A DENY on access
        // denies whatever the other question says: the low attack must not make it undecidable.
        let answers = parse_response(&response(
            ("DENY", [0.05, 0.9, 0.05]),
            ("BENIGN", [0.58, 0.40, 0.02]),
        ))
        .unwrap();
        assert_eq!(conclude(&answers), Conclusion::Deny);
        assert!(!low_confidence(&answers));
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
