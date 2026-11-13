//! Request and response value extraction (docs/01 sections 1.2 and 1.3).
//!
//! A *value* is a scalar the origin could use to select an object: a path
//! segment, a query or form value, a JSON scalar. Extraction is lossy by
//! design: it only needs to be deterministic and bounded.

use std::collections::BTreeSet;

use serde_json::Value;
use xshield_core::context::{SHAPE_FIELDS_MAX, ShapeField};
use xshield_core::hex::hex_digit;
use xshield_core::kind::kind_words;

// The field and location rules are shared with the control plane's impact preview,
// so both read them from `xshield_core::kind`.
pub use xshield_core::kind::{is_id_like, path_segment};

/// Longest value kept; longer scalars are not object references.
pub const VALUE_MAX_CHARS: usize = 128;
/// Most values taken from one response.
pub const RESPONSE_VALUES_MAX: usize = 2_000;
/// Most values taken from one request.
pub const REQUEST_VALUES_MAX: usize = 200;
/// Largest request body parsed for values.
pub const BODY_PARSE_MAX: usize = 64 * 1024;
/// Largest response body parsed for values (docs/01 section 1.2).
pub const RESPONSE_PARSE_MAX: usize = 1024 * 1024;
const JSON_DEPTH_MAX: usize = 16;
const FIELD_MAX: usize = 32;

/// One scalar found in a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestValue {
    /// Location, for example `path[2]`, `query.doctor`, `body.patient.id`.
    pub at: String,
    /// The decoded value.
    pub value: String,
    /// The key it travels under, when it has one: a query, form or body name
    /// (`doctor`), or for a bare identifier nested in a named object that
    /// object's name (`patient.id`).
    pub key: Option<String>,
    /// Whether the value can never be an object reference or an injection
    /// payload on its own (a route word, a pagination number).
    pub inert: bool,
}

/// One scalar the origin returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseValue {
    /// Field name it appeared under (`id`, `patient_id`, `link`).
    pub field: String,
    /// The value.
    pub value: String,
    /// Where it sits in the response: the JSON path with `[]` for array items
    /// (`[].doc_id`, `attachments[].doc_id`), `$` for a bare scalar, and the
    /// field name for HTML (`link`, `value`). Empty when the path is too long to
    /// keep; such a value is still judged, but no position is learned from it.
    pub at: String,
}

/// Request values plus whether the body had to be summarised.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExtractedRequest {
    /// Values in request order.
    pub values: Vec<RequestValue>,
    /// The body was not structured, too large, or the value cap was reached.
    pub truncated: bool,
}

/// What a successful response teaches: its scalars with their positions, and
/// for JSON its structure.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResponseFacts {
    /// Scalars in the order the JSON parser yields them (object keys sorted).
    pub values: Vec<ResponseValue>,
    /// Field paths and types, sorted by path, at most [`SHAPE_FIELDS_MAX`].
    /// `Some` only for a JSON document that parsed, where an empty document
    /// has an empty structure. `None` for HTML, for a body that was not read,
    /// and for JSON that did not parse, so a broken body is never reported as
    /// a structure.
    pub shape: Option<Vec<ShapeField>>,
}

/// The longest response position kept, in bytes.
const AT_MAX: usize = 128;

/// What a request value is for the access question: `reference` where an
/// object reference would sit (an id-like path segment, or a field whose name
/// reads like an id, an owner or a file), `route` for a plain-word path
/// segment (a collection name such as `Addresss`, or occasionally a person's
/// name), `input` for everything else. A `name` in a request body is `input` too:
/// the name typed into a new record, not a pointer to an existing one.
#[must_use]
pub fn value_kind(at: &str, key: Option<&str>, value: &str) -> &'static str {
    if at.starts_with("path[") {
        return if value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            "route"
        } else {
            "reference"
        };
    }
    let reference = key.is_some_and(|key| {
        let lower = key.to_ascii_lowercase();
        is_id_like(key)
            || (is_identity_key(key) && !is_body_name(at, key))
            || [
                "file", "path", "doc", "record", "order", "share", "token", "basket", "item",
            ]
            .iter()
            .any(|word| lower.contains(word))
    });
    if reference { "reference" } else { "input" }
}

/// A `name` key in a request body (JSON or form) is free text: the name typed
/// into a new record (docs/01 section 1.5). A query or a path can use the same
/// key to look an object up by name (`?name=`), so it stays a reference there.
fn is_body_name(at: &str, key: &str) -> bool {
    (at.starts_with("body.") || at.starts_with("body[")) && key.eq_ignore_ascii_case("name")
}

fn is_identity_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "user", "name", "owner", "account", "email", "doctor", "patient", "member", "login", "uid",
    ]
    .iter()
    .any(|word| lower.contains(word))
}

fn is_paging_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().replace(['_', '-'], "").as_str(),
        "page"
            | "pagesize"
            | "size"
            | "limit"
            | "offset"
            | "perpage"
            | "count"
            | "skip"
            | "take"
            | "index"
    )
}

fn is_word(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 40
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte == b'-')
}

/// A path segment made only of letters (`api`, `Addresss`, `BasketItems`).
/// Before another segment it is a route name; as the last segment it may be
/// an object name (`/users/Alice`), so only lowercase words are inert there.
fn is_route_word(value: &str) -> bool {
    value.len() <= 32
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte == b'_' || byte == b'-')
}

/// An ISO date or time (`2026-11-01`, `2026-11-01T10:20:30Z`) or a JavaScript
/// date string (`Sun Nov 01 2026`): digits, letters of a fixed shape and a few
/// separators, so neither an object name nor a payload.
fn is_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    let iso = bytes.len() >= 10
        && bytes.len() <= 32
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[10..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || b" :.+-TZ".contains(byte));
    let words: Vec<&str> = value.split(' ').collect();
    let js = words.len() == 4
        && words[0].len() == 3
        && words[1].len() == 3
        && words[0]
            .bytes()
            .chain(words[1].bytes())
            .all(|b| b.is_ascii_alphabetic())
        && words[2].len() == 2
        && words[3].len() == 4
        && words[2]
            .bytes()
            .chain(words[3].bytes())
            .all(|b| b.is_ascii_digit());
    iso || js
}

fn inert_value(key: Option<&str>, value: &str) -> bool {
    match key {
        None => is_word(value),
        Some(key) => {
            if is_paging_key(key) {
                return value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit());
            }
            (is_word(value) || is_date(value)) && !is_id_like(key) && !is_identity_key(key)
        }
    }
}

/// Percent-decodes `text`; `plus` also maps `+` to a space (query and forms).
#[must_use]
pub fn percent_decode(text: &str, plus: bool) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (hex_digit(bytes[index + 1]), hex_digit(bytes[index + 2]))
                {
                    out.push(high * 16 + low);
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            b'+' if plus => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decodes the JSON `\uXXXX` escapes of `text`, so that the tokens of an escaped
/// value match the value the origin decodes from it. A malformed escape stays as
/// it is. The other JSON escapes (`\"`, `\\`, `\/`) only sit beside a token, where
/// the tokenizer already splits.
#[must_use]
pub fn json_unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find("\\u") {
        out.push_str(&rest[..index]);
        let decoded = rest
            .get(index + 2..index + 6)
            .and_then(|digits| u32::from_str_radix(digits, 16).ok())
            .and_then(char::from_u32);
        if let Some(c) = decoded {
            out.push(c);
            rest = &rest[index + 6..];
        } else {
            out.push_str("\\u");
            rest = &rest[index + 2..];
        }
    }
    out.push_str(rest);
    out
}

fn push(out: &mut ExtractedRequest, at: String, key: Option<String>, value: String) {
    if value.is_empty() {
        return;
    }
    if out.values.len() >= REQUEST_VALUES_MAX {
        out.truncated = true;
        return;
    }
    let inert = inert_value(key.as_deref(), &value);
    out.values.push(RequestValue {
        at,
        value,
        key,
        inert,
    });
}

/// Extracts every value of one request. The credential is never passed in.
#[must_use]
pub fn extract_request(
    path: &str,
    query: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> ExtractedRequest {
    let mut out = ExtractedRequest::default();
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    for (index, segment) in segments.iter().enumerate() {
        let value = percent_decode(segment, false);
        let route = index + 1 < segments.len() && is_route_word(&value);
        push(&mut out, format!("path[{index}]"), None, value);
        if let Some(last) = out.values.last_mut().filter(|_| route) {
            last.inert = true;
        }
    }
    if let Some(query) = query {
        pairs(&mut out, "query", query);
    }
    if body.is_empty() {
        return out;
    }
    let kind = content_type
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    if body.len() > BODY_PARSE_MAX {
        out.truncated = true;
    }
    let parsed = body.len() <= BODY_PARSE_MAX
        && match kind.as_str() {
            "application/x-www-form-urlencoded" => {
                pairs(&mut out, "body", &String::from_utf8_lossy(body));
                true
            }
            "application/json" => serde_json::from_slice::<Value>(body).is_ok_and(|json| {
                walk_request(&mut out, &json, "body", None, 0);
                true
            }),
            _ => false,
        };
    if !parsed {
        out.truncated = true;
        let head = &body[..body.len().min(2048)];
        push(
            &mut out,
            "body".to_owned(),
            None,
            String::from_utf8_lossy(head).into_owned(),
        );
    }
    out
}

/// A field *name* that carries syntax (`$ne`, `a'b`, `x;y`) is itself input:
/// `NoSQL` operators and key-based injections travel in names, not values.
fn push_unusual_key(out: &mut ExtractedRequest, at: &str, name: &str) {
    let unusual = name.starts_with('$')
        || name.chars().any(|c| {
            matches!(
                c,
                '$' | '\''
                    | '"'
                    | ';'
                    | '|'
                    | '&'
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '{'
                    | '}'
                    | '`'
                    | '\\'
                    | '/'
                    | ' '
            )
        });
    if unusual {
        push(out, format!("{at}#name"), None, name.to_owned());
    }
}

fn pairs(out: &mut ExtractedRequest, prefix: &str, text: &str) {
    for pair in text.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key, true);
        let value = percent_decode(value, true);
        push_unusual_key(out, &format!("{prefix}.{key}"), &key);
        push(out, format!("{prefix}.{key}"), Some(key), value);
    }
}

/// The key a JSON member travels under. A bare identifier nested in a named
/// object takes the object's name (`doc.id`), as the response side names
/// `Doc.id`, so the object decides what the id is. The member's own name still
/// decides how the value is judged.
fn member_key(parent: Option<&str>, name: &str) -> String {
    match parent {
        Some(parent)
            if is_id_like(name)
                && kind_words(name).is_empty()
                && !is_wrapper_key(parent)
                && !kind_words(parent).is_empty() =>
        {
            format!("{parent}.{name}")
        }
        _ => name.to_owned(),
    }
}

fn walk_request(
    out: &mut ExtractedRequest,
    json: &Value,
    at: &str,
    key: Option<&str>,
    depth: usize,
) {
    if depth > JSON_DEPTH_MAX {
        out.truncated = true;
        return;
    }
    match json {
        Value::Object(map) => {
            for (name, inner) in map {
                push_unusual_key(out, &format!("{at}.{name}"), name);
                let named = member_key(key, name);
                walk_request(out, inner, &format!("{at}.{name}"), Some(&named), depth + 1);
            }
        }
        Value::Array(items) => {
            for inner in items {
                walk_request(out, inner, &format!("{at}[]"), key, depth + 1);
            }
        }
        Value::String(text) => push(out, at.to_owned(), key.map(str::to_owned), text.clone()),
        Value::Number(number) => push(
            out,
            at.to_owned(),
            key.map(str::to_owned),
            number.to_string(),
        ),
        Value::Bool(_) | Value::Null => {}
    }
}

/// Extracts the values of a successful response. Unparsed types yield none.
#[must_use]
pub fn extract_response(content_type: Option<&str>, body: &[u8]) -> Vec<ResponseValue> {
    extract_response_facts(content_type, body).values
}

/// Extracts the values and, for JSON, the structure of a successful response.
/// Unparsed types and oversized bodies yield nothing.
#[must_use]
pub fn extract_response_facts(content_type: Option<&str>, body: &[u8]) -> ResponseFacts {
    let mut facts = ResponseFacts::default();
    if body.len() > RESPONSE_PARSE_MAX {
        return facts;
    }
    let kind = content_type
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    match kind.as_str() {
        "application/json" => {
            if let Ok(json) = serde_json::from_slice::<Value>(body) {
                let mut shape = BTreeSet::new();
                walk_response(&mut facts.values, &mut shape, &json, "", "value", "", 0);
                facts.shape = Some(
                    shape
                        .into_iter()
                        .map(|(path, kind)| ShapeField {
                            path,
                            kind: kind.to_owned(),
                        })
                        .collect(),
                );
            }
        }
        "text/html" | "application/xhtml+xml" => {
            html_values(&mut facts.values, &String::from_utf8_lossy(body));
        }
        _ => {}
    }
    facts
}

fn field_name(name: &str) -> String {
    name.chars().take(FIELD_MAX).collect()
}

/// The position a value keeps: `$` for a bare scalar, empty when the path is
/// too long to keep.
fn position(at: &str) -> String {
    if at.is_empty() {
        "$".to_owned()
    } else if at.len() <= AT_MAX {
        at.to_owned()
    } else {
        String::new()
    }
}

fn add_at(out: &mut Vec<ResponseValue>, field: &str, at: &str, value: String) {
    if !value.is_empty()
        && value.chars().count() <= VALUE_MAX_CHARS
        && out.len() < RESPONSE_VALUES_MAX
    {
        out.push(ResponseValue {
            field: field_name(field),
            value,
            at: position(at),
        });
    }
}

/// HTML values: the position is the field name itself.
fn add(out: &mut Vec<ResponseValue>, field: &str, value: String) {
    add_at(out, field, field, value);
}

/// Records one structure entry, keeping the [`SHAPE_FIELDS_MAX`] smallest paths
/// seen so far, since that is what the structure reports. Positions too long to
/// keep are left out, as they are for values. A path that sorts after all the
/// kept ones is dropped, so a field late in a long list still shows when it
/// sorts early.
fn note_shape(shape: &mut BTreeSet<(String, &'static str)>, at: &str, kind: &'static str) {
    if at.len() > AT_MAX {
        return;
    }
    let entry = (position(at), kind);
    if shape.contains(&entry) {
        return;
    }
    if shape.len() < SHAPE_FIELDS_MAX {
        shape.insert(entry);
    } else if shape.last().is_some_and(|last| entry < *last) {
        shape.pop_last();
        shape.insert(entry);
    }
}

/// Generic wrapper keys that say nothing about the kind of object inside.
fn is_wrapper_key(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "data"
            | "value"
            | "items"
            | "results"
            | "result"
            | "response"
            | "rows"
            | "list"
            | "records"
    )
}

/// `BasketItem.id` for an identifier nested in a named object, so the model
/// and the specificity check can tell a basket id from a product id.
fn qualified(parent: &str, field: &str) -> String {
    if is_id_like(field) && !parent.is_empty() && !is_wrapper_key(parent) {
        format!("{parent}.{field}")
    } else {
        field.to_owned()
    }
}

/// Walks a JSON response. `at` is the JSON path so far: empty at the root,
/// `attachments[]` inside an array, `attachments[].doc_id` at a field.
fn walk_response(
    out: &mut Vec<ResponseValue>,
    shape: &mut BTreeSet<(String, &'static str)>,
    json: &Value,
    parent: &str,
    field: &str,
    at: &str,
    depth: usize,
) {
    if depth > JSON_DEPTH_MAX {
        return;
    }
    match json {
        Value::Object(map) => {
            for (name, inner) in map {
                let child = if at.is_empty() {
                    name.clone()
                } else {
                    format!("{at}.{name}")
                };
                walk_response(out, shape, inner, field, name, &child, depth + 1);
            }
        }
        Value::Array(items) => {
            let item = format!("{at}[]");
            for inner in items {
                walk_response(out, shape, inner, parent, field, &item, depth + 1);
            }
        }
        Value::String(text) => {
            note_shape(shape, at, "string");
            add_at(out, &qualified(parent, field), at, text.clone());
        }
        Value::Number(number) => {
            note_shape(shape, at, "number");
            add_at(out, &qualified(parent, field), at, number.to_string());
        }
        Value::Bool(_) => note_shape(shape, at, "boolean"),
        Value::Null => note_shape(shape, at, "null"),
    }
}

fn html_values(out: &mut Vec<ResponseValue>, html: &str) {
    for (attribute, field) in [
        ("href", "link"),
        ("src", "link"),
        ("action", "link"),
        ("value", "value"),
    ] {
        let mut rest = html;
        let needle = format!("{attribute}=");
        while let Some(found) = rest.find(&needle) {
            let after = &rest[found + needle.len()..];
            let Some(quote) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else {
                rest = after;
                continue;
            };
            let inner = &after[1..];
            let Some(end) = inner.find(quote) else { break };
            let attribute_value = &inner[..end];
            if field == "link" {
                link_values(out, attribute_value);
            } else {
                add(out, "value", attribute_value.to_owned());
            }
            rest = &inner[end..];
        }
    }
}

fn link_values(out: &mut Vec<ResponseValue>, link: &str) {
    let without_origin = link.find("://").map_or(link, |at| {
        link[at + 3..]
            .find('/')
            .map_or("", |slash| &link[at + 3 + slash..])
    });
    let (path, query) = without_origin
        .split_once('?')
        .unwrap_or((without_origin, ""));
    for segment in path.split('/').filter(|part| !part.is_empty()) {
        add(out, "link", percent_decode(segment, false));
    }
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (_, value) = pair.split_once('=').unwrap_or((pair, ""));
        add(out, "link", percent_decode(value, true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(extracted: &ExtractedRequest) -> Vec<(&str, &str, bool)> {
        extracted
            .values
            .iter()
            .map(|value| (value.at.as_str(), value.value.as_str(), value.inert))
            .collect()
    }

    #[test]
    fn path_segments_split_and_route_words_are_inert() {
        let request = extract_request("/api/patients/8", None, None, b"");
        assert_eq!(
            values(&request),
            [
                ("path[0]", "api", true),
                ("path[1]", "patients", true),
                ("path[2]", "8", false)
            ]
        );
    }

    #[test]
    fn camel_case_route_names_are_inert_but_ids_are_not() {
        let request = extract_request("/api/BasketItems/9", None, None, b"");
        assert_eq!(
            values(&request),
            vec![
                ("path[0]", "api", true),
                ("path[1]", "BasketItems", true),
                ("path[2]", "9", false)
            ]
        );
        let request = extract_request("/rest/user/'%20OR%201=1", None, None, b"");
        assert!(request.values.iter().any(|value| !value.inert));
        // The last segment may be an object name, and hyphenated ids are ids.
        let request = extract_request("/rest/admin/application-configuration", None, None, b"");
        assert!(request.values.iter().all(|value| value.inert));
        let request = extract_request("/api/users/Alice", None, None, b"");
        assert!(!request.values[2].inert);
        let request = extract_request("/api/patients/patient-S-shared", None, None, b"");
        assert!(!request.values[2].inert);
    }

    #[test]
    fn dates_are_inert_unless_they_travel_under_an_id_key() {
        let request = extract_request(
            "/api/Products/1",
            Some("d=Sun%20Nov%2001%202026&since=2026-11-01T10%3A20%3A30Z&owner_id=2026-11-01"),
            None,
            b"",
        );
        let got = values(&request);
        assert!(got.contains(&("query.d", "Sun Nov 01 2026", true)));
        assert!(got.contains(&("query.since", "2026-11-01T10:20:30Z", true)));
        assert!(got.contains(&("query.owner_id", "2026-11-01", false)));
        let request = extract_request("/x", Some("d=Sun%20Nov%2001%202026%27%20OR%201"), None, b"");
        assert!(!request.values[1].inert);
    }

    #[test]
    fn query_values_are_decoded_and_paging_is_inert() {
        let request = extract_request("/x", Some("page=2&doctor=B&sort=asc&q=a%27+b"), None, b"");
        let got = values(&request);
        assert!(got.contains(&("query.page", "2", true)));
        assert!(got.contains(&("query.doctor", "B", false)));
        assert!(got.contains(&("query.sort", "asc", true)));
        assert!(got.contains(&("query.q", "a' b", false)));
    }

    #[test]
    fn identity_keys_keep_lowercase_words_judgeable() {
        let request = extract_request("/", Some("username=bob&owner_id=bob"), None, b"");
        assert_eq!(request.values.len(), 2);
        assert!(request.values.iter().all(|value| !value.inert));
    }

    #[test]
    fn a_name_in_a_body_is_input_but_a_name_in_a_query_still_selects() {
        let body = br#"{"name":"Chen Yu","patient":{"name":"Wang Fang"},"items":[{"name":"Li"}],"username":"bob","patient_id":"P-7"}"#;
        let request = extract_request(
            "/api/patients",
            Some("name=Zhang"),
            Some("application/json"),
            body,
        );
        let kind_of = |at: &str| {
            let value = request.values.iter().find(|value| value.at == at).unwrap();
            value_kind(&value.at, value.key.as_deref(), &value.value)
        };
        assert_eq!(kind_of("body.name"), "input");
        assert_eq!(kind_of("body.patient.name"), "input");
        assert_eq!(kind_of("body.items[].name"), "input");
        assert_eq!(kind_of("body.username"), "reference");
        assert_eq!(kind_of("body.patient_id"), "reference");
        assert_eq!(kind_of("query.name"), "reference");
        // A top-level array of records is body content too.
        let list = extract_request(
            "/api/patients",
            None,
            Some("application/json"),
            br#"[{"name":"Li"}]"#,
        );
        let name = list
            .values
            .iter()
            .find(|value| value.at == "body[].name")
            .unwrap();
        assert_eq!(
            value_kind(&name.at, name.key.as_deref(), &name.value),
            "input"
        );
    }

    #[test]
    fn json_bodies_yield_scalars_with_paths() {
        let body = br#"{"patient":{"id":7,"tags":["a","b"],"ok":true},"note":"x' OR 1=1"}"#;
        let request = extract_request("/", None, Some("application/json; charset=utf-8"), body);
        let got = values(&request);
        assert!(got.contains(&("body.patient.id", "7", false)));
        assert!(got.contains(&("body.patient.tags[]", "a", true)));
        assert!(got.contains(&("body.note", "x' OR 1=1", false)));
        assert!(!request.truncated);
    }

    #[test]
    fn a_bare_id_nested_in_a_named_object_travels_under_the_object_name() {
        let body = br#"{"doc":{"id":5,"no":"A1"},"data":{"id":6},"ids":[7],"id":8,"patient":{"ok":"active"}}"#;
        let request = extract_request("/api/records", None, Some("application/json"), body);
        let keys: Vec<(&str, Option<&str>)> = request
            .values
            .iter()
            .map(|value| (value.at.as_str(), value.key.as_deref()))
            .collect();
        assert!(keys.contains(&("body.doc.id", Some("doc.id"))));
        assert!(keys.contains(&("body.doc.no", Some("doc.no"))));
        // A wrapper object says nothing about its id, and `ids` is no identifier name.
        assert!(keys.contains(&("body.data.id", Some("id"))));
        assert!(keys.contains(&("body.ids[]", Some("ids"))));
        assert!(keys.contains(&("body.id", Some("id"))));
        // Only the key changes: a name that is no identifier is judged as before.
        let ok = request
            .values
            .iter()
            .find(|value| value.at == "body.patient.ok")
            .unwrap();
        assert_eq!(ok.key.as_deref(), Some("ok"));
        assert!(ok.inert);
    }

    #[test]
    fn unstructured_or_oversized_bodies_are_summarised_and_flagged() {
        let request = extract_request("/", None, Some("application/octet-stream"), b"abc");
        assert!(request.truncated);
        assert_eq!(request.values.last().unwrap().at, "body");
        let big = vec![b'a'; BODY_PARSE_MAX + 1];
        assert!(extract_request("/", None, Some("application/json"), &big).truncated);
        assert!(extract_request("/", None, Some("application/json"), b"{broken").truncated);
    }

    #[test]
    fn form_bodies_parse_like_queries() {
        let request = extract_request(
            "/",
            None,
            Some("application/x-www-form-urlencoded"),
            b"a=1&b=%3Cx%3E",
        );
        assert!(values(&request).contains(&("body.b", "<x>", false)));
    }

    #[test]
    fn value_cap_sets_truncated() {
        let query = (0..REQUEST_VALUES_MAX + 5)
            .map(|i| format!("k{i}=v{i}"))
            .collect::<Vec<_>>()
            .join("&");
        let request = extract_request("/", Some(&query), None, b"");
        assert_eq!(request.values.len(), REQUEST_VALUES_MAX);
        assert!(request.truncated);
    }

    #[test]
    fn id_like_fields() {
        for field in [
            "id",
            "patient_id",
            "patientId",
            "uuid",
            "orderNo",
            "code",
            "link",
        ] {
            assert!(is_id_like(field), "{field}");
        }
        for field in ["age", "name", "status"] {
            assert!(!is_id_like(field), "{field}");
        }
    }

    #[test]
    fn json_responses_yield_scalars_under_their_field() {
        let body = br#"{"items":[{"id":7,"name":"A","age":8},{"id":9}],"total":2,"ok":true}"#;
        let got = extract_response(Some("application/json"), body);
        let pairs: Vec<_> = got
            .iter()
            .map(|v| (v.field.as_str(), v.value.as_str()))
            .collect();
        assert!(pairs.contains(&("id", "7")));
        assert!(pairs.contains(&("age", "8")));
        assert!(pairs.contains(&("id", "9")));
        assert!(pairs.contains(&("total", "2")));
    }

    #[test]
    fn html_responses_yield_link_segments_and_form_values() {
        let body = br#"<a href="/patients/P-0042?tab=notes">x</a><form action='/p/9'><input name=a value="v1"></form>"#;
        let got = extract_response(Some("text/html"), body);
        let values: Vec<_> = got.iter().map(|v| v.value.as_str()).collect();
        for expected in ["patients", "P-0042", "notes", "9", "v1"] {
            assert!(values.contains(&expected), "{expected}");
        }
    }

    #[test]
    fn oversized_or_binary_responses_yield_nothing() {
        assert!(extract_response(Some("image/png"), b"\x89PNG").is_empty());
        assert!(
            extract_response(
                Some("application/json"),
                &vec![b' '; RESPONSE_PARSE_MAX + 1]
            )
            .is_empty()
        );
    }

    #[test]
    fn percent_decoding_is_lossy_and_total() {
        assert_eq!(percent_decode("a%2Fb%zz%", false), "a/b%zz%");
        assert_eq!(percent_decode("a+b", true), "a b");
        assert_eq!(percent_decode("a+b", false), "a+b");
    }

    #[test]
    fn json_unicode_escapes_decode_and_malformed_ones_stay() {
        assert_eq!(
            json_unescape(r#"{"id":"P-0000099"}"#),
            r#"{"id":"P-0000099"}"#
        );
        assert_eq!(json_unescape(r"\uZZZZ \u00"), r"\uZZZZ \u00");
        assert_eq!(json_unescape("plain text"), "plain text");
    }

    #[test]
    fn operator_and_syntax_bearing_field_names_are_values() {
        let body = br#"{"username":{"$ne":null},"password":{"$ne":null},"ok_name":"fine1x"}"#;
        let out = extract_request("/", None, Some("application/json"), body);
        let names: Vec<&str> = out
            .values
            .iter()
            .filter(|v| v.at.ends_with("#name"))
            .map(|v| v.value.as_str())
            .collect();
        assert_eq!(names, vec!["$ne", "$ne"]);
        let form = extract_request(
            "/",
            None,
            Some("application/x-www-form-urlencoded"),
            b"user%5B%24ne%5D=&plain=1",
        );
        assert!(
            form.values
                .iter()
                .any(|v| v.at.ends_with("#name") && v.value == "user[$ne]")
        );
        assert!(!form.values.iter().any(|v| v.at.ends_with("plain#name")));
    }

    #[test]
    fn response_values_keep_their_positions() {
        let body = br#"{"items":[{"id":5,"name":"a"}],"total":2,"meta":{"doc_id":7}}"#;
        let at: Vec<String> = extract_response(Some("application/json"), body)
            .into_iter()
            .map(|value| value.at)
            .collect();
        assert_eq!(at, ["items[].id", "items[].name", "meta.doc_id", "total"]);
        let root: Vec<String> = extract_response(Some("application/json"), br#"[{"doc_id":2}]"#)
            .into_iter()
            .map(|value| value.at)
            .collect();
        assert_eq!(root, ["[].doc_id"]);
        let bare = extract_response(Some("application/json"), br#""abc""#);
        assert_eq!(bare[0].at, "$");
        let html = extract_response(Some("text/html"), br#"<input value="7">"#);
        assert_eq!(html[0].at, "value");
    }

    #[test]
    fn a_position_too_long_to_keep_is_left_empty() {
        let long = "k".repeat(AT_MAX + 1);
        let body = format!(r#"{{"{long}":"abc"}}"#);
        let values = extract_response(Some("application/json"), body.as_bytes());
        assert_eq!(values.len(), 1);
        assert!(values[0].at.is_empty());
        assert!(
            extract_response_facts(Some("application/json"), body.as_bytes())
                .shape
                .is_some_and(|shape| shape.is_empty())
        );
    }

    #[test]
    fn response_shape_lists_each_path_with_its_types_and_no_values() {
        let body = br#"[{"id":1,"ok":true,"note":null,"name":"x"},{"id":2,"ok":false,"note":"n","name":"y"}]"#;
        let facts = extract_response_facts(Some("application/json"), body);
        let shape: Vec<(&str, &str)> = facts
            .shape
            .iter()
            .flatten()
            .map(|field| (field.path.as_str(), field.kind.as_str()))
            .collect();
        assert_eq!(
            shape,
            [
                ("[].id", "number"),
                ("[].name", "string"),
                ("[].note", "null"),
                ("[].note", "string"),
                ("[].ok", "boolean"),
            ]
        );
        assert!(
            extract_response_facts(Some("text/html"), b"<a href='/x/1'>")
                .shape
                .is_none()
        );
    }

    #[test]
    fn a_body_that_does_not_parse_has_no_structure() {
        let facts = extract_response_facts(Some("application/json"), b"{bad");
        assert!(facts.values.is_empty());
        assert_eq!(facts.shape, None);
        // An empty document is a structure with no fields, not a failure.
        assert_eq!(
            extract_response_facts(Some("application/json"), b"[]").shape,
            Some(Vec::new())
        );
    }

    #[test]
    fn a_long_list_keeps_the_first_paths_whatever_comes_after_them() {
        let mut items: Vec<String> = (0..5_000)
            .map(|index| format!(r#"{{"z{index:04}":1}}"#))
            .collect();
        items.push(r#"{"a":1}"#.to_owned());
        let body = format!("[{}]", items.join(","));
        let shape = extract_response_facts(Some("application/json"), body.as_bytes())
            .shape
            .expect("a parsed document has a structure");
        assert_eq!(shape.len(), SHAPE_FIELDS_MAX);
        // `[].a` sorts before all 5,000 of the `[].z...` paths that came first.
        assert_eq!(shape[0].path, "[].a");
        assert_eq!(shape[0].kind, "number");
        assert!(shape.windows(2).all(|pair| pair[0].path <= pair[1].path));
    }
}
