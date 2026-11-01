//! Request and response value extraction (docs/01 sections 1.2 and 1.3).
//!
//! A *value* is a scalar the origin could use to select an object: a path
//! segment, a query or form value, a JSON scalar. Extraction is lossy by
//! design: it only needs to be deterministic and bounded.

use serde_json::Value;

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
    /// The key it travels under, when it has one (`doctor`, `patient.id`).
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
}

/// Request values plus whether the body had to be summarised.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExtractedRequest {
    /// Values in request order.
    pub values: Vec<RequestValue>,
    /// The body was not structured, too large, or the value cap was reached.
    pub truncated: bool,
}

/// Whether a field name reads like an object identifier.
#[must_use]
pub fn is_id_like(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "id" | "uuid" | "guid" | "pk" | "key" | "ref" | "link"
    ) || ["id", "_id", "no", "num", "code", "uuid", "ref"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
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
    value.len() <= 24
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte == b'-')
}

fn inert_value(key: Option<&str>, value: &str) -> bool {
    match key {
        None => is_word(value),
        Some(key) => {
            if is_paging_key(key) {
                return value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit());
            }
            is_word(value) && !is_id_like(key) && !is_identity_key(key)
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
                if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
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

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
    for (index, segment) in path.split('/').filter(|part| !part.is_empty()).enumerate() {
        push(
            &mut out,
            format!("path[{index}]"),
            None,
            percent_decode(segment, false),
        );
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

fn pairs(out: &mut ExtractedRequest, prefix: &str, text: &str) {
    for pair in text.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key, true);
        let value = percent_decode(value, true);
        push(out, format!("{prefix}.{key}"), Some(key), value);
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
                walk_request(out, inner, &format!("{at}.{name}"), Some(name), depth + 1);
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
    if body.len() > RESPONSE_PARSE_MAX {
        return Vec::new();
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
    let mut out = Vec::new();
    match kind.as_str() {
        "application/json" => {
            if let Ok(json) = serde_json::from_slice::<Value>(body) {
                walk_response(&mut out, &json, "value", 0);
            }
        }
        "text/html" | "application/xhtml+xml" => {
            html_values(&mut out, &String::from_utf8_lossy(body));
        }
        _ => {}
    }
    out
}

fn field_name(name: &str) -> String {
    name.chars().take(FIELD_MAX).collect()
}

fn add(out: &mut Vec<ResponseValue>, field: &str, value: String) {
    if !value.is_empty()
        && value.chars().count() <= VALUE_MAX_CHARS
        && out.len() < RESPONSE_VALUES_MAX
    {
        out.push(ResponseValue {
            field: field_name(field),
            value,
        });
    }
}

fn walk_response(out: &mut Vec<ResponseValue>, json: &Value, field: &str, depth: usize) {
    if depth > JSON_DEPTH_MAX {
        return;
    }
    match json {
        Value::Object(map) => {
            for (name, inner) in map {
                walk_response(out, inner, name, depth + 1);
            }
        }
        Value::Array(items) => {
            for inner in items {
                walk_response(out, inner, field, depth + 1);
            }
        }
        Value::String(text) => add(out, field, text.clone()),
        Value::Number(number) => add(out, field, number.to_string()),
        Value::Bool(_) | Value::Null => {}
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
}
