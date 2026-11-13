//! Request and response value extraction (docs/01 sections 1.2 and 1.3).
//!
//! A *value* is a scalar the origin could use to select an object: a path
//! segment, a query or form value, a JSON scalar. Extraction is lossy by
//! design: it only needs to be deterministic and bounded.

use std::collections::{BTreeSet, HashMap};

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use xshield_core::context::{SHAPE_FIELDS_MAX, ShapeField};
use xshield_core::hex::hex_digit;
use xshield_core::kind::kind_words;

// The field and location rules are shared with the control plane's impact preview,
// so both read them from `xshield_core::kind`.
pub use xshield_core::kind::{is_id_like, path_segment};

/// Longest value kept; longer scalars are not object references.
pub const VALUE_MAX_CHARS: usize = 128;
/// Largest string kept as a login credential candidate, in bytes (docs/01 section 1.7). A longer
/// string is dropped.
pub const CREDENTIAL_MAX_BYTES: usize = 8 * 1024;
/// Most credential candidates taken from one response, in document order.
pub const CREDENTIAL_CANDIDATES_MAX: usize = 16;
/// Most values taken from one response.
pub const RESPONSE_VALUES_MAX: usize = 2_000;
/// Largest response body parsed for values (docs/01 section 1.2).
pub const RESPONSE_PARSE_MAX: usize = 1024 * 1024;
/// Deepest JSON container walked member by member. A container below it is one value: its JSON
/// text (docs/01 section 1.3).
const JSON_DEPTH_MAX: usize = 16;
/// A field name longer than this is judged as a name that carries syntax (docs/01 section 1.3).
const KEY_CHARS_MAX: usize = 64;
const FIELD_MAX: usize = 32;
/// Most distinct field names read for one multipart part. A part with more is read as one text.
const PART_NAMES_MAX: usize = 4;

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

/// Request values plus whether they cover the whole request.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExtractedRequest {
    /// Values in request order.
    pub values: Vec<RequestValue>,
    /// The body is not structured data and was judged as one text (docs/01 section 1.3), or a
    /// multipart part carries a file whose content is not extracted, or a part could not be read
    /// into its parts. The values then do not cover every byte the origin may echo.
    pub truncated: bool,
}

/// What a successful response teaches: its scalars with their positions, and
/// for JSON its structure.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResponseFacts {
    /// Scalars in the order the JSON parser yields them (object keys sorted).
    pub values: Vec<ResponseValue>,
    /// Strings too long to be values but shaped like a credential: longer than
    /// [`VALUE_MAX_CHARS`], at most [`CREDENTIAL_MAX_BYTES`] bytes, only visible ASCII, and not
    /// a URL or a data URI. Taken in the order of `values`, at most
    /// [`CREDENTIAL_CANDIDATES_MAX`]. They only serve to bind a login (docs/01 section 1.7):
    /// they are never values of the session.
    pub credentials: Vec<ResponseValue>,
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
    let inert = inert_value(key.as_deref(), &value);
    out.values.push(RequestValue {
        at,
        value,
        key,
        inert,
    });
}

/// The media type of a `Content-Type` header value: the part before the parameters,
/// trimmed and in lower case.
#[must_use]
pub fn media_kind(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Whether a media type (parameters already removed, lower case) is a JSON document:
/// `application/json` or a structured-syntax suffix type such as `application/vnd.api+json`.
#[must_use]
pub fn is_json_media(kind: &str) -> bool {
    kind == "application/json" || (kind.starts_with("application/") && kind.ends_with("+json"))
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
    let kind = content_type.map(media_kind).unwrap_or_default();
    // A body whose text starts like a JSON object or array, and parses as one, is read as JSON
    // whatever its type. It is also read as its type says, so one body can be both (docs/01 section
    // 1.3).
    let text = body.trim_ascii();
    let json = matches!(text.first(), Some(b'{' | b'[')) && walk_json(&mut out, text, "body", None);
    let lossy = String::from_utf8_lossy(body);
    if kind == "application/x-www-form-urlencoded" {
        // A form-typed body is read as its fields, every one of them.
        pairs(&mut out, "body", &lossy);
        return out;
    }
    if kind.is_empty() {
        // With no type, each reading that makes sense is taken (docs/01 section 1.3). A body of the
        // strict shape of a form is read as its fields, every one of them. Any other body is read
        // for the names that look like field names, and it is one text as well unless it is JSON or
        // a form.
        let form = form_shaped(body);
        if form {
            pairs(&mut out, "body", &lossy);
        } else {
            loose_pairs(&mut out, &lossy);
        }
        if !json && !form {
            whole_body(&mut out, body);
        }
        return out;
    }
    if json {
        return out;
    }
    // The body is read as its media type says (docs/01 section 1.3). A body that does not read as
    // structured data is judged as one text.
    let read = match kind.as_str() {
        // Every multipart type with a boundary is read by its parts: form-data, mixed, related, ...
        kind if kind.starts_with("multipart/") => content_type
            .and_then(boundary_of)
            .is_some_and(|boundary| multipart_body(&mut out, body, &boundary)),
        kind if is_json_media(kind) => walk_json(&mut out, body, "body", None),
        _ => false,
    };
    if !read {
        whole_body(&mut out, body);
    }
    out
}

/// A body read as one text: its bytes decoded leniently, as one value at `body` with no key. The
/// body is not structured data, so the request is flagged truncated (docs/01 section 1.3).
fn whole_body(out: &mut ExtractedRequest, body: &[u8]) {
    out.truncated = true;
    push(
        out,
        "body".to_owned(),
        None,
        String::from_utf8_lossy(body).into_owned(),
    );
}

/// Whether a body with no type has the shape of a form (docs/01 section 1.3): once its blanks at the
/// ends are trimmed it is not empty, it holds no whitespace, control character or `;`, and every
/// `&`-separated segment holds an `=`. A `;` may split fields at the origin too, so such a body is
/// kept as one text.
fn form_shaped(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body.trim_ascii());
    !text.is_empty()
        && !text
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == ';')
        && text.split('&').all(|segment| segment.contains('='))
}

/// Walks `bytes` as a JSON document into values at `at`. Returns false, having read nothing, when
/// the bytes are not JSON.
fn walk_json(out: &mut ExtractedRequest, bytes: &[u8], at: &str, key: Option<&str>) -> bool {
    match serde_json::from_slice::<Json>(bytes) {
        Ok(json) => {
            walk_request(out, &json, at, key, 0);
            true
        }
        Err(_) => false,
    }
}

/// The parameters of a header value after its first part, such as `form-data; name="a"`. Names are
/// lower case and quotes are taken off the values; a quoted value may hold `;` and a backslash
/// escapes the next character. The plain parameters that RFC 2231 restores come after the written
/// ones (docs/01 section 1.3).
fn parameters(value: &str) -> Vec<(String, String)> {
    let mut pieces = Vec::new();
    let mut piece = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            piece.push(c);
            escaped = false;
        } else if quoted && c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if c == ';' && !quoted {
            pieces.push(std::mem::take(&mut piece));
        } else {
            piece.push(c);
        }
    }
    pieces.push(piece);
    let written: Vec<(String, String)> = pieces
        .iter()
        .skip(1)
        .filter_map(|piece| {
            let (name, value) = piece.split_once('=')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    let restored = restored(&written);
    written.into_iter().chain(restored).collect()
}

/// The boundary of a multipart body: the `boundary` parameter of its `Content-Type`.
fn boundary_of(content_type: &str) -> Option<String> {
    parameters(content_type)
        .into_iter()
        .find(|(name, _)| name == "boundary")
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
}

/// The plain parameters RFC 2231 restores from the written ones (docs/01 section 1.3). `x*=` is
/// `x`, and the numbered pieces `x*0=`, `x*1*=`, ... join in order into `x`; the first missing
/// number ends them. A name written more than once is restored from its first value and from its
/// last, and each reading that differs is kept, since parsers differ on which one they take.
fn restored(written: &[(String, String)]) -> Vec<(String, String)> {
    let mut values: HashMap<&str, Vec<&str>> = HashMap::new();
    for (name, value) in written {
        values
            .entry(name.as_str())
            .or_default()
            .push(value.as_str());
    }
    let bases: BTreeSet<&str> = values
        .keys()
        .filter_map(|name| name.split_once('*').map(|(base, _)| base))
        .filter(|base| !base.is_empty())
        .collect();
    let mut restored = Vec::new();
    for base in bases {
        let first = restored_value(&values, base, false);
        let last = restored_value(&values, base, true);
        let readings = if first == last {
            vec![first]
        } else {
            vec![first, last]
        };
        restored.extend(
            readings
                .into_iter()
                .flatten()
                .map(|value| (base.to_owned(), value)),
        );
    }
    restored
}

/// The value RFC 2231 restores under `base`, from the first value written under each name, or from
/// the last one when `last`. `None` when no piece of `base` is written.
fn restored_value(values: &HashMap<&str, Vec<&str>>, base: &str, last: bool) -> Option<String> {
    // A single encoded value, `base*=charset'lang'percent-encoded`.
    if let Some(encoded) = picked(values, &format!("{base}*"), last) {
        return Some(rfc2231_text(encoded, true));
    }
    let mut restored = String::new();
    let mut pieces = 0_usize;
    for index in 0.. {
        if let Some(plain) = picked(values, &format!("{base}*{index}"), last) {
            restored.push_str(plain);
        } else if let Some(encoded) = picked(values, &format!("{base}*{index}*"), last) {
            restored.push_str(&rfc2231_text(encoded, index == 0));
        } else {
            break;
        }
        pieces += 1;
    }
    (pieces > 0).then_some(restored)
}

/// The value written under `name`: the first one, or the last one when `last`.
fn picked<'w>(values: &HashMap<&str, Vec<&'w str>>, name: &str, last: bool) -> Option<&'w str> {
    let found = values.get(name)?;
    let chosen = if last { found.last() } else { found.first() };
    chosen.copied()
}

/// One RFC 2231 piece, percent-decoded. The first piece of an encoded value begins with
/// `charset'lang'`, which is taken off; a piece without that prefix is taken as it is.
fn rfc2231_text(piece: &str, first: bool) -> String {
    let mut parts = piece.splitn(3, '\'');
    let text = match (parts.next(), parts.next(), parts.next()) {
        (Some(_), Some(_), Some(rest)) if first => rest,
        _ => piece,
    };
    percent_decode(text, false)
}

/// The first position at or after `from` where `needle` starts in `haystack`.
fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

/// The parts of a multipart body, as the bytes between one delimiter line and the next, without the
/// line break that ends each part (docs/01 section 1.3). A delimiter line is `--boundary` at the
/// start of the body or of a line, followed only by blanks; the close delimiter `--boundary--` ends
/// the list. Text before the first delimiter line is no part, and neither is an empty block.
fn multipart_parts<'b>(body: &'b [u8], boundary: &str) -> Vec<&'b [u8]> {
    let delimiter = format!("--{boundary}");
    let delimiter = delimiter.as_bytes();
    // Each delimiter line as (where it starts, where its content starts, whether it closes).
    let mut lines: Vec<(usize, usize, bool)> = Vec::new();
    let mut from = 0;
    while let Some(found) = find(body, delimiter, from) {
        from = found + 1;
        if found != 0 && body.get(found - 1) != Some(&b'\n') {
            continue;
        }
        let after = found + delimiter.len();
        let line_end = find(body, b"\n", after).unwrap_or(body.len());
        let rest = body.get(after..line_end).unwrap_or_default();
        let (close, blanks) = match rest.strip_prefix(b"--") {
            Some(tail) => (true, tail),
            None => (false, rest),
        };
        if !blanks.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let content = (line_end + 1).min(body.len());
        lines.push((found, content, close));
        if close {
            break;
        }
    }
    let mut parts = Vec::new();
    for (index, &(_, content, close)) in lines.iter().enumerate() {
        if close {
            break;
        }
        let end = lines.get(index + 1).map_or(body.len(), |next| next.0);
        let block = strip_line_break(body.get(content..end).unwrap_or_default());
        if !block.is_empty() {
            parts.push(block);
        }
    }
    parts
}

/// The part without the line break that ends it: `\r\n` or `\n`.
fn strip_line_break(block: &[u8]) -> &[u8] {
    block
        .strip_suffix(b"\r\n")
        .or_else(|| block.strip_suffix(b"\n"))
        .unwrap_or(block)
}

/// Splits a part at the blank line that ends its headers, `\r\n\r\n` or `\n\n`. A part whose first
/// line is already blank has no headers. `None` when no blank line ends the headers.
fn split_headers(block: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(content) = block.strip_prefix(b"\r\n") {
        return Some((&b""[..], content));
    }
    if let Some(content) = block.strip_prefix(b"\n") {
        return Some((&b""[..], content));
    }
    for (index, byte) in block.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        if block.get(index + 1) == Some(&b'\n') {
            return Some((block.get(..index)?, block.get(index + 2..)?));
        }
        if block.get(index + 1..index + 3) == Some(&b"\r\n"[..]) {
            return Some((block.get(..index)?, block.get(index + 3..)?));
        }
    }
    None
}

/// The lines of a part's headers, with each line that starts with a space or a tab joined to the
/// line before it by one space (docs/01 section 1.3).
fn header_lines(head: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for line in head.split('\n') {
        let line = line.trim_end_matches('\r');
        match lines.last_mut() {
            Some(previous) if line.starts_with([' ', '\t']) => {
                previous.push(' ');
                previous.push_str(line.trim());
            }
            _ => lines.push(line.to_owned()),
        }
    }
    lines
}

/// Reads a multipart body part by part (docs/01 section 1.3). Returns false, having read nothing,
/// when the body has no part, so that it is read as one text.
fn multipart_body(out: &mut ExtractedRequest, body: &[u8], boundary: &str) -> bool {
    let parts = multipart_parts(body, boundary);
    if parts.is_empty() {
        return false;
    }
    for part in parts {
        multipart_part(out, part);
    }
    true
}

/// Reads one part of a multipart body (docs/01 section 1.3). A file part, one with a non-empty file
/// name, gives its file name only, as `body.<name>#filename` with no key, and its content is not
/// read. Any other part is a text: its content is read under each of its field names, as a form
/// field does, or as the JSON it holds when its own type says JSON. A part whose transfer encoding
/// is base64 or quoted-printable is read decoded as well. A part with more than [`PART_NAMES_MAX`]
/// field names is read as one text at `body`, flagged. A part whose headers never end is one text
/// at `body`.
fn multipart_part(out: &mut ExtractedRequest, block: &[u8]) {
    let Some((head, content)) = split_headers(block) else {
        out.truncated = true;
        push(
            out,
            "body".to_owned(),
            None,
            String::from_utf8_lossy(block).into_owned(),
        );
        return;
    };
    let head = String::from_utf8_lossy(head);
    let mut dispositions = Vec::new();
    let mut content_type = None;
    let mut decodings: Vec<String> = Vec::new();
    for line in header_lines(&head) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name == "content-disposition" {
            dispositions.push(value.trim().to_owned());
        } else if name == "content-type" && content_type.is_none() {
            content_type = Some(value.trim().to_owned());
        } else if name == "content-transfer-encoding" {
            // Only base64 and quoted-printable change the content, so only they are read decoded.
            let encoding = value.trim().to_ascii_lowercase();
            if matches!(encoding.as_str(), "base64" | "quoted-printable")
                && !decodings.contains(&encoding)
            {
                decodings.push(encoding);
            }
        }
    }
    let params: Vec<(String, String)> = dispositions
        .iter()
        .flat_map(|disposition| parameters(disposition))
        .collect();
    // Each distinct non-empty name is a field name of its own, because parsers differ on which of
    // several names they take. A part with no name, or with an empty one, is also read at `body`.
    let mut names: Vec<&str> = Vec::new();
    for (param, value) in &params {
        if param == "name" && !value.is_empty() && !names.contains(&value.as_str()) {
            names.push(value);
            if names.len() > PART_NAMES_MAX {
                break;
            }
        }
    }
    let mut places: Vec<(String, Option<String>)> = Vec::new();
    if names.len() > PART_NAMES_MAX {
        // Too many names to read each under its own place: the content is one text, and flagged.
        out.truncated = true;
        places.push(("body".to_owned(), None));
    } else {
        for name in names {
            let at = format!("body.{name}");
            push_unusual_key(out, &at, name);
            places.push((at, Some(name.to_owned())));
        }
        let nameless = params
            .iter()
            .any(|(param, value)| param == "name" && value.is_empty());
        if places.is_empty() || nameless {
            places.push(("body".to_owned(), None));
        }
    }
    // An empty file name is no file name, so such a part is a text and its content is judged.
    let file_names: BTreeSet<&str> = params
        .iter()
        .filter(|(param, _)| param == "filename")
        .map(|(_, value)| value.as_str())
        .filter(|file_name| !file_name.is_empty())
        .collect();
    if !file_names.is_empty() {
        // The content of a file is not extracted: the values do not cover it (docs/01 section 1.3).
        out.truncated = true;
        for (at, _) in &places {
            for file_name in &file_names {
                push(out, format!("{at}#filename"), None, (*file_name).to_owned());
            }
        }
        return;
    }
    let is_json =
        content_type.is_some_and(|content_type| is_json_media(&media_kind(&content_type)));
    read_text(out, content, is_json, &places);
    // Content that decodes to something else is read decoded too (docs/01 section 1.3).
    for decoding in &decodings {
        if let Some(decoded) = transfer_decoded(decoding, content) {
            read_text(out, &decoded, is_json, &places);
        }
    }
}

/// Reads the content of a text part under each of its places (docs/01 section 1.3): as the JSON it
/// holds when its own type says JSON and it parses, else as one text, decoded leniently.
fn read_text(
    out: &mut ExtractedRequest,
    content: &[u8],
    is_json: bool,
    places: &[(String, Option<String>)],
) {
    if is_json
        && places
            .iter()
            .all(|(at, key)| walk_json(out, content, at, key.as_deref()))
    {
        return;
    }
    for (at, key) in places {
        push(
            out,
            at.clone(),
            key.clone(),
            String::from_utf8_lossy(content).into_owned(),
        );
    }
}

/// The content decoded by a transfer encoding that is base64 or quoted-printable, the encoding given
/// in lower case. `None` for any other encoding, and when the decoding adds no reading: it is empty,
/// or it is the content as it was sent.
fn transfer_decoded(encoding: &str, content: &[u8]) -> Option<Vec<u8>> {
    let decoded = match encoding {
        "base64" => base64_decoded(content),
        "quoted-printable" => quoted_printable_decoded(content),
        _ => return None,
    };
    (!decoded.is_empty() && decoded != content).then_some(decoded)
}

/// The bytes of a base64 text, read as Python reads it without checking (docs/01 section 1.3):
/// every character outside the standard alphabet is dropped, blanks included. A `=` ends the data
/// only when it completes a group, a group of three symbols taking one and a group of two taking
/// the second after its first; any other `=` is dropped and decoding goes on. Bits that do not make
/// a whole byte at the end are dropped. It never fails and never panics; what decodes to nothing
/// gives nothing.
fn base64_decoded(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    // The bits not yet written out are the `spare` low bits of `bits`.
    let mut bits: u32 = 0;
    let mut spare: u32 = 0;
    // The symbols in the group being read (0 to 3), and the `=` signs since the last symbol.
    let mut group: u8 = 0;
    let mut padding: u8 = 0;
    for &byte in text {
        if byte == b'=' {
            if group == 3 || (group == 2 && padding == 1) {
                break;
            }
            padding = padding.saturating_add(1);
            continue;
        }
        let Some(value) = base64_value(byte) else {
            continue;
        };
        group = (group + 1) % 4;
        padding = 0;
        bits = (bits << 6) | u32::from(value);
        spare += 6;
        if spare >= 8 {
            spare -= 8;
            // `bits` holds at most `spare + 8` significant bits, so the shift leaves one byte.
            if let Ok(byte) = u8::try_from(bits >> spare) {
                out.push(byte);
            }
            bits &= (1 << spare) - 1;
        }
    }
    out
}

/// The value of one base64 symbol of the standard alphabet.
fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The bytes of a quoted-printable text, read leniently (docs/01 section 1.3): `=` with two hex digits,
/// in either case, is the byte they name, and `=` at the end of a line is a soft line break. Any other
/// `=` stands for itself, so the decoding never fails.
fn quoted_printable_decoded(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut rest = text;
    while let Some((&byte, tail)) = rest.split_first() {
        if byte != b'=' {
            out.push(byte);
            rest = tail;
        } else if let Some((decoded, after)) = quoted_pair(tail) {
            out.push(decoded);
            rest = after;
        } else if let Some(after) = soft_break(tail) {
            rest = after;
        } else {
            out.push(byte);
            rest = tail;
        }
    }
    out
}

/// The byte that the two hex digits at the start of `tail` name, and the text after them.
fn quoted_pair(tail: &[u8]) -> Option<(u8, &[u8])> {
    let [high, low, after @ ..] = tail else {
        return None;
    };
    Some(((hex_digit(*high)? << 4) | hex_digit(*low)?, after))
}

/// What follows a `=` that is not a hex pair, when it is a line break: the text after the break.
fn soft_break(tail: &[u8]) -> Option<&[u8]> {
    match tail {
        [b'\r', b'\n', after @ ..] | [b'\n', after @ ..] => Some(after),
        _ => None,
    }
}

/// A field *name* that carries syntax (`$ne`, `a'b`, `x;y`) is itself input:
/// `NoSQL` operators and key-based injections travel in names, not values. So is a name longer
/// than [`KEY_CHARS_MAX`] characters.
fn push_unusual_key(out: &mut ExtractedRequest, at: &str, name: &str) {
    let unusual = name.starts_with('$')
        || name.chars().count() > KEY_CHARS_MAX
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

/// The fields of a body that is not a strict form, for the names that look like field names: a name
/// is kept when it holds only letters, digits and `_ - . [ ] % +` once its blanks at the ends are
/// trimmed. The trimmed name is the key and the place of the value (docs/01 section 1.3). Other
/// names are not fields, so the `=` in an XML attribute or in a JSON string makes no reference out
/// of them.
fn loose_pairs(out: &mut ExtractedRequest, text: &str) {
    for pair in text.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = name.trim();
        let field_name = !name.is_empty()
            && name.chars().all(|c| {
                c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '[' | ']' | '%' | '+')
            });
        if !field_name {
            continue;
        }
        let key = percent_decode(name, true);
        push_unusual_key(out, &format!("body.{key}"), &key);
        push(
            out,
            format!("body.{key}"),
            Some(key),
            percent_decode(value, true),
        );
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

/// A request body as a tree that keeps every member of an object. `serde_json::Value` keeps only
/// the last of several members with one name, but an origin may read the first one: each
/// occurrence of a repeated key is a value of its own (docs/01 section 1.3).
enum Json {
    Object(Vec<(String, Json)>),
    Array(Vec<Json>),
    Text(String),
    Number(serde_json::Number),
    /// `true`, `false` or `null`, as its text: nothing to judge on its own, but part of a subtree's
    /// text.
    Other(&'static str),
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Other(if value { "true" } else { "false" }))
    }

    fn visit_i64<E>(self, number: i64) -> Result<Json, E> {
        Ok(Json::Number(number.into()))
    }

    fn visit_u64<E>(self, number: u64) -> Result<Json, E> {
        Ok(Json::Number(number.into()))
    }

    fn visit_f64<E>(self, number: f64) -> Result<Json, E> {
        Ok(serde_json::Number::from_f64(number).map_or(Json::Other("null"), Json::Number))
    }

    fn visit_str<E>(self, text: &str) -> Result<Json, E> {
        Ok(Json::Text(text.to_owned()))
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Other("null"))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Json>()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut members = Vec::new();
        while let Some((name, value)) = map.next_entry::<String, Json>()? {
            members.push((name, value));
        }
        // Sorted by name, as the map of `serde_json::Value` iterates, so the values keep the order
        // they always had. A stable sort keeps members that repeat a name in document order.
        members.sort_by(|(a, _), (b, _)| a.cmp(b));
        Ok(Json::Object(members))
    }
}

fn walk_request(
    out: &mut ExtractedRequest,
    json: &Json,
    at: &str,
    key: Option<&str>,
    depth: usize,
) {
    match json {
        // A container below the depth limit is one value at this position: its JSON text
        // (docs/01 section 1.3). Scalars are values wherever they sit.
        Json::Object(_) | Json::Array(_) if depth > JSON_DEPTH_MAX => {
            push(out, at.to_owned(), key.map(str::to_owned), json_text(json));
        }
        Json::Object(members) => {
            for (name, inner) in members {
                push_unusual_key(out, &format!("{at}.{name}"), name);
                let named = member_key(key, name);
                walk_request(out, inner, &format!("{at}.{name}"), Some(&named), depth + 1);
            }
        }
        Json::Array(items) => {
            for inner in items {
                walk_request(out, inner, &format!("{at}[]"), key, depth + 1);
            }
        }
        Json::Text(text) => push(out, at.to_owned(), key.map(str::to_owned), text.clone()),
        Json::Number(number) => push(
            out,
            at.to_owned(),
            key.map(str::to_owned),
            number.to_string(),
        ),
        Json::Other(_) => {}
    }
}

/// The JSON text of a parsed subtree, with its members in the order the walk reads them.
fn json_text(json: &Json) -> String {
    match json {
        Json::Object(members) => {
            let inner: Vec<String> = members
                .iter()
                .map(|(name, value)| format!("{}:{}", json_string(name), json_text(value)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Json::Array(items) => {
            let inner: Vec<String> = items.iter().map(json_text).collect();
            format!("[{}]", inner.join(","))
        }
        Json::Text(text) => json_string(text),
        Json::Number(number) => number.to_string(),
        Json::Other(literal) => (*literal).to_owned(),
    }
}

fn json_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_default()
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
    let kind = content_type.map(media_kind).unwrap_or_default();
    match kind.as_str() {
        kind if is_json_media(kind) => {
            if let Ok(json) = serde_json::from_slice::<Value>(body) {
                let mut shape = BTreeSet::new();
                walk_response(&mut facts, &mut shape, &json, "", "value", "", 0);
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

/// Keeps a JSON string: as a value when it is at most [`VALUE_MAX_CHARS`] characters long, as a
/// credential candidate when it is longer but shaped like a credential, and not at all otherwise.
fn add_text(facts: &mut ResponseFacts, field: &str, at: &str, text: &str) {
    if text.chars().count() <= VALUE_MAX_CHARS {
        add_at(&mut facts.values, field, at, text.to_owned());
    } else if text.len() <= CREDENTIAL_MAX_BYTES
        && credential_shaped(text)
        && facts.credentials.len() < CREDENTIAL_CANDIDATES_MAX
    {
        facts.credentials.push(ResponseValue {
            field: field_name(field),
            value: text.to_owned(),
            at: position(at),
        });
    }
}

/// Whether a long string is shaped like a credential (docs/01 section 1.7): every byte is visible
/// ASCII, which leaves out prose, HTML fragments and anything with a blank or a non-ASCII
/// character, and it does not start with `http://`, `https://` or `data:` in any case.
fn credential_shaped(text: &str) -> bool {
    text.bytes().all(|byte| byte.is_ascii_graphic())
        && !["http://", "https://", "data:"].iter().any(|scheme| {
            text.get(..scheme.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
        })
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
    facts: &mut ResponseFacts,
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
                walk_response(facts, shape, inner, field, name, &child, depth + 1);
            }
        }
        Value::Array(items) => {
            let item = format!("{at}[]");
            for inner in items {
                walk_response(facts, shape, inner, parent, field, &item, depth + 1);
            }
        }
        Value::String(text) => {
            note_shape(shape, at, "string");
            add_text(facts, &qualified(parent, field), at, text);
        }
        Value::Number(number) => {
            note_shape(shape, at, "number");
            add_at(
                &mut facts.values,
                &qualified(parent, field),
                at,
                number.to_string(),
            );
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
    fn every_value_of_a_repeated_json_key_is_a_request_value() {
        let body = br#"{"patient":"PT-1","patient":"PT-2","nested":{"id":3,"id":4}}"#;
        let request = extract_request("/", None, Some("application/json"), body);
        // Members come out sorted by name, as before; the repeats keep their document order.
        assert_eq!(
            values(&request),
            [
                ("body.nested.id", "3", false),
                ("body.nested.id", "4", false),
                ("body.patient", "PT-1", false),
                ("body.patient", "PT-2", false),
            ]
        );
        assert!(!request.truncated);
    }

    #[test]
    fn a_repeated_key_keeps_an_object_and_a_scalar_both() {
        let body = br#"{"doc":{"id":"A"},"doc":"B"}"#;
        let request = extract_request("/", None, Some("application/json"), body);
        let got = values(&request);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&("body.doc.id", "A", false)));
        assert!(got.contains(&("body.doc", "B", false)));
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
    fn unstructured_bodies_are_one_text_and_flagged() {
        let request = extract_request("/", None, Some("application/octet-stream"), b"abc");
        assert!(request.truncated);
        assert_eq!(request.values.last().unwrap().at, "body");
        // Whatever its size, the body is one value, not cut at 2048 bytes.
        let big = format!("{}END-MARK", "a".repeat(5_000));
        let request = extract_request("/", None, Some("application/octet-stream"), big.as_bytes());
        assert_eq!(request.values.len(), 1);
        assert_eq!(request.values[0].value, big);
        assert!(request.values[0].key.is_none());
        assert!(extract_request("/", None, Some("application/json"), b"{broken").truncated);
    }

    #[test]
    fn a_text_xml_body_is_one_value_holding_all_of_it() {
        let xml = format!("<x>{}END-MARK</x>", "a".repeat(5_000));
        let request = extract_request("/", None, Some("text/xml"), xml.as_bytes());
        assert!(request.truncated);
        assert_eq!(located(&request), [("body", xml.as_str())]);
        assert!(request.values[0].value.contains("END-MARK"));
    }

    #[test]
    fn a_json_body_that_does_not_parse_is_one_text() {
        let request = extract_request("/", None, Some("application/json"), b"{\"a\": ");
        assert!(request.truncated);
        assert_eq!(located(&request), [("body", "{\"a\": ")]);
    }

    /// The `(at, value)` pairs of a request, in order.
    fn located(extracted: &ExtractedRequest) -> Vec<(&str, &str)> {
        extracted
            .values
            .iter()
            .map(|value| (value.at.as_str(), value.value.as_str()))
            .collect()
    }

    #[test]
    fn text_plain_holding_a_json_object_is_read_as_json() {
        let request = extract_request("/", None, Some("text/plain"), br#"{"patient_id":8}"#);
        assert!(!request.truncated);
        assert!(values(&request).contains(&("body.patient_id", "8", false)));
        let bare = extract_request("/", None, None, b"  [{\"patient_id\":8}]  ");
        assert!(!bare.truncated);
        assert!(values(&bare).contains(&("body[].patient_id", "8", false)));
        // Text that merely starts with a brace and does not parse is one text.
        let broken = extract_request("/", None, Some("text/plain"), b"{ patient_id=8");
        assert!(broken.truncated);
        assert_eq!(located(&broken), [("body", "{ patient_id=8")]);
    }

    #[test]
    fn multipart_text_fields_keep_their_names_and_a_file_gives_only_its_name() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"patient_id\"\r\n\r\n8\r\n\
            --b\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n\
            --b\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"me.png\"\r\n\
            Content-Type: image/png\r\n\r\nSECRET-MARK\r\n--b--\r\n";
        let request = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary=b"),
            body.as_bytes(),
        );
        assert_eq!(
            located(&request),
            [
                ("body.patient_id", "8"),
                ("body.note", "hello"),
                ("body.avatar#filename", "me.png"),
            ]
        );
        assert_eq!(request.values[0].key.as_deref(), Some("patient_id"));
        assert_eq!(request.values[1].key.as_deref(), Some("note"));
        assert!(
            request
                .values
                .iter()
                .all(|value| value.key.as_deref() != Some("avatar"))
        );
        assert!(
            request
                .values
                .iter()
                .all(|value| !value.value.contains("SECRET-MARK"))
        );
        // The content of a file is not judged, so the request is not whole.
        assert!(request.truncated);
    }

    #[test]
    fn multipart_variants_read_without_panicking() {
        // A quoted boundary, with line feeds only.
        let lf = "--bnd\nContent-Disposition: form-data; name=\"a\"\n\nvalA\n--bnd--\n";
        let quoted = extract_request(
            "/",
            None,
            Some("multipart/form-data; Boundary=\"bnd\""),
            lf.as_bytes(),
        );
        assert_eq!(located(&quoted), [("body.a", "valA")]);
        assert!(!quoted.truncated);
        // An RFC 5987 file name.
        let star = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename*=UTF-8''na%20me.txt\r\n\r\nX\r\n--b--";
        let star = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary=b"),
            star.as_bytes(),
        );
        assert_eq!(located(&star), [("body.f#filename", "na me.txt")]);
        // A part with no name is a text at `body`, with no key.
        let nameless = "--b\r\nContent-Type: text/plain\r\n\r\nfree text\r\n--b--";
        let nameless = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary=b"),
            nameless.as_bytes(),
        );
        assert_eq!(located(&nameless), [("body", "free text")]);
        assert!(nameless.values[0].key.is_none());
        // A part that says JSON is read as JSON under its field name.
        let json = "--b\r\nContent-Disposition: form-data; name=\"doc\"\r\nContent-Type: application/json\r\n\r\n{\"id\":5}\r\n--b--";
        let json = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary=b"),
            json.as_bytes(),
        );
        assert!(values(&json).contains(&("body.doc.id", "5", false)));
        // Without a boundary, or with no part in it, the body is one text.
        let no_boundary = extract_request("/", None, Some("multipart/form-data"), b"--b\r\n\r\nx");
        assert!(no_boundary.truncated);
        assert_eq!(located(&no_boundary), [("body", "--b\r\n\r\nx")]);
        let no_part = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary=b"),
            b"just text",
        );
        assert!(no_part.truncated);
        assert_eq!(located(&no_part), [("body", "just text")]);
        // A part whose headers never end is one text too, and the request is not whole.
        let unended = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary=b"),
            b"--b\r\nContent-Disposition: form-data; name=\"x\"\r\n--b--",
        );
        assert!(unended.truncated);
        assert_eq!(unended.values.len(), 1);
    }

    #[test]
    fn every_multipart_type_with_a_boundary_is_read_by_its_parts() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"patient_id\"\r\n\r\n8\r\n\
            --b\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--b--\r\n";
        for kind in ["multipart/mixed", "multipart/related"] {
            let content_type = format!("{kind}; boundary=b");
            let request = extract_request("/", None, Some(content_type.as_str()), body.as_bytes());
            assert_eq!(
                located(&request),
                [("body.patient_id", "8"), ("body.note", "hello")],
                "{kind}"
            );
            assert_eq!(
                request.values[0].key.as_deref(),
                Some("patient_id"),
                "{kind}"
            );
            assert!(!request.truncated, "{kind}");
            // The boundary and the part headers are in no value.
            assert!(
                request.values.iter().all(|value| {
                    !value.value.contains("--b") && !value.value.contains("Content-Disposition")
                }),
                "{kind}"
            );
        }
    }

    #[test]
    fn a_body_with_no_type_that_is_a_form_is_read_as_its_fields() {
        let request = extract_request("/", None, None, b"patient_id=8&note=routine");
        assert!(!request.truncated);
        assert_eq!(
            located(&request),
            [("body.patient_id", "8"), ("body.note", "routine")]
        );
        assert!(request.values.iter().any(
            |value| value.at == "body.patient_id" && value.key.as_deref() == Some("patient_id")
        ));
    }

    #[test]
    fn a_body_with_no_type_that_is_not_a_form_stays_one_text() {
        // Each body is one text at `body`, flagged. The names that look like field names are read
        // too, before the text (docs/01 section 1.3).
        let cases: [(&str, &[(&str, &str)]); 6] = [
            ("a sentence with spaces", &[]),
            ("a=1&b", &[("body.a", "1")]),
            ("a=1\nb=2", &[("body.a", "1\nb=2")]),
            ("a=1&&b=2", &[("body.a", "1"), ("body.b", "2")]),
            ("a=1&", &[("body.a", "1")]),
            // A `;` may split fields at the origin, so the field before it is read, and the text.
            ("note=x;patient_id=8", &[("body.note", "x;patient_id=8")]),
        ];
        for (text, fields) in cases {
            let request = extract_request("/", None, None, text.as_bytes());
            assert!(request.truncated, "{text:?}");
            let mut expected = fields.to_vec();
            expected.push(("body", text));
            assert_eq!(located(&request), expected, "{text:?}");
        }
        // Other types are not read as forms, whatever their shape.
        let plain = extract_request("/", None, Some("text/plain"), b"patient_id=8&note=routine");
        assert!(plain.truncated);
        assert_eq!(located(&plain), [("body", "patient_id=8&note=routine")]);
    }

    #[test]
    fn an_empty_file_name_leaves_a_text_part_a_text() {
        // `filename=""`, or a `filename*` that decodes to nothing, is no file name: the content is judged.
        for disposition in [
            "form-data; name=\"patient_id\"; filename=\"\"",
            "form-data; name=\"patient_id\"; filename*=UTF-8''",
        ] {
            let text = format!("--b\r\nContent-Disposition: {disposition}\r\n\r\n8\r\n--b--\r\n");
            let request = extract_request(
                "/",
                None,
                Some("multipart/form-data; boundary=b"),
                text.as_bytes(),
            );
            assert_eq!(
                located(&request),
                [("body.patient_id", "8")],
                "{disposition}"
            );
            assert_eq!(request.values[0].key.as_deref(), Some("patient_id"));
            assert!(!request.truncated, "{disposition}");
        }
        // A file name makes a file part: only the name is a value.
        let file = "--b\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"a.png\"\r\n\r\nSECRET-MARK\r\n--b--\r\n";
        let request = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary=b"),
            file.as_bytes(),
        );
        assert_eq!(located(&request), [("body.avatar#filename", "a.png")]);
        assert!(request.truncated);
    }

    #[test]
    fn a_part_with_several_field_names_is_judged_under_each() {
        let one_header = "--b\r\nContent-Disposition: form-data; name=\"note\"; name=\"patient_id\"\r\n\r\n8\r\n--b--\r\n";
        let two_headers = "--b\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Disposition: form-data; name=\"patient_id\"\r\n\r\n8\r\n--b--\r\n";
        for body in [one_header, two_headers] {
            let request = extract_request(
                "/",
                None,
                Some("multipart/form-data; boundary=b"),
                body.as_bytes(),
            );
            assert_eq!(
                located(&request),
                [("body.note", "8"), ("body.patient_id", "8")]
            );
            assert_eq!(request.values[0].key.as_deref(), Some("note"));
            assert_eq!(request.values[1].key.as_deref(), Some("patient_id"));
            assert!(!request.truncated);
        }
    }

    #[test]
    fn a_base64_or_quoted_printable_part_is_judged_decoded_too() {
        let read = |encoding: &str, content: &str| {
            let body = format!(
                "--b\r\nContent-Disposition: form-data; name=\"note\"\r\n\
                 Content-Transfer-Encoding: {encoding}\r\n\r\n{content}\r\n--b--\r\n"
            );
            let request = extract_request(
                "/",
                None,
                Some("multipart/form-data; boundary=b"),
                body.as_bytes(),
            );
            assert!(!request.truncated);
            request
        };
        // Base64 for `' OR 1=1--`: the text as sent and the decoded text, both under `note`, whatever
        // the case of the encoding's name.
        for encoding in ["base64", "BASE64"] {
            let request = read(encoding, "JyBPUiAxPTEtLQ==");
            assert_eq!(
                located(&request),
                [
                    ("body.note", "JyBPUiAxPTEtLQ=="),
                    ("body.note", "' OR 1=1--")
                ],
                "{encoding}"
            );
            assert!(
                request
                    .values
                    .iter()
                    .all(|value| value.key.as_deref() == Some("note"))
            );
        }
        // Quoted-printable for `' OR 1=1--`.
        let request = read("quoted-printable", "=27 OR 1=3D1--");
        assert_eq!(
            located(&request),
            [("body.note", "=27 OR 1=3D1--"), ("body.note", "' OR 1=1--")]
        );
        // A literal `=` stands for itself, so the escape before it still decodes.
        let request = read("quoted-printable", "=27 OR 1=1--");
        assert_eq!(
            located(&request),
            [("body.note", "=27 OR 1=1--"), ("body.note", "' OR 1=1--")]
        );
        // A `'` is outside the base64 alphabet and is dropped, as an origin drops it, so the
        // decoded text is read as well as the text as sent.
        let request = read("base64", "JyBPUi'AxPTEtLQ==");
        assert_eq!(
            located(&request),
            [
                ("body.note", "JyBPUi'AxPTEtLQ=="),
                ("body.note", "' OR 1=1--")
            ]
        );
        // Nothing decodes from `'''`, so the text as sent is the only reading.
        let request = read("base64", "'''");
        assert_eq!(located(&request), [("body.note", "'''")]);
        // Blanks are dropped in base64, so a line break in the middle does not stop the decoding.
        let request = read("Base64", "JyBPUi\r\nAxPTEtLQ==");
        assert_eq!(
            located(&request),
            [
                ("body.note", "JyBPUi\r\nAxPTEtLQ=="),
                ("body.note", "' OR 1=1--")
            ]
        );
        // A `=` after one symbol is dropped and the decoding goes on, so the second `=` in the
        // middle does not end the data.
        let request = read("base64", "J=yBPUiAxPTEtLQ==");
        assert_eq!(
            located(&request),
            [
                ("body.note", "J=yBPUiAxPTEtLQ=="),
                ("body.note", "' OR 1=1--")
            ]
        );
        // Two `=` after a group of two symbols end the data: `OA==eA` is `8`.
        let request = read("base64", "OA==eA");
        assert_eq!(
            located(&request),
            [("body.note", "OA==eA"), ("body.note", "8")]
        );
        // Unpadded base64 decodes as well.
        let request = read("base64", "JyBPUiAxPTEtLQ");
        assert_eq!(
            located(&request),
            [("body.note", "JyBPUiAxPTEtLQ"), ("body.note", "' OR 1=1--")]
        );
    }

    #[test]
    fn a_json_body_is_json_whatever_its_type() {
        let form = extract_request(
            "/",
            None,
            Some("application/x-www-form-urlencoded"),
            br#"{"patient_id":8}"#,
        );
        assert!(!form.truncated);
        assert!(values(&form).contains(&("body.patient_id", "8", false)));
        // An ordinary form is read as its fields, as before.
        let fields = extract_request(
            "/",
            None,
            Some("application/x-www-form-urlencoded"),
            b"a=1&b=2",
        );
        assert_eq!(located(&fields), [("body.a", "1"), ("body.b", "2")]);
        // A multipart body with no part, and holding JSON, is read as JSON.
        let multipart = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary=b"),
            br#"{"patient_id":8}"#,
        );
        assert!(!multipart.truncated);
        assert!(values(&multipart).contains(&("body.patient_id", "8", false)));
    }

    #[test]
    fn a_body_that_is_both_json_and_a_form_is_read_both_ways() {
        let body = br#"{"a=":"&patient_id=8&b="}"#;
        // Typed as a form: the fields, and the JSON values as well, none of it truncated.
        let form = extract_request("/", None, Some("application/x-www-form-urlencoded"), body);
        assert!(!form.truncated);
        assert!(located(&form).contains(&("body.patient_id", "8")));
        assert!(form.values.iter().any(
            |value| value.at == "body.patient_id" && value.key.as_deref() == Some("patient_id")
        ));
        assert!(located(&form).contains(&("body.a=", "&patient_id=8&b=")));
        // With no type: the same two readings, none of it truncated.
        let typeless = extract_request("/", None, None, body);
        assert!(!typeless.truncated);
        assert!(located(&typeless).contains(&("body.patient_id", "8")));
        assert!(typeless.values.iter().any(
            |value| value.at == "body.patient_id" && value.key.as_deref() == Some("patient_id")
        ));
        assert!(located(&typeless).contains(&("body.a=", "&patient_id=8&b=")));
        // Typed as text: JSON only, so no field of the form is read.
        let text = extract_request("/", None, Some("text/plain"), body);
        assert!(!text.truncated);
        assert!(located(&text).contains(&("body.a=", "&patient_id=8&b=")));
        assert!(
            !located(&text)
                .iter()
                .any(|(at, _)| *at == "body.patient_id")
        );
    }

    #[test]
    fn typeless_bodies_take_every_reading_that_makes_sense() {
        // A blank in a value takes the body out of the strict form, but the field names are read,
        // and the whole text is one value as well.
        let spaced = extract_request("/", None, None, b"note=a b&patient_id=8");
        assert!(spaced.truncated);
        assert!(located(&spaced).contains(&("body.patient_id", "8")));
        assert!(spaced.values.iter().any(
            |value| value.at == "body.patient_id" && value.key.as_deref() == Some("patient_id")
        ));
        assert!(located(&spaced).contains(&("body", "note=a b&patient_id=8")));
        // JSON with a blank: its values, and the field names of the same text; not truncated.
        let json = extract_request("/", None, None, br#"{"a": "&patient_id=8&b="}"#);
        assert!(!json.truncated);
        assert!(located(&json).contains(&("body.patient_id", "8")));
        assert!(located(&json).contains(&("body.a", "&patient_id=8&b=")));
        // A blank before the name: the key is the name without its blanks.
        let blank = extract_request("/", None, None, b"x& patient_id=8");
        assert!(blank.truncated);
        assert!(blank.values.iter().any(
            |value| value.at == "body.patient_id" && value.key.as_deref() == Some("patient_id")
        ));
        // Markup with an `=` in an attribute: the text only, with no keyed value.
        let markup = extract_request("/", None, None, br#"<user id="5">t</user>"#);
        assert!(markup.truncated);
        assert_eq!(located(&markup), [("body", r#"<user id="5">t</user>"#)]);
        // A JSON object: its values. It is also a strict form, so its one field, `{"token":"abc`,
        // is read as well; the rule as written does not exempt it (see the report on this test).
        let token = extract_request("/", None, None, br#"{"token":"abc=="}"#);
        assert!(!token.truncated);
        assert!(located(&token).contains(&("body.token", "abc==")));
        assert!(!located(&token).iter().any(|(at, _)| *at == "body"));
    }

    #[test]
    fn an_rfc_2231_parameter_is_restored_to_its_plain_name() {
        let part = |disposition: &str| {
            format!("--b\r\nContent-Disposition: {disposition}\r\n\r\n8\r\n--b--\r\n")
        };
        let multipart = Some("multipart/form-data; boundary=b");
        // `name*=charset'lang'percent-encoded`, and numbered pieces, are the plain name.
        for disposition in [
            "form-data; name*=UTF-8''patient_id",
            "form-data; name*0=\"patient\"; name*1=\"_id\"",
            "form-data; name*0*=UTF-8''patient; name*1=\"_id\"",
            "form-data; name*0*=UTF-8''patient; name*1*=%5Fid",
        ] {
            let request = extract_request("/", None, multipart, part(disposition).as_bytes());
            assert_eq!(
                located(&request),
                [("body.patient_id", "8")],
                "{disposition}"
            );
            assert_eq!(
                request.values[0].key.as_deref(),
                Some("patient_id"),
                "{disposition}"
            );
            assert!(!request.truncated, "{disposition}");
        }
        // A written name and an encoded one name the part under each.
        let both = extract_request(
            "/",
            None,
            multipart,
            part("form-data; name=\"note\"; name*=UTF-8''patient_id").as_bytes(),
        );
        assert_eq!(
            located(&both),
            [("body.note", "8"), ("body.patient_id", "8")]
        );
        // A boundary given in pieces splits the body.
        let pieces = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary*0=a; boundary*1=b"),
            b"--ab\r\nContent-Disposition: form-data; name=\"patient_id\"\r\n\r\n8\r\n--ab--\r\n",
        );
        assert_eq!(located(&pieces), [("body.patient_id", "8")]);
        assert!(!pieces.truncated);
        // The file name of an encoded `filename*` is the file name; an empty one is no file name.
        let file = extract_request(
            "/",
            None,
            multipart,
            b"--b\r\nContent-Disposition: form-data; name=\"avatar\"; filename*=UTF-8''a.png\r\n\r\nSECRET-MARK\r\n--b--\r\n",
        );
        assert_eq!(located(&file), [("body.avatar#filename", "a.png")]);
        // Numbered pieces that are missing, repeated or huge do not panic, and the written values
        // stay.
        let odd = extract_request(
            "/",
            None,
            multipart,
            part("form-data; name*1=\"_id\"; name*99999999999999999999=\"x\"; name*0=\"a\"; name*0=\"b\"")
                .as_bytes(),
        );
        // A repeated first piece is restored from its first value and from its last: `a_id` and
        // `b_id`.
        assert!(!odd.truncated);
        assert_eq!(
            located(&odd),
            [("body.a_id", "8"), ("body.b_id", "8")],
            "the missing and huge pieces are no part of the name"
        );
    }

    #[test]
    fn a_folded_part_header_is_joined_before_it_is_read() {
        let multipart = Some("multipart/form-data; boundary=b");
        // A header line that starts with a blank continues the line before it, with one space.
        let folded =
            "--b\r\nContent-Disposition: form-data;\r\n name=\"patient_id\"\r\n\r\n8\r\n--b--\r\n";
        let request = extract_request("/", None, multipart, folded.as_bytes());
        assert_eq!(located(&request), [("body.patient_id", "8")]);
        assert_eq!(request.values[0].key.as_deref(), Some("patient_id"));
        assert!(!request.truncated);
        // A folded file name makes a file part, whose content is not read.
        let file = "--b\r\nContent-Disposition: form-data; name=\"avatar\";\r\n\tfilename=\"a.png\"\r\n\r\nSECRET-MARK\r\n--b--\r\n";
        let request = extract_request("/", None, multipart, file.as_bytes());
        assert_eq!(located(&request), [("body.avatar#filename", "a.png")]);
        // A folded transfer encoding is read: base64 for `' OR 1=1--`.
        let encoded = "--b\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Transfer-Encoding:\r\n base64\r\n\r\nJyBPUiAxPTEtLQ==\r\n--b--\r\n";
        let request = extract_request("/", None, multipart, encoded.as_bytes());
        assert_eq!(
            located(&request),
            [
                ("body.note", "JyBPUiAxPTEtLQ=="),
                ("body.note", "' OR 1=1--")
            ]
        );
    }

    #[test]
    fn a_part_with_many_field_names_is_one_flagged_text() {
        let names: Vec<String> = (0..=super::PART_NAMES_MAX)
            .map(|i| format!("name=\"n{i}\""))
            .collect();
        let body = format!(
            "--b\r\nContent-Disposition: form-data; {}\r\n\r\n8\r\n--b--\r\n",
            names.join("; ")
        );
        let request = extract_request(
            "/",
            None,
            Some("multipart/form-data; boundary=b"),
            body.as_bytes(),
        );
        assert!(request.truncated);
        assert_eq!(located(&request), [("body", "8")]);
    }

    #[test]
    fn a_json_document_nested_past_the_depth_limit_keeps_its_deepest_value() {
        let mut body = String::from("\"MARKER-DEEP\"");
        for _ in 0..20 {
            body = format!("{{\"n\":{body}}}");
        }
        let request = extract_request("/", None, Some("application/json"), body.as_bytes());
        assert!(!request.truncated);
        assert!(
            request
                .values
                .iter()
                .any(|value| value.value.contains("MARKER-DEEP"))
        );
    }

    #[test]
    fn a_name_longer_than_sixty_four_characters_is_a_value() {
        let name = "k".repeat(100);
        let body = format!(r#"{{"{name}":"x"}}"#);
        let request = extract_request("/", None, Some("application/json"), body.as_bytes());
        assert!(
            request
                .values
                .iter()
                .any(|value| value.at.ends_with("#name") && value.value == name)
        );
    }

    #[test]
    fn every_query_value_is_extracted_however_many() {
        let query = (0..5_000)
            .map(|i| format!("k{i}=v{i}"))
            .collect::<Vec<_>>()
            .join("&");
        let request = extract_request("/", Some(&query), None, b"");
        assert_eq!(request.values.len(), 5_000);
        assert!(!request.truncated);
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
    fn json_media_is_application_json_or_a_json_suffix_type() {
        for kind in [
            "application/json",
            "application/vnd.api+json",
            "application/problem+json",
        ] {
            assert!(is_json_media(kind), "{kind}");
        }
        for kind in [
            "text/html",
            "application/x-ndjson",
            "application/jsonp",
            "text/json",
            "",
        ] {
            assert!(!is_json_media(kind), "{kind}");
        }
        assert_eq!(
            media_kind(" Application/Vnd.API+JSON ; charset=utf-8"),
            "application/vnd.api+json"
        );
    }

    #[test]
    fn a_json_suffix_request_body_is_read_like_application_json() {
        let body = br#"{"patient":{"id":7,"tags":["a","b"],"ok":true},"note":"x' OR 1=1"}"#;
        let suffix = extract_request(
            "/",
            None,
            Some("application/vnd.api+json; charset=utf-8"),
            body,
        );
        assert!(!suffix.truncated);
        assert!(values(&suffix).contains(&("body.patient.id", "7", false)));
        assert_eq!(
            suffix,
            extract_request("/", None, Some("application/json"), body)
        );
    }

    #[test]
    fn a_json_suffix_response_body_is_read_like_application_json() {
        let body = br#"{"items":[{"id":7,"name":"A","age":8},{"id":9}],"total":2,"ok":true}"#;
        let suffix = extract_response_facts(Some("application/vnd.api+json; charset=utf-8"), body);
        assert!(
            suffix
                .values
                .iter()
                .any(|value| value.field == "id" && value.value == "7")
        );
        assert!(suffix.shape.is_some());
        assert_eq!(
            suffix,
            extract_response_facts(Some("application/json"), body)
        );
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

    /// A string of `chars` visible ASCII characters that starts with `tag`, so each tag gives a
    /// different string.
    fn credential(tag: &str, chars: usize) -> String {
        format!("{tag}{}", "Q".repeat(chars.saturating_sub(tag.len())))
    }

    /// A JSON login body whose token is `token` and whose basket id is 6.
    fn login_json(token: &str) -> String {
        format!(r#"{{"authentication":{{"token":"{token}","bid":6}}}}"#)
    }

    #[test]
    fn a_long_token_is_a_credential_candidate_and_not_a_value() {
        let token = credential("tok-", 700);
        let facts = extract_response_facts(Some("application/json"), login_json(&token).as_bytes());
        let values: Vec<&str> = facts
            .values
            .iter()
            .map(|value| value.value.as_str())
            .collect();
        assert_eq!(values, ["6"], "only the basket id is a value");
        assert_eq!(facts.credentials.len(), 1);
        let candidate = &facts.credentials[0];
        assert_eq!(candidate.value, token);
        // It sits where a short token would: the field and the position a value there gets.
        let short = extract_response(
            Some("application/json"),
            login_json("short-token-000000000000").as_bytes(),
        );
        let same_place = short
            .iter()
            .find(|value| value.value == "short-token-000000000000")
            .expect("a short token is a value");
        assert_eq!(candidate.field, same_place.field);
        assert_eq!(candidate.at, same_place.at);
        // The structure is what it was: the token is still a string at its path.
        assert!(facts.shape.is_some_and(|shape| {
            shape
                .iter()
                .any(|field| field.path == "authentication.token" && field.kind == "string")
        }));
    }

    #[test]
    fn the_value_limit_decides_between_a_value_and_a_candidate() {
        let at_limit = credential("a", VALUE_MAX_CHARS);
        let past_limit = credential("b", VALUE_MAX_CHARS + 1);
        let body = serde_json::json!([at_limit, past_limit]).to_string();
        let facts = extract_response_facts(Some("application/json"), body.as_bytes());
        assert_eq!(facts.values.len(), 1);
        assert_eq!(facts.values[0].value, at_limit);
        assert_eq!(facts.credentials.len(), 1);
        assert_eq!(facts.credentials[0].value, past_limit);
    }

    #[test]
    fn a_long_text_or_a_url_is_no_candidate() {
        let spaced = "word ".repeat(40);
        let chinese = "中".repeat(200);
        let https = format!("https://example.test/{}", "x".repeat(200));
        let upper = format!("HTTP://example.test/{}", "x".repeat(200));
        let data = format!("data:text/plain;base64,{}", "A".repeat(200));
        let body = serde_json::json!([spaced, chinese, https, upper, data]).to_string();
        let facts = extract_response_facts(Some("application/json"), body.as_bytes());
        assert!(facts.credentials.is_empty());
        assert!(facts.values.is_empty());
    }

    #[test]
    fn a_scalar_past_the_credential_limit_is_dropped() {
        let largest = credential("c", CREDENTIAL_MAX_BYTES);
        let past = credential("d", CREDENTIAL_MAX_BYTES + 1);
        let body = serde_json::json!({ "largest": largest, "past": past }).to_string();
        let facts = extract_response_facts(Some("application/json"), body.as_bytes());
        assert_eq!(facts.credentials.len(), 1, "the largest one is kept");
        assert_eq!(facts.credentials[0].value, largest);
        assert!(facts.values.is_empty());
    }

    #[test]
    fn a_response_yields_at_most_sixteen_candidates() {
        let tokens: Vec<String> = (0..20)
            .map(|index| credential(&format!("t{index:02}-"), 200))
            .collect();
        let body = serde_json::to_string(&tokens).expect("the tokens serialise");
        let facts = extract_response_facts(Some("application/json"), body.as_bytes());
        assert_eq!(facts.credentials.len(), CREDENTIAL_CANDIDATES_MAX);
        assert!(
            facts
                .credentials
                .iter()
                .zip(&tokens)
                .all(|(kept, token)| kept.value == *token),
            "the first sixteen, in document order"
        );
    }

    #[test]
    fn html_yields_no_candidates() {
        let long = credential("h", 300);
        let html =
            format!(r#"<html><input value="{long}"><a href="/items?token={long}">x</a></html>"#);
        let facts = extract_response_facts(Some("text/html"), html.as_bytes());
        assert!(facts.credentials.is_empty());
        let values: Vec<&str> = facts
            .values
            .iter()
            .map(|value| value.value.as_str())
            .collect();
        assert_eq!(values, ["items"], "only the short path segment is a value");
    }
}
