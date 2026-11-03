//! A bounded, deterministic normalization from a request path to a display
//! template. The console groups unmatched requests by it for route discovery,
//! and the judge keys its object-map positions by it ([`position_template`]).
//!
//! The heuristic is deliberately narrow: it replaces a segment only when the
//! whole segment is all-ASCII-digits or a canonical UUID, and leaves every
//! other segment untouched. Positions first take the spelling the origin routes
//! a path by ([`canonical_path`]), so that `/orders/7/` and `/orders/%37` find
//! the position of `/orders/7`. A template is never fed back into route matching
//! or route configuration as a literal path.

/// Maximum accepted input length. Longer paths are rejected rather than
/// normalized, keeping the audit field bounded without truncating a value
/// into a different, misleading template.
pub const MAX_PATH_BYTES: usize = 256;

/// Placeholder written in place of a recognized variable segment.
const PLACEHOLDER: &str = "{id}";

/// Normalizes `path` into a display template, or returns `None` when `path`
/// is not a plain, bounded absolute path this heuristic can safely describe.
///
/// # Examples
/// `/orders/482910` becomes `/orders/{id}`; `/orders` is unchanged; a path
/// containing a query string, a control byte, or longer than
/// [`MAX_PATH_BYTES`] returns `None`.
#[must_use]
pub fn normalize(path: &str) -> Option<String> {
    if !is_plain(path) {
        return None;
    }
    let mut template = String::with_capacity(path.len());
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            template.push('/');
        }
        if is_variable_segment(segment) {
            template.push_str(PLACEHOLDER);
        } else {
            template.push_str(segment);
        }
    }
    Some(template)
}

/// Whether `path` is a plain, bounded absolute path the heuristics can describe: the
/// refusals [`normalize`] makes.
fn is_plain(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && path.starts_with('/')
        && !path.contains(['?', '#'])
        && !path.bytes().any(|byte| byte.is_ascii_control())
}

/// The spelling of `path` that the usual HTTP stacks route it by: the equivalences of RFC 3986
/// section 6.2.2. Empty segments go, so a trailing slash and a doubled slash too; `.` segments go,
/// and a `..` segment takes its parent away (at the root it goes); a percent-escape of an
/// unreserved character is decoded, and the other escapes keep their escape with upper-case hex
/// digits. Every other character is kept, so a spelling that may route differently (an encoded
/// slash, another case) is not folded into another one.
///
/// Returns `None` for a path [`normalize`] refuses, and for a malformed escape.
#[must_use]
pub fn canonical_path(path: &str) -> Option<String> {
    if !is_plain(path) {
        return None;
    }
    let mut segments: Vec<String> = Vec::new();
    for raw in path.split('/').skip(1) {
        let decoded = decode_unreserved(raw)?;
        match decoded.as_str() {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(decoded),
        }
    }
    Some(format!("/{}", segments.join("/")))
}

/// `segment` with each escape of an unreserved character decoded, and each other escape kept
/// with upper-case hex digits. `None` when an escape is not followed by two hex digits.
fn decode_unreserved(segment: &str) -> Option<String> {
    let mut out = String::with_capacity(segment.len());
    let mut rest = segment;
    while let Some(index) = rest.find('%') {
        out.push_str(&rest[..index]);
        let hex = rest.get(index + 1..index + 3)?;
        if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let byte = u8::from_str_radix(hex, 16).ok()?;
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&hex.to_ascii_uppercase());
        }
        rest = &rest[index + 3..];
    }
    out.push_str(rest);
    Some(out)
}

/// The template a route position is keyed by: the canonical spelling of `path`, with its
/// numeric and UUID segments replaced as [`normalize`] does. A path without a canonical
/// spelling is kept as it is.
#[must_use]
pub fn position_template(path: &str) -> String {
    match canonical_path(path) {
        Some(canonical) => normalize(&canonical).unwrap_or(canonical),
        None => path.to_owned(),
    }
}

/// A segment counts as variable only when it is entirely digits or a
/// canonical (hyphenated, case-insensitive) UUID. Anything else — including a
/// mixed alphanumeric slug — is kept literal: the heuristic would rather
/// under-merge than quietly fold two distinct literal endpoints together.
fn is_variable_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    (!segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()))
        || is_canonical_uuid(segment)
}

fn is_canonical_uuid(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            *byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    })
}

#[cfg(test)]
mod canonical_tests {
    use super::{canonical_path, position_template};

    #[test]
    fn equivalent_spellings_share_one_canonical_path() {
        assert_eq!(
            canonical_path("/api/patients/7005/").as_deref(),
            Some("/api/patients/7005")
        );
        assert_eq!(
            canonical_path("/api//patients/7005").as_deref(),
            Some("/api/patients/7005")
        );
        assert_eq!(
            canonical_path("/api/./patients/7005").as_deref(),
            Some("/api/patients/7005")
        );
        assert_eq!(
            canonical_path("/api/x/../patients/7005").as_deref(),
            Some("/api/patients/7005")
        );
        assert_eq!(
            canonical_path("/../api/patients").as_deref(),
            Some("/api/patients")
        );
        assert_eq!(canonical_path("/api/%37005").as_deref(), Some("/api/7005"));
        assert_eq!(
            canonical_path("/api/%2e%2E/patients").as_deref(),
            Some("/patients")
        );
        assert_eq!(canonical_path("/").as_deref(), Some("/"));
    }

    #[test]
    fn spellings_that_may_route_differently_are_kept_apart() {
        assert_eq!(canonical_path("/api/a%2fb").as_deref(), Some("/api/a%2Fb"));
        assert_eq!(canonical_path("/api/a%2Fb").as_deref(), Some("/api/a%2Fb"));
        assert_eq!(
            canonical_path("/api/Patients").as_deref(),
            Some("/api/Patients")
        );
    }

    #[test]
    fn refuses_what_it_cannot_place() {
        assert_eq!(canonical_path("orders/1"), None);
        assert_eq!(canonical_path("/orders?x=1"), None);
        assert_eq!(canonical_path("/api/%zz"), None);
        assert_eq!(canonical_path("/api/%4"), None);
        assert_eq!(canonical_path("/api/%+1"), None);
    }

    #[test]
    fn positions_key_equivalent_spellings_alike() {
        assert_eq!(
            position_template("/api/patients/7005/"),
            "/api/patients/{id}"
        );
        assert_eq!(
            position_template("/api/patients/%37005"),
            "/api/patients/{id}"
        );
        assert_eq!(
            position_template("/api/patients/7005"),
            "/api/patients/{id}"
        );
        assert_eq!(position_template("/orders/a%2Fb/"), "/orders/a%2Fb");
        assert_eq!(position_template("orders/1"), "orders/1");
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_PATH_BYTES, normalize};

    #[test]
    fn replaces_only_fully_numeric_or_uuid_segments() {
        assert_eq!(normalize("/orders/482910"), Some("/orders/{id}".to_owned()));
        assert_eq!(
            normalize("/orders/482910/items/7"),
            Some("/orders/{id}/items/{id}".to_owned())
        );
        assert_eq!(
            normalize("/users/9c858f3e-5b61-4d1a-8c7e-6b1c9d9f2a3b"),
            Some("/users/{id}".to_owned())
        );
        // Mixed-case UUID hex is still canonical.
        assert_eq!(
            normalize("/users/9C858F3E-5B61-4D1A-8C7E-6B1C9D9F2A3B"),
            Some("/users/{id}".to_owned())
        );
    }

    #[test]
    fn keeps_literal_and_mixed_segments_untouched() {
        assert_eq!(normalize("/orders"), Some("/orders".to_owned()));
        assert_eq!(normalize("/"), Some(String::new() + "/"));
        assert_eq!(normalize("/orders/"), Some("/orders/".to_owned()));
        assert_eq!(
            normalize("/orders/order-42"),
            Some("/orders/order-42".to_owned())
        );
        assert_eq!(normalize("/v2/users"), Some("/v2/users".to_owned()));
        // A near-UUID with the wrong hyphen positions or length stays literal.
        assert_eq!(
            normalize("/users/9c858f3e-5b61-4d1a-8c7e-6b1c9d9f2a3"),
            Some("/users/9c858f3e-5b61-4d1a-8c7e-6b1c9d9f2a3".to_owned())
        );
    }

    #[test]
    fn rejects_values_this_heuristic_cannot_safely_describe() {
        assert_eq!(normalize(""), None);
        assert_eq!(normalize("orders/1"), None);
        assert_eq!(normalize("/orders?page=2"), None);
        assert_eq!(normalize("/orders#frag"), None);
        assert_eq!(normalize("/orders/\u{7}1"), None);
        assert_eq!(
            normalize(&("/".to_owned() + &"a".repeat(MAX_PATH_BYTES))),
            None
        );
    }

    #[test]
    fn accepts_the_exact_byte_ceiling() {
        let path = format!("/{}", "a".repeat(MAX_PATH_BYTES - 1));
        assert_eq!(path.len(), MAX_PATH_BYTES);
        assert!(normalize(&path).is_some());
    }
}
