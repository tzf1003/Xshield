//! A bounded, deterministic normalization from a request path to a display
//! template, used only to group unmatched requests for route discovery.
//!
//! The heuristic is deliberately narrow: it replaces a segment only when the
//! whole segment is all-ASCII-digits or a canonical UUID, and leaves every
//! other segment untouched. A template is never fed back into route matching
//! or route configuration as a literal path; it is a grouping key for the
//! console's "import routes from observed traffic" discovery list.

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
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.contains(['?', '#'])
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
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
        assert_eq!(normalize("/orders/order-42"), Some("/orders/order-42".to_owned()));
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
        assert_eq!(normalize(&("/".to_owned() + &"a".repeat(MAX_PATH_BYTES))), None);
    }

    #[test]
    fn accepts_the_exact_byte_ceiling() {
        let path = format!("/{}", "a".repeat(MAX_PATH_BYTES - 1));
        assert_eq!(path.len(), MAX_PATH_BYTES);
        assert!(normalize(&path).is_some());
    }
}
