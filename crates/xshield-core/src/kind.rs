//! Which kind of object a word names, and when two words name the same kind.
//!
//! The judge uses these rules to decide whether a short value is an object the
//! session was shown, and the console previews a configuration change with the
//! same rules, so they live here and nowhere else.
//!
//! Both sides of a comparison reduce to kind words. What an origin showed a
//! value as: the field's own name (`ProductId` names a product), a bare `id`'s
//! parent object (`Products.id`), or with no parent the route word nearest the
//! end of the path that returned it. What a request
//! uses a value as: its key's name (a bare `id` nested in a named object travels
//! as `Object.id`), for a path segment the route word just before it, and for a
//! key with no name the route word nearest the end of the path. A site may also
//! declare the kind of a field or parameter with `advanced.field_kinds`, which
//! overrides the name for that field.

use super::context::advanced::{Advanced, FieldKind};

/// Words that name no kind: route prefixes, generic field names, and the verbs and
/// service words an interface name carries. `doctorService` and `getDoctorById`
/// both name a doctor; `save`, `list` or `query` name nothing.
pub(crate) const GENERIC_WORDS: [&str; 26] = [
    "api", "rest", "v1", "v2", "v3", "data", "value", "id", "service", "get", "set", "save",
    "query", "list", "update", "delete", "add", "create", "remove", "find", "search", "fetch",
    "load", "put", "post", "submit",
];

/// Words for one kind of object that differ between a field and the endpoint
/// that lists it (`paymentId` selects a card of `/api/Cards`).
const SYNONYMS: [(&str, &str); 1] = [("payment", "card")];

/// Identifier endings a compound word may carry (`doctorid`, `patientno`).
/// Longer endings come first so that `uuid` is not read as `id`.
const ID_SUFFIXES: [&str; 6] = ["uuid", "code", "num", "ref", "id", "no"];

/// Lower-cased words of a path or field name, camel case split, plural
/// endings and generic route prefixes removed: `/api/Addresss/7` gives
/// `address`, `ProductId` gives `product`.
#[must_use]
pub fn kind_words(text: &str) -> Vec<String> {
    let mut spaced = String::with_capacity(text.len() + 8);
    let mut previous_lower = false;
    for c in text.chars() {
        if c.is_ascii_uppercase() && previous_lower {
            spaced.push(' ');
        }
        previous_lower = c.is_ascii_lowercase();
        spaced.push(c);
    }
    spaced
        .split(|c: char| !c.is_ascii_alphabetic())
        .map(|word| word.to_ascii_lowercase().trim_end_matches('s').to_owned())
        .filter(|word| word.len() >= 3 && !GENERIC_WORDS.contains(&word.as_str()))
        .collect()
}

/// The kind a word names: a compound with an identifier ending loses the ending
/// (`doctorid` names a doctor); any other word is its own kind. Containment does
/// not make two words one kind: `doc` is part of `doctor`, and `outpatient` of
/// `patient`, so a document id must not unlock a doctor path.
#[must_use]
pub fn kind_of(word: &str) -> &str {
    ID_SUFFIXES
        .into_iter()
        .find_map(|suffix| word.strip_suffix(suffix))
        .filter(|rest| rest.len() >= 3)
        .unwrap_or(word)
}

fn same_kind(left: &str, right: &str) -> bool {
    kind_of(left) == kind_of(right)
}

/// Whether two words name the same kind of object, or are a built-in or site
/// synonym pair.
#[must_use]
pub fn related(left: &str, right: &str, synonyms: &[(String, String)]) -> bool {
    let pairs = SYNONYMS
        .iter()
        .map(|(first, second)| (*first, *second))
        .chain(
            synonyms
                .iter()
                .map(|(first, second)| (first.as_str(), second.as_str())),
        );
    same_kind(left, right)
        || pairs.into_iter().any(|(first, second)| {
            (same_kind(left, first) && same_kind(right, second))
                || (same_kind(left, second) && same_kind(right, first))
        })
}

/// A site's synonym pair as the kind rules compare it: the same reduction
/// `kind_words` applies to field and path names (lower case, trailing `s`
/// removed), so `address` matches the `addre` that `/api/Addresss` yields.
/// A pair with a word shorter than three letters after that is dropped: an
/// empty word would match every field.
#[must_use]
pub fn site_synonym(first: &str, second: &str) -> Option<(String, String)> {
    let first = first.to_ascii_lowercase();
    let second = second.to_ascii_lowercase();
    let (first, second) = (first.trim_end_matches('s'), second.trim_end_matches('s'));
    (first.len() >= 3 && second.len() >= 3).then(|| (first.to_owned(), second.to_owned()))
}

/// A site's kind rules: its synonym pairs as they compare, and the kinds it
/// declares for fields. The default holds the built-in rules only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    synonyms: Vec<(String, String)>,
    fields: Vec<FieldKind>,
}

impl Rules {
    /// The rules of a site's `advanced` section.
    #[must_use]
    pub fn of(advanced: &Advanced) -> Self {
        Self {
            synonyms: advanced
                .synonyms()
                .iter()
                .filter_map(|(first, second)| site_synonym(first, second))
                .collect(),
            fields: advanced.field_kinds().to_vec(),
        }
    }

    /// Whether two words name the same kind under these rules, by the built-in and the site's
    /// synonym pairs.
    #[must_use]
    pub fn relates(&self, left: &str, right: &str) -> bool {
        related(left, right, &self.synonyms)
    }
}

/// Where an origin showed a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shown<'a> {
    /// The field the value sat under, as the state keeps it (`doc.id` for a
    /// nested field).
    pub field: &'a str,
    /// `METHOD /path` of the request whose response showed the value.
    pub request: &'a str,
}

/// How a request uses a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Used<'a> {
    /// The value, decoded.
    pub value: &'a str,
    /// The request path, without query.
    pub path: &'a str,
    /// The query, form or body key the value travels under, if it has one. A
    /// bare `id` nested in a named object travels under `Object.id`.
    pub key: Option<&'a str>,
    /// For a path value, the index of its segment among the non-empty segments
    /// of `path`. A path value has no key, so this is what places it.
    pub segment: Option<usize>,
}

/// Whether the origin shows the value as the kind of object the request names
/// for it.
#[must_use]
pub fn affinity(shown: Shown<'_>, used: Used<'_>, rules: &Rules) -> bool {
    let wanted = wanted_kinds(used, rules);
    let known = shown_kinds(shown, rules);
    !wanted.is_empty()
        && wanted.iter().any(|word| {
            known
                .iter()
                .any(|other| related(word, other, &rules.synonyms))
        })
}

/// Whether the request names the kind `kind` for the value, by the same words
/// [`affinity`] compares. The object map uses it where it gives the origin's
/// position a kind and the request's own kind comes from its name.
#[must_use]
pub fn names_kind(used: Used<'_>, rules: &Rules, kind: &str) -> bool {
    wanted_kinds(used, rules)
        .iter()
        .any(|word| related(word, kind, &rules.synonyms))
}

/// Whether the origin shows the value as the kind `kind` by its name: the
/// declared kind of its field, or the words of the field's own name. The object
/// map uses it where it gives the request's position a kind and the origin's
/// own name has to carry that kind.
#[must_use]
pub fn shows_kind(shown: Shown<'_>, rules: &Rules, kind: &str) -> bool {
    shown_kinds(shown, rules)
        .iter()
        .any(|word| related(kind, word, &rules.synonyms))
}

/// Whether a declaration names the field the origin showed the value under, so
/// that the field counts as an identifier whatever its name looks like.
#[must_use]
pub fn declares(shown: Shown<'_>, rules: &Rules) -> bool {
    declared_for(&rules.fields, shown.field, request_path(shown.request)).is_some()
}

/// Values at least this long are specific enough to fast-allow when seen: one that a
/// response showed as an object of any kind counts, whatever its field is called.
pub const LONG_VALUE_CHARS: usize = 8;

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

/// The index of the path segment a value sits in, from its location: `path[2]`
/// is segment 2 among the non-empty segments. `None` for any other location.
#[must_use]
pub fn path_segment(at: &str) -> Option<usize> {
    at.strip_prefix("path[")?.strip_suffix(']')?.parse().ok()
}

/// Whether one place a session saw a value shows it as the object the request needs:
/// the test the judge applies to each origin. `wanted` is the kind the object map gives
/// the request's position and `known` the kind it gives the origin's position. Where the
/// map is silent on a side, the name of that side decides. `long` says whether the value
/// is long enough to be an identifier on its own ([`LONG_VALUE_CHARS`]).
#[must_use]
pub fn shown_as(
    used: Used<'_>,
    shown: Shown<'_>,
    wanted: Option<&str>,
    known: Option<&str>,
    rules: &Rules,
    long: bool,
) -> bool {
    let identifier = is_id_like(shown.field) || declares(shown, rules);
    match (wanted, known) {
        (Some(wanted), Some(kind)) => wanted == kind,
        (None, Some(kind)) => names_kind(used, rules, kind),
        (Some(wanted), None) => identifier && (long || shows_kind(shown, rules, wanted)),
        (None, None) => identifier && (long || affinity(shown, used, rules)),
    }
}

/// The kinds an origin shows a value as: the declared kind of its field when a
/// declaration names it, else the field's own name. A bare `id` takes the kind
/// of its parent (`Products.id`). With no parent it takes the route word nearest
/// the end of the request that returned it, the object that request addresses.
fn shown_kinds(shown: Shown<'_>, rules: &Rules) -> Vec<String> {
    if let Some(kind) = declared_for(&rules.fields, shown.field, request_path(shown.request)) {
        return vec![kind.to_owned()];
    }
    let (parent, last) = split_field(shown.field);
    let mut words = kind_words(last);
    if words.is_empty() {
        words = kind_words(parent);
    }
    if words.is_empty() {
        words = object_kinds(request_path(shown.request));
    }
    words
}

/// The kinds a use of a value names. A query, form or body value takes the
/// kind its key names: a declared kind when a declaration names the key in the
/// request's scope, else the key's words. A key with no words (a bare `id`, or
/// `ids`) names no kind, so it takes the route word nearest the end of the path:
/// `?id=9` on `/api/doctors/7/files` is a file, the object the path addresses. A
/// path segment has no key: it takes the route word nearest before it, so in
/// `/api/doctors/7/files/9` the 9 is a file whatever else the path names.
fn wanted_kinds(used: Used<'_>, rules: &Rules) -> Vec<String> {
    if let Some(key) = used.key {
        if let Some(kind) = declared_for(&rules.fields, key, used.path) {
            return vec![kind.to_owned()];
        }
        let by_key = kind_words(key);
        if !by_key.is_empty() {
            return by_key;
        }
    }
    route_kinds(used.path, used.segment)
}

/// The kinds of the route word nearest before segment `before` of the path,
/// counting its non-empty segments from zero, or nearest the end of the path
/// without one. A path with no route word there takes the whole path's words.
fn route_kinds(path: &str, before: Option<usize>) -> Vec<String> {
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let end = before.unwrap_or(segments.len()).min(segments.len());
    segments[..end]
        .iter()
        .rev()
        .map(|segment| kind_words(segment))
        .find(|words| !words.is_empty())
        .unwrap_or_else(|| kind_words(path))
}

/// Words that name an action on a path's objects, not an object: a search
/// returns the objects it names, so `/rest/products/search` lists products.
const ACTION_WORDS: [&str; 6] = ["search", "list", "find", "query", "filter", "lookup"];

/// The kinds a response's bare id takes from the request that returned it: the
/// route word nearest the end of the path that names an object, skipping action
/// words, else the whole path's words.
fn object_kinds(path: &str) -> Vec<String> {
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    segments
        .iter()
        .rev()
        .map(|segment| kind_words(segment))
        .find(|words| {
            !words.is_empty()
                && !words
                    .iter()
                    .all(|word| ACTION_WORDS.contains(&word.as_str()))
        })
        .unwrap_or_else(|| kind_words(path))
}

/// The declared kind of a field or key name, when a declaration names it and its
/// scope covers `path`. A name is its last dotted segment, and a bare `id` is
/// named by its parent (`doc.id` is the field `doc`).
fn declared_for<'r>(fields: &'r [FieldKind], name: &str, path: &str) -> Option<&'r str> {
    let (parent, last) = split_field(name);
    let find = |wanted: &str| {
        fields
            .iter()
            .find(|declared| {
                same_field(declared.field(), wanted)
                    && (declared.scope().is_empty()
                        || declared.scope().iter().any(|pattern| pattern.matches(path)))
            })
            .map(FieldKind::kind)
    };
    find(last).or_else(|| {
        if last.eq_ignore_ascii_case("id") && !parent.is_empty() {
            find(parent.rsplit('.').next().unwrap_or(parent))
        } else {
            None
        }
    })
}

/// The parent and the last segment of a dotted field name.
fn split_field(name: &str) -> (&str, &str) {
    name.rsplit_once('.').unwrap_or(("", name))
}

/// The path of a `METHOD /path` request text.
fn request_path(request: &str) -> &str {
    request.split_once(' ').map_or("", |(_, path)| path)
}

/// Field names compare without case and without `_` or `-`: `doc_id`, `docId`
/// and `DocID` are one name.
pub(crate) fn same_field(stored: &str, name: &str) -> bool {
    folded_name(stored).eq(folded_name(name))
}

fn folded_name(text: &str) -> impl Iterator<Item = u8> + '_ {
    text.bytes()
        .filter(|byte| !matches!(byte, b'_' | b'-'))
        .map(|byte| byte.to_ascii_lowercase())
}

/// Where a position's name gave it its kind: the reason the console shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// The field's own name, or a request key's, is an identifier of the kind.
    Field,
    /// A bare `id` takes the kind of the object it belongs to.
    Parent,
    /// A bare `id` takes the kind of the endpoint's name.
    Endpoint,
    /// A path segment takes the route word before it, or a bare key the route word nearest the
    /// end of the path.
    Route,
}

/// The kind a position's name gives it, and the name it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameReason {
    /// Where the name was read.
    pub source: NameSource,
    /// The kind word the name gives, in the form the rules compare.
    pub word: String,
    /// The field name, when the name is a field's own.
    pub field: Option<String>,
}

/// The kind a request position's name gives it. `route` is the request's route, `key` the query,
/// form or body key of the position (`None` for a path position), and `segment` the index of a path
/// position among the route's segments. A declared key gives no name, since its declaration decides,
/// and a key that names no identifier gives none either: `name` is a word, not an object.
#[must_use]
pub fn request_name(
    route: &str,
    key: Option<&str>,
    segment: Option<usize>,
    rules: &Rules,
) -> Option<NameReason> {
    let Some(key) = key else {
        let word = first_kind(route_kinds(route, segment))?;
        return Some(NameReason {
            source: NameSource::Route,
            word,
            field: None,
        });
    };
    if declared_for(&rules.fields, key, route).is_some() {
        return None;
    }
    let (parent, last) = split_field(key);
    if names_identifier(last) {
        return Some(NameReason {
            source: NameSource::Field,
            word: first_kind(kind_words(last))?,
            field: Some(key.to_owned()),
        });
    }
    if !kind_words(last).is_empty() {
        return None;
    }
    if let Some(word) = first_kind(kind_words(nearest(parent))) {
        return Some(NameReason {
            source: NameSource::Parent,
            word,
            field: None,
        });
    }
    let word = first_kind(route_kinds(route, None))?;
    Some(NameReason {
        source: NameSource::Route,
        word,
        field: None,
    })
}

/// The kind a response position's name gives it. `field` is the field as the state keeps it, and
/// `request` the `METHOD /path` that returned it. A declared field gives no name, and a field whose
/// name is not an identifier gives none either. A bare `id` takes its parent's kind, else the
/// endpoint's.
#[must_use]
pub fn response_name(field: &str, request: &str, rules: &Rules) -> Option<NameReason> {
    if declares(Shown { field, request }, rules) {
        return None;
    }
    let (parent, last) = split_field(field);
    if names_identifier(last) {
        return Some(NameReason {
            source: NameSource::Field,
            word: first_kind(kind_words(last))?,
            field: Some(field.to_owned()),
        });
    }
    if !kind_words(last).is_empty() {
        return None;
    }
    if let Some(word) = first_kind(kind_words(nearest(parent))) {
        return Some(NameReason {
            source: NameSource::Parent,
            word,
            field: None,
        });
    }
    let word = first_kind(object_kinds(request_path(request)))?;
    Some(NameReason {
        source: NameSource::Endpoint,
        word,
        field: None,
    })
}

/// Whether a field or key's last segment names an identifier: its name without `_` or `-`
/// ends in an identifier ending (`docId`, `doc_id`, `doctorno`), where a word that merely ends
/// in the same letters (`paid`) does not.
fn names_identifier(last: &str) -> bool {
    let folded: String = last
        .chars()
        .filter(|c| !matches!(c, '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    kind_of(&folded) != folded.as_str()
}

/// The first kind word of a name, with its identifier ending taken off.
fn first_kind(words: Vec<String>) -> Option<String> {
    words
        .into_iter()
        .next()
        .map(|word| kind_of(&word).to_owned())
}

/// The last dotted segment of a name's parent: the object a bare key sits in (`doctor` for
/// `patient.doctor.id`), with the whole name when it has no parent.
fn nearest(parent: &str) -> &str {
    parent.rsplit('.').next().unwrap_or(parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_gives_a_kind_only_when_it_names_an_identifier() {
        let rules = Rules::default();
        let route = request_name("/doctor/{id}", None, Some(1), &rules).expect("a route word");
        assert_eq!(
            (route.source, route.word.as_str()),
            (NameSource::Route, "doctor")
        );
        let query = request_name("/api/search", Some("doctor_id"), None, &rules).expect("a key");
        assert_eq!(
            (query.source, query.word.as_str(), query.field.as_deref()),
            (NameSource::Field, "doctor", Some("doctor_id"))
        );
        let nested = request_name("/api/notes", Some("doctor.id"), None, &rules).expect("a parent");
        assert_eq!(
            (nested.source, nested.word.as_str()),
            (NameSource::Parent, "doctor")
        );
        let bare = request_name("/api/doctors/7", Some("id"), None, &rules).expect("a route word");
        assert_eq!(
            (bare.source, bare.word.as_str()),
            (NameSource::Route, "doctor")
        );
        assert!(request_name("/api/search", Some("name"), None, &rules).is_none());
        assert!(request_name("/rest/save", None, None, &rules).is_none());
        let field =
            response_name("doc_id", "GET /api/records", &rules).expect("an identifier field");
        assert_eq!(
            (field.source, field.word.as_str()),
            (NameSource::Field, "doc")
        );
        assert_eq!(
            response_name("docid", "GET /api/records", &rules)
                .expect("a compound identifier")
                .word,
            "doc"
        );
        let parent = response_name("doctor.id", "GET /api/notes", &rules).expect("a parent");
        assert_eq!(
            (parent.source, parent.word.as_str()),
            (NameSource::Parent, "doctor")
        );
        let endpoint = response_name("id", "GET /api/doctors", &rules).expect("an endpoint");
        assert_eq!(
            (endpoint.source, endpoint.word.as_str()),
            (NameSource::Endpoint, "doctor")
        );
        assert!(response_name("name", "GET /api/me", &rules).is_none());
        assert!(response_name("paid", "GET /api/me", &rules).is_none());
    }

    #[test]
    fn words_come_from_names_without_route_prefixes_or_plurals() {
        assert_eq!(kind_words("/api/Addresss/7"), ["addre"]);
        assert_eq!(kind_words("ProductId"), ["product"]);
        assert_eq!(kind_words("/api/doctors/7/files/9"), ["doctor", "file"]);
        assert!(kind_words("id").is_empty());
    }

    #[test]
    fn an_identifier_ending_names_the_kind_before_it() {
        assert_eq!(kind_of("doctorid"), "doctor");
        assert_eq!(kind_of("doc"), "doc");
        assert_eq!(kind_of("uuid"), "uuid");
        assert!(related("doctor", "doctorid", &[]));
        assert!(!related("doc", "doctor", &[]));
        assert!(related("paymentid", "card", &[]));
        assert!(!related(
            "paymentid",
            "zebra",
            &[("zebra".into(), "apple".into())]
        ));
        let pairs = [site_synonym("Coupon", "vouchers").unwrap()];
        assert!(related("coupon", "voucher", &pairs));
        assert!(!related("coupon", "voucher", &[]));
        assert_eq!(site_synonym("ab", "card"), None);
    }

    #[test]
    fn field_names_compare_without_case_or_separators() {
        assert!(same_field("doc_id", "docId"));
        assert!(same_field("doc_id", "DocID"));
        assert!(same_field("doc-id", "doc_id"));
        assert!(!same_field("doc_id", "doc"));
    }

    #[test]
    fn a_declaration_names_a_bare_id_by_its_parent() {
        let spec = crate::context::SiteSpec::from_json(
            r#"{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{"cookie":"SID"},
               "entries":["/login"],"advanced":{"field_kinds":[{"field":"doc","kind":"doctor"}]}}"#,
        )
        .unwrap();
        let declared = Rules::of(spec.advanced());
        let shown = Shown {
            field: "doc.id",
            request: "GET /api/records/7",
        };
        let used = Used {
            value: "5",
            path: "/doctor/5",
            key: None,
            segment: Some(1),
        };
        // Without the declaration `doc.id` names a document, so it is no doctor.
        assert!(!affinity(shown, used, &Rules::default()));
        assert!(affinity(shown, used, &declared));
        assert!(declares(shown, &declared));
    }

    #[test]
    fn a_path_segment_takes_the_route_word_nearest_before_it() {
        let rules = Rules::default();
        let doctor = Shown {
            field: "id",
            request: "GET /api/doctors",
        };
        let used = |value, segment| Used {
            value,
            path: "/api/doctors/7/files/9",
            key: None,
            segment: Some(segment),
        };
        assert!(affinity(doctor, used("7", 2), &rules));
        assert!(!affinity(doctor, used("9", 4), &rules));
        assert!(affinity(
            doctor,
            Used {
                value: "9",
                path: "/api/doctors/7/9",
                key: None,
                segment: Some(2),
            },
            &rules
        ));
    }

    #[test]
    fn a_nameless_key_takes_the_route_word_at_the_end_of_the_path() {
        let rules = Rules::default();
        let doctor = Shown {
            field: "id",
            request: "GET /api/doctors",
        };
        let query = |path: &'static str| Used {
            value: "9",
            path,
            key: Some("id"),
            segment: None,
        };
        // `?id=9` on a file path names the file the path addresses, not the doctor.
        assert!(!affinity(doctor, query("/api/doctors/7/files"), &rules));
        assert!(affinity(doctor, query("/api/doctors"), &rules));
        // With no route word in the path there is nothing for the key to take.
        assert!(!affinity(doctor, query("/7"), &rules));
    }

    #[test]
    fn a_value_without_a_key_takes_the_route_word_at_the_end_too() {
        let rules = Rules::default();
        let doctor = Shown {
            field: "id",
            request: "GET /api/doctors",
        };
        let body = |path: &'static str| Used {
            value: "9",
            path,
            key: None,
            segment: None,
        };
        assert!(!affinity(doctor, body("/api/doctors/7/files"), &rules));
        assert!(affinity(doctor, body("/api/doctors"), &rules));
    }

    #[test]
    fn a_bare_id_nested_in_a_named_object_takes_that_name() {
        let rules = Rules::default();
        let document = Shown {
            field: "id",
            request: "GET /api/docs",
        };
        // `{"doc": {"id": 5}}` travels as `doc.id`: a document, as `?doc=5` would be.
        let nested = Used {
            value: "5",
            path: "/api/records",
            key: Some("doc.id"),
            segment: None,
        };
        assert!(affinity(document, nested, &rules));
        // The bare key names the record, so the same id is no document there.
        assert!(!affinity(
            document,
            Used {
                key: Some("id"),
                ..nested
            },
            &rules
        ));
    }

    #[test]
    fn a_bare_id_in_a_response_takes_the_route_word_at_the_end() {
        let rules = Rules::default();
        // Doctor 7's file list shows bare ids, and they are files, not doctors.
        let files = Shown {
            field: "id",
            request: "GET /api/doctors/7/files",
        };
        let doctor_path = Used {
            value: "9",
            path: "/api/doctors/9",
            key: None,
            segment: Some(2),
        };
        assert!(!affinity(files, doctor_path, &rules));
        let file_path = Used {
            value: "9",
            path: "/api/files/9",
            key: None,
            segment: Some(2),
        };
        assert!(affinity(files, file_path, &rules));
        // A doctor list's bare ids are still doctors.
        let doctors = Shown {
            field: "id",
            request: "GET /api/doctors",
        };
        assert!(affinity(doctors, doctor_path, &rules));
        // A search returns the objects it names, so its bare ids are products.
        let search = Shown {
            field: "id",
            request: "GET /rest/products/search",
        };
        let basket_product = Used {
            value: "9",
            path: "/api/BasketItems/9",
            key: Some("ProductId"),
            segment: None,
        };
        assert!(affinity(search, basket_product, &rules));
    }

    #[test]
    fn a_kind_the_map_gives_is_matched_by_the_names_on_the_other_side() {
        let used = Used {
            value: "5",
            path: "/doctor/5",
            key: None,
            segment: Some(1),
        };
        assert!(names_kind(used, &Rules::default(), "doctor"));
        assert!(!names_kind(used, &Rules::default(), "document"));
        let shown = Shown {
            field: "doctor_id",
            request: "GET /api/appointments",
        };
        assert!(shows_kind(shown, &Rules::default(), "doctor"));
        assert!(!shows_kind(shown, &Rules::default(), "document"));
        // A bare `id` takes the kind of the request that returned it.
        let bare = Shown {
            field: "id",
            request: "GET /api/documents",
        };
        assert!(shows_kind(bare, &Rules::default(), "document"));
        assert!(!shows_kind(bare, &Rules::default(), "doctor"));
    }
}
