//! Interface names read from the request (docs/header-routes-design section 2).
//!
//! A route says where the origin keeps the real interface name when the URL
//! path does not carry it: a request header, a query parameter or a body field.
//! The logical path is the URL path followed by that name, and the gateway
//! judges, remembers and logs a request by it. The request itself is forwarded
//! unchanged.
//!
//! Everything here is a pure function of the site configuration and the
//! request. The console computes the same answers in the browser, and
//! `web/console/tests/fixtures/logical-path-cases.json` holds the cases both
//! sides must pass.

use std::borrow::Cow;
use std::fmt;

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserializer, Serialize, Serializer};

use super::config::PathPattern;
use crate::hex::hex_digit;

/// Most routes one site may declare.
pub const ROUTES_MAX: usize = 32;
/// Most parts (groups of sources) in one `name_from`.
pub const PARTS_MAX: usize = 8;
/// Most sources in one part.
pub const SOURCES_MAX: usize = 4;
/// Longest source name, interface name part or interface name value, in bytes.
pub const NAME_MAX: usize = 64;
/// Most request header names a decision row keeps.
pub const HEADER_NAMES_MAX: usize = 64;
/// Largest JSON body read to find an interface name part.
const BODY_PARSE_MAX: usize = 64 * 1024;

/// Why a request has no usable interface name. Each reason is an unknown
/// interface: never an entry, never bypassed, always judged by Jev.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// A source of a part holds no value.
    Missing,
    /// A source appears more than once (a repeated header, query parameter or key).
    Repeated,
    /// Sources of the same part hold different values.
    Conflict,
    /// A value is not a plain name (letters, digits, `.`, `_`, `-`, up to 64 bytes),
    /// or the body field is not a string.
    InvalidName,
    /// A body source is used but the body is neither JSON nor a form.
    BodyUnsupported,
    /// A body source is used but the JSON body does not parse (encrypted bodies too).
    BodyNotJson,
    /// A body source is used but the body was too large to read.
    BodyTooLarge,
    /// The URL path lies under a route's path but is not the route itself, so its
    /// spelling could collide with a named logical path.
    RouteSubpath,
}

/// The interface name of a request, or the reason it has none. Serialized as
/// `{"name", "from"}` or `{"unknown", "source"}`. A decision row holds `null`
/// when no route covers the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Api {
    /// The name the route read, and the configured sources that supplied it.
    Named {
        /// The interface name: the parts joined with `/`.
        name: String,
        /// The configured sources that supplied the parts, in order.
        from: Vec<String>,
    },
    /// The request is an unknown interface. `source` names the configured source
    /// that failed, when one did.
    Unknown {
        /// Why the request is an unknown interface.
        unknown: UnknownReason,
        /// The configured source that failed, when one did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
}

/// Where one part of an interface name is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A request header, matched by name without regard to case.
    Header(String),
    /// A query parameter, matched by its decoded name.
    Query(String),
    /// A body field. In JSON these are the keys of the path to the string; in a
    /// form the field whose whole name is these keys joined by dots.
    Body(Vec<String>),
}

impl Source {
    /// Parses `header.<name>`, `query.<name>` or `body.<a.b.c>`. Anything else,
    /// `path` included, is not a source.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (kind, rest) = text.split_once('.')?;
        match kind {
            "header" => valid_header_name(rest).then(|| Self::Header(rest.to_owned())),
            "query" => valid_query_name(rest).then(|| Self::Query(rest.to_owned())),
            "body" => {
                let keys: Vec<String> = rest.split('.').map(str::to_owned).collect();
                (rest.len() <= NAME_MAX && keys.iter().all(|key| valid_body_key(key)))
                    .then_some(Self::Body(keys))
            }
            _ => None,
        }
    }

    /// Where the value this source reads sits among the request's values
    /// (`query.<name>`, `body.<a.b.c>`). Headers are never request values.
    #[must_use]
    pub fn location(&self) -> Option<String> {
        match self {
            Self::Header(_) => None,
            Self::Query(name) => Some(format!("query.{name}")),
            Self::Body(keys) => Some(format!("body.{}", keys.join("."))),
        }
    }

    /// The value this source gives: `None` when it is absent, an unknown reason
    /// when it cannot be read exactly once.
    fn read(&self, request: &RequestView<'_>) -> Result<Option<String>, UnknownReason> {
        match self {
            Self::Header(name) => one_value(
                request
                    .headers
                    .iter()
                    .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| (*value).to_owned())
                    .collect(),
            ),
            Self::Query(name) => one_value(form_values(request.query.unwrap_or(""), name)),
            Self::Body(keys) => match request.body {
                Body::Unread => Err(UnknownReason::BodyTooLarge),
                Body::Read { bytes: [], .. } => Ok(None),
                Body::Read {
                    content_type,
                    bytes,
                } => {
                    let media = media_type(content_type);
                    if media == "application/x-www-form-urlencoded" {
                        let text = String::from_utf8_lossy(bytes);
                        one_value(form_values(&text, &keys.join(".")))
                    } else if media == "application/json" || media.ends_with("+json") {
                        json_value(bytes, keys)
                    } else {
                        Err(UnknownReason::BodyUnsupported)
                    }
                }
            },
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(name) => write!(formatter, "header.{name}"),
            Self::Query(name) => write!(formatter, "query.{name}"),
            Self::Body(keys) => write!(formatter, "body.{}", keys.join(".")),
        }
    }
}

impl Serialize for Source {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// One route: the URL paths it covers and where the origin reads the interface
/// name from. A route's path must not nest in another route's path (see
/// [`overlaps`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route {
    path: PathPattern,
    name_from: Vec<Vec<Source>>,
}

impl Route {
    /// Validates one route as configured: an entry-style path that does not end
    /// in `/`, and 1 to [`PARTS_MAX`] non-empty parts of 1 to [`SOURCES_MAX`]
    /// sources each.
    #[must_use]
    pub fn parse(path: &str, name_from: &[Vec<String>]) -> Option<Self> {
        let path = PathPattern::parse(path)?;
        if path.stem().ends_with('/') || name_from.is_empty() || name_from.len() > PARTS_MAX {
            return None;
        }
        let mut parts = Vec::with_capacity(name_from.len());
        for group in name_from {
            if group.is_empty() || group.len() > SOURCES_MAX {
                return None;
            }
            let sources = group
                .iter()
                .map(|text| Source::parse(text))
                .collect::<Option<Vec<_>>>()?;
            parts.push(sources);
        }
        Some(Self {
            path,
            name_from: parts,
        })
    }

    /// The URL paths the route covers.
    #[must_use]
    pub fn path(&self) -> &PathPattern {
        &self.path
    }

    /// The parts of the interface name, in order.
    #[must_use]
    pub fn name_from(&self) -> &[Vec<Source>] {
        &self.name_from
    }

    fn reads_body(&self) -> bool {
        self.name_from
            .iter()
            .flatten()
            .any(|source| matches!(source, Source::Body(_)))
    }

    /// Whether `path` is under this exact route's path without being the route
    /// itself. Prefix routes cover their sub-paths by matching them.
    fn covers_subpath(&self, path: &str) -> bool {
        !self.path.is_prefix() && is_under(path, self.path.stem())
    }

    fn fixed_segments(&self) -> usize {
        self.path
            .stem()
            .split('/')
            .filter(|segment| !segment.is_empty())
            .count()
    }

    fn resolve(&self, request: &RequestView<'_>) -> Resolved {
        let fixed = self.fixed_segments();
        let mut parts = Vec::with_capacity(self.name_from.len());
        let mut from = Vec::new();
        let mut locations = Vec::new();
        for group in &self.name_from {
            match read_part(group, request) {
                Ok(part) => {
                    parts.push(part.value);
                    from.extend(part.sources);
                    locations.extend(part.locations);
                }
                Err(failure) => {
                    return Resolved::unknown(
                        request.path,
                        failure.reason,
                        Some(failure.source),
                        fixed,
                    );
                }
            }
        }
        Resolved::named(request.path, &parts.join("/"), from, locations, fixed)
    }
}

/// Whether two routes both cover some URL path. Routes must not overlap, so
/// that every logical path names exactly one route and one interface.
#[must_use]
pub fn overlaps(first: &Route, second: &Route) -> bool {
    let (left, right) = (&first.path, &second.path);
    match (left.is_prefix(), right.is_prefix()) {
        (true, true) => {
            left.stem().starts_with(right.stem()) || right.stem().starts_with(left.stem())
        }
        (false, false) => {
            left.stem() == right.stem()
                || is_under(left.stem(), right.stem())
                || is_under(right.stem(), left.stem())
        }
        (false, true) => exact_meets_prefix(left.stem(), right.stem()),
        (true, false) => exact_meets_prefix(right.stem(), left.stem()),
    }
}

fn exact_meets_prefix(exact: &str, prefix: &str) -> bool {
    exact.starts_with(prefix) || is_under(prefix, exact)
}

/// Whether `path` lies strictly under `base` at a segment boundary.
fn is_under(path: &str, base: &str) -> bool {
    path.len() > base.len()
        && path.starts_with(base)
        && path.as_bytes().get(base.len()) == Some(&b'/')
}

/// What the gateway knows about the request's path and interface name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    logical: String,
    api: Option<Api>,
    kind: String,
    fixed: usize,
    locations: Vec<String>,
}

impl Resolved {
    /// A request no route covers: its logical path is its URL path.
    #[must_use]
    pub fn plain(path: &str) -> Self {
        Self {
            logical: path.to_owned(),
            api: None,
            kind: path.to_owned(),
            fixed: 0,
            locations: Vec::new(),
        }
    }

    fn named(
        path: &str,
        name: &str,
        from: Vec<String>,
        locations: Vec<String>,
        fixed: usize,
    ) -> Self {
        Self {
            logical: format!("{}/{name}", path.trim_end_matches('/')),
            api: Some(Api::Named {
                name: name.to_owned(),
                from,
            }),
            kind: name.to_owned(),
            fixed,
            locations,
        }
    }

    fn unknown(path: &str, reason: UnknownReason, source: Option<String>, fixed: usize) -> Self {
        Self {
            logical: path.to_owned(),
            api: Some(Api::Unknown {
                unknown: reason,
                source,
            }),
            kind: String::new(),
            fixed,
            locations: Vec::new(),
        }
    }

    /// The logical path: the URL path followed by the interface name. For an
    /// unknown interface, the URL path, which never matches an entry or bypass.
    #[must_use]
    pub fn logical_path(&self) -> &str {
        &self.logical
    }

    /// The interface name or unknown reason; `None` when no route covers the request.
    #[must_use]
    pub fn api(&self) -> Option<&Api> {
        self.api.as_ref()
    }

    /// Whether the request is an unknown interface: never an entry, never
    /// bypassed, never settled by values or by a cached allow.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        matches!(self.api, Some(Api::Unknown { .. }))
    }

    /// The path entries and bypass patterns are matched against. `None` for an
    /// unknown interface.
    #[must_use]
    pub fn entry_path(&self) -> Option<&str> {
        if self.is_unknown() {
            None
        } else {
            Some(&self.logical)
        }
    }

    /// The text the category of the request is read from: the interface name
    /// (`doctorService/getDoctorById`), the URL path without a route, and
    /// nothing for an unknown interface.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// How many leading URL path segments the route fixes. Those segments are
    /// configuration, not request values.
    #[must_use]
    pub fn fixed_segments(&self) -> usize {
        self.fixed
    }

    /// The request values that became part of the interface name (`query.action`,
    /// `body.method`). They are the name now, not values to verify.
    #[must_use]
    pub fn name_locations(&self) -> &[String] {
        &self.locations
    }
}

/// The request as the route rules read it. Header names are matched without
/// regard to case; a header value that is not text is passed as empty, which is
/// never a valid name.
#[derive(Debug, Clone, Copy)]
pub struct RequestView<'a> {
    /// Request path without query, as sent.
    pub path: &'a str,
    /// Raw query string, without `?`.
    pub query: Option<&'a str>,
    /// Header name and value pairs, repeated names repeated.
    pub headers: &'a [(&'a str, &'a str)],
    /// The body, when it was read.
    pub body: Body<'a>,
}

/// The request body as far as interface names need it.
#[derive(Debug, Clone, Copy)]
pub enum Body<'a> {
    /// The body was read: its `Content-Type` and its bytes.
    Read {
        /// The `Content-Type` header, if any.
        content_type: Option<&'a str>,
        /// The whole body; empty when there is none.
        bytes: &'a [u8],
    },
    /// The body was not read: too large, or not inspectable.
    Unread,
}

/// Resolves `request` against `routes`: the logical path and interface name.
#[must_use]
pub fn resolve(routes: &[Route], request: &RequestView<'_>) -> Resolved {
    if let Some(route) = routes.iter().find(|route| route.path.matches(request.path)) {
        return route.resolve(request);
    }
    if routes
        .iter()
        .any(|route| route.covers_subpath(request.path))
    {
        return Resolved::unknown(request.path, UnknownReason::RouteSubpath, None, 0);
    }
    Resolved::plain(request.path)
}

/// Whether the route covering `path`, if any, reads the body to name it.
#[must_use]
pub fn names_from_body(routes: &[Route], path: &str) -> bool {
    routes
        .iter()
        .find(|route| route.path.matches(path))
        .is_some_and(Route::reads_body)
}

/// The names of a request's headers as a decision row keeps them: lower case,
/// no values, each name once, at most [`HEADER_NAMES_MAX`].
#[must_use]
pub fn header_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in names {
        if out.len() >= HEADER_NAMES_MAX {
            break;
        }
        let lower: String = name.to_ascii_lowercase().chars().take(NAME_MAX).collect();
        if !out.contains(&lower) {
            out.push(lower);
        }
    }
    out
}

struct Part {
    value: String,
    sources: Vec<String>,
    locations: Vec<String>,
}

struct Failure {
    reason: UnknownReason,
    source: String,
}

/// Reads one part: every source that gives a value must agree, and at least one
/// must. A source that cannot be read exactly once fails the part outright.
fn read_part(group: &[Source], request: &RequestView<'_>) -> Result<Part, Failure> {
    let first = group.first().map(ToString::to_string).unwrap_or_default();
    let mut part = Part {
        value: String::new(),
        sources: Vec::new(),
        locations: Vec::new(),
    };
    let mut found = false;
    for source in group {
        let label = source.to_string();
        let read = source.read(request).map_err(|reason| Failure {
            reason,
            source: label.clone(),
        })?;
        let Some(value) = read else { continue };
        if !valid_value(&value) {
            return Err(Failure {
                reason: UnknownReason::InvalidName,
                source: label,
            });
        }
        if found && value != part.value {
            return Err(Failure {
                reason: UnknownReason::Conflict,
                source: first,
            });
        }
        if !found {
            part.value = value;
            found = true;
        }
        part.sources.push(label);
        part.locations.extend(source.location());
    }
    if found {
        Ok(part)
    } else {
        Err(Failure {
            reason: UnknownReason::Missing,
            source: first,
        })
    }
}

/// Zero values are absent, one is the value, more than one is a repeat.
fn one_value<T>(mut values: Vec<T>) -> Result<Option<T>, UnknownReason> {
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.pop()),
        _ => Err(UnknownReason::Repeated),
    }
}

/// The decoded values of `name` in a query string or form body.
fn form_values(text: &str, name: &str) -> Vec<String> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key) == name).then(|| decode(value))
        })
        .collect()
}

/// Percent-decodes one query or form component, where `+` is a space.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len()
                && hex_digit(bytes[index + 1]).is_some()
                && hex_digit(bytes[index + 2]).is_some() =>
            {
                let high = hex_digit(bytes[index + 1]).unwrap_or(0);
                let low = hex_digit(bytes[index + 2]).unwrap_or(0);
                out.push(high * 16 + low);
                index += 3;
            }
            b'+' => {
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

/// The media type of a `Content-Type`, lower case, without parameters.
fn media_type(content_type: Option<&str>) -> String {
    content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// What a walk through a JSON document found at a path.
enum Hit {
    Absent,
    Text(String),
    Other,
    Many,
}

impl Hit {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Absent, found) | (found, Self::Absent) => found,
            _ => Self::Many,
        }
    }
}

/// The string at `keys` in a JSON document. Any duplicate key on the way, or any
/// array, is not taken: parsers disagree on which duplicate wins, and a batch
/// call has no single name.
fn json_value(bytes: &[u8], keys: &[String]) -> Result<Option<String>, UnknownReason> {
    if bytes.len() > BODY_PARSE_MAX {
        return Err(UnknownReason::BodyTooLarge);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let hit = JsonPath { keys }
        .deserialize(&mut deserializer)
        .map_err(|_| UnknownReason::BodyNotJson)?;
    deserializer.end().map_err(|_| UnknownReason::BodyNotJson)?;
    match hit {
        Hit::Absent => Ok(None),
        Hit::Text(text) => Ok(Some(text)),
        Hit::Other => Err(UnknownReason::InvalidName),
        Hit::Many => Err(UnknownReason::Repeated),
    }
}

/// Walks a JSON document along `keys`, skipping every other member unparsed.
struct JsonPath<'k> {
    keys: &'k [String],
}

impl<'de> DeserializeSeed<'de> for JsonPath<'_> {
    type Value = Hit;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Hit, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonPath<'_> {
    type Value = Hit;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Hit, A::Error> {
        let Some((head, rest)) = self.keys.split_first() else {
            return Ok(Hit::Absent);
        };
        let mut hit = Hit::Absent;
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            let found = if key.as_ref() == head.as_str() {
                if rest.is_empty() {
                    match map.next_value::<serde_json::Value>()? {
                        serde_json::Value::String(text) => Hit::Text(text),
                        _ => Hit::Other,
                    }
                } else {
                    map.next_value_seed(JsonPath { keys: rest })?
                }
            } else {
                map.next_value::<IgnoredAny>()?;
                Hit::Absent
            };
            hit = hit.merge(found);
        }
        Ok(hit)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Hit, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Hit::Absent)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Hit, E> {
        Ok(Hit::Absent)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Hit, E> {
        Ok(Hit::Absent)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Hit, E> {
        Ok(Hit::Absent)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Hit, E> {
        Ok(Hit::Absent)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Hit, E> {
        Ok(Hit::Absent)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Hit, E> {
        Ok(Hit::Absent)
    }
}

/// A plain name value: 1 to [`NAME_MAX`] bytes of letters, digits, `.`, `_`
/// and `-`, and not made of dots alone (so never a `.` or `..` segment).
fn valid_value(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= NAME_MAX
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && text.bytes().any(|byte| byte != b'.')
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn valid_query_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_body_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= NAME_MAX
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(text: &str) -> Vec<Route> {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|route| {
                let name_from: Vec<Vec<String>> = route["name_from"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|group| {
                        group
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|source| source.as_str().unwrap().to_owned())
                            .collect()
                    })
                    .collect();
                Route::parse(route["path"].as_str().unwrap(), &name_from).unwrap()
            })
            .collect()
    }

    const GATEWAY: &str =
        r#"[{"path": "/gw", "name_from": [["header.X-Service-Id"], ["header.X-Service-Method"]]}]"#;

    fn view<'a>(
        path: &'a str,
        headers: &'a [(&'a str, &'a str)],
        body: Body<'a>,
    ) -> RequestView<'a> {
        RequestView {
            path,
            query: None,
            headers,
            body,
        }
    }

    #[test]
    fn a_route_without_a_source_or_with_a_bad_one_is_refused() {
        let ok = |path: &str, name: &[&[&str]]| {
            let name: Vec<Vec<String>> = name
                .iter()
                .map(|group| group.iter().map(|s| (*s).to_owned()).collect())
                .collect();
            Route::parse(path, &name).is_some()
        };
        assert!(ok("/gw", &[&["header.X-Id"]]));
        assert!(!ok("/gw", &[]));
        assert!(!ok("/gw", &[&[]]));
        assert!(!ok("/gw", &[&["path.0"]]));
        assert!(!ok("/gw", &[&["cookie.SID"]]));
        assert!(!ok("/gw", &[&["header."]]));
        assert!(!ok("/gw", &[&["body"]]));
        assert!(!ok("/gw", &[&["body.a..b"]]));
        assert!(!ok("/gw", &[&["query.a b"]]));
        assert!(!ok(
            "/gw",
            &[&[
                "header.X-Id",
                "header.a",
                "header.b",
                "header.c",
                "header.d"
            ]]
        ));
        assert!(!ok("/", &[&["header.X-Id"]]));
        assert!(!ok("/gw/", &[&["header.X-Id"]]));
        assert!(!ok("/gw/*", &[&["header.X-Id"]]));
        assert!(ok("/gw*", &[&["header.X-Id"]]));
    }

    #[test]
    fn overlapping_routes_are_detected() {
        let nested = routes(
            r#"[{"path": "/a", "name_from": [["header.X"]]},
                {"path": "/a/b", "name_from": [["header.X"]]}]"#,
        );
        assert!(overlaps(&nested[0], &nested[1]));
        let apart = routes(
            r#"[{"path": "/a", "name_from": [["header.X"]]},
                {"path": "/ab", "name_from": [["header.X"]]}]"#,
        );
        assert!(!overlaps(&apart[0], &apart[1]));
        let prefix = routes(
            r#"[{"path": "/a*", "name_from": [["header.X"]]},
                {"path": "/a/b", "name_from": [["header.X"]]}]"#,
        );
        assert!(overlaps(&prefix[0], &prefix[1]));
    }

    #[test]
    fn a_named_request_takes_its_logical_path_from_the_header() {
        let rules = routes(GATEWAY);
        let headers = [
            ("x-service-id", "bus.buriedPointService"),
            ("x-service-method", "saveBuriedPointList"),
        ];
        let resolved = resolve(&rules, &view("/gw", &headers, Body::Unread));
        assert_eq!(
            resolved.logical_path(),
            "/gw/bus.buriedPointService/saveBuriedPointList"
        );
        assert_eq!(
            resolved.api(),
            Some(&Api::Named {
                name: "bus.buriedPointService/saveBuriedPointList".to_owned(),
                from: vec![
                    "header.X-Service-Id".to_owned(),
                    "header.X-Service-Method".to_owned()
                ],
            })
        );
        assert_eq!(resolved.entry_path(), Some(resolved.logical_path()));
    }

    #[test]
    fn a_repeated_or_missing_header_is_an_unknown_interface() {
        let rules = routes(GATEWAY);
        let repeated = [
            ("x-service-id", "a"),
            ("x-service-id", "a"),
            ("x-service-method", "m"),
        ];
        let resolved = resolve(&rules, &view("/gw", &repeated, Body::Unread));
        assert_eq!(resolved.entry_path(), None);
        assert_eq!(
            resolved.api(),
            Some(&Api::Unknown {
                unknown: UnknownReason::Repeated,
                source: Some("header.X-Service-Id".to_owned()),
            })
        );
        let missing = [("x-service-id", "a")];
        let resolved = resolve(&rules, &view("/gw", &missing, Body::Unread));
        assert_eq!(
            resolved.api(),
            Some(&Api::Unknown {
                unknown: UnknownReason::Missing,
                source: Some("header.X-Service-Method".to_owned()),
            })
        );
        assert_eq!(resolved.kind(), "");
    }

    #[test]
    fn values_outside_the_plain_name_charset_are_invalid() {
        let rules = routes(GATEWAY);
        for value in ["a/b", "a b", "..", "a%2Fb", "é", ""] {
            let headers = [("x-service-id", value), ("x-service-method", "m")];
            let resolved = resolve(&rules, &view("/gw", &headers, Body::Unread));
            assert!(
                matches!(
                    resolved.api(),
                    Some(Api::Unknown {
                        unknown: UnknownReason::InvalidName | UnknownReason::Missing,
                        ..
                    })
                ),
                "{value:?} -> {:?}",
                resolved.api()
            );
        }
    }

    #[test]
    fn sources_of_one_part_must_agree() {
        let rules =
            routes(r#"[{"path": "/index.php", "name_from": [["query.action", "body.action"]]}]"#);
        let body = br#"{"action": "list"}"#;
        let json = [("content-type", "application/json")];
        let mut query_view = view(
            "/index.php",
            &json,
            Body::Read {
                content_type: Some("application/json"),
                bytes: body,
            },
        );
        query_view.query = Some("action=list");
        let resolved = resolve(&rules, &query_view);
        assert_eq!(resolved.logical_path(), "/index.php/list");
        assert_eq!(resolved.name_locations(), ["query.action", "body.action"]);

        query_view.query = Some("action=get");
        let resolved = resolve(&rules, &query_view);
        assert_eq!(
            resolved.api(),
            Some(&Api::Unknown {
                unknown: UnknownReason::Conflict,
                source: Some("query.action".to_owned()),
            })
        );
    }

    #[test]
    fn json_body_fields_are_read_by_path_and_duplicates_are_refused() {
        let rules = routes(r#"[{"path": "/api/rpc", "name_from": [["body.method"]]}]"#);
        let none: [(&str, &str); 0] = [];
        let ok = br#"{"id": 1, "method": "getDoctorById"}"#;
        let resolved = resolve(
            &rules,
            &view(
                "/api/rpc",
                &none,
                Body::Read {
                    content_type: Some("application/json; charset=utf-8"),
                    bytes: ok,
                },
            ),
        );
        assert_eq!(resolved.logical_path(), "/api/rpc/getDoctorById");

        let duplicate = br#"{"method": "a", "method": "b"}"#;
        let resolved = resolve(
            &rules,
            &view(
                "/api/rpc",
                &none,
                Body::Read {
                    content_type: Some("application/json"),
                    bytes: duplicate,
                },
            ),
        );
        assert_eq!(
            resolved.api(),
            Some(&Api::Unknown {
                unknown: UnknownReason::Repeated,
                source: Some("body.method".to_owned()),
            })
        );

        let batch = br#"[{"method": "a"}, {"method": "b"}]"#;
        let resolved = resolve(
            &rules,
            &view(
                "/api/rpc",
                &none,
                Body::Read {
                    content_type: Some("application/json"),
                    bytes: batch,
                },
            ),
        );
        assert!(matches!(
            resolved.api(),
            Some(Api::Unknown {
                unknown: UnknownReason::Missing,
                ..
            })
        ));

        let broken = br#"{"method": "a""#;
        let resolved = resolve(
            &rules,
            &view(
                "/api/rpc",
                &none,
                Body::Read {
                    content_type: Some("application/json"),
                    bytes: broken,
                },
            ),
        );
        assert!(matches!(
            resolved.api(),
            Some(Api::Unknown {
                unknown: UnknownReason::BodyNotJson,
                ..
            })
        ));
    }

    #[test]
    fn bodies_that_cannot_be_read_name_nothing() {
        let rules = routes(r#"[{"path": "/api/rpc", "name_from": [["body.method"]]}]"#);
        let none: [(&str, &str); 0] = [];
        let text = view(
            "/api/rpc",
            &none,
            Body::Read {
                content_type: Some("text/plain"),
                bytes: b"method=x",
            },
        );
        assert!(matches!(
            resolve(&rules, &text).api(),
            Some(Api::Unknown {
                unknown: UnknownReason::BodyUnsupported,
                ..
            })
        ));
        let unread = view("/api/rpc", &none, Body::Unread);
        assert!(matches!(
            resolve(&rules, &unread).api(),
            Some(Api::Unknown {
                unknown: UnknownReason::BodyTooLarge,
                ..
            })
        ));
        let empty = view(
            "/api/rpc",
            &none,
            Body::Read {
                content_type: None,
                bytes: b"",
            },
        );
        assert!(matches!(
            resolve(&rules, &empty).api(),
            Some(Api::Unknown {
                unknown: UnknownReason::Missing,
                ..
            })
        ));
    }

    #[test]
    fn form_bodies_match_the_whole_dotted_field_name() {
        let rules = routes(r#"[{"path": "/f", "name_from": [["body.a.b"]]}]"#);
        let none: [(&str, &str); 0] = [];
        let form = view(
            "/f",
            &none,
            Body::Read {
                content_type: Some("application/x-www-form-urlencoded"),
                bytes: b"a.b=doctor&c=1",
            },
        );
        assert_eq!(resolve(&rules, &form).logical_path(), "/f/doctor");
        let spaces = view(
            "/f",
            &none,
            Body::Read {
                content_type: Some("application/x-www-form-urlencoded"),
                bytes: b"a.b=doc%20list",
            },
        );
        assert_eq!(
            resolve(&rules, &spaces).api(),
            Some(&Api::Unknown {
                unknown: UnknownReason::InvalidName,
                source: Some("body.a.b".to_owned()),
            })
        );
    }

    #[test]
    fn paths_under_an_exact_route_are_never_named_by_their_spelling() {
        let rules = routes(GATEWAY);
        let none: [(&str, &str); 0] = [];
        let spelled = resolve(
            &rules,
            &view(
                "/gw/bus.buriedPointService/saveBuriedPointList",
                &none,
                Body::Unread,
            ),
        );
        assert_eq!(spelled.entry_path(), None);
        assert_eq!(
            spelled.api(),
            Some(&Api::Unknown {
                unknown: UnknownReason::RouteSubpath,
                source: None,
            })
        );
        let plain = resolve(&rules, &view("/other", &none, Body::Unread));
        assert_eq!(plain, Resolved::plain("/other"));
        assert_eq!(plain.api(), None);
        assert_eq!(plain.entry_path(), Some("/other"));
    }

    #[test]
    fn a_prefix_route_fixes_only_its_own_segments() {
        let rules = routes(r#"[{"path": "/api*", "name_from": [["header.X-M"]]}]"#);
        let headers = [("x-m", "list")];
        let resolved = resolve(&rules, &view("/api/patients/8", &headers, Body::Unread));
        assert_eq!(resolved.logical_path(), "/api/patients/8/list");
        assert_eq!(resolved.fixed_segments(), 1);
    }

    #[test]
    fn header_names_are_lower_case_distinct_and_capped() {
        let names = header_names(["Host", "X-Service-Id", "host"]);
        assert_eq!(names, ["host", "x-service-id"]);
        let many: Vec<String> = (0..100).map(|index| format!("h{index}")).collect();
        let kept = header_names(many.iter().map(String::as_str));
        assert_eq!(kept.len(), HEADER_NAMES_MAX);
    }

    #[test]
    fn the_shared_cases_hold() {
        let text = include_str!("../../../../web/console/tests/fixtures/logical-path-cases.json");
        let cases: serde_json::Value = serde_json::from_str(text).unwrap();
        for case in cases["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let rules = routes(&case["routes"].to_string());
            let request = &case["request"];
            let headers: Vec<(String, String)> = request["headers"]
                .as_array()
                .map(|pairs| {
                    pairs
                        .iter()
                        .map(|pair| {
                            (
                                pair[0].as_str().unwrap().to_owned(),
                                pair[1].as_str().unwrap().to_owned(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let header_refs: Vec<(&str, &str)> = headers
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            let body_text = request["body"].as_str();
            let content_type = request["content_type"].as_str();
            let path = request["path"].as_str().unwrap();
            let query = request["query"].as_str();
            let body = match body_text {
                Some(text) => Body::Read {
                    content_type,
                    bytes: text.as_bytes(),
                },
                None if request["body_unread"].as_bool() == Some(true) => Body::Unread,
                None => Body::Read {
                    content_type,
                    bytes: b"",
                },
            };
            let view = RequestView {
                path,
                query,
                headers: &header_refs,
                body,
            };
            let resolved = resolve(&rules, &view);
            let expect = &case["expect"];
            assert_eq!(
                resolved.logical_path(),
                expect["logical_path"].as_str().unwrap(),
                "{name}"
            );
            let api = serde_json::to_value(resolved.api()).unwrap();
            assert_eq!(api, expect["api"], "{name}");
        }
    }
}
