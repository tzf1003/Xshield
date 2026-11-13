//! Minimal v4 site configuration (docs/03 section 3.2).
//!
//! Context capacity and the other limits that shape gateway memory or the Jev
//! input contract are code defaults, not site options. The judging parameters a
//! site may override (Jev timeout, call limits, allow cache time, extra
//! redaction words, synonyms) live in the optional `advanced` section
//! (docs/07 section 7.6).

use serde::{Deserialize, Serialize};

use super::advanced::{Advanced, AdvancedDto};
use super::objects::{ObjectMap, ObjectMapDto, ObjectsIssue, ObjectsPlace};
use super::route::{self, ROUTES_MAX, RequestView, Resolved, Route, overlaps};

const NAME_MAX: usize = 64;
const HOSTS_MAX: usize = 16;
const HOST_MAX: usize = 253;
const PATTERNS_MAX: usize = 64;
const PATTERN_MAX: usize = 256;
const CREDENTIAL_NAME_MAX: usize = 64;

/// Why a site configuration was rejected. Messages never echo configured values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// The document is not valid JSON for the site schema (unknown field, wrong type).
    Malformed,
    /// `name` is empty, too long or contains characters outside `[a-z0-9_-]`.
    Name,
    /// `hosts` is empty, too long, or holds an invalid host name.
    Hosts,
    /// `origin` is not a plain `http(s)://host[:port]` URL.
    Origin,
    /// `session` names no credential or an invalid cookie/header name.
    Session,
    /// `entries` is empty or holds an invalid pattern.
    Entries,
    /// `bypass` holds an invalid pattern.
    Bypass,
    /// `routes` holds an invalid route, too many routes, or two routes that overlap.
    Routes,
    /// `advanced` holds an out of range number, an invalid or too short word, a
    /// synonym group that is not two different words, or too many entries.
    Advanced,
    /// `objects` names an undeclared or malformed kind, repeats a position, or
    /// holds more entries than the object map allows. The issue says which part.
    Objects(ObjectsIssue),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "SITE_CONFIG_MALFORMED",
            Self::Name => "SITE_CONFIG_NAME_INVALID",
            Self::Hosts => "SITE_CONFIG_HOSTS_INVALID",
            Self::Origin => "SITE_CONFIG_ORIGIN_INVALID",
            Self::Session => "SITE_CONFIG_SESSION_INVALID",
            Self::Entries => "SITE_CONFIG_ENTRIES_INVALID",
            Self::Bypass => "SITE_CONFIG_BYPASS_INVALID",
            Self::Routes => "SITE_CONFIG_ROUTES_INVALID",
            Self::Advanced => "SITE_CONFIG_ADVANCED_INVALID",
            Self::Objects(_) => "SITE_CONFIG_OBJECTS_INVALID",
        })
    }
}

impl std::error::Error for ConfigError {}

/// Whether blocked requests are enforced or only recorded (docs/00 section 0.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Judge and record; always forward. The default for a new site.
    #[default]
    Observe,
    /// Return 403 for requests judged unsafe.
    Enforce,
}

/// What to do when Jev times out, fails, is rate limited or answers UNKNOWN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnJevUnavailable {
    /// Refuse the request. The default.
    #[default]
    Deny,
    /// Forward the request and mark it as not judged in the decision log.
    Allow,
}

/// Where the origin's session credential travels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCredential {
    /// A cookie name, for example `SESSIONID`.
    Cookie(String),
    /// A request header name, for example `Authorization`.
    Header(String),
}

/// An exact path, or a prefix when it ends in `*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathPattern(String);

impl PathPattern {
    /// Parses a pattern: absolute path, no query, `*` only as the last byte.
    ///
    /// # Errors
    /// Returns `None` for empty, relative, oversized, control-byte, query,
    /// dot-segment or interior-wildcard patterns.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let literal = raw.strip_suffix('*').unwrap_or(raw);
        let valid = !raw.is_empty()
            && raw.len() <= PATTERN_MAX
            && raw.starts_with('/')
            && !literal.contains(['*', '?', '#', '\\'])
            && !literal
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
            && !has_dot_segment(literal);
        valid.then(|| Self(raw.to_owned()))
    }

    /// The pattern as configured.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the pattern is a prefix (ends in `*`).
    #[must_use]
    pub fn is_prefix(&self) -> bool {
        self.0.ends_with('*')
    }

    /// The pattern without its trailing `*`: the whole path of an exact pattern.
    #[must_use]
    pub fn stem(&self) -> &str {
        self.0.strip_suffix('*').unwrap_or(&self.0)
    }

    /// Whether `path` (without query) is covered by this pattern.
    ///
    /// A path with dot segments, doubled slashes, a backslash, a path parameter
    /// (`;`), a control byte or an encoded slash/dot/backslash never matches: a bypass or entry must not
    /// be reachable through a spelling the origin may resolve differently.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        if !is_plain_path(path) {
            return false;
        }
        match self.0.strip_suffix('*') {
            Some(prefix) => path.starts_with(prefix),
            None => path == self.0,
        }
    }
}

fn has_dot_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
}

/// True when `path` has one unambiguous spelling.
#[must_use]
pub fn is_plain_path(path: &str) -> bool {
    if !path.starts_with('/')
        || path.contains("//")
        || path.contains(['\\', '?', '#', ';'])
        || path.bytes().any(|byte| byte.is_ascii_control())
        || has_dot_segment(path)
    {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    !["%2e", "%2f", "%5c", "%00"]
        .iter()
        .any(|bad| lower.contains(bad))
}

/// A validated site (docs/03 section 3.2). Deserializing re-validates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SiteSpecDto")]
pub struct SiteSpec {
    name: String,
    hosts: Vec<String>,
    origin: String,
    session: SessionCredential,
    entries: Vec<PathPattern>,
    bypass: Vec<PathPattern>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    routes: Vec<Route>,
    mode: Mode,
    on_jev_unavailable: OnJevUnavailable,
    #[serde(skip_serializing_if = "Advanced::is_empty")]
    advanced: Advanced,
    #[serde(skip_serializing_if = "ObjectMap::is_empty")]
    objects: ObjectMap,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteDto {
    path: String,
    name_from: Vec<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteSpecDto {
    name: String,
    hosts: Vec<String>,
    origin: String,
    session: SessionCredential,
    entries: Vec<String>,
    #[serde(default)]
    bypass: Vec<String>,
    #[serde(default)]
    routes: Vec<RouteDto>,
    #[serde(default)]
    mode: Mode,
    #[serde(default)]
    on_jev_unavailable: OnJevUnavailable,
    // Read as a raw value: serde would otherwise take a JSON array as the
    // positional form of a struct, and reject `null` outright.
    #[serde(default)]
    advanced: Option<serde_json::Value>,
    // The object map is read as a raw value too, so that its own errors are
    // reported as `SITE_CONFIG_OBJECTS_INVALID` and not as a malformed site.
    #[serde(default)]
    objects: Option<serde_json::Value>,
}

impl TryFrom<SiteSpecDto> for SiteSpec {
    type Error = ConfigError;

    fn try_from(dto: SiteSpecDto) -> Result<Self, ConfigError> {
        if !valid_name(&dto.name) {
            return Err(ConfigError::Name);
        }
        if dto.hosts.is_empty()
            || dto.hosts.len() > HOSTS_MAX
            || !dto.hosts.iter().all(|host| valid_host(host))
        {
            return Err(ConfigError::Hosts);
        }
        if !valid_origin(&dto.origin) {
            return Err(ConfigError::Origin);
        }
        let credential = match &dto.session {
            SessionCredential::Cookie(name) | SessionCredential::Header(name) => name,
        };
        if !valid_token(credential) {
            return Err(ConfigError::Session);
        }
        if dto.entries.is_empty() || dto.entries.len() > PATTERNS_MAX {
            return Err(ConfigError::Entries);
        }
        if dto.bypass.len() > PATTERNS_MAX {
            return Err(ConfigError::Bypass);
        }
        let entries = parse_patterns(&dto.entries).ok_or(ConfigError::Entries)?;
        let bypass = parse_patterns(&dto.bypass).ok_or(ConfigError::Bypass)?;
        let routes = parse_routes(&dto.routes)?;
        let advanced = match dto.advanced {
            None | Some(serde_json::Value::Null) => Advanced::default(),
            Some(section @ serde_json::Value::Object(_)) => {
                let section: AdvancedDto =
                    serde_json::from_value(section).map_err(|_| ConfigError::Malformed)?;
                Advanced::try_from(section)?
            }
            Some(_) => return Err(ConfigError::Malformed),
        };
        let objects = match dto.objects {
            None | Some(serde_json::Value::Null) => ObjectMap::default(),
            Some(section @ serde_json::Value::Object(_)) => {
                let section: ObjectMapDto = serde_json::from_value(section).map_err(|_| {
                    ConfigError::Objects(ObjectsIssue {
                        place: ObjectsPlace::Section,
                        reason: None,
                    })
                })?;
                ObjectMap::try_from(section)?
            }
            // A JSON array would be read as the positional form of the struct.
            Some(_) => {
                return Err(ConfigError::Objects(ObjectsIssue {
                    place: ObjectsPlace::Section,
                    reason: None,
                }));
            }
        };
        let hosts = dto
            .hosts
            .iter()
            .map(|host| host.to_ascii_lowercase())
            .collect();
        Ok(Self {
            name: dto.name,
            hosts,
            origin: dto.origin,
            session: dto.session,
            entries,
            bypass,
            routes,
            mode: dto.mode,
            on_jev_unavailable: dto.on_jev_unavailable,
            advanced,
            objects,
        })
    }
}

impl SiteSpec {
    /// Parses and validates one site from its JSON form.
    ///
    /// # Errors
    /// [`ConfigError::Malformed`] for syntax, type or unknown-field problems,
    /// otherwise the first invalid section.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let dto: SiteSpecDto = serde_json::from_str(text).map_err(|_| ConfigError::Malformed)?;
        dto.try_into()
    }

    /// Parses and validates one site from an already parsed JSON document, for
    /// callers that hold a `serde_json::Value` (a `jsonb` column).
    ///
    /// # Errors
    /// The same as [`SiteSpec::from_json`].
    pub fn from_value(value: &serde_json::Value) -> Result<Self, ConfigError> {
        let dto: SiteSpecDto =
            SiteSpecDto::deserialize(value).map_err(|_| ConfigError::Malformed)?;
        dto.try_into()
    }

    /// Site name, unique per deployment.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Host names (lowercase) the gateway routes to this site.
    #[must_use]
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// Origin base URL.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Where the session credential is carried.
    #[must_use]
    pub fn session(&self) -> &SessionCredential {
        &self.session
    }

    /// Enforcement mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Behaviour when Jev cannot answer.
    #[must_use]
    pub fn on_jev_unavailable(&self) -> OnJevUnavailable {
        self.on_jev_unavailable
    }

    /// The site level judging parameters; empty when the site sets none.
    #[must_use]
    pub fn advanced(&self) -> &Advanced {
        &self.advanced
    }

    /// The site's object map (the object-map design note); empty before learning.
    #[must_use]
    pub fn objects(&self) -> &ObjectMap {
        &self.objects
    }

    /// The same site with its object map replaced. The learning task writes its automatic
    /// pauses with it, and the result is stored as a new configuration version.
    #[must_use]
    pub fn with_objects(mut self, objects: ObjectMap) -> Self {
        self.objects = objects;
        self
    }

    /// The entry pattern that covers `path`, as configured.
    #[must_use]
    pub fn matching_entry(&self, path: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|pattern| pattern.matches(path))
            .map(PathPattern::as_str)
    }

    /// The bypass pattern that covers `path`, as configured.
    #[must_use]
    pub fn matching_bypass(&self, path: &str) -> Option<&str> {
        self.bypass
            .iter()
            .find(|pattern| pattern.matches(path))
            .map(PathPattern::as_str)
    }

    /// Whether `path` is registered as an entry.
    #[must_use]
    pub fn is_entry(&self, path: &str) -> bool {
        self.entries.iter().any(|pattern| pattern.matches(path))
    }

    /// Whether `path` skips judging (the gateway still writes a brief log row).
    #[must_use]
    pub fn is_bypass(&self, path: &str) -> bool {
        self.bypass.iter().any(|pattern| pattern.matches(path))
    }

    /// The routes that name interfaces from the request, in configured order.
    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// The logical path of a request and its interface name (docs/header-routes-design
    /// section 2). A site without routes resolves every request to its URL path.
    #[must_use]
    pub fn resolve(&self, request: &RequestView<'_>) -> Resolved {
        route::resolve(&self.routes, request)
    }

    /// Whether the route covering `path`, if any, needs the body to name the request.
    #[must_use]
    pub fn names_from_body(&self, path: &str) -> bool {
        route::names_from_body(&self.routes, path)
    }
}

fn parse_patterns(raw: &[String]) -> Option<Vec<PathPattern>> {
    raw.iter()
        .map(|pattern| PathPattern::parse(pattern))
        .collect()
}

/// Validates each route, then refuses any two that overlap: a request must
/// belong to one route, and a logical path to one interface.
fn parse_routes(raw: &[RouteDto]) -> Result<Vec<Route>, ConfigError> {
    if raw.len() > ROUTES_MAX {
        return Err(ConfigError::Routes);
    }
    let routes = raw
        .iter()
        .map(|route| Route::parse(&route.path, &route.name_from).ok_or(ConfigError::Routes))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, first) in routes.iter().enumerate() {
        if routes[index + 1..]
            .iter()
            .any(|second| overlaps(first, second))
        {
            return Err(ConfigError::Routes);
        }
    }
    Ok(routes)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= HOST_MAX
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..")
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

fn valid_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= CREDENTIAL_NAME_MAX
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn valid_origin(origin: &str) -> bool {
    let Some(rest) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };
    let (host, port) = rest
        .rsplit_once(':')
        .map_or((rest, None), |(host, port)| (host, Some(port)));
    valid_host(host)
        && port.is_none_or(|port| {
            !port.is_empty() && port.len() <= 5 && port.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::super::objects::ObjectsReason;
    use super::*;

    const MINIMAL: &str = r#"{
        "name": "emr",
        "hosts": ["EMR.example.com"],
        "origin": "http://10.0.0.5:8080",
        "session": {"cookie": "SESSIONID"},
        "entries": ["/login", "/api/home", "/share/*"]
    }"#;

    #[test]
    fn minimal_site_gets_safe_defaults() {
        let site = SiteSpec::from_json(MINIMAL).unwrap();
        assert_eq!(site.mode(), Mode::Observe);
        assert_eq!(site.on_jev_unavailable(), OnJevUnavailable::Deny);
        assert_eq!(site.hosts(), ["emr.example.com"]);
        assert!(!site.is_bypass("/static/app.js"));
    }

    #[test]
    fn entries_match_exact_or_prefix() {
        let site = SiteSpec::from_json(MINIMAL).unwrap();
        assert!(site.is_entry("/login"));
        assert!(!site.is_entry("/login/extra"));
        assert!(site.is_entry("/share/abc123"));
        assert!(!site.is_entry("/api/patients/8"));
    }

    #[test]
    fn ambiguous_spellings_never_match_a_pattern() {
        let site = SiteSpec::from_json(MINIMAL).unwrap();
        for path in [
            "/share/../api/patients/8",
            "/share//x",
            "/share/%2e%2e/api",
            "/share/%2F",
            "/share/a\\b",
            "/share/a\u{0}b",
            "share/x",
        ] {
            assert!(!site.is_entry(path), "{path:?}");
        }
    }

    #[test]
    fn bypass_is_prefix_matched_and_defaults_empty() {
        let text = MINIMAL.replace(
            "\"entries\"",
            "\"bypass\": [\"/static/*\", \"/favicon.ico\"], \"entries\"",
        );
        let site = SiteSpec::from_json(&text).unwrap();
        assert!(site.is_bypass("/static/app.js"));
        assert!(site.is_bypass("/favicon.ico"));
        assert!(!site.is_bypass("/static/../api/patients"));
        // Servlet containers resolve `..;/` and `;x/..` as dot segments.
        assert!(!site.is_bypass("/static/..;/api/patients"));
        assert!(!site.is_bypass("/static/;x/../api/patients"));
    }

    #[test]
    fn modes_parse() {
        let text = MINIMAL.replace(
            "\"entries\"",
            "\"mode\": \"enforce\", \"on_jev_unavailable\": \"allow\", \"entries\"",
        );
        let site = SiteSpec::from_json(&text).unwrap();
        assert_eq!(site.mode(), Mode::Enforce);
        assert_eq!(site.on_jev_unavailable(), OnJevUnavailable::Allow);
    }

    #[test]
    fn invalid_sections_are_rejected() {
        let cases = [
            (
                MINIMAL.replace("\"emr\"", "\"Bad Name\""),
                ConfigError::Name,
            ),
            (
                MINIMAL.replace("[\"EMR.example.com\"]", "[]"),
                ConfigError::Hosts,
            ),
            (
                MINIMAL.replace("EMR.example.com", "a..b"),
                ConfigError::Hosts,
            ),
            (
                MINIMAL.replace("http://10.0.0.5:8080", "http://user@host/x"),
                ConfigError::Origin,
            ),
            (MINIMAL.replace("http://", "ftp://"), ConfigError::Origin),
            (
                MINIMAL.replace("SESSIONID", "bad name"),
                ConfigError::Session,
            ),
            (
                MINIMAL.replace("[\"/login\", \"/api/home\", \"/share/*\"]", "[]"),
                ConfigError::Entries,
            ),
            (
                MINIMAL.replace("\"/login\"", "\"login\""),
                ConfigError::Entries,
            ),
            (
                MINIMAL.replace("\"/login\"", "\"/lo*gin\""),
                ConfigError::Entries,
            ),
            (
                MINIMAL.replace("\"name\"", "\"extra\": 1, \"name\""),
                ConfigError::Malformed,
            ),
            ("not json".to_owned(), ConfigError::Malformed),
        ];
        for (text, expected) in cases {
            assert_eq!(SiteSpec::from_json(&text).unwrap_err(), expected, "{text}");
        }
    }

    #[test]
    fn site_round_trips_through_json() {
        let site = SiteSpec::from_json(MINIMAL).unwrap();
        let text = serde_json::to_string(&site).unwrap();
        // The stored form is the struct's own layout and must re-validate.
        let again: SiteSpec = serde_json::from_str(&text).unwrap();
        assert_eq!(site, again);
    }

    #[test]
    fn the_object_map_is_validated_as_its_own_section() {
        let with = |objects: &str| {
            MINIMAL.replace(
                "\"entries\"",
                &format!("\"objects\": {objects}, \"entries\""),
            )
        };
        let text = with(
            r#"{"classes":[{"id":"doctor","name":"医生"}],
                "slots":[{"key":"GET /doctor/{id} path[1]","class":"doctor","source":"admin"}]}"#,
        );
        let site = SiteSpec::from_json(&text).unwrap();
        assert_eq!(
            site.objects().class_of("GET /doctor/{id} path[1]"),
            Some("doctor")
        );
        let again: SiteSpec = serde_json::from_str(&serde_json::to_string(&site).unwrap()).unwrap();
        assert_eq!(again.objects(), site.objects());
        // A position of an undeclared kind, a repeated position, and a section
        // that is not an object are each refused as the objects section, and the
        // refusal names the part that is wrong.
        let refused = [
            (
                r#"{"classes":[],"slots":[{"key":"GET /d path[1]","class":"doctor","source":"admin"}]}"#,
                ObjectsPlace::Slot(0),
                Some(ObjectsReason::ClassUnknown),
            ),
            (
                r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
                {"key":"GET /d path[1]","class":"doctor","source":"admin"},
                {"key":"GET /d path[1]","class":"doctor","source":"rule"}]}"#,
                ObjectsPlace::Slot(1),
                Some(ObjectsReason::DuplicateKey),
            ),
            ("[]", ObjectsPlace::Section, None),
        ];
        for (objects, place, reason) in refused {
            assert_eq!(
                SiteSpec::from_json(&with(objects)).unwrap_err(),
                ConfigError::Objects(ObjectsIssue { place, reason }),
                "{objects}"
            );
        }
    }

    #[test]
    fn the_functions_are_read_in_the_objects_section() {
        let with = |objects: &str| {
            MINIMAL.replace(
                "\"entries\"",
                &format!("\"objects\": {objects}, \"entries\""),
            )
        };
        let site = SiteSpec::from_json(&with(
            r#"{"functions":[
                {"key":"POST /api/admin/export","source":"rule","tier":"admin","reliability":"high"},
                {"key":"GET /api/patients/{id}","source":"admin"}]}"#,
        ))
        .unwrap();
        assert_eq!(site.objects().functions().len(), 2);
        assert!(site.objects().admin_only("POST", "/api/admin/export"));
        let again: SiteSpec = serde_json::from_str(&serde_json::to_string(&site).unwrap()).unwrap();
        assert_eq!(again.objects(), site.objects());
        // An entry with a field it does not know is refused as the objects section.
        assert_eq!(
            SiteSpec::from_json(&with(
                r#"{"functions":[{"key":"GET /a","source":"admin","paused":true}]}"#
            ))
            .unwrap_err(),
            ConfigError::Objects(ObjectsIssue {
                place: ObjectsPlace::Section,
                reason: None,
            }),
        );
        // A refused entry names itself and the reason.
        assert_eq!(
            SiteSpec::from_json(&with(
                r#"{"functions":[{"key":"get /a","source":"admin"}]}"#
            ))
            .unwrap_err(),
            ConfigError::Objects(ObjectsIssue {
                place: ObjectsPlace::Function(0),
                reason: Some(ObjectsReason::KeyInvalid),
            }),
        );
    }

    #[test]
    fn routes_are_optional_validated_and_round_trip() {
        let plain = SiteSpec::from_json(MINIMAL).unwrap();
        assert!(plain.routes().is_empty());
        assert!(!serde_json::to_string(&plain).unwrap().contains("routes"));

        let text = MINIMAL.replace(
            "\"entries\"",
            "\"routes\": [{\"path\": \"/gw\", \"name_from\": [[\"header.X-Service-Id\"], [\"query.action\", \"body.action\"]]}], \"entries\"",
        );
        let site = SiteSpec::from_json(&text).unwrap();
        assert_eq!(site.routes().len(), 1);
        let again: SiteSpec = serde_json::from_str(&serde_json::to_string(&site).unwrap()).unwrap();
        assert_eq!(site, again);

        let overlapping = MINIMAL.replace(
            "\"entries\"",
            "\"routes\": [{\"path\": \"/gw\", \"name_from\": [[\"header.X\"]]}, {\"path\": \"/gw/x\", \"name_from\": [[\"header.X\"]]}], \"entries\"",
        );
        assert_eq!(
            SiteSpec::from_json(&overlapping).unwrap_err(),
            ConfigError::Routes
        );
        let path_is_no_source = MINIMAL.replace(
            "\"entries\"",
            "\"routes\": [{\"path\": \"/gw\", \"name_from\": [[\"path.1\"]]}], \"entries\"",
        );
        assert_eq!(
            SiteSpec::from_json(&path_is_no_source).unwrap_err(),
            ConfigError::Routes
        );
        let unknown_field = MINIMAL.replace(
            "\"entries\"",
            "\"routes\": [{\"path\": \"/gw\", \"name_from\": [[\"header.X\"]], \"x\": 1}], \"entries\"",
        );
        assert_eq!(
            SiteSpec::from_json(&unknown_field).unwrap_err(),
            ConfigError::Malformed
        );
    }
}
