//! Site level judging parameters, the optional `advanced` section of a site
//! (docs/07 section 7.6).
//!
//! Every item may be left out and then takes the gateway's code default, so a
//! site without an `advanced` section judges exactly as before. Validation
//! happens when the site is parsed; the stored form is normalized (words
//! lower-cased, sorted and deduplicated) so that reordering words alone never
//! makes a new configuration version.

use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::config::{ConfigError, PathPattern};
use crate::kind::{GENERIC_WORDS, same_field};

/// Allowed `jev_timeout_ms`.
pub const JEV_TIMEOUT_MS: RangeInclusive<u32> = 100..=30_000;
/// Allowed `session_calls_per_minute`.
pub const SESSION_CALLS_PER_MINUTE: RangeInclusive<u32> = 1..=600;
/// Allowed `address_calls_per_minute`.
pub const ADDRESS_CALLS_PER_MINUTE: RangeInclusive<u32> = 1..=600;
/// Allowed `allow_cache_minutes`; 0 switches the cache off.
pub const ALLOW_CACHE_MINUTES: RangeInclusive<u32> = 0..=60;
/// Most `secret_fields` words.
pub const SECRET_FIELDS_MAX: usize = 32;
/// Allowed length of a `secret_fields` word, in characters.
pub const SECRET_WORD_LEN: RangeInclusive<usize> = 3..=32;
/// Most `synonyms` groups.
pub const SYNONYMS_MAX: usize = 32;
/// Allowed length of a synonym word, in characters.
pub const SYNONYM_WORD_LEN: RangeInclusive<usize> = 3..=24;
/// Most `field_kinds` declarations.
pub const FIELD_KINDS_MAX: usize = 32;
/// Allowed length of a declared field name, in characters.
pub const FIELD_NAME_LEN: RangeInclusive<usize> = 1..=32;
/// Allowed length of a declared kind, in characters, once a trailing `s` is removed.
pub const KIND_LEN: RangeInclusive<usize> = 3..=24;
/// Most path patterns one declaration may be limited to.
pub const FIELD_KIND_SCOPE_MAX: usize = 8;

/// Validated, normalized site level judging parameters.
///
/// The default value is the empty section: nothing overridden.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Advanced {
    #[serde(skip_serializing_if = "Option::is_none")]
    jev_timeout_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_calls_per_minute: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_calls_per_minute: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_cache_minutes: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    secret_fields: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    synonyms: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    field_kinds: Vec<FieldKind>,
}

/// A declared kind: the kind of object a field or parameter name carries. It
/// overrides the kind the name suggests, for that name only, and holds only in
/// the paths it is limited to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldKind {
    field: String,
    kind: String,
    #[serde(rename = "in", skip_serializing_if = "Vec::is_empty")]
    scope: Vec<PathPattern>,
}

impl FieldKind {
    /// The field or parameter name, lower case as written.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The kind of object the field carries, reduced as `kind_words` reduces words.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The paths the declaration is limited to; empty for every path.
    #[must_use]
    pub fn scope(&self) -> &[PathPattern] {
        &self.scope
    }
}

/// The section as written. Numbers are read wide so that a negative or huge
/// number is a value error of this section, not a malformed document.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdvancedDto {
    #[serde(default)]
    jev_timeout_ms: Option<i64>,
    #[serde(default)]
    session_calls_per_minute: Option<i64>,
    #[serde(default)]
    address_calls_per_minute: Option<i64>,
    #[serde(default)]
    allow_cache_minutes: Option<i64>,
    #[serde(default)]
    secret_fields: Vec<String>,
    #[serde(default)]
    synonyms: Vec<Vec<String>>,
    /// Each declaration is read as a JSON object: a serde struct would also take
    /// an array, so the keys are checked by hand in `declaration`.
    #[serde(default)]
    field_kinds: Vec<Map<String, Value>>,
}

impl TryFrom<AdvancedDto> for Advanced {
    type Error = ConfigError;

    fn try_from(dto: AdvancedDto) -> Result<Self, ConfigError> {
        Ok(Self {
            jev_timeout_ms: ranged(dto.jev_timeout_ms, &JEV_TIMEOUT_MS)?,
            session_calls_per_minute: ranged(
                dto.session_calls_per_minute,
                &SESSION_CALLS_PER_MINUTE,
            )?,
            address_calls_per_minute: ranged(
                dto.address_calls_per_minute,
                &ADDRESS_CALLS_PER_MINUTE,
            )?,
            allow_cache_minutes: ranged(dto.allow_cache_minutes, &ALLOW_CACHE_MINUTES)?,
            secret_fields: secret_fields(&dto.secret_fields)?,
            synonyms: synonyms(&dto.synonyms)?,
            field_kinds: field_kinds(&dto.field_kinds)?,
        })
    }
}

fn ranged(value: Option<i64>, range: &RangeInclusive<u32>) -> Result<Option<u32>, ConfigError> {
    value
        .map(|number| {
            u32::try_from(number)
                .ok()
                .filter(|number| range.contains(number))
                .ok_or(ConfigError::Advanced)
        })
        .transpose()
}

fn secret_fields(raw: &[String]) -> Result<Vec<String>, ConfigError> {
    if raw.len() > SECRET_FIELDS_MAX {
        return Err(ConfigError::Advanced);
    }
    let mut words = raw
        .iter()
        .map(|word| {
            let word = word.to_ascii_lowercase();
            let valid = SECRET_WORD_LEN.contains(&word.len())
                && word.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte)
                });
            valid.then_some(word).ok_or(ConfigError::Advanced)
        })
        .collect::<Result<Vec<_>, _>>()?;
    words.sort_unstable();
    words.dedup();
    Ok(words)
}

fn synonyms(raw: &[Vec<String>]) -> Result<Vec<(String, String)>, ConfigError> {
    if raw.len() > SYNONYMS_MAX {
        return Err(ConfigError::Advanced);
    }
    let mut pairs = raw
        .iter()
        .map(|group| {
            let [first, second] = group.as_slice() else {
                return Err(ConfigError::Advanced);
            };
            let (first, second) = (first.to_ascii_lowercase(), second.to_ascii_lowercase());
            let valid = first != second
                && [&first, &second].iter().all(|word| {
                    SYNONYM_WORD_LEN.contains(&word.len())
                        && word.bytes().all(|byte| byte.is_ascii_lowercase())
                });
            if !valid {
                return Err(ConfigError::Advanced);
            }
            Ok(if first <= second {
                (first, second)
            } else {
                (second, first)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    pairs.sort_unstable();
    pairs.dedup();
    Ok(pairs)
}

/// One declaration's `field`, `kind` and `in` as written. A missing or differently
/// shaped item is a malformed document; a bad value is checked afterwards.
fn declaration(
    item: &Map<String, Value>,
) -> Result<(String, String, Option<Vec<String>>), ConfigError> {
    if item
        .keys()
        .any(|key| !matches!(key.as_str(), "field" | "kind" | "in"))
    {
        return Err(ConfigError::Malformed);
    }
    let text = |key: &str| match item.get(key) {
        Some(Value::String(text)) => Ok(text.clone()),
        _ => Err(ConfigError::Malformed),
    };
    let scope = match item.get("in") {
        None | Some(Value::Null) => None,
        Some(Value::Array(patterns)) => Some(
            patterns
                .iter()
                .map(|pattern| match pattern {
                    Value::String(pattern) => Ok(pattern.clone()),
                    _ => Err(ConfigError::Malformed),
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => return Err(ConfigError::Malformed),
    };
    Ok((text("field")?, text("kind")?, scope))
}

fn field_kinds(raw: &[Map<String, Value>]) -> Result<Vec<FieldKind>, ConfigError> {
    if raw.len() > FIELD_KINDS_MAX {
        return Err(ConfigError::Advanced);
    }
    let mut declared = raw
        .iter()
        .map(declaration)
        .map(|item| {
            let (field, kind, scope) = item?;
            let field = field.to_ascii_lowercase();
            let valid_field = FIELD_NAME_LEN.contains(&field.len())
                && field.bytes().any(|byte| byte.is_ascii_alphanumeric())
                && field.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte)
                });
            // The kind is stored as the kind words reduce it, so it is checked after that.
            let written = kind.to_ascii_lowercase();
            let kind = written.trim_end_matches('s').to_owned();
            let valid_kind = (3..=24).contains(&written.len())
                && written.bytes().all(|byte| byte.is_ascii_lowercase())
                && KIND_LEN.contains(&kind.len())
                && !GENERIC_WORDS.contains(&kind.as_str());
            if !valid_field || !valid_kind {
                return Err(ConfigError::Advanced);
            }
            let scope = match scope {
                None => Vec::new(),
                Some(patterns) => {
                    if patterns.is_empty() || patterns.len() > FIELD_KIND_SCOPE_MAX {
                        return Err(ConfigError::Advanced);
                    }
                    let mut scope = patterns
                        .iter()
                        .map(|pattern| PathPattern::parse(pattern).ok_or(ConfigError::Advanced))
                        .collect::<Result<Vec<_>, _>>()?;
                    scope.sort_by(|left, right| left.as_str().cmp(right.as_str()));
                    scope.dedup();
                    scope
                }
            };
            Ok(FieldKind { field, kind, scope })
        })
        .collect::<Result<Vec<_>, _>>()?;
    // One name may carry two kinds only where their paths do not overlap.
    for (index, first) in declared.iter().enumerate() {
        let clash = declared[index + 1..].iter().any(|second| {
            same_field(&first.field, &second.field)
                && first.kind != second.kind
                && scopes_overlap(&first.scope, &second.scope)
        });
        if clash {
            return Err(ConfigError::Advanced);
        }
    }
    declared.sort_by(|left, right| {
        (left.field.as_str(), left.kind.as_str(), scope_text(left)).cmp(&(
            right.field.as_str(),
            right.kind.as_str(),
            scope_text(right),
        ))
    });
    declared.dedup();
    Ok(declared)
}

fn scope_text(declared: &FieldKind) -> Vec<&str> {
    declared.scope.iter().map(PathPattern::as_str).collect()
}

/// Whether some path both scopes cover. An empty scope covers every path.
fn scopes_overlap(left: &[PathPattern], right: &[PathPattern]) -> bool {
    left.is_empty()
        || right.is_empty()
        || left
            .iter()
            .any(|first| right.iter().any(|second| patterns_overlap(first, second)))
}

/// Whether some path both patterns cover: two prefixes overlap when one extends
/// the other, a prefix and an exact path when the path starts with the prefix.
fn patterns_overlap(left: &PathPattern, right: &PathPattern) -> bool {
    let (first, first_prefix) = split_pattern(left.as_str());
    let (second, second_prefix) = split_pattern(right.as_str());
    match (first_prefix, second_prefix) {
        (true, true) => first.starts_with(second) || second.starts_with(first),
        (true, false) => second.starts_with(first),
        (false, true) => first.starts_with(second),
        (false, false) => first == second,
    }
}

fn split_pattern(pattern: &str) -> (&str, bool) {
    match pattern.strip_suffix('*') {
        Some(prefix) => (prefix, true),
        None => (pattern, false),
    }
}

impl Advanced {
    /// Whether nothing is overridden.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// The configured Jev timeout in milliseconds, if the site sets one.
    #[must_use]
    pub fn jev_timeout_ms(&self) -> Option<u32> {
        self.jev_timeout_ms
    }

    /// The configured per session Jev calls per minute, if any.
    #[must_use]
    pub fn session_calls_per_minute(&self) -> Option<u32> {
        self.session_calls_per_minute
    }

    /// The configured per address Jev calls per minute, if any.
    #[must_use]
    pub fn address_calls_per_minute(&self) -> Option<u32> {
        self.address_calls_per_minute
    }

    /// The configured allow cache time in minutes (0 is off), if any.
    #[must_use]
    pub fn allow_cache_minutes(&self) -> Option<u32> {
        self.allow_cache_minutes
    }

    /// Extra redaction words: lower case, sorted, unique. The built-in words
    /// stay in force whatever this holds.
    #[must_use]
    pub fn secret_fields(&self) -> &[String] {
        &self.secret_fields
    }

    /// Extra synonym pairs, each pair and the list sorted, unique.
    #[must_use]
    pub fn synonyms(&self) -> &[(String, String)] {
        &self.synonyms
    }

    /// Declared field kinds, sorted, unique.
    #[must_use]
    pub fn field_kinds(&self) -> &[FieldKind] {
        &self.field_kinds
    }

    /// The Jev timeout in effect: the site's value, else `default`.
    #[must_use]
    pub fn jev_timeout_ms_or(&self, default: u32) -> u32 {
        self.jev_timeout_ms.unwrap_or(default)
    }

    /// Jev calls per minute allowed for one session: the site's value, else `default`.
    #[must_use]
    pub fn session_calls_per_minute_or(&self, default: u32) -> u32 {
        self.session_calls_per_minute.unwrap_or(default)
    }

    /// Jev calls per minute allowed for one client address: the site's value, else `default`.
    #[must_use]
    pub fn address_calls_per_minute_or(&self, default: u32) -> u32 {
        self.address_calls_per_minute.unwrap_or(default)
    }

    /// Minutes a Jev allow is reused: the site's value, else `default`.
    #[must_use]
    pub fn allow_cache_minutes_or(&self, default: u32) -> u32 {
        self.allow_cache_minutes.unwrap_or(default)
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::SiteSpec;
    use super::*;

    fn site(advanced: &str) -> String {
        format!(
            r#"{{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{{"cookie":"SID"}},
               "entries":["/login"],"advanced":{advanced}}}"#
        )
    }

    fn parse(advanced: &str) -> Result<Advanced, ConfigError> {
        SiteSpec::from_json(&site(advanced)).map(|site| site.advanced().clone())
    }

    #[test]
    fn a_site_without_the_section_overrides_nothing() {
        let text = r#"{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{"cookie":"SID"},"entries":["/login"]}"#;
        let spec = SiteSpec::from_json(text).unwrap();
        assert!(spec.advanced().is_empty());
        assert_eq!(spec.advanced().jev_timeout_ms_or(2000), 2000);
        assert_eq!(spec.advanced().session_calls_per_minute_or(60), 60);
        assert_eq!(spec.advanced().address_calls_per_minute_or(30), 30);
        assert_eq!(spec.advanced().allow_cache_minutes_or(10), 10);
        // The stored form is unchanged for such a site: no `advanced` key.
        let stored = serde_json::to_value(&spec).unwrap();
        assert!(stored.get("advanced").is_none(), "{stored}");
        assert!(parse("{}").unwrap().is_empty());
        assert!(parse("null").is_ok(), "null reads as an absent section");
    }

    #[test]
    fn the_documented_example_parses() {
        let advanced = parse(
            r#"{"jev_timeout_ms":3000,"session_calls_per_minute":60,"address_calls_per_minute":30,
                "allow_cache_minutes":10,"secret_fields":["ssn","idcard"],"synonyms":[["payment","card"]]}"#,
        )
        .unwrap();
        assert_eq!(advanced.jev_timeout_ms(), Some(3000));
        assert_eq!(advanced.jev_timeout_ms_or(2000), 3000);
        assert_eq!(advanced.session_calls_per_minute(), Some(60));
        assert_eq!(advanced.address_calls_per_minute(), Some(30));
        assert_eq!(advanced.allow_cache_minutes(), Some(10));
        assert_eq!(advanced.secret_fields(), ["idcard", "ssn"]);
        assert_eq!(
            advanced.synonyms(),
            [("card".to_owned(), "payment".to_owned())]
        );
        assert!(!advanced.is_empty());
    }

    #[test]
    fn items_may_be_left_out_one_by_one() {
        let advanced = parse(r#"{"allow_cache_minutes":0}"#).unwrap();
        assert_eq!(advanced.allow_cache_minutes(), Some(0));
        assert_eq!(
            advanced.allow_cache_minutes_or(10),
            0,
            "zero is a value, not absent"
        );
        assert_eq!(advanced.jev_timeout_ms(), None);
        assert!(advanced.secret_fields().is_empty());
        let nulls = parse(r#"{"jev_timeout_ms":null,"secret_fields":[]}"#).unwrap();
        assert!(nulls.is_empty());
    }

    #[test]
    fn range_edges_are_inclusive() {
        for (item, low, high) in [
            ("jev_timeout_ms", 100, 30_000),
            ("session_calls_per_minute", 1, 600),
            ("address_calls_per_minute", 1, 600),
            ("allow_cache_minutes", 0, 60),
        ] {
            for ok in [low, high] {
                assert!(
                    parse(&format!(r#"{{"{item}":{ok}}}"#)).is_ok(),
                    "{item}={ok}"
                );
            }
            for bad in [i64::from(low) - 1, i64::from(high) + 1, -5, i64::MAX] {
                assert_eq!(
                    parse(&format!(r#"{{"{item}":{bad}}}"#)).unwrap_err(),
                    ConfigError::Advanced,
                    "{item}={bad}"
                );
            }
        }
    }

    #[test]
    fn words_are_normalized_so_that_order_never_makes_a_new_version() {
        let first = SiteSpec::from_json(&site(
            r#"{"secret_fields":["SSN","idcard","ssn","Bank_No"],"synonyms":[["Payment","card"],["card","payment"],["zebra","apple"]]}"#,
        ))
        .unwrap();
        let second = SiteSpec::from_json(&site(
            r#"{"secret_fields":["bank_no","idcard","ssn"],"synonyms":[["apple","zebra"],["payment","card"]]}"#,
        ))
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.advanced().secret_fields(),
            ["bank_no", "idcard", "ssn"]
        );
        assert_eq!(
            first.advanced().synonyms(),
            [
                ("apple".to_owned(), "zebra".to_owned()),
                ("card".to_owned(), "payment".to_owned())
            ]
        );
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }

    #[test]
    fn the_stored_form_parses_back_to_the_same_site() {
        let spec = SiteSpec::from_json(&site(
            r#"{"jev_timeout_ms":3000,"allow_cache_minutes":0,"secret_fields":["ssn"],"synonyms":[["payment","card"]]}"#,
        ))
        .unwrap();
        let stored = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            stored["advanced"],
            serde_json::json!({
                "jev_timeout_ms": 3000, "allow_cache_minutes": 0,
                "secret_fields": ["ssn"], "synonyms": [["card", "payment"]]
            })
        );
        assert_eq!(SiteSpec::from_value(&stored).unwrap(), spec);
        let text = serde_json::to_string(&spec).unwrap();
        assert_eq!(serde_json::from_str::<SiteSpec>(&text).unwrap(), spec);
    }

    #[test]
    fn invalid_words_are_rejected() {
        let long_secret = "a".repeat(33);
        let long_synonym = "a".repeat(25);
        let too_many_secrets = (0..33)
            .map(|index| format!("\"word{index}\""))
            .collect::<Vec<_>>()
            .join(",");
        let too_many_synonyms = (0..33)
            .map(|index| {
                let letter = char::from(b'a' + u8::try_from(index % 26).unwrap());
                format!("[\"left{letter}\",\"right{index}\"]")
            })
            .collect::<Vec<_>>()
            .join(",");
        let cases = [
            // Too short: this is what keeps `id` and `no` from hiding every id.
            r#"{"secret_fields":["id"]}"#.to_owned(),
            r#"{"secret_fields":["no"]}"#.to_owned(),
            format!(r#"{{"secret_fields":["{long_secret}"]}}"#),
            r#"{"secret_fields":["has space"]}"#.to_owned(),
            r#"{"secret_fields":["a.b.c"]}"#.to_owned(),
            r#"{"secret_fields":["passé"]}"#.to_owned(),
            r#"{"secret_fields":[""]}"#.to_owned(),
            format!(r#"{{"secret_fields":[{too_many_secrets}]}}"#),
            r#"{"synonyms":[["card"]]}"#.to_owned(),
            r#"{"synonyms":[["card","payment","wallet"]]}"#.to_owned(),
            r#"{"synonyms":[[]]}"#.to_owned(),
            r#"{"synonyms":[["card","card"]]}"#.to_owned(),
            r#"{"synonyms":[["Card","card"]]}"#.to_owned(),
            r#"{"synonyms":[["ab","card"]]}"#.to_owned(),
            r#"{"synonyms":[["card","pay2"]]}"#.to_owned(),
            r#"{"synonyms":[["card","pay_ment"]]}"#.to_owned(),
            format!(r#"{{"synonyms":[["card","{long_synonym}"]]}}"#),
            format!(r#"{{"synonyms":[{too_many_synonyms}]}}"#),
        ];
        for advanced in cases {
            assert_eq!(
                parse(&advanced).unwrap_err(),
                ConfigError::Advanced,
                "{advanced}"
            );
        }
        // The limits themselves are fine.
        let exact_secret = "a".repeat(32);
        let exact_synonym = "b".repeat(24);
        let at_limit = (0..32)
            .map(|index| format!("\"word{index}\""))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            parse(&format!(
                r#"{{"secret_fields":["{exact_secret}","abc","a_1","x-y"]}}"#
            ))
            .is_ok()
        );
        assert!(parse(&format!(r#"{{"secret_fields":[{at_limit}]}}"#)).is_ok());
        assert!(parse(&format!(r#"{{"synonyms":[["abc","{exact_synonym}"]]}}"#)).is_ok());
    }

    #[test]
    fn a_wrong_shape_is_malformed_not_an_advanced_error() {
        for advanced in [
            r#"{"unknown_item":1}"#,
            r#"{"jev_timeout_ms":"3000"}"#,
            r#"{"jev_timeout_ms":1.5}"#,
            r#"{"secret_fields":"ssn"}"#,
            r#"{"synonyms":["card","payment"]}"#,
            r"[1]",
            r#""yes""#,
        ] {
            assert_eq!(
                parse(advanced).unwrap_err(),
                ConfigError::Malformed,
                "{advanced}"
            );
        }
    }

    #[test]
    fn field_kinds_are_normalized_so_that_order_never_makes_a_new_version() {
        let first = SiteSpec::from_json(&site(
            r#"{"field_kinds":[{"field":"Doc_ID","kind":"Doctors","in":["/api/schedule","/api/appointments*"]},{"field":"visit","kind":"visit"}]}"#,
        ))
        .unwrap();
        let second = SiteSpec::from_json(&site(
            r#"{"field_kinds":[{"field":"visit","kind":"visit"},{"field":"doc_id","kind":"doctor","in":["/api/appointments*","/api/schedule"]}]}"#,
        ))
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        let declared = first.advanced().field_kinds();
        assert_eq!(declared[0].field(), "doc_id");
        assert_eq!(declared[0].kind(), "doctor");
        let scope: Vec<&str> = declared[0]
            .scope()
            .iter()
            .map(PathPattern::as_str)
            .collect();
        assert_eq!(scope, ["/api/appointments*", "/api/schedule"]);
        assert_eq!(declared[1].field(), "visit");
        assert!(declared[1].scope().is_empty());
    }

    #[test]
    fn field_kinds_store_and_read_back_the_same_site() {
        let spec = SiteSpec::from_json(&site(
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctors","in":["/api/appointments*"]},{"field":"visit","kind":"visit","in":null}]}"#,
        ))
        .unwrap();
        let stored = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            stored["advanced"]["field_kinds"],
            serde_json::json!([
                {"field": "doc_id", "kind": "doctor", "in": ["/api/appointments*"]},
                {"field": "visit", "kind": "visit"}
            ])
        );
        assert_eq!(SiteSpec::from_value(&stored).unwrap(), spec);
    }

    #[test]
    fn invalid_field_kinds_are_rejected() {
        let long_field = "a".repeat(33);
        let too_many = (0..33)
            .map(|index| format!(r#"{{"field":"f{index}","kind":"kind"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let cases = [
            r#"{"field_kinds":[{"field":"","kind":"doctor"}]}"#.to_owned(),
            format!(r#"{{"field_kinds":[{{"field":"{long_field}","kind":"doctor"}}]}}"#),
            r#"{"field_kinds":[{"field":"doc id","kind":"doctor"}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"_","kind":"doctor"}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc.id","kind":"doctor"}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"ab"}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"abs"}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor1"}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"Doc-tor"}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"api"}]}"#.to_owned(),
            format!(
                r#"{{"field_kinds":[{{"field":"doc_id","kind":"{}"}}]}}"#,
                "a".repeat(25)
            ),
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","in":[]}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","in":["api/appointments"]}]}"#
                .to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","in":["/api/a*b"]}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","in":["/api/x?y=1"]}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","in":["/a1","/a2","/a3","/a4","/a5","/a6","/a7","/a8","/a9"]}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor"},{"field":"doc_id","kind":"document"}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","in":["/api/*"]},{"field":"doc_id","kind":"document","in":["/api/records*"]}]}"#.to_owned(),
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor"},{"field":"DocID","kind":"document","in":["/api/records"]}]}"#.to_owned(),
            format!(r#"{{"field_kinds":[{too_many}]}}"#),
        ];
        for advanced in cases {
            assert_eq!(
                parse(&advanced).unwrap_err(),
                ConfigError::Advanced,
                "{advanced}"
            );
        }
        // Kinds that differ only after the trailing `s` is removed are one kind, and
        // declarations that name one field in disjoint paths are both allowed.
        for advanced in [
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor"},{"field":"doc_id","kind":"doctors"}]}"#,
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","in":["/api/appointments*"]},{"field":"doc_id","kind":"document","in":["/api/records*"]}]}"#,
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","in":["/api/a"]},{"field":"doc_id","kind":"document","in":["/api/a/b"]}]}"#,
            r#"{"field_kinds":[{"field":"a1","kind":"abc"}]}"#,
        ] {
            assert!(parse(advanced).is_ok(), "{advanced}");
        }
        let exact_field = "a".repeat(32);
        let exact_kind = "b".repeat(24);
        assert!(
            parse(&format!(
                r#"{{"field_kinds":[{{"field":"{exact_field}","kind":"{exact_kind}"}}]}}"#
            ))
            .is_ok()
        );
        let at_limit = (0..32)
            .map(|index| format!(r#"{{"field":"f{index}","kind":"kind"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse(&format!(r#"{{"field_kinds":[{at_limit}]}}"#)).is_ok());
    }

    #[test]
    fn a_wrong_field_kinds_shape_is_malformed() {
        for advanced in [
            r#"{"field_kinds":"doc_id"}"#,
            r#"{"field_kinds":[["doc_id","doctor"]]}"#,
            r#"{"field_kinds":[{"field":"doc_id"}]}"#,
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","in":"/api/x*"}]}"#,
            r#"{"field_kinds":[{"field":"doc_id","kind":"doctor","extra":1}]}"#,
        ] {
            assert_eq!(
                parse(advanced).unwrap_err(),
                ConfigError::Malformed,
                "{advanced}"
            );
        }
    }

    #[test]
    fn the_error_names_the_section_and_never_echoes_the_value() {
        let error = parse(r#"{"secret_fields":["no"],"jev_timeout_ms":50}"#).unwrap_err();
        assert_eq!(error.to_string(), "SITE_CONFIG_ADVANCED_INVALID");
    }

    #[test]
    fn other_sections_are_still_checked_first() {
        let text = r#"{"name":"Bad Name","hosts":["emr.test"],"origin":"http://o:1","session":{"cookie":"SID"},
                       "entries":["/login"],"advanced":{"jev_timeout_ms":1}}"#;
        assert_eq!(SiteSpec::from_json(text).unwrap_err(), ConfigError::Name);
    }
}
