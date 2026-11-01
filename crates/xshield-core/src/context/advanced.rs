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

use super::config::ConfigError;

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
