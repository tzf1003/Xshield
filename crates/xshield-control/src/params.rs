//! Query parameters, time windows and page cursors of the control API
//! (docs/07-console-architecture.md sections 7.9.1 and 7.9.3).

use std::collections::BTreeMap;

use axum::http::{HeaderMap, StatusCode, header};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::de::DeserializeOwned;

use crate::error::{ApiError, ApiResult};

/// Parses a JSON request body. The body must be sent as `application/json`,
/// otherwise it is refused with 415; a body that does not parse as `T` gets
/// `INVALID_BODY`.
///
/// # Errors
/// `UNSUPPORTED_MEDIA_TYPE` (415) or `INVALID_BODY` (400).
pub fn json_body<T: DeserializeOwned>(headers: &HeaderMap, body: &[u8]) -> ApiResult<T> {
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !media_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
        ));
    }
    serde_json::from_slice(body).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "INVALID_BODY"))
}

/// One day in milliseconds.
pub const DAY_MILLIS: i64 = 86_400_000;
/// The longest window a list or a statistic may cover.
pub const MAX_WINDOW_MILLIS: i64 = 7 * DAY_MILLIS;
/// The window a request gets when it names no bounds: the last 24 hours.
pub const DEFAULT_WINDOW_MILLIS: i64 = DAY_MILLIS;

/// Unix time now, in milliseconds.
#[must_use]
pub fn now_millis() -> i64 {
    Utc::now().timestamp_millis()
}

/// An RFC 3339 UTC time with millisecond precision, or `None` when the value
/// is outside the range a timestamp can hold.
#[must_use]
pub fn rfc3339(millis: i64) -> Option<String> {
    DateTime::from_timestamp_millis(millis)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// A half-open-free time window: both bounds are inclusive, as the store reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// The earliest time in the window, Unix milliseconds.
    pub since_millis: i64,
    /// The latest time in the window, Unix milliseconds.
    pub until_millis: i64,
}

/// The raw query parameters of one request.
#[derive(Debug, Default)]
pub struct Params(BTreeMap<String, String>);

impl From<BTreeMap<String, String>> for Params {
    fn from(map: BTreeMap<String, String>) -> Self {
        Self(map)
    }
}

impl Params {
    /// The value of a parameter when it is present and not empty.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    /// An integer parameter.
    ///
    /// # Errors
    /// `INVALID_FILTER` naming the parameter when it is not an integer.
    pub fn int(&self, name: &str) -> ApiResult<Option<i64>> {
        self.text(name)
            .map(|raw| {
                raw.parse::<i64>()
                    .map_err(|_| ApiError::invalid_filter(name))
            })
            .transpose()
    }

    /// A comma-separated list in which every item is one of `allowed`.
    ///
    /// # Errors
    /// `INVALID_FILTER` naming the parameter when an item is not allowed.
    pub fn list(&self, name: &str, allowed: &[&str]) -> ApiResult<Vec<String>> {
        let Some(raw) = self.text(name) else {
            return Ok(Vec::new());
        };
        raw.split(',')
            .map(|item| {
                if allowed.contains(&item) {
                    Ok(item.to_owned())
                } else {
                    Err(ApiError::invalid_filter(name))
                }
            })
            .collect()
    }

    /// A `true` or `false` parameter.
    ///
    /// # Errors
    /// `INVALID_FILTER` naming the parameter for any other value.
    pub fn flag(&self, name: &str) -> ApiResult<Option<bool>> {
        match self.text(name) {
            None => Ok(None),
            Some("true") => Ok(Some(true)),
            Some("false") => Ok(Some(false)),
            Some(_) => Err(ApiError::invalid_filter(name)),
        }
    }

    /// The page size: `limit` when given, `default` otherwise.
    ///
    /// # Errors
    /// `INVALID_FILTER` for a limit outside `1..=max`.
    pub fn limit(&self, default: i64, max: i64) -> ApiResult<i64> {
        match self.int("limit")? {
            None => Ok(default),
            Some(limit) if (1..=max).contains(&limit) => Ok(limit),
            Some(_) => Err(ApiError::invalid_filter("limit")),
        }
    }

    /// The window named by `since_millis` and `until_millis`. Without bounds it
    /// is the 24 hours up to `now`; without a start it is 24 hours before the end.
    ///
    /// # Errors
    /// `INVALID_FILTER` when the window is empty, `WINDOW_TOO_LARGE` when it is
    /// longer than seven days.
    pub fn window(&self, now: i64) -> ApiResult<Window> {
        let until = self.int("until_millis")?.unwrap_or(now);
        let since = self
            .int("since_millis")?
            .unwrap_or_else(|| until.saturating_sub(DEFAULT_WINDOW_MILLIS));
        if since >= until {
            return Err(ApiError::invalid_filter("since_millis"));
        }
        if until.saturating_sub(since) > MAX_WINDOW_MILLIS {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "WINDOW_TOO_LARGE"));
        }
        Ok(Window {
            since_millis: since,
            until_millis: until,
        })
    }

    /// A keyset cursor `<at_millis>.<id>` from a previous page.
    ///
    /// # Errors
    /// `INVALID_FILTER` naming the parameter when the cursor is malformed.
    pub fn cursor(&self, name: &str) -> ApiResult<Option<(i64, i64)>> {
        self.text(name)
            .map(|raw| parse_cursor(raw).ok_or_else(|| ApiError::invalid_filter(name)))
            .transpose()
    }
}

/// Formats a keyset cursor for the next page.
#[must_use]
pub fn format_cursor(at_millis: i64, id: i64) -> String {
    format!("{at_millis}.{id}")
}

/// Reads a keyset cursor written by [`format_cursor`].
#[must_use]
pub fn parse_cursor(raw: &str) -> Option<(i64, i64)> {
    let (at, id) = raw.split_once('.')?;
    Some((at.parse().ok()?, id.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> Params {
        Params::from(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    #[test]
    fn an_empty_window_defaults_to_the_last_day() {
        let window = params(&[]).window(10 * DAY_MILLIS).expect("default window");
        assert_eq!(window.until_millis, 10 * DAY_MILLIS);
        assert_eq!(window.since_millis, 9 * DAY_MILLIS);
    }

    #[test]
    fn a_window_longer_than_seven_days_is_refused_by_name() {
        let error = params(&[("since_millis", "0"), ("until_millis", "900000000")])
            .window(900_000_000)
            .expect_err("too long");
        assert_eq!(error.code(), "WINDOW_TOO_LARGE");
    }

    #[test]
    fn an_empty_or_reversed_window_names_its_bound() {
        let error = params(&[("since_millis", "5"), ("until_millis", "5")])
            .window(100)
            .expect_err("empty");
        assert_eq!(error.code(), "INVALID_FILTER");
    }

    #[test]
    fn cursors_round_trip_and_reject_garbage() {
        assert_eq!(
            parse_cursor(&format_cursor(1_793_538_986_100, 91_234)),
            Some((1_793_538_986_100, 91_234))
        );
        assert_eq!(parse_cursor("12"), None);
        assert_eq!(parse_cursor("a.b"), None);
    }

    #[test]
    fn lists_accept_only_the_allowed_items() {
        let parsed = params(&[("outcome", "blocked,would_block")])
            .list("outcome", &["blocked", "would_block", "allowed"])
            .expect("allowed items");
        assert_eq!(parsed, vec!["blocked".to_owned(), "would_block".to_owned()]);
        assert!(
            params(&[("outcome", "blocked,nope")])
                .list("outcome", &["blocked"])
                .is_err()
        );
    }

    #[test]
    fn limits_stay_within_their_maximum() {
        assert_eq!(params(&[]).limit(100, 500).expect("default"), 100);
        assert_eq!(
            params(&[("limit", "500")]).limit(100, 500).expect("max"),
            500
        );
        assert!(params(&[("limit", "501")]).limit(100, 500).is_err());
        assert!(params(&[("limit", "0")]).limit(100, 500).is_err());
    }

    #[test]
    fn flags_are_true_or_false_only() {
        assert_eq!(
            params(&[("entry", "true")]).flag("entry").expect("true"),
            Some(true)
        );
        assert_eq!(params(&[]).flag("entry").expect("absent"), None);
        assert!(params(&[("entry", "yes")]).flag("entry").is_err());
    }
}
