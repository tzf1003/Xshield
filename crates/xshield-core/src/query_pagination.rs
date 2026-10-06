//! Per-route query-string allowlist restricted to pagination-shaped
//! parameters (docs/05 §5.3.1, "发放响应资格的列表不接受查询串").
//!
//! A list that issues response-derived grants must not let the caller choose
//! whose objects it lists, so by default any query string on such a route is
//! refused. A route may opt in to a closed list of up to four parameters of
//! three kinds (`page`, `page_size`, `offset`). Values are plain base-10
//! digits with a hard range: there is no opaque or cursor kind, because an
//! opaque value can encode a selector (`customerId=B`) that the origin might
//! honor.
//!
//! The same [`SiteQueryPagination::validate`] runs in the control plane and
//! the edge compiler, and [`QueryPaginationRule::admit`] is the only function
//! that turns a client query string into something the edge forwards: the
//! forwarded query is rebuilt from the validated values in declared order and
//! never copied from the request.
//!
//! The module is pure: no I/O, no clock, no panics on any input.

use crate::domain::InvalidValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// [`InvalidValue`] field for a rejected `query_pagination` block.
pub const QUERY_PAGINATION_INVALID: &str = "site_policy.route.query_pagination";

/// Most parameters one route may declare.
pub const MAX_PAGINATION_PARAMETERS: usize = 4;
/// Longest parameter name.
pub const MAX_PARAMETER_NAME_BYTES: usize = 32;
/// Longest accepted client query string, in bytes. Four names of 32 bytes
/// with seven-digit values and separators fit with room to spare.
pub const MAX_PAGINATION_QUERY_BYTES: usize = 256;
/// Largest `page` value.
pub const MAX_PAGE: u32 = 10_000;
/// Largest `offset` value.
pub const MAX_OFFSET: u32 = 1_000_000;
/// Default largest `page_size` value.
pub const DEFAULT_MAX_PAGE_SIZE: u32 = 200;
/// Hard ceiling of a configured `page_size` bound.
pub const PAGE_SIZE_CEILING: u32 = 1_000;

/// What a pagination parameter selects. There is deliberately no cursor kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaginationKind {
    /// One-based page number, `1..=10000`.
    Page,
    /// Page length, `1..=max_value` (default 200, never above 1000).
    PageSize,
    /// Zero-based item offset, `0..=1000000`.
    Offset,
}

/// One declared pagination parameter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteQueryParameter {
    /// Query parameter name, `[a-z_]{1,32}`.
    pub name: String,
    /// What the value means, which fixes its range.
    pub kind: PaginationKind,
    /// Upper bound of a `page_size` value, 1–1000 (default 200). Absent and
    /// refused for the other kinds, whose bounds are fixed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value: Option<u32>,
}

/// The `query_pagination` route block.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteQueryPagination {
    /// The closed parameter list, 1–4 entries with unique names.
    pub parameters: Vec<SiteQueryParameter>,
}

impl SiteQueryParameter {
    fn is_valid(&self) -> bool {
        let name_ok = (1..=MAX_PARAMETER_NAME_BYTES).contains(&self.name.len())
            && self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
        let bound_ok = match (self.kind, self.max_value) {
            (PaginationKind::PageSize, Some(bound)) => (1..=PAGE_SIZE_CEILING).contains(&bound),
            (PaginationKind::PageSize, None) => true,
            (_, bound) => bound.is_none(),
        };
        name_ok && bound_ok
    }

    const fn upper_bound(&self) -> u32 {
        match (self.kind, self.max_value) {
            (PaginationKind::Page, _) => MAX_PAGE,
            (PaginationKind::Offset, _) => MAX_OFFSET,
            (PaginationKind::PageSize, Some(bound)) => bound,
            (PaginationKind::PageSize, None) => DEFAULT_MAX_PAGE_SIZE,
        }
    }

    const fn lower_bound(&self) -> u32 {
        match self.kind {
            PaginationKind::Offset => 0,
            PaginationKind::Page | PaginationKind::PageSize => 1,
        }
    }
}

impl SiteQueryPagination {
    /// Checks the rules the edge compiler applies to the same block.
    ///
    /// Collisions with resource-location parameters are cross-route and are
    /// checked by callers through [`Self::collides_with`].
    ///
    /// # Errors
    /// Returns [`InvalidValue`] named [`QUERY_PAGINATION_INVALID`].
    pub fn validate(&self) -> Result<(), InvalidValue> {
        let names = self
            .parameters
            .iter()
            .map(|parameter| parameter.name.as_str())
            .collect::<BTreeSet<_>>();
        if self.parameters.is_empty()
            || self.parameters.len() > MAX_PAGINATION_PARAMETERS
            || names.len() != self.parameters.len()
            || !self.parameters.iter().all(SiteQueryParameter::is_valid)
        {
            return Err(InvalidValue::new(QUERY_PAGINATION_INVALID));
        }
        Ok(())
    }

    /// Whether any declared name equals (ASCII case-insensitively, because an
    /// origin may fold case) one of `resource_parameters`.
    #[must_use]
    pub fn collides_with<'a>(
        &self,
        resource_parameters: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        let resource = resource_parameters
            .into_iter()
            .map(str::to_ascii_lowercase)
            .collect::<BTreeSet<_>>();
        self.parameters
            .iter()
            .any(|parameter| resource.contains(&parameter.name.to_ascii_lowercase()))
    }
}

/// Why a query string was refused. The edge audits every one of them as the
/// stable `FIELD_NOT_ALLOWED` reason; the variant exists for tests and local
/// diagnostics because the closed audit schema carries no sub-reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryDenial {
    /// The query is empty (`?` alone), longer than the cap, or has an empty
    /// pair (`&&`, leading or trailing `&`).
    Malformed,
    /// A percent escape, `+`, `;`, bracket, uppercase letter or any other byte
    /// that belongs to neither a declared-name alphabet nor the digits.
    Encoding,
    /// A name that is not declared.
    UnknownParameter,
    /// A declared name more than once.
    DuplicateParameter,
    /// A pair without `=`, with more than one `=`, or with an empty value.
    Shape,
    /// A value that is not plain digits, has a leading zero, or lies outside
    /// the declared range.
    Value,
}

/// A compiled `query_pagination` block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPaginationRule {
    parameters: Vec<SiteQueryParameter>,
}

impl QueryPaginationRule {
    /// Compiles a validated block.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] when [`SiteQueryPagination::validate`] fails.
    pub fn compile(block: &SiteQueryPagination) -> Result<Self, InvalidValue> {
        block.validate()?;
        Ok(Self {
            parameters: block.parameters.clone(),
        })
    }

    /// The declared parameter names, in declared order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.parameters
            .iter()
            .map(|parameter| parameter.name.as_str())
    }

    /// Validates the request's raw query (`None` when the target has no `?`)
    /// and returns the query to forward.
    ///
    /// `Ok(None)` means forward no query at all. The returned string is built
    /// from parsed integers in declared order, so it never contains a byte the
    /// client chose beyond the numeric values.
    ///
    /// # Errors
    /// Returns [`QueryDenial`] for anything that is not exactly a subset of
    /// the declared parameters, each at most once, with digit-only values in
    /// range.
    pub fn admit(&self, query: Option<&str>) -> Result<Option<String>, QueryDenial> {
        let Some(query) = query else {
            return Ok(None);
        };
        if query.is_empty() || query.len() > MAX_PAGINATION_QUERY_BYTES {
            return Err(QueryDenial::Malformed);
        }
        let mut values: Vec<Option<u32>> = vec![None; self.parameters.len()];
        for pair in query.split('&') {
            if pair.is_empty() {
                return Err(QueryDenial::Malformed);
            }
            // Any byte outside the name and digit alphabets is an encoding
            // trick or a different syntax (`%`, `+`, `;`, `[`, `#`, ...).
            if !pair.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'=')
            }) {
                return Err(QueryDenial::Encoding);
            }
            let (name, value) = pair.split_once('=').ok_or(QueryDenial::Shape)?;
            if value.is_empty() || value.contains('=') {
                return Err(QueryDenial::Shape);
            }
            let index = self
                .parameters
                .iter()
                .position(|parameter| parameter.name == name)
                .ok_or(QueryDenial::UnknownParameter)?;
            let slot = values.get_mut(index).ok_or(QueryDenial::UnknownParameter)?;
            if slot.is_some() {
                return Err(QueryDenial::DuplicateParameter);
            }
            *slot = Some(self.parameters[index].parse_value(value)?);
        }
        let canonical = self
            .parameters
            .iter()
            .zip(values)
            .filter_map(|(parameter, value)| Some(format!("{}={}", parameter.name, value?)))
            .collect::<Vec<_>>()
            .join("&");
        Ok(Some(canonical))
    }
}

impl SiteQueryParameter {
    fn parse_value(&self, value: &str) -> Result<u32, QueryDenial> {
        // At most seven digits cover the largest bound; a longer value is out
        // of range whatever it contains, and parsing it could overflow.
        if value.len() > 7
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(QueryDenial::Value);
        }
        let number = value.parse::<u32>().map_err(|_| QueryDenial::Value)?;
        if (self.lower_bound()..=self.upper_bound()).contains(&number) {
            Ok(number)
        } else {
            Err(QueryDenial::Value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameter(name: &str, kind: PaginationKind) -> SiteQueryParameter {
        SiteQueryParameter {
            name: name.to_owned(),
            kind,
            max_value: None,
        }
    }

    fn rule() -> QueryPaginationRule {
        QueryPaginationRule::compile(&SiteQueryPagination {
            parameters: vec![
                parameter("page", PaginationKind::Page),
                parameter("page_size", PaginationKind::PageSize),
                parameter("offset", PaginationKind::Offset),
            ],
        })
        .unwrap()
    }

    #[test]
    fn admits_subsets_and_rebuilds_in_declared_order() {
        let rule = rule();
        assert_eq!(rule.admit(None), Ok(None));
        assert_eq!(
            rule.admit(Some("page=2&page_size=20")),
            Ok(Some("page=2&page_size=20".to_owned()))
        );
        // Request order is irrelevant; the forwarded order is canonical.
        assert_eq!(
            rule.admit(Some("offset=0&page_size=200&page=10000")),
            Ok(Some("page=10000&page_size=200&offset=0".to_owned()))
        );
        assert_eq!(
            rule.admit(Some("offset=1000000")),
            Ok(Some("offset=1000000".to_owned()))
        );
    }

    #[test]
    fn rejects_selectors_and_every_encoding_trick() {
        let rule = rule();
        let cases: &[(&str, QueryDenial)] = &[
            ("", QueryDenial::Malformed),
            ("&", QueryDenial::Malformed),
            ("page=1&&page_size=2", QueryDenial::Malformed),
            ("page=1&", QueryDenial::Malformed),
            ("&page=1", QueryDenial::Malformed),
            ("customerId=B", QueryDenial::Encoding),
            ("customer=b", QueryDenial::UnknownParameter),
            ("customer=7", QueryDenial::UnknownParameter),
            ("page=2&customer=7", QueryDenial::UnknownParameter),
            ("page=1&page=2", QueryDenial::DuplicateParameter),
            ("pag%65=1", QueryDenial::Encoding),
            ("page=%31", QueryDenial::Encoding),
            ("page=1%00", QueryDenial::Encoding),
            ("page=+1", QueryDenial::Encoding),
            ("page=1+", QueryDenial::Encoding),
            ("page=1;page_size=2", QueryDenial::Encoding),
            ("page[]=1", QueryDenial::Encoding),
            ("page%5B%5D=1", QueryDenial::Encoding),
            ("page=1#x", QueryDenial::Encoding),
            ("page=1 ", QueryDenial::Encoding),
            ("PAGE=1", QueryDenial::Encoding),
            ("page", QueryDenial::Shape),
            ("page=", QueryDenial::Shape),
            ("page=1=2", QueryDenial::Shape),
            ("=1", QueryDenial::UnknownParameter),
            ("page=02", QueryDenial::Value),
            ("page=00", QueryDenial::Value),
            ("page=0", QueryDenial::Value),
            ("page=10001", QueryDenial::Value),
            ("page=-1", QueryDenial::Encoding),
            ("page=1.5", QueryDenial::Encoding),
            ("page=a", QueryDenial::Value),
            ("page=99999999999999999999", QueryDenial::Value),
            ("page_size=0", QueryDenial::Value),
            ("page_size=201", QueryDenial::Value),
            ("offset=1000001", QueryDenial::Value),
            ("offset=00", QueryDenial::Value),
        ];
        for (query, expected) in cases {
            assert_eq!(rule.admit(Some(query)), Err(*expected), "{query:?}");
        }
        // Non-ASCII digits never reach the number parser.
        assert_eq!(
            rule.admit(Some("page=\u{0661}")),
            Err(QueryDenial::Encoding)
        );
        // Over-long queries are refused before any parsing.
        let long = format!("page=1&{}", "a".repeat(MAX_PAGINATION_QUERY_BYTES));
        assert_eq!(rule.admit(Some(&long)), Err(QueryDenial::Malformed));
    }

    #[test]
    fn page_size_bound_is_configurable_but_capped() {
        let mut block = SiteQueryPagination {
            parameters: vec![SiteQueryParameter {
                name: "limit".to_owned(),
                kind: PaginationKind::PageSize,
                max_value: Some(1_000),
            }],
        };
        let rule = QueryPaginationRule::compile(&block).unwrap();
        assert!(rule.admit(Some("limit=1000")).is_ok());
        assert_eq!(rule.admit(Some("limit=1001")), Err(QueryDenial::Value));
        block.parameters[0].max_value = Some(1_001);
        assert!(block.validate().is_err());
        block.parameters[0].max_value = Some(0);
        assert!(block.validate().is_err());
        block.parameters[0].kind = PaginationKind::Page;
        block.parameters[0].max_value = Some(5);
        assert!(block.validate().is_err(), "fixed-bound kinds take no bound");
    }

    #[test]
    fn validation_is_closed() {
        let block = |names: &[&str]| SiteQueryPagination {
            parameters: names
                .iter()
                .map(|name| parameter(name, PaginationKind::Page))
                .collect(),
        };
        assert!(block(&["page"]).validate().is_ok());
        assert!(block(&["a", "b", "c", "d"]).validate().is_ok());
        assert!(block(&[]).validate().is_err());
        assert!(block(&["a", "b", "c", "d", "e"]).validate().is_err());
        assert!(block(&["page", "page"]).validate().is_err());
        for bad in [
            "",
            "Page",
            "page1",
            "page-x",
            "page.x",
            "pag\u{e9}",
            &"a".repeat(33),
        ] {
            assert!(block(&[bad]).validate().is_err(), "{bad:?}");
        }
        assert!(block(&[&"a".repeat(32)]).validate().is_ok());
    }

    #[test]
    fn collisions_with_resource_parameters_ignore_case() {
        let block = SiteQueryPagination {
            parameters: vec![parameter("page", PaginationKind::Page)],
        };
        assert!(block.collides_with(["Page"]));
        assert!(block.collides_with(["page"]));
        assert!(!block.collides_with(["customer_id"]));
    }

    #[test]
    fn serialization_is_closed_and_stable() {
        let text = r#"{"parameters":[{"name":"page","kind":"page"},{"name":"n","kind":"page_size","max_value":50}]}"#;
        let block: SiteQueryPagination = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::to_string(&block).unwrap(), text);
        for bad in [
            r#"{"parameters":[{"name":"p","kind":"cursor"}]}"#,
            r#"{"parameters":[{"name":"p","kind":"page","extra":1}]}"#,
            r#"{"parameters":[],"extra":1}"#,
        ] {
            assert!(serde_json::from_str::<SiteQueryPagination>(bad).is_err());
        }
    }
}
