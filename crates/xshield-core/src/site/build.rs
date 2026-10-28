//! Page-build registration for `SENSOR_HTML` routes (docs/33).
//!
//! A front-end release produces a new static page whose bytes no approved
//! build matches, so the edge would refuse it. These pure functions let a
//! release pipeline compute the new build's fingerprint and stage it next to
//! the builds already served: old and new stay valid together (at most 16),
//! the old one is retired in a later revision. Staging never approves
//! anything: a changed build is `SENSOR_HTML_CHANGED`, which only an
//! independent `PolicyApprover` clears.

use sha2::{Digest, Sha256};

use super::SiteConfig;
use super::flow::{SiteSensorHtml, SiteSensorHtmlAdapter};

/// The largest page the fingerprint reads, matching the console's limit.
pub const MAX_PAGE_BYTES: usize = 16 * 1024 * 1024;
/// Builds one `SENSOR_HTML` route may hold at once (primary included).
pub const MAX_BUILDS: usize = 16;

const HEAD_CLOSE: &[u8] = b"</head>";

/// What the edge matches a page by: the SHA-256 of the exact origin bytes and
/// the byte offset of the first `</head>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageBuild {
    /// 64 lowercase hexadecimal digits.
    pub origin_sha256: String,
    /// Byte offset of the first lowercase `</head>`.
    pub injection_offset: usize,
    /// Length of the page in bytes.
    pub bytes: usize,
}

/// Why a build cannot be computed or staged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// The page is empty or larger than [`MAX_PAGE_BYTES`].
    PageSize,
    /// The page has no lowercase `</head>`.
    NoHeadClose,
    /// No route has this operation ID.
    UnknownOperation,
    /// The route is not a `SENSOR_HTML` route with builds.
    NotSensorHtml,
    /// The page is larger than the route's response limit.
    ExceedsRouteLimit,
    /// The revision label is already used by a different build.
    RevisionInUse,
    /// A build named for retirement does not exist.
    UnknownRetirement,
    /// Retiring would leave the route without a build.
    NoBuildLeft,
    /// The route would hold more than [`MAX_BUILDS`] builds.
    TooManyBuilds,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PageSize => "the page is empty or larger than 16 MiB",
            Self::NoHeadClose => "the page has no lowercase </head>",
            Self::UnknownOperation => "no route has this operation ID",
            Self::NotSensorHtml => "the route is not a SENSOR_HTML route with builds",
            Self::ExceedsRouteLimit => "the page is larger than the route's max_response_bytes",
            Self::RevisionInUse => "the adapter revision already names a different build",
            Self::UnknownRetirement => "a build named for retirement does not exist",
            Self::NoBuildLeft => "retiring would leave the route without a build",
            Self::TooManyBuilds => "the route would hold more than 16 builds; retire one",
        })
    }
}

impl std::error::Error for BuildError {}

/// The fingerprint of one page, from its exact bytes.
///
/// # Errors
///
/// [`BuildError::PageSize`] or [`BuildError::NoHeadClose`].
pub fn fingerprint(page: &[u8]) -> Result<PageBuild, BuildError> {
    if page.is_empty() || page.len() > MAX_PAGE_BYTES {
        return Err(BuildError::PageSize);
    }
    let injection_offset = page
        .windows(HEAD_CLOSE.len())
        .position(|window| window == HEAD_CLOSE)
        .ok_or(BuildError::NoHeadClose)?;
    let digest = Sha256::digest(page);
    let origin_sha256 = digest
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        });
    Ok(PageBuild {
        origin_sha256,
        injection_offset,
        bytes: page.len(),
    })
}

/// What staging changed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Registration {
    /// The build was added (and any named builds retired).
    Changed,
    /// The same build is already approved under this revision and nothing
    /// was asked to retire: nothing to stage.
    Unchanged,
}

/// Adds `build` to the `SENSOR_HTML` route `operation_id` under
/// `adapter_revision` and removes the builds named in `retire`. Retiring the
/// primary promotes the first remaining build. Whole-configuration rules stay
/// with [`SiteConfig::validate`] and the server.
///
/// # Errors
///
/// See [`BuildError`]; `config` is unchanged on error.
pub fn register(
    config: &mut SiteConfig,
    operation_id: &str,
    adapter_revision: &str,
    build: &PageBuild,
    retire: &[String],
) -> Result<Registration, BuildError> {
    let route = config
        .policy
        .routes
        .iter_mut()
        .find(|route| route.operation_id == operation_id)
        .ok_or(BuildError::UnknownOperation)?;
    if route.response_mode != "SENSOR_HTML" {
        return Err(BuildError::NotSensorHtml);
    }
    if build.bytes > route.max_response_bytes {
        return Err(BuildError::ExceedsRouteLimit);
    }
    let sensor = route
        .sensor_html
        .as_ref()
        .ok_or(BuildError::NotSensorHtml)?;
    let mut builds: Vec<SiteSensorHtmlAdapter> = std::iter::once(SiteSensorHtmlAdapter {
        adapter_revision: sensor.adapter_revision.clone(),
        origin_sha256: sensor.origin_sha256.clone(),
        injection_offset: sensor.injection_offset,
    })
    .chain(sensor.additional_adapters.iter().cloned())
    .collect();
    if retire.iter().any(|name| {
        !builds
            .iter()
            .any(|existing| &existing.adapter_revision == name)
    }) {
        return Err(BuildError::UnknownRetirement);
    }
    let wanted = SiteSensorHtmlAdapter {
        adapter_revision: adapter_revision.to_owned(),
        origin_sha256: build.origin_sha256.clone(),
        injection_offset: build.injection_offset,
    };
    let present = builds.contains(&wanted);
    if !present
        && builds.iter().any(|existing| {
            existing.adapter_revision == adapter_revision
                || existing.origin_sha256 == build.origin_sha256
        })
    {
        return Err(BuildError::RevisionInUse);
    }
    if present && retire.is_empty() {
        return Ok(Registration::Unchanged);
    }
    if retire.iter().any(|name| name == adapter_revision) {
        return Err(BuildError::RevisionInUse);
    }
    builds.retain(|existing| !retire.contains(&existing.adapter_revision));
    if !present {
        builds.push(wanted);
    }
    if builds.len() > MAX_BUILDS {
        return Err(BuildError::TooManyBuilds);
    }
    let mut remaining = builds.into_iter();
    let primary = remaining.next().ok_or(BuildError::NoBuildLeft)?;
    route.sensor_html = Some(SiteSensorHtml {
        adapter_revision: primary.adapter_revision,
        origin_sha256: primary.origin_sha256,
        injection_offset: primary.injection_offset,
        additional_adapters: remaining.collect(),
    });
    Ok(Registration::Changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &[u8] = b"<!doctype html><html><head><title>x</title></head><body></body></html>";

    fn config() -> SiteConfig {
        let config: SiteConfig = serde_json::from_str(include_str!(
            "../../../../tests/site-config/browser-loop.json"
        ))
        .unwrap();
        config.validate().unwrap();
        config
    }

    fn sensor(config: &SiteConfig) -> &SiteSensorHtml {
        config
            .policy
            .routes
            .iter()
            .find(|route| route.operation_id == "app.page")
            .and_then(|route| route.sensor_html.as_ref())
            .unwrap()
    }

    fn revisions(config: &SiteConfig) -> Vec<String> {
        let sensor = sensor(config);
        std::iter::once(sensor.adapter_revision.clone())
            .chain(
                sensor
                    .additional_adapters
                    .iter()
                    .map(|adapter| adapter.adapter_revision.clone()),
            )
            .collect()
    }

    #[test]
    fn the_fingerprint_is_the_digest_and_the_first_head_close() {
        let build = fingerprint(PAGE).unwrap();
        assert_eq!(build.injection_offset, 43);
        assert_eq!(&PAGE[43..50], b"</head>");
        assert_eq!(build.bytes, PAGE.len());
        assert_eq!(build.origin_sha256, format!("{:x}", Sha256::digest(PAGE)));
        let twice = b"<head></head><script>'</head>'</script>";
        assert_eq!(fingerprint(twice).unwrap().injection_offset, 6);
        assert_eq!(fingerprint(b"<HEAD></HEAD>"), Err(BuildError::NoHeadClose));
        assert_eq!(fingerprint(b""), Err(BuildError::PageSize));
        assert_eq!(
            fingerprint(&vec![b' '; MAX_PAGE_BYTES + 1]),
            Err(BuildError::PageSize)
        );
    }

    #[test]
    fn a_new_build_is_added_beside_the_served_one_and_validates() {
        let mut config = config();
        let build = fingerprint(PAGE).unwrap();
        assert_eq!(
            register(&mut config, "app.page", "app-r2", &build, &[]),
            Ok(Registration::Changed)
        );
        config.validate().unwrap();
        assert_eq!(revisions(&config), ["app-r1", "app-r2"]);
        // The same build again is a no-op, so a re-run pipeline stages nothing.
        let before = config.clone();
        assert_eq!(
            register(&mut config, "app.page", "app-r2", &build, &[]),
            Ok(Registration::Unchanged)
        );
        assert_eq!(config, before);
    }

    #[test]
    fn retiring_the_primary_promotes_the_next_build() {
        let mut config = config();
        let build = fingerprint(PAGE).unwrap();
        register(&mut config, "app.page", "app-r2", &build, &[]).unwrap();
        assert_eq!(
            register(
                &mut config,
                "app.page",
                "app-r2",
                &build,
                &["app-r1".to_owned()]
            ),
            Ok(Registration::Changed)
        );
        config.validate().unwrap();
        assert_eq!(revisions(&config), ["app-r2"]);
        assert_eq!(sensor(&config).origin_sha256, build.origin_sha256);
        assert!(sensor(&config).additional_adapters.is_empty());
    }

    #[test]
    fn refusals_leave_the_configuration_unchanged() {
        let build = fingerprint(PAGE).unwrap();
        let served = sensor(&config()).origin_sha256.clone();
        let cases: Vec<(&str, &str, PageBuild, Vec<String>, BuildError)> = vec![
            (
                "missing",
                "app-r2",
                build.clone(),
                vec![],
                BuildError::UnknownOperation,
            ),
            (
                "orders.list",
                "app-r2",
                build.clone(),
                vec![],
                BuildError::NotSensorHtml,
            ),
            (
                "app.page",
                "app-r1",
                build.clone(),
                vec![],
                BuildError::RevisionInUse,
            ),
            (
                "app.page",
                "app-r2",
                PageBuild {
                    origin_sha256: served,
                    ..build.clone()
                },
                vec![],
                BuildError::RevisionInUse,
            ),
            (
                "app.page",
                "app-r2",
                PageBuild {
                    bytes: 16_385,
                    ..build.clone()
                },
                vec![],
                BuildError::ExceedsRouteLimit,
            ),
            (
                "app.page",
                "app-r2",
                build.clone(),
                vec!["app-r0".to_owned()],
                BuildError::UnknownRetirement,
            ),
            (
                "app.page",
                "app-r2",
                build.clone(),
                vec!["app-r2".to_owned()],
                BuildError::UnknownRetirement,
            ),
        ];
        for (operation, revision, page, retire, expected) in cases {
            let mut config = config();
            let before = config.clone();
            assert_eq!(
                register(&mut config, operation, revision, &page, &retire),
                Err(expected.clone()),
                "{operation} {revision} {expected:?}"
            );
            assert_eq!(config, before);
        }
    }

    #[test]
    fn a_route_holds_at_most_sixteen_builds() {
        let mut config = config();
        for index in 2..=16 {
            let mut page = PAGE.to_vec();
            page.extend_from_slice(format!("<!-- {index} -->").as_bytes());
            let build = fingerprint(&page).unwrap();
            register(
                &mut config,
                "app.page",
                &format!("app-r{index}"),
                &build,
                &[],
            )
            .unwrap();
        }
        config.validate().unwrap();
        let before = config.clone();
        let build = fingerprint(b"<head></head>17").unwrap();
        assert_eq!(
            register(&mut config, "app.page", "app-r17", &build, &[]),
            Err(BuildError::TooManyBuilds)
        );
        assert_eq!(config, before);
        assert_eq!(
            register(
                &mut config,
                "app.page",
                "app-r17",
                &build,
                &["app-r1".to_owned()]
            ),
            Ok(Registration::Changed)
        );
        config.validate().unwrap();
        assert_eq!(revisions(&config).len(), 16);
    }
}
