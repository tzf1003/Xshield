//! Fuzz targets for the parsers that read bytes from outside the trust
//! boundary.
//!
//! Each target is a plain function from bytes to nothing that panics only
//! when the parser breaks its own contract: it must never panic on any input,
//! and every value it accepts must satisfy the invariant stated on the
//! target. The same functions run in two places:
//!
//! - `fuzz_targets/*.rs`, coverage-guided under libFuzzer (`cargo fuzz`), on
//!   a schedule and on demand (`.github/workflows/fuzz.yml`);
//! - `tests/replay.rs`, on the stable toolchain in every CI run, over the
//!   checked-in seeds and a fixed number of deterministic mutations of them.
//!
//! A crash libFuzzer finds is minimized, added under `seeds/<target>/`, and
//! from then on replayed by every CI run.

// Every target panics, by design, exactly when its contract breaks; that is
// stated once here instead of on each function.
#![allow(clippy::missing_panics_doc)]

use xshield_core::{
    context::SiteSpec,
    path_template::{canonical_path, is_templatable, normalize, position_template},
};

/// One fuzz target: panics only when the parser breaks its contract.
pub type Target = fn(&[u8]);

/// Every target, by the name of its `fuzz_targets/<name>.rs` and
/// `seeds/<name>/` directory.
pub const TARGETS: &[(&str, Target)] =
    &[("request_path", request_path), ("site_config", site_config)];

/// A request path as the gateway reads it off the wire. The canonical
/// spelling is absolute, has no empty or dot segment, and is its own
/// canonical spelling; a display template keeps the segment count.
pub fn request_path(data: &[u8]) {
    let path = String::from_utf8_lossy(data);
    if let Some(canonical) = canonical_path(&path) {
        assert!(canonical.starts_with('/'), "{canonical:?}");
        if canonical != "/" {
            assert!(
                canonical
                    .split('/')
                    .skip(1)
                    .all(|segment| !matches!(segment, "" | "." | "..")),
                "{canonical:?}"
            );
        }
        assert_eq!(canonical_path(&canonical).as_deref(), Some(&*canonical));
        assert_eq!(is_templatable(&path), normalize(&canonical).is_some());
    } else {
        assert!(!is_templatable(&path));
        assert_eq!(position_template(&path), path);
    }
    if let Some(template) = normalize(&path) {
        assert_eq!(template.split('/').count(), path.split('/').count());
    }
}

/// A site configuration as the control API receives it and the gateway loads
/// it: the first line is a request path, the rest the JSON document. A refused
/// document only returns an error; an accepted one answers the questions the
/// gateway asks of every request without panicking.
pub fn site_config(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let (path, document) = text.split_once('\n').unwrap_or(("/", &text));
    if let Ok(site) = SiteSpec::from_json(document) {
        assert!(!site.name().is_empty());
        assert!(!site.hosts().is_empty());
        assert_eq!(site.is_entry(path), site.matching_entry(path).is_some());
        assert_eq!(site.is_bypass(path), site.matching_bypass(path).is_some());
        let _ = site.names_from_body(path);
    }
}
