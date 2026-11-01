//! v4 session-context authorization: the pure logic behind docs/00–03.
//!
//! A request may only reference values the origin already showed this session,
//! or arrive through a registered entry; everything else goes to Jev. This
//! module owns the site configuration, value extraction, session context and
//! decision steps. It performs no I/O.

pub mod config;
pub mod log;

pub use config::{ConfigError, Mode, OnJevUnavailable, PathPattern, SessionCredential, SiteSpec};
