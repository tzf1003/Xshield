//! The v4 data plane (docs/00 and docs/01): a Pingora reverse proxy that asks
//! [`xshield_judge::Judge`] about every request before the origin sees it and
//! lets the judge learn from every response the origin returns.
//!
//! Nothing here decides anything; the module split is plumbing only:
//! - [`sites`] holds the Host to site table and each site's status,
//! - [`source`] loads sites from `PostgreSQL` or a file,
//! - [`sink`] ships decision log rows,
//! - [`status`] writes the heartbeat and registers the Jev prompt,
//! - [`proxy`] is the `ProxyHttp` implementation,
//! - [`server`] puts listeners around it,
//! - [`settings`] reads the environment.

pub mod proxy;
pub mod server;
pub mod settings;
pub mod sink;
pub mod sites;
pub mod source;
pub mod status;
