//! `PostgreSQL` adapters for the v4 schema (docs/05-v3-removal.md section
//! 5.2): a site's current configuration, that site's configuration history,
//! and the decision log the gateway writes. Everything v3 (identity bindings,
//! grants, cases, evidence access, calibration, outbox, management API keys,
//! ...) was deleted along with its tables; see [`site_spec_store`] and
//! [`decision_log_store`] for the two modules that remain.

#![warn(missing_docs)]

pub mod decision_log_store;
pub mod site_spec_store;
