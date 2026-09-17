//! Minimal M0 core for Xshield.
//!
//! This crate owns validated domain identifiers, management identity,
//! deterministic stage results, request orchestration, and the ports needed by
//! that orchestration. It performs no network, storage, or origin side effects.

#![warn(missing_docs)]

pub mod admin;
pub mod application;
pub mod audit;
pub mod domain;
pub mod grant;
pub mod identity;
pub mod ports;
pub mod provenance;
