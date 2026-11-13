//! The domain logic of Xshield v4, shared by the gateway, the judge and the control plane.
//!
//! This crate owns the site configuration, the request and response values a judgement
//! reads, the object map and its learning rules, the model settings, and the decision
//! record. It performs no network, storage, or origin side effects
//! (`tests/dependency_boundary.rs` keeps it that way).

#![warn(missing_docs)]

pub mod constant_time;
pub mod context;
pub mod kind;
pub mod model;
pub mod path_template;
