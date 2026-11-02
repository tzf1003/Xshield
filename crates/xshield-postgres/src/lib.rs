//! `PostgreSQL` storage for the v4 control plane (docs/07-console-architecture.md
//! sections 7.8 and 7.9).
//!
//! The control plane is the only writer of site configuration and of the
//! decision log partitions it maintains; the gateway writes decision rows,
//! heartbeats and instruction versions. The modules here are the storage
//! adapters both sides use, and they hold no authorization logic.

#![warn(missing_docs)]

pub mod decision_log_store;
pub mod decision_stats;
pub mod edge_status_store;
pub mod jev_prompt_store;
pub mod object_learning_store;
pub mod partitions;
pub mod site_spec_store;
