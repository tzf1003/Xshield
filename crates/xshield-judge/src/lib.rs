//! The v4 request judge: session context, Jev client and decision flow.
//!
//! Gateway-independent so it can be tested without a proxy. See docs/01 and 02.

#![warn(missing_docs)]

pub mod context;
pub mod engine;
mod exposure;
pub mod jev;
pub mod probe;
pub mod slot;
pub mod slots;
pub mod state;
mod trace;
pub mod values;
