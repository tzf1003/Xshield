//! v4 site configuration and decision log types (docs/03).
//!
//! The judging logic lives in the `xshield-judge` crate.

pub mod advanced;
pub mod config;
pub mod log;
pub mod trace;

pub use advanced::Advanced;
pub use config::{ConfigError, Mode, OnJevUnavailable, PathPattern, SessionCredential, SiteSpec};
pub use log::{Conclusion, ContextKind, DecisionPath, DecisionRecord, JevRecord, Outcome};
pub use trace::{
    FieldCount, ObservationSummary, Observed, Skip, Timing, Trace, TraceEntry, TraceRecent,
    TraceSession, TraceSource, TraceValue,
};
