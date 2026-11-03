//! v4 site configuration and decision log types (docs/03).
//!
//! The judging logic lives in the `xshield-judge` crate.

pub mod advanced;
pub mod agent;
pub mod config;
pub mod learning;
pub mod log;
pub mod objects;
pub mod route;
pub mod trace;

pub use advanced::Advanced;
pub use config::{ConfigError, Mode, OnJevUnavailable, PathPattern, SessionCredential, SiteSpec};
pub use log::{Conclusion, ContextKind, DecisionPath, DecisionRecord, JevRecord, Outcome};
pub use objects::{
    LearningSettings, ObjectClass, ObjectMap, ObjectSlot, ObjectsIssue, ObjectsPlace,
    ObjectsReason, Reliability, SlotSource, Tier,
};
pub use route::{Api, Body, RequestView, Resolved, Route, UnknownReason, header_names};
pub use trace::{
    FieldCount, ObjectFrom, ObservationSummary, Observed, SHAPE_FIELDS_MAX, ShapeField, Skip,
    Timing, Trace, TraceEntry, TraceRecent, TraceSession, TraceSource, TraceValue,
};
