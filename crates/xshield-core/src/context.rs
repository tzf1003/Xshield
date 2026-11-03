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
    ADMIN_ROLE, IdentityRole, LearningSettings, ObjectClass, ObjectMap, ObjectSlot, ObjectsIssue,
    ObjectsPlace, ObjectsReason, Reliability, SlotSource, Tier, role_label, tier_proves,
};
pub use route::{Api, Body, RequestView, Resolved, Route, UnknownReason, header_names};
pub use trace::{
    Attempt, EXPOSURE_ATTRIBUTES_MAX, EXPOSURE_USERS_MAX, ExposedAttribute, Exposure,
    ExposureBasis, ExposureKind, FINGERPRINT_SLOTS_MAX, FINGERPRINTS_PER_SLOT_MAX, FieldCount,
    ObjectFrom, ObservationSummary, Observed, PublicAccess, SHAPE_FIELDS_MAX, ShapeField, Skip,
    Timing, Trace, TraceEntry, TraceIdentity, TraceRecent, TraceSession, TraceSource, TraceValue,
};
