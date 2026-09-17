//! Typed request-stage facts; required security facts go through `AuditSink`.

use crate::domain::{EventId, RequestId, StageExecutionId};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Stable request stages exposed by the M0 timeline.
pub enum Stage {
    /// Tenant/site policy lookup.
    SiteConfig,
    /// Business credential binding.
    IdentityBind,
    /// Approved UI action provenance.
    UiProvenance,
    /// Resource-operation grant lookup.
    Capability,
    /// Conventional WAF inspection.
    BaselineInspection,
    /// Protected-origin dispatch.
    OriginForward,
}

impl Stage {
    #[must_use]
    /// Returns the audit-contract stage name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SiteConfig => "site_config",
            Self::IdentityBind => "identity_bind",
            Self::UiProvenance => "ui_provenance",
            Self::Capability => "capability",
            Self::BaselineInspection => "baseline_inspection",
            Self::OriginForward => "origin_forward",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Stage outcomes used by the v3 audit contract.
pub enum Outcome {
    /// The stage accepted the request.
    Pass,
    /// A deterministic policy rejected the request.
    Deny,
    /// The stage could not complete because of an internal dependency.
    Error,
    /// A prior terminal stage prevented execution.
    Skipped,
}

impl Outcome {
    #[must_use]
    /// Returns the uppercase audit-contract value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Deny => "DENY",
            Self::Error => "ERROR",
            Self::Skipped => "SKIPPED",
        }
    }
}

/// Stable machine-readable reasons for the implemented M0 branches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasonCode {
    /// The request has no authenticated binding.
    AuthRequired,
    /// Presented credentials do not match the bound combination.
    AuthBindingMismatch,
    /// The exact credential combination matches an active binding.
    AuthBindingValid,
    /// The server-side session lease has expired.
    AuthSessionExpired,
    /// No site policy exists for the requested scope.
    SiteNotConfigured,
    /// The scoped site policy is explicitly disabled.
    SiteDisabled,
    /// The site policy dependency could not answer.
    SiteConfigUnavailable,
    /// A prior site-policy result made the stage inapplicable.
    SkippedBySiteUnavailable,
    /// Required audit durability was not obtained.
    AuditDurabilityFailed,
    /// The request ended without an active site implementation.
    RequestNotConfigured,
}

impl ReasonCode {
    #[must_use]
    /// Returns the stable machine-readable code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::AuthBindingMismatch => "AUTH_BINDING_MISMATCH",
            Self::AuthBindingValid => "AUTH_BINDING_VALID",
            Self::AuthSessionExpired => "AUTH_SESSION_EXPIRED",
            Self::SiteNotConfigured => "SITE_NOT_CONFIGURED",
            Self::SiteDisabled => "SITE_DISABLED",
            Self::SiteConfigUnavailable => "SITE_CONFIG_UNAVAILABLE",
            Self::SkippedBySiteUnavailable => "SKIPPED_BY_SITE_UNAVAILABLE",
            Self::AuditDurabilityFailed => "AUDIT_DURABILITY_FAILED",
            Self::RequestNotConfigured => "REQUEST_NOT_CONFIGURED",
        }
    }
}

/// A deterministic stage result. Confidence is intentionally absent: v3
/// requires deterministic checks to serialize confidence as `null`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageResult {
    /// Distinguishes retries and concurrent stage executions.
    pub execution_id: StageExecutionId,
    /// Stage that produced this result.
    pub stage: Stage,
    /// Terminal stage outcome.
    pub outcome: Outcome,
    /// Stable explanation for the outcome.
    pub reason_code: ReasonCode,
    /// Monotonic stage duration in microseconds.
    pub duration_us: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Typed payload for an M0 audit event.
pub enum AuditKind {
    /// The edge accepted a complete HTTP request.
    RequestAccepted,
    /// A stage ran to a terminal result.
    StageCompleted(StageResult),
    /// A stage did not run and records why.
    StageSkipped(StageResult),
    /// The request reached its terminal response state.
    RequestCompleted {
        /// Composed request decision.
        decision: FinalDecision,
        /// Stable terminal reason.
        reason_code: ReasonCode,
        /// Whether origin side effects may have occurred.
        origin_state: OriginState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Final decisions implemented in M0.
pub enum FinalDecision {
    /// The site is missing, disabled, or unavailable.
    NotConfigured,
}

impl FinalDecision {
    #[must_use]
    /// Returns the audit-contract decision value.
    pub const fn as_str(self) -> &'static str {
        "NOT_CONFIGURED"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Protected-origin side-effect state.
pub enum OriginState {
    /// No origin request was attempted.
    NotSent,
}

impl OriginState {
    #[must_use]
    /// Returns the audit-contract origin state.
    pub const fn as_str(self) -> &'static str {
        "not_sent"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One immutable, request-ordered M0 audit fact.
pub struct AuditEvent {
    /// Unique event identifier; retries retain their original ID.
    pub event_id: EventId,
    /// Internal request correlation ID.
    pub request_id: RequestId,
    /// Monotonic sequence within this request coordinator.
    pub request_seq: u32,
    /// Typed event payload.
    pub kind: AuditKind,
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            AuditKind::RequestAccepted => write!(formatter, "request.accepted"),
            AuditKind::StageCompleted(result) | AuditKind::StageSkipped(result) => write!(
                formatter,
                "{} {} {}",
                result.stage.as_str(),
                result.outcome.as_str(),
                result.reason_code.as_str()
            ),
            AuditKind::RequestCompleted {
                decision,
                reason_code,
                origin_state,
            } => write!(
                formatter,
                "request.completed {} {} origin={}",
                decision.as_str(),
                reason_code.as_str(),
                origin_state.as_str()
            ),
        }
    }
}
