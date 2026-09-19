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
    /// The anonymous-session quota is full for this tenant and site.
    AnonymousSessionCapacityExceeded,
    /// Anonymous-session creation exceeded its bounded rate.
    AnonymousSessionRateExceeded,
    /// The request has no authenticated binding.
    AuthRequired,
    /// Presented credentials do not match the bound combination.
    AuthBindingMismatch,
    /// The exact credential combination matches an active binding.
    AuthBindingValid,
    /// A previously captured identity epoch is no longer current.
    AuthEpochChanged,
    /// A previously captured credential generation is no longer current.
    AuthCredentialGenerationChanged,
    /// The server revoked this authentication binding.
    AuthBindingRevoked,
    /// The server-side session lease has expired.
    AuthSessionExpired,
    /// No active exact grant exists for the requested resource.
    CapabilityMissing,
    /// A grant exists for the resource but not the requested operation or view.
    OperationNotGranted,
    /// The grant ledger reached its configured hard capacity.
    GrantCapacityExceeded,
    /// A grant draft has invalid time bounds.
    GrantExpiryInvalid,
    /// An idempotency key was reused with different authorization semantics.
    GrantIssuanceConflict,
    /// A new exact grant and its issuance event committed.
    GrantIssued,
    /// An identical issuance key resolved to the original grant.
    GrantAlreadyIssued,
    /// The identity, approved action, policy, or lease cannot issue a grant.
    GrantSourceIneligible,
    /// No approved action mapping is available for the verified page.
    UiActionNotAvailable,
    /// Page evidence is unverified, expired, or revoked.
    UiEvidenceUnverified,
    /// The action target exceeds the approved subject or resource scope.
    TargetScopeMismatch,
    /// The request contains a field outside the approved action profile.
    FieldNotAllowed,
    /// An action grant has invalid time bounds.
    UiActionExpiryInvalid,
    /// Verified page evidence and a new exact action grant committed.
    UiActionIssued,
    /// An identical action grant was already committed.
    UiActionAlreadyIssued,
    /// An action reference was reused with different semantics.
    UiActionIssuanceConflict,
    /// The exact public operation entry was approved.
    PublicEntryAllowed,
    /// The exact authentication operation entry was approved.
    AuthEntryAllowed,
    /// The authenticated root operation was approved.
    FlowRootAllowed,
    /// Exact UI action and resource requirements passed.
    UiActionAllowed,
    /// Method or route does not match the frozen operation policy.
    OperationNotMatched,
    /// Share proof does not match the exact resource, view, operation, or lease.
    ShareScopeMismatch,
    /// A new limited-share grant and its issuance event committed.
    ShareIssued,
    /// An identical limited-share issuance resolved to the original grant.
    ShareAlreadyIssued,
    /// A share issuance key was reused with different authorization semantics.
    ShareIssuanceConflict,
    /// The issuer identity, resource grant, rule, policy, or lease is ineligible.
    ShareSourceIneligible,
    /// The issuer reached the configured active-share bound.
    ShareCapacityExceeded,
    /// Service identity proof does not match the exact operation scope.
    ServiceIdentityMismatch,
    /// Exact limited-share proof passed.
    ShareEntryAllowed,
    /// Exact service identity operation scope passed.
    ServiceIdentityAllowed,
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
    /// A truncated crash tail was repaired before accepting traffic.
    AuditTailRecovered,
    /// The forward intent reached the required durability boundary.
    OriginForwardIntentRecorded,
    /// A response was received from the selected origin.
    OriginResponseReceived,
    /// The versioned browser sensor asset was served by the edge.
    SensorAssetServed,
    /// The immutable browser sensor bootstrap loader was served by the edge.
    SensorLoaderServed,
    /// A dynamic browser sensor bootstrap was served by the edge.
    SensorBootstrapServed,
    /// A session-bound browser observation was durably accepted.
    SensorObservationAccepted,
    /// Browser observation framing or content failed strict validation.
    SensorObservationInvalid,
    /// An exact approved HTML entity received versioned sensor scripts.
    SensorHtmlInjected,
    /// HTML sensor injection validation or rewriting failed closed.
    SensorHtmlValidationFailed,
    /// A configured private response exceeded its complete-buffer bound.
    ResponseBodyTooLarge,
    /// Aggregate private-response buffering capacity was unavailable.
    ResponseBufferCapacityExhausted,
    /// A configured private response failed framing, encoding, media-type, or JSON validation.
    ResponseValidationFailed,
    /// Evidence capture failed strict parsing or secret-policy validation.
    EvidenceCaptureInvalid,
    /// Evidence source, output, or exclusion manifest exceeded its bound.
    EvidenceCaptureLimitExceeded,
    /// Evidence capture concurrency, byte quota, or file quota is exhausted.
    EvidenceCaptureCapacityExhausted,
    /// Required encrypted evidence storage or catalog publication failed.
    EvidenceCaptureUnavailable,
    /// A configured encrypted request exceeded its complete-buffer bound.
    RequestBodyTooLarge,
    /// Aggregate encrypted-request buffering capacity was unavailable.
    RequestBufferCapacityExhausted,
    /// The encrypted request framing, media type, envelope, version, or plaintext was invalid.
    RequestEnvelopeInvalid,
    /// The encrypted request failed authenticated decryption.
    RequestCryptoAuthenticationFailed,
    /// Authenticated plaintext was validated and frozen for origin rebuilding.
    RequestCryptoDecoded,
    /// The server-selected observe mode forwarded the original opaque entity.
    RequestCryptoObservedOpaque,
    /// An approved compatibility scope forwarded the original opaque entity.
    RequestCryptoCompatibilityOpaque,
    /// The compatibility approval expired before request admission.
    RequestCryptoCompatibilityExpired,
    /// Verified page evidence does not match an approved compatibility build.
    RequestCryptoBuildNotApproved,
    /// The scoped request-decryption key could not be obtained.
    RequestCryptoKeyUnavailable,
    /// The authenticated request message expired before replay consumption.
    RequestCryptoMessageExpired,
    /// The authenticated request message was issued beyond the configured skew.
    RequestCryptoMessageFromFuture,
    /// The authenticated request nonce or message identifier was already consumed.
    RequestCryptoReplayDetected,
    /// The authoritative replay ledger could not consume the message safely.
    RequestCryptoReplayStoreUnavailable,
    /// The authoritative replay ledger reached its configured active bound.
    RequestCryptoReplayCapacityExceeded,
    /// The transformed origin response was encrypted for the client.
    ResponseCryptoEncoded,
    /// The scoped response-encryption key could not be obtained.
    ResponseCryptoKeyUnavailable,
    /// Response encryption or required randomness failed.
    ResponseCryptoEncodingFailed,
    /// The encrypted response exceeded its configured serialized bound.
    ResponseCryptoEnvelopeTooLarge,
    /// Origin side effects cannot be determined after a proxy failure.
    OriginOutcomeUnknown,
    /// A durable request prefix ended before a release decision or forward intent committed.
    RequestIncomplete,
    /// Trusted wall-clock time was unavailable for admission.
    ClockUnavailable,
    /// Authoritative identity state could not be read safely.
    IdentityStoreUnavailable,
    /// The request ended without an active site implementation.
    RequestNotConfigured,
}

impl ReasonCode {
    #[must_use]
    /// Returns the stable machine-readable code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnonymousSessionCapacityExceeded => "ANONYMOUS_SESSION_CAPACITY_EXCEEDED",
            Self::AnonymousSessionRateExceeded => "ANONYMOUS_SESSION_RATE_EXCEEDED",
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::AuthBindingMismatch => "AUTH_BINDING_MISMATCH",
            Self::AuthBindingValid => "AUTH_BINDING_VALID",
            Self::AuthEpochChanged => "AUTH_EPOCH_CHANGED",
            Self::AuthCredentialGenerationChanged => "AUTH_CREDENTIAL_GENERATION_CHANGED",
            Self::AuthBindingRevoked => "AUTH_BINDING_REVOKED",
            Self::AuthSessionExpired => "AUTH_SESSION_EXPIRED",
            Self::CapabilityMissing => "CAPABILITY_MISSING",
            Self::OperationNotGranted => "OPERATION_NOT_GRANTED",
            Self::GrantCapacityExceeded => "GRANT_CAPACITY_EXCEEDED",
            Self::GrantExpiryInvalid => "GRANT_EXPIRY_INVALID",
            Self::GrantIssuanceConflict => "GRANT_ISSUANCE_CONFLICT",
            Self::GrantIssued => "GRANT_ISSUED",
            Self::GrantAlreadyIssued => "GRANT_ALREADY_ISSUED",
            Self::GrantSourceIneligible => "GRANT_SOURCE_INELIGIBLE",
            Self::UiActionNotAvailable => "UI_ACTION_NOT_AVAILABLE",
            Self::UiEvidenceUnverified => "UI_EVIDENCE_UNVERIFIED",
            Self::TargetScopeMismatch => "TARGET_SCOPE_MISMATCH",
            Self::FieldNotAllowed => "FIELD_NOT_ALLOWED",
            Self::UiActionExpiryInvalid => "UI_ACTION_EXPIRY_INVALID",
            Self::UiActionIssued => "UI_ACTION_ISSUED",
            Self::UiActionAlreadyIssued => "UI_ACTION_ALREADY_ISSUED",
            Self::UiActionIssuanceConflict => "UI_ACTION_ISSUANCE_CONFLICT",
            Self::PublicEntryAllowed => "PUBLIC_ENTRY_ALLOWED",
            Self::AuthEntryAllowed => "AUTH_ENTRY_ALLOWED",
            Self::FlowRootAllowed => "FLOW_ROOT_ALLOWED",
            Self::UiActionAllowed => "UI_ACTION_ALLOWED",
            Self::OperationNotMatched => "OPERATION_NOT_MATCHED",
            Self::ShareScopeMismatch => "SHARE_SCOPE_MISMATCH",
            Self::ShareIssued => "SHARE_ISSUED",
            Self::ShareAlreadyIssued => "SHARE_ALREADY_ISSUED",
            Self::ShareIssuanceConflict => "SHARE_ISSUANCE_CONFLICT",
            Self::ShareSourceIneligible => "SHARE_SOURCE_INELIGIBLE",
            Self::ShareCapacityExceeded => "SHARE_CAPACITY_EXCEEDED",
            Self::ServiceIdentityMismatch => "SERVICE_IDENTITY_MISMATCH",
            Self::ShareEntryAllowed => "SHARE_ENTRY_ALLOWED",
            Self::ServiceIdentityAllowed => "SERVICE_IDENTITY_ALLOWED",
            Self::SiteNotConfigured => "SITE_NOT_CONFIGURED",
            Self::SiteDisabled => "SITE_DISABLED",
            Self::SiteConfigUnavailable => "SITE_CONFIG_UNAVAILABLE",
            Self::SkippedBySiteUnavailable => "SKIPPED_BY_SITE_UNAVAILABLE",
            Self::AuditDurabilityFailed => "AUDIT_DURABILITY_FAILED",
            Self::AuditTailRecovered => "AUDIT_TAIL_RECOVERED",
            Self::OriginForwardIntentRecorded => "ORIGIN_FORWARD_INTENT_RECORDED",
            Self::OriginResponseReceived => "ORIGIN_RESPONSE_RECEIVED",
            Self::SensorAssetServed => "SENSOR_ASSET_SERVED",
            Self::SensorLoaderServed => "SENSOR_LOADER_SERVED",
            Self::SensorBootstrapServed => "SENSOR_BOOTSTRAP_SERVED",
            Self::SensorObservationAccepted => "SENSOR_OBSERVATION_ACCEPTED",
            Self::SensorObservationInvalid => "SENSOR_OBSERVATION_INVALID",
            Self::SensorHtmlInjected => "SENSOR_HTML_INJECTED",
            Self::SensorHtmlValidationFailed => "SENSOR_HTML_VALIDATION_FAILED",
            Self::ResponseBodyTooLarge => "RESPONSE_BODY_TOO_LARGE",
            Self::ResponseBufferCapacityExhausted => "RESPONSE_BUFFER_CAPACITY_EXHAUSTED",
            Self::ResponseValidationFailed => "RESPONSE_VALIDATION_FAILED",
            Self::EvidenceCaptureInvalid => "EVIDENCE_CAPTURE_INVALID",
            Self::EvidenceCaptureLimitExceeded => "EVIDENCE_CAPTURE_LIMIT_EXCEEDED",
            Self::EvidenceCaptureCapacityExhausted => "EVIDENCE_CAPTURE_CAPACITY_EXHAUSTED",
            Self::EvidenceCaptureUnavailable => "EVIDENCE_CAPTURE_UNAVAILABLE",
            Self::RequestBodyTooLarge => "REQUEST_BODY_TOO_LARGE",
            Self::RequestBufferCapacityExhausted => "REQUEST_BUFFER_CAPACITY_EXHAUSTED",
            Self::RequestEnvelopeInvalid => "REQUEST_ENVELOPE_INVALID",
            Self::RequestCryptoAuthenticationFailed => "REQUEST_CRYPTO_AUTHENTICATION_FAILED",
            Self::RequestCryptoDecoded => "REQUEST_CRYPTO_DECODED",
            Self::RequestCryptoObservedOpaque => "REQUEST_CRYPTO_OBSERVED_OPAQUE",
            Self::RequestCryptoCompatibilityOpaque => "REQUEST_CRYPTO_COMPATIBILITY_OPAQUE",
            Self::RequestCryptoCompatibilityExpired => "REQUEST_CRYPTO_COMPATIBILITY_EXPIRED",
            Self::RequestCryptoBuildNotApproved => "REQUEST_CRYPTO_BUILD_NOT_APPROVED",
            Self::RequestCryptoKeyUnavailable => "REQUEST_CRYPTO_KEY_UNAVAILABLE",
            Self::RequestCryptoMessageExpired => "REQUEST_CRYPTO_MESSAGE_EXPIRED",
            Self::RequestCryptoMessageFromFuture => "REQUEST_CRYPTO_MESSAGE_FROM_FUTURE",
            Self::RequestCryptoReplayDetected => "REQUEST_CRYPTO_REPLAY_DETECTED",
            Self::RequestCryptoReplayStoreUnavailable => "REQUEST_CRYPTO_REPLAY_STORE_UNAVAILABLE",
            Self::RequestCryptoReplayCapacityExceeded => "REQUEST_CRYPTO_REPLAY_CAPACITY_EXCEEDED",
            Self::ResponseCryptoEncoded => "RESPONSE_CRYPTO_ENCODED",
            Self::ResponseCryptoKeyUnavailable => "RESPONSE_CRYPTO_KEY_UNAVAILABLE",
            Self::ResponseCryptoEncodingFailed => "RESPONSE_CRYPTO_ENCODING_FAILED",
            Self::ResponseCryptoEnvelopeTooLarge => "RESPONSE_CRYPTO_ENVELOPE_TOO_LARGE",
            Self::OriginOutcomeUnknown => "ORIGIN_OUTCOME_UNKNOWN",
            Self::RequestIncomplete => "REQUEST_INCOMPLETE",
            Self::ClockUnavailable => "CLOCK_UNAVAILABLE",
            Self::IdentityStoreUnavailable => "IDENTITY_STORE_UNAVAILABLE",
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
