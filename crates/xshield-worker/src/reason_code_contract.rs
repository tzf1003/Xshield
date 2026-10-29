//! Reason-code contract between the edge audit producer and this publisher
//! (AGENTS.md "新增分支必须有稳定原因码、结构化审计及终态").
//!
//! Every `ReasonCode` the gateway can journal is listed once below. The list
//! feeds both an exhaustive `match` without a wildcard arm and the assertions,
//! so adding a variant to `xshield_core::audit::ReasonCode` fails compilation
//! here until someone lists it, which forces the new branch's code through this
//! review: its wire string must be unique, upper snake case and accepted by the
//! publisher's name validation, or every sealed segment containing it would be
//! refused at publication.

use super::valid_name;
use std::collections::BTreeSet;
use xshield_core::audit::ReasonCode;

macro_rules! reason_codes {
    ($($variant:ident),+ $(,)?) => {
        const ALL: &[ReasonCode] = &[$(ReasonCode::$variant),+];

        /// No wildcard arm: a new variant is a compile error until listed.
        const fn listed(code: ReasonCode) -> bool {
            match code {
                $(ReasonCode::$variant)|+ => true,
            }
        }
    };
}

reason_codes![
    AnonymousSessionCapacityExceeded,
    AnonymousSessionRateExceeded,
    AuthRequired,
    AuthBindingMismatch,
    AuthBindingValid,
    AuthEpochChanged,
    AuthCredentialGenerationChanged,
    AuthBindingRevoked,
    AuthSessionExpired,
    CapabilityMissing,
    OperationNotGranted,
    GrantCapacityExceeded,
    GrantExpiryInvalid,
    GrantIssuanceConflict,
    GrantIssued,
    GrantAlreadyIssued,
    GrantSourceIneligible,
    UiActionNotAvailable,
    UiEvidenceUnverified,
    TargetScopeMismatch,
    FieldNotAllowed,
    UiActionExpiryInvalid,
    UiActionIssued,
    UiActionAlreadyIssued,
    UiActionIssuanceConflict,
    UiActionCapacityExceeded,
    UiDescriptorConflict,
    PageRootSessionAllowed,
    PublicEntryAllowed,
    AuthEntryAllowed,
    FlowRootAllowed,
    UiActionAllowed,
    OperationNotMatched,
    ShareScopeMismatch,
    ShareIssued,
    ShareAlreadyIssued,
    ShareIssuanceConflict,
    ShareSourceIneligible,
    ShareCapacityExceeded,
    ServiceIdentityMismatch,
    ShareEntryAllowed,
    ServiceIdentityAllowed,
    SiteNotConfigured,
    SiteDisabled,
    SiteConfigUnavailable,
    SkippedBySiteUnavailable,
    AuditDurabilityFailed,
    AuditTailRecovered,
    AuditBarrierReopened,
    HostNotRouted,
    OriginForwardIntentRecorded,
    OriginResponseReceived,
    SensorAssetServed,
    SensorLoaderServed,
    SensorBootstrapServed,
    SensorBootstrapInvalid,
    SensorActionsDelivered,
    SensorActionsUnavailable,
    SensorObservationAccepted,
    SensorObservationInvalid,
    SensorHtmlInjected,
    SensorHtmlValidationFailed,
    ResponseBodyTooLarge,
    ResponseBufferCapacityExhausted,
    ResponseValidationFailed,
    EvidenceCaptureInvalid,
    EvidenceCaptureLimitExceeded,
    EvidenceCaptureCapacityExhausted,
    EvidenceCaptureUnavailable,
    RequestBodyTooLarge,
    WafHeaderBlocked,
    WafQueryBlocked,
    WafQueryInvalid,
    WafCookieTooLarge,
    SiteRateLimitExceeded,
    RequestBufferCapacityExhausted,
    RequestEnvelopeInvalid,
    RequestCryptoAuthenticationFailed,
    RequestCryptoDecoded,
    RequestCryptoObservedOpaque,
    RequestCryptoCompatibilityOpaque,
    RequestCryptoCompatibilityExpired,
    RequestCryptoBuildNotApproved,
    RequestCryptoKeyUnavailable,
    RequestCryptoMessageExpired,
    RequestCryptoMessageFromFuture,
    RequestCryptoReplayDetected,
    RequestCryptoReplayStoreUnavailable,
    RequestCryptoReplayCapacityExceeded,
    ResponseCryptoEncoded,
    ResponseCryptoKeyUnavailable,
    ResponseCryptoEncodingFailed,
    ResponseCryptoEnvelopeTooLarge,
    OriginOutcomeUnknown,
    RequestIncomplete,
    ClockUnavailable,
    IdentityStoreUnavailable,
    RequestNotConfigured,
];

fn upper_snake(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_uppercase())
        && value.bytes().last().is_some_and(|byte| byte != b'_')
        && !value.contains("__")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[test]
fn every_edge_reason_code_is_listed_stable_unique_and_publishable() {
    let mut seen = BTreeSet::new();
    for code in ALL {
        let wire = code.as_str();
        assert!(listed(*code));
        assert!(seen.insert(wire), "{wire} is used by two reason codes");
        assert!(upper_snake(wire), "{wire} is not a stable upper-snake code");
        assert!(valid_name(wire), "the publisher would refuse {wire}");
    }
    assert_eq!(seen.len(), ALL.len());
}

#[test]
fn reason_code_shape_check_rejects_unstable_spellings() {
    for bad in [
        "",
        "auth_required",
        "AUTH-REQUIRED",
        "AUTH__REQUIRED",
        "AUTH_",
        "_AUTH",
        "9AUTH",
    ] {
        assert!(!upper_snake(bad), "{bad:?}");
    }
    assert!(upper_snake("AUTH_REQUIRED"));
    assert!(!valid_name(&"A".repeat(129)));
}
