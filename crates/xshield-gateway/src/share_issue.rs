//! Committed limited-share issuance for validated response adapters.

use chrono::{DateTime, SecondsFormat};
use serde_json::{Value, json};
use std::{error::Error, fmt};
use xshield_core::{
    access::{ShareGrantDraft, ShareIssueAuthority},
    audit::ReasonCode,
    domain::{
        EventId, IssuanceKey, OperationId, PolicyRevision, RequestId, ResourceType, ShareGrantId,
        ViewProfile,
    },
    grant::ResourceKeyHmac,
    identity::{AuthSnapshot, UnixSeconds},
};
use xshield_postgres::{
    PostgresIdentityStore, ShareGrantPersistence, ShareGrantWriteOutcome, StoreError,
};

use crate::share_token::{ShareToken, ShareTokenError, ShareTokenIssuer, lower_hex};

/// Exact, validated response facts required to issue one limited share.
///
/// A versioned response adapter constructs this only after the source response
/// is completely validated. `event_id` and `issuance_key` must remain stable
/// across retries, together with the request context and issuance time. All
/// resource and policy values come from trusted mappings. The store separately
/// checks live expiry and revocation before every commit or replay.
pub struct ShareIssueRequest<'a> {
    /// Immutable identity captured before the source request was sent.
    pub snapshot: &'a AuthSnapshot,
    /// Existing resource grant and active rule authorizing the share.
    pub authority: &'a ShareIssueAuthority,
    /// Idempotency key derived from the approved response item and rule.
    pub issuance_key: IssuanceKey,
    /// Resource type inherited from the exact source grant.
    pub resource_type: ResourceType,
    /// Tenant-isolated resource digest inherited from the source grant.
    pub resource_key: ResourceKeyHmac,
    /// Read-only operation exposed at the share entry.
    pub operation_id: OperationId,
    /// Limited response view exposed at the share entry.
    pub view_profile: ViewProfile,
    /// Frozen policy revision used by the source request.
    pub policy_revision: PolicyRevision,
    /// Share expiry already bounded by the response adapter.
    pub expires_at: UnixSeconds,
    /// Stable outbox event ID for this issuance retry family.
    pub event_id: &'a EventId,
    /// Original edge request that obtained the validated issuance response.
    pub request_id: &'a RequestId,
    /// Internal lowercase W3C trace identifier from that request.
    pub trace_id: &'a str,
    /// Trusted server time frozen before the short transaction.
    pub now: UnixSeconds,
    /// Configured active-share ceiling for the issuer binding.
    pub max_active_shares: u32,
}

/// Post-commit result safe for a response adapter to translate.
#[derive(Debug)]
pub enum ShareIssueResponse {
    /// Exact grant committed, with the plaintext credential available for release.
    Granted {
        /// Stable persisted share ID.
        share_id: ShareGrantId,
        /// Opaque credential; its formatter is always redacted.
        token: ShareToken,
        /// True when this call created the row, false for an exact replay.
        created: bool,
        /// Committed expiry, equal to the exact replay request on retries.
        expires_at: UnixSeconds,
    },
    /// Deterministic policy or capacity outcome; no credential is returned.
    Denied {
        /// Stable reason for request-stage audit and response mapping.
        reason_code: ReasonCode,
    },
}

/// Joins secret-backed credential derivation to the qualified `PostgreSQL` write.
pub struct ShareIssueApi<'a> {
    store: &'a PostgresIdentityStore,
    tokens: &'a ShareTokenIssuer,
}

impl<'a> ShareIssueApi<'a> {
    /// Borrows the authoritative store and purpose-separated token issuer.
    #[must_use]
    pub const fn new(store: &'a PostgresIdentityStore, tokens: &'a ShareTokenIssuer) -> Self {
        Self { store, tokens }
    }

    /// Issues or exactly replays one limited share.
    ///
    /// The plaintext token becomes observable only after the `ShareGrant` and
    /// `share.issued` outbox event commit atomically. Deterministic denials erase
    /// the derived token and return a stable reason without releasing it.
    ///
    /// # Errors
    /// Returns [`ShareIssueError`] when cryptography, generated identifiers,
    /// command validation, or the authoritative transaction fails. Callers must
    /// treat every error as no releasable credential.
    pub async fn issue(
        &self,
        request: ShareIssueRequest<'_>,
    ) -> Result<ShareIssueResponse, ShareIssueError> {
        let share_id = generated_share_id(request.event_id)?;
        let envelope = issuance_envelope(&request, &share_id)?;
        let token = self.tokens.issue(
            request.snapshot.tenant_id(),
            request.snapshot.site_id(),
            &request.issuance_key,
        )?;
        let token_fingerprint = self.tokens.fingerprint(
            request.snapshot.tenant_id(),
            request.snapshot.site_id(),
            &token,
        )?;
        let draft = ShareGrantDraft {
            share_id,
            issuance_key: request.issuance_key,
            token_fingerprint,
            resource_type: request.resource_type,
            resource_key: request.resource_key,
            operation_id: request.operation_id,
            view_profile: request.view_profile,
            policy_revision: request.policy_revision,
            expires_at: request.expires_at,
        };
        let outcome = self
            .store
            .issue_share_grant(ShareGrantPersistence::new(
                request.snapshot,
                &draft,
                request.authority,
                request.event_id,
                &envelope,
                request.now,
                request.max_active_shares,
            )?)
            .await?;

        Ok(response(outcome, token, draft.expires_at))
    }
}

fn response(
    outcome: ShareGrantWriteOutcome,
    token: ShareToken,
    expires_at: UnixSeconds,
) -> ShareIssueResponse {
    match outcome {
        ShareGrantWriteOutcome::Created(share_id) => ShareIssueResponse::Granted {
            share_id,
            token,
            created: true,
            expires_at,
        },
        ShareGrantWriteOutcome::Existing(share_id) => ShareIssueResponse::Granted {
            share_id,
            token,
            created: false,
            expires_at,
        },
        denied => ShareIssueResponse::Denied {
            reason_code: denied.reason_code(),
        },
    }
}

fn generated_share_id(event_id: &EventId) -> Result<ShareGrantId, ShareIssueError> {
    // The stable event owns one issuance. Prefix separation preserves the UUID
    // identity while keeping share references distinct from audit references.
    let suffix = event_id
        .as_str()
        .strip_prefix("ev_")
        .ok_or(ShareIssueError::GeneratedId)?;
    ShareGrantId::parse(format!("share_{suffix}")).map_err(|_| ShareIssueError::GeneratedId)
}

fn issuance_envelope(
    request: &ShareIssueRequest<'_>,
    share_id: &ShareGrantId,
) -> Result<Value, ShareIssueError> {
    if request.trace_id.len() != 32
        || !request
            .trace_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || request.snapshot.epoch().value() == 0
        || i64::try_from(request.snapshot.epoch().value()).is_err()
        || !request
            .expires_at
            .value()
            .checked_sub(request.now.value())
            .is_some_and(|ttl| (1..=86_400).contains(&ttl))
        || i64::try_from(request.expires_at.value()).is_err()
        || request.max_active_shares == 0
    {
        return Err(ShareIssueError::InvalidAudit);
    }
    let timestamp = i64::try_from(request.now.value())
        .ok()
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        .ok_or(ShareIssueError::InvalidAudit)?
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    if timestamp.len() != 20 {
        return Err(ShareIssueError::InvalidAudit);
    }
    let span = request
        .trace_id
        .get(..16)
        .ok_or(ShareIssueError::InvalidAudit)?;
    Ok(json!({
        "schema_version": 3, "event_type": "share.issued", "event_id": request.event_id.as_str(),
        "tenant_id": request.snapshot.tenant_id().as_str(), "site_id": request.snapshot.site_id().as_str(),
        "request_id": request.request_id.as_str(), "trace_id": request.trace_id, "span_id": span,
        "producer_id": "gateway-share-grant", "producer_boot_id": request.event_id.as_str(),
        "producer_seq": 1, "request_seq": 1, "occurred_at": timestamp, "observed_at": timestamp,
        "policy_revision": request.policy_revision.as_str(), "example_only": false,
        "sensitivity": "SENSITIVE", "evidence_refs": [], "cause_event_ids": [],
        "integrity": {"state": "pending", "previous_hash": null, "event_hash": null},
        "payload": {
            "stage": "share_grant", "outcome": "PASS", "reason_code": ReasonCode::ShareIssued.as_str(),
            "share_id": share_id.as_str(), "issuer_binding_id": request.snapshot.binding_id().as_str(),
            "issuer_auth_epoch": request.snapshot.epoch().value(),
            "issuer_grant_id": request.authority.resource_grant_id.as_str(),
            "issuance_rule_id": request.authority.rule_id.as_str(),
            "issuer_operation_id": request.authority.operation_id.as_str(),
            "issuer_view_profile": request.authority.view_profile.as_str(),
            "resource_type": request.resource_type.as_str(), "resource_key_hmac": lower_hex(request.resource_key.as_bytes()),
            "operation_id": request.operation_id.as_str(), "view_profile": request.view_profile.as_str(),
            "method": "GET", "use_policy": "reusable_read",
            "issued_at_unix": request.now.value(), "expires_at_unix": request.expires_at.value(),
        }
    }))
}

/// Failure before a limited-share credential can be released.
#[derive(Debug)]
pub enum ShareIssueError {
    /// Credential derivation or fingerprinting failed.
    Token(ShareTokenError),
    /// The stable event ID could not be converted into a share identifier.
    GeneratedId,
    /// Issuance context, trace, or frozen time violates the audit contract.
    InvalidAudit,
    /// Command validation or the authoritative transaction failed.
    Store(StoreError),
}

impl fmt::Display for ShareIssueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Token(_) => "share credential generation failed",
            Self::GeneratedId => "share identifier generation failed",
            Self::InvalidAudit => "invalid share issuance audit context",
            Self::Store(_) => "share issuance transaction failed",
        })
    }
}

impl Error for ShareIssueError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Token(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::GeneratedId | Self::InvalidAudit => None,
        }
    }
}

impl From<ShareTokenError> for ShareIssueError {
    fn from(value: ShareTokenError) -> Self {
        Self::Token(value)
    }
}

impl ShareIssueError {
    /// Stable failure classification for the calling request's terminal audit.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::Token(_) | Self::Store(_) => ReasonCode::IdentityStoreUnavailable,
            Self::GeneratedId | Self::InvalidAudit => ReasonCode::ResponseValidationFailed,
        }
    }
}

impl From<StoreError> for ShareIssueError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::domain::{SiteId, TenantId};

    fn token() -> ShareToken {
        ShareTokenIssuer::from_hex(&"11".repeat(32), &"22".repeat(32))
            .unwrap()
            .issue(
                &TenantId::parse("tenant_test").unwrap(),
                &SiteId::parse("site_test").unwrap(),
                &IssuanceKey::parse("issuance-test").unwrap(),
            )
            .unwrap()
    }

    #[test]
    fn generated_ids_are_valid_and_unique() {
        let event = EventId::parse(format!("ev_{}", uuid::Uuid::now_v7())).unwrap();
        let first = generated_share_id(&event).unwrap();
        assert_eq!(first, generated_share_id(&event).unwrap());
        let second =
            generated_share_id(&EventId::parse(format!("ev_{}", uuid::Uuid::now_v7())).unwrap())
                .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn releases_tokens_only_for_committed_or_replayed_grants() {
        let share_id =
            generated_share_id(&EventId::parse(format!("ev_{}", uuid::Uuid::now_v7())).unwrap())
                .unwrap();
        let expiry = UnixSeconds::new(1_900_000_000);
        assert!(matches!(
            response(
                ShareGrantWriteOutcome::Created(share_id.clone()),
                token(),
                expiry
            ),
            ShareIssueResponse::Granted {
                share_id: actual,
                created: true,
                expires_at,
                ..
            } if actual == share_id && expires_at == expiry
        ));
        assert!(matches!(
            response(ShareGrantWriteOutcome::Existing(share_id), token(), expiry),
            ShareIssueResponse::Granted { created: false, .. }
        ));
        assert!(matches!(
            response(ShareGrantWriteOutcome::Ineligible, token(), expiry),
            ShareIssueResponse::Denied {
                reason_code: ReasonCode::ShareSourceIneligible
            }
        ));
    }
}
