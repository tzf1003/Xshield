//! Committed limited-share issuance for validated response adapters.

use serde_json::Value;
use std::{error::Error, fmt};
use uuid::Uuid;
use xshield_core::{
    access::{ShareGrantDraft, ShareIssueAuthority},
    audit::ReasonCode,
    domain::{
        EventId, IssuanceKey, OperationId, PolicyRevision, ResourceType, ShareGrantId, ViewProfile,
    },
    grant::ResourceKeyHmac,
    identity::{AuthSnapshot, UnixSeconds},
};
use xshield_postgres::{
    PostgresIdentityStore, ShareGrantPersistence, ShareGrantWriteOutcome, StoreError,
};

use crate::share_token::{ShareToken, ShareTokenError, ShareTokenIssuer};

/// Exact, validated response facts required to issue one limited share.
///
/// A versioned response adapter constructs this only after the source response
/// is completely validated. `event_id` and `issuance_key` must remain stable
/// across retries; all resource and policy values come from trusted mappings.
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
    /// Complete validated v3 audit envelope persisted with the share.
    pub event_envelope: &'a Value,
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
            share_id: generated_share_id()?,
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
                request.event_envelope,
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

fn generated_share_id() -> Result<ShareGrantId, ShareIssueError> {
    ShareGrantId::parse(format!("share_{}", Uuid::now_v7()))
        .map_err(|_| ShareIssueError::GeneratedId)
}

/// Failure before a limited-share credential can be released.
#[derive(Debug)]
pub enum ShareIssueError {
    /// Credential derivation or fingerprinting failed.
    Token(ShareTokenError),
    /// The platform UUID generator returned an invalid identifier shape.
    GeneratedId,
    /// Command validation or the authoritative transaction failed.
    Store(StoreError),
}

impl fmt::Display for ShareIssueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Token(_) => "share credential generation failed",
            Self::GeneratedId => "share identifier generation failed",
            Self::Store(_) => "share issuance transaction failed",
        })
    }
}

impl Error for ShareIssueError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Token(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::GeneratedId => None,
        }
    }
}

impl From<ShareTokenError> for ShareIssueError {
    fn from(value: ShareTokenError) -> Self {
        Self::Token(value)
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
        let first = generated_share_id().unwrap();
        let second = generated_share_id().unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn releases_tokens_only_for_committed_or_replayed_grants() {
        let share_id = generated_share_id().unwrap();
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
