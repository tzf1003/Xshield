//! Pure identity binding rules for WAF sessions and verified business credentials.

use crate::{
    audit::ReasonCode,
    domain::{AuthBindingId, SiteId, TenantId, WafSessionId, parse_lower_hex_32},
};
use std::{collections::BTreeMap, fmt};

/// Server time represented as whole Unix seconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixSeconds(u64);

impl UnixSeconds {
    /// Creates a timestamp from the trusted server clock.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns whole Unix seconds for persistence adapters.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Monotonic identity generation within one binding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CredentialGeneration(u64);

impl CredentialGeneration {
    /// Creates a generation counter.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the monotonic counter for persistence comparisons.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Epoch that invalidates grants when identity or authorization context changes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuthEpoch(u64);

impl AuthEpoch {
    /// Creates an identity epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the epoch counter for persistence comparisons.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Authentication credential location selected by the site profile.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CredentialSlot {
    /// The effective business authentication cookie.
    Cookie,
    /// The effective `Authorization` bearer token.
    Bearer,
    /// A body-carried token for an explicitly configured operation.
    BodyToken,
}

impl CredentialSlot {
    /// Returns the database contract value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cookie => "cookie",
            Self::Bearer => "bearer",
            Self::BodyToken => "body_token",
        }
    }
}

/// Tenant-isolated fingerprint of one verified credential.
///
/// The original credential is never stored in this type or exposed through
/// `Debug` or `Display`.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CredentialFingerprint([u8; 32]);

impl CredentialFingerprint {
    /// Wraps a fingerprint produced by a trusted tenant-isolated HMAC adapter.
    #[must_use]
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Parses a lowercase 64-character hexadecimal HMAC fingerprint.
    ///
    /// # Errors
    /// Returns [`IdentityInputError`] for malformed or uppercase input.
    pub fn parse(value: &str) -> Result<Self, IdentityInputError> {
        parse_lower_hex_32(value)
            .map(Self)
            .ok_or(IdentityInputError::CredentialFingerprint)
    }

    /// Borrows the tenant-isolated fingerprint bytes for persistence.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CredentialFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialFingerprint([REDACTED])")
    }
}

/// Invalid data rejected while constructing identity domain values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityInputError {
    /// Credential fingerprint is not canonical lowercase SHA-256/HMAC hex.
    CredentialFingerprint,
    /// An authenticated binding has no effective verified credential.
    EmptyCredentialSet,
    /// Principal reference is empty, oversized, or contains control data.
    PrincipalRef,
}

impl fmt::Display for IdentityInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CredentialFingerprint => "invalid credential fingerprint",
            Self::EmptyCredentialSet => "authenticated binding requires a credential",
            Self::PrincipalRef => "invalid principal reference",
        })
    }
}

impl std::error::Error for IdentityInputError {}

/// A newly issued WAF session with no business identity or grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnonymousSession {
    session_id: WafSessionId,
    site_id: SiteId,
    absolute_expires_at: UnixSeconds,
}

impl AnonymousSession {
    /// Creates an empty anonymous session. It performs no external effects.
    #[must_use]
    pub const fn new(
        session_id: WafSessionId,
        site_id: SiteId,
        absolute_expires_at: UnixSeconds,
    ) -> Self {
        Self {
            session_id,
            site_id,
            absolute_expires_at,
        }
    }

    /// Always reports zero grants; only verified transitions can create a ledger.
    #[must_use]
    pub const fn grant_count(&self) -> usize {
        0
    }

    /// Rejects an authenticated operation without changing this session.
    ///
    /// # Errors
    /// Always returns [`IdentityDenied::AuthRequired`].
    pub const fn require_authenticated(&self) -> Result<AuthSnapshot, IdentityDenied> {
        Err(IdentityDenied::AuthRequired)
    }

    /// Verifies that this anonymous session is usable for the requested site.
    ///
    /// # Errors
    /// Returns [`IdentityDenied`] for cross-site use or server-side expiry.
    pub fn verify(&self, site: &SiteId, now: UnixSeconds) -> Result<(), IdentityDenied> {
        if &self.site_id != site {
            return Err(IdentityDenied::BindingMismatch);
        }
        if now >= self.absolute_expires_at {
            return Err(IdentityDenied::SessionExpired);
        }
        Ok(())
    }

    /// Returns the opaque server-side WAF session ID.
    #[must_use]
    pub const fn session_id(&self) -> &WafSessionId {
        &self.session_id
    }
}

/// Active binding between a WAF session and the exact effective credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthBinding {
    binding_id: AuthBindingId,
    session_id: WafSessionId,
    tenant_id: TenantId,
    site_id: SiteId,
    principal_ref: String,
    epoch: AuthEpoch,
    generation: CredentialGeneration,
    credentials: BTreeMap<CredentialSlot, CredentialFingerprint>,
    absolute_expires_at: UnixSeconds,
    status: BindingStatus,
}

impl AuthBinding {
    /// Creates a binding from credentials already verified by a site adapter.
    ///
    /// # Errors
    /// Rejects an empty credential set or invalid principal reference.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding_id: AuthBindingId,
        session_id: WafSessionId,
        tenant_id: TenantId,
        site_id: SiteId,
        principal_ref: impl Into<String>,
        epoch: AuthEpoch,
        generation: CredentialGeneration,
        credentials: BTreeMap<CredentialSlot, CredentialFingerprint>,
        absolute_expires_at: UnixSeconds,
    ) -> Result<Self, IdentityInputError> {
        let principal_ref = validate_principal_ref(principal_ref.into())?;
        if credentials.is_empty() {
            return Err(IdentityInputError::EmptyCredentialSet);
        }
        Ok(Self {
            binding_id,
            session_id,
            tenant_id,
            site_id,
            principal_ref,
            epoch,
            generation,
            credentials,
            absolute_expires_at,
            status: BindingStatus::Active,
        })
    }

    /// Matches the complete credential combination and returns an immutable snapshot.
    ///
    /// # Errors
    /// Returns [`IdentityDenied`] for scope mismatch, expiry, or any missing,
    /// substituted, or additional credential.
    pub fn verify(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        session: &WafSessionId,
        credentials: &BTreeMap<CredentialSlot, CredentialFingerprint>,
        now: UnixSeconds,
    ) -> Result<AuthSnapshot, IdentityDenied> {
        if self.status == BindingStatus::Revoked {
            return Err(IdentityDenied::BindingRevoked);
        }
        if &self.tenant_id != tenant
            || &self.site_id != site
            || &self.session_id != session
            || &self.credentials != credentials
        {
            return Err(IdentityDenied::BindingMismatch);
        }
        if now >= self.absolute_expires_at {
            return Err(IdentityDenied::SessionExpired);
        }
        Ok(AuthSnapshot {
            binding_id: self.binding_id.clone(),
            tenant_id: self.tenant_id.clone(),
            site_id: self.site_id.clone(),
            principal_ref: self.principal_ref.clone(),
            epoch: self.epoch,
            generation: self.generation,
        })
    }

    /// Replaces verified credentials while preserving principal, scope, and epoch.
    ///
    /// The captured counters are the expected values for a persistence-layer
    /// compare-and-swap. The absolute WAF session lease is not extended.
    ///
    /// # Errors
    /// Returns [`IdentityTransitionError`] for a stale snapshot, revoked
    /// binding, empty credential set, or exhausted generation counter.
    pub fn refresh_same_context(
        &mut self,
        snapshot: &AuthSnapshot,
        credentials: BTreeMap<CredentialSlot, CredentialFingerprint>,
        now: UnixSeconds,
    ) -> Result<IdentityTransition, IdentityTransitionError> {
        self.validate_snapshot(snapshot, now)?;
        if credentials.is_empty() {
            return Err(IdentityInputError::EmptyCredentialSet.into());
        }
        let next_generation = self
            .generation
            .0
            .checked_add(1)
            .ok_or(IdentityTransitionError::CounterExhausted)?;
        let transition = IdentityTransition {
            kind: IdentityTransitionKind::SameContextRefresh,
            previous_epoch: self.epoch,
            current_epoch: self.epoch,
            previous_generation: self.generation,
            current_generation: CredentialGeneration(next_generation),
        };
        self.credentials = credentials;
        self.generation = transition.current_generation;
        Ok(transition)
    }

    /// Rebinds the WAF session to a newly verified principal or permission context.
    ///
    /// Incrementing the epoch makes every grant keyed by the prior snapshot
    /// immediately ineligible, even before asynchronous cleanup runs.
    ///
    /// # Errors
    /// Returns [`IdentityTransitionError`] for invalid input, a stale snapshot,
    /// revoked binding, or exhausted counters.
    pub fn switch_context(
        &mut self,
        snapshot: &AuthSnapshot,
        principal_ref: impl Into<String>,
        credentials: BTreeMap<CredentialSlot, CredentialFingerprint>,
        now: UnixSeconds,
    ) -> Result<IdentityTransition, IdentityTransitionError> {
        self.validate_snapshot(snapshot, now)?;
        let principal_ref = validate_principal_ref(principal_ref.into())?;
        if credentials.is_empty() {
            return Err(IdentityInputError::EmptyCredentialSet.into());
        }
        let next_epoch = self
            .epoch
            .0
            .checked_add(1)
            .ok_or(IdentityTransitionError::CounterExhausted)?;
        let next_generation = self
            .generation
            .0
            .checked_add(1)
            .ok_or(IdentityTransitionError::CounterExhausted)?;
        let transition = IdentityTransition {
            kind: IdentityTransitionKind::ContextChanged,
            previous_epoch: self.epoch,
            current_epoch: AuthEpoch(next_epoch),
            previous_generation: self.generation,
            current_generation: CredentialGeneration(next_generation),
        };
        self.principal_ref = principal_ref;
        self.credentials = credentials;
        self.epoch = transition.current_epoch;
        self.generation = transition.current_generation;
        Ok(transition)
    }

    /// Permanently revokes this in-memory binding state.
    pub fn revoke(&mut self) {
        self.status = BindingStatus::Revoked;
    }

    /// Checks whether a captured request identity is still current.
    ///
    /// Response handlers call this before issuing grants so a late response
    /// cannot write into a newer identity ledger.
    ///
    /// # Errors
    /// Returns [`IdentityDenied`] when scope, epoch, generation, or status changed.
    pub fn validate_snapshot(
        &self,
        snapshot: &AuthSnapshot,
        now: UnixSeconds,
    ) -> Result<(), IdentityDenied> {
        self.validate_epoch(snapshot, now)?;
        if self.generation != snapshot.generation {
            return Err(IdentityDenied::CredentialGenerationChanged);
        }
        Ok(())
    }

    /// Checks the stable identity epoch while allowing same-context refreshes.
    ///
    /// Grant authorization and response issuance use this check so a verified
    /// credential rotation preserves the ledger while an account switch does not.
    ///
    /// # Errors
    /// Returns [`IdentityDenied`] when scope, epoch, expiry, or status changed.
    pub fn validate_epoch(
        &self,
        snapshot: &AuthSnapshot,
        now: UnixSeconds,
    ) -> Result<(), IdentityDenied> {
        if self.status == BindingStatus::Revoked {
            return Err(IdentityDenied::BindingRevoked);
        }
        if self.binding_id != snapshot.binding_id
            || self.tenant_id != snapshot.tenant_id
            || self.site_id != snapshot.site_id
        {
            return Err(IdentityDenied::BindingMismatch);
        }
        if now >= self.absolute_expires_at {
            return Err(IdentityDenied::SessionExpired);
        }
        if self.epoch != snapshot.epoch {
            return Err(IdentityDenied::EpochChanged);
        }
        if self.principal_ref != snapshot.principal_ref {
            return Err(IdentityDenied::BindingMismatch);
        }
        Ok(())
    }

    /// Returns the current identity epoch.
    #[must_use]
    pub const fn epoch(&self) -> AuthEpoch {
        self.epoch
    }

    /// Returns the current credential generation.
    #[must_use]
    pub const fn generation(&self) -> CredentialGeneration {
        self.generation
    }

    /// Returns the binding lifecycle state.
    #[must_use]
    pub const fn status(&self) -> BindingStatus {
        self.status
    }

    /// Returns the server-enforced absolute session expiry.
    #[must_use]
    pub const fn absolute_expires_at(&self) -> UnixSeconds {
        self.absolute_expires_at
    }

    /// Returns the server-issued binding identifier.
    #[must_use]
    pub const fn binding_id(&self) -> &AuthBindingId {
        &self.binding_id
    }

    /// Returns the tenant scope fixed when the binding was established.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the site scope fixed when the binding was established.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the verified non-secret principal reference.
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// Returns the exact credential fingerprints for the current generation.
    #[must_use]
    pub const fn credentials(&self) -> &BTreeMap<CredentialSlot, CredentialFingerprint> {
        &self.credentials
    }
}

fn validate_principal_ref(value: String) -> Result<String, IdentityInputError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(IdentityInputError::PrincipalRef);
    }
    Ok(value)
}

/// Lifecycle state that affects request and response authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingStatus {
    /// Binding can verify requests and snapshots.
    Active,
    /// Binding rejects all later request and response work.
    Revoked,
}

/// Security meaning of an accepted identity transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityTransitionKind {
    /// Credential rotation with the same principal and authorization context.
    SameContextRefresh,
    /// Principal or authorization context changed and grants must not carry over.
    ContextChanged,
}

/// Auditable before/after counters returned by a successful transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityTransition {
    /// Kind of verified transition.
    pub kind: IdentityTransitionKind,
    /// Epoch before the transition.
    pub previous_epoch: AuthEpoch,
    /// Epoch after the transition.
    pub current_epoch: AuthEpoch,
    /// Credential generation before the transition.
    pub previous_generation: CredentialGeneration,
    /// Credential generation after the transition.
    pub current_generation: CredentialGeneration,
}

/// Rejected identity state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityTransitionError {
    /// New binding data is invalid.
    InvalidInput(IdentityInputError),
    /// The captured request identity is stale or belongs to another binding.
    Denied(IdentityDenied),
    /// An epoch or generation counter cannot advance safely.
    CounterExhausted,
}

impl From<IdentityInputError> for IdentityTransitionError {
    fn from(value: IdentityInputError) -> Self {
        Self::InvalidInput(value)
    }
}

impl From<IdentityDenied> for IdentityTransitionError {
    fn from(value: IdentityDenied) -> Self {
        Self::Denied(value)
    }
}

impl fmt::Display for IdentityTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(error) => error.fmt(formatter),
            Self::Denied(error) => error.fmt(formatter),
            Self::CounterExhausted => formatter.write_str("identity counter exhausted"),
        }
    }
}

impl std::error::Error for IdentityTransitionError {}

/// Immutable identity captured for one request and later response commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthSnapshot {
    binding_id: AuthBindingId,
    tenant_id: TenantId,
    site_id: SiteId,
    principal_ref: String,
    epoch: AuthEpoch,
    generation: CredentialGeneration,
}

impl AuthSnapshot {
    /// Returns the binding ID used by grant keys and response commit checks.
    #[must_use]
    pub const fn binding_id(&self) -> &AuthBindingId {
        &self.binding_id
    }

    /// Returns the captured identity epoch.
    #[must_use]
    pub const fn epoch(&self) -> AuthEpoch {
        self.epoch
    }

    /// Returns the captured credential generation.
    #[must_use]
    pub const fn generation(&self) -> CredentialGeneration {
        self.generation
    }

    /// Returns the non-secret principal reference.
    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    /// Returns the captured tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the captured site scope.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }
}

/// Deterministic identity rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityDenied {
    /// No authenticated binding exists for an operation that requires one.
    AuthRequired,
    /// Session, scope, or credential combination differs from the binding.
    BindingMismatch,
    /// The server-side absolute lease has expired.
    SessionExpired,
    /// The binding was explicitly revoked.
    BindingRevoked,
    /// The identity context changed after the request snapshot was captured.
    EpochChanged,
    /// Another verified refresh advanced the credential generation.
    CredentialGenerationChanged,
}

impl IdentityDenied {
    /// Maps the denial to its stable audit reason code.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Self::AuthRequired => ReasonCode::AuthRequired,
            Self::BindingMismatch => ReasonCode::AuthBindingMismatch,
            Self::SessionExpired => ReasonCode::AuthSessionExpired,
            Self::BindingRevoked => ReasonCode::AuthBindingRevoked,
            Self::EpochChanged => ReasonCode::AuthEpochChanged,
            Self::CredentialGenerationChanged => ReasonCode::AuthCredentialGenerationChanged,
        }
    }
}

impl fmt::Display for IdentityDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code().as_str())
    }
}

impl std::error::Error for IdentityDenied {}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn credentials(value: &str) -> BTreeMap<CredentialSlot, CredentialFingerprint> {
        [(
            CredentialSlot::Cookie,
            CredentialFingerprint::parse(value).unwrap(),
        )]
        .into_iter()
        .collect()
    }

    fn binding() -> AuthBinding {
        AuthBinding::new(
            AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
            WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
            TenantId::parse("tenant_a").unwrap(),
            SiteId::parse("site_a").unwrap(),
            "principal_a",
            AuthEpoch::new(4),
            CredentialGeneration::new(2),
            credentials(A),
            UnixSeconds::new(200),
        )
        .unwrap()
    }

    #[test]
    fn new_session_is_anonymous_and_empty() {
        let session = AnonymousSession::new(
            WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000003").unwrap(),
            SiteId::parse("site_a").unwrap(),
            UnixSeconds::new(200),
        );

        assert_eq!(session.grant_count(), 0);
        assert_eq!(
            session.require_authenticated(),
            Err(IdentityDenied::AuthRequired)
        );
        assert!(
            session
                .verify(&SiteId::parse("site_a").unwrap(), UnixSeconds::new(199))
                .is_ok()
        );
        assert_eq!(
            session.verify(&SiteId::parse("site_b").unwrap(), UnixSeconds::new(100)),
            Err(IdentityDenied::BindingMismatch)
        );
        assert_eq!(
            session.verify(&SiteId::parse("site_a").unwrap(), UnixSeconds::new(200)),
            Err(IdentityDenied::SessionExpired)
        );
    }

    #[test]
    fn exact_bound_combination_creates_snapshot() {
        let binding = binding();
        let snapshot = binding
            .verify(
                &TenantId::parse("tenant_a").unwrap(),
                &SiteId::parse("site_a").unwrap(),
                &WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
                &credentials(A),
                UnixSeconds::new(199),
            )
            .unwrap();

        assert_eq!(snapshot.principal_ref(), "principal_a");
        assert_eq!(snapshot.epoch(), AuthEpoch::new(4));
    }

    #[test]
    fn rejects_substitution_extra_credentials_scope_and_expiry() {
        let binding = binding();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let session = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000002").unwrap();
        assert_eq!(
            binding.verify(
                &tenant,
                &site,
                &session,
                &credentials(B),
                UnixSeconds::new(100)
            ),
            Err(IdentityDenied::BindingMismatch)
        );

        let mut conflicting = credentials(A);
        conflicting.insert(
            CredentialSlot::Bearer,
            CredentialFingerprint::parse(B).unwrap(),
        );
        assert_eq!(
            binding.verify(
                &tenant,
                &site,
                &session,
                &conflicting,
                UnixSeconds::new(100)
            ),
            Err(IdentityDenied::BindingMismatch)
        );
        assert_eq!(
            binding.verify(
                &TenantId::parse("tenant_b").unwrap(),
                &site,
                &session,
                &credentials(A),
                UnixSeconds::new(100),
            ),
            Err(IdentityDenied::BindingMismatch)
        );
        assert_eq!(
            binding.verify(
                &tenant,
                &site,
                &session,
                &credentials(A),
                UnixSeconds::new(200)
            ),
            Err(IdentityDenied::SessionExpired)
        );
    }

    #[test]
    fn fingerprint_is_canonical_and_redacted() {
        assert!(CredentialFingerprint::parse(A).is_ok());
        assert!(CredentialFingerprint::parse(&A.to_uppercase()).is_err());
        assert_eq!(
            format!("{:?}", CredentialFingerprint::parse(A).unwrap()),
            "CredentialFingerprint([REDACTED])"
        );
    }

    #[test]
    fn refresh_advances_only_generation_and_rejects_late_response() {
        let mut binding = binding();
        let snapshot = binding
            .verify(
                &TenantId::parse("tenant_a").unwrap(),
                &SiteId::parse("site_a").unwrap(),
                &WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
                &credentials(A),
                UnixSeconds::new(100),
            )
            .unwrap();

        let transition = binding
            .refresh_same_context(&snapshot, credentials(C), UnixSeconds::new(100))
            .unwrap();
        assert_eq!(transition.kind, IdentityTransitionKind::SameContextRefresh);
        assert_eq!(transition.previous_epoch, transition.current_epoch);
        assert_eq!(binding.epoch(), AuthEpoch::new(4));
        assert_eq!(binding.generation(), CredentialGeneration::new(3));
        assert_eq!(
            binding.refresh_same_context(&snapshot, credentials(A), UnixSeconds::new(100)),
            Err(IdentityTransitionError::Denied(
                IdentityDenied::CredentialGenerationChanged
            ))
        );
        assert_eq!(
            binding.validate_snapshot(&snapshot, UnixSeconds::new(100)),
            Err(IdentityDenied::CredentialGenerationChanged)
        );
        assert_eq!(
            binding.validate_snapshot(&snapshot, UnixSeconds::new(200)),
            Err(IdentityDenied::SessionExpired)
        );
    }

    #[test]
    fn context_switch_advances_epoch_and_invalidates_old_snapshot() {
        let mut binding = binding();
        let snapshot = binding
            .verify(
                &TenantId::parse("tenant_a").unwrap(),
                &SiteId::parse("site_a").unwrap(),
                &WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
                &credentials(A),
                UnixSeconds::new(100),
            )
            .unwrap();

        let transition = binding
            .switch_context(
                &snapshot,
                "principal_b",
                credentials(B),
                UnixSeconds::new(100),
            )
            .unwrap();
        assert_eq!(transition.kind, IdentityTransitionKind::ContextChanged);
        assert_eq!(binding.epoch(), AuthEpoch::new(5));
        assert_eq!(binding.generation(), CredentialGeneration::new(3));
        assert_eq!(
            binding.validate_snapshot(&snapshot, UnixSeconds::new(100)),
            Err(IdentityDenied::EpochChanged)
        );
    }

    #[test]
    fn revocation_stops_request_and_response_paths() {
        let mut binding = binding();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let session = WafSessionId::parse("ses_018f2a3b-4c5d-7000-8000-000000000002").unwrap();
        let snapshot = binding
            .verify(
                &tenant,
                &site,
                &session,
                &credentials(A),
                UnixSeconds::new(100),
            )
            .unwrap();

        binding.revoke();
        assert_eq!(binding.status(), BindingStatus::Revoked);
        assert_eq!(
            binding.verify(
                &tenant,
                &site,
                &session,
                &credentials(A),
                UnixSeconds::new(100)
            ),
            Err(IdentityDenied::BindingRevoked)
        );
        assert_eq!(
            binding.validate_snapshot(&snapshot, UnixSeconds::new(100)),
            Err(IdentityDenied::BindingRevoked)
        );
    }
}
