//! Pure model-evaluation admission boundary.
//!
//! A model-evaluation admission only reserves bounded provider-call capacity
//! for one tenant/site. It is deliberately separate from business admission,
//! evidence access, approvals, grants, and policy publication. Persistence
//! adapters own the durable lease token and trusted database clock.

use crate::domain::{ModelCallId, PolicyRevision, RequestId, SiteId, TenantId};
use std::fmt;

/// Immutable identity of one provider-call admission attempt.
///
/// The trusted worker creates this value before it writes model evidence. The
/// runner is deployment configuration, not a console subject or a business
/// authorization authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelEvaluationAdmissionAttempt {
    tenant_id: TenantId,
    site_id: SiteId,
    request_id: RequestId,
    model_call_id: ModelCallId,
    policy_revision: PolicyRevision,
    runner_id: String,
}

impl ModelEvaluationAdmissionAttempt {
    /// Builds one bounded, scope-fixed provider-call attempt.
    ///
    /// # Errors
    /// Returns [`ModelEvaluationAdmissionInputError`] when `runner_id` is
    /// empty, overlong, contains control bytes, or has surrounding whitespace.
    /// Construction performs no database, network, evidence, audit, or
    /// authorization side effect.
    pub fn new(
        tenant_id: TenantId,
        site_id: SiteId,
        request_id: RequestId,
        model_call_id: ModelCallId,
        policy_revision: PolicyRevision,
        runner_id: impl Into<String>,
    ) -> Result<Self, ModelEvaluationAdmissionInputError> {
        let runner_id = runner_id.into();
        if !valid_runner_id(&runner_id) {
            return Err(ModelEvaluationAdmissionInputError);
        }
        Ok(Self {
            tenant_id,
            site_id,
            request_id,
            model_call_id,
            policy_revision,
            runner_id,
        })
    }

    /// Returns the trusted tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the trusted site scope.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the model lifecycle's request identity.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the single provider-call identity.
    #[must_use]
    pub const fn model_call_id(&self) -> &ModelCallId {
        &self.model_call_id
    }

    /// Returns the approved policy revision frozen into the model input.
    #[must_use]
    pub const fn policy_revision(&self) -> &PolicyRevision {
        &self.policy_revision
    }

    /// Returns the configured worker runner identity.
    #[must_use]
    pub fn runner_id(&self) -> &str {
        &self.runner_id
    }
}

fn valid_runner_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value.trim() == value
}

/// A local validation failure while constructing an admission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelEvaluationAdmissionInputError;

impl fmt::Display for ModelEvaluationAdmissionInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid model evaluation admission attempt")
    }
}

impl std::error::Error for ModelEvaluationAdmissionInputError {}

/// Closed authoritative denial of one model-evaluation admission operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelEvaluationAdmissionDenied {
    /// Deployment has not provisioned the requested tenant/site capacity scope.
    ScopeNotConfigured,
    /// The scope has already reached its configured active-call bound.
    CapacityExhausted,
    /// This model-call identity conflicts with an incompatible durable lease.
    Conflict,
    /// A historical lease cannot safely be reused after recovery.
    RecoveryRequired,
    /// The approved evaluation policy does not match the provisioned scope.
    PolicyRevisionMismatch,
    /// The exact lease expired before the operation could proceed.
    LeaseExpired,
}

impl ModelEvaluationAdmissionDenied {
    /// Returns the stable, non-secret reason code for the caller-owned audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::ScopeNotConfigured => "MODEL_EVALUATION_ADMISSION_NOT_CONFIGURED",
            Self::CapacityExhausted => "MODEL_EVALUATION_CAPACITY_EXHAUSTED",
            Self::Conflict => "MODEL_EVALUATION_ADMISSION_CONFLICT",
            Self::RecoveryRequired => "MODEL_EVALUATION_ADMISSION_RECOVERY_REQUIRED",
            Self::PolicyRevisionMismatch => "MODEL_EVALUATION_ADMISSION_POLICY_MISMATCH",
            Self::LeaseExpired => "MODEL_EVALUATION_ADMISSION_LEASE_EXPIRED",
        }
    }
}

/// Result of acquiring or confirming a capacity lease.
#[derive(Debug)]
pub enum ModelEvaluationAdmissionState<Lease> {
    /// The exact lease may continue toward one provider request.
    Admitted(Lease),
    /// The operation is safely refused before a provider side effect.
    Denied(ModelEvaluationAdmissionDenied),
}

/// Result of closing a model-evaluation capacity lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelEvaluationAdmissionReleaseState {
    /// The active lease moved to its durable released state.
    Released,
    /// This exact lease was already released by a prior completion attempt.
    AlreadyReleased,
    /// The lease expired before its holder could close it.
    Expired,
    /// The lease is unavailable or does not match its private holder token.
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::{ModelEvaluationAdmissionAttempt, ModelEvaluationAdmissionDenied};
    use crate::domain::{ModelCallId, PolicyRevision, RequestId, SiteId, TenantId};

    fn attempt(
        runner: &str,
    ) -> Result<ModelEvaluationAdmissionAttempt, super::ModelEvaluationAdmissionInputError> {
        ModelEvaluationAdmissionAttempt::new(
            TenantId::parse("tenant_model").unwrap(),
            SiteId::parse("site_model").unwrap(),
            RequestId::parse("req_01a0afa6-3320-7791-8f45-b4d5a34ffb57").unwrap(),
            ModelCallId::parse("mdl_01a0afa6-3320-7791-8f45-b4d5a34ffb58").unwrap(),
            PolicyRevision::parse("model-evaluation-admission-r1").unwrap(),
            runner,
        )
    }

    #[test]
    fn attempt_freezes_scope_and_rejects_ambiguous_runner_text() {
        let admission = attempt("model-eval-runner-r1").unwrap();
        assert_eq!(admission.tenant_id().as_str(), "tenant_model");
        assert_eq!(admission.site_id().as_str(), "site_model");
        assert_eq!(
            admission.policy_revision().as_str(),
            "model-evaluation-admission-r1"
        );
        assert_eq!(admission.runner_id(), "model-eval-runner-r1");
        for runner in ["", " runner", "runner ", "runner\n"] {
            assert!(attempt(runner).is_err());
        }
    }

    #[test]
    fn denials_have_stable_non_secret_reasons() {
        assert_eq!(
            ModelEvaluationAdmissionDenied::CapacityExhausted.reason_code(),
            "MODEL_EVALUATION_CAPACITY_EXHAUSTED"
        );
        assert_eq!(
            ModelEvaluationAdmissionDenied::LeaseExpired.reason_code(),
            "MODEL_EVALUATION_ADMISSION_LEASE_EXPIRED"
        );
    }
}
