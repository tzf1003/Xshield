//! Pure investigation-case values for control-plane workflows.

use crate::domain::{ArtifactId, CaseId, EvidenceAccessRequestId, InvalidValue, SiteId, TenantId};

const SUBJECT_MAX: usize = 256;
const PURPOSE_MAX: usize = 512;
const JUSTIFICATION_MAX: usize = 512;

/// A validated new investigation case before persistence assigns its timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationCaseDraft {
    case_id: CaseId,
    tenant_id: TenantId,
    site_id: SiteId,
    owner_ref: String,
    purpose: String,
}

/// Content scope requested for one evidence-access approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceAccessKind {
    /// Decrypts the authenticated evidence object after independent approval.
    SensitiveRaw,
}

/// Terminal decision applied by an independent evidence approver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceAccessDecisionKind {
    /// Grants a bounded, short-lived content capability.
    Approved,
    /// Closes the request without a content capability.
    Denied,
}

impl EvidenceAccessDecisionKind {
    /// Returns the stable storage value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }

    /// Returns the corresponding immutable audit event type.
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::Approved => "evidence.access.approved",
            Self::Denied => "evidence.access.denied",
        }
    }

    /// Returns the corresponding stable terminal reason.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Approved => "EVIDENCE_ACCESS_APPROVED",
            Self::Denied => "EVIDENCE_ACCESS_DENIED",
        }
    }
}

/// A validated terminal decision for one pending evidence-access request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceAccessDecisionDraft {
    tenant_id: TenantId,
    site_id: SiteId,
    access_request_id: EvidenceAccessRequestId,
    decided_by: String,
    kind: EvidenceAccessDecisionKind,
    reason: String,
    requested_ttl_seconds: Option<u32>,
}

impl EvidenceAccessDecisionDraft {
    /// Builds an approval that requests a non-zero bounded lease.
    ///
    /// The application layer supplies the configured upper bound; persistence
    /// clamps the resulting lease to the evidence object's current expiry.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for invalid approver text, reason text, or TTL.
    pub fn approve(
        tenant_id: TenantId,
        site_id: SiteId,
        access_request_id: EvidenceAccessRequestId,
        decided_by: impl Into<String>,
        reason: impl Into<String>,
        requested_ttl_seconds: u32,
        max_ttl_seconds: u32,
    ) -> Result<Self, InvalidValue> {
        if requested_ttl_seconds == 0 || requested_ttl_seconds > max_ttl_seconds {
            return Err(InvalidValue::new("evidence_access_ttl_seconds"));
        }
        Self::new(
            tenant_id,
            site_id,
            access_request_id,
            decided_by,
            EvidenceAccessDecisionKind::Approved,
            reason,
            Some(requested_ttl_seconds),
        )
    }

    /// Builds a denial, which never carries a content lease.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] for invalid approver or reason text.
    pub fn deny(
        tenant_id: TenantId,
        site_id: SiteId,
        access_request_id: EvidenceAccessRequestId,
        decided_by: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, InvalidValue> {
        Self::new(
            tenant_id,
            site_id,
            access_request_id,
            decided_by,
            EvidenceAccessDecisionKind::Denied,
            reason,
            None,
        )
    }

    fn new(
        tenant_id: TenantId,
        site_id: SiteId,
        access_request_id: EvidenceAccessRequestId,
        decided_by: impl Into<String>,
        kind: EvidenceAccessDecisionKind,
        reason: impl Into<String>,
        requested_ttl_seconds: Option<u32>,
    ) -> Result<Self, InvalidValue> {
        let decided_by = decided_by.into();
        let reason = reason.into();
        if !valid_text(&decided_by, SUBJECT_MAX) {
            return Err(InvalidValue::new("evidence_access_decider"));
        }
        if !valid_text(&reason, JUSTIFICATION_MAX) || reason.trim() != reason {
            return Err(InvalidValue::new("evidence_access_decision_reason"));
        }
        Ok(Self {
            tenant_id,
            site_id,
            access_request_id,
            decided_by,
            kind,
            reason,
            requested_ttl_seconds,
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

    /// Returns the target access-request identity.
    #[must_use]
    pub const fn access_request_id(&self) -> &EvidenceAccessRequestId {
        &self.access_request_id
    }

    /// Returns the independently authenticated decision subject.
    #[must_use]
    pub fn decided_by(&self) -> &str {
        &self.decided_by
    }

    /// Returns the terminal decision.
    #[must_use]
    pub const fn kind(&self) -> EvidenceAccessDecisionKind {
        self.kind
    }

    /// Returns the bounded decision reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns the requested lease for approvals.
    #[must_use]
    pub const fn requested_ttl_seconds(&self) -> Option<u32> {
        self.requested_ttl_seconds
    }
}

impl EvidenceAccessKind {
    /// Returns the stable storage and audit value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SensitiveRaw => "sensitive_raw",
        }
    }
}

/// A validated request for independently approved evidence access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceAccessRequestDraft {
    access_request_id: EvidenceAccessRequestId,
    tenant_id: TenantId,
    site_id: SiteId,
    case_id: CaseId,
    artifact_id: ArtifactId,
    requested_by: String,
    kind: EvidenceAccessKind,
    justification: String,
}

impl EvidenceAccessRequestDraft {
    /// Binds an access request to one server-derived scope, case, and artifact.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] when the requester or justification is empty,
    /// oversized, padded, or contains control characters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        access_request_id: EvidenceAccessRequestId,
        tenant_id: TenantId,
        site_id: SiteId,
        case_id: CaseId,
        artifact_id: ArtifactId,
        requested_by: impl Into<String>,
        kind: EvidenceAccessKind,
        justification: impl Into<String>,
    ) -> Result<Self, InvalidValue> {
        let requested_by = requested_by.into();
        let justification = justification.into();
        if !valid_text(&requested_by, SUBJECT_MAX) {
            return Err(InvalidValue::new("evidence_access_requester"));
        }
        if !valid_text(&justification, JUSTIFICATION_MAX) || justification.trim() != justification {
            return Err(InvalidValue::new("evidence_access_justification"));
        }
        Ok(Self {
            access_request_id,
            tenant_id,
            site_id,
            case_id,
            artifact_id,
            requested_by,
            kind,
            justification,
        })
    }

    /// Returns the server-generated request identity.
    #[must_use]
    pub const fn access_request_id(&self) -> &EvidenceAccessRequestId {
        &self.access_request_id
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

    /// Returns the owning investigation case.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the requested evidence object.
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Returns the independently authenticated requester.
    #[must_use]
    pub fn requested_by(&self) -> &str {
        &self.requested_by
    }

    /// Returns the requested content scope.
    #[must_use]
    pub const fn kind(&self) -> EvidenceAccessKind {
        self.kind
    }

    /// Returns the bounded investigation justification.
    #[must_use]
    pub fn justification(&self) -> &str {
        &self.justification
    }
}

impl InvestigationCaseDraft {
    /// Binds a server-generated case identity to one management scope and owner.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] when owner or purpose is empty, oversized, or
    /// contains control characters.
    pub fn new(
        case_id: CaseId,
        tenant_id: TenantId,
        site_id: SiteId,
        owner_ref: impl Into<String>,
        purpose: impl Into<String>,
    ) -> Result<Self, InvalidValue> {
        let owner_ref = owner_ref.into();
        let purpose = purpose.into();
        if !valid_text(&owner_ref, SUBJECT_MAX) {
            return Err(InvalidValue::new("case_owner_ref"));
        }
        if !valid_text(&purpose, PURPOSE_MAX) || purpose.trim() != purpose {
            return Err(InvalidValue::new("case_purpose"));
        }
        Ok(Self {
            case_id,
            tenant_id,
            site_id,
            owner_ref,
            purpose,
        })
    }

    /// Returns the server-generated case identity.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
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

    /// Returns the authenticated case owner reference.
    #[must_use]
    pub fn owner_ref(&self) -> &str {
        &self.owner_ref
    }

    /// Returns the bounded investigation purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::{
        EvidenceAccessDecisionDraft, EvidenceAccessDecisionKind, EvidenceAccessKind,
        EvidenceAccessRequestDraft, InvestigationCaseDraft,
    };
    use crate::domain::{ArtifactId, CaseId, EvidenceAccessRequestId, SiteId, TenantId};

    #[test]
    fn case_draft_is_scoped_and_bounded() {
        let case_id = CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000901").unwrap();
        let tenant = TenantId::parse("tenant_case").unwrap();
        let site = SiteId::parse("site_case").unwrap();
        assert!(
            InvestigationCaseDraft::new(
                case_id.clone(),
                tenant.clone(),
                site.clone(),
                "investigator-1",
                "Review a scoped evidence anomaly",
            )
            .is_ok()
        );
        assert!(
            InvestigationCaseDraft::new(case_id, tenant, site, "investigator-1", " padded ",)
                .is_err()
        );
        let case_id = CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000902").unwrap();
        let tenant = TenantId::parse("tenant_case").unwrap();
        let site = SiteId::parse("site_case").unwrap();
        assert!(
            InvestigationCaseDraft::new(
                case_id.clone(),
                tenant.clone(),
                site.clone(),
                "investigator\n1",
                "Review",
            )
            .is_err()
        );
        assert!(
            InvestigationCaseDraft::new(case_id, tenant, site, "investigator-1", "x".repeat(513))
                .is_err()
        );
    }

    #[test]
    fn evidence_access_request_is_scoped_and_bounded() {
        let access = EvidenceAccessRequestDraft::new(
            EvidenceAccessRequestId::parse("access_018f2a3b-4c5d-7000-8000-000000000910").unwrap(),
            TenantId::parse("tenant_case").unwrap(),
            SiteId::parse("site_case").unwrap(),
            CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000911").unwrap(),
            ArtifactId::parse("artifact_018f2a3b-4c5d-7000-8000-000000000912").unwrap(),
            "investigator-1",
            EvidenceAccessKind::SensitiveRaw,
            "Verify the encrypted source response",
        )
        .unwrap();
        assert_eq!(access.kind().as_str(), "sensitive_raw");
        assert!(
            EvidenceAccessRequestDraft::new(
                access.access_request_id().clone(),
                access.tenant_id().clone(),
                access.site_id().clone(),
                access.case_id().clone(),
                access.artifact_id().clone(),
                access.requested_by(),
                access.kind(),
                " padded ",
            )
            .is_err()
        );
    }

    #[test]
    fn evidence_access_decision_is_terminal_and_bounded() {
        let tenant = TenantId::parse("tenant_case").unwrap();
        let site = SiteId::parse("site_case").unwrap();
        let access =
            EvidenceAccessRequestId::parse("access_018f2a3b-4c5d-7000-8000-000000000913").unwrap();
        let approved = EvidenceAccessDecisionDraft::approve(
            tenant.clone(),
            site.clone(),
            access.clone(),
            "approver-1",
            "Required for incident verification",
            300,
            900,
        )
        .unwrap();
        assert_eq!(approved.kind(), EvidenceAccessDecisionKind::Approved);
        assert_eq!(approved.requested_ttl_seconds(), Some(300));
        assert!(
            EvidenceAccessDecisionDraft::approve(
                tenant.clone(),
                site.clone(),
                access.clone(),
                "approver-1",
                "Reason",
                901,
                900,
            )
            .is_err()
        );
        assert!(
            EvidenceAccessDecisionDraft::deny(tenant, site, access, "approver-1", " padded ",)
                .is_err()
        );
    }
}
