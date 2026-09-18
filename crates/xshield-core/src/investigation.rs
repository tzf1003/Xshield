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
    use super::{EvidenceAccessKind, EvidenceAccessRequestDraft, InvestigationCaseDraft};
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
}
