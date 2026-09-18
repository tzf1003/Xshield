//! Pure investigation-case values for control-plane workflows.

use crate::domain::{CaseId, InvalidValue, SiteId, TenantId};

const SUBJECT_MAX: usize = 256;
const PURPOSE_MAX: usize = 512;

/// A validated new investigation case before persistence assigns its timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationCaseDraft {
    case_id: CaseId,
    tenant_id: TenantId,
    site_id: SiteId,
    owner_ref: String,
    purpose: String,
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
    use super::InvestigationCaseDraft;
    use crate::domain::{CaseId, SiteId, TenantId};

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
}
