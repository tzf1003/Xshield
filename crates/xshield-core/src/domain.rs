//! Validated domain values shared by the M0 request flow.

use std::fmt;

/// A rejected value at an external boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidValue {
    field: &'static str,
}

impl InvalidValue {
    pub(crate) const fn new(field: &'static str) -> Self {
        Self { field }
    }
}

impl fmt::Display for InvalidValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}", self.field)
    }
}

impl std::error::Error for InvalidValue {}

fn valid_scoped_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_v7_id(value: &str, prefix: &str) -> bool {
    let Some(uuid) = value.strip_prefix(prefix) else {
        return false;
    };
    let bytes = uuid.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index) || matches!(byte, b'0'..=b'9' | b'a'..=b'f')
        })
        && bytes[14] == b'7'
        && matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
}

macro_rules! scoped_name {
    ($name:ident, $field:literal) => {
        /// A validated tenant-scoped name.
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns a non-secret scoped name.
            ///
            /// # Errors
            /// Returns [`InvalidValue`] for an empty, oversized, or unsupported value.
            pub fn parse(value: impl Into<String>) -> Result<Self, InvalidValue> {
                let value = value.into();
                valid_scoped_name(&value)
                    .then_some(Self(value))
                    .ok_or_else(|| InvalidValue::new($field))
            }

            #[must_use]
            /// Returns the validated wire value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

macro_rules! v7_id {
    ($name:ident, $prefix:literal, $field:literal) => {
        /// A validated Xshield-prefixed `UUIDv7` identifier.
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Parses an Xshield-prefixed `UUIDv7` identifier.
            ///
            /// # Errors
            /// Returns [`InvalidValue`] when the prefix or `UUIDv7` shape is invalid.
            pub fn parse(value: impl Into<String>) -> Result<Self, InvalidValue> {
                let value = value.into();
                valid_v7_id(&value, $prefix)
                    .then_some(Self(value))
                    .ok_or_else(|| InvalidValue::new($field))
            }

            #[must_use]
            /// Returns the validated wire value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

scoped_name!(TenantId, "tenant_id");
scoped_name!(SiteId, "site_id");
scoped_name!(PolicyRevision, "policy_revision");
v7_id!(RequestId, "req_", "request_id");
v7_id!(ModelCallId, "mdl_", "model_call_id");
v7_id!(ModelEvaluationLeaseId, "mle_", "model_evaluation_lease_id");
v7_id!(CalibrationReportId, "calr_", "calibration_report_id");
v7_id!(
    CalibrationLineageReviewId,
    "calrev_",
    "calibration_lineage_review_id"
);
v7_id!(
    CalibrationReadCapabilityId,
    "calcap_",
    "calibration_read_capability_id"
);
v7_id!(
    CalibrationReadLeaseId,
    "callease_",
    "calibration_read_lease_id"
);
v7_id!(EventId, "ev_", "event_id");
v7_id!(ArtifactId, "artifact_", "artifact_id");
v7_id!(CaseId, "case_", "case_id");
v7_id!(
    EvidenceAccessRequestId,
    "access_",
    "evidence_access_request_id"
);
v7_id!(StageExecutionId, "stg_", "stage_execution_id");
v7_id!(WafSessionId, "ses_", "waf_session_id");
v7_id!(AuthBindingId, "auth_", "auth_binding_id");
v7_id!(GrantId, "grant_", "grant_id");
v7_id!(PageEvidenceId, "page_", "page_evidence_id");
v7_id!(ResponseEvidenceId, "response_", "response_evidence_id");
v7_id!(ShareGrantId, "share_", "share_grant_id");
v7_id!(ServiceIdentityId, "svc_", "service_identity_id");
scoped_name!(OperationId, "operation_id");
scoped_name!(ResourceType, "resource_type");
scoped_name!(ViewProfile, "view_profile");
scoped_name!(IssuanceKey, "issuance_key");
scoped_name!(ShareIssuanceRuleId, "share_issuance_rule_id");
scoped_name!(ActionRef, "action_ref");
scoped_name!(ActionId, "action_id");
scoped_name!(PageTemplate, "page_template");
scoped_name!(MappingRevision, "mapping_revision");
scoped_name!(FieldName, "field_name");
scoped_name!(ApprovalRef, "approval_ref");
scoped_name!(DatasetRevision, "dataset_revision");
scoped_name!(LabelRevision, "label_revision");
scoped_name!(TaskRevision, "task_revision");
scoped_name!(ThresholdPolicyRevision, "threshold_policy_revision");
scoped_name!(ModelRevision, "model_revision");
scoped_name!(PromptRevision, "prompt_revision");
scoped_name!(ProviderId, "provider_id");

pub(crate) fn parse_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Some(bytes)
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactId, CalibrationReadLeaseId, CaseId, EvidenceAccessRequestId, ModelCallId,
        ModelEvaluationLeaseId, RequestId, TenantId,
    };

    #[test]
    fn validates_boundary_identifiers() {
        assert!(RequestId::parse("req_01a0afa6-3320-758a-9554-d0d3b561b8c6").is_ok());
        assert!(RequestId::parse("req_01a0afa6-3320-458a-9554-d0d3b561b8c6").is_err());
        assert!(RequestId::parse("req_01A0AFA6-3320-758a-9554-d0d3b561b8c6").is_err());
        assert!(RequestId::parse("ev_01a0afa6-3320-758a-9554-d0d3b561b8c6").is_err());
        assert!(ModelCallId::parse("mdl_01a0afa6-3320-7791-8f45-b4d5a34ffb57").is_ok());
        assert!(ModelEvaluationLeaseId::parse("mle_01a0afa6-3320-7791-8f45-b4d5a34ffb57").is_ok());
        assert!(
            CalibrationReadLeaseId::parse("callease_01a0afa6-3320-7791-8f45-b4d5a34ffb57").is_ok()
        );
        for id in [
            "model_01a0afa6-3320-7791-8f45-b4d5a34ffb57",
            "req_01a0afa6-3320-7791-8f45-b4d5a34ffb57",
            "mdl_01a0afa6-3320-4791-8f45-b4d5a34ffb57",
            "mdl_01A0afa6-3320-7791-8f45-b4d5a34ffb57",
        ] {
            assert!(ModelCallId::parse(id).is_err());
        }
        assert!(ArtifactId::parse("artifact_01a0afa6-3320-758a-9554-d0d3b561b8c6").is_ok());
        assert!(ArtifactId::parse("art_01a0afa6-3320-758a-9554-d0d3b561b8c6").is_err());
        assert!(CaseId::parse("case_01a0afa6-3320-758a-9554-d0d3b561b8c6").is_ok());
        assert!(
            EvidenceAccessRequestId::parse("access_01a0afa6-3320-758a-9554-d0d3b561b8c6").is_ok()
        );
        assert!(TenantId::parse("tenant_demo").is_ok());
        assert!(TenantId::parse("tenant/demo").is_err());
    }
}
