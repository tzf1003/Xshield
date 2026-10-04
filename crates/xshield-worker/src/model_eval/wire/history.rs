//! Operator-supplied, bounded historical facts for offline model evaluation.
//! These claims are evidence in an approved private input, not an authorization source.

use serde::{Deserialize, Serialize};
use xshield_core::domain::{PageEvidenceId, RequestId, ResponseEvidenceId};

use super::INPUT_INVALID;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthFacts {
    provenance: Provenance,
    subject_ref: String,
    requested_resource_ref: String,
    current_grant: GrantState,
    source_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_request_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageEvidence {
    provenance: Provenance,
    source_kind: SourceKind,
    source_evidence_ref: String,
    source_request_id: String,
    action_id: String,
    action_subject_ref: String,
    action_resource_ref: String,
    mapping_revision: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Provenance {
    OperatorSuppliedOffline,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    ResponseEvidence,
    PageEvidence,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum GrantState {
    Active,
    Missing,
    Revoked,
}

fn valid_ref(value: &str) -> bool {
    crate::valid_name(value) && value.len() <= 128
}

impl AuthFacts {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if !valid_ref(&self.subject_ref)
            || !valid_ref(&self.requested_resource_ref)
            || RequestId::parse(&self.source_request_id).is_err()
            || self
                .attempt_request_id
                .as_deref()
                .is_some_and(|id| RequestId::parse(id).is_err())
        {
            return Err(INPUT_INVALID);
        }
        Ok(())
    }

    pub(super) fn source_request_id(&self) -> &str {
        &self.source_request_id
    }

    pub(super) fn text_chars(&self) -> usize {
        self.subject_ref.chars().count()
            + self.requested_resource_ref.chars().count()
            + self.source_request_id.chars().count()
            + self
                .attempt_request_id
                .as_ref()
                .map_or(0, |id| id.chars().count())
    }
}

impl PageEvidence {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        let source_valid = match self.source_kind {
            SourceKind::ResponseEvidence => {
                ResponseEvidenceId::parse(&self.source_evidence_ref).is_ok()
            }
            SourceKind::PageEvidence => PageEvidenceId::parse(&self.source_evidence_ref).is_ok(),
        };
        if RequestId::parse(&self.source_request_id).is_err()
            || !source_valid
            || !valid_ref(&self.action_id)
            || !valid_ref(&self.action_subject_ref)
            || !valid_ref(&self.action_resource_ref)
            || !valid_ref(&self.mapping_revision)
        {
            return Err(INPUT_INVALID);
        }
        Ok(())
    }

    pub(super) fn source_request_id(&self) -> &str {
        &self.source_request_id
    }

    pub(super) fn text_chars(&self) -> usize {
        self.source_evidence_ref.chars().count()
            + self.source_request_id.chars().count()
            + self.action_id.chars().count()
            + self.action_subject_ref.chars().count()
            + self.action_resource_ref.chars().count()
            + self.mapping_revision.chars().count()
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use serde_json::{Value, json};

    const REQUEST: &str = "req_01a0afa6-3320-7791-8f45-b4d5a34ffb57";
    const CALL: &str = "mdl_01a0afa6-3320-7791-8f45-b4d5a34ffb58";
    const ARTIFACT: &str = "artifact_01a0afa6-3320-7791-8f45-b4d5a34ffb59";

    fn fixture() -> Value {
        json!({
            "schema_version":1, "approval_ref":"synthetic-lab-r1",
            "model_revision":"jev-1.13.0", "policy_revision":"policy-r1",
            "prompt_revision":"prompt-r1", "untrusted_content":"GET /orders/order-b",
            "question":{"type":"choice","instructions":"Classify the request using the supplied facts.",
                "criteria":{"ALLOW":"Authorized target.","DENY":"Target lacks the required grant.",
                    "NONE":"No applicable request.","UNKNOWN":"Insufficient evidence."}},
            "auth_facts":{"provenance":"operator_supplied_offline","subject_ref":"principal_alice",
                "requested_resource_ref":"order-b","current_grant":"missing",
                "source_request_id":REQUEST},
            "page_evidence":{"provenance":"operator_supplied_offline",
                "source_kind":"response_evidence",
                "source_evidence_ref":"response_01a0afa6-3320-7791-8f45-b4d5a34ffb55",
                "source_request_id":REQUEST,"action_id":"orders.open",
                "action_subject_ref":"principal_alice","action_resource_ref":"order-a",
                "mapping_revision":"mapping-r1"}
        })
    }

    fn parse(value: &Value) -> Result<Input, &'static str> {
        Input::parse(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn offline_history_is_captured_and_sent_with_explicit_coverage() {
        let input = parse(&fixture()).unwrap();
        let internal: Value = serde_json::from_slice(&input.internal_bytes().unwrap()).unwrap();
        let sent: Value =
            serde_json::from_slice(&input.api_bytes(REQUEST, CALL, ARTIFACT).unwrap()).unwrap();
        assert_eq!(sent["state"]["auth_facts"], internal["auth_facts"]);
        assert_eq!(sent["state"]["page_evidence"], internal["page_evidence"]);
        assert_eq!(sent["state"]["coverage"]["auth_facts"], "operator_supplied");
        assert_eq!(
            sent["state"]["coverage"]["page_evidence"],
            "operator_supplied"
        );
        assert_eq!(sent["state"]["auth_facts"]["current_grant"], "missing");
        assert_eq!(
            sent["state"]["page_evidence"]["action_resource_ref"],
            "order-a"
        );
    }

    #[test]
    fn offline_history_rejects_incomplete_mismatched_and_unbounded_claims() {
        let mut incomplete = fixture();
        incomplete.as_object_mut().unwrap().remove("page_evidence");
        assert!(parse(&incomplete).is_err());

        let mut mismatch = fixture();
        mismatch["page_evidence"]["source_request_id"] =
            json!("req_01a0afa6-3320-7791-8f45-b4d5a34ffb56");
        assert!(parse(&mismatch).is_err());

        let mut invalid_attempt = fixture();
        invalid_attempt["auth_facts"]["attempt_request_id"] = json!("another-site");
        assert!(parse(&invalid_attempt).is_err());

        let mut unknown = fixture();
        unknown["auth_facts"]["current_grant"] = json!("assumed_active");
        assert!(parse(&unknown).is_err());

        let mut wrong_source = fixture();
        wrong_source["page_evidence"]["source_kind"] = json!("page_evidence");
        assert!(parse(&wrong_source).is_err());

        let mut extra = fixture();
        extra["auth_facts"]["raw_cookie"] = json!("forbidden");
        assert!(parse(&extra).is_err());

        let mut oversized = fixture();
        oversized["page_evidence"]["action_id"] = json!("a".repeat(129));
        assert!(parse(&oversized).is_err());
    }
}
