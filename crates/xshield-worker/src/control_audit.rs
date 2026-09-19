//! Strict publication of control-plane access attempts from authenticated journals.
//! Management attempts retain their own request IDs and do not assert an origin
//! outcome. Transactional outbox facts use a separate payload and delivery contract.

use super::{PayloadSummary, PublishError, WireEvent, valid_lower_hex, valid_prefixed_v7};
use serde::Deserialize;

#[cfg(test)]
mod tests;

pub(super) fn supports(event_type: &str) -> bool {
    matches!(
        event_type,
        "console.health.read"
            | "console.request.read"
            | "console.events.read"
            | "console.manifest.read"
            | "console.model.read"
            | "console.query.executed"
            | "console.case.read"
            | "case.created"
            | "case.closed"
            | "case.evidence.added"
            | "evidence.access.requested"
            | "evidence.access.approved"
            | "evidence.access.denied"
            | "evidence.read"
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessPayload {
    method: String,
    path: String,
    subject_ref: Option<String>,
    target_request_id: Option<String>,
    target_artifact_id: Option<String>,
    target_case_id: Option<String>,
    target_access_request_id: Option<String>,
    target_model_call_id: Option<String>,
    query_digest: Option<String>,
    outcome: String,
    reason_code: String,
    bytes_read: Option<u64>,
}

pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    if event.producer_id != "xshield-control"
        || event.policy_revision != "control-v1"
        || event.request_id.is_none()
        || event.request_seq != 1
        || !event.cause_event_ids.is_empty()
        || event.sensitivity != "INTERNAL"
    {
        return Err(PublishError::InvalidEvent);
    }
    let payload: AccessPayload = serde_json::from_str(event.payload.get())?;
    payload.validate(event)?;
    Ok(PayloadSummary {
        stage: "control_access".to_owned(),
        method: payload.method,
        outcome: payload.outcome,
        reason_code: payload.reason_code,
        proof_kind: "deterministic".to_owned(),
        confidence_status: "not_applicable".to_owned(),
        // A management attempt is not evidence of a business request's terminal
        // decision, HTTP response delivery, or source-server execution.
        ..PayloadSummary::default()
    })
}

impl AccessPayload {
    fn validate(&self, event: &WireEvent) -> Result<(), PublishError> {
        let success = self.outcome == "PASS";
        if !matches!(self.outcome.as_str(), "PASS" | "DENY" | "ERROR")
            || self.reason_code.is_empty()
            || self.reason_code.len() > 128
            || !self
                .reason_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || self.subject_ref.as_ref().is_some_and(|subject| {
                subject.is_empty() || subject.len() > 256 || subject.chars().any(char::is_control)
            })
            || (success && self.subject_ref.is_none())
        {
            return Err(PublishError::InvalidEvent);
        }
        self.validate_targets(&event.event_type, success)?;
        for reference in &event.evidence_refs {
            valid_prefixed_v7(reference, "artifact_")?;
        }
        let is_query = event.event_type == "console.query.executed";
        let is_read = event.event_type == "evidence.read";
        if self
            .query_digest
            .as_ref()
            .is_some_and(|digest| !is_query || !valid_lower_hex(digest, 64))
            || (success && is_query && self.query_digest.is_none())
            || self
                .bytes_read
                .is_some_and(|bytes| !is_read || !success || bytes > 64 * 1024 * 1024)
            || (success && is_read && self.bytes_read.is_none())
            || (!success && !event.evidence_refs.is_empty())
        {
            return Err(PublishError::InvalidEvent);
        }
        if success {
            self.validate_evidence(event)?;
        }
        Ok(())
    }

    fn validate_targets(&self, event_type: &str, success: bool) -> Result<(), PublishError> {
        // Keep the field order explicit: request, artifact, case, access request,
        // model call. Denials may have only the targets validated before failure.
        let targets = [
            (&self.target_request_id, "req_"),
            (&self.target_artifact_id, "artifact_"),
            (&self.target_case_id, "case_"),
            (&self.target_access_request_id, "access_"),
            (&self.target_model_call_id, "mdl_"),
        ];
        let allowed = match (event_type, self.method.as_str(), self.path.as_str()) {
            ("console.health.read", "GET", "/control/v1/audit/health") => [false; 5],
            ("console.query.executed", "POST", "/control/v1/search")
            | ("console.request.read", "GET", "/control/v1/requests/{request_id}")
            | ("console.events.read", "GET", "/control/v1/requests/{request_id}/events")
            | ("console.manifest.read", "GET", "/control/v1/requests/{request_id}/evidence") => {
                [true, false, false, false, false]
            }
            ("console.manifest.read", "GET", "/control/v1/artifacts/{artifact_id}") => {
                [false, true, false, false, false]
            }
            ("console.model.read", "GET", "/control/v1/model-calls/{model_call_id}") => {
                [false, false, false, false, true]
            }
            ("case.created", "POST", "/control/v1/cases")
            | ("case.closed", "POST", "/control/v1/cases/{case_id}/close")
            | ("console.case.read", "GET", "/control/v1/cases/{case_id}/items") => {
                [false, false, true, false, false]
            }
            ("case.evidence.added", "POST", "/control/v1/cases/{case_id}/items") => {
                [false, true, true, false, false]
            }
            ("evidence.access.requested", "POST", "/control/v1/artifacts/{artifact_id}/access")
            | (
                "evidence.access.approved",
                "POST",
                "/control/v1/evidence-access-requests/{access_request_id}/approve",
            )
            | (
                "evidence.access.denied",
                "POST",
                "/control/v1/evidence-access-requests/{access_request_id}/deny",
            ) => [false, true, true, true, false],
            ("evidence.read", "GET", "/control/v1/artifacts/{artifact_id}/content") => {
                [false, true, false, true, false]
            }
            _ => return Err(PublishError::InvalidEvent),
        };
        for ((target, prefix), allowed) in targets.into_iter().zip(allowed) {
            let required = allowed && !(event_type == "console.query.executed" && prefix == "req_");
            if target.is_some() && !allowed || success && required && target.is_none() {
                return Err(PublishError::InvalidEvent);
            }
            if let Some(target) = target {
                valid_prefixed_v7(target, prefix)?;
            }
        }
        Ok(())
    }

    fn validate_evidence(&self, event: &WireEvent) -> Result<(), PublishError> {
        let valid = match event.event_type.as_str() {
            "case.evidence.added"
            | "evidence.access.requested"
            | "evidence.access.approved"
            | "evidence.access.denied"
            | "evidence.read" => {
                event.evidence_refs.len() == 1
                    && self.target_artifact_id.as_ref() == event.evidence_refs.first()
            }
            "console.manifest.read" if self.target_artifact_id.is_some() => {
                event.evidence_refs.is_empty()
                    || (event.evidence_refs.len() == 1
                        && self.target_artifact_id.as_ref() == event.evidence_refs.first())
            }
            "console.manifest.read"
            | "console.events.read"
            | "console.model.read"
            | "console.case.read"
            | "console.query.executed" => true,
            _ => event.evidence_refs.is_empty(),
        };
        if valid {
            Ok(())
        } else {
            Err(PublishError::InvalidEvent)
        }
    }
}
