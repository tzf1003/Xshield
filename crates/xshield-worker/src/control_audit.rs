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
        "console.auth.login"
            | "console.auth.callback"
            | "console.auth.reauth.start"
            | "console.auth.reauth.callback"
            | "console.auth.session.read"
            | "console.auth.session.logout"
            | "console.health.read"
            | "console.site.config.read"
            | "console.site.config.write"
            | "console.sites.list"
            | "console.site.create"
            | "console.site.delete"
            | "console.site.status.read"
            | "console.site.config.validate"
            | "console.site.config.apply"
            | "console.site.config.approve"
            | "console.site.config.rollback"
            | "console.workbench.overview.read"
            | "console.agent_api_key.admin"
            | "console.agent_api_key.list"
            | "console.agent_api_key.use"
            | "console.export.read"
            | "console.export.list"
            | "export.requested"
            | "export.approved"
            | "export.denied"
            | "export.downloaded"
            | "console.request.read"
            | "console.events.read"
            | "console.manifest.read"
            | "console.model.read"
            | "console.model.list"
            | "console.agent.read"
            | "console.case.analyze"
            | "console.job.read"
            | "console.job.list"
            | "console.calibration.report.read"
            | "console.grant.read"
            | "console.binding.read"
            | "console.query.executed"
            | "console.causality.read"
            | "console.case.read"
            | "console.case.list"
            | "console.evidence.access.read"
            | "console.evidence.access.list"
            | "console.evidence.hold.created"
            | "console.evidence.hold.released"
            | "console.evidence.hold.read"
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
    target_agent_run_id: Option<String>,
    target_job_id: Option<String>,
    target_export_id: Option<String>,
    target_api_key_id: Option<String>,
    target_grant_id: Option<String>,
    target_binding_id: Option<String>,
    target_hold_id: Option<String>,
    target_calibration_report_id: Option<String>,
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
        if event.event_type == "console.evidence.access.read" {
            self.validate_access_read_reason()?;
        }
        if event.event_type == "console.evidence.access.list" {
            self.validate_access_list_reason()?;
        }
        if event.event_type == "console.export.list" {
            self.validate_export_list_reason()?;
        }
        if event.event_type == "console.job.list" {
            self.validate_job_list_reason()?;
        }
        if event.event_type == "console.model.list" {
            self.validate_model_list_reason()?;
        }
        if event.event_type == "console.calibration.report.read" {
            self.validate_calibration_report_read_reason()?;
        }
        if event.event_type == "console.query.executed" {
            self.validate_search_reason()?;
        }
        if event.event_type == "console.causality.read" {
            self.validate_causality_reason()?;
        }
        if event.event_type == "console.agent.read" {
            self.validate_agent_run_reason()?;
        }
        if matches!(
            event.event_type.as_str(),
            "console.case.analyze" | "console.job.read"
        ) {
            self.validate_job_reason(&event.event_type)?;
        }
        let success = self.outcome == "PASS";
        let valid_reason = self.success_reason_is_valid(&event.event_type);
        if !matches!(self.outcome.as_str(), "PASS" | "DENY" | "ERROR")
            || success && !valid_reason
            || self.reason_code.is_empty()
            || self.reason_code.len() > 128
            || !self
                .reason_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || self.subject_ref.as_ref().is_some_and(|subject| {
                subject.is_empty() || subject.len() > 256 || subject.chars().any(char::is_control)
            })
            || (success && self.subject_ref.is_none() && event.event_type != "console.auth.login")
        {
            return Err(PublishError::InvalidEvent);
        }
        self.validate_targets(&event.event_type, success)?;
        self.validate_job_target(&event.event_type, success)?;
        self.validate_export_target(&event.event_type, success)?;
        self.validate_api_key_target(&event.event_type, success)?;
        for reference in &event.evidence_refs {
            valid_prefixed_v7(reference, "artifact_")?;
        }
        let is_query = matches!(
            event.event_type.as_str(),
            "console.query.executed" | "console.causality.read"
        );
        let is_read = matches!(
            event.event_type.as_str(),
            "evidence.read" | "export.downloaded"
        );
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

    fn validate_model_list_reason(&self) -> Result<(), PublishError> {
        let valid = match self.outcome.as_str() {
            "PASS" => self.reason_code == "CONTROL_MODEL_CALLS_READ",
            "DENY" => matches!(
                self.reason_code.as_str(),
                "CONTROL_MODEL_CALLS_REQUEST_INVALID"
                    | "CONTROL_CURSOR_INVALID"
                    | "CONTROL_QUERY_CAPACITY_EXHAUSTED"
                    | "CONTROL_QUERY_BUDGET_EXCEEDED"
            ),
            "ERROR" => matches!(
                self.reason_code.as_str(),
                "CONTROL_CURSOR_UNAVAILABLE"
                    | "CONTROL_QUERY_TIMEOUT"
                    | "CONTROL_MODEL_CALLS_INDEX_UNAVAILABLE"
                    | "CONTROL_MODEL_CALLS_HEALTH_UNAVAILABLE"
            ),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(PublishError::InvalidEvent)
        }
    }

    fn validate_search_reason(&self) -> Result<(), PublishError> {
        let valid = match self.outcome.as_str() {
            "PASS" => self.reason_code == "CONTROL_QUERY_EXECUTED",
            "DENY" => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_QUERY_INVALID"
                    | "CONTROL_CURSOR_INVALID"
                    | "CONTROL_CALIBRATION_REPORT_HISTORY_SCOPE_DENIED"
                    | "CONTROL_QUERY_CAPACITY_EXHAUSTED"
                    | "CONTROL_QUERY_BUDGET_EXCEEDED"
            ),
            "ERROR" => matches!(
                self.reason_code.as_str(),
                "CONTROL_CLOCK_UNAVAILABLE"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CURSOR_UNAVAILABLE"
                    | "CONTROL_QUERY_TIMEOUT"
                    | "CONTROL_INDEX_UNAVAILABLE"
                    | "CONTROL_HEALTH_UNAVAILABLE"
            ),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(PublishError::InvalidEvent)
        }
    }

    fn validate_causality_reason(&self) -> Result<(), PublishError> {
        let valid = match self.outcome.as_str() {
            "PASS" => self.reason_code == "CONTROL_CAUSALITY_READ",
            "DENY" => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_CAUSALITY_REQUEST_INVALID"
                    | "CONTROL_QUERY_CAPACITY_EXHAUSTED"
                    | "CONTROL_QUERY_BUDGET_EXCEEDED"
            ),
            "ERROR" => matches!(
                self.reason_code.as_str(),
                "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
                    | "CONTROL_CAUSALITY_TIMEOUT"
                    | "CONTROL_CAUSALITY_INDEX_UNAVAILABLE"
                    | "CONTROL_CAUSALITY_HEALTH_UNAVAILABLE"
            ),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(PublishError::InvalidEvent)
        }
    }

    fn validate_agent_run_reason(&self) -> Result<(), PublishError> {
        let valid = match self.outcome.as_str() {
            "PASS" => self.reason_code == "CONTROL_AGENT_RUN_READ",
            "DENY" => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_AGENT_RUN_ID_INVALID"
                    | "CONTROL_QUERY_CAPACITY_EXHAUSTED"
                    | "CONTROL_QUERY_BUDGET_EXCEEDED"
            ),
            "ERROR" => matches!(
                self.reason_code.as_str(),
                "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
                    | "CONTROL_QUERY_TIMEOUT"
                    | "CONTROL_INDEX_UNAVAILABLE"
                    | "CONTROL_HEALTH_UNAVAILABLE"
            ),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(PublishError::InvalidEvent)
        }
    }

    fn validate_job_reason(&self, event_type: &str) -> Result<(), PublishError> {
        let valid = match (event_type, self.outcome.as_str()) {
            ("console.case.analyze", "PASS") => matches!(
                self.reason_code.as_str(),
                "CONTROL_CASE_ANALYSIS_CREATED" | "CONTROL_CASE_ANALYSIS_REPLAYED"
            ),
            ("console.case.analyze", "DENY") => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_CASE_ID_INVALID"
                    | "CONTROL_IDEMPOTENCY_KEY_INVALID"
                    | "CONTROL_IDEMPOTENCY_UNAVAILABLE"
                    | "CONTROL_CASE_ANALYSIS_BUSY"
                    | "CONTROL_IDEMPOTENCY_CONFLICT"
                    | "CONTROL_CASE_ANALYSIS_TARGET_UNAVAILABLE"
            ),
            ("console.case.analyze", "ERROR") => matches!(
                self.reason_code.as_str(),
                "CONTROL_CASE_ANALYSIS_STORE_UNAVAILABLE"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
            ),
            ("console.job.read", "PASS") => self.reason_code == "CONTROL_JOB_READ",
            ("console.job.read", "DENY") => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_JOB_ID_INVALID"
            ),
            ("console.job.read", "ERROR") => matches!(
                self.reason_code.as_str(),
                "CONTROL_JOB_STORE_UNAVAILABLE"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
            ),
            _ => false,
        };
        valid.then_some(()).ok_or(PublishError::InvalidEvent)
    }

    fn validate_job_target(&self, event_type: &str, success: bool) -> Result<(), PublishError> {
        if event_type == "console.job.read" {
            if success && self.target_job_id.is_none() {
                return Err(PublishError::InvalidEvent);
            }
        } else if self.target_job_id.is_some() {
            return Err(PublishError::InvalidEvent);
        }
        if let Some(target) = &self.target_job_id {
            valid_prefixed_v7(target, "job_")?;
        }
        Ok(())
    }

    fn validate_export_target(&self, event_type: &str, success: bool) -> Result<(), PublishError> {
        let is_export = matches!(
            event_type,
            "console.export.read"
                | "export.requested"
                | "export.approved"
                | "export.denied"
                | "export.downloaded"
        );
        if is_export {
            if success && self.target_export_id.is_none() {
                return Err(PublishError::InvalidEvent);
            }
        } else if self.target_export_id.is_some() {
            return Err(PublishError::InvalidEvent);
        }
        if let Some(target) = &self.target_export_id {
            valid_prefixed_v7(target, "export_")?;
        }
        Ok(())
    }

    /// Key administration names the key it acted on. Success always carries
    /// it; a refusal keeps it only when the path id had already been validated.
    /// Listing, key use and every other event type never carry one: a key id in
    /// the wrong place would let an event claim an action it did not perform.
    fn validate_api_key_target(&self, event_type: &str, success: bool) -> Result<(), PublishError> {
        if event_type == "console.agent_api_key.admin" {
            if success && self.target_api_key_id.is_none() {
                return Err(PublishError::InvalidEvent);
            }
        } else if self.target_api_key_id.is_some() {
            return Err(PublishError::InvalidEvent);
        }
        if let Some(target) = &self.target_api_key_id {
            valid_prefixed_v7(target, "key_")?;
        }
        Ok(())
    }

    fn validate_calibration_report_read_reason(&self) -> Result<(), PublishError> {
        let valid = match self.outcome.as_str() {
            "PASS" => self.reason_code == "CONTROL_CALIBRATION_REPORT_READ",
            "DENY" => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_CALIBRATION_REPORT_ID_INVALID"
                    | "CONTROL_CALIBRATION_REPORT_READ_REQUEST_INVALID"
                    | "CONTROL_CALIBRATION_REPORT_BUSY"
            ),
            "ERROR" => matches!(
                self.reason_code.as_str(),
                "CONTROL_CALIBRATION_REPORT_STORE_UNAVAILABLE"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
            ),
            _ => false,
        };
        let before_target = self.subject_ref.is_none()
            || matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
                    | "CONTROL_CALIBRATION_REPORT_ID_INVALID"
            );
        let requires_target = matches!(
            self.reason_code.as_str(),
            "CONTROL_CALIBRATION_REPORT_READ"
                | "CONTROL_CALIBRATION_REPORT_READ_REQUEST_INVALID"
                | "CONTROL_CALIBRATION_REPORT_BUSY"
                | "CONTROL_CALIBRATION_REPORT_STORE_UNAVAILABLE"
        );
        if !valid
            || before_target && self.target_calibration_report_id.is_some()
            || requires_target && self.target_calibration_report_id.is_none()
        {
            return Err(PublishError::InvalidEvent);
        }
        Ok(())
    }

    fn validate_access_list_reason(&self) -> Result<(), PublishError> {
        let valid = match self.outcome.as_str() {
            "PASS" => self.reason_code == "CONTROL_EVIDENCE_ACCESS_LIST_READ",
            "DENY" => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_CURSOR_INVALID"
                    | "CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID"
                    | "CONTROL_EVIDENCE_ACCESS_BUSY"
            ),
            "ERROR" => matches!(
                self.reason_code.as_str(),
                "CONTROL_CURSOR_UNAVAILABLE"
                    | "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
            ),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(PublishError::InvalidEvent)
        }
    }

    // Export discovery has no direct target, so the reason set alone is the
    // contract. `CONTROL_SESSION_UNAVAILABLE` is the one reason beyond the
    // access-list set: the shared authenticator can emit it for any endpoint,
    // and an unpublishable event would stop its whole segment.
    fn validate_job_list_reason(&self) -> Result<(), PublishError> {
        let valid = match self.outcome.as_str() {
            "PASS" => self.reason_code == "CONTROL_JOBS_READ",
            "DENY" => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_CURSOR_INVALID"
                    | "CONTROL_JOB_LIST_REQUEST_INVALID"
                    | "CONTROL_JOB_LIST_BUSY"
            ),
            "ERROR" => matches!(
                self.reason_code.as_str(),
                "CONTROL_CURSOR_UNAVAILABLE"
                    | "CONTROL_JOB_STORE_UNAVAILABLE"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
                    | "CONTROL_SESSION_UNAVAILABLE"
            ),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(PublishError::InvalidEvent)
        }
    }

    fn validate_export_list_reason(&self) -> Result<(), PublishError> {
        let valid = match self.outcome.as_str() {
            "PASS" => self.reason_code == "CONTROL_EXPORTS_READ",
            "DENY" => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_CURSOR_INVALID"
                    | "CONTROL_EXPORT_LIST_REQUEST_INVALID"
                    | "CONTROL_EXPORT_BUSY"
            ),
            "ERROR" => matches!(
                self.reason_code.as_str(),
                "CONTROL_CURSOR_UNAVAILABLE"
                    | "CONTROL_EXPORT_STORE_UNAVAILABLE"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
                    | "CONTROL_SESSION_UNAVAILABLE"
            ),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(PublishError::InvalidEvent)
        }
    }

    fn validate_access_read_reason(&self) -> Result<(), PublishError> {
        let valid = match self.outcome.as_str() {
            "PASS" => self.reason_code == "CONTROL_EVIDENCE_ACCESS_READ",
            "DENY" => matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_EVIDENCE_ACCESS_ID_INVALID"
                    | "CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID"
                    | "CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE"
                    | "CONTROL_EVIDENCE_ACCESS_BUSY"
            ),
            "ERROR" => matches!(
                self.reason_code.as_str(),
                "CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
            ),
            _ => false,
        };
        let before_target = self.subject_ref.is_none()
            || matches!(
                self.reason_code.as_str(),
                "CONTROL_AUTH_REQUIRED"
                    | "CONTROL_SCOPE_DENIED"
                    | "CONTROL_RATE_LIMITED"
                    | "CONTROL_RATE_UNAVAILABLE"
                    | "CONTROL_CLOCK_UNAVAILABLE"
                    | "CONTROL_EVIDENCE_ACCESS_ID_INVALID"
            );
        if !valid || before_target && self.target_access_request_id.is_some() {
            return Err(PublishError::InvalidEvent);
        }
        Ok(())
    }

    /// Success reason codes are fixed per event type where the producer's set is
    /// closed; the generic code format is enforced separately for every outcome.
    fn success_reason_is_valid(&self, event_type: &str) -> bool {
        match event_type {
            "console.auth.login" => self.reason_code == "CONTROL_OIDC_LOGIN_STARTED",
            "console.auth.callback" => self.reason_code == "CONTROL_OIDC_LOGIN_COMPLETED",
            "console.auth.reauth.start" => self.reason_code == "CONTROL_OIDC_REAUTH_STARTED",
            "console.auth.reauth.callback" => self.reason_code == "CONTROL_OIDC_REAUTH_VERIFIED",
            "console.auth.session.read" => self.reason_code == "CONTROL_BROWSER_SESSION_READ",
            "console.auth.session.logout" => self.reason_code == "CONTROL_BROWSER_SESSION_REVOKED",
            "console.case.list" => self.reason_code == "CONTROL_CASES_READ",
            "console.evidence.hold.created" => matches!(
                self.reason_code.as_str(),
                "CONTROL_EVIDENCE_HOLD_CREATED" | "CONTROL_EVIDENCE_HOLD_CREATE_REPLAYED"
            ),
            "console.evidence.hold.released" => matches!(
                self.reason_code.as_str(),
                "CONTROL_EVIDENCE_HOLD_RELEASED" | "CONTROL_EVIDENCE_HOLD_RELEASE_REPLAYED"
            ),
            "console.evidence.hold.read" => self.reason_code == "CONTROL_EVIDENCE_HOLD_READ",
            "console.workbench.overview.read" => self.reason_code == "WORKBENCH_OVERVIEW_READ",
            "console.export.read" => self.reason_code == "CONTROL_EXPORT_READ",
            "console.job.list" => self.reason_code == "CONTROL_JOBS_READ",
            "export.requested" => matches!(
                self.reason_code.as_str(),
                "EXPORT_REQUESTED" | "EXPORT_REQUEST_REPLAYED"
            ),
            "export.approved" => matches!(
                self.reason_code.as_str(),
                "EXPORT_APPROVED" | "EXPORT_APPROVAL_REPLAYED"
            ),
            "export.denied" => matches!(
                self.reason_code.as_str(),
                "EXPORT_DENIED" | "EXPORT_DENIAL_REPLAYED"
            ),
            "export.downloaded" => self.reason_code == "EXPORT_DOWNLOADED",
            // Site approval and API-key administration success reasons are not
            // enumerated: the closed code format above still applies, and an
            // unknown success code must never stop publication of the segment.
            _ => true,
        }
    }

    // The explicit matrix is the audit contract; keeping it in one place is
    // safer than spreading target rules across event-specific validators.
    #[allow(clippy::too_many_lines, clippy::unnested_or_patterns)]
    fn validate_targets(&self, event_type: &str, success: bool) -> Result<(), PublishError> {
        // Keep the field order explicit: request, artifact, case, access request,
        // model call, agent run, grant, binding, hold, calibration report. Denials retain
        // only their already validated direct target.
        let targets = [
            (&self.target_request_id, "req_"),
            (&self.target_artifact_id, "artifact_"),
            (&self.target_case_id, "case_"),
            (&self.target_access_request_id, "access_"),
            (&self.target_model_call_id, "mdl_"),
            (&self.target_agent_run_id, "agt_"),
            (&self.target_grant_id, "grant_"),
            (&self.target_binding_id, "auth_"),
            (&self.target_hold_id, "ev_"),
            (&self.target_calibration_report_id, "calr_"),
        ];
        let allowed = match (event_type, self.method.as_str(), self.path.as_str()) {
            ("console.auth.login", "GET", "/control/v1/auth/oidc/start")
            | (
                "console.auth.callback" | "console.auth.reauth.callback",
                "GET",
                "/control/v1/auth/oidc/callback",
            )
            | ("console.auth.reauth.start", "POST", "/control/v1/auth/oidc/reauth/start")
            | ("console.auth.session.read", "GET", "/control/v1/session")
            | ("console.auth.session.logout", "POST", "/control/v1/session/logout")
            | ("console.health.read", "GET", "/control/v1/audit/health")
            | ("console.site.config.read", "GET", "/control/v1/site-config")
            | ("console.site.config.write", "PUT", "/control/v1/site-config")
            | ("console.site.config.read", "GET", "/control/v1/sites/{site_id}/config")
            | ("console.site.config.read", "GET", "/control/v1/sites/{site_id}")
            | ("console.site.config.write", "PUT", "/control/v1/sites/{site_id}/config")
            | ("console.site.config.write", "PATCH", "/control/v1/sites/{site_id}")
            | ("console.sites.list", "GET", "/control/v1/sites")
            | ("console.site.create", "POST", "/control/v1/sites")
            | ("console.site.delete", "DELETE", "/control/v1/sites/{site_id}")
            | ("console.site.status.read", "GET", "/control/v1/sites/{site_id}/status")
            | ("console.site.status.read", "GET", "/control/v1/sites/{site_id}/health")
            | ("console.site.status.read", "GET", "/control/v1/sites/{site_id}/revisions")
            | ("console.site.config.validate", "POST", "/control/v1/sites/{site_id}/validate")
            | ("console.site.config.apply", "POST", "/control/v1/sites/{site_id}/apply")
            | ("console.site.config.approve", "POST", "/control/v1/sites/{site_id}/approve")
            | ("console.site.config.rollback", "POST", "/control/v1/sites/{site_id}/rollback")
            | ("console.workbench.overview.read", "GET", "/control/v1/workbench/overview")
            | ("console.agent_api_key.admin", "POST", "/control/v1/agent-api-keys")
            | ("console.agent_api_key.list", "GET", "/control/v1/agent-api-keys")
            | ("console.agent_api_key.use", "*", "/control/v1/*")
            | ("console.export.read", "GET", "/control/v1/exports/{export_id}")
            | ("console.export.list", "GET", "/control/v1/exports")
            | ("console.case.list", "GET", "/control/v1/cases")
            | ("console.model.list", "GET", "/control/v1/model-calls")
            | ("console.evidence.access.list", "GET", "/control/v1/evidence-access-requests")
            | ("console.job.read", "GET", "/control/v1/jobs/{job_id}")
            | ("console.job.list", "GET", "/control/v1/jobs")
            | ("console.causality.read", "POST", "/control/v1/causality") => [false; 10],
            ("console.query.executed", "POST", "/control/v1/search")
            | ("console.request.read", "GET", "/control/v1/requests/{request_id}")
            | ("console.events.read", "GET", "/control/v1/requests/{request_id}/events")
            | ("console.manifest.read", "GET", "/control/v1/requests/{request_id}/evidence") => [
                true, false, false, false, false, false, false, false, false, false,
            ],
            ("console.manifest.read", "GET", "/control/v1/artifacts/{artifact_id}") => [
                false, true, false, false, false, false, false, false, false, false,
            ],
            ("console.model.read", "GET", "/control/v1/model-calls/{model_call_id}") => [
                false, false, false, false, true, false, false, false, false, false,
            ],
            ("console.agent.read", "GET", "/control/v1/agent-runs/{agent_run_id}") => [
                false, false, false, false, false, true, false, false, false, false,
            ],
            ("console.grant.read", "GET", "/control/v1/grants/{grant_id}") => [
                false, false, false, false, false, false, true, false, false, false,
            ],
            ("console.binding.read", "GET", "/control/v1/auth-bindings/{binding_id}") => [
                false, false, false, false, false, false, false, true, false, false,
            ],
            (
                "console.calibration.report.read",
                "GET",
                "/control/v1/calibration-reports/{report_id}",
            ) => [
                false, false, false, false, false, false, false, false, false, true,
            ],
            ("case.created", "POST", "/control/v1/cases")
            | ("export.requested", "POST", "/control/v1/exports")
            | ("export.approved", "POST", "/control/v1/exports/{export_id}/approve")
            | ("export.denied", "POST", "/control/v1/exports/{export_id}/deny")
            | ("case.closed", "POST", "/control/v1/cases/{case_id}/close")
            | ("console.case.read", "GET", "/control/v1/cases/{case_id}/items")
            | ("console.evidence.hold.read", "GET", "/control/v1/cases/{case_id}/holds")
            | ("console.case.analyze", "POST", "/control/v1/cases/{case_id}/analyze") => [
                false, false, true, false, false, false, false, false, false, false,
            ],
            ("case.evidence.added", "POST", "/control/v1/cases/{case_id}/items")
            | ("export.downloaded", "GET", "/control/v1/exports/{export_id}/download") => [
                false, true, true, false, false, false, false, false, false, false,
            ],
            ("console.evidence.hold.created", "POST", "/control/v1/cases/{case_id}/holds")
            | (
                "console.evidence.hold.released",
                "POST",
                "/control/v1/evidence-holds/{hold_id}/release",
            ) => [
                false, true, true, false, false, false, false, false, true, false,
            ],
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
            ) => [
                false, true, true, true, false, false, false, false, false, false,
            ],
            ("evidence.read", "GET", "/control/v1/artifacts/{artifact_id}/content") => [
                false, true, false, true, false, false, false, false, false, false,
            ],
            (
                "console.evidence.access.read",
                "GET",
                "/control/v1/evidence-access-requests/{access_request_id}",
            ) => [
                false, success, success, true, false, false, false, false, false, false,
            ],
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
            | "console.evidence.access.read"
            | "console.evidence.hold.created"
            | "console.evidence.hold.released"
            | "export.downloaded"
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
            | "console.agent.read"
            | "console.case.read"
            | "console.evidence.hold.read"
            | "console.query.executed"
            | "console.causality.read" => true,
            _ => event.evidence_refs.is_empty(),
        };
        if valid {
            Ok(())
        } else {
            Err(PublishError::InvalidEvent)
        }
    }
}
