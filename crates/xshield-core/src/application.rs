//! M0 request orchestration: audit a disabled/unconfigured site and stop before origin.

use crate::{
    audit::{
        AuditEvent, AuditKind, FinalDecision, OriginState, Outcome, ReasonCode, Stage, StageResult,
    },
    domain::{RequestId, SiteId, TenantId},
    ports::{AuditSink, IdGenerator, SiteActivation, SiteConfigStore},
};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Validated scope and server-generated ID for one request.
pub struct RequestInput {
    /// Internal security request ID; never taken from a client header.
    pub request_id: RequestId,
    /// Tenant selected by trusted edge configuration.
    pub tenant_id: TenantId,
    /// Site selected by trusted edge configuration.
    pub site_id: SiteId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Terminal M0 result after required audit events are accepted.
pub struct RequestReport {
    /// Correlates every stage in the report.
    pub request_id: RequestId,
    /// M0 supports only the explicit unconfigured terminal state.
    pub decision: FinalDecision,
    /// Stable reason for the terminal state.
    pub reason_code: ReasonCode,
    /// Proves that M0 did not contact the protected origin.
    pub origin_state: OriginState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Required dependency failures that stop request processing.
pub enum ProcessError {
    /// A required event was not accepted by the audit sink.
    AuditUnavailable,
    /// The site configuration lookup failed.
    ConfigUnavailable,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuditUnavailable => "required audit sink unavailable",
            Self::ConfigUnavailable => "site configuration unavailable",
        })
    }
}

impl std::error::Error for ProcessError {}

/// Coordinates M0 request stages through explicit side-effect ports.
pub struct RequestProcessor<'a, A, C, I> {
    audit: &'a A,
    configs: &'a C,
    ids: &'a I,
}

impl<'a, A, C, I> RequestProcessor<'a, A, C, I>
where
    A: AuditSink,
    C: SiteConfigStore,
    I: IdGenerator,
{
    #[must_use]
    /// Borrows the request's audit, configuration, and identifier ports.
    pub const fn new(audit: &'a A, configs: &'a C, ids: &'a I) -> Self {
        Self {
            audit,
            configs,
            ids,
        }
    }

    /// Processes the currently implemented M0 path.
    ///
    /// Required audit failure fails closed. A disabled or missing site produces
    /// an explicit `NOT_CONFIGURED` terminal result and is never sent upstream.
    ///
    /// # Errors
    /// Returns [`ProcessError`] when a required port is unavailable.
    pub fn process(&self, input: RequestInput) -> Result<RequestReport, ProcessError> {
        let mut request_seq = 1;
        self.append(&input.request_id, request_seq, AuditKind::RequestAccepted)?;

        let Ok(profile) = self.configs.find(&input.tenant_id, &input.site_id) else {
            request_seq += 1;
            self.append(
                &input.request_id,
                request_seq,
                AuditKind::StageCompleted(self.stage(
                    Stage::SiteConfig,
                    Outcome::Error,
                    ReasonCode::SiteConfigUnavailable,
                )),
            )?;
            request_seq += 1;
            self.append(
                &input.request_id,
                request_seq,
                AuditKind::RequestCompleted {
                    decision: FinalDecision::NotConfigured,
                    reason_code: ReasonCode::SiteConfigUnavailable,
                    origin_state: OriginState::NotSent,
                },
            )?;
            return Err(ProcessError::ConfigUnavailable);
        };
        request_seq += 1;
        let reason_code = match profile.map(|profile| profile.activation) {
            None => ReasonCode::SiteNotConfigured,
            Some(SiteActivation::Disabled) => ReasonCode::SiteDisabled,
        };
        self.append(
            &input.request_id,
            request_seq,
            AuditKind::StageCompleted(self.stage(Stage::SiteConfig, Outcome::Deny, reason_code)),
        )?;

        for stage in [
            Stage::IdentityBind,
            Stage::UiProvenance,
            Stage::Capability,
            Stage::BaselineInspection,
            Stage::OriginForward,
        ] {
            request_seq += 1;
            self.append(
                &input.request_id,
                request_seq,
                AuditKind::StageSkipped(self.stage(
                    stage,
                    Outcome::Skipped,
                    ReasonCode::SkippedBySiteUnavailable,
                )),
            )?;
        }

        request_seq += 1;
        self.append(
            &input.request_id,
            request_seq,
            AuditKind::RequestCompleted {
                decision: FinalDecision::NotConfigured,
                reason_code: ReasonCode::RequestNotConfigured,
                origin_state: OriginState::NotSent,
            },
        )?;

        Ok(RequestReport {
            request_id: input.request_id,
            decision: FinalDecision::NotConfigured,
            reason_code: ReasonCode::RequestNotConfigured,
            origin_state: OriginState::NotSent,
        })
    }

    fn append(
        &self,
        request_id: &RequestId,
        request_seq: u32,
        kind: AuditKind,
    ) -> Result<(), ProcessError> {
        self.audit
            .append(AuditEvent {
                event_id: self.ids.event_id(),
                request_id: request_id.clone(),
                request_seq,
                kind,
            })
            .map_err(|_| ProcessError::AuditUnavailable)
    }

    fn stage(&self, stage: Stage, outcome: Outcome, reason_code: ReasonCode) -> StageResult {
        StageResult {
            execution_id: self.ids.stage_execution_id(),
            stage,
            outcome,
            reason_code,
            duration_us: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcessError, RequestInput, RequestProcessor};
    use crate::{
        audit::{AuditKind, FinalDecision, OriginState, Outcome, ReasonCode, Stage},
        domain::{RequestId, SiteId, TenantId},
        ports::{DisabledSiteStore, FailingSiteStore, MockAuditSink, MockIds},
    };

    fn input() -> RequestInput {
        RequestInput {
            request_id: RequestId::parse("req_01a0afa6-3320-758a-9554-d0d3b561b8c6").unwrap(),
            tenant_id: TenantId::parse("tenant_demo").unwrap(),
            site_id: SiteId::parse("demo").unwrap(),
        }
    }

    #[test]
    fn disabled_site_has_complete_not_configured_stage_tree() {
        let audit = MockAuditSink::new();
        let ids = MockIds::default();
        let processor = RequestProcessor::new(&audit, &DisabledSiteStore, &ids);

        let report = processor.process(input()).unwrap();
        let events = audit.events();

        assert_eq!(report.decision, FinalDecision::NotConfigured);
        assert_eq!(report.origin_state, OriginState::NotSent);
        assert_eq!(events.len(), 8);
        assert_eq!(
            events
                .iter()
                .map(|event| event.request_seq)
                .collect::<Vec<_>>(),
            (1..=8).collect::<Vec<_>>()
        );
        assert!(
            events
                .iter()
                .all(|event| event.request_id == report.request_id)
        );
        assert!(matches!(
            &events[1].kind,
            AuditKind::StageCompleted(result)
                if result.stage == Stage::SiteConfig
                    && result.outcome == Outcome::Deny
                    && result.reason_code == ReasonCode::SiteDisabled
        ));
        assert!(matches!(
            &events[6].kind,
            AuditKind::StageSkipped(result)
                if result.stage == Stage::OriginForward
                    && result.outcome == Outcome::Skipped
        ));
    }

    #[test]
    fn required_audit_failure_fails_closed() {
        let audit = MockAuditSink::failing_at(1);
        let ids = MockIds::default();
        let processor = RequestProcessor::new(&audit, &DisabledSiteStore, &ids);

        assert_eq!(
            processor.process(input()),
            Err(ProcessError::AuditUnavailable)
        );
        assert_eq!(audit.events().len(), 1);
    }

    #[test]
    fn config_failure_records_terminal_state_before_returning() {
        let audit = MockAuditSink::new();
        let ids = MockIds::default();
        let processor = RequestProcessor::new(&audit, &FailingSiteStore, &ids);

        assert_eq!(
            processor.process(input()),
            Err(ProcessError::ConfigUnavailable)
        );
        let events = audit.events();
        assert_eq!(events.len(), 3);
        assert!(matches!(
            &events[1].kind,
            AuditKind::StageCompleted(result)
                if result.outcome == Outcome::Error
                    && result.reason_code == ReasonCode::SiteConfigUnavailable
        ));
        assert!(matches!(
            &events[2].kind,
            AuditKind::RequestCompleted {
                reason_code: ReasonCode::SiteConfigUnavailable,
                origin_state: OriginState::NotSent,
                ..
            }
        ));
    }
}
