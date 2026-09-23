//! Typed, bounded query plans for control-plane investigation.
//!
//! A query plan is deliberately smaller than SQL: callers can select only
//! allow-listed fields, a bounded time window, a stable sort, and a finite
//! result page.  Storage adapters compile this value into parameterised
//! queries after injecting the authenticated tenant/site scope.

use crate::{
    domain::{
        ArtifactId, AuthBindingId, CalibrationReportId, CaseId, EventId, EvidenceAccessRequestId,
        GrantId, ModelCallId, RequestId, SubjectRef,
    },
    identity::UnixSeconds,
};
use std::fmt;

/// Hard upper bound for one investigation window.
pub const MAX_WINDOW_SECONDS: u64 = 31 * 24 * 60 * 60;
/// Hard upper bound for one query page.
pub const MAX_LIMIT: u16 = 1_000;
/// Maximum number of independent predicates in one plan.
pub const MAX_FILTERS: usize = 8;
const TEXT_MAX: usize = 128;
// Matches the index's DateTime64 range, with an exclusive upper window bound.
const TIMESTAMP_MAX: u64 = 10_413_792_000;

/// A half-open UTC time window `[start, end)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryWindow {
    start: UnixSeconds,
    end: UnixSeconds,
}

impl QueryWindow {
    /// Validates a non-empty window within the investigation budget.
    ///
    /// # Errors
    /// Returns [`QueryPlanError::InvalidWindow`] when the end is not after the
    /// start, the window exceeds [`MAX_WINDOW_SECONDS`], or the end is after
    /// `2300-01-01T00:00:00Z` (the index's exclusive upper timestamp bound).
    pub fn new(start: UnixSeconds, end: UnixSeconds) -> Result<Self, QueryPlanError> {
        let duration = end
            .value()
            .checked_sub(start.value())
            .ok_or(QueryPlanError::InvalidWindow)?;
        if duration == 0 || duration > MAX_WINDOW_SECONDS || end.value() > TIMESTAMP_MAX {
            return Err(QueryPlanError::InvalidWindow);
        }
        Ok(Self { start, end })
    }

    /// Returns the inclusive lower bound.
    #[must_use]
    pub const fn start(self) -> UnixSeconds {
        self.start
    }

    /// Returns the exclusive upper bound.
    #[must_use]
    pub const fn end(self) -> UnixSeconds {
        self.end
    }
}

/// Fields that may be compared for exact equality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryTextField {
    /// Versioned event family.
    EventType,
    /// Pipeline stage name.
    Stage,
    /// Stable reason code.
    ReasonCode,
    /// Origin operation identifier.
    OperationId,
    /// Resolved model revision.
    ModelRevision,
}

impl QueryTextField {
    /// Returns the stable field name in the query contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventType => "event_type",
            Self::Stage => "stage",
            Self::ReasonCode => "reason_code",
            Self::OperationId => "operation_id",
            Self::ModelRevision => "model_revision",
        }
    }
}

/// Stable request outcome values accepted by the analytical event contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryOutcome {
    /// A stage passed its check.
    Pass,
    /// The final request decision permits forwarding.
    Allow,
    /// Deterministic or model-backed deny result.
    Deny,
    /// A result was not determined.
    Unknown,
    /// A dependency or internal check failed.
    Error,
    /// The stage was intentionally not run.
    Skipped,
    /// The stage was cancelled before completion.
    Cancelled,
}

impl QueryOutcome {
    /// Returns the event-contract value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
            Self::Unknown => "UNKNOWN",
            Self::Error => "ERROR",
            Self::Skipped => "SKIPPED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

/// A bounded confidence threshold represented without floating-point input.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConfidenceThreshold(u16);

impl ConfidenceThreshold {
    /// Builds a threshold in basis points (`0` through `10_000`).
    ///
    /// # Errors
    /// Returns [`QueryPlanError::InvalidConfidence`] when the threshold is
    /// outside the inclusive probability range.
    pub const fn new(basis_points: u16) -> Result<Self, QueryPlanError> {
        if basis_points <= 10_000 {
            Ok(Self(basis_points))
        } else {
            Err(QueryPlanError::InvalidConfidence)
        }
    }

    /// Returns the exact integer representation.
    #[must_use]
    pub const fn basis_points(self) -> u16 {
        self.0
    }

    /// Returns the value used by a parameterised analytical query.
    #[must_use]
    pub fn as_f64(self) -> f64 {
        f64::from(self.0) / 10_000.0
    }
}

/// One allow-listed predicate in a query plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryFilter {
    /// Exact request identity.
    RequestId(RequestId),
    /// Exact immutable event identity.
    EventId(EventId),
    /// Exact direct predecessor event reference.
    ///
    /// This returns events whose recorded cause list contains the reference;
    /// it does not recursively traverse an event graph.
    CausedByEventId(EventId),
    /// Exact direct identity reference in fixed identity and management payload fields.
    SubjectRef(SubjectRef),
    /// Exact resource-grant reference in an issuance event or share source.
    /// This selects historical facts, not the current grant's eligibility.
    GrantId(GrantId),
    /// Exact binding reference in identity or qualification issuance events.
    /// The caller's management scope is applied independently by the adapter.
    AuthBindingId(AuthBindingId),
    /// Direct case reference in case facts or validated management attempts.
    /// This selects history independently of current case access permissions.
    CaseId(CaseId),
    /// Exact evidence reference or validated management target.
    /// Matching metadata does not grant access to the evidence content.
    ArtifactId(ArtifactId),
    /// Exact calibration-report reference in restricted lifecycle history or a
    /// validated management read attempt.
    ///
    /// This selects retained metadata only. It does not authorize report-body
    /// access, evidence access, threshold publication, or business operations.
    CalibrationReportId(CalibrationReportId),
    /// Exact evidence-hold reference in fixed hold lifecycle history or a
    /// validated management mutation attempt.
    ///
    /// This selects retained, redacted metadata only. It does not authorize
    /// retention changes, evidence access, replay, or business operations.
    EvidenceHoldId(EventId),
    /// Exact evidence-access request reference in fixed access lifecycle
    /// history or a validated management detail read.
    ///
    /// This selects retained, redacted metadata only. It does not authorize
    /// evidence access, approval, replay, or business operations.
    EvidenceAccessRequestId(EvidenceAccessRequestId),
    /// Exact model-call reference in fixed model lifecycle history or a
    /// validated management detail read.
    ///
    /// This selects retained, redacted event metadata only. It does not
    /// authorize model-detail access, evidence access, replay, or business
    /// operations.
    ModelCallId(ModelCallId),
    /// Exact equality on an allow-listed text column.
    Text {
        /// Column selected from [`QueryTextField`].
        field: QueryTextField,
        /// Canonical value bound as a query parameter.
        value: String,
    },
    /// Exact event outcome.
    Outcome(QueryOutcome),
    /// Upper confidence bound, inclusive.
    ConfidenceAtMost(ConfidenceThreshold),
}

impl QueryFilter {
    fn validate(&self) -> Result<(), QueryPlanError> {
        match self {
            Self::RequestId(_)
            | Self::EventId(_)
            | Self::CausedByEventId(_)
            | Self::SubjectRef(_)
            | Self::GrantId(_)
            | Self::AuthBindingId(_)
            | Self::CaseId(_)
            | Self::ArtifactId(_)
            | Self::CalibrationReportId(_)
            | Self::EvidenceHoldId(_)
            | Self::EvidenceAccessRequestId(_)
            | Self::ModelCallId(_)
            | Self::Outcome(_)
            | Self::ConfidenceAtMost(_) => Ok(()),
            Self::Text { value, .. } => {
                if valid_query_text(value) {
                    Ok(())
                } else {
                    Err(QueryPlanError::InvalidText)
                }
            }
        }
    }
}

/// Stable ordering supported by the first query adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuerySort {
    /// Oldest event first, then event ID.
    OccurredAtAsc,
    /// Newest event first, then event ID.
    OccurredAtDesc,
}

/// A validated, bounded query plan; authorization is a separate boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPlan {
    window: QueryWindow,
    filters: Vec<QueryFilter>,
    sort: QuerySort,
    limit: u16,
}

impl QueryPlan {
    /// Constructs a plan after applying all static query budgets.
    ///
    /// Tenant and site are intentionally absent.  The control-plane adapter
    /// injects those values from authenticated startup configuration.
    ///
    /// # Errors
    /// Returns a stable [`QueryPlanError`] for an empty/oversized page,
    /// excessive predicates, or an invalid predicate value.
    pub fn new(
        window: QueryWindow,
        filters: Vec<QueryFilter>,
        sort: QuerySort,
        limit: u16,
    ) -> Result<Self, QueryPlanError> {
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(QueryPlanError::InvalidLimit);
        }
        if filters.len() > MAX_FILTERS {
            return Err(QueryPlanError::TooManyFilters);
        }
        for filter in &filters {
            filter.validate()?;
        }
        Ok(Self {
            window,
            filters,
            sort,
            limit,
        })
    }

    /// Returns the bounded time window.
    #[must_use]
    pub const fn window(&self) -> QueryWindow {
        self.window
    }

    /// Returns the validated predicates in caller order.
    #[must_use]
    pub fn filters(&self) -> &[QueryFilter] {
        &self.filters
    }

    /// Returns the stable event ordering.
    #[must_use]
    pub const fn sort(&self) -> QuerySort {
        self.sort
    }

    /// Returns the maximum number of rows returned by one adapter page.
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }
}

/// Stable validation failures for a user- or agent-produced plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryPlanError {
    /// The end of the window is not after its start or exceeds the budget.
    InvalidWindow,
    /// The requested page is zero or exceeds [`MAX_LIMIT`].
    InvalidLimit,
    /// More than [`MAX_FILTERS`] predicates were supplied.
    TooManyFilters,
    /// A text predicate is empty, oversized, or contains control data.
    InvalidText,
    /// A confidence threshold is outside `[0, 1]`.
    InvalidConfidence,
}

impl fmt::Display for QueryPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidWindow => "invalid query window",
            Self::InvalidLimit => "invalid query limit",
            Self::TooManyFilters => "too many query filters",
            Self::InvalidText => "invalid query text",
            Self::InvalidConfidence => "invalid confidence threshold",
        })
    }
}

impl std::error::Error for QueryPlanError {}

fn valid_query_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= TEXT_MAX
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::{
        ConfidenceThreshold, MAX_FILTERS, MAX_LIMIT, MAX_WINDOW_SECONDS, QueryFilter, QueryOutcome,
        QueryPlan, QueryPlanError, QuerySort, QueryTextField, QueryWindow,
    };
    use crate::{
        domain::{
            ArtifactId, AuthBindingId, CalibrationReportId, CaseId, EventId,
            EvidenceAccessRequestId, GrantId, ModelCallId, RequestId, SubjectRef,
        },
        identity::UnixSeconds,
    };

    fn window(seconds: u64) -> QueryWindow {
        QueryWindow::new(UnixSeconds::new(10), UnixSeconds::new(10 + seconds)).unwrap()
    }

    #[test]
    fn plan_is_bounded_and_keeps_scope_out_of_client_input() {
        let request_id = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        let plan = QueryPlan::new(
            window(60),
            vec![
                QueryFilter::RequestId(request_id),
                QueryFilter::Text {
                    field: QueryTextField::ReasonCode,
                    value: "UI_SOURCE_MISSING".to_owned(),
                },
                QueryFilter::Outcome(QueryOutcome::Deny),
                QueryFilter::ConfidenceAtMost(ConfidenceThreshold::new(8_000).unwrap()),
                QueryFilter::GrantId(
                    GrantId::parse("grant_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
                ),
                QueryFilter::AuthBindingId(
                    AuthBindingId::parse("auth_018f2a3b-4c5d-7000-8000-000000000002").unwrap(),
                ),
                QueryFilter::CaseId(
                    CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000003").unwrap(),
                ),
                QueryFilter::ArtifactId(
                    ArtifactId::parse("artifact_018f2a3b-4c5d-7000-8000-000000000004").unwrap(),
                ),
            ],
            QuerySort::OccurredAtAsc,
            50,
        )
        .unwrap();
        assert_eq!(plan.limit(), 50);
        assert_eq!(plan.filters().len(), MAX_FILTERS);
        assert_eq!(
            plan.filters()[1],
            QueryFilter::Text {
                field: QueryTextField::ReasonCode,
                value: "UI_SOURCE_MISSING".to_owned(),
            }
        );
        assert!(
            QueryPlan::new(
                window(60),
                vec![QueryFilter::CalibrationReportId(
                    CalibrationReportId::parse("calr_018f2a3b-4c5d-7000-8000-000000000005")
                        .unwrap(),
                )],
                QuerySort::OccurredAtAsc,
                1,
            )
            .is_ok()
        );
        assert!(
            QueryPlan::new(
                window(60),
                vec![QueryFilter::SubjectRef(
                    SubjectRef::parse("operator-1").unwrap(),
                )],
                QuerySort::OccurredAtAsc,
                1,
            )
            .is_ok()
        );
        assert!(
            QueryPlan::new(
                window(60),
                vec![QueryFilter::EvidenceHoldId(
                    EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000006").unwrap(),
                )],
                QuerySort::OccurredAtAsc,
                1,
            )
            .is_ok()
        );
        assert!(
            QueryPlan::new(
                window(60),
                vec![QueryFilter::EvidenceAccessRequestId(
                    EvidenceAccessRequestId::parse("access_018f2a3b-4c5d-7000-8000-000000000006")
                        .unwrap(),
                )],
                QuerySort::OccurredAtAsc,
                1,
            )
            .is_ok()
        );
        assert!(
            QueryPlan::new(
                window(60),
                vec![QueryFilter::ModelCallId(
                    ModelCallId::parse("mdl_018f2a3b-4c5d-7000-8000-000000000006").unwrap(),
                )],
                QuerySort::OccurredAtAsc,
                1,
            )
            .is_ok()
        );
        let mut excess = plan.filters().to_vec();
        excess.push(plan.filters()[MAX_FILTERS - 1].clone());
        assert_eq!(
            QueryPlan::new(plan.window(), excess, plan.sort(), plan.limit()),
            Err(QueryPlanError::TooManyFilters)
        );
    }

    #[test]
    fn direct_cause_filter_uses_a_typed_event_reference() {
        let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000008").unwrap();
        let plan = QueryPlan::new(
            window(60),
            vec![QueryFilter::CausedByEventId(event.clone())],
            QuerySort::OccurredAtAsc,
            1,
        )
        .unwrap();
        assert_eq!(plan.filters(), [QueryFilter::CausedByEventId(event)]);
    }

    #[test]
    fn rejects_window_limit_filter_and_text_boundaries() {
        assert!(
            QueryWindow::new(UnixSeconds::new(0), UnixSeconds::new(MAX_WINDOW_SECONDS)).is_ok()
        );
        assert!(
            QueryWindow::new(
                UnixSeconds::new(super::TIMESTAMP_MAX - 1),
                UnixSeconds::new(super::TIMESTAMP_MAX)
            )
            .is_ok()
        );
        for (start, end) in [
            (11, 10),
            (super::TIMESTAMP_MAX, super::TIMESTAMP_MAX + 1),
            (u64::MAX - 1, u64::MAX),
        ] {
            assert_eq!(
                QueryWindow::new(UnixSeconds::new(start), UnixSeconds::new(end)),
                Err(QueryPlanError::InvalidWindow)
            );
        }
        assert!(matches!(
            QueryWindow::new(UnixSeconds::new(10), UnixSeconds::new(10)),
            Err(QueryPlanError::InvalidWindow)
        ));
        assert!(matches!(
            QueryWindow::new(
                UnixSeconds::new(10),
                UnixSeconds::new(10 + MAX_WINDOW_SECONDS + 1)
            ),
            Err(QueryPlanError::InvalidWindow)
        ));
        assert!(matches!(
            QueryPlan::new(window(1), Vec::new(), QuerySort::OccurredAtAsc, 0),
            Err(QueryPlanError::InvalidLimit)
        ));
        assert!(matches!(
            QueryPlan::new(
                window(1),
                Vec::new(),
                QuerySort::OccurredAtAsc,
                MAX_LIMIT + 1
            ),
            Err(QueryPlanError::InvalidLimit)
        ));
        assert!(matches!(
            QueryPlan::new(
                window(1),
                (0..=MAX_FILTERS)
                    .map(|_| QueryFilter::Outcome(QueryOutcome::Pass))
                    .collect(),
                QuerySort::OccurredAtAsc,
                1,
            ),
            Err(QueryPlanError::TooManyFilters)
        ));
        assert!(matches!(
            QueryPlan::new(
                window(1),
                vec![QueryFilter::Text {
                    field: QueryTextField::Stage,
                    value: "stage\nname".to_owned(),
                }],
                QuerySort::OccurredAtAsc,
                1,
            ),
            Err(QueryPlanError::InvalidText)
        ));
        assert!(ConfidenceThreshold::new(10_001).is_err());
    }
}
