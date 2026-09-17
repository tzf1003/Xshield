//! Side-effect boundaries used by the request application service.

use crate::{
    audit::AuditEvent,
    domain::{EventId, SiteId, StageExecutionId, TenantId},
};
use std::{cell::RefCell, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Runtime activation state implemented by M0.
pub enum SiteActivation {
    /// Traffic must stop before protected-origin dispatch.
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Minimal trusted site policy needed by M0 orchestration.
pub struct SiteProfile {
    /// Server-selected activation state.
    pub activation: SiteActivation,
}

/// Reads a tenant-scoped site profile. Implementations must not fall back to a
/// profile from another scope.
pub trait SiteConfigStore {
    /// Adapter-specific lookup failure.
    type Error;

    /// # Errors
    /// Returns the adapter's typed failure when the scoped lookup is unavailable.
    fn find(&self, tenant: &TenantId, site: &SiteId) -> Result<Option<SiteProfile>, Self::Error>;
}

/// Commits required audit facts in request order.
pub trait AuditSink {
    /// Adapter-specific durability failure.
    type Error;

    /// # Errors
    /// Returns the adapter's typed failure when the event is not accepted durably.
    fn append(&self, event: AuditEvent) -> Result<(), Self::Error>;
}

/// Supplies opaque identifiers. Production implementations must generate
/// `UUIDv7` values; deterministic mocks are used by M0 tests and examples.
pub trait IdGenerator {
    /// Generates an immutable audit event ID.
    fn event_id(&self) -> EventId;
    /// Generates an ID for one stage attempt.
    fn stage_execution_id(&self) -> StageExecutionId;
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Failure injected by an M0 mock port.
pub struct MockError;

impl fmt::Display for MockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mock port failure")
    }
}

impl std::error::Error for MockError {}

/// In-memory M0 audit adapter. It can inject a durability failure before an
/// event is accepted.
#[derive(Debug, Default)]
pub struct MockAuditSink {
    events: RefCell<Vec<AuditEvent>>,
    fail_at: Option<usize>,
}

impl MockAuditSink {
    #[must_use]
    /// Creates an empty, successful in-memory sink.
    pub const fn new() -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            fail_at: None,
        }
    }

    #[must_use]
    /// Creates a sink that rejects the zero-based event index.
    pub const fn failing_at(event_index: usize) -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            fail_at: Some(event_index),
        }
    }

    #[must_use]
    /// Returns a snapshot of accepted events in request order.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.borrow().clone()
    }
}

impl AuditSink for MockAuditSink {
    type Error = MockError;

    fn append(&self, event: AuditEvent) -> Result<(), Self::Error> {
        if self.fail_at == Some(self.events.borrow().len()) {
            return Err(MockError);
        }
        self.events.borrow_mut().push(event);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
/// M0 configuration adapter that always returns a disabled scoped site.
pub struct DisabledSiteStore;

impl SiteConfigStore for DisabledSiteStore {
    type Error = MockError;

    fn find(&self, _tenant: &TenantId, _site: &SiteId) -> Result<Option<SiteProfile>, Self::Error> {
        Ok(Some(SiteProfile {
            activation: SiteActivation::Disabled,
        }))
    }
}

#[derive(Clone, Copy, Debug, Default)]
/// M0 configuration adapter that injects a lookup failure.
pub struct FailingSiteStore;

impl SiteConfigStore for FailingSiteStore {
    type Error = MockError;

    fn find(&self, _tenant: &TenantId, _site: &SiteId) -> Result<Option<SiteProfile>, Self::Error> {
        Err(MockError)
    }
}

#[derive(Debug, Default)]
/// Deterministic ID source for tests and synthetic examples only.
pub struct MockIds {
    next: RefCell<u64>,
}

impl MockIds {
    fn next(&self, prefix: &str) -> String {
        let value = *self.next.borrow();
        *self.next.borrow_mut() = value + 1;
        format!("{prefix}018f2a3b-4c5d-7000-8000-{value:012x}")
    }
}

impl IdGenerator for MockIds {
    fn event_id(&self) -> EventId {
        EventId::parse(self.next("ev_")).expect("mock generates a valid UUIDv7")
    }

    fn stage_execution_id(&self) -> StageExecutionId {
        StageExecutionId::parse(self.next("stg_")).expect("mock generates a valid UUIDv7")
    }
}
